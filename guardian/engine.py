"""通信の変化を追跡し、危険度に応じて止める監視エンジン。"""
from __future__ import annotations

import ntpath
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

from .models import HIGH, LEVEL_RANK, LOW, MEDIUM, Alert, Assessment, BlockedConnect, Conn, Context, ProcFacts, Reason
from .launchwatch import assess_launch
from .traps import TrapHit, is_benign_reader, is_owner
from .sysmonrules import (
    DNS_QUERY, PROCESS_CREATE, REGISTRY_VALUE_SET, SysmonEvent, assess_dns, assess_persistence,
    facts_from_create, is_persistence_key, is_watched_host, parse_event, registered_path,
)
from .risk import MEDIUM_THRESHOLD, LOLBINS, MASQUERADE_NAMES, SHELLS, UNTRUSTABLE, assess, classify_location, is_beacon, is_external, is_loopback

# 止めるとWindows自体が不安定になるプロセス（システムフォルダ内のものだけ保護する）
PROTECTED_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
    "fontdrvhost.exe", "memory compression", "secure system", "lsaiso.exe",
}
FANOUT_WINDOW = 60.0
MAX_HOSTS_PER_PROCESS = 32
IDLE_STATE_LIMIT = 3600.0
INBOUND_ALERT_SOURCES = 20  # 大量の接続元から狙われても、通知で画面を埋めない
RESUME = "resume"
TRUST = "trust"
TERMINATE = "terminate"
SUSPEND = "suspend"
KEEP = "keep"
GATE_ERROR_LIMIT = 5  # 監視が連続で失敗したら遮断を解除する（判定できないまま止め続けない）
GATE_RETRY_SECONDS = 60.0
# パスだけで許可すると中身を問わず通してしまうので、確認済みでも毎回判定するもの
GATE_NEVER_SEED = SHELLS | LOLBINS
DEV_SHELL_MEMORY = 120.0


def is_untrustable(path: str | None) -> bool:
    return bool(path) and path.rsplit("\\", 1)[-1].lower() in UNTRUSTABLE


@dataclass
class _ProcState:
    facts: ProcFacts
    last_active: float
    ip_events: deque = field(default_factory=deque)
    connect_times: dict[str, list[float]] = field(default_factory=dict)
    alerted_rank: int = -1
    inbound_ranks: dict[str, int] = field(default_factory=dict)  # 接続元ごとの通知済み危険度
    allowed: bool = False
    suspended: bool = False


@dataclass
class _GateApp:
    """送信前の遮断で止めたアプリの状態。"""

    permitted: bool = False
    alerted_rank: int = -1
    revoked: bool = False  # 罠に触れたので許可を取り消した。判断があるまで止めたまま


class Engine:
    def __init__(
        self,
        source,
        inspector,
        actions,
        store,
        *,
        on_alert: Callable[[Alert], None] | None = None,
        observe: bool = False,
        external_check: Callable[[str], bool] = is_external,
        clock: Callable[[], float] = time.time,
        self_pids: set[int] | None = None,
        poll_interval: float = 0.5,
        assess_fn=assess,
        gate=None,
        launches=None,
        launch_assess=assess_launch,
        zone_of: Callable[[str | None], int | None] | None = None,
        sysmon=None,
        strict: bool = False,
        traps=None,
    ):
        self.source = source
        self.inspector = inspector
        self.actions = actions
        self.store = store
        self.on_alert = on_alert
        self.observe = observe
        self.external_check = external_check
        self.clock = clock
        self.self_pids = self_pids if self_pids is not None else {os.getpid()}
        self.poll_interval = poll_interval
        self.assess_fn = assess_fn
        self.gate = gate
        self.launches = launches
        self.launch_assess = launch_assess
        self.zone_of = zone_of
        self._known_pids: set[int] | None = None
        self.sysmon = sysmon
        self._hosts: dict[int, deque] = {}
        self._dev_shells: dict[int, tuple[str, float]] = {}
        self.strict = strict
        self.traps = traps
        self._trap_alerted: set[tuple] = set()
        self._revoked_paths: set[str] = set()

        self._lock = threading.RLock()
        self._states: dict[tuple[int, int], _ProcState] = {}
        self._rows: list[dict] = []
        self._scores: dict[tuple, Assessment] = {}
        self._pending: dict[int, Alert] = {}
        self._next_id = 1
        self._baseline_done = False
        self._gate_apps: dict[str, _GateApp] = {}
        self._gate_retry_at = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.paused_until = 0.0
        self.heartbeat = clock()
        self.errors = 0
        self.last_error = ""

    # ---------- 実行制御
    def _remove_untrustable(self) -> None:
        """以前の版で登録された PowerShell などの信頼を外す。"""
        for entry in self.store.trust_entries():
            path = entry.get("path")
            if is_untrustable(path):
                self.store.remove_trust(path)
                self.store.log({"event": "trust_removed", "path": path, "reason": "untrustable"})

    def start(self) -> None:
        self._remove_untrustable()
        self.recover_suspended()
        self._thread = threading.Thread(target=self._run, name="guardian-engine", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                if self.clock() >= self.paused_until:
                    self.poll_once()
                self.errors = 0
            except Exception as exc:  # 監視ループは止めず、UIに異常を伝える
                self.errors += 1
                self.last_error = repr(exc)
                self.store.log({"event": "engine_error", "detail": repr(exc)})
            self.sync_gate()
            self.heartbeat = self.clock()
            self._stop.wait(self.poll_interval)

    def shutdown(self, resume_suspended: bool = True) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
        if self.gate is not None:
            with self._lock:
                self.gate.disable()
        if resume_suspended:
            with self._lock:
                for state in self._states.values():
                    if state.suspended:
                        self.actions.resume(state.facts.pid)
                        state.suspended = False
                self._pending.clear()
                self._persist_suspended()

    def pause(self, seconds: float) -> None:
        self.paused_until = self.clock() + seconds
        self.store.log({"event": "paused", "seconds": seconds})

    def unpause(self) -> None:
        self.paused_until = 0.0
        self.store.log({"event": "unpaused"})

    @property
    def paused(self) -> bool:
        return self.clock() < self.paused_until

    # ---------- 監視本体
    def poll_once(self) -> None:
        now = self.clock()
        conns = self.source.snapshot()
        listening = {(c.pid, c.local_port) for c in conns if c.state == "LISTEN"}
        with self._lock:
            # Sysmonを先に読むと、短時間で終わるプログラムも本来の情報で判定できる
            self._drain_sysmon(now)
            self._drain_traps(now)
            self._check_launches(now)
            self._drain_blocks(now)
            rows = []
            scores = {}
            for conn in conns:
                if conn.pid in self.self_pids or conn.pid == 0 or conn.state == "OTHER":
                    continue
                direction = self._direction(conn, listening)
                if direction is None:
                    continue
                # 状態が変わっただけ（接続中→確立など）では新しい接続として数えない
                key = (conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port, conn.pid)
                assessment = scores.get(key) or self._scores.get(key)
                if assessment is None:
                    assessment = self._evaluate(conn, direction, now, new_app_allowed=self._baseline_done)
                scores[key] = assessment
                rows.append(self._row(conn, direction, assessment))
            self._scores = scores
            self._rows = rows
            self._baseline_done = True
            self._prune(now)

    def _check_launches(self, now: float) -> None:
        """新しく起動したプログラムを見る。感染の入口で止めるため、通信を待たない。"""
        if self.launches is None:
            return
        current = set(self.launches.snapshot())
        known, self._known_pids = self._known_pids, current
        if known is None:
            return  # 起動時にすでに動いているものは、通信の監視に任せる
        for pid in sorted(current - known):
            if pid in self.self_pids or pid in (0, 4) or not self.inspector.created(pid):
                continue
            self._judge_launch(self._state_for(pid, now))

    def _judge_launch(self, state: _ProcState) -> None:
        if state.allowed or state.suspended:
            return
        zone = self.zone_of(state.facts.path) if self.zone_of else None
        self._alert_if_needed(state, "launch", self.launch_assess(state.facts, zone))

    def _alert_if_needed(self, state: _ProcState, direction: str, assessment: Assessment) -> None:
        if assessment.level == LOW or state.allowed or state.suspended or self._is_trusted(state.facts):
            return
        rank = LEVEL_RANK[assessment.level]
        if rank > state.alerted_rank:
            state.alerted_rank = rank
            self._raise_alert(state, None, direction, assessment)

    # ---------- Sysmon
    def _drain_sysmon(self, now: float) -> None:
        if self.sysmon is None:
            return
        for xml in self.sysmon.poll():
            event = parse_event(xml)
            if event is None or event.pid in self.self_pids:
                continue
            if event.event_id == PROCESS_CREATE:
                self._on_process_create(event, now)
            elif event.event_id == DNS_QUERY:
                self._on_dns(event, now)
            elif event.event_id == REGISTRY_VALUE_SET:
                self._on_registry(event, now)
        if self.sysmon.cleared:
            self.sysmon.cleared = False
            facts = ProcFacts(0, 0, "Sysmonの記録")
            assessment = Assessment(80, HIGH, [Reason("log_cleared", 80, "Sysmonの記録が消されました。攻撃者が痕跡を消すときの手口です")])
            self._emit_alert(facts, None, "tamper", assessment, "exited", 0)

    def _live_state(self, event: SysmonEvent, now: float) -> _ProcState | None:
        """イベントのプロセスがまだ動いていれば状態を返す。PIDの使い回しは別物として扱う。"""
        if not event.pid or not self.inspector.created(event.pid):
            return None
        state = self._state_for(event.pid, now)
        same = not event.image or not state.facts.path or state.facts.path.lower() == event.image.lower()
        return state if same else None

    def _signature_of(self, path: str | None) -> str:
        reader = getattr(self.inspector, "signature_of", None)
        return reader(path) if reader else "unknown"

    def _emit_exited(self, facts: ProcFacts, direction: str, assessment: Assessment) -> None:
        """すでに終了したプログラムの検知。止めるものはないが、起きたことを知らせる。"""
        if assessment.level != LOW and not self._is_trusted(facts):
            self._emit_alert(facts, None, direction, assessment, "exited", 0)

    def _dev_tool_of_event(self, event: SysmonEvent, now: float) -> str | None:
        """すぐ終了したシェルは親をたどれないので、記録の親子関係で開発ツールからの実行かを調べる。"""
        reader = getattr(self.inspector, "dev_tool_of_image", None)
        if reader is None or not event.image:
            return None
        if event.image.rsplit("\\", 1)[-1].lower() not in SHELLS:
            return None
        for pid, (_tool, seen) in list(self._dev_shells.items()):
            if now - seen > DEV_SHELL_MEMORY:
                del self._dev_shells[pid]
        try:
            parent_pid = int(event.data.get("ParentProcessId", "0"))
        except ValueError:
            parent_pid = 0
        known = self._dev_shells.get(parent_pid)
        tool = known[0] if known else reader(event.data.get("ParentImage"))
        if tool and event.pid:
            self._dev_shells[event.pid] = (tool, now)
        return tool

    def _on_process_create(self, event: SysmonEvent, now: float) -> None:
        tool = self._dev_tool_of_event(event, now)
        state = self._live_state(event, now)
        if state is not None:
            state.facts.dev_tool = state.facts.dev_tool or tool
            self._judge_launch(state)
            return
        facts = facts_from_create(event, self._signature_of(event.image))
        facts.dev_tool = tool
        zone = self.zone_of(facts.path) if self.zone_of else None
        self._emit_exited(facts, "launch", self.launch_assess(facts, zone))

    def _on_dns(self, event: SysmonEvent, now: float) -> None:
        host = event.data.get("QueryName", "").strip().lower()
        if not host or not event.pid:
            return
        hosts = self._hosts.setdefault(event.pid, deque(maxlen=MAX_HOSTS_PER_PROCESS))
        if host not in hosts:
            hosts.append(host)
        if not is_watched_host(host):
            return
        state = self._live_state(event, now)
        if state is not None:
            self._alert_if_needed(state, "dns", assess_dns(state.facts, host))
            return
        facts = facts_from_create(event, self._signature_of(event.image))
        self._emit_exited(facts, "dns", assess_dns(facts, host))

    def _on_registry(self, event: SysmonEvent, now: float) -> None:
        target = event.data.get("TargetObject", "")
        if not is_persistence_key(target):
            return
        details = event.data.get("Details", "")
        path = registered_path(details)
        if self._is_trusted_path(path):
            return
        assessment = assess_persistence(
            facts_from_create(event), target, details, self._signature_of(path),
        )
        # 判定の結果にかかわらず、自動起動の登録は記録に残す
        self.store.log({
            "event": "persistence", "writer": event.image, "target": target, "details": details[:300],
            "score": assessment.score, "level": assessment.level,
        })
        state = self._live_state(event, now)
        if state is not None:
            self._alert_if_needed(state, "persistence", assessment)
        else:
            self._emit_exited(facts_from_create(event, self._signature_of(event.image)), "persistence", assessment)

    # ---------- 罠
    def _drain_traps(self, now: float) -> None:
        if self.traps is None:
            return
        for hit in self.traps.poll():
            if hit.pid not in self.self_pids:
                self._on_trap_hit(hit, now)

    def _on_trap_hit(self, hit: TrapHit, now: float) -> None:
        name = ntpath.basename(hit.image) or f"PID {hit.pid}"
        state = None
        if hit.pid and self.inspector.created(hit.pid):
            candidate = self._state_for(hit.pid, now)
            if not hit.image or not candidate.facts.path or candidate.facts.path.lower() == hit.image.lower():
                state = candidate
        facts = state.facts if state else ProcFacts(hit.pid, 0, name, hit.image or None, signature=self._signature_of(hit.image))
        if (
            is_benign_reader(facts.name, facts.path, facts.signature)
            or is_owner(hit, facts.name, facts.path, facts.signature)
            or self._is_trusted(facts)
        ):
            return
        key = (hit.pid, facts.created, hit.path.lower())
        if key in self._trap_alerted:
            return
        self._trap_alerted.add(key)
        real = hit.kind == "real"
        self.store.log({
            "event": "watch_read" if real else "trap_hit", "name": facts.name, "path": facts.path,
            "pid": hit.pid, "trap": hit.path,
        })
        # 本物の見張りは、誤動作を確かめるため既定では記録だけにする
        if real and not self.traps.enforce:
            return
        file_name = ntpath.basename(hit.path)
        text = (
            f"本物の認証ファイル {file_name} を読みました。本来読むプログラムではありません" if real
            else f"罠のファイル {file_name} を読みました。普通のプログラムは触らない場所です"
        )
        assessment = Assessment(90, HIGH, [Reason("trap", 90, text)])
        if state is None:
            self._emit_alert(facts, None, "trap", assessment, "exited", 0)
            return
        if state.suspended:
            return
        # 許可済みのプログラムでも、もう自動では通さない
        state.allowed = False
        ordinary = self._strict_ok(facts.path, facts.signature) and facts.name.lower() not in SHELLS | LOLBINS
        if ordinary and not self.observe and not self.is_protected(facts):
            self._restrain_signed(state, assessment)
        else:
            self._raise_alert(state, None, "trap", assessment)

    def _restrain_signed(self, state: _ProcState, assessment: Assessment) -> None:
        """署名つきのプログラムは正規のソフトの場合があるので止めず、外への接続だけを封じて確認する。"""
        facts = state.facts
        revoke = getattr(self.gate, "revoke", None) if self.gate_active else None
        app_id = revoke(facts.path) if revoke else None
        disconnected = 0
        if app_id:
            app = self._gate_apps.setdefault(app_id, _GateApp())
            app.permitted = False
            app.revoked = True
            app.alerted_rank = LEVEL_RANK[HIGH]
            self._revoked_paths.add((facts.path or "").lower())
            disconnected = self._disconnect_all(facts.pid)
        self._emit_alert(facts, None, "trap", assessment, "blocked" if app_id else "ask", disconnected, gate_app=app_id)

    # ---------- 厳格モード
    def _strict_ok(self, path: str | None, signature: str) -> bool:
        """厳格モードで確認なしに通してよいもの。有効な署名があるか、Windowsのシステムフォルダのもの。"""
        return signature == "valid" or classify_location(path) == "system"

    @staticmethod
    def _strict_assessment(assessment: Assessment) -> Assessment:
        reason = Reason("strict_unknown", 0, "厳格モード: 署名のない初めてのプログラムです。心当たりがなければ止めたままにしてください")
        return Assessment(max(assessment.score, MEDIUM_THRESHOLD), MEDIUM, [*assessment.reasons, reason])

    def set_strict(self, enabled: bool) -> None:
        with self._lock:
            self.strict = enabled
            self.store.log({"event": "strict", "enabled": enabled})
            # 遮断の許可を今の方針で作り直す。sync_gate がすぐ入れ直す
            if self.gate is not None and self.gate.active:
                self._gate_apps.clear()
                self.gate.disable()

    def dns_hosts(self, pid: int) -> list[str]:
        with self._lock:
            return list(self._hosts.get(pid, ()))

    @property
    def sysmon_status(self) -> str | None:
        return self.sysmon.status if self.sysmon is not None else None

    def _direction(self, conn: Conn, listening: set[tuple[int, int]]) -> str | None:
        if conn.state == "LISTEN":
            return None if is_loopback(conn.local_ip) else "listen"
        if not self.external_check(conn.remote_ip):
            return None
        return "inbound" if (conn.pid, conn.local_port) in listening else "outbound"

    def _evaluate(self, conn: Conn, direction: str, now: float, new_app_allowed: bool) -> Assessment:
        state = self._state_for(conn.pid, now)
        facts = state.facts

        distinct, beacon = (0, False) if direction == "listen" else self._track_attempt(state, conn.remote_ip, now)

        first_seen = (
            new_app_allowed and direction == "outbound" and bool(facts.path)
            and not self.store.is_seen(facts.path)
        )
        ctx = Context(
            direction=direction,
            remote_port=conn.remote_port,
            local_port=conn.local_port,
            first_seen=first_seen,
            distinct_ips_60s=distinct,
            beacon=beacon,
        )
        assessment = self.assess_fn(facts, ctx)

        # 遮断が動いていないときは止められないので、初めて外へつないだ時点で知らせる
        strict_unknown = (
            self.strict and assessment.level == LOW and first_seen and not self.gate_active
            and not self._strict_ok(facts.path, facts.signature)
        )
        if strict_unknown:
            assessment = self._strict_assessment(assessment)
        if assessment.level == LOW:
            if direction == "outbound":
                self.store.mark_seen(facts.path)
            return assessment
        if state.allowed or state.suspended:
            return assessment
        if self._is_trusted(facts):
            return assessment
        rank = LEVEL_RANK[assessment.level]
        if direction == "inbound":
            # svchost経由のリモートデスクトップなど、同じプログラムでも接続元ごとに知らせる
            if rank > state.inbound_ranks.get(conn.remote_ip, -1) and len(state.inbound_ranks) < INBOUND_ALERT_SOURCES:
                state.inbound_ranks[conn.remote_ip] = rank
                self._raise_alert(state, conn, direction, assessment)
        elif rank > state.alerted_rank:
            state.alerted_rank = rank
            self._raise_alert(state, conn, direction, assessment)
        return assessment

    @staticmethod
    def _track_attempt(state: _ProcState, remote_ip: str, now: float) -> tuple[int, bool]:
        """接続の試みを記録し、60秒間の宛先数と、一定間隔の接続かどうかを返す。"""
        state.ip_events.append((now, remote_ip))
        while state.ip_events and now - state.ip_events[0][0] > FANOUT_WINDOW:
            state.ip_events.popleft()
        times = state.connect_times.setdefault(remote_ip, [])
        times.append(now)
        del times[:-16]
        return len({ip for _, ip in state.ip_events}), is_beacon(times)

    def _state_for(self, pid: int, now: float) -> _ProcState:
        created = self.inspector.created(pid)
        key = (pid, created)
        state = self._states.get(key)
        if state is None:
            state = _ProcState(self.inspector.inspect(pid), now)
            self._states[key] = state
        state.last_active = now
        return state

    def _is_trusted(self, facts: ProcFacts) -> bool:
        return self._is_trusted_path(facts.path)

    def _is_trusted_path(self, path: str | None) -> bool:
        if not self.store.has_trust_entry(path) or is_untrustable(path):
            return False
        return self.store.is_trusted(path, self.inspector.file_hash(path))

    def _prune(self, now: float) -> None:
        for key, state in list(self._states.items()):
            if not state.suspended and now - state.last_active > IDLE_STATE_LIMIT:
                del self._states[key]

    # ---------- 送信前の遮断
    @property
    def gate_active(self) -> bool:
        return self.gate is not None and self.gate.active

    def sync_gate(self) -> None:
        """遮断のオンとオフを、今の状態に合わせる。休止の解除もここで反映される。"""
        if self.gate is None:
            return
        now = self.clock()
        want = (
            not self.observe and not self.paused and self._baseline_done
            and self.errors < GATE_ERROR_LIMIT and not self._stop.is_set()
        )
        try:
            if want and not self.gate.active and now >= self._gate_retry_at:
                self._enable_gate(now)
            elif not want and self.gate.active:
                with self._lock:
                    self.gate.disable()
                self.store.log({"event": "gate_off", "errors": self.errors, "paused": self.paused})
        except Exception as exc:  # 遮断の失敗で監視を止めない
            self._gate_retry_at = now + GATE_RETRY_SECONDS
            self.last_error = repr(exc)
            self.store.log({"event": "gate_error", "detail": repr(exc)})

    def _enable_gate(self, now: float) -> None:
        with self._lock:
            permitted = [key for key, app in self._gate_apps.items() if app.permitted]
        if self.gate.enable(self.known_app_paths(), permitted):
            self.store.log({"event": "gate_on"})
        else:
            self._gate_retry_at = now + GATE_RETRY_SECONDS
            self.store.log({"event": "gate_error", "detail": getattr(self.gate, "last_error", "")})

    def known_app_paths(self) -> list[str]:
        """遮断の開始時から通してよいアプリ。低危険度で通信を確認したものと、信頼リストのもの。"""
        paths = []
        for path in self.store.seen_apps():
            if path.lower() in self._revoked_paths:
                continue
            name = path.rsplit("\\", 1)[-1].lower()
            location = classify_location(path)
            masquerade = name in MASQUERADE_NAMES and location != "system"
            if location == "risky" or masquerade or name in GATE_NEVER_SEED:
                continue
            # 信頼リストにあって中身が変わったものは、改めて判定する
            if self.store.has_trust_entry(path) and not self._is_trusted_path(path):
                continue
            # 厳格モードでは、一度通信しただけの署名なしプログラムを無条件では通さない
            if self.strict and not self.store.has_trust_entry(path) and not self._strict_ok(path, self._signature_of(path)):
                continue
            paths.append(path)
        known = {p.lower() for p in paths}
        for entry in self.store.trust_entries():
            path = entry.get("path")
            if path and path.lower() not in known and self._is_trusted_path(path):
                paths.append(path)
        return paths

    def _drain_blocks(self, now: float) -> None:
        if self.gate is None:
            return
        events = {(e.app_id, e.remote_ip, e.remote_port): e for e in self.gate.drain()}
        for event in events.values():
            try:
                self._handle_block(event, now)
            except Exception as exc:  # 1件の失敗で残りの判定を止めない。この接続は止まったまま
                self.store.log({"event": "gate_error", "detail": repr(exc), "app": event.app_id})

    def _handle_block(self, event: BlockedConnect, now: float) -> None:
        if not event.app_id:
            self.store.log({"event": "gate_unknown_app", "remote": f"{event.remote_ip}:{event.remote_port}"})
            return
        app = self._gate_apps.setdefault(event.app_id, _GateApp())
        if app.permitted or app.revoked:
            return  # 許可を追加する前に止まった接続の通知か、判断待ちで封じている接続
        facts = self.inspector.inspect_image(event.app_id)
        state = self._state_for(facts.pid, now) if facts.pid else None
        if state is not None:
            facts = state.facts
        distinct, beacon = self._track_attempt(state, event.remote_ip, now) if state else (0, False)
        ctx = Context(
            direction="outbound", remote_port=event.remote_port,
            first_seen=bool(facts.path) and not self.store.is_seen(facts.path),
            distinct_ips_60s=distinct, beacon=beacon,
        )
        assessment = self.assess_fn(facts, ctx)
        decided = self._is_trusted(facts) or (state is not None and state.allowed)
        if self.strict and assessment.level == LOW and not decided and not self._strict_ok(facts.path, facts.signature):
            assessment = self._strict_assessment(assessment)
        if assessment.level == LOW or decided:
            if assessment.level == LOW:
                self.store.mark_seen(facts.path)
            self._gate_permit(event.app_id, app, facts, assessment)
            return

        rank = LEVEL_RANK[assessment.level]
        if rank <= app.alerted_rank:
            return  # 確認済みの危険度なら、止めたまま何度も知らせない
        app.alerted_rank = rank
        conn = Conn("", 0, event.remote_ip, event.remote_port, "BLOCKED", facts.pid)
        action = "blocked"
        if facts.pid and self.is_protected(facts):
            # Windowsに必要なプログラムは止めると不安定になるので、通して知らせるだけにする
            action = "protected"
            self._gate_permit(event.app_id, app, facts, assessment)
        elif assessment.level == HIGH and state is not None and self.actions.suspend(facts.pid):
            action = "suspended"
            state.suspended = True
            self._persist_suspended()
        if state is not None:
            state.alerted_rank = max(state.alerted_rank, rank)
        self._emit_alert(facts, conn, "outbound", assessment, action, 0, gate_app=event.app_id)

    def _gate_permit(self, app_id: str, app: _GateApp, facts: ProcFacts, assessment: Assessment) -> bool:
        ok = self.gate.permit(app_id)
        app.permitted = ok
        self.store.log({
            "event": "gate_permit", "name": facts.name, "path": facts.path,
            "score": assessment.score, "ok": ok,
        })
        return ok

    # ---------- 検知時の対応
    def is_protected(self, facts: ProcFacts) -> bool:
        if facts.pid in (0, 4) or facts.pid in self.self_pids:
            return True
        if facts.name.lower() not in PROTECTED_NAMES:
            return False
        # パス不明はシステム保護プロセスに限られる。別の場所にある同名ファイルは保護しない。
        return not facts.path or classify_location(facts.path) == "system"

    def _raise_alert(self, state: _ProcState, conn: Conn | None, direction: str, assessment: Assessment) -> None:
        action = "ask"
        disconnected = 0
        if assessment.level == HIGH:
            if self.observe:
                action = "observe"
            elif self.is_protected(state.facts):
                action = "protected"
            elif self.actions.suspend(state.facts.pid):
                action = "suspended"
                state.suspended = True
                self._persist_suspended()
                disconnected = self._disconnect_all(state.facts.pid)
            else:
                action = "suspend_failed"
        self._emit_alert(state.facts, conn, direction, assessment, action, disconnected)

    def _emit_alert(self, facts: ProcFacts, conn: Conn | None, direction: str, assessment: Assessment,
                    action: str, disconnected: int, gate_app: str | None = None) -> None:
        alert = Alert(
            id=self._next_id, at=self.clock(), proc=facts, conn=conn, direction=direction,
            assessment=assessment, action=action, disconnected=disconnected, gate_app=gate_app,
        )
        self._next_id += 1
        self._pending[alert.id] = alert
        self.store.log({
            "event": "detected", "alert_id": alert.id, "name": facts.name, "pid": facts.pid,
            "path": facts.path, "cmdline": (facts.cmdline or "")[:300],
            "signature": facts.signature, "remote": f"{conn.remote_ip}:{conn.remote_port}" if conn else "",
            "local_port": conn.local_port if conn else 0, "direction": direction, "score": assessment.score,
            "level": assessment.level, "action": action, "disconnected": disconnected,
            "reasons": [r.text for r in assessment.reasons],
        })
        if self.on_alert:
            self.on_alert(alert)

    def _disconnect_all(self, pid: int) -> int:
        count = 0
        for conn in self.source.snapshot():
            if conn.pid == pid and conn.state in ("ESTABLISHED", "SYN_SENT", "SYN_RCVD", "UNKNOWN"):
                if self.actions.disconnect(conn):
                    count += 1
        return count

    def _persist_suspended(self) -> None:
        self.store.save_suspended([
            {"pid": s.facts.pid, "created": s.facts.created, "name": s.facts.name, "path": s.facts.path}
            for s in self._states.values() if s.suspended
        ])

    def recover_suspended(self) -> None:
        """前回異常終了して止めたままのプロセスを、確認待ちとして引き継ぐ。"""
        with self._lock:
            for entry in self.store.load_suspended():
                pid, created = entry.get("pid"), entry.get("created")
                if not pid or not created or self.inspector.created(pid) != created:
                    continue
                facts = self.inspector.inspect(pid)
                state = _ProcState(facts, self.clock(), suspended=True, alerted_rank=LEVEL_RANK[HIGH])
                self._states[(pid, created)] = state
                assessment = Assessment(100, HIGH, [Reason("recovered", 100, "前回の終了時に止めたままになっていました")])
                alert = Alert(self._next_id, self.clock(), facts, None, "outbound", assessment, "recovered")
                self._next_id += 1
                self._pending[alert.id] = alert
                if self.on_alert:
                    self.on_alert(alert)
            self._persist_suspended()

    # ---------- ユーザーの判断
    def decide(self, alert_id: int, decision: str) -> tuple[bool, str]:
        with self._lock:
            alert = self._pending.get(alert_id)
            if alert is None:
                return False, "この確認はすでに処理済みです。"
            facts = alert.proc
            state = self._states.get((facts.pid, facts.created))
            if decision == KEEP:
                self.store.log({"event": "decision", "alert_id": alert_id, "decision": decision, "name": facts.name})
                return True, "止めたままにします。"
            # pid=0 は遮断イベントの時点で終了していたプログラム
            alive = bool(facts.pid) and self.inspector.created(facts.pid) == facts.created
            ok, message = True, ""
            if decision == SUSPEND:
                if self.observe:
                    ok, message = False, "観察モードでは止められません。"
                elif not alive:
                    message = "このプログラムはすでに終了しています。"
                elif self.is_protected(facts):
                    ok, message = False, "Windowsの動作に必要なプログラムなので止められません。"
                else:
                    ok = self.actions.suspend(facts.pid)
                    message = "止めました。" if ok else "止められませんでした（権限が足りない可能性があります）。"
                    if ok and state is not None:
                        state.suspended = True
                        alert.action = "suspended"
                        alert.disconnected = self._disconnect_all(facts.pid)
                self.store.log({"event": "decision", "alert_id": alert_id, "decision": decision, "ok": ok, "name": facts.name})
                self._persist_suspended()
                if self.on_alert and ok and alive:
                    self.on_alert(alert)
                return ok, message
            if decision == TERMINATE:
                if not alive:
                    message = "このプログラムはすでに終了しています。"
                elif self.is_protected(facts):
                    return False, "Windowsの動作に必要なプログラムなので終了できません。"
                else:
                    ok = self.actions.terminate(facts.pid)
                    message = "終了させました。" if ok else "終了できませんでした（権限が足りない可能性があります）。"
                    if not ok:
                        self.store.log({"event": "decision", "alert_id": alert_id, "decision": decision, "ok": False, "name": facts.name})
                        return False, message
                if state is not None:
                    state.suspended = False
                if alert.gate_app and alert.gate_app in self._gate_apps:
                    # 止めたまま。次にまた起動して接続しようとしたら改めて確認する
                    self._gate_apps[alert.gate_app].alerted_rank = -1
                    self._gate_apps[alert.gate_app].revoked = False
                    self._revoked_paths.discard((facts.path or "").lower())
            elif decision in (RESUME, TRUST):
                if decision == TRUST:
                    if is_untrustable(facts.path):
                        return False, f"{facts.name} は攻撃にも使われるので、常に信頼にはできません。"
                    digest = self.inspector.file_hash(facts.path)
                    if not digest:
                        return False, "ファイルを確認できないため信頼リストに登録できません。"
                    self.store.add_trust(facts.path, digest)
                    self.store.mark_seen(facts.path)
                if state is not None:
                    if state.suspended and alive and not self.actions.resume(facts.pid):
                        return False, "再開できませんでした（権限が足りない可能性があります）。"
                    state.suspended = False
                    state.allowed = True
                if alert.gate_app and self.gate is not None:
                    app = self._gate_apps.setdefault(alert.gate_app, _GateApp())
                    # 休止中は次に遮断を始めるときに許可へ含める
                    if self.gate.active and not self.gate.permit(alert.gate_app):
                        self.store.log({"event": "decision", "alert_id": alert_id, "decision": decision, "ok": False, "name": facts.name})
                        return False, "通信の許可を追加できませんでした。"
                    app.permitted = True
                    app.revoked = False
                    self._revoked_paths.discard((facts.path or "").lower())
                message = "信頼リストに登録して再開しました。" if decision == TRUST else "今回だけ許可しました。"
            else:
                return False, f"不明な操作です: {decision}"
            del self._pending[alert_id]
            self._persist_suspended()
            self.store.log({"event": "decision", "alert_id": alert_id, "decision": decision, "ok": ok, "name": facts.name})
            return ok, message

    # ---------- 詳細画面からの操作
    def control(self, pid: int, operation: str) -> tuple[bool, str]:
        """利用者が詳細画面で選んだ停止・再開・終了。保護の判定は自動の場合と同じ。"""
        with self._lock:
            created = self.inspector.created(pid) if pid else 0
            if not created:
                return False, "このプログラムはすでに終了しています。"
            state = self._state_for(pid, self.clock())
            facts = state.facts
            ok, message = False, f"不明な操作です: {operation}"
            if operation == SUSPEND:
                if self.observe:
                    return False, "観察モードでは止められません。"
                if self.is_protected(facts):
                    return False, "Windowsの動作に必要なプログラムなので止められません。"
                # 二重に止めると、再開も二回必要になる
                if state.suspended:
                    return True, "すでに止めています。"
                ok = self.actions.suspend(pid)
                message = "止めました。" if ok else "止められませんでした（権限が足りない可能性があります）。"
                if ok:
                    state.suspended = True
                    self._disconnect_all(pid)
            elif operation == RESUME:
                if not state.suspended:
                    return True, "このプログラムは止めていません。"
                ok = self.actions.resume(pid)
                message = "再開しました。" if ok else "再開できませんでした（権限が足りない可能性があります）。"
                if ok:
                    state.suspended = False
            elif operation == TERMINATE:
                if self.is_protected(facts):
                    return False, "Windowsの動作に必要なプログラムなので終了できません。"
                ok = self.actions.terminate(pid)
                message = "終了させました。" if ok else "終了できませんでした（権限が足りない可能性があります）。"
                if ok:
                    state.suspended = False
            self._persist_suspended()
            self.store.log({"event": "decision", "decision": operation, "ok": ok, "name": facts.name, "source": "detail"})
            return ok, message

    def is_suspended(self, pid: int) -> bool:
        with self._lock:
            state = self._states.get((pid, self.inspector.created(pid)))
            return bool(state and state.suspended)

    # ---------- UI向け
    def _row(self, conn: Conn, direction: str, assessment: Assessment) -> dict:
        created = self.inspector.created(conn.pid)
        state = self._states.get((conn.pid, created))
        return {
            "name": state.facts.name if state else f"PID {conn.pid}",
            "path": state.facts.path if state else None,
            "pid": conn.pid,
            "direction": direction,
            "remote": conn.remote_ip,
            "remote_port": conn.remote_port,
            "local_port": conn.local_port,
            "state": conn.state,
            "score": assessment.score,
            "level": assessment.level,
            "suspended": bool(state and state.suspended),
        }

    def rows(self) -> list[dict]:
        with self._lock:
            return list(self._rows)

    def pending(self) -> list[Alert]:
        with self._lock:
            return list(self._pending.values())

    def suspended_count(self) -> int:
        with self._lock:
            return sum(1 for s in self._states.values() if s.suspended)


class WinSource:
    def snapshot(self) -> list[Conn]:
        from .winapi import tcp_snapshot

        return tcp_snapshot()


__all__ = ["Engine", "WinSource", "RESUME", "TRUST", "TERMINATE", "SUSPEND", "KEEP", "HIGH", "MEDIUM"]
