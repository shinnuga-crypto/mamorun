"""実機の自己検査。止める対象は検査用に自分で起動した子プロセスだけに限定する。"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from . import VERSION
from .engine import RESUME, TERMINATE, Engine, WinSource
from .models import HIGH, Assessment, Conn, ProcFacts, Reason
from .store import Store
from .winapi import (
    WinActions, WinInspector, device_path_to_dos, is_admin, process_native_path, process_path,
    signature_status, tcp_snapshot,
)


# 封じ込みはインターネット宛だけが対象なので、予約済みのアドレスでは確かめられない。
# 接続できても何も送らずに閉じる。
REVOKE_TEST_HOST = "1.1.1.1"
REVOKE_TEST_PORT = 443
REVOKE_CHECK_KEYS = (
    "gate_enabled", "external_open_when_permitted", "revoke_returns_app", "external_blocked_by_revoke",
    "local_kept_during_revoke", "permit_clears_revoke", "external_open_after_permit", "gate_removed",
    "local_after_gate_removed",
)


def beacon_child(port: int, heartbeat_file: str) -> int:
    """検査用の無害な子プロセス。自分のPC内のポートへ接続し、動いた証拠を書き続ける。"""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        count = 0
        deadline = time.time() + 60
        while time.time() < deadline:
            count += 1
            temp = heartbeat_file + ".tmp"
            with open(temp, "w", encoding="ascii") as handle:
                handle.write(str(count))
            try:
                os.replace(temp, heartbeat_file)
            except PermissionError:
                pass  # 検査側が読んでいる瞬間は置き換えられない。次の周で書く
            try:
                sock.sendall(b".")
            except OSError:
                pass
            time.sleep(0.05)
    return 0


def _spawn_child(port: int, heartbeat: Path) -> subprocess.Popen:
    if getattr(sys, "frozen", False):
        command = [sys.executable, "--test-beacon", str(port), str(heartbeat)]
    else:
        main_py = Path(__file__).resolve().parent.parent / "main.py"
        command = [sys.executable, str(main_py), "--test-beacon", str(port), str(heartbeat)]
    return subprocess.Popen(command, creationflags=subprocess.CREATE_NO_WINDOW)


def _read_counter(path: Path) -> int:
    try:
        return int(path.read_text(encoding="ascii") or 0)
    except (OSError, ValueError):
        return 0


def _wait_counter_change(path: Path, timeout: float = 15) -> bool:
    first = _read_counter(path)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _read_counter(path) > first:
            return True
        time.sleep(0.05)
    return False


class _OnlyPid:
    """検査中に別のプログラムを止めないよう、対象PIDの接続だけをエンジンに渡す。"""

    def __init__(self, pid: int):
        self.pid = pid
        self.inner = WinSource()

    def snapshot(self):
        return [c for c in self.inner.snapshot() if c.pid == self.pid and c.state != "LISTEN"]


def _force_high(_facts, _ctx):
    return Assessment(90, HIGH, [Reason("selfcheck", 90, "自己検査用")])


def _pipeline_check(work: Path, decision: str) -> dict:
    """検知→一時停止→再開または終了 を実プロセスで確かめる。"""
    result: dict = {"decision": decision}
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(20)
    port = server.getsockname()[1]
    heartbeat = work / f"heartbeat-{decision}.txt"
    child = _spawn_child(port, heartbeat)
    peer = None
    alerts = []
    engine = None
    try:
        peer, _ = server.accept()
        peer.settimeout(0.05)
        result["child_running"] = _wait_counter_change(heartbeat)
        store = Store(work / f"data-{decision}")
        engine = Engine(
            _OnlyPid(child.pid), WinInspector(), WinActions(), store,
            on_alert=alerts.append, external_check=lambda _ip: True, assess_fn=_force_high,
        )
        start = time.perf_counter()
        engine.poll_once()
        result["detect_and_stop_ms"] = round((time.perf_counter() - start) * 1000, 1)
        result["alert_action"] = alerts[0].action if alerts else None
        if not alerts:
            result["connections_seen"] = [c.state for c in engine.source.snapshot()]
            result["detected"] = False
            return result
        result["path_found"] = bool(alerts and alerts[0].proc.path)
        time.sleep(0.4)
        before = _read_counter(heartbeat)
        time.sleep(1.0)
        result["stopped_while_suspended"] = _read_counter(heartbeat) == before
        result["suspended_listed"] = len(store.load_suspended()) == 1
        ok, message = engine.decide(alerts[0].id, decision)
        result["decide_ok"] = ok
        result["message"] = message
        if decision == RESUME:
            result["running_after_resume"] = _wait_counter_change(heartbeat)
        else:
            child.wait(timeout=5)
            result["exited_after_terminate"] = child.poll() is not None
        result["suspended_cleared"] = store.load_suspended() == []
    finally:
        if peer is not None:
            peer.close()
        server.close()
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
    return result


def _ui_check(shots: Path | None, work: Path) -> dict:
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QColor, QImage, QPainter, QPixmap

    from .art import STATES, MascotArt
    from .ui import AlertWindow, Dashboard, MascotWidget, make_app, demo_alert

    app = make_app(sys.argv)
    result: dict = {}
    placeholder = MascotArt(work / "no-images")
    result["placeholder_mode"] = not placeholder.has_images
    widget = MascotWidget(placeholder)

    def capture(target: MascotWidget, state: str) -> QImage:
        target.set_state(state)
        image = QImage(target.size(), QImage.Format.Format_ARGB32_Premultiplied)
        image.fill(Qt.GlobalColor.transparent)
        painter = QPainter(image)
        target.render_to(painter, 1.0)
        painter.end()
        return image

    painted = {}
    for state in STATES:
        image = capture(widget, state)
        painted[state] = image.pixelColor(image.width() // 2, image.height() // 2).alpha() > 0
        if shots:
            image.save(str(shots / f"mascot-{state}.png"))
    result["placeholder_painted"] = painted
    corner = capture(widget, "idle").pixelColor(0, 0).alpha()
    result["background_transparent"] = corner == 0

    # 差し替え口: 透過PNGを置くと、仮キャラの代わりに読み込まれること
    folder = work / "art"
    folder.mkdir(exist_ok=True)
    sample = QPixmap(300, 600)
    sample.fill(QColor(30, 120, 220, 255))
    sample.save(str(folder / "idle_1.png"))
    sample.fill(QColor(30, 200, 120, 255))
    sample.save(str(folder / "idle_2.png"))
    sample.fill(QColor(220, 30, 30, 255))
    sample.save(str(folder / "alert.png"))
    (folder / "broken.png").write_bytes(b"not an image")
    (folder / "watch.png").write_bytes(b"not an image")
    art = MascotArt(folder)
    result["image_count"] = sum(len(v) for v in art.frames.values())
    result["image_frames_cycle"] = art.frame("idle", 0).cacheKey() != art.frame("idle", 0.6).cacheKey()
    result["image_alert_used"] = art.frame("alert", 0).cacheKey() == art.frames["alert"][0].cacheKey()
    result["broken_falls_back_to_idle"] = art.frame("watch", 0).cacheKey() == art.frames["idle"][0].cacheKey()
    image_widget = MascotWidget(art)
    result["image_widget_fits_aspect"] = image_widget.width() < widget.width()
    image = capture(image_widget, "alert")
    center = image.pixelColor(image.width() // 2, image.height() // 2)
    result["image_drawn"] = center.red() > 180 and center.blue() < 80
    if shots:
        image.save(str(shots / "mascot-image-slot.png"))

    window = AlertWindow()
    window.show_alert(demo_alert(), others=1, demo=True)
    app.processEvents()
    result["alert_locked_initially"] = all(not b.isEnabled() for b, _ in window._locked)
    if shots:
        window.grab().save(str(shots / "alert.png"))
    window.alert = None
    window.close()

    store = Store(work / "data-ui")
    engine = Engine(_NoSource(), WinInspector(), WinActions(), store)
    board = Dashboard(engine, lambda: "自己検査")
    board.refresh()
    if shots:
        board.grab().save(str(shots / "dashboard.png"))
    result["dashboard_ok"] = True
    return result


class _NoSource:
    def snapshot(self):
        return []


class _ListSource:
    def __init__(self, conns):
        self.conns = conns

    def snapshot(self):
        return list(self.conns)


class _FakeInspector:
    """実在しない検査用プロセス。OSのプロセスには触れない。"""

    def created(self, _pid):
        return 1

    def inspect(self, pid):
        return ProcFacts(pid, 1, "sample.exe", r"C:\Users\you\Downloads\sample.exe", None, None, "unsigned")

    def file_hash(self, _path):
        return "selfcheck"


class _RecordingActions:
    def __init__(self):
        self.calls = []

    def suspend(self, pid):
        self.calls.append(("suspend", pid))
        return True

    def resume(self, pid):
        self.calls.append(("resume", pid))
        return True

    def terminate(self, pid):
        self.calls.append(("terminate", pid))
        return True

    def disconnect(self, _conn):
        return False


def _controller_check(work: Path) -> dict:
    """検知が画面に届き、判断がエンジンに戻るまでの流れを確かめる。"""
    from PyQt6.QtWidgets import QApplication

    from .ui import Controller

    result: dict = {}
    actions = _RecordingActions()
    source = _ListSource([Conn("192.168.1.2", 50000, "203.0.113.10", 4444, "ESTABLISHED", 900001)])
    engine = Engine(source, _FakeInspector(), actions, Store(work / "data-controller"), external_check=lambda _ip: True)
    controller = Controller(engine, work / "no-images", True)
    window = controller.alert_window
    try:
        controller.update_state()
        result["starts_idle"] = controller.mascot.state == "idle"
        engine.poll_once()
        QApplication.processEvents()
        alert = window.alert
        result["alert_reaches_window"] = alert is not None and window.isVisible()
        result["process_suspended"] = ("suspend", 900001) in actions.calls
        controller.update_state()
        result["mascot_turns_alert"] = controller.mascot.state == "alert"
        result["release_buttons_locked"] = bool(window._locked) and all(not b.isEnabled() for b, _ in window._locked)
        for _ in range(3):
            window._tick_lock()
        result["release_buttons_unlock"] = all(b.isEnabled() for b, _ in window._locked)
        window.close()  # ×で閉じても解除しない
        QApplication.processEvents()
        result["close_keeps_stopped"] = engine.suspended_count() == 1 and ("resume", 900001) not in actions.calls
        controller.on_mascot_click()
        QApplication.processEvents()
        result["click_reopens"] = window.isVisible() and window.alert is not None
        controller.on_decided(alert.id, RESUME)
        QApplication.processEvents()
        result["decision_resumes"] = ("resume", 900001) in actions.calls and engine.pending() == []
        controller.update_state()
        result["mascot_back_to_idle"] = controller.mascot.state == "idle"
        result["window_hidden_when_done"] = not window.isVisible()
        controller.show_demo()
        calls_before = list(actions.calls)
        controller.on_decided(-1, RESUME)
        result["demo_touches_nothing"] = actions.calls == calls_before
    finally:
        controller.shutdown()
        controller.mascot.close()
        controller.bubble.close()
        window.alert = None
        window.close()
    return result


def _character_check(shots: Path | None, work: Path) -> dict:
    """同梱の絵で、全場面の表示とキャラの切り替えを確かめる。"""
    from dataclasses import replace

    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QImage, QPainter

    from .art import STATES, MascotArt, default_art_root
    from .characters import CHARACTERS, DEFAULT_CHARACTER, PLAIN
    from .ui import Controller, MascotWidget, demo_alert

    root = default_art_root()
    result: dict = {}
    for character in CHARACTERS:
        art = MascotArt(root / character)
        result[f"{character}_all_states"] = all(art.frames.get(state) for state in STATES)
        widget = MascotWidget(art)
        drawn = True
        for state in STATES:
            widget.set_state(state)
            image = QImage(widget.size(), QImage.Format.Format_ARGB32_Premultiplied)
            image.fill(Qt.GlobalColor.transparent)
            painter = QPainter(image)
            widget.render_to(painter, 1.0)
            painter.end()
            # 中央に絵があり、下端は足元まで届き、左下の角は透明
            drawn = drawn and image.pixelColor(image.width() // 2, image.height() // 3).alpha() > 200
            drawn = drawn and image.pixelColor(0, image.height() - 1).alpha() == 0
            if shots:
                image.save(str(shots / f"{character}-{state}.png"))
        result[f"{character}_drawn"] = drawn
        widget.close()

    data = work / "data-character"
    store = Store(data)
    store.settings["character"] = "nobody"
    engine = Engine(_NoSource(), WinInspector(), WinActions(), store)
    controller = Controller(engine, root, True)
    try:
        result["unknown_setting_falls_back"] = controller.character.id == DEFAULT_CHARACTER
        controller.mascot.show()
        luce_frame = controller.art.frame("idle", 0).cacheKey()
        center, bottom = controller.mascot.geometry().center().x(), controller.mascot.geometry().bottom()
        controller.set_character("ansel")
        result["image_changes"] = controller.art.frame("idle", 0).cacheKey() != luce_frame
        result["feet_stay_in_place"] = (
            abs(controller.mascot.geometry().center().x() - center) <= 1 and controller.mascot.geometry().bottom() == bottom
        )
        result["greets_in_character"] = controller.bubble.label.text() == CHARACTERS["ansel"].line("selected")
        result["choice_saved"] = Store(data).settings.get("character") == "ansel"
        restored = Controller(engine, root, True)
        result["choice_restored"] = restored.character.id == "ansel"
        restored.tray.hide()
        restored.mascot.close()
        restored.bubble.close()
        controller._build_menu()
        titles = [action.text() for action in controller.menu.actions()]
        result["menu_has_character"] = "キャラクター" in titles
        engine._pending[1] = replace(demo_alert(), id=1, action="blocked")
        result["blocked_shows_alert_state"] = controller.compute_state() == "alert"
        engine._pending.clear()
        controller.mascot.show()
        controller.set_mascot_hidden(True)
        result["hide_removes_character"] = not controller.mascot.isVisible() and not controller.bubble.isVisible()
        result["hide_uses_plain_lines"] = controller.line("resume") == PLAIN.line("resume")
        result["hide_saved"] = Store(data).settings.get("mascot_hidden") is True
        controller._build_menu()
        result["hidden_menu_has_no_size"] = "大きさ" not in [action.text() for action in controller.menu.actions()]
        controller.say("自己検査")  # 吹き出しを出さずにトレイの通知へ回す
        result["hidden_shows_no_bubble"] = not controller.bubble.isVisible()
        hidden_start = Controller(engine, root, True)
        hidden_start.start = None  # 表示の分岐だけを確かめる
        result["hidden_setting_restored"] = hidden_start.mascot_hidden
        hidden_start.tray.hide()
        hidden_start.mascot.close()
        hidden_start.bubble.close()
        controller.set_character("luce")
        result["choosing_character_shows_again"] = controller.mascot.isVisible() and not controller.mascot_hidden
        # 警告画面: 内容が長くても画面内に収まり、ボタンの文字が切れない
        from dataclasses import replace as replace_alert

        from PyQt6.QtCore import QRect
        from PyQt6.QtWidgets import QPushButton

        window = controller.alert_window
        long_alert = replace_alert(demo_alert(), assessment=Assessment(95, HIGH, [
            Reason(f"r{i}", 5, "長い説明の文章です。" * 12) for i in range(30)
        ]))
        window.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen)
        window.show_alert(long_alert, others=2)
        area = QRect(0, 0, 1366, 728)
        window.fit_to_screen(area)
        buttons = window.findChildren(QPushButton)
        result["alert_fits_screen"] = window.y() <= 16 and window.y() + window.height() + 40 <= area.bottom() + 1
        result["alert_buttons_not_cut"] = bool(buttons) and all(b.width() >= b.sizeHint().width() for b in buttons)
        window.alert = None
        window.hide()
        # Sysmonが止まったら知らせる（検査用の状態で確かめる）
        notices: list[str] = []
        controller.warn = lambda spoken, _detail: notices.append(spoken)
        states = {"Sysmon": "running", "SysmonDrv": "running"}
        controller.sysmon_watch.query = lambda name: states.get(name, "missing")
        controller.check_stops()
        states["Sysmon"] = "stopped"
        controller.check_stops()
        result["sysmon_stop_warns"] = notices == [controller.line("sysmon_stopped")]
        result["sysmon_stop_in_status"] = "Sysmon: 止まっています" in controller.status_text()
    finally:
        engine._pending.clear()
        controller.shutdown()
        controller.mascot.close()
        controller.bubble.close()
    return result


def connect_child(port: int, host: str = "127.0.0.1", timeout: float = 10) -> int:
    """検査用の子プロセス。接続できれば0、WFPに拒否されれば13、それ以外の失敗は1で終わる。"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return 0
    except PermissionError:  # WSAEACCES: 接続を許可する段階で止められた
        return 13
    except OSError as exc:
        return 13 if getattr(exc, "winerror", None) == 10013 else 1


def _try_connect(port: int, host: str | None = None) -> int:
    if getattr(sys, "frozen", False):
        command = [sys.executable, "--test-connect", str(port)]
    else:
        main_py = Path(__file__).resolve().parent.parent / "main.py"
        command = [sys.executable, str(main_py), "--test-connect", str(port)]
    if host:
        command += ["--test-connect-host", host]
    return subprocess.run(command, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30).returncode


def _gate_probe(work: Path) -> dict:
    """管理者権限なしで確かめられる部分。フィルターは1つも追加しない。"""
    from .wfp import WfpGate, app_id_from_path, interactive_user_sids, sddl_for_users, security_descriptor_bytes

    own_path = process_path(os.getpid())
    app_id = app_id_from_path(own_path)
    native = process_native_path(os.getpid())
    sids = interactive_user_sids()
    result: dict = {
        "app_id_found": bool(app_id),
        "app_id_matches_process": bool(native) and bool(app_id) and native.lower() == app_id.lower(),
        "device_path_converts": bool(native) and (device_path_to_dos(native) or "").lower() == own_path.lower(),
        "user_sid_found": bool(sids),
        "security_descriptor_built": len(security_descriptor_bytes(sddl_for_users(sids))) > 0 if sids else False,
    }
    if not is_admin():
        # 権限がないときは最初の問い合わせで断られ、何も残さず v0.1 の動作に戻ること
        gate = WfpGate()
        result["refused_without_admin"] = gate.enable([]) is False and not gate.active
    return result


def _disconnect_probe() -> bool:
    """管理者権限で、検査用に自分で作ったPC内の接続だけを切断できるか確かめる。"""
    server = socket.socket()
    client = socket.socket()
    peer = None
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        client.connect(server.getsockname())
        peer, _ = server.accept()
        local, remote = client.getsockname(), client.getpeername()
        if not WinActions().disconnect(Conn(local[0], local[1], remote[0], remote[1], "ESTABLISHED", os.getpid())):
            return False
        client.settimeout(3)
        try:
            return client.recv(1) == b""
        except OSError:
            return True  # 切断されると接続リセットのエラーになる
    finally:
        client.close()
        if peer is not None:
            peer.close()
        server.close()


def _revoke_probe(port: int) -> dict:
    """許可済みのプログラムの送信を封じ、解除できるかを確かめる。

    実際の遮断を数秒だけ有効にする。接続先へはつなぐだけで、データは送らない。
    """
    from .wfp import WfpGate, app_id_from_path

    path = process_path(os.getpid())
    app_id = app_id_from_path(path)
    gate = WfpGate()
    result: dict = {"gate_enabled": gate.enable([path])}
    try:
        if result["gate_enabled"]:
            result["external_open_when_permitted"] = _try_connect(REVOKE_TEST_PORT, REVOKE_TEST_HOST) != 13
            result["revoke_returns_app"] = (gate.revoke(path) or "").lower() == (app_id or "").lower() != ""
            result["external_blocked_by_revoke"] = _try_connect(REVOKE_TEST_PORT, REVOKE_TEST_HOST) == 13
            result["local_kept_during_revoke"] = _try_connect(port) == 0
            result["permit_clears_revoke"] = gate.permit(app_id)
            result["external_open_after_permit"] = _try_connect(REVOKE_TEST_PORT, REVOKE_TEST_HOST) != 13
    finally:
        gate.disable()
    result["gate_removed"] = not gate.active
    result["local_after_gate_removed"] = _try_connect(port) == 0
    return result


def run_gate_check(output: str) -> int:
    """送信前の遮断の実機検査。止めるのはこのプログラムの接続で、普段の遮断も数秒だけ有効にする。

    戻り値: 0=合格 / 1=不合格 / 2=管理者権限がない
    """
    from .wfp import NarrowBlockCheck, app_id_from_path

    report: dict = {"version": VERSION, "is_admin": is_admin()}
    out_path = Path(output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not report["is_admin"]:
        report.update(passed=False, reason="管理者権限が必要です。管理者のターミナルから実行してください。")
        out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return 2

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    port = server.getsockname()[1]
    stop = threading.Event()

    def accept_loop():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                peer, _ = server.accept()
                peer.close()
            except OSError:
                continue

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    # venv の python.exe は本体を起動し直すので、実際に動いている実行ファイルを対象にする
    app_id = app_id_from_path(process_path(os.getpid()))
    check = None
    try:
        report["connects_before_filter"] = _try_connect(port) == 0
        check = NarrowBlockCheck(app_id, port)
        check.block()
        report["blocked_by_filter"] = _try_connect(port) == 13
        deadline = time.time() + 15
        while not check.events and time.time() < deadline:
            time.sleep(0.1)
        event = check.events[0] if check.events else None
        report["drop_event_received"] = event is not None
        report["drop_event_app_id_matches"] = bool(event) and event.app_id.lower() == app_id.lower()
        report["drop_event_address_matches"] = bool(event) and event.remote_ip == "127.0.0.1" and event.remote_port == port
        check.permit()
        report["connects_after_permit"] = _try_connect(port) == 0
        check.block()
        check.close()
        check = None
        report["connects_after_close"] = _try_connect(port) == 0
        report["disconnect_works"] = _disconnect_probe()
        report["revoke"] = _revoke_probe(port)
    except Exception as exc:
        report["error"] = repr(exc)
    finally:
        if check is not None:
            check.close()
        stop.set()
        thread.join(timeout=2)
        server.close()
    keys = (
        "connects_before_filter", "blocked_by_filter", "drop_event_received", "drop_event_app_id_matches",
        "drop_event_address_matches", "connects_after_permit", "connects_after_close", "disconnect_works",
    )
    report["passed"] = (
        all(report.get(k) is True for k in keys)
        and len(report.get("revoke", {})) == len(REVOKE_CHECK_KEYS)
        and all(report["revoke"].get(k) is True for k in REVOKE_CHECK_KEYS)
    )
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if report["passed"] else 1


def _inspect_check(shots: Path | None, work: Path) -> dict:
    """本物のファイルで署名と構造を読む。改ざんの検査は作業フォルダのコピーだけに行う。"""
    from .proginfo import ProgramInspector
    from .report import BAD, WARN
    from .reportview import report_html
    from .signinfo import TAMPERED, UNSIGNED, VALID

    result: dict = {}
    inspector = ProgramInspector()
    root = os.environ.get("SystemRoot", r"C:\Windows")
    explorer = inspector.inspect_file(os.path.join(root, "explorer.exe"))
    signer = explorer.signature.signer
    result["signature_valid"] = explorer.signature.status == VALID
    result["signer_is_microsoft"] = bool(signer) and "Microsoft" in signer.organization
    result["chain_read"] = len(explorer.signature.chain) >= 2
    result["timestamp_read"] = explorer.signature.signed_at is not None
    result["digest_read"] = bool(explorer.signature.digest)
    result["version_read"] = "Microsoft" in explorer.version.get("CompanyName", "")
    result["pe_read"] = bool(explorer.pe and explorer.pe.sections and explorer.pe.imports)
    result["system_file_has_no_warning"] = explorer.count(BAD) == 0 and explorer.count(WARN) == 0
    catalog = inspector.inspect_file(os.path.join(root, "System32", "notepad.exe"))
    result["catalog_or_embedded_signed"] = catalog.signature.status == VALID and catalog.signer_name != ""

    # 署名済みファイルのコピーを1バイトだけ変えると、改ざんとして見つかること
    tampered_path = work / "tampered.exe"
    data = bytearray(Path(os.path.join(root, "explorer.exe")).read_bytes())
    data[len(data) // 2] ^= 0xFF
    tampered_path.write_bytes(data)
    tampered = inspector.inspect_file(str(tampered_path))
    result["tampered_is_found"] = tampered.signature.status == TAMPERED and tampered.count(BAD) >= 1

    # 署名なしのファイルと、入手元の記録
    unsigned_path = work / "unsigned.exe"
    unsigned_path.write_bytes(b"MZ" + b"\0" * 2048)
    with open(str(unsigned_path) + ":Zone.Identifier", "w", encoding="utf-8") as handle:
        handle.write("[ZoneTransfer]\nZoneId=3\nHostUrl=https://example.test/a.exe\n")
    unsigned = inspector.inspect_file(str(unsigned_path))
    result["unsigned_is_found"] = unsigned.signature.status == UNSIGNED
    result["motw_read"] = unsigned.motw.get("ZoneId") == "3" and "example.test" in unsigned.motw.get("HostUrl", "")

    missing = inspector.inspect_file(str(work / "missing.exe"))
    result["missing_file_is_safe"] = not missing.exists

    own = inspector.inspect_process(os.getpid())
    process = own.process
    result["process_read"] = bool(process and process.user and process.integrity and process.cmdline and process.started)
    result["parents_read"] = bool(process and process.parents)
    result["modules_read"] = bool(process and process.modules_total > 0 and not process.modules_error)
    result["html_builds"] = own.name in report_html(own)

    from .ui import DetailWindow, make_app

    app = make_app(sys.argv)
    window = DetailWindow()
    window.show_report(own)
    app.processEvents()
    result["detail_buttons_follow_state"] = window.suspend_button.isEnabled() and not window.resume_button.isEnabled()
    if shots:
        window.grab().save(str(shots / "detail.png"))
    window.show_report(tampered)
    app.processEvents()
    result["file_only_has_no_stop_button"] = not window.suspend_button.isEnabled() and not window.terminate_button.isEnabled()
    if shots:
        window.grab().save(str(shots / "detail-tampered.png"))
    window.close()
    return result


class _OnlyPids:
    """検査用: 指定したプロセスだけが起動したように見せ、ほかのプログラムを止めない。"""

    def __init__(self):
        self.pids: list[int] = []

    def snapshot(self):
        return list(self.pids)


def _launch_check(work: Path) -> dict:
    """起動の検知→一時停止→終了を、自分で起動した検査用プロセスで確かめる。"""
    result: dict = {}
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(20)
    heartbeat = work / "heartbeat-launch.txt"
    launches = _OnlyPids()
    alerts: list = []
    engine = Engine(
        _NoSource(), WinInspector(), WinActions(), Store(work / "data-launch"), on_alert=alerts.append,
        launches=launches, launch_assess=lambda _facts, _zone: _force_high(None, None),
    )
    engine.poll_once()
    child = _spawn_child(server.getsockname()[1], heartbeat)
    peer = None
    try:
        peer, _ = server.accept()
        result["child_running"] = _wait_counter_change(heartbeat)
        launches.pids.append(child.pid)
        engine.poll_once()
        result["launch_is_stopped"] = bool(alerts) and alerts[0].action == "suspended" and alerts[0].conn is None
        time.sleep(0.4)
        before = _read_counter(heartbeat)
        time.sleep(1.0)
        result["stopped_while_suspended"] = _read_counter(heartbeat) == before
        if alerts:
            result["terminate_ok"] = engine.decide(alerts[0].id, TERMINATE)[0]
            child.wait(timeout=5)
            result["exited"] = child.poll() is not None
    finally:
        if peer is not None:
            peer.close()
        server.close()
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
    return result


def read_child(path: str, heartbeat_file: str) -> int:
    """検査用の無害な子プロセス。罠の偽物を1回読み、動いた証拠を書き続ける。"""
    with open(path, "rb") as handle:
        handle.read()
    count = 0
    deadline = time.time() + 60
    while time.time() < deadline:
        count += 1
        temp = heartbeat_file + ".tmp"
        with open(temp, "w", encoding="ascii") as handle:
            handle.write(str(count))
        os.replace(temp, heartbeat_file)
        time.sleep(0.05)
    return 0


SYSMON_REQUIRED_FIELDS = {1: ("Image", "CommandLine", "ParentImage", "ParentProcessId", "ProcessId"), 22: ("Image", "QueryName", "ProcessId")}


def sysmon_field_report(items: list[str], child_pid: int = 0) -> dict:
    """まもるんが使う項目が実際のイベントにあるかを調べる。内容は記録せず、有無だけを返す。"""
    from .sysmonrules import parse_event

    events = [parse_event(xml) for xml in items]
    parsed = [event for event in events if event is not None]
    ids = sorted({event.event_id for event in parsed})
    report: dict = {
        "events_read": len(items), "events_parse": len(parsed) == len(items) and bool(items), "event_ids": ids,
    }
    for event_id, fields in SYSMON_REQUIRED_FIELDS.items():
        found = [event for event in parsed if event.event_id == event_id]
        report[f"event_{event_id}_seen"] = bool(found)
        report[f"event_{event_id}_fields_ok"] = bool(found) and all(field in found[0].data for field in fields)
    report["own_child_found"] = any(event.event_id == 1 and event.pid == child_pid for event in parsed)
    return report


def run_sysmon_check(output: str) -> int:
    """Sysmon連携の実機検査。無害なコマンドと名前解決を1回ずつ行い、記録に載るかを確かめる。

    戻り値: 0=合格 / 1=不合格 / 2=管理者権限がない
    """
    from .eventlog import OK, SYSMON_CHANNEL, latest_record_id, read_events

    out_path = Path(output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report: dict = {"version": VERSION, "is_admin": is_admin()}
    code = 2
    if report["is_admin"]:
        status, latest = latest_record_id(SYSMON_CHANNEL)
        report["channel_status"] = status
        if status == OK:
            child = subprocess.Popen(["cmd.exe", "/c", "exit"], creationflags=subprocess.CREATE_NO_WINDOW)
            child.wait(timeout=10)
            try:
                socket.getaddrinfo("example.com", 443)
            except OSError:
                pass
            keys = (
                "events_parse", "event_1_seen", "event_1_fields_ok", "event_22_seen", "event_22_fields_ok",
                "own_child_found",
            )
            deadline = time.time() + 10
            while True:
                read_status, items = read_events(SYSMON_CHANNEL, latest)
                fields = sysmon_field_report(items, child.pid)
                if all(fields.get(key) is True for key in keys) or time.time() >= deadline:
                    break
                time.sleep(0.5)
            report.update(fields, read_status=read_status)
            report["passed"] = read_status == OK and all(fields.get(key) is True for key in keys)
        else:
            report["passed"] = False
        code = 0 if report["passed"] else 1
    else:
        report["passed"] = False
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return code


def run_startup_check(output: str) -> int:
    """起動時の登録の実機検査。検査用の名前で登録して、すぐ消す。プログラムは起動しない。"""
    from .startup import StartupTask, current_command

    out_path = Path(output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report: dict = {"version": VERSION, "is_admin": is_admin()}
    code = 2
    if report["is_admin"]:
        task = StartupTask("GuardianMascot-check")
        command, arguments = current_command()
        try:
            report["created"] = task.enable(command, arguments)
            report["found_after_create"] = task.is_enabled()
        finally:
            report["deleted"] = task.disable()
        report["gone_after_delete"] = not task.is_enabled()
        report["passed"] = all(report[key] for key in ("created", "found_after_create", "deleted", "gone_after_delete"))
        code = 0 if report["passed"] else 1
    else:
        report["passed"] = False
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return code


def run_bundle_check(output: str) -> int:
    """配布用EXEの検査。絵がEXEの中から読めることだけを確かめる。"""
    from .art import STATES, MascotArt, default_art_root
    from .characters import CHARACTERS
    from .ui import make_app

    make_app(sys.argv)
    root = default_art_root()
    images = {
        character: all(MascotArt(root / character).frames.get(state) for state in STATES) for character in CHARACTERS
    }
    report = {
        "version": VERSION, "frozen": bool(getattr(sys, "frozen", False)), "art_root": str(root), "images": images,
        "passed": all(images.values()),
    }
    out_path = Path(output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if report["passed"] else 1


def run_trap_check(output: str) -> int:
    """罠の実機検査。要管理者。作業フォルダの偽物だけを使い、監査の設定は最後に元へ戻す。"""
    from .traps import TrapManager, WinAuditBackend

    out_path = Path(output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report: dict = {"is_admin": is_admin()}
    if not report["is_admin"]:
        report["passed"] = False
        report["error"] = "管理者権限が必要です"
        out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return 2
    with tempfile.TemporaryDirectory(dir=out_path.parent, prefix="trapcheck-") as temp:
        work = Path(temp)
        store = Store(work / "data")
        backend = WinAuditBackend()
        policy_before = backend.read_policy()
        report["policy_readable"] = policy_before is not None
        specs = (("TRAPROOT", r"wallet\passphrase.json", "wallet"),)
        manager = TrapManager(store, backend, environ={"TRAPROOT": str(work / "bait")}, specs=specs)
        alerts: list = []
        engine = Engine(_NoSource(), WinInspector(), WinActions(), store, on_alert=alerts.append, traps=manager)
        child = None
        try:
            ok, message = manager.install()
            report["installed"] = ok
            report["message"] = message
            if not manager.entries:
                raise RuntimeError(message)  # 読ませる偽物がないので、ここで検査を終える
            bait = manager.entries[0]["path"]
            report["policy_enabled"] = bool((backend.read_policy() or 0) & backend.POLICY_SUCCESS)
            engine.poll_once()  # 今より新しいイベントだけを見るようにする
            report["security_log_readable"] = manager.status == "ok"
            heartbeat = work / "heartbeat.txt"
            if getattr(sys, "frozen", False):
                command = [sys.executable, "--test-read", bait, str(heartbeat)]
            else:
                command = [sys.executable, str(Path(__file__).resolve().parent.parent / "main.py"), "--test-read", bait, str(heartbeat)]
            child = subprocess.Popen(command, creationflags=subprocess.CREATE_NO_WINDOW)
            report["child_running"] = _wait_counter_change(heartbeat)
            deadline = time.time() + 15
            while time.time() < deadline and not alerts:
                engine.poll_once()
                time.sleep(0.2)
            report["hit_found"] = bool(alerts)
            report["hit_is_child"] = bool(alerts) and alerts[0].proc.pid == child.pid
            report["child_suspended"] = bool(alerts) and alerts[0].action == "suspended"
            time.sleep(0.4)
            before = _read_counter(heartbeat)
            time.sleep(1.0)
            report["stopped_while_suspended"] = _read_counter(heartbeat) == before
            if alerts:
                report["terminated"] = engine.decide(alerts[0].id, TERMINATE)[0]
        except Exception as exc:
            report["error"] = repr(exc)
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            removed, _message = manager.remove()
            report["removed"] = removed
            report["bait_deleted"] = not (work / "bait" / "wallet" / "passphrase.json").exists()
            # 本物の見張りに使う設定と解除を、作業フォルダのファイルで確かめる
            sample = work / "watch-sample.txt"
            sample.write_text("sample", encoding="ascii")
            content = sample.read_bytes()
            before_text = backend.sacl_text(str(sample))  # 監査の設定がないときは空の文字列
            report["real_sacl_empty_before"] = before_text is not None and "(" not in before_text
            report["real_sacl_set"] = backend.audit_file_reads(str(sample)) and "(" in (backend.sacl_text(str(sample)) or "")
            report["real_sacl_cleared"] = backend.clear_audit(str(sample)) and "(" not in (backend.sacl_text(str(sample)) or "(")
            report["real_content_unchanged"] = sample.read_bytes() == content
            report["policy_restored"] = backend.read_policy() == policy_before
    keys = (
        "policy_readable", "installed", "policy_enabled", "security_log_readable", "child_running", "hit_found",
        "hit_is_child", "child_suspended", "stopped_while_suspended", "terminated", "removed", "bait_deleted",
        "policy_restored", "real_sacl_empty_before", "real_sacl_set", "real_sacl_cleared", "real_content_unchanged",
    )
    report["passed"] = "error" not in report and all(report.get(key) is True for key in keys)
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if report["passed"] else 1


def _sysmon_check() -> dict:
    """イベントログの読み取りを確かめる。Sysmonが未導入でも、状態を正しく見分けられること。"""
    from .eventlog import DENIED, NOT_INSTALLED, NOT_READY, OK, SYSMON_CHANNEL, latest_record_id, read_events
    from .sysmonrules import parse_event

    result: dict = {}
    status, latest = latest_record_id("Application")
    result["reader_works"] = status == OK
    status, items = read_events("Application", max(0, latest - 3))
    result["events_parse"] = status == OK and all(parse_event(xml) is not None for xml in items)
    result["unknown_channel_found"] = latest_record_id("No-Such-Channel/Operational")[0] == NOT_INSTALLED
    channel_status = latest_record_id(SYSMON_CHANNEL)[0]
    result["sysmon_status_known"] = channel_status in (OK, NOT_INSTALLED, DENIED, NOT_READY)
    result["sysmon_status"] = channel_status
    from .winstatus import build_rows, read_status

    result["defense_rows_built"] = len(build_rows(read_status())) >= 1
    return result


def _all_true(value) -> bool:
    if isinstance(value, dict):
        return all(_all_true(v) for k, v in value.items() if k not in ("decision", "message", "alert_action"))
    if isinstance(value, bool):
        return value
    return True


def run(output: str, shots_dir: str | None = None) -> bool:
    report: dict = {"version": VERSION, "frozen": bool(getattr(sys, "frozen", False)), "is_admin": is_admin()}
    out_path = Path(output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out_path.parent, prefix="selfcheck-") as temp:
        work = Path(temp)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        conns = tcp_snapshot()
        listener.close()
        inspector = WinInspector()
        own = inspector.inspect(os.getpid())
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        report["api"] = {
            "tcp_table_read": len(conns) > 0,
            "own_listener_found": any(c.pid == os.getpid() and c.local_port == port and c.state == "LISTEN" for c in conns),
            "own_path_found": bool(own.path) and Path(own.path).exists(),
            "own_cmdline_found": bool(own.cmdline),
            "created_time_found": own.created > 0,
            "explorer_signature": signature_status(os.path.join(system_root, "explorer.exe")),
            "sha256_ok": len(inspector.file_hash(own.path) or "") == 64,
        }
        report["gate_probe"] = _gate_probe(work)
        report["resume_path"] = _pipeline_check(work, RESUME)
        report["terminate_path"] = _pipeline_check(work, TERMINATE)
        shots = Path(shots_dir).resolve() if shots_dir else None
        if shots:
            shots.mkdir(parents=True, exist_ok=True)
        report["ui"] = _ui_check(shots, work)
        report["controller"] = _controller_check(work)
        report["characters"] = _character_check(shots, work)
        report["inspect"] = _inspect_check(shots, work)
        report["launch"] = _launch_check(work)
        report["sysmon"] = _sysmon_check()
    pipeline_ok = all(
        report[name].get("alert_action") == "suspended" for name in ("resume_path", "terminate_path")
    )
    report["passed"] = bool(
        _all_true(report["api"]) and _all_true(report["gate_probe"]) and _all_true(report["resume_path"]) and _all_true(report["terminate_path"])
        and _all_true(report["ui"]) and _all_true(report["controller"]) and _all_true(report["characters"]) and _all_true(report["inspect"]) and _all_true(report["launch"]) and _all_true(report["sysmon"]) and pipeline_ok
    )
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report["passed"]
