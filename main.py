"""まもるん（Guardian Mascot）の起動口。"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def default_data_dir() -> Path:
    # 版の入れ替えや作り直しで消えないよう、プログラムのフォルダとは分けて保存する
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "GuardianMascot"


def scan_once(output: str, data_dir: Path) -> int:
    """現在の通信を1回だけ判定して書き出す。何も止めない。"""
    from guardian.engine import Engine, WinSource
    from guardian.store import Store
    from guardian.winapi import WinInspector

    store = Store(data_dir)
    engine = Engine(WinSource(), WinInspector(), None, store, observe=True)
    engine.poll_once()
    rows = sorted(engine.rows(), key=lambda r: -r["score"])
    alerts = [{
        "name": a.proc.name, "path": a.proc.path, "signature": a.proc.signature, "direction": a.direction,
        "score": a.assessment.score, "level": a.assessment.level,
        "reasons": [f"{r.points:+d} {r.text}" for r in a.assessment.reasons],
    } for a in engine.pending()]
    Path(output).write_text(
        json.dumps({"connections": len(rows), "alerts": alerts, "rows": rows}, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="まもるん: 通信を見張るデスクトップマスコット")
    parser.add_argument("--data-dir", help="設定と記録の保存先")
    parser.add_argument("--observe", action="store_true", help="観察モード（検知しても止めない）")
    parser.add_argument("--self-check", metavar="OUT.json", help="自己検査を実行して結果を書き出す")
    parser.add_argument("--shots-dir", help="自己検査の画面画像の保存先")
    parser.add_argument("--scan-once", metavar="OUT.json", help="今の通信を1回判定して書き出す（止めない）")
    parser.add_argument("--run-seconds", type=float, help="指定秒数後に自動終了（動作確認用）")
    parser.add_argument("--gate", action="store_true", help=argparse.SUPPRESS)  # 管理者権限なら既定で有効。古い起動方法のために残す
    parser.add_argument("--no-gate", action="store_true", help="送信前の遮断を使わない")
    parser.add_argument("--no-elevate", action="store_true", help="管理者権限を求めずに起動する")
    parser.add_argument("--no-watchdog", action="store_true", help="本体が止められたときの見張り役を使わない")
    parser.add_argument("--watchdog", type=int, metavar="PID", help=argparse.SUPPRESS)
    parser.add_argument("--watchdog-args", default="[]", help=argparse.SUPPRESS)
    parser.add_argument("--restarted", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--startup-check", metavar="OUT.json", help="起動時の登録の実機検査（管理者権限が必要。検査用の登録はすぐ消す）")
    parser.add_argument("--bundle-check", metavar="OUT.json", help="配布用EXEの中の絵を確かめる")
    parser.add_argument("--gate-check", metavar="OUT.json", help="送信前の遮断の実機検査（管理者権限が必要。検査用ポートだけを止める）")
    parser.add_argument("--trap-check", metavar="OUT.json", help="罠の実機検査（管理者権限が必要。作業フォルダの偽物だけを使い、監査の設定は元に戻す）")
    parser.add_argument("--sysmon-check", metavar="OUT.json", help="Sysmon連携の実機検査（管理者権限が必要。Sysmonの記録を読む）")
    parser.add_argument("--test-read", nargs=2, metavar=("PATH", "FILE"), help=argparse.SUPPRESS)
    parser.add_argument("--test-beacon", nargs=2, metavar=("PORT", "FILE"), help=argparse.SUPPRESS)
    parser.add_argument("--test-connect", type=int, metavar="PORT", help=argparse.SUPPRESS)
    parser.add_argument("--test-connect-host", metavar="HOST", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.watchdog:
        from guardian.watchdog import run_watchdog

        data_dir = Path(args.data_dir).resolve() if args.data_dir else default_data_dir()
        return run_watchdog(args.watchdog, data_dir, json.loads(args.watchdog_args))
    if args.test_read:
        from guardian.selfcheck import read_child

        return read_child(args.test_read[0], args.test_read[1])
    if args.startup_check:
        from guardian.selfcheck import run_startup_check

        return run_startup_check(args.startup_check)
    if args.bundle_check:
        from guardian.selfcheck import run_bundle_check

        return run_bundle_check(args.bundle_check)
    if args.sysmon_check:
        from guardian.selfcheck import run_sysmon_check

        return run_sysmon_check(args.sysmon_check)
    if args.trap_check:
        from guardian.selfcheck import run_trap_check

        return run_trap_check(args.trap_check)
    if args.test_beacon:
        from guardian.selfcheck import beacon_child

        return beacon_child(int(args.test_beacon[0]), args.test_beacon[1])
    if args.test_connect:
        from guardian.selfcheck import connect_child

        if args.test_connect_host:
            return connect_child(args.test_connect, args.test_connect_host, timeout=1.5)
        return connect_child(args.test_connect)
    if args.gate_check:
        from guardian.selfcheck import run_gate_check

        return run_gate_check(args.gate_check)
    if args.self_check:
        from guardian.selfcheck import run

        return 0 if run(args.self_check, args.shots_dir) else 1

    data_dir = Path(args.data_dir).resolve() if args.data_dir else default_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    if args.scan_once:
        return scan_once(args.scan_once, data_dir)

    # 配布用EXEはダブルクリックだけで管理者権限を求める。断られたら権限なしで続ける
    from guardian.winapi import is_admin, relaunch_elevated

    if getattr(sys, "frozen", False) and not args.no_elevate and not is_admin():
        if relaunch_elevated(sys.executable, subprocess.list2cmdline(sys.argv[1:])):
            return 0

    from PyQt6.QtCore import QLockFile, QTimer
    from PyQt6.QtWidgets import QApplication, QMessageBox

    from guardian.engine import Engine, WinSource
    from guardian.store import Store
    from guardian.ui import Controller, make_app
    from guardian.winapi import WinActions, WinInspector

    app = make_app(sys.argv)
    lock = QLockFile(str(data_dir / "running.lock"))
    if not lock.tryLock(100):
        if not args.restarted:  # 見張り役の起動し直しでは、すでに動いていれば何もしない
            QMessageBox.information(None, "まもるん", "まもるんはすでに起動しています。")
        return 0

    store = Store(data_dir)
    gate = None
    if args.gate and args.observe:
        QMessageBox.information(None, "まもるん", "観察モードでは送信前の遮断を使いません。")
    elif args.gate and not is_admin():
        QMessageBox.warning(None, "まもるん", "送信前の遮断には管理者権限が必要です。今回は遮断なしで見張ります。")
    elif is_admin() and not args.observe and not args.no_gate:
        from guardian.wfp import WfpGate

        gate = WfpGate(store.settings, store.save_settings)
    from guardian.eventlog import SysmonSource
    from guardian.proginfo import WinLaunchSource, zone_of
    from guardian.traps import TrapManager

    engine = Engine(
        WinSource(), WinInspector(), WinActions(), store, observe=args.observe, gate=gate,
        launches=WinLaunchSource(), zone_of=zone_of, sysmon=SysmonSource(),
        strict=store.settings.get("strict", True) is not False, traps=TrapManager(store),
    )
    from guardian.art import default_art_root

    controller = Controller(engine, default_art_root(), is_admin())
    app.aboutToQuit.connect(controller.shutdown)
    controller.start()
    if not args.no_watchdog:
        from guardian.watchdog import Guard

        controller.guard = Guard(data_dir, sys.argv[1:])
        controller.guard.start()
    controller.start_stop_watch()
    if args.restarted:
        controller.notify_restarted()
    if args.run_seconds:
        QTimer.singleShot(int(args.run_seconds * 1000), QApplication.quit)
    code = app.exec()
    if controller.guard is not None:
        from guardian.watchdog import mark_clean_exit

        mark_clean_exit(data_dir)
    lock.unlock()
    return code


if __name__ == "__main__":
    sys.exit(main())
