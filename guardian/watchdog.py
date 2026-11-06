"""まもるん本体の見張り役。本体が自分の停止に気づくことはできないので、別のプロセスで見る。

本体が正常に終了すると印のファイルを残す。印がないまま本体が消えたら、起動し直して知らせる。
管理者権限を持つマルウェアなら、両方を同時に止められる。そのときは検知できない。
"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

from .store import Store

CLEAN_EXIT_FILE = "clean_exit"
RESTART_LOG_FILE = "restarts.json"
RESTART_LIMIT = 3
RESTART_WINDOW = 300.0
RESTARTED_FLAG = "--restarted"
_SYNCHRONIZE = 0x00100000
_WAIT_TIMEOUT = 0x102
_SM_SHUTTINGDOWN = 0x2000
_CREATE_NO_WINDOW = 0x08000000
_MB_ICONWARNING_TOPMOST = 0x00000030 | 0x00040000

RESTART = "restart"
GIVE_UP = "give_up"
NOTHING = "nothing"


def self_command(arguments: list[str]) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, *arguments]
    return [sys.executable, str(Path(__file__).resolve().parent.parent / "main.py"), *arguments]


def decide(clean_exit: bool, shutting_down: bool, restart_allowed: bool) -> str:
    if clean_exit or shutting_down:
        return NOTHING
    return RESTART if restart_allowed else GIVE_UP


def allow_restart(path: Path, now: float) -> bool:
    """短い間に止まり続けるなら、起動し直しを繰り返さない。"""
    try:
        times = [t for t in json.loads(path.read_text(encoding="ascii")) if isinstance(t, (int, float))]
    except (OSError, ValueError, TypeError):
        times = []
    times = [t for t in times if now - t < RESTART_WINDOW]
    if len(times) >= RESTART_LIMIT:
        return False
    times.append(now)
    try:
        path.write_text(json.dumps(times), encoding="ascii")
    except OSError:
        pass
    return True


def restart_arguments(arguments: list[str]) -> list[str]:
    """権限の確認を出さない。管理者で動いていた本体の見張り役なら、権限はそのまま引き継がれる。"""
    result = [a for a in arguments if a not in (RESTARTED_FLAG, "--no-elevate")]
    return [*result, "--no-elevate", RESTARTED_FLAG]


def mark_clean_exit(data_dir: Path) -> None:
    try:
        (data_dir / CLEAN_EXIT_FILE).write_text("ok", encoding="ascii")
    except OSError:
        pass


class Guard:
    """本体から見た見張り役。見張り役が止められていないかも確かめる。"""

    def __init__(self, data_dir: Path, arguments: list[str]):
        self.data_dir = data_dir
        self.arguments = arguments
        self.process: subprocess.Popen | None = None

    def start(self) -> None:
        try:
            (self.data_dir / CLEAN_EXIT_FILE).unlink(missing_ok=True)
        except OSError:
            pass
        command = self_command([
            "--watchdog", str(os.getpid()), "--data-dir", str(self.data_dir),
            "--watchdog-args", json.dumps(self.arguments),
        ])
        self.process = subprocess.Popen(command, creationflags=_CREATE_NO_WINDOW)

    def restart_if_stopped(self) -> bool:
        """見張り役が止まっていたら起動し直して True を返す。"""
        if self.process is None or self.process.poll() is None:
            return False
        self.start()
        return True


def run_watchdog(parent_pid: int, data_dir: Path, arguments: list[str]) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    handle = kernel32.OpenProcess(_SYNCHRONIZE, False, parent_pid)
    if handle:
        while kernel32.WaitForSingleObject(handle, 1000) == _WAIT_TIMEOUT:
            pass
        kernel32.CloseHandle(handle)
    marker = data_dir / CLEAN_EXIT_FILE
    clean = marker.exists()
    if clean:
        try:
            marker.unlink()
        except OSError:
            pass
    shutting_down = bool(ctypes.WinDLL("user32").GetSystemMetrics(_SM_SHUTTINGDOWN))
    action = decide(clean, shutting_down, clean or shutting_down or allow_restart(data_dir / RESTART_LOG_FILE, time.time()))
    if action == NOTHING:
        return 0
    Store(data_dir).log({"event": "self_stopped", "action": action, "pid": parent_pid})
    if action == RESTART:
        subprocess.Popen(self_command(restart_arguments(arguments)), creationflags=_CREATE_NO_WINDOW)
    else:
        ctypes.WinDLL("user32").MessageBoxW(
            None,
            "まもるんが止まり続けているので、起動し直しをやめました。今は見張っていません。\n"
            "心当たりがなければ、不審なプログラムに止められている可能性があります。",
            "まもるん", _MB_ICONWARNING_TOPMOST,
        )
    return 0
