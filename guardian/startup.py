"""Windowsへのログオン時に、管理者権限で起動する設定（タスクスケジューラ）。

スタートアップフォルダや Run キーでは起動のたびに権限の確認が出るので使わない。
本人がメニューから選んだときだけ登録する。登録と解除には管理者権限が必要。
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable
from xml.sax.saxutils import escape

TASK_NAME = "GuardianMascot"
CREATE_NO_WINDOW = 0x08000000
LOGON_DELAY = "PT15S"  # デスクトップとトレイの準備を待つ


def default_user() -> str:
    domain, name = os.environ.get("USERDOMAIN", ""), os.environ.get("USERNAME", "")
    return f"{domain}\\{name}" if domain else name


def current_command() -> tuple[str, str]:
    """(実行するプログラム, 引数)。ソースから動かしているときは main.py を渡す。"""
    if getattr(sys, "frozen", False):
        return sys.executable, ""
    return sys.executable, subprocess.list2cmdline([str(Path(__file__).resolve().parent.parent / "main.py")])


def task_xml(command: str, arguments: str, user: str) -> str:
    """既定のままだと、バッテリー動作で起動せず、3日で強制終了されるので明示する。"""
    args = f"<Arguments>{escape(arguments)}</Arguments>" if arguments else ""
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<RegistrationInfo><Description>GuardianMascot: start at logon</Description></RegistrationInfo>"
        f"<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{escape(user)}</UserId><Delay>{LOGON_DELAY}</Delay></LogonTrigger></Triggers>"
        f'<Principals><Principal id="Author"><UserId>{escape(user)}</UserId><LogonType>InteractiveToken</LogonType>'
        "<RunLevel>HighestAvailable</RunLevel></Principal></Principals>"
        "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
        "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>"
        f'<Actions Context="Author"><Exec><Command>{escape(command)}</Command>{args}</Exec></Actions>'
        "</Task>"
    )


def _schtasks(arguments: list[str]) -> bool:
    try:
        result = subprocess.run(
            ["schtasks.exe", *arguments], capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


class StartupTask:
    def __init__(self, name: str = TASK_NAME, run: Callable[[list[str]], bool] = _schtasks):
        self.name = name
        self.run = run

    def is_enabled(self) -> bool:
        return self.run(["/query", "/tn", self.name])

    def enable(self, command: str | None = None, arguments: str | None = None, user: str | None = None) -> bool:
        if command is None:
            command, arguments = current_command()
        xml = task_xml(command, arguments or "", user or default_user())
        handle, path = tempfile.mkstemp(suffix=".xml", prefix="guardian-task-")
        os.close(handle)
        try:
            Path(path).write_text(xml, encoding="utf-16")
            return self.run(["/create", "/tn", self.name, "/xml", path, "/f"])
        except OSError:
            return False
        finally:
            try:
                os.remove(path)
            except OSError:
                pass

    def disable(self) -> bool:
        return self.run(["/delete", "/tn", self.name, "/f"])
