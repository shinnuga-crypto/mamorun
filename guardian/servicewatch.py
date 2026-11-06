"""Sysmonのサービスとドライバーが止められていないかの確認。読み取りだけで、権限は要らない。"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import Callable

RUNNING = "running"
STOPPED = "stopped"
MISSING = "missing"
UNKNOWN = "unknown"
SYSMON_SERVICES = ("Sysmon64", "Sysmon", "Sysmon64a")
SYSMON_DRIVER = "SysmonDrv"
SEEN_KEY = "sysmon_was_running"

_SC_MANAGER_CONNECT = 0x1
_SERVICE_QUERY_STATUS = 0x4
_ERROR_SERVICE_DOES_NOT_EXIST = 1060
_RUNNING_STATES = {2, 4, 5}  # 開始中、実行中、再開中


class _ServiceStatus(ctypes.Structure):
    _fields_ = [
        ("type", wintypes.DWORD), ("state", wintypes.DWORD), ("controls", wintypes.DWORD),
        ("exit_code", wintypes.DWORD), ("service_exit_code", wintypes.DWORD),
        ("checkpoint", wintypes.DWORD), ("wait_hint", wintypes.DWORD),
    ]


def service_state(name: str) -> str:
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    api.OpenSCManagerW.restype = wintypes.HANDLE
    api.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    api.OpenServiceW.restype = wintypes.HANDLE
    api.QueryServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ServiceStatus)]
    api.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    manager = api.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
    if not manager:
        return UNKNOWN
    try:
        service = api.OpenServiceW(manager, name, _SERVICE_QUERY_STATUS)
        if not service:
            return MISSING if ctypes.get_last_error() == _ERROR_SERVICE_DOES_NOT_EXIST else UNKNOWN
        try:
            status = _ServiceStatus()
            if not api.QueryServiceStatus(service, ctypes.byref(status)):
                return UNKNOWN
            return RUNNING if status.state in _RUNNING_STATES else STOPPED
        finally:
            api.CloseServiceHandle(service)
    finally:
        api.CloseServiceHandle(manager)


class SysmonWatch:
    """一度でも動いていたSysmonが止まったら知らせる。未導入のPCでは何も言わない。

    動いていた記録は保存するので、まもるんが止まっている間に消された場合も次の起動で分かる。
    """

    def __init__(self, store, query: Callable[[str], str] = service_state):
        self.store = store
        self.query = query
        self.down = False

    def _state(self) -> str:
        states = [self.query(name) for name in SYSMON_SERVICES]
        if RUNNING in states:
            # サービスが動いていても、ドライバーを外されると記録は止まる
            return STOPPED if self.query(SYSMON_DRIVER) in (STOPPED, MISSING) else RUNNING
        if STOPPED in states:
            return STOPPED
        return MISSING if all(state == MISSING for state in states) else UNKNOWN

    def check(self) -> str | None:
        """変化があったときだけ "stopped" か "recovered" を返す。"""
        state = self._state()
        if state == UNKNOWN:
            return None
        seen = self.store.settings.get(SEEN_KEY) is True
        if state == RUNNING:
            if not seen:
                self.store.settings[SEEN_KEY] = True
                self.store.save_settings()
            if self.down:
                self.down = False
                return "recovered"
            return None
        if seen:
            self.store.settings[SEEN_KEY] = False  # 1回だけ知らせる。動き出したらまた見張る
            self.store.save_settings()
            self.down = True
            return "stopped"
        return None
