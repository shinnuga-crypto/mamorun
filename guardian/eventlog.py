"""Windowsイベントログの読み取り（ctypes のみ）。書き込みも通信もしない。"""
from __future__ import annotations

import ctypes
from ctypes import wintypes

wevtapi = ctypes.WinDLL("wevtapi", use_last_error=True)

EVT_QUERY_CHANNEL_PATH = 0x1
EVT_QUERY_FORWARD_DIRECTION = 0x100
EVT_RENDER_EVENT_XML = 1
ERROR_ACCESS_DENIED = 5
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_MORE_ITEMS = 259
ERROR_WMI_INSTANCE_NOT_FOUND = 4201  # Windows組み込みのSysmonを導入した直後に、標準権限で確認
ERROR_EVT_CHANNEL_NOT_FOUND = 15007
BATCH = 64
CLEAR_CHECK_POLLS = 10

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
OK = "ok"
NOT_INSTALLED = "not_installed"
DENIED = "denied"
NOT_READY = "not_ready"
FAILED = "failed"

wevtapi.EvtQuery.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
wevtapi.EvtQuery.restype = wintypes.HANDLE
wevtapi.EvtNext.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
wevtapi.EvtNext.restype = wintypes.BOOL
wevtapi.EvtRender.argtypes = [
    wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
]
wevtapi.EvtRender.restype = wintypes.BOOL
wevtapi.EvtClose.argtypes = [wintypes.HANDLE]
wevtapi.EvtClose.restype = wintypes.BOOL


def _render(event) -> str | None:
    used, count = wintypes.DWORD(0), wintypes.DWORD(0)
    wevtapi.EvtRender(None, event, EVT_RENDER_EVENT_XML, 0, None, ctypes.byref(used), ctypes.byref(count))
    if ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER or not used.value:
        return None
    buffer = ctypes.create_string_buffer(used.value)
    if not wevtapi.EvtRender(None, event, EVT_RENDER_EVENT_XML, used, buffer, ctypes.byref(used), ctypes.byref(count)):
        return None
    return ctypes.wstring_at(buffer)


def _status_of(error: int) -> str:
    if error == ERROR_EVT_CHANNEL_NOT_FOUND:
        return NOT_INSTALLED
    if error == ERROR_ACCESS_DENIED:
        return DENIED
    if error == ERROR_WMI_INSTANCE_NOT_FOUND:
        return NOT_READY
    return FAILED


def read_events(channel: str, after_record: int = 0, limit: int = 2048, xpath: str | None = None) -> tuple[str, list[str]]:
    """after_record より新しいイベントのXMLを古い順に返す。(状態, XMLの一覧)"""
    query = xpath or (f"*[System[EventRecordID>{int(after_record)}]]" if after_record else "*")
    handle = wevtapi.EvtQuery(None, channel, query, EVT_QUERY_CHANNEL_PATH | EVT_QUERY_FORWARD_DIRECTION)
    if not handle:
        return _status_of(ctypes.get_last_error()), []
    results: list[str] = []
    try:
        events = (wintypes.HANDLE * BATCH)()
        returned = wintypes.DWORD(0)
        while len(results) < limit:
            if not wevtapi.EvtNext(handle, BATCH, events, 0, 0, ctypes.byref(returned)):
                error = ctypes.get_last_error()
                if error != ERROR_NO_MORE_ITEMS:
                    return _status_of(error), results
                break
            for index in range(returned.value):
                try:
                    xml = _render(events[index])
                    if xml:
                        results.append(xml)
                finally:
                    wevtapi.EvtClose(events[index])
    finally:
        wevtapi.EvtClose(handle)
    return OK, results


def latest_record_id(channel: str) -> tuple[str, int]:
    """今ある最新のレコード番号。起動より前のイベントを判定しないために使う。"""
    handle = wevtapi.EvtQuery(None, channel, "*", EVT_QUERY_CHANNEL_PATH | 0x200)  # 0x200 = 新しい順
    if not handle:
        return _status_of(ctypes.get_last_error()), 0
    try:
        events = (wintypes.HANDLE * 1)()
        returned = wintypes.DWORD(0)
        if not wevtapi.EvtNext(handle, 1, events, 0, 0, ctypes.byref(returned)):
            error = ctypes.get_last_error()
            return (OK, 0) if error == ERROR_NO_MORE_ITEMS else (_status_of(error), 0)
        try:
            xml = _render(events[0]) or ""
        finally:
            wevtapi.EvtClose(events[0])
    finally:
        wevtapi.EvtClose(handle)
    start, end = xml.find("<EventRecordID>"), xml.find("</EventRecordID>")
    try:
        return OK, int(xml[start + len("<EventRecordID>"):end]) if start >= 0 else 0
    except ValueError:
        return OK, 0


class SysmonSource:
    """エンジンへ、前回より新しいSysmonのイベントを渡す。"""

    def __init__(self, channel: str = SYSMON_CHANNEL):
        self.channel = channel
        self.status = FAILED
        self.cleared = False  # 記録が消された形跡。エンジンが読んだら戻す
        self._last_record: int | None = None
        self._retry_after = 0
        self._polls = 0

    def poll(self) -> list[str]:
        self._polls += 1
        # マルウェアが痕跡を消すと番号が巻き戻るので、ときどき最新の番号と比べる
        if self._last_record and self._polls % CLEAR_CHECK_POLLS == 0:
            status, latest = latest_record_id(self.channel)
            if status == OK and latest < self._last_record:
                self.cleared = True
                self._last_record = latest
        if self._last_record is None:
            # 導入前や起動前のものは判定しない。未導入なら数十回に一度だけ確かめ直す
            if self._retry_after > 0:
                self._retry_after -= 1
                return []
            self.status, latest = latest_record_id(self.channel)
            if self.status != OK:
                self._retry_after = 60
                return []
            self._last_record = latest
            return []
        self.status, items = read_events(self.channel, self._last_record)
        if items:
            from .sysmonrules import parse_event

            for xml in reversed(items):
                event = parse_event(xml)
                if event is not None:
                    self._last_record = max(self._last_record, event.record_id)
                    break
        return items
