"""Windows Filtering Platform による送信前の遮断（ctypes のみ、ドライバなし）。

仕組み:
- ログオン中ユーザーのプログラムが外部へ接続するのを、接続を許可する段階（ALE_AUTH_CONNECT）で止める。
- ループバック、LAN などの非グローバル宛先、確認済みアプリは許可フィルターで通す。
- 止めた接続は遮断イベントとして受け取り、エンジンが判定して許可を追加するか、止めたまま確認する。

ユーザーモードのWFPでは接続を「保留」できないため、初めてのアプリの最初の接続は失敗する。
動的セッションなので、このプロセスが異常終了してもフィルターはWindowsが自動で取り除く。
Windowsのサービスとカーネルの通信は、フィルターの対象ユーザーに含めないので止めない。
"""
from __future__ import annotations

import collections
import ctypes
import ipaddress
import os
import time
import uuid
from ctypes import wintypes
from typing import Callable, Iterable

from .models import BlockedConnect
from .winapi import GUID, process_table, process_user_sid

_fw = ctypes.WinDLL("fwpuclnt")
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


def make_guid(text: str) -> GUID:
    value = uuid.UUID(text)
    return GUID(value.time_low, value.time_mid, value.time_hi_version, (ctypes.c_ubyte * 8)(*value.bytes[8:]))


# --- 定数（fwpmu.h / fwptypes.h）
RPC_C_AUTHN_WINNT = 10
FWPM_SESSION_FLAG_DYNAMIC = 0x1
FWPM_ENGINE_COLLECT_NET_EVENTS = 0
FWP_UINT8 = 1
FWP_UINT16 = 2
FWP_UINT32 = 3
FWP_BYTE_BLOB_TYPE = 12
FWP_SECURITY_DESCRIPTOR_TYPE = 14
FWP_V4_ADDR_MASK = 0x100
FWP_V6_ADDR_MASK = 0x101
FWP_MATCH_EQUAL = 0
FWP_MATCH_FLAGS_ALL_SET = 6
FWP_ACTION_BLOCK = 0x1001
FWP_ACTION_PERMIT = 0x1002
FWP_CONDITION_FLAG_IS_LOOPBACK = 0x1
FWP_IP_VERSION_V4 = 0
FWP_IP_VERSION_V6 = 1
FWPM_NET_EVENT_TYPE_CLASSIFY_DROP = 3
FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET = 0x4
FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET = 0x10
FWPM_NET_EVENT_FLAG_APP_ID_SET = 0x20
SDDL_REVISION_1 = 1
ERROR_ACCESS_DENIED = 5

LAYER_CONNECT_V4 = make_guid("c38d57d1-05a7-4c33-904f-7fbceee60e82")
LAYER_CONNECT_V6 = make_guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4")
COND_APP_ID = make_guid("d78e1e87-8644-4ea5-9437-d809ecefc971")
COND_USER_ID = make_guid("af043a0a-b34d-4f86-979c-c90371af6e66")
COND_REMOTE_ADDRESS = make_guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045")
COND_REMOTE_PORT = make_guid("c35a604d-d22b-4e1a-91b4-68f674ee674b")
COND_FLAGS = make_guid("632ce23b-5167-435c-86d7-e903684aa80c")

WEIGHT_BLOCK = 1
WEIGHT_PERMIT_APP = 10
WEIGHT_REVOKE_APP = 12  # アプリの許可より強く、PC内とLANの許可より弱い
WEIGHT_PERMIT_LOCAL = 14
SUBLAYER_WEIGHT = 0xFFFF
SETTING_COLLECT_ORIGINAL = "wfp_collect_original"
QUEUE_LIMIT = 2048

# risk.is_external が外部と見なさない宛先。エンジンの判定対象と揃える。
LOCAL_NETWORKS_V4 = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
))
LOCAL_NETWORKS_V6 = tuple(ipaddress.ip_network(n) for n in (
    "::/128", "::1/128", "fe80::/10", "fc00::/7", "ff00::/8", "2001:db8::/32",
))


# --- 構造体
class FWP_BYTE_BLOB(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.c_void_p)]


class _ValueUnion(ctypes.Union):
    _fields_ = [
        ("uint8", ctypes.c_uint8), ("uint16", ctypes.c_uint16), ("uint32", ctypes.c_uint32),
        ("uint64", ctypes.c_uint64), ("pointer", ctypes.c_void_p),
    ]


class FWP_VALUE0(ctypes.Structure):
    """FWP_CONDITION_VALUE0 も同じ配置なので兼用する。"""

    _fields_ = [("type", ctypes.c_int), ("value", _ValueUnion)]


class FWP_V4_ADDR_AND_MASK(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint32), ("mask", ctypes.c_uint32)]


class FWP_V6_ADDR_AND_MASK(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_ubyte * 16), ("prefixLength", ctypes.c_uint8)]


class FWPM_DISPLAY_DATA0(ctypes.Structure):
    _fields_ = [("name", wintypes.LPWSTR), ("description", wintypes.LPWSTR)]


class FWPM_ACTION0(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32), ("filterType", GUID)]


class FWPM_FILTER_CONDITION0(ctypes.Structure):
    _fields_ = [("fieldKey", GUID), ("matchType", ctypes.c_int), ("conditionValue", FWP_VALUE0)]


class _FilterContext(ctypes.Union):
    _fields_ = [("rawContext", ctypes.c_uint64), ("providerContextKey", GUID)]


class FWPM_FILTER0(ctypes.Structure):
    _fields_ = [
        ("filterKey", GUID), ("displayData", FWPM_DISPLAY_DATA0), ("flags", ctypes.c_uint32),
        ("providerKey", ctypes.c_void_p), ("providerData", FWP_BYTE_BLOB), ("layerKey", GUID),
        ("subLayerKey", GUID), ("weight", FWP_VALUE0), ("numFilterConditions", ctypes.c_uint32),
        ("filterCondition", ctypes.POINTER(FWPM_FILTER_CONDITION0)), ("action", FWPM_ACTION0),
        ("context", _FilterContext), ("reserved", ctypes.c_void_p), ("filterId", ctypes.c_uint64),
        ("effectiveWeight", FWP_VALUE0),
    ]


class FWPM_SESSION0(ctypes.Structure):
    _fields_ = [
        ("sessionKey", GUID), ("displayData", FWPM_DISPLAY_DATA0), ("flags", ctypes.c_uint32),
        ("txnWaitTimeoutInMSec", ctypes.c_uint32), ("processId", ctypes.c_uint32),
        ("sid", ctypes.c_void_p), ("username", wintypes.LPWSTR), ("kernelMode", wintypes.BOOL),
    ]


class FWPM_SUBLAYER0(ctypes.Structure):
    _fields_ = [
        ("subLayerKey", GUID), ("displayData", FWPM_DISPLAY_DATA0), ("flags", ctypes.c_uint32),
        ("providerKey", ctypes.c_void_p), ("providerData", FWP_BYTE_BLOB), ("weight", ctypes.c_uint16),
    ]


class _Addr(ctypes.Union):
    _fields_ = [("v4", ctypes.c_uint32), ("v6", ctypes.c_ubyte * 16)]


class _HeaderReserved(ctypes.Structure):
    _fields_ = [
        ("reserved2", ctypes.c_ubyte * 6), ("reserved3", ctypes.c_ubyte * 6),
        ("reserved4", ctypes.c_uint32), ("reserved5", ctypes.c_uint32), ("reserved6", ctypes.c_uint16),
        ("reserved7", ctypes.c_uint32), ("reserved8", ctypes.c_uint32), ("reserved9", ctypes.c_uint16),
        ("reserved10", ctypes.c_uint64),
    ]


class FWPM_NET_EVENT_HEADER1(ctypes.Structure):
    _fields_ = [
        ("timeStamp", wintypes.FILETIME), ("flags", ctypes.c_uint32), ("ipVersion", ctypes.c_int),
        ("ipProtocol", ctypes.c_uint8), ("local", _Addr), ("remote", _Addr),
        ("localPort", ctypes.c_uint16), ("remotePort", ctypes.c_uint16), ("scopeId", ctypes.c_uint32),
        ("appId", FWP_BYTE_BLOB), ("userId", ctypes.c_void_p),
        ("reserved1", ctypes.c_int), ("reservedBlock", _HeaderReserved),
    ]


class FWPM_NET_EVENT_CLASSIFY_DROP1(ctypes.Structure):
    _fields_ = [
        ("filterId", ctypes.c_uint64), ("layerId", ctypes.c_uint16), ("reauthReason", ctypes.c_uint32),
        ("originalProfile", ctypes.c_uint32), ("currentProfile", ctypes.c_uint32),
        ("msFwpDirection", ctypes.c_uint32), ("isLoopback", wintypes.BOOL),
    ]


class FWPM_NET_EVENT1(ctypes.Structure):
    _fields_ = [
        ("header", FWPM_NET_EVENT_HEADER1), ("type", ctypes.c_int),
        ("classifyDrop", ctypes.POINTER(FWPM_NET_EVENT_CLASSIFY_DROP1)),
    ]


class FWPM_NET_EVENT_SUBSCRIPTION0(ctypes.Structure):
    _fields_ = [("enumTemplate", ctypes.c_void_p), ("flags", ctypes.c_uint32), ("sessionKey", GUID)]


NET_EVENT_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)

_DW = wintypes.DWORD
_H = wintypes.HANDLE
_fw.FwpmEngineOpen0.argtypes = [wintypes.LPCWSTR, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(FWPM_SESSION0), ctypes.POINTER(_H)]
_fw.FwpmEngineOpen0.restype = _DW
_fw.FwpmEngineClose0.argtypes = [_H]
_fw.FwpmEngineClose0.restype = _DW
_fw.FwpmEngineGetOption0.argtypes = [_H, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(FWP_VALUE0))]
_fw.FwpmEngineGetOption0.restype = _DW
_fw.FwpmEngineSetOption0.argtypes = [_H, ctypes.c_int, ctypes.POINTER(FWP_VALUE0)]
_fw.FwpmEngineSetOption0.restype = _DW
_fw.FwpmFreeMemory0.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
_fw.FwpmFreeMemory0.restype = None
_fw.FwpmTransactionBegin0.argtypes = [_H, ctypes.c_uint32]
_fw.FwpmTransactionBegin0.restype = _DW
_fw.FwpmTransactionCommit0.argtypes = [_H]
_fw.FwpmTransactionCommit0.restype = _DW
_fw.FwpmTransactionAbort0.argtypes = [_H]
_fw.FwpmTransactionAbort0.restype = _DW
_fw.FwpmSubLayerAdd0.argtypes = [_H, ctypes.POINTER(FWPM_SUBLAYER0), ctypes.c_void_p]
_fw.FwpmSubLayerAdd0.restype = _DW
_fw.FwpmFilterAdd0.argtypes = [_H, ctypes.POINTER(FWPM_FILTER0), ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
_fw.FwpmFilterAdd0.restype = _DW
_fw.FwpmFilterDeleteById0.argtypes = [_H, ctypes.c_uint64]
_fw.FwpmFilterDeleteById0.restype = _DW
_fw.FwpmGetAppIdFromFileName0.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.POINTER(FWP_BYTE_BLOB))]
_fw.FwpmGetAppIdFromFileName0.restype = _DW
_fw.FwpmNetEventSubscribe0.argtypes = [_H, ctypes.POINTER(FWPM_NET_EVENT_SUBSCRIPTION0), NET_EVENT_CALLBACK, ctypes.c_void_p, ctypes.POINTER(_H)]
_fw.FwpmNetEventSubscribe0.restype = _DW
_fw.FwpmNetEventUnsubscribe0.argtypes = [_H, _H]
_fw.FwpmNetEventUnsubscribe0.restype = _DW
_advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG),
]
_advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
_kernel32.LocalFree.restype = ctypes.c_void_p
_kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
_kernel32.ProcessIdToSessionId.restype = wintypes.BOOL


class WfpError(OSError):
    def __init__(self, what: str, code: int):
        super().__init__(code, f"{what}: 0x{code & 0xFFFFFFFF:08X}")
        self.code = code & 0xFFFFFFFF


def _check(code: int, what: str) -> None:
    if code != 0:
        raise WfpError(what, code)


# --- 補助
def app_id_from_path(path: str) -> str | None:
    """実行ファイルのパスをWFPのアプリID（\\device\\harddiskvolumeN\\... 小文字）に変換する。"""
    blob = ctypes.POINTER(FWP_BYTE_BLOB)()
    if _fw.FwpmGetAppIdFromFileName0(path, ctypes.byref(blob)) != 0:
        return None
    try:
        return _read_app_id(blob.contents)
    finally:
        holder = ctypes.c_void_p(ctypes.cast(blob, ctypes.c_void_p).value)
        _fw.FwpmFreeMemory0(ctypes.byref(holder))


def _read_app_id(blob: FWP_BYTE_BLOB) -> str:
    if not blob.data or not blob.size:
        return ""
    return ctypes.wstring_at(blob.data, blob.size // 2).rstrip("\0")


def sddl_for_users(sids: Iterable[str]) -> str:
    """指定ユーザーだけに一致する条件。AccessCheck の仕様で所有者とグループも必要。"""
    aces = "".join(f"(A;;CC;;;{sid})" for sid in dict.fromkeys(sids))
    return f"O:SYG:SYD:{aces}"


def security_descriptor_bytes(sddl: str) -> bytes:
    pointer = ctypes.c_void_p()
    size = wintypes.ULONG(0)
    if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, ctypes.byref(pointer), ctypes.byref(size),
    ):
        raise WfpError("セキュリティ記述子の作成", ctypes.get_last_error())
    try:
        return ctypes.string_at(pointer, size.value)
    finally:
        _kernel32.LocalFree(pointer)


def interactive_user_sids() -> list[str]:
    """このプロセスのユーザーと、同じWindowsセッションのエクスプローラーのユーザーのSID。

    別の管理者アカウントで昇格して起動した場合も、ログオン中のユーザーのプログラムを対象にするため。
    """
    sids: list[str] = []
    own = process_user_sid(os.getpid())
    if own:
        sids.append(own)
    session = wintypes.DWORD()
    if not _kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
        return sids
    for pid, (name, _parent) in process_table().items():
        if name.lower() != "explorer.exe":
            continue
        other = wintypes.DWORD()
        if _kernel32.ProcessIdToSessionId(pid, ctypes.byref(other)) and other.value == session.value:
            sid = process_user_sid(pid)
            if sid and sid not in sids:
                sids.append(sid)
    return sids


def parse_net_event(event: FWPM_NET_EVENT1, filter_ids: set[int], now: float) -> BlockedConnect | None:
    """遮断イベントのうち、自分のフィルターが止めたものだけを取り出す。"""
    if event.type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP or not event.classifyDrop:
        return None
    if event.classifyDrop.contents.filterId not in filter_ids:
        return None
    header = event.header
    if not header.flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET:
        return None
    if header.ipVersion == FWP_IP_VERSION_V4:
        remote = str(ipaddress.IPv4Address(header.remote.v4))
    elif header.ipVersion == FWP_IP_VERSION_V6:
        remote = str(ipaddress.IPv6Address(bytes(header.remote.v6)))
    else:
        return None
    app_id = _read_app_id(header.appId) if header.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET else ""
    port = header.remotePort if header.flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET else 0
    return BlockedConnect(app_id, remote, port, header.ipProtocol, now)


class _Condition:
    """フィルター条件1つ。ポインターの参照先が消えないよう一緒に持つ。"""

    def __init__(self, key: GUID, match: int, value_type: int, *, uint=None, target=None):
        self.keep = target
        self.key, self.match, self.value_type, self.uint = key, match, value_type, uint

    def fill(self, out: FWPM_FILTER_CONDITION0) -> None:
        out.fieldKey = self.key
        out.matchType = self.match
        out.conditionValue.type = self.value_type
        if self.keep is not None:
            out.conditionValue.value.pointer = ctypes.addressof(self.keep)
        elif self.value_type == FWP_UINT16:
            out.conditionValue.value.uint16 = self.uint
        else:
            out.conditionValue.value.uint32 = self.uint


def _blob_condition(key: GUID, value_type: int, data: bytes) -> _Condition:
    buffer = ctypes.create_string_buffer(data, len(data))
    blob = FWP_BYTE_BLOB(len(data), ctypes.addressof(buffer))
    condition = _Condition(key, FWP_MATCH_EQUAL, value_type, target=blob)
    condition.buffer = buffer
    return condition


def cond_app(app_id: str) -> _Condition:
    return _blob_condition(COND_APP_ID, FWP_BYTE_BLOB_TYPE, app_id.encode("utf-16-le") + b"\0\0")


def cond_users(descriptor: bytes) -> _Condition:
    return _blob_condition(COND_USER_ID, FWP_SECURITY_DESCRIPTOR_TYPE, descriptor)


def cond_loopback() -> _Condition:
    return _Condition(COND_FLAGS, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT32, uint=FWP_CONDITION_FLAG_IS_LOOPBACK)


def cond_port(port: int) -> _Condition:
    return _Condition(COND_REMOTE_PORT, FWP_MATCH_EQUAL, FWP_UINT16, uint=port)


def cond_network(network) -> _Condition:
    if network.version == 4:
        target = FWP_V4_ADDR_AND_MASK(int(network.network_address), int(network.netmask))
        return _Condition(COND_REMOTE_ADDRESS, FWP_MATCH_EQUAL, FWP_V4_ADDR_MASK, target=target)
    target = FWP_V6_ADDR_AND_MASK((ctypes.c_ubyte * 16)(*network.network_address.packed), network.prefixlen)
    return _Condition(COND_REMOTE_ADDRESS, FWP_MATCH_EQUAL, FWP_V6_ADDR_MASK, target=target)


class _Session:
    """動的セッション1つ。閉じると（異常終了でも）中身はWindowsが取り除く。"""

    def __init__(self, name: str):
        session = FWPM_SESSION0()
        session.displayData.name = name
        session.flags = FWPM_SESSION_FLAG_DYNAMIC
        handle = _H()
        _check(_fw.FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, ctypes.byref(session), ctypes.byref(handle)), "FwpmEngineOpen0")
        self.handle = handle
        self.name = name
        self.sublayer = make_guid(str(uuid.uuid4()))
        self._events = None
        self._callback = None

    def collect_events(self) -> int:
        value = ctypes.POINTER(FWP_VALUE0)()
        _check(_fw.FwpmEngineGetOption0(self.handle, FWPM_ENGINE_COLLECT_NET_EVENTS, ctypes.byref(value)), "FwpmEngineGetOption0")
        try:
            return value.contents.value.uint32
        finally:
            holder = ctypes.c_void_p(ctypes.cast(value, ctypes.c_void_p).value)
            _fw.FwpmFreeMemory0(ctypes.byref(holder))

    def set_collect_events(self, enabled: int) -> None:
        value = FWP_VALUE0()
        value.type = FWP_UINT32
        value.value.uint32 = enabled
        _check(_fw.FwpmEngineSetOption0(self.handle, FWPM_ENGINE_COLLECT_NET_EVENTS, ctypes.byref(value)), "FwpmEngineSetOption0")

    def subscribe(self, handler: Callable[[FWPM_NET_EVENT1], None]) -> None:
        def callback(_context, pointer):
            try:
                handler(ctypes.cast(pointer, ctypes.POINTER(FWPM_NET_EVENT1)).contents)
            except Exception:  # Windowsのスレッドへ例外を返さない
                pass

        self._callback = NET_EVENT_CALLBACK(callback)
        subscription = FWPM_NET_EVENT_SUBSCRIPTION0()
        events = _H()
        _check(_fw.FwpmNetEventSubscribe0(self.handle, ctypes.byref(subscription), self._callback, None, ctypes.byref(events)), "FwpmNetEventSubscribe0")
        self._events = events

    def begin(self) -> None:
        _check(_fw.FwpmTransactionBegin0(self.handle, 0), "FwpmTransactionBegin0")

    def commit(self) -> None:
        _check(_fw.FwpmTransactionCommit0(self.handle), "FwpmTransactionCommit0")

    def abort(self) -> None:
        _fw.FwpmTransactionAbort0(self.handle)

    def add_sublayer(self) -> None:
        sublayer = FWPM_SUBLAYER0()
        sublayer.subLayerKey = self.sublayer
        sublayer.displayData.name = self.name
        sublayer.weight = SUBLAYER_WEIGHT
        _check(_fw.FwpmSubLayerAdd0(self.handle, ctypes.byref(sublayer), None), "FwpmSubLayerAdd0")

    def add_filter(self, layer: GUID, action: int, weight: int, conditions: list[_Condition]) -> int:
        array = (FWPM_FILTER_CONDITION0 * len(conditions))()
        for out, condition in zip(array, conditions):
            condition.fill(out)
        item = FWPM_FILTER0()
        item.displayData.name = self.name
        item.layerKey = layer
        item.subLayerKey = self.sublayer
        item.weight.type = FWP_UINT8
        item.weight.value.uint8 = weight
        item.numFilterConditions = len(conditions)
        item.filterCondition = array
        item.action.type = action
        filter_id = ctypes.c_uint64(0)
        _check(_fw.FwpmFilterAdd0(self.handle, ctypes.byref(item), None, ctypes.byref(filter_id)), "FwpmFilterAdd0")
        return filter_id.value

    def delete_filter(self, filter_id: int) -> None:
        _check(_fw.FwpmFilterDeleteById0(self.handle, filter_id), "FwpmFilterDeleteById0")

    def close(self) -> None:
        if self._events is not None:
            _fw.FwpmNetEventUnsubscribe0(self.handle, self._events)
            self._events = None
        if self.handle:
            _fw.FwpmEngineClose0(self.handle)
            self.handle = None


class _EventCollection:
    """遮断イベントの収集をオンにし、元の設定へ戻すための記録。

    この設定はWindows全体で再起動後も残る。異常終了に備えて元の値を settings に保存し、
    次回の正常な解除で戻す。
    """

    def __init__(self, settings: dict | None, save: Callable[[], None] | None):
        self.settings = settings if settings is not None else {}
        self.save = save or (lambda: None)

    def turn_on(self, session: _Session) -> None:
        current = session.collect_events()
        if current == 1:
            return
        if SETTING_COLLECT_ORIGINAL not in self.settings:
            self.settings[SETTING_COLLECT_ORIGINAL] = current
            self.save()
        session.set_collect_events(1)

    def restore(self, session: _Session) -> None:
        original = self.settings.get(SETTING_COLLECT_ORIGINAL)
        if original is None:
            return
        session.set_collect_events(original)
        del self.settings[SETTING_COLLECT_ORIGINAL]
        self.save()


class WfpGate:
    """engine.py が使う遮断の本体。engine.py からはこの公開メソッドだけを呼ぶ。"""

    def __init__(self, settings: dict | None = None, save_settings: Callable[[], None] | None = None,
                 clock: Callable[[], float] = time.time):
        self._collection = _EventCollection(settings, save_settings)
        self._clock = clock
        self._session: _Session | None = None
        self._block_ids: set[int] = set()
        self._permitted: set[str] = set()
        self._revoked: dict[str, list[int]] = {}
        self._queue: collections.deque[BlockedConnect] = collections.deque(maxlen=QUEUE_LIMIT)
        self.last_error = ""

    @property
    def active(self) -> bool:
        return self._session is not None

    def enable(self, known_paths: Iterable[str], extra_app_ids: Iterable[str] = ()) -> bool:
        """遮断を始める。途中で失敗したら何も残さず False を返す（通信は止まらない）。"""
        if self.active:
            return True
        session = None
        try:
            session = _Session("GuardianMascot")
            self._collection.turn_on(session)
            # 通知を受ける準備ができるまで遮断しない。通知なしの遮断は理由不明の通信障害になる。
            session.subscribe(self._on_event)
            descriptor = security_descriptor_bytes(sddl_for_users(interactive_user_sids()))
            app_ids = set(extra_app_ids)
            for path in known_paths:
                app_id = app_id_from_path(path)
                if app_id:
                    app_ids.add(app_id)
            session.begin()
            try:
                session.add_sublayer()
                for layer, networks in ((LAYER_CONNECT_V4, LOCAL_NETWORKS_V4), (LAYER_CONNECT_V6, LOCAL_NETWORKS_V6)):
                    session.add_filter(layer, FWP_ACTION_PERMIT, WEIGHT_PERMIT_LOCAL, [cond_loopback()])
                    for network in networks:
                        session.add_filter(layer, FWP_ACTION_PERMIT, WEIGHT_PERMIT_LOCAL, [cond_network(network)])
                    for app_id in app_ids:
                        session.add_filter(layer, FWP_ACTION_PERMIT, WEIGHT_PERMIT_APP, [cond_app(app_id)])
                    self._block_ids.add(
                        session.add_filter(layer, FWP_ACTION_BLOCK, WEIGHT_BLOCK, [cond_users(descriptor)]),
                    )
                session.commit()
            except Exception:
                session.abort()
                raise
        except Exception as exc:
            self.last_error = str(exc)
            self._block_ids.clear()
            if session is not None:
                self._close(session)
            return False
        self._session = session
        self._permitted = app_ids
        self.last_error = ""
        return True

    def disable(self) -> None:
        session, self._session = self._session, None
        self._block_ids.clear()
        self._permitted = set()
        self._revoked = {}
        if session is not None:
            self._close(session)

    def revoke(self, path: str | None) -> str | None:
        """動いているプログラムを止めずに、外部への新しい接続だけを封じる。アプリIDを返す。"""
        session = self._session
        app_id = app_id_from_path(path) if path else None
        if session is None or not app_id:
            return None
        if app_id in self._revoked:
            return app_id
        try:
            session.begin()
            try:
                ids = [
                    session.add_filter(layer, FWP_ACTION_BLOCK, WEIGHT_REVOKE_APP, [cond_app(app_id)])
                    for layer in (LAYER_CONNECT_V4, LAYER_CONNECT_V6)
                ]
                session.commit()
            except Exception:
                session.abort()
                raise
        except OSError as exc:
            self.last_error = str(exc)
            return None
        self._revoked[app_id] = ids
        self._block_ids.update(ids)
        return app_id

    def _close(self, session: _Session) -> None:
        try:
            self._collection.restore(session)
        except OSError as exc:
            self.last_error = str(exc)
        session.close()

    def permit(self, app_id: str) -> bool:
        """このアプリの外部接続を、遮断を解除するまで許可する。"""
        session = self._session
        if session is None or not app_id:
            return False
        revoked = self._revoked.get(app_id)
        if revoked:
            try:
                for filter_id in revoked:
                    session.delete_filter(filter_id)
            except OSError as exc:
                self.last_error = str(exc)
                return False
            del self._revoked[app_id]
            self._block_ids.difference_update(revoked)
        if app_id in self._permitted:
            return True
        try:
            session.begin()
            try:
                for layer in (LAYER_CONNECT_V4, LAYER_CONNECT_V6):
                    session.add_filter(layer, FWP_ACTION_PERMIT, WEIGHT_PERMIT_APP, [cond_app(app_id)])
                session.commit()
            except Exception:
                session.abort()
                raise
        except OSError as exc:
            self.last_error = str(exc)
            return False
        self._permitted.add(app_id)
        return True

    def drain(self) -> list[BlockedConnect]:
        events = []
        while True:
            try:
                events.append(self._queue.popleft())
            except IndexError:
                return events

    def _on_event(self, event: FWPM_NET_EVENT1) -> None:
        blocked = parse_net_event(event, self._block_ids, self._clock())
        if blocked is not None:
            self._queue.append(blocked)


class NarrowBlockCheck:
    """自己検査用。指定アプリから指定ポートへの接続だけを止める。ほかの通信には触れない。"""

    def __init__(self, app_id: str, port: int):
        self.app_id = app_id
        self.port = port
        self.events: list[BlockedConnect] = []
        self.block_ids: set[int] = set()
        self._collection = _EventCollection(None, None)
        self._session = _Session("GuardianMascot self-check")
        try:
            self._collection.turn_on(self._session)
            self._session.subscribe(self._on_event)
            self._session.add_sublayer()
        except Exception:
            self.close()
            raise

    def _conditions(self) -> list[_Condition]:
        return [cond_app(self.app_id), cond_port(self.port)]

    def block(self) -> None:
        descriptor = security_descriptor_bytes(sddl_for_users(interactive_user_sids()))
        conditions = [*self._conditions(), cond_users(descriptor)]
        self.block_ids.add(self._session.add_filter(LAYER_CONNECT_V4, FWP_ACTION_BLOCK, WEIGHT_BLOCK, conditions))

    def permit(self) -> None:
        self._session.add_filter(LAYER_CONNECT_V4, FWP_ACTION_PERMIT, WEIGHT_PERMIT_APP, self._conditions())

    def _on_event(self, event: FWPM_NET_EVENT1) -> None:
        blocked = parse_net_event(event, self.block_ids, time.time())
        if blocked is not None:
            self.events.append(blocked)

    def close(self) -> None:
        session, self._session = self._session, None
        if session is None:
            return
        try:
            self._collection.restore(session)
        finally:
            session.close()
