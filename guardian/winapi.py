"""Windows API の薄いラッパー（ctypes のみ）。ネットワーク通信は行わない。"""
from __future__ import annotations

import ctypes
import hashlib
import os
import socket
import struct
from ctypes import wintypes

from .models import Conn, ProcFacts

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
wintrust = ctypes.WinDLL("wintrust")
shell32 = ctypes.WinDLL("shell32")
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

AF_INET = 2
AF_INET6 = 23
TCP_TABLE_OWNER_PID_ALL = 5
ERROR_INSUFFICIENT_BUFFER = 122
NO_ERROR = 0
MIB_TCP_STATE_DELETE_TCB = 12
STATE_NAMES = {
    3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
    6: "CLOSING", 7: "CLOSING", 8: "CLOSING", 9: "CLOSING", 10: "CLOSING",
}
_ZERO_ADDRESSES = {"0.0.0.0", "::"}


def state_name(raw_state: int, remote_ip: str, remote_port: int) -> str:
    """接続状態を名前に変換する。

    Windowsのビルドによっては、待ち受けが 0、通信中の接続が 2 で返ることがある
    （Windows 11 26300 で確認）。そのため状態の値だけでなく相手の有無でも判断する。
    """
    no_remote = remote_ip in _ZERO_ADDRESSES and remote_port == 0
    if raw_state in (0, 2):
        return "LISTEN" if no_remote else "UNKNOWN"
    return STATE_NAMES.get(raw_state, "OTHER")


PROCESS_TERMINATE = 0x0001
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
PROCESS_COMMAND_LINE_INFORMATION = 60
PROCESS_NAME_NATIVE = 1
TOKEN_QUERY = 0x0008
TOKEN_USER_CLASS = 1

advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
]
advapi32.GetTokenInformation.restype = wintypes.BOOL
advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.LocalFree.restype = ctypes.c_void_p
kernel32.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
kernel32.QueryDosDeviceW.restype = wintypes.DWORD

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
]
kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

iphlpapi.GetExtendedTcpTable.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
    wintypes.ULONG, ctypes.c_int, wintypes.ULONG,
]
iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD

ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]
ntdll.NtSuspendProcess.restype = wintypes.LONG
ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
ntdll.NtResumeProcess.restype = wintypes.LONG
ntdll.NtQueryInformationProcess.argtypes = [
    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG),
]
ntdll.NtQueryInformationProcess.restype = wintypes.LONG


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("state", wintypes.DWORD), ("local_addr", wintypes.DWORD), ("local_port", wintypes.DWORD),
        ("remote_addr", wintypes.DWORD), ("remote_port", wintypes.DWORD), ("pid", wintypes.DWORD),
    ]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("local_addr", ctypes.c_ubyte * 16), ("local_scope", wintypes.DWORD), ("local_port", wintypes.DWORD),
        ("remote_addr", ctypes.c_ubyte * 16), ("remote_scope", wintypes.DWORD), ("remote_port", wintypes.DWORD),
        ("state", wintypes.DWORD), ("pid", wintypes.DWORD),
    ]


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [
        ("state", wintypes.DWORD), ("local_addr", wintypes.DWORD), ("local_port", wintypes.DWORD),
        ("remote_addr", wintypes.DWORD), ("remote_port", wintypes.DWORD),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG), ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", ctypes.c_void_p)]


class GUID(ctypes.Structure):
    _fields_ = [("a", wintypes.DWORD), ("b", wintypes.WORD), ("c", wintypes.WORD), ("d", ctypes.c_ubyte * 8)]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
wintrust.WinVerifyTrust.restype = wintypes.LONG

_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_REVOCATION_CHECK_NONE = 0x10
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000
_INVALID_SIGNATURE = {
    0x80096010,  # TRUST_E_BAD_DIGEST
    0x80096004,  # TRUST_E_CERT_SIGNATURE
    0x800B0111,  # TRUST_E_EXPLICIT_DISTRUST
    0x800B010C,  # CERT_E_REVOKED
}


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


def relaunch_elevated(executable: str, arguments: str) -> bool:
    """管理者権限で起動し直す。Windowsの確認で断られたら False。"""
    shell32.ShellExecuteW.argtypes = [
        wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int,
    ]
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    return (shell32.ShellExecuteW(None, "runas", executable, arguments, None, 1) or 0) > 32


def _read_table(family: int) -> ctypes.Array | None:
    size = wintypes.DWORD(0)
    for _ in range(4):
        buffer = ctypes.create_string_buffer(size.value or 4096)
        size.value = len(buffer)
        result = iphlpapi.GetExtendedTcpTable(buffer, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_ALL, 0)
        if result == NO_ERROR:
            return buffer
        if result != ERROR_INSUFFICIENT_BUFFER:
            raise OSError(result, f"GetExtendedTcpTable failed: {result}")
    return None


def tcp_snapshot() -> list[Conn]:
    """現在のTCP接続（IPv4 / IPv6）を返す。"""
    conns: list[Conn] = []
    buffer = _read_table(AF_INET)
    if buffer is not None:
        count = struct.unpack_from("<I", buffer, 0)[0]
        rows = ctypes.cast(ctypes.byref(buffer, 4), ctypes.POINTER(MIB_TCPROW_OWNER_PID * count)).contents
        for row in rows:
            remote_ip = socket.inet_ntoa(struct.pack("<I", row.remote_addr))
            remote_port = socket.ntohs(row.remote_port & 0xFFFF)
            conns.append(Conn(
                socket.inet_ntoa(struct.pack("<I", row.local_addr)), socket.ntohs(row.local_port & 0xFFFF),
                remote_ip, remote_port, state_name(row.state, remote_ip, remote_port), row.pid,
            ))
    buffer = _read_table(AF_INET6)
    if buffer is not None:
        count = struct.unpack_from("<I", buffer, 0)[0]
        rows6 = ctypes.cast(ctypes.byref(buffer, 4), ctypes.POINTER(MIB_TCP6ROW_OWNER_PID * count)).contents
        for row in rows6:
            remote_ip = socket.inet_ntop(socket.AF_INET6, bytes(row.remote_addr))
            remote_port = socket.ntohs(row.remote_port & 0xFFFF)
            conns.append(Conn(
                socket.inet_ntop(socket.AF_INET6, bytes(row.local_addr)), socket.ntohs(row.local_port & 0xFFFF),
                remote_ip, remote_port, state_name(row.state, remote_ip, remote_port), row.pid,
            ))
    return conns


def process_table() -> dict[int, tuple[str, int]]:
    """{pid: (実行ファイル名, 親pid)} を返す。"""
    table: dict[int, tuple[str, int]] = {}
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE or not snapshot:
        return table
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            table[entry.th32ProcessID] = (entry.szExeFile, entry.th32ParentProcessID)
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return table


def _open(pid: int, access: int):
    return kernel32.OpenProcess(access, False, pid) or None


def process_created(pid: int) -> int | None:
    """プロセス作成時刻。PIDの使い回しを見分けるために使う。"""
    handle = _open(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    if not handle:
        return None
    try:
        created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
        if not kernel32.GetProcessTimes(handle, created, exited, kernel, user):
            return None
        return (created.dwHighDateTime << 32) | created.dwLowDateTime
    finally:
        kernel32.CloseHandle(handle)


def process_path(pid: int) -> str | None:
    handle = _open(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value
        return None
    finally:
        kernel32.CloseHandle(handle)


def process_native_path(pid: int) -> str | None:
    """\\Device\\HarddiskVolumeN\\... 形式のパス。WFPのアプリIDと比べるために使う。"""
    handle = _open(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if kernel32.QueryFullProcessImageNameW(handle, PROCESS_NAME_NATIVE, buffer, ctypes.byref(size)):
            return buffer.value
        return None
    finally:
        kernel32.CloseHandle(handle)


def device_path_to_dos(path: str) -> str | None:
    """\\device\\harddiskvolumeN\\a.exe を C:\\a.exe に変換する。対応するドライブがなければ None。"""
    lowered = path.lower()
    buffer = ctypes.create_unicode_buffer(1024)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:"
        if not kernel32.QueryDosDeviceW(drive, buffer, len(buffer)):
            continue
        device = buffer.value.lower() + "\\"
        if lowered.startswith(device):
            return drive + path[len(device) - 1:]
    return None


def process_user_sid(pid: int) -> str | None:
    """プロセスを動かしているユーザーのSID文字列。"""
    handle = _open(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    if not handle:
        return None
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token)):
            return None
        try:
            size = wintypes.DWORD(0)
            advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, None, 0, ctypes.byref(size))
            if not size.value:
                return None
            buffer = ctypes.create_string_buffer(size.value)
            if not advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, buffer, size, ctypes.byref(size)):
                return None
            # TOKEN_USER の先頭は SID へのポインター
            sid = ctypes.c_void_p.from_buffer(buffer).value
            text = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
                return None
            try:
                return text.value
            finally:
                kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        finally:
            kernel32.CloseHandle(token)
    finally:
        kernel32.CloseHandle(handle)


def process_cmdline(pid: int) -> str | None:
    handle = _open(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    if not handle:
        return None
    try:
        needed = wintypes.ULONG(0)
        ntdll.NtQueryInformationProcess(handle, PROCESS_COMMAND_LINE_INFORMATION, None, 0, ctypes.byref(needed))
        if not needed.value:
            return None
        buffer = ctypes.create_string_buffer(needed.value)
        status = ntdll.NtQueryInformationProcess(
            handle, PROCESS_COMMAND_LINE_INFORMATION, buffer, needed, ctypes.byref(needed),
        )
        if status != 0:
            return None
        text = UNICODE_STRING.from_buffer(buffer)
        if not text.Buffer or not text.Length:
            return None
        return ctypes.wstring_at(text.Buffer, text.Length // 2)
    finally:
        kernel32.CloseHandle(handle)


def signature_status(path: str | None) -> str:
    """Authenticode署名を確認する。失効確認のためのネットワーク通信はしない。"""
    if not path or not os.path.exists(path):
        return "unknown"
    info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = WTD_UI_NONE
    data.fdwRevocationChecks = WTD_REVOKE_NONE
    data.dwUnionChoice = WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(info)
    data.dwStateAction = WTD_STATEACTION_VERIFY
    data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
    result = wintrust.WinVerifyTrust(None, ctypes.byref(_VERIFY_V2), ctypes.byref(data))
    data.dwStateAction = WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(_VERIFY_V2), ctypes.byref(data))
    code = result & 0xFFFFFFFF
    if code == 0:
        return "valid"
    if code in _INVALID_SIGNATURE:
        return "invalid"
    return "unsigned"


def file_sha256(path: str | None) -> str | None:
    if not path:
        return None
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


# 開発ツールが実行するシェルの符号化した引数は、難読化として扱わない。署名者の組織まで確かめる
DEV_TOOL_SIGNERS = {"claude.exe": "Anthropic, PBC", "codex.exe": "OpenAI OpCo, LLC", "chatgpt.exe": "OpenAI OpCo, LLC"}
DEV_TOOL_CHILD_SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe"}
DEV_TOOL_MAX_DEPTH = 4


def is_dev_tool_signer(name: str, organization: str) -> bool:
    return DEV_TOOL_SIGNERS.get(name.lower()) == organization


class WinInspector:
    """engine.py が使うプロセス情報の取得元。"""

    def __init__(self):
        self._signatures: dict[tuple[str, int, int], str] = {}
        self._hashes: dict[tuple[str, int, int], str | None] = {}
        self._dev_tools: dict[tuple[str, int, int], bool] = {}

    @staticmethod
    def _file_key(path: str) -> tuple[str, int, int] | None:
        try:
            stat = os.stat(path)
        except OSError:
            return None
        return (path.lower(), stat.st_mtime_ns, stat.st_size)

    def created(self, pid: int) -> int:
        return process_created(pid) or 0

    def inspect(self, pid: int) -> ProcFacts:
        table = process_table()
        name, parent_pid = table.get(pid, (f"PID {pid}", 0))
        path = process_path(pid)
        if path:
            name = os.path.basename(path)
        created = self.created(pid)
        parent_name = None
        if parent_pid and parent_pid in table:
            parent_created = process_created(parent_pid)
            # 親のPIDが別プロセスに使い回されていないことを確かめる
            if not (parent_created and created and parent_created > created):
                parent_name = table[parent_pid][0]
        return ProcFacts(
            pid=pid, created=created, name=name, path=path, parent_name=parent_name,
            cmdline=process_cmdline(pid), signature=self._signature(path),
            dev_tool=self._dev_tool_ancestor(name, parent_pid, created, table),
        )

    def _dev_tool_ancestor(self, name: str, parent_pid: int, created: int, table: dict) -> str | None:
        """シェルの起動元をたどり、署名を確かめた開発ツールならその名前を返す。"""
        if name.lower() not in DEV_TOOL_CHILD_SHELLS:
            return None
        current, younger = parent_pid, created
        for _ in range(DEV_TOOL_MAX_DEPTH):
            if current not in table:
                return None
            ancestor_created = process_created(current)
            if not ancestor_created or (younger and ancestor_created > younger):
                return None  # PIDが別のプロセスに使い回されている
            ancestor = table[current][0].lower()
            if ancestor in DEV_TOOL_SIGNERS:
                return self.dev_tool_of_image(process_path(current))
            if ancestor not in DEV_TOOL_CHILD_SHELLS:
                return None
            current, younger = table[current][1], ancestor_created
        return None

    def dev_tool_of_image(self, path: str | None) -> str | None:
        """名前だけでは偽装できるので、有効な署名と署名者の組織まで確かめる。"""
        if not path:
            return None
        name = os.path.basename(path).lower()
        expected = DEV_TOOL_SIGNERS.get(name)
        key = self._file_key(path)
        if expected is None or key is None:
            return None
        if key not in self._dev_tools:
            from .signinfo import read_signature

            info = read_signature(path)
            organization = info.chain[0].organization if info.chain else ""
            self._dev_tools[key] = info.status == "valid" and is_dev_tool_signer(name, organization)
        return name if self._dev_tools[key] else None

    def inspect_image(self, app_id: str) -> ProcFacts:
        """WFPのアプリIDから、そのプログラムの情報を返す。

        遮断イベントにPIDは含まれない。動いている中で最も新しいプロセスを選び、
        すでに終了していれば pid=0 でファイルの情報だけを返す。
        """
        newest_pid, newest_created = 0, -1
        for pid in process_table():
            native = process_native_path(pid) if pid else None
            if native and native.lower() == app_id.lower():
                created = self.created(pid)
                if created > newest_created:
                    newest_pid, newest_created = pid, created
        if newest_pid:
            return self.inspect(newest_pid)
        path = device_path_to_dos(app_id)
        name = app_id.rsplit("\\", 1)[-1]
        return ProcFacts(pid=0, created=0, name=name, path=path, signature=self._signature(path))

    def signature_of(self, path: str | None) -> str:
        return self._signature(path)

    def _signature(self, path: str | None) -> str:
        if not path:
            return "unknown"
        key = self._file_key(path)
        if key is None:
            return "unknown"
        if key not in self._signatures:
            self._signatures[key] = signature_status(path)
        return self._signatures[key]

    def file_hash(self, path: str | None) -> str | None:
        if not path:
            return None
        key = self._file_key(path)
        if key is None:
            return None
        if key not in self._hashes:
            self._hashes[key] = file_sha256(path)
        return self._hashes[key]


class WinActions:
    """プロセスへの操作。engine.py の保護リストを通った後に呼ばれる。"""

    @staticmethod
    def _nt_call(pid: int, function) -> bool:
        handle = _open(pid, PROCESS_SUSPEND_RESUME)
        if not handle:
            return False
        try:
            return function(handle) == 0
        finally:
            kernel32.CloseHandle(handle)

    def suspend(self, pid: int) -> bool:
        return self._nt_call(pid, ntdll.NtSuspendProcess)

    def resume(self, pid: int) -> bool:
        return self._nt_call(pid, ntdll.NtResumeProcess)

    def terminate(self, pid: int) -> bool:
        handle = _open(pid, PROCESS_TERMINATE)
        if not handle:
            return False
        try:
            return bool(kernel32.TerminateProcess(handle, 1))
        finally:
            kernel32.CloseHandle(handle)

    def disconnect(self, conn: Conn) -> bool:
        """IPv4のTCP接続を切断する。管理者権限が必要で、IPv6は対応するAPIがない。"""
        if ":" in conn.remote_ip or conn.state == "LISTEN":
            return False
        row = MIB_TCPROW(
            MIB_TCP_STATE_DELETE_TCB,
            struct.unpack("<I", socket.inet_aton(conn.local_ip))[0], socket.htons(conn.local_port),
            struct.unpack("<I", socket.inet_aton(conn.remote_ip))[0], socket.htons(conn.remote_port),
        )
        return iphlpapi.SetTcpEntry(ctypes.byref(row)) == 0
