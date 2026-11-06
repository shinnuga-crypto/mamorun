"""プログラムの調査。対象を読むだけで、実行も通信もしない。"""
from __future__ import annotations

import configparser
import ctypes
import os
import threading
from ctypes import wintypes
from datetime import datetime, timezone
from typing import Callable

from . import winapi
from .models import Conn
from .pemeta import parse_pe_file
from .report import ModuleInfo, ProcessInfo, ProgramReport, build_notes
from .risk import classify_location, is_external
from .signinfo import VALID, filetime_to_datetime, read_signature

kernel32 = winapi.kernel32
advapi32 = winapi.advapi32
psapi = ctypes.WinDLL("psapi", use_last_error=True)
version_dll = ctypes.WinDLL("version", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 3
TOKEN_QUERY = 0x0008
TOKEN_ELEVATION = 20
TOKEN_INTEGRITY_LEVEL = 25
MAX_MODULES = 2048
MAX_CHECKED_MODULES = 200
MAX_PARENTS = 6
MAX_MOTW_BYTES = 8192
VERSION_KEYS = ("CompanyName", "ProductName", "FileDescription", "OriginalFilename", "InternalName", "FileVersion")
INTEGRITY = {0: "信頼なし", 4096: "低", 8192: "中", 8448: "中（プラス）", 12288: "高", 16384: "システム"}

psapi.EnumProcessModulesEx.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
]
psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
version_dll.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
version_dll.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
version_dll.VerQueryValueW.argtypes = [
    ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT),
]
advapi32.LookupAccountSidW.argtypes = [
    wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
]
advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]


def read_version(path: str) -> dict[str, str]:
    """VERSIONINFO を読む。データとして読むだけで、DLLのコードは実行されない。"""
    size = version_dll.GetFileVersionInfoSizeW(path, None)
    if not size:
        return {}
    buffer = ctypes.create_string_buffer(size)
    if not version_dll.GetFileVersionInfoW(path, 0, size, buffer):
        return {}
    pointer = ctypes.c_void_p()
    length = wintypes.UINT(0)
    codepages = []
    if version_dll.VerQueryValueW(buffer, r"\VarFileInfo\Translation", ctypes.byref(pointer), ctypes.byref(length)):
        count = length.value // 4
        words = ctypes.cast(pointer, ctypes.POINTER(wintypes.WORD))
        codepages = [f"{words[i * 2]:04x}{words[i * 2 + 1]:04x}" for i in range(min(count, 8))]
    codepages += ["041104b0", "040904b0", "040904e4"]
    result: dict[str, str] = {}
    for key in VERSION_KEYS:
        for codepage in codepages:
            if version_dll.VerQueryValueW(
                buffer, f"\\StringFileInfo\\{codepage}\\{key}", ctypes.byref(pointer), ctypes.byref(length),
            ) and length.value > 0:
                value = ctypes.wstring_at(pointer.value, length.value).split("\0", 1)[0].strip()
                if value:
                    result[key] = value
                    break
    return result


def read_motw(path: str) -> dict[str, str]:
    """Mark of the Web（Zone.Identifier）を読む。なければ空。"""
    try:
        with open(path + ":Zone.Identifier", "rb") as handle:
            raw = handle.read(MAX_MOTW_BYTES)
    except OSError:
        return {}
    text = None
    for encoding in ("utf-8-sig", "utf-16", "cp932"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeError:
            continue
    if text is None:
        return {}
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    try:
        parser.read_string(text)
    except configparser.Error:
        return {}
    if not parser.has_section("ZoneTransfer"):
        return {}
    return {key: value[:500] for key, value in parser.items("ZoneTransfer") if key in ("ZoneId", "HostUrl", "ReferrerUrl")}


def _token_info(pid: int) -> tuple[str, str, bool | None]:
    """(ユーザー名, 整合性レベル, 管理者権限か)。読めない項目は空。"""
    handle = winapi._open(pid, winapi.PROCESS_QUERY_LIMITED_INFORMATION)
    if not handle:
        return "", "", None
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token)):
            return "", "", None
        try:
            elevated: bool | None = None
            value = wintypes.DWORD(0)
            size = wintypes.DWORD(0)
            if advapi32.GetTokenInformation(token, TOKEN_ELEVATION, ctypes.byref(value), 4, ctypes.byref(size)):
                elevated = bool(value.value)
            integrity = ""
            advapi32.GetTokenInformation(token, TOKEN_INTEGRITY_LEVEL, None, 0, ctypes.byref(size))
            if size.value:
                buffer = ctypes.create_string_buffer(size.value)
                if advapi32.GetTokenInformation(token, TOKEN_INTEGRITY_LEVEL, buffer, size, ctypes.byref(size)):
                    sid = ctypes.c_void_p.from_buffer(buffer).value
                    text = wintypes.LPWSTR()
                    if advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
                        try:
                            rid = int(text.value.rsplit("-", 1)[-1])
                            integrity = INTEGRITY.get(rid, str(rid))
                        finally:
                            kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        finally:
            kernel32.CloseHandle(token)
    finally:
        kernel32.CloseHandle(handle)
    return _user_name(pid), integrity, elevated


def _user_name(pid: int) -> str:
    sid_text = winapi.process_user_sid(pid)
    if not sid_text:
        return ""
    sid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(sid_text, ctypes.byref(sid)):
        return sid_text
    try:
        name = ctypes.create_unicode_buffer(256)
        domain = ctypes.create_unicode_buffer(256)
        name_size, domain_size, use = wintypes.DWORD(256), wintypes.DWORD(256), wintypes.DWORD(0)
        if advapi32.LookupAccountSidW(
            None, sid, name, ctypes.byref(name_size), domain, ctypes.byref(domain_size), ctypes.byref(use),
        ):
            return f"{domain.value}\\{name.value}"
        return sid_text
    finally:
        kernel32.LocalFree(sid)


def _modules(pid: int) -> tuple[list[str], str]:
    handle = winapi._open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    if not handle:
        return [], f"アクセスできません（エラー {ctypes.get_last_error()}）"
    try:
        array = (wintypes.HMODULE * MAX_MODULES)()
        needed = wintypes.DWORD(0)
        if not psapi.EnumProcessModulesEx(handle, array, ctypes.sizeof(array), ctypes.byref(needed), LIST_MODULES_ALL):
            return [], f"一覧を取得できません（エラー {ctypes.get_last_error()}）"
        count = min(needed.value // ctypes.sizeof(wintypes.HMODULE), MAX_MODULES)
        paths = []
        buffer = ctypes.create_unicode_buffer(32768)
        for index in range(count):
            if psapi.GetModuleFileNameExW(handle, array[index], buffer, len(buffer)):
                paths.append(buffer.value)
        return paths, ""
    finally:
        kernel32.CloseHandle(handle)


def _parents(pid: int, table: dict[int, tuple[str, int]]) -> list[str]:
    chain: list[str] = []
    current = pid
    seen = {pid}
    child_created = winapi.process_created(pid)
    while len(chain) < MAX_PARENTS:
        entry = table.get(current)
        if entry is None or not entry[1] or entry[1] in seen:
            break
        parent = entry[1]
        seen.add(parent)
        parent_entry = table.get(parent)
        if parent_entry is None:
            chain.append(f"（終了済み: PID {parent}）")
            break
        parent_created = winapi.process_created(parent)
        # PIDが使い回された別プロセスを親と誤認しない
        if parent_created and child_created and parent_created > child_created:
            chain.append(f"（終了済み: PID {parent}）")
            break
        chain.append(parent_entry[0])
        current, child_created = parent, parent_created
    return chain


def _datetime_of(pid: int) -> datetime | None:
    created = winapi.process_created(pid)
    if not created:
        return None
    value = wintypes.FILETIME(created & 0xFFFFFFFF, created >> 32)
    return filetime_to_datetime(value)


class ProgramInspector:
    """調査結果の取得。ファイルごとの結果は内容が変わるまで使い回す。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._files: dict[tuple[str, int, int], ProgramReport] = {}
        self._module_signatures: dict[tuple[str, int, int], tuple[str, str]] = {}

    def inspect_file(self, path: str | None, name: str | None = None) -> ProgramReport:
        report = ProgramReport(path=path, name=name or (os.path.basename(path) if path else "不明"))
        if not path:
            report.notes = build_notes(report)
            return report
        try:
            stat = os.stat(path)
        except OSError:
            report.notes = build_notes(report)
            return report
        key = (path.lower(), stat.st_mtime_ns, stat.st_size)
        with self._lock:
            cached = self._files.get(key)
        if cached is not None:
            report = _copy_file_part(cached)
            report.notes = build_notes(report)
            return report
        report.exists = True
        report.size = stat.st_size
        report.modified = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
        report.created = datetime.fromtimestamp(stat.st_ctime, timezone.utc)
        report.sha256 = winapi.file_sha256(path) or ""
        report.signature = read_signature(path)
        report.version = read_version(path)
        report.motw = read_motw(path)
        report.pe = parse_pe_file(path)
        with self._lock:
            self._files[key] = report
        result = _copy_file_part(report)
        result.notes = build_notes(result)
        return result

    def inspect_process(self, pid: int, connections: list[Conn] | None = None, suspended: bool = False,
                        dns_hosts: list[str] | None = None) -> ProgramReport:
        path = winapi.process_path(pid)
        table = winapi.process_table()
        report = self.inspect_file(path, os.path.basename(path) if path else table.get(pid, (f"PID {pid}", 0))[0])
        user, integrity, elevated = _token_info(pid)
        process = ProcessInfo(
            pid=pid, started=_datetime_of(pid), user=user, integrity=integrity, elevated=elevated,
            cmdline=winapi.process_cmdline(pid) or "", parents=_parents(pid, table), suspended=suspended,
        )
        paths, error = _modules(pid)
        process.modules_error = error
        process.modules_total = len(paths)
        outside = [p for p in paths if classify_location(p) != "system" and (not path or p.lower() != path.lower())]
        for module in outside[:MAX_CHECKED_MODULES]:
            status, signer = self._module_signature(module)
            process.modules_outside.append(ModuleInfo(module, status, signer))
        process.connections = [_describe(conn) for conn in connections or []]
        process.dns_hosts = list(dns_hosts or [])
        report.process = process
        report.notes = build_notes(report)
        return report

    def _module_signature(self, path: str) -> tuple[str, str]:
        try:
            stat = os.stat(path)
        except OSError:
            return "error", ""
        key = (path.lower(), stat.st_mtime_ns, stat.st_size)
        with self._lock:
            cached = self._module_signatures.get(key)
        if cached is not None:
            return cached
        signature = read_signature(path)
        signer = signature.signer.subject if signature.signer else ""
        result = (signature.status, signer)
        with self._lock:
            self._module_signatures[key] = result
        return result


class WinLaunchSource:
    """起動の見張りに使う、動いているプロセスの一覧。"""

    def snapshot(self) -> list[int]:
        return list(winapi.process_table())


def zone_of(path: str | None) -> int | None:
    """Mark of the Web のゾーン番号。記録がなければ None。"""
    if not path:
        return None
    try:
        return int(read_motw(path).get("ZoneId", ""))
    except ValueError:
        return None


def _copy_file_part(source: ProgramReport) -> ProgramReport:
    return ProgramReport(
        path=source.path, name=source.name, exists=source.exists, size=source.size, modified=source.modified,
        created=source.created, sha256=source.sha256, signature=source.signature, version=source.version,
        motw=source.motw, pe=source.pe,
    )


def _describe(conn: Conn) -> str:
    place = "外部" if is_external(conn.remote_ip) else "内部"
    return f"{conn.remote_ip}:{conn.remote_port}（{place}、{conn.state}）"


__all__ = ["ProgramInspector", "read_motw", "read_version", "VALID"]
