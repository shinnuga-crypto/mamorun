"""罠のファイル。情報窃取マルウェアが探す場所に偽物を置き、読まれたら知らせる。

実在のファイルには触らない。置いたものは一覧に残し、一覧にあるものだけを消す。
読み取りの検知はファイルの監査（SACL）とセキュリティログのイベント4663を使うので、管理者権限が必要。
"""
from __future__ import annotations

import ctypes
import glob
import os
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import Callable

from . import eventlog
from .eventlog import OK, latest_record_id, read_events
from .risk import classify_location
from .sysmonrules import SysmonEvent, parse_event

SECURITY_CHANNEL = "Security"
OBJECT_ACCESS_EVENT = 4663
FILE_READ_DATA = 0x1
DECOY_NOTE = "This is a decoy file placed by GuardianMascot. Nothing here is real.\n"
# ウイルス対策、検索、同期のように、中身を見ずに全ファイルを読むもの。正規の場所か署名があるときだけ除外する
BENIGN_READERS = {
    "msmpeng.exe", "mpdefendercoreservice.exe", "nissrv.exe", "searchindexer.exe", "searchprotocolhost.exe",
    "searchfilterhost.exe", "onedrive.exe", "explorer.exe", "system",
}


def _decoy_text(kind: str) -> str:
    if kind == "wallet":
        return DECOY_NOTE + '{"seed": "decoy decoy decoy decoy decoy decoy decoy decoy decoy decoy decoy decoy"}\n'
    if kind == "key":
        return DECOY_NOTE + "decoy-private-key-material\n"
    return DECOY_NOTE + "bank.example.invalid  user: decoy  password: Decoy-Not-Real-1\n"


# (基準の環境変数, 相対パス, 種類)
# どのアプリも開かない名前にする。本物のアプリの標準の場所に置くと、そのアプリを壊す恐れがある
TRAP_SPECS = (
    ("USERPROFILE", r"Documents\wallet_seed_backup.txt", "wallet"),
    ("USERPROFILE", r"Documents\passwords_old.txt", "password"),
    ("USERPROFILE", r".ssh\old_server_key.txt", "key"),
    ("USERPROFILE", r".aws\credentials_old.txt", "key"),
)

_BROWSER_FILES = ("Local State", r"Default\Login Data", r"Default\Network\Cookies", r"Profile *\Login Data", r"Profile *\Network\Cookies")
_SSH_READERS = ("ssh.exe", "ssh-add.exe", "ssh-agent.exe", "ssh-keygen.exe", "scp.exe", "sftp.exe")
# 本物の認証ファイルの場所と、読むのが正常なプログラム。(基準の環境変数, パターン, 所有者)
WATCH_SPECS = tuple(
    ("LOCALAPPDATA", rf"{folder}\User Data\{item}", owners)
    for folder, owners in (
        (r"Google\Chrome", ("chrome.exe", "elevation_service.exe")),
        (r"Microsoft\Edge", ("msedge.exe", "elevation_service.exe", "msedgewebview2.exe")),
        (r"BraveSoftware\Brave-Browser", ("brave.exe", "elevation_service.exe")),
    )
    for item in _BROWSER_FILES
) + (
    ("APPDATA", r"Mozilla\Firefox\Profiles\*\logins.json", ("firefox.exe",)),
    ("APPDATA", r"Mozilla\Firefox\Profiles\*\key4.db", ("firefox.exe",)),
    ("APPDATA", r"Mozilla\Firefox\Profiles\*\cookies.sqlite", ("firefox.exe",)),
    ("USERPROFILE", r".ssh\id_rsa", _SSH_READERS),
    ("USERPROFILE", r".ssh\id_ed25519", _SSH_READERS),
    ("USERPROFILE", r".ssh\id_ecdsa", _SSH_READERS),
    ("USERPROFILE", r".aws\credentials", ("aws.exe",)),
)
REFRESH_POLLS = 600  # 約5分。ブラウザがファイルを置き換えると監査設定が消えるので付け直す


@dataclass(frozen=True)
class TrapHit:
    path: str
    pid: int
    image: str
    kind: str = "decoy"  # decoy=偽物 / real=本物の認証ファイル
    owners: tuple[str, ...] = ()


def is_owner(hit: TrapHit, name: str, path: str | None, signature: str, system_root: str | None = None) -> bool:
    """本来そのファイルを読むプログラムか。名前だけでなく、署名か正規の場所も求める。"""
    if name.lower() not in hit.owners or not path:
        return False
    return signature == "valid" or classify_location(path, system_root) in ("system", "program")


def hit_from_event(event: SysmonEvent, targets: dict[str, dict]) -> TrapHit | None:
    """イベント4663のうち、見張っているファイルの読み取りだけを取り出す。"""
    if event.event_id != OBJECT_ACCESS_EVENT:
        return None
    target = event.data.get("ObjectName", "")
    entry = targets.get(target.lower())
    if entry is None:
        return None
    try:
        mask = int(event.data.get("AccessMask", "0"), 16)
        pid = int(event.data.get("ProcessId", "0"), 16)
    except ValueError:
        return None
    if not mask & FILE_READ_DATA:
        return None
    return TrapHit(
        target, pid, event.data.get("ProcessName", ""),
        entry.get("kind", "decoy"), tuple(owner.lower() for owner in entry.get("owners", ())),
    )


def is_benign_reader(name: str, path: str | None, signature: str, system_root: str | None = None) -> bool:
    if name.lower() not in BENIGN_READERS:
        return False
    if not path:
        return name.lower() == "system"
    return signature == "valid" or classify_location(path, system_root) in ("system", "program")


class WinAuditBackend:
    """ファイルの監査設定と、Windows全体の監査ポリシー。どちらも管理者権限が必要。"""

    FILE_SYSTEM_SUBCATEGORY = "{0CCE921D-69AE-11D9-BED3-505054503030}"
    POLICY_SUCCESS = 0x1
    POLICY_NONE = 0x4

    def __init__(self):
        self.advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        api = self.advapi32
        api.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD),
        ]
        api.GetSecurityDescriptorSacl.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL),
        ]
        api.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ]
        api.SetNamedSecurityInfoW.restype = wintypes.DWORD
        api.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
        api.AdjustTokenPrivileges.argtypes = [
            wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
        ]
        api.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        api.AuditQuerySystemPolicy.argtypes = [ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(ctypes.c_void_p)]
        api.AuditQuerySystemPolicy.restype = wintypes.BOOLEAN
        api.AuditSetSystemPolicy.argtypes = [ctypes.c_void_p, wintypes.ULONG]
        api.AuditSetSystemPolicy.restype = wintypes.BOOLEAN
        api.AuditFree.argtypes = [ctypes.c_void_p]
        api.AuditFree.restype = None
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel32.LocalFree.restype = ctypes.c_void_p

    def _enable_privilege(self, name: str) -> bool:
        class Luid(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class Privileges(ctypes.Structure):
            _fields_ = [("Count", wintypes.DWORD), ("Luid", Luid), ("Attributes", wintypes.DWORD)]

        token = wintypes.HANDLE()
        # TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
        if not self.advapi32.OpenProcessToken(self.kernel32.GetCurrentProcess(), 0x20 | 0x8, ctypes.byref(token)):
            return False
        try:
            privileges = Privileges(1, Luid(), 0x2)  # SE_PRIVILEGE_ENABLED
            if not self.advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(privileges.Luid)):
                return False
            if not self.advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(privileges), 0, None, None):
                return False
            return ctypes.get_last_error() == 0  # ERROR_NOT_ALL_ASSIGNED は権限なし
        finally:
            self.kernel32.CloseHandle(token)

    def audit_file_reads(self, path: str) -> bool:
        """誰が読んでも成功を監査するSACLを付ける。"""
        if not self._enable_privilege("SeSecurityPrivilege"):
            return False
        descriptor = ctypes.c_void_p()
        api = self.advapi32
        # S:(AU;SA;0x1;;;WD) = 全員の FILE_READ_DATA の成功を監査
        if not api.ConvertStringSecurityDescriptorToSecurityDescriptorW("S:(AU;SA;0x1;;;WD)", 1, ctypes.byref(descriptor), None):
            return False
        try:
            present, defaulted = wintypes.BOOL(), wintypes.BOOL()
            sacl = ctypes.c_void_p()
            if not api.GetSecurityDescriptorSacl(descriptor, ctypes.byref(present), ctypes.byref(sacl), ctypes.byref(defaulted)):
                return False
            # SE_FILE_OBJECT = 1, SACL_SECURITY_INFORMATION = 8
            return api.SetNamedSecurityInfoW(path, 1, 8, None, None, None, sacl) == 0
        finally:
            self.kernel32.LocalFree(descriptor)

    def clear_audit(self, path: str) -> bool:
        """自分で付けたSACLを外す。ファイルの中身には触らない。"""
        if not self._enable_privilege("SeSecurityPrivilege"):
            return False
        descriptor = ctypes.c_void_p()
        api = self.advapi32
        if not api.ConvertStringSecurityDescriptorToSecurityDescriptorW("S:", 1, ctypes.byref(descriptor), None):
            return False
        try:
            present, defaulted = wintypes.BOOL(), wintypes.BOOL()
            sacl = ctypes.c_void_p()
            if not api.GetSecurityDescriptorSacl(descriptor, ctypes.byref(present), ctypes.byref(sacl), ctypes.byref(defaulted)):
                return False
            return api.SetNamedSecurityInfoW(path, 1, 8, None, None, None, sacl) == 0
        finally:
            self.kernel32.LocalFree(descriptor)

    def sacl_text(self, path: str) -> str | None:
        """今のSACLの文字列。読めなければ None。"""
        if not self._enable_privilege("SeSecurityPrivilege"):
            return None
        api = self.advapi32
        api.GetNamedSecurityInfoW.argtypes = [
            wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ]
        api.GetNamedSecurityInfoW.restype = wintypes.DWORD
        api.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p,
        ]
        sacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
        if api.GetNamedSecurityInfoW(path, 1, 8, None, None, None, ctypes.byref(sacl), ctypes.byref(descriptor)) != 0:
            return None
        try:
            text = wintypes.LPWSTR()
            if not api.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 8, ctypes.byref(text), None):
                return None
            try:
                return text.value
            finally:
                self.kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        finally:
            self.kernel32.LocalFree(descriptor)

    def _guid(self):
        import uuid

        return uuid.UUID(self.FILE_SYSTEM_SUBCATEGORY).bytes_le

    def read_policy(self) -> int | None:
        """ファイルシステムの監査の今の設定。読めなければ None。"""
        guid = ctypes.create_string_buffer(self._guid(), 16)
        result = ctypes.c_void_p()
        if not self.advapi32.AuditQuerySystemPolicy(guid, 1, ctypes.byref(result)):
            return None
        try:
            # AUDIT_POLICY_INFORMATION: GUID(16) の次が AuditingInformation
            return ctypes.c_ulong.from_address(result.value + 16).value
        finally:
            self.advapi32.AuditFree(result)

    def write_policy(self, value: int) -> bool:
        # 管理者でも、この特権は有効にしないと監査ポリシーを変更できない
        if not self._enable_privilege("SeSecurityPrivilege"):
            return False
        # 書き込みでは 0 が「変更しない」の意味になる。成功の監査を切るには、先に「なし」を書く
        if not value & self.POLICY_SUCCESS and not self._set_policy(self.POLICY_NONE):
            return False
        return not value or self._set_policy(value)

    def _set_policy(self, value: int) -> bool:
        record = ctypes.create_string_buffer(self._guid() + value.to_bytes(4, "little") + b"\0" * 16, 36)
        return bool(self.advapi32.AuditSetSystemPolicy(record, 1))


class TrapManager:
    """罠の設置と取り外し、読み取りの検知。設置の一覧は設定に保存する。"""

    def __init__(self, store, backend=None, environ: dict | None = None, specs=TRAP_SPECS, clock: Callable[[], float] = time.time,
                 watch_specs=WATCH_SPECS):
        self.store = store
        self.backend = backend if backend is not None else WinAuditBackend()
        self.environ = environ if environ is not None else os.environ
        self.specs = specs
        self.watch_specs = watch_specs
        self.clock = clock
        self.status = OK
        self._last_record: int | None = None
        self._retry_after = 0
        self._polls = 0

    # ---------- 本物の認証ファイルの見張り
    @property
    def watched(self) -> list[dict]:
        value = self.store.settings.get("watched")
        return value if isinstance(value, list) else []

    @property
    def watching(self) -> bool:
        return bool(self.watched)

    @property
    def enforce(self) -> bool:
        """読まれたら止めるか。既定は記録だけ。"""
        return self.store.settings.get("watch_enforce") is True

    def set_enforce(self, enabled: bool) -> None:
        self.store.settings["watch_enforce"] = enabled
        self.store.save_settings()

    def _ensure_policy(self) -> str | None:
        """読み取りの監査を有効にする。失敗したら理由を返す。"""
        current = self.backend.read_policy()
        if current is None:
            return "監査ポリシーを読めません（管理者権限が必要です）。"
        if "trap_previous_policy" not in self.store.settings:
            self.store.settings["trap_previous_policy"] = current
        if not current & self.backend.POLICY_SUCCESS and not self.backend.write_policy(current | self.backend.POLICY_SUCCESS):
            self.store.settings.pop("trap_previous_policy", None)
            return "監査ポリシーを変更できません（管理者権限が必要です）。"
        return None

    def _restore_policy_if_unused(self) -> bool:
        if self.entries or self.watched:
            return True
        previous = self.store.settings.pop("trap_previous_policy", None)
        return previous is None or self.backend.write_policy(previous)

    def _find_watch_files(self) -> list[dict]:
        found = []
        for base, pattern, owners in self.watch_specs:
            root = self.environ.get(base)
            if root:
                for path in glob.glob(os.path.join(glob.escape(root), pattern)):
                    if os.path.isfile(path):
                        found.append({"path": path, "owners": list(owners), "kind": "real"})
        return found

    def _refresh_watch(self) -> tuple[list[dict], int]:
        """見つかったファイルに監査設定を付ける。他のツールのSACLがあるものには触らない。"""
        known = {entry["path"].lower() for entry in self.watched}
        result, skipped = [], 0
        for entry in self._find_watch_files():
            text = self.backend.sacl_text(entry["path"])
            if text is None:
                skipped += 1
                continue
            mine = entry["path"].lower() in known
            if "(" in text and not mine:
                skipped += 1
                continue
            if "(" not in text and not self.backend.audit_file_reads(entry["path"]):
                skipped += 1
                continue
            result.append(entry)
        return result, skipped

    def install_watch(self) -> tuple[bool, str]:
        problem = self._ensure_policy()
        if problem:
            return False, problem
        watched, skipped = self._refresh_watch()
        self.store.settings["watched"] = watched
        self._last_record = None
        ok = bool(watched)
        if not ok:
            self._restore_policy_if_unused()
        self.store.save_settings()
        self.store.log({"event": "watch_installed", "count": len(watched), "skipped": skipped})
        if not ok:
            return False, "見張れる認証ファイルが見つかりませんでした。"
        return True, f"本物の認証ファイル {len(watched)} 個を見張ります。今は記録だけです。"

    def remove_watch(self) -> tuple[bool, str]:
        failures = 0
        for entry in self.watched:
            if os.path.exists(entry["path"]) and not self.backend.clear_audit(entry["path"]):
                failures += 1
        self.store.settings["watched"] = []
        restored = self._restore_policy_if_unused()
        self.store.save_settings()
        self.store.log({"event": "watch_removed", "failures": failures, "policy_restored": restored})
        if failures or not restored:
            return False, "見張りをやめましたが、設定を一部元に戻せませんでした（管理者権限が必要です）。"
        return True, "見張りをやめて、監査の設定を元に戻しました。"

    @property
    def entries(self) -> list[dict]:
        value = self.store.settings.get("traps")
        return value if isinstance(value, list) else []

    @property
    def installed(self) -> bool:
        return bool(self.entries)

    def planned_paths(self) -> list[str]:
        paths = []
        for base, relative, _kind in self.specs:
            root = self.environ.get(base)
            if root:
                paths.append(os.path.join(root, relative))
        return paths

    def install(self) -> tuple[bool, str]:
        problem = self._ensure_policy()
        if problem:
            return False, problem
        created: list[dict] = list(self.entries)
        known = {entry["path"].lower() for entry in created}
        failures = 0
        for base, relative, kind in self.specs:
            root = self.environ.get(base)
            if not root:
                continue
            path = os.path.join(root, relative)
            # 実在のファイルには触らない。同じ名前があれば置かない
            if path.lower() in known or os.path.exists(path):
                continue
            made = self._make_parents(path)
            try:
                with open(path, "x", encoding="ascii", newline="\n") as handle:
                    handle.write(_decoy_text(kind))
            except OSError:
                failures += 1
                continue
            entry = {"path": path, "dirs": made}
            if not self.backend.audit_file_reads(path):
                failures += 1
                self._remove_entry(entry)
                continue
            created.append(entry)
        self.store.settings["traps"] = created
        self.store.save_settings()
        self._last_record = None
        self.store.log({"event": "traps_installed", "count": len(created), "failures": failures})
        if not created:
            self.remove()
            return False, "罠を置けませんでした。"
        return True, f"罠を {len(created)} 個置きました。" + (f"（{failures} 個は失敗）" if failures else "")

    @staticmethod
    def _make_parents(path: str) -> list[str]:
        """新しく作ったフォルダーだけを、深い順に返す。取り外しで消すのはこれだけ。"""
        missing = []
        folder = os.path.dirname(path)
        while folder and not os.path.exists(folder):
            missing.append(folder)
            parent = os.path.dirname(folder)
            if parent == folder:
                break
            folder = parent
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return missing

    @staticmethod
    def _remove_entry(entry: dict) -> None:
        try:
            os.remove(entry["path"])
        except OSError:
            pass
        for folder in entry.get("dirs", []):
            try:
                os.rmdir(folder)  # 空でなければ失敗する。他のものが入っていれば残す
            except OSError:
                break

    def remove(self) -> tuple[bool, str]:
        count = len(self.entries)
        for entry in self.entries:
            self._remove_entry(entry)
        self.store.settings["traps"] = []
        restored = self._restore_policy_if_unused()
        self.store.save_settings()
        self.store.log({"event": "traps_removed", "count": count, "policy_restored": restored})
        if not restored:
            return False, "罠は外しましたが、監査ポリシーを元に戻せませんでした（管理者権限が必要です）。"
        return True, "罠を外して、監査の設定を元に戻しました。"

    def poll(self) -> list[TrapHit]:
        if not self.installed and not self.watching:
            return []
        self._polls += 1
        if self.watching and self._polls % REFRESH_POLLS == 0:
            watched, _skipped = self._refresh_watch()
            if watched and watched != self.watched:
                self.store.settings["watched"] = watched
                self.store.save_settings()
        if self._last_record is None:
            if self._retry_after > 0:
                self._retry_after -= 1
                return []
            self.status, latest = latest_record_id(SECURITY_CHANNEL)
            if self.status != OK:
                self._retry_after = 60
                return []
            self._last_record = latest
            return []
        xpath = f"*[System[(EventID={OBJECT_ACCESS_EVENT}) and EventRecordID>{self._last_record}]]"
        self.status, items = read_events(SECURITY_CHANNEL, self._last_record, xpath=xpath)
        paths = {entry["path"].lower(): {"kind": "decoy"} for entry in self.entries}
        paths.update({entry["path"].lower(): entry for entry in self.watched})
        hits = []
        for xml in items:
            event = parse_event(xml)
            if event is None:
                continue
            self._last_record = max(self._last_record, event.record_id)
            hit = hit_from_event(event, paths)
            if hit is not None:
                hits.append(hit)
        return hits


__all__ = ["TrapManager", "TrapHit", "TRAP_SPECS", "WATCH_SPECS", "eventlog", "hit_from_event", "is_benign_reader", "is_owner"]
