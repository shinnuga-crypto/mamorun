"""プログラムの調査結果と、そこから導く判断材料。OSに触れない。

判定を下すのではなく、止めるかどうかを決めるための事実を重要な順に並べる。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .pemeta import PeInfo
from .risk import DOCUMENT_APPS, LOLBINS, SHELLS, classify_location
from .signinfo import EXPIRED, REVOKED, STATUS_LABEL, TAMPERED, UNSIGNED, UNTRUSTED, VALID, DISTRUSTED, SignatureInfo

BAD = "bad"
WARN = "warn"
INFO = "info"
GOOD = "good"
SEVERITY_ORDER = {BAD: 0, WARN: 1, INFO: 2, GOOD: 3}
SEVERITY_LABEL = {BAD: "危険", WARN: "注意", INFO: "参考", GOOD: "安心材料"}

HIGH_ENTROPY = 7.2
LARGE_OVERLAY = 1024 * 1024
NEW_CERT_DAYS = 30
SHORT_LIVED_DAYS = 14
BROWSERS = {"chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "opera.exe"}
ZONE_LABEL = {0: "このPC", 1: "イントラネット", 2: "信頼済みサイト", 3: "インターネット", 4: "制限付きサイト"}
# 有名企業を名乗っているのに署名者が違う場合を見つける
CLAIMED_VENDORS = (
    "microsoft", "google", "adobe", "mozilla", "apple", "intel", "nvidia", "amd", "oracle", "cisco",
    "zoom", "discord", "valve", "steam", "telegram", "opera", "brave", "dropbox", "logitech",
)
IMPORT_GROUPS = {
    "他のプロセスへの注入": {
        "writeprocessmemory", "createremotethread", "createremotethreadex", "ntcreatethreadex", "queueuserapc",
        "ntqueueapcthread", "setthreadcontext", "ntmapviewofsection", "ntunmapviewofsection", "virtualallocex",
    },
    "資格情報の復号（ブラウザのパスワードやCookieの窃取に使われる）": {
        "cryptunprotectdata", "credenumeratea", "credenumeratew", "credreadw", "credreada", "lsaretrieveprivatedata",
    },
    "キー入力の監視": {"setwindowshookexa", "setwindowshookexw", "getasynckeystate", "registerrawinputdevices"},
}
# 署名がなくても通常は問題にならない、WindowsとProgram Files以外のモジュールだけを疑う
USER_WRITABLE = ("risky", "appdata", "other")


@dataclass
class ModuleInfo:
    path: str
    signature: str  # signinfo の状態
    signer: str = ""

    @property
    def status_text(self) -> str:
        return self.signature


@dataclass
class ProcessInfo:
    pid: int
    started: datetime | None = None
    user: str = ""
    integrity: str = ""
    elevated: bool | None = None
    cmdline: str = ""
    parents: list[str] = field(default_factory=list)  # 近い親から順
    suspended: bool = False
    modules_total: int = 0
    modules_outside: list[ModuleInfo] = field(default_factory=list)  # システムフォルダ外のDLL
    modules_error: str = ""
    connections: list[str] = field(default_factory=list)
    dns_hosts: list[str] = field(default_factory=list)  # Sysmonで分かった問い合わせ先


@dataclass
class Note:
    severity: str
    text: str


@dataclass
class ProgramReport:
    path: str | None
    name: str
    exists: bool = False
    size: int = 0
    modified: datetime | None = None
    created: datetime | None = None
    sha256: str = ""
    signature: SignatureInfo | None = None
    version: dict[str, str] = field(default_factory=dict)
    motw: dict[str, str] = field(default_factory=dict)
    pe: PeInfo | None = None
    process: ProcessInfo | None = None
    notes: list[Note] = field(default_factory=list)

    def count(self, severity: str) -> int:
        return sum(1 for note in self.notes if note.severity == severity)

    @property
    def signature_summary(self) -> str:
        if self.signature is None:
            return "確認できず"
        kind = f"（{self.signature.kind}）" if self.signature.status == VALID else ""
        return STATUS_LABEL.get(self.signature.status, self.signature.status) + kind

    @property
    def signer_name(self) -> str:
        signer = self.signature.signer if self.signature else None
        return signer.subject if signer else ""


def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _strip_mui(name: str) -> str:
    return re.sub(r"\.mui$", "", name.strip(), flags=re.IGNORECASE).lower()


def build_notes(report: ProgramReport, now: datetime | None = None, system_root: str | None = None) -> list[Note]:
    now = now or datetime.now(timezone.utc)
    notes: list[Note] = []

    def add(severity: str, text: str) -> None:
        notes.append(Note(severity, text))

    location = classify_location(report.path, system_root)
    if not report.exists:
        add(WARN, "実行ファイルを確認できません。削除された、または読めない場所にあります")
    if location == "risky":
        add(WARN, "一時フォルダやダウンロードなど、不審な場所から動いています")

    _signature_notes(report, location, now, add)
    _version_notes(report, add)
    _motw_notes(report, add)
    _pe_notes(report, now, add)
    _process_notes(report, location, system_root, add)

    notes.sort(key=lambda note: SEVERITY_ORDER[note.severity])
    return notes


def _signature_notes(report: ProgramReport, location: str, now: datetime, add) -> None:
    signature = report.signature
    if signature is None:
        return
    status = signature.status
    if status == TAMPERED:
        add(BAD, "署名の後でファイルが書き換えられた可能性があります（ハッシュ不一致）")
    elif status == REVOKED:
        add(BAD, "署名に使われた証明書は失効しています")
    elif status == DISTRUSTED:
        add(BAD, "署名に使われた証明書はWindowsが拒否しています")
    elif status == UNTRUSTED:
        add(WARN, "署名はありますが、信頼されていない発行元のものです（自己署名の可能性）")
    elif status == EXPIRED:
        add(WARN, "証明書の期限が切れていて、署名時刻の証明（タイムスタンプ）もありません")
    elif status == UNSIGNED:
        if location in USER_WRITABLE:
            add(WARN, "デジタル署名がありません")
        else:
            add(INFO, "デジタル署名がありません（書き換えに管理者権限が必要な場所です）")
    elif status != VALID:
        add(WARN, f"署名を検証できませんでした（0x{signature.code:08X}）")

    if status == VALID:
        signer = signature.signer
        name = signer.subject if signer else "不明"
        add(GOOD, f"署名は有効です（{signature.kind}、署名者: {name}）。ただし盗まれた証明書の悪用は見分けられません")
        add(INFO, "失効の確認はしていません（通信しないため、Windowsのキャッシュのみ）")
        if signature.kind == "埋め込み" and not signature.signed_at:
            add(INFO, "タイムスタンプがありません")
        if signature.digest in ("SHA-1", "MD5"):
            add(WARN, f"署名に古いハッシュ方式（{signature.digest}）が使われています")
        if signer and signer.not_before and signer.not_after:
            lifetime = signer.not_after - signer.not_before
            if lifetime <= timedelta(days=SHORT_LIVED_DAYS):
                # Microsoft のクラウド署名など正規にも使われるが、悪用の報告もある
                add(INFO, f"有効期間 {lifetime.days} 日の短命な証明書です（正規にも使われますが、悪用の報告もあります）")
            elif signature.signed_at:
                age = signature.signed_at - signer.not_before
                if timedelta(0) <= age < timedelta(days=NEW_CERT_DAYS):
                    add(INFO, f"証明書の発行から {age.days} 日で署名されています（盗難や使い捨ての証明書で見られる特徴）")


def _version_notes(report: ProgramReport, add) -> None:
    version = report.version
    original = version.get("OriginalFilename", "")
    company = version.get("CompanyName", "")
    signature = report.signature
    if original and report.name and _strip_mui(original) != report.name.lower():
        # Electron製アプリは本来の名前がすべて chrome.exe などになるので、署名があれば参考に留める
        signed = signature is not None and signature.status == VALID
        add(INFO if signed else WARN, f"本来のファイル名は {original} です（改名された可能性があります）")
    if not company or signature is None:
        return
    claimed = next((vendor for vendor in CLAIMED_VENDORS if vendor in _normalize(company)), None)
    if not claimed:
        return
    signer = signature.signer
    signed_as = _normalize(f"{signer.subject} {signer.organization}") if signer else ""
    if signature.status != VALID:
        add(BAD, f"会社名に「{company}」とありますが、有効な署名がありません（なりすましの可能性）")
    elif claimed not in signed_as:
        add(BAD, f"会社名に「{company}」とありますが、署名者は {signer.subject if signer else '不明'} です（なりすましの可能性）")


def _motw_notes(report: ProgramReport, add) -> None:
    motw = report.motw
    if not motw:
        return
    try:
        zone = int(motw.get("ZoneId", ""))
    except ValueError:
        zone = -1
    origin = motw.get("HostUrl") or motw.get("ReferrerUrl") or "不明"
    if zone >= 3:
        add(WARN, f"{ZONE_LABEL.get(zone, zone)}から入手したファイルです（入手元: {origin}）")
    else:
        add(INFO, f"入手元の記録があります（ゾーン: {ZONE_LABEL.get(zone, zone)}、入手元: {origin}）")


def _pe_notes(report: ProgramReport, now: datetime, add) -> None:
    pe = report.pe
    if pe is None:
        return
    for error in pe.errors:
        add(WARN, f"ファイルの構造に異常があります: {error}")
    if pe.cert_slack:
        add(WARN, f"署名領域に、署名の検証対象外のデータが {pe.cert_slack:,} バイトあります（隠し場所に使われる手口）")
    if pe.packers:
        add(WARN, f"圧縮・難読化ツールの痕跡があります: {', '.join(pe.packers)}")
    for section in pe.sections:
        if section.executable and section.writable:
            add(WARN, f"書き込みと実行の両方ができるセクションがあります（{section.name}。自己展開で見られます）")
        if section.executable and section.entropy >= HIGH_ENTROPY:
            add(WARN, f"実行部分（{section.name}）のエントロピーが {section.entropy} と高く、圧縮か暗号化の可能性があります")
    if pe.entry_outside_sections:
        add(WARN, "開始位置がどのセクションにもありません")
    if not pe.is_dotnet and pe.import_count and pe.import_count < 5:
        add(WARN, f"インポートが {pe.import_count} 個しかありません（実行時に解決する難読化の可能性）")
    if pe.overlay_size >= LARGE_OVERLAY:
        add(INFO, f"ファイル末尾に追加データが {pe.overlay_size / 1024 / 1024:.1f} MB あります（インストーラーでもよく見られます）")
    names = {function.lower() for functions in pe.imports.values() for function in functions}
    for label, group in IMPORT_GROUPS.items():
        found = sorted(names & group)
        if found:
            add(INFO, f"{label}に使える機能を読み込みます: {', '.join(found)}")
    # 再現可能ビルドでは日時の欄にハッシュが入るので、有効な署名があれば触れない
    signed = report.signature is not None and report.signature.status == VALID
    if not signed and pe.timestamp and datetime.fromtimestamp(pe.timestamp, timezone.utc) > now + timedelta(days=1):
        add(INFO, "ビルド日時が未来です（偽装の可能性。再現可能ビルドでも起こります）")


def _process_notes(report: ProgramReport, location: str, system_root: str | None, add) -> None:
    process = report.process
    if process is None:
        return
    name = report.name.lower()
    if process.parents:
        parent = process.parents[0].lower()
        if parent in DOCUMENT_APPS:
            add(BAD, f"文書アプリ {process.parents[0]} から起動されています")
        elif parent in SHELLS or parent in LOLBINS:
            add(INFO, f"{process.parents[0]} から起動されています")
    if (name in SHELLS or name in LOLBINS) and location == "system":
        add(WARN, f"{report.name} はWindows標準ですが、攻撃によく悪用されます。コマンドラインを確認してください")
    if name in BROWSERS and "--remote-debugging-port" in process.cmdline.lower():
        add(WARN, "ブラウザがリモートデバッグ付きで動いています（Cookie窃取の手口。開発ツールでも使います）")
    from .sysmonrules import dead_drop_service, known_bad_host  # 互いに参照するのでここで読み込む

    for host in process.dns_hosts:
        incident = known_bad_host(host)
        if incident:
            add(BAD, f"{incident}で使われた通信先 {host} の名前を引きました")
            continue
        service = dead_drop_service(host)
        if service and name not in BROWSERS:
            add(WARN, f"持ち出しに悪用される {service}（{host}）の名前を引きました")
    if process.elevated:
        add(INFO, f"管理者権限で動いています（整合性: {process.integrity or '不明'}）")
    # 正規の署名済みアプリに不正なDLLを読ませる「サイドローディング」を見つける
    for module in process.modules_outside:
        module_location = classify_location(module.path, system_root)
        if module.signature != VALID and module_location in USER_WRITABLE:
            severity = BAD if report.signature and report.signature.status == VALID else WARN
            add(severity, f"署名のないDLLを読み込んでいます: {module.path}")
        elif module.signature in (TAMPERED, REVOKED, DISTRUSTED):
            add(BAD, f"署名に問題のあるDLLを読み込んでいます: {module.path}")
    if process.modules_error:
        add(INFO, f"読み込みDLLを確認できませんでした（{process.modules_error}）")
