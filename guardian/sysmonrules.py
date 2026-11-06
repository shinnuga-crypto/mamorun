"""Sysmonのイベントの解析と判定。OSに触れない。

イベントの中身はマルウェアが決められるので、XMLは標準の解析器で読み、値は文字列としてだけ扱う。
"""
from __future__ import annotations

import ntpath
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .models import Assessment, ProcFacts, Reason
from .report import BROWSERS
from .risk import LOLBINS, SHELLS, classify_location, level_of

PROCESS_CREATE = 1
REGISTRY_VALUE_SET = 13
DNS_QUERY = 22
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
MAX_XML_CHARS = 256_000

# 情報窃取マルウェアが、指令の受け取りや持ち出しに悪用すると報告されている正規サービス
DEAD_DROP_SUFFIXES = {
    "api.telegram.org": "Telegram",
    "t.me": "Telegram",
    "telegram.me": "Telegram",
    "discord.com": "Discord",
    "discordapp.com": "Discord",
    "cdn.discordapp.com": "Discord",
    "steamcommunity.com": "Steam",
    "workers.dev": "Cloudflare Workers",
    "pastebin.com": "Pastebin",
    # 実行時にLLMを呼ぶマルウェアの通信先として報告されている、または同じ使い方ができるもの
    "huggingface.co": "Hugging Face",
    "generativelanguage.googleapis.com": "Gemini API",
    "api.openai.com": "OpenAI API",
    "api.anthropic.com": "Anthropic API",
    "openrouter.ai": "OpenRouter",
    "api.groq.com": "Groq API",
}
# 公開された事件の通信先。署名やブラウザかどうかに関係なく止める
KNOWN_BAD_HOSTS = {
    "insightjs.com": "NIKKE PCランチャー事件（2026年）",
    "insightjs.org": "NIKKE PCランチャー事件（2026年）",
}
COM_KEY_MARKERS = ("_classes\\clsid\\", "\\software\\classes\\clsid\\")
RUN_KEY_MARKERS = (
    "\\software\\microsoft\\windows\\currentversion\\run\\",
    "\\software\\microsoft\\windows\\currentversion\\runonce\\",
)


@dataclass
class SysmonEvent:
    event_id: int
    record_id: int = 0
    time: datetime | None = None
    data: dict[str, str] = field(default_factory=dict)

    @property
    def pid(self) -> int:
        try:
            return int(self.data.get("ProcessId", "0"))
        except ValueError:
            return 0

    @property
    def image(self) -> str:
        return self.data.get("Image", "")


def parse_event(xml: str) -> SysmonEvent | None:
    """イベントのXMLを読む。壊れていれば None。"""
    if len(xml) > MAX_XML_CHARS:
        return None
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    system = root.find(f"{_NS}System")
    if system is None:
        return None
    try:
        event_id = int(system.findtext(f"{_NS}EventID", ""))
        record_id = int(system.findtext(f"{_NS}EventRecordID", "0"))
    except ValueError:
        return None
    event = SysmonEvent(event_id, record_id)
    created = system.find(f"{_NS}TimeCreated")
    if created is not None:
        event.time = _parse_time(created.get("SystemTime", ""))
    body = root.find(f"{_NS}EventData")
    if body is not None:
        for item in body.findall(f"{_NS}Data"):
            name = item.get("Name")
            if name:
                event.data[name] = item.text or ""
    return event


def _parse_time(text: str) -> datetime | None:
    # 例: 2026-11-06T00:29:59.4134080Z。小数は6桁までにそろえる
    match = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,6})\d*)?Z?$", text)
    if not match:
        return None
    try:
        value = datetime.fromisoformat(match.group(1) + (f".{match.group(2):0<6}" if match.group(2) else ""))
    except ValueError:
        return None
    return value.replace(tzinfo=timezone.utc)


def facts_from_create(event: SysmonEvent, signature: str = "unknown") -> ProcFacts:
    image = event.image
    parent = event.data.get("ParentImage", "")
    return ProcFacts(
        pid=event.pid, created=0, name=ntpath.basename(image) or f"PID {event.pid}", path=image or None,
        parent_name=ntpath.basename(parent) or None, cmdline=event.data.get("CommandLine"), signature=signature,
    )


def dead_drop_service(host: str) -> str | None:
    """名前が悪用の多いサービスのものなら、そのサービス名を返す。"""
    host = host.strip().rstrip(".").lower()
    for suffix, service in DEAD_DROP_SUFFIXES.items():
        if host == suffix or host.endswith("." + suffix):
            return service
    return None


def known_bad_host(host: str) -> str | None:
    host = host.strip().rstrip(".").lower()
    for bad, incident in KNOWN_BAD_HOSTS.items():
        if host == bad or host.endswith("." + bad):
            return incident
    return None


def is_watched_host(host: str) -> bool:
    return known_bad_host(host) is not None or dead_drop_service(host) is not None


def assess_dns(proc: ProcFacts, host: str, system_root: str | None = None) -> Assessment:
    """ブラウザや署名済みの専用アプリ以外が、悪用の多いサービスの名前を引いたら点を付ける。"""
    reasons: list[Reason] = []
    incident = known_bad_host(host)
    if incident:
        reasons.append(Reason("known_bad_host", 90, f"{incident}で使われた通信先 {host} へつなごうとしています"))
        return Assessment(90, level_of(90), reasons)
    service = dead_drop_service(host)
    name = proc.name.lower()
    location = classify_location(proc.path, system_root)
    # システムフォルダの普通のアプリはカタログ署名が多く、署名なしと見えることがある。PowerShellなどは疑う
    ordinary_system = location == "system" and name not in SHELLS and name not in LOLBINS
    if service and name not in BROWSERS and proc.signature != "valid" and not ordinary_system:
        reasons.append(Reason("dead_drop", 45, f"持ち出し、指令の受け取り、実行時のコード生成に悪用される {service}（{host}）へつなごうとしています"))
        if location == "risky":
            reasons.append(Reason("risky_path", 30, "一時フォルダやダウンロードなど、不審な場所から動いています"))
        elif location in ("appdata", "other"):
            reasons.append(Reason("user_path", 15, "ユーザーが書き込める場所から動いています"))
    score = min(100, sum(reason.points for reason in reasons))
    return Assessment(score, level_of(score), reasons)


def is_run_key(target: str) -> bool:
    lowered = target.lower()
    return any(marker in lowered for marker in RUN_KEY_MARKERS)


def is_com_key(target: str) -> bool:
    """COMのDLL登録。正規のプログラムの読み込み先を横取りする手口に使われる。"""
    lowered = target.lower()
    return "\\inprocserver32" in lowered and any(marker in lowered for marker in COM_KEY_MARKERS)


def is_persistence_key(target: str) -> bool:
    return is_run_key(target) or is_com_key(target)


def registered_path(details: str) -> str | None:
    """Runキーの値から実行ファイルのパスを取り出す。"""
    text = details.strip()
    if not text:
        return None
    if text.startswith('"'):
        end = text.find('"', 1)
        return text[1:end] if end > 0 else None
    lowered = text.lower()
    for extension in (".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".dll", ".scr"):
        position = lowered.find(extension)
        if position >= 0:
            return text[:position + len(extension)]
    return text.split(" ", 1)[0]


def assess_persistence(writer: ProcFacts, target: str, details: str, target_signature: str = "unknown",
                       system_root: str | None = None) -> Assessment:
    """Windows起動時に自動で動く登録を判定する。署名済みの更新機能などは静かに通す。"""
    reasons: list[Reason] = []
    if is_com_key(target):
        path = registered_path(details)
        location = classify_location(path, system_root)
        if path and "\\user data\\" in path.lower():
            # NIKKE PCランチャー事件で使われた形。署名の有無によらず強く疑う
            reasons.append(Reason("com_browser_dll", 75, "ブラウザのデータフォルダにあるDLLを、COMの登録で読み込ませようとしています"))
        elif target_signature != "valid" and location in ("risky", "appdata", "other", "unknown"):
            reasons.append(Reason("com_hijack", 45, "署名のないDLLがCOMに登録されました（正規のプログラムに読み込ませる手口）"))
            if location == "risky":
                reasons.append(Reason("persistence_risky", 30, "登録先が一時フォルダやダウンロードにあります"))
        score = min(100, sum(reason.points for reason in reasons))
        return Assessment(score, level_of(score), reasons)
    if not is_run_key(target):
        return Assessment(0, level_of(0), reasons)
    path = registered_path(details)
    location = classify_location(path, system_root)
    value = ntpath.basename(target)
    if target_signature != "valid" and location in ("risky", "appdata", "other", "unknown"):
        reasons.append(Reason("persistence", 45, f"署名のないプログラムが自動起動に登録されました（{value}）"))
        if location == "risky":
            reasons.append(Reason("persistence_risky", 30, "登録先が一時フォルダやダウンロードにあります"))
    lowered = details.lower()
    if any(marker in lowered for marker in ("powershell", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "cmd /c", "cmd.exe /c")):
        reasons.append(Reason("persistence_script", 70, f"標準ツールでコマンドを動かす自動起動が登録されました（{value}）"))
    score = min(100, sum(reason.points for reason in reasons))
    return Assessment(score, level_of(score), reasons)
