"""危険度の点数付け。OSに触れない純粋な関数だけを置く。"""
from __future__ import annotations

import ipaddress
import os
import statistics

from .models import HIGH, LOW, MEDIUM, Assessment, Context, ProcFacts, Reason

MEDIUM_THRESHOLD = 40
HIGH_THRESHOLD = 70

SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe"}
LOLBINS = {
    "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "installutil.exe", "msbuild.exe",
    "regasm.exe", "regsvcs.exe", "wmic.exe",
}
# 攻撃にも使われるので「常に信頼」にしない。信頼すると、これらを使った攻撃の警告が出なくなる
UNTRUSTABLE = SHELLS | LOLBINS
# システムと同じ名前で、システムフォルダ以外から動くものは偽装を疑う。
MASQUERADE_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "smss.exe", "wininit.exe", "explorer.exe", "spoolsv.exe", "dwm.exe",
    "taskhostw.exe", "conhost.exe", "rundll32.exe", "ctfmon.exe",
}
DOCUMENT_APPS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
    "acrord32.exe", "acrobat.exe", "hwp.exe", "ichitaro.exe",
}
SUSPICIOUS_PORTS = {
    1337, 4444, 5555, 6666, 6667, 6697, 9001, 9030, 9050, 9150, 12345, 31337, 54321,
}
COMMON_PORTS = {
    20, 21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 853, 993, 995, 3478, 5228, 8080, 8443,
}
ENCODED_MARKERS = (
    " -enc", " -encodedcommand", "frombase64string", "downloadstring",
    "downloadfile", "invoke-webrequest", "invoke-expression", " iex ", "iex(",
    "-windowstyle hidden", "-w hidden",
)
SENSITIVE_INBOUND_PORTS = {135, 139, 445, 3389, 5985, 5986}

FANOUT_THRESHOLD = 20
BEACON_MIN_EVENTS = 5
BEACON_MIN_INTERVAL = 5.0
BEACON_MAX_JITTER = 0.15


def is_external(ip: str) -> bool:
    """インターネット上のアドレスかどうか。解析できない値は False。"""
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return addr.is_global and not addr.is_multicast


def is_loopback(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    return (mapped or addr).is_loopback


def classify_location(path: str | None, system_root: str | None = None) -> str:
    """実行ファイルの場所を system / program / risky / appdata / other / unknown に分類する。"""
    if not path:
        return "unknown"
    root = (system_root or os.environ.get("SystemRoot") or r"C:\Windows").lower().rstrip("\\")
    p = path.lower()
    for marker in ("\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\", "\\$recycle.bin\\"):
        if marker in p:
            return "risky"
    if p.startswith(root + "\\temp\\"):
        return "risky"
    if p.startswith(root + "\\"):
        return "system"
    if len(p) > 3 and (p[1:].startswith(":\\program files\\") or p[1:].startswith(":\\program files (x86)\\")):
        return "program"
    if "\\appdata\\" in p:
        return "appdata"
    return "other"


def is_beacon(times: list[float]) -> bool:
    """同じ接続先へ、ほぼ一定の間隔で接続を繰り返しているか。"""
    if len(times) < BEACON_MIN_EVENTS:
        return False
    recent = times[-BEACON_MIN_EVENTS:]
    gaps = [b - a for a, b in zip(recent, recent[1:])]
    mean = statistics.fmean(gaps)
    if mean < BEACON_MIN_INTERVAL:
        return False
    return statistics.pstdev(gaps) / mean <= BEACON_MAX_JITTER


def level_of(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return HIGH
    if score >= MEDIUM_THRESHOLD:
        return MEDIUM
    return LOW


def assess(proc: ProcFacts, ctx: Context, system_root: str | None = None) -> Assessment:
    reasons: list[Reason] = []

    def add(code: str, points: int, text: str) -> None:
        reasons.append(Reason(code, points, text))

    name = proc.name.lower()
    loc = classify_location(proc.path, system_root)
    user_writable = loc in ("risky", "appdata", "other")
    is_shell = name in SHELLS and loc in ("system", "program")
    is_lolbin = name in LOLBINS and loc == "system"
    masquerade = bool(proc.path) and name in MASQUERADE_NAMES and loc != "system"

    if masquerade:
        add("masquerade", 70, f"システムと同じ名前（{proc.name}）なのに、別の場所から動いています")

    if ctx.direction != "listen":
        if is_shell:
            add("shell_net", 45, f"{proc.name} が直接外部と通信しています")
        if is_lolbin:
            add("lolbin_net", 55, f"悪用されやすい標準ツール {proc.name} が外部と通信しています")

    if is_shell or is_lolbin:
        cmd = f" {(proc.cmdline or '').lower()} "
        # 署名を確かめた開発ツールは、PowerShellの実行に符号化した引数を常に使う
        if not (is_shell and proc.dev_tool) and any(marker in cmd for marker in ENCODED_MARKERS):
            add("encoded_cmd", 30, "難読化やダウンロードを示す命令が含まれています")
        if (proc.parent_name or "").lower() in DOCUMENT_APPS:
            add("document_child", 35, f"文書アプリ {proc.parent_name} から起動されています")

    if proc.signature == "invalid":
        add("bad_signature", 40, "デジタル署名が壊れているか失効しています")
    elif proc.signature == "unsigned" and user_writable:
        add("unsigned", 15, "デジタル署名がありません")

    if loc == "risky":
        add("risky_path", 30, "一時フォルダやダウンロードなど、不審な場所から動いています")
    elif loc == "appdata" and proc.signature != "valid":
        add("appdata_path", 10, "署名なしでユーザーデータのフォルダから動いています")

    if ctx.direction == "outbound":
        if ctx.remote_port in SUSPICIOUS_PORTS:
            add("bad_port", 30, f"遠隔操作やTorでよく使われるポート {ctx.remote_port} へ接続しています")
        elif proc.signature != "valid" and user_writable and ctx.remote_port not in COMMON_PORTS:
            add("odd_port", 10, f"一般的でないポート {ctx.remote_port} へ接続しています")
    elif ctx.direction == "inbound":
        if ctx.local_port in SENSITIVE_INBOUND_PORTS:
            add("sensitive_inbound", 70, f"遠隔操作・共有用のポート {ctx.local_port} へ外部から接続されています")
        else:
            add("inbound", 35, f"外部からポート {ctx.local_port} へ接続されています")
    elif ctx.direction == "listen" and user_writable:
        add("open_listener", 25, f"ポート {ctx.local_port} で外部からの接続を待ち受けています")

    if ctx.first_seen:
        add("new_app", 10, "このPCで初めて通信を確認したアプリです")
    if ctx.distinct_ips_60s >= FANOUT_THRESHOLD:
        add("fan_out", 30, f"60秒間に {ctx.distinct_ips_60s} か所へ接続しています")
    if ctx.beacon:
        add("beacon", 25, "同じ接続先へ一定間隔で接続を繰り返しています")

    if not (masquerade or is_shell or is_lolbin):
        if proc.signature == "valid":
            add("signed", -30, "有効なデジタル署名があります")
        elif loc == "system":
            add("system_app", -20, "Windowsのシステムフォルダ内のアプリです")
        elif loc == "program":
            add("program_app", -10, "Program Files 内のアプリです")

    score = max(0, min(100, sum(r.points for r in reasons)))
    return Assessment(score, level_of(score), reasons)


__all__ = [
    "LOW", "MEDIUM", "HIGH", "assess", "classify_location", "is_beacon",
    "is_external", "is_loopback", "level_of",
]
