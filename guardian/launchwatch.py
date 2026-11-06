"""プログラムの起動を見て、感染の入口らしい動きに点数を付ける。OSに触れない。

ClickFix（Win+Rなどへ貼り付けさせる手口）、悪用されやすい標準ツールでのダウンロード、
ネットから入手した署名なしプログラムの実行などを見る。
"""
from __future__ import annotations

from .models import Assessment, ProcFacts, Reason
from .report import BROWSERS
from .risk import DOCUMENT_APPS, ENCODED_MARKERS, LOLBINS, MASQUERADE_NAMES, SHELLS, classify_location, level_of

INTERACTIVE_PARENTS = {"explorer.exe"}
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe"}
URL_MARKERS = ("http://", "https://", "ftp://", "\\\\")
DOWNLOAD_TOOLS = {
    "mshta.exe": ("http", "javascript:", "vbscript:"),
    "certutil.exe": ("-urlcache", "/urlcache", "-decode", "/decode", "-verifyctl"),
    "bitsadmin.exe": ("/transfer", "/addfile"),
    "regsvr32.exe": ("http", "scrobj"),
    "rundll32.exe": ("http", "javascript:"),
    "msiexec.exe": ("http",),
}
RISKY_PATH_MARKERS = ("\\downloads\\", "\\appdata\\local\\temp\\", "\\users\\public\\", "\\$recycle.bin\\")
WEAK_DOWNLOAD_MARKERS = ("curl ", "curl.exe", "wget ", "start-bitstransfer")


def assess_launch(proc: ProcFacts, zone: int | None = None, system_root: str | None = None) -> Assessment:
    """zone は Mark of the Web のゾーン（3=インターネット）。記録がなければ None。"""
    reasons: list[Reason] = []

    def add(code: str, points: int, text: str) -> None:
        reasons.append(Reason(code, points, text))

    name = proc.name.lower()
    location = classify_location(proc.path, system_root)
    in_system = location in ("system", "program")
    cmd = f" {(proc.cmdline or '').lower()} "
    parent = (proc.parent_name or "").lower()
    user_writable = location in ("risky", "appdata", "other")

    if proc.path and name in MASQUERADE_NAMES and location != "system":
        add("masquerade", 70, f"システムと同じ名前（{proc.name}）なのに、別の場所から起動しました")

    if name in SHELLS and in_system:
        from_interactive = parent in INTERACTIVE_PARENTS or parent in BROWSERS
        origin = "エクスプローラーやブラウザから直接起動しています（貼り付けを促す ClickFix の手口）"
        if not proc.dev_tool and any(marker in cmd for marker in ENCODED_MARKERS):
            add("shell_download", 50, f"{proc.name} が難読化やダウンロードの命令付きで起動しました")
            if from_interactive:
                add("clickfix", 25, origin)
        elif from_interactive and any(marker in cmd for marker in WEAK_DOWNLOAD_MARKERS):
            # curl などは開発で日常的に使うので、直接起動されたときだけ見る
            add("clickfix_download", 70, f"{proc.name} にダウンロードの命令が渡されています。{origin}")

    patterns = DOWNLOAD_TOOLS.get(name)
    if patterns and location == "system" and any(pattern in cmd for pattern in patterns):
        add("lolbin_download", 70, f"悪用されやすい標準ツール {proc.name} が、ダウンロードや外部コード実行の引数付きで起動しました")

    if name in SCRIPT_HOSTS and location == "system" and any(marker in cmd for marker in RISKY_PATH_MARKERS):
        add("script_risky", 70, "ダウンロードや一時フォルダのスクリプトが実行されました")

    if parent in DOCUMENT_APPS and (name in SHELLS or name in LOLBINS):
        add("document_child", 70, f"文書アプリ {proc.parent_name} が {proc.name} を起動しました")

    if name in BROWSERS and "--remote-debugging-port" in cmd:
        add("browser_debug", 50, "ブラウザがリモートデバッグ付きで起動しました（Cookie窃取の手口。開発ツールでも使います）")

    if user_writable:
        if proc.signature == "invalid":
            add("bad_signature", 40, "デジタル署名が壊れているか失効しています")
        elif proc.signature == "unsigned":
            if location == "risky":
                add("unsigned_risky", 45, "署名のないプログラムが、ダウンロードや一時フォルダから起動しました")
            if zone is not None and zone >= 3:
                add("from_internet", 20, "インターネットから入手したファイルです")

    score = max(0, min(100, sum(reason.points for reason in reasons)))
    return Assessment(score, level_of(score), reasons)
