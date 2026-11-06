"""調査結果を画面と文章に整える。OSにもQtにも触れない。

調査対象のファイルが持つ文字列は攻撃者が決められるので、HTMLには必ずエスケープして入れる。
"""
from __future__ import annotations

from datetime import datetime
from html import escape

from .report import BAD, GOOD, INFO, SEVERITY_LABEL, WARN, ProgramReport
from .signinfo import STATUS_LABEL

SEVERITY_COLOR = {BAD: "#b3261e", WARN: "#a15c00", INFO: "#44506a", GOOD: "#1b7f5c"}
MAX_IMPORT_LINES = 40
MAX_MODULE_LINES = 60


def _time(value: datetime | None) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S") if value else "なし"


def _size(value: int) -> str:
    if value >= 1024 * 1024:
        return f"{value / 1024 / 1024:.1f} MB（{value:,} バイト）"
    return f"{value:,} バイト"


def report_sections(report: ProgramReport) -> list[tuple[str, list[tuple[str, str]]]]:
    """[(見出し, [(項目, 値)])]。文章表示とHTML表示で共通に使う。"""
    sections: list[tuple[str, list[tuple[str, str]]]] = []

    process = report.process
    if process is not None:
        rows = [
            ("PID", str(process.pid) + ("（一時停止中）" if process.suspended else "")),
            ("起動日時", _time(process.started)),
            ("ユーザー", process.user or "取得できません"),
            ("権限", f"整合性 {process.integrity or '不明'}、管理者権限 "
                     + {True: "あり", False: "なし", None: "不明"}[process.elevated]),
            ("起動元", " ← ".join(process.parents) if process.parents else "不明"),
            ("コマンドライン", process.cmdline or "取得できません"),
        ]
        sections.append(("プロセス", rows))
        if process.connections:
            sections.append(("接続", [(str(i + 1), text) for i, text in enumerate(process.connections)]))
        if process.dns_hosts:
            sections.append(("名前の問い合わせ（Sysmon）", [(str(i + 1), host) for i, host in enumerate(process.dns_hosts)]))

    sections.append(("ファイル", [
        ("場所", report.path or "取得できません"),
        ("大きさ", _size(report.size) if report.exists else "不明"),
        ("更新日時", _time(report.modified)),
        ("作成日時", _time(report.created)),
        ("SHA-256", report.sha256 or "不明"),
    ]))

    signature = report.signature
    if signature is not None:
        rows = [
            ("状態", STATUS_LABEL.get(signature.status, signature.status)),
            ("方式", signature.kind),
            ("ハッシュ方式", signature.digest or "不明"),
            ("タイムスタンプ", _time(signature.signed_at)),
            ("時刻の発行者", signature.timestamp_signer or "なし"),
            ("失効の確認", "未確認（通信しないためWindowsのキャッシュのみ）"),
        ]
        if signature.code:
            rows.append(("検証コード", f"0x{signature.code:08X}"))
        if signature.catalog:
            rows.append(("カタログ", signature.catalog))
        sections.append(("デジタル署名", rows))
        for index, cert in enumerate(signature.chain):
            title = "署名者の証明書" if index == 0 else f"発行元の証明書 {index}"
            sections.append((title, [
                ("名前", cert.subject),
                ("組織", cert.organization or "なし"),
                ("発行者", cert.issuer),
                ("有効期間", f"{_time(cert.not_before)} 〜 {_time(cert.not_after)}"),
                ("シリアル", cert.serial),
                ("拇印 SHA-256", cert.sha256),
            ]))

    if report.version:
        sections.append(("バージョン情報", list(report.version.items())))
    if report.motw:
        sections.append(("入手元（Mark of the Web）", list(report.motw.items())))
    elif report.exists:
        sections.append(("入手元（Mark of the Web）", [("記録", "なし（なくても安全とは限りません）")]))

    pe = report.pe
    if pe is not None:
        flags = [label for label, on in (("ASLR", pe.aslr), ("DEP", pe.dep), ("CFG", pe.cfg)) if on]
        rows = [
            ("種類", f"{pe.machine}、{pe.subsystem}" + ("、DLL" if pe.is_dll else "") + ("、.NET" if pe.is_dotnet else "")),
            ("ビルド日時の欄", datetime.fromtimestamp(pe.timestamp).strftime("%Y-%m-%d %H:%M:%S") if pe.timestamp else "なし"),
            ("保護機能", "、".join(flags) or "なし"),
            ("末尾の追加データ", _size(pe.overlay_size)),
            ("署名領域", f"{_size(pe.cert_size)}（検証対象外のデータ {_size(pe.cert_slack)}）"),
            ("インポート", f"{len(pe.imports)} DLL、{pe.import_count} 関数"),
        ]
        sections.append(("実行ファイルの構造", rows))
        sections.append(("セクション", [
            (section.name or "（名前なし）",
             f"{_size(section.raw_size)}、エントロピー {section.entropy}"
             + ("、実行可" if section.executable else "") + ("、書込可" if section.writable else ""))
            for section in pe.sections
        ]))
        imports = sorted(pe.imports.items())[:MAX_IMPORT_LINES]
        if imports:
            sections.append(("読み込むDLL（静的）", [(dll, f"{len(functions)} 関数") for dll, functions in imports]))

    if process is not None:
        title = f"読み込み中のDLL（全 {process.modules_total} 件のうちシステムフォルダ外）"
        if process.modules_outside:
            sections.append((title, [
                (STATUS_LABEL.get(module.status_text, module.status_text), module.path + (f"（{module.signer}）" if module.signer else ""))
                for module in process.modules_outside[:MAX_MODULE_LINES]
            ]))
        elif process.modules_error:
            sections.append((title, [("確認", process.modules_error)]))
        else:
            sections.append((title, [("件数", "なし")]))
    return sections


def report_html(report: ProgramReport) -> str:
    parts = [f'<h2 style="margin:0">{escape(report.name)}</h2>']
    parts.append('<h3 style="margin-bottom:4px">判断材料</h3>')
    if report.notes:
        parts.append('<table cellspacing="0" cellpadding="3">')
        for note in report.notes:
            color = SEVERITY_COLOR[note.severity]
            parts.append(
                f'<tr><td style="color:{color};font-weight:700" nowrap>{SEVERITY_LABEL[note.severity]}</td>'
                f"<td>{escape(note.text)}</td></tr>"
            )
        parts.append("</table>")
    else:
        parts.append("<p>特に気になる点はありません。</p>")
    for title, rows in report_sections(report):
        parts.append(f'<h3 style="margin-bottom:4px">{escape(title)}</h3><table cellspacing="0" cellpadding="2">')
        for key, value in rows:
            parts.append(
                f'<tr><td style="color:#5c6880;padding-right:12px" nowrap>{escape(str(key))}</td>'
                f"<td>{escape(str(value))}</td></tr>"
            )
        parts.append("</table>")
    return "".join(parts)


def report_text(report: ProgramReport) -> str:
    lines = [report.name, "", "[判断材料]"]
    lines += [f"{SEVERITY_LABEL[note.severity]}: {note.text}" for note in report.notes] or ["特に気になる点はありません。"]
    for title, rows in report_sections(report):
        lines += ["", f"[{title}]"]
        lines += [f"{key}: {value}" for key, value in rows]
    return "\n".join(lines)
