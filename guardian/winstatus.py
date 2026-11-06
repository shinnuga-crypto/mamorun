"""Windows の防御機能の状態を読むだけのモジュール。設定は変更しない。

既知のマルウェアの検出などは Defender に任せる方針なので、それが実際に働いているかを見えるようにする。
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

OK = "ok"
WARN = "warn"
INFO = "info"
ASR_ACTIONS = {0: "オフ", 1: "ブロック", 2: "監査のみ", 6: "警告"}
# 状態の確認に使う主なASRルール（Microsoft Learn の参照ページのGUID）
ASR_RULES = {
    "01443614-cd74-433a-b99e-2ecdc07bfc25": "未知の実行ファイルを止める（普及度、経過時間、信頼リスト）",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "LSASSからの資格情報の窃取を止める",
    "56a863a9-875e-4185-98a7-b882c64b5ce5": "悪用される脆弱な署名済みドライバーを止める",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Officeアプリが子プロセスを作るのを止める",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "難読化されたスクリプトを止める",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": "WMIによる永続化を止める",
}
SAC_STATES = {0: "オフ", 1: "オン（強制）", 2: "評価モード"}
_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$s = Get-MpComputerStatus
$p = Get-MpPreference
$c = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
[pscustomobject]@{
  available = [bool]$s
  mode = $s.AMRunningMode
  antivirus = $s.AntivirusEnabled
  realtime = $s.RealTimeProtectionEnabled
  behavior = $s.BehaviorMonitorEnabled
  tamper = $s.IsTamperProtected
  maps = $p.MAPSReporting
  cfa = $p.EnableControlledFolderAccess
  network = $p.EnableNetworkProtection
  asrIds = @($p.AttackSurfaceReductionRules_Ids)
  asrActions = @($p.AttackSurfaceReductionRules_Actions)
  sac = $c.VerifiedAndReputablePolicyState
} | ConvertTo-Json -Compress
"""


@dataclass(frozen=True)
class StatusRow:
    label: str
    state: str
    level: str
    note: str = ""


def _switch(value) -> str:
    return "オン" if value else "オフ"


def build_rows(data: dict) -> list[StatusRow]:
    """読み取った値を、利用者に見せる行にする。分からない項目は「確認できず」とする。"""
    if not data.get("available"):
        return [StatusRow("Microsoft Defender", "確認できず", WARN, "状態を読めません。他のウイルス対策を使っている場合があります")]
    rows: list[StatusRow] = []
    mode = str(data.get("mode") or "不明")
    active = mode.lower() == "normal"
    rows.append(StatusRow(
        "Defender の動作", mode, OK if active else WARN,
        "" if active else "主に動いていません。ASRと「フォルダーの保護」が働かない可能性があります",
    ))
    rows.append(StatusRow("リアルタイム保護", _switch(data.get("realtime")), OK if data.get("realtime") else WARN))
    rows.append(StatusRow("振る舞いの監視", _switch(data.get("behavior")), OK if data.get("behavior") else WARN))
    rows.append(StatusRow("改ざん防止", _switch(data.get("tamper")), OK if data.get("tamper") else WARN))
    maps = data.get("maps")
    rows.append(StatusRow(
        "クラウド保護", "確認できず" if maps is None else _switch(maps), OK if maps else WARN,
        "「未知の実行ファイルを止める」ルールに必要です",
    ))
    cfa = data.get("cfa")
    rows.append(StatusRow(
        "フォルダーの保護（ランサムウェア対策）", {0: "オフ", 1: "オン", 2: "監査のみ"}.get(cfa, "確認できず"),
        OK if cfa == 1 else INFO,
    ))
    rows.append(StatusRow(
        "ネットワーク保護", {0: "オフ", 1: "オン", 2: "監査のみ"}.get(data.get("network"), "確認できず"),
        OK if data.get("network") == 1 else INFO,
    ))
    ids = [str(item).lower() for item in data.get("asrIds") or [] if item]
    actions = data.get("asrActions") or []
    current = dict(zip(ids, actions))
    for guid, label in ASR_RULES.items():
        action = current.get(guid, 0)
        rows.append(StatusRow(
            f"ASR: {label}", ASR_ACTIONS.get(action, str(action)), OK if action == 1 else INFO,
        ))
    sac = data.get("sac")
    rows.append(StatusRow(
        "Smart App Control", SAC_STATES.get(sac, "確認できず"), OK if sac == 1 else INFO,
        "署名のない未知のプログラムを実行前に止めます",
    ))
    return rows


def read_status(timeout: float = 30.0) -> dict:
    """PowerShell で状態を読む。読むだけで、失敗しても例外を出さない。"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _SCRIPT],
            capture_output=True, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return json.loads(result.stdout.decode("utf-8", "replace") or "{}")
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}
