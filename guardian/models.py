"""監視エンジンとUIで共有するデータ型。"""
from __future__ import annotations

from dataclasses import dataclass, field

LOW = "low"
MEDIUM = "medium"
HIGH = "high"
LEVEL_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}
LEVEL_LABEL = {LOW: "低", MEDIUM: "中", HIGH: "高"}


@dataclass(frozen=True)
class Conn:
    """TCP接続表の1行。"""

    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str  # LISTEN / SYN_SENT / SYN_RCVD / ESTABLISHED / CLOSING / UNKNOWN / OTHER
    pid: int


@dataclass
class ProcFacts:
    """危険度判定に使うプロセス情報。取得できない項目は None。"""

    pid: int
    created: int
    name: str
    path: str | None = None
    parent_name: str | None = None
    cmdline: str | None = None
    signature: str = "unknown"  # valid / unsigned / invalid / unknown
    dev_tool: str | None = None  # シェルの起動元が、署名を確かめた開発ツールのとき、その名前


@dataclass(frozen=True)
class Context:
    """判定対象の接続に関する状況。"""

    direction: str  # outbound / inbound / listen
    remote_port: int = 0
    local_port: int = 0
    first_seen: bool = False
    distinct_ips_60s: int = 0
    beacon: bool = False


@dataclass(frozen=True)
class Reason:
    code: str
    points: int
    text: str


@dataclass
class Assessment:
    score: int
    level: str
    reasons: list[Reason] = field(default_factory=list)


@dataclass
class Alert:
    id: int
    at: float
    proc: ProcFacts
    conn: Conn | None
    direction: str
    assessment: Assessment
    # suspended / blocked / ask / observe / protected / suspend_failed / recovered
    action: str
    disconnected: int = 0
    gate_app: str | None = None  # 送信前の遮断で止めた場合のWFPアプリID


@dataclass(frozen=True)
class BlockedConnect:
    """送信前の遮断で止めた接続1回分。"""

    app_id: str  # \device\harddiskvolumeN\... 形式（小文字）
    remote_ip: str
    remote_port: int
    protocol: int  # 6=TCP / 17=UDP
    at: float
