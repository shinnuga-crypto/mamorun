"""マスコットの見た目。assets/mascot の画像を優先し、無ければ仮キャラを描く。"""
from __future__ import annotations

import math
import re
import sys
from pathlib import Path

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap, QPolygonF

STATES = ("idle", "watch", "alert", "sleep", "observe", "down")
STATE_LABEL = {
    "idle": "見守り中",
    "watch": "確認待ち",
    "alert": "停止中",
    "sleep": "休憩中",
    "observe": "観察モード",
    "down": "監視が止まっています",
}
STATE_COLOR = {
    "idle": "#2fb59a",
    "watch": "#e8a33a",
    "alert": "#e0463f",
    "sleep": "#7f8fa8",
    "observe": "#4f8fe0",
    "down": "#4a4f58",
}
PLACEHOLDER_ASPECT = 200 / 270
FRAME_SECONDS = 0.5


def default_art_root() -> Path:
    """絵の置き場所。EXEの隣に assets\\mascot があれば差し替え用として優先し、なければ同梱の絵を使う。"""
    if not getattr(sys, "frozen", False):
        return Path(__file__).resolve().parent.parent / "assets" / "mascot"
    beside = Path(sys.executable).resolve().parent / "assets" / "mascot"
    return beside if beside.is_dir() else Path(sys._MEIPASS) / "assets" / "mascot"


class MascotArt:
    """画像の読み込みと状態ごとのコマ選択を担当する。

    置ける名前は <状態>.png、または連番の <状態>_1.png, <状態>_2.png ...（0.5秒ごとに切替）。
    idle 以外が無い場合は idle の画像を使い、状態はランプの色で示す。
    """

    def __init__(self, folder: str | Path):
        self.folder = Path(folder)
        self.frames: dict[str, list[QPixmap]] = {}
        self.reload()

    def set_folder(self, folder: str | Path) -> int:
        self.folder = Path(folder)
        return self.reload()

    def reload(self) -> int:
        self.frames = {}
        for state in STATES:
            pattern = re.compile(rf"^{state}(?:_(\d+))?\.png$", re.IGNORECASE)
            found: list[tuple[int, Path]] = []
            if self.folder.is_dir():
                for file in self.folder.iterdir():
                    match = pattern.match(file.name)
                    if match:
                        found.append((int(match.group(1) or 0), file))
            pixmaps = [QPixmap(str(path)) for _, path in sorted(found, key=lambda item: item[0])]
            pixmaps = [p for p in pixmaps if not p.isNull()]
            if pixmaps:
                self.frames[state] = pixmaps
        return sum(len(v) for v in self.frames.values())

    @property
    def has_images(self) -> bool:
        return bool(self.frames)

    def aspect(self) -> float:
        all_frames = [p for frames in self.frames.values() for p in frames]
        if not all_frames:
            return PLACEHOLDER_ASPECT
        return max(p.width() / p.height() for p in all_frames)

    def frame(self, state: str, seconds: float) -> QPixmap | None:
        frames = self.frames.get(state) or self.frames.get("idle")
        if not frames:
            frames = next(iter(self.frames.values()), None)
        if not frames:
            return None
        return frames[int(seconds / FRAME_SECONDS) % len(frames)]


def draw_placeholder(p: QPainter, state: str, seconds: float, width: float, height: float) -> None:
    """画像が届くまでの仮キャラ。盾の体で立っている見張り番。設計サイズ 200x270。"""
    p.save()
    scale = min(width / 200, height / 270)
    p.translate((width - 200 * scale) / 2, height - 270 * scale)
    p.scale(scale, scale)
    color = QColor(STATE_COLOR.get(state, STATE_COLOR["idle"]))
    dark = color.darker(145)
    outline = QPen(QColor("#253044"), 4)

    # 足元の影
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(0, 0, 0, 55))
    p.drawEllipse(QRectF(48, 254, 104, 13))

    # 脚とブーツ
    p.setPen(outline)
    p.setBrush(QColor("#39465e"))
    p.drawRoundedRect(QRectF(70, 205, 22, 42), 8, 8)
    p.drawRoundedRect(QRectF(108, 205, 22, 42), 8, 8)
    p.setBrush(dark)
    p.drawRoundedRect(QRectF(60, 238, 38, 20), 9, 9)
    p.drawRoundedRect(QRectF(102, 238, 38, 20), 9, 9)

    # 腕（警告中は「止まれ」と両手を上げる）
    p.setBrush(color.lighter(112))
    raised = state in ("alert", "down")
    if raised:
        p.drawRoundedRect(QRectF(10, 62, 24, 74), 12, 12)
        p.drawRoundedRect(QRectF(166, 62, 24, 74), 12, 12)
    else:
        p.drawRoundedRect(QRectF(18, 108, 24, 70), 12, 12)
        p.drawRoundedRect(QRectF(158, 108, 24, 70), 12, 12)

    # アンテナ
    p.setPen(QPen(QColor("#253044"), 5, cap=Qt.PenCapStyle.RoundCap))
    p.drawLine(QPointF(100, 34), QPointF(100, 14))
    glow = 0.5 + 0.5 * math.sin(seconds * (9 if state == "alert" else 2.5))
    lamp = QColor(color.lighter(130))
    lamp.setAlpha(int(120 + 135 * glow))
    p.setPen(outline)
    p.setBrush(lamp)
    p.drawEllipse(QPointF(100, 11), 9, 9)

    # 盾の体
    body = QPainterPath()
    body.moveTo(100, 30)
    body.cubicTo(128, 44, 152, 46, 172, 44)
    body.cubicTo(178, 118, 168, 186, 100, 226)
    body.cubicTo(32, 186, 22, 118, 28, 44)
    body.cubicTo(48, 46, 72, 44, 100, 30)
    body.closeSubpath()
    gradient = QLinearGradient(0, 30, 0, 226)
    gradient.setColorAt(0, color.lighter(125))
    gradient.setColorAt(1, dark)
    p.setPen(outline)
    p.setBrush(gradient)
    p.drawPath(body)

    # 顔の窓
    p.setBrush(QColor("#fbfdff"))
    p.setPen(QPen(QColor("#253044"), 3))
    p.drawRoundedRect(QRectF(50, 66, 100, 76), 28, 28)

    _draw_face(p, state, seconds)

    # 胸の印
    p.setPen(QPen(QColor(255, 255, 255, 220), 6, cap=Qt.PenCapStyle.RoundCap, join=Qt.PenJoinStyle.RoundJoin))
    p.setBrush(Qt.BrushStyle.NoBrush)
    if state == "alert":
        p.drawLine(QPointF(90, 158), QPointF(110, 180))
        p.drawLine(QPointF(110, 158), QPointF(90, 180))
    elif state in ("watch", "down"):
        p.drawLine(QPointF(100, 155), QPointF(100, 172))
        p.drawPoint(QPointF(100, 185))
    else:
        path = QPainterPath(QPointF(87, 169))
        path.lineTo(97, 180)
        path.lineTo(115, 158)
        p.drawPath(path)

    # 止まれの札
    if state == "alert":
        points = []
        for i in range(8):
            angle = math.radians(22.5 + 45 * i)
            points.append(QPointF(22 + 22 * math.cos(angle), 44 + 22 * math.sin(angle)))
        p.setPen(QPen(QColor("#ffffff"), 3))
        p.setBrush(QColor("#d3322c"))
        p.drawPolygon(QPolygonF(points))
        font = QFont("Yu Gothic UI", 18, QFont.Weight.Bold)
        p.setFont(font)
        p.setPen(QColor("#ffffff"))
        p.drawText(QRectF(0, 22, 44, 44), Qt.AlignmentFlag.AlignCenter, "止")

    if state == "sleep":
        p.setPen(QColor("#5a6a85"))
        p.setFont(QFont("Yu Gothic UI", 15, QFont.Weight.Bold))
        rise = (seconds * 6) % 12
        p.drawText(QPointF(150, 38 - rise), "z")
        p.setFont(QFont("Yu Gothic UI", 20, QFont.Weight.Bold))
        p.drawText(QPointF(163, 24 - rise), "Z")
    p.restore()


def _draw_face(p: QPainter, state: str, seconds: float) -> None:
    ink = QColor("#253044")
    blink = (seconds % 4.3) < 0.14
    if state in ("sleep", "down") or blink:
        p.setPen(QPen(ink, 5, cap=Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawArc(QRectF(66, 94, 24, 14), 200 * 16, 140 * 16)
        p.drawArc(QRectF(110, 94, 24, 14), 200 * 16, 140 * 16)
    else:
        size = 13 if state == "alert" else 11
        look = 3 * math.sin(seconds * 0.7) if state in ("idle", "observe") else 0
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(ink)
        p.drawEllipse(QPointF(78 + look, 100), size * 0.8, size)
        p.drawEllipse(QPointF(122 + look, 100), size * 0.8, size)
        p.setBrush(QColor("#ffffff"))
        p.drawEllipse(QPointF(81 + look, 95), 3, 3)
        p.drawEllipse(QPointF(125 + look, 95), 3, 3)
    if state in ("alert", "watch"):
        p.setPen(QPen(ink, 5, cap=Qt.PenCapStyle.RoundCap))
        tilt = 8 if state == "alert" else 3
        p.drawLine(QPointF(66, 80), QPointF(88, 80 + tilt))
        p.drawLine(QPointF(134, 80), QPointF(112, 80 + tilt))
    p.setPen(QPen(ink, 4, cap=Qt.PenCapStyle.RoundCap))
    p.setBrush(Qt.BrushStyle.NoBrush)
    if state == "alert":
        p.setBrush(ink)
        p.drawEllipse(QRectF(91, 116, 18, 15))
    elif state in ("watch", "down"):
        p.drawLine(QPointF(90, 125), QPointF(110, 125))
    else:
        p.drawArc(QRectF(88, 110, 24, 18), 200 * 16, 140 * 16)
