"""マスコット、確認画面、見守り状況画面。"""
from __future__ import annotations

import math
import random
import time
from pathlib import Path

import itertools
import queue
import threading

from PyQt6.QtCore import QObject, QPoint, QPointF, QRectF, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QFrame, QHBoxLayout, QHeaderView, QLabel, QMenu, QMessageBox,
    QPushButton, QScrollArea, QSystemTrayIcon, QTableWidget, QTableWidgetItem, QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
)

from .art import STATE_COLOR, STATE_LABEL, MascotArt, draw_placeholder
from .characters import CHARACTERS, PLAIN, get_character
from .engine import KEEP, RESUME, SUSPEND, TERMINATE, TRUST, Engine, is_untrustable
from .models import HIGH, LEVEL_LABEL, MEDIUM, Alert, Assessment, Conn, ProcFacts, Reason
from .proginfo import ProgramInspector
from .servicewatch import SysmonWatch
from .startup import StartupTask
from .report import BAD, WARN, ProgramReport
from .reportview import report_html, report_text
from .winstatus import build_rows, read_status

STOP_CHECK_MS = 5000
ALERT_WIDTH = 680  # ボタン5個の文字が切れない幅
ALERT_SCREEN_MARGIN = 16
ALERT_TITLEBAR_RESERVE = 40  # 表示前はタイトルバーの高さが分からないので多めに見る
ALERT_MIN_BODY = 80
SIZES = {"小": 160, "中": 220, "大": 300}
DEFAULT_SIZE = "中"
SIDE_MARGIN = 10
TOP_MARGIN = 6
HEARTBEAT_LIMIT = 8.0
RELEASE_LOCK_SECONDS = 3
INSPECT_WORKERS = 2
DIRECTION_LABEL = {"outbound": "送信", "inbound": "外部から受信", "listen": "待ち受け"}
# 記録の一覧で使う（"exited" は終了後に検知したもの）
SIGNATURE_LABEL = {"valid": "あり（有効）", "unsigned": "なし", "invalid": "壊れている・失効", "unknown": "確認できず"}
EVENT_LABEL = {
    "suspended": "一時停止", "blocked": "送信前に遮断", "ask": "確認", "observe": "観察のみ", "protected": "保護対象（通知のみ）",
    "suspend_failed": "停止失敗", "recovered": "引き継ぎ", "exited": "終了後に検知",
}
DECISION_LABEL = {
    RESUME: "今回だけ許可", TRUST: "常に信頼", TERMINATE: "終了", SUSPEND: "止めた", KEEP: "止めたまま",
}
STYLE = """
QWidget#panel { background: #f6f8fb; }
QLabel#title { font-size: 17px; font-weight: 700; color: white; padding: 12px 14px; }
QLabel#key { color: #5c6880; }
QLabel#value { color: #1d2638; }
QPushButton { padding: 7px 12px; border: 1px solid #b9c2d2; border-radius: 6px; background: white; color: #1d2638; }
QPushButton:hover { background: #eef2f8; }
QPushButton:disabled { color: #9aa3b4; background: #eef0f4; }
QPushButton#danger { background: #d3322c; border-color: #b0261f; color: white; font-weight: 700; }
QPushButton#danger:hover { background: #bb2a24; }
QPushButton#danger:disabled { background: #eef0f4; border-color: #b9c2d2; color: #9aa3b4; font-weight: 400; }
QTableWidget { background: white; gridline-color: #e6eaf1; color: #1d2638; }
QHeaderView::section { background: #edf0f6; color: #1d2638; padding: 5px; border: 0; border-right: 1px solid #dde2eb; }
"""


class MascotWidget(QWidget):
    clicked = pyqtSignal()
    menu_requested = pyqtSignal(QPoint)
    moved = pyqtSignal()

    def __init__(self, art: MascotArt, size_name: str = DEFAULT_SIZE):
        super().__init__(None, Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.Tool)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.art = art
        self.state = "idle"
        self.size_name = size_name if size_name in SIZES else DEFAULT_SIZE
        self._start = time.monotonic()
        self._drag_from: QPoint | None = None
        self._dragged = False
        self._cache: dict[tuple[int, int], QPixmap] = {}
        self.apply_size()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.update)
        self._timer.start(33)

    def apply_size(self) -> None:
        """足元の位置を保ったまま大きさを変える。"""
        bottom_center = self.geometry().center().x(), self.geometry().bottom()
        had_position = self.isVisible()
        self._cache.clear()
        height = SIZES[self.size_name]
        width = int(height * self.art.aspect())
        self.setFixedSize(width + SIDE_MARGIN * 2, height + TOP_MARGIN)
        if had_position:
            self.move(bottom_center[0] - self.width() // 2, bottom_center[1] - self.height() + 1)

    def stand_on_taskbar(self) -> None:
        """定位置: メイン画面の右下、タスクバーの上に立つ。"""
        area = QApplication.primaryScreen().availableGeometry()
        self.move(area.right() - self.width() - 24, area.bottom() - self.height() + 1)

    def set_state(self, state: str) -> None:
        if state != self.state:
            self.state = state
            self.setToolTip(f"まもるん: {STATE_LABEL.get(state, state)}")

    def _scaled(self, pixmap: QPixmap, height: int) -> QPixmap:
        key = (pixmap.cacheKey(), height)
        if key not in self._cache:
            self._cache[key] = pixmap.scaledToHeight(height, Qt.TransformationMode.SmoothTransformation)
        return self._cache[key]

    def render_to(self, painter: QPainter, seconds: float) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        width, height = self.width(), self.height()
        art_height = height - TOP_MARGIN
        shake = 4 * math.sin(seconds * 34) if self.state == "alert" and (seconds % 1.6) < 0.45 else 0
        # 足元を固定したまま、呼吸するように少しだけ伸び縮みする
        breathe = 1.0
        if self.state not in ("alert", "down"):
            breathe = 1 + 0.012 * math.sin(seconds * (1.1 if self.state == "sleep" else 2.0))
        painter.save()
        painter.translate(width / 2 + shake, height)
        painter.scale(1.0, breathe)
        painter.translate(-width / 2, -height)
        pixmap = self.art.frame(self.state, seconds)
        if pixmap is None:
            painter.translate(SIDE_MARGIN, TOP_MARGIN)
            draw_placeholder(painter, self.state, seconds, width - SIDE_MARGIN * 2, art_height)
        else:
            scaled = self._scaled(pixmap, art_height)
            painter.drawPixmap((width - scaled.width()) // 2, height - scaled.height(), scaled)
        painter.restore()
        if pixmap is not None:
            self._draw_lamp(painter, seconds)

    def _draw_lamp(self, painter: QPainter, seconds: float) -> None:
        color = QColor(STATE_COLOR.get(self.state, STATE_COLOR["idle"]))
        radius = 7 + (1.5 * math.sin(seconds * 8) if self.state == "alert" else 0)
        painter.setPen(QPen(QColor("white"), 2))
        painter.setBrush(color)
        painter.drawEllipse(QPointF(self.width() - 12, 14), radius, radius)

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        self.render_to(painter, time.monotonic() - self._start)
        painter.end()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_from = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            self._dragged = False

    def mouseMoveEvent(self, event) -> None:
        if self._drag_from is not None and event.buttons() & Qt.MouseButton.LeftButton:
            target = event.globalPosition().toPoint() - self._drag_from
            if (target - self.pos()).manhattanLength() > 3:
                self._dragged = True
            if self._dragged:
                self.move(target)
                self.moved.emit()

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            if not self._dragged:
                self.clicked.emit()
            self._drag_from = None

    def contextMenuEvent(self, event) -> None:
        self.menu_requested.emit(event.globalPos())


class SpeechBubble(QWidget):
    """マスコットの吹き出し。入力フォーカスを奪わない。"""

    def __init__(self):
        super().__init__(
            None,
            Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.Tool
            | Qt.WindowType.WindowDoesNotAcceptFocus,
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 20)
        self.label = QLabel()
        self.label.setWordWrap(True)
        self.label.setStyleSheet("color: #1d2638;")
        self.label.setFixedWidth(230)
        layout.addWidget(self.label)
        self._hide_timer = QTimer(self)
        self._hide_timer.setSingleShot(True)
        self._hide_timer.timeout.connect(self.hide)

    def say(self, text: str, anchor: QWidget, seconds: float = 7) -> None:
        self.label.setText(text)
        self.adjustSize()
        area = (anchor.screen() or QApplication.primaryScreen()).availableGeometry()
        x = anchor.x() + anchor.width() // 2 - self.width() // 2
        y = anchor.y() - self.height() + 8
        self.move(max(area.left(), min(x, area.right() - self.width())), max(area.top(), y))
        self.show()
        self._hide_timer.start(int(seconds * 1000))

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        body = QRectF(1, 1, self.width() - 2, self.height() - 14)
        path = QPainterPath()
        path.addRoundedRect(body, 12, 12)
        center = self.width() / 2
        tail = QPainterPath(QPointF(center - 9, body.bottom() - 1))
        tail.lineTo(center, self.height() - 2)
        tail.lineTo(center + 9, body.bottom() - 1)
        tail.closeSubpath()
        painter.setPen(QPen(QColor("#253044"), 1.5))
        painter.setBrush(QColor("#ffffff"))
        painter.drawPath(path.united(tail))
        painter.end()


class AlertWindow(QWidget):
    """検知内容を示して判断を求める画面。

    誤操作で解除しないよう、フォーカスを奪わず、既定ボタンを作らず、
    止めた通信を再開するボタンは数秒待たないと押せない。
    """

    decided = pyqtSignal(int, str)
    details_requested = pyqtSignal(object)

    def __init__(self):
        super().__init__(None, Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.Tool)
        self.setObjectName("panel")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setWindowTitle("まもるんからの確認")
        self.setStyleSheet(STYLE)
        self.setFixedWidth(ALERT_WIDTH)
        self.alert: Alert | None = None
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 12)
        self._layout.setSpacing(8)
        self._content: QWidget | None = None
        self._locked: list[tuple[QPushButton, str]] = []
        self._remaining = 0
        self._lock_timer = QTimer(self)
        self._lock_timer.timeout.connect(self._tick_lock)

    def show_alert(self, alert: Alert, others: int = 0, demo: bool = False) -> None:
        self.alert = alert
        if self._content is not None:
            self._layout.removeWidget(self._content)
            self._content.hide()  # deleteLater は後から効くので、新しい内容と重ならないよう先に隠す
            self._content.deleteLater()
        self._locked = []
        self._content = self._build(alert, others, demo)
        self._layout.addWidget(self._content)
        self._start_lock()
        area = QApplication.primaryScreen().availableGeometry()
        self.fit_to_screen(area)
        self.show()
        self.raise_()
        self.fit_to_screen(area)  # タイトルバーの高さは表示してから分かる

    def fit_to_screen(self, area) -> None:
        """画面の上に寄せて、ボタンまで必ず収める。入りきらない分は説明の部分だけをスクロールする。"""
        wanted = self._inner.layout().totalHeightForWidth(self.width())
        self._scroll.setFixedHeight(wanted)
        self._content.layout().invalidate()
        self._layout.invalidate()
        natural = self._layout.totalHeightForWidth(self.width())
        chrome = max(self.frameGeometry().height() - self.height(), 0) or ALERT_TITLEBAR_RESERVE
        height = min(natural, area.height() - ALERT_SCREEN_MARGIN * 2 - chrome)
        self._scroll.setFixedHeight(max(ALERT_MIN_BODY, wanted - (natural - height)))
        self.setFixedHeight(height)
        self.move(area.right() - self.width() - 24, area.top() + ALERT_SCREEN_MARGIN)

    def _build(self, alert: Alert, others: int, demo: bool) -> QWidget:
        box = QWidget()
        root = QVBoxLayout(box)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)
        title_text, detail, color = self._headline(alert)
        title = QLabel(("【試験表示】" if demo else "") + title_text)
        title.setObjectName("title")
        title.setWordWrap(True)
        title.setStyleSheet(f"background: {color};")
        root.addWidget(title)

        self._inner = QWidget()
        self._inner.setObjectName("panel")
        body = QVBoxLayout(self._inner)
        body.setContentsMargins(14, 0, 14, 0)
        body.setSpacing(6)
        detail_label = QLabel(detail)
        detail_label.setWordWrap(True)
        detail_label.setObjectName("value")
        body.addWidget(detail_label)

        facts = alert.proc
        pairs = [
            ("プログラム", f"{facts.name}（PID {facts.pid}）" if facts.pid else f"{facts.name}（終了済み）"),
            ("場所", facts.path or "取得できません"),
            ("署名", SIGNATURE_LABEL.get(facts.signature, facts.signature)),
        ]
        if alert.conn is not None:
            if alert.direction == "listen":
                pairs.append(("通信", f"ポート {alert.conn.local_port} で待ち受け"))
            elif alert.direction == "inbound":
                pairs.append(("通信", f"{alert.conn.remote_ip} からポート {alert.conn.local_port} へ接続"))
            else:
                pairs.append(("通信", f"{alert.conn.remote_ip} のポート {alert.conn.remote_port} へ接続"))
        if facts.parent_name:
            pairs.append(("起動元", facts.parent_name))
        pairs.append(("危険度", f"{alert.assessment.score} / 100（{LEVEL_LABEL[alert.assessment.level]}）"))
        for key, value in pairs:
            row = QHBoxLayout()
            key_label = QLabel(key)
            key_label.setObjectName("key")
            key_label.setFixedWidth(72)
            key_label.setAlignment(Qt.AlignmentFlag.AlignTop)
            value_label = QLabel(value)
            value_label.setObjectName("value")
            value_label.setWordWrap(True)
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            row.addWidget(key_label)
            row.addWidget(value_label, 1)
            body.addLayout(row)

        heading = QLabel("そう判断した理由")
        heading.setObjectName("key")
        heading.setContentsMargins(0, 6, 0, 0)
        body.addWidget(heading)
        for reason in sorted(alert.assessment.reasons, key=lambda r: -r.points):
            sign = "+" if reason.points >= 0 else "−"
            item = QLabel(f"{sign}{abs(reason.points)}　{reason.text}")
            item.setObjectName("value")
            item.setWordWrap(True)
            body.addWidget(item)
        if others:
            more = QLabel(f"ほかに {others} 件の確認があります。")
            more.setObjectName("key")
            body.addWidget(more)
        self._scroll = QScrollArea()
        self._scroll.setWidget(self._inner)
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        root.addWidget(self._scroll)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #dde2eb;")
        root.addWidget(line)
        buttons = QHBoxLayout()
        buttons.setContentsMargins(14, 0, 14, 0)
        details = QPushButton("詳しく調べる")
        details.setAutoDefault(False)
        details.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        details.clicked.connect(lambda _checked=False: self.details_requested.emit(self.alert))
        buttons.addWidget(details)
        for label, decision, kind in self._button_specs(alert):
            button = QPushButton(label)
            button.setAutoDefault(False)
            button.setDefault(False)
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            if kind == "danger":
                button.setObjectName("danger")
            if kind == "locked":
                button.setEnabled(False)
                self._locked.append((button, label))
            button.clicked.connect(lambda _checked=False, d=decision: self._choose(d))
            buttons.addWidget(button)
        root.addLayout(buttons)
        return box

    @staticmethod
    def _headline(alert: Alert) -> tuple[str, str, str]:
        name = alert.proc.name
        action = alert.action
        if alert.direction == "trap" and action == "blocked":
            return (
                "読まれたよ！外へは出させないよ",
                f"{name} は署名つきですが、普通は触らないファイルを読みました。正規のソフトの場合もあるので止めず、外への新しい接続だけを封じています。",
                STATE_COLOR["alert"],
            )
        if alert.direction == "trap" and action == "ask":
            return (
                "読まれたよ！確認して",
                f"{name} は署名つきですが、普通は触らないファイルを読みました。送信前の遮断が無効なので、通信は止まっていません。心当たりがなければ止めてください。",
                STATE_COLOR["alert"],
            )
        if alert.direction == "trap" and action == "suspended":
            return (
                "罠に触った！止めたよ",
                f"{name} が、普通のプログラムは触らない罠のファイルを読みました。一時停止しています。情報窃取を疑ってください。",
                STATE_COLOR["alert"],
            )
        if action == "exited":
            if alert.direction == "tamper":
                return (
                    "記録が消されたよ！",
                    "Sysmonの記録が消された形跡があります。心当たりがなければ、感染を疑ってください。",
                    STATE_COLOR["alert"],
                )
            return (
                "もう終わったプログラムだけど、怪しかったよ",
                f"{name} はすでに終了しているので止められません。起きたことを確認してください。",
                STATE_COLOR["alert"],
            )
        if alert.direction == "persistence":
            if action == "suspended":
                return (
                    "待って！自動起動の登録を見つけたよ",
                    f"{name} がWindows起動時に動く登録をしたので、一時停止しました。登録自体はまだ残っています。",
                    STATE_COLOR["alert"],
                )
            if action == "ask":
                return (
                    "自動起動の登録、心当たりある？",
                    f"{name} がWindows起動時に動く登録をしました。登録は残っています。",
                    STATE_COLOR["watch"],
                )
        if alert.direction == "launch":
            if action == "suspended":
                return (
                    "待って！起動を止めたよ",
                    f"{name} の起動が感染の入口に似ているので、一時停止しました。心当たりがなければ、止めたまま調べるか終了させてください。",
                    STATE_COLOR["alert"],
                )
            if action == "ask":
                return (
                    "この起動、大丈夫？",
                    f"{name} の起動が少し気になります。プログラムは動いたままです。",
                    STATE_COLOR["watch"],
                )
        if action == "suspended":
            extra = f"接続 {alert.disconnected} 件も切断しました。" if alert.disconnected else ""
            return (
                "待って！通信を止めたよ",
                f"{name} を一時停止しました。{extra}心当たりがなければ、止めたまま確認するか終了させてください。",
                STATE_COLOR["alert"],
            )
        if action == "blocked":
            return (
                "待って！送信する前に止めたよ",
                f"{name} の外部への接続を、送信前に止めています。プログラム自体は動いています。心当たりがなければ、止めたまま確認するか終了させてください。",
                STATE_COLOR["alert"],
            )
        if action == "recovered":
            return (
                "止めたままのプログラムがあるよ",
                f"{name} は前回のマスコット終了時から一時停止したままです。",
                STATE_COLOR["alert"],
            )
        if action == "suspend_failed":
            return (
                "止めようとしたけど止められなかった！",
                f"{name} を一時停止できません（権限が足りない可能性があります）。通信は続いている可能性があります。",
                STATE_COLOR["alert"],
            )
        if action == "protected":
            return (
                "危険な可能性があるよ",
                f"{name} はWindowsに必要なプログラムなので、止めずにお知らせだけします。",
                STATE_COLOR["alert"],
            )
        if action == "observe":
            return (
                "止める基準に達したよ（観察モード）",
                f"観察モードなので {name} は止めていません。通常モードならここで一時停止します。",
                STATE_COLOR["observe"],
            )
        return (
            "ちょっと確認させて",
            f"{name} の通信が少し気になります。通信は止めていません。心当たりはありますか？",
            STATE_COLOR["watch"],
        )

    @staticmethod
    def _button_specs(alert: Alert) -> list[tuple[str, str, str]]:
        can_trust = bool(alert.proc.path) and not is_untrustable(alert.proc.path)
        if alert.action in ("suspended", "recovered", "blocked"):
            specs = [("止めたままにする", KEEP, "normal"), ("終了させる", TERMINATE, "danger"),
                     ("今回だけ再開", RESUME, "locked")]
            if can_trust:
                specs.append(("常に信頼", TRUST, "locked"))
            return specs
        if alert.action in ("protected", "observe", "exited"):
            return [("確認した", RESUME, "normal")]
        specs = [("今回は許可", RESUME, "normal")]
        if alert.action == "ask":
            specs.append(("止める", SUSPEND, "danger"))
        specs.append(("終了させる", TERMINATE, "danger" if alert.action == "suspend_failed" else "normal"))
        if can_trust:
            specs.append(("常に信頼", TRUST, "normal"))
        return specs

    def _start_lock(self) -> None:
        self._lock_timer.stop()
        if not self._locked:
            return
        self._remaining = RELEASE_LOCK_SECONDS
        self._paint_lock()
        self._lock_timer.start(1000)

    def _tick_lock(self) -> None:
        self._remaining -= 1
        self._paint_lock()
        if self._remaining <= 0:
            self._lock_timer.stop()

    def _paint_lock(self) -> None:
        for button, label in self._locked:
            if self._remaining > 0:
                button.setText(f"{label}（{self._remaining}）")
                button.setEnabled(False)
            else:
                button.setText(label)
                button.setEnabled(True)

    def _choose(self, decision: str) -> None:
        if self.alert is None:
            return
        if decision == TERMINATE:
            answer = QMessageBox.question(
                self, "プログラムの終了",
                f"{self.alert.proc.name} を強制終了します。保存していない内容は失われます。よろしいですか？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.decided.emit(self.alert.id, decision)

    def closeEvent(self, event) -> None:
        # ×で閉じても判断したことにはならない。止めたままマスコットから開き直せる。
        if self.alert is not None:
            self.decided.emit(self.alert.id, KEEP)
        event.accept()


class DetailWindow(QWidget):
    """プログラムの調査結果。止めるかどうかの判断材料を出す。"""

    operation_requested = pyqtSignal(int, str)
    reinspect_requested = pyqtSignal(object)

    def __init__(self):
        super().__init__(None, Qt.WindowType.Window | Qt.WindowType.WindowStaysOnTopHint)
        self.setObjectName("panel")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setWindowTitle("まもるん プログラムの調査")
        self.setStyleSheet(STYLE)
        self.resize(760, 680)
        self.report: ProgramReport | None = None
        layout = QVBoxLayout(self)
        self.browser = QTextBrowser()
        # 調査対象の文字列を信用しないので、リンクも外部の内容も開かない
        self.browser.setOpenLinks(False)
        self.browser.setOpenExternalLinks(False)
        self.browser.setStyleSheet("background: white; color: #1d2638;")
        layout.addWidget(self.browser, 1)
        buttons = QHBoxLayout()
        self.suspend_button = self._button("一時停止", lambda: self._operate(SUSPEND))
        self.resume_button = self._button("再開", lambda: self._operate(RESUME))
        self.terminate_button = self._button("終了させる", self._confirm_terminate, danger=True)
        self.again_button = self._button("調べ直す", lambda: self.reinspect_requested.emit(self.report))
        self.copy_button = self._button("内容をコピー", self._copy)
        for button in (self.suspend_button, self.resume_button, self.terminate_button):
            buttons.addWidget(button)
        buttons.addStretch(1)
        buttons.addWidget(self.again_button)
        buttons.addWidget(self.copy_button)
        layout.addLayout(buttons)

    @staticmethod
    def _button(label: str, callback, danger: bool = False) -> QPushButton:
        button = QPushButton(label)
        button.setAutoDefault(False)
        button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        if danger:
            button.setObjectName("danger")
        button.clicked.connect(lambda _checked=False: callback())
        return button

    def show_loading(self, name: str) -> None:
        self.report = None
        self.browser.setPlainText(f"{name} を調べています…")
        self._update_buttons()
        self.show()
        self.raise_()

    def show_report(self, report: ProgramReport) -> None:
        self.report = report
        position = self.browser.verticalScrollBar().value()
        self.browser.setHtml(report_html(report))
        self.browser.verticalScrollBar().setValue(position)
        self._update_buttons()
        self.show()
        self.raise_()

    def _update_buttons(self) -> None:
        process = self.report.process if self.report else None
        self.suspend_button.setEnabled(bool(process) and not process.suspended)
        self.resume_button.setEnabled(bool(process) and process.suspended)
        self.terminate_button.setEnabled(bool(process))
        self.again_button.setEnabled(self.report is not None)
        self.copy_button.setEnabled(self.report is not None)

    def _operate(self, operation: str) -> None:
        if self.report and self.report.process:
            self.operation_requested.emit(self.report.process.pid, operation)

    def _confirm_terminate(self) -> None:
        if not (self.report and self.report.process):
            return
        answer = QMessageBox.question(
            self, "プログラムの終了",
            f"{self.report.name} を強制終了します。保存していない内容は失われます。よろしいですか？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._operate(TERMINATE)

    def _copy(self) -> None:
        if self.report:
            QApplication.clipboard().setText(report_text(self.report))


class Dashboard(QWidget):
    def __init__(self, engine: Engine, status_text, programs=None, open_program=None, defense=None):
        super().__init__(None, Qt.WindowType.Window)
        self.engine = engine
        self.defense = defense or (lambda: [])
        self.status_text = status_text
        self.programs = programs or (lambda: [])
        self.open_program = open_program or (lambda _pid: None)
        self.setObjectName("panel")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.setWindowTitle("まもるん 見守り状況")
        self.setStyleSheet(STYLE)
        self.resize(860, 520)
        layout = QVBoxLayout(self)
        self.status = QLabel()
        self.status.setObjectName("value")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.program_table = self._table(["プログラム", "PID", "署名", "署名者", "入手元", "接続", "危険", "注意", "主な判断材料"])
        self.program_table.cellDoubleClicked.connect(lambda row, _col: self._open_row(self.program_table, row))
        self.tabs.addTab(self.program_table, "外部へつなぐプログラム")
        self.conn_table = self._table(["プログラム", "PID", "向き", "相手", "ポート", "状態", "危険度"])
        self.conn_table.cellDoubleClicked.connect(lambda row, _col: self._open_row(self.conn_table, row))
        self.tabs.addTab(self.conn_table, "今の通信")
        self.history_table = self._table(["日時", "内容", "プログラム", "相手", "危険度", "理由"])
        self.tabs.addTab(self.history_table, "検知の記録")
        trust_page = QWidget()
        trust_layout = QVBoxLayout(trust_page)
        self.trust_table = self._table(["プログラム", "登録日時"])
        trust_layout.addWidget(self.trust_table)
        remove = QPushButton("選んだアプリの信頼を取り消す")
        remove.clicked.connect(self._remove_trust)
        trust_layout.addWidget(remove, 0, Qt.AlignmentFlag.AlignRight)
        self.tabs.addTab(trust_page, "信頼済みアプリ")
        defense_page = QWidget()
        defense_layout = QVBoxLayout(defense_page)
        note = QLabel("既知のマルウェアの検出などは Defender の役割です。働いているかをここで確かめられます（読み取りのみ）。")
        note.setObjectName("key")
        note.setWordWrap(True)
        defense_layout.addWidget(note)
        self.defense_table = self._table(["機能", "状態", "補足"])
        defense_layout.addWidget(self.defense_table)
        self.defense_page = defense_page
        self.tabs.addTab(defense_page, "Windowsの防御")
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self.tabs.currentChanged.connect(lambda _index: self.refresh())

    @staticmethod
    def _table(headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def showEvent(self, event) -> None:
        self.refresh()
        self._timer.start(1500)
        super().showEvent(event)

    def hideEvent(self, event) -> None:
        self._timer.stop()
        super().hideEvent(event)

    @staticmethod
    def _fill(table: QTableWidget, rows: list[list[str]], colors: list[str | None] | None = None) -> None:
        selected = table.currentRow()
        table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, text in enumerate(row):
                item = QTableWidgetItem(text)
                if colors and colors[r]:
                    item.setBackground(QColor(colors[r]))
                table.setItem(r, c, item)
        if 0 <= selected < len(rows):
            table.setCurrentCell(selected, 0)

    def refresh(self) -> None:
        self.status.setText(self.status_text())
        page = self.tabs.currentWidget()
        if page is self.defense_page:
            rows = self.defense()
            tint = {"warn": "#fdeecd"}
            self._fill(self.defense_table, [[r.label, r.state, r.note] for r in rows], [tint.get(r.level) for r in rows])
        elif page is self.program_table:
            self._fill_programs()
        elif page is self.conn_table:
            rows = sorted(self.engine.rows(), key=lambda r: (-r["score"], r["name"].lower()))
            tint = {HIGH: "#fbd9d6", MEDIUM: "#fdeecd"}
            self._fill(
                self.conn_table,
                [[
                    r["name"] + ("（停止中）" if r["suspended"] else ""), str(r["pid"]),
                    DIRECTION_LABEL.get(r["direction"], r["direction"]),
                    "" if r["direction"] == "listen" else r["remote"],
                    str(r["local_port"] if r["direction"] != "outbound" else r["remote_port"]),
                    r["state"], f'{r["score"]}（{LEVEL_LABEL[r["level"]]}）',
                ] for r in rows],
                [tint.get(r["level"]) for r in rows],
            )
        elif page is self.history_table:
            rows = []
            for event in self.engine.store.recent_events():
                if event.get("event") == "detected":
                    rows.append([
                        event.get("time", ""), EVENT_LABEL.get(event.get("action"), event.get("action", "")),
                        event.get("name", ""), event.get("remote", ""), str(event.get("score", "")),
                        " / ".join(event.get("reasons", [])),
                    ])
                elif event.get("event") == "decision":
                    rows.append([
                        event.get("time", ""), "判断: " + DECISION_LABEL.get(event.get("decision"), event.get("decision", "")),
                        event.get("name", ""), "", "", "",
                    ])
                elif event.get("event") in ("trap_hit", "watch_read"):
                    label = "罠に触れた" if event["event"] == "trap_hit" else "認証ファイルの読み取り"
                    rows.append([event.get("time", ""), label, event.get("name", ""), "", "", event.get("trap", "")])
            self._fill(self.history_table, rows)
        else:
            self._fill(self.trust_table, [[e.get("path", ""), e.get("added", "")] for e in self.engine.store.trust_entries()])

    def _fill_programs(self) -> None:
        entries = sorted(
            self.programs(),
            key=lambda e: (-(e["report"].count(BAD) if e["report"] else 0), -(e["report"].count(WARN) if e["report"] else 0), e["name"].lower()),
        )
        rows, colors = [], []
        for entry in entries:
            report = entry["report"]
            if report is None:
                rows.append([entry["name"], str(entry["pid"]), "調査中…", "", "", str(entry["connections"]), "", "", ""])
                colors.append(None)
                continue
            first = next((note.text for note in report.notes if note.severity in (BAD, WARN)), "")
            origin = report.motw.get("HostUrl") or report.motw.get("ReferrerUrl") or (f'ゾーン {report.motw["ZoneId"]}' if report.motw.get("ZoneId") else "")
            rows.append([
                report.name, str(entry["pid"]), report.signature_summary, report.signer_name, origin,
                str(entry["connections"]), str(report.count(BAD)), str(report.count(WARN)), first,
            ])
            colors.append("#fbd9d6" if report.count(BAD) else "#fdeecd" if report.count(WARN) else None)
        self._fill(self.program_table, rows, colors)

    def _open_row(self, table: QTableWidget, row: int) -> None:
        item = table.item(row, 1)
        if item is not None and item.text().isdigit():
            self.open_program(int(item.text()))

    def _remove_trust(self) -> None:
        row = self.trust_table.currentRow()
        item = self.trust_table.item(row, 0) if row >= 0 else None
        if item is not None:
            self.engine.store.remove_trust(item.text())
            self.refresh()


class _Bridge(QObject):
    alert = pyqtSignal(object)
    inspected = pyqtSignal(object, object, bool)


def demo_alert() -> Alert:
    """通信にもプロセスにも触れない、見た目の確認用の警告。"""
    facts = ProcFacts(0, 0, "sample.exe", r"C:\Users\you\Downloads\sample.exe", "explorer.exe", None, "unsigned")
    assessment = Assessment(85, HIGH, [
        Reason("bad_port", 30, "遠隔操作やTorでよく使われるポート 4444 へ接続しています"),
        Reason("risky_path", 30, "一時フォルダやダウンロードなど、不審な場所から動いています"),
        Reason("unsigned", 15, "デジタル署名がありません"),
        Reason("new_app", 10, "このPCで初めて通信を確認したアプリです"),
    ])
    conn = Conn("192.168.1.2", 50000, "203.0.113.10", 4444, "ESTABLISHED", 0)
    return Alert(-1, time.time(), facts, conn, "outbound", assessment, "suspended")


class Controller(QObject):
    """エンジンと画面をつなぐ。"""

    def __init__(self, engine: Engine, art_root: str | Path, is_admin: bool):
        super().__init__()
        self.engine = engine
        self.store = engine.store
        self.is_admin = is_admin
        self.art_root = Path(art_root)
        self.character = get_character(self.store.settings.get("character"))
        self.mascot_hidden = self.store.settings.get("mascot_hidden") is True
        self.startup = StartupTask()
        self._startup_enabled = self.startup.is_enabled()
        self.sysmon_watch = SysmonWatch(self.store)
        self.guard = None  # 見張り役。main.py が渡す
        self._warnings: list[QMessageBox] = []
        self.art = MascotArt(self.art_folder)
        self.mascot = MascotWidget(self.art, self.store.settings.get("size", DEFAULT_SIZE))
        self.bubble = SpeechBubble()
        self.alert_window = AlertWindow()
        self._defense_rows: list = []
        self.dashboard = Dashboard(engine, self.status_text, self.program_entries, self.open_program, lambda: self._defense_rows)
        self.detail_window = DetailWindow()
        self.program_inspector = ProgramInspector()
        self._program_reports: dict[tuple[int, int], ProgramReport] = {}
        self._program_rows: dict[tuple[int, int], dict] = {}
        self._inspect_queued: set[tuple[int, int]] = set()
        self._inspect_queue: queue.PriorityQueue = queue.PriorityQueue()
        self._inspect_order = itertools.count()
        self._inspect_threads: list[threading.Thread] = []
        self._announced_paths: set[str] = set()
        self._kept: set[int] = set()
        self._demo_open = False
        self._quitting = False
        self._last_state = ""

        self._bridge = _Bridge()
        self._bridge.alert.connect(self.on_alert)
        engine.on_alert = self._bridge.alert.emit
        self._bridge.inspected.connect(self.on_inspected)
        self.alert_window.details_requested.connect(self.open_alert_details)
        self.detail_window.operation_requested.connect(self.on_detail_operation)
        self.detail_window.reinspect_requested.connect(self.reinspect)

        self.mascot.clicked.connect(self.on_mascot_click)
        self.mascot.menu_requested.connect(self.show_menu)
        self.mascot.moved.connect(self.save_position)
        self.alert_window.decided.connect(self.on_decided)

        self.menu = QMenu()
        self.tray = QSystemTrayIcon(self._tray_icon())
        self.tray.setToolTip("まもるん")
        self.tray.activated.connect(self._on_tray)
        self.tray.setContextMenu(self.menu)
        self.menu.aboutToShow.connect(self._build_menu)
        self._build_menu()

        self._state_timer = QTimer(self)
        self._state_timer.timeout.connect(self.update_state)
        self._state_timer.start(500)
        self._chat_timer = QTimer(self)
        self._chat_timer.timeout.connect(self._idle_chat)
        self._chat_timer.start(10 * 60 * 1000)

    def start(self) -> None:
        self._restore_position()
        if not self.mascot_hidden:
            self.mascot.show()
        self.tray.show()
        self.engine.start()
        self._ensure_inspector()
        threading.Thread(target=self._read_defense_status, name="guardian-defense", daemon=True).start()
        self._program_timer = QTimer(self)
        self._program_timer.timeout.connect(self.scan_programs)
        self._program_timer.start(1500)
        self.update_state()
        if self.engine.observe:
            self.say(self.line("start_observe"))
        elif self.is_admin:
            self.say(self.line("start"))
        else:
            self.say(self.line("start_no_admin"), 10)

    def start_stop_watch(self) -> None:
        self._stop_watch_timer = QTimer(self)
        self._stop_watch_timer.timeout.connect(self.check_stops)
        self._stop_watch_timer.start(STOP_CHECK_MS)
        self.check_stops()

    def check_stops(self) -> None:
        """Sysmonと見張り役が止められていないかを確かめる。"""
        change = self.sysmon_watch.check()
        if change == "stopped":
            self.store.log({"event": "sysmon_stopped"})
            self.warn(self.line("sysmon_stopped"), "Sysmonが止まりました。\n自分で止めたり削除したりしたのでなければ、不審なプログラムの仕業かもしれません。")
        elif change == "recovered":
            self.store.log({"event": "sysmon_recovered"})
            self.say(self.line("sysmon_back"))
        if self.guard is not None and self.guard.restart_if_stopped():
            self.store.log({"event": "guard_restarted"})
            self.say(self.line("guard_restarted"), 10)

    def notify_restarted(self) -> None:
        self.warn(self.line("self_restarted"), "まもるんが予期せず止まったので、起動し直しました。\n自分で止めたのでなければ、不審なプログラムに止められた可能性があります。")

    def warn(self, spoken: str, detail: str) -> None:
        """見逃されないよう、吹き出しに加えて、作業を止めない警告の窓を出す。"""
        self.say(spoken, 15)
        box = QMessageBox(QMessageBox.Icon.Warning, "まもるん", detail, QMessageBox.StandardButton.Ok)
        box.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        box.setModal(False)
        box.finished.connect(lambda _result=0, b=box: self._warnings.remove(b) if b in self._warnings else None)
        self._warnings.append(box)
        box.show()

    def say(self, text: str, seconds: float = 7) -> None:
        if self.mascot_hidden:
            self.tray.showMessage("まもるん", text, QSystemTrayIcon.MessageIcon.Information, int(seconds * 1000))
        else:
            self.bubble.say(text, self.mascot, seconds)

    def line(self, key: str, **values) -> str:
        return (PLAIN if self.mascot_hidden else self.character).line(key, **values)

    def set_mascot_hidden(self, hidden: bool) -> None:
        """キャラクターの表示と非表示を切り替える。見張りは止めない。"""
        if hidden == self.mascot_hidden:
            return
        if hidden:
            self.save_position()  # 再表示のときに同じ場所へ戻す
            self.bubble.hide()
            self.mascot.hide()
        self.mascot_hidden = hidden
        self.store.settings["mascot_hidden"] = hidden
        self.store.save_settings()
        self.tray.setIcon(self._tray_icon())
        if not hidden:
            self._restore_position()
            self.mascot.show()
            self.say(self.line("selected"))

    @property
    def art_folder(self) -> Path:
        return self.art_root / self.character.id

    def set_character(self, character_id: str) -> None:
        character = get_character(character_id)
        if self.mascot_hidden:
            self.character = character
            self.store.settings["character"] = character.id
            self.art.set_folder(self.art_folder)
            self.mascot.apply_size()
            self.set_mascot_hidden(False)
            return
        if character.id == self.character.id:
            return
        self.character = character
        self.store.settings["character"] = character.id
        self.store.save_settings()
        self.art.set_folder(self.art_folder)
        self.mascot.apply_size()
        self.tray.setIcon(self._tray_icon())
        self.save_position()
        self.say(self.line("selected"))

    # ---------- 状態
    def compute_state(self) -> str:
        if self.engine.errors >= 5 or time.time() - self.engine.heartbeat > HEARTBEAT_LIMIT:
            return "down"
        pending = self.engine.pending()
        if any(a.action in ("suspended", "blocked", "recovered", "suspend_failed", "protected") for a in pending):
            return "alert"
        if pending:
            return "watch"
        if self.engine.paused:
            return "sleep"
        if self.engine.observe:
            return "observe"
        return "idle"

    def update_state(self) -> None:
        state = self.compute_state()
        self.mascot.set_state(state)
        if state != self._last_state:
            self.tray.setToolTip(f"まもるん: {STATE_LABEL[state]}")
            if state == "down":
                self.say(self.line("down"), 20)
            self._last_state = state

    def status_text(self) -> str:
        rows = self.engine.rows()
        mode = "観察モード（止めない）" if self.engine.observe else "自動判断モード"
        admin = "管理者権限あり" if self.is_admin else "管理者権限なし（一部は止められません）"
        gate = "送信前の遮断: 有効" if self.engine.gate_active else "送信前の遮断: 無効"
        sysmon = {
            "ok": "Sysmon: 連携中", "not_installed": "Sysmon: 未導入", "denied": "Sysmon: 読めません（管理者権限が必要）",
            "not_ready": "Sysmon: 記録を読めません（管理者権限か、導入後の再起動が必要な場合があります）",
        }.get(self.engine.sysmon_status, "Sysmon: 確認できず")
        if self.sysmon_watch.down:
            sysmon = "Sysmon: 止まっています"
        strict = "厳格モード: 有効" if self.engine.strict else "厳格モード: 無効"
        traps = self.engine.traps
        trap = f"罠: {len(traps.entries)} 個" if traps is not None and traps.installed else "罠: なし"
        if traps is None or not traps.watching:
            watch = "認証ファイル: 見張りなし"
        else:
            watch = f"認証ファイル: {len(traps.watched)} 個（{'読まれたら止める' if traps.enforce else '記録のみ'}）"
        return (
            f"{STATE_LABEL[self.compute_state()]}　｜　{mode}　｜　{admin}　｜　{gate}　｜　{strict}　｜　{sysmon}　｜　{trap}　｜　{watch}　｜　"
            f"見張り中の通信 {len(rows)} 件　｜　停止中 {self.engine.suspended_count()} 件"
        )

    # ---------- 検知と判断
    def on_alert(self, alert: Alert) -> None:
        self.update_state()
        current = self.alert_window.alert
        if not self.alert_window.isVisible() or (current is not None and current.id == alert.id):
            self._show(alert)
        elif self.alert_window.isVisible():
            self._show(current)  # 件数の表示を更新する
        if alert.direction == "trap":
            self.say(self.line("trap_hit", name=alert.proc.name), 15)
        elif alert.action == "exited":
            self.say(self.line("exited_seen", name=alert.proc.name), 12)
        elif alert.direction == "launch" and alert.action == "suspended":
            self.say(self.line("launch_stopped", name=alert.proc.name), 10)
        elif alert.direction == "launch" and alert.action == "ask":
            self.say(self.line("launch_concerned", name=alert.proc.name), 10)
        elif alert.action == "suspended":
            self.say(self.line("stopped", name=alert.proc.name), 10)
        elif alert.action == "blocked":
            self.say(self.line("blocked", name=alert.proc.name), 10)
        elif alert.action == "suspend_failed":
            self.say(self.line("stop_failed", name=alert.proc.name), 15)
        else:
            self.say(self.line("concerned", name=alert.proc.name), 10)

    def _show(self, alert: Alert) -> None:
        others = sum(1 for a in self.engine.pending() if a.id != alert.id)
        self.alert_window.show_alert(alert, others)

    def _show_next(self) -> None:
        for alert in self.engine.pending():
            if alert.id not in self._kept:
                self._show(alert)
                return
        self.alert_window.alert = None
        self.alert_window.hide()

    def on_decided(self, alert_id: int, decision: str) -> None:
        if self._quitting:
            return
        if self._demo_open and alert_id == -1:
            self._demo_open = False
            self.alert_window.alert = None
            self.alert_window.hide()
            self.say(self.line("demo"))
            return
        ok, message = self.engine.decide(alert_id, decision)
        if decision == KEEP:
            self._kept.add(alert_id)
            if any(a.id == alert_id and a.action not in ("suspended", "blocked", "recovered") for a in self.engine.pending()):
                message = self.line("keep_later")
            else:
                message = self.line("keep_stopped")
        self.say(message, 8 if ok else 15)
        if ok or decision == KEEP:
            self._show_next()
        self.update_state()

    def _read_defense_status(self) -> None:
        while not self._quitting:
            try:
                self._defense_rows = build_rows(read_status())
            except Exception as exc:  # 状態の表示の失敗で見張りを止めない
                self.store.log({"event": "defense_error", "detail": repr(exc)})
            for _ in range(600):  # 10分ごと
                if self._quitting:
                    return
                time.sleep(1)

    # ---------- プログラムの調査
    def scan_programs(self) -> None:
        """外部へつないでいるプログラムを見つけたら、裏で詳しく調べる。"""
        groups: dict[tuple[int, int], dict] = {}
        for row in self.engine.rows():
            if row["direction"] == "listen":
                continue
            created = self.engine.inspector.created(row["pid"])
            if not created:
                continue
            group = groups.setdefault((row["pid"], created), {"pid": row["pid"], "name": row["name"], "conns": []})
            group["conns"].append(Conn("", row["local_port"], row["remote"], row["remote_port"], row["state"], row["pid"]))
        self._program_rows = groups
        for key, group in groups.items():
            if key not in self._program_reports and key not in self._inspect_queued:
                self._inspect_queued.add(key)
                self._enqueue_inspection(key, group["pid"], None, group["conns"], False)

    def program_entries(self) -> list[dict]:
        return [
            {"pid": group["pid"], "name": group["name"], "connections": len(group["conns"]), "report": self._program_reports.get(key)}
            for key, group in self._program_rows.items()
        ]

    def _inspect_worker(self) -> None:
        while not self._quitting:
            try:
                _priority, _order, item = self._inspect_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            self._inspect_one(*item)

    def _enqueue_inspection(self, key, pid: int, path: str | None, conns, open_after: bool) -> None:
        # 人が開いた調査を、裏の調査より先に処理する
        self._inspect_queue.put((0 if open_after else 1, next(self._inspect_order), (key, pid, path, conns, open_after)))

    def _inspect_one(self, key, pid: int, path: str | None, conns, open_after: bool) -> None:
        # 調査の失敗で見張りを止めない
        try:
            if pid:
                report = self.program_inspector.inspect_process(
                    pid, conns, self.engine.is_suspended(pid), self.engine.dns_hosts(pid),
                )
            else:
                report = self.program_inspector.inspect_file(path)
        except Exception as exc:
            self.store.log({"event": "inspect_error", "pid": pid, "detail": repr(exc)})
            report = ProgramReport(path=path, name=path or f"PID {pid}")
        if not self._quitting:
            self._bridge.inspected.emit(key, report, open_after)

    def on_inspected(self, key, report: ProgramReport, open_after: bool) -> None:
        if key is not None:
            self._program_reports[key] = report
            self._inspect_queued.discard(key)
        if open_after:
            self.detail_window.show_report(report)
        path = (report.path or report.name).lower()
        if path in self._announced_paths:
            return
        self._announced_paths.add(path)
        bad, warn = report.count(BAD), report.count(WARN)
        self.store.log({
            "event": "inspected", "name": report.name, "path": report.path, "sha256": report.sha256,
            "signature": report.signature.status if report.signature else "", "signer": report.signer_name,
            "bad": bad, "warn": warn, "notes": [note.text for note in report.notes if note.severity in (BAD, WARN)],
        })
        if bad:
            self.detail_window.show_report(report)
            self.say(self.line("inspected_bad", name=report.name, count=bad), 12)
        elif warn:
            self.say(self.line("inspected_warn", name=report.name, count=warn), 8)

    def open_program(self, pid: int) -> None:
        created = self.engine.inspector.created(pid)
        report = self._program_reports.get((pid, created))
        if report is not None:
            self.detail_window.show_report(report)
            return
        self.detail_window.show_loading(f"PID {pid}")
        self._enqueue_inspection((pid, created) if created else None, pid if created else 0, None, [], True)
        self._ensure_inspector()

    def open_alert_details(self, alert: Alert) -> None:
        facts = alert.proc
        alive = bool(facts.pid) and self.engine.inspector.created(facts.pid) == facts.created
        self.detail_window.show_loading(facts.name)
        conns = [alert.conn] if alert.conn is not None else []
        key = (facts.pid, facts.created) if alive else None
        self._enqueue_inspection(key, facts.pid if alive else 0, facts.path, conns, True)
        self._ensure_inspector()

    def reinspect(self, report: ProgramReport | None) -> None:
        if report is None:
            return
        pid = report.process.pid if report.process else 0
        created = self.engine.inspector.created(pid) if pid else 0
        self.detail_window.show_loading(report.name)
        group = self._program_rows.get((pid, created))
        conns = group["conns"] if group else []
        self._enqueue_inspection((pid, created) if created else None, pid if created else 0, report.path, conns, True)
        self._ensure_inspector()

    def on_detail_operation(self, pid: int, operation: str) -> None:
        ok, message = self.engine.control(pid, operation)
        self.say(message, 8 if ok else 15)
        self.update_state()
        if self.detail_window.report is not None:
            self.reinspect(self.detail_window.report)

    def _ensure_inspector(self) -> None:
        """調査の処理を用意する。大きなファイルの調査で後ろが長く待たされないよう、2本で動かす。"""
        while len(self._inspect_threads) < INSPECT_WORKERS:
            thread = threading.Thread(target=self._inspect_worker, name="guardian-inspect", daemon=True)
            self._inspect_threads.append(thread)
            thread.start()

    def on_mascot_click(self) -> None:
        pending = self.engine.pending()
        if pending:
            self._kept.clear()
            self._show(pending[0])
            return
        rows = self.engine.rows()
        external = sum(1 for r in rows if r["direction"] != "listen")
        self.say(self.line("status", state=STATE_LABEL[self.compute_state()], count=external))

    def _idle_chat(self) -> None:
        if self.compute_state() == "idle" and not self.mascot_hidden:
            self.say(random.choice(self.character.idle_lines), 6)

    # ---------- メニューと操作
    def _build_menu(self) -> None:
        menu = self.menu
        menu.clear()
        self._add(menu, "見守り状況を開く", self.open_dashboard)
        if self.engine.pending():
            self._add(menu, f"確認待ちを開く（{len(self.engine.pending())} 件）", self.on_mascot_click)
        menu.addSeparator()
        if self.engine.paused:
            self._add(menu, "見張りを再開する", self.resume_watch)
        else:
            self._add(menu, "15分だけ休ませる", lambda: self.pause_watch(15 * 60))
        strict_action = QAction("厳格モード", menu, checkable=True, checked=self.engine.strict)
        strict_action.triggered.connect(lambda _checked=False: self.toggle_strict())
        menu.addAction(strict_action)
        if self.engine.traps is not None:
            if self.engine.traps.installed:
                self._add(menu, "罠を外す", self.remove_traps)
            else:
                self._add(menu, "罠を仕掛ける…", self.install_traps)
            if self.engine.traps.watching:
                enforce = QAction("認証ファイルが読まれたら止める", menu, checkable=True, checked=self.engine.traps.enforce)
                enforce.triggered.connect(lambda _checked=False: self.toggle_watch_enforce())
                menu.addAction(enforce)
                self._add(menu, "認証ファイルの見張りをやめる", self.remove_watch)
            else:
                self._add(menu, "認証ファイルを見張る…", self.install_watch)
        character_menu = menu.addMenu("キャラクター")
        for character in CHARACTERS.values():
            checked = not self.mascot_hidden and character.id == self.character.id
            action = QAction(character.label, character_menu, checkable=True, checked=checked)
            action.triggered.connect(lambda _checked=False, c=character.id: self.set_character(c))
            character_menu.addAction(action)
        character_menu.addSeparator()
        hide_action = QAction("表示しない", character_menu, checkable=True, checked=self.mascot_hidden)
        hide_action.triggered.connect(lambda _checked=False: self.set_mascot_hidden(True))
        character_menu.addAction(hide_action)
        if not self.mascot_hidden:
            size_menu = menu.addMenu("大きさ")
            for name in SIZES:
                action = QAction(name, size_menu, checkable=True, checked=name == self.mascot.size_name)
                action.triggered.connect(lambda _checked=False, n=name: self.set_size(n))
                size_menu.addAction(action)
            self._add(menu, "定位置（画面右下）に立たせる", self.reset_position)
            self._add(menu, "画像を読み直す", self.reload_art)
        startup_action = QAction("Windowsの起動時に起動する", menu, checkable=True, checked=self._startup_enabled)
        startup_action.triggered.connect(lambda _checked=False: self.toggle_startup())
        menu.addAction(startup_action)
        self._add(menu, "警告画面を試しに表示", self.show_demo)
        menu.addSeparator()
        self._add(menu, "終了", self.quit)

    @staticmethod
    def _add(menu: QMenu, text: str, callback) -> None:
        action = menu.addAction(text)
        action.triggered.connect(lambda _checked=False: callback())

    def toggle_startup(self) -> None:
        if not self.is_admin:
            QMessageBox.information(None, "まもるん", "この設定には管理者権限が必要です。まもるんを管理者権限で起動し直してください。")
            return
        turning_on = not self._startup_enabled
        ok = self.startup.enable() if turning_on else self.startup.disable()
        self._startup_enabled = self.startup.is_enabled()
        if ok and turning_on:
            self.say("Windowsの起動時に、管理者権限で起動します。プログラムの場所を移したら設定し直してください。", 10)
        elif ok:
            self.say("Windowsの起動時に起動しないようにしました。")
        else:
            QMessageBox.warning(None, "まもるん", "Windowsの起動時の設定を変更できませんでした。")

    def show_menu(self, position: QPoint) -> None:
        self.menu.exec(position)

    def _on_tray(self, reason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self.open_dashboard()

    def open_dashboard(self) -> None:
        self.dashboard.show()
        self.dashboard.raise_()
        self.dashboard.activateWindow()

    def toggle_strict(self) -> None:
        enabled = not self.engine.strict
        self.engine.set_strict(enabled)
        self.store.settings["strict"] = enabled
        self.store.save_settings()
        self.say(self.line("strict_on" if enabled else "strict_off"))

    def install_traps(self) -> None:
        traps = self.engine.traps
        if not self.is_admin:
            self.say("罠を仕掛けるには、まもるんを管理者権限で起動してください。", 10)
            return
        planned = "\n".join(traps.planned_paths())
        answer = QMessageBox.question(
            None, "罠を仕掛ける",
            "情報窃取マルウェアが探す場所に、偽物のファイルを置きます。\n"
            "同じ名前のファイルがあれば、そこには置きません。\n\n"
            f"{planned}\n\n"
            "読み取りを検知するため、Windowsの「ファイルシステムの監査」を有効にします。\n"
            "取り外すと、ファイルを消して設定を元に戻します。よろしいですか？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            ok, message = traps.install()
            self.say(message, 8 if ok else 15)

    def remove_traps(self) -> None:
        ok, message = self.engine.traps.remove()
        self.say(message, 8 if ok else 15)

    def install_watch(self) -> None:
        if not self.is_admin:
            self.say("認証ファイルを見張るには、まもるんを管理者権限で起動してください。", 10)
            return
        answer = QMessageBox.question(
            None, "認証ファイルの見張り",
            "ブラウザのパスワードとCookie、SSH鍵、AWSの認証ファイルの読み取りを見張ります。\n"
            "本物のファイルに監査の設定を追加します。中身は変更しません。\n"
            "本来読むプログラム（ブラウザ自身など）は対象外です。\n\n"
            "最初は記録だけで、何も止めません。「検知の記録」を見て問題がなければ、止める設定に切り替えてください。\n"
            "Windowsの「ファイルシステムの監査」も有効にします。やめると元に戻します。よろしいですか？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            ok, message = self.engine.traps.install_watch()
            self.say(message, 10 if ok else 15)

    def remove_watch(self) -> None:
        ok, message = self.engine.traps.remove_watch()
        self.say(message, 8 if ok else 15)

    def toggle_watch_enforce(self) -> None:
        traps = self.engine.traps
        traps.set_enforce(not traps.enforce)
        self.say("認証ファイルが読まれたら止めます。" if traps.enforce else "認証ファイルの読み取りは記録だけにします。", 8)

    def pause_watch(self, seconds: float) -> None:
        self.engine.pause(seconds)
        self.update_state()
        self.say(self.line("pause", minutes=int(seconds // 60)), 8)

    def resume_watch(self) -> None:
        self.engine.unpause()
        self.update_state()
        self.say(self.line("resume"))

    def set_size(self, name: str) -> None:
        self.mascot.size_name = name
        self.mascot.apply_size()
        self.store.settings["size"] = name
        self.store.save_settings()
        self.save_position()

    def reload_art(self) -> None:
        count = self.art.reload()
        self.mascot.apply_size()
        self.tray.setIcon(self._tray_icon())
        if count:
            self.say(self.line("art_loaded", count=count))
        else:
            self.say(self.line("art_missing", folder=self.art_folder), 12)

    def show_demo(self) -> None:
        self._demo_open = True
        self.alert_window.show_alert(demo_alert(), demo=True)

    def save_position(self) -> None:
        if self.mascot_hidden:
            return  # 非表示の間は位置が変わらない
        self.store.settings["x"] = self.mascot.x()
        self.store.settings["bottom"] = self.mascot.y() + self.mascot.height()
        self.store.save_settings()

    def reset_position(self) -> None:
        self.mascot.stand_on_taskbar()
        self.save_position()

    def _restore_position(self) -> None:
        x, bottom = self.store.settings.get("x"), self.store.settings.get("bottom")
        if isinstance(x, int) and isinstance(bottom, int):
            center = QPoint(x + self.mascot.width() // 2, bottom - self.mascot.height() // 2)
            if QApplication.screenAt(center) is not None:
                self.mascot.move(x, bottom - self.mascot.height())
                return
        self.mascot.stand_on_taskbar()

    def _tray_icon(self) -> QIcon:
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        frame = self.art.frame("idle", 0)
        if self.mascot_hidden:
            # キャラクターを出さないので、盾の形だけにする
            shield = QPainterPath(QPointF(32, 4))
            shield.lineTo(56, 13)
            shield.lineTo(56, 32)
            shield.quadTo(54, 50, 32, 60)
            shield.quadTo(10, 50, 8, 32)
            shield.lineTo(8, 13)
            shield.closeSubpath()
            painter.setPen(QPen(QColor("#253044"), 3))
            painter.setBrush(QColor(STATE_COLOR["idle"]))
            painter.drawPath(shield)
        elif frame is not None:
            scaled = frame.scaled(
                64, 64, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation,
            )
            painter.drawPixmap((64 - scaled.width()) // 2, (64 - scaled.height()) // 2, scaled)
        else:
            draw_placeholder(painter, "idle", 0, 64, 64)
        painter.end()
        return QIcon(pixmap)

    def quit(self) -> None:
        stopped = self.engine.suspended_count()
        text = "まもるんを終了すると見張りが止まります。終了しますか？"
        if stopped:
            text = f"止めているプログラム {stopped} 件は再開されます。\n" + text
        answer = QMessageBox.question(
            None, "まもるんの終了", text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.shutdown()
            QApplication.quit()

    def shutdown(self) -> None:
        if self._quitting:
            return
        self._quitting = True
        try:
            self.save_position()
            self._state_timer.stop()
            self.tray.hide()
        finally:
            # 止めたプログラムを残さないよう、ここだけは必ず実行する
            self.engine.shutdown(resume_suspended=True)


_app: QApplication | None = None


def make_app(argv: list[str]) -> QApplication:
    # 呼び出し元の変数が消えてもアプリ本体が破棄されないよう、ここで保持する
    global _app
    _app = QApplication.instance() or QApplication(argv)
    _app.setApplicationName("GuardianMascot")
    _app.setQuitOnLastWindowClosed(False)
    _app.setFont(QFont("Yu Gothic UI", 10))
    return _app


__all__ = ["Controller", "MascotWidget", "AlertWindow", "Dashboard", "SpeechBubble", "make_app", "demo_alert"]
