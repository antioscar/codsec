from __future__ import annotations
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QGraphicsOpacityEffect
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QPoint, Property
from PySide6.QtGui import QColor


class Toast(QFrame):
    """Non-blocking notification that slides in and auto-dismisses."""

    ICONS = {
        "info": "\u2139\ufe0f",
        "success": "\u2705",
        "warning": "\u26a0\ufe0f",
        "error": "\u274c",
    }

    COLORS = {
        "info": "#569cd6",
        "success": "#228B22",
        "warning": "#FFA500",
        "error": "#DC143C",
    }

    def __init__(self, text: str, toast_type: str = "info", duration: int = 3000, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        color = self.COLORS.get(toast_type, self.COLORS["info"])
        icon = self.ICONS.get(toast_type, self.ICONS["info"])

        self.setStyleSheet(
            f"Toast {{ background-color: #2a2a42; border: 1px solid {color}60; "
            f"border-radius: 10px; padding: 0px; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 10, 16, 10)

        label = QLabel(f"{icon}  {text}")
        label.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: 500;")
        label.setWordWrap(True)
        layout.addWidget(label)

        self._opacity_effect = QGraphicsOpacityEffect(self)
        self._opacity_effect.setOpacity(0.0)
        self.setGraphicsEffect(self._opacity_effect)

        self._duration = duration

    def show_at(self, parent_widget, offset_y: int = 60):
        if parent_widget is None:
            return

        self.adjustSize()
        x = parent_widget.width() - self.width() - 20
        y = offset_y
        self.setParent(parent_widget)
        self.move(x, y)
        self.show()

        fade_in = QPropertyAnimation(self._opacity_effect, b"opacity")
        fade_in.setDuration(250)
        fade_in.setStartValue(0.0)
        fade_in.setEndValue(1.0)
        fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)

        slide = QPropertyAnimation(self, b"pos")
        slide.setDuration(300)
        slide.setStartValue(QPoint(x, y - 20))
        slide.setEndValue(QPoint(x, y))
        slide.setEasingCurve(QEasingCurve.Type.OutBack)

        fade_in.start()
        slide.start()

        if self._duration > 0:
            QTimer.singleShot(self._duration, self._fade_out)

    def _fade_out(self):
        fade_out = QPropertyAnimation(self._opacity_effect, b"opacity")
        fade_out.setDuration(300)
        fade_out.setStartValue(1.0)
        fade_out.setEndValue(0.0)
        fade_out.finished.connect(self.close)
        fade_out.start()


def show_toast(parent_widget, text: str, toast_type: str = "info", duration: int = 3000):
    toast = Toast(text, toast_type, duration)
    toast.show_at(parent_widget)
    return toast
