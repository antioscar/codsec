from __future__ import annotations
from PySide6.QtWidgets import QPlainTextEdit, QWidget, QHBoxLayout
from PySide6.QtGui import QPainter, QColor, QFont, QFontDatabase, QTextFormat
from PySide6.QtCore import Qt, QRect


class LineNumberArea(QWidget):
    def __init__(self, editor: CodeViewer):
        super().__init__(editor)
        self.editor = editor

    def sizeHint(self):
        return self.editor.line_number_area_size()

    def paintEvent(self, event):
        self.editor.line_number_area_paint(event)


class CodeViewer(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        font = QFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        font.setPointSize(10)
        self.setFont(font)

        self.line_number_area = LineNumberArea(self)
        self.blockCountChanged.connect(self._update_line_number_width)
        self.updateRequest.connect(self._update_line_number_area)

        self._highlighted_line = -1
        self._highlight_color = QColor(220, 20, 60, 40)

        self._update_line_number_width()

    def set_highlighted_line(self, line_number: int, color: QColor = None):
        self._highlighted_line = line_number
        if color:
            self._highlight_color = QColor(color.red(), color.green(), color.blue(), 40)
        self.viewport().update()

    def line_number_area_size(self):
        digits = max(1, len(str(self.blockCount())))
        space = 8 + self.fontMetrics().horizontalAdvance("9") * digits
        return space

    def _update_line_number_width(self):
        self.setViewportMargins(self.line_number_area_size(), 0, 0, 0)

    def _update_line_number_area(self, rect, dy):
        if dy:
            self.line_number_area.scroll(0, dy)
        else:
            self.line_number_area.update(0, rect.y(), self.line_number_area.width(), rect.height())

        if rect.contains(self.viewport().rect()):
            self._update_line_number_width()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.line_number_area.setGeometry(
            QRect(cr.left(), cr.top(), self.line_number_area_size(), cr.height())
        )

    def line_number_area_paint(self, event):
        painter = QPainter(self.line_number_area)
        block = self.firstVisibleBlock()
        block_number = block.blockNumber() + 1
        top = self.blockBoundingGeometry(block).translated(self.contentOffset()).top()
        bottom = top + self.blockBoundingRect(block).height()

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number)
                if block_number == self._highlighted_line:
                    painter.setPen(QColor("#DC143C"))
                    font = painter.font()
                    font.setBold(True)
                    painter.setFont(font)
                else:
                    painter.setPen(QColor("#5a5a7a"))
                    font = painter.font()
                    font.setBold(False)
                    painter.setFont(font)
                painter.drawText(0, int(top), self.line_number_area.width() - 4,
                                 self.fontMetrics().height(), Qt.AlignmentFlag.AlignRight, number)

            block = block.next()
            top = bottom
            bottom = top + self.blockBoundingRect(block).height()
            block_number += 1

        painter.end()

    def paintEvent(self, event):
        super().paintEvent(event)
        if self._highlighted_line > 0:
            painter = QPainter(self.viewport())
            block = self.document().findBlockByNumber(self._highlighted_line - 1)
            if block.isValid():
                rect = QRect(
                    self.contentOffset().x(),
                    int(self.blockBoundingGeometry(block).translated(self.contentOffset()).top()),
                    self.viewport().width(),
                    int(self.blockBoundingRect(block).height()),
                )
                painter.fillRect(rect, self._highlight_color)
            painter.end()
