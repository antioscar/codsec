from __future__ import annotations
from PySide6.QtWidgets import QPlainTextEdit, QWidget
from PySide6.QtGui import QPainter, QColor, QFont, QFontDatabase, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtCore import Qt, QRect

from src.rules.parser import _get_language
from tree_sitter import Parser

_COLORS_DARK = {
    "comment": QColor(106, 153, 85),
    "string": QColor(206, 145, 120),
    "keyword": QColor(86, 156, 214),
    "number": QColor(181, 206, 168),
    "constant": QColor(86, 156, 214),
    "function": QColor(220, 220, 170),
    "type": QColor(78, 201, 176),
}

_COLORS_LIGHT = {
    "comment": QColor(0, 128, 0),
    "string": QColor(163, 21, 21),
    "keyword": QColor(0, 0, 255),
    "number": QColor(9, 134, 88),
    "constant": QColor(0, 0, 255),
    "function": QColor(121, 94, 38),
    "type": QColor(38, 127, 153),
}

_KEYWORD_SET = frozenset({
    "if", "else", "elif", "return", "def", "class", "import", "from",
    "try", "except", "finally", "raise", "yield", "lambda", "pass",
    "break", "continue", "global", "nonlocal", "and", "or", "not",
    "is", "in", "as", "with", "async", "await", "del", "print",
    "for", "while", "do", "switch", "case", "default", "typeof",
    "throw", "new", "this", "super", "extends", "instanceof",
    "void", "delete", "var", "let", "const", "export", "static",
    "get", "set", "debugger", "of",
    "public", "private", "protected", "abstract", "final",
    "boolean", "int", "long", "float", "double", "char", "short", "byte",
    "namespace", "using", "goto", "defer", "package",
    "require", "include", "require_once", "include_once",
    "go", "chan", "select", "range", "map", "struct", "interface",
    "nil", "true", "false", "null", "enum", "match",
    "implements", "transient", "volatile", "synchronized", "native",
    "strictfp", "assert", "trait", "insteadof",
    "unless", "until", "undef", "defined", "alias", "BEGIN", "END",
    "elsif", "next", "redo", "retry", "rescue", "ensure",
    "module", "end", "begin", "__LINE__", "__FILE__", "__ENCODING__",
    "ref", "out", "inout", "foreach", "echo", "list", "unset",
    "empty", "isset", "clone", "instanceof", "insteadof",
    "__halt_compiler", "declare", "use", "namespace",
    "__FUNCTION__", "__CLASS__", "__TRAIT__", "__METHOD__", "__NAMESPACE__",
    "extern", "const", "readonly", "sealed", "unsafe", "checked", "unchecked",
    "lock", "fixed", "event", "delegate", "explicit", "implicit",
    "operator", "sizeof", "params", "internal", "virtual", "override",
    "nint", "nuint", "object", "record",
})

_FUNC_DEF_PATTERNS = frozenset({
    "function_definition", "function_declaration", "method_definition",
    "method_declaration", "function_item", "function_expression",
    "arrow_function", "generator_function", "generator_function_declaration",
})

_CLASS_DEF_PATTERNS = frozenset({
    "class_definition", "class_declaration", "class_body",
})


class SyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None, theme="dark"):
        super().__init__(parent)
        self._theme = theme
        self._highlights: list[tuple[int, int, int, str]] = []
        self._setup_formats()

    def _setup_formats(self):
        colors = _COLORS_DARK if self._theme == "dark" else _COLORS_LIGHT
        self._formats: dict[str, QTextCharFormat] = {}

        for name, color in colors.items():
            fmt = QTextCharFormat()
            fmt.setForeground(color)
            if name == "keyword":
                fmt.setFontWeight(QFont.Weight.Bold)
            if name in ("comment",):
                fmt.setFontItalic(True)
            self._formats[name] = fmt

    def set_theme(self, theme: str):
        if self._theme == theme:
            return
        self._theme = theme
        self._setup_formats()
        self.rehighlight()

    def set_source(self, source: str, language: str):
        lang_obj = _get_language(language)
        if lang_obj is None:
            self._highlights = []
            self.rehighlight()
            return

        try:
            parser = Parser(lang_obj)
            source_bytes = source.encode("utf-8", errors="replace")
            tree = parser.parse(source_bytes)
            self._highlights = []
            self._collect_highlights(tree.root_node, source_bytes)
        except Exception:
            self._highlights = []
        self.rehighlight()

    def _collect_highlights(self, node, source_bytes):
        category = self._classify_node(node, source_bytes)
        if category is not None:
            start_row, start_col = node.start_point
            end_row, end_col = node.end_point
            self._highlights.append((start_row, start_col, end_row, end_col, category))
            return

        for child in node.children:
            self._collect_highlights(child, source_bytes)

    def _classify_node(self, node, source_bytes) -> str | None:
        node_type = node.type

        if "comment" in node_type:
            return "comment"

        if node_type in (
            "string", "string_literal", "string_fragment", "template_string",
            "template_literal", "string_content", "heredoc", "heredoc_body",
            "encapsed_string", "raw_string_literal", "interpreted_string_literal",
            "simple_string", "nowdoc_body", "nowdoc",
            "string_expression", "interpolation", "charliteral", "character_literal",
        ) or "string" in node_type:
            return "string"

        if node_type in (
            "integer", "float", "number", "decimal_integer_literal",
            "hex_integer_literal", "float_literal", "real_literal",
            "int_literal", "decimal", "real", "numeric_literal",
            "octal_integer_literal", "binary_integer_literal",
        ):
            return "number"

        if node_type in ("true", "false", "null", "nil", "none"):
            return "constant"

        if node_type in _KEYWORD_SET:
            return "keyword"

        if node_type in ("identifier", "name", "property_identifier", "method_name"):
            parent = node.parent
            if parent is not None:
                if parent.type in _FUNC_DEF_PATTERNS:
                    return "function"
                if parent.type in ("call_expression", "call", "function_call",
                                   "method_call", "method_invocation",
                                   "function_call_expression",
                                   "method_invocation_expression",
                                   "scoped_call_expression"):
                    txt = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
                    if txt.islower() and txt.isidentifier():
                        return "function"

        if node_type in ("identifier", "type_identifier", "name"):
            parent = node.parent
            if parent is not None and parent.type in _CLASS_DEF_PATTERNS:
                return "type"

        return None

    def highlightBlock(self, text: str):
        block = self.currentBlock()
        line_num = block.blockNumber()

        for start_row, start_col, end_row, end_col, category in self._highlights:
            fmt = self._formats.get(category)
            if fmt is None:
                continue

            if start_row == line_num:
                if end_row == start_row:
                    length = end_col - start_col
                    self.setFormat(start_col, length, fmt)
                else:
                    self.setFormat(start_col, len(text) - start_col, fmt)
            elif start_row < line_num < end_row:
                self.setFormat(0, len(text), fmt)
            elif end_row == line_num and end_row != start_row:
                self.setFormat(0, end_col, fmt)


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

        self._highlighter = SyntaxHighlighter(self.document())

        self._update_line_number_width()

    def set_source(self, source: str, language: str | None = None):
        lang = language or ""
        self._highlighter.set_source(source, lang)
        self.setPlainText(source)

    def set_theme(self, theme: str):
        self._highlighter.set_theme(theme)

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
