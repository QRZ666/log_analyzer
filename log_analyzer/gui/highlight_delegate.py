"""高亮代理 — 在表格中高亮命中的攻击关键词"""

import re

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont, QTextCharFormat, QSyntaxHighlighter
from PyQt5.QtWidgets import QStyledItemDelegate, QStyleOptionViewItem, QStyle


class HighlightDelegate(QStyledItemDelegate):
    """在表格单元格中高亮显示匹配的关键词"""

    def __init__(self, highlight_words: list[str], parent=None):
        """
        highlight_words: 要高亮的词语列表（按长度降序排列以优先匹配长词）
        """
        super().__init__(parent)
        self.set_highlight_words(highlight_words)

    def set_highlight_words(self, words: list[str]):
        """设置要高亮的词语"""
        self._words = sorted(words, key=len, reverse=True)
        if self._words:
            escaped = [re.escape(w) for w in self._words]
            self._pattern = re.compile(
                "(" + "|".join(escaped) + ")",
                re.IGNORECASE,
            )
        else:
            self._pattern = None

    def initStyleOption(self, option: QStyleOptionViewItem, index):
        super().initStyleOption(option, index)

    def paint(self, painter, option, index):
        """自定义绘制以支持高亮"""
        text = index.data(Qt.DisplayRole)
        if not text or not self._pattern:
            super().paint(painter, option, index)
            return

        painter.save()

        try:
            # 绘制选中背景
            if option.state & QStyle.State_Selected:
                painter.fillRect(option.rect, option.palette.highlight())
                text_color = option.palette.highlightedText().color()
            else:
                # 交替行颜色
                if index.row() % 2 == 1:
                    painter.fillRect(option.rect, QColor("#172033"))
                else:
                    painter.fillRect(option.rect, QColor("#0b1220"))
                text_color = QColor("#e2e8f0")

            painter.setPen(text_color)
            painter.setFont(option.font)

            # 逐段绘制（高亮/非高亮交替）
            x = option.rect.left() + 4
            y = option.rect.top() + option.rect.height() // 2 + painter.fontMetrics().ascent() // 2

            last_end = 0
            for match in self._pattern.finditer(text):
                # 匹配前的普通文本
                if match.start() > last_end:
                    normal_text = text[last_end:match.start()]
                    painter.setPen(text_color)
                    painter.drawText(x, y, normal_text)
                    x += painter.fontMetrics().horizontalAdvance(normal_text)

                # 高亮的匹配文本
                match_text = match.group(0)
                painter.setPen(QColor("#fbbf24"))  # 黄色
                bold_font = QFont(option.font)
                bold_font.setBold(True)
                painter.setFont(bold_font)
                painter.drawText(x, y, match_text)
                x += painter.fontMetrics().horizontalAdvance(match_text)

                last_end = match.end()

            # 剩余文本
            if last_end < len(text):
                painter.setPen(text_color)
                painter.setFont(option.font)
                painter.drawText(x, y, text[last_end:])

        finally:
            painter.restore()
