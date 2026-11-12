"""自定义控件 — 文件拖放与带轻量防抖的搜索栏。"""

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QDragEnterEvent, QDropEvent
from PyQt5.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QPushButton, QSpinBox, QWidget


class DropArea(QLabel):
    file_dropped = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignCenter)
        self.setTextFormat(Qt.PlainText)
        self.setText("把日志文件拖到这里\n或者点击\"选择文件\"")
        self.setMinimumHeight(120)
        self.setObjectName("DropArea")

    def dragEnterEvent(self, event: QDragEnterEvent):
        urls = event.mimeData().urls()
        if self.isEnabled() and urls and urls[0].isLocalFile():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if self.isEnabled() and urls and urls[0].isLocalFile():
            self.file_dropped.emit(urls[0].toLocalFile())
            event.acceptProposedAction()


class FilterBar(QWidget):
    filter_changed = pyqtSignal(str, int, int)
    MAX_SCORE = 2147483647

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.addWidget(QLabel("搜索："))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("IP / 特征 / 类型 / 内容...")
        self.search_edit.setClearButtonEnabled(True)
        layout.addWidget(self.search_edit, 2)
        layout.addWidget(QLabel("最低分："))
        self.min_score = QSpinBox()
        self.min_score.setRange(0, self.MAX_SCORE)
        self.min_score.setFixedWidth(90)
        layout.addWidget(self.min_score)
        layout.addWidget(QLabel("最高分："))
        self.max_score = QSpinBox()
        self.max_score.setRange(0, self.MAX_SCORE)
        self.max_score.setSpecialValueText("不限")
        self.max_score.setToolTip("0 表示不限最高分")
        self.max_score.setFixedWidth(90)
        layout.addWidget(self.max_score)
        btn_clear = QPushButton("清除过滤")
        btn_clear.clicked.connect(self._clear)
        layout.addWidget(btn_clear)

        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(150)
        self._search_timer.timeout.connect(self._emit_change)
        self.search_edit.textChanged.connect(lambda _text: self._search_timer.start())
        self.min_score.valueChanged.connect(self._emit_change)
        self.max_score.valueChanged.connect(self._emit_change)

    def values(self):
        return (self.search_edit.text(), self.min_score.value(),
                self.max_score.value() or self.MAX_SCORE)

    def _emit_change(self, *_args):
        self._search_timer.stop()
        self.filter_changed.emit(*self.values())

    def _clear(self):
        controls = (self.search_edit, self.min_score, self.max_score)
        for control in controls:
            control.blockSignals(True)
        try:
            self.search_edit.clear()
            self.min_score.setValue(0)
            self.max_score.setValue(0)
        finally:
            for control in controls:
                control.blockSignals(False)
        self._emit_change()
