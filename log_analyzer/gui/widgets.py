"""自定义控件 — 拖放区域、搜索栏等"""

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QDragEnterEvent, QDropEvent
from PyQt5.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QWidget,
)


class DropArea(QLabel):
    """文件拖放区域"""
    file_dropped = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignCenter)
        self.setText("把日志文件拖到这里\n或者点击\"选择文件\"")
        self.setMinimumHeight(120)
        self.setObjectName("DropArea")

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if not urls:
            return
        path = urls[0].toLocalFile()
        if path:
            self.file_dropped.emit(path)


class FilterBar(QWidget):
    """结果过滤/搜索栏"""
    filter_changed = pyqtSignal(str, int, int)  # text, min_score, max_score

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)

        # 搜索框
        layout.addWidget(QLabel("搜索："))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("IP / 特征 / 类型 / 内容...")
        self.search_edit.setClearButtonEnabled(True)
        layout.addWidget(self.search_edit, 2)

        # 分数范围
        layout.addWidget(QLabel("最低分："))
        self.min_score = QSpinBox()
        self.min_score.setRange(0, 999)
        self.min_score.setValue(0)
        self.min_score.setFixedWidth(70)
        layout.addWidget(self.min_score)

        layout.addWidget(QLabel("最高分："))
        self.max_score = QSpinBox()
        self.max_score.setRange(0, 999)
        self.max_score.setValue(999)
        self.max_score.setFixedWidth(70)
        layout.addWidget(self.max_score)

        # 清除按钮
        btn_clear = QPushButton("清除过滤")
        btn_clear.clicked.connect(self._clear)
        layout.addWidget(btn_clear)

        # 信号连接
        self.search_edit.textChanged.connect(self._emit_change)
        self.min_score.valueChanged.connect(self._emit_change)
        self.max_score.valueChanged.connect(self._emit_change)

    def _emit_change(self):
        self.filter_changed.emit(
            self.search_edit.text(),
            self.min_score.value(),
            self.max_score.value(),
        )

    def _clear(self):
        self.search_edit.clear()
        self.min_score.setValue(0)
        self.max_score.setValue(999)
