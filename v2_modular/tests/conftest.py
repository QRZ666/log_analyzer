"""GUI回归不依赖pytest-qt或显示器，所有用户配置由测试各自隔离。"""

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if os.name == "nt":
    os.environ.setdefault("QT_QPA_FONTDIR", str(Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"))


@pytest.fixture(scope="session")
def qapp():
    pytest.importorskip("PyQt5.QtWidgets")
    from PyQt5.QtWidgets import QApplication
    application = QApplication.instance() or QApplication([])
    application.setQuitOnLastWindowClosed(False)
    yield application


@pytest.fixture
def wait_for(qapp):
    """通过Qt事件循环等待条件，超时是测试失败而不是无期限挂起。"""
    from PyQt5.QtCore import QEventLoop, QTimer

    def wait(predicate, timeout=5000):
        qapp.processEvents()
        if predicate():
            return
        loop = QEventLoop()
        poll = QTimer(loop)
        poll.setInterval(10)
        poll.timeout.connect(lambda: loop.quit() if predicate() else None)
        deadline = QTimer(loop)
        deadline.setSingleShot(True)
        deadline.timeout.connect(loop.quit)
        poll.start()
        deadline.start(timeout)
        loop.exec_()
        poll.stop()
        deadline.stop()
        assert predicate(), "Qt任务未在限定时间内完成"
        qapp.processEvents()
    return wait
