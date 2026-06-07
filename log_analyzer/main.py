"""入口点 — 启动日志分析工具"""

import sys
from pathlib import Path

# 确保项目根目录在 sys.path 中，方便直接运行此文件
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))


def main():
    from PyQt5.QtWidgets import QApplication
    from log_analyzer.gui.main_window import LogAnalyzerWindow

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = LogAnalyzerWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
