"""主窗口 — 集成所有配置、分析、过滤、导出功能"""

import os
from pathlib import Path

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..analyzer import LogAnalyzer
from ..config import ConfigManager
from ..export import export_report
from ..geoip import GeoIPResolver, get_resolver, reset_resolver
from ..models import Finding, GeoInfo
from ..rules import RuleEngine, get_engine
from ..whitelist import WhitelistManager
from .highlight_delegate import HighlightDelegate
from .widgets import DropArea, FilterBar
from .worker import LogAnalysisWorker


class WhitelistDialog(QDialog):
    """白名单管理对话框"""

    def __init__(self, whitelist: WhitelistManager, parent=None):
        super().__init__(parent)
        self.whitelist = whitelist
        self.setWindowTitle("白名单管理")
        self.setMinimumSize(500, 400)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        tabs = QTabWidget()

        # ── IP 白名单 Tab ──
        ip_tab = QWidget()
        ip_layout = QVBoxLayout(ip_tab)
        ip_input_row = QHBoxLayout()
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("输入 IP 地址，如 192.168.1.1")
        ip_input_row.addWidget(self.ip_edit)
        btn_add_ip = QPushButton("添加 IP")
        btn_add_ip.clicked.connect(self._add_ip)
        ip_input_row.addWidget(btn_add_ip)
        ip_layout.addLayout(ip_input_row)

        self.ip_list = QListWidget()
        self.ip_list.addItems(self.whitelist.get_ips())
        ip_layout.addWidget(self.ip_list)

        btn_remove_ip = QPushButton("移除选中 IP")
        btn_remove_ip.clicked.connect(self._remove_ip)
        ip_layout.addWidget(btn_remove_ip)
        tabs.addTab(ip_tab, "IP 白名单")

        # ── 模式白名单 Tab ──
        pattern_tab = QWidget()
        pattern_layout = QVBoxLayout(pattern_tab)
        pattern_input_row = QHBoxLayout()
        self.pattern_edit = QLineEdit()
        self.pattern_edit.setPlaceholderText("正则表达式，如 /healthcheck")
        pattern_input_row.addWidget(self.pattern_edit)
        btn_add_pattern = QPushButton("添加模式")
        btn_add_pattern.clicked.connect(self._add_pattern)
        pattern_input_row.addWidget(btn_add_pattern)
        pattern_layout.addLayout(pattern_input_row)

        self.pattern_list = QListWidget()
        self.pattern_list.addItems(self.whitelist.get_patterns())
        pattern_layout.addWidget(self.pattern_list)

        btn_remove_pattern = QPushButton("移除选中模式")
        btn_remove_pattern.clicked.connect(self._remove_pattern)
        pattern_layout.addWidget(btn_remove_pattern)
        tabs.addTab(pattern_tab, "模式白名单")

        layout.addWidget(tabs)

        # 按钮
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._save_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _add_ip(self):
        ip = self.ip_edit.text().strip()
        if ip:
            self.whitelist.add_ip(ip)
            self.ip_list.clear()
            self.ip_list.addItems(self.whitelist.get_ips())
            self.ip_edit.clear()

    def _remove_ip(self):
        for item in self.ip_list.selectedItems():
            self.whitelist.remove_ip(item.text())
        self.ip_list.clear()
        self.ip_list.addItems(self.whitelist.get_ips())

    def _add_pattern(self):
        pattern = self.pattern_edit.text().strip()
        if pattern:
            try:
                self.whitelist.add_pattern(pattern)
                self.pattern_list.clear()
                self.pattern_list.addItems(self.whitelist.get_patterns())
                self.pattern_edit.clear()
            except ValueError as e:
                QMessageBox.warning(self, "错误", str(e))

    def _remove_pattern(self):
        for item in self.pattern_list.selectedItems():
            self.whitelist.remove_pattern(item.text())
        self.pattern_list.clear()
        self.pattern_list.addItems(self.whitelist.get_patterns())

    def _save_and_accept(self):
        self.whitelist.save()
        self.accept()


class LogAnalyzerWindow(QMainWindow):
    """日志分析工具主窗口"""

    def __init__(self):
        super().__init__()
        self.file_path = ""
        self.findings: list[Finding] = []
        self.ip_stats: dict[str, int] = {}
        self.ip_geo: dict[str, GeoInfo] = {}
        self.worker = None

        # 核心组件
        self.config = ConfigManager()
        self.rule_engine = get_engine(self.config.config.rules_path)
        self.whitelist = WhitelistManager(self.config.config.whitelist_path)
        self.analyzer = LogAnalyzer(
            rule_engine=self.rule_engine,
            whitelist=self.whitelist,
            risk_threshold=self.config.risk_threshold,
        )
        self.geoip_resolver: GeoIPResolver = None  # 延迟初始化

        self.setWindowTitle("Web攻击日志分析工具 v2.0")
        self.setMinimumSize(1300, 820)

        self._build_ui()
        self._apply_style()

    # ── UI 构建 ────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # 标题
        title = QLabel("🛡️ Web攻击日志分析工具 v2.0")
        title.setObjectName("TitleLabel")
        subtitle = QLabel(
            "支持 SQL注入 / XSS / 扫描器 / 路径穿越 / Python日志  |  "
            "拖拽日志文件或点击选择"
        )
        subtitle.setObjectName("SubtitleLabel")
        main_layout.addWidget(title)
        main_layout.addWidget(subtitle)

        # ── 顶部：文件输入 + 配置 ──
        top_box = QGroupBox("文件输入 & 配置")
        top_layout = QVBoxLayout(top_box)

        self.drop_area = DropArea()
        self.drop_area.file_dropped.connect(self.load_file)

        file_row = QHBoxLayout()
        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("日志文件路径")
        self.file_edit.setReadOnly(True)
        file_row.addWidget(self.file_edit, 1)

        btn_choose = QPushButton("📂 选择文件")
        btn_choose.clicked.connect(self.choose_file)
        file_row.addWidget(btn_choose)

        # 阈值配置
        file_row.addWidget(QLabel("阈值："))
        self.threshold_spin = QSpinBox()
        self.threshold_spin.setRange(1, 50)
        self.threshold_spin.setValue(self.config.risk_threshold)
        self.threshold_spin.setToolTip("风险分数阈值，达到此分数的记录才会显示")
        self.threshold_spin.valueChanged.connect(self._on_threshold_changed)
        file_row.addWidget(self.threshold_spin)

        # GeoIP 开关
        self.geoip_check = QCheckBox("IP地理")
        self.geoip_check.setChecked(self.config.geoip_enabled)
        self.geoip_check.setToolTip("启用 IP 地理位置查询")
        self.geoip_check.stateChanged.connect(self._on_geoip_toggled)
        file_row.addWidget(self.geoip_check)

        self.btn_analyze = QPushButton("🔍 开始分析")
        self.btn_analyze.clicked.connect(self.start_analysis)
        file_row.addWidget(self.btn_analyze)

        self.btn_cancel = QPushButton("⏹ 取消")
        self.btn_cancel.clicked.connect(self.cancel_analysis)
        self.btn_cancel.setEnabled(False)
        file_row.addWidget(self.btn_cancel)

        btn_whitelist = QPushButton("📋 白名单")
        btn_whitelist.clicked.connect(self._open_whitelist_dialog)
        file_row.addWidget(btn_whitelist)

        btn_export = QPushButton("💾 导出报告")
        btn_export.clicked.connect(self.export_report)
        file_row.addWidget(btn_export)

        top_layout.addWidget(self.drop_area)
        top_layout.addLayout(file_row)
        main_layout.addWidget(top_box)

        # ── 搜索/过滤栏 ──
        self.filter_bar = FilterBar()
        self.filter_bar.filter_changed.connect(self._apply_filters)
        main_layout.addWidget(self.filter_bar)

        # ── 中部：结果列表 + 详情 ──
        mid_layout = QHBoxLayout()

        # 左：结果表格
        left_box = QGroupBox("攻击记录")
        left_layout = QVBoxLayout(left_box)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "行号", "IP", "地理位置", "风险分", "类型", "命中特征"
        ])
        self.table.setWordWrap(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.Interactive)

        # 高亮代理
        self.highlight_delegate = HighlightDelegate(
            self.rule_engine.all_keywords, self.table
        )
        # 在"命中特征"列（索引5）应用高亮
        self.table.setItemDelegateForColumn(5, self.highlight_delegate)

        self.table.itemSelectionChanged.connect(self.show_selected_detail)
        left_layout.addWidget(self.table)

        # 右：详情面板
        right_box = QGroupBox("详细信息")
        right_layout = QVBoxLayout(right_box)

        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("选中结果后查看详情")
        right_layout.addWidget(self.detail)

        mid_layout.addWidget(left_box, 3)
        mid_layout.addWidget(right_box, 1)
        main_layout.addLayout(mid_layout)

        # ── 底部：IP 统计 ──
        bottom_box = QGroupBox("攻击IP统计")
        bottom_layout = QVBoxLayout(bottom_box)

        self.ip_table = QTableWidget(0, 4)
        self.ip_table.setHorizontalHeaderLabels(["IP", "地理位置", "攻击次数", "国家"])
        self.ip_table.setAlternatingRowColors(True)
        self.ip_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ip_table.setSelectionMode(QTableWidget.SingleSelection)
        self.ip_table.setEditTriggers(QTableWidget.NoEditTriggers)
        ip_header = self.ip_table.horizontalHeader()
        ip_header.setStretchLastSection(True)
        bottom_layout.addWidget(self.ip_table)

        main_layout.addWidget(bottom_box)

        # ── 状态栏 ──
        status_row = QHBoxLayout()
        self.status_label = QLabel("就绪")
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximumHeight(18)
        status_row.addWidget(self.status_label, 1)
        status_row.addWidget(self.progress_bar, 2)
        main_layout.addLayout(status_row)

    # ── 样式 ─────────────────────────────────────────

    def _apply_style(self):
        self.setStyleSheet("""
            QWidget {
                background: #0f172a;
                color: #e2e8f0;
                font-size: 14px;
            }
            QGroupBox {
                border: 1px solid #334155;
                border-radius: 10px;
                margin-top: 12px;
                padding: 10px;
                background: #111827;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                top: 4px;
                padding: 0 6px;
                color: #93c5fd;
            }
            QLabel#TitleLabel {
                font-size: 28px;
                font-weight: 700;
                color: #f8fafc;
                padding: 4px 0;
            }
            QLabel#SubtitleLabel {
                color: #94a3b8;
                padding-bottom: 6px;
            }
            QLabel#DropArea {
                border: 2px dashed #475569;
                border-radius: 14px;
                padding: 18px;
                background: #0b1220;
                color: #cbd5e1;
                font-size: 16px;
                min-height: 100px;
            }
            QLineEdit, QTextEdit, QSpinBox {
                background: #0b1220;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 8px;
                color: #e2e8f0;
            }
            QSpinBox {
                padding: 6px;
            }
            QPushButton {
                background: #2563eb;
                border: none;
                border-radius: 8px;
                padding: 10px 16px;
                color: white;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #1d4ed8;
            }
            QPushButton:pressed {
                background: #1e40af;
            }
            QPushButton:disabled {
                background: #475569;
                color: #94a3b8;
            }
            QTableWidget {
                background: #0b1220;
                alternate-background-color: #172033;
                gridline-color: #334155;
                selection-background-color: #1d4ed8;
                selection-color: #ffffff;
                border: 1px solid #334155;
                border-radius: 8px;
                color: #e2e8f0;
            }
            QTableWidget::item {
                color: #e2e8f0;
                background-color: transparent;
            }
            QTableWidget::item:selected {
                color: #ffffff;
            }
            QHeaderView::section {
                background: #1e293b;
                color: #e2e8f0;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #334155;
            }
            QProgressBar {
                border: 1px solid #334155;
                border-radius: 8px;
                background: #0b1220;
                text-align: center;
                color: #e2e8f0;
            }
            QProgressBar::chunk {
                background: #22c55e;
                border-radius: 8px;
            }
            QCheckBox {
                spacing: 6px;
            }
            QListWidget {
                background: #0b1220;
                border: 1px solid #334155;
                border-radius: 8px;
                color: #e2e8f0;
            }
        """)
        font = QFont("Microsoft YaHei", 10)
        self.setFont(font)

    # ── 文件操作 ─────────────────────────────────────

    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择日志文件", "",
            "All Supported (*.log *.txt *.csv *.json *.py);;"
            "Log Files (*.log *.txt *.csv);;"
            "Python Files (*.py);;"
            "JSON Files (*.json);;"
            "All Files (*)"
        )
        if path:
            self.load_file(path)

    def load_file(self, path: str):
        self.file_path = path
        self.file_edit.setText(path)
        self.drop_area.setText(f"✅ 已选择文件：\n{path}\n\n点击\"开始分析\"")
        self.status_label.setText("文件已加载")
        self.detail.setPlainText("")
        self.clear_results()
        self.progress_bar.setValue(0)

    def clear_results(self):
        self.table.setRowCount(0)
        self.ip_table.setRowCount(0)
        self.findings.clear()
        self.ip_stats.clear()
        self.ip_geo.clear()

    # ── 分析流程 ─────────────────────────────────────

    def start_analysis(self):
        if not self.file_path:
            QMessageBox.warning(self, "提示", "请先选择或拖入日志文件。")
            return

        # 检查文件大小
        try:
            size_mb = os.path.getsize(self.file_path) / (1024 * 1024)
            if size_mb > self.config.config.max_file_size_mb:
                QMessageBox.warning(
                    self, "提示",
                    f"文件大小 {size_mb:.1f}MB 超过限制 "
                    f"{self.config.config.max_file_size_mb}MB，仍将尝试分析。"
                )
        except Exception:
            pass

        self.clear_results()
        self.status_label.setText("准备分析...")
        self.progress_bar.setValue(0)

        # 更新分析器阈值
        self.analyzer.risk_threshold = self.config.risk_threshold

        # 更新高亮关键词
        self.highlight_delegate.set_highlight_words(self.rule_engine.all_keywords)

        # 启动工作线程
        self.worker = LogAnalysisWorker(
            file_path=self.file_path,
            rule_engine=self.rule_engine,
            whitelist=self.whitelist,
            risk_threshold=self.config.risk_threshold,
        )
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.status.connect(self.status_label.setText)
        self.worker.finding_found.connect(self._on_finding_found)
        self.worker.finished_analysis.connect(self._on_analysis_finished)
        self.worker.finished.connect(self._on_worker_done)

        self.btn_analyze.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.worker.start()

    def cancel_analysis(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.status_label.setText("正在取消...")
            self.btn_cancel.setEnabled(False)

    def _on_finding_found(self, finding: Finding):
        """流式接收每条发现（增量更新表格）"""
        self.findings.append(finding)
        self.ip_stats[finding.ip] = self.ip_stats.get(finding.ip, 0) + 1
        # 增量添加行
        self._append_table_row(finding)

    def _append_table_row(self, finding: Finding):
        """在表格末尾追加一行"""
        row = self.table.rowCount()
        self.table.setSortingEnabled(False)
        self.table.insertRow(row)

        geo_str = ""
        if self.geoip_check.isChecked() and self.geoip_resolver:
            geo_info = self.geoip_resolver.lookup(finding.ip)
            self.ip_geo[finding.ip] = geo_info
            geo_str = geo_info.summary()

        values = [
            str(finding.line_no),
            finding.ip,
            geo_str,
            str(finding.score),
            finding.categories,
            finding.matched,
        ]
        for col, value in enumerate(values):
            cell = QTableWidgetItem(value)
            if col in (0, 3):
                cell.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, col, cell)

        self.table.setSortingEnabled(True)

    def _on_analysis_finished(self, findings, ip_stats):
        self.findings = findings
        self.ip_stats = ip_stats
        self._refresh_full_table()
        self._populate_ip_table()

        if not findings:
            self.detail.setPlainText(
                "未发现达到阈值的攻击行为。\n\n"
                f"当前阈值：{self.config.risk_threshold}\n\n"
                "可能原因：\n"
                "1. 日志中没有攻击特征\n"
                "2. 阈值设置过高\n"
                "3. 匹配的IP/模式在白名单中\n"
                "4. 文件格式太特殊，当前解析器还没覆盖到"
            )
        else:
            self.detail.setPlainText(
                f"✅ 分析完成。\n"
                f"命中记录：{len(findings)}\n"
                f"攻击IP数：{len(ip_stats)}\n"
                f"日志文件：{self.file_path}\n"
                f"当前阈值：{self.config.risk_threshold}"
            )

    def _on_worker_done(self):
        self.btn_analyze.setEnabled(True)
        self.btn_cancel.setEnabled(False)

    # ── 表格填充 ─────────────────────────────────────

    def _refresh_full_table(self, findings=None):
        """全量刷新结果表格（用于过滤后重新显示）"""
        data = findings if findings is not None else self.findings
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(data))

        for row, item in enumerate(data):
            geo_str = ""
            if item.ip in self.ip_geo:
                geo_str = self.ip_geo[item.ip].summary()

            values = [
                str(item.line_no), item.ip, geo_str,
                str(item.score), item.categories, item.matched,
            ]
            for col, value in enumerate(values):
                cell = QTableWidgetItem(value)
                if col in (0, 3):
                    cell.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, col, cell)

        self.table.resizeColumnsToContents()
        self.table.setSortingEnabled(True)

    def _populate_ip_table(self):
        sorted_ips = sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)
        self.ip_table.setRowCount(len(sorted_ips))

        for row, (ip, count) in enumerate(sorted_ips):
            self.ip_table.setItem(row, 0, QTableWidgetItem(ip))

            # 地理位置
            geo_str = ""
            country = ""
            if ip in self.ip_geo:
                g = self.ip_geo[ip]
                geo_str = g.summary()
                country = g.flag() + " " + g.country if g.country else ""
            self.ip_table.setItem(row, 1, QTableWidgetItem(geo_str))

            count_item = QTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignCenter)
            self.ip_table.setItem(row, 2, count_item)

            self.ip_table.setItem(row, 3, QTableWidgetItem(country))

        self.ip_table.resizeColumnsToContents()

    # ── 详情 ─────────────────────────────────────────

    def show_selected_detail(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return

        row = rows[0].row()
        if row < 0 or row >= len(self.findings):
            return

        item = self.findings[row]

        # 地理位置信息
        geo_str = ""
        if item.ip in self.ip_geo:
            g = self.ip_geo[item.ip]
            geo_str = (
                f"\n地理位置：{g.summary()}\n"
                f"国旗：{g.flag()}\n"
                f"国家：{g.country}\n"
                f"城市：{g.city}\n"
                f"坐标：{g.latitude}, {g.longitude}\n"
                f"组织：{g.org}\n"
            )

        detail_text = (
            f"行号：{item.line_no}\n"
            f"IP：{item.ip}"
            f"{geo_str}\n"
            f"风险分：{item.score}\n"
            f"攻击类型：{item.categories}\n"
            f"命中特征：{item.matched}\n"
            f"\n解码后内容：\n{item.normalized}\n"
            f"\n原始日志：\n{item.raw}"
        )
        self.detail.setPlainText(detail_text)

    # ── 过滤 ─────────────────────────────────────────

    def _apply_filters(self, text: str, min_score: int, max_score: int):
        """应用搜索和分数过滤"""
        if not self.findings:
            return

        filtered = self.analyzer.filter_by_search(
            self.findings,
            text=text,
            min_score=min_score,
            max_score=max_score,
        )
        self._refresh_full_table(filtered)
        self.status_label.setText(
            f"过滤结果：{len(filtered)}/{len(self.findings)} 条"
        )

    # ── 阈值变更 ─────────────────────────────────────

    def _on_threshold_changed(self, value: int):
        self.config.risk_threshold = value
        self.analyzer.risk_threshold = value
        self.config.save()

        if self.findings:
            # 实时重新过滤
            text = self.filter_bar.search_edit.text()
            min_s = self.filter_bar.min_score.value()
            max_s = self.filter_bar.max_score.value()
            filtered = self.analyzer.filter_by_search(
                [f for f in self.findings if f.score >= value],
                text=text, min_score=min_s, max_score=max_s,
            )
            self._refresh_full_table(filtered)
            self.status_label.setText(
                f"阈值={value}，显示 {len(filtered)}/{len(self.findings)} 条"
            )

    # ── GeoIP 开关 ──────────────────────────────────

    def _on_geoip_toggled(self, state: int):
        enabled = state == Qt.Checked
        self.config.geoip_enabled = enabled
        self.config.save()

        if enabled and self.geoip_resolver is None:
            db_path = self.config.config.geoip_db_path
            self.geoip_resolver = get_resolver(db_path)

        if self.findings:
            # 重新查询
            if enabled and self.geoip_resolver:
                ips = list(self.ip_stats.keys())
                for ip in ips:
                    if ip not in self.ip_geo:
                        self.ip_geo[ip] = self.geoip_resolver.lookup(ip)
            self._refresh_full_table()
            self._populate_ip_table()

    # ── 白名单 ──────────────────────────────────────

    def _open_whitelist_dialog(self):
        dialog = WhitelistDialog(self.whitelist, self)
        dialog.exec_()

    # ── 导出 ────────────────────────────────────────

    def export_report(self):
        if not self.findings:
            QMessageBox.information(self, "提示", "没有可导出的分析结果。")
            return

        save_path, selected_filter = QFileDialog.getSaveFileName(
            self, "导出报告", "log_report.html",
            "HTML Files (*.html);;CSV Files (*.csv);;Text Files (*.txt)"
        )
        if not save_path:
            return

        try:
            export_report(
                file_path=save_path,
                findings=self.findings,
                source_file=self.file_path,
                ip_stats=self.ip_stats,
                ip_geo=self.ip_geo if self.ip_geo else None,
            )
            QMessageBox.information(self, "成功", f"报告已导出：\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出失败：{e}")
