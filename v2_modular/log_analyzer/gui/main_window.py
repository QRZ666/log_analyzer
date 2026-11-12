"""主窗口 — 集成所有配置、分析、过滤、导出功能"""

from collections import Counter
from pathlib import Path

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
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
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from ..analyzer import AnalysisResult
from ..config import ConfigManager
from ..export import export_report
from ..models import Finding, GeoInfo
from ..rules import RuleEngine
from ..whitelist import WhitelistManager
from .highlight_delegate import HighlightDelegate
from .table_model import FindingsTableModel, FindingsFilterProxyModel
from .widgets import DropArea, FilterBar
from .worker import LogAnalysisWorker, GeoIPLookupWorker


class WhitelistDialog(QDialog):
    """白名单管理对话框"""

    def __init__(self, whitelist: WhitelistManager, parent=None, categories=None):
        super().__init__(parent)
        self.original_whitelist = whitelist
        self.whitelist = whitelist.copy()
        self.categories = sorted(set(categories or ()) | {"Scan Behavior"}
                                 | set(whitelist.get_suppressed_categories()))
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

        category_tab = QWidget()
        category_layout = QVBoxLayout(category_tab)
        category_layout.addWidget(QLabel("勾选要压制的攻击类别（下次分析生效）："))
        for category in self.categories:
            check = QCheckBox(category)
            check.setChecked(self.whitelist.is_category_suppressed(category))
            check.toggled.connect(
                lambda checked, name=category: self._toggle_category(name, checked)
            )
            category_layout.addWidget(check)
        category_layout.addStretch()
        tabs.addTab(category_tab, "类别压制")

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

    def _toggle_category(self, category, checked):
        if checked:
            self.whitelist.add_suppressed_category(category)
        else:
            self.whitelist.remove_suppressed_category(category)

    def _save_and_accept(self):
        try:
            self.whitelist.save()
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "保存失败", f"白名单未保存：{exc}")
            return
        self.original_whitelist.replace_from(self.whitelist)
        self.accept()


class LogAnalyzerWindow(QMainWindow):
    """日志分析工具主窗口"""

    def __init__(self, config=None, parent=None):
        super().__init__(parent)
        self.file_path = ""
        self.findings: list[Finding] = []
        self.ip_stats: dict[str, int] = {}
        self.ip_geo: dict[str, GeoInfo] = {}
        self.last_result = None
        self.analysis_threshold = None
        self.worker = None
        self.geoip_worker = None
        self._analysis_running = False
        self._geoip_running = False
        self._cancel_requested = False
        self._closing = False

        # 每个窗口持有自己的组件，避免全局单例串用旧规则/配置。
        self.config = config if config is not None else ConfigManager()
        self.rule_engine = RuleEngine(self.config.config.rules_path)
        self.whitelist = WhitelistManager(self.config.config.whitelist_path)

        self.setWindowTitle(f"Web攻击日志分析工具 v{__version__}")
        self.setMinimumSize(1300, 820)
        self._build_ui()
        self._apply_style()
        self._apply_filters()
        self._update_controls()
        warnings = [getattr(obj, "load_warning", "") for obj in
                    (self.config, self.whitelist)]
        if any(warnings):
            self.status_label.setText("配置提示：" + "；".join(filter(None, warnings)))

    # ── UI 构建 ────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # 标题
        title = QLabel(f"🛡️ Web攻击日志分析工具 v{__version__}")
        title.setObjectName("TitleLabel")
        subtitle = QLabel(
            "支持 SQL注入 / XSS / 命令注入 / LFI&RFI / 扫描器 / 路径穿越 / Python日志  |  "
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

        self.btn_choose = QPushButton("📂 选择文件")
        self.btn_choose.clicked.connect(self.choose_file)
        file_row.addWidget(self.btn_choose)

        # 阈值配置
        file_row.addWidget(QLabel("阈值："))
        self.threshold_spin = QSpinBox()
        self.threshold_spin.setRange(0, 2147483647)
        self.threshold_spin.setValue(self.config.risk_threshold)
        self.threshold_spin.setToolTip("风险分数阈值，达到此分数的记录才会显示")
        self.threshold_spin.valueChanged.connect(self._on_threshold_changed)
        file_row.addWidget(self.threshold_spin)

        # GeoIP 开关
        self.geoip_check = QCheckBox("IP地理")
        self.geoip_check.setChecked(self.config.geoip_enabled)
        self.geoip_check.setToolTip(
            "分析完成后在后台查询；优先离线库，否则将公开IP发送到ipinfo.io。\n"
            "默认关闭；取消查询需等待当前请求超时。"
        )
        self.geoip_check.stateChanged.connect(self._on_geoip_toggled)
        file_row.addWidget(self.geoip_check)

        self.btn_analyze = QPushButton("🔍 开始分析")
        self.btn_analyze.clicked.connect(self.start_analysis)
        file_row.addWidget(self.btn_analyze)

        self.btn_cancel = QPushButton("⏹ 取消")
        self.btn_cancel.clicked.connect(self.cancel_analysis)
        self.btn_cancel.setEnabled(False)
        file_row.addWidget(self.btn_cancel)

        self.btn_whitelist = QPushButton("📋 白名单")
        self.btn_whitelist.clicked.connect(self._open_whitelist_dialog)
        file_row.addWidget(self.btn_whitelist)

        self.btn_export = QPushButton("💾 导出报告")
        self.btn_export.clicked.connect(self.export_report)
        file_row.addWidget(self.btn_export)

        top_layout.addWidget(self.drop_area)
        top_layout.addLayout(file_row)
        main_layout.addWidget(top_box)

        # ── 搜索/过滤栏 ──
        filter_row = QHBoxLayout()
        self.filter_bar = FilterBar()
        self.filter_bar.filter_changed.connect(self._apply_filters)
        filter_row.addWidget(self.filter_bar, 1)
        self.export_visible_only = QCheckBox("仅导出当前筛选结果")
        self.export_visible_only.setChecked(True)
        self.export_visible_only.setToolTip("取消勾选可导出本次分析保留的全部命中记录")
        filter_row.addWidget(self.export_visible_only)
        main_layout.addLayout(filter_row)
        self.results_label = QLabel("显示 0 / 0 条")
        self.results_label.setWordWrap(True)
        main_layout.addWidget(self.results_label)

        # ── 中部：结果列表 + 详情 ──
        mid_layout = QHBoxLayout()

        # 左：结果表格
        left_box = QGroupBox("攻击记录")
        left_layout = QVBoxLayout(left_box)

        self.findings_model = FindingsTableModel(self.findings, self.ip_geo, self)
        self.findings_model.set_geo_visible(self.geoip_check.isChecked())
        self.filter_model = FindingsFilterProxyModel(self)
        self.filter_model.setSourceModel(self.findings_model)
        self.table = QTableView()
        self.table.setModel(self.filter_model)
        self.table.setWordWrap(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setEditTriggers(QTableView.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.AscendingOrder)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.Interactive)
        for column, width in enumerate((60, 130, 140, 70, 160, 220)):
            self.table.setColumnWidth(column, width)

        # 高亮代理
        self.highlight_delegate = HighlightDelegate(
            self.rule_engine.all_keywords, self.table
        )
        # 在"命中特征"列（索引5）应用高亮
        self.table.setItemDelegateForColumn(5, self.highlight_delegate)

        self.table.selectionModel().selectionChanged.connect(self.show_selected_detail)
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
        bottom_box = QGroupBox("IP统计（本次全部命中，包含扫描行为提示）")
        bottom_layout = QVBoxLayout(bottom_box)

        self.ip_table = QTableWidget(0, 4)
        self.ip_table.setHorizontalHeaderLabels(["IP", "地理位置", "命中数（含行为提示）", "国家"])
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
        self.status_label.setWordWrap(True)
        self.geoip_status_label = QLabel("")
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximumHeight(18)
        status_row.addWidget(self.status_label, 2)
        status_row.addWidget(self.geoip_status_label, 1)
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
            QTableView {
                background: #0b1220;
                alternate-background-color: #172033;
                gridline-color: #334155;
                selection-background-color: #1d4ed8;
                selection-color: #ffffff;
                border: 1px solid #334155;
                border-radius: 8px;
                color: #e2e8f0;
            }
            QTableView::item {
                color: #e2e8f0;
                background-color: transparent;
            }
            QTableView::item:selected {
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
        if self._analysis_running or self._geoip_running:
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "选择日志文件", "",
            "All Supported (*.log *.txt *.csv *.json *.py);;"
            "Log Files (*.log *.txt *.csv);;Python Files (*.py);;"
            "JSON Files (*.json);;All Files (*)",
        )
        if path:
            self.load_file(path)

    def load_file(self, path: str):
        if self._analysis_running or self._geoip_running or self._closing:
            return  # 拖放与直接调用同样受保护，旧任务不会写入新文件的结果。
        if not Path(path).is_file():
            QMessageBox.warning(self, "无法加载", "请选择一个存在的日志文件，而不是文件夹。")
            return
        self.file_path = str(Path(path).resolve())
        self.file_edit.setText(self.file_path)
        self.drop_area.setText(f"✅ 已选择文件：\n{self.file_path}\n\n点击\"开始分析\"")
        self.clear_results()
        self.status_label.setText("文件已加载")
        self.progress_bar.setValue(0)

    def clear_results(self):
        self.findings_model.clear()
        self.ip_table.setRowCount(0)
        self.ip_stats.clear()
        self.last_result = None
        self.analysis_threshold = None
        self.detail.clear()
        self.geoip_status_label.clear()
        self._update_result_count()
        self._update_controls()

    # ── 分析流程 ─────────────────────────────────────

    def start_analysis(self):
        if self._analysis_running or self._geoip_running or self._closing:
            return
        if not self.file_path:
            QMessageBox.warning(self, "提示", "请先选择或拖入日志文件。")
            return
        try:
            source = Path(self.file_path)
            if not source.is_file():
                raise OSError("日志文件不存在或不是普通文件")
            size_mb = source.stat().st_size / (1024 * 1024)
            if size_mb > self.config.config.max_file_size_mb:
                QMessageBox.warning(
                    self, "文件超过限制",
                    f"文件大小 {size_mb:.1f}MB 超过配置上限 "
                    f"{self.config.config.max_file_size_mb}MB。\n"
                    "请在配置中调大 max_file_size_mb 后重试。",
                )
                return
        except OSError as exc:
            QMessageBox.warning(self, "无法读取", str(exc))
            return

        self.clear_results()
        self.analysis_threshold = self.config.risk_threshold
        self.status_label.setText("准备分析...")
        self.progress_bar.setValue(0)
        self._cancel_requested = False
        self._analysis_running = True
        self.worker = LogAnalysisWorker(
            self.file_path, self.rule_engine, self.whitelist,
            risk_threshold=self.analysis_threshold, parent=self,
        )
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.status.connect(self._on_worker_status)
        self.worker.findings_found.connect(self._on_findings_found)
        self.worker.completed.connect(self._on_analysis_finished)
        self.worker.finished.connect(self._on_worker_done)
        self.worker.finished.connect(self.worker.deleteLater)
        self._update_controls()
        self.worker.start()

    def _on_worker_status(self, text):
        if not self._cancel_requested:
            self.status_label.setText(text)

    def cancel_analysis(self):
        self._cancel_requested = True
        if self.worker is not None:
            self.worker.cancel()
            self.status_label.setText("正在取消，已得到的结果会保留...")
        if self.geoip_worker is not None:
            self.geoip_worker.cancel()
            self.geoip_status_label.setText("正在取消IP查询（等待当前请求结束）...")
        self._update_controls()

    def _on_findings_found(self, findings: list[Finding]):
        """每批只通知模型一次插入；排序/筛选交给代理，保持记录身份。"""
        self.findings_model.append_findings(findings)
        for finding in findings:
            self.ip_stats[finding.ip] = self.ip_stats.get(finding.ip, 0) + 1
        self._update_result_count()

    def _on_analysis_finished(self, result: AnalysisResult):
        # 正常情况下最终批次已先送达，仅补缺失后缀，绝不重建整个表格。
        if len(self.findings) < len(result.findings):
            self._on_findings_found(result.findings[len(self.findings):])
        elif len(self.findings) > len(result.findings) and result.error:
            result.findings = list(self.findings)
            result.ip_attack_count = Counter(f.ip for f in self.findings)
        self.last_result = result
        self.ip_stats.clear()
        self.ip_stats.update(result.ip_attack_count)
        self._populate_ip_table()
        self._update_result_count()
        if result.error:
            self.status_label.setText(f"分析失败（部分结果）：{result.error}")
        elif result.cancelled:
            self.status_label.setText(f"已取消：已处理 {result.processed_entries} 条，结果不完整")
        else:
            self.status_label.setText(
                f"分析完成：处理 {result.processed_entries} 条，命中 {len(self.findings)} 条"
            )
        if not self.table.selectionModel().hasSelection():
            self._show_result_summary()

    def _show_result_summary(self):
        result = self.last_result
        if result is None:
            self.detail.clear()
            return
        if result.error:
            heading = f"❌ 分析失败，以下仅为部分结果。\n错误：{result.error}"
        elif result.cancelled:
            heading = "⏹ 用户已取消分析，以下仅为部分结果。"
        else:
            heading = "✅ 分析完成。"
        text = (
            f"{heading}\n\n已处理记录：{result.processed_entries}\n"
            f"命中数（含扫描行为提示）：{len(self.findings)}\n"
            f"命中IP数：{len(self.ip_stats)}\n"
            f"分析时阈值：{self.analysis_threshold}\n日志文件：{self.file_path}"
        )
        if not self.findings and not result.error and not result.cancelled:
            text += "\n\n未发现达到阈值的可疑记录；这不代表日志一定安全。"
        self.detail.setPlainText(text)

    def _on_worker_done(self):
        self._analysis_running = False
        self.worker = None
        self._cancel_requested = False
        self._update_controls()
        if self._closing:
            self._finish_close_if_idle()
        elif self.last_result is not None and not (
            self.last_result.error or self.last_result.cancelled
        ):
            self._start_geoip_lookup()

    def _update_controls(self):
        busy = self._analysis_running or self._geoip_running or self._closing
        self.btn_choose.setEnabled(not busy)
        self.drop_area.setEnabled(not busy)
        self.drop_area.setAcceptDrops(not busy)
        self.btn_analyze.setEnabled(not busy)
        self.btn_whitelist.setEnabled(not busy)
        self.threshold_spin.setEnabled(not busy)
        self.geoip_check.setEnabled(not self._closing)
        self.btn_export.setEnabled(bool(self.findings) and not self._analysis_running
                                   and not self._closing)
        self.btn_cancel.setEnabled(busy and not self._closing and not self._cancel_requested)

    def _update_result_count(self):
        text = f"显示 {self.filter_model.rowCount()} / {len(self.findings)} 条"
        if (self.analysis_threshold is not None
                and self.config.risk_threshold < self.analysis_threshold):
            text += (f"  ·  本次按阈值 {self.analysis_threshold} 分析；"
                     "降低阈值后请重新分析，才能找回此前未保留的低分记录。")
        self.results_label.setText(text)

    # ── IP 统计（本次全部命中，不受显示筛选影响） ─────────────

    def _populate_ip_table(self):
        sorted_ips = sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)
        self.ip_table.setRowCount(len(sorted_ips))
        self._ip_rows = {}

        for row, (ip, count) in enumerate(sorted_ips):
            self._ip_rows[ip] = row
            self.ip_table.setItem(row, 0, QTableWidgetItem(ip))

            # 地理位置
            geo_str = ""
            country = ""
            if self.geoip_check.isChecked() and ip in self.ip_geo:
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

    def show_selected_detail(self, *_args):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            self._show_result_summary()
            return
        item = rows[0].data(Qt.UserRole)
        if item is None:
            return
        geo_str = ""
        if self.geoip_check.isChecked() and item.ip in self.ip_geo:
            g = self.ip_geo[item.ip]
            geo_str = (
                f"\n地理位置：{g.summary()}\n国旗：{g.flag()}\n"
                f"国家：{g.country}\n城市：{g.city}\n"
                f"坐标：{g.latitude}, {g.longitude}\n组织：{g.org}\n"
            )
        self.detail.setPlainText(
            f"行号：{item.line_no}\nIP：{item.ip}{geo_str}\n"
            f"风险分：{item.score}\n攻击类型：{item.categories}\n"
            f"命中特征：{item.matched}\n\n解码后内容：\n{item.normalized}\n"
            f"\n原始日志：\n{item.raw}"
        )

    # ── 过滤与配置 ────────────────────────────────────

    def _apply_filters(self, *_args):
        text, minimum, maximum = self.filter_bar.values()
        self.filter_model.set_filters(
            text, minimum, maximum, threshold=self.config.risk_threshold,
        )
        self._update_result_count()

    def _save_config(self):
        try:
            self.config.save()
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "配置未保存", f"本次设置已生效，但无法持久化：{exc}")

    def _on_threshold_changed(self, value: int):
        self.config.risk_threshold = value
        self._save_config()
        self._apply_filters()

    # ── GeoIP：独立任务，不在界面线程请求网络 ────────────

    def _on_geoip_toggled(self, state: int):
        enabled = state == Qt.Checked
        self.config.geoip_enabled = enabled
        self._save_config()
        self.findings_model.set_geo_visible(enabled)
        self._populate_ip_table()
        self.show_selected_detail()
        if not enabled and self.geoip_worker is not None:
            self.geoip_worker.cancel()
        elif enabled:
            self._start_geoip_lookup()

    def _start_geoip_lookup(self):
        if (self._analysis_running or self._geoip_running or self._closing
                or not self.geoip_check.isChecked()):
            return
        ips = [ip for ip in self.ip_stats if ip not in self.ip_geo]
        if not ips:
            return
        self._geoip_running = True
        self._cancel_requested = False
        self.geoip_status_label.setText(f"IP地理查询：0/{len(ips)}")
        self.geoip_worker = GeoIPLookupWorker(
            ips, db_path=self.config.config.geoip_db_path, parent=self,
        )
        self.geoip_worker.resolved.connect(self._on_geoip_results)
        self.geoip_worker.status.connect(self.geoip_status_label.setText)
        self.geoip_worker.finished_lookup.connect(self._on_geoip_finished)
        self.geoip_worker.finished.connect(self._on_geoip_done)
        self.geoip_worker.finished.connect(self.geoip_worker.deleteLater)
        self._update_controls()
        self.geoip_worker.start()

    def _on_geoip_results(self, infos):
        self.findings_model.update_geo(infos)
        if self.geoip_check.isChecked():
            for info in infos:
                row = getattr(self, "_ip_rows", {}).get(info.ip)
                if row is not None:
                    self.ip_table.setItem(row, 1, QTableWidgetItem(info.summary()))
                    self.ip_table.setItem(row, 3, QTableWidgetItem(
                        info.flag() + " " + info.country if info.country else ""
                    ))
        self.show_selected_detail()

    def _on_geoip_finished(self, cancelled, error):
        if error:
            text = f"IP查询失败：{error}"
        elif cancelled:
            text = "IP查询已取消（已查询结果保留）"
        else:
            text = "IP查询完成"
        self.geoip_status_label.setText(text)

    def _on_geoip_done(self):
        self.geoip_worker = None
        self._geoip_running = False
        self._cancel_requested = False
        self._update_controls()
        self._finish_close_if_idle()

    # ── 白名单 ──────────────────────────────────────

    def _open_whitelist_dialog(self):
        if self._analysis_running or self._geoip_running:
            return
        dialog = WhitelistDialog(self.whitelist, self, categories=self.rule_engine.categories)
        if dialog.exec_() == QDialog.Accepted:
            self.status_label.setText("白名单已保存，下次分析生效")

    # ── 导出 ────────────────────────────────────────

    def _export_findings(self):
        self._apply_filters()  # 导出不等待搜索防抖计时器。
        return (self.filter_model.visible_findings() if self.export_visible_only.isChecked()
                else list(self.findings))

    def export_report(self):
        if self._analysis_running:
            return
        findings = self._export_findings()
        if not findings:
            QMessageBox.information(self, "提示", "当前导出范围没有结果；可清除筛选或导出全部命中。")
            return
        save_path, selected_filter = QFileDialog.getSaveFileName(
            self, "导出报告", "log_report.html",
            "HTML Files (*.html);;CSV Files (*.csv);;Text Files (*.txt)",
        )
        if not save_path:
            return
        if not Path(save_path).suffix:
            suffix = ".csv" if "*.csv" in selected_filter else (
                ".txt" if "*.txt" in selected_filter else ".html"
            )
            save_path += suffix
        if self.file_path and Path(save_path).resolve() == Path(self.file_path).resolve():
            QMessageBox.warning(self, "不能覆盖源日志", "请使用另一个报告文件名，保留原始日志。")
            return
        note = "完整分析"
        if self.last_result is not None:
            if self.last_result.error:
                note = f"分析失败，报告仅含部分结果：{self.last_result.error}"
            elif self.last_result.cancelled:
                note = "用户取消分析，报告仅含部分结果"
        scope = "当前筛选" if self.export_visible_only.isChecked() else "全部命中"
        note += f"；范围：{scope}；分析时阈值：{self.analysis_threshold}"
        try:
            export_report(
                file_path=save_path, findings=findings, source_file=self.file_path,
                ip_stats=dict(Counter(item.ip for item in findings)),
                ip_geo=self.ip_geo if self.geoip_check.isChecked() else None,
                analysis_note=note,
            )
            QMessageBox.information(self, "成功", f"已导出 {len(findings)} 条：\n{save_path}")
        except Exception as exc:
            QMessageBox.critical(self, "错误", f"导出失败：{exc}")

    # ── 安全关闭：不销毁仍在运行的QThread ────────────────

    def closeEvent(self, event):
        if self._analysis_running or self._geoip_running:
            self._closing = True
            self.cancel_analysis()
            self.status_label.setText("正在停止后台任务，完成后关闭窗口...")
            event.ignore()
            return
        event.accept()

    def _finish_close_if_idle(self):
        if self._closing and not self._analysis_running and not self._geoip_running:
            QTimer.singleShot(0, self.close)
