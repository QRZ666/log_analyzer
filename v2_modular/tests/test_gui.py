"""排序/筛选身份、任务生命周期和导出范围的离屏回归。"""

from collections import Counter
import threading

import pytest

pytest.importorskip("PyQt5")
from PyQt5.QtCore import Qt, QRect, QTimer
from PyQt5.QtGui import QColor, QCloseEvent, QImage, QPainter
from PyQt5.QtWidgets import QDialog, QStyleOptionViewItem

from log_analyzer.analyzer import AnalysisResult
from log_analyzer.config import ConfigManager
from log_analyzer.models import Finding, GeoInfo
from log_analyzer.gui import main_window as gui
from log_analyzer.gui import worker as workers
from log_analyzer.gui.highlight_delegate import HighlightDelegate
from log_analyzer.gui.table_model import FindingsTableModel, FindingsFilterProxyModel


def finding(number, score=10, ip=None):
    return Finding(number, ip or f"10.0.0.{number}", score, "Scanner", "sqlmap(10)",
                   f"decoded-{number}", f"raw-{number}")


def result_for(items, *, error=None, cancelled=False):
    result = AnalysisResult()
    result.findings = list(items)
    result.ip_attack_count = Counter(item.ip for item in items)
    result.processed_entries = len(items)
    result.error = error
    result.cancelled = cancelled
    return result


@pytest.fixture
def window(qapp, tmp_path, monkeypatch, wait_for):
    messages = []
    for method in ("warning", "information", "critical"):
        monkeypatch.setattr(gui.QMessageBox, method,
                            lambda _self, title, text: messages.append((title, text)))
    config = ConfigManager(str(tmp_path / "config.json"))
    config.save()
    win = gui.LogAnalyzerWindow(config=config)
    win._test_messages = messages
    yield win
    if win._analysis_running or win._geoip_running:
        win.cancel_analysis()
        wait_for(lambda: not win._analysis_running and not win._geoip_running)
    win.close()
    qapp.processEvents()


def test_model_sort_is_numeric_and_keeps_finding_identity(qapp):
    items = [finding(10, 2), finding(2, 100), finding(100, 10)]
    source = FindingsTableModel()
    proxy = FindingsFilterProxyModel()
    proxy.setSourceModel(source)
    source.append_findings(items)
    proxy.sort(3, Qt.DescendingOrder)
    assert [proxy.index(row, 3).data() for row in range(3)] == [100, 10, 2]
    assert proxy.index(0, 0).data(Qt.UserRole) is items[1]
    proxy.sort(0, Qt.AscendingOrder)
    assert [proxy.index(row, 0).data() for row in range(3)] == [2, 10, 100]


def test_model_batches_do_not_reset_and_filter_future_rows(qapp):
    source = FindingsTableModel()
    proxy = FindingsFilterProxyModel()
    proxy.setSourceModel(source)
    proxy.set_filters("raw", 0, 20, threshold=8)
    inserted, reset = [], []
    source.rowsInserted.connect(lambda _parent, first, last: inserted.append((first, last)))
    source.modelReset.connect(lambda: reset.append(True))
    source.append_findings([finding(1, 2), finding(2, 10)])
    source.append_findings([finding(3, 15), finding(4, 100)])
    assert inserted == [(0, 1), (2, 3)]
    assert reset == []
    assert [item.line_no for item in proxy.visible_findings()] == [2, 3]
    assert source.rowCount() == 4


def test_detail_follows_sort_and_filtered_selection(window):
    items = [finding(1, 10), finding(2, 100), finding(3, 20)]
    window._on_findings_found(items)
    window.table.sortByColumn(3, Qt.DescendingOrder)
    window.table.selectRow(0)
    assert "原始日志：\nraw-2" in window.detail.toPlainText()
    window.filter_bar.search_edit.setText("raw-3")
    window.filter_bar._emit_change()
    assert window.filter_model.rowCount() == 1
    window.table.selectRow(0)
    assert "原始日志：\nraw-3" in window.detail.toPlainText()
    assert len(window.findings) == 3


def test_finishing_does_not_reset_or_remove_active_filters(window):
    items = [finding(1), finding(2)]
    window.filter_bar.search_edit.setText("raw-2")
    window.filter_bar._emit_change()
    window._on_findings_found(items)
    resets = []
    window.findings_model.modelReset.connect(lambda: resets.append(True))
    window._on_analysis_finished(result_for(items))
    assert resets == []
    assert window.filter_model.rowCount() == 1
    assert window._export_findings() == [items[1]]
    assert window.findings == items


def test_threshold_is_not_bypassed_by_search_changes(window):
    window.analysis_threshold = 5
    window._on_findings_found([finding(1, 10), finding(2, 25)])
    window.threshold_spin.setValue(20)
    window.filter_bar.search_edit.setText("raw")
    window.filter_bar._emit_change()
    assert [f.score for f in window._export_findings()] == [25]
    window.threshold_spin.setValue(1)
    assert "重新分析" in window.results_label.text()
    window.filter_bar.max_score.setValue(15)
    assert [f.score for f in window._export_findings()] == [10]
    window.filter_bar._clear()
    assert len(window._export_findings()) == 2


@pytest.mark.parametrize("error,cancelled,expected", [
    ("disk failure", False, "分析失败"),
    (None, True, "已取消"),
    (None, False, "分析完成"),
])
def test_outcomes_remain_distinct_after_filtering(window, error, cancelled, expected):
    window._on_analysis_finished(result_for([], error=error, cancelled=cancelled))
    window.filter_bar.search_edit.setText("whatever")
    window.filter_bar._emit_change()
    assert expected in window.status_label.text()
    if error or cancelled:
        assert "✅ 分析完成" not in window.detail.toPlainText()
        assert "部分结果" in window.detail.toPlainText()


def test_complete_evidence_is_shown_in_detail(window):
    item = finding(1)
    item.raw = "begin " + "x" * 8000 + " end"
    item.normalized = item.raw.lower()
    window._on_findings_found([item])
    window.table.selectRow(0)
    assert item.raw in window.detail.toPlainText()


def test_real_worker_pipeline_appends_without_final_reset(window, tmp_path, wait_for):
    path = tmp_path / "batch.log"
    path.write_text("10.0.0.42 sqlmap request\n" * 600, encoding="utf-8")
    window.load_file(str(path))
    resets, batches = [], []
    window.findings_model.modelReset.connect(lambda: resets.append(True))
    window.findings_model.rowsInserted.connect(lambda _p, a, b: batches.append(b - a + 1))
    window.start_analysis()
    assert not window.btn_choose.isEnabled()
    assert not window.threshold_spin.isEnabled()
    wait_for(lambda: not window._analysis_running)
    assert window.last_result.error is None
    assert window.last_result.processed_entries == 600
    assert len(window.findings) == 600
    assert window.filter_model.rowCount() == 600
    assert len(resets) == 1  # 仅开始分析清空一次，没有完成时全量重建。
    assert sum(batches) == 600
    assert len(batches) < 10
    assert window.progress_bar.value() == 100
    assert window.btn_choose.isEnabled()
    assert window.btn_export.isEnabled()


def test_immediate_cancel_keeps_non_success_state(window, tmp_path, wait_for):
    path = tmp_path / "cancel.log"
    path.write_text("10.0.0.42 sqlmap request\n" * 10000, encoding="utf-8")
    window.load_file(str(path))
    window.start_analysis()
    window.cancel_analysis()
    wait_for(lambda: not window._analysis_running)
    assert window.last_result.cancelled
    assert "已取消" in window.status_label.text()
    assert window.progress_bar.value() < 100


def test_loading_another_file_while_busy_is_rejected(window, tmp_path):
    first, second = tmp_path / "first.log", tmp_path / "second.log"
    first.write_text("first", encoding="utf-8")
    second.write_text("second", encoding="utf-8")
    window.load_file(str(first))
    window._analysis_running = True
    try:
        window.load_file(str(second))
        window.start_analysis()
        assert window.file_path == str(first.resolve())
    finally:
        window._analysis_running = False


def test_size_limit_does_not_destroy_previous_results(window, tmp_path):
    source = tmp_path / "big.log"
    source.write_bytes(b"x" * (1024 * 1024 + 1))
    window.load_file(str(source))
    window._on_findings_found([finding(1)])
    window.config.config.max_file_size_mb = 1
    window.start_analysis()
    assert not window._analysis_running
    assert len(window.findings) == 1
    assert window._test_messages[-1][0] == "文件超过限制"


def test_close_is_deferred_until_worker_has_stopped(window, tmp_path, wait_for):
    path = tmp_path / "close.log"
    path.write_text("10.0.0.42 sqlmap\n" * 10000, encoding="utf-8")
    window.load_file(str(path))
    window.start_analysis()
    event = QCloseEvent()
    window.closeEvent(event)
    assert not event.isAccepted()
    assert window._closing
    wait_for(lambda: not window._analysis_running)
    assert window.worker is None


def test_export_matches_visible_rows_order_and_stats(window, tmp_path, monkeypatch):
    items = [finding(1, 10), finding(2, 20), finding(3, 30)]
    window.analysis_threshold = 5
    window._on_findings_found(items)
    window._on_analysis_finished(result_for(items, cancelled=True))
    window.table.sortByColumn(3, Qt.DescendingOrder)
    window.filter_bar.min_score.setValue(15)
    captured = []
    monkeypatch.setattr(gui, "export_report", lambda **kwargs: captured.append(kwargs))
    monkeypatch.setattr(gui.QFileDialog, "getSaveFileName",
                        lambda *_args: (str(tmp_path / "report"), "CSV Files (*.csv)"))
    window.export_report()
    report = captured[0]
    assert report["findings"] == [items[2], items[1]]
    assert report["ip_stats"] == {items[2].ip: 1, items[1].ip: 1}
    assert "部分结果" in report["analysis_note"]
    assert report["file_path"].endswith(".csv")
    window.export_visible_only.setChecked(False)
    window.export_report()
    assert captured[1]["findings"] == items


def test_export_applies_pending_search_and_refuses_source_overwrite(window, tmp_path, monkeypatch):
    source = tmp_path / "source.log"
    source.write_text("original log", encoding="utf-8")
    window.load_file(str(source))
    items = [finding(1), finding(2)]
    window._on_findings_found(items)
    window.filter_bar.search_edit.setText("raw-2")  # 防抖尚未触发。
    assert window._export_findings() == [items[1]]
    monkeypatch.setattr(gui.QFileDialog, "getSaveFileName",
                        lambda *_args: (str(source), "Text Files (*.txt)"))
    window.export_report()
    assert source.read_text(encoding="utf-8") == "original log"
    assert window._test_messages[-1][0] == "不能覆盖源日志"


def test_whitelist_cancel_does_not_change_memory_or_disk(window):
    dialog = gui.WhitelistDialog(window.whitelist, window, categories=["XSS"])
    dialog.ip_edit.setText("8.8.8.8")
    dialog._add_ip()
    dialog._toggle_category("XSS", True)
    dialog.reject()
    assert not window.whitelist.is_ip_whitelisted("8.8.8.8")
    assert not window.whitelist.is_category_suppressed("XSS")
    assert not window.whitelist._path.exists()


def test_whitelist_save_failure_does_not_commit_draft(window, monkeypatch):
    dialog = gui.WhitelistDialog(window.whitelist, window)
    dialog.whitelist.add_ip("8.8.8.8")
    def denied():
        raise PermissionError("read only")
    monkeypatch.setattr(dialog.whitelist, "save", denied)
    dialog._save_and_accept()
    assert dialog.result() != QDialog.Accepted
    assert not window.whitelist.is_ip_whitelisted("8.8.8.8")
    assert window._test_messages[-1][0] == "保存失败"


def test_whitelist_save_commits_only_after_persistence(window):
    dialog = gui.WhitelistDialog(window.whitelist, window)
    dialog.whitelist.add_ip("8.8.8.8")
    dialog._save_and_accept()
    assert dialog.result() == QDialog.Accepted
    assert window.whitelist.is_ip_whitelisted("8.8.8.8")
    assert "8.8.8.8" in window.whitelist._path.read_text(encoding="utf-8")


def test_geoip_uses_background_thread_and_preserves_filters(window, monkeypatch, wait_for):
    main_thread = threading.get_ident()
    lookup_threads, closed, heartbeats = [], [], []
    release = threading.Event()
    class Resolver:
        def __init__(self, db_path=""):
            pass
        def lookup(self, ip):
            lookup_threads.append(threading.get_ident())
            assert release.wait(2), "GUI未能在查询期间继续处理事件"
            return GeoInfo(ip, country="US", city="Test City")
        def close(self):
            closed.append(True)
    monkeypatch.setattr(workers, "GeoIPResolver", Resolver)
    items = [finding(1), finding(2)]
    window._on_findings_found(items)
    window._on_analysis_finished(result_for(items))
    window.filter_bar.search_edit.setText("raw-2")
    window.filter_bar._emit_change()
    window.table.selectRow(0)
    def heartbeat():
        heartbeats.append(True)
        release.set()
    QTimer.singleShot(30, heartbeat)
    window.geoip_check.setChecked(True)
    wait_for(lambda: not window._geoip_running)
    assert heartbeats and lookup_threads
    assert all(thread_id != main_thread for thread_id in lookup_threads)
    assert closed == [True]
    assert window.filter_model.rowCount() == 1
    assert window._export_findings() == [items[1]]
    assert "Test City" in window.detail.toPlainText()
    window.geoip_check.setChecked(False)
    assert window.filter_model.index(0, 2).data() == ""
    assert "Test City" not in window.detail.toPlainText()


def test_highlight_painter_never_draws_into_next_column(qapp):
    source = FindingsTableModel([finding(1)])
    source.findings[0].matched = "sqlmap " + "very long " * 1000
    delegate = HighlightDelegate(["sqlmap"])
    image = QImage(220, 40, QImage.Format_ARGB32)
    background = QColor("magenta")
    image.fill(background)
    option = QStyleOptionViewItem()
    option.rect = QRect(10, 5, 70, 30)
    option.font = qapp.font()
    option.palette = qapp.palette()
    painter = QPainter(image)
    delegate.paint(painter, option, source.index(0, 5))
    painter.end()
    assert all(image.pixelColor(x, 20) == background for x in range(80, 220))
