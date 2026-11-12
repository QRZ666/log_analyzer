"""后台任务：可取消的流式分析、批量 Qt 信号以及独立的 GeoIP 查询。"""

import logging
import time
from collections import Counter

from PyQt5.QtCore import QThread, pyqtSignal

from ..analyzer import AnalysisResult, CancelFlag, LogAnalyzer
from ..geoip import GeoIPResolver
from ..models import Finding
from ..parser import iter_entries
from ..rules import RuleEngine
from ..whitelist import WhitelistManager

logger = logging.getLogger(__name__)


class LogAnalysisWorker(QThread):
    """GUI 仅连接 findings_found / completed，避免逐行跨线程刷新。

    finding_found、finished_analysis 为旧调用方保留；completed 始终携带
    AnalysisResult，可明确区分正常完成、用户取消和读取/分析失败。
    """

    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    findings_found = pyqtSignal(list)
    completed = pyqtSignal(object)
    finding_found = pyqtSignal(object)
    finished_analysis = pyqtSignal(list, dict)

    BATCH_SIZE = 256
    BATCH_INTERVAL = 0.1

    def __init__(
        self, file_path: str, rule_engine: RuleEngine,
        whitelist: WhitelistManager, risk_threshold: int = 5, parent=None,
    ):
        super().__init__(parent)
        self.file_path = file_path
        self.rule_engine = rule_engine
        # 每个任务独立快照，后续配置操作不会改变正在执行的检测。
        self.whitelist = whitelist.copy() if whitelist is not None else None
        self.risk_threshold = risk_threshold
        self._cancel = CancelFlag()

    def cancel(self):
        self._cancel.set()
        self.requestInterruption()

    def run(self):
        pending: list[Finding] = []
        emitted_findings: list[Finding] = []
        result = AnalysisResult()
        last_flush = time.monotonic()
        last_status = last_flush
        last_percent = -1

        def flush(force=False):
            nonlocal pending, last_flush
            now = time.monotonic()
            if pending and (force or len(pending) >= self.BATCH_SIZE
                            or now - last_flush >= self.BATCH_INTERVAL):
                batch, pending = pending, []
                self.findings_found.emit(batch)
                last_flush = now

        def on_bytes(current, total):
            nonlocal last_percent
            if self._cancel.is_set:
                return
            # 读完不等于后处理完成，只有成功的最终结果才显示100%。
            percent = min(99, int(current * 100 / max(total, 1)))
            if percent > last_percent:
                self.progress.emit(percent)
                last_percent = percent
            flush()

        def on_progress(current, total, text):
            nonlocal last_status
            # 在核心意外抛出而没有返回AnalysisResult时也保留最近进度。
            result.processed_entries = current
            result.total_entries = total
            flush()
            now = time.monotonic()
            if not self._cancel.is_set and now - last_status >= self.BATCH_INTERVAL:
                self.status.emit(text)
                last_status = now

        def on_finding(finding):
            pending.append(finding)
            emitted_findings.append(finding)
            # 未连接旧逐条信号时完全跳过，避免给主线程增加事件。
            if self.receivers(self.finding_found):
                self.finding_found.emit(finding)
            flush()

        try:
            self.status.emit("正在检测编码并读取日志（可取消）...")
            entries = iter_entries(
                self.file_path, should_cancel=lambda: self._cancel.is_set,
                on_progress=on_bytes,
            )
            analyzer = LogAnalyzer(
                self.rule_engine, self.whitelist, self.risk_threshold,
            )
            result = analyzer.analyze(
                entries, cancel_flag=self._cancel,
                on_progress=on_progress, on_finding=on_finding,
            )
        except Exception as exc:
            # 核心返回的error保留部分结果；这里保护初始化/接口等意外失败。
            logger.exception("日志分析任务失败")
            result.error = str(exc) or type(exc).__name__
        finally:
            flush(force=True)

        # 对齐 worker 已经分批送达的结果：意外接口/核心故障时核心结果
        # 可能不存在或不含回调前已产生的记录；正常返回时以核心为准，避免重计。
        if result.error and emitted_findings:
            if not result.findings:
                result.findings = list(emitted_findings)
            # 按 Finding 出现次数重建计数，包含 line_no=0 的扫描行为结果，
            # 并避免把核心已经统计过的结果加两遍。
            result.ip_attack_count.clear()
            result.ip_attack_count.update(Counter(finding.ip for finding in result.findings))
        if result.error:
            self.status.emit(f"分析失败：{result.error}")
        elif result.cancelled:
            self.status.emit(f"已取消 — 已处理 {result.processed_entries} 条（部分结果）")
        else:
            self.progress.emit(100)
            self.status.emit(f"分析完成，发现 {len(result.findings)} 条可疑记录")
        self.completed.emit(result)
        self.finished_analysis.emit(result.findings, dict(result.ip_attack_count))


class GeoIPLookupWorker(QThread):
    """网络/离线数据库查询都在后台运行，绝不从表格的paint/data调用网络。

    取消在单次请求间生效；正在进行的HTTP请求由Resolver的超时控制。
    """

    resolved = pyqtSignal(list)
    status = pyqtSignal(str)
    finished_lookup = pyqtSignal(bool, str)

    def __init__(self, ips, db_path="", parent=None):
        super().__init__(parent)
        self.ips = list(dict.fromkeys(ips))
        self.db_path = db_path
        self._cancel = CancelFlag()

    def cancel(self):
        self._cancel.set()
        self.requestInterruption()

    def run(self):
        pending = []
        error = ""
        resolver = None
        last_flush = time.monotonic()
        try:
            if not self._cancel.is_set:
                resolver = GeoIPResolver(db_path=self.db_path)
            for index, ip in enumerate(self.ips, 1):
                if self._cancel.is_set:
                    break
                pending.append(resolver.lookup(ip))
                now = time.monotonic()
                if len(pending) >= 32 or now - last_flush >= 0.1:
                    self.resolved.emit(pending)
                    pending = []
                    self.status.emit(f"IP地理查询：{index}/{len(self.ips)}")
                    last_flush = now
        except Exception as exc:
            logger.exception("IP地理查询失败")
            error = str(exc) or type(exc).__name__
        finally:
            if pending:
                self.resolved.emit(pending)
            if resolver is not None:
                try:
                    resolver.close()
                except Exception as exc:
                    logger.exception("释放GeoIP资源失败")
                    error = error or str(exc) or type(exc).__name__
        self.finished_lookup.emit(self._cancel.is_set, error)
