"""后台分析线程 — 复用 LogAnalyzer.analyze()，通过 Qt 信号与主线程通信"""

from PyQt5.QtCore import QThread, pyqtSignal

from ..analyzer import CancelFlag, LogAnalyzer
from ..models import Finding
from ..parser import collect_entries
from ..rules import RuleEngine
from ..whitelist import WhitelistManager


class LogAnalysisWorker(QThread):
    """日志分析工作线程

    信号：
        progress(int)            — 进度百分比 0-100
        status(str)              — 状态文字
        finding_found(Finding)   — 每发现一条攻击即发射（流式）
        finished_analysis(list, dict) — 完成时发射 (findings, ip_stats)
    """
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finding_found = pyqtSignal(object)       # Finding
    finished_analysis = pyqtSignal(list, dict)

    def __init__(
        self,
        file_path: str,
        rule_engine: RuleEngine,
        whitelist: WhitelistManager,
        risk_threshold: int = 5,
        parent=None,
    ):
        super().__init__(parent)
        self.file_path = file_path
        self.rule_engine = rule_engine
        self.whitelist = whitelist
        self.risk_threshold = risk_threshold
        self._cancel = CancelFlag()

    def cancel(self):
        """请求取消分析"""
        self._cancel.set()
        self.requestInterruption()

    def run(self):
        findings: list[Finding] = []
        ip_attack_count: dict[str, int] = {}

        try:
            # ── 1. 解析日志文件 ──
            self.status.emit("正在解析日志文件...")
            entries = collect_entries(self.file_path)
            total = max(len(entries), 1)
            self.status.emit(f"开始分析... 共读取 {len(entries)} 条记录")

            # ── 2. 创建分析器 ──
            analyzer = LogAnalyzer(
                rule_engine=self.rule_engine,
                whitelist=self.whitelist,
                risk_threshold=self.risk_threshold,
            )

            # ── 3. 流式分析 — 回调通过 Qt 信号发射到主线程 ──
            def on_progress(current: int, total_count: int, text: str):
                if self._cancel.is_set or self.isInterruptionRequested():
                    return
                pct = int(current * 100 / max(total_count, 1))
                self.progress.emit(pct)
                self.status.emit(text)

            def on_status(text: str):
                if not self._cancel.is_set and not self.isInterruptionRequested():
                    self.status.emit(text)

            def on_finding(finding: Finding):
                findings.append(finding)
                ip_attack_count[finding.ip] = (
                    ip_attack_count.get(finding.ip, 0) + 1
                )
                self.finding_found.emit(finding)

            result = analyzer.analyze(
                entries=entries,
                cancel_flag=self._cancel,
                on_progress=on_progress,
                on_finding=on_finding,
                on_status=on_status,
            )

            # 保留 analyzer 内部累积的统计（更准确）
            findings = result.findings
            ip_attack_count = dict(result.ip_attack_count)

            if result.cancelled:
                self.status.emit(
                    f"已取消 — 处理了 {result.processed_entries}/{total} 条"
                )
            else:
                self.progress.emit(100)
                self.status.emit(f"分析完成，发现 {len(findings)} 条攻击")

        except Exception as e:
            self.status.emit(f"分析失败：{e}")
            findings.clear()
            ip_attack_count.clear()

        self.finished_analysis.emit(findings, ip_attack_count)
