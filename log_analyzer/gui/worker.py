"""后台分析线程 — 支持流式输出和取消"""

from PyQt5.QtCore import QThread, pyqtSignal

from ..analyzer import CancelFlag, LogAnalyzer
from ..models import Finding, SourceEntry
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
        findings = []
        ip_attack_count = {}

        try:
            # 解析日志
            self.status.emit("正在解析日志文件...")
            entries = collect_entries(
                self.file_path,
                attack_hints=self.rule_engine.all_keywords,
            )
            total = max(len(entries), 1)
            self.status.emit(f"开始分析... 共读取 {len(entries)} 条记录")

            # 创建分析器
            analyzer = LogAnalyzer(
                rule_engine=self.rule_engine,
                whitelist=self.whitelist,
                risk_threshold=self.risk_threshold,
            )

            # 流式分析（回调在主线程通过信号发射）
            def on_finding(finding: Finding):
                findings.append(finding)
                # 更新 ip 统计
                ip_attack_count[finding.ip] = ip_attack_count.get(finding.ip, 0) + 1
                self.finding_found.emit(finding)

            def on_progress(current: int, total_count: int, text: str):
                # 检查取消
                if self._cancel.is_set or self.isInterruptionRequested():
                    return
                pct = int(current * 100 / max(total_count, 1))
                self.progress.emit(pct)
                self.status.emit(text)

            def on_status(text: str):
                if not self._cancel.is_set and not self.isInterruptionRequested():
                    self.status.emit(text)

            # 手动迭代（不使用 analyzer.analyze 的回调，因为 QThread 需要手动检查取消）
            self._run_analysis(analyzer, entries, findings, ip_attack_count)

            if not self._cancel.is_set and not self.isInterruptionRequested():
                self.progress.emit(100)
                self.status.emit(f"分析完成，发现 {len(findings)} 条攻击")

        except Exception as e:
            self.status.emit(f"分析失败：{e}")
            findings.clear()
            ip_attack_count.clear()

        self.finished_analysis.emit(findings, ip_attack_count)

    def _run_analysis(
        self,
        analyzer: LogAnalyzer,
        entries: list[SourceEntry],
        findings: list[Finding],
        ip_attack_count: dict[str, int],
    ):
        """内联分析循环（便于在每次迭代检查取消标志）"""
        total = max(len(entries), 1)

        for idx, entry in enumerate(entries, start=1):
            # 检查取消
            if self._cancel.is_set or self.isInterruptionRequested():
                self.status.emit(f"已取消 — 处理了 {idx - 1}/{total} 条")
                return

            if not entry.text.strip():
                continue

            # 白名单检查
            if self.whitelist:
                if self.whitelist.is_ip_whitelisted(entry.ip):
                    continue
                if self.whitelist.is_pattern_whitelisted(entry.text):
                    continue

            from ..parser import extract_ip, normalize_line

            score, categories, matches = self.rule_engine.score_line(
                normalize_line(entry.text)
            )

            if score >= self.risk_threshold:
                ip = entry.ip if entry.ip else extract_ip(entry.text)
                if not ip:
                    ip = "Unknown"

                ip_attack_count[ip] = ip_attack_count.get(ip, 0) + 1
                finding = Finding(
                    line_no=entry.line_no,
                    ip=ip,
                    score=score,
                    categories=", ".join(sorted(categories)) if categories else "Unknown",
                    matched=", ".join(matches),
                    normalized=normalize_line(entry.text)[:250],
                    raw=entry.raw[:250],
                )
                findings.append(finding)
                self.finding_found.emit(finding)

            # 进度
            if idx % 50 == 0 or idx == total:
                pct = int(idx * 100 / total)
                self.progress.emit(pct)
                self.status.emit(f"分析中... {idx}/{total}")
