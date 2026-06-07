"""流式分析引擎 — 逐行评分、支持取消、白名单过滤"""

import threading
from collections import defaultdict
from typing import Callable, Optional

from .models import Finding, SourceEntry
from .parser import extract_ip, normalize_line
from .rules import RuleEngine
from .whitelist import WhitelistManager


class CancelFlag:
    """协作式取消标志 — 线程安全"""
    def __init__(self):
        self._event = threading.Event()

    @property
    def is_set(self) -> bool:
        return self._event.is_set()

    def set(self):
        self._event.set()

    def clear(self):
        self._event.clear()


class AnalysisResult:
    """分析结果容器"""
    def __init__(self):
        self.findings: list[Finding] = []
        self.ip_attack_count: dict[str, int] = defaultdict(int)
        self.total_entries: int = 0
        self.processed_entries: int = 0
        self.cancelled: bool = False
        self.error: Optional[str] = None


class LogAnalyzer:
    """流式日志分析器"""

    def __init__(
        self,
        rule_engine: RuleEngine,
        whitelist: Optional[WhitelistManager] = None,
        risk_threshold: int = 5,
    ):
        self.engine = rule_engine
        self.whitelist = whitelist
        self.risk_threshold = risk_threshold

    def analyze(
        self,
        entries: list[SourceEntry],
        cancel_flag: Optional[CancelFlag] = None,
        on_progress: Optional[Callable[[int, int, str], None]] = None,
        on_finding: Optional[Callable[[Finding], None]] = None,
        on_status: Optional[Callable[[str], None]] = None,
    ) -> AnalysisResult:
        """
        流式分析日志条目。

        参数：
            entries: 待分析的 SourceEntry 列表
            cancel_flag: 取消标志
            on_progress: 进度回调 (current, total, status_text)
            on_finding: 每发现一条攻击即回调
            on_status: 状态文字回调

        返回：AnalysisResult
        """
        result = AnalysisResult()
        result.total_entries = max(len(entries), 1)

        if on_status:
            on_status(f"开始分析... 共读取 {len(entries)} 条记录")

        for idx, entry in enumerate(entries, start=1):
            # 检查取消
            if cancel_flag and cancel_flag.is_set:
                result.cancelled = True
                if on_status:
                    on_status(f"已取消 — 处理了 {idx - 1}/{len(entries)} 条")
                return result

            if not entry.text.strip():
                continue

            # 白名单检查
            if self.whitelist:
                if self.whitelist.is_ip_whitelisted(entry.ip):
                    continue
                if self.whitelist.is_pattern_whitelisted(entry.text):
                    continue
                if self.whitelist.is_category_suppressed_all():
                    # 全类别压制意味着跳过所有，但一般不会
                    pass

            score, categories, matches = self.engine.score_line(
                normalize_line(entry.text)
            )

            if score >= self.risk_threshold:
                ip = entry.ip if entry.ip else extract_ip(entry.text)
                if not ip:
                    ip = "Unknown"

                result.ip_attack_count[ip] += 1
                finding = Finding(
                    line_no=entry.line_no,
                    ip=ip,
                    score=score,
                    categories=", ".join(sorted(categories)) if categories else "Unknown",
                    matched=", ".join(matches),
                    normalized=normalize_line(entry.text)[:250],
                    raw=entry.raw[:250],
                )
                result.findings.append(finding)

                if on_finding:
                    on_finding(finding)

            result.processed_entries = idx

            # 进度回调（每 50 条或最后一条）
            if idx % 50 == 0 or idx == len(entries):
                if on_progress:
                    on_progress(idx, len(entries), f"分析中... {idx}/{len(entries)}")
                if on_status:
                    on_status(f"分析中... {idx}/{len(entries)}")

        if on_progress:
            on_progress(len(entries), len(entries), f"分析完成，发现 {len(result.findings)} 条攻击")
        if on_status:
            on_status(f"分析完成，发现 {len(result.findings)} 条攻击")

        return result

    def filter_by_threshold(
        self, findings: list[Finding], threshold: int
    ) -> list[Finding]:
        """按新阈值过滤已有结果（无需重新分析）"""
        return [f for f in findings if f.score >= threshold]

    def filter_by_search(
        self,
        findings: list[Finding],
        text: str = "",
        categories: Optional[list[str]] = None,
        min_score: int = 0,
        max_score: int = 999,
    ) -> list[Finding]:
        """多条件过滤已有结果"""
        results = findings
        if text:
            text_lower = text.lower()
            results = [
                f for f in results
                if text_lower in f.ip.lower()
                or text_lower in f.categories.lower()
                or text_lower in f.matched.lower()
                or text_lower in f.normalized.lower()
                or text_lower in f.raw.lower()
            ]
        if categories:
            results = [
                f for f in results
                if any(cat in f.categories for cat in categories)
            ]
        results = [f for f in results if min_score <= f.score <= max_score]
        return results
