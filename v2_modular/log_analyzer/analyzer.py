"""流式分析引擎 — 逐行评分、支持取消、白名单过滤、扫描行为分析"""

import threading
from collections import defaultdict
from typing import Callable, Iterable, Iterator, Optional

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
    """流式日志分析器 — 逐行评分 + 扫描行为分析"""

    # 扫描行为配置
    SCAN_MULTI_DIM_THRESHOLD = 3       # 同一IP触发 ≥3 个不同类别 → 扫描行为
    SCAN_404_RATIO_THRESHOLD = 0.3     # 同一IP的404比例 ≥ 30% → 扫描行为
    SCAN_404_MIN_COUNT = 5             # 至少5次404才考虑扫描
    SCAN_BEHAVIOR_SCORE = 8            # 扫描行为发现的分数

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
        entries: Iterable[SourceEntry],
        cancel_flag: Optional[CancelFlag] = None,
        on_progress: Optional[Callable[[int, int, str], None]] = None,
        on_finding: Optional[Callable[[Finding], None]] = None,
        on_status: Optional[Callable[[str], None]] = None,
        enable_scan_behavior: bool = True,
        total_entries: Optional[int] = None,
    ) -> AnalysisResult:
        """逐条消费 Iterable，不预取、不要求 len，也不保存输入列表。

        原有回调签名不变：on_progress(current, total, status_text)、
        on_finding(finding)、on_status(text)。total_entries 是可选总数提示；
        未知时进度回调的 total 为 0，正常耗尽后改为实际条目数（空输入为
        0）。未耗尽即取消/失败时，无法知道剩余数量，保留提示值或 0。
        processed_entries 包括已消费的空文本、白名单、类别压制条目及
        处理时发生异常的当前条目。

        每次 next() 前后检查取消；iter_entries 的取消耗尽也会被识别。
        读取、评分或回调失败保留部分 findings 并返回 error，取消不算错误。
        取消或读取失败不做扫描后处理。若输入迭代器提供 close()，退出
        时会调用它以释放文件；调用方不应复用已交给分析器的迭代器。
        """
        result = AnalysisResult()
        result.total_entries = max(total_entries, 0) if total_entries is not None else 0
        iterator = None

        def is_cancelled() -> bool:
            stream = iterator if iterator is not None else entries
            return bool(
                (cancel_flag is not None and cancel_flag.is_set)
                or getattr(stream, "cancelled", False)
            )

        def read_failed(exc: Exception) -> None:
            if is_cancelled():
                result.cancelled = True
            elif result.error is None:
                result.error = f"读取日志失败：{str(exc) or type(exc).__name__}"

        def analysis_failed(exc: Exception) -> None:
            if is_cancelled():
                result.cancelled = True
            elif result.error is None:
                result.error = f"分析日志失败：{str(exc) or type(exc).__name__}"

        def report(text: str) -> None:
            if on_progress is not None:
                on_progress(result.processed_entries, result.total_entries, text)
            if on_status is not None:
                on_status(text)

        scan_enabled = (
            enable_scan_behavior
            and self.SCAN_BEHAVIOR_SCORE >= self.risk_threshold
            and (self.whitelist is None
                 or not self.whitelist.is_category_suppressed("Scan Behavior"))
        )
        ip_categories: dict[str, set[str]] = defaultdict(set)
        ip_404_count: dict[str, int] = defaultdict(int)
        ip_total_count: dict[str, int] = defaultdict(int)

        def process_entry(entry: SourceEntry) -> None:
            if not entry.text.strip():
                return
            if self.whitelist is not None:
                if self.whitelist.is_ip_whitelisted(entry.ip):
                    return
                if self.whitelist.is_pattern_whitelisted(entry.text):
                    return

            ip = entry.ip or extract_ip(entry.text) or "Unknown"
            if scan_enabled and entry.status_code:
                ip_total_count[ip] += 1
                if entry.status_code == "404":
                    ip_404_count[ip] += 1

            normalized = normalize_line(entry.text)
            if is_cancelled():
                return
            score, categories, matches = self.engine.score_line(normalized)
            if is_cancelled() or score < self.risk_threshold:
                return

            # 保持旧评分语义：只过滤类别，不重新分摊规则引擎的分数。
            if self.whitelist is not None:
                categories = {
                    category for category in categories
                    if not self.whitelist.is_category_suppressed(category)
                }
                if not categories:
                    return

            result.ip_attack_count[ip] += 1
            if scan_enabled:
                ip_categories[ip].update(categories)
            finding = Finding(
                line_no=entry.line_no, ip=ip, score=score,
                categories=", ".join(sorted(categories)) if categories else "Unknown",
                matched=", ".join(matches), normalized=normalized, raw=entry.raw,
            )
            result.findings.append(finding)
            if on_finding is not None:
                on_finding(finding)

        try:
            if on_status is not None:
                if total_entries is None:
                    on_status("开始流式分析... 总记录数尚未知")
                else:
                    on_status(f"开始分析... 预计 {result.total_entries} 条记录")
        except Exception as exc:
            analysis_failed(exc)

        try:
            if is_cancelled():
                result.cancelled = True
            elif result.error is None:
                try:
                    iterator = iter(entries)
                except Exception as exc:
                    read_failed(exc)

                if iterator is not None:
                    while True:
                        # 不用 for：for 会先拉取下一条，再执行循环内取消检查。
                        if is_cancelled():
                            result.cancelled = True
                            break
                        try:
                            entry = next(iterator)
                        except StopIteration:
                            if is_cancelled():
                                result.cancelled = True
                            else:
                                result.total_entries = result.processed_entries
                            break
                        except Exception as exc:
                            read_failed(exc)
                            break
                        if is_cancelled():
                            result.cancelled = True
                            break

                        result.processed_entries += 1
                        try:
                            process_entry(entry)
                            current = result.processed_entries
                            if not is_cancelled() and (
                                current % 50 == 0
                                or (total_entries is not None and current == total_entries)
                            ):
                                detail = (f"{current}/{result.total_entries}"
                                          if result.total_entries else f"已处理 {current} 条")
                                report(f"分析中... {detail}")
                        except Exception as exc:
                            analysis_failed(exc)
                            break

        finally:
            # 预取消也关闭已经由调用方启动的流，但不调用它的 __iter__/next。
            stream = iterator if iterator is not None else entries
            try:
                close = getattr(stream, "close", None)
                if callable(close):
                    close()
            except Exception as exc:
                read_failed(exc)

        if is_cancelled():
            result.cancelled = True
        if scan_enabled and not result.cancelled and not result.error:
            try:
                for finding in self._detect_scan_behavior(
                    ip_categories, ip_404_count, ip_total_count, is_cancelled,
                ):
                    if is_cancelled():
                        result.cancelled = True
                        break
                    result.findings.append(finding)
                    result.ip_attack_count[finding.ip] += 1
                    if on_finding is not None:
                        on_finding(finding)
            except Exception as exc:
                analysis_failed(exc)
            if is_cancelled():
                result.cancelled = True

        try:
            if result.error:
                report(f"分析失败 — 已处理 {result.processed_entries} 条；{result.error}")
            elif result.cancelled:
                report(f"已取消 — 已处理 {result.processed_entries} 条（部分结果）")
            else:
                report(f"分析完成，发现 {len(result.findings)} 条攻击")
        except Exception as exc:
            # 回调故障也必须返回失败；不要为了再次报告错误反复调用坏回调。
            analysis_failed(exc)
        return result

    def _detect_scan_behavior(
        self,
        ip_categories: dict[str, set[str]],
        ip_404_count: dict[str, int],
        ip_total_count: dict[str, int],
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> Iterator[Finding]:
        """只基于聚合计数逐 IP 推断扫描；阈值、类别压制及取消都有效。"""
        if self.SCAN_BEHAVIOR_SCORE < self.risk_threshold:
            return
        if self.whitelist is not None and self.whitelist.is_category_suppressed("Scan Behavior"):
            return
        seen_ips: set[str] = set()

        # 规则1：同一 IP 触发至少 3 个不同攻击类别。
        for ip, cats in ip_categories.items():
            if should_cancel is not None and should_cancel():
                return
            if len(cats) >= self.SCAN_MULTI_DIM_THRESHOLD:
                seen_ips.add(ip)
                yield Finding(
                    line_no=0, ip=ip, score=self.SCAN_BEHAVIOR_SCORE,
                    categories="Scan Behavior",
                    matched=f"多维度攻击({len(cats)}类: {', '.join(sorted(cats))})",
                    normalized=f"IP {ip} 触发了 {len(cats)} 种不同攻击类型，疑似扫描器行为",
                    raw="",
                )

        # 规则2：404 至少 5 次且比例不低于 30%，同一 IP 只报告一次。
        for ip, count_404 in ip_404_count.items():
            if should_cancel is not None and should_cancel():
                return
            if ip in seen_ips:
                continue
            total = ip_total_count.get(ip, 0)
            if total > 0 and count_404 >= self.SCAN_404_MIN_COUNT:
                ratio = count_404 / total
                if ratio >= self.SCAN_404_RATIO_THRESHOLD:
                    seen_ips.add(ip)
                    yield Finding(
                        line_no=0, ip=ip, score=self.SCAN_BEHAVIOR_SCORE,
                        categories="Scan Behavior",
                        matched=f"目录扫描(404={count_404}/{total}, {ratio:.0%})",
                        normalized=f"IP {ip} 请求了 {count_404}/{total} 个不存在路径(404)，疑似目录扫描",
                        raw="",
                    )

    def filter_by_threshold(
        self, findings: list[Finding], threshold: int
    ) -> list[Finding]:
        """过滤已保存的发现；降低原分析阈值需要重新分析源文件。"""
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
