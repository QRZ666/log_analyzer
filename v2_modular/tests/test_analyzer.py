"""测试分析引擎"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from log_analyzer.analyzer import CancelFlag, LogAnalyzer
from log_analyzer.models import SourceEntry
from log_analyzer.rules import RuleEngine
from log_analyzer.whitelist import WhitelistManager


class TestCancelFlag:
    """取消标志测试"""

    def test_initial_state(self):
        cf = CancelFlag()
        assert not cf.is_set

    def test_set_and_clear(self):
        cf = CancelFlag()
        cf.set()
        assert cf.is_set
        cf.clear()
        assert not cf.is_set


class TestLogAnalyzer:
    """分析器测试"""

    def setup_method(self):
        self.engine = RuleEngine(rules_path="/nonexistent/rules.json")
        self.analyzer = LogAnalyzer(
            rule_engine=self.engine,
            whitelist=None,
            risk_threshold=5,
        )

    def test_scan_behavior_multi_dim(self):
        """多维度攻击 → 扫描行为"""
        entries = [
            SourceEntry(1, "10.0.0.99", "<script>alert(1)", "<script>alert(1)"),
            SourceEntry(2, "10.0.0.99", "../../../etc/passwd", "../../../etc/passwd"),
            SourceEntry(3, "10.0.0.99", "1' or '1'='1", "1' or '1'='1"),
        ]
        result = self.analyzer.analyze(entries)
        assert len(result.findings) >= 3  # 3条攻击 + 1条扫描行为
        scan_findings = [f for f in result.findings if "Scan Behavior" in f.categories]
        assert len(scan_findings) >= 1
        assert "多维度攻击" in scan_findings[0].matched

    def test_scan_behavior_404(self):
        """高404比例 → 目录扫描行为"""
        entries = []
        for i in range(10):
            entries.append(SourceEntry(
                i + 1, "10.0.0.88", f"GET /nonexistent{i} HTTP/1.1",
                f"GET /nonexistent{i} HTTP/1.1", status_code="404",
            ))
        result = self.analyzer.analyze(entries)
        scan_findings = [f for f in result.findings if "Scan Behavior" in f.categories]
        assert len(scan_findings) >= 1
        assert "目录扫描" in scan_findings[0].matched

    def test_detect_sql_injection(self):
        entries = [
            SourceEntry(
                line_no=1, ip="10.0.0.1",
                text="id=1' or '1'='1",
                raw="GET /user.php?id=1' or '1'='1"
            ),
        ]
        result = self.analyzer.analyze(entries)
        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.score >= 5
        assert "SQL Injection" in finding.categories

    def test_no_findings_below_threshold(self):
        entries = [
            SourceEntry(
                line_no=1, ip="10.0.0.1",
                text="GET /index.html HTTP/1.1",
                raw="GET /index.html HTTP/1.1"
            ),
        ]
        result = self.analyzer.analyze(entries)
        assert len(result.findings) == 0

    def test_cancel_analysis(self):
        entries = [SourceEntry(1, "10.0.0.1", "test", "test")] * 1000
        cancel = CancelFlag()
        cancel.set()  # 开始前就取消
        result = self.analyzer.analyze(entries, cancel_flag=cancel)
        assert result.cancelled

    def test_respect_threshold(self):
        """低阈值应检测更多，高阈值应检测更少"""
        entries = [
            SourceEntry(1, "10.0.0.1",
                        "id=1 union select", "GET /?id=1 union select"),
            SourceEntry(2, "10.0.0.2",
                        "normal request", "GET /index.html"),
        ]
        # 阈值=1 应检测到
        analyzer_low = LogAnalyzer(self.engine, risk_threshold=1)
        result_low = analyzer_low.analyze(entries)
        assert len(result_low.findings) >= 1

        # 阈值=999 应该检测不到
        analyzer_high = LogAnalyzer(self.engine, risk_threshold=999)
        result_high = analyzer_high.analyze(entries)
        assert len(result_high.findings) == 0

    def test_filter_by_search(self):
        findings = self._make_sample_findings()
        # 按IP过滤
        result = self.analyzer.filter_by_search(findings, text="10.0.0.1")
        assert len(result) == 1
        assert result[0].ip == "10.0.0.1"

        # 按类型过滤
        result = self.analyzer.filter_by_search(findings, text="XSS")
        assert len(result) == 1
        assert "XSS" in result[0].categories

    def test_filter_by_score_range(self):
        findings = self._make_sample_findings()
        result = self.analyzer.filter_by_search(findings, min_score=8, max_score=100)
        # XSS(8分) + Scanner(10分) = 2条
        assert len(result) == 2

    def test_whitelist_ip(self):
        """白名单IP应被跳过"""
        whitelist = WhitelistManager(
            whitelist_path="/nonexistent/whitelist.json"
        )
        whitelist.add_ip("10.0.0.1")
        analyzer = LogAnalyzer(self.engine, whitelist=whitelist, risk_threshold=5)
        entries = [
            SourceEntry(1, "10.0.0.1", "sqlmap/1.0", "sqlmap/1.0"),
            SourceEntry(2, "10.0.0.2", "sqlmap/1.0", "sqlmap/1.0"),
        ]
        result = analyzer.analyze(entries)
        # 10.0.0.1被白名单跳过，只有10.0.0.2
        assert all(f.ip == "10.0.0.2" for f in result.findings)

    @staticmethod
    def _make_sample_findings():
        from log_analyzer.models import Finding
        return [
            Finding(1, "10.0.0.1", 5, "SQL Injection", "union(2), select(1)",
                    "union select", "union select"),
            Finding(2, "10.0.0.2", 8, "XSS", "<script>(5)",
                    "<script>alert", "<script>alert"),
            Finding(3, "10.0.0.3", 10, "Scanner", "sqlmap(10)",
                    "sqlmap", "sqlmap"),
        ]
