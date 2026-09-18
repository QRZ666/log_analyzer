"""测试规则引擎"""

import sys
from pathlib import Path

# 确保能导入 log_analyzer
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from log_analyzer.rules import RuleEngine


class TestRuleEngine:
    """规则引擎测试"""

    def test_load_builtin_rules(self):
        """从内置规则加载（不依赖JSON文件）"""
        # 使用不存在的路径触发内置规则回退
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        assert len(engine.categories) >= 4
        assert "SQL Injection" in engine.categories
        assert "XSS" in engine.categories
        assert "Scanner" in engine.categories
        assert "Path Traversal" in engine.categories

    def test_score_sql_injection(self):
        """SQL注入检测"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        score, cats, matches = engine.score_line("id=1' or '1'='1")
        assert score >= 5
        assert "SQL Injection" in cats

    def test_score_union_select(self):
        """UNION SELECT检测"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        score, cats, matches = engine.score_line(
            "union select username,password from users"
        )
        assert score > 0
        assert "SQL Injection" in cats

    def test_score_xss_script(self):
        """XSS script标签检测"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        score, cats, matches = engine.score_line("<script>alert('xss')</script>")
        assert score >= 5
        assert "XSS" in cats

    def test_score_scanner_sqlmap(self):
        """扫描器检测"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        score, cats, matches = engine.score_line("sqlmap/1.0 user-agent")
        assert score >= 10
        assert "Scanner" in cats

    def test_score_path_traversal(self):
        """路径穿越检测"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        score, cats, matches = engine.score_line("../../../etc/passwd")
        # ../ 贡献5分, /etc/passwd 贡献10分, 合计≥5
        assert score >= 5
        assert "Path Traversal" in cats

    def test_clean_input_no_score(self):
        """正常输入不应有分数"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        score, cats, matches = engine.score_line(
            "get /index.html http/1.1 200 1234"
        )
        assert score == 0

    def test_all_keywords(self):
        """获取所有关键词"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        keywords = engine.all_keywords
        assert len(keywords) > 0
        assert "union" in keywords or "UNION" in [k.lower() for k in keywords]
        assert all(isinstance(k, str) for k in keywords)

    def test_advanced_sql_pattern(self):
        """高级SQL模式匹配"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        score, cats, matches = engine.score_line(
            "id=1 union select 1,2,3 from users"
        )
        assert score > 0
        assert "SQL Injection" in cats

    def test_default_threshold(self):
        """默认阈值应在合理范围"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        assert 1 <= engine.default_threshold <= 100

    def test_score_command_injection(self):
        """命令注入检测"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        score, cats, matches = engine.score_line(";whoami")
        assert score >= 5
        assert "Command Injection" in cats

    def test_score_command_injection_pipe(self):
        """管道命令注入"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        score, cats, matches = engine.score_line("|cat /etc/passwd")
        assert score >= 5
        assert "Command Injection" in cats

    def test_score_lfi(self):
        """LFI / RFI 检测"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        score, cats, matches = engine.score_line("?file=php://filter/convert.base64-encode/resource=config")
        assert score >= 5
        assert "LFI / RFI" in cats

    def test_new_categories_exist(self):
        """验证新增的规则类别存在"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        assert "Command Injection" in engine.categories
        assert "LFI / RFI" in engine.categories
        assert len(engine.categories) >= 6  # SQL, XSS, Scanner, PathTrav, CmdInj, LFI

    def test_reload(self):
        """重新加载规则"""
        engine = RuleEngine(rules_path="/nonexistent/rules.json")
        original_count = len(engine.categories)
        engine.reload("/nonexistent/rules.json")
        assert len(engine.categories) == original_count
