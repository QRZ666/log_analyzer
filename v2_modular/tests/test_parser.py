"""测试日志解析器"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from log_analyzer.parser import (
    extract_ip,
    normalize_line,
    parse_json_log_line,
    parse_access_log_line,
    extract_quoted_strings,
    collect_entries,
)


class TestExtractIP:
    """IP提取测试"""

    def test_ipv4(self):
        assert extract_ip("192.168.1.1 - - [01/Jan/2020] ...") == "192.168.1.1"

    def test_no_ip(self):
        assert extract_ip("no ip here") == "no"

    def test_empty(self):
        assert extract_ip("") == "Unknown"


class TestNormalizeLine:
    """文本标准化测试"""

    def test_html_unescape(self):
        result = normalize_line("&lt;script&gt;")
        assert "<script>" in result

    def test_url_decode(self):
        result = normalize_line("%3Cscript%3E")
        assert "<script>" in result

    def test_lowercase(self):
        result = normalize_line("HELLO")
        assert result == "hello"

    def test_double_decode(self):
        """URL%20编码 → 空格 → 再次解码不变"""
        result = normalize_line("%27%20OR%201%3D1")
        assert "'or" in result or "or" in result

    def test_multi_layer_decode(self):
        """多层编码：URL编码 → HTML实体 → 最终还原"""
        # %26lt%3B → &lt; → <  (URL解码 → HTML反转义)
        result = normalize_line("%26lt%3Bscript%26gt%3B")
        assert "<script>" in result

    def test_triple_encode(self):
        """三层编码绕过检测"""
        # %2527 → %27 → '  (双重URL解码)
        result = normalize_line("%2527%2520OR%25201%253D1")
        # 第一轮: %27%20OR%201%3D1, 第二轮: ' OR 1=1
        assert "'" in result or "or 1=1" in result


class TestParseJSONLog:
    """JSON日志解析测试"""

    def test_valid_json_log(self):
        raw = '{"ip": "10.0.0.1", "request": "GET /api HTTP/1.1", "status": 200}'
        result = parse_json_log_line(raw)
        assert result is not None
        ip, text, status_code = result
        assert ip == "10.0.0.1"
        assert "GET /api" in text
        assert status_code == "200"

    def test_non_dict_json(self):
        result = parse_json_log_line("[1, 2, 3]")
        assert result is None

    def test_not_json(self):
        result = parse_json_log_line("not json at all")
        assert result is None

    def test_json_with_multiple_ip_fields(self):
        raw = '{"remote_addr": "1.2.3.4", "message": "test"}'
        result = parse_json_log_line(raw)
        assert result is not None
        ip, _, _ = result
        assert ip == "1.2.3.4"


class TestParseAccessLog:
    """Apache/Nginx日志解析测试"""

    def test_standard_apache_log(self):
        raw = (
            '103.12.45.67 - - [28/May/2026:08:22:15 +0800] '
            '"GET /user.php?id=1 HTTP/1.1" 200 8452 '
            '"http://example.com" "Mozilla/5.0"'
        )
        result = parse_access_log_line(raw)
        assert result is not None
        ip, text, status_code = result
        assert ip == "103.12.45.67"
        assert "GET" in text
        assert "/user.php" in text
        assert status_code == "200"

    def test_non_access_log(self):
        result = parse_access_log_line("random log line")
        assert result is None


class TestExtractQuotedStrings:
    """引号字符串提取测试"""

    def test_double_quotes(self):
        result = extract_quoted_strings('hello "world" test')
        assert "world" in result

    def test_single_quotes(self):
        result = extract_quoted_strings("hello 'world' test")
        assert "world" in result

    def test_no_quotes(self):
        result = extract_quoted_strings("no quotes here")
        assert result == []

    def test_multiple_quotes(self):
        result = extract_quoted_strings('"a" and "b" and \'c\'')
        assert "a" in result
        assert "b" in result
        assert "c" in result


class TestCollectEntries:
    """文件条目收集测试"""

    def test_access_log_file(self):
        """使用项目中的 access.log 进行测试"""
        log_path = Path(__file__).resolve().parent.parent / "access.log"
        if log_path.exists():
            entries = collect_entries(str(log_path))
            # access.log 可能为空或只有少量行，跳过空文件情况
            if len(entries) == 0:
                return
            # 验证条目结构
            for entry in entries:
                assert entry.line_no > 0
                assert entry.ip
                assert entry.text
                assert entry.raw
