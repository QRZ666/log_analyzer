"""测试白名单管理"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from log_analyzer.whitelist import WhitelistManager


class TestWhitelistManager:
    """白名单管理器测试"""

    def setup_method(self):
        self.wl = WhitelistManager(
            whitelist_path="/nonexistent/test_whitelist.json"
        )

    def test_add_and_check_ip(self):
        self.wl.add_ip("192.168.1.100")
        assert self.wl.is_ip_whitelisted("192.168.1.100")
        assert not self.wl.is_ip_whitelisted("192.168.1.200")

    def test_remove_ip(self):
        self.wl.add_ip("10.0.0.1")
        assert self.wl.is_ip_whitelisted("10.0.0.1")
        self.wl.remove_ip("10.0.0.1")
        assert not self.wl.is_ip_whitelisted("10.0.0.1")

    def test_add_and_check_pattern(self):
        self.wl.add_pattern("/healthcheck")
        assert self.wl.is_pattern_whitelisted("GET /healthcheck HTTP/1.1")
        assert not self.wl.is_pattern_whitelisted("GET /admin HTTP/1.1")

    def test_invalid_pattern_raises(self):
        try:
            self.wl.add_pattern("[invalid(regex")
            assert False, "应该抛出 ValueError"
        except ValueError:
            pass

    def test_category_suppression(self):
        self.wl.add_suppressed_category("Scanner")
        assert self.wl.is_category_suppressed("Scanner")
        assert not self.wl.is_category_suppressed("XSS")

    def test_comprehensive_check(self):
        self.wl.add_ip("127.0.0.1")
        self.wl.add_pattern("/api/health")
        assert self.wl.is_whitelisted("127.0.0.1")
        assert self.wl.is_whitelisted("10.0.0.1", "GET /api/health")
        assert not self.wl.is_whitelisted("10.0.0.1", "GET /api/admin")

    def test_get_methods(self):
        self.wl.add_ip("10.0.0.1")
        self.wl.add_ip("10.0.0.2")
        self.wl.add_pattern("/test")
        self.wl.add_suppressed_category("XSS")

        assert "10.0.0.1" in self.wl.get_ips()
        assert "10.0.0.2" in self.wl.get_ips()
        assert "/test" in self.wl.get_patterns()
        assert "XSS" in self.wl.get_suppressed_categories()

    def test_len(self):
        self.wl.add_ip("10.0.0.1")
        self.wl.add_pattern("/test")
        self.wl.add_suppressed_category("XSS")
        assert len(self.wl) == 3
