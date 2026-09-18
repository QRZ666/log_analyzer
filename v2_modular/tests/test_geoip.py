"""测试 IP 地理位置"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from log_analyzer.geoip import GeoIPResolver, LRUCache, _is_private_ip


class TestIsPrivateIP:
    """内网IP检测测试"""

    def test_private_ipv4(self):
        assert _is_private_ip("192.168.1.1")
        assert _is_private_ip("10.0.0.1")
        assert _is_private_ip("172.16.0.1")

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1")
        assert _is_private_ip("::1")

    def test_public_ip(self):
        assert not _is_private_ip("8.8.8.8")
        assert not _is_private_ip("1.1.1.1")


class TestLRUCache:
    """LRU缓存测试"""

    def test_put_and_get(self):
        cache = LRUCache(maxsize=3)
        from log_analyzer.models import GeoInfo
        info = GeoInfo(ip="1.2.3.4", country="US")
        cache.put("1.2.3.4", info)
        result = cache.get("1.2.3.4")
        assert result is not None
        assert result.country == "US"

    def test_cache_miss(self):
        cache = LRUCache(maxsize=3)
        assert cache.get("nonexistent") is None

    def test_eviction(self):
        cache = LRUCache(maxsize=2)
        from log_analyzer.models import GeoInfo
        cache.put("a", GeoInfo(ip="a"))
        cache.put("b", GeoInfo(ip="b"))
        cache.put("c", GeoInfo(ip="c"))  # 应逐出 'a'
        assert cache.get("a") is None
        assert cache.get("b") is not None
        assert cache.get("c") is not None

    def test_len(self):
        cache = LRUCache(maxsize=5)
        from log_analyzer.models import GeoInfo
        cache.put("a", GeoInfo(ip="a"))
        cache.put("b", GeoInfo(ip="b"))
        assert len(cache) == 2


class TestGeoIPResolver:
    """GeoIP解析器测试（不依赖外部数据库）"""

    def test_no_db_available(self):
        resolver = GeoIPResolver(db_path="")
        assert not resolver.available

    def test_private_ip_lookup(self):
        resolver = GeoIPResolver(db_path="")
        result = resolver.lookup("192.168.1.1")
        assert result.country == "局域网" or "内网" in result.raw

    def test_unknown_ip(self):
        resolver = GeoIPResolver(db_path="")
        result = resolver.lookup("Unknown")
        assert "未知" in result.raw

    def test_caching(self):
        resolver = GeoIPResolver(db_path="")
        r1 = resolver.lookup("10.0.0.1")
        r2 = resolver.lookup("10.0.0.1")
        # 应该返回同一个缓存结果
        assert r1.ip == r2.ip
        assert r1.country == r2.country

    def test_clear_cache(self):
        resolver = GeoIPResolver(db_path="")
        resolver.lookup("10.0.0.1")
        assert len(resolver._cache) >= 1
        resolver.clear_cache()
        assert len(resolver._cache) == 0
