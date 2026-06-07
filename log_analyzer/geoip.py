"""IP 地理位置查询 — geoip2 / ipinfo.io 双后端 + LRU 缓存"""

import ipaddress
import json
from collections import OrderedDict
from pathlib import Path
from typing import Optional

from .models import GeoInfo


class LRUCache:
    """简单的 LRU 缓存"""
    def __init__(self, maxsize: int = 512):
        self._maxsize = maxsize
        self._cache: OrderedDict[str, GeoInfo] = OrderedDict()

    def get(self, key: str) -> Optional[GeoInfo]:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def put(self, key: str, value: GeoInfo):
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = value
        while len(self._cache) > self._maxsize:
            self._cache.popitem(last=False)

    def clear(self):
        self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)


def _is_private_ip(ip: str) -> bool:
    """判断是否为内网/保留 IP"""
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except ValueError:
        return True


class GeoIPResolver:
    """IP 地理位置解析器

    优先使用 geoip2 (MaxMind GeoLite2)，失败则回退到 ipinfo.io API。
    """

    def __init__(
        self,
        db_path: str = "",
        cache_size: int = 512,
        timeout: float = 3.0,
    ):
        self._db_path = db_path
        self._cache = LRUCache(maxsize=cache_size)
        self._timeout = timeout
        self._geoip2_reader = None

        # 尝试初始化 geoip2
        if db_path and Path(db_path).exists():
            try:
                import geoip2.database
                self._geoip2_reader = geoip2.database.Reader(db_path)
            except Exception:
                self._geoip2_reader = None

    @property
    def available(self) -> bool:
        """是否有可用的查询后端"""
        return self._geoip2_reader is not None

    def lookup(self, ip: str) -> GeoInfo:
        """查询 IP 地理位置（带缓存）"""
        if not ip or ip == "Unknown":
            return GeoInfo(ip=ip, raw="未知IP")

        # 检查缓存
        cached = self._cache.get(ip)
        if cached:
            return cached

        # 内网 IP 直接返回
        if _is_private_ip(ip):
            info = GeoInfo(ip=ip, country="局域网", city="", raw="内网/保留地址")
            self._cache.put(ip, info)
            return info

        # 尝试 geoip2
        if self._geoip2_reader:
            result = self._lookup_geoip2(ip)
            if result:
                self._cache.put(ip, result)
                return result

        # 回退到 ipinfo.io
        result = self._lookup_ipinfo(ip)
        self._cache.put(ip, result)
        return result

    def _lookup_geoip2(self, ip: str) -> Optional[GeoInfo]:
        try:
            response = self._geoip2_reader.city(ip)
            return GeoInfo(
                ip=ip,
                country=response.country.iso_code or "",
                city=response.city.name or "",
                latitude=response.location.latitude or 0.0,
                longitude=response.location.longitude or 0.0,
                raw=f"{response.country.name or ''}, {response.city.name or ''}".strip(", "),
            )
        except Exception:
            return None

    def _lookup_ipinfo(self, ip: str) -> GeoInfo:
        try:
            import requests
            resp = requests.get(
                f"https://ipinfo.io/{ip}/json",
                timeout=self._timeout,
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                loc = data.get("loc", "0,0").split(",")
                lat = float(loc[0]) if len(loc) >= 2 and loc[0] else 0.0
                lon = float(loc[1]) if len(loc) >= 2 and loc[1] else 0.0
                return GeoInfo(
                    ip=ip,
                    country=data.get("country", ""),
                    city=data.get("city", ""),
                    latitude=lat,
                    longitude=lon,
                    org=data.get("org", ""),
                    raw=f"{data.get('country', '')} {data.get('city', '')} {data.get('org', '')}".strip(),
                )
        except Exception:
            pass

        return GeoInfo(ip=ip, raw="查询失败")

    def bulk_lookup(self, ips: list[str], on_progress=None) -> dict[str, GeoInfo]:
        """批量查询 IP"""
        results = {}
        total = len(ips)
        for idx, ip in enumerate(ips, start=1):
            results[ip] = self.lookup(ip)
            if on_progress:
                on_progress(idx, total)
        return results

    def clear_cache(self):
        self._cache.clear()


# 全局单例
_resolver: Optional[GeoIPResolver] = None


def get_resolver(db_path: str = "") -> GeoIPResolver:
    global _resolver
    if _resolver is None:
        _resolver = GeoIPResolver(db_path=db_path)
    return _resolver


def reset_resolver():
    global _resolver
    _resolver = None
