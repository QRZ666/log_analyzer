"""白名单管理 — IP / 正则模式 / 类别压制"""

import json
import re
from pathlib import Path
from typing import Optional

from .models import WhitelistEntry

_DEFAULT_WHITELIST_PATH = Path(__file__).resolve().parent.parent / "whitelist.json"


class WhitelistManager:
    """白名单管理器"""

    def __init__(self, whitelist_path: Optional[str] = None):
        self._ips: set[str] = set()
        self._patterns: list[re.Pattern] = []
        self._suppressed_categories: set[str] = set()
        self._path = Path(whitelist_path) if whitelist_path else _DEFAULT_WHITELIST_PATH
        self.load()

    def load(self):
        """从 JSON 文件加载白名单"""
        self._ips.clear()
        self._patterns.clear()
        self._suppressed_categories.clear()

        if not self._path.exists():
            return

        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return

        for ip in data.get("ips", []):
            self._ips.add(ip.strip())

        for pattern_str in data.get("patterns", []):
            try:
                self._patterns.append(re.compile(pattern_str, re.IGNORECASE))
            except re.error:
                pass

        for cat in data.get("categories", []):
            self._suppressed_categories.add(cat.strip())

    def save(self):
        """保存白名单到 JSON 文件"""
        data = {
            "ips": sorted(self._ips),
            "patterns": [p.pattern for p in self._patterns],
            "categories": sorted(self._suppressed_categories),
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    # ── IP 白名单 ─────────────────────────────────────────

    def is_ip_whitelisted(self, ip: str) -> bool:
        return ip in self._ips

    def add_ip(self, ip: str):
        self._ips.add(ip.strip())

    def remove_ip(self, ip: str):
        self._ips.discard(ip)

    def get_ips(self) -> list[str]:
        return sorted(self._ips)

    # ── 模式白名单 ────────────────────────────────────────

    def is_pattern_whitelisted(self, text: str) -> bool:
        for pattern in self._patterns:
            if pattern.search(text):
                return True
        return False

    def add_pattern(self, pattern_str: str):
        try:
            compiled = re.compile(pattern_str, re.IGNORECASE)
            self._patterns.append(compiled)
        except re.error:
            raise ValueError(f"无效的正则表达式: {pattern_str}")

    def remove_pattern(self, pattern_str: str):
        self._patterns = [p for p in self._patterns if p.pattern != pattern_str]

    def get_patterns(self) -> list[str]:
        return [p.pattern for p in self._patterns]

    # ── 类别压制 ──────────────────────────────────────────

    def is_category_suppressed(self, category: str) -> bool:
        return category in self._suppressed_categories

    def is_category_suppressed_all(self) -> bool:
        """是否压制了所有类别（罕见情况）"""
        return len(self._suppressed_categories) > 0 and len(self._suppressed_categories) >= 4

    def add_suppressed_category(self, category: str):
        self._suppressed_categories.add(category.strip())

    def remove_suppressed_category(self, category: str):
        self._suppressed_categories.discard(category)

    def get_suppressed_categories(self) -> list[str]:
        return sorted(self._suppressed_categories)

    # ── 批量操作 ──────────────────────────────────────────

    def is_whitelisted(self, ip: str, text: str = "") -> bool:
        """综合检查：IP 或文本是否在白名单中"""
        if self.is_ip_whitelisted(ip):
            return True
        if text and self.is_pattern_whitelisted(text):
            return True
        return False

    def __len__(self) -> int:
        return len(self._ips) + len(self._patterns) + len(self._suppressed_categories)
