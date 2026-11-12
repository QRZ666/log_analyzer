"""白名单管理 — IP / 正则模式 / 类别压制"""

import copy
import json
import re
from pathlib import Path
from typing import Optional

from . import paths
from .persistence import atomic_write_json

_DEFAULT_WHITELIST_PATH = paths.SOURCE_ROOT / "whitelist.json"


class WhitelistManager:
    """白名单管理器；对话框可用 copy/replace_from 实现确认后提交。"""

    def __init__(self, whitelist_path: Optional[str] = None):
        self._ips: set[str] = set()
        self._patterns: list[re.Pattern] = []
        self._suppressed_categories: set[str] = set()
        self._unknown_fields: dict = {}
        startup_warning = ""
        if whitelist_path is None:
            whitelist_path = (
                paths.default_data_dir() / "whitelist.json"
                if paths.is_frozen() else _DEFAULT_WHITELIST_PATH
            )
            startup_warning = paths.bootstrap_user_defaults()
        self._path = Path(whitelist_path).expanduser().resolve()
        self.load_warning: str = ""
        self.load()
        self.load_warning = "\n".join(
            warning for warning in (startup_warning, self.load_warning) if warning
        )

    def load(self):
        """健壮加载 JSON；忽略无效字段/条目并提供非致命提示，不自动写盘。"""
        self._ips.clear()
        self._patterns.clear()
        self._suppressed_categories.clear()
        self._unknown_fields = {}
        self.load_warning = ""
        try:
            with self._path.open("r", encoding="utf-8-sig") as stream:
                data = json.load(stream)
        except FileNotFoundError:
            self.load_warning = f"白名单文件不存在，已使用空白名单：{self._path}"
            return
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            self.load_warning = f"无法加载白名单，已使用空白名单：{self._path}（{exc}）"
            return

        if not isinstance(data, dict):
            self.load_warning = "白名单 JSON 顶层必须为对象，已使用空白名单。"
            return

        self._unknown_fields = {
            key: value for key, value in data.items()
            if key not in ("ips", "patterns", "categories")
        }
        warnings = []
        for field in ("ips", "patterns", "categories"):
            values = data.get(field, [])
            if not isinstance(values, list):
                warnings.append(f"白名单字段 {field} 必须为列表，已忽略。")
                continue
            invalid_count = 0
            for value in values:
                if not isinstance(value, str) or not value.strip():
                    invalid_count += 1
                    continue
                if field == "patterns":
                    try:
                        self._patterns.append(re.compile(value, re.IGNORECASE))
                    except (re.error, OverflowError, RecursionError):
                        invalid_count += 1
                elif field == "ips":
                    self._ips.add(value.strip())
                else:
                    self._suppressed_categories.add(value.strip())
            if invalid_count:
                warnings.append(f"白名单字段 {field} 中 {invalid_count} 个无效条目已忽略。")
        self.load_warning = "\n".join(warnings)

    def save(self):
        """原子保存，失败正常抛错且不截断旧白名单。"""
        data = dict(self._unknown_fields)
        data.update({
            "ips": sorted(self._ips),
            "patterns": [p.pattern for p in self._patterns],
            "categories": sorted(self._suppressed_categories),
        })
        paths.ensure_writable_path(self._path)
        atomic_write_json(self._path, data)

    def copy(self) -> "WhitelistManager":
        """纯内存快照：保留保存路径，不调用构造器/load/save 或执行任何 I/O。"""
        snapshot = object.__new__(type(self))
        snapshot._path = self._path
        snapshot.replace_from(self)
        return snapshot

    def replace_from(self, other: "WhitelistManager") -> None:
        """拷贝集合及模式，不修改自己的路径，不读写文件。

        确认流程：draft.save() 成功后再 original.replace_from(draft)。编译后的
        re.Pattern 不可变，可共享；保存它们的列表和其他可变数据都独立复制。
        """
        if not isinstance(other, WhitelistManager):
            raise TypeError("other 必须是 WhitelistManager")
        ips = set(other._ips)
        patterns = list(other._patterns)
        categories = set(other._suppressed_categories)
        unknown_fields = copy.deepcopy(other._unknown_fields)
        self._ips = ips
        self._patterns = patterns
        self._suppressed_categories = categories
        self._unknown_fields = unknown_fields
        self.load_warning = other.load_warning

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
