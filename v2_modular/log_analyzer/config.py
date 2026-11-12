"""配置管理 — 校验加载、稳定路径与原子保存 config.json。"""

import json
from pathlib import Path
from typing import Optional

from . import paths
from .models import AnalyzerConfig
from .persistence import atomic_write_json

_DEFAULT_CONFIG_PATH = paths.SOURCE_ROOT / "config.json"
_PATH_FIELDS = ("rules_path", "whitelist_path", "geoip_db_path")
_CONFIG_FIELDS = (
    "risk_threshold", "geoip_enabled", "geoip_db_path", "max_file_size_mb",
    "rules_path", "whitelist_path",
)
_MAX_CONFIG_INT = 2_147_483_647


class ConfigManager:
    """应用配置管理器；load_warning 为最近一次加载的非致命提示。"""

    def __init__(self, config_path: Optional[str] = None):
        startup_warning = ""
        if config_path is None:
            config_path = (
                paths.default_data_dir() / "config.json"
                if paths.is_frozen() else _DEFAULT_CONFIG_PATH
            )
            startup_warning = paths.bootstrap_user_defaults()
        # 固定实际配置位置，之后改变工作目录不影响加载、默认路径或保存。
        self._path = Path(config_path).expanduser().resolve()
        self._config = AnalyzerConfig()
        self._unknown_fields: dict = {}
        self._path_sources: dict[str, tuple[str, str]] = {}
        self.load_warning: str = ""
        self.load()
        self.load_warning = "\n".join(
            warning for warning in (startup_warning, self.load_warning) if warning
        )

    @property
    def config(self) -> AnalyzerConfig:
        return self._config

    @property
    def risk_threshold(self) -> int:
        return self._config.risk_threshold

    @risk_threshold.setter
    def risk_threshold(self, value: int):
        self._config.risk_threshold = max(0, value)

    @property
    def geoip_enabled(self) -> bool:
        return self._config.geoip_enabled

    @geoip_enabled.setter
    def geoip_enabled(self, value: bool):
        self._config.geoip_enabled = value

    def load(self):
        """无效结构/字段采用默认值；不把修复结果自动写回用户文件。"""
        self.load_warning = ""
        self._apply_defaults()
        try:
            with self._path.open("r", encoding="utf-8-sig") as stream:
                data = json.load(stream)
        except FileNotFoundError:
            self.load_warning = f"配置文件不存在，已使用默认设置：{self._path}"
            return
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            self.load_warning = f"无法加载配置，已使用默认设置：{self._path}（{exc}）"
            return

        if not isinstance(data, dict):
            self.load_warning = "配置 JSON 顶层必须为对象，已使用默认设置。"
            return

        self._unknown_fields = {
            key: value for key, value in data.items() if key not in _CONFIG_FIELDS
        }
        warnings = []
        for field, minimum in (("risk_threshold", 0), ("max_file_size_mb", 1)):
            if field not in data:
                continue
            value = data[field]
            if type(value) is int and minimum <= value <= _MAX_CONFIG_INT:
                setattr(self._config, field, value)
            else:
                warnings.append(f"配置字段 {field} 必须是 {minimum}..{_MAX_CONFIG_INT} 的整数，已使用默认值。")

        if "geoip_enabled" in data:
            if type(data["geoip_enabled"]) is bool:
                self._config.geoip_enabled = data["geoip_enabled"]
            else:
                warnings.append("配置字段 geoip_enabled 必须是布尔值，已使用默认值。")

        for field in _PATH_FIELDS:
            if field not in data:
                continue
            value = data[field]
            optional_empty = field == "geoip_db_path" and value == ""
            if not isinstance(value, str) or "\x00" in value or (not value.strip() and not optional_empty):
                warnings.append(f"配置字段 {field} 不是有效的路径字符串，已使用默认值。")
                continue
            try:
                resolved = self._resolve_path(value)
            except (OSError, ValueError, RuntimeError) as exc:
                warnings.append(f"配置字段 {field} 路径无效，已使用默认值（{exc}）。")
                continue
            setattr(self._config, field, resolved)
            self._path_sources[field] = (value, resolved)
        self.load_warning = "\n".join(warnings)

    def _resolve_path(self, value: str) -> str:
        """相对路径以实际配置目录解析；空 GeoIP 路径保持关闭/未配置语义。"""
        if not value:
            return ""
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = self._path.parent / path
        return str(path.resolve())

    def save(self):
        """原子保存；未知字段及未改动的相对路径保留，失败正常抛给调用者。"""
        data = dict(self._unknown_fields)
        data.update({field: getattr(self._config, field) for field in _CONFIG_FIELDS})
        for field, (original, resolved) in self._path_sources.items():
            if data[field] == resolved:
                data[field] = original
        paths.ensure_writable_path(self._path)
        atomic_write_json(self._path, data)

    def _apply_defaults(self):
        self._config = AnalyzerConfig()
        self._unknown_fields = {}
        self._path_sources = {}
        for field in _PATH_FIELDS:
            value = getattr(self._config, field)
            resolved = self._resolve_path(value)
            setattr(self._config, field, resolved)
            self._path_sources[field] = (value, resolved)
