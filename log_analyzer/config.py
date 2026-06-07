"""配置管理 — 加载/保存 config.json"""

import json
from pathlib import Path
from typing import Optional

from .models import AnalyzerConfig

_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"


class ConfigManager:
    """应用配置管理器"""

    def __init__(self, config_path: Optional[str] = None):
        self._path = Path(config_path) if config_path else _DEFAULT_CONFIG_PATH
        self._config = AnalyzerConfig()
        self.load()

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
        """从 JSON 文件加载配置"""
        if not self._path.exists():
            self._apply_defaults()
            return

        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            self._apply_defaults()
            return

        self._config = AnalyzerConfig(
            risk_threshold=data.get("risk_threshold", 5),
            geoip_enabled=data.get("geoip_enabled", False),
            geoip_db_path=data.get("geoip_db_path", ""),
            max_file_size_mb=data.get("max_file_size_mb", 100),
            rules_path=data.get("rules_path", "rules.json"),
            whitelist_path=data.get("whitelist_path", "whitelist.json"),
        )

    def save(self):
        """保存配置到 JSON 文件"""
        data = {
            "risk_threshold": self._config.risk_threshold,
            "geoip_enabled": self._config.geoip_enabled,
            "geoip_db_path": self._config.geoip_db_path,
            "max_file_size_mb": self._config.max_file_size_mb,
            "rules_path": self._config.rules_path,
            "whitelist_path": self._config.whitelist_path,
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _apply_defaults(self):
        self._config = AnalyzerConfig()
