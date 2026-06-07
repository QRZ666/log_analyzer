"""数据模型定义"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """单条攻击发现"""
    line_no: int
    ip: str
    score: int
    categories: str          # 逗号分隔的攻击类型
    matched: str             # 逗号分隔的命中特征
    normalized: str          # 解码后的文本
    raw: str                 # 原始日志行


@dataclass
class SourceEntry:
    """日志源条目（解析后待分析的一行）"""
    line_no: int
    ip: str
    text: str                # 提取的有效文本
    raw: str                 # 原始行


@dataclass
class WhitelistEntry:
    """白名单条目"""
    entry_type: str          # "ip" | "pattern" | "category"
    value: str               # IP地址 / 正则模式 / 类别名
    description: str = ""    # 备注


@dataclass
class GeoInfo:
    """IP 地理位置信息"""
    ip: str
    country: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    org: str = ""
    raw: str = ""            # 原始返回文本（用于展示）

    def summary(self) -> str:
        parts = []
        if self.country:
            parts.append(self.country)
        if self.city:
            parts.append(self.city)
        if self.org:
            parts.append(self.org)
        return ", ".join(parts) if parts else "未知"

    def flag(self) -> str:
        """将国家代码转为国旗emoji"""
        if not self.country or len(self.country) != 2:
            return ""
        try:
            base = 0x1F1E6
            offset_a = ord('A')
            return chr(base + ord(self.country[0].upper()) - offset_a) + \
                   chr(base + ord(self.country[1].upper()) - offset_a)
        except Exception:
            return ""


@dataclass
class RuleCategory:
    """规则类别定义"""
    name: str
    keywords: dict[str, int]           # keyword -> score
    advanced_patterns: list[dict] = field(default_factory=list)  # [{pattern, score}]


@dataclass
class AnalyzerConfig:
    """分析器配置"""
    risk_threshold: int = 5
    geoip_enabled: bool = False
    geoip_db_path: str = ""
    max_file_size_mb: int = 100
    rules_path: str = "rules.json"
    whitelist_path: str = "whitelist.json"
