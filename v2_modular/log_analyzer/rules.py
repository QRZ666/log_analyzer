"""规则引擎 — 从 JSON 加载规则、编译正则、对日志行评分"""

import json
import re
from pathlib import Path
from typing import Optional

from .models import RuleCategory

# 默认规则 JSON 路径（相对于项目根目录）
_DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules.json"

# 内置后备规则（JSON 加载失败时使用）
_BUILTIN_RULES = {
    "SQL Injection": {
        "keywords": {
            "union": 2, "select": 1, "or 1=1": 5, "or'1'='1": 5,
            "or '1'='1": 5, "and 1=1": 5, "and'1'='1": 5,
            "and '1'='1": 5, "1=1": 3, "sleep(": 5, "benchmark(": 5,
            "information_schema": 4, "load_file": 5, "into outfile": 5,
            "into dumpfile": 5, "updatexml": 5, "extractvalue": 5,
            "concat(": 2, "group_concat": 3, "--": 2, "#": 2, "/*": 2,
            "id=": 1, "%27or": 5, "or%27": 5,
        },
        "advanced_patterns": [
            {"pattern": r"'\s+or\s+'\w+'\s*=\s*'\w+'", "score": 4},
            {"pattern": r"'\s+and\s+'\w+'\s*=\s*'\w+'", "score": 4},
            {"pattern": r"id\s*=\s*\d+'\s+(or|and)", "score": 3},
            {"pattern": r"\d+\s+(or|and)\s+\d+\s*=\s*\d+", "score": 3},
            {"pattern": r"union\s+select", "score": 4},
            {"pattern": r"union\s+all\s+select", "score": 4},
            {"pattern": r"select\s+.+\s+from\s+", "score": 2},
        ],
    },
    "XSS": {
        "keywords": {
            "<script>": 5, "<script": 4, "alert(": 3, "onerror=": 5,
            "onload=": 5, "javascript:": 4, "onclick=": 4, "onmouseover": 4,
            "onfocus=": 4, "onblur=": 4, "onsubmit=": 4, "onkeydown=": 4,
            "onkeyup=": 4, "<img": 3, "<svg": 3, "<iframe": 4,
            "prompt(": 3, "confirm(": 3, "eval(": 3, "alert('": 3,
            'alert("': 3, "document.cookie": 3, "document.write": 3,
            "innerHTML": 3, "String.fromCharCode": 3,
            "%3Cscript%3E": 5, "%3Cimg": 3, "%3Ciframe": 4,
        },
        "advanced_patterns": [
            {"pattern": r"<script[^>]*>.*?</script>", "score": 5},
            {"pattern": r"on\w+\s*=\s*[\"']", "score": 4},
            {"pattern": r"javascript\s*:", "score": 4},
        ],
    },
    "Scanner": {
        "keywords": {
            "sqlmap": 10, "nikto": 10, "nmap": 8, "acunetix": 10,
            "dirb": 8, "gobuster": 8, "dirsearch": 8, "hydra": 8,
            "bruteforce": 8, "awvs": 10, "appscan": 10, "nessus": 8,
            "openvas": 8, "masscan": 8, "zap": 6, "burp": 6,
            "w3af": 8, "vega": 8, "netsparker": 10, "qualys": 8,
            "skipfish": 8,
        },
        "advanced_patterns": [],
    },
    "Path Traversal": {
        "keywords": {
            "../": 5, "..\\": 5, "/etc/passwd": 10, "/etc/shadow": 10,
            "windows\\system32": 10, "c:\\windows": 10, "boot.ini": 8,
            "win.ini": 8, "cmd.exe": 8, "..;/": 5,
            "..%2f": 5, "..%252f": 5, "%2e%2e": 5, "%252e%252e": 5,
        },
        "advanced_patterns": [
            {"pattern": r"\.\.(?:/|%2f|%252f|\\\\|%5c)", "score": 5},
        ],
    },
    "Command Injection": {
        "keywords": {
            ";whoami": 8, ";id": 8, ";ls": 6, ";uname": 8, ";cat ": 8,
            "|whoami": 8, "|id": 8, "|ls": 6, "|cat ": 8,
            "|/bin/bash": 10, "|/bin/sh": 10, "`id`": 8, "`whoami`": 8,
            "$(whoami)": 8, "$(id)": 8, "$(cat": 8,
            "ping -c": 6, "nslookup ": 6, "cmd.exe /c": 10,
            "powershell": 6, "net user": 8, "net localgroup": 8,
            "whoami": 6, "ipconfig": 5, "systeminfo": 5,
            "&&whoami": 8, "&&id": 8,
        },
        "advanced_patterns": [
            {"pattern": r"[;|&`]\s*(?:ls|id|whoami|cat|dir|pwd|uname)\b", "score": 5},
            {"pattern": r"\$\([^)]+\)", "score": 4},
            {"pattern": r"`[^`]+`", "score": 4},
        ],
    },
    "LFI / RFI": {
        "keywords": {
            "php://": 8, "file://": 6, "expect://": 8, "data://": 6,
            "php://filter": 10, "php://input": 10,
            "=http://": 6, "=https://": 6, "=ftp://": 6,
            "/proc/self/": 8, "wrapper": 3, "base64-decode": 5,
            "base64_encode": 5, "readfile": 5,
        },
        "advanced_patterns": [
            {"pattern": r"(?:include|require)\s*\(?\s*['\"]", "score": 4},
            {"pattern": r"php://(?:filter|input|fd|memory|temp)", "score": 10},
            {"pattern": r"file://(?:/etc|/proc|/var|/home|C:)", "score": 8},
        ],
    },
}


class RuleEngine:
    """攻击规则引擎 — 加载规则、编译正则、分析文本"""

    def __init__(self, rules_path: Optional[str] = None):
        self.categories: dict[str, RuleCategory] = {}
        self.default_threshold: int = 5

        # 每个类别编译好的正则：(keyword_regex, {keyword_lower -> score})
        self._compiled: dict[str, tuple[re.Pattern, dict[str, int]]] = {}

        # 高级模式：(compiled_pattern, score, category_name)
        self._advanced: list[tuple[re.Pattern, int, str]] = []

        self._load(str(rules_path) if rules_path else str(_DEFAULT_RULES_PATH))

    def _load(self, rules_path: str):
        """从 JSON 文件加载规则，失败则使用内置规则"""
        raw = None
        path = Path(rules_path)
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

        if raw is None:
            raw = {"categories": _BUILTIN_RULES, "settings": {"default_threshold": 5}}

        self.default_threshold = raw.get("settings", {}).get("default_threshold", 5)
        categories_raw = raw.get("categories", {})

        self.categories.clear()
        self._compiled.clear()
        self._advanced.clear()

        for name, cat_data in categories_raw.items():
            keywords = cat_data.get("keywords", {})
            adv_patterns = cat_data.get("advanced_patterns", [])

            category = RuleCategory(
                name=name,
                keywords=dict(keywords),
                advanced_patterns=list(adv_patterns),
            )
            self.categories[name] = category

            # 编译关键词正则（按长度降序，优先匹配长词）
            if keywords:
                sorted_kws = sorted(keywords.keys(), key=len, reverse=True)
                pattern = "|".join(re.escape(kw) for kw in sorted_kws)
                self._compiled[name] = (
                    re.compile(pattern, re.IGNORECASE),
                    {k.lower(): v for k, v in keywords.items()},
                )

            # 编译高级模式
            for adv in adv_patterns:
                try:
                    compiled = re.compile(adv["pattern"], re.IGNORECASE)
                    self._advanced.append((compiled, adv["score"], name))
                except re.error:
                    pass

    def reload(self, rules_path: Optional[str] = None):
        """重新加载规则（用于切换规则文件）"""
        path = rules_path if rules_path else str(_DEFAULT_RULES_PATH)
        self._load(path)

    def score_line(self, normalized_text: str) -> tuple[int, set[str], list[str]]:
        """
        对一行已标准化的文本进行评分。

        返回：(总分, {类别名集合}, [命中描述列表])
        """
        total_score = 0
        categories = set()
        matches: list[str] = []
        matched_keywords: set[str] = set()

        # 1) 关键词匹配
        for cat_name, (regex, kw_score_map) in self._compiled.items():
            found = regex.findall(normalized_text)
            if not found:
                continue

            for match in found:
                match_lower = match.lower()
                if match_lower in matched_keywords:
                    continue

                # 精确匹配
                score = kw_score_map.get(match_lower)
                if score is None:
                    # 子串匹配
                    for kw, s in kw_score_map.items():
                        if kw in match_lower:
                            score = s
                            break

                if score is not None:
                    total_score += score
                    categories.add(cat_name)
                    matches.append(f"{match}({score})")
                    matched_keywords.add(match_lower)

        # 2) 高级正则模式
        for pattern, score, cat_name in self._advanced:
            if pattern.search(normalized_text):
                total_score += score
                categories.add(cat_name)
                matches.append(f"advanced_pattern({score})")

        return total_score, categories, matches[:10]

    @property
    def all_keywords(self) -> list[str]:
        """返回所有关键词列表（用于高亮），按长度降序"""
        all_kws: set[str] = set()
        for cat in self.categories.values():
            all_kws.update(cat.keywords.keys())
        return sorted(all_kws, key=len, reverse=True)


# 全局单例
_engine: Optional[RuleEngine] = None


def get_engine(rules_path: Optional[str] = None) -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine(rules_path)
    return _engine
