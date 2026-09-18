"""日志解析器 — Apache/Nginx / JSON / Python 源码等多种格式"""

import ast
import html
import json
import re
import urllib.parse
from pathlib import Path
from typing import Optional

from .models import SourceEntry

# ── 预编译正则 ──────────────────────────────────────────────

# 标准 Apache/Nginx 日志（带方括号时间戳 + 身份字段）
APACHE_NGINX_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>.*?)\s+HTTP/[^"]*"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?',
    re.IGNORECASE,
)

# 简化格式（无方括号时间戳、无身份字段）：IP 时间戳 "METHOD URI" 状态码 大小 "REF" "UA"
APACHE_NGINX_RE_SIMPLE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+(?:"(?P<method>[A-Z]+)\s+(?P<uri>.*?)\s+HTTP/[^"]*"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?)',
    re.IGNORECASE,
)

# 所有格式的列表（按优先级尝试）
ALL_APACHE_RE_LIST = [APACHE_NGINX_RE, APACHE_NGINX_RE_SIMPLE]

QUOTED_TEXT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'')

LOG_MARKERS = (
    "print(", "logging.", "logger.", "traceback", "exception",
    "warn(", "warning(", "error(", "info(", "critical(", "debug(",
)


# ── 工具函数 ────────────────────────────────────────────────

def extract_ip(text: str) -> str:
    """从文本开头提取 IP 地址"""
    m = re.match(r"^(\S+)", text.strip())
    return m.group(1) if m else "Unknown"


def normalize_line(text: str) -> str:
    """标准化文本：交替进行URL解码 + HTML反转义直到稳定 + 转小写

    处理多层编码绕过，例如：
      %26lt%3B → &lt; (URL解码) → < (HTML反转义)
      不会因为解码顺序单一而被绕过。
    """
    try:
        decoded = str(text)
        for _ in range(5):  # 最多5轮，防止死循环
            changed = False
            # URL 解码
            before = decoded
            decoded = urllib.parse.unquote_plus(decoded)
            if decoded != before:
                changed = True
            # HTML 反转义
            before = decoded
            decoded = html.unescape(decoded)
            if decoded != before:
                changed = True
            if not changed:
                break
    except Exception:
        decoded = str(text)
    return decoded.lower()


def extract_quoted_strings(text: str) -> list[str]:
    """提取引号内的字符串"""
    results = []
    for match in QUOTED_TEXT_RE.finditer(text):
        value = match.group(1) if match.group(1) is not None else match.group(2)
        if value:
            results.append(html.unescape(value))
    return results


def _get_call_name(node) -> str:
    """获取 AST 调用的完整名称"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _get_call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


# ── 文件读取 ────────────────────────────────────────────────

def read_text_file_lines(file_path: str) -> list[str]:
    """尝试多种编码读取文本文件"""
    encodings = [
        "utf-8", "utf-8-sig", "gbk", "gb2312",
        "utf-16", "utf-16le", "utf-16be",
    ]
    last_error = None
    for enc in encodings:
        try:
            with open(file_path, "r", encoding=enc, errors="strict") as f:
                return f.readlines()
        except Exception as e:
            last_error = e

    # 最终兜底
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except Exception as e:
        raise RuntimeError(f"无法读取文件：{e if e else last_error}")


# ── 各格式解析器 ────────────────────────────────────────────

def parse_json_log_line(raw: str) -> Optional[tuple[str, str, str]]:
    """尝试将一行解析为 JSON 日志，返回 (ip, text, status_code) 或 None"""
    stripped = raw.strip()
    if not stripped.startswith("{") or not stripped.endswith("}"):
        return None

    try:
        obj = json.loads(stripped)
    except Exception:
        return None

    if not isinstance(obj, dict):
        return None

    ip = (
        obj.get("ip") or obj.get("remote_addr") or obj.get("client_ip")
        or obj.get("src_ip") or obj.get("host") or "Unknown"
    )

    status_code = str(obj.get("status") or obj.get("status_code") or "")

    fields = [
        "request", "request_line", "uri", "url", "path", "query", "args",
        "message", "msg", "log", "body", "data", "referer",
        "user_agent", "http_user_agent", "ua", "cookie", "payload",
    ]

    parts = []
    for key in fields:
        value = obj.get(key)
        if value is not None and value != "":
            parts.append(str(value))

    if not parts:
        parts.append(str(obj))

    return ip, " ".join(parts), status_code


def parse_access_log_line(raw: str) -> Optional[tuple[str, str, str]]:
    """尝试按 Apache/Nginx 通用格式解析，返回 (ip, text, status_code) 或 None"""
    stripped = raw.strip()
    for regex in ALL_APACHE_RE_LIST:
        m = regex.match(stripped)
        if not m:
            continue

        ip = m.group("ip") or "Unknown"
        method = m.group("method") or ""
        uri = m.group("uri") or ""
        referer = m.group("referer") or ""
        ua = m.group("ua") or ""
        status = m.group("status") or ""
        text = " ".join(part for part in [method, uri, referer, ua] if part)
        # 提取 UA 引号之后的尾部载荷（POST 请求体/附加参数），如 "UA" user=admin'--&pass=x
        tail = stripped[m.end():].strip()
        if tail:
            text = text + " " + tail
        return ip, text, status

    return None


# ── Python 源码解析 ─────────────────────────────────────────

def _looks_like_py_log_line(raw: str) -> bool:
    """判断一行 Python 代码是否像日志/注释行（仅靠语法特征，不用攻击关键词）"""
    low = raw.lower()
    if raw.lstrip().startswith("#"):
        return True
    if any(marker in low for marker in LOG_MARKERS):
        return True
    return False


def extract_entries_from_py_file(file_path: str) -> list[SourceEntry]:
    """从 Python 文件中提取日志条目（AST + 行级兜底）"""
    entries = []
    seen = set()

    lines = read_text_file_lines(file_path)
    source = "".join(lines)

    # 1) AST 提取 print / logging / logger 调用
    try:
        tree = ast.parse(source, filename=file_path)

        class _Visitor(ast.NodeVisitor):
            def visit_Call(self, node):
                call_name = _get_call_name(node.func).lower()
                is_log_call = (
                    call_name == "print"
                    or call_name.startswith("logging.")
                    or call_name.startswith("logger.")
                    or call_name.startswith("log.")
                    or call_name.endswith(".print")
                )

                if is_log_call:
                    segment = ast.get_source_segment(source, node) or ""
                    quoted = extract_quoted_strings(segment)
                    candidate_text = " ".join(quoted).strip() if quoted else segment.strip()

                    if candidate_text:
                        key = (getattr(node, "lineno", 1), candidate_text)
                        if key not in seen:
                            seen.add(key)
                            entries.append(SourceEntry(
                                line_no=getattr(node, "lineno", 1),
                                ip=extract_ip(candidate_text),
                                text=candidate_text,
                                raw=segment.strip() or candidate_text,
                            ))

                self.generic_visit(node)

        _Visitor().visit(tree)
    except Exception:
        pass

    # 2) 行级兜底：注释、日志行、含攻击载荷的字符串
    for line_no, raw in enumerate(source.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue

        should_add = False
        candidate_text = ""

        if stripped.startswith("#"):
            should_add = True
            candidate_text = stripped[1:].strip()
        elif _looks_like_py_log_line(stripped):
            should_add = True
            quoted = extract_quoted_strings(stripped)
            candidate_text = " ".join(quoted).strip() if quoted else stripped

        if should_add and candidate_text:
            key = (line_no, candidate_text)
            if key not in seen:
                seen.add(key)
                entries.append(SourceEntry(
                    line_no=line_no,
                    ip=extract_ip(candidate_text),
                    text=candidate_text,
                    raw=stripped,
                ))

    return entries


# ── 通用文件解析入口 ────────────────────────────────────────

def extract_entries_from_plain_file(file_path: str) -> list[SourceEntry]:
    """从普通日志文件提取条目（JSON / Apache / 纯文本）"""
    entries = []
    lines = read_text_file_lines(file_path)

    for line_no, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped:
            continue

        parsed = parse_json_log_line(stripped)
        if parsed:
            ip, text, status_code = parsed
        else:
            parsed = parse_access_log_line(stripped)
            if parsed:
                ip, text, status_code = parsed
            else:
                ip = extract_ip(stripped)
                text = stripped
                status_code = ""

        entries.append(SourceEntry(
            line_no=line_no, ip=ip, text=text, raw=stripped,
            status_code=status_code,
        ))
    return entries


def collect_entries(file_path: str) -> list[SourceEntry]:
    """
    统一入口：根据文件后缀选择解析策略，返回 SourceEntry 列表。
    """
    suffix = Path(file_path).suffix.lower()
    if suffix == ".py":
        py_entries = extract_entries_from_py_file(file_path)
        if py_entries:
            return py_entries
        return extract_entries_from_plain_file(file_path)

    return extract_entries_from_plain_file(file_path)
