"""日志解析器 — Apache/Nginx / JSON / Python 源码等多种格式"""

import ast
import codecs
import html
import io
import json
import os
import re
import urllib.parse
from pathlib import Path
from typing import BinaryIO, Callable, Iterable, Iterator, Optional

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

_READ_CHUNK_SIZE = 64 * 1024


class _ReadCancelled(Exception):
    """内部协作取消信号，不能被编码重试或 AST 兜底吞掉。"""


def _check_cancel(should_cancel: Optional[Callable[[], bool]]) -> None:
    if should_cancel is not None and should_cancel():
        raise _ReadCancelled()


def _encoding_candidates(sample: bytes) -> tuple[str, ...]:
    # BOM 必须先识别：UTF-8 BOM 不能落入 IP，UTF-16 不能误当 GBK。
    if sample.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return ("utf-32",)
    if sample.startswith(codecs.BOM_UTF8):
        return ("utf-8-sig",)
    if sample.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return ("utf-16",)

    candidates = ("utf-8", "gbk", "gb18030", "gb2312", "utf-16-le", "utf-16-be")
    # 无 BOM 时只对明显的交替 NUL 模式优先尝试 UTF-16；其余有歧义
    # 的字节沿用 UTF-8 / GBK 优先级，不把日志中偶发的 NUL 当编码标记。
    even, odd = sample[::2], sample[1::2]
    if even and odd:
        if odd.count(0) > len(odd) // 2 and even.count(0) < len(even) / 4:
            return ("utf-16-le",) + candidates[:-2] + ("utf-16-be",)
        if even.count(0) > len(even) // 2 and odd.count(0) < len(odd) / 4:
            return ("utf-16-be",) + candidates[:-2] + ("utf-16-le",)
    return candidates


def _validated_encoding(
    stream: BinaryIO, should_cancel: Optional[Callable[[], bool]],
) -> str:
    """固定内存并行验证候选编码；开始产出后绝不回退编码或重放。"""
    # 即使底层短读或测试把块设得很小，也先收齐 BOM 所需的最多 4 字节。
    prefix_parts = []
    prefix_size = 0
    while prefix_size < 4:
        _check_cancel(should_cancel)
        part = stream.read(_READ_CHUNK_SIZE)
        _check_cancel(should_cancel)
        prefix_parts.append(part)
        prefix_size += len(part)
        if not part:
            break
    block = b"".join(prefix_parts)
    candidates = _encoding_candidates(block)
    decoders = {
        encoding: codecs.getincrementaldecoder(encoding)(errors="strict")
        for encoding in candidates
    }
    last_error = None
    while True:
        _check_cancel(should_cancel)
        for encoding in tuple(decoders):
            _check_cancel(should_cancel)
            try:
                decoders[encoding].decode(block, final=not block)
            except UnicodeError as exc:
                last_error = exc
                del decoders[encoding]
        if not decoders:
            raise UnicodeError(f"无法解码文件（尝试 {', '.join(candidates)}）：{last_error}")
        if not block:
            break
        _check_cancel(should_cancel)
        block = stream.read(_READ_CHUNK_SIZE)
        _check_cancel(should_cancel)

    _check_cancel(should_cancel)
    stream.seek(0)
    return next(iter(decoders))


def _iter_text_file_lines(
    file_path: str,
    should_cancel: Optional[Callable[[], bool]] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> Iterator[str]:
    """按块解码，按行产出；只缓冲一个块和当前未结束的长行。"""
    _check_cancel(should_cancel)
    with open(file_path, "rb") as stream:
        total_bytes = os.fstat(stream.fileno()).st_size
        if on_progress is not None:
            on_progress(0, total_bytes)
        encoding = _validated_encoding(stream, should_cancel)
        decoder = io.IncrementalNewlineDecoder(
            codecs.getincrementaldecoder(encoding)(errors="strict"), translate=True,
        )
        current_bytes = 0
        fragments: list[str] = []
        while True:
            _check_cancel(should_cancel)
            block = stream.read(_READ_CHUNK_SIZE)
            _check_cancel(should_cancel)
            if block:
                current_bytes += len(block)
                if on_progress is not None:
                    on_progress(current_bytes, total_bytes)
                _check_cancel(should_cancel)
            text = decoder.decode(block, final=not block)
            start = 0
            while True:
                _check_cancel(should_cancel)
                end = text.find("\n", start)
                if end < 0:
                    if start < len(text):
                        fragments.append(text[start:])
                    break
                fragments.append(text[start:end + 1])
                line = "".join(fragments)
                fragments.clear()
                yield line
                start = end + 1
            if not block:
                break
        _check_cancel(should_cancel)
        if fragments:
            yield "".join(fragments)


def read_text_file_lines(file_path: str) -> list[str]:
    """兼容旧的列表 API；编码严格验证，I/O/解码错误不再静默丢字节。"""
    return list(_iter_text_file_lines(file_path))


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


def _iter_source_lines(source: str) -> Iterator[str]:
    """惰性的 str.splitlines() 等价物，保留 Python 行级兜底原有行号语义。"""
    start = 0
    for match in re.finditer(r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]", source):
        yield source[start:match.start()]
        start = match.end()
    if start < len(source):
        yield source[start:]


def _iter_py_source_entries(
    source: str, file_path: str, should_cancel: Optional[Callable[[], bool]],
) -> Iterator[SourceEntry]:
    seen = set()
    _check_cancel(should_cancel)
    try:
        # ast.parse 是单次同步调用，不能中途抢占；调用前后都检查取消。
        tree = ast.parse(source, filename=file_path)
    except _ReadCancelled:
        raise
    except Exception:
        tree = None
    _check_cancel(should_cancel)

    def visit(node):
        # 与旧 NodeVisitor 一样按深度优先、先调用节点后子节点访问。
        _check_cancel(should_cancel)
        if isinstance(node, ast.Call):
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
                _check_cancel(should_cancel)
                if candidate_text:
                    key = (getattr(node, "lineno", 1), candidate_text)
                    if key not in seen:
                        seen.add(key)
                        yield SourceEntry(
                            line_no=getattr(node, "lineno", 1),
                            ip=extract_ip(candidate_text),
                            text=candidate_text,
                            raw=segment.strip() or candidate_text,
                        )
        for child in ast.iter_child_nodes(node):
            _check_cancel(should_cancel)
            yield from visit(child)

    if tree is not None:
        try:
            yield from visit(tree)
        except _ReadCancelled:
            raise
        except Exception:
            # 保留旧的 AST 提取失败后仍进行行级兜底的行为。
            pass

    # 只提取原有的注释/日志语法，不扩大到任意字符串或攻击关键词。
    _check_cancel(should_cancel)
    for line_no, raw in enumerate(_iter_source_lines(source), start=1):
        _check_cancel(should_cancel)
        stripped = raw.strip()
        if not stripped:
            continue
        candidate_text = ""
        if stripped.startswith("#"):
            candidate_text = stripped[1:].strip()
        elif _looks_like_py_log_line(stripped):
            quoted = extract_quoted_strings(stripped)
            candidate_text = " ".join(quoted).strip() if quoted else stripped
        _check_cancel(should_cancel)
        if candidate_text:
            key = (line_no, candidate_text)
            if key not in seen:
                seen.add(key)
                yield SourceEntry(
                    line_no=line_no, ip=extract_ip(candidate_text),
                    text=candidate_text, raw=stripped,
                )


def _iter_entries_from_py_file(
    file_path: str,
    should_cancel: Optional[Callable[[], bool]] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
    fallback_to_plain: bool = False,
) -> Iterator[SourceEntry]:
    source = "".join(_iter_text_file_lines(file_path, should_cancel, on_progress))
    _check_cancel(should_cancel)
    found = False
    for entry in _iter_py_source_entries(source, file_path, should_cancel):
        found = True
        yield entry
    _check_cancel(should_cancel)
    if fallback_to_plain and not found:
        # Python 无日志时仍按普通文本提取，但无需重读文件或回退字节进度。
        yield from _iter_plain_entries(io.StringIO(source), should_cancel)


def extract_entries_from_py_file(file_path: str) -> list[SourceEntry]:
    """兼容旧 API：AST + 行级兜底，无日志时返回空列表。"""
    return list(_iter_entries_from_py_file(file_path))


# ── 通用文件解析入口 ────────────────────────────────────────

def _iter_plain_entries(
    lines: Iterable[str], should_cancel: Optional[Callable[[], bool]] = None,
) -> Iterator[SourceEntry]:
    for line_no, raw in enumerate(lines, start=1):
        _check_cancel(should_cancel)
        stripped = raw.strip()
        if not stripped:
            continue
        parsed = parse_json_log_line(stripped) or parse_access_log_line(stripped)
        if parsed:
            ip, text, status_code = parsed
        else:
            ip, text, status_code = extract_ip(stripped), stripped, ""
        _check_cancel(should_cancel)
        yield SourceEntry(
            line_no=line_no, ip=ip, text=text, raw=raw.rstrip("\r\n"),
            status_code=status_code,
        )


def extract_entries_from_plain_file(file_path: str) -> list[SourceEntry]:
    """兼容旧 API：普通日志（JSON / Apache / 纯文本）的条目列表。"""
    return list(_iter_plain_entries(_iter_text_file_lines(file_path)))


class _EntryStream(Iterator[SourceEntry]):
    """取消时正常耗尽，同时让分析器区分取消与真正的 EOF。"""
    def __init__(self, source: Iterator[SourceEntry]):
        self._source = source
        self._closed = False
        self.cancelled = False

    def __iter__(self) -> Iterator[SourceEntry]:
        return self

    def __next__(self) -> SourceEntry:
        if self._closed:
            raise StopIteration
        try:
            return next(self._source)
        except _ReadCancelled:
            self.cancelled = True
            self._closed = True
            raise StopIteration from None
        except StopIteration:
            self._closed = True
            raise

    def close(self) -> None:
        self._closed = True
        close = getattr(self._source, "close", None)
        if close is not None:
            close()


def iter_entries(
    file_path: str,
    should_cancel: Optional[Callable[[], bool]] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> Iterator[SourceEntry]:
    """惰性读取日志，保留旧的解析、空行过滤和 Python 提取顺序。

    创建迭代器不打开文件。普通日志先以固定大小块严格验证编码，随后
    只进行一次产出遍历；内存为当前块及最长一行，而不是整文件。
    text 仍按原规则去除两端空白；普通日志 raw 只去行结束符，保留证据空白。
    BOM 优先（UTF-8 / UTF-16 / UTF-32），无 BOM 依次验证 UTF-8、GBK 等。
    I/O 或解码失败直接抛出，不忽略字节，也不会换编码重放已有条目。

    on_progress(current_bytes, total_bytes) 在开始时报告 (0, 文件大小)，
    后续只统计产出遍历实际读取的原始字节，不包含编码预验证的读取。
    total_bytes 是打开文件时的大小；静态文件的进度单调不回退。块预读
    可能早于对应条目的分析，达到 total 不代表分析或扫描后处理完成。
    空文件报告 (0, 0)。预验证期间百分比保持 0，但每块仍检查取消。

    验证、读取、产出每行、AST 节点访问及行级兜底都检查 should_cancel。
    Python 源码允许整体驻留内存；ast.parse 单次调用无法抢占，前后会
    检查取消。取消时迭代器正常结束，其 cancelled 属性为 True；close()
    可提前释放文件。传给 LogAnalyzer 时建议同时传入同一个取消标志。
    """
    if Path(file_path).suffix.lower() == ".py":
        source = _iter_entries_from_py_file(
            file_path, should_cancel, on_progress, fallback_to_plain=True,
        )
    else:
        source = _iter_plain_entries(
            _iter_text_file_lines(file_path, should_cancel, on_progress), should_cancel,
        )
    return _EntryStream(source)


def collect_entries(file_path: str) -> list[SourceEntry]:
    """兼容旧的统一入口：根据后缀选择策略，返回 SourceEntry 列表。"""
    return list(iter_entries(file_path))
