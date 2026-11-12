"""流式读取/分析回归：惰性、取消、编码边界、部分结果和完整证据。"""

import builtins
import codecs
import sys
import weakref
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import log_analyzer.analyzer as analyzer_module
import log_analyzer.parser as parser
from log_analyzer.analyzer import CancelFlag, LogAnalyzer
from log_analyzer.models import SourceEntry
from log_analyzer.rules import RuleEngine
from log_analyzer.whitelist import WhitelistManager


@pytest.fixture
def engine(tmp_path):
    return RuleEngine(str(tmp_path / "missing_rules.json"))


@pytest.fixture
def analyzer(engine):
    return LogAnalyzer(engine, risk_threshold=5)


def attack(line_no=1, ip="10.0.0.1", status_code=""):
    return SourceEntry(line_no, ip, "sqlmap", "sqlmap", status_code)


def not_found(line_no=1, ip="10.0.0.1"):
    return SourceEntry(line_no, ip, "GET /missing HTTP/1.1", "GET /missing", "404")


def watch_binary_reads(monkeypatch, on_read=None):
    """监测生产代码的所有文件读取，禁止 readlines 和无界 read。"""
    opened = []
    reads = []

    class WatchedFile:
        def __init__(self, stream):
            self.stream = stream
            self.phase = "validation"
            self.counts = {"validation": 0, "production": 0}

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size=-1):
            assert 0 < size <= parser._READ_CHUNK_SIZE, "必须使用固定大小块读取"
            self.counts[self.phase] += 1
            reads.append((self.phase, size))
            if on_read is not None:
                replacement = on_read(self, self.phase, self.counts[self.phase])
                if replacement is not None:
                    return replacement
            return self.stream.read(size)

        def readlines(self, *args, **kwargs):
            pytest.fail("不能使用整文件 readlines")

        def seek(self, offset, whence=0):
            if offset == 0 and whence == 0:
                self.phase = "production"
            return self.stream.seek(offset, whence)

    def open_file(path, mode="r", *args, **kwargs):
        assert mode == "rb"
        stream = WatchedFile(builtins.open(path, mode, *args, **kwargs))
        opened.append(stream)
        return stream

    monkeypatch.setattr(parser, "open", open_file, raising=False)
    return opened, reads


class TestStreamingParser:
    def test_lazy_creation_and_no_parsing_ahead(self, tmp_path, monkeypatch):
        path = tmp_path / "lazy.log"
        path.write_bytes(b"10.0.0.1 sqlmap\n" * 100)
        opened, reads = watch_binary_reads(monkeypatch)
        parsed = []
        original = parser.parse_json_log_line

        def parse_line(raw):
            parsed.append(raw)
            return original(raw)

        monkeypatch.setattr(parser, "parse_json_log_line", parse_line)
        monkeypatch.setattr(parser, "read_text_file_lines", lambda *args: pytest.fail("旧列表读取"))
        entries = parser.iter_entries(str(path))
        assert iter(entries) is entries
        assert not opened and not reads and not parsed
        assert next(entries).line_no == 1
        assert len(parsed) == 1
        assert next(entries).line_no == 2
        assert len(parsed) == 2
        entries.close()
        assert opened[0].closed

    def test_cancelled_before_open(self, tmp_path, monkeypatch):
        monkeypatch.setattr(parser, "open", lambda *args: pytest.fail("取消后不应打开文件"), raising=False)
        entries = parser.iter_entries(str(tmp_path / "absent.log"), should_cancel=lambda: True)
        assert list(entries) == []
        assert entries.cancelled

    def test_cancel_during_encoding_validation(self, tmp_path, monkeypatch):
        path = tmp_path / "validate.log"
        path.write_bytes(b"10.0.0.1 sqlmap\n" * 20)
        monkeypatch.setattr(parser, "_READ_CHUNK_SIZE", 17)
        cancel = CancelFlag()

        def on_read(stream, phase, count):
            if phase == "validation" and count == 2:
                cancel.set()

        opened, reads = watch_binary_reads(monkeypatch, on_read)
        progress = []
        entries = parser.iter_entries(
            str(path), lambda: cancel.is_set, lambda current, total: progress.append((current, total)),
        )
        assert list(entries) == []
        assert entries.cancelled
        assert reads == [("validation", 17), ("validation", 17)]
        assert progress == [(0, path.stat().st_size)]
        assert opened[0].closed

    def test_cancel_during_production_read(self, tmp_path, monkeypatch):
        path = tmp_path / "cancel_read.log"
        line = b"10.0.0.1 sqlmap\n"
        path.write_bytes(line * 10)
        chunk_size = len(line) * 2
        monkeypatch.setattr(parser, "_READ_CHUNK_SIZE", chunk_size)
        opened, reads = watch_binary_reads(monkeypatch)
        cancel = CancelFlag()

        def progress(current, total):
            if current > chunk_size:
                cancel.set()

        stream = parser.iter_entries(str(path), lambda: cancel.is_set, progress)
        assert [entry.line_no for entry in stream] == [1, 2]
        assert stream.cancelled
        assert sum(phase == "production" for phase, _ in reads) == 2
        assert opened[0].closed

    @pytest.mark.parametrize("encoding,bom", [
        ("utf-8", b""),
        ("utf-8-sig", b""),
        ("utf-16", b""),
        ("utf-16-le", codecs.BOM_UTF16_LE),
        ("utf-16-be", codecs.BOM_UTF16_BE),
        ("utf-16-le", b""),
        ("utf-16-be", b""),
        ("gbk", b""),
        ("gb18030", b""),
    ])
    @pytest.mark.parametrize("chunk_size", [1, 2, 3, 7, 17])
    def test_encodings_bom_and_non_ascii_chunk_boundaries(self, tmp_path, monkeypatch, encoding, bom, chunk_size):
        path = tmp_path / "encoded.log"
        text = ('{"ip":"10.0.0.1","message":"中文测试 sqlmap 尾部","status":404}\r\n'
                '10.0.0.2 另一行\r10.0.0.3 结束')
        if encoding == "gb18030":
            text += " 𠀀"
        data = bom + text.encode(encoding)
        path.write_bytes(data)
        monkeypatch.setattr(parser, "_READ_CHUNK_SIZE", chunk_size)
        progress = []
        entries = list(parser.iter_entries(str(path), on_progress=lambda a, b: progress.append((a, b))))
        assert len(entries) == 3
        assert [entry.line_no for entry in entries] == [1, 2, 3]
        assert entries[0].ip == "10.0.0.1"
        assert entries[0].text == "中文测试 sqlmap 尾部"
        assert entries[0].status_code == "404"
        assert entries[1].raw == "10.0.0.2 另一行"
        assert entries[2].raw == ("10.0.0.3 结束 𠀀" if encoding == "gb18030" else "10.0.0.3 结束")
        assert all("\ufeff" not in entry.raw for entry in entries)
        assert progress[0] == (0, len(data))
        assert progress[-1] == (len(data), len(data))
        assert [current for current, _ in progress] == sorted(current for current, _ in progress)
        assert all(total == len(data) for _, total in progress)

    def test_universal_newlines_and_legacy_line_numbers(self, tmp_path, monkeypatch):
        path = tmp_path / "newlines.log"
        path.write_bytes(b"123456\r\nb\rc\n\r\nlast")
        monkeypatch.setattr(parser, "_READ_CHUNK_SIZE", 7)
        assert parser.read_text_file_lines(str(path)) == ["123456\n", "b\n", "c\n", "\n", "last"]
        entries = list(parser.iter_entries(str(path)))
        assert [(entry.line_no, entry.raw) for entry in entries] == [(1, "123456"), (2, "b"), (3, "c"), (5, "last")]
        assert parser.collect_entries(str(path)) == entries
        assert parser.extract_entries_from_plain_file(str(path)) == entries

    def test_long_unterminated_line_keeps_all_characters(self, tmp_path, monkeypatch):
        path = tmp_path / "long.log"
        text = "10.0.0.1 " + "中文A" * 4000 + " sqlmap END"
        path.write_bytes(text.encode("utf-8"))
        monkeypatch.setattr(parser, "_READ_CHUNK_SIZE", 17)
        entries = list(parser.iter_entries(str(path)))
        assert len(entries) == 1
        assert entries[0].text == text
        assert entries[0].raw == text

    def test_plain_raw_keeps_leading_and_trailing_whitespace(self, tmp_path, analyzer):
        path = tmp_path / "evidence.log"
        raw = "\t 10.0.0.1 sqlmap " + "证据" * 300 + " END \t  "
        path.write_bytes((raw + "\r\n").encode("utf-8"))
        entries = list(parser.iter_entries(str(path)))
        assert len(entries) == 1
        assert entries[0].raw == raw
        assert entries[0].text == raw.strip()
        result = analyzer.analyze(iter(entries))
        assert result.findings[0].raw == raw
        assert result.findings[0].normalized == parser.normalize_line(raw.strip())

    def test_late_gbk_byte_does_not_replay_findings(self, tmp_path, monkeypatch, analyzer):
        path = tmp_path / "late_gbk.log"
        text = "10.0.0.1 sqlmap\n" * 40 + "10.0.0.1 sqlmap 中文结束\n"
        path.write_bytes(text.encode("gbk"))
        monkeypatch.setattr(parser, "_READ_CHUNK_SIZE", 31)
        emitted = []
        result = analyzer.analyze(parser.iter_entries(str(path)), on_finding=emitted.append)
        assert result.error is None and not result.cancelled
        assert [finding.line_no for finding in result.findings] == list(range(1, 42))
        assert emitted == result.findings
        assert "中文结束" in result.findings[-1].raw

    def test_invalid_bom_declared_encoding_is_an_error(self, tmp_path, analyzer):
        path = tmp_path / "corrupt.log"
        path.write_bytes(codecs.BOM_UTF8 + b"10.0.0.1 sqlmap\n\xff")
        result = analyzer.analyze(parser.iter_entries(str(path)))
        assert result.error and "解码" in result.error
        assert not result.cancelled
        assert result.processed_entries == 0
        assert result.findings == []
        with pytest.raises(UnicodeError):
            parser.collect_entries(str(path))

    def test_io_error_during_validation_is_not_encoding_retry(self, tmp_path, monkeypatch, analyzer):
        path = tmp_path / "validate_error.log"
        path.write_bytes(b"10.0.0.1 sqlmap\n" * 20)
        monkeypatch.setattr(parser, "_READ_CHUNK_SIZE", 17)

        def on_read(stream, phase, count):
            if phase == "validation" and count == 2:
                raise OSError("validation disk failure")

        opened, reads = watch_binary_reads(monkeypatch, on_read)
        result = analyzer.analyze(parser.iter_entries(str(path)))
        assert result.error and "validation disk failure" in result.error
        assert not result.cancelled and result.findings == []
        assert len(opened) == 1 and opened[0].closed
        assert reads == [("validation", 17), ("validation", 17)]

    @pytest.mark.parametrize("decode_error", [False, True])
    def test_mid_read_failure_keeps_partial_findings(self, tmp_path, monkeypatch, analyzer, decode_error):
        path = tmp_path / "partial.log"
        line = b'10.0.0.1 - - [now] "GET /sqlmap HTTP/1.1" 404 0\n'
        path.write_bytes(line * 10)
        monkeypatch.setattr(parser, "_READ_CHUNK_SIZE", len(line) * 5)

        def on_read(stream, phase, count):
            if phase == "production" and count == 2:
                if decode_error:
                    return b"\xff"
                raise OSError("production disk failure")

        opened, reads = watch_binary_reads(monkeypatch, on_read)
        emitted = []
        result = analyzer.analyze(parser.iter_entries(str(path)), on_finding=emitted.append)
        assert result.error is not None and not result.cancelled
        assert result.processed_entries == 5
        assert result.total_entries == 0  # 未耗尽的流无法得知真实条目总数。
        assert [finding.line_no for finding in result.findings] == [1, 2, 3, 4, 5]
        assert emitted == result.findings
        assert result.ip_attack_count["10.0.0.1"] == 5
        assert all(finding.categories != "Scan Behavior" for finding in result.findings)
        assert len(opened) == 1 and opened[0].closed
        assert sum(phase == "production" for phase, _ in reads) == 2

    @pytest.mark.parametrize("data", [b"", b"\r\n \n\t\r\n"])
    def test_empty_or_blank_file_progress(self, tmp_path, analyzer, data):
        path = tmp_path / "empty.log"
        path.write_bytes(data)
        progress = []
        result = analyzer.analyze(parser.iter_entries(str(path), on_progress=lambda a, b: progress.append((a, b))))
        assert result.processed_entries == result.total_entries == 0
        assert result.error is None and not result.cancelled
        assert progress[0] == (0, len(data))
        assert progress[-1] == (len(data), len(data))

    def test_parser_only_cancel_predicate_is_recognized_by_analyzer(self, tmp_path, analyzer):
        path = tmp_path / "predicate.log"
        path.write_bytes(b"10.0.0.1 sqlmap\n" * 10)
        stopped = False

        def on_finding(finding):
            nonlocal stopped
            stopped = True

        stream = parser.iter_entries(str(path), should_cancel=lambda: stopped)
        result = analyzer.analyze(stream, on_finding=on_finding)
        assert result.cancelled and stream.cancelled
        assert result.error is None
        assert result.processed_entries == len(result.findings) == 1


class TestStreamingPython:
    def test_ast_order_deduplication_and_fallback_meaning(self, tmp_path):
        path = tmp_path / "source.py"
        path.write_text(
            'payload = "ignored sqlmap"\n'
            'logger.info("10.0.0.1 first")\n'
            '# 10.0.0.2 comment\n'
            'log.custom("10.0.0.3 ast-only")\n'
            'print(logger.info("10.0.0.4 nested"))\n', encoding="utf-8",
        )
        entries = list(parser.iter_entries(str(path)))
        assert [(entry.line_no, entry.text) for entry in entries] == [
            (2, "10.0.0.1 first"), (4, "10.0.0.3 ast-only"),
            (5, "10.0.0.4 nested"), (3, "10.0.0.2 comment"),
        ]
        assert entries[2].raw == 'print(logger.info("10.0.0.4 nested"))'
        assert parser.extract_entries_from_py_file(str(path)) == entries
        assert parser.collect_entries(str(path)) == entries

    def test_python_without_logs_uses_plain_fallback_without_re_read(self, tmp_path, monkeypatch):
        path = tmp_path / "ordinary.py"
        path.write_text("value = 'sqlmap'\nother = 42\n", encoding="utf-8")
        assert parser.extract_entries_from_py_file(str(path)) == []
        opened, reads = watch_binary_reads(monkeypatch)
        progress = []
        entries = list(parser.iter_entries(str(path), on_progress=lambda a, b: progress.append((a, b))))
        assert [entry.text for entry in entries] == ["value = 'sqlmap'", "other = 42"]
        assert len(opened) == 1 and opened[0].closed
        assert [current for current, _ in progress] == sorted(current for current, _ in progress)

    def test_invalid_syntax_keeps_line_fallback(self, tmp_path):
        path = tmp_path / "invalid.py"
        path.write_text('broken = (\n# 10.0.0.1 comment\nlogger.info("10.0.0.2 log")\n', encoding="utf-8")
        entries = list(parser.iter_entries(str(path)))
        assert [(entry.line_no, entry.text) for entry in entries] == [(2, "10.0.0.1 comment"), (3, "10.0.0.2 log")]

    def test_cancel_during_source_read_never_calls_ast(self, tmp_path, monkeypatch):
        path = tmp_path / "read_cancel.py"
        path.write_bytes(b'print("sqlmap")\n' * 20)
        monkeypatch.setattr(parser, "_READ_CHUNK_SIZE", 17)
        monkeypatch.setattr(parser.ast, "parse", lambda *args, **kwargs: pytest.fail("取消后不能解析 AST"))
        cancel = CancelFlag()

        def progress(current, total):
            if current > 17:
                cancel.set()

        stream = parser.iter_entries(str(path), lambda: cancel.is_set, progress)
        assert list(stream) == []
        assert stream.cancelled

    def test_cancel_after_non_preemptible_ast_parse(self, tmp_path, monkeypatch):
        path = tmp_path / "ast_cancel.py"
        path.write_text('print("sqlmap")\n# fallback\n', encoding="utf-8")
        cancel = CancelFlag()
        original = parser.ast.parse
        calls = []

        def parse_then_cancel(*args, **kwargs):
            calls.append(True)
            tree = original(*args, **kwargs)
            cancel.set()
            return tree

        monkeypatch.setattr(parser.ast, "parse", parse_then_cancel)
        stream = parser.iter_entries(str(path), lambda: cancel.is_set)
        assert list(stream) == []
        assert stream.cancelled and len(calls) == 1

    def test_cancel_while_visiting_non_call_ast_node(self, tmp_path, monkeypatch):
        path = tmp_path / "node_cancel.py"
        path.write_text('value = 1\nprint("sqlmap")\n# fallback\n', encoding="utf-8")
        cancel = CancelFlag()
        original = parser.ast.iter_child_nodes
        visited = []

        def children(node):
            visited.append(type(node).__name__)
            if isinstance(node, parser.ast.Assign):
                cancel.set()
            return original(node)

        monkeypatch.setattr(parser.ast, "iter_child_nodes", children)
        stream = parser.iter_entries(str(path), lambda: cancel.is_set)
        assert list(stream) == []
        assert stream.cancelled
        assert visited == ["Module", "Assign"]

    def test_cancel_during_line_fallback_preserves_earlier_entry(self, tmp_path, monkeypatch):
        path = tmp_path / "fallback_cancel.py"
        path.write_text("# sqlmap\nvalue = 1\nother = 2\n# later\n", encoding="utf-8")
        cancel = CancelFlag()
        original = parser._looks_like_py_log_line
        checked = []

        def check_line(raw):
            checked.append(raw)
            if raw == "other = 2":
                cancel.set()
            return original(raw)

        monkeypatch.setattr(parser, "_looks_like_py_log_line", check_line)
        stream = parser.iter_entries(str(path), lambda: cancel.is_set)
        assert [entry.text for entry in stream] == ["sqlmap"]
        assert stream.cancelled
        assert checked == ["value = 1", "other = 2"]


class TestIterableAnalyzer:
    def test_consumes_single_pass_iterable_without_len_or_prefetch(self, analyzer):
        emitted = []

        class SinglePass:
            calls = 0

            def __len__(self):
                pytest.fail("不能假设 len(entries)")

            def __iter__(self):
                self.calls += 1
                assert self.calls == 1
                yield attack(1)
                assert len(emitted) == 1, "下一条拉取前必须处理当前条目"
                yield attack(2)

        source = SinglePass()
        result = analyzer.analyze(source, on_finding=emitted.append)
        assert result.error is None and not result.cancelled
        assert result.processed_entries == result.total_entries == 2
        assert emitted == result.findings
        assert source.calls == 1

    def test_does_not_keep_consumed_inputs(self, analyzer):
        references = []

        def source():
            for index in range(100):
                assert all(ref() is None for ref in references[:-1]), "保留了全部 SourceEntry 输入"
                entry = SourceEntry(index + 1, "10.0.0.1", "ordinary", "ordinary")
                references.append(weakref.ref(entry))
                yield entry
                del entry

        result = analyzer.analyze(source(), enable_scan_behavior=False)
        assert result.error is None
        assert result.processed_entries == 100
        assert result.findings == []

    def test_pre_cancel_does_not_even_create_iterator(self, analyzer):
        class Source:
            def __iter__(self):
                pytest.fail("预取消后不应启动迭代器")

        cancel = CancelFlag()
        cancel.set()
        result = analyzer.analyze(Source(), cancel_flag=cancel)
        assert result.cancelled and result.error is None
        assert result.processed_entries == result.total_entries == 0

    def test_pre_cancel_closes_a_stream_started_by_caller(self, tmp_path, monkeypatch, analyzer):
        path = tmp_path / "started.log"
        path.write_bytes(b"10.0.0.1 sqlmap\n" * 5)
        opened, reads = watch_binary_reads(monkeypatch)
        stream = parser.iter_entries(str(path))
        assert next(stream).line_no == 1
        assert not opened[0].closed
        previous_reads = list(reads)
        cancel = CancelFlag()
        cancel.set()
        result = analyzer.analyze(stream, cancel_flag=cancel)
        assert result.cancelled and result.error is None
        assert result.processed_entries == 0
        assert reads == previous_reads
        assert opened[0].closed

    def test_cancel_callback_does_not_pull_next_and_closes_generator(self, analyzer):
        cancel = CancelFlag()
        pulled = []
        closed = []

        def source():
            try:
                pulled.append(1)
                yield attack(1)
                pulled.append(2)
                yield attack(2)
            finally:
                closed.append(True)

        result = analyzer.analyze(source(), cancel_flag=cancel, on_finding=lambda finding: cancel.set())
        assert result.cancelled and result.error is None
        assert result.processed_entries == len(result.findings) == 1
        assert pulled == [1]
        assert closed == [True]

    def test_cancel_on_iterator_exhaustion_prevents_scan(self, analyzer, monkeypatch):
        cancel = CancelFlag()

        def source():
            for index in range(5):
                yield not_found(index + 1)
            cancel.set()

        monkeypatch.setattr(analyzer, "_detect_scan_behavior", lambda *args: pytest.fail("取消后不得扫描推断"))
        result = analyzer.analyze(source(), cancel_flag=cancel)
        assert result.cancelled and result.error is None
        assert result.processed_entries == 5
        assert result.findings == []

    def test_cancel_during_next_does_not_score_returned_entry(self, analyzer, monkeypatch):
        cancel = CancelFlag()

        def source():
            cancel.set()
            yield attack()

        monkeypatch.setattr(analyzer.engine, "score_line", lambda *args: pytest.fail("取消后不得评分"))
        result = analyzer.analyze(source(), cancel_flag=cancel)
        assert result.cancelled and result.error is None
        assert result.processed_entries == 0

    @pytest.mark.parametrize("total_hint", [None, 10])
    def test_empty_input_has_zero_actual_total(self, analyzer, total_hint):
        progress = []
        result = analyzer.analyze(iter(()), on_progress=lambda a, b, text: progress.append((a, b)), total_entries=total_hint)
        assert result.error is None and not result.cancelled
        assert result.processed_entries == result.total_entries == 0
        assert result.findings == []
        assert progress[-1] == (0, 0)

    @pytest.mark.parametrize("total_hint", [None, 100])
    def test_blank_whitelist_and_suppressed_entries_count_toward_progress(self, tmp_path, engine, total_hint):
        whitelist = WhitelistManager(str(tmp_path / "missing_whitelist.json"))
        whitelist.add_ip("10.0.0.1")
        whitelist.add_pattern("approved")
        whitelist.add_suppressed_category("Scanner")
        analyzer = LogAnalyzer(engine, whitelist)
        rows = [
            attack(1, "10.0.0.1"),
            SourceEntry(2, "10.0.0.2", "  \t", "  \t"),
            SourceEntry(3, "10.0.0.3", "approved sqlmap", "approved sqlmap"),
            attack(4, "10.0.0.4"),
        ]
        progress = []
        result = analyzer.analyze(
            (rows[index % 4] for index in range(100)), total_entries=total_hint,
            on_progress=lambda a, b, text: progress.append((a, b)),
        )
        assert result.processed_entries == result.total_entries == 100
        assert result.findings == []
        assert progress == [(50, total_hint or 0), (100, total_hint or 0), (100, 100)]

    def test_iterator_initialization_error_is_reported(self, analyzer):
        class Source:
            def __iter__(self):
                raise OSError("cannot start input")

        statuses = []
        result = analyzer.analyze(Source(), on_status=statuses.append, total_entries=99)
        assert result.error and "cannot start input" in result.error
        assert not result.cancelled and result.processed_entries == 0
        assert result.total_entries == 99
        assert "分析失败" in statuses[-1]

    def test_mid_iterator_error_retains_findings_and_skips_scan(self, analyzer, monkeypatch):
        def source():
            for index in range(5):
                yield attack(index + 1, status_code="404")
            raise OSError("input ended unexpectedly")

        monkeypatch.setattr(analyzer, "_detect_scan_behavior", lambda *args: pytest.fail("错误后不推断扫描"))
        emitted = []
        result = analyzer.analyze(source(), on_finding=emitted.append, total_entries=20)
        assert result.error and "input ended unexpectedly" in result.error
        assert not result.cancelled
        assert result.processed_entries == 5 and result.total_entries == 20
        assert result.findings == emitted and len(emitted) == 5

    def test_close_error_retains_findings_and_prevents_scan(self, analyzer, monkeypatch):
        class Source:
            def __init__(self):
                self.index = 0

            def __iter__(self):
                return self

            def __next__(self):
                self.index += 1
                if self.index > 5:
                    raise StopIteration
                return attack(self.index, status_code="404")

            def close(self):
                raise OSError("close input failure")

        monkeypatch.setattr(analyzer, "_detect_scan_behavior", lambda *args: pytest.fail("关闭失败后不推断扫描"))
        result = analyzer.analyze(Source())
        assert result.error and "close input failure" in result.error
        assert not result.cancelled
        assert result.processed_entries == result.total_entries == len(result.findings) == 5

    def test_rule_failure_on_second_entry_keeps_partial_result(self, analyzer, monkeypatch):
        score_line = analyzer.engine.score_line
        calls = []
        pulled = []
        closed = []

        def score(text):
            calls.append(text)
            if len(calls) == 2:
                raise ValueError("second rule evaluation failed")
            return score_line(text)

        def source():
            try:
                for index in range(1, 4):
                    pulled.append(index)
                    yield attack(index, status_code="404")
            finally:
                closed.append(True)

        monkeypatch.setattr(analyzer.engine, "score_line", score)
        monkeypatch.setattr(analyzer, "_detect_scan_behavior", lambda *args: pytest.fail("评分失败后不推断扫描"))
        result = analyzer.analyze(source(), total_entries=3)
        assert result.error == "分析日志失败：second rule evaluation failed"
        assert not result.cancelled
        assert result.processed_entries == 2 and result.total_entries == 3
        assert [finding.line_no for finding in result.findings] == [1]
        assert result.ip_attack_count["10.0.0.1"] == 1
        assert len(calls) == 2 and pulled == [1, 2]
        assert closed == [True]

    def test_finding_callback_error_is_failure_with_partial_findings(self, analyzer, monkeypatch):
        pulled = []
        emitted = []

        def source():
            for index in range(1, 4):
                pulled.append(index)
                yield attack(index)

        def on_finding(finding):
            emitted.append(finding)
            if len(emitted) == 2:
                raise RuntimeError("finding consumer failed")

        monkeypatch.setattr(analyzer, "_detect_scan_behavior", lambda *args: pytest.fail("回调失败后不推断扫描"))
        result = analyzer.analyze(source(), on_finding=on_finding)
        assert result.error == "分析日志失败：finding consumer failed"
        assert not result.cancelled and result.processed_entries == 2
        assert result.findings == emitted and len(emitted) == 2
        assert pulled == [1, 2]

    def test_terminal_progress_callback_error_is_not_silenced(self, analyzer):
        def progress(current, total, text):
            raise RuntimeError("progress consumer failed")

        result = analyzer.analyze(iter([attack()]), on_progress=progress)
        assert result.error == "分析日志失败：progress consumer failed"
        assert result.processed_entries == result.total_entries == len(result.findings) == 1

    @pytest.mark.parametrize("exception_type", [KeyboardInterrupt, SystemExit])
    def test_process_control_exceptions_are_not_caught(self, analyzer, monkeypatch, exception_type):
        def score(text):
            raise exception_type()

        monkeypatch.setattr(analyzer.engine, "score_line", score)
        with pytest.raises(exception_type):
            analyzer.analyze(iter([attack()]))

    def test_cancellation_during_failed_read_is_not_error(self, analyzer):
        cancel = CancelFlag()

        def source():
            yield attack()
            cancel.set()
            raise OSError("cancelled read")

        result = analyzer.analyze(source(), cancel_flag=cancel)
        assert result.cancelled and result.error is None
        assert result.processed_entries == len(result.findings) == 1

    def test_normalizes_once_and_keeps_complete_long_evidence(self, analyzer, monkeypatch):
        text = "GET /?value=" + "A" * 2000 + "%253Cscript%253Ealert(1)%253C/script%253E END"
        raw = "10.0.0.1 " + text + " ORIGINAL-END"
        original = analyzer_module.normalize_line
        calls = []

        def normalize(value):
            calls.append(value)
            return original(value)

        monkeypatch.setattr(analyzer_module, "normalize_line", normalize)
        result = analyzer.analyze(iter([SourceEntry(1, "10.0.0.1", text, raw)]))
        assert calls == [text]
        assert len(result.findings) == 1
        assert result.findings[0].raw == raw
        assert result.findings[0].normalized == original(text)
        assert result.findings[0].normalized.endswith("<script>alert(1)</script> end")
        assert len(result.findings[0].raw) > 2000


class TestStreamingScanBehavior:
    @pytest.mark.parametrize("threshold,expected", [(5, 1), (8, 1), (9, 0), (999, 0)])
    def test_scan_respects_risk_threshold(self, engine, threshold, expected):
        analyzer = LogAnalyzer(engine, risk_threshold=threshold)
        result = analyzer.analyze(not_found(index + 1) for index in range(5))
        assert len(result.findings) == expected
        assert all(finding.score >= threshold for finding in result.findings)
        assert result.processed_entries == 5

    def test_scan_category_suppression_keeps_other_findings(self, tmp_path, engine):
        whitelist = WhitelistManager(str(tmp_path / "missing_whitelist.json"))
        whitelist.add_suppressed_category("Scan Behavior")
        analyzer = LogAnalyzer(engine, whitelist)
        result = analyzer.analyze(attack(index + 1, status_code="404") for index in range(5))
        assert len(result.findings) == 5
        assert all(finding.categories == "Scanner" for finding in result.findings)
        assert result.ip_attack_count["10.0.0.1"] == 5

    def test_scan_can_be_disabled(self, analyzer):
        result = analyzer.analyze((not_found(index + 1) for index in range(5)), enable_scan_behavior=False)
        assert result.findings == []

    def test_multidimensional_scan_uses_unsuppressed_categories(self, tmp_path, engine):
        whitelist = WhitelistManager(str(tmp_path / "missing_whitelist.json"))
        whitelist.add_suppressed_category("SQL Injection")
        analyzer = LogAnalyzer(engine, whitelist)
        rows = [
            SourceEntry(1, "10.0.0.1", "<script>alert(1)", "<script>alert(1)"),
            SourceEntry(2, "10.0.0.1", "../../../etc/passwd", "../../../etc/passwd"),
            SourceEntry(3, "10.0.0.1", "1' or '1'='1", "1' or '1'='1"),
        ]
        result = analyzer.analyze(iter(rows))
        assert result.processed_entries == 3
        assert len(result.findings) == 2
        assert all("Scan Behavior" not in finding.categories for finding in result.findings)
        # 压制仅影响类别展示/扫描聚合，不擅自重算混合命中的原始分数。
        mixed = "sqlmap <script>alert(1)"
        score = engine.score_line(parser.normalize_line(mixed))[0]
        whitelist.add_suppressed_category("Scanner")
        result = analyzer.analyze(iter([SourceEntry(1, "10.0.0.1", mixed, mixed)]))
        assert result.findings[0].score == score
        assert result.findings[0].categories == "XSS"

    def test_scan_cancel_callback_stops_other_ips(self, analyzer):
        cancel = CancelFlag()
        rows = (not_found(index + 1, f"10.0.0.{index // 5 + 1}") for index in range(15))
        result = analyzer.analyze(rows, cancel_flag=cancel, on_finding=lambda finding: cancel.set())
        assert result.cancelled and result.error is None
        assert result.processed_entries == result.total_entries == 15
        assert len(result.findings) == 1
        assert result.findings[0].categories == "Scan Behavior"

    def test_scan_callback_failure_preserves_first_scan_finding(self, analyzer):
        rows = (not_found(index + 1, f"10.0.0.{index // 5 + 1}") for index in range(10))

        def on_finding(finding):
            raise RuntimeError("scan consumer failed")

        result = analyzer.analyze(rows, on_finding=on_finding)
        assert result.error == "分析日志失败：scan consumer failed"
        assert not result.cancelled
        assert result.processed_entries == result.total_entries == 10
        assert len(result.findings) == 1
        assert result.findings[0].categories == "Scan Behavior"

    def test_cancel_from_last_entry_progress_skips_scan(self, analyzer, monkeypatch):
        cancel = CancelFlag()
        monkeypatch.setattr(analyzer, "_detect_scan_behavior", lambda *args: pytest.fail("取消后不得扫描"))

        def progress(current, total, text):
            if current == 5:
                cancel.set()

        result = analyzer.analyze(
            (not_found(index + 1) for index in range(5)), cancel_flag=cancel,
            on_progress=progress, total_entries=5,
        )
        assert result.cancelled and result.error is None
        assert result.processed_entries == 5
        assert result.findings == []
