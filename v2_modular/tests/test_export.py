"""测试报告导出"""

import csv
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from log_analyzer.export import export_csv, export_txt, export_html
from log_analyzer.models import Finding, GeoInfo


class TestExportCSV:
    def test_export_csv(self):
        findings = [
            Finding(1, "10.0.0.1", 8, "SQL Injection", "union(2)",
                    "union select 1", "GET /?id=1 union select 1"),
        ]
        with tempfile.NamedTemporaryFile(
            suffix=".csv", delete=False, mode="w", encoding="utf-8"
        ) as f:
            path = f.name

        try:
            export_csv(path, findings)
            assert os.path.exists(path)
            assert os.path.getsize(path) > 0
            with open(path, "r", encoding="utf-8-sig") as f:
                content = f.read()
            assert "行号" in content
            assert "10.0.0.1" in content
            assert "SQL Injection" in content
        finally:
            os.unlink(path)


class TestExportTXT:
    def test_export_txt(self):
        findings = [
            Finding(1, "10.0.0.1", 5, "XSS", "<script>(5)",
                    "<script>alert", "<script>alert(1)"),
        ]
        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False, mode="w", encoding="utf-8"
        ) as f:
            path = f.name

        try:
            export_txt(path, findings, source_file="test.log",
                       ip_stats={"10.0.0.1": 1})
            assert os.path.exists(path)
            assert os.path.getsize(path) > 0
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            assert "Web攻击日志分析报告" in content
            assert "10.0.0.1" in content
            assert "test.log" in content
        finally:
            os.unlink(path)


class TestExportHTML:
    def test_export_html(self):
        findings = [
            Finding(1, "10.0.0.1", 8, "SQL Injection", "union(2)",
                    "union select", "union select"),
        ]
        with tempfile.NamedTemporaryFile(
            suffix=".html", delete=False, mode="w", encoding="utf-8"
        ) as f:
            path = f.name

        try:
            export_html(path, findings, source_file="test.log",
                        ip_stats={"10.0.0.1": 1})
            assert os.path.exists(path)
            assert os.path.getsize(path) > 0
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            assert "<html" in content.lower()
            assert "10.0.0.1" in content
            assert "SQL Injection" in content
        finally:
            os.unlink(path)


class TestExportWithGeoIP:
    def test_export_with_geo(self):
        findings = [
            Finding(1, "8.8.8.8", 5, "Scanner", "nmap(8)",
                    "nmap scan", "nmap scan"),
        ]
        geo = {
            "8.8.8.8": GeoInfo(ip="8.8.8.8", country="US",
                                city="Mountain View", org="Google"),
        }
        with tempfile.NamedTemporaryFile(
            suffix=".html", delete=False, mode="w", encoding="utf-8"
        ) as f:
            path = f.name

        try:
            export_html(path, findings, source_file="test.log",
                        ip_stats={"8.8.8.8": 1}, ip_geo=geo)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            assert "US" in content
            assert "Google" in content
        finally:
            os.unlink(path)


class TestExportControlChars:
    def test_nul_byte_does_not_truncate_csv(self):
        """回归：payload 里的空字节会让 csv 抛
        _csv.Error: need to escape, but no escapechar set，
        文件写到一半就断了（实测 917 条只写进 144 条）"""
        findings = [
            Finding(1, "10.0.0.1", 7, "Path Traversal", "../etc/passwd",
                    "get /files?name=../../etc/passwd\x00.html",
                    "GET /files?name=../../etc/passwd\x00.html"),
            Finding(2, "10.0.0.2", 6, "XSS", "<script>(5)",
                    "<script>alert(1)</script>", "<script>alert(1)</script>"),
            Finding(3, "10.0.0.3", 5, "Scanner", "nmap(5)", "nmap", "nmap"),
        ]
        with tempfile.NamedTemporaryFile(
            suffix=".csv", delete=False, mode="w", encoding="utf-8"
        ) as f:
            path = f.name

        try:
            export_csv(path, findings)

            with open(path, "r", encoding="utf-8-sig") as f:
                rows = list(csv.reader(f))
            # 表头 + 每一条都必须写进去
            assert len(rows) == len(findings) + 1, "空字节之后的记录被丢弃了"
            assert rows[-1][1] == "10.0.0.3"

            content = open(path, "r", encoding="utf-8-sig").read()
            assert "\x00" not in content, "空字节应被转义，不能留在文件里"
            assert "\\x00" in content, "空字节应转成可见的 \\x00 证据"
        finally:
            os.unlink(path)


class TestExportHTMLEscaping:
    def test_payload_is_escaped_not_injected(self):
        """回归：日志里的 XSS payload 曾原样插进报告，打开报告就执行攻击者的 JS"""
        payload = "<script>alert('xss')</script>"
        findings = [
            Finding(1, "10.0.0.1", 9, "XSS", "<script>(5)", payload, payload),
        ]
        with tempfile.NamedTemporaryFile(
            suffix=".html", delete=False, mode="w", encoding="utf-8"
        ) as f:
            path = f.name

        try:
            export_html(path, findings, source_file="test.log")

            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

            assert "<script>alert" not in content, "payload 逃逸成了真脚本标签"
            assert "&lt;script&gt;alert" in content, "payload 应以纯文本呈现"
            assert content.count("<tr>") == 2, "表格结构被 payload 破坏"  # 表头 + 1 行
        finally:
            os.unlink(path)


class TestAtomicWrite:
    def test_failed_export_keeps_previous_file(self):
        """回归：导出中途失败不能留下半截文件"""
        with tempfile.NamedTemporaryFile(
            suffix=".csv", delete=False, mode="w", encoding="utf-8"
        ) as f:
            path = f.name

        try:
            export_csv(path, [])
            good = open(path, "r", encoding="utf-8-sig").read()

            class Boom:
                def __getattr__(self, name):
                    raise RuntimeError("模拟导出中途炸掉")

            with pytest.raises(RuntimeError):
                export_csv(path, [Boom()])

            assert open(path, "r", encoding="utf-8-sig").read() == good, \
                "失败时原文件被破坏了"
            assert not os.path.exists(path + ".part"), "残留了临时文件"
        finally:
            os.unlink(path)
