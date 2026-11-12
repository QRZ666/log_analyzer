"""完整证据、报告状态、CSV安全和唯一临时文件的回归。"""

import csv
import html
from pathlib import Path

import pytest

from log_analyzer import export
from log_analyzer.models import Finding


@pytest.fixture
def evidence():
    raw = "head <script>alert(1)</script> " + "证据 " * 1000 + "END"
    return Finding(123, "10.0.0.1", 10, "XSS", "<script>", raw.lower(), raw)


@pytest.mark.parametrize("extension", ["csv", "txt", "html"])
def test_all_reports_preserve_complete_evidence_and_analysis_status(tmp_path, evidence, extension):
    path = tmp_path / f"report.{extension}"
    note = "用户取消分析，报告仅含部分结果；范围：当前筛选"
    export.export_report(str(path), [evidence], analysis_note=note,
                         ip_stats={evidence.ip: 1})
    text = path.read_text(encoding="utf-8-sig")
    assert note in text
    if extension == "html":
        assert html.escape(evidence.raw, quote=True) in text
        assert "<script>alert(1)</script>" not in text
        assert "text-overflow: ellipsis" not in text
    elif extension == "csv":
        with path.open(encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.reader(stream))
        assert rows[0][-1] == "分析状态"
        assert rows[1][-2] == evidence.raw
        assert rows[1][-1] == note
    else:
        assert evidence.raw in text


def test_html_analysis_note_is_escaped(tmp_path, evidence):
    path = tmp_path / "report.html"
    export.export_html(str(path), [evidence], analysis_note="failed <img src=x onerror=alert(1)>")
    text = path.read_text(encoding="utf-8")
    assert "failed &lt;img" in text
    assert "failed <img" not in text


def test_default_csv_columns_stay_backward_compatible(tmp_path, evidence):
    path = tmp_path / "default.csv"
    export.export_csv(str(path), [evidence])
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.reader(stream))
    assert len(rows[0]) == len(rows[1]) == 8


@pytest.mark.parametrize("payload", [
    '=HYPERLINK("https://example.invalid", "click")',
    "+1+1", "-1+1", "@SUM(1,2)", " \t=1+1", "\tcommand", "\r=1+1",
])
def test_csv_payload_cannot_start_spreadsheet_formula(tmp_path, payload):
    path = tmp_path / "untrusted.csv"
    item = Finding(1, "10.0.0.1", 10, "Test", "match", payload, payload)
    export.export_csv(str(path), [item])
    with path.open(encoding="utf-8-sig", newline="") as stream:
        row = list(csv.reader(stream))[1]
    assert row[-1] == "'" + payload
    assert row[-2] == "'" + payload
    assert item.raw == payload  # 内存中的原始证据不改变。


def test_unique_temp_path_does_not_touch_existing_part_file(tmp_path, evidence):
    path = tmp_path / "report.csv"
    unrelated = tmp_path / "report.csv.part"
    unrelated.write_text("another unfinished export", encoding="utf-8")
    export.export_csv(str(path), [evidence])
    assert unrelated.read_text(encoding="utf-8") == "another unfinished export"
    assert not list(tmp_path.glob(".report.csv.*.part"))


def test_publish_failure_keeps_old_report_and_cleans_own_temp(tmp_path, evidence, monkeypatch):
    path = tmp_path / "report.csv"
    path.write_text("old report", encoding="utf-8")
    def deny(source, target):
        assert Path(source).parent == path.parent
        assert Path(source) != path.with_name(path.name + ".part")
        assert Path(target) == path
        raise PermissionError("locked report")
    monkeypatch.setattr(export.os, "replace", deny)
    with pytest.raises(PermissionError, match="locked report"):
        export.export_csv(str(path), [evidence])
    assert path.read_text(encoding="utf-8") == "old report"
    assert not list(tmp_path.glob(".report.csv.*.part"))
