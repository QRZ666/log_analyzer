"""测试白名单管理"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from log_analyzer import persistence, whitelist as whitelist_module
from log_analyzer.whitelist import WhitelistManager


class TestWhitelistManager:
    """白名单管理器测试"""

    @pytest.fixture(autouse=True)
    def setup_whitelist(self, tmp_path):
        self.wl = WhitelistManager(whitelist_path=tmp_path / "whitelist.json")

    def test_add_and_check_ip(self):
        self.wl.add_ip("192.168.1.100")
        assert self.wl.is_ip_whitelisted("192.168.1.100")
        assert not self.wl.is_ip_whitelisted("192.168.1.200")

    def test_remove_ip(self):
        self.wl.add_ip("10.0.0.1")
        assert self.wl.is_ip_whitelisted("10.0.0.1")
        self.wl.remove_ip("10.0.0.1")
        assert not self.wl.is_ip_whitelisted("10.0.0.1")

    def test_add_and_check_pattern(self):
        self.wl.add_pattern("/healthcheck")
        assert self.wl.is_pattern_whitelisted("GET /healthcheck HTTP/1.1")
        assert not self.wl.is_pattern_whitelisted("GET /admin HTTP/1.1")

    def test_invalid_pattern_raises(self):
        try:
            self.wl.add_pattern("[invalid(regex")
            assert False, "应该抛出 ValueError"
        except ValueError:
            pass

    def test_category_suppression(self):
        self.wl.add_suppressed_category("Scanner")
        assert self.wl.is_category_suppressed("Scanner")
        assert not self.wl.is_category_suppressed("XSS")

    def test_comprehensive_check(self):
        self.wl.add_ip("127.0.0.1")
        self.wl.add_pattern("/api/health")
        assert self.wl.is_whitelisted("127.0.0.1")
        assert self.wl.is_whitelisted("10.0.0.1", "GET /api/health")
        assert not self.wl.is_whitelisted("10.0.0.1", "GET /api/admin")

    def test_get_methods(self):
        self.wl.add_ip("10.0.0.1")
        self.wl.add_ip("10.0.0.2")
        self.wl.add_pattern("/test")
        self.wl.add_suppressed_category("XSS")

        assert "10.0.0.1" in self.wl.get_ips()
        assert "10.0.0.2" in self.wl.get_ips()
        assert "/test" in self.wl.get_patterns()
        assert "XSS" in self.wl.get_suppressed_categories()

    def test_len(self):
        self.wl.add_ip("10.0.0.1")
        self.wl.add_pattern("/test")
        self.wl.add_suppressed_category("XSS")
        assert len(self.wl) == 3


def write_whitelist(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_missing_whitelist_is_empty_without_writing(tmp_path):
    path = tmp_path / "missing" / "whitelist.json"
    whitelist = WhitelistManager(path)
    assert len(whitelist) == 0
    assert whitelist.load_warning
    assert not path.parent.exists()


def test_source_default_whitelist_keeps_project_location(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    assert whitelist_module._DEFAULT_WHITELIST_PATH == Path(whitelist_module.__file__).resolve().parent.parent / "whitelist.json"
    path = tmp_path / "source" / "whitelist.json"
    write_whitelist(path, {"ips": ["192.0.2.1"]})
    monkeypatch.setattr(whitelist_module, "_DEFAULT_WHITELIST_PATH", path)
    whitelist = WhitelistManager()
    assert whitelist._path == path
    assert whitelist.is_ip_whitelisted("192.0.2.1")


@pytest.mark.parametrize("contents", [b"{broken", b"[]", b"null", b"4", b"true", b'"abc"', b"\xff"])
def test_malformed_whitelist_is_nonfatal_and_unchanged(tmp_path, contents):
    path = tmp_path / "whitelist.json"
    path.write_bytes(contents)
    whitelist = WhitelistManager(path)
    assert len(whitelist) == 0
    assert whitelist.load_warning
    assert path.read_bytes() == contents


@pytest.mark.parametrize("field", ["ips", "patterns", "categories"])
@pytest.mark.parametrize("value", [None, False, 123, "not-a-list", {}])
def test_wrong_whitelist_field_types_are_ignored(tmp_path, field, value):
    path = tmp_path / "whitelist.json"
    write_whitelist(path, {field: value})
    whitelist = WhitelistManager(path)
    assert len(whitelist) == 0
    assert field in whitelist.load_warning


def test_invalid_entries_are_skipped_and_valid_entries_survive(tmp_path):
    path = tmp_path / "whitelist.json"
    write_whitelist(path, {
        "ips": [None, 1, {}, "", "  ", " 192.0.2.1 "],
        "patterns": [None, [], 1, "", " ", "[broken", "a{99999999999999999999999}", "(" * 2000, "/health"],
        "categories": [None, 1, [], "", " XSS "],
    })
    whitelist = WhitelistManager(path)
    assert whitelist.get_ips() == ["192.0.2.1"]
    assert whitelist.get_patterns() == ["/health"]
    assert whitelist.get_suppressed_categories() == ["XSS"]
    assert whitelist.is_pattern_whitelisted("GET /HEALTH")
    assert not whitelist.is_pattern_whitelisted("GET /admin")
    assert all(field in whitelist.load_warning for field in ("ips", "patterns", "categories"))


def test_whitelist_load_resets_state_and_warning(tmp_path):
    path = tmp_path / "whitelist.json"
    whitelist = WhitelistManager(path)
    whitelist.add_ip("192.0.2.1")
    whitelist.add_pattern("/health")
    whitelist.add_suppressed_category("XSS")
    path.write_text("{}", encoding="utf-8-sig")
    whitelist.load()
    assert len(whitelist) == 0
    assert whitelist.load_warning == ""


def test_whitelist_round_trip_preserves_unknown_fields(tmp_path):
    path = tmp_path / "whitelist.json"
    write_whitelist(path, {"ips": ["192.0.2.1"], "future": {"names": ["keep"]}})
    whitelist = WhitelistManager(path)
    whitelist.add_ip("192.0.2.2")
    whitelist.add_pattern("/health")
    whitelist.add_suppressed_category("XSS")
    whitelist.save()
    reloaded = WhitelistManager(path)
    assert reloaded.get_ips() == ["192.0.2.1", "192.0.2.2"]
    assert reloaded.get_patterns() == ["/health"]
    assert reloaded.get_suppressed_categories() == ["XSS"]
    assert json.loads(path.read_text())["future"] == {"names": ["keep"]}
    assert reloaded.load_warning == ""


def test_whitelist_copy_is_independent_and_performs_no_io(monkeypatch, tmp_path):
    path = tmp_path / "whitelist.json"
    write_whitelist(path, {"ips": ["192.0.2.1"], "patterns": ["/health"], "categories": ["XSS"], "future": {"names": ["keep"]}})
    original = WhitelistManager(path)
    # 磁盘上的修改不应该被 copy 重新读取。
    write_whitelist(path, {"ips": ["198.51.100.1"]})

    def no_io(*args, **kwargs):
        raise AssertionError("snapshot must not perform I/O or call a constructor")

    monkeypatch.setattr(WhitelistManager, "__init__", no_io)
    monkeypatch.setattr(WhitelistManager, "load", no_io)
    monkeypatch.setattr(WhitelistManager, "save", no_io)
    monkeypatch.setattr(Path, "open", no_io)
    monkeypatch.setattr(Path, "resolve", no_io)
    snapshot = original.copy()
    assert snapshot._path == original._path
    assert snapshot.get_ips() == ["192.0.2.1"]
    assert snapshot.get_patterns() == ["/health"]
    assert snapshot.get_suppressed_categories() == ["XSS"]
    assert snapshot.load_warning == original.load_warning
    snapshot.add_ip("203.0.113.1")
    snapshot.remove_pattern("/health")
    snapshot.add_pattern("/status")
    snapshot.remove_suppressed_category("XSS")
    snapshot._unknown_fields["future"]["names"].append("draft")
    assert original.get_ips() == ["192.0.2.1"]
    assert original.get_patterns() == ["/health"]
    assert original.get_suppressed_categories() == ["XSS"]
    assert original._unknown_fields["future"]["names"] == ["keep"]
    original.add_ip("192.0.2.2")
    assert not snapshot.is_ip_whitelisted("192.0.2.2")


def test_replace_from_copies_memory_without_changing_destination_path(monkeypatch, tmp_path):
    original = WhitelistManager(tmp_path / "original.json")
    other = WhitelistManager(tmp_path / "other.json")
    other.add_ip("192.0.2.1")
    other.add_pattern("/health")
    other.add_suppressed_category("XSS")
    old_path = original._path

    def no_io(*args, **kwargs):
        raise AssertionError("replace_from must not perform I/O")

    monkeypatch.setattr(Path, "open", no_io)
    monkeypatch.setattr(WhitelistManager, "load", no_io)
    monkeypatch.setattr(WhitelistManager, "save", no_io)
    assert original.replace_from(other) is None
    assert original._path == old_path
    assert original.get_ips() == ["192.0.2.1"]
    assert original.is_pattern_whitelisted("/HEALTH")
    assert original.is_category_suppressed("XSS")
    other.remove_ip("192.0.2.1")
    other.remove_pattern("/health")
    other.remove_suppressed_category("XSS")
    assert len(original) == 3
    original.replace_from(original)
    assert len(original) == 3
    with pytest.raises(TypeError):
        original.replace_from({})


def test_draft_save_failure_leaves_original_and_old_file_unchanged(monkeypatch, tmp_path):
    path = tmp_path / "whitelist.json"
    write_whitelist(path, {"ips": ["192.0.2.1"]})
    old_bytes = path.read_bytes()
    original = WhitelistManager(path)
    draft = original.copy()
    draft.remove_ip("192.0.2.1")
    draft.add_ip("203.0.113.1")
    draft.add_pattern("/health")

    def fail_replace(*args):
        raise PermissionError("simulated replace denial")

    with monkeypatch.context() as patch:
        patch.setattr(persistence.os, "replace", fail_replace)
        with pytest.raises(PermissionError, match="simulated replace denial"):
            draft.save()
            original.replace_from(draft)
    assert original.get_ips() == ["192.0.2.1"]
    assert original.get_patterns() == []
    assert path.read_bytes() == old_bytes
    assert list(tmp_path.iterdir()) == [path]

    # 先保存再提交；未提交前运行中实例保持原值。
    draft.save()
    assert original.get_ips() == ["192.0.2.1"]
    original.replace_from(draft)
    assert original.get_ips() == ["203.0.113.1"]
    assert original.get_patterns() == ["/health"]
    assert WhitelistManager(path).get_ips() == original.get_ips()
    draft.add_ip("203.0.113.2")
    assert not original.is_ip_whitelisted("203.0.113.2")


def test_cancelled_draft_does_not_change_file_or_running_whitelist(tmp_path):
    path = tmp_path / "whitelist.json"
    write_whitelist(path, {"ips": ["192.0.2.1"], "patterns": ["/health"]})
    old_bytes = path.read_bytes()
    original = WhitelistManager(path)
    draft = original.copy()
    draft.remove_ip("192.0.2.1")
    draft.remove_pattern("/health")
    draft.add_suppressed_category("XSS")
    assert original.get_ips() == ["192.0.2.1"]
    assert original.get_patterns() == ["/health"]
    assert original.get_suppressed_categories() == []
    assert path.read_bytes() == old_bytes
