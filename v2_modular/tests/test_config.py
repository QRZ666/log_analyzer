"""配置校验、路径解析和冻结应用持久化；所有写入均在 tmp_path。"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from log_analyzer import config as config_module
from log_analyzer import paths, persistence
from log_analyzer.config import ConfigManager
from log_analyzer.whitelist import WhitelistManager


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def make_bundle(path, threshold=5, ip="127.0.0.1"):
    write_json(path / "config.json", {
        "risk_threshold": threshold,
        "rules_path": "rules.json", "whitelist_path": "whitelist.json",
        "geoip_db_path": "db/city.mmdb",
    })
    write_json(path / "rules.json", {"categories": {}, "settings": {"default_threshold": threshold}})
    write_json(path / "whitelist.json", {"ips": [ip], "patterns": [], "categories": []})


def frozen_environment(monkeypatch, tmp_path, bundle):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(bundle), raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    return tmp_path / "appdata" / "LogAnalyzer"


def assert_default_paths(manager, directory):
    assert manager.config.rules_path == str((directory / "rules.json").resolve())
    assert manager.config.whitelist_path == str((directory / "whitelist.json").resolve())
    assert manager.config.geoip_db_path == ""


def test_source_defaults_remain_at_project_root(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    project_root = Path(config_module.__file__).resolve().parent.parent
    assert paths.default_data_dir() == project_root
    assert config_module._DEFAULT_CONFIG_PATH == project_root / "config.json"
    config_path = tmp_path / "source" / "config.json"
    write_json(config_path, {})
    monkeypatch.setattr(config_module, "_DEFAULT_CONFIG_PATH", config_path)
    monkeypatch.setenv("APPDATA", str(tmp_path / "unused-appdata"))
    manager = ConfigManager()
    assert manager._path == config_path
    assert_default_paths(manager, config_path.parent)
    assert not (tmp_path / "unused-appdata").exists()


@pytest.mark.parametrize("relative_config", [False, True])
def test_explicit_paths_resolve_beside_actual_config(monkeypatch, tmp_path, relative_config):
    path = tmp_path / "settings" / "custom.json"
    write_json(path, {
        "rules_path": "rules/custom.json",
        "whitelist_path": "../lists/trusted.json",
        "geoip_db_path": "db/city.mmdb",
    })
    monkeypatch.chdir(tmp_path)
    manager = ConfigManager("settings/custom.json" if relative_config else path)
    assert manager.config.rules_path == str(path.parent / "rules" / "custom.json")
    assert manager.config.whitelist_path == str(tmp_path / "lists" / "trusted.json")
    assert manager.config.geoip_db_path == str(path.parent / "db" / "city.mmdb")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    manager.risk_threshold = 12
    manager.save()
    manager.load()
    assert manager.risk_threshold == 12
    assert manager._path == path
    assert manager.load_warning == ""
    assert not (elsewhere / "settings").exists()


def test_absolute_config_paths_are_respected(tmp_path):
    absolute = tmp_path / "external" / "custom.json"
    database = tmp_path / "external" / "city.mmdb"
    path = tmp_path / "settings" / "config.json"
    write_json(path, {"rules_path": str(absolute), "whitelist_path": str(absolute), "geoip_db_path": str(database)})
    manager = ConfigManager(path)
    assert manager.config.rules_path == str(absolute)
    assert manager.config.whitelist_path == str(absolute)
    assert manager.config.geoip_db_path == str(database)


def test_missing_config_uses_local_defaults_without_writing(tmp_path):
    path = tmp_path / "missing" / "config.json"
    manager = ConfigManager(path)
    assert_default_paths(manager, path.parent)
    assert manager.risk_threshold == 5
    assert manager.load_warning
    assert not path.parent.exists()


@pytest.mark.parametrize("contents", [
    b"{broken", b"[]", b"null", b"12", b"true", b'"text"', b"\xff\xfe",
    ("[" * 2000 + "]" * 2000).encode(),
])
def test_malformed_config_uses_local_defaults(tmp_path, contents):
    path = tmp_path / "config.json"
    path.write_bytes(contents)
    manager = ConfigManager(path)
    assert_default_paths(manager, tmp_path)
    assert manager.risk_threshold == 5
    assert manager.geoip_enabled is False
    assert manager.load_warning
    assert path.read_bytes() == contents


@pytest.mark.parametrize("field,value,expected", [
    ("risk_threshold", "9", 5), ("risk_threshold", True, 5),
    ("risk_threshold", -1, 5), ("risk_threshold", 1.5, 5),
    ("risk_threshold", 2**80, 5), ("risk_threshold", None, 5),
    ("max_file_size_mb", 0, 100), ("max_file_size_mb", -5, 100),
    ("max_file_size_mb", False, 100), ("max_file_size_mb", "100", 100),
    ("max_file_size_mb", 2**80, 100), ("max_file_size_mb", 1.5, 100),
    ("geoip_enabled", "false", False), ("geoip_enabled", 1, False),
    ("geoip_enabled", None, False),
])
def test_invalid_config_fields_fall_back_individually(tmp_path, field, value, expected):
    path = tmp_path / "config.json"
    write_json(path, {field: value, "custom": {"keep": True}})
    manager = ConfigManager(path)
    assert getattr(manager.config, field) == expected
    assert field in manager.load_warning
    assert_default_paths(manager, tmp_path)


@pytest.mark.parametrize("field", ["rules_path", "whitelist_path", "geoip_db_path"])
@pytest.mark.parametrize("value", [None, 1, [], {}, " \t ", "bad\x00path"])
def test_invalid_path_fields_use_config_directory_defaults(tmp_path, field, value):
    path = tmp_path / "config.json"
    write_json(path, {field: value, "risk_threshold": 7})
    manager = ConfigManager(path)
    assert manager.risk_threshold == 7
    assert field in manager.load_warning
    assert_default_paths(manager, tmp_path)


@pytest.mark.parametrize("field", ["rules_path", "whitelist_path"])
def test_required_paths_cannot_be_empty(tmp_path, field):
    path = tmp_path / "config.json"
    write_json(path, {field: ""})
    manager = ConfigManager(path)
    assert field in manager.load_warning
    assert_default_paths(manager, tmp_path)


@pytest.mark.parametrize("threshold,size", [(0, 1), (10, 200), (2_147_483_647, 2_147_483_647)])
def test_valid_numeric_config_range(tmp_path, threshold, size):
    path = tmp_path / "config.json"
    write_json(path, {"risk_threshold": threshold, "max_file_size_mb": size, "geoip_enabled": True})
    manager = ConfigManager(path)
    assert manager.risk_threshold == threshold
    assert manager.config.max_file_size_mb == size
    assert manager.geoip_enabled is True
    assert manager.load_warning == ""


def test_config_round_trip_preserves_unknown_fields_and_relative_paths(tmp_path):
    path = tmp_path / "config.json"
    original = {
        "risk_threshold": 8, "rules_path": "rules/custom.json",
        "whitelist_path": "lists/trusted.json", "geoip_db_path": "db/city.mmdb",
        "future_feature": {"enabled": True, "names": ["中文", "keep"]},
    }
    write_json(path, original)
    manager = ConfigManager(path)
    manager.risk_threshold = 12
    manager.geoip_enabled = True
    manager.save()
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["future_feature"] == original["future_feature"]
    for field in ("rules_path", "whitelist_path", "geoip_db_path"):
        assert saved[field] == original[field]
    loaded = ConfigManager(path)
    assert loaded.risk_threshold == 12
    assert loaded.geoip_enabled is True
    assert loaded.load_warning == ""


def test_load_warning_resets_and_utf8_bom_is_supported(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("[]", encoding="utf-8")
    manager = ConfigManager(path)
    assert manager.load_warning
    path.write_text('{"risk_threshold": 11}', encoding="utf-8-sig")
    manager.load()
    assert manager.risk_threshold == 11
    assert manager.load_warning == ""


def test_config_unreadable_file_uses_defaults(monkeypatch, tmp_path):
    path = tmp_path / "config.json"
    write_json(path, {"risk_threshold": 12})
    real_open = Path.open

    def denied_open(self, *args, **kwargs):
        if self == path:
            raise PermissionError("simulated read denial")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied_open)
    manager = ConfigManager(path)
    assert manager.risk_threshold == 5
    assert "simulated read denial" in manager.load_warning
    assert_default_paths(manager, tmp_path)


def test_config_save_failure_preserves_old_json(monkeypatch, tmp_path):
    path = tmp_path / "config.json"
    write_json(path, {"risk_threshold": 5, "unknown": "keep"})
    old_bytes = path.read_bytes()
    manager = ConfigManager(path)
    manager.risk_threshold = 11

    def fail_replace(*args):
        raise PermissionError("simulated replace denial")

    monkeypatch.setattr(persistence.os, "replace", fail_replace)
    with pytest.raises(PermissionError, match="simulated replace denial"):
        manager.save()
    assert path.read_bytes() == old_bytes
    assert sorted(tmp_path.iterdir()) == [path]


def test_frozen_two_resource_directories_keep_user_settings(monkeypatch, tmp_path):
    first_bundle = tmp_path / "bundle-one"
    second_bundle = tmp_path / "bundle-two"
    make_bundle(first_bundle, threshold=6)
    make_bundle(second_bundle, threshold=9, ip="192.0.2.2")
    bundled_bytes = {
        path: path.read_bytes()
        for directory in (first_bundle, second_bundle) for path in directory.iterdir()
    }
    user_dir = frozen_environment(monkeypatch, tmp_path, first_bundle)
    first = ConfigManager()
    assert first._path == user_dir / "config.json"
    assert first.config.rules_path == str(user_dir / "rules.json")
    assert first.config.whitelist_path == str(user_dir / "whitelist.json")
    assert first.config.geoip_db_path == str(user_dir / "db" / "city.mmdb")
    assert first.risk_threshold == 6
    assert first.load_warning == ""
    whitelist = WhitelistManager()
    assert whitelist._path == user_dir / "whitelist.json"
    whitelist.add_ip("203.0.113.8")
    whitelist.save()
    first.risk_threshold = 17
    first.save()
    write_json(user_dir / "rules.json", {"custom": "do not replace"})
    user_bytes = {path: path.read_bytes() for path in user_dir.iterdir()}

    monkeypatch.setattr(sys, "_MEIPASS", str(second_bundle))
    second = ConfigManager()
    second_whitelist = WhitelistManager()
    assert second.risk_threshold == 17
    assert second.config.rules_path == str(user_dir / "rules.json")
    assert second_whitelist.is_ip_whitelisted("203.0.113.8")
    assert not second_whitelist.is_ip_whitelisted("192.0.2.2")
    assert {path: path.read_bytes() for path in user_dir.iterdir()} == user_bytes
    assert all(path.read_bytes() == contents for path, contents in bundled_bytes.items())
    assert all(len(list(directory.iterdir())) == 3 for directory in (first_bundle, second_bundle))


def test_frozen_only_missing_files_are_seeded_even_if_user_json_is_broken(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle"
    make_bundle(bundle)
    user_dir = frozen_environment(monkeypatch, tmp_path, bundle)
    user_dir.mkdir(parents=True)
    (user_dir / "config.json").write_bytes(b"{broken user config")
    (user_dir / "whitelist.json").write_bytes(b"{broken user whitelist")
    manager = ConfigManager()
    assert manager.load_warning
    assert (user_dir / "config.json").read_bytes() == b"{broken user config"
    assert (user_dir / "whitelist.json").read_bytes() == b"{broken user whitelist"
    assert json.loads((user_dir / "rules.json").read_text()) == json.loads((bundle / "rules.json").read_text())
    assert_default_paths(manager, user_dir)


def test_frozen_explicit_paths_do_not_initialize_appdata(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle"
    make_bundle(bundle)
    user_dir = frozen_environment(monkeypatch, tmp_path, bundle)
    path = tmp_path / "explicit" / "config.json"
    manager = ConfigManager(path)
    assert_default_paths(manager, path.parent)
    whitelist = WhitelistManager(path.parent / "whitelist.json")
    manager.save()
    whitelist.save()
    assert path.is_file()
    assert not user_dir.exists()


def test_frozen_bootstrap_failure_is_nonfatal(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle"
    make_bundle(bundle)
    user_dir = frozen_environment(monkeypatch, tmp_path, bundle)

    def fail_seed(*args, **kwargs):
        raise PermissionError("simulated user directory denial")

    monkeypatch.setattr(paths, "atomic_write_json", fail_seed)
    manager = ConfigManager()
    assert manager._path == user_dir / "config.json"
    assert_default_paths(manager, user_dir)
    assert "simulated user directory denial" in manager.load_warning
    assert not user_dir.exists()


@pytest.mark.parametrize("filename,manager_type", [("config.json", ConfigManager), ("whitelist.json", WhitelistManager)])
def test_frozen_managers_refuse_to_write_bundled_defaults(monkeypatch, tmp_path, filename, manager_type):
    bundle = tmp_path / "bundle"
    make_bundle(bundle)
    frozen_environment(monkeypatch, tmp_path, bundle)
    target = bundle / filename
    old_bytes = target.read_bytes()
    manager = manager_type(target)
    with pytest.raises(PermissionError, match="只读"):
        manager.save()
    assert target.read_bytes() == old_bytes
    assert len(list(bundle.iterdir())) == 3


def test_frozen_appdata_inside_bundle_never_writes_resources(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle"
    make_bundle(bundle)
    frozen_environment(monkeypatch, tmp_path, bundle)
    monkeypatch.setenv("APPDATA", str(bundle / "bad-appdata"))
    manager = ConfigManager()
    assert manager.load_warning
    assert not (bundle / "bad-appdata").exists()
    with pytest.raises(PermissionError):
        manager.save()
    assert not (bundle / "bad-appdata").exists()


@pytest.mark.parametrize("platform,environment,expected", [
    ("win32", {"APPDATA": "roaming"}, "roaming/LogAnalyzer"),
    ("win32", {}, "home/AppData/Roaming/LogAnalyzer"),
    ("darwin", {}, "home/Library/Application Support/LogAnalyzer"),
    ("linux", {"XDG_CONFIG_HOME": "xdg"}, "xdg/LogAnalyzer"),
    ("linux", {}, "home/.config/LogAnalyzer"),
])
def test_user_directories_by_platform(monkeypatch, tmp_path, platform, environment, expected):
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    for name, directory in environment.items():
        monkeypatch.setenv(name, str(tmp_path / directory))
    assert paths.user_data_dir() == tmp_path / expected
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("platform,variable,expected", [
    ("win32", "APPDATA", "AppData/Roaming"),
    ("linux", "XDG_CONFIG_HOME", ".config"),
])
def test_relative_user_directory_environment_does_not_follow_cwd(monkeypatch, tmp_path, platform, variable, expected):
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.setenv(variable, "relative-directory")
    assert paths.user_data_dir() == tmp_path / "home" / expected / "LogAnalyzer"
