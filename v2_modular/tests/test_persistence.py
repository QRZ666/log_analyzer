"""同目录原子 JSON 保存的故障注入测试。"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from log_analyzer import persistence
from log_analyzer.persistence import atomic_write_json


@pytest.mark.parametrize("phase", ["serialize", "flush_to_disk", "replace"])
def test_failure_during_save_does_not_truncate_existing_json(monkeypatch, tmp_path, phase):
    path = tmp_path / "settings.json"
    old_bytes = b'{"original": "keep"}\n'
    path.write_bytes(old_bytes)
    unrelated_temp = tmp_path / ".settings.json.some-other-writer.tmp"
    unrelated_temp.write_text("other writer", encoding="utf-8")

    def failure(*args, **kwargs):
        if phase == "serialize":
            args[1].write('{"partial":')
        assert path.read_bytes() == old_bytes
        raise OSError(f"simulated {phase} failure")

    if phase == "serialize":
        monkeypatch.setattr(persistence.json, "dump", failure)
    elif phase == "flush_to_disk":
        monkeypatch.setattr(persistence.os, "fsync", failure)
    else:
        monkeypatch.setattr(persistence.os, "replace", failure)
    with pytest.raises(OSError, match=f"simulated {phase} failure"):
        atomic_write_json(path, {"replacement": "new data"})
    assert path.read_bytes() == old_bytes
    assert unrelated_temp.read_text() == "other writer"
    assert set(tmp_path.iterdir()) == {path, unrelated_temp}


def test_non_json_value_raises_without_destroying_old_file(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text('{"keep": true}', encoding="utf-8")
    old_bytes = path.read_bytes()
    with pytest.raises(ValueError):
        atomic_write_json(path, {"invalid": float("nan")})
    assert path.read_bytes() == old_bytes
    assert list(tmp_path.iterdir()) == [path]


def test_failed_first_save_leaves_no_partial_target(monkeypatch, tmp_path):
    path = tmp_path / "settings.json"

    def fail_replace(*args):
        raise PermissionError("denied")

    monkeypatch.setattr(persistence.os, "replace", fail_replace)
    with pytest.raises(PermissionError):
        atomic_write_json(path, {"new": True})
    assert not path.exists()
    assert list(tmp_path.iterdir()) == []


def test_each_save_has_a_unique_complete_same_directory_temporary_file(monkeypatch, tmp_path):
    path = tmp_path / "nested" / "settings.json"
    real_replace = persistence.os.replace
    seen = []

    def inspect_replace(source, destination):
        source = Path(source)
        assert source.parent == path.parent
        assert Path(destination) == path
        assert source not in seen
        assert json.loads(source.read_text(encoding="utf-8")) == {"iteration": len(seen), "label": "中文"}
        seen.append(source)
        real_replace(source, destination)

    monkeypatch.setattr(persistence.os, "replace", inspect_replace)
    for iteration in range(5):
        assert atomic_write_json(path, {"iteration": iteration, "label": "中文"}) is True
    assert len(seen) == len(set(seen)) == 5
    assert all(not temporary.exists() for temporary in seen)
    assert json.loads(path.read_text(encoding="utf-8")) == {"iteration": 4, "label": "中文"}


def test_bootstrap_publish_never_replaces_an_existing_file(tmp_path):
    path = tmp_path / "settings.json"
    assert atomic_write_json(path, {"user": "keep"}, overwrite=False) is True
    old_bytes = path.read_bytes()
    assert atomic_write_json(path, {"bundled": "new"}, overwrite=False) is False
    assert path.read_bytes() == old_bytes
    assert list(tmp_path.iterdir()) == [path]


def test_bootstrap_publish_handles_a_competing_startup(monkeypatch, tmp_path):
    path = tmp_path / "settings.json"
    method = "rename" if persistence.os.name == "nt" else "link"
    publish = getattr(persistence.os, method)
    other_startup = b'{"other startup": "keep"}'

    def competing_publish(source, destination):
        # 模拟初次 exists 检查之后，另一启动先发布了自己的完整配置。
        path.write_bytes(other_startup)
        publish(source, destination)

    monkeypatch.setattr(persistence.os, method, competing_publish)
    assert atomic_write_json(path, {"bundled": "new"}, overwrite=False) is False
    assert path.read_bytes() == other_startup
    assert list(tmp_path.iterdir()) == [path]
