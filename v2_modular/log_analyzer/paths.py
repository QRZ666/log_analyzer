"""源码资源位置与冻结应用的可写用户数据位置。"""

import json
import os
import sys
from pathlib import Path

from .persistence import atomic_write_json

SOURCE_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_JSON_FILES = ("config.json", "rules.json", "whitelist.json")


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundled_defaults_dir() -> Path:
    """只读默认资源目录；不缓存每次启动可能不同的 _MEIPASS。"""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)).resolve()
    return SOURCE_ROOT


def user_data_dir() -> Path:
    """Windows 使用 Roaming AppData，macOS/Linux 使用惯常用户配置目录。"""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        root = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
        if not root.is_absolute():
            root = Path.home() / "AppData" / "Roaming"
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        xdg_home = os.environ.get("XDG_CONFIG_HOME", "")
        root = Path(xdg_home) if xdg_home else Path.home() / ".config"
        if not root.is_absolute():
            root = Path.home() / ".config"
    return (root / "LogAnalyzer").resolve()


def default_data_dir() -> Path:
    return user_data_dir() if is_frozen() else SOURCE_ROOT


def ensure_writable_path(path: Path) -> None:
    """冻结资源只能读；即使调用者显式传入资源路径也不得保存到资源目录。"""
    if is_frozen():
        try:
            Path(path).resolve().relative_to(bundled_defaults_dir())
        except ValueError:
            return
        raise PermissionError(f"不能写入只读的打包资源目录：{path}")


def bootstrap_user_defaults() -> str:
    """冻结启动时只补充缺失的默认 JSON，已有/损坏的用户文件都不覆盖。

    不创建源码模式或显式指定配置的用户目录。初始化失败只返回提示，调用者
    仍可使用内存默认值；后续显式 save 的错误不在这里吞掉。
    """
    if not is_frozen():
        return ""

    warnings = []
    source_dir = bundled_defaults_dir()
    destination_dir = user_data_dir()
    for filename in _DEFAULT_JSON_FILES:
        destination = destination_dir / filename
        try:
            ensure_writable_path(destination)
            if destination.exists() or destination.is_symlink():
                continue
            with (source_dir / filename).open("r", encoding="utf-8-sig") as stream:
                data = json.load(stream)
            if not isinstance(data, dict):
                raise ValueError("默认 JSON 顶层必须为对象")
            # 独占发布消除 exists 检查与复制之间的竞态，保留另一启动的用户文件。
            atomic_write_json(destination, data, overwrite=False)
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            warnings.append(f"无法初始化用户默认文件 {filename}：{exc}")
    return "\n".join(warnings)
