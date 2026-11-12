"""同目录临时文件发布 JSON；失败时不截断已有文件。"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Union


def atomic_write_json(
    path: Union[str, Path], data: Any, *, overwrite: bool = True
) -> bool:
    """完整写入并 fsync 后原子发布，返回是否发布了新文件。

    overwrite=False 用于首次初始化：若目标已存在（包括另一进程刚创建的
    目标），绝不覆盖它。Windows 的 rename 不覆盖目标，其他平台用硬链接
    原子发布同目录临时文件。保存异常原样向上传播；不使用固定临时文件名。
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary_path = Path(temporary_name)
    try:
        try:
            stream = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
        except BaseException:
            os.close(fd)
            raise
        with stream:
            json.dump(data, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

        if overwrite:
            os.replace(temporary_path, path)
        else:
            try:
                if os.name == "nt":
                    os.rename(temporary_path, path)
                else:
                    os.link(temporary_path, path)
            except FileExistsError:
                return False
        return True
    finally:
        # 只清理本次 mkstemp 创建的文件，绝不删除目标或其他进程的临时文件。
        try:
            temporary_path.unlink()
        except OSError:
            # 不让清理失败掩盖真正的保存异常；replace 成功时文件也已不存在。
            pass
