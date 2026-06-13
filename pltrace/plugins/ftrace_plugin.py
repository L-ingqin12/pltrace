"""ftrace 文本格式插件

内置插件，支持 bytrace / hitrace --text 产出的标准 ftrace 文本格式。
这是 pltrace 的默认解析格式。
"""

import gzip
import os
from typing import Iterator, Optional

from .base import BaseFormatPlugin

# 复用 parser.py 中的解析逻辑
from ..parser import TraceEvent, parse_line


class FtracePlugin(BaseFormatPlugin):
    """ftrace 文本格式解析插件"""

    name = "ftrace"
    extensions = {".ftrace", ".hitrace", ".txt", ".log"}
    description = "bytrace / hitrace --text 文本 trace 格式"
    priority = 100  # 最高优先级

    @classmethod
    def can_handle(cls, filepath: str) -> bool:
        """检测文件是否为 ftrace 文本格式"""
        # 检查扩展名
        ext = os.path.splitext(filepath)[-1]
        if filepath.endswith(".gz"):
            ext = os.path.splitext(filepath[:-3])[-1] + ".gz"
        if ext in cls.extensions or ext in {".ftrace.gz", ".hitrace.gz", ".txt.gz", ".log.gz"}:
            return True

        # 内容检测：读取前几字节
        try:
            opener = gzip.open if filepath.endswith(".gz") else open
            with opener(filepath, "rb") as f:
                head = f.read(200)
            # ftrace 文本以空白、# 或线程名开头
            if head and (head[0:1] in (b" ", b"\t", b"#") or
                         (head[0:1].isascii() and head[0:1].isalpha())):
                return True
        except (IOError, OSError):
            pass
        return False

    @classmethod
    def iter_events(cls, filepath: str, event_filter: Optional[set] = None) -> Iterator[TraceEvent]:
        """流式解析 ftrace 文本文件"""
        opener = gzip.open if filepath.endswith(".gz") else open
        filtered_count = 0
        total_parsed = 0

        with opener(filepath, "rt", encoding="utf-8", errors="replace") as f:
            buf = ""
            while True:
                chunk = f.read(16 * 1024 * 1024)
                if not chunk:
                    break
                buf += chunk
                lines = buf.split("\n")
                buf = lines.pop()
                for line in lines:
                    ev = parse_line(line)
                    if ev is None:
                        continue
                    total_parsed += 1
                    if event_filter and ev.event_name not in event_filter:
                        continue
                    filtered_count += 1
                    yield ev

            if buf.strip():
                ev = parse_line(buf)
                if ev is not None:
                    total_parsed += 1
                    if not event_filter or ev.event_name in event_filter:
                        filtered_count += 1
                        yield ev

        if total_parsed == 0:
            raise ValueError(
                f"未能从文件中解析到任何 ftrace 事件: {filepath}\n"
                f"请确认文件是 bytrace/hitrace --text 输出的文本格式。"
            )
        if filtered_count == 0 and event_filter:
            # 所有事件被过滤掉（不是解析错误，是过滤条件太严格）
            pass

    @classmethod
    def scan_info(cls, filepath: str) -> dict:
        """扫描 ftrace 文件元信息"""
        from ..parser import scan_events
        return scan_events(filepath)
