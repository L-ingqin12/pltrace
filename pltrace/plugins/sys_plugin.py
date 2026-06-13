""".sys / .htrace 二进制格式插件

HiProfiler 产出的 protobuf 二进制 trace 文件解析插件。
依赖 trace_streamer 工具进行格式转换。

安装 trace_streamer:
  1. 下载: https://gitee.com/openharmony/developtools_smartperf_host/releases
  2. 解压: unzip trace_streamer_binary.zip
  3. 将 trace_streamer 放入 PATH 或 pltrace 目录

如果没有 trace_streamer，插件会给出明确的安装指引。
"""

import os
import sys
import tempfile
from typing import Iterator, Optional

from .base import BaseFormatPlugin
from ..parser import TraceEvent


class SysPlugin(BaseFormatPlugin):
    """HiProfiler .sys / .htrace 二进制格式解析插件"""

    name = "sys"
    extensions = {".sys", ".htrace"}
    description = "HiProfiler 二进制 trace（需 trace_streamer 转换）"
    priority = 75
    dependencies = ["trace_streamer"]

    @classmethod
    def can_handle(cls, filepath: str) -> bool:
        """检测 .sys 二进制文件"""
        ext = os.path.splitext(filepath)[-1]
        if ext in cls.extensions:
            return True
        # 内容检测：protobuf 魔数
        try:
            with open(filepath, "rb") as f:
                head = f.read(16)
            # protobuf varint 开头: 0x0a 或 0x08 等
            if head and head[0] in (0x08, 0x0a, 0x12):
                # 排除文本文件（文本不会以这些字节开头）
                if not (head[0:1].isascii() and head[0:1].isalpha()):
                    return True
        except (IOError, OSError):
            pass
        return False

    @classmethod
    def iter_events(cls, filepath: str, event_filter: Optional[set] = None) -> Iterator[TraceEvent]:
        """解析 .sys 文件：自动调用 trace_streamer 转换后提取事件"""
        if not cls.is_available():
            ok, msg = cls.check_dependencies()
            raise RuntimeError(
                f"SysPlugin 不可用: {msg}\n\n"
                f"请安装 trace_streamer 工具:\n"
                f"  1. 下载: https://gitee.com/openharmony/developtools_smartperf_host/releases\n"
                f"  2. 解压: unzip trace_streamer_binary.zip\n"
                f"  3. 将 trace_streamer 添加到 PATH\n\n"
                f"替代方案: 使用 bytrace 重新抓取文本格式 trace:\n"
                f"  hdc shell \"bytrace -t 10 -b 16384 sched freq block disk > /data/local/tmp/trace.ftrace\""
            )

        from ..sys_parser import convert_sys_to_db, parse_sys_db
        import shutil

        ts_bin = shutil.which("trace_streamer") or "trace_streamer"
        print(f"[pltrace:sys] 使用 trace_streamer 转换二进制文件...", file=sys.stderr)
        print(f"[pltrace:sys] trace_streamer: {ts_bin}", file=sys.stderr)
        print(f"[pltrace:sys] 源文件: {filepath}", file=sys.stderr)

        db_path = tempfile.mktemp(suffix=".db", prefix="pltrace_sys_")
        try:
            db_path = convert_sys_to_db(filepath, output_db=db_path, trace_streamer_bin=ts_bin)
            print(f"[pltrace:sys] 转换完成 → {db_path}", file=sys.stderr)

            count = 0
            for ev in parse_sys_db(db_path):
                if event_filter and ev.event_name not in event_filter:
                    continue
                count += 1
                yield ev
            print(f"[pltrace:sys] 提取 {count} 个事件", file=sys.stderr)
        finally:
            try:
                if os.path.exists(db_path):
                    os.unlink(db_path)
            except OSError:
                pass

    @classmethod
    def scan_info(cls, filepath: str) -> dict:
        """获取 .sys 文件基本信息"""
        file_size_mb = os.path.getsize(filepath) / (1024 * 1024) if os.path.exists(filepath) else 0
        ok, msg = cls.check_dependencies()
        return {
            "plugin": cls.name,
            "file": filepath,
            "format": cls.description,
            "file_size_mb": round(file_size_mb, 2),
            "trace_streamer_available": ok,
            "dependency_status": msg or "OK",
        }

    @classmethod
    def get_guidance(cls, filepath: str) -> str:
        """获取 .sys 文件的处理指导"""
        ok, msg = cls.check_dependencies()
        file_size_mb = os.path.getsize(filepath) / (1024 * 1024) if os.path.exists(filepath) else 0

        lines = [
            f"",
            f"╔════════════════════════════════════════════════╗",
            f"║  HiProfiler 二进制 trace (.sys/.htrace)       ║",
            f"╠════════════════════════════════════════════════╣",
            f"║  文件: {os.path.basename(filepath):<40}║",
            f"║  大小: {file_size_mb:.1f} MB{'':>36}║",
            f"╠════════════════════════════════════════════════╣",
        ]

        if ok:
            lines.extend([
                f"║  ✅ trace_streamer 已安装                     ║",
                f"║  pltrace 将自动转换并分析                     ║",
                f"╚════════════════════════════════════════════════╝",
            ])
        else:
            lines.extend([
                f"║  ❌ 未检测到 trace_streamer                    ║",
                f"║                                                ║",
                f"║  安装方法:                                     ║",
                f"║  1. 下载 trace_streamer 二进制包              ║",
                f"║     https://gitee.com/openharmony/             ║",
                f"║     developtools_smartperf_host/releases       ║",
                f"║  2. 解压: unzip trace_streamer_binary.zip      ║",
                f"║  3. 添加到 PATH                                ║",
                f"║                                                ║",
                f"║  替代方案: 使用 bytrace 文本格式              ║",
                f"║  hdc shell \"bytrace -t 10 -b 16384 \\         ║",
                f"║    sched freq block disk > trace.ftrace\"       ║",
                f"╚════════════════════════════════════════════════╝",
            ])

        return "\n".join(lines)
