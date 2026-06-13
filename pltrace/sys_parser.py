""".sys / .htrace 二进制 trace 解析器

HarmonyOS HiProfiler 产出的二进制 trace 文件（.sys / .htrace）基于 protobuf 格式。
通过调用 OpenHarmony trace_streamer 工具将其转换为 SQLite 数据库，
然后从中提取调度、I/O 等事件进行分析。

工作流程:
  1. 检测 trace_streamer 是否可用
  2. 自动调用 trace_streamer 将 .sys 转为 .db
  3. 从 SQLite 中提取关键事件表
  4. 转换为 pltrace 内部格式继续分析
"""

import os
import sys
import sqlite3
import subprocess
import tempfile
import shutil
from dataclasses import dataclass, field
from typing import Optional, Iterator

from .parser import TraceEvent

# trace_streamer 可能的安装路径
TRACE_STREAMER_PATHS = [
    "trace_streamer",
    "./trace_streamer",
    "/usr/local/bin/trace_streamer",
    os.path.expanduser("~/smartperf/trace_streamer"),
]


@dataclass
class SysFileInfo:
    """.sys 文件元信息"""
    path: str
    file_size_mb: float
    trace_streamer_available: bool
    trace_streamer_path: str = ""
    conversion_db_path: str = ""


def detect_trace_streamer() -> Optional[str]:
    """检测系统上是否安装了 trace_streamer"""
    for path in TRACE_STREAMER_PATHS:
        if shutil.which(path) or (os.path.exists(path) and os.access(path, os.X_OK)):
            return path
    return None


def inspect_sys_file(filepath: str) -> SysFileInfo:
    """检查 .sys 文件并返回信息"""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"文件不存在: {filepath}")

    file_size = os.path.getsize(filepath)
    ts_path = detect_trace_streamer()

    return SysFileInfo(
        path=filepath,
        file_size_mb=file_size / (1024 * 1024),
        trace_streamer_available=ts_path is not None,
        trace_streamer_path=ts_path or "",
    )


def convert_sys_to_db(sys_path: str, output_db: str = None,
                      trace_streamer_bin: str = None) -> str:
    """使用 trace_streamer 将 .sys 文件转换为 SQLite 数据库

    Args:
        sys_path: .sys 源文件路径
        output_db: 输出数据库路径（默认在当前目录生成临时文件）
        trace_streamer_bin: trace_streamer 可执行文件路径

    Returns:
        生成的 .db 文件路径

    Raises:
        RuntimeError: trace_streamer 不可用或转换失败
    """
    ts_bin = trace_streamer_bin or detect_trace_streamer()
    if not ts_bin:
        raise RuntimeError(
            "未找到 trace_streamer。\n"
            "请从 https://gitee.com/openharmony/developtools_smartperf_host/releases "
            "下载 trace_streamer_binary.zip 并解压。\n"
            "或使用 bytrace 重新抓取文本格式 trace: "
            "hdc shell \"bytrace -t 10 -b 16384 sched freq block disk > /data/local/tmp/trace.ftrace\""
        )

    if output_db is None:
        output_db = tempfile.mktemp(suffix=".db", prefix="pltrace_")

    cmd = [ts_bin, sys_path, "-e", output_db]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 大文件可能需要较长时间
        )
        if result.returncode != 0:
            stderr = result.stderr or "未知错误"
            raise RuntimeError(f"trace_streamer 转换失败 (code={result.returncode}): {stderr}")
    except subprocess.TimeoutExpired:
        raise RuntimeError("trace_streamer 转换超时（>5分钟）。文件可能过大。")
    except FileNotFoundError:
        raise RuntimeError(f"trace_streamer 不可用: {ts_bin}")

    if not os.path.exists(output_db):
        raise RuntimeError(f"trace_streamer 未生成输出文件: {output_db}")

    return output_db


def parse_sys_db(db_path: str) -> Iterator[TraceEvent]:
    """从 trace_streamer 生成的 SQLite 数据库中提取事件

    trace_streamer 生成的主要表:
      - thread_state: 线程状态变化（类似 sched_switch）
      - sched_slice: 调度时间片
      - raw: 原始 ftrace 事件（如果存在）
      - measure: 指标数据
      - app_startup: 应用启动数据
      - process: 进程信息
      - thread: 线程信息

    我们主要从 thread_state 表和 raw 表中提取事件。
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # 优先尝试 raw 表（如果 trace_streamer 保留了原始 ftrace 事件）
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='raw'"
    )
    has_raw = cursor.fetchone() is not None

    if has_raw:
        # raw 表包含原始 ftrace 事件
        try:
            rows = conn.execute(
                "SELECT ts, cpu, itid, name as event_name, args "
                "FROM raw "
                "WHERE name IN ('sched_switch', 'sched_waking', 'sched_wakeup', "
                "'block_rq_issue', 'block_rq_complete', 'cpu_frequency', "
                "'irq_handler_entry', 'irq_handler_exit', "
                "'syscall_exit_openat', 'syscall_exit_openat2', "
                "'syscall_exit_futex', 'binder_transaction') "
                "ORDER BY ts"
            ).fetchall()

            for row in rows:
                yield _raw_row_to_event(row, conn)
        except sqlite3.OperationalError:
            pass  # fall through to thread_state table

    # 如果没有 raw 表，从 thread_state 重建 sched_switch 事件
    try:
        rows = conn.execute(
            "SELECT ts, cpu, tid, state "
            "FROM thread_state "
            "ORDER BY ts"
        ).fetchall()

        for row in rows:
            yield _thread_state_to_event(row)
    except sqlite3.OperationalError:
        pass

    conn.close()


def _raw_row_to_event(row: sqlite3.Row, conn: sqlite3.Connection) -> TraceEvent:
    """将 raw 表行转换为 TraceEvent"""
    ts_ns = row["ts"]
    ts_s = ts_ns / 1_000_000_000.0 if ts_ns else 0.0
    cpu = row["cpu"] or 0
    itid = row["itid"] or 0
    event_name = row["event_name"] or "unknown"

    # 从 args 解析参数
    event_data = {}
    args_str = row["args"] or ""
    if args_str:
        for part in args_str.split():
            if "=" in part:
                k, v = part.split("=", 1)
                try:
                    if "." in v:
                        event_data[k] = float(v)
                    else:
                        event_data[k] = int(v)
                except ValueError:
                    event_data[k] = v.strip("'\"")

    # 从 itid 获取线程信息
    tid = itid
    comm = ""
    try:
        trow = conn.execute(
            "SELECT name FROM thread WHERE id=?", (itid,)
        ).fetchone()
        if trow:
            comm = trow["name"] or ""
    except sqlite3.OperationalError:
        pass

    return TraceEvent(
        timestamp=ts_s,
        cpu=cpu,
        pid=tid,
        tid=tid,
        comm=comm,
        flags="....",
        event_name=event_name,
        event_data=event_data,
        raw_line=f"sys://{event_name}/{ts_ns}",
    )


def _thread_state_to_event(row: sqlite3.Row) -> TraceEvent:
    """将 thread_state 表行转换为 TraceEvent

    thread_state 记录的 state 字段:
      R → 0 (Running)
      S → 1 (Sleeping/Interruptible)
      D → 2 (Uninterruptible/Disk)
      Running → 3 (实际运行中)
    """
    ts_ns = row["ts"]
    ts_s = ts_ns / 1_000_000_000.0 if ts_ns else 0.0
    cpu = row["cpu"] or 0
    tid = row["tid"] or 0
    state = row["state"] or "R"

    # 状态映射
    state_map = {"R": 0, "S": 1, "D": 2, "Running": 0}
    prev_state = state_map.get(state, 0)

    return TraceEvent(
        timestamp=ts_s,
        cpu=cpu,
        pid=tid,
        tid=tid,
        comm="",
        flags="....",
        event_name="sched_switch",
        event_data={"prev_pid": tid, "prev_state": prev_state,
                     "next_pid": 0, "next_comm": ""},
        raw_line=f"sys://thread_state/{ts_ns}",
    )


def list_db_tables(db_path: str) -> list[str]:
    """列出数据库中的所有表"""
    conn = sqlite3.connect(db_path)
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = [row[0] for row in cursor.fetchall()]
    conn.close()
    return tables


def get_db_stats(db_path: str) -> dict:
    """获取数据库统计信息"""
    conn = sqlite3.connect(db_path)
    stats = {}

    # 读取 stat 表
    try:
        rows = conn.execute("SELECT name, count FROM stat ORDER BY count DESC").fetchall()
        stats["events"] = {row["name"]: row["count"] for row in rows}
    except sqlite3.OperationalError:
        stats["events"] = {}

    # 进程/线程数
    for table in ["process", "thread"]:
        try:
            cnt = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            stats[f"{table}_count"] = cnt
        except sqlite3.OperationalError:
            pass

    conn.close()
    return stats
