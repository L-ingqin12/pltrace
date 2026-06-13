"""ftrace / hitrace 文本格式解析器

支持 HarmonyOS bytrace / hitrace 输出的 ftrace 文本格式，
逐行流式解析，不一次性加载整个文件。

兼容:
  - .ftrace     bytrace 文本输出
  - .hitrace    hitrace 文本输出 (--text 模式)
  - .ftrace.gz  压缩格式
  - .hitrace.gz 压缩格式
"""

import re
import gzip
import os
from dataclasses import dataclass, field
from typing import Iterator, Optional

# 支持的文件扩展名
SUPPORTED_EXTENSIONS = {".ftrace", ".hitrace", ".ftrace.gz", ".hitrace.gz", ".sys", ".htrace"}

# 二进制 hitrace 文件的魔数（protobuf 或 SysTace 头部）
BINARY_SIGNATURES = [
    b"\x0a",  # protobuf field 1 varint
    b"\x0a\x08",  # 常见 trace packet 开头
]


@dataclass
class TraceEvent:
    """单条 trace 事件"""
    timestamp: float          # 秒（保留原始精度）
    cpu: int                  # CPU 核心号
    pid: int                  # 进程 ID (tgid)
    tid: int                  # 线程 ID
    comm: str                 # 线程名
    flags: str                # 内核标志位 (d..2. 等)
    event_name: str           # 事件名 (sched_switch, block_rq_issue 等)
    event_data: dict = field(default_factory=dict)  # 事件参数字典
    raw_line: str = ""        # 原始行（调试用）

    @property
    def timestamp_us(self) -> float:
        return self.timestamp * 1_000_000

    def state_label(self) -> str:
        """从 sched_switch 事件中提取线程状态标签"""
        prev_state = self.event_data.get("prev_state")
        if prev_state is None:
            return "?"
        # 按 Linux 状态解释
        try:
            st = int(prev_state)
            if st == 0: return "R"       # TASK_RUNNING
            if st & 0x0001: return "S"   # TASK_INTERRUPTIBLE (1)
            if st & 0x0002: return "D"   # TASK_UNINTERRUPTIBLE (2)
            if st & 0x0004: return "T"   # TASK_STOPPED / traced
            if st & 0x0008: return "t"   # traced
            if st & 0x0080: return "x"   # EXIT_DEAD
            if st & 0x0402: return "D"   # TASK_KILLABLE | TASK_UNINTERRUPTIBLE
            if st & 0x0800: return "I"   # TASK_NEW (idle)
            return f"unk({st:#x})"
        except (ValueError, TypeError):
            return str(prev_state)

    def is_sched_switch(self) -> bool:
        return self.event_name == "sched_switch"

    def is_block_event(self) -> bool:
        return self.event_name.startswith("block_") or self.event_name.startswith("block:")

    def is_cpu_freq(self) -> bool:
        return self.event_name in ("cpu_frequency", "cpu_frequency_limits")

    def is_irq(self) -> bool:
        return self.event_name.startswith("irq_") or self.event_name.startswith("softirq_")

    def is_binder(self) -> bool:
        return self.event_name.startswith("binder_")


# ---- ftrace / hitrace 行正则 ----
# 格式:  <comm>-<pid>  [<cpu>] <flags> <timestamp>: <event>: <data>
# 例:    my_thread-12345 [002] d..2.  456.789012: sched_switch: prev_comm=...
# HiTrace 事件可能含 : 或 |，如 H:HITRACE_BEGIN, B:|my_span

FTRACE_LINE_RE = re.compile(
    r"^\s*"                                           # 前导空白
    r"(?P<task_pid>.+?)\s+"                           # 任务-PID
    r"\[(?P<cpu>\d+)\]\s+"                            # CPU 号
    r"(?P<flags>[a-zA-Z0-9_\.\+#]+)\s+"               # 标志位
    r"(?P<timestamp>[\d]+\.[\d]+):\s+"                # 时间戳
    r"(?P<event>[a-zA-Z0-9_:|]+?):\s*"                # 事件名（支持 HiTrace 前缀）
    r"(?P<data>.*?)$"                                  # 事件数据（到行尾）
)

# 解析 task-pid: "thread_name-12345" 或 "thread_name-12345 (more)"
TASK_PID_RE = re.compile(r"^(.+)-(\d+)$")

# 事件数据 key=value 分隔（处理字符串值含空格的情况）
KV_RE = re.compile(r'(\w+)=("[^"]*"|\'[^\']*\'|\S+)')


def parse_event_data(data_str: str) -> dict:
    """将 ftrace 事件数据字符串解析为字典"""
    result = {}
    for m in KV_RE.finditer(data_str):
        key = m.group(1)
        val = m.group(2).strip("'\"")
        # 尝试转为数值
        try:
            if "." in val:
                val = float(val)
            else:
                val = int(val)
        except (ValueError, AttributeError):
            pass
        result[key] = val
    return result


def parse_line(line: str) -> Optional[TraceEvent]:
    """解析一行 ftrace 文本，失败返回 None"""
    line = line.rstrip("\n\r")
    if not line or line.startswith("#"):
        return None

    m = FTRACE_LINE_RE.match(line)
    if not m:
        return None

    # 解析 task-pid
    task_pid = m.group("task_pid").strip()
    comm, pid = "", 0
    tm = TASK_PID_RE.match(task_pid)
    if tm:
        comm = tm.group(1).strip()
        pid = int(tm.group(2))
    else:
        comm = task_pid

    # tid 从 event data 里提取（如果有），否则用 pid
    tid = pid

    # 解析 event data
    data_str = m.group("data")
    event_data = parse_event_data(data_str)

    # 对于部分事件，tid 在 next_pid / prev_pid / pid 字段中
    # 这里保留 pid 作为主键，实际区分 tgid/tid 在后续处理中完成
    if "pid" in event_data and isinstance(event_data["pid"], int):
        tid = event_data["pid"]

    return TraceEvent(
        timestamp=float(m.group("timestamp")),
        cpu=int(m.group("cpu")),
        pid=pid,
        tid=tid,
        comm=comm,
        flags=m.group("flags"),
        event_name=m.group("event"),
        event_data=event_data,
        raw_line=line,
    )


def _detect_format(filepath: str) -> str:
    """检测 trace 文件格式：'text' (ftrace) 或 'binary' (protobuf/SysTace)"""
    opener = gzip.open if filepath.endswith(".gz") else open
    with opener(filepath, "rb") as f:
        head = f.read(4)
    # 文本格式以空白或 # 开头
    if head and (head[0:1] in (b" ", b"\t", b"#") or head[0:1].isascii() and head[0:1].isalpha()):
        return "text"
    # 二进制格式检测（protobuf 开头）
    for sig in BINARY_SIGNATURES:
        if head.startswith(sig):
            return "binary"
    # 默认尝试按文本处理
    return "text"


def _raise_sys_guidance(filepath: str):
    """针对 .sys/.htrace 文件给出转换指导"""
    from .sys_parser import detect_trace_streamer

    ts_path = detect_trace_streamer()
    file_size_mb = os.path.getsize(filepath) / (1024 * 1024)

    guidance = [
        f"检测到二进制 HiProfiler trace 文件: {filepath}",
        f"文件大小: {file_size_mb:.1f} MB",
        f"",
    ]

    if ts_path:
        guidance.append(f"✅ 检测到 trace_streamer: {ts_path}")
        guidance.append(f"   请使用以下命令转换：")
        guidance.append(f"   trace_streamer {filepath} -e output.db")
        guidance.append(f"   然后运行: pltrace analyze output.db")
        guidance.append(f"")
        guidance.append(f"   或直接运行: pltrace comprehensive {filepath}")
        guidance.append(f"   (pltrace 将自动调用 trace_streamer 转换)")
    else:
        guidance.append(f"❌ 未检测到 trace_streamer")
        guidance.append(f"   请安装 trace_streamer:")
        guidance.append(f"   1. 下载: https://gitee.com/openharmony/developtools_smartperf_host/releases")
        guidance.append(f"   2. 解压: unzip trace_streamer_binary.zip")
        guidance.append(f"   3. 运行: ./trace_streamer {filepath} -e output.db")
        guidance.append(f"")
        guidance.append(f"   替代方案: 使用 bytrace 重新抓取文本格式 trace:")
        guidance.append(f"   hdc shell \"bytrace -t 10 -b 16384 sched freq block disk > /data/local/tmp/trace.ftrace\"")
        guidance.append(f"   hdc file recv /data/local/tmp/trace.ftrace .")

    raise ValueError("\n".join(guidance))


def _iter_from_sys(filepath: str, event_filter: Optional[set] = None) -> Iterator[TraceEvent]:
    """从 .sys 二进制文件提取事件 - 自动调用 trace_streamer 转换"""
    from .sys_parser import detect_trace_streamer, convert_sys_to_db, parse_sys_db

    ts_path = detect_trace_streamer()
    if not ts_path:
        _raise_sys_guidance(filepath)
        return  # unreachable due to raise

    import sys as _sys
    print(f"[pltrace] 检测到二进制 .sys 文件，使用 trace_streamer 自动转换...", file=_sys.stderr)
    print(f"[pltrace] trace_streamer: {ts_path}", file=_sys.stderr)

    import tempfile
    db_path = tempfile.mktemp(suffix=".db", prefix="pltrace_")
    try:
        db_path = convert_sys_to_db(filepath, output_db=db_path, trace_streamer_bin=ts_path)
        print(f"[pltrace] 转换完成: {db_path}", file=_sys.stderr)

        event_count = 0
        for ev in parse_sys_db(db_path):
            if event_filter and ev.event_name not in event_filter:
                continue
            event_count += 1
            yield ev

        print(f"[pltrace] 从 SQLite 提取了 {event_count} 个事件", file=_sys.stderr)
    finally:
        # 清理临时数据库
        try:
            if os.path.exists(db_path):
                os.unlink(db_path)
        except OSError:
            pass


def iter_events(filepath: str, event_filter: Optional[set] = None) -> Iterator[TraceEvent]:
    """流式读取 trace 文件，逐行返回 TraceEvent

    支持格式:
      - .ftrace / .hitrace           文本格式
      - .ftrace.gz / .hitrace.gz       gzip 压缩
      - 自动检测文本/二进制，二进制会抛出 ValueError

    Args:
        filepath: trace 文件路径
        event_filter: 如果指定，只返回事件名在此集合内的记录

    Raises:
        ValueError: 检测到二进制格式（需要使用 hitrace --text 转换）
        FileNotFoundError: 文件不存在
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"文件不存在: {filepath}")

    ext = os.path.splitext(filepath)[-1] if filepath.endswith(".gz") else os.path.splitext(filepath)[-1]
    # 对 .gz 取双扩展名
    if filepath.endswith(".gz"):
        base = filepath[:-3]
        ext = os.path.splitext(base)[-1] + ".gz"

    if ext not in SUPPORTED_EXTENSIONS:
        # 不做严格校验，允许用户传入任何扩展名（可能是符号链接等）
        pass

    is_sys = ext in {".sys", ".htrace"} or filepath.endswith(".sys") or filepath.endswith(".htrace")

    fmt = _detect_format(filepath)
    if fmt == "binary":
        if is_sys:
            # 尝试自动转换 .sys 文件
            yield from _iter_from_sys(filepath, event_filter)
            return
        else:
            raise ValueError(
                f"检测到二进制格式 trace 文件: {filepath}\n"
                f"二进制 .hitrace 文件不支持直接解析。请用以下命令转换为文本格式：\n"
                f"  hitrace --text -o output.ftrace --trace_file {filepath}\n"
                f"  或重新抓取: bytrace -t 10 -b 16384 sched freq block disk > trace.ftrace"
            )

    opener = gzip.open if filepath.endswith(".gz") else open
    line_count = 0
    with opener(filepath, "rt", encoding="utf-8", errors="replace") as f:
        buf = ""
        while True:
            chunk = f.read(16 * 1024 * 1024)
            if not chunk:
                break
            buf += chunk
            lines = buf.split("\n")
            buf = lines.pop()  # 最后一个不完整行保留
            for line in lines:
                ev = parse_line(line)
                if ev is None:
                    continue
                if event_filter and ev.event_name not in event_filter:
                    continue
                line_count += 1
                yield ev

        # 处理最后一行
        if buf.strip():
            ev = parse_line(buf)
            if ev and (not event_filter or ev.event_name in event_filter):
                line_count += 1
                yield ev

    if line_count == 0:
        raise ValueError(
            f"未能从文件中解析到任何 trace 事件: {filepath}\n"
            f"请确认文件是 bytrace/hitrace --text 输出的文本格式。"
        )


def scan_events(filepath: str) -> dict:
    """快速扫描 trace 文件，返回元信息（事件类型、时间范围等）"""
    info = {
        "path": filepath,
        "event_types": set(),
        "min_ts": float("inf"),
        "max_ts": 0.0,
        "total_events": 0,
        "pids": set(),
        "comms": set(),
        "cpus": set(),
    }
    for ev in iter_events(filepath):
        info["event_types"].add(ev.event_name)
        info["min_ts"] = min(info["min_ts"], ev.timestamp)
        info["max_ts"] = max(info["max_ts"], ev.timestamp)
        info["total_events"] += 1
        info["pids"].add(ev.pid)
        info["comms"].add(ev.comm)
        info["cpus"].add(ev.cpu)
        if info["total_events"] >= 5_000_000:
            break  # 扫描上限，避免对大文件耗时太久
    return info
