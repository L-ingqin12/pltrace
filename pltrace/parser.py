"""ftrace 文本格式解析器

支持 HarmonyOS bytrace 输出的 ftrace 格式，逐行流式解析，
不一次性加载整个文件。兼容多种 bytrace 输出变体。
"""

import re
import gzip
from dataclasses import dataclass, field
from typing import Iterator, Optional


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


# ---- ftrace 行正则 ----
# 格式:  <comm>-<pid>  [<cpu>] <flags> <timestamp>: <event>: <data>
# 例:    my_thread-12345 [002] d..2.  456.789012: sched_switch: prev_comm=...

FTRACE_LINE_RE = re.compile(
    r"^\s*"                                         # 前导空白
    r"(?P<task_pid>.+?)\s+"                           # 任务-PID（含可能的空格）
    r"\[(?P<cpu>\d+)\]\s+"                            # CPU 号
    r"(?P<flags>[a-zA-Z0-9_\.\+#]+)\s+"               # 标志位
    r"(?P<timestamp>[\d]+\.[\d]+):\s+"                # 时间戳
    r"(?P<event>[a-zA-Z0-9_]+):\s*"                   # 事件名
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


def iter_events(filepath: str, event_filter: Optional[set] = None) -> Iterator[TraceEvent]:
    """流式读取 trace 文件，逐行返回 TraceEvent

    Args:
        filepath: trace 文件路径，支持 .gz 压缩
        event_filter: 如果指定，只返回事件名在此集合内的记录
    """
    opener = gzip.open if filepath.endswith(".gz") else open

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
                yield ev

        # 处理最后一行
        if buf.strip():
            ev = parse_line(buf)
            if ev and (not event_filter or ev.event_name in event_filter):
                yield ev


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
