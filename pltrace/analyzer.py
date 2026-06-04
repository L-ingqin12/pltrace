"""trace 间隙分析引擎

分析 dlopen 之间的空白期：线程调度状态、I/O 事件、CPU 抢占、频率变化。
"""

from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

from .parser import iter_events


@dataclass
class ThreadSlice:
    """线程在某个时间段内的状态摘要"""
    start_us: float
    end_us: float
    duration_us: float

    # 状态统计 (微秒)
    state_running_us: float = 0.0      # R - 在 CPU 上运行
    state_runnable_us: float = 0.0     # R+ - 等待调度
    state_sleeping_us: float = 0.0     # S - 可中断等待 (I/O、锁)
    state_disk_wait_us: float = 0.0    # D - 不可中断 I/O
    state_other_us: float = 0.0        # 其他状态

    # 调度事件
    sched_switches: int = 0            # 上下文切换次数
    preemptions: int = 0               # 被抢占次数
    preempting_threads: list = field(default_factory=list)  # 抢占者线程名

    # I/O 事件
    io_events: list = field(default_factory=list)   # block 事件列表
    io_wait_us: float = 0.0           # 累计 I/O 等待时间

    # CPU 频率
    avg_cpu_freq_mhz: float = 0.0
    min_cpu_freq_mhz: float = 0.0
    max_cpu_freq_mhz: float = 0.0
    freq_samples: int = 0

    # 中断
    irq_count: int = 0

    # 判定结论
    conclusion: str = ""
    conclusion_detail: str = ""


@dataclass
class GapAnalysis:
    """两个 dlopen 之间的完整分析"""
    gap_id: int
    start_us: float
    end_us: float
    total_duration_us: float

    # 目标线程
    target_pid: int
    target_comm: str

    # 线程级别分析
    thread_slice: Optional[ThreadSlice] = None

    # 整个间隙内发生的 I/O 概况
    total_io_events: int = 0
    io_breakdown: dict = field(default_factory=dict)  # event_type -> count
    total_io_wait_us: float = 0.0

    # context
    dlopen_before_ts: float = 0.0
    dlopen_after_ts: float = 0.0

    # 最终判定
    dominant_factor: str = ""       # "IO", "CPU_PREEMPT", "CPU_FREQ", "SELF_WORK", "MIXED"
    confidence: str = ""            # "HIGH", "MEDIUM", "LOW"
    conclusion_detail: str = ""     # 判定依据说明


@dataclass
class TraceGapFindResult:
    """定位到的 gap 位置的简要描述"""
    gap_id: int
    before_ts: float     # 第一个 dlopen 的时间
    after_ts: float      # 第二个 dlopen 的时间
    duration_ms: float
    thread: str
    pid: int
    cpu: int


# ---- 事件名列表 ----
SYSCALL_EXIT_EVENTS = {
    "syscall_exit_openat", "syscall_exit_openat2",
    "sys_exit_openat", "sys_exit_openat2",
    "syscall_exit_open", "sys_exit_open",
}

SCHED_SWITCH = "sched_switch"
CPU_FREQ = "cpu_frequency"
BLOCK_EVENTS = {
    "block_bio_queue", "block_bio_backmerge", "block_bio_bounce",
    "block_bio_complete", "block_bio_frontmerge", "block_bio_remap",
    "block_dirty_buffer", "block_getrq", "block_plug",
    "block_rq_complete", "block_rq_issue", "block_rq_remap",
    "block_split", "block_touch_buffer", "block_unplug",
}

# 线程状态常量
TASK_RUNNING = 0x0000
TASK_INTERRUPTIBLE = 0x0001
TASK_UNINTERRUPTIBLE = 0x0002


def find_gaps(
    trace_path: str,
    marker_events: Optional[set] = None,
    target_comm: Optional[str] = None,
    target_pid: Optional[int] = None,
) -> list:
    """扫描 trace，找到两个 marker 之间的间隙

    默认以 `sys_exit_openat` 系列事件作为 marker（dlopen 最后会调用 openat）。
    也可指定其他 marker。

    返回 (gap_id, 线程信息, before_ts, after_ts) 列表。
    """
    if marker_events is None:
        marker_events = SYSCALL_EXIT_EVENTS

    # 收集所有 marker 事件
    markers = []
    for ev in iter_events(trace_path, event_filter=marker_events):
        if target_comm and ev.comm != target_comm:
            continue
        if target_pid and ev.pid != target_pid:
            continue
        markers.append(ev)

    if len(markers) < 2:
        return []

    markers.sort(key=lambda e: e.timestamp)

    # 合并太近的 marker（<5ms 视为同一次调用）
    merged = [markers[0]]
    for m in markers[1:]:
        if (m.timestamp - merged[-1].timestamp) < 0.005:
            # 同一次调用中的多个 openat，保留最新的
            if m.timestamp > merged[-1].timestamp:
                merged[-1] = m
        else:
            merged.append(m)

    gaps = []
    for i in range(1, len(merged)):
        before = merged[i - 1]
        after = merged[i]
        gaps.append(TraceGapFindResult(
            gap_id=i,
            before_ts=before.timestamp,
            after_ts=after.timestamp,
            duration_ms=(after.timestamp - before.timestamp) * 1000,
            thread=before.comm,
            pid=before.pid,
            cpu=before.cpu,
        ))

    return gaps


def analyze_gap(
    trace_path: str,
    gap: TraceGapFindResult,
) -> GapAnalysis:
    """分析一个 gap，返回详细的 GapAnalysis。

    遍历 gap 内的 sched_switch、block I/O、cpu_frequency 事件，
    统计目标线程的调度状态分布，判定耗时主导因素。
    """
    analysis = GapAnalysis(
        gap_id=gap.gap_id,
        start_us=gap.before_ts * 1_000_000,
        end_us=gap.after_ts * 1_000_000,
        total_duration_us=gap.duration_ms * 1000,
        target_pid=gap.pid,
        target_comm=gap.thread,
        dlopen_before_ts=gap.before_ts,
        dlopen_after_ts=gap.after_ts,
    )

    start_us = analysis.start_us
    end_us = analysis.end_us
    target_pid = analysis.target_pid

    # 需要的事件类型：调度、I/O、频率、中断
    interest = {SCHED_SWITCH} | BLOCK_EVENTS | {CPU_FREQ}

    # 收集数据
    state_segments: list[tuple[float, float, str]] = []  # (start_us, end_us, state_label)
    io_log: list[dict] = []
    freq_log: list[tuple[float, float]] = []    # (ts_us, freq_mhz)
    irq_count = 0
    sched_count = 0
    preempt_count = 0
    preempters: list[str] = []

    # 状态机：追踪目标线程的当前状态及其起始时间
    current_state = "Running"  # gap 开始时线程在 CPU 上
    state_since = start_us

    def _close_state(ts: float):
        """结束当前状态段，记录到 segments 中"""
        nonlocal current_state, state_since
        dur = ts - state_since
        if dur > 0:
            state_segments.append((state_since, ts, current_state))
        state_since = ts

    def _start_state(ts: float, new_state: str):
        nonlocal current_state, state_since
        current_state = new_state
        state_since = ts

    # 遍历相关事件
    for ev in iter_events(trace_path, event_filter=interest):
        ts_us = ev.timestamp * 1_000_000
        if ts_us < start_us - 1000:  # 留 1ms 容错用于状态追踪
            continue
        if ts_us > end_us + 1000:
            break

        # 针对目标线程的 sched_switch
        if ev.event_name == SCHED_SWITCH:
            prev_pid = ev.event_data.get("prev_pid")
            next_pid = ev.event_data.get("next_pid")

            # 目标线程被切出（prev）
            if prev_pid == target_pid:
                sched_count += 1

                # 结束 Running 状态
                _close_state(ts_us)

                prev_state_raw = ev.event_data.get("prev_state", 0)
                try:
                    prev_state = int(prev_state_raw)
                except (ValueError, TypeError):
                    prev_state = 0

                # 根据切出原因进入新状态
                if prev_state == 0:
                    _start_state(ts_us, "R")  # 非自愿切出 → Runnable（被抢占）
                elif prev_state & TASK_UNINTERRUPTIBLE:
                    _start_state(ts_us, "D")  # 不可中断 → 磁盘 I/O
                elif prev_state & TASK_INTERRUPTIBLE:
                    _start_state(ts_us, "S")  # 可中断等待
                else:
                    _start_state(ts_us, f"X({prev_state:#x})")

                # 抢占判定：非自愿切出且下一个不是自己
                if prev_state == 0 and next_pid != target_pid:
                    preempt_count += 1
                    preempters.append(ev.event_data.get("next_comm", f"pid_{next_pid}"))

            # 目标线程被切入（next）
            if next_pid == target_pid:
                # 结束等待状态，进入 Running
                _close_state(ts_us)
                _start_state(ts_us, "Running")

        # block I/O 事件
        if ev.event_name in BLOCK_EVENTS:
            if ts_us < start_us or ts_us > end_us:
                continue
            io_log.append({
                "ts_us": ts_us,
                "event": ev.event_name,
                "cpu": ev.cpu,
                "data": dict(ev.event_data),
            })

        # CPU 频率
        if ev.event_name == CPU_FREQ:
            if ts_us < start_us or ts_us > end_us:
                continue
            freq_vals = [v for _k, v in ev.event_data.items()
                        if isinstance(v, (int, float)) and v > 0]
            if freq_vals:
                raw_hz = max(freq_vals)
                # 按数量级推断单位：>100000 是 Hz，否则是 kHz
                freq_mhz = raw_hz / 1_000_000 if raw_hz > 100000 else raw_hz / 1000
                freq_log.append((ts_us, freq_mhz))

        # 中断
        if ev.is_irq():
            if ts_us < start_us or ts_us > end_us:
                continue
            irq_count += 1

    # 关闭 gap 结束时仍在进行的状态
    _close_state(end_us)

    # 计算状态统计
    state_dur = {"Running": 0.0, "R": 0.0, "S": 0.0, "D": 0.0, "Other": 0.0}
    for seg_start, seg_end, label in state_segments:
        dur = seg_end - seg_start
        dur = max(0, min(dur, end_us - start_us))
        if label in state_dur:
            state_dur[label] += dur
        else:
            state_dur["Other"] += dur

    # 计算 I/O 等待：看 block_rq_issue → block_rq_complete 的时间
    io_issues = {}
    io_wait_total = 0.0
    for entry in io_log:
        if entry["event"] in ("block_rq_issue", "block:rq_issue"):
            dev = entry["data"].get("dev", "")
            sector = entry["data"].get("sector", 0)
            key = (dev, sector)
            io_issues[key] = entry["ts_us"]
        elif entry["event"] in ("block_rq_complete", "block:rq_complete"):
            dev = entry["data"].get("dev", "")
            sector = entry["data"].get("sector", 0)
            key = (dev, sector)
            if key in io_issues:
                io_wait_total += entry["ts_us"] - io_issues.pop(key)

    # 构建 ThreadSlice
    tslice = ThreadSlice(
        start_us=start_us,
        end_us=end_us,
        duration_us=end_us - start_us,
        state_running_us=state_dur["Running"],
        state_runnable_us=state_dur["R"],
        state_sleeping_us=state_dur["S"],
        state_disk_wait_us=state_dur["D"],
        state_other_us=state_dur["Other"],
        sched_switches=sched_count,
        preemptions=preempt_count,
        preempting_threads=preempters[:10],
        io_events=[{k: (float(v) if k == "ts_us" else str(v)) for k, v in e.items()} for e in io_log],
        io_wait_us=io_wait_total,
        irq_count=irq_count,
    )

    # CPU 频率统计
    if freq_log:
        freqs = [f[1] for f in freq_log if start_us <= f[0] <= end_us]
        if freqs:
            tslice.avg_cpu_freq_mhz = sum(freqs) / len(freqs)
            tslice.min_cpu_freq_mhz = min(freqs)
            tslice.max_cpu_freq_mhz = max(freqs)
            tslice.freq_samples = len(freqs)

    analysis.thread_slice = tslice
    analysis.total_io_events = len(io_log)
    analysis.total_io_wait_us = io_wait_total

    # 统计 I/O 事件类型
    io_breakdown = defaultdict(int)
    for e in io_log:
        io_breakdown[e["event"]] += 1
    analysis.io_breakdown = dict(io_breakdown)

    # ---- 判定主导因素 ----
    total = analysis.total_duration_us
    if total == 0:
        analysis.dominant_factor = "UNKNOWN"
        analysis.confidence = "LOW"
        return analysis

    disk_pct = tslice.state_disk_wait_us / total * 100
    sleep_pct = tslice.state_sleeping_us / total * 100
    runnable_pct = tslice.state_runnable_us / total * 100
    running_pct = tslice.state_running_us / total * 100

    if disk_pct > 30:
        analysis.dominant_factor = "IO_DISK_WAIT"
        analysis.confidence = "HIGH"
        analysis.conclusion_detail = (
            f"目标线程 {disk_pct:.1f}% 时间处于 D 状态（不可中断 I/O），"
            f"间隙内检测到 {analysis.total_io_events} 个 I/O 事件，"
            f"累计 I/O 等待 {io_wait_total:.0f}us"
        )
    elif io_wait_total > total * 0.2:
        analysis.dominant_factor = "IO_DISK_WAIT"
        analysis.confidence = "MEDIUM"
        analysis.conclusion_detail = (
            f"block I/O 等待时间 {io_wait_total:.0f}us 占总时长 {io_wait_total/total*100:.1f}%"
        )
    elif sleep_pct > 40:
        analysis.dominant_factor = "IO_OR_LOCK_WAIT"
        analysis.confidence = "MEDIUM"
        analysis.conclusion_detail = (
            f"目标线程 {sleep_pct:.1f}% 时间处于 S 状态（可中断等待），"
            f"可能是网络 I/O、锁等待或信号。间隙内 I/O 事件数 {analysis.total_io_events}"
        )
    elif runnable_pct > 25:
        analysis.dominant_factor = "CPU_PREEMPT"
        analysis.confidence = "HIGH" if runnable_pct > 40 else "MEDIUM"
        preempt_str = ", ".join(preempters[:5]) if preempters else "无标记"
        analysis.conclusion_detail = (
            f"目标线程 {runnable_pct:.1f}% 时间处于 Runnable 状态（等 CPU），"
            f"被抢占 {preempt_count} 次。抢占者: {preempt_str}"
        )
    elif running_pct > 60:
        analysis.dominant_factor = "SELF_WORK"
        analysis.confidence = "HIGH" if running_pct > 80 else "MEDIUM"
        analysis.conclusion_detail = (
            f"目标线程 {running_pct:.1f}% 时间在 CPU 上运行，"
            f"空白期可能是自身业务逻辑（如 ELF 解析、重定位等）"
        )
    else:
        # 混合：看哪个占比最大
        components = [
            ("D(不可中断IO)", disk_pct),
            ("S(可中断等待)", sleep_pct),
            ("R(等CPU)", runnable_pct),
            ("Running(CPU)", running_pct),
        ]
        top = max(components, key=lambda x: x[1])
        analysis.dominant_factor = "MIXED"
        analysis.confidence = "LOW"
        analysis.conclusion_detail = (
            f"无明显主导因素。D={disk_pct:.1f}% S={sleep_pct:.1f}% "
            f"R={runnable_pct:.1f}% Running={running_pct:.1f}%。"
            f"最大占比: {top[0]}={top[1]:.1f}%"
        )

    return analysis


def split_gap_into_slices(gap: GapAnalysis, slice_size_us: int = 50_000) -> list:
    """将一个 gap 按时间等距切割为多个子切片，返回每个切片的简要分析。

    每个切片返回 (slice_id, start_us, end_us, duration_ms, 主导状态, 说明)
    """
    slices = []
    ts = gap.thread_slice
    if ts is None:
        return slices

    start = ts.start_us
    end = ts.end_us
    cur = start
    idx = 0

    while cur < end:
        s_end = min(cur + slice_size_us, end)
        dur = s_end - cur

        # 在这个切片内的事件
        s_io = [e for e in ts.io_events
                if cur <= e["ts_us"] < s_end]
        s_running = ts.state_running_us * (dur / ts.duration_us) if ts.duration_us else 0
        s_sleeping = ts.state_sleeping_us * (dur / ts.duration_us) if ts.duration_us else 0
        s_disk = ts.state_disk_wait_us * (dur / ts.duration_us) if ts.duration_us else 0
        s_runnable = ts.state_runnable_us * (dur / ts.duration_us) if ts.duration_us else 0

        # 判断主导状态
        dominant = "running"
        max_val = s_running
        if s_disk > max_val:
            dominant = "D(disk wait)"
            max_val = s_disk
        if s_sleeping > max_val:
            dominant = "S(sleeping)"
            max_val = s_sleeping
        if s_runnable > max_val:
            dominant = "R(wait CPU)"
            max_val = s_runnable

        detail = (
            f"running={s_running/1000:.1f}us disk={s_disk/1000:.1f}us "
            f"sleep={s_sleeping/1000:.1f}us runnable={s_runnable/1000:.1f}us "
            f"io_events={len(s_io)}"
        )
        slices.append({
            "slice_id": idx,
            "start_us": cur,
            "end_us": s_end,
            "duration_ms": dur / 1000,
            "dominant": dominant,
            "detail": detail,
            "io_events": len(s_io),
        })
        idx += 1
        cur = s_end

    return slices
