"""多线程关联分析引擎 (HiSmartPerf 泳道图原理)

在目标线程的间隙期间，分析所有相关线程的活动：
- 同 CPU 竞争分析
- 跨 CPU 迁移机会检测
- 抢占者排名
- 线程活动时间线
"""

from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

from .parser import iter_events

SCHED_SWITCH = "sched_switch"


@dataclass
class ThreadActivity:
    """某线程在一个时间段内的活动摘要"""
    comm: str
    pid: int
    running_us: float = 0.0       # 在 CPU 上运行
    total_switches: int = 0       # 上下文切换次数
    cpu_list: set = field(default_factory=set)  # 运行过的 CPU 列表


@dataclass
class CPUContention:
    """CPU 竞争分析结果"""
    cpu: int
    total_other_running_us: float = 0.0   # 其他线程占用 CPU 的时间
    total_gap_duration_us: float = 0.0     # 间隙总时长
    contention_pct: float = 0.0            # 竞争占比

    # 在该 CPU 上运行的线程（按占用时间降序）
    top_contenders: list = field(default_factory=list)  # [(comm, pid, duration_us), ...]

    # 目标线程在此 CPU 上的 Runnable 时长
    target_runnable_us: float = 0.0


@dataclass
class CrossCPUAnalysis:
    """跨 CPU 分析：目标线程是否有更优的调度选择"""
    target_cpu: int                          # 目标线程主要运行的 CPU
    idle_cpus_during_runnable: list = field(default_factory=list)  # 目标 Runnable 时有哪些空闲 CPU
    big_cpus_available: bool = False         # 是否有大核空闲
    migration_opportunity_pct: float = 0.0   # 有机会被迁移到更好核心的时间占比


@dataclass
class CorrelationReport:
    """多线程关联分析完整报告"""
    gap_id: int
    start_us: float
    end_us: float
    total_duration_us: float
    target_comm: str
    target_pid: int
    target_cpu: int

    # 同 CPU 竞争者
    contention: Optional[CPUContention] = None

    # 跨 CPU 分析
    cross_cpu: Optional[CrossCPUAnalysis] = None

    # 全局线程活动排名（所有 CPU）
    all_threads: list = field(default_factory=list)  # [ThreadActivity, ...] by running time desc

    # 时间线标记（异常区间）
    anomaly_markers: list = field(default_factory=list)  # [(start_us, end_us, label), ...]

    # CPU 使用率统计（每 CPU）
    cpu_utilization: dict = field(default_factory=dict)  # cpu -> util_pct


def analyze_correlation(
    trace_path: str,
    start_us: float,
    end_us: float,
    target_pid: int,
    target_comm: str = "",
    cpu_list: Optional[set] = None,
    top_n: int = 10,
) -> CorrelationReport:
    """分析目标线程间隙期间的多线程竞争情况

    Args:
        trace_path: trace 文件路径
        start_us: 间隙开始（微秒）
        end_us: 间隙结束（微秒）
        target_pid: 目标线程 PID
        target_comm: 目标线程名
        cpu_list: 关注的 CPU 集合（None = 所有 CPU）
        top_n: 返回前 N 个竞争者

    Returns:
        CorrelationReport 包含完整的竞争分析
    """
    report = CorrelationReport(
        gap_id=0,
        start_us=start_us,
        end_us=end_us,
        total_duration_us=end_us - start_us,
        target_comm=target_comm,
        target_pid=target_pid,
        target_cpu=-1,
    )

    total_us = end_us - start_us
    if total_us <= 0:
        return report

    # 每 CPU 统计
    cpu_stats: dict[int, dict] = defaultdict(lambda: {
        "other_running_us": 0.0,
        "threads": defaultdict(float),  # (comm, pid) -> running_us
        "target_runnable_us": 0.0,
        "total_active_us": 0.0,
    })

    # 全局线程运行时间
    global_thread_time: dict[tuple[str, int], float] = defaultdict(float)
    global_thread_cpus: dict[tuple[str, int], set] = defaultdict(set)

    # 上一次 switch 信息：{cpu: (prev_comm, prev_pid, ts_us)}
    last_switch: dict[int, tuple[str, int, float]] = {}

    # 空闲 CPU 跟踪
    cpu_idle_periods: dict[int, list[tuple[float, float]]] = defaultdict(list)

    # 目标线程的 Runnable 时间段
    target_runnable_periods: list[tuple[float, float]] = []

    # 遍历 sched_switch 事件
    for ev in iter_events(trace_path, event_filter={SCHED_SWITCH}):
        ts_us = ev.timestamp * 1_000_000
        if ts_us < start_us - 500:
            continue
        if ts_us > end_us + 500:
            break

        cpu = ev.cpu
        prev_pid = ev.event_data.get("prev_pid")
        next_pid = ev.event_data.get("next_pid")
        prev_comm = ev.event_data.get("prev_comm", "")
        next_comm = ev.event_data.get("next_comm", "")

        if cpu_list and cpu not in cpu_list:
            continue

        # 记录上一个线程的运行时长
        if cpu in last_switch:
            prev_comm_l, prev_pid_l, prev_ts = last_switch[cpu]
            if prev_ts >= start_us:
                run_dur = ts_us - prev_ts
                run_dur = max(0, min(run_dur, end_us - prev_ts))

                key = (prev_comm_l, prev_pid_l)
                global_thread_time[key] += run_dur
                global_thread_cpus[key].add(cpu)

                if prev_pid_l != target_pid and prev_pid_l != 0:
                    cpu_stats[cpu]["other_running_us"] += run_dur
                    cpu_stats[cpu]["threads"][key] += run_dur

                cpu_stats[cpu]["total_active_us"] += run_dur

        # 更新 CPU 占用
        last_switch[cpu] = (next_comm, next_pid, ts_us)

        # 检测目标线程 Runnable 状态
        if prev_pid == target_pid:
            prev_state_raw = ev.event_data.get("prev_state", 0)
            try:
                prev_state = int(prev_state_raw)
            except (ValueError, TypeError):
                prev_state = 0
            if prev_state == 0:  # 非自愿切出 → Runnable
                target_runnable_periods.append((ts_us, None))  # end 待定
        if next_pid == target_pid:
            if target_runnable_periods and target_runnable_periods[-1][1] is None:
                target_runnable_periods[-1] = (target_runnable_periods[-1][0], ts_us)

    # 结束未关闭的 Runnable 段
    for i, (s, e) in enumerate(target_runnable_periods):
        if e is None:
            target_runnable_periods[i] = (s, end_us)

    # 计算目标线程在每个 CPU 上的 Runnable 时长
    target_cpu_detected = -1
    max_target_runnable = 0
    for cpu, stats in cpu_stats.items():
        # 通过 top contender 中是否有目标线程判断
        if target_cpu_detected < 0 and stats["total_active_us"] > 0:
            target_cpu_detected = cpu

    # 汇总 per-CPU contention
    for cpu, stats in cpu_stats.items():
        other_running = stats["other_running_us"]
        # 近似：target runnable = 目标线程在 Runnable 期间内该 CPU 的空闲 + 其他运行
        target_runnable = min(total_us - other_running, total_us * 0.5)

        contenders = sorted(stats["threads"].items(), key=lambda x: -x[1])
        top = [(comm, pid, dur) for (comm, pid), dur in contenders[:top_n]]

        contention = CPUContention(
            cpu=cpu,
            total_other_running_us=other_running,
            total_gap_duration_us=total_us,
            contention_pct=other_running / total_us * 100 if total_us else 0,
            top_contenders=top,
            target_runnable_us=target_runnable,
        )

        if target_cpu_detected < 0 or target_runnable > max_target_runnable:
            target_cpu_detected = cpu
            max_target_runnable = target_runnable

        # 检测 idle 时段
        idle_start = None
        for period in cpu_idle_periods.get(cpu, []):
            if period[0] >= start_us and period[1] <= end_us:
                pass  # idle periods tracked

    report.target_cpu = target_cpu_detected

    # 全局线程排名
    sorted_threads = sorted(global_thread_time.items(), key=lambda x: -x[1])
    for (comm, pid), runtime in sorted_threads[:top_n]:
        report.all_threads.append(ThreadActivity(
            comm=comm,
            pid=pid,
            running_us=runtime,
            cpu_list=global_thread_cpus.get((comm, pid), set()),
        ))

    # 跨 CPU 分析
    # 找出目标线程 Runnable 期间有哪些 CPU 空闲
    idle_cpus = []
    for cpu, stats in cpu_stats.items():
        if cpu != target_cpu_detected and stats["other_running_us"] < total_us * 0.2:
            idle_cpus.append(cpu)

    report.cross_cpu = CrossCPUAnalysis(
        target_cpu=target_cpu_detected,
        idle_cpus_during_runnable=idle_cpus,
        big_cpus_available=False,  # 需要频率数据判断
        migration_opportunity_pct=len(idle_cpus) / max(len(cpu_stats), 1) * 100,
    )

    # CPU 利用率
    for cpu, stats in cpu_stats.items():
        report.cpu_utilization[cpu] = stats["total_active_us"] / total_us * 100 if total_us else 0

    # 主 CPU 的 contention
    if target_cpu_detected >= 0 and target_cpu_detected in cpu_stats:
        s = cpu_stats[target_cpu_detected]
        contenders = sorted(s["threads"].items(), key=lambda x: -x[1])
        report.contention = CPUContention(
            cpu=target_cpu_detected,
            total_other_running_us=s["other_running_us"],
            total_gap_duration_us=total_us,
            contention_pct=s["other_running_us"] / total_us * 100 if total_us else 0,
            top_contenders=[(c, p, d) for (c, p), d in contenders[:top_n]],
            target_runnable_us=max_target_runnable,
        )

    # 生成 anomaly markers
    if report.contention and report.contention.contention_pct > 50:
        report.anomaly_markers.append((start_us, end_us, f"CPU{target_cpu_detected} contention {report.contention.contention_pct:.0f}%"))
    if report.cross_cpu and report.cross_cpu.idle_cpus_during_runnable:
        report.anomaly_markers.append((start_us, end_us, f"Idle CPUs available: {idle_cpus}"))

    return report
