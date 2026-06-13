"""HiSmartPerf 风格分析模板

预定义的分析模板，自动识别性能瓶颈模式：
- dlopen 耗时分析
- 应用启动分析
- 帧率抖动分析
- 全链路延迟分析
"""

from dataclasses import dataclass, field
from collections import defaultdict

from .parser import iter_events
from .analyzer import find_gaps, analyze_gap


@dataclass
class TemplateResult:
    """模板分析结果"""
    template_name: str
    summary: str
    overall_score: str           # "GOOD", "WARNING", "CRITICAL"
    findings: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    detail: str = ""


def analyze_dlopen(trace_path: str, target_comm: str = None, target_pid: int = None) -> TemplateResult:
    """dlopen 耗时分析模板

    自动找到所有 dlopen 间隙，分析每个间隙的瓶颈类型，
    统计整体分布，标记异常间隙。
    """
    gaps = find_gaps(trace_path, target_comm=target_comm, target_pid=target_pid)

    if not gaps:
        return TemplateResult(
            template_name="dlopen_latency",
            summary="未找到 dlopen 间隙。",
            overall_score="UNKNOWN",
        )

    analyses = []
    for gap in gaps:
        a = analyze_gap(trace_path, gap)
        analyses.append(a)

    # 统计
    durations = [a.total_duration_us / 1000 for a in analyses]
    avg_ms = sum(durations) / len(durations)
    max_ms = max(durations)
    min_ms = min(durations)
    range_ms = max_ms - min_ms

    # 分类统计
    by_factor = defaultdict(int)
    for a in analyses:
        by_factor[a.dominant_factor] += 1

    findings = []
    recommendations = []

    # 发现 1: 总体耗时
    findings.append(f"共 {len(analyses)} 次 dlopen 调用，平均耗时 {avg_ms:.1f}ms，范围 [{min_ms:.1f}, {max_ms:.1f}]ms")

    # 发现 2: 瓶颈分布
    for factor, count in sorted(by_factor.items(), key=lambda x: -x[1]):
        pct = count / len(analyses) * 100
        label = {
            "IO_DISK_WAIT": "磁盘 I/O 阻塞",
            "IO_OR_LOCK_WAIT": "I/O 或锁等待",
            "CPU_PREEMPT": "CPU 被抢占",
            "SELF_WORK": "自身业务（ELF 解析等）",
            "MIXED": "混合因素",
        }.get(factor, factor)
        findings.append(f"  {label}: {count} 次 ({pct:.0f}%)")

    # 发现 3: 异常间隙
    if range_ms > avg_ms * 0.5:
        # 方差大，查找异常
        threshold = avg_ms + range_ms * 0.5
        anomalies = [a for a in analyses if a.total_duration_us / 1000 > threshold]
        if anomalies:
            findings.append(f"⚠ 异常间隙 ({len(anomalies)} 个，耗时 > {threshold:.0f}ms):")
            for a in anomalies[:5]:
                findings.append(f"  Gap #{a.gap_id}: {a.total_duration_us/1000:.1f}ms, "
                                f"因素={a.dominant_factor}, 置信度={a.confidence}")

    # 建议
    io_count = by_factor.get("IO_DISK_WAIT", 0)
    preempt_count = by_factor.get("CPU_PREEMPT", 0)
    self_count = by_factor.get("SELF_WORK", 0)

    if io_count > len(analyses) * 0.3:
        recommendations.append("磁盘 I/O 是主要瓶颈。建议：检查动态库路径是否在慢速存储设备上，考虑预加载或使用 zRAM 缓存。")
    if preempt_count > len(analyses) * 0.3:
        recommendations.append("CPU 抢占频繁。建议：将 dlopen 线程优先级提升或绑定到大核，减少与高负载线程的竞争。")
    if self_count > len(analyses) * 0.5:
        recommendations.append("自身业务耗时占主导。建议：检查 ELF 解析逻辑，考虑使用 dlsym 延迟符号解析，或减少依赖库数量。")
    if max_ms > avg_ms * 2:
        recommendations.append(f"耗时波动大（最大 {max_ms:.0f}ms vs 平均 {avg_ms:.0f}ms）。建议：逐 gap 分析异常间隙的触发条件（是否在特定时间点/syscall 后发生）。")

    # 综合评分
    if max_ms < 50:
        score = "GOOD"
    elif max_ms < 150 and range_ms < avg_ms:
        score = "WARNING"
    else:
        score = "CRITICAL"

    detail = (
        f"┌ dlopen 耗时分析模板 ──────────────────────\n"
        f"│ 分析次数: {len(analyses)}\n"
        f"│ 平均耗时: {avg_ms:.1f}ms\n"
        f"│ 最小/最大: {min_ms:.1f}ms / {max_ms:.1f}ms\n"
        f"│ 波动范围: {range_ms:.1f}ms ({(range_ms/avg_ms*100) if avg_ms else 0:.0f}% of avg)\n"
        f"│ 综合评级: {score}\n"
        f"└──────────────────────────────────────────"
    )

    return TemplateResult(
        template_name="dlopen_latency",
        summary=f"dlopen 耗时分析: {len(analyses)} 次调用, 平均 {avg_ms:.1f}ms, 最大 {max_ms:.1f}ms",
        overall_score=score,
        findings=findings,
        recommendations=recommendations,
        detail=detail,
    )


def analyze_startup(trace_path: str, target_comm: str = None) -> TemplateResult:
    """应用启动分析模板

    模仿 HiSmartPerf 的 AppStartup 模板，自动识别启动阶段：
    1. 进程创建 → 2. Application 初始化 → 3. 首页渲染

    通过寻找关键的 trace 标记点来划分阶段。
    """
    # 扫描可用的标记事件
    markers_of_interest = {
        "syscall_exit_execve", "sys_exit_execve",      # 进程创建
        "syscall_exit_openat", "sys_exit_openat",       # 首次 dlopen
        "tracing_mark_write",                            # 自定义打点
    }

    # 按时间排序收集标记事件
    markers = []
    for ev in iter_events(trace_path, event_filter=markers_of_interest):
        markers.append(ev)

    markers.sort(key=lambda e: e.timestamp)

    if len(markers) < 2:
        return TemplateResult(
            template_name="app_startup",
            summary="标记事件不足，无法分析启动阶段。请确保 trace 覆盖了从进程创建到首页渲染的完整过程。",
            overall_score="UNKNOWN",
        )

    first_ts = markers[0].timestamp
    last_ts = markers[-1].timestamp
    total_ms = (last_ts - first_ts) * 1000

    # 简单分阶段：最早的事件到第一个 openat = 进程创建阶段
    # 第一个 openat 到最后一个 openat = 初始化阶段
    # 最后一个 openat 到最后事件 = 渲染阶段
    openat_events = [m for m in markers if "openat" in m.event_name.lower() or "openat2" in m.event_name.lower()]
    phase_breakdown = []

    if openat_events:
        first_openat = openat_events[0].timestamp
        last_openat = openat_events[-1].timestamp

        phase1_ms = (first_openat - first_ts) * 1000
        phase2_ms = (last_openat - first_openat) * 1000
        phase3_ms = (last_ts - last_openat) * 1000

        phase_breakdown = [
            ("进程创建→首次dlopen", phase1_ms),
            ("初始化阶段(dlopen密集)", phase2_ms),
            ("渲染准备阶段", phase3_ms),
        ]

    findings = [
        f"总启动耗时: {total_ms:.0f}ms",
    ]
    for name, dur in phase_breakdown:
        pct = dur / total_ms * 100 if total_ms else 0
        findings.append(f"  {name}: {dur:.0f}ms ({pct:.0f}%)")

    recommendations = []
    if total_ms > 3000:
        score = "CRITICAL"
        recommendations.append("启动耗时超过 3 秒，建议排查初始化阶段的 I/O 和锁等待。")
    elif total_ms > 1500:
        score = "WARNING"
        recommendations.append("启动耗时偏高，建议检查 dlopen 数量和库依赖链。")
    else:
        score = "GOOD"

    return TemplateResult(
        template_name="app_startup",
        summary=f"应用启动分析: 总耗时 {total_ms:.0f}ms, {len(phase_breakdown)} 个阶段",
        overall_score=score,
        findings=findings,
        recommendations=recommendations,
        detail=f"启动轨迹: {len(markers)} 个标记事件, 跨度 {total_ms:.0f}ms",
    )


def analyze_frame_jank(trace_path: str, render_thread: str = "RSMainThread",
                       app_thread: str = None) -> TemplateResult:
    """帧率抖动分析模板

    模仿 HiSmartPerf 的丢帧分析，关联 App 主线程和 RenderService 线程。
    """
    # 寻找 RSMainThread 的 DoComposition 事件（渲染帧标记）
    frame_events = []
    for ev in iter_events(trace_path):
        if ev.comm == render_thread and "composition" in ev.event_name.lower():
            frame_events.append(ev)
        if app_thread and ev.comm == app_thread:
            frame_events.append(ev)

    if len(frame_events) < 2:
        return TemplateResult(
            template_name="frame_jank",
            summary=f"未找到足够的帧事件（需要 RSMainThread DoComposition 标记）。",
            overall_score="UNKNOWN",
        )

    frame_events.sort(key=lambda e: e.timestamp)

    # 计算帧间隔
    intervals = []
    for i in range(1, len(frame_events)):
        dt = (frame_events[i].timestamp - frame_events[i-1].timestamp) * 1000
        intervals.append(dt)

    if not intervals:
        return TemplateResult(template_name="frame_jank", summary="无法计算帧间隔。", overall_score="UNKNOWN")

    avg_interval = sum(intervals) / len(intervals)
    max_interval = max(intervals)
    # 丢帧：间隔 > 16.67ms * 2 = 33.3ms（默认 60fps 下超过 2 帧）
    jank_count = sum(1 for i in intervals if i > 33.3)
    jank_pct = jank_count / len(intervals) * 100

    findings = [
        f"帧率分析: {len(intervals)} 个帧间隔",
        f"平均帧间隔: {avg_interval:.1f}ms (~{1000/avg_interval:.0f}fps)" if avg_interval > 0 else "",
        f"最大帧间隔: {max_interval:.1f}ms",
        f"丢帧次数: {jank_count}/{len(intervals)} ({jank_pct:.1f}%)",
    ]

    recommendations = []
    if jank_pct > 10:
        score = "CRITICAL"
        recommendations.append("丢帧率超过 10%，建议使用 trace_correlate 检查渲染线程是否被抢占。")
    elif jank_pct > 2:
        score = "WARNING"
        recommendations.append("存在偶发丢帧，建议查看最大帧间隔时刻的 CPU 状态。")
    else:
        score = "GOOD"

    return TemplateResult(
        template_name="frame_jank",
        summary=f"帧率抖动分析: 丢帧率 {jank_pct:.1f}%",
        overall_score=score,
        findings=findings,
        recommendations=recommendations,
        detail=f"avg={avg_interval:.1f}ms max={max_interval:.1f}ms jank={jank_count}",
    )


TEMPLATES = {
    "dlopen": analyze_dlopen,
    "startup": analyze_startup,
    "frame": analyze_frame_jank,
}
