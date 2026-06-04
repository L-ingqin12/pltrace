"""报告生成模块

将分析结果输出为可读文本报告和 JSON 格式。
"""

import json
from datetime import datetime

from .analyzer import GapAnalysis, split_gap_into_slices


def format_us(us: float) -> str:
    """微秒格式化"""
    if us >= 1_000_000:
        return f"{us / 1_000_000:.2f}s"
    elif us >= 1000:
        return f"{us / 1000:.2f}ms"
    else:
        return f"{us:.1f}us"


def format_pct(part: float, total: float) -> str:
    """百分比格式化"""
    if total == 0:
        return "0.0%"
    return f"{part / total * 100:.1f}%"


def generate_gap_report(analysis: GapAnalysis) -> str:
    """为单个 gap 生成文本报告"""
    ts = analysis.thread_slice
    if ts is None:
        return f"Gap #{analysis.gap_id}: 未找到目标线程的调度数据\n"

    total = ts.duration_us
    lines = []
    lines.append("=" * 68)
    lines.append(f"  Gap #{analysis.gap_id} 分析报告")
    lines.append("=" * 68)
    lines.append(f"  起始偏移:     +0.00ms")
    lines.append(f"  结束偏移:     +{ts.duration_us / 1000:.2f}ms")
    lines.append(f"  总耗时:       {format_us(total)} ({total / 1000:.3f}ms)")
    lines.append(f"  目标线程:     {analysis.target_comm} (PID={analysis.target_pid})")
    lines.append("")

    # 状态分布
    lines.append("  ── 线程状态分布 ──")
    lines.append(f"  Running (CPU):     {format_us(ts.state_running_us):>10}  {format_pct(ts.state_running_us, total)}")
    lines.append(f"  Runnable (等CPU):  {format_us(ts.state_runnable_us):>10}  {format_pct(ts.state_runnable_us, total)}")
    lines.append(f"  Sleeping (可中断): {format_us(ts.state_sleeping_us):>10}  {format_pct(ts.state_sleeping_us, total)}")
    lines.append(f"  Disk Wait (不可中断): {format_us(ts.state_disk_wait_us):>8}  {format_pct(ts.state_disk_wait_us, total)}")
    lines.append(f"  Other:             {format_us(ts.state_other_us):>10}  {format_pct(ts.state_other_us, total)}")
    lines.append("")

    # 调度事件
    lines.append("  ── 调度统计 ──")
    lines.append(f"  上下文切换:    {ts.sched_switches} 次")
    lines.append(f"  被抢占次数:    {ts.preemptions} 次")
    if ts.preempting_threads:
        preempt_str = " → ".join(ts.preempting_threads[:5])
        lines.append(f"  抢占者:        {preempt_str}")
    lines.append("")

    # I/O 统计
    lines.append("  ── I/O 统计 ──")
    lines.append(f"  I/O 事件总数:  {analysis.total_io_events}")
    lines.append(f"  累计 I/O 等待: {format_us(analysis.total_io_wait_us)}")
    for evt, cnt in sorted(analysis.io_breakdown.items()):
        lines.append(f"    {evt}:  {cnt}")
    lines.append("")

    # CPU 频率
    if ts.freq_samples > 0:
        lines.append("  ── CPU 频率 ──")
        lines.append(f"  采样数:        {ts.freq_samples}")
        lines.append(f"  平均频率:      {ts.avg_cpu_freq_mhz:.0f} MHz")
        lines.append(f"  最低频率:      {ts.min_cpu_freq_mhz:.0f} MHz")
        lines.append(f"  最高频率:      {ts.max_cpu_freq_mhz:.0f} MHz")
        lines.append("")

    # 中断
    lines.append(f"  ── 中断:       {ts.irq_count} 次")
    lines.append("")

    # 判定结论
    lines.append("  ── 结论 ──")
    lines.append(f"  主导因素:      {analysis.dominant_factor}")
    lines.append(f"  置信度:        {analysis.confidence}")
    lines.append(f"  依据:          {analysis.conclusion_detail}")
    lines.append("")

    # 子切片分析
    slices = split_gap_into_slices(analysis, slice_size_us=50_000)  # 50ms 切片
    if len(slices) > 1:
        lines.append(f"  ── 时间线切片 ({len(slices)}×50ms) ──")
        lines.append(f"  {'ID':<5} {'起始(ms)':<10} {'耗时(ms)':<10} {'主导状态':<20} {'I/O数':<8}")
        lines.append("  " + "-" * 60)
        for s in slices:
            lines.append(
                f"  {s['slice_id']:<5} {s['start_us'] / 1000 - ts.start_us / 1000:<10.2f} "
                f"{s['duration_ms']:<10.2f} {s['dominant']:<20} {s['io_events']:<8}"
            )
        lines.append("")
        # 标注异常切片
        anomaly_slices = [s for s in slices if s["dominant"] in ("D(disk wait)", "R(wait CPU)")]
        if anomaly_slices:
            lines.append(f"  ⚠ 异常切片 ({len(anomaly_slices)} 个):")
            for s in anomaly_slices:
                offset = s["start_us"] / 1000 - ts.start_us / 1000
                lines.append(f"    [+{offset:.1f}ms] {s['dominant']} - {s['detail']}")

    lines.append("=" * 68)
    return "\n".join(lines)


def generate_summary_report(
    gaps_found: list,
    gap_analyses: list,
    trace_path: str,
    elapsed_sec: float,
) -> str:
    """生成总体摘要报告"""
    lines = []
    lines.append("")
    lines.append("█" * 68)
    lines.append("█  pltrace - 鸿蒙 ftrace 间隙分析")
    lines.append("█" * 68)
    lines.append(f"  文件:         {trace_path}")
    lines.append(f"  分析时间:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  处理耗时:     {elapsed_sec:.1f}s")
    lines.append(f"  发现间隙数:   {len(gap_analyses)}")
    lines.append("")

    if not gap_analyses:
        lines.append("  未找到可分析的 dlopen 间隙。")
        return "\n".join(lines)

    # 摘要表
    lines.append("  ── 间隙摘要 ──")
    header = f"  {'ID':<4} {'耗时(ms)':<10} {'线程':<20} {'主导因素':<22} {'置信度':<8}"
    lines.append(header)
    lines.append("  " + "-" * 66)
    for a in gap_analyses:
        dur_ms = a.total_duration_us / 1000
        lines.append(
            f"  {a.gap_id:<4} {dur_ms:<10.2f} {a.target_comm:<20} "
            f"{a.dominant_factor:<22} {a.confidence:<8}"
        )
    lines.append("")

    # 统计
    io_gaps = [a for a in gap_analyses if a.dominant_factor.startswith("IO")]
    cpu_gaps = [a for a in gap_analyses if "PREEMPT" in a.dominant_factor]
    freq_gaps = [a for a in gap_analyses if "FREQ" in a.dominant_factor]
    self_gaps = [a for a in gap_analyses if "SELF" in a.dominant_factor]

    lines.append("  ── 分布统计 ──")
    lines.append(f"  I/O 相关:         {len(io_gaps)}/{len(gap_analyses)} 个间隙")
    lines.append(f"  CPU 抢占:         {len(cpu_gaps)}/{len(gap_analyses)} 个间隙")
    lines.append(f"  CPU 频率:         {len(freq_gaps)}/{len(gap_analyses)} 个间隙")
    lines.append(f"  自身业务:         {len(self_gaps)}/{len(gap_analyses)} 个间隙")

    # 计算 I/O 的总贡献
    total_io_wait = sum(a.total_io_wait_us for a in gap_analyses)
    total_dur = sum(a.total_duration_us for a in gap_analyses)
    lines.append("")
    lines.append(f"  总 I/O 等待时间: {format_us(total_io_wait)} ({format_pct(total_io_wait, total_dur)} 的总间隙时间)")

    lines.append("")
    lines.append("█" * 68)
    return "\n".join(lines)


def export_gap_json(analysis: GapAnalysis, filepath: str):
    """将单个 gap 分析导出为 JSON"""
    ts = analysis.thread_slice
    data = {
        "gap_id": analysis.gap_id,
        "start_us": ts.start_us if ts else 0,
        "end_us": ts.end_us if ts else 0,
        "duration_us": ts.duration_us if ts else 0,
        "target_thread": analysis.target_comm,
        "target_pid": analysis.target_pid,
        "states": {
            "running_us": ts.state_running_us if ts else 0,
            "runnable_us": ts.state_runnable_us if ts else 0,
            "sleeping_us": ts.state_sleeping_us if ts else 0,
            "disk_wait_us": ts.state_disk_wait_us if ts else 0,
            "other_us": ts.state_other_us if ts else 0,
        } if ts else {},
        "sched_switches": ts.sched_switches if ts else 0,
        "preemptions": ts.preemptions if ts else 0,
        "preempting_threads": ts.preempting_threads if ts else [],
        "io_events_total": analysis.total_io_events,
        "io_wait_us": analysis.total_io_wait_us,
        "io_breakdown": analysis.io_breakdown,
        "cpu_freq": {
            "avg_mhz": ts.avg_cpu_freq_mhz if ts else 0,
            "min_mhz": ts.min_cpu_freq_mhz if ts else 0,
            "max_mhz": ts.max_cpu_freq_mhz if ts else 0,
        } if ts else {},
        "irq_count": ts.irq_count if ts else 0,
        "dominant_factor": analysis.dominant_factor,
        "confidence": analysis.confidence,
        "conclusion_detail": analysis.conclusion_detail,
        "slices": split_gap_into_slices(analysis),
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
