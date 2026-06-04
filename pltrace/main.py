#!/usr/bin/env python3
"""pltrace - 鸿蒙 bytrace/ftrace 快速间隙分析工具

Usage:
    pltrace scan <trace_file>                        # 扫描 trace 基本信息
    pltrace gaps <trace_file> [--thread NAME]        # 找到 dlopen 间隙
    pltrace gaps <trace_file> [--pid PID]            # 按 PID 筛选
    pltrace analyze <trace_file> [--thread NAME]     # 完整分析 + 报告
    pltrace analyze <trace_file> --gap-id N          # 只分析指定 gap
    pltrace slice <trace_file> --gap-id N [--size MS] # 将一个 gap 切割成子切片
    pltrace slice <trace_file> [--thread NAME] --gap-id N

Examples:
    pltrace scan trace.ftrace
    pltrace gaps trace.ftrace --thread my_worker
    pltrace gaps trace.ftrace --pid 12345
    pltrace analyze trace.ftrace --thread my_worker
    pltrace analyze trace.ftrace --gap-id 3
    pltrace slice trace.ftrace --gap-id 3 --size 20
"""

import argparse
import sys
import os
import time

# 允许包内直接运行
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pltrace.parser import scan_events
from pltrace.analyzer import find_gaps, analyze_gap, split_gap_into_slices
from pltrace.reporter import generate_summary_report, generate_gap_report, export_gap_json


def _resolve_target(args):
    """从 args 中提取目标线程名和 PID"""
    target_comm = args.thread if getattr(args, "thread", None) else None
    target_pid = args.pid if getattr(args, "pid", None) else None
    return target_comm, target_pid


def cmd_scan(args):
    """扫描 trace 基本信息"""
    print(f"扫描文件: {args.trace_file}")
    t0 = time.perf_counter()
    info = scan_events(args.trace_file)
    elapsed = time.perf_counter() - t0

    print(f"  事件总数 (扫描上限 500万): {info['total_events']:,}")
    print(f"  时间范围: {info['min_ts']:.6f} → {info['max_ts']:.6f}")
    print(f"  跨度: {(info['max_ts'] - info['min_ts'])*1000:.2f}ms")
    print(f"  事件类型 ({len(info['event_types'])} 种):")
    for t in sorted(info['event_types']):
        print(f"    - {t}")
    print(f"  PID 数: {len(info['pids'])}")
    print(f"  线程名: {', '.join(sorted(list(info['comms']))[:20])}")
    print(f"  CPU 数: {len(info['cpus'])} ({sorted(info['cpus'])[:8]})")
    print(f"  扫描耗时: {elapsed:.2f}s")


def cmd_gaps(args):
    """查找 dlopen 间隙"""
    target_comm, target_pid = _resolve_target(args)

    print(f"查找间隙: {args.trace_file}")
    if target_comm:
        print(f"  目标线程: {target_comm}")
    if target_pid:
        print(f"  目标 PID: {target_pid}")

    gaps = find_gaps(
        args.trace_file,
        target_comm=target_comm,
        target_pid=target_pid,
    )

    if not gaps:
        print("  未找到 dlopen 间隙")
        if not target_comm and not target_pid:
            print("  提示: 使用 --thread 指定目标线程名，或 --pid 指定线程 PID")
        print("  提示: 使用 pltrace scan <file> 查看 trace 中有哪些线程")
        return

    print(f"  找到 {len(gaps)} 个间隙:\n")
    print(f"  {'ID':<4} {'开始(s)':<14} {'结束(s)':<14} {'耗时(ms)':<10} {'线程':<20} {'PID':<7} {'CPU':<4}")
    print("  " + "-" * 79)
    for g in gaps:
        print(f"  {g.gap_id:<4} {g.before_ts:<14.6f} {g.after_ts:<14.6f} "
              f"{g.duration_ms:<10.3f} {g.thread:<20} {g.pid:<7} {g.cpu:<4}")

    if args.output:
        import json
        with open(args.output, "w") as f:
            json.dump([{
                "gap_id": g.gap_id,
                "before_ts": g.before_ts,
                "after_ts": g.after_ts,
                "duration_ms": g.duration_ms,
                "thread": g.thread,
                "pid": g.pid,
                "cpu": g.cpu,
            } for g in gaps], f, indent=2)
        print(f"\n  间隙列表已导出: {args.output}")


def cmd_analyze(args):
    """分析间隙"""
    target_comm, target_pid = _resolve_target(args)
    t0 = time.perf_counter()

    # 先查找间隙
    print(f"Step 1/3: 定位 dlopen 间隙 ...")
    gaps = find_gaps(
        args.trace_file,
        target_comm=target_comm,
        target_pid=target_pid,
    )

    if not gaps:
        print("未找到间隙。")
        if not target_comm and not target_pid:
            print("提示: 使用 --thread 指定目标线程名，或 --pid 指定线程 PID")
        return

    # 筛选
    if args.gap_id is not None:
        gaps = [g for g in gaps if g.gap_id == args.gap_id]
        if not gaps:
            print(f"未找到 gap_id={args.gap_id}")
            return

    print(f"  找到 {len(gaps)} 个间隙待分析")

    # 分析每个间隙
    analyses = []
    for i, gap in enumerate(gaps):
        print(f"Step 2/3: 分析间隙 #{gap.gap_id} ({i+1}/{len(gaps)}) "
              f"[{gap.duration_ms:.1f}ms] ...")
        a = analyze_gap(args.trace_file, gap)
        analyses.append(a)

    # 输出报告
    out_dir = args.output_dir or "."
    os.makedirs(out_dir, exist_ok=True)

    elapsed = time.perf_counter() - t0

    # 摘要
    summary = generate_summary_report(gaps, analyses, args.trace_file, elapsed)
    print(summary)

    # 每个 gap 详细报告
    for a in analyses:
        report = generate_gap_report(a)
        # 写入文件
        gap_file = os.path.join(out_dir, f"gap_{a.gap_id:04d}_report.txt")
        with open(gap_file, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"  详细报告: {gap_file}")

        # JSON 导出
        json_file = os.path.join(out_dir, f"gap_{a.gap_id:04d}.json")
        export_gap_json(a, json_file)
        print(f"  JSON导出: {json_file}")

    # 总 JSON
    summary_json = os.path.join(out_dir, "summary.json")
    import json
    with open(summary_json, "w") as f:
        json.dump([{
            "gap_id": a.gap_id,
            "duration_us": a.total_duration_us,
            "dominant_factor": a.dominant_factor,
            "confidence": a.confidence,
            "detail": a.conclusion_detail,
        } for a in analyses], f, indent=2, ensure_ascii=False)
    print(f"\n  摘要JSON: {summary_json}")

    print(f"\nStep 3/3: 完成。总耗时 {elapsed:.1f}s")


def cmd_slice(args):
    """切割单个 gap 为子切片"""
    target_comm, target_pid = _resolve_target(args)

    # 先找到指定 gap
    gaps = find_gaps(
        args.trace_file,
        target_comm=target_comm,
        target_pid=target_pid,
    )
    target = None
    for g in gaps:
        if g.gap_id == args.gap_id:
            target = g
            break
    if target is None:
        print(f"未找到 gap_id={args.gap_id}")
        return

    print(f"分析 gap #{args.gap_id} [{target.duration_ms:.2f}ms] ...")
    a = analyze_gap(args.trace_file, target)

    slice_size = (args.size or 20) * 1000  # ms → us
    slices = split_gap_into_slices(a, slice_size_us=slice_size)

    print(f"\n  Gap #{args.gap_id} 切分为 {len(slices)} 个 {args.size or 20}ms 子切片:")
    print(f"  {'切片':<6} {'偏移(ms)':<10} {'耗时(ms)':<10} {'主导状态':<20} {'I/O数':<7} {'说明'}")
    print("  " + "-" * 78)
    for s in slices:
        offset = s["start_us"] / 1000 - a.thread_slice.start_us / 1000 if a.thread_slice else 0
        print(f"  {s['slice_id']:<6} {offset:<10.2f} {s['duration_ms']:<10.2f} "
              f"{s['dominant']:<20} {s['io_events']:<7} {s['detail']}")

    # 标记异常
    anomalies = [s for s in slices if s["dominant"] in ("D(disk wait)", "R(wait CPU)")]
    if anomalies:
        print(f"\n  ⚠ 异常子切片 ({len(anomalies)} 个):")
        for s in anomalies:
            offset = s["start_us"] / 1000 - a.thread_slice.start_us / 1000 if a.thread_slice else 0
            print(f"    [偏移 +{offset:.1f}ms] {s['dominant']}")

    if args.output:
        import json
        with open(args.output, "w") as f:
            json.dump(slices, f, indent=2, ensure_ascii=False)
        print(f"\n  子切片数据已导出: {args.output}")


def main():
    parser = argparse.ArgumentParser(
        description="pltrace - 鸿蒙 ftrace 间隙分析工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  pltrace scan trace.ftrace                       # 扫描：查看有哪些线程和事件
  pltrace gaps trace.ftrace                       # 查找所有 dlopen 间隙
  pltrace gaps trace.ftrace --thread dlopen_th    # 按线程名过滤
  pltrace gaps trace.ftrace --pid 12345           # 按 PID 过滤
  pltrace analyze trace.ftrace -t dlopen_th       # 完整分析
  pltrace analyze trace.ftrace --gap-id 3         # 只分析第 3 个 gap
  pltrace slice trace.ftrace --gap-id 3 --size 10 # 10ms 粒度切割
""",
    )
    sub = parser.add_subparsers(dest="command")

    # 公共参数
    def _add_target_args(p):
        p.add_argument("--thread", "-t", help="目标线程名")
        p.add_argument("--pid", "-p", type=int, help="目标线程 PID")

    # scan
    p_scan = sub.add_parser("scan", help="扫描 trace 基本信息（事件类型、线程、时间范围）")
    p_scan.add_argument("trace_file", help="trace 文件路径 (.ftrace 或 .gz)")

    # gaps
    p_gaps = sub.add_parser("gaps", help="查找 dlopen 间隙（列出所有间隙的位置和耗时）")
    p_gaps.add_argument("trace_file")
    _add_target_args(p_gaps)
    p_gaps.add_argument("--output", "-o", help="JSON 导出路径")

    # analyze
    p_analyze = sub.add_parser("analyze", help="完整分析间隙（状态分布 + I/O + 调度 + 结论）")
    p_analyze.add_argument("trace_file")
    _add_target_args(p_analyze)
    p_analyze.add_argument("--gap-id", type=int, help="只分析指定 gap")
    p_analyze.add_argument("--output-dir", "-o", default="pltrace_output",
                           help="输出目录 (默认: pltrace_output)")

    # slice
    p_slice = sub.add_parser("slice", help="切割间隙为子切片（细粒度时间线）")
    p_slice.add_argument("trace_file")
    _add_target_args(p_slice)
    p_slice.add_argument("--gap-id", type=int, required=True, help="目标 gap ID")
    p_slice.add_argument("--size", type=int, default=20, help="子切片大小 (ms, 默认 20)")
    p_slice.add_argument("--output", "-o", help="JSON 导出路径")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "gaps":
        cmd_gaps(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "slice":
        cmd_slice(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
