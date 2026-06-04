#!/usr/bin/env python3
"""生成模拟的 ftrace 数据，用于测试 pltrace 工具。

生成包含两个 dlopen 调用之间的间隔，模拟几种典型场景：
1. 磁盘 I/O 导致的等待（D 状态）
2. CPU 被抢占导致的等待（Runnable 状态）
3. 混合场景
"""

import random
import sys
import os

# 将 pltrace 加入路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def generate_demo_trace(output_path: str, scenario: str = "mixed"):
    """生成模拟 trace 文件

    Args:
        output_path: 输出文件路径
        scenario: 场景类型 - "io_wait", "cpu_preempt", "mixed"
    """
    lines = []
    ts = 100.0  # 起始时间戳（秒）

    def write_event(t, cpu, comm, pid, flags, event_name, data):
        lines.append(
            f"  {comm}-{pid:>5}     [{cpu:03d}] {flags} {t:>12.6f}: {event_name}: {data}"
        )

    target_pid = 12345
    target_comm = "dlopen_thread"
    other_pid = 67890
    other_comm = "heavy_worker"

    # --- 第一个 dlopen 完成 ---
    write_event(ts, 2, target_comm, target_pid, "d..2.",
                "syscall_exit_openat", "ret=3")
    ts += 0.0001

    gap_start = ts

    if scenario == "io_wait":
        _generate_io_wait(write_event, ts, target_comm, target_pid,
                          other_comm, other_pid)
    elif scenario == "cpu_preempt":
        _generate_cpu_preempt(write_event, ts, target_comm, target_pid,
                              other_comm, other_pid)
    else:
        _generate_mixed(write_event, ts, target_comm, target_pid,
                        other_comm, other_pid)

    # 计算 gap 结束时间
    final_ts = gap_start + 0.085  # 85ms 间隙

    # --- 第二个 dlopen 开始 ---
    write_event(final_ts, 2, target_comm, target_pid, "d..2.",
                "syscall_exit_openat", "ret=4")

    with open(output_path, "w") as f:
        f.write(f"# tracer: nop\n")
        f.write(f"#\n")
        f.write("\n".join(lines))
        f.write("\n")

    # 统计
    total_events = len(lines)
    with open(output_path) as f:
        content = f.read()
    file_size = os.path.getsize(output_path)

    print(f"生成 trace: {output_path}")
    print(f"  场景:     {scenario}")
    print(f"  事件数:   {total_events}")
    print(f"  文件大小: {file_size:,} bytes")
    print(f"  间隙:     {gap_start:.6f} → {final_ts:.6f} ({(final_ts - gap_start) * 1000:.1f}ms)")

    return lines


def _generate_io_wait(write_event, ts, comm, pid, other_comm, other_pid):
    """磁盘 I/O 场景：目标线程进入 D 状态，磁盘 I/O 事件"""
    t = ts

    # 目标线程切出 → D 状态（磁盘 I/O）
    write_event(t, 2, comm, pid, "d..2.", "sched_switch",
                f"prev_comm={comm} prev_pid={pid} prev_prio=120 prev_state={0x0002} "
                f"==> next_comm=swapper/2 next_pid=0")
    t += 0.0001

    # block I/O 事件
    write_event(t, 2, "mmcqd/0", 89, "....", "block_bio_queue",
                f"dev=179,0 sector=123456 nr_sector=8 rw=0 comm={comm}")
    t += 0.0001
    write_event(t, 2, "mmcqd/0", 89, "....", "block_rq_issue",
                f"dev=179,0 sector=123456 nr_sector=8 rw=0 comm={comm}")
    t += 0.0001

    # 磁盘耗时 40ms
    t += 0.040

    write_event(t, 2, "mmcqd/0", 89, "....", "block_rq_complete",
                f"dev=179,0 sector=123456 nr_sector=8 rw=0")
    t += 0.0001

    # 目标线程被唤醒
    write_event(t, 2, "swapper/2", 0, "d..2.", "sched_waking",
                f"comm={comm} pid={pid} prio=120 target_cpu=2")
    t += 0.0001
    write_event(t, 2, "swapper/2", 0, "d..2.", "sched_switch",
                f"prev_comm=swapper/2 prev_pid=0 prev_prio=120 prev_state={0x0000} "
                f"==> next_comm={comm} next_pid={pid}")
    t += 0.0001

    # 目标线程处理数据
    write_event(t, 2, comm, pid, "d..2.", "syscall_exit_read",
                "ret=4096")
    t += 0.001

    # 再次短 I/O
    write_event(t, 2, comm, pid, "d..2.", "sched_switch",
                f"prev_comm={comm} prev_pid={pid} prev_prio=120 prev_state={0x0002} "
                f"==> next_comm=swapper/2 next_pid=0")
    t += 0.0001
    write_event(t, 2, "mmcqd/0", 89, "....", "block_rq_issue",
                f"dev=179,0 sector=123464 nr_sector=8 rw=0 comm={comm}")
    t += 0.015
    write_event(t, 2, "mmcqd/0", 89, "....", "block_rq_complete",
                f"dev=179,0 sector=123464 nr_sector=8 rw=0")
    t += 0.0001
    write_event(t, 2, "swapper/2", 0, "d..2.", "sched_switch",
                f"prev_comm=swapper/2 prev_pid=0 prev_prio=120 prev_state={0x0000} "
                f"==> next_comm={comm} next_pid={pid}")

    # 加一些 CPU 频率事件
    write_event(t - 0.020, 2, "<...>", 0, "....", "cpu_frequency",
                "state=1800000 cpu_id=2")
    write_event(t - 0.010, 2, "<...>", 0, "....", "cpu_frequency",
                "state=1200000 cpu_id=2")


def _generate_cpu_preempt(write_event, ts, comm, pid, other_comm, other_pid):
    """CPU 抢占场景：heavy_worker 抢占目标线程"""
    t = ts

    # heavy_worker 被唤醒
    write_event(t, 2, "swapper/2", 0, "d..2.", "sched_waking",
                f"comm={other_comm} pid={other_pid} prio=90 target_cpu=2")
    t += 0.0001

    # heavy_worker 抢占目标线程（prev_state=0 表示非自愿切出）
    write_event(t, 2, comm, pid, "d..2.", "sched_switch",
                f"prev_comm={comm} prev_pid={pid} prev_prio=120 prev_state={0x0000} "
                f"==> next_comm={other_comm} next_pid={other_pid}")
    t += 0.0001

    # heavy_worker 跑了 50ms
    for i in range(10):
        write_event(t, 2, other_comm, other_pid, "d..2.", "syscall_exit_write",
                    "ret=4096")
        t += 0.0001
        write_event(t, 2, other_comm, other_pid, "d..2.", "syscall_exit_futex",
                    "ret=0")
        t += 0.0001
        t += 0.0046  # 每个循环 ~5ms

    # 目标线程被重新调度
    write_event(t, 2, "swapper/2", 0, "d..2.", "sched_switch",
                f"prev_comm={other_comm} prev_pid={other_pid} prev_prio=120 prev_state={0x0001} "
                f"==> next_comm={comm} next_pid={pid}")
    t += 0.0001

    # 目标线程运行一段
    write_event(t, 2, comm, pid, "d..2.", "syscall_exit_read",
                "ret=1024")
    t += 0.001

    # 又被抢占
    write_event(t, 2, comm, pid, "d..2.", "sched_switch",
                f"prev_comm={comm} prev_pid={pid} prev_prio=120 prev_state={0x0000} "
                f"==> next_comm={other_comm} next_pid={other_pid}")
    t += 0.0001

    for i in range(5):
        write_event(t, 2, other_comm, other_pid, "d..2.", "syscall_exit_write",
                    "ret=4096")
        t += 0.0001
        t += 0.0049

    write_event(t, 2, "swapper/2", 0, "d..2.", "sched_switch",
                f"prev_comm={other_comm} prev_pid={other_pid} prev_prio=120 prev_state={0x0001} "
                f"==> next_comm={comm} next_pid={pid}")

    write_event(t - 0.030, 2, "<...>", 0, "....", "cpu_frequency",
                "state=2000000 cpu_id=2")


def _generate_mixed(write_event, ts, comm, pid, other_comm, other_pid):
    """混合场景：既有 I/O 也有 CPU 抢占"""
    t = ts

    # 第一段：目标线程在运行（自己业务逻辑，ELF 解析等）
    for i in range(5):
        write_event(t, 2, comm, pid, "d..2.", "syscall_exit_mmap",
                    "ret=0x7f000000")
        t += 0.0005
    t += 0.015

    # 第二段：进入 D 状态（page fault 读磁盘）
    write_event(t, 2, comm, pid, "d..2.", "sched_switch",
                f"prev_comm={comm} prev_pid={pid} prev_prio=120 prev_state={0x0002} "
                f"==> next_comm=swapper/2 next_pid=0")
    t += 0.0001
    write_event(t, 2, "mmcqd/0", 89, "....", "block_rq_issue",
                f"dev=179,0 sector=654321 nr_sector=16 rw=0 comm={comm}")
    t += 0.030  # 30ms I/O
    write_event(t, 2, "mmcqd/0", 89, "....", "block_rq_complete",
                f"dev=179,0 sector=654321 nr_sector=16 rw=0")
    t += 0.0001

    # 唤醒
    write_event(t, 2, "swapper/2", 0, "d..2.", "sched_switch",
                f"prev_comm=swapper/2 prev_pid=0 prev_prio=120 prev_state={0x0000} "
                f"==> next_comm={comm} next_pid={pid}")
    t += 0.0001

    # 第三段：运行一会儿后被抢占
    write_event(t, 2, comm, pid, "d..2.", "syscall_exit_mmap",
                "ret=0x7f001000")
    t += 0.005

    write_event(t, 2, "swapper/2", 0, "d..2.", "sched_waking",
                f"comm={other_comm} pid={other_pid} prio=90 target_cpu=2")
    t += 0.0001

    write_event(t, 2, comm, pid, "d..2.", "sched_switch",
                f"prev_comm={comm} prev_pid={pid} prev_prio=120 prev_state={0x0000} "
                f"==> next_comm={other_comm} next_pid={other_pid}")
    t += 0.0001

    for i in range(6):
        write_event(t, 2, other_comm, other_pid, "d..2.", "syscall_exit_write",
                    "ret=4096")
        t += 0.0001
        t += 0.0049

    write_event(t, 2, "swapper/2", 0, "d..2.", "sched_switch",
                f"prev_comm={other_comm} prev_pid={other_pid} prev_prio=120 prev_state={0x0001} "
                f"==> next_comm={comm} next_pid={pid}")

    # 中断
    write_event(t - 0.010, 2, "<...>", 0, "....", "irq_handler_entry",
                "irq=42 name=mmc0")
    write_event(t - 0.009, 2, "<...>", 0, "....", "irq_handler_exit",
                "irq=42 ret=handled")

    write_event(t - 0.020, 2, "<...>", 0, "....", "cpu_frequency",
                "state=1500000 cpu_id=2")
    write_event(t - 0.005, 2, "<...>", 0, "....", "cpu_frequency",
                "state=900000 cpu_id=2")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("output", nargs="?", default="demo_trace.ftrace",
                   help="输出文件 (默认: demo_trace.ftrace)")
    p.add_argument("--scenario", "-s", choices=["io_wait", "cpu_preempt", "mixed"],
                   default="mixed")
    args = p.parse_args()
    generate_demo_trace(args.output, args.scenario)
