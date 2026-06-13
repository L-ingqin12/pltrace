#!/usr/bin/env python3
"""生成丰富的模拟 ftrace 数据，用于测试 pltrace 全维度分析。

生成 4 个典型场景的 trace 文件，每个包含多种性能问题：
  - 磁盘 I/O 瓶颈
  - CPU 抢占竞争
  - big.LITTLE 调度问题
  - 锁竞争 / futex 等待
  - 中断风暴
  - 内存缺页
  - Binder IPC
"""

import os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


class TraceBuilder:
    """构建 ftrace 格式的 trace 文件"""

    def __init__(self, scenario_name: str):
        self.lines = []
        self.ts = 1000.0  # 起始时间（秒）
        self.scenario = scenario_name
        self.line_num = 0
        # 多 CPU 环境
        self.cpus = [0, 1, 2, 3]  # 4 核: 0-1 big, 2-3 little
        self.big_cores = {0, 1}
        self.little_cores = {2, 3}

    def _event(self, cpu: int, comm: str, pid: int, flags: str,
               event_name: str, data: str, ts_offset: float = 0.0):
        if ts_offset > 0:
            self.ts += ts_offset
        t = self.ts
        self.lines.append(
            f"  {comm}-{pid:>5}     [{cpu:03d}] {flags} {t:>12.6f}: {event_name}: {data}"
        )
        self.line_num += 1
        return t

    def sched_switch(self, cpu: int, prev_comm: str, prev_pid: int,
                     prev_state: int, next_comm: str, next_pid: int,
                     ts_offset: float = 0.0):
        return self._event(cpu, prev_comm, prev_pid, "d..2.",
                           "sched_switch",
                           f"prev_comm={prev_comm} prev_pid={prev_pid} prev_prio=120 "
                           f"prev_state={prev_state:#06x} "
                           f"==> next_comm={next_comm} next_pid={next_pid}",
                           ts_offset=ts_offset)

    def sched_waking(self, cpu: int, waker_comm: str, waker_pid: int,
                     target_comm: str, target_pid: int, ts_offset: float = 0.0):
        return self._event(cpu, waker_comm, waker_pid, "d..2.",
                           "sched_waking",
                           f"comm={target_comm} pid={target_pid} prio=120 target_cpu={cpu}",
                           ts_offset=ts_offset)

    def block_rq_issue(self, cpu: int, dev: str, sector: int, size: int,
                       rw: int = 0, ts_offset: float = 0.0):
        return self._event(cpu, "mmcqd/0", 89, "....",
                           "block_rq_issue",
                           f"dev={dev},0 sector={sector} nr_sector={size} rw={rw} comm=mmcqd",
                           ts_offset=ts_offset)

    def block_rq_complete(self, cpu: int, dev: str, sector: int, size: int,
                          ts_offset: float = 0.0):
        return self._event(cpu, "mmcqd/0", 89, "....",
                           "block_rq_complete",
                           f"dev={dev},0 sector={sector} nr_sector={size} rw=0",
                           ts_offset=ts_offset)

    def cpu_freq(self, cpu: int, freq_hz: int, ts_offset: float = 0.0):
        return self._event(cpu, "<...>", 0, "....",
                           "cpu_frequency",
                           f"state={freq_hz} cpu_id={cpu}",
                           ts_offset=ts_offset)

    def syscall_exit(self, cpu: int, comm: str, pid: int,
                     syscall: str, ret: str, ts_offset: float = 0.0):
        return self._event(cpu, comm, pid, "....",
                           f"syscall_exit_{syscall}",
                           f"ret={ret}",
                           ts_offset=ts_offset)

    def irq_entry(self, cpu: int, irq: int, name: str, ts_offset: float = 0.0):
        return self._event(cpu, "<...>", 0, "....",
                           "irq_handler_entry",
                           f"irq={irq} name={name}",
                           ts_offset=ts_offset)

    def irq_exit(self, cpu: int, irq: int, ts_offset: float = 0.0):
        return self._event(cpu, "<...>", 0, "....",
                           "irq_handler_exit",
                           f"irq={irq} ret=handled",
                           ts_offset=ts_offset)

    def binder_tx(self, cpu: int, from_pid: int, to_pid: int, ts_offset: float = 0.0):
        return self._event(cpu, "binder", from_pid, "....",
                           "binder_transaction",
                           f"transaction=1 from_pid={from_pid} to_pid={to_pid}",
                           ts_offset=ts_offset)

    def futex_exit(self, cpu: int, comm: str, pid: int, ret: int, ts_offset: float = 0.0):
        return self._event(cpu, comm, pid, "....",
                           "syscall_exit_futex",
                           f"ret={ret}",
                           ts_offset=ts_offset)

    def build(self) -> str:
        return (
            f"# tracer: nop\n"
            f"# scenario: {self.scenario}\n"
            f"# events: {self.line_num}\n"
            f"#\n" +
            "\n".join(self.lines)
        )

    def save(self, filename: str):
        filepath = os.path.join(OUTPUT_DIR, filename)
        with open(filepath, "w") as f:
            f.write(self.build())
        size_kb = os.path.getsize(filepath) / 1024
        print(f"  ✓ {filename} ({self.line_num} events, {size_kb:.1f}KB)")
        return filepath


def scenario_io_bottleneck():
    """场景 1: 磁盘 I/O 瓶颈 — dlopen 加载多个 .so 文件，频繁 I/O"""
    tb = TraceBuilder("io_bottleneck")

    # CPU 频率初始化
    tb.cpu_freq(2, 1_800_000, ts_offset=0.001)

    # --- Gap 1: 第一次 dlopen (I/O 密集，85ms) ---
    # syscall exit openat (dlopen 完成)
    tb.syscall_exit(2, "app_main", 12345, "openat", "3", ts_offset=0.001)
    gap1_start = tb.ts

    # 线程进入 D 状态（page cache miss）
    tb.sched_switch(2, "app_main", 12345, 0x0002, "swapper/2", 0, ts_offset=0.001)
    # Block I/O
    tb.block_rq_issue(2, "179", 1000, 8, ts_offset=0.001)
    tb.ts += 0.045  # 45ms I/O 延迟
    tb.block_rq_complete(2, "179", 1000, 8)
    # 唤醒
    tb.sched_waking(2, "swapper/2", 0, "app_main", 12345, ts_offset=0.001)
    tb.sched_switch(2, "swapper/2", 0, 0x0000, "app_main", 12345, ts_offset=0.001)

    # 再次 I/O
    tb.sched_switch(2, "app_main", 12345, 0x0002, "swapper/2", 0, ts_offset=0.002)
    tb.block_rq_issue(2, "179", 2000, 16, ts_offset=0.001)
    tb.ts += 0.030
    tb.block_rq_complete(2, "179", 2000, 16)
    tb.sched_waking(2, "swapper/2", 0, "app_main", 12345, ts_offset=0.001)
    tb.sched_switch(2, "swapper/2", 0, 0x0000, "app_main", 12345, ts_offset=0.001)

    # mmap 操作（ELF 映射）
    tb.syscall_exit(2, "app_main", 12345, "mmap", "0x7f000000", ts_offset=0.003)
    tb.syscall_exit(2, "app_main", 12345, "mmap", "0x7f100000", ts_offset=0.002)

    # 第二个 dlopen 完成
    tb.syscall_exit(2, "app_main", 12345, "openat", "4", ts_offset=0.002)
    gap1_end = tb.ts
    print(f"  Gap 1 (I/O密集): {(gap1_end - gap1_start)*1000:.1f}ms")

    # --- Gap 2: 锁竞争 (futex, 30ms) ---
    tb.syscall_exit(2, "app_main", 12345, "openat", "5", ts_offset=0.005)
    gap2_start = tb.ts
    # futex 失败
    tb.futex_exit(2, "app_main", 12345, -1, ts_offset=0.003)
    # 等待锁（S 状态）
    tb.sched_switch(2, "app_main", 12345, 0x0001, "worker", 12346, ts_offset=0.001)
    tb.futex_exit(2, "worker", 12346, 0, ts_offset=0.002)
    tb.syscall_exit(2, "worker", 12346, "write", "4096", ts_offset=0.020)
    tb.sched_waking(2, "worker", 12346, "app_main", 12345, ts_offset=0.001)
    tb.sched_switch(2, "worker", 12346, 0x0001, "app_main", 12345, ts_offset=0.001)
    tb.futex_exit(2, "app_main", 12345, 0, ts_offset=0.001)
    tb.syscall_exit(2, "app_main", 12345, "openat", "6", ts_offset=0.002)
    gap2_end = tb.ts
    print(f"  Gap 2 (锁竞争): {(gap2_end - gap2_start)*1000:.1f}ms")

    # 更多 IRQ
    for i in range(5):
        tb.irq_entry(2, 42 + i, f"mmc{i}", ts_offset=0.001)
        tb.irq_exit(2, 42 + i, ts_offset=0.0001)

    tb.save("rich_io_bottleneck.ftrace")


def scenario_cpu_preempt():
    """场景 2: CPU 抢占 — 高负载多线程，关键线程频繁切换"""
    tb = TraceBuilder("cpu_preempt")

    tb.cpu_freq(0, 2_200_000, ts_offset=0.001)
    tb.cpu_freq(1, 2_200_000, ts_offset=0.001)
    tb.cpu_freq(2, 1_200_000, ts_offset=0.001)
    tb.cpu_freq(3, 1_200_000, ts_offset=0.001)

    # 在 4 个 CPU 上放多个高负载线程
    workers = [
        ("bg_worker1", 20001, 0),
        ("bg_worker2", 20002, 1),
        ("bg_worker3", 20003, 2),
        ("render", 30001, 0),
    ]

    # Gap 1: 关键线程在 CPU0 被抢占
    tb.syscall_exit(0, "critical_thread", 10001, "openat", "3", ts_offset=0.001)
    gap_start = tb.ts

    # 被 render 抢占
    tb.sched_switch(0, "critical_thread", 10001, 0x0000,
                    "render", 30001, ts_offset=0.002)
    # render 跑了 30ms
    for i in range(6):
        tb.syscall_exit(0, "render", 30001, "write", "4096", ts_offset=0.005)
    # 切回 critical
    tb.sched_switch(0, "render", 30001, 0x0001,
                    "critical_thread", 10001, ts_offset=0.001)
    tb.syscall_exit(0, "critical_thread", 10001, "mmap", "0x7f000000", ts_offset=0.003)

    # 再次被 bg_worker1 抢占
    tb.sched_switch(0, "critical_thread", 10001, 0x0000,
                    "bg_worker1", 20001, ts_offset=0.001)
    for i in range(4):
        tb.syscall_exit(0, "bg_worker1", 20001, "write", "4096", ts_offset=0.005)
    tb.sched_switch(0, "bg_worker1", 20001, 0x0001,
                    "critical_thread", 10001, ts_offset=0.001)

    # 同时 CPU1 也在跑 bg_worker2
    for i in range(3):
        tb.syscall_exit(1, "bg_worker2", 20002, "write", "4096", ts_offset=0.003)

    tb.syscall_exit(0, "critical_thread", 10001, "openat", "4", ts_offset=0.005)
    gap_end = tb.ts
    print(f"  Gap 1 (CPU抢占): {(gap_end - gap_start)*1000:.1f}ms")

    # 更多调度事件
    for cpu in [0, 1, 2, 3]:
        for i in range(3):
            w = workers[i % len(workers)]
            tb.sched_switch(cpu, "swapper/2", 0, 0x0000,
                           w[0], w[1], ts_offset=0.002)
            tb.syscall_exit(cpu, w[0], w[1], "read", "1024", ts_offset=0.001)

    # CPU 频率变化
    tb.cpu_freq(2, 800_000, ts_offset=0.010)
    tb.cpu_freq(3, 800_000, ts_offset=0.001)

    tb.save("rich_cpu_preempt.ftrace")


def scenario_binder_ipc():
    """场景 3: Binder IPC + 内存缺页 + 中断"""
    tb = TraceBuilder("binder_ipc")

    tb.cpu_freq(0, 2_000_000, ts_offset=0.001)

    # Binder 事务
    tb.syscall_exit(0, "app_main", 11111, "openat", "3", ts_offset=0.001)
    gap_start = tb.ts

    tb.binder_tx(0, 11111, 22222, ts_offset=0.003)
    tb.binder_tx(0, 22222, 11111, ts_offset=0.008)

    # 缺页
    tb.syscall_exit(0, "app_main", 11111, "page_fault", "0", ts_offset=0.002)
    tb.sched_switch(0, "app_main", 11111, 0x0002, "swapper/2", 0, ts_offset=0.001)
    tb.block_rq_issue(0, "179", 5000, 4, ts_offset=0.001)
    tb.ts += 0.012
    tb.block_rq_complete(0, "179", 5000, 4)
    tb.sched_waking(0, "swapper/2", 0, "app_main", 11111, ts_offset=0.001)
    tb.sched_switch(0, "swapper/2", 0, 0x0000, "app_main", 11111, ts_offset=0.001)

    # 更多 mmap
    for i in range(4):
        tb.syscall_exit(0, "app_main", 11111, "mmap",
                       f"0x7f{i:02d}0000", ts_offset=0.002)

    # 中断
    for i in range(8):
        tb.irq_entry(0, 100 + i, f"irq_dev{i}", ts_offset=0.0005)
        tb.irq_exit(0, 100 + i, ts_offset=0.0001)

    tb.syscall_exit(0, "app_main", 11111, "openat", "5", ts_offset=0.003)
    gap_end = tb.ts
    print(f"  Gap 1 (Binder+缺页): {(gap_end - gap_start)*1000:.1f}ms")

    tb.save("rich_binder_ipc.ftrace")


def scenario_biglittle_migration():
    """场景 4: big.LITTLE 调度 — 线程在小核上运行导致延迟飙升"""
    tb = TraceBuilder("biglittle_migration")

    # 4 核: 0,1 = big (2.2GHz), 2,3 = little (1.2GHz)
    tb.cpu_freq(0, 2_200_000, ts_offset=0.001)
    tb.cpu_freq(1, 2_200_000, ts_offset=0.001)
    tb.cpu_freq(2, 1_200_000, ts_offset=0.001)
    tb.cpu_freq(3, 1_200_000, ts_offset=0.001)

    # --- Gap 1: 在大核上运行（正常，30ms） ---
    tb.syscall_exit(0, "app_main", 10001, "openat", "3", ts_offset=0.001)
    gap1_start = tb.ts
    # 在大核 0 上做 ELF 解析
    for i in range(5):
        tb.syscall_exit(0, "app_main", 10001, "mmap",
                       f"0x7f{i:02d}0000", ts_offset=0.003)
    tb.syscall_exit(0, "app_main", 10001, "openat", "4", ts_offset=0.002)
    gap1_end = tb.ts
    print(f"  Gap 1 (大核正常): {(gap1_end - gap1_start)*1000:.1f}ms")

    # --- Gap 2: 被迁移到小核（异常，120ms） ---
    tb.syscall_exit(0, "app_main", 10001, "openat", "5", ts_offset=0.005)

    # 大核被高负载线程占满
    tb.sched_switch(0, "app_main", 10001, 0x0000,
                    "heavy_task", 30001, ts_offset=0.002)
    # app_main 被迁移到小核 CPU2
    tb.sched_waking(2, "swapper/2", 0, "app_main", 10001, ts_offset=0.001)
    tb.sched_switch(2, "swapper/2", 0, 0x0000,
                    "app_main", 10001, ts_offset=0.001)

    # 小核降频
    tb.cpu_freq(2, 800_000, ts_offset=0.005)

    # 在小核上缓慢执行
    for i in range(8):
        tb.syscall_exit(2, "app_main", 10001, "mmap",
                       f"0x7f{i+5:02d}0000", ts_offset=0.010)

    # 小核继续降频
    tb.cpu_freq(2, 600_000, ts_offset=0.010)

    # 在小核上又做了一次 I/O
    tb.sched_switch(2, "app_main", 10001, 0x0002,
                    "swapper/2", 0, ts_offset=0.002)
    tb.block_rq_issue(2, "179", 3000, 8, ts_offset=0.001)
    tb.ts += 0.025
    tb.block_rq_complete(2, "179", 3000, 8)
    tb.sched_waking(2, "swapper/2", 0, "app_main", 10001, ts_offset=0.001)
    tb.sched_switch(2, "swapper/2", 0, 0x0000, "app_main", 10001, ts_offset=0.001)

    tb.syscall_exit(2, "app_main", 10001, "openat", "6", ts_offset=0.005)
    gap2_end = tb.ts
    print(f"  Gap 2 (小核慢速): {(gap2_end - gap1_end)*1000:.1f}ms")

    # 同时大核 CPU1 基本空闲
    tb.syscall_exit(1, "idle_task", 0, "read", "0", ts_offset=0.001)

    tb.save("rich_biglittle.ftrace")


if __name__ == "__main__":
    print("生成丰富测试数据...\n")
    scenario_io_bottleneck()
    scenario_cpu_preempt()
    scenario_binder_ipc()
    scenario_biglittle_migration()
    print(f"\n共 4 个场景生成完毕 → {OUTPUT_DIR}/")
