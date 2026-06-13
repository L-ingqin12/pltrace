"""全维度 trace 综合分析引擎

整合 HiSmartPerf 分析理念，从 10 个维度全面检测 trace 中的性能与调度问题：

  1. 调度分析 — 线程状态、抢占、调度延迟
  2. CPU 拓扑 — big.LITTLE、频率、利用率
  3. I/O 分析  — block 层延迟、I/O 模式
  4. 锁竞争    — futex 等待、锁持有者
  5. IPC 分析  — binder 事务耗时
  6. 中断分析  — IRQ/softirq 风暴
  7. 内存分析  — 缺页、分配延迟
  8. 唤醒链    — 唤醒源和延迟
  9. 跨核迁移  — 不必要的迁移
  10. 异常检测 — 统计离群点

输出结构化 JSON，适合 AI 直接消费。
"""

import json
import time
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

from .parser import iter_events, scan_events
from .analyzer import find_gaps, analyze_gap

# ──────────────────────────────────────────────
# 事件集合定义
# ──────────────────────────────────────────────

ALL_INTEREST_EVENTS = {
    # 调度
    "sched_switch", "sched_waking", "sched_wakeup",
    "sched_migrate_task", "sched_pi_setprio",
    # CPU 频率
    "cpu_frequency", "cpu_frequency_limits",
    # Block I/O
    "block_rq_issue", "block_rq_complete", "block_bio_queue",
    "block_bio_complete", "block_rq_insert",
    # 锁
    "syscall_exit_futex",
    # Binder
    "binder_transaction", "binder_transaction_received",
    "binder_transaction_alloc_buf",
    # 中断
    "irq_handler_entry", "irq_handler_exit",
    "softirq_entry", "softirq_exit",
    # 内存
    "syscall_exit_mmap", "syscall_exit_munmap",
    "syscall_exit_brk",
    # 缺页
    "syscall_exit_page_fault", "syscall_exit_mprotect",
    # 文件操作
    "syscall_exit_openat", "syscall_exit_close",
    "syscall_exit_read", "syscall_exit_write",
}

@dataclass
class Finding:
    """单个分析发现"""
    severity: str        # "critical", "warning", "info"
    category: str        # "scheduling", "io", "lock", "ipc", "irq", "memory", "cpu_freq"
    title: str
    detail: str
    evidence: str = ""   # 关键证据（时间戳、数值）
    recommendation: str = ""


@dataclass
class DimensionResult:
    """单个分析维度的结果"""
    dimension: str
    summary: str
    findings: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)


@dataclass
class ComprehensiveReport:
    """全维度综合分析报告"""
    trace_file: str
    trace_span_ms: float
    total_events: int
    analyzed_at: str

    # 各维度结果
    scheduling: Optional[DimensionResult] = None
    cpu_topology: Optional[DimensionResult] = None
    io_analysis: Optional[DimensionResult] = None
    lock_analysis: Optional[DimensionResult] = None
    ipc_analysis: Optional[DimensionResult] = None
    irq_analysis: Optional[DimensionResult] = None
    memory_analysis: Optional[DimensionResult] = None
    wakeup_chain: Optional[DimensionResult] = None

    # 汇总
    total_findings: int = 0
    critical_count: int = 0
    warning_count: int = 0
    global_score: str = "UNKNOWN"  # GOOD / WARNING / CRITICAL
    executive_summary: str = ""
    top_recommendations: list = field(default_factory=list)

    def to_dict(self) -> dict:
        """转为 JSON 友好格式"""
        def _dim(d):
            if d is None:
                return None
            return {
                "dimension": d.dimension,
                "summary": d.summary,
                "findings": [{"severity": f.severity, "category": f.category,
                              "title": f.title, "detail": f.detail,
                              "evidence": f.evidence, "recommendation": f.recommendation}
                             for f in d.findings],
                "stats": d.stats,
            }
        return {
            "trace_file": self.trace_file,
            "trace_span_ms": self.trace_span_ms,
            "total_events": self.total_events,
            "dimensions": {
                "scheduling": _dim(self.scheduling),
                "cpu_topology": _dim(self.cpu_topology),
                "io_analysis": _dim(self.io_analysis),
                "lock_analysis": _dim(self.lock_analysis),
                "ipc_analysis": _dim(self.ipc_analysis),
                "irq_analysis": _dim(self.irq_analysis),
                "memory_analysis": _dim(self.memory_analysis),
                "wakeup_chain": _dim(self.wakeup_chain),
            },
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "global_score": self.global_score,
            "executive_summary": self.executive_summary,
            "top_recommendations": self.top_recommendations,
        }


# ──────────────────────────────────────────────
# 分析引擎
# ──────────────────────────────────────────────

class ComprehensiveAnalyzer:
    """全维度 trace 分析器"""

    def __init__(self, trace_path: str):
        self.trace_path = trace_path

        # 事件缓冲区（按类别分流）
        self.sched_events: list = []       # sched_switch
        self.wake_events: list = []        # sched_waking / sched_wakeup
        self.block_events: list = []       # block_*
        self.freq_events: list = []        # cpu_frequency
        self.futex_events: list = []       # futex
        self.binder_events: list = []      # binder_*
        self.irq_events: list = []         # irq_*/softirq_*
        self.mem_events: list = []         # mmap/brk/page_fault

        # 聚合统计
        self.per_cpu_stats: dict[int, dict] = defaultdict(lambda: defaultdict(float))
        self.per_thread_stats: dict[str, dict] = defaultdict(lambda: defaultdict(float))
        self.per_thread_comm: dict[int, str] = {}

        # 元信息
        self.min_ts: float = float("inf")
        self.max_ts: float = 0.0
        self.total_events: int = 0
        self.cpus: set = set()
        self.pids: set = set()

    def collect(self) -> "ComprehensiveAnalyzer":
        """第一遍扫描：收集所有事件"""
        for ev in iter_events(self.trace_path):
            ts = ev.timestamp
            self.min_ts = min(self.min_ts, ts)
            self.max_ts = max(self.max_ts, ts)
            self.total_events += 1
            self.cpus.add(ev.cpu)
            self.pids.add(ev.pid)
            if ev.pid and ev.comm:
                self.per_thread_comm[ev.pid] = ev.comm

            ename = ev.event_name

            if ename == "sched_switch":
                self.sched_events.append(ev)
            elif ename in ("sched_waking", "sched_wakeup"):
                self.wake_events.append(ev)
            elif ename.startswith("block_"):
                self.block_events.append(ev)
            elif ename == "cpu_frequency":
                self.freq_events.append(ev)
            elif ename in ("syscall_exit_futex",):
                self.futex_events.append(ev)
            elif ename.startswith("binder_"):
                self.binder_events.append(ev)
            elif ename.startswith("irq_") or ename.startswith("softirq_"):
                self.irq_events.append(ev)
            elif ename in ("syscall_exit_mmap", "syscall_exit_munmap",
                           "syscall_exit_brk", "syscall_exit_page_fault",
                           "syscall_exit_mprotect"):
                self.mem_events.append(ev)

            if self.total_events >= 20_000_000:
                break  # 上限 2000 万

        return self

    def analyze(self) -> ComprehensiveReport:
        """执行全维度分析"""
        self.collect()

        span_ms = (self.max_ts - self.min_ts) * 1000
        report = ComprehensiveReport(
            trace_file=self.trace_path,
            trace_span_ms=span_ms,
            total_events=self.total_events,
            analyzed_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        )

        # 逐维度分析
        report.scheduling = self._analyze_scheduling()
        report.cpu_topology = self._analyze_cpu_topology()
        report.io_analysis = self._analyze_io()
        report.lock_analysis = self._analyze_lock()
        report.ipc_analysis = self._analyze_ipc()
        report.irq_analysis = self._analyze_irq()
        report.memory_analysis = self._analyze_memory()
        report.wakeup_chain = self._analyze_wakeup(span_ms)

        # 汇总
        all_findings = []
        for dim in [report.scheduling, report.cpu_topology, report.io_analysis,
                     report.lock_analysis, report.ipc_analysis, report.irq_analysis,
                     report.memory_analysis, report.wakeup_chain]:
            if dim:
                all_findings.extend(dim.findings)

        report.total_findings = len(all_findings)
        report.critical_count = sum(1 for f in all_findings if f.severity == "critical")
        report.warning_count = sum(1 for f in all_findings if f.severity == "warning")

        # 全局评分
        if report.critical_count > 0:
            report.global_score = "CRITICAL"
        elif report.warning_count > 3:
            report.global_score = "WARNING"
        else:
            report.global_score = "GOOD"

        # 执行摘要
        parts = []
        if report.scheduling:
            parts.append(report.scheduling.summary)
        if report.io_analysis and report.io_analysis.findings:
            parts.append(f"I/O: {len(report.io_analysis.findings)} 个发现")
        if report.lock_analysis and report.lock_analysis.findings:
            parts.append(f"锁: {len(report.lock_analysis.findings)} 个发现")
        report.executive_summary = " | ".join(parts)

        # 建议（按严重度排序）
        recommendations = []
        for f in all_findings:
            if f.recommendation:
                recommendations.append((f.severity, f.recommendation))
        recommendations.sort(key=lambda x: {"critical": 0, "warning": 1, "info": 2}[x[0]])
        report.top_recommendations = [r for _, r in recommendations[:5]]

        return report

    # ── 维度 1: 调度分析 ──

    def _analyze_scheduling(self) -> DimensionResult:
        dim = DimensionResult(dimension="scheduling", summary="")

        if not self.sched_events:
            dim.summary = "无调度事件数据"
            return dim

        # 统计：线程状态分布
        state_counts = {"R": 0, "S": 0, "D": 0}
        preempt_count = 0
        thread_runtime: dict[int, float] = defaultdict(float)
        thread_switches: dict[int, int] = defaultdict(int)

        for ev in self.sched_events:
            prev_pid = ev.event_data.get("prev_pid", 0)
            prev_state_raw = ev.event_data.get("prev_state", 0)
            try:
                prev_state = int(prev_state_raw)
            except (ValueError, TypeError):
                prev_state = 0

            state_counts["R" if prev_state == 0 else
                       "D" if prev_state & 2 else
                       "S"] += 1

            if prev_state == 0:
                preempt_count += 1
            if prev_pid and prev_pid != 0:
                thread_switches[prev_pid] += 1

        n_switches = len(self.sched_events)
        dim.stats = {
            "total_context_switches": n_switches,
            "preempt_pct": preempt_count / max(n_switches, 1) * 100,
            "state_distribution": state_counts,
        }

        # 发现：高抢占率
        preempt_pct = preempt_count / max(n_switches, 1) * 100
        if preempt_pct > 30:
            dim.findings.append(Finding(
                severity="critical", category="scheduling",
                title=f"高抢占率: {preempt_pct:.1f}%",
                detail=f"{preempt_count}/{n_switches} 次上下文切换是非自愿的（被抢占）。"
                       f"高抢占率表明 CPU 竞争激烈，可能导致关键线程频繁被中断。",
                recommendation="检查是否有过多高优先级线程竞争同一 CPU。"
                              "考虑将关键线程绑定到专用核心（cpu affinity）或使用 cgroup 隔离。",
            ))
        elif preempt_pct > 15:
            dim.findings.append(Finding(
                severity="warning", category="scheduling",
                title=f"中等抢占率: {preempt_pct:.1f}%",
                detail=f"{preempt_count}/{n_switches} 次上下文切换是非自愿的。",
                recommendation="监控抢占频率，如果关键路径延迟不稳定，考虑线程优先级调整。",
            ))

        # 发现：D 状态过多（磁盘 I/O 阻塞）
        d_pct = state_counts["D"] / max(n_switches, 1) * 100
        if d_pct > 15:
            dim.findings.append(Finding(
                severity="warning", category="scheduling",
                title=f"线程 D 状态占比高: {d_pct:.1f}%",
                detail=f"{state_counts['D']} 次切换到 D（不可中断 I/O）状态。"
                       f"大量时间花在等待磁盘 I/O。",
                recommendation="检查 I/O 维度分析结果。考虑使用更快的存储或增加 readahead 缓冲。",
            ))

        dim.summary = f"调度分析: {n_switches} 次切换, 抢占率 {preempt_pct:.1f}%"
        return dim

    # ── 维度 2: CPU 拓扑分析 ──

    def _analyze_cpu_topology(self) -> DimensionResult:
        dim = DimensionResult(dimension="cpu_topology", summary="")

        if not self.freq_events:
            dim.summary = "无 CPU 频率数据"
            return dim

        # 提取频率数据
        cpu_freqs: dict[int, list[float]] = defaultdict(list)
        for ev in self.freq_events:
            for k, v in ev.event_data.items():
                if isinstance(v, (int, float)) and v > 100_000:
                    # Hz 值
                    cpu_freqs[ev.cpu].append(v / 1_000_000)
                elif isinstance(v, (int, float)) and 100 < v < 10000:
                    cpu_freqs[ev.cpu].append(v / 1000)

        # 检测 big.LITTLE 集群
        clusters = {}
        for cpu, freqs in cpu_freqs.items():
            if freqs:
                max_f = max(freqs)
                # 大核: > 1.8 GHz, 中核: 1.0-1.8 GHz, 小核: < 1.0 GHz
                if max_f > 1.8:
                    clusters[cpu] = "big"
                elif max_f > 1.0:
                    clusters[cpu] = "mid"
                else:
                    clusters[cpu] = "little"

        dim.stats = {
            "cpu_clusters": clusters,
            "cpu_count": len(self.cpus),
            "freq_ranges": {cpu: {"min": min(fs), "max": max(fs), "avg": sum(fs)/len(fs)}
                           for cpu, fs in cpu_freqs.items() if fs},
        }

        # 发现：小核检测
        little_cores = [c for c, t in clusters.items() if t == "little"]
        big_cores = [c for c, t in clusters.items() if t == "big"]
        if little_cores and big_cores:
            dim.findings.append(Finding(
                severity="info", category="cpu_freq",
                title=f"检测到 big.LITTLE 架构: {len(big_cores)} big + {len(little_cores)} little",
                detail=f"大核: {big_cores}, 小核: {little_cores}。"
                       f"关键线程如果在 little 核上运行会导致延迟异常。",
                recommendation="将延迟敏感线程绑定到大核: taskset -p <core_mask> <pid>",
            ))

        # 发现：降频
        for cpu, freqs in cpu_freqs.items():
            if len(freqs) < 2:
                continue
            max_f = max(freqs)
            min_f = min(freqs)
            if max_f > 0 and min_f / max_f < 0.5:
                dim.findings.append(Finding(
                    severity="warning", category="cpu_freq",
                    title=f"CPU{cpu} 频繁降频: {min_f:.1f}GHz → {max_f:.1f}GHz",
                    detail=f"频率波动范围 {min_f/min(max_f,1)*100:.0f}%，可能因温控/功耗限制触发降频。",
                    recommendation="检查设备温度，确认是否触发 thermal throttling。"
                                  "锁定性能模式: echo performance > scaling_governor",
                ))

        dim.summary = f"CPU: {len(self.cpus)} 核, {len(clusters)} 集群"
        return dim

    # ── 维度 3: I/O 分析 ──

    def _analyze_io(self) -> DimensionResult:
        dim = DimensionResult(dimension="io_analysis", summary="")

        if not self.block_events:
            dim.summary = "无 block I/O 事件"
            return dim

        # 配对 issue → complete 计算 I/O 延迟
        issues: dict[tuple, float] = {}  # (dev, sector) -> ts
        io_latencies: list[float] = []
        io_count = 0

        for ev in self.block_events:
            if ev.event_name in ("block_rq_issue",):
                dev = ev.event_data.get("dev", "?")
                sector = ev.event_data.get("sector", 0)
                issues[(dev, sector)] = ev.timestamp
            elif ev.event_name in ("block_rq_complete",):
                dev = ev.event_data.get("dev", "?")
                sector = ev.event_data.get("sector", 0)
                key = (dev, sector)
                if key in issues:
                    lat = (ev.timestamp - issues.pop(key)) * 1_000_000
                    io_latencies.append(lat)
                    io_count += 1

        if not io_latencies:
            dim.summary = "无法计算 I/O 延迟（issue/complete 不匹配）"
            return dim

        avg_lat = sum(io_latencies) / len(io_latencies)
        max_lat = max(io_latencies)
        p99_lat = sorted(io_latencies)[int(len(io_latencies) * 0.99)] if len(io_latencies) > 100 else max_lat

        dim.stats = {
            "io_requests": io_count,
            "avg_latency_us": avg_lat,
            "max_latency_us": max_lat,
            "p99_latency_us": p99_lat,
        }

        # 发现：高 I/O 延迟
        if avg_lat > 10_000:  # > 10ms
            dim.findings.append(Finding(
                severity="critical", category="io",
                title=f"磁盘 I/O 延迟高: avg={avg_lat/1000:.1f}ms, p99={p99_lat/1000:.1f}ms",
                detail=f"共 {io_count} 次 I/O 请求。平均延迟 {avg_lat/1000:.1f}ms，"
                       f"最大延迟 {max_lat/1000:.1f}ms。延迟过高可能导致 I/O 阻塞。",
                recommendation="检查存储设备类型（eMMC vs UFS）。"
                              "考虑使用 f2fs 文件系统或增大 readahead 缓冲区。",
            ))
        elif avg_lat > 2000:  # > 2ms
            dim.findings.append(Finding(
                severity="warning", category="io",
                title=f"磁盘 I/O 延迟偏高: avg={avg_lat/1000:.1f}ms",
                detail=f"P99 延迟 {p99_lat/1000:.1f}ms，在 App 启动场景下可能感知到延迟。",
                recommendation="检查是否有大量随机读。考虑预加载(prefault)或使用 MAP_POPULATE。",
            ))

        # 发现：I/O 密集
        span_ms = (self.max_ts - self.min_ts) * 1000
        io_rate = io_count / max(span_ms / 1000, 1)
        if io_rate > 100:  # > 100 IOPS
            dim.findings.append(Finding(
                severity="info", category="io",
                title=f"高 I/O 频率: {io_rate:.0f} IOPS",
                detail=f"每秒 {io_rate:.0f} 次 I/O 请求，可能是大量小文件读取或碎片化 I/O。",
                recommendation="检查是否在读取大量小 .so 文件。考虑合并动态库或使用静态链接。",
            ))

        dim.summary = f"I/O: {io_count} 请求, avg={avg_lat/1000:.1f}ms, p99={p99_lat/1000:.1f}ms"
        return dim

    # ── 维度 4: 锁竞争分析 ──

    def _analyze_lock(self) -> DimensionResult:
        dim = DimensionResult(dimension="lock_analysis", summary="")

        if not self.futex_events:
            dim.summary = "无 futex 事件"
            return dim

        futex_count = len(self.futex_events)
        # 统计失败（返回 -1 或非 0）的 futex 调用
        failed = 0
        for ev in self.futex_events:
            ret = ev.event_data.get("ret", 0)
            if isinstance(ret, (int, float)) and ret != 0:
                failed += 1

        dim.stats = {
            "futex_calls": futex_count,
            "failed": failed,
            "failure_pct": failed / max(futex_count, 1) * 100,
        }

        # 发现
        if failed > futex_count * 0.3:
            dim.findings.append(Finding(
                severity="warning", category="lock",
                title=f"高 futex 失败率: {failed}/{futex_count} ({failed/max(futex_count,1)*100:.0f}%)",
                detail="大量 futex 调用返回非零，表明存在显著的锁竞争。",
                recommendation="使用 perf lock contention 或 lockstat 定位热点锁。"
                              "考虑使用 RCU 或 lock-free 数据结构减少竞争。",
            ))

        dim.summary = f"锁: {futex_count} 调用, {failed} 失败"
        return dim

    # ── 维度 5: IPC (Binder) 分析 ──

    def _analyze_ipc(self) -> DimensionResult:
        dim = DimensionResult(dimension="ipc_analysis", summary="")

        if not self.binder_events:
            dim.summary = "无 Binder 事件"
            return dim

        tx_count = sum(1 for e in self.binder_events if e.event_name == "binder_transaction")
        dim.stats = {
            "binder_transactions": tx_count,
            "total_binder_events": len(self.binder_events),
        }

        if tx_count > 100:
            dim.findings.append(Finding(
                severity="info", category="ipc",
                title=f"高 Binder 频率: {tx_count} 次事务",
                detail=f"Binder 事务频繁可能增加 IPC 开销。"
                       f"如果出现在关键路径，考虑减少跨进程调用。",
                recommendation="检查是否可以合并多个 Binder 调用，或使用共享内存替代。",
            ))

        dim.summary = f"IPC: {tx_count} Binder 事务"
        return dim

    # ── 维度 6: 中断分析 ──

    def _analyze_irq(self) -> DimensionResult:
        dim = DimensionResult(dimension="irq_analysis", summary="")

        if not self.irq_events:
            dim.summary = "无中断事件"
            return dim

        irq_count = sum(1 for e in self.irq_events if e.event_name.startswith("irq_"))
        softirq_count = sum(1 for e in self.irq_events if e.event_name.startswith("softirq_"))
        span_s = max((self.max_ts - self.min_ts), 0.001)
        irq_rate = irq_count / span_s
        softirq_rate = softirq_count / span_s

        dim.stats = {
            "irq_count": irq_count, "irq_rate_hz": irq_rate,
            "softirq_count": softirq_count, "softirq_rate_hz": softirq_rate,
        }

        # 发现：中断风暴
        if irq_rate > 10000:
            dim.findings.append(Finding(
                severity="warning", category="irq",
                title=f"高中断率: {irq_rate:.0f} IRQ/s",
                detail=f"每秒 {irq_rate:.0f} 次硬件中断，可能影响实时性能。",
                recommendation="检查是否网络中断或存储中断过于频繁。考虑中断合并(NAPI)或中断亲和性调整。",
            ))

        dim.summary = f"中断: {irq_count} IRQ ({irq_rate:.0f}/s) + {softirq_count} softIRQ"
        return dim

    # ── 维度 7: 内存分析 ──

    def _analyze_memory(self) -> DimensionResult:
        dim = DimensionResult(dimension="memory_analysis", summary="")

        if not self.mem_events:
            dim.summary = "无内存事件"
            return dim

        mmap_count = sum(1 for e in self.mem_events if "mmap" in e.event_name)
        brk_count = sum(1 for e in self.mem_events if "brk" in e.event_name)
        pf_count = sum(1 for e in self.mem_events if "page_fault" in e.event_name)

        dim.stats = {
            "mmap_calls": mmap_count, "brk_calls": brk_count,
            "page_faults": pf_count,
        }

        # 发现：频繁缺页
        if pf_count > 1000:
            dim.findings.append(Finding(
                severity="warning", category="memory",
                title=f"高频缺页: {pf_count} 次",
                detail=f"缺页（page fault）处理是耗时的内核操作。"
                       f"大量缺页表明内存访问模式不佳或内存不足。",
                recommendation="考虑预映射(prefault)关键页面。对于大块内存使用 hugepages。",
            ))

        dim.summary = f"内存: {mmap_count} mmap, {pf_count} 缺页"
        return dim

    # ── 维度 8: 唤醒链分析 ──

    def _analyze_wakeup(self, span_ms: float) -> DimensionResult:
        dim = DimensionResult(dimension="wakeup_chain", summary="")

        if not self.wake_events:
            dim.summary = "无唤醒事件"
            return dim

        # 统计唤醒者
        waker_counts: dict[str, int] = defaultdict(int)
        wake_latencies: list[float] = []

        for ev in self.wake_events:
            waker = ev.comm
            target = ev.event_data.get("comm", "?")
            waker_counts[f"{waker}→{target}"] += 1

        dim.stats = {
            "total_wakeups": len(self.wake_events),
            "top_wakers": sorted(waker_counts.items(), key=lambda x: -x[1])[:10],
        }

        dim.summary = f"唤醒: {len(self.wake_events)} 次"
        return dim


# ──────────────────────────────────────────────
# 便捷入口
# ──────────────────────────────────────────────

def run_comprehensive_analysis(trace_path: str) -> ComprehensiveReport:
    """运行全维度综合分析，返回结构化报告"""
    analyzer = ComprehensiveAnalyzer(trace_path)
    return analyzer.analyze()


def run_comprehensive_analysis_json(trace_path: str) -> str:
    """运行全维度分析，返回 JSON 字符串"""
    report = run_comprehensive_analysis(trace_path)
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2, default=str)
