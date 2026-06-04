"""pltrace MCP Server

将 pltrace 分析能力暴露为 MCP (Model Context Protocol) 工具，
通过 stdio JSON-RPC 与 AI 助手交互。

启动方式:
    python3 -m pltrace.mcp_server
    或: python3 pltrace/mcp_server.py

在 Claude Code 中配置:
    {
      "mcpServers": {
        "pltrace": {
          "command": "python3",
          "args": ["-m", "pltrace.mcp_server"],
          "cwd": "/path/to/trace-analyzer"
        }
      }
    }
"""

import json
import sys
import os
import traceback
from typing import Any

# 确保可以导入同包模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pltrace.parser import scan_events
from pltrace.analyzer import find_gaps, analyze_gap, split_gap_into_slices
from pltrace.reporter import generate_gap_report

VERSION = "1.0.0"
SERVER_NAME = "pltrace-mcp"


# ── JSON-RPC 协议处理 ──

def _send(data: dict):
    """发送 JSON-RPC 消息到 stdout"""
    line = json.dumps(data, ensure_ascii=False, default=str)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _recv() -> dict | None:
    """从 stdin 读取一条 JSON-RPC 消息"""
    line = sys.stdin.readline()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def _response(request_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error_response(request_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


# ── 工具定义 ──

TOOLS = [
    {
        "name": "trace_scan",
        "description": (
            "扫描 bytrace/ftrace 文件的基本信息，包括事件类型、线程列表、"
            "时间范围、PID 数量等。在分析前先用此工具了解 trace 内容。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "trace_file": {
                    "type": "string",
                    "description": "trace 文件路径（支持 .ftrace 和 .ftrace.gz）",
                },
            },
            "required": ["trace_file"],
        },
    },
    {
        "name": "trace_find_gaps",
        "description": (
            "在 trace 文件中定位 dlopen 调用之间的空白间隙。"
            "间隙 = 两次 sys_exit_openat 之间的时间段，是潜在的性能瓶颈区。"
            "返回每个间隙的起始时间、结束时间、耗时、所属线程和 PID。"
            "可通过 --thread 或 --pid 参数指定目标任务。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "trace_file": {
                    "type": "string",
                    "description": "trace 文件路径",
                },
                "thread": {
                    "type": "string",
                    "description": "按线程名过滤（可选）",
                },
                "pid": {
                    "type": "integer",
                    "description": "按线程 PID 过滤（可选）",
                },
            },
            "required": ["trace_file"],
        },
    },
    {
        "name": "trace_analyze_gap",
        "description": (
            "深度分析指定的 dlopen 间隙。对间隙内的线程调度状态、I/O 事件、"
            "CPU 频率、中断等进行完整分析，自动判定耗时主导因素。\n\n"
            "输出包含：\n"
            "- 线程状态分布：Running / Runnable(等CPU) / Sleeping / DiskWait(不可中断I/O)\n"
            "- 调度统计：上下文切换、被抢占次数、抢占者\n"
            "- I/O 统计：block 事件类型和累计等待时间\n"
            "- CPU 频率：平均/最低/最高\n"
            "- 时间线切片：50ms 粒度\n"
            "- 结论：IO_DISK_WAIT / CPU_PREEMPT / SELF_WORK / MIXED，含置信度"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "trace_file": {
                    "type": "string",
                    "description": "trace 文件路径",
                },
                "gap_id": {
                    "type": "integer",
                    "description": "要分析的间隙 ID（从 trace_find_gaps 获取）",
                },
                "thread": {
                    "type": "string",
                    "description": "按线程名过滤（可选）",
                },
                "pid": {
                    "type": "integer",
                    "description": "按线程 PID 过滤（可选）",
                },
            },
            "required": ["trace_file", "gap_id"],
        },
    },
    {
        "name": "trace_slice_gap",
        "description": (
            "将单个 dlopen 间隙按指定时间粒度切割为子切片，每个切片独立分析。"
            "用于定位间隙内哪些时间段是异常的。异常切片标注为 D(disk wait) 或 R(wait CPU)。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "trace_file": {
                    "type": "string",
                    "description": "trace 文件路径",
                },
                "gap_id": {
                    "type": "integer",
                    "description": "要切割的间隙 ID",
                },
                "slice_size_ms": {
                    "type": "integer",
                    "description": "每个子切片大小（毫秒，默认 20）",
                },
                "thread": {
                    "type": "string",
                    "description": "按线程名过滤（可选）",
                },
                "pid": {
                    "type": "integer",
                    "description": "按线程 PID 过滤（可选）",
                },
            },
            "required": ["trace_file", "gap_id"],
        },
    },
]


# ── 工具实现 ──

def _tool_scan(args: dict) -> str:
    trace_file = args["trace_file"]
    if not os.path.exists(trace_file):
        return f"错误: 文件不存在: {trace_file}"

    info = scan_events(trace_file)
    return (
        f"=== trace 扫描结果 ===\n"
        f"文件: {trace_file}\n"
        f"事件总数 (扫描上限): {info['total_events']:,}\n"
        f"时间范围: {info['min_ts']:.6f} → {info['max_ts']:.6f}\n"
        f"跨度: {(info['max_ts'] - info['min_ts']) * 1000:.2f}ms\n"
        f"CPU 数: {len(info['cpus'])}\n"
        f"事件类型 ({len(info['event_types'])} 种):\n" +
        "".join(f"  - {t}\n" for t in sorted(info["event_types"])) +
        f"线程名 (前 30):\n" +
        "".join(f"  - {c}\n" for c in sorted(list(info["comms"]))[:30])
    )


def _tool_find_gaps(args: dict) -> str:
    trace_file = args["trace_file"]
    thread = args.get("thread")
    pid = args.get("pid")

    gaps = find_gaps(
        trace_file,
        target_comm=thread,
        target_pid=pid,
    )

    if not gaps:
        return "未找到 dlopen 间隙。请检查: 1) trace 中是否有 sys_exit_openat 事件 2) 线程名/PID 是否正确"

    lines = [f"找到 {len(gaps)} 个间隙:\n"]
    lines.append(f"| ID | 耗时(ms) | 线程 | PID | CPU |")
    lines.append(f"|---|---|---|---|---|")
    for g in gaps:
        lines.append(f"| {g.gap_id} | {g.duration_ms:.2f} | {g.thread} | {g.pid} | {g.cpu} |")
    return "\n".join(lines)


def _tool_analyze_gap(args: dict) -> str:
    trace_file = args["trace_file"]
    gap_id = args["gap_id"]
    thread = args.get("thread")
    pid = args.get("pid")

    gaps = find_gaps(trace_file, target_comm=thread, target_pid=pid)
    target = None
    for g in gaps:
        if g.gap_id == gap_id:
            target = g
            break

    if target is None:
        return f"未找到 gap_id={gap_id}。可用的 gap ID: {[g.gap_id for g in gaps]}"

    analysis = analyze_gap(trace_file, target)
    return generate_gap_report(analysis)


def _tool_slice_gap(args: dict) -> str:
    trace_file = args["trace_file"]
    gap_id = args["gap_id"]
    thread = args.get("thread")
    pid = args.get("pid")
    slice_size_ms = args.get("slice_size_ms", 20)

    gaps = find_gaps(trace_file, target_comm=thread, target_pid=pid)
    target = None
    for g in gaps:
        if g.gap_id == gap_id:
            target = g
            break

    if target is None:
        return f"未找到 gap_id={gap_id}"

    analysis = analyze_gap(trace_file, target)
    slices = split_gap_into_slices(analysis, slice_size_us=slice_size_ms * 1000)

    if not slices:
        return "无切片数据"

    lines = [f"Gap #{gap_id} 切分为 {len(slices)} 个 {slice_size_ms}ms 子切片:\n"]
    lines.append(f"| 切片 | 偏移(ms) | 耗时(ms) | 主导状态 | I/O数 |")
    lines.append(f"|---|---|---|---|---|")
    base = analysis.thread_slice.start_us if analysis.thread_slice else 0
    for s in slices:
        offset = s["start_us"] / 1000 - base / 1000
        lines.append(
            f"| {s['slice_id']} | {offset:.1f} | {s['duration_ms']:.1f} | "
            f"{s['dominant']} | {s['io_events']} |"
        )

    # 异常切片
    anomalies = [s for s in slices if s["dominant"] in ("D(disk wait)", "R(wait CPU)")]
    if anomalies:
        lines.append(f"\n⚠ 异常切片 ({len(anomalies)} 个):")
        for s in anomalies:
            offset = s["start_us"] / 1000 - base / 1000
            lines.append(f"  [+{offset:.1f}ms] {s['dominant']} - {s['detail']}")

    return "\n".join(lines)


TOOL_HANDLERS = {
    "trace_scan": _tool_scan,
    "trace_find_gaps": _tool_find_gaps,
    "trace_analyze_gap": _tool_analyze_gap,
    "trace_slice_gap": _tool_slice_gap,
}


# ── 请求处理 ──

def handle_request(msg: dict) -> dict | None:
    """处理一条 JSON-RPC 请求/通知，返回响应或 None"""
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params", {})

    try:
        if method == "initialize":
            return _response(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": VERSION,
                },
            })

        elif method == "notifications/initialized":
            return None  # 通知，无需响应

        elif method == "tools/list":
            return _response(req_id, {"tools": TOOLS})

        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            if tool_name not in TOOL_HANDLERS:
                return _error_response(req_id, -32601, f"Unknown tool: {tool_name}")
            result_text = TOOL_HANDLERS[tool_name](tool_args)
            return _response(req_id, {
                "content": [{"type": "text", "text": result_text}],
            })

        elif method == "ping":
            return _response(req_id, {})

        else:
            return _error_response(req_id, -32601, f"Unknown method: {method}")

    except Exception as e:
        return _error_response(req_id, -32603, f"Internal error: {e}\n{traceback.format_exc()}")


def main():
    """MCP 主循环：stdio JSON-RPC"""
    while True:
        msg = _recv()
        if msg is None:
            break
        resp = handle_request(msg)
        if resp is not None:
            _send(resp)


if __name__ == "__main__":
    main()
