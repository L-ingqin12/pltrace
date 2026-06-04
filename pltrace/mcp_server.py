"""pltrace MCP Server

将 pltrace 分析能力暴露为 MCP (Model Context Protocol) 工具，
支持 stdio 和 HTTP/SSE 两种传输协议。

启动方式:
    # stdio 模式（默认，适用于本地进程通信）
    python3 -m pltrace.mcp_server

    # HTTP 模式（适用于远程调用、容器部署）
    python3 -m pltrace.mcp_server --http --port 9020
    python3 -m pltrace.mcp_server --http --host 0.0.0.0 --port 9020

Claude Code 配置:
    {
      "mcpServers": {
        "pltrace": {
          "command": "python3",
          "args": ["-m", "pltrace.mcp_server"],
          "cwd": "/path/to/trace-analyzer"
        }
      }
    }

OpenCode 本地配置:
    {
      "mcp": {
        "pltrace": {
          "type": "local",
          "command": ["python3", "-m", "pltrace.mcp_server"]
        }
      }
    }

OpenCode HTTP 配置:
    {
      "mcp": {
        "pltrace": {
          "type": "remote",
          "url": "http://localhost:9020/mcp"
        }
      }
    }
"""

import json
import sys
import os
import traceback
import argparse
from typing import Any

# 确保可以导入同包模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pltrace.parser import scan_events
from pltrace.analyzer import find_gaps, analyze_gap, split_gap_into_slices
from pltrace.reporter import generate_gap_report

VERSION = "1.0.0"
SERVER_NAME = "pltrace-mcp"

# ──────────────────────────────────────────────
# JSON-RPC 协议核心（传输无关）
# ──────────────────────────────────────────────

def make_response(request_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def make_error(request_id: Any, code: int, message: str) -> dict:
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
                    "description": "trace 文件路径（支持 .ftrace / .hitrace / .ftrace.gz / .hitrace.gz）",
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
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "trace_file": {"type": "string", "description": "trace 文件路径"},
                "thread": {"type": "string", "description": "按线程名过滤（可选）"},
                "pid": {"type": "integer", "description": "按线程 PID 过滤（可选）"},
            },
            "required": ["trace_file"],
        },
    },
    {
        "name": "trace_analyze_gap",
        "description": (
            "深度分析指定的 dlopen 间隙。对间隙内的线程调度状态、I/O 事件、"
            "CPU 频率、中断等进行完整分析，自动判定耗时主导因素。\n\n"
            "输出包含：线程状态分布(Running/Runnable/Sleeping/DiskWait)、"
            "调度统计(上下文切换/抢占)、I/O 统计(block 事件/累计等待)、"
            "CPU 频率(平均/最低/最高)、时间线切片(50ms)、"
            "结论(IO_DISK_WAIT/CPU_PREEMPT/SELF_WORK/MIXED 含置信度)。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "trace_file": {"type": "string", "description": "trace 文件路径"},
                "gap_id": {"type": "integer", "description": "要分析的间隙 ID（从 trace_find_gaps 获取）"},
                "thread": {"type": "string", "description": "按线程名过滤（可选）"},
                "pid": {"type": "integer", "description": "按线程 PID 过滤（可选）"},
            },
            "required": ["trace_file", "gap_id"],
        },
    },
    {
        "name": "trace_slice_gap",
        "description": (
            "将单个 dlopen 间隙按指定时间粒度切割为子切片，每个切片独立分析。"
            "用于定位间隙内哪些时间段异常。异常切片标注为 D(disk wait) 或 R(wait CPU)。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "trace_file": {"type": "string", "description": "trace 文件路径"},
                "gap_id": {"type": "integer", "description": "要切割的间隙 ID"},
                "slice_size_ms": {"type": "integer", "description": "每个子切片大小（毫秒，默认 20）"},
                "thread": {"type": "string", "description": "按线程名过滤（可选）"},
                "pid": {"type": "integer", "description": "按线程 PID 过滤（可选）"},
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
        f"事件总数: {info['total_events']:,}\n"
        f"时间范围: {info['min_ts']:.6f} → {info['max_ts']:.6f}\n"
        f"跨度: {(info['max_ts'] - info['min_ts']) * 1000:.2f}ms\n"
        f"CPU 数: {len(info['cpus'])}\n"
        f"事件类型 ({len(info['event_types'])} 种):\n" +
        "".join(f"  - {t}\n" for t in sorted(info["event_types"])) +
        f"线程名 (前 30):\n" +
        "".join(f"  - {c}\n" for c in sorted(list(info["comms"]))[:30])
    )


def _tool_find_gaps(args: dict) -> str:
    gaps = find_gaps(
        args["trace_file"],
        target_comm=args.get("thread"),
        target_pid=args.get("pid"),
    )
    if not gaps:
        return "未找到 dlopen 间隙。检查: 1) 是否有 sys_exit_openat 事件 2) 线程名/PID 是否正确"
    lines = [f"找到 {len(gaps)} 个间隙:\n"]
    lines.append("| ID | 耗时(ms) | 线程 | PID | CPU |")
    lines.append("|---|---|---|---|---|")
    for g in gaps:
        lines.append(f"| {g.gap_id} | {g.duration_ms:.2f} | {g.thread} | {g.pid} | {g.cpu} |")
    return "\n".join(lines)


def _tool_analyze_gap(args: dict) -> str:
    gaps = find_gaps(
        args["trace_file"],
        target_comm=args.get("thread"),
        target_pid=args.get("pid"),
    )
    target = next((g for g in gaps if g.gap_id == args["gap_id"]), None)
    if target is None:
        return f"未找到 gap_id={args['gap_id']}。可用: {[g.gap_id for g in gaps]}"
    return generate_gap_report(analyze_gap(args["trace_file"], target))


def _tool_slice_gap(args: dict) -> str:
    gaps = find_gaps(
        args["trace_file"],
        target_comm=args.get("thread"),
        target_pid=args.get("pid"),
    )
    target = next((g for g in gaps if g.gap_id == args["gap_id"]), None)
    if target is None:
        return f"未找到 gap_id={args['gap_id']}"
    analysis = analyze_gap(args["trace_file"], target)
    slice_us = (args.get("slice_size_ms", 20)) * 1000
    slices = split_gap_into_slices(analysis, slice_size_us=slice_us)

    if not slices:
        return "无切片数据"
    lines = [f"Gap #{args['gap_id']} 切分为 {len(slices)} 个 {args.get('slice_size_ms', 20)}ms 子切片:\n"]
    lines.append("| 切片 | 偏移(ms) | 耗时(ms) | 主导状态 | I/O数 |")
    lines.append("|---|---|---|---|---|")
    base = analysis.thread_slice.start_us if analysis.thread_slice else 0
    for s in slices:
        offset = s["start_us"] / 1000 - base / 1000
        lines.append(f"| {s['slice_id']} | {offset:.1f} | {s['duration_ms']:.1f} | {s['dominant']} | {s['io_events']} |")
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


# ── 核心请求处理（传输无关）──

def handle_request(msg: dict) -> dict | None:
    """处理一条 JSON-RPC 请求/通知，返回响应或 None（通知不需要响应）"""
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params", {})

    try:
        if method == "initialize":
            return make_response(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": VERSION},
            })

        elif method == "notifications/initialized":
            return None

        elif method == "tools/list":
            return make_response(req_id, {"tools": TOOLS})

        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            if tool_name not in TOOL_HANDLERS:
                return make_error(req_id, -32601, f"Unknown tool: {tool_name}")
            result_text = TOOL_HANDLERS[tool_name](tool_args)
            return make_response(req_id, {
                "content": [{"type": "text", "text": result_text}],
            })

        elif method == "ping":
            return make_response(req_id, {})

        else:
            return make_error(req_id, -32601, f"Unknown method: {method}")

    except Exception as e:
        return make_error(
            req_id, -32603,
            f"Internal error: {e}\n{traceback.format_exc()}"
        )


# ──────────────────────────────────────────────
# stdio 传输
# ──────────────────────────────────────────────

def _stdio_send(data: dict):
    line = json.dumps(data, ensure_ascii=False, default=str)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _stdio_recv() -> dict | None:
    line = sys.stdin.readline()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def stdio_main():
    while True:
        msg = _stdio_recv()
        if msg is None:
            break
        resp = handle_request(msg)
        if resp is not None:
            _stdio_send(resp)


# ──────────────────────────────────────────────
# HTTP/SSE 传输
# ──────────────────────────────────────────────

from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread


class MCPHTTPHandler(BaseHTTPRequestHandler):
    """MCP Streamable HTTP 传输处理器

    路由:
      POST /mcp  — JSON-RPC 请求（Accept: application/json）
      POST /mcp  — SSE 流式响应（Accept: text/event-stream）
      GET  /mcp  — SSE 通道（接收 server→client 通知，如果将来有）
      GET  /health — 健康检查
    """

    # 类级别属性，由主线程设置
    server_instance = None  # type: MCPHTTPServer | None

    def log_message(self, format, *args):
        """抑制默认日志，改用简洁格式"""
        print(f"[pltrace-http] {self.client_address[0]} - {format % args}", file=sys.stderr)

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_sse(self, data: dict):
        """发送一条 SSE 事件"""
        payload = json.dumps(data, ensure_ascii=False, default=str)
        msg = f"data: {payload}\n\n".encode("utf-8")
        self.wfile.write(msg)
        self.wfile.flush()

    def _send_sse_response(self, response_data: dict):
        """将 JSON-RPC 响应包装为 SSE 流"""
        body = json.dumps(response_data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        # 对于非流式 SSE 响应，直接发送完整 body
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        """CORS 预检"""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "server": SERVER_NAME, "version": VERSION})
        elif self.path == "/mcp":
            # SSE 通道 — 用于 server→client 推送（当前无持久推送需求，返回 200 后关闭）
            self._send_sse_response({"jsonrpc": "2.0", "id": None, "result": {"message": "SSE channel ready"}})
        elif self.path == "/":
            self._send_json(200, {
                "server": SERVER_NAME,
                "version": VERSION,
                "endpoints": {
                    "mcp": "POST /mcp (JSON-RPC)",
                    "sse": "GET /mcp (Server-Sent Events)",
                    "health": "GET /health",
                },
                "tools": [t["name"] for t in TOOLS],
            })
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/mcp":
            self._send_json(404, {"error": "not found"})
            return

        # 读取请求体
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._send_json(400, {"error": "empty body"})
            return
        raw_body = self.rfile.read(content_length)

        try:
            msg = json.loads(raw_body)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid JSON"})
            return

        # 处理请求
        resp = handle_request(msg)

        # 根据 Accept 头决定响应格式
        accept = self.headers.get("Accept", "application/json")

        if resp is None:
            # 通知无需响应，返回 202
            self._send_json(202, {"jsonrpc": "2.0", "id": None, "result": None})
        elif "text/event-stream" in accept:
            self._send_sse_response(resp)
        else:
            self._send_json(200, resp)


class MCPHTTPServer:
    """MCP HTTP 服务器包装"""

    def __init__(self, host: str = "127.0.0.1", port: int = 9020):
        self.host = host
        self.port = port
        self._httpd: HTTPServer | None = None
        self._thread: Thread | None = None

    def start(self):
        MCPHTTPHandler.server_instance = self
        self._httpd = HTTPServer((self.host, self.port), MCPHTTPHandler)
        print(f"[pltrace-mcp] HTTP server listening on http://{self.host}:{self.port}")
        print(f"[pltrace-mcp] Endpoints:")
        print(f"  POST /mcp         — JSON-RPC")
        print(f"  GET  /mcp         — SSE channel")
        print(f"  GET  /health      — Health check")
        print(f"  GET  /            — Server info")
        try:
            self._httpd.serve_forever()
        except KeyboardInterrupt:
            pass

    def start_in_thread(self):
        self._thread = Thread(target=self.start, daemon=True)
        self._thread.start()
        return self._thread

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd = None


def http_main(host: str, port: int):
    server = MCPHTTPServer(host, port)
    server.start()


# ──────────────────────────────────────────────
# 入口
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="pltrace MCP Server - stdio / HTTP 双传输",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # stdio 模式（默认）
  python3 -m pltrace.mcp_server

  # HTTP 模式（本地）
  python3 -m pltrace.mcp_server --http

  # HTTP 模式（指定端口和绑定地址）
  python3 -m pltrace.mcp_server --http --port 9020 --host 0.0.0.0
""",
    )
    parser.add_argument("--http", action="store_true", help="启用 HTTP 传输模式")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP 绑定地址 (默认: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9020, help="HTTP 端口 (默认: 9020)")
    args = parser.parse_args()

    if args.http:
        http_main(args.host, args.port)
    else:
        stdio_main()


if __name__ == "__main__":
    main()
