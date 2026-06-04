# pltrace - 鸿蒙 bytrace/ftrace 间隙分析工具

快速分析鸿蒙系统 bytrace 产出的 ftrace 文件，定位 dlopen 之间的空白间隙，自动判定耗时是 I/O 阻塞还是 CPU 抢占导致。

## 安装

```bash
pip install -e .
```

或者直接运行：

```bash
python3 -m pltrace.main <command> [args...]
```

## 快速开始

```bash
# 1. 扫描 trace 文件，了解有哪些线程和事件
./run_pltrace.sh scan trace.ftrace

# 2. 查找 dlopen 之间的间隙
./run_pltrace.sh gaps trace.ftrace --thread my_worker

# 3. 完整分析
./run_pltrace.sh analyze trace.ftrace --thread my_worker

# 4. 细粒度切片（10ms 每片）
./run_pltrace.sh slice trace.ftrace --gap-id 3 --size 10
```

## 命令说明

### `scan` - 扫描基本信息

```
pltrace scan <trace_file>
```

输出 trace 文件的事件类型、线程列表、时间范围、PID 数量等元信息。

### `gaps` - 定位间隙

```
pltrace gaps <trace_file> [--thread NAME] [--pid PID] [--output FILE]
```

列出两个 dlopen（sys_exit_openat）之间的所有间隙，包括起始时间、耗时、所属线程。

### `analyze` - 完整分析

```
pltrace analyze <trace_file> [--thread NAME] [--pid PID] [--gap-id N] [--output-dir DIR]
```

对每个间隙进行深度分析，输出：
- **线程状态分布**：Running / Runnable(等CPU) / Sleeping(可中断) / DiskWait(不可中断I/O)
- **调度统计**：上下文切换次数、被抢占次数、抢占者线程名
- **I/O 统计**：block 层事件数量和累计等待时间
- **CPU 频率**：间隙内的平均/最低/最高频率
- **时间线切片**：50ms 粒度切片，标注异常片
- **结论**：主导因素 + 置信度

### `slice` - 细粒度切片

```
pltrace slice <trace_file> --gap-id N [--thread NAME] [--size MS] [--output FILE]
```

将单个间隙按指定粒度（默认 20ms）切割为子切片，显示每片的线程主导状态。

## 指定目标任务

所有命令均支持 `--thread/-t` 和 `--pid/-p` 参数来锁定分析目标：

```bash
# 按线程名过滤
pltrace analyze trace.ftrace -t dlopen_thread

# 按 PID 过滤
pltrace analyze trace.ftrace -p 12345 --gap-id 3

# 不指定则分析全部
pltrace gaps trace.ftrace
```

## MCP Server（AI 助手集成）

pltrace 可作为 MCP 服务器运行，支持 **stdio** 和 **HTTP/SSE** 两种传输协议。
兼容 **Claude Code**、**OpenCode** 以及所有支持 MCP 标准的客户端。

### 启动方式

```bash
# stdio 模式（默认，本地进程通信）
python3 -m pltrace.mcp_server

# HTTP 模式（远程调用、容器部署）
python3 -m pltrace.mcp_server --http --port 9020
python3 -m pltrace.mcp_server --http --host 0.0.0.0 --port 9020
```

HTTP 模式端点：

| 端点 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 服务器信息和工具列表 |
| `/health` | GET | 健康检查 |
| `/mcp` | POST | JSON-RPC 请求（`Accept: application/json`） |
| `/mcp` | POST | SSE 流式响应（`Accept: text/event-stream`） |
| `/mcp` | GET | SSE 通道 |

### 在 Claude Code 中配置（stdio）

在 `~/.claude/settings.json` 或项目的 `.claude/settings.json` 中添加：

```json
{
  "mcpServers": {
    "pltrace": {
      "command": "python3",
      "args": ["-m", "pltrace.mcp_server"],
      "cwd": "/path/to/pltrace"
    }
  }
}
```

### 在 OpenCode 中配置

**本地模式（stdio）：**

```json
{
  "mcp": {
    "pltrace": {
      "type": "local",
      "command": ["python3", "-m", "pltrace.mcp_server"],
      "enabled": true
    }
  }
}
```

**远程模式（HTTP）：**

```bash
# 先在服务器上启动 HTTP 模式
python3 -m pltrace.mcp_server --http --host 0.0.0.0 --port 9020
```

然后在 `opencode.json` 中配置：

```json
{
  "mcp": {
    "pltrace": {
      "type": "remote",
      "url": "http://localhost:9020/mcp",
      "enabled": true
    }
  }
}
```

配置文件参考：[opencode.example.json](opencode.example.json)

### 传输协议对比

| | stdio | HTTP |
|---|---|---|
| 通信方式 | stdin/stdout 管道 | HTTP POST + SSE |
| 适用场景 | 本地 IDE/CLI 集成 | 容器部署、远程调用 |
| 启动方式 | `python3 -m pltrace.mcp_server` | `python3 -m pltrace.mcp_server --http` |
| 并发支持 | 单连接 | 多连接（线程池） |

### Claude Code vs OpenCode 配置差异

| 配置项 | Claude Code | OpenCode |
|--------|-------------|----------|
| 顶层键 | `mcpServers` | `mcp` |
| 命令格式 | `"command": "python3"` + `"args": [...]` | `"command": ["python3", ...]` |
| 服务器类型 | 无需声明 | `"type": "local"` / `"remote"` |
| 远程 HTTP | 不支持 | `"type": "remote"` + `"url"` |
| 环境变量 | `"env": {}` | `"environment": {}` |
| 开关 | 无 | `"enabled": true/false` |

### 可用 MCP 工具

| 工具 | 说明 |
|------|------|
| `trace_scan` | 扫描 trace 基本信息（事件类型、线程、时间范围） |
| `trace_find_gaps` | 定位 dlopen 间隙，支持按线程名/PID 过滤 |
| `trace_analyze_gap` | 完整分析 gap，输出状态分布 + I/O + 调度 + 结论 |
| `trace_slice_gap` | 细粒度切割 gap，标注异常时间片 |

### MCP 使用示例

配置后，在 AI 助手中直接对话：

> 帮我看下这个 trace 文件 `/path/to/trace.ftrace` 里 dlopen 之间的耗时是什么原因导致的？

AI 会自动调用 `trace_find_gaps` 定位间隙，再调用 `trace_analyze_gap` 深度分析，最后给出结论。

## 输出文件

`analyze` 命令在输出目录生成：

```
pltrace_output/
├── gap_0001_report.txt    # 文本报告
├── gap_0001.json           # JSON 数据
├── gap_0002_report.txt
├── gap_0002.json
├── ...
└── summary.json            # 汇总摘要
```

## 分析原理

工具基于 ftrace 中的内核调度事件进行分析：

| 数据来源 | 分析内容 |
|---------|---------|
| `sched_switch` | 线程状态（R/S/D），上下文切换，抢占 |
| `block_rq_issue / block_rq_complete` | 磁盘 I/O 精确耗时 |
| `cpu_frequency` | CPU 频率变化（降频检测） |
| `irq_handler_entry` | 中断次数 |

### 判定逻辑

```
线程状态 D > 30%   → IO_DISK_WAIT  (磁盘 I/O)
block I/O > 20%    → IO_DISK_WAIT  (磁盘 I/O)
线程状态 S > 40%   → IO_OR_LOCK_WAIT (网络I/O/锁)
线程状态 R > 25%   → CPU_PREEMPT   (被抢占)
Running > 60%      → SELF_WORK     (自身业务)
其他               → MIXED         (混合因素)
```

## 支持格式

- bytrace 文本输出 (.ftrace)
- gzip 压缩的 trace (.ftrace.gz)
- 兼容标准 ftrace trace-cmd 格式

## 测试

```bash
# 生成模拟数据并测试
python3 sample/generate_demo_trace.py --scenario io_wait   sample/demo_io.ftrace
python3 sample/generate_demo_trace.py --scenario cpu_preempt sample/demo_cpu.ftrace
python3 sample/generate_demo_trace.py --scenario mixed      sample/demo_mixed.ftrace

# 分析
python3 -m pltrace.main analyze sample/demo_io.ftrace -o output/
```

## 许可

MIT
