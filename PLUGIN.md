# pltrace 插件开发指南

pltrace 采用插件架构支持多种 trace 格式。本文档说明如何编写、安装和使用格式解析插件。

## 目录

- [快速开始](#快速开始)
- [插件架构](#插件架构)
- [内置插件](#内置插件)
- [编写自定义插件](#编写自定义插件)
- [插件开发示例](#插件开发示例)
- [插件生命周期](#插件生命周期)
- [接入指引](#接入指引)

## 快速开始

```bash
# 查看已安装的插件
pltrace plugins
pltrace plugins --verbose

# 列出插件能力和状态
python3 -c "
from pltrace.plugins import list_plugins
import json
print(json.dumps(list_plugins(), indent=2, ensure_ascii=False))
"
```

## 插件架构

```
pltrace/
├── plugins/
│   ├── __init__.py          # 插件注册表、自动发现
│   ├── base.py              # BaseFormatPlugin 抽象基类
│   ├── ftrace_plugin.py     # ftrace 文本格式（内置）
│   └── sys_plugin.py        # .sys 二进制格式（需 trace_streamer）
├── parser.py                # 核心解析器（委托给插件）
└── sys_parser.py            # trace_streamer SQLite 解析逻辑

~/.pltrace/plugins/          # 用户自定义插件目录
└── my_format.py             # 第三方格式插件
```

### 核心流程

```
文件 → find_plugin(filepath)
         ├─ 扩展名匹配
         ├─ can_handle() 内容检测
         └─ 返回最佳匹配插件
              │
              ├─ plugin.is_available()? → iter_events()
              └─ 不可用 → 清晰错误 + 安装指引
```

## 内置插件

| 插件名 | 扩展名 | 说明 | 依赖 |
|--------|--------|------|------|
| `ftrace` | `.ftrace`, `.hitrace`, `.txt`, `.log` | bytrace/hitrace --text 输出 | 无 |
| `sys` | `.sys`, `.htrace` | HiProfiler 二进制 protobuf 格式 | `trace_streamer` |

### sys 插件依赖安装

```bash
# 1. 下载 trace_streamer
wget https://gitee.com/openharmony/developtools_smartperf_host/releases/download/v5.0.0/trace_streamer_binary.zip

# 2. 解压
unzip trace_streamer_binary.zip

# 3. 添加到 PATH 或保存在项目目录
chmod +x trace_streamer
sudo mv trace_streamer /usr/local/bin/

# 4. 验证
trace_streamer --help
```

## 编写自定义插件

### 1. 继承 BaseFormatPlugin

```python
# my_format_plugin.py
from pltrace.plugins.base import BaseFormatPlugin
from pltrace.parser import TraceEvent  # 复用标准事件类型

class MyFormatPlugin(BaseFormatPlugin):
    """自定义 trace 格式解析插件"""

    # ── 必须定义 ──
    name = "my_format"                    # 唯一标识
    extensions = {".myfmt", ".mft"}       # 支持的文件扩展名
    description = "我的自定义 trace 格式"
    priority = 50                          # 优先级 (0-100)

    @classmethod
    def can_handle(cls, filepath: str) -> bool:
        """检测文件是否为此格式"""
        # 方法 1: 扩展名（自动匹配，无需在此实现）
        # 方法 2: 魔数检测
        with open(filepath, "rb") as f:
            magic = f.read(4)
        return magic == b"MYFT"  # 自定义魔数

    @classmethod
    def iter_events(cls, filepath, event_filter=None):
        """解析文件，yield TraceEvent"""
        with open(filepath) as f:
            for line in f:
                # 解析逻辑...
                ev = TraceEvent(
                    timestamp=float(ts),
                    cpu=int(cpu),
                    pid=pid,
                    tid=tid,
                    comm=comm,
                    flags="....",
                    event_name=event_name,
                    event_data={},
                    raw_line=line,
                )
                if event_filter and ev.event_name not in event_filter:
                    continue
                yield ev
```

### 2. 安装插件

**方法 A: 放入用户插件目录**
```bash
mkdir -p ~/.pltrace/plugins/
cp my_format_plugin.py ~/.pltrace/plugins/
```

**方法 B: 放入内置插件目录**
```bash
cp my_format_plugin.py pltrace/plugins/
```

**方法 C: 通过 Python 注册**
```python
from pltrace.plugins import register
from my_format_plugin import MyFormatPlugin
register(MyFormatPlugin)
```

### 3. 验证
```bash
pltrace plugins          # 应该看到 my_format
pltrace scan test.myfmt   # 测试解析
```

## 插件开发示例

### 示例 1: JSON trace 格式插件

```python
"""JSON trace 格式解析插件"""
import json
from pltrace.plugins.base import BaseFormatPlugin
from pltrace.parser import TraceEvent

class JSONTracePlugin(BaseFormatPlugin):
    name = "json_trace"
    extensions = {".json", ".jsontrace"}
    description = "JSON 格式 trace（每行一个事件）"
    priority = 60

    @classmethod
    def can_handle(cls, filepath):
        with open(filepath) as f:
            line = f.readline().strip()
        return line.startswith("{") and "timestamp" in line

    @classmethod
    def iter_events(cls, filepath, event_filter=None):
        with open(filepath) as f:
            for line in f:
                obj = json.loads(line.strip())
                if not obj:
                    continue
                ev = TraceEvent(
                    timestamp=obj.get("ts", 0),
                    cpu=obj.get("cpu", 0),
                    pid=obj.get("pid", 0),
                    tid=obj.get("tid", 0),
                    comm=obj.get("comm", ""),
                    flags="....",
                    event_name=obj.get("event", "unknown"),
                    event_data=obj.get("data", {}),
                    raw_line=line,
                )
                if event_filter and ev.event_name not in event_filter:
                    continue
                yield ev
```

### 示例 2: Perfetto trace 格式插件（带依赖）

```python
"""Perfetto trace 格式插件（需 trace_processor）"""
import subprocess
import json
from pltrace.plugins.base import BaseFormatPlugin
from pltrace.parser import TraceEvent

class PerfettoPlugin(BaseFormatPlugin):
    name = "perfetto"
    extensions = {".perfetto-trace", ".pftrace"}
    description = "Perfetto/SysTace 二进制 trace（需 trace_processor）"
    priority = 70
    dependencies = ["trace_processor_shell"]

    @classmethod
    def can_handle(cls, filepath):
        with open(filepath, "rb") as f:
            return f.read(2) == b"\x0a\x00"

    @classmethod
    def iter_events(cls, filepath, event_filter=None):
        # 调用 trace_processor_shell 导出 JSON
        result = subprocess.run(
            ["trace_processor_shell", "--run-metrics", "android_trace_metrics",
             filepath, "--stdout"],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        for row in data.get("events", []):
            ev = TraceEvent(...)
            yield ev
```

## 插件生命周期

```
1. 注册阶段
   pltrace 启动 → discover_builtin_plugins() → discover_user_plugins()
   → 导入 .py 文件 → register() 注册每个 BaseFormatPlugin 子类

2. 匹配阶段
   文件输入 → find_plugin(filepath)
   → 按 priority 降序遍历插件
   → 扩展名匹配 OR can_handle() 返回 True
   → 返回最佳插件

3. 解析阶段
   plugin.iter_events(filepath) → yield TraceEvent
   → 分析引擎消费事件流

4. 错误处理
   插件不可用时：
   - 返回清晰的依赖安装指引
   - 给出替代方案（如 bytrace 重新抓取）
```

## 接入指引

### 为 AI 助手接入新格式

如果想让 Claude Code / OpenCode 等 AI 自动使用你的插件：

1. **编写插件文件** 并放入 `~/.pltrace/plugins/`
2. **在 MCP 配置中引用**：

```json
{
  "mcpServers": {
    "pltrace": {
      "command": "python3",
      "args": ["-m", "pltrace.mcp_server"],
      "env": {
        "PLTRACE_PLUGIN_DIR": "/custom/plugins"
      }
    }
  }
}
```

3. **AI 自动调用**：

> 帮我分析这个自定义格式的 trace 文件 `test.myfmt`

AI 会通过 MCP 调用 `trace_scan` → `find_plugin` → `MyFormatPlugin.iter_events()` → 分析。

### 在资源具备时的开发路线

当以下资源就绪后，可进一步扩展：

| 资源 | 开发目标 | 参考文件 |
|------|---------|---------|
| `trace_streamer` 已安装 | 完善 `.sys` 自动转换链路 | `plugins/sys_plugin.py`, `sys_parser.py` |
| 真实 `.sys` 测试文件 | 验证 sys_plugin 事件提取准确性 | `sys_parser.parse_sys_db()` |
| Perfetto trace_processor | 添加 Perfetto/SysTace 格式插件 | 示例 2 |
| 自定义日志格式 | 编写专用解析插件 | 示例 1 |
| 多平台 trace 数据 | 添加 Android systrace, XCode instruments 等插件 | `plugins/` 目录 |

### 插件 API 参考

```python
class BaseFormatPlugin(ABC):
    name: str              # 唯一名称
    extensions: set        # 支持扩展名
    description: str       # 说明
    priority: int          # 优先级 (0-100)
    dependencies: list     # 外部依赖

    @classmethod
    def can_handle(cls, filepath: str) -> bool: ...
    @classmethod
    def iter_events(cls, filepath, event_filter=None) -> Iterator[TraceEvent]: ...
    @classmethod
    def scan_info(cls, filepath) -> dict: ...
    @classmethod
    def check_dependencies(cls) -> tuple[bool, str]: ...
    @classmethod
    def is_available(cls) -> bool: ...
```
