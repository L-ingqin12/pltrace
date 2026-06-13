"""pltrace 格式解析插件基类

所有 trace 格式解析器必须继承 BaseFormatPlugin 并实现:
  - name: 插件名称
  - extensions: 支持的文件扩展名集合
  - can_handle(filepath) -> bool
  - iter_events(filepath, event_filter) -> Iterator[TraceEvent]

插件可放置在:
  1. pltrace/plugins/           （内置插件）
  2. ~/.pltrace/plugins/        （用户自定义插件）
"""

from abc import ABC, abstractmethod
from typing import Iterator, Optional, Any


class BaseFormatPlugin(ABC):
    """trace 格式解析插件基类"""

    # ── 必须覆盖的类属性 ──

    name: str = "base"
    extensions: set = set()
    description: str = ""
    version: str = "1.0.0"
    priority: int = 50

    # ── 可选覆盖的类属性 ──

    dependencies: list = []
    platforms: list = ["linux", "darwin", "win32"]

    @classmethod
    @abstractmethod
    def can_handle(cls, filepath: str) -> bool:
        """判断此插件能否解析该文件"""
        ...

    @classmethod
    @abstractmethod
    def iter_events(cls, filepath: str, event_filter: Optional[set] = None) -> Iterator[Any]:
        """流式解析文件，yield TraceEvent"""
        ...

    @classmethod
    def scan_info(cls, filepath: str) -> dict:
        return {
            "plugin": cls.name,
            "file": filepath,
            "format": cls.description,
        }

    @classmethod
    def check_dependencies(cls) -> tuple[bool, str]:
        """检查插件依赖是否满足

        Returns:
            (可用, 说明信息) 元组
        """
        if not cls.dependencies:
            return True, ""
        missing = []
        for dep in cls.dependencies:
            # 检查外部命令
            import shutil
            if not shutil.which(dep):
                missing.append(dep)
        if missing:
            return False, f"Missing dependencies: {', '.join(missing)}"
        return True, ""

    @classmethod
    def is_available(cls) -> bool:
        """插件当前是否可用"""
        ok, _ = cls.check_dependencies()
        if not ok:
            return False
        import sys
        if sys.platform not in cls.platforms:
            return False
        return True
