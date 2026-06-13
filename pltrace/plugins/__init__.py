"""pltrace 插件系统

格式解析插件注册表，支持：
  - 内置插件自动发现
  - 用户自定义插件加载（~/.pltrace/plugins/）
  - 按扩展名/内容匹配最佳插件
  - 插件依赖检查
"""

import os
import sys
import importlib
import pkgutil
from typing import Optional

from .base import BaseFormatPlugin

_registry: dict[str, type[BaseFormatPlugin]] = {}
_initialized = False


def discover_builtin_plugins():
    """自动发现 pltrace/plugins/ 下的内置插件"""
    global _initialized
    if _initialized:
        return
    _initialized = True

    plugins_dir = os.path.dirname(__file__)
    for _, name, is_pkg in pkgutil.iter_modules([plugins_dir]):
        if name in ("base", "__init__") or is_pkg:
            continue
        try:
            mod = importlib.import_module(f".{name}", package="pltrace.plugins")
            _register_from_module(mod)
        except ImportError as e:
            pass  # 依赖缺失等，静默跳过


def discover_user_plugins():
    """加载用户自定义插件（~/.pltrace/plugins/）"""
    user_dir = os.path.expanduser("~/.pltrace/plugins")
    if not os.path.isdir(user_dir):
        return
    sys.path.insert(0, user_dir)
    for fname in sorted(os.listdir(user_dir)):
        if fname.endswith(".py") and not fname.startswith("_"):
            mod_name = fname[:-3]
            try:
                mod = importlib.import_module(mod_name)
                _register_from_module(mod)
            except ImportError:
                pass


def _register_from_module(module):
    """从模块中查找并注册所有 BaseFormatPlugin 子类"""
    for attr_name in dir(module):
        attr = getattr(module, attr_name)
        if (isinstance(attr, type) and
                issubclass(attr, BaseFormatPlugin) and
                attr is not BaseFormatPlugin and
                attr.name != "base"):
            register(attr)


def register(plugin_cls: type[BaseFormatPlugin]):
    """手动注册一个插件"""
    if plugin_cls.name in _registry:
        existing = _registry[plugin_cls.name]
        if plugin_cls.priority > existing.priority:
            _registry[plugin_cls.name] = plugin_cls
    else:
        _registry[plugin_cls.name] = plugin_cls


def unregister(name: str):
    """移除插件"""
    _registry.pop(name, None)


def list_plugins() -> list[dict]:
    """列出所有已注册的插件及其状态"""
    discover_builtin_plugins()
    discover_user_plugins()
    result = []
    for name, cls in sorted(_registry.items(), key=lambda x: -x[1].priority):
        ok, msg = cls.check_dependencies()
        result.append({
            "name": cls.name,
            "description": cls.description,
            "extensions": sorted(cls.extensions),
            "version": cls.version,
            "priority": cls.priority,
            "available": ok,
            "dependency_status": msg or "OK",
            "builtin": "pltrace.plugins" in cls.__module__,
        })
    return result


def find_plugin(filepath: str) -> Optional[type[BaseFormatPlugin]]:
    """根据文件路径查找最佳匹配插件

    匹配策略:
      1. 扩展名精确匹配（按 priority 降序）
      2. can_handle() 内容检测
      3. 返回第一个匹配的插件
    """
    discover_builtin_plugins()
    discover_user_plugins()

    ext = os.path.splitext(filepath)[-1]
    if filepath.endswith(".gz"):
        ext = os.path.splitext(filepath[:-3])[-1] + ".gz"

    candidates = sorted(_registry.values(), key=lambda c: -c.priority)

    # 1. 扩展名匹配
    for cls in candidates:
        if ext in cls.extensions:
            if cls.is_available():
                return cls

    # 2. 扩展名匹配（即使依赖缺失，也返回以给出清晰的错误信息）
    for cls in candidates:
        if ext in cls.extensions:
            return cls

    # 3. 内容检测
    for cls in candidates:
        try:
            if cls.can_handle(filepath):
                return cls
        except Exception:
            pass

    # 4. 默认：返回 ftrace 插件尝试
    return _registry.get("ftrace")


def get_plugin(name: str) -> Optional[type[BaseFormatPlugin]]:
    """按名称获取插件"""
    discover_builtin_plugins()
    discover_user_plugins()
    return _registry.get(name)


# 启动时自动发现
discover_builtin_plugins()
