"""
manager模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import importlib
import sys
import inspect
from pathlib import Path
from typing import Dict, List, Optional
from utils.logger import log
from plugins.base import BasePlugin, PluginTool, ExamplePlugin


class PluginManager:
    """插件管理器"""

    def __init__(self, plugins_dir: Optional[str] = None):
        """初始化PluginManager实例。

        Args:
            self: 类实例。
        """
        self.plugins_dir = Path(plugins_dir) if plugins_dir else Path(__file__).parent
        self.plugins: Dict[str, BasePlugin] = {}
        self._builtin_plugins = [ExamplePlugin]
        log.info(f"插件管理器初始化: {self.plugins_dir}")

    def load_builtin_plugins(self):
        """加载内置插件"""
        for plugin_class in self._builtin_plugins:
            try:
                plugin = plugin_class()
                self.plugins[plugin.name] = plugin
                log.info(f"内置插件加载: {plugin.name} v{plugin.version} ({len(plugin.tools)}个工具)")
            except Exception as e:
                log.error(f"内置插件加载失败 {plugin_class.__name__}: {e}")

    def load_external_plugin(self, plugin_path: str) -> bool:
        """
        加载外部插件
        plugin_path: 插件文件路径或目录路径
        """
        try:
            plugin_path = Path(plugin_path)
            if not plugin_path.exists():
                log.error(f"插件路径不存在: {plugin_path}")
                return False

            # 添加到系统路径
            if str(plugin_path.parent) not in sys.path:
                sys.path.insert(0, str(plugin_path.parent))

            # 动态导入
            module_name = plugin_path.stem
            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # 查找插件类（继承BasePlugin的类）
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and
                    issubclass(attr, BasePlugin) and
                    attr != BasePlugin):
                    plugin = attr()
                    self.plugins[plugin.name] = plugin
                    log.info(f"外部插件加载: {plugin.name} v{plugin.version} ({len(plugin.tools)}个工具)")
                    return True

            log.error(f"未在 {plugin_path} 中找到插件类")
            return False

        except Exception as e:
            log.error(f"外部插件加载失败: {e}")
            return False

    def get_all_tools(self) -> List[PluginTool]:
        """获取所有已启用插件的工具"""
        all_tools = []
        for plugin in self.plugins.values():
            if plugin.enabled:
                all_tools.extend(plugin.get_tools())
        return all_tools

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """获取指定插件"""
        return self.plugins.get(name)

    def enable_plugin(self, name: str) -> bool:
        """启用插件"""
        plugin = self.plugins.get(name)
        if plugin:
            plugin.enabled = True
            log.info(f"插件已启用: {name}")
            return True
        return False

    def disable_plugin(self, name: str) -> bool:
        """禁用插件"""
        plugin = self.plugins.get(name)
        if plugin:
            plugin.enabled = False
            log.info(f"插件已禁用: {name}")
            return True
        return False

    def list_plugins(self) -> List[Dict]:
        """列出所有插件"""
        return [plugin.get_metadata() for plugin in self.plugins.values()]

    async def call_tool(self, tool_name: str, **kwargs) -> Optional[Dict]:
        """调用插件工具"""
        for plugin in self.plugins.values():
            if not plugin.enabled:
                continue
            for tool in plugin.tools:
                if tool.name == tool_name:
                    import asyncio
                    if inspect.iscoroutinefunction(tool.handler):
                        return await tool.handler(**kwargs)
                    else:
                        return tool.handler(**kwargs)
        return None

    def has_tool(self, tool_name: str) -> bool:
        """检查是否存在指定工具"""
        return any(
            tool.name == tool_name
            for plugin in self.plugins.values()
            if plugin.enabled
            for tool in plugin.tools
        )


# 全局插件管理器实例
plugin_manager = PluginManager()
plugin_manager.load_builtin_plugins()
