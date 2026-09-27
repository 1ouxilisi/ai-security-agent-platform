"""
plugin_system工具函数模块，提供通用的辅助函数和工具类。

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
import inspect
import json
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Type
from pathlib import Path
from utils.logger import log


class Plugin(ABC):
    """插件基类 - 所有安全工具插件必须继承此类"""

    # 插件元数据（子类必须定义）
    name: str = ""
    version: str = "1.0.0"
    description: str = ""
    author: str = ""
    category: str = "misc"  # recon, exploit, verification, reporting, misc
    tags: List[str] = []

    def __init__(self, config: dict = None):
        """初始化Plugin实例。

        Args:
            self: 类实例。
        """
        self.config = config or {}
        self._initialized = False

    @abstractmethod
    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        执行插件功能
        返回: {"success": bool, "result": Any, "error": str}
        """
        pass

    def initialize(self) -> bool:
        """初始化插件（可选重写）"""
        self._initialized = True
        return True

    def cleanup(self):
        """清理插件资源（可选重写）"""
        pass

    def get_parameters(self) -> Dict[str, Any]:
        """获取插件参数定义（可选重写）"""
        return {}

    def get_help(self) -> str:
        """获取插件帮助信息"""
        params = self.get_parameters()
        help_text = f"## {self.name} v{self.version}\n\n"
        help_text += f"{self.description}\n\n"
        help_text += f"**分类**: {self.category}\n"
        help_text += f"**作者**: {self.author}\n"
        if self.tags:
            help_text += f"**标签**: {', '.join(self.tags)}\n"
        if params:
            help_text += f"\n### 参数\n\n"
            for name, info in params.items():
                help_text += f"- `{name}`: {info.get('description', '')} "
                help_text += f"(类型: {info.get('type', 'any')}"
                if info.get('required'):
                    help_text += ", 必填"
                help_text += ")\n"
        return help_text

    def is_available(self) -> bool:
        """检查插件是否可用（可选重写，如检查依赖工具是否安装）"""
        return True


class PluginManager:
    """插件管理器"""

    def __init__(self, plugin_dir: str = None):
        """初始化PluginManager实例。

        Args:
            self: 类实例。
        """
        if plugin_dir is None:
            plugin_dir = str(Path(__file__).parent.parent / "plugins")
        self.plugin_dir = plugin_dir
        self._plugins: Dict[str, Plugin] = {}
        self._plugin_classes: Dict[str, Type[Plugin]] = {}
        self._ensure_plugin_dir()

    def _ensure_plugin_dir(self):
        """确保插件目录存在"""
        Path(self.plugin_dir).mkdir(parents=True, exist_ok=True)
        # 创建__init__.py
        init_file = Path(self.plugin_dir) / "__init__.py"
        if not init_file.exists():
            init_file.write_text("# AI Hacking Agent Plugins\n")

    def register_plugin(self, plugin_class: Type[Plugin]) -> bool:
        """注册插件类"""
        if not issubclass(plugin_class, Plugin):
            log.error(f"插件类必须继承Plugin基类: {plugin_class}")
            return False

        if not plugin_class.name:
            log.error(f"插件必须定义name属性: {plugin_class}")
            return False

        if plugin_class.name in self._plugin_classes:
            log.warning(f"插件已存在，将覆盖: {plugin_class.name}")

        self._plugin_classes[plugin_class.name] = plugin_class
        log.info(f"✅ 插件已注册: {plugin_class.name} v{plugin_class.version}")
        return True

    def load_plugin(self, name: str, config: dict = None) -> Optional[Plugin]:
        """加载并实例化插件"""
        if name not in self._plugin_classes:
            log.error(f"插件未注册: {name}")
            return None

        try:
            plugin_class = self._plugin_classes[name]
            plugin = plugin_class(config)
            if plugin.initialize():
                self._plugins[name] = plugin
                log.info(f"✅ 插件已加载: {name}")
                return plugin
            else:
                log.error(f"插件初始化失败: {name}")
                return None
        except Exception as e:
            log.error(f"加载插件失败 {name}: {e}")
            return None

    def unload_plugin(self, name: str) -> bool:
        """卸载插件"""
        if name in self._plugins:
            try:
                self._plugins[name].cleanup()
            except Exception as e:
                log.error(f"插件清理失败 {name}: {e}")
            del self._plugins[name]
            log.info(f"插件已卸载: {name}")
            return True
        return False

    def execute_plugin(self, name: str, **kwargs) -> Dict[str, Any]:
        """执行插件"""
        if name not in self._plugins:
            # 尝试自动加载
            plugin = self.load_plugin(name)
            if not plugin:
                return {"success": False, "error": f"插件未加载: {name}"}

        plugin = self._plugins[name]
        if not plugin.is_available():
            return {"success": False, "error": f"插件不可用: {name}"}

        try:
            result = plugin.execute(**kwargs)
            if not isinstance(result, dict):
                result = {"success": True, "result": result}
            return result
        except Exception as e:
            log.error(f"插件执行失败 {name}: {e}")
            return {"success": False, "error": str(e)}

    def discover_plugins(self) -> List[str]:
        """自动发现插件目录中的插件"""
        discovered = []
        plugin_path = Path(self.plugin_dir)

        if not plugin_path.exists():
            return discovered

        # 扫描Python文件
        for py_file in plugin_path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue

            try:
                module_name = f"plugins.{py_file.stem}"
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    # 查找Plugin子类
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, Plugin) and obj != Plugin and obj.name:
                            if self.register_plugin(obj):
                                discovered.append(obj.name)
            except Exception as e:
                log.error(f"发现插件失败 {py_file}: {e}")

        return discovered

    def list_plugins(self) -> List[dict]:
        """列出所有已注册插件"""
        plugins = []
        for name, plugin_class in self._plugin_classes.items():
            plugins.append({
                "name": name,
                "version": plugin_class.version,
                "description": plugin_class.description,
                "category": plugin_class.category,
                "author": plugin_class.author,
                "tags": plugin_class.tags,
                "loaded": name in self._plugins,
                "available": self._plugins[name].is_available() if name in self._plugins else None,
            })
        return plugins

    def get_plugin(self, name: str) -> Optional[Plugin]:
        """获取已加载的插件实例"""
        return self._plugins.get(name)

    def get_plugin_help(self, name: str) -> Optional[str]:
        """获取插件帮助信息"""
        if name in self._plugins:
            return self._plugins[name].get_help()
        if name in self._plugin_classes:
            # 临时实例化获取帮助
            try:
                plugin = self._plugin_classes[name]()
                return plugin.get_help()
            except Exception:
                pass
        return None

    def reload_plugin(self, name: str) -> bool:
        """重新加载插件"""
        self.unload_plugin(name)
        return self.load_plugin(name) is not None

    def get_statistics(self) -> dict:
        """获取插件统计"""
        categories = {}
        for plugin_class in self._plugin_classes.values():
            cat = plugin_class.category
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_registered": len(self._plugin_classes),
            "total_loaded": len(self._plugins),
            "categories": categories,
            "plugin_dir": self.plugin_dir,
        }


# 全局插件管理器实例
plugin_manager = PluginManager()
