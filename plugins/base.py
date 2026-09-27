"""
base模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class PluginTool:
    """插件工具定义"""
    name: str
    description: str
    input_schema: Dict
    handler: Any  # 异步或同步函数


class BasePlugin(ABC):
    """插件基类"""

    # 插件元数据（子类必须设置）
    name: str = "base_plugin"
    version: str = "1.0.0"
    description: str = "基础插件"
    author: str = "Anonymous"
    enabled: bool = True

    def __init__(self, config: Optional[Dict] = None):
        """初始化BasePlugin实例。

        Args:
            self: 类实例。
        """
        self.config = config or {}
        self.tools: List[PluginTool] = []
        self._register_tools()

    @abstractmethod
    def _register_tools(self):
        """
        注册插件提供的工具
        子类必须实现此方法，在方法中调用 self._add_tool()
        """
        pass

    def _add_tool(self, name: str, description: str, input_schema: Dict, handler):
        """添加一个工具"""
        tool = PluginTool(
            name=name,
            description=description,
            input_schema=input_schema,
            handler=handler
        )
        self.tools.append(tool)

    def get_tools(self) -> List[PluginTool]:
        """获取插件提供的所有工具"""
        return self.tools if self.enabled else []

    def get_metadata(self) -> Dict:
        """获取插件元数据"""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "enabled": self.enabled,
            "tool_count": len(self.tools),
        }

    async def initialize(self):
        """插件初始化钩子（可选重写）"""
        pass

    async def cleanup(self):
        """插件清理钩子（可选重写）"""
        pass


# ===== 示例插件 =====

class ExamplePlugin(BasePlugin):
    """示例插件 - 演示如何编写自定义插件"""

    name = "example_plugin"
    version = "1.0.0"
    description = "示例插件，演示插件系统用法"
    author = "AI Hacking Agent"

    def _register_tools(self):
        """注册示例工具"""
        self._add_tool(
            name="example_hello",
            description="示例工具 - 打招呼，演示插件系统",
            input_schema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "你的名字"}
                },
                "required": ["name"]
            },
            handler=self._hello
        )

        self._add_tool(
            name="example_calculate",
            description="示例工具 - 简单计算器，演示带参数的工具",
            input_schema={
                "type": "object",
                "properties": {
                    "a": {"type": "number", "description": "第一个数"},
                    "b": {"type": "number", "description": "第二个数"},
                    "operation": {"type": "string", "description": "运算: add/sub/mul/div"}
                },
                "required": ["a", "b", "operation"]
            },
            handler=self._calculate
        )

    async def _hello(self, name: str) -> Dict:
        """示例处理函数"""
        return {"message": f"你好, {name}! 这是来自示例插件的问候。", "plugin": self.name}

    async def _calculate(self, a: float, b: float, operation: str) -> Dict:
        """示例计算器"""
        operations = {
            "add": a + b,
            "sub": a - b,
            "mul": a * b,
            "div": a / b if b != 0 else "错误: 除数不能为0"
        }
        result = operations.get(operation, "未知运算")
        return {"a": a, "b": b, "operation": operation, "result": result}
