"""
base_agent智能体模块，提供相关AI驱动的安全分析和决策功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import asyncio
import inspect
import json
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from openai import OpenAI
from config.settings import settings
from utils.logger import log


@dataclass
class ToolDefinition:
    """工具定义"""
    name: str
    description: str
    handler: Callable
    parameters: Dict = field(default_factory=dict)
    category: str = "general"


@dataclass
class AgentConfig:
    """Agent配置"""
    name: str = "Agent"
    role: str = "助手"
    description: str = "通用AI助手"
    system_prompt: str = ""
    model: str = ""
    temperature: float = 0.1
    max_tokens: int = 4096
    max_iterations: int = 15
    tools: List[str] = field(default_factory=list)  # 空列表表示使用所有工具


class BaseAgent:
    """
    通用Agent基类
    所有业务领域的Agent都继承此类
    """

    # 子类可以重写默认配置
    DEFAULT_NAME = "BaseAgent"
    DEFAULT_ROLE = "通用助手"
    DEFAULT_DESCRIPTION = "通用AI助手"
    DEFAULT_SYSTEM_PROMPT = """你是一个专业的AI助手，使用ReAct（推理+行动）框架完成任务。

## 工作流程
1. Thought：分析当前状态，思考下一步做什么
2. Action：选择工具并生成参数
3. Observation：获取工具执行结果，继续思考
4. 重复直到任务完成，输出Final Answer

## 可用工具
{tools_list}

## 规则
- 每次只调用一个工具
- 格式：Action: 工具名 / Action Input: JSON
- 工具失败时分析原因，调整重试或换工具
- 任务完成时输出：Final Answer: [结论]
"""

    def __init__(self, config: Optional[AgentConfig] = None, tool_registry: Optional[Dict[str, ToolDefinition]] = None):
        """
        初始化Agent
        config: Agent配置
        tool_registry: 工具注册表，格式 {工具名: ToolDefinition}
        """
        self.config = config or AgentConfig(
            name=self.DEFAULT_NAME,
            role=self.DEFAULT_ROLE,
            description=self.DEFAULT_DESCRIPTION,
        )
        self.tool_registry = tool_registry or {}
        self.client = OpenAI(
            api_key=settings.llm.api_key,
            base_url=settings.llm.base_url,
        )
        self.model = self.config.model or settings.llm.model
        self.conversation_history: List[Dict] = []
        self._initialize_history()
        log.info(f"Agent初始化: {self.config.name} ({self.config.role}), 工具数: {len(self._get_available_tools())}")

    def _initialize_history(self):
        """初始化对话历史"""
        system_prompt = self.config.system_prompt or self.DEFAULT_SYSTEM_PROMPT
        self.conversation_history = [
            {"role": "system", "content": system_prompt.format(tools_list=self._build_tools_list())},
        ]

    def _get_available_tools(self) -> Dict[str, ToolDefinition]:
        """获取当前Agent可用的工具"""
        if not self.config.tools:
            return self.tool_registry
        return {name: tool for name, tool in self.tool_registry.items() if name in self.config.tools}

    def _build_tools_list(self) -> str:
        """构建工具列表文本"""
        lines = []
        for name, tool in self._get_available_tools().items():
            lines.append(f"- **{name}** ({tool.category}): {tool.description}")
        return "\n".join(lines) if lines else "（无可用工具）"

    def register_tool(self, tool: ToolDefinition):
        """注册工具"""
        self.tool_registry[tool.name] = tool
        log.debug(f"工具已注册: {tool.name}")
        # 重新初始化历史以更新工具列表
        self._initialize_history()

    def unregister_tool(self, tool_name: str):
        """注销工具"""
        if tool_name in self.tool_registry:
            del self.tool_registry[tool_name]
            log.debug(f"工具已注销: {tool_name}")
            self._initialize_history()

    async def execute_tool(self, tool_name: str, parameters: Dict) -> tuple[str, bool]:
        """
        执行工具
        返回: (结果文本, 是否成功)
        """
        available_tools = self._get_available_tools()
        if tool_name not in available_tools:
            return f"错误: 未知工具 '{tool_name}'，可用工具: {list(available_tools.keys())}", False

        try:
            tool = available_tools[tool_name]
            if inspect.iscoroutinefunction(tool.handler):
                result = await tool.handler(**parameters)
            else:
                result = tool.handler(**parameters)

            if isinstance(result, dict):
                result_text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
            else:
                result_text = str(result)

            if len(result_text) > 5000:
                result_text = result_text[:5000] + f"\n... [截断，共{len(result_text)}字符]"

            return result_text, True

        except Exception as e:
            error_msg = f"工具执行错误: {str(e)}"
            log.error(f"Agent工具执行失败 {tool_name}: {e}")
            return error_msg, False

    def parse_action(self, response: str) -> tuple[Optional[str], Optional[Dict], Optional[str]]:
        """解析Action，子类可重写"""
        import re
        final_match = re.search(r'Final Answer:\s*(.+?)(?:\n\n|\Z)', response, re.DOTALL)
        if final_match:
            return None, None, final_match.group(1).strip()

        action_match = re.search(r'Action:\s*(.+?)(?:\n|$)', response)
        if not action_match:
            return None, None, None

        tool_name = action_match.group(1).strip()
        input_match = re.search(r'Action Input:\s*(\{.+?\})(?:\n\n|\n|$)', response, re.DOTALL)
        try:
            action_input = json.loads(input_match.group(1).strip()) if input_match else {}
        except json.JSONDecodeError:
            action_input = {}

        return tool_name, action_input, None

    async def run(self, task: str) -> Dict:
        """
        执行任务（ReAct循环）
        返回: 执行结果字典
        """
        log.info(f"Agent {self.config.name} 开始任务: {task[:50]}...")

        self.conversation_history.append({"role": "user", "content": f"任务: {task}\n\n请开始执行。"})

        result = {
            "agent": self.config.name,
            "task": task,
            "status": "running",
            "iterations": 0,
            "tool_calls": 0,
            "final_answer": "",
            "errors": [],
            "steps": [],
        }

        for iteration in range(self.config.max_iterations):
            result["iterations"] = iteration + 1
            step_info = {"iteration": iteration + 1, "thought": "", "action": "", "observation": "", "status": ""}

            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=self.conversation_history,
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                )
                ai_response = response.choices[0].message.content.strip()

                import re
                thought_match = re.search(r'Thought:\s*(.+?)(?:\n\n|Action:|Final Answer:|$)', ai_response, re.DOTALL)
                step_info["thought"] = thought_match.group(1).strip() if thought_match else ai_response[:200]

                tool_name, tool_input, final_answer = self.parse_action(ai_response)

                if final_answer:
                    step_info["status"] = "completed"
                    result["final_answer"] = final_answer
                    result["status"] = "completed"
                    result["steps"].append(step_info)
                    log.info(f"Agent任务完成: {final_answer[:100]}...")
                    break

                if not tool_name:
                    step_info["observation"] = "无法解析Action，请按格式输出"
                    step_info["status"] = "failed"
                    result["errors"].append(f"迭代{iteration+1}: 无法解析Action")
                    self.conversation_history.append({"role": "assistant", "content": ai_response})
                    self.conversation_history.append({"role": "user", "content": f"Observation: {step_info['observation']}"})
                    result["steps"].append(step_info)
                    continue

                step_info["action"] = tool_name
                step_info["status"] = "acting"
                result["tool_calls"] += 1

                observation, success = await self.execute_tool(tool_name, tool_input or {})
                step_info["observation"] = observation
                step_info["status"] = "success" if success else "failed"

                if not success:
                    result["errors"].append(f"迭代{iteration+1}: 工具{tool_name}失败")

                self.conversation_history.append({"role": "assistant", "content": ai_response})
                self.conversation_history.append({"role": "user", "content": f"Observation: {observation}"})

            except Exception as e:
                error_msg = f"迭代错误: {str(e)}"
                step_info["status"] = "failed"
                step_info["observation"] = error_msg
                result["errors"].append(error_msg)
                log.error(f"Agent迭代错误: {e}")

            result["steps"].append(step_info)

        if result["status"] == "running":
            result["status"] = "max_iterations"
            result["final_answer"] = f"达到最大迭代次数({self.config.max_iterations})"

        log.info(f"Agent任务结束，状态: {result['status']}, 迭代: {result['iterations']}, 工具调用: {result['tool_calls']}")
        return result

    def reset(self):
        """重置Agent状态"""
        self._initialize_history()
        log.info(f"Agent {self.config.name} 已重置")
