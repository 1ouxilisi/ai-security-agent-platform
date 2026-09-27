"""
react_engine智能体模块，提供相关AI驱动的安全分析和决策功能。

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
import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from openai import OpenAI
from config.settings import settings
from utils.logger import log


@dataclass
class ReActStep:
    """ReAct单步记录"""
    step_number: int
    thought: str = ""
    action: str = ""
    action_input: Dict = field(default_factory=dict)
    observation: str = ""
    status: str = "pending"  # pending / thinking / acting / observing / completed / failed
    started_at: float = 0.0
    completed_at: float = 0.0
    error: Optional[str] = None
    retry_count: int = 0


@dataclass
class ReActResult:
    """ReAct执行结果"""
    task: str
    steps: List[ReActStep] = field(default_factory=list)
    final_answer: str = ""
    status: str = "pending"  # pending / running / completed / failed / max_iterations
    started_at: float = 0.0
    completed_at: float = 0.0
    total_iterations: int = 0
    tool_calls: int = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "task": self.task,
            "steps": [asdict(s) for s in self.steps],
            "final_answer": self.final_answer,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_iterations": self.total_iterations,
            "tool_calls": self.tool_calls,
            "errors": self.errors,
            "duration_seconds": round(self.completed_at - self.started_at, 2) if self.completed_at else 0,
        }


class ReActEngine:
    """ReAct推理引擎"""

    # 系统提示词模板（v3.1优化版 - 更专业的安全测试指导）
    SYSTEM_PROMPT = """你是一个专业的安全测试AI助手，使用ReAct（推理+行动）框架完成授权范围内的安全测试任务。

## 角色定位
你是一名经验丰富的渗透测试工程师，擅长：
- 信息收集与侦察
- 漏洞扫描与验证
- 漏洞利用与权限提升
- 报告生成与修复建议

## 工作流程
你需要按照以下循环工作，直到任务完成：

1. **Thought（思考）**：分析当前状态，思考下一步应该做什么
   - 先分析已有的观察结果
   - 再决定下一步使用什么工具
   - 最后生成工具参数

2. **Action（行动）**：选择一个工具并生成参数，格式必须是：
   ```
   Action: 工具名
   Action Input: {"参数名": "参数值"}
   ```

3. **Observation（观察）**：我会返回工具执行结果，你根据结果继续思考

## 安全测试最佳实践
1. **先侦察后攻击**：先做信息收集（端口、服务、版本），再根据服务版本匹配漏洞
2. **由浅入深**：先做基础扫描，再做深度利用，不要一上来就尝试复杂攻击
3. **验证优先**：发现潜在漏洞后，先用POC验证，确认可利用再深入
4. **记录证据**：每个发现都要记录证据（请求、响应、截图）
5. **风险评估**：根据CVSS评分和实际影响评估漏洞严重程度

## 工具使用规范
1. 每次只调用一个工具，不要同时调用多个
2. 工具调用格式必须严格遵循：Action: 工具名 + Action Input: JSON
3. 调用工具前确认参数正确，目标在授权范围内
4. 如果工具调用失败，分析错误原因：
   - 参数错误 → 修正参数重试
   - 工具不适用 → 换一个工具
   - 目标不可达 → 记录并继续其他测试
5. 不要重复调用同一个工具超过3次，换策略

## 可用工具
{tools_list}

## 重要规则
1. 当你认为任务已经完成，输出：
   ```
   Final Answer: [你的最终结论和总结，包含发现的漏洞、风险评级、修复建议]
   ```
2. 不要编造工具执行结果，必须等待真实的Observation
3. 所有操作必须在授权范围内，不要尝试未授权的目标
4. 如果任务超出你的能力范围，如实说明，不要编造结果
5. 保持专业、客观，不要夸大或缩小漏洞影响

## 输出格式
每次输出必须包含Thought，然后是Action或Final Answer。
Thought要简洁明了，说明你为什么选择这个工具。
"""

    def __init__(self, tool_registry: Dict[str, Any], max_iterations: int = 15):
        """
        初始化ReAct引擎
        tool_registry: 工具注册表，格式 {工具名: 处理函数}
        max_iterations: 最大迭代次数，防止死循环
        """
        self.client = OpenAI(api_key=settings.llm.api_key, base_url=settings.llm.base_url)
        self.model = settings.llm.model
        self.tool_registry = tool_registry
        self.max_iterations = max_iterations
        self.conversation_history: List[Dict] = []
        log.info(f"ReAct引擎初始化，工具数: {len(tool_registry)}, 最大迭代: {max_iterations}")

    def _build_tools_list(self) -> str:
        """构建工具列表文本"""
        lines = []
        for name, handler in self.tool_registry.items():
            # 尝试获取工具描述
            desc = getattr(handler, "__doc__", "") or "无描述"
            lines.append(f"- **{name}**: {desc[:100]}")
        return "\n".join(lines)

    def _build_system_prompt(self) -> str:
        """构建系统提示词"""
        return self.SYSTEM_PROMPT.format(tools_list=self._build_tools_list())

    def _parse_action(self, response: str) -> Tuple[Optional[str], Optional[Dict], Optional[str]]:
        """
        解析AI响应，提取Action和Action Input
        返回: (工具名, 参数, Final Answer)
        """
        import re

        # 检查是否有Final Answer
        final_match = re.search(r'Final Answer:\s*(.+?)(?:\n\n|\Z)', response, re.DOTALL)
        if final_match:
            return None, None, final_match.group(1).strip()

        # 解析Action
        action_match = re.search(r'Action:\s*(.+?)(?:\n|$)', response)
        if not action_match:
            return None, None, None

        tool_name = action_match.group(1).strip()

        # 解析Action Input
        input_match = re.search(r'Action Input:\s*(\{.+?\})(?:\n\n|\n|$)', response, re.DOTALL)
        if input_match:
            try:
                action_input = json.loads(input_match.group(1).strip())
            except json.JSONDecodeError:
                action_input = {}
        else:
            action_input = {}

        return tool_name, action_input, None

    def _extract_thought(self, response: str) -> str:
        """提取Thought部分"""
        import re
        thought_match = re.search(r'Thought:\s*(.+?)(?:\n\n|Action:|Final Answer:|$)', response, re.DOTALL)
        if thought_match:
            return thought_match.group(1).strip()
        return response[:200]

    async def _execute_tool(self, tool_name: str, tool_input: Dict) -> Tuple[str, bool]:
        """
        执行工具
        返回: (结果文本, 是否成功)
        """
        if tool_name not in self.tool_registry:
            return f"错误: 未知工具 '{tool_name}'，可用工具: {list(self.tool_registry.keys())}", False

        try:
            handler = self.tool_registry[tool_name]
            # 支持同步和异步函数
            if inspect.iscoroutinefunction(handler):
                result = await handler(**tool_input)
            else:
                result = handler(**tool_input)

            # 序列化结果
            if isinstance(result, dict):
                result_text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
            else:
                result_text = str(result)

            # 截断过长的结果
            if len(result_text) > 5000:
                result_text = result_text[:5000] + f"\n... [结果截断，共{len(result_text)}字符]"

            return result_text, True

        except Exception as e:
            error_msg = f"工具执行错误: {str(e)}"
            log.error(f"ReAct工具执行失败 {tool_name}: {e}")
            return error_msg, False

    async def run(self, task: str) -> ReActResult:
        """
        执行ReAct循环
        task: 任务描述
        返回: ReActResult
        """
        log.info(f"ReAct引擎开始执行任务: {task[:50]}...")

        result = ReActResult(task=task, started_at=time.time(), status="running")
        self.conversation_history = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": f"任务: {task}\n\n请开始执行。"},
        ]

        for iteration in range(self.max_iterations):
            result.total_iterations = iteration + 1
            step = ReActStep(step_number=iteration + 1, started_at=time.time(), status="thinking")
            result.steps.append(step)

            log.info(f"ReAct迭代 {iteration + 1}/{self.max_iterations}")

            try:
                # 1. 调用大模型思考
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=self.conversation_history,
                    temperature=settings.llm.temperature,
                    max_tokens=settings.llm.max_tokens,
                )
                ai_response = response.choices[0].message.content.strip()
                step.thought = self._extract_thought(ai_response)

                log.debug(f"AI思考: {step.thought[:100]}...")

                # 2. 解析Action
                tool_name, tool_input, final_answer = self._parse_action(ai_response)

                # 3. 如果有Final Answer，任务完成
                if final_answer:
                    step.status = "completed"
                    step.completed_at = time.time()
                    result.final_answer = final_answer
                    result.status = "completed"
                    result.completed_at = time.time()
                    log.info(f"ReAct任务完成: {final_answer[:100]}...")
                    break

                # 4. 如果没有解析到Action，继续
                if not tool_name:
                    step.observation = "无法解析Action，请按照指定格式输出: Action: 工具名 / Action Input: JSON"
                    step.status = "failed"
                    step.completed_at = time.time()
                    result.errors.append(f"迭代{iteration+1}: 无法解析Action")
                    self.conversation_history.append({"role": "assistant", "content": ai_response})
                    self.conversation_history.append({"role": "user", "content": f"Observation: {step.observation}"})
                    continue

                # 5. 执行工具
                step.action = tool_name
                step.action_input = tool_input
                step.status = "acting"
                result.tool_calls += 1

                log.info(f"ReAct调用工具: {tool_name}, 参数: {json.dumps(tool_input, ensure_ascii=False)[:100]}")

                observation, success = await self._execute_tool(tool_name, tool_input)
                step.observation = observation
                step.status = "observing" if success else "failed"
                step.completed_at = time.time()

                if not success:
                    step.retry_count += 1
                    result.errors.append(f"迭代{iteration+1}: 工具{tool_name}执行失败")

                # 6. 将结果加入对话历史
                self.conversation_history.append({"role": "assistant", "content": ai_response})
                self.conversation_history.append({"role": "user", "content": f"Observation: {observation}"})

            except Exception as e:
                error_msg = f"迭代错误: {str(e)}"
                log.error(f"ReAct迭代错误: {e}")
                step.status = "failed"
                step.error = error_msg
                step.completed_at = time.time()
                result.errors.append(error_msg)
                self.conversation_history.append({"role": "user", "content": f"Observation: 发生错误: {error_msg}"})

        # 达到最大迭代次数
        if result.status == "running":
            result.status = "max_iterations"
            result.completed_at = time.time()
            result.final_answer = f"达到最大迭代次数({self.max_iterations})，任务未完成。已执行{result.tool_calls}次工具调用。"
            log.warning(f"ReAct达到最大迭代次数: {self.max_iterations}")

        log.info(f"ReAct任务结束，状态: {result.status}, 迭代: {result.total_iterations}, 工具调用: {result.tool_calls}")
        return result

    def get_conversation_history(self) -> List[Dict]:
        """获取对话历史"""
        return self.conversation_history.copy()
