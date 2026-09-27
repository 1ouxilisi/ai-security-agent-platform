"""
agent_orchestrator智能体模块，提供相关AI驱动的安全分析和决策功能。

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
import json
import time
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from utils.logger import log
from agent.base_agent import BaseAgent, AgentConfig, ToolDefinition


@dataclass
class PipelineStep:
    """流水线步骤"""
    step_name: str
    agent_name: str
    input_mapping: Dict[str, str] = field(default_factory=dict)  # 输入字段映射
    output_key: str = ""  # 输出存储的key
    condition: Optional[Callable] = None  # 条件执行


@dataclass
class OrchestratorResult:
    """编排器执行结果"""
    task: str
    status: str = "pending"
    steps: List[Dict] = field(default_factory=list)
    outputs: Dict[str, Any] = field(default_factory=dict)
    final_output: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "task": self.task,
            "status": self.status,
            "steps": self.steps,
            "outputs": {k: str(v)[:500] if v else "" for k, v in self.outputs.items()},
            "final_output": self.final_output,
            "duration_seconds": round(self.completed_at - self.started_at, 2) if self.completed_at else 0,
            "errors": self.errors,
        }


class AgentOrchestrator:
    """Agent编排器"""

    def __init__(self):
        """初始化AgentOrchestrator实例。

        Args:
            self: 类实例。
        """
        self.agents: Dict[str, BaseAgent] = {}
        self.pipeline: List[PipelineStep] = []
        self.shared_tool_registry: Dict[str, ToolDefinition] = {}
        log.info("Agent编排器初始化")

    def register_agent(self, agent: BaseAgent):
        """注册Agent"""
        self.agents[agent.config.name] = agent
        log.info(f"Agent已注册: {agent.config.name} ({agent.config.role})")

    def register_tool(self, tool: ToolDefinition):
        """注册共享工具"""
        self.shared_tool_registry[tool.name] = tool
        log.debug(f"共享工具已注册: {tool.name}")

    def add_pipeline_step(self, step: PipelineStep):
        """添加流水线步骤"""
        self.pipeline.append(step)
        log.info(f"流水线步骤已添加: {step.step_name} -> {step.agent_name}")

    def build_security_pipeline(self) -> List[PipelineStep]:
        """
        构建安全测试流水线（预设）
        侦察Agent → 测试Agent → 验证Agent → 报告Agent
        """
        return [
            PipelineStep(
                step_name="信息收集",
                agent_name="ReconAgent",
                output_key="recon_result",
            ),
            PipelineStep(
                step_name="漏洞测试",
                agent_name="ExploitAgent",
                input_mapping={"target": "recon_result.target"},
                output_key="exploit_result",
            ),
            PipelineStep(
                step_name="漏洞验证",
                agent_name="VerificationAgent",
                input_mapping={"findings": "exploit_result.findings"},
                output_key="verification_result",
            ),
            PipelineStep(
                step_name="生成报告",
                agent_name="ReportAgent",
                input_mapping={
                    "recon": "recon_result",
                    "findings": "verification_result",
                },
                output_key="final_report",
            ),
        ]

    async def execute_pipeline(self, task: str, initial_input: Optional[Dict] = None) -> OrchestratorResult:
        """
        执行流水线
        task: 任务描述
        initial_input: 初始输入数据
        """
        log.info(f"编排器开始执行流水线: {task[:50]}...")

        result = OrchestratorResult(task=task, started_at=time.time(), status="running")
        context: Dict[str, Any] = initial_input or {}
        context["task"] = task

        for i, step in enumerate(self.pipeline):
            step_info = {
                "step_number": i + 1,
                "step_name": step.step_name,
                "agent": step.agent_name,
                "status": "pending",
            }

            # 检查条件
            if step.condition and not step.condition(context):
                step_info["status"] = "skipped"
                result.steps.append(step_info)
                log.info(f"步骤跳过: {step.step_name}")
                continue

            # 检查Agent是否存在
            if step.agent_name not in self.agents:
                error = f"Agent不存在: {step.agent_name}"
                step_info["status"] = "failed"
                step_info["error"] = error
                result.errors.append(error)
                result.steps.append(step_info)
                log.error(error)
                continue

            agent = self.agents[step.agent_name]

            # 构建Agent任务描述
            agent_task = self._build_agent_task(step, task, context)

            try:
                step_info["status"] = "running"
                log.info(f"步骤开始: {step.step_name} (Agent: {step.agent_name})")

                # 执行Agent
                agent_result = await agent.run(agent_task)

                step_info["status"] = agent_result.get("status", "completed")
                step_info["iterations"] = agent_result.get("iterations", 0)
                step_info["tool_calls"] = agent_result.get("tool_calls", 0)

                # 存储输出
                if step.output_key:
                    context[step.output_key] = agent_result
                    result.outputs[step.output_key] = agent_result.get("final_answer", "")

                if agent_result.get("errors"):
                    result.errors.extend(agent_result["errors"])

                log.info(f"步骤完成: {step.step_name}, 状态: {step_info['status']}")

            except Exception as e:
                error = f"步骤执行错误: {str(e)}"
                step_info["status"] = "failed"
                step_info["error"] = error
                result.errors.append(error)
                log.error(f"步骤失败: {step.step_name}: {e}")

            result.steps.append(step_info)

        # 完成
        result.status = "completed" if not result.errors else "completed_with_errors"
        result.completed_at = time.time()
        result.final_output = context.get("final_report", {}).get("final_answer", "") if isinstance(context.get("final_report"), dict) else ""

        log.info(f"流水线执行完成，状态: {result.status}, 步骤: {len(result.steps)}, 错误: {len(result.errors)}")
        return result

    def _build_agent_task(self, step: PipelineStep, task: str, context: Dict) -> str:
        """构建Agent任务描述"""
        parts = [f"【{step.step_name}】", f"总体任务: {task}"]

        # 添加上下文输入
        if step.input_mapping:
            parts.append("\n可用信息:")
            for input_key, context_key in step.input_mapping.items():
                value = context.get(context_key, "")
                if isinstance(value, dict):
                    value = value.get("final_answer", str(value)[:200])
                parts.append(f"- {input_key}: {str(value)[:300]}")

        parts.append("\n请执行你的职责，完成后输出Final Answer。")
        return "\n".join(parts)

    async def execute_parallel(self, task: str, agent_names: List[str]) -> Dict[str, Any]:
        """
        并行执行多个Agent
        """
        log.info(f"并行执行Agent: {agent_names}")

        async def run_agent(name: str) -> tuple[str, Any]:
            if name not in self.agents:
                return name, {"error": f"Agent不存在: {name}"}
            return name, await self.agents[name].run(task)

        results = await asyncio.gather(*[run_agent(name) for name in agent_names])
        return dict(results)

    def get_agent_status(self) -> Dict[str, Any]:
        """获取所有Agent状态"""
        return {
            name: {
                "role": agent.config.role,
                "description": agent.config.description,
                "tools_count": len(agent._get_available_tools()),
            }
            for name, agent in self.agents.items()
        }
