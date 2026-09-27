"""
增强型AI智能体模块
- 真正的自主规划（动态生成计划，不是预设流程）
- 动态调整策略（根据中间结果调整下一步）
- 多轮ReAct推理循环（思考-行动-观察-反思）
- 任务自动分解
- 工具自动选择和调用
- 反思和自我纠正机制
"""

import json
import time
import os
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum


class AgentState(Enum):
    """智能体状态"""
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    OBSERVING = "observing"
    REFLECTING = "reflecting"
    ADJUSTING = "adjusting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class TaskStep:
    """任务步骤"""
    step_id: int
    description: str
    tool: Optional[str] = None
    parameters: Optional[Dict] = None
    status: str = "pending"  # pending/running/completed/failed/skipped
    result: Optional[Any] = None
    observation: Optional[str] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    retries: int = 0


@dataclass
class AgentMemory:
    """智能体记忆"""
    goal: str = ""
    plan: List[TaskStep] = field(default_factory=list)
    current_step_index: int = 0
    observations: List[str] = field(default_factory=list)
    reflections: List[str] = field(default_factory=list)
    adjustments: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    max_iterations: int = 20
    current_iteration: int = 0


class EnhancedAgent:
    """增强型AI智能体 - 真正自主规划和动态调整"""

    def __init__(self, agent_type: str = "recon", llm_config: Optional[Dict] = None):
        self.agent_type = agent_type
        self.state = AgentState.IDLE
        self.memory = AgentMemory()
        self.tools_registry: Dict[str, Callable] = {}
        self.llm_config = llm_config or self._load_default_llm_config()
        self.max_retries = 3
        self.callbacks = {
            "on_plan": None,
            "on_execute": None,
            "on_observe": None,
            "on_reflect": None,
            "on_adjust": None,
            "on_complete": None,
        }

    def _load_default_llm_config(self) -> Dict:
        """加载默认LLM配置"""
        return {
            "api_key": os.getenv("LLM_API_KEY", ""),
            "base_url": os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1"),
            "model": os.getenv("LLM_MODEL", "deepseek-chat"),
            "temperature": 0.3,
            "max_tokens": 2048,
        }

    def register_tool(self, name: str, func: Callable, description: str = ""):
        """注册工具"""
        self.tools_registry[name] = {
            "func": func,
            "description": description,
        }

    def register_tools_from_dict(self, tools: Dict[str, Dict]):
        """从字典批量注册工具"""
        for name, tool_info in tools.items():
            self.tools_registry[name] = tool_info

    def set_goal(self, goal: str):
        """设置目标"""
        self.memory.goal = goal
        self.memory.plan = []
        self.memory.current_step_index = 0
        self.memory.observations = []
        self.memory.reflections = []
        self.memory.adjustments = []
        self.memory.errors = []
        self.state = AgentState.IDLE

    def run(self, goal: str) -> Dict[str, Any]:
        """
        运行智能体（完整的自主规划-执行-观察-反思-调整循环）
        """
        self.set_goal(goal)
        self.memory.start_time = time.time()

        try:
            # 阶段1：规划
            self.state = AgentState.PLANNING
            self._plan()

            # 阶段2：执行循环（多轮ReAct）
            while self.memory.current_iteration < self.memory.max_iterations:
                self.memory.current_iteration += 1

                # 检查是否所有步骤完成
                if all(s.status in ("completed", "skipped") for s in self.memory.plan):
                    break

                # 执行当前步骤
                self.state = AgentState.EXECUTING
                step = self._get_current_step()
                if step is None:
                    break

                if step.status == "completed":
                    self.memory.current_step_index += 1
                    continue

                # 执行
                self._execute_step(step)

                # 观察
                self.state = AgentState.OBSERVING
                self._observe(step)

                # 反思
                self.state = AgentState.REFLECTING
                need_adjust = self._reflect(step)

                # 调整（如果需要）
                if need_adjust:
                    self.state = AgentState.ADJUSTING
                    self._adjust(step)

                # 移动到下一步
                if step.status in ("completed", "failed", "skipped"):
                    self.memory.current_step_index += 1

            # 阶段3：完成
            self.state = AgentState.COMPLETED
            result = self._generate_final_result()

            if self.callbacks["on_complete"]:
                self.callbacks["on_complete"](result)

            return result

        except Exception as e:
            self.state = AgentState.FAILED
            self.memory.errors.append(str(e))
            return {
                "status": "failed",
                "error": str(e),
                "goal": self.memory.goal,
                "iterations": self.memory.current_iteration,
                "duration": round(time.time() - self.memory.start_time, 2),
            }

    def _plan(self):
        """
        规划阶段：根据目标自动生成执行计划
        优先使用LLM生成计划，如果LLM不可用则使用规则引擎
        """
        goal = self.memory.goal.lower()

        # 尝试使用LLM生成计划
        plan = self._plan_with_llm(goal)

        # 如果LLM失败，使用规则引擎
        if not plan:
            plan = self._plan_with_rules(goal)

        self.memory.plan = plan
        self.memory.current_step_index = 0

        if self.callbacks["on_plan"]:
            self.callbacks["on_plan"](plan)

    def _plan_with_llm(self, goal: str) -> List[TaskStep]:
        """使用LLM生成计划"""
        if not self.llm_config.get("api_key"):
            return []

        try:
            import urllib.request

            tools_list = "\n".join([
                f"- {name}: {info.get('description', '')}"
                for name, info in self.tools_registry.items()
            ])

            prompt = f"""你是一个网络安全渗透测试智能体。请根据以下目标生成执行计划。

目标: {goal}

可用工具:
{tools_list}

请以JSON格式返回计划，格式如下:
{{
    "steps": [
        {{
            "description": "步骤描述",
            "tool": "工具名称（可选）",
            "parameters": {{参数对象}}
        }}
    ]
}}

只返回JSON，不要返回其他内容。"""

            payload = json.dumps({
                "model": self.llm_config["model"],
                "messages": [{"role": "user", "content": prompt}],
                "temperature": self.llm_config["temperature"],
                "max_tokens": self.llm_config["max_tokens"],
            }).encode()

            req = urllib.request.Request(
                f"{self.llm_config['base_url']}/chat/completions",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.llm_config['api_key']}",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=30) as resp:
                response = json.loads(resp.read().decode())
                content = response["choices"][0]["message"]["content"]

                # 解析JSON
                content = content.strip()
                if content.startswith("```"):
                    content = content.split("```")[1]
                    if content.startswith("json"):
                        content = content[4:]
                content = content.strip()

                plan_data = json.loads(content)
                steps = []
                for i, step_data in enumerate(plan_data.get("steps", [])):
                    steps.append(TaskStep(
                        step_id=i + 1,
                        description=step_data.get("description", ""),
                        tool=step_data.get("tool"),
                        parameters=step_data.get("parameters"),
                    ))
                return steps

        except Exception as e:
            self.memory.errors.append(f"LLM规划失败: {e}")
            return []

    def _plan_with_rules(self, goal: str) -> List[TaskStep]:
        """使用规则引擎生成计划（基于目标关键词匹配）"""
        steps = []
        step_id = 1

        # 通用渗透测试流程
        if any(k in goal for k in ["渗透", "扫描", "评估", "安全测试", "pentest", "scan"]):
            # 1. 资产发现
            steps.append(TaskStep(
                step_id=step_id,
                description="目标资产发现与端口扫描",
                tool="port_scan",
                parameters={"target": "", "ports": "top100"},
            ))
            step_id += 1

            # 2. 服务识别
            steps.append(TaskStep(
                step_id=step_id,
                description="服务版本与技术栈识别",
                tool="tech_stack_detect",
                parameters={"target": ""},
            ))
            step_id += 1

            # 3. 漏洞扫描
            steps.append(TaskStep(
                step_id=step_id,
                description="Web漏洞扫描（SQL注入/XSS/命令执行等）",
                tool="vuln_scan",
                parameters={"target": ""},
            ))
            step_id += 1

            # 4. 安全头检查
            steps.append(TaskStep(
                step_id=step_id,
                description="安全响应头与SSL/TLS配置检查",
                tool="security_headers_audit",
                parameters={"target": ""},
            ))
            step_id += 1

            # 5. 报告生成
            steps.append(TaskStep(
                step_id=step_id,
                description="生成专业安全评估报告",
                tool="generate_report",
                parameters={},
            ))

        # 侦察任务
        elif any(k in goal for k in ["侦察", "recon", "信息收集", "资产", "子域名"]):
            steps.append(TaskStep(step_id=step_id, description="子域名爆破", tool="subdomain_scan", parameters={"target": ""}))
            step_id += 1
            steps.append(TaskStep(step_id=step_id, description="目录与文件扫描", tool="directory_scan", parameters={"target": ""}))
            step_id += 1
            steps.append(TaskStep(step_id=step_id, description="API端点发现", tool="api_endpoint_discovery", parameters={"target": ""}))
            step_id += 1
            steps.append(TaskStep(step_id=step_id, description="技术栈深度识别", tool="tech_stack_detect", parameters={"target": ""}))

        # 漏洞验证任务
        elif any(k in goal for k in ["验证", "verify", "漏洞验证", "poc"]):
            steps.append(TaskStep(step_id=step_id, description="漏洞信息确认", tool="cve_lookup", parameters={}))
            step_id += 1
            steps.append(TaskStep(step_id=step_id, description="PoC概念验证（授权范围内）", tool="poc_verify", parameters={}))
            step_id += 1
            steps.append(TaskStep(step_id=step_id, description="验证结果记录", tool="record_result", parameters={}))

        # 默认计划
        else:
            steps.append(TaskStep(step_id=step_id, description="目标信息收集", tool="port_scan", parameters={"target": ""}))
            step_id += 1
            steps.append(TaskStep(step_id=step_id, description="安全评估", tool="vuln_scan", parameters={"target": ""}))
            step_id += 1
            steps.append(TaskStep(step_id=step_id, description="生成报告", tool="generate_report", parameters={}))

        return steps

    def _get_current_step(self) -> Optional[TaskStep]:
        """获取当前步骤"""
        if self.memory.current_step_index < len(self.memory.plan):
            return self.memory.plan[self.memory.current_step_index]
        return None

    def _execute_step(self, step: TaskStep):
        """执行步骤"""
        step.status = "running"
        step.started_at = time.time()

        if self.callbacks["on_execute"]:
            self.callbacks["on_execute"](step)

        # 如果没有指定工具，标记为已完成（纯分析步骤）
        if not step.tool or step.tool not in self.tools_registry:
            step.status = "completed"
            step.result = {"message": f"步骤完成（无工具调用）: {step.description}"}
            step.completed_at = time.time()
            return

        # 执行工具
        try:
            tool_info = self.tools_registry[step.tool]
            func = tool_info["func"]
            params = step.parameters or {}
            result = func(**params)
            step.result = result
            step.status = "completed"
            self.memory.tools_used.append(step.tool)
        except Exception as e:
            step.status = "failed"
            step.result = {"error": str(e)}
            self.memory.errors.append(f"步骤{step.step_id}执行失败: {e}")

            # 重试机制
            if step.retries < self.max_retries:
                step.retries += 1
                step.status = "pending"
                self.memory.current_step_index -= 1  # 重新执行

        step.completed_at = time.time()

    def _observe(self, step: TaskStep):
        """观察步骤结果，提取关键信息"""
        observation = f"步骤{step.step_id} [{step.description}] 状态: {step.status}"

        if step.result:
            if isinstance(step.result, dict):
                # 提取关键指标
                for key in ["vulnerabilities_found", "open_ports", "directories_found", "risk_score", "total"]:
                    if key in step.result:
                        observation += f", {key}: {step.result[key]}"
            observation += f", 结果类型: {type(step.result).__name__}"

        self.memory.observations.append(observation)
        step.observation = observation

        if self.callbacks["on_observe"]:
            self.callbacks["on_observe"](step)

    def _reflect(self, step: TaskStep) -> bool:
        """
        反思：评估步骤结果，判断是否需要调整计划
        返回True表示需要调整
        """
        need_adjust = False
        reflection = f"反思步骤{step.step_id}: "

        # 检查步骤是否失败
        if step.status == "failed":
            reflection += "步骤失败，需要调整策略"
            need_adjust = True

        # 检查结果是否为空或异常
        elif step.result and isinstance(step.result, dict):
            if step.result.get("vulnerabilities_found", 0) == 0 and step.tool == "vuln_scan":
                reflection += "未发现漏洞，可能需要增加扫描深度或更换策略"
                need_adjust = True
            if step.result.get("open_ports", 0) == 0 and step.tool == "port_scan":
                reflection += "未发现开放端口，可能需要扩大端口范围"
                need_adjust = True

        # 检查是否已经进行了太多轮
        if self.memory.current_iteration > self.memory.max_iterations * 0.7:
            reflection += "迭代次数较多，考虑简化计划"
            need_adjust = True

        if not need_adjust:
            reflection += "结果正常，继续执行"

        self.memory.reflections.append(reflection)

        if self.callbacks["on_reflect"]:
            self.callbacks["on_reflect"](step, reflection, need_adjust)

        return need_adjust

    def _adjust(self, step: TaskStep):
        """调整计划：根据反思结果动态修改后续步骤"""
        adjustment = f"调整计划（基于步骤{step.step_id}的反思）: "

        # 如果步骤失败，添加替代方案
        if step.status == "failed":
            # 在当前步骤后添加替代步骤
            alt_step = TaskStep(
                step_id=len(self.memory.plan) + 1,
                description=f"替代方案: {step.description}（使用不同方法）",
                tool=step.tool,
                parameters={**(step.parameters or {}), "alternative": True},
            )
            self.memory.plan.insert(self.memory.current_step_index + 1, alt_step)
            adjustment += "添加替代方案步骤"

        # 如果漏洞扫描没结果，增加深度扫描
        elif step.tool == "vuln_scan" and step.result and step.result.get("vulnerabilities_found", 0) == 0:
            deep_step = TaskStep(
                step_id=len(self.memory.plan) + 1,
                description="深度漏洞扫描（增加模板和超时）",
                tool="vuln_scan",
                parameters={**(step.parameters or {}), "deep": True, "timeout": 10},
            )
            self.memory.plan.insert(self.memory.current_step_index + 1, deep_step)
            adjustment += "添加深度漏洞扫描步骤"

        # 如果端口扫描没结果，扩大范围
        elif step.tool == "port_scan" and step.result and step.result.get("open_ports", 0) == 0:
            wide_step = TaskStep(
                step_id=len(self.memory.plan) + 1,
                description="全端口扫描（扩大范围）",
                tool="port_scan",
                parameters={**(step.parameters or {}), "ports": "1-65535", "timeout": 5},
            )
            self.memory.plan.insert(self.memory.current_step_index + 1, wide_step)
            adjustment += "添加全端口扫描步骤"

        self.memory.adjustments.append(adjustment)

        if self.callbacks["on_adjust"]:
            self.callbacks["on_adjust"](step, adjustment)

    def _generate_final_result(self) -> Dict[str, Any]:
        """生成最终结果"""
        completed_steps = [s for s in self.memory.plan if s.status == "completed"]
        failed_steps = [s for s in self.memory.plan if s.status == "failed"]

        # 汇总所有步骤结果
        all_results = {}
        for step in self.memory.plan:
            if step.result:
                all_results[f"step_{step.step_id}"] = {
                    "description": step.description,
                    "status": step.status,
                    "result": step.result,
                }

        return {
            "status": "completed",
            "goal": self.memory.goal,
            "agent_type": self.agent_type,
            "summary": {
                "total_steps": len(self.memory.plan),
                "completed": len(completed_steps),
                "failed": len(failed_steps),
                "iterations": self.memory.current_iteration,
                "tools_used": list(set(self.memory.tools_used)),
                "duration": round(time.time() - self.memory.start_time, 2),
            },
            "plan": [
                {
                    "step_id": s.step_id,
                    "description": s.description,
                    "tool": s.tool,
                    "status": s.status,
                    "result": s.result,
                    "observation": s.observation,
                }
                for s in self.memory.plan
            ],
            "observations": self.memory.observations,
            "reflections": self.memory.reflections,
            "adjustments": self.memory.adjustments,
            "errors": self.memory.errors,
            "results": all_results,
        }

    def get_status(self) -> Dict[str, Any]:
        """获取智能体当前状态"""
        return {
            "state": self.state.value,
            "goal": self.memory.goal,
            "current_step": self.memory.current_step_index + 1,
            "total_steps": len(self.memory.plan),
            "iteration": self.memory.current_iteration,
            "max_iterations": self.memory.max_iterations,
            "tools_registered": list(self.tools_registry.keys()),
            "errors": self.memory.errors,
        }


class AgentOrchestrator:
    """智能体编排器 - 管理多个智能体协作"""

    def __init__(self):
        self.agents: Dict[str, EnhancedAgent] = {}
        self.shared_memory: Dict[str, Any] = {}

    def create_agent(self, agent_type: str, name: str) -> EnhancedAgent:
        """创建智能体"""
        agent = EnhancedAgent(agent_type=agent_type)
        self.agents[name] = agent
        return agent

    def register_shared_tool(self, name: str, func: Callable, description: str = ""):
        """注册共享工具（所有智能体可用）"""
        for agent in self.agents.values():
            agent.register_tool(name, func, description)

    def run_pipeline(self, tasks: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        运行智能体流水线
        tasks: [{"agent": "recon", "goal": "..."}, ...]
        """
        results = {}
        for i, task in enumerate(tasks):
            agent_name = task.get("agent", "default")
            goal = task.get("goal", "")

            if agent_name in self.agents:
                agent = self.agents[agent_name]
                # 传递前一个智能体的结果作为上下文
                if i > 0:
                    prev_result = results.get(f"task_{i-1}", {})
                    self.shared_memory[f"prev_result_{i}"] = prev_result

                result = agent.run(goal)
                results[f"task_{i}"] = result
                self.shared_memory[f"result_{i}"] = result

        return {
            "pipeline_status": "completed",
            "total_tasks": len(tasks),
            "results": results,
            "shared_memory_keys": list(self.shared_memory.keys()),
        }
