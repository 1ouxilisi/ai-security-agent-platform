#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
engine工作流引擎模块，提供相关安全测试工作流的定义和执行。

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
import uuid
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable
from enum import Enum

from utils.logger import log


class WorkflowStatus(str, Enum):
    """工作流状态"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PhaseStatus(str, Enum):
    """阶段状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING_APPROVAL = "waiting_approval"


class WorkflowPhase:
    """工作流阶段定义 - 增强版"""
    def __init__(
        self,
        phase_id: str,
        name: str,
        description: str,
        order: int,
        tools: List[Dict[str, Any]],
        ai_analysis_prompt: Optional[str] = None,
        required: bool = True,
        timeout: int = 300,
        # 增强属性
        condition: Optional[str] = None,  # 条件表达式，满足才执行
        parallel: bool = False,  # 阶段内工具是否并行执行
        require_approval: bool = False,  # 完成后是否需要人工审核才能继续
        approval_prompt: Optional[str] = None,  # 审核提示信息
        max_retries: int = 1,  # 阶段失败最大重试次数
        retry_delay: int = 5,  # 重试间隔（秒）
        on_failure: str = "continue",  # 失败后策略: continue/stop/jump:<phase_id>
        on_skip_reason: Optional[str] = None,  # 跳过时的原因
    ):
        """初始化WorkflowPhase实例。

        Args:
            self: 类实例。
        """
        self.phase_id = phase_id
        self.name = name
        self.description = description
        self.order = order
        self.tools = tools  # [{tool_name, parameters, description, max_retries, retry_delay}]
        self.ai_analysis_prompt = ai_analysis_prompt
        self.required = required
        self.timeout = timeout
        # 增强属性
        self.condition = condition
        self.parallel = parallel
        self.require_approval = require_approval
        self.approval_prompt = approval_prompt
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.on_failure = on_failure
        self.on_skip_reason = on_skip_reason
        # 运行时状态
        self.status = PhaseStatus.PENDING
        self.results: List[Dict[str, Any]] = []
        self.ai_analysis: Optional[str] = None
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.error: Optional[str] = None
        self.retry_count = 0
        self.approval_result: Optional[Dict[str, Any]] = None  # 审核结果
        self.skipped_reason: Optional[str] = None  # 实际跳过原因

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

            Returns:
            操作结果。
        """
        return {
            "phase_id": self.phase_id,
            "name": self.name,
            "description": self.description,
            "order": self.order,
            "tools_count": len(self.tools),
            "required": self.required,
            "status": self.status.value,
            "results_count": len(self.results),
            "ai_analysis": self.ai_analysis,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": round((self.end_time - self.start_time) * 1000, 2) if self.start_time and self.end_time else None,
            "error": self.error,
            "retry_count": self.retry_count,
            # 增强属性
            "has_condition": self.condition is not None,
            "condition": self.condition,
            "parallel": self.parallel,
            "require_approval": self.require_approval,
            "approval_prompt": self.approval_prompt,
            "approval_result": self.approval_result,
            "skipped_reason": self.skipped_reason,
            "results": self.results
        }


class WorkflowInstance:
    """工作流实例 - 增强版"""
    def __init__(
        self,
        workflow_id: str,
        name: str,
        target: str,
        description: str = "",
        phases: Optional[List[WorkflowPhase]] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """初始化WorkflowInstance实例。

        Args:
            self: 类实例。
        """
        self.instance_id = str(uuid.uuid4())[:8]
        self.workflow_id = workflow_id
        self.name = name
        self.target = target
        self.description = description
        self.phases: List[WorkflowPhase] = phases or []
        self.config = config or {}
        self.status = WorkflowStatus.PENDING
        self.current_phase_index = -1
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.created_at = datetime.now().isoformat()
        self.error: Optional[str] = None
        self.summary: Optional[Dict[str, Any]] = None
        self.report: Optional[str] = None
        # 增强：上下文变量，用于条件判断和动态参数
        self.context: Dict[str, Any] = {}
        # 增强：执行日志
        self.execution_log: List[Dict[str, Any]] = []
        # 增强：暂停事件
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # 默认不暂停

    def get_phase(self, phase_id: str) -> Optional[WorkflowPhase]:
        """获取相关数据。

            Args:
            phase_id: 相关参数。

            Returns:
            操作结果。
        """
        for phase in self.phases:
            if phase.phase_id == phase_id:
                return phase
        return None

    def get_current_phase(self) -> Optional[WorkflowPhase]:
        """获取相关数据。

            Returns:
            操作结果。
        """
        if 0 <= self.current_phase_index < len(self.phases):
            return self.phases[self.current_phase_index]
        return None

    def add_log(self, level: str, message: str, data: Optional[Dict] = None):
        """添加执行日志"""
        self.execution_log.append({
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
            "data": data
        })
        if len(self.execution_log) > 1000:
            self.execution_log = self.execution_log[-1000:]

    def to_dict(self, include_results: bool = True) -> Dict[str, Any]:
        """执行相关操作。

            Args:
            include_results: 相关参数。

            Returns:
            操作结果。
        """
        return {
            "instance_id": self.instance_id,
            "workflow_id": self.workflow_id,
            "name": self.name,
            "target": self.target,
            "description": self.description,
            "status": self.status.value,
            "current_phase_index": self.current_phase_index,
            "current_phase": self.get_current_phase().name if self.get_current_phase() else None,
            "phases_count": len(self.phases),
            "completed_phases": sum(1 for p in self.phases if p.status == PhaseStatus.COMPLETED),
            "failed_phases": sum(1 for p in self.phases if p.status == PhaseStatus.FAILED),
            "skipped_phases": sum(1 for p in self.phases if p.status == PhaseStatus.SKIPPED),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": round((self.end_time - self.start_time) * 1000, 2) if self.start_time and self.end_time else None,
            "created_at": self.created_at,
            "error": self.error,
            "summary": self.summary,
            "context_keys": list(self.context.keys()),
            "log_count": len(self.execution_log),
            "recent_logs": self.execution_log[-20:],
            "phases": [p.to_dict() if include_results else {k: v for k, v in p.to_dict().items() if k != 'results'} for p in self.phases]
        }


class ConditionEvaluator:
    """条件表达式求值器 - 用于阶段条件判断"""

    @staticmethod
    def evaluate(condition: str, instance: WorkflowInstance) -> bool:
        """
            求值条件表达式
            支持的函数：
            - has_open_port(port): 检查是否有开放端口
            - has_service(service): 检查是否有指定服务
            - has_vulnerability(severity): 检查是否有指定严重程度的漏洞
            - phase_completed(phase_id): 检查阶段是否完成
            - phase_failed(phase_id): 检查阶段是否失败
            - result_contains(phase_id, keyword): 检查阶段结果是否包含关键词
            - config_get(key): 获取配置值
            - context_get(key): 获取上下文变量
            支持逻辑运算符: and, or, not, ==, !=, >, <, >=, <=
        """
        try:
            # 构建可用变量和函数的命名空间
            namespace = ConditionEvaluator._build_namespace(instance)
            # 安全求值（只允许特定函数和运算符）
            result = eval(condition, {"__builtins__": {}}, namespace)
            return bool(result)
        except Exception as e:
            log.warning(f"条件表达式求值失败: {condition}, 错误: {e}")
            return True  # 求值失败默认执行，避免误跳过

    @staticmethod
    def _build_namespace(instance: WorkflowInstance) -> Dict[str, Any]:
        """构建条件求值的命名空间"""
        # 收集所有开放端口
        all_open_ports = set()
        all_services = set()
        all_vuln_severities = set()
        phase_results_map = {}

        for phase in instance.phases:
            phase_results_map[phase.phase_id] = phase.results
            for result in phase.results:
                if result.get("status") == "success" and result.get("result"):
                    r = result["result"]
                    if isinstance(r, dict):
                        if r.get("open_ports"):
                            all_open_ports.update(r["open_ports"])
                        if r.get("services"):
                            all_services.update(r["services"].keys() if isinstance(r["services"], dict) else r["services"])
                        if r.get("vulnerabilities"):
                            for v in r["vulnerabilities"]:
                                if isinstance(v, dict):
                                    all_vuln_severities.add(v.get("severity", "").lower())

        def has_open_port(port):
            """打开相关资源。

                Args:
                port: 相关参数。

                Returns:
                操作结果。
            """
            return int(port) in all_open_ports

        def has_service(service):
            """别名赋值。

                Args:
                service: 相关参数。

                Returns:
                操作结果。
            """
            return service.lower() in {s.lower() for s in all_services}

        def has_vulnerability(severity):
            """别名赋值。

                Args:
                severity: 相关参数。

                Returns:
                操作结果。
            """
            return severity.lower() in all_vuln_severities

        def phase_completed(phase_id):
            """别名赋值。

                Args:
                phase_id: 相关参数。

                Returns:
                操作结果。
            """
            p = instance.get_phase(phase_id)
            return p is not None and p.status == PhaseStatus.COMPLETED

        def phase_failed(phase_id):
            """别名赋值。

                Args:
                phase_id: 相关参数。

                Returns:
                操作结果。
            """
            p = instance.get_phase(phase_id)
            return p is not None and p.status == PhaseStatus.FAILED

        def result_contains(phase_id, keyword):
            """检查是否包含。

                Args:
                phase_id: 相关参数。
                keyword: 相关参数。

                Returns:
                操作结果。
            """
            results = phase_results_map.get(phase_id, [])
            for r in results:
                if keyword.lower() in json.dumps(r, ensure_ascii=False).lower():
                    return True
            return False

        def config_get(key):
            """获取相关数据。

                Args:
                key: 相关参数。

                Returns:
                操作结果。
            """
            return instance.config.get(key)

        def context_get(key):
            """获取相关数据。

                Args:
                key: 相关参数。

                Returns:
                操作结果。
            """
            return instance.context.get(key)

        return {
            "has_open_port": has_open_port,
            "has_service": has_service,
            "has_vulnerability": has_vulnerability,
            "phase_completed": phase_completed,
            "phase_failed": phase_failed,
            "result_contains": result_contains,
            "config_get": config_get,
            "context_get": context_get,
            "True": True,
            "False": False,
            "None": None,
        }


class WorkflowEngine:
    """工作流引擎 - 增强版 v2.0"""

    def __init__(self, tool_executor: Optional[Callable] = None, ai_analyzer: Optional[Callable] = None):
        """初始化WorkflowEngine实例。

            Args:
            self: 类实例。
        """
        self.tool_executor = tool_executor
        self.ai_analyzer = ai_analyzer
        self.instances: Dict[str, WorkflowInstance] = {}
        self._running = False

    def create_instance(
        self,
        workflow_id: str,
        name: str,
        target: str,
        phases: List[WorkflowPhase],
        description: str = "",
        config: Optional[Dict[str, Any]] = None
    ) -> WorkflowInstance:
        """创建相关数据。

        Args:
            workflow_id: 相关参数。
            name: 相关参数。
            target: 相关参数。
            phases: 相关参数。
            description: 相关参数。
            config: 相关参数。

        Returns:
            操作结果。
        """
        instance = WorkflowInstance(
            workflow_id=workflow_id,
            name=name,
            target=target,
            description=description,
            phases=phases,
            config=config
        )
        self.instances[instance.instance_id] = instance
        instance.add_log("info", f"工作流实例创建: {name}, 目标: {target}")
        log.info(f"创建工作流实例: {instance.instance_id} - {name} - 目标: {target}")
        return instance

    def get_instance(self, instance_id: str) -> Optional[WorkflowInstance]:
        """获取相关数据。

            Args:
            instance_id: 相关参数。

            Returns:
            操作结果。
        """
        return self.instances.get(instance_id)

    def list_instances(self) -> List[Dict[str, Any]]:
        """列出相关数据。

            Returns:
            操作结果。
        """
        return [inst.to_dict(include_results=False) for inst in self.instances.values()]

    async def _execute_single_tool(self, tool_def: Dict, instance: WorkflowInstance, phase: WorkflowPhase) -> Dict:
        """执行单个工具（含重试）"""
        tool_name = tool_def["tool_name"]
        parameters = tool_def.get("parameters", {})
        max_retries = tool_def.get("max_retries", 1)
        retry_delay = tool_def.get("retry_delay", 3)

        # 替换参数中的目标占位符和上下文变量
        parameters = self._replace_placeholders(parameters, instance)

        last_error = None
        for attempt in range(max_retries):
            try:
                instance.add_log("info", f"执行工具: {tool_name} (尝试 {attempt+1}/{max_retries})", {"tool": tool_name})
                log.info(f"  执行工具: {tool_name}, 参数: {json.dumps(parameters, ensure_ascii=False)[:100]}")

                if self.tool_executor:
                    result = await self.tool_executor(tool_name, parameters)
                else:
                    result = {"status": "skipped", "message": "工具执行器未配置"}

                return {
                    "tool_name": tool_name,
                    "parameters": parameters,
                    "status": "success",
                    "result": result,
                    "attempt": attempt + 1,
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                last_error = str(e)
                instance.add_log("warning", f"工具 {tool_name} 执行失败 (尝试 {attempt+1}/{max_retries}): {e}")
                log.error(f"  工具 {tool_name} 执行失败: {str(e)}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)

        return {
            "tool_name": tool_name,
            "parameters": parameters,
            "status": "failed",
            "error": last_error,
            "attempt": max_retries,
            "timestamp": datetime.now().isoformat()
        }

    async def execute_phase(self, instance: WorkflowInstance, phase: WorkflowPhase) -> bool:
        """执行单个阶段（增强版：支持并行/重试/AI分析）"""
        phase.status = PhaseStatus.RUNNING
        phase.start_time = time.time()
        instance.add_log("info", f"开始执行阶段: {phase.name}")
        log.info(f"开始执行阶段: {phase.name}")

        try:
            # 执行阶段中的工具
            if phase.parallel and len(phase.tools) > 1:
                # 并行执行
                instance.add_log("info", f"阶段 {phase.name} 并行执行 {len(phase.tools)} 个工具")
                tasks = [self._execute_single_tool(tool_def, instance, phase) for tool_def in phase.tools]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, Exception):
                        phase.results.append({
                            "tool_name": "unknown",
                            "status": "failed",
                            "error": str(r),
                            "timestamp": datetime.now().isoformat()
                        })
                    else:
                        phase.results.append(r)
            else:
                # 顺序执行
                for tool_def in phase.tools:
                    result = await self._execute_single_tool(tool_def, instance, phase)
                    phase.results.append(result)

            # 更新上下文变量（从工具结果中提取）
            self._update_context_from_results(instance, phase)

            # AI分析阶段结果
            if self.ai_analyzer and phase.ai_analysis_prompt:
                try:
                    context = {
                        "target": instance.target,
                        "phase_name": phase.name,
                        "phase_description": phase.description,
                        "results": phase.results,
                        "workflow_context": instance.context
                    }
                    instance.add_log("info", f"阶段 {phase.name} 开始AI分析")
                    phase.ai_analysis = await self.ai_analyzer(phase.ai_analysis_prompt, context)
                    instance.add_log("info", f"阶段 {phase.name} AI分析完成")
                    log.info(f"  AI分析完成: {phase.name}")
                except Exception as e:
                    log.error(f"  AI分析失败: {str(e)}")
                    phase.ai_analysis = f"AI分析失败: {str(e)}"
                    instance.add_log("warning", f"阶段 {phase.name} AI分析失败: {e}")

            phase.status = PhaseStatus.COMPLETED
            phase.end_time = time.time()
            instance.add_log("info", f"阶段完成: {phase.name}, 耗时: {round(phase.end_time - phase.start_time, 2)}秒")
            log.info(f"阶段完成: {phase.name}, 耗时: {round(phase.end_time - phase.start_time, 2)}秒")
            return True

        except Exception as e:
            phase.status = PhaseStatus.FAILED
            phase.error = str(e)
            phase.end_time = time.time()
            instance.add_log("error", f"阶段失败: {phase.name}, 错误: {e}")
            log.error(f"阶段失败: {phase.name}, 错误: {str(e)}")
            return False

    def _update_context_from_results(self, instance: WorkflowInstance, phase: WorkflowPhase):
        """从工具结果中更新上下文变量"""
        for result in phase.results:
            if result.get("status") == "success" and result.get("result"):
                r = result["result"]
                if isinstance(r, dict):
                    # 提取开放端口
                    if r.get("open_ports"):
                        instance.context.setdefault("open_ports", [])
                        instance.context["open_ports"] = list(set(instance.context["open_ports"] + r["open_ports"]))
                    # 提取服务
                    if r.get("services"):
                        instance.context.setdefault("services", {})
                        if isinstance(r["services"], dict):
                            instance.context["services"].update(r["services"])
                    # 提取漏洞
                    if r.get("vulnerabilities"):
                        instance.context.setdefault("vulnerabilities", [])
                        instance.context["vulnerabilities"].extend(r["vulnerabilities"])
                    # 提取HTTP状态
                    if r.get("status_code"):
                        instance.context[f"{phase.phase_id}_http_status"] = r["status_code"]

    async def execute_workflow(self, instance_id: str) -> WorkflowInstance:
        """执行完整工作流（增强版：支持条件分支/人工审核/暂停继续/动态跳转）"""
        instance = self.get_instance(instance_id)
        if not instance:
            raise ValueError(f"工作流实例不存在: {instance_id}")

        instance.status = WorkflowStatus.RUNNING
        instance.start_time = time.time()
        instance.add_log("info", f"工作流开始执行: {instance.name}, 目标: {instance.target}")
        log.info(f"开始执行工作流: {instance.name} - 目标: {instance.target}")

        try:
            i = 0
            while i < len(instance.phases):
                instance.current_phase_index = i
                phase = instance.phases[i]

                # 检查暂停
                await instance._pause_event.wait()

                # 检查取消
                if instance.status == WorkflowStatus.CANCELLED:
                    instance.add_log("warning", "工作流被取消")
                    break

                # 条件判断
                if phase.condition:
                    if not ConditionEvaluator.evaluate(phase.condition, instance):
                        phase.status = PhaseStatus.SKIPPED
                        phase.skipped_reason = f"条件不满足: {phase.condition}"
                        instance.add_log("info", f"跳过阶段 {phase.name}: 条件不满足")
                        log.info(f"跳过阶段: {phase.name} (条件不满足: {phase.condition})")
                        i += 1
                        continue

                # 已跳过的阶段
                if phase.status == PhaseStatus.SKIPPED:
                    i += 1
                    continue

                # 执行阶段（含重试）
                success = False
                for retry in range(phase.max_retries):
                    phase.retry_count = retry
                    if retry > 0:
                        instance.add_log("info", f"阶段 {phase.name} 重试 {retry}/{phase.max_retries}")
                        await asyncio.sleep(phase.retry_delay)
                        # 重置阶段状态
                        phase.status = PhaseStatus.RUNNING
                        phase.results = []
                        phase.error = None

                    success = await self.execute_phase(instance, phase)
                    if success:
                        break

                # 处理失败
                if not success:
                    instance.add_log("error", f"阶段 {phase.name} 最终失败")
                    if phase.required:
                        instance.status = WorkflowStatus.FAILED
                        instance.error = f"必需阶段失败: {phase.name}"
                        break
                    elif phase.on_failure == "stop":
                        instance.status = WorkflowStatus.FAILED
                        instance.error = f"阶段失败后停止: {phase.name}"
                        break
                    elif phase.on_failure.startswith("jump:"):
                        target_phase_id = phase.on_failure.split(":", 1)[1]
                        target_idx = next((idx for idx, p in enumerate(instance.phases) if p.phase_id == target_phase_id), None)
                        if target_idx is not None:
                            instance.add_log("info", f"跳转到阶段: {target_phase_id}")
                            i = target_idx
                            continue

                # 人工审核节点
                if phase.require_approval and success:
                    phase.status = PhaseStatus.WAITING_APPROVAL
                    instance.status = WorkflowStatus.WAITING_APPROVAL
                    instance.add_log("info", f"阶段 {phase.name} 完成，等待人工审核")
                    log.info(f"等待人工审核: {phase.name}")

                    # 等待审核（通过approval_result判断）
                    while phase.approval_result is None:
                        if instance.status == WorkflowStatus.CANCELLED:
                            break
                        await asyncio.sleep(1)

                    if instance.status == WorkflowStatus.CANCELLED:
                        break

                    # 处理审核结果
                    approval = phase.approval_result
                    if approval.get("action") == "reject":
                        instance.status = WorkflowStatus.FAILED
                        instance.error = f"人工审核拒绝: {approval.get('reason', '无原因')}"
                        instance.add_log("warning", f"人工审核拒绝: {approval.get('reason')}")
                        break
                    elif approval.get("action") == "skip":
                        instance.add_log("info", "人工审核选择跳过后续阶段")
                        break
                    # approve 则继续

                    instance.status = WorkflowStatus.RUNNING
                    phase.status = PhaseStatus.COMPLETED
                    instance.add_log("info", "人工审核通过，继续执行")

                i += 1

            if instance.status in (WorkflowStatus.RUNNING, WorkflowStatus.WAITING_APPROVAL):
                instance.status = WorkflowStatus.COMPLETED
                instance.summary = self._generate_summary(instance)
                instance.add_log("info", "工作流全部完成")
                log.info(f"工作流完成: {instance.name}")

        except Exception as e:
            instance.status = WorkflowStatus.FAILED
            instance.error = str(e)
            instance.add_log("error", f"工作流异常: {e}")
            log.error(f"工作流失败: {instance.name}, 错误: {str(e)}")

        instance.end_time = time.time()
        return instance

    def pause_workflow(self, instance_id: str) -> bool:
        """暂停工作流"""
        instance = self.get_instance(instance_id)
        if not instance or instance.status != WorkflowStatus.RUNNING:
            return False
        instance._pause_event.clear()
        instance.status = WorkflowStatus.PAUSED
        instance.add_log("info", "工作流被暂停")
        log.info(f"暂停工作流: {instance_id}")
        return True

    def resume_workflow(self, instance_id: str) -> bool:
        """继续工作流"""
        instance = self.get_instance(instance_id)
        if not instance or instance.status != WorkflowStatus.PAUSED:
            return False
        instance._pause_event.set()
        instance.status = WorkflowStatus.RUNNING
        instance.add_log("info", "工作流继续执行")
        log.info(f"继续工作流: {instance_id}")
        return True

    def submit_approval(self, instance_id: str, phase_id: str, action: str, reason: str = "") -> bool:
        """提交人工审核结果"""
        instance = self.get_instance(instance_id)
        if not instance:
            return False
        phase = instance.get_phase(phase_id)
        if not phase or phase.status != PhaseStatus.WAITING_APPROVAL:
            return False
        phase.approval_result = {
            "action": action,  # approve/reject/skip
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        }
        instance.add_log("info", f"人工审核提交: {action}, 原因: {reason}")
        log.info(f"人工审核: {instance_id}/{phase_id} -> {action}")
        return True

    def cancel_workflow(self, instance_id: str) -> bool:
        """取消工作流"""
        instance = self.get_instance(instance_id)
        if not instance:
            return False
        if instance.status in (WorkflowStatus.RUNNING, WorkflowStatus.PAUSED, WorkflowStatus.WAITING_APPROVAL):
            instance.status = WorkflowStatus.CANCELLED
            instance._pause_event.set()  # 解除暂停
            instance.add_log("warning", "工作流被取消")
            log.info(f"取消工作流: {instance_id}")
            return True
        return False

    def _replace_placeholders(self, parameters: Dict[str, Any], instance: WorkflowInstance) -> Dict[str, Any]:
        """替换参数中的占位符（支持{target}和{context.key}）"""
        result = {}
        for key, value in parameters.items():
            if isinstance(value, str):
                # 替换 {target}
                value = value.replace("{target}", instance.target).replace("{TARGET}", instance.target)
                # 替换 {context.key}
                context_vars = re.findall(r'\{context\.(\w+)\}', value)
                for var in context_vars:
                    if var in instance.context:
                        val = instance.context[var]
                        if isinstance(val, (list, dict)):
                            val = json.dumps(val, ensure_ascii=False)
                        value = value.replace(f"{{context.{var}}}", str(val))
                result[key] = value
            elif isinstance(value, dict):
                result[key] = self._replace_placeholders(value, instance)
            else:
                result[key] = value
        return result

    def _generate_summary(self, instance: WorkflowInstance) -> Dict[str, Any]:
        """生成工作流总结"""
        total_tools = sum(len(p.tools) for p in instance.phases)
        successful_tools = sum(
            sum(1 for r in p.results if r.get("status") == "success")
            for p in instance.phases
        )
        failed_tools = sum(
            sum(1 for r in p.results if r.get("status") == "failed")
            for p in instance.phases
        )
        skipped_phases = sum(1 for p in instance.phases if p.status == PhaseStatus.SKIPPED)

        # 收集所有发现
        findings = []
        for phase in instance.phases:
            for result in phase.results:
                if result.get("status") == "success" and result.get("result"):
                    r = result["result"]
                    if isinstance(r, dict):
                        if r.get("open_ports"):
                            findings.append({
                                "type": "open_ports",
                                "phase": phase.name,
                                "tool": result["tool_name"],
                                "data": r["open_ports"],
                                "severity": "info"
                            })
                        if r.get("vulnerabilities"):
                            for vuln in r["vulnerabilities"]:
                                findings.append({
                                    "type": "vulnerability",
                                    "phase": phase.name,
                                    "tool": result["tool_name"],
                                    "data": vuln,
                                    "severity": vuln.get("severity", "medium") if isinstance(vuln, dict) else "medium"
                                })

        return {
            "target": instance.target,
            "total_phases": len(instance.phases),
            "completed_phases": sum(1 for p in instance.phases if p.status == PhaseStatus.COMPLETED),
            "skipped_phases": skipped_phases,
            "failed_phases": sum(1 for p in instance.phases if p.status == PhaseStatus.FAILED),
            "total_tools": total_tools,
            "successful_tools": successful_tools,
            "failed_tools": failed_tools,
            "findings_count": len(findings),
            "findings": findings[:20],
            "context_summary": {k: type(v).__name__ for k, v in instance.context.items()},
            "duration_seconds": round((instance.end_time - instance.start_time), 2) if instance.start_time and instance.end_time else 0
        }


# 全局工作流引擎实例
workflow_engine = WorkflowEngine()


# ============================================================
# Round 7 新增：步骤级 DAG 执行引擎（向后兼容，不影响上述已有代码）
# ============================================================
import threading  # noqa: E402
from concurrent.futures import ThreadPoolExecutor  # noqa: E402


class StepStatus(str, Enum):
    """DAG 步骤状态"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class _DotDict(dict):
    """支持点号访问的字典，用于条件表达式 steps.xxx.result.yyy"""
    def __getattr__(self, item):
        try:
            v = self[item]
        except KeyError:
            raise AttributeError(item)
        if isinstance(v, dict) and not isinstance(v, _DotDict):
            v = _DotDict(v)
            self[item] = v
        return v

    def __setattr__(self, key, value):
        self[key] = value


class WorkflowStep:
    """DAG 工作流步骤定义与运行态"""

    def __init__(
        self,
        step_id: str,
        name: str,
        description: str = "",
        action_type: str = "tool_call",
        action_params: Optional[Dict[str, Any]] = None,
        depends_on: Optional[List[str]] = None,
        condition: Optional[str] = None,
        on_failure: str = "continue",
        retry_count: int = 0,
        retry_delay: float = 2.0,
        timeout: int = 300,
    ):
        self.step_id = step_id
        self.name = name
        self.description = description
        self.action_type = action_type
        self.action_params = action_params or {}
        self.depends_on = depends_on or []
        self.condition = condition
        self.on_failure = on_failure
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.timeout = timeout
        self.status = StepStatus.PENDING
        self.result: Any = None
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.error: Optional[str] = None
        self.logs: List[Dict[str, Any]] = []
        self.attempts = 0

    def add_log(self, level: str, message: str, data: Any = None):
        self.logs.append({
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
            "data": data,
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "name": self.name,
            "description": self.description,
            "action_type": self.action_type,
            "action_params": self.action_params,
            "depends_on": self.depends_on,
            "condition": self.condition,
            "on_failure": self.on_failure,
            "retry_count": self.retry_count,
            "retry_delay": self.retry_delay,
            "timeout": self.timeout,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": round((self.end_time - self.start_time) * 1000, 2)
            if self.start_time and self.end_time else None,
            "attempts": self.attempts,
            "logs": self.logs,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "WorkflowStep":
        return cls(
            step_id=d.get("step_id") or d.get("id") or "",
            name=d.get("name", ""),
            description=d.get("description", ""),
            action_type=d.get("action_type", "tool_call"),
            action_params=d.get("action_params") or d.get("parameters") or {},
            depends_on=d.get("depends_on", []) or [],
            condition=d.get("condition"),
            on_failure=d.get("on_failure", "continue"),
            retry_count=int(d.get("retry_count", 0) or 0),
            retry_delay=float(d.get("retry_delay", 2.0) or 2.0),
            timeout=int(d.get("timeout", 300) or 300),
        )


class DAGInstance:
    """DAG 工作流实例"""

    def __init__(self, instance_id: str, name: str, target: str,
                 steps: List[WorkflowStep], description: str = "",
                 params: Optional[Dict[str, Any]] = None):
        self.instance_id = instance_id
        self.name = name
        self.target = target
        self.description = description
        self.steps: Dict[str, WorkflowStep] = {s.step_id: s for s in steps}
        self.params = params or {}
        self.status = StepStatus.PENDING
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.created_at = datetime.now().isoformat()
        self.logs: List[Dict[str, Any]] = []
        self.aggregated_result: Dict[str, Any] = {}
        self.error: Optional[str] = None
        self._cancel_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()

    def step_list(self) -> List[WorkflowStep]:
        return list(self.steps.values())

    def add_log(self, level: str, message: str, data: Any = None):
        self.logs.append({
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
            "data": data,
        })
        if len(self.logs) > 2000:
            self.logs = self.logs[-2000:]

    def progress(self) -> Dict[str, Any]:
        total = len(self.steps)
        completed = sum(1 for s in self.steps.values()
                        if s.status in (StepStatus.COMPLETED, StepStatus.SKIPPED))
        failed = sum(1 for s in self.steps.values() if s.status == StepStatus.FAILED)
        running = sum(1 for s in self.steps.values() if s.status == StepStatus.RUNNING)
        pending = sum(1 for s in self.steps.values() if s.status == StepStatus.PENDING)
        pct = round(completed / total * 100, 1) if total else 100.0
        elapsed = (time.time() - self.start_time) if self.start_time else 0.0
        eta = None
        if 0 < completed < total and elapsed > 0:
            eta = round((elapsed / completed) * (total - completed), 1)
        return {
            "total_steps": total,
            "completed_steps": completed,
            "failed_steps": failed,
            "running_steps": running,
            "pending_steps": pending,
            "percent": pct,
            "elapsed_seconds": round(elapsed, 2),
            "eta_seconds": eta,
        }

    def to_dict(self, include_steps: bool = True) -> Dict[str, Any]:
        d = {
            "instance_id": self.instance_id,
            "name": self.name,
            "target": self.target,
            "description": self.description,
            "status": self.status.value,
            "params": self.params,
            "created_at": self.created_at,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round((self.end_time - self.start_time), 2)
            if self.start_time and self.end_time else None,
            "error": self.error,
            "progress": self.progress(),
            "log_count": len(self.logs),
            "recent_logs": self.logs[-30:],
        }
        if include_steps:
            d["steps"] = [s.to_dict() for s in self.step_list()]
        return d


class DAGWorkflowEngine:
    """步骤级 DAG 执行引擎：拓扑排序 + 线程池并行 + 条件分支 + 重试退避"""

    MAX_RETRY = 3

    def __init__(self, tool_executor: Optional[Callable] = None):
        self.tool_executor = tool_executor
        self.instances: Dict[str, DAGInstance] = {}
        self._lock = threading.RLock()

    def create_instance(self, name: str, target: str, steps_def: List[Dict[str, Any]],
                        description: str = "", params: Optional[Dict[str, Any]] = None) -> DAGInstance:
        steps = [WorkflowStep.from_dict(s) for s in steps_def]
        inst = DAGInstance(
            instance_id=str(uuid.uuid4())[:8],
            name=name, target=target, steps=steps,
            description=description, params=params,
        )
        self._replace_placeholders(inst)
        with self._lock:
            self.instances[inst.instance_id] = inst
        inst.add_log("info", f"DAG工作流创建: {name}, 步骤数={len(steps)}, 目标={target}")
        log.info(f"[DAG] 创建实例 {inst.instance_id}: {name}, 步骤数={len(steps)}")
        return inst

    def get_instance(self, instance_id: str) -> Optional[DAGInstance]:
        return self.instances.get(instance_id)

    def list_instances(self) -> List[Dict[str, Any]]:
        return [i.to_dict(include_steps=False) for i in self.instances.values()]

    def _replace_placeholders(self, inst: DAGInstance):
        def repl(v):
            if isinstance(v, str):
                v = v.replace("{target}", inst.target).replace("{TARGET}", inst.target)
                for k, val in inst.params.items():
                    v = v.replace("{%s}" % k, str(val))
                return v
            if isinstance(v, dict):
                return {kk: repl(vv) for kk, vv in v.items()}
            if isinstance(v, list):
                return [repl(x) for x in v]
            return v

        for s in inst.steps.values():
            s.action_params = repl(s.action_params)
            if isinstance(s.name, str):
                s.name = repl(s.name)
            if isinstance(s.description, str):
                s.description = repl(s.description)

    @staticmethod
    def topo_sort(steps: Dict[str, WorkflowStep]) -> List[str]:
        indeg = {sid: 0 for sid in steps}
        graph = {sid: [] for sid in steps}
        for sid, s in steps.items():
            for dep in s.depends_on:
                if dep in steps:
                    graph[dep].append(sid)
                    indeg[sid] += 1
        queue = [sid for sid, d in indeg.items() if d == 0]
        order = []
        while queue:
            n = queue.pop(0)
            order.append(n)
            for nxt in graph[n]:
                indeg[nxt] -= 1
                if indeg[nxt] == 0:
                    queue.append(nxt)
        if len(order) != len(steps):
            raise ValueError("DAG 存在循环依赖")
        return order

    def _eval_condition(self, cond: str, inst: DAGInstance) -> bool:
        if not cond:
            return True
        try:
            ns = {
                "steps": _DotDict({
                    sid: _DotDict({
                        "result": s.result if isinstance(s.result, dict)
                        else ({"value": s.result} if s.result is not None else {}),
                        "status": s.status.value,
                        "error": s.error,
                    }) for sid, s in inst.steps.items()
                }),
                "target": inst.target,
                "params": inst.params,
                "True": True, "False": False, "None": None,
                "true": True, "false": False,
            }
            return bool(eval(cond, {"__builtins__": {}}, ns))
        except Exception as e:
            inst.add_log("warning", f"条件求值失败，默认执行: {cond} ({e})")
            return True

    def _execute_step(self, inst: DAGInstance, step: WorkflowStep) -> Any:
        step.attempts += 1
        step.status = StepStatus.RUNNING
        step.start_time = time.time()
        step.add_log("info", f"开始执行步骤 (第{step.attempts}次)")
        inst.add_log("info", f"[{step.step_id}] 开始: {step.name}", {"params": step.action_params})

        last_err = None
        max_try = 1 + max(0, min(step.retry_count, self.MAX_RETRY))
        for attempt in range(1, max_try + 1):
            if inst._cancel_event.is_set():
                step.status = StepStatus.CANCELLED
                step.end_time = time.time()
                return None
            inst._pause_event.wait()
            try:
                if self.tool_executor is not None:
                    result = self.tool_executor(step.action_type, step.action_params, {
                        "target": inst.target, "step": step.step_id, "params": inst.params,
                    })
                    if asyncio.iscoroutine(result):
                        try:
                            loop = asyncio.new_event_loop()
                            result = loop.run_until_complete(result)
                            loop.close()
                        except Exception:
                            result = {"status": "failed", "error": "协程执行失败"}
                else:
                    result = {
                        "status": "success",
                        "dry_run": True,
                        "message": f"[dry-run] 模拟执行 {step.action_type}:{step.action_params}",
                        "tool": step.action_params.get("tool") or step.action_params.get("action") or step.name,
                    }
                step.result = result
                step.status = StepStatus.COMPLETED
                step.end_time = time.time()
                step.error = None
                step.add_log("info", f"步骤成功，耗时 {round(step.end_time - step.start_time, 2)}s")
                inst.add_log("info", f"[{step.step_id}] 完成")
                return result
            except Exception as e:
                last_err = str(e)
                step.error = last_err
                step.add_log("error", f"执行失败(尝试{attempt}/{max_try}): {e}")
                if attempt < max_try:
                    delay = step.retry_delay * (2 ** (attempt - 1))
                    inst.add_log("warning", f"[{step.step_id}] {delay:.1f}s 后重试")
                    for _ in range(int(delay * 10)):
                        if inst._cancel_event.is_set():
                            break
                        time.sleep(0.1)
        step.status = StepStatus.FAILED
        step.end_time = time.time()
        inst.add_log("error", f"[{step.step_id}] 最终失败: {last_err}")
        raise RuntimeError(last_err or "步骤执行失败")

    def run(self, instance_id: str) -> DAGInstance:
        inst = self.instances.get(instance_id)
        if not inst:
            raise ValueError(f"实例不存在: {instance_id}")

        inst.status = StepStatus.RUNNING
        inst.start_time = time.time()
        inst.add_log("info", f"DAG 工作流开始执行，共 {len(inst.steps)} 步")

        failed_fatal = False
        try:
            order = self.topo_sort(inst.steps)
            remaining = set(order)

            while remaining:
                if inst._cancel_event.is_set():
                    inst.add_log("warning", "工作流被取消")
                    inst.status = StepStatus.CANCELLED
                    break

                ready = []
                for sid in order:
                    if sid not in remaining:
                        continue
                    s = inst.steps[sid]
                    if s.status in (StepStatus.COMPLETED, StepStatus.FAILED,
                                    StepStatus.SKIPPED, StepStatus.CANCELLED):
                        remaining.discard(sid)
                        continue
                    deps = [inst.steps[d] for d in s.depends_on if d in inst.steps]
                    deps_ok = all(dep.status in (StepStatus.COMPLETED, StepStatus.SKIPPED) for dep in deps)
                    deps_failed = any(dep.status == StepStatus.FAILED for dep in deps)
                    if deps_failed and s.on_failure == "stop":
                        s.status = StepStatus.SKIPPED
                        s.add_log("warning", "依赖步骤失败，跳过")
                        remaining.discard(sid)
                        continue
                    if deps_ok:
                        ready.append(s)

                if not ready:
                    for sid in list(remaining):
                        s = inst.steps[sid]
                        if s.status == StepStatus.PENDING:
                            s.status = StepStatus.SKIPPED
                            s.add_log("warning", "依赖失败，跳过")
                    remaining.clear()
                    break

                to_run = []
                for s in ready:
                    if s.condition and not self._eval_condition(s.condition, inst):
                        s.status = StepStatus.SKIPPED
                        s.end_time = time.time()
                        s.add_log("info", f"条件不满足，跳过: {s.condition}")
                        remaining.discard(s.step_id)
                    else:
                        to_run.append(s)

                if not to_run:
                    continue

                max_workers = min(4, max(1, len(to_run)))
                from concurrent.futures import as_completed
                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    fut_map = {ex.submit(self._execute_step, inst, s): s for s in to_run}
                    for fut in as_completed(fut_map):
                        s = fut_map[fut]
                        try:
                            fut.result()
                        except Exception as e:
                            inst.add_log("error", f"[{s.step_id}] 失败: {e}")
                            if s.on_failure == "stop":
                                failed_fatal = True
                                inst.error = f"步骤 {s.step_id} 失败且策略为 stop"
                                inst.add_log("error", f"策略 stop，终止: {s.step_id}")
                        remaining.discard(s.step_id)

                if failed_fatal:
                    inst.status = StepStatus.FAILED
                    break

            if inst.status == StepStatus.RUNNING:
                inst.status = StepStatus.COMPLETED
                inst.add_log("info", "DAG 工作流全部完成")

        except Exception as e:
            inst.status = StepStatus.FAILED
            inst.error = str(e)
            inst.add_log("error", f"工作流异常: {e}")
            log.error(f"[DAG] 实例 {instance_id} 异常: {e}")
        finally:
            inst.end_time = time.time()
            inst.aggregated_result = self._aggregate(inst)
            inst.add_log("info", f"工作流结束，状态={inst.status.value}, 耗时={round(inst.end_time - inst.start_time, 2)}s")

        return inst

    def _aggregate(self, inst: DAGInstance) -> Dict[str, Any]:
        step_results = {}
        vulns = []
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for s in inst.steps.values():
            step_results[s.step_id] = {
                "name": s.name,
                "status": s.status.value,
                "result": s.result,
                "error": s.error,
                "duration_ms": round((s.end_time - s.start_time) * 1000, 2) if s.start_time and s.end_time else None,
            }
            if isinstance(s.result, dict):
                vs = s.result.get("vulnerabilities") or s.result.get("vulns") or []
                if isinstance(vs, list):
                    for v in vs:
                        if isinstance(v, dict):
                            sev = str(v.get("severity", "info")).lower()
                            severity_count[sev] = severity_count.get(sev, 0) + 1
                            vulns.append({**v, "_step": s.step_id, "_step_name": s.name})

        score = min(100, severity_count["critical"] * 40 + severity_count["high"] * 15
                    + severity_count["medium"] * 5 + severity_count["low"] * 1)
        if severity_count["critical"] > 0:
            risk_level = "critical"
        elif severity_count["high"] > 0:
            risk_level = "high"
        elif severity_count["medium"] > 0:
            risk_level = "medium"
        elif severity_count["low"] > 0:
            risk_level = "low"
        else:
            risk_level = "info"

        return {
            "target": inst.target,
            "name": inst.name,
            "status": inst.status.value,
            "progress": inst.progress(),
            "step_results": step_results,
            "vulnerabilities": vulns,
            "severity_count": severity_count,
            "risk_score": score,
            "risk_level": risk_level,
            "summary": {
                "total_steps": len(inst.steps),
                "completed": sum(1 for s in inst.steps.values() if s.status == StepStatus.COMPLETED),
                "failed": sum(1 for s in inst.steps.values() if s.status == StepStatus.FAILED),
                "skipped": sum(1 for s in inst.steps.values() if s.status == StepStatus.SKIPPED),
                "vulnerabilities_count": len(vulns),
                "duration_seconds": round(inst.end_time - inst.start_time, 2) if inst.start_time and inst.end_time else None,
            },
        }

    def cancel(self, instance_id: str) -> bool:
        inst = self.instances.get(instance_id)
        if not inst:
            return False
        if inst.status in (StepStatus.RUNNING, StepStatus.PENDING, StepStatus.PAUSED):
            inst._cancel_event.set()
            inst._pause_event.set()
            inst.add_log("warning", "收到取消信号")
            return True
        return False

    def pause(self, instance_id: str) -> bool:
        inst = self.instances.get(instance_id)
        if inst and inst.status == StepStatus.RUNNING:
            inst._pause_event.clear()
            inst.status = StepStatus.PAUSED
            inst.add_log("warning", "工作流暂停")
            return True
        return False

    def resume(self, instance_id: str) -> bool:
        inst = self.instances.get(instance_id)
        if inst and inst.status == StepStatus.PAUSED:
            inst._pause_event.set()
            inst.status = StepStatus.RUNNING
            inst.add_log("info", "工作流继续")
            return True
        return False

    def retry_failed(self, instance_id: str) -> bool:
        inst = self.instances.get(instance_id)
        if not inst:
            return False
        failed = [s for s in inst.steps.values() if s.status == StepStatus.FAILED]
        if not failed:
            return False
        for s in failed:
            s.status = StepStatus.PENDING
            s.result = None
            s.error = None
            s.start_time = None
            s.end_time = None
            s.attempts = 0
        inst.status = StepStatus.RUNNING
        inst._cancel_event.clear()
        inst.start_time = time.time()
        t = threading.Thread(target=self._run_guarded, args=(instance_id,), daemon=True)
        t.start()
        return True

    def start_async(self, instance_id: str) -> threading.Thread:
        t = threading.Thread(target=self._run_guarded, args=(instance_id,), daemon=True)
        t.start()
        return t

    def _run_guarded(self, instance_id: str):
        try:
            self.run(instance_id)
        except Exception as e:
            inst = self.instances.get(instance_id)
            if inst:
                inst.status = StepStatus.FAILED
                inst.error = str(e)
                inst.end_time = time.time()
                inst.aggregated_result = self._aggregate(inst)
            log.error(f"[DAG] 后台执行异常 {instance_id}: {e}")


# 全局 DAG 工作流引擎单例
dag_engine = DAGWorkflowEngine()
