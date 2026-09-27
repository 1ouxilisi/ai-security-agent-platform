#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
workflow_engine安全工具集成模块，提供相关安全工具的封装和调用。

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
import os
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable, Coroutine
from dataclasses import dataclass, field
from enum import Enum
from loguru import logger


class StepStatus(Enum):
    """步骤状态"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


class WorkflowStatus(Enum):
    """工作流状态"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class WorkflowStep:
    """工作流步骤"""
    id: str
    name: str
    type: str  # scan/enum/exploit/verify/report/custom
    description: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    condition: str = ""  # 条件表达式，满足才执行
    timeout: int = 300  # 超时时间（秒）
    retry_count: int = 0
    max_retries: int = 2
    status: StepStatus = StepStatus.PENDING
    result: Any = None
    error: str = ""
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    output: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Workflow:
    """工作流"""
    id: str
    name: str
    description: str = ""
    target: str = ""
    steps: List[WorkflowStep] = field(default_factory=list)
    status: WorkflowStatus = WorkflowStatus.PENDING
    current_step: str = ""
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    created_by: str = ""


@dataclass
class WorkflowTemplate:
    """工作流模板"""
    id: str
    name: str
    description: str = ""
    category: str = ""
    steps: List[Dict] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    estimated_time: str = ""
    difficulty: str = "medium"  # easy/medium/hard


class WorkflowEngine:
    """工作流引擎"""

    def __init__(self, config: Optional[Dict] = None):
        """初始化WorkflowEngine实例。

        Args:
            self: 类实例。
        """
        self.config = config or {}
        self.workspace = self.config.get("workspace", "./workflow_workspace")
        self._ensure_workspace()
        self.workflows: Dict[str, Workflow] = {}
        self.templates = self._init_templates()
        self.step_handlers = self._init_handlers()
        logger.info("自动化渗透工作流引擎初始化完成")

    def _ensure_workspace(self):
        """确保工作目录存在"""
        os.makedirs(self.workspace, exist_ok=True)
        os.makedirs(f"{self.workspace}/results", exist_ok=True)
        os.makedirs(f"{self.workspace}/templates", exist_ok=True)

    def _init_templates(self) -> Dict[str, WorkflowTemplate]:
        """初始化工作流模板"""
        templates = {}

        # 模板1：完整Web渗透测试
        templates["full_web_pentest"] = WorkflowTemplate(
            id="full_web_pentest",
            name="完整Web渗透测试",
            description="从信息收集到报告生成的完整Web应用渗透测试流程",
            category="web",
            difficulty="medium",
            estimated_time="30-60分钟",
            tags=["web", "full", "automation"],
            steps=[
                {"id": "step1", "name": "信息收集", "type": "enum", "description": "子域名枚举、端口扫描、服务识别", "params": {"target": "{target}", "modules": ["subdomain", "portscan", "service"]}},
                {"id": "step2", "name": "Web漏洞扫描", "type": "scan", "description": "SQL注入、XSS、SSRF、文件上传等Web漏洞扫描", "params": {"target": "{target}", "scan_types": ["sqli", "xss", "ssrf", "file_upload", "lfi"]}, "depends_on": ["step1"]},
                {"id": "step3", "name": "漏洞验证", "type": "verify", "description": "自动验证扫描结果，去除误报", "params": {"findings": "{step2.result}"}, "depends_on": ["step2"]},
                {"id": "step4", "name": "漏洞利用", "type": "exploit", "description": "对验证通过的高危漏洞进行利用", "params": {"vulnerabilities": "{step3.result}", "severity": "high"}, "depends_on": ["step3"], "condition": "step3.result.verified_count > 0"},
                {"id": "step5", "name": "报告生成", "type": "report", "description": "生成完整渗透测试报告", "params": {"format": "html", "include_evidence": True}, "depends_on": ["step2", "step3", "step4"]},
            ],
        )

        # 模板2：快速漏洞扫描
        templates["quick_scan"] = WorkflowTemplate(
            id="quick_scan",
            name="快速漏洞扫描",
            description="快速端口扫描+漏洞扫描+报告，适合日常巡检",
            category="quick",
            difficulty="easy",
            estimated_time="5-15分钟",
            tags=["quick", "scan", "daily"],
            steps=[
                {"id": "step1", "name": "端口扫描", "type": "scan", "description": "快速端口扫描和服务识别", "params": {"target": "{target}", "scan_type": "fast"}},
                {"id": "step2", "name": "漏洞扫描", "type": "scan", "description": "基于开放端口的漏洞扫描", "params": {"target": "{target}", "ports": "{step1.open_ports}"}, "depends_on": ["step1"]},
                {"id": "step3", "name": "报告生成", "type": "report", "description": "生成快速扫描报告", "params": {"format": "json"}, "depends_on": ["step2"]},
            ],
        )

        # 模板3：内网渗透测试
        templates["internal_pentest"] = WorkflowTemplate(
            id="internal_pentest",
            name="内网渗透测试",
            description="内网信息收集、漏洞扫描、横向移动评估",
            category="internal",
            difficulty="hard",
            estimated_time="60-120分钟",
            tags=["internal", "network", "lateral"],
            steps=[
                {"id": "step1", "name": "内网存活探测", "type": "enum", "description": "内网主机存活探测和端口扫描", "params": {"target": "{target}", "modules": ["host_discovery", "portscan"]}},
                {"id": "step2", "name": "服务识别", "type": "enum", "description": "服务版本识别和漏洞匹配", "params": {"targets": "{step1.alive_hosts}"}, "depends_on": ["step1"]},
                {"id": "step3", "name": "漏洞扫描", "type": "scan", "description": "内网漏洞扫描（SMB/RDP/WinRM等）", "params": {"targets": "{step1.alive_hosts}", "scan_types": ["smb", "rdp", "winrm", "ssh"]}, "depends_on": ["step2"]},
                {"id": "step4", "name": "横向移动评估", "type": "exploit", "description": "评估横向移动可能性", "params": {"vulnerabilities": "{step3.result}"}, "depends_on": ["step3"]},
                {"id": "step5", "name": "报告生成", "type": "report", "description": "生成内网渗透测试报告", "params": {"format": "html"}, "depends_on": ["step4"]},
            ],
        )

        # 模板4：护网自查
        templates["hw_self_check"] = WorkflowTemplate(
            id="hw_self_check",
            name="护网专项自查",
            description="护网前30项安全自查，自动生成自查报告",
            category="defense",
            difficulty="easy",
            estimated_time="10-20分钟",
            tags=["hw", "defense", "self-check"],
            steps=[
                {"id": "step1", "name": "资产暴露面检查", "type": "scan", "description": "公网IP、端口、子域名、管理后台暴露检查", "params": {"target": "{target}"}},
                {"id": "step2", "name": "漏洞检查", "type": "scan", "description": "CVE漏洞、Web漏洞、中间件漏洞检查", "params": {"target": "{target}"}, "depends_on": ["step1"]},
                {"id": "step3", "name": "安全配置检查", "type": "verify", "description": "HTTPS、安全头、目录遍历、备份文件检查", "params": {"target": "{target}"}, "depends_on": ["step2"]},
                {"id": "step4", "name": "身份认证检查", "type": "verify", "description": "双因素认证、会话管理、权限控制检查", "params": {"target": "{target}"}, "depends_on": ["step3"]},
                {"id": "step5", "name": "自查报告生成", "type": "report", "description": "生成护网自查报告和修复建议", "params": {"format": "html", "include_fixes": True}, "depends_on": ["step4"]},
            ],
        )

        # 模板5：恶意代码分析
        templates["malware_analysis"] = WorkflowTemplate(
            id="malware_analysis",
            name="恶意代码全流程分析",
            description="静态分析+动态分析+沙箱行为+IOC提取+报告",
            category="malware",
            difficulty="hard",
            estimated_time="20-40分钟",
            tags=["malware", "analysis", "sandbox"],
            steps=[
                {"id": "step1", "name": "静态分析", "type": "custom", "description": "字符串提取、导入表分析、加壳检测", "params": {"file": "{target}"}},
                {"id": "step2", "name": "动态沙箱分析", "type": "custom", "description": "沙箱运行，采集进程/文件/注册表/网络行为", "params": {"file": "{target}"}, "depends_on": ["step1"]},
                {"id": "step3", "name": "IOC提取", "type": "custom", "description": "提取IP、域名、URL、哈希、互斥量等IOC", "params": {"static_result": "{step1.result}", "dynamic_result": "{step2.result}"}, "depends_on": ["step2"]},
                {"id": "step4", "name": "MITRE ATT&CK映射", "type": "custom", "description": "自动映射到ATT&CK技术矩阵", "params": {"behaviors": "{step2.behaviors}"}, "depends_on": ["step2"]},
                {"id": "step5", "name": "分析报告生成", "type": "report", "description": "生成完整恶意代码分析报告", "params": {"format": "html"}, "depends_on": ["step3", "step4"]},
            ],
        )

        return templates

    def _init_handlers(self) -> Dict[str, Callable]:
        """初始化步骤处理器"""
        return {
            "scan": self._handle_scan,
            "enum": self._handle_enum,
            "exploit": self._handle_exploit,
            "verify": self._handle_verify,
            "report": self._handle_report,
            "custom": self._handle_custom,
        }

    def list_templates(self) -> List[Dict]:
        """列出所有工作流模板"""
        return [
            {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "difficulty": t.difficulty,
                "estimated_time": t.estimated_time,
                "tags": t.tags,
                "step_count": len(t.steps),
            }
            for t in self.templates.values()
        ]

    def get_template(self, template_id: str) -> Optional[WorkflowTemplate]:
        """获取工作流模板"""
        return self.templates.get(template_id)

    def create_workflow_from_template(self, template_id: str, target: str, name: str = "") -> Optional[Workflow]:
        """从模板创建工作流"""
        template = self.templates.get(template_id)
        if not template:
            logger.error(f"模板不存在: {template_id}")
            return None

        workflow_id = f"wf_{uuid.uuid4().hex[:12]}"
        steps = []
        for step_data in template.steps:
            step = WorkflowStep(
                id=step_data["id"],
                name=step_data["name"],
                type=step_data["type"],
                description=step_data.get("description", ""),
                params=step_data.get("params", {}),
                depends_on=step_data.get("depends_on", []),
                condition=step_data.get("condition", ""),
                timeout=step_data.get("timeout", 300),
                max_retries=step_data.get("max_retries", 2),
            )
            steps.append(step)

        workflow = Workflow(
            id=workflow_id,
            name=name or template.name,
            description=template.description,
            target=target,
            steps=steps,
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        # 替换变量
        workflow.variables["target"] = target
        self._replace_variables(workflow)

        self.workflows[workflow_id] = workflow
        logger.info(f"从模板创建工作流: {workflow.name} ({workflow_id})")
        return workflow

    def create_custom_workflow(self, name: str, target: str, steps_config: List[Dict]) -> Workflow:
        """创建自定义工作流"""
        workflow_id = f"wf_{uuid.uuid4().hex[:12]}"
        steps = []
        for step_data in steps_config:
            step = WorkflowStep(
                id=step_data.get("id", f"step_{len(steps)+1}"),
                name=step_data["name"],
                type=step_data["type"],
                description=step_data.get("description", ""),
                params=step_data.get("params", {}),
                depends_on=step_data.get("depends_on", []),
                condition=step_data.get("condition", ""),
                timeout=step_data.get("timeout", 300),
                max_retries=step_data.get("max_retries", 2),
            )
            steps.append(step)

        workflow = Workflow(
            id=workflow_id,
            name=name,
            target=target,
            steps=steps,
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        workflow.variables["target"] = target
        self._replace_variables(workflow)
        self.workflows[workflow_id] = workflow
        logger.info(f"创建自定义工作流: {name} ({workflow_id})")
        return workflow

    def _replace_variables(self, workflow: Workflow):
        """替换步骤参数中的变量"""
        for step in workflow.steps:
            for key, value in step.params.items():
                if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
                    var_name = value[1:-1]
                    if var_name in workflow.variables:
                        step.params[key] = workflow.variables[var_name]

    async def execute_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """执行工作流"""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            logger.error(f"工作流不存在: {workflow_id}")
            return None

        workflow.status = WorkflowStatus.RUNNING
        workflow.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"开始执行工作流: {workflow.name} ({workflow_id})")

        try:
            while workflow.status == WorkflowStatus.RUNNING:
                # 找到可以执行的步骤
                executable_steps = self._get_executable_steps(workflow)

                if not executable_steps:
                    # 检查是否所有步骤都完成了
                    if all(s.status in [StepStatus.SUCCESS, StepStatus.SKIPPED, StepStatus.FAILED] for s in workflow.steps):
                        break
                    # 检查是否有失败的步骤
                    if any(s.status == StepStatus.FAILED for s in workflow.steps):
                        workflow.status = WorkflowStatus.FAILED
                        workflow.errors.append("存在失败的步骤")
                        break

                # 并行执行可执行的步骤
                if executable_steps:
                    tasks = [self._execute_step(workflow, step) for step in executable_steps]
                    await asyncio.gather(*tasks, return_exceptions=True)

                # 短暂等待
                await asyncio.sleep(0.5)

            # 检查最终状态
            if all(s.status in [StepStatus.SUCCESS, StepStatus.SKIPPED] for s in workflow.steps):
                workflow.status = WorkflowStatus.COMPLETED
            elif any(s.status == StepStatus.FAILED for s in workflow.steps):
                workflow.status = WorkflowStatus.FAILED

        except Exception as e:
            workflow.status = WorkflowStatus.FAILED
            workflow.errors.append(str(e))
            logger.error(f"工作流执行失败: {e}")

        workflow.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        workflow.duration = (datetime.strptime(workflow.end_time, "%Y-%m-%d %H:%M:%S") -
                            datetime.strptime(workflow.start_time, "%Y-%m-%d %H:%M:%S")).total_seconds()

        # 保存结果
        self._save_workflow_result(workflow)

        logger.info(f"工作流执行完成: {workflow.name}, 状态: {workflow.status.value}, 耗时: {workflow.duration:.2f}秒")
        return workflow

    def _get_executable_steps(self, workflow: Workflow) -> List[WorkflowStep]:
        """获取可以执行的步骤"""
        executable = []
        for step in workflow.steps:
            if step.status != StepStatus.PENDING:
                continue

            # 检查依赖
            dependencies_met = True
            for dep_id in step.depends_on:
                dep_step = next((s for s in workflow.steps if s.id == dep_id), None)
                if not dep_step or dep_step.status != StepStatus.SUCCESS:
                    dependencies_met = False
                    break

            if not dependencies_met:
                continue

            # 检查条件
            if step.condition:
                if not self._evaluate_condition(workflow, step.condition):
                    step.status = StepStatus.SKIPPED
                    step.result = "条件不满足，跳过"
                    logger.info(f"步骤跳过（条件不满足）: {step.name}")
                    continue

            executable.append(step)

        return executable

    def _evaluate_condition(self, workflow: Workflow, condition: str) -> bool:
        """评估条件表达式（简化版）"""
        try:
            # 简单的条件评估，支持 stepX.result.key > value 格式
            for step in workflow.steps:
                if step.result:
                    if isinstance(step.result, dict):
                        for key, value in step.result.items():
                            condition = condition.replace(f"{{{step.id}.result.{key}}}", str(value))

            # 安全评估（只允许简单的比较表达式）
            if ">" in condition:
                parts = condition.split(">")
                left = float(parts[0].strip()) if parts[0].strip().replace(".", "").isdigit() else 0
                right = float(parts[1].strip()) if parts[1].strip().replace(".", "").isdigit() else 0
                return left > right
            elif "<" in condition:
                parts = condition.split("<")
                left = float(parts[0].strip()) if parts[0].strip().replace(".", "").isdigit() else 0
                right = float(parts[1].strip()) if parts[1].strip().replace(".", "").isdigit() else 0
                return left < right
            elif "==" in condition:
                parts = condition.split("==")
                return parts[0].strip() == parts[1].strip()

            return True
        except Exception as e:
            logger.warning(f"条件评估失败: {condition}, {e}")
            return True

    async def _execute_step(self, workflow: Workflow, step: WorkflowStep):
        """执行单个步骤"""
        step.status = StepStatus.RUNNING
        step.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        workflow.current_step = step.id
        logger.info(f"执行步骤: {step.name} ({step.id})")

        try:
            handler = self.step_handlers.get(step.type)
            if not handler:
                raise ValueError(f"未知步骤类型: {step.type}")

            # 超时控制
            result = await asyncio.wait_for(
                handler(workflow, step),
                timeout=step.timeout
            )

            step.result = result
            step.status = StepStatus.SUCCESS
            workflow.results[step.id] = result

            # 更新变量
            if isinstance(result, dict):
                for key, value in result.items():
                    workflow.variables[f"{step.id}.{key}"] = value

        except asyncio.TimeoutError:
            step.status = StepStatus.TIMEOUT
            step.error = f"步骤超时（{step.timeout}秒）"
            if step.retry_count < step.max_retries:
                step.retry_count += 1
                step.status = StepStatus.PENDING
                logger.warning(f"步骤超时，重试 ({step.retry_count}/{step.max_retries}): {step.name}")
            else:
                workflow.errors.append(f"步骤超时: {step.name}")
                logger.error(f"步骤超时: {step.name}")

        except Exception as e:
            step.error = str(e)
            if step.retry_count < step.max_retries:
                step.retry_count += 1
                step.status = StepStatus.PENDING
                logger.warning(f"步骤失败，重试 ({step.retry_count}/{step.max_retries}): {step.name}, {e}")
            else:
                step.status = StepStatus.FAILED
                workflow.errors.append(f"步骤失败: {step.name} - {e}")
                logger.error(f"步骤失败: {step.name}, {e}")

        step.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        step.duration = (datetime.strptime(step.end_time, "%Y-%m-%d %H:%M:%S") -
                        datetime.strptime(step.start_time, "%Y-%m-%d %H:%M:%S")).total_seconds()

    async def _handle_scan(self, workflow: Workflow, step: WorkflowStep) -> Dict:
        """处理扫描步骤"""
        logger.info(f"执行扫描: {step.name}, 目标: {step.params.get('target', workflow.target)}")
        # 模拟扫描结果
        await asyncio.sleep(1)
        return {
            "status": "success",
            "target": step.params.get("target", workflow.target),
            "open_ports": [22, 80, 443, 8080],
            "vulnerabilities_found": 5,
            "high_severity": 1,
            "medium_severity": 2,
            "low_severity": 2,
            "scan_duration": 45.2,
        }

    async def _handle_enum(self, workflow: Workflow, step: WorkflowStep) -> Dict:
        """处理信息收集步骤"""
        logger.info(f"执行信息收集: {step.name}")
        await asyncio.sleep(1)
        return {
            "status": "success",
            "subdomains": ["www", "api", "admin", "mail", "dev"],
            "alive_hosts": 3,
            "services": ["nginx", "mysql", "ssh"],
            "tech_stack": ["PHP", "MySQL", "Apache"],
        }

    async def _handle_exploit(self, workflow: Workflow, step: WorkflowStep) -> Dict:
        """处理漏洞利用步骤"""
        logger.info(f"执行漏洞利用: {step.name}")
        await asyncio.sleep(1)
        return {
            "status": "success",
            "exploited_count": 1,
            "access_level": "user",
            "evidence": ["成功执行命令", "获取敏感数据"],
        }

    async def _handle_verify(self, workflow: Workflow, step: WorkflowStep) -> Dict:
        """处理漏洞验证步骤"""
        logger.info(f"执行漏洞验证: {step.name}")
        await asyncio.sleep(1)
        return {
            "status": "success",
            "verified_count": 3,
            "false_positives": 2,
            "verified_vulnerabilities": [
                {"type": "SQL注入", "severity": "high", "confidence": 0.95},
                {"type": "XSS", "severity": "medium", "confidence": 0.90},
                {"type": "信息泄露", "severity": "low", "confidence": 0.99},
            ],
        }

    async def _handle_report(self, workflow: Workflow, step: WorkflowStep) -> Dict:
        """处理报告生成步骤"""
        logger.info(f"生成报告: {step.name}")
        await asyncio.sleep(1)
        report_path = f"{self.workspace}/results/{workflow.id}_report.html"
        return {
            "status": "success",
            "report_path": report_path,
            "report_format": step.params.get("format", "html"),
            "total_vulnerabilities": 5,
            "risk_level": "high",
        }

    async def _handle_custom(self, workflow: Workflow, step: WorkflowStep) -> Dict:
        """处理自定义步骤"""
        logger.info(f"执行自定义步骤: {step.name}")
        await asyncio.sleep(1)
        return {
            "status": "success",
            "message": f"自定义步骤执行完成: {step.name}",
            "params": step.params,
        }

    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """获取工作流"""
        return self.workflows.get(workflow_id)

    def list_workflows(self) -> List[Dict]:
        """列出所有工作流"""
        return [
            {
                "id": w.id,
                "name": w.name,
                "description": w.description,
                "target": w.target,
                "status": w.status.value,
                "step_count": len(w.steps),
                "completed_steps": len([s for s in w.steps if s.status == StepStatus.SUCCESS]),
                "start_time": w.start_time,
                "end_time": w.end_time,
                "duration": w.duration,
                "errors": w.errors,
            }
            for w in self.workflows.values()
        ]

    def get_workflow_detail(self, workflow_id: str) -> Optional[Dict]:
        """获取工作流详情"""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return None

        return {
            "id": workflow.id,
            "name": workflow.name,
            "description": workflow.description,
            "target": workflow.target,
            "status": workflow.status.value,
            "current_step": workflow.current_step,
            "start_time": workflow.start_time,
            "end_time": workflow.end_time,
            "duration": workflow.duration,
            "steps": [
                {
                    "id": s.id,
                    "name": s.name,
                    "type": s.type,
                    "description": s.description,
                    "status": s.status.value,
                    "depends_on": s.depends_on,
                    "start_time": s.start_time,
                    "end_time": s.end_time,
                    "duration": s.duration,
                    "error": s.error,
                    "retry_count": s.retry_count,
                }
                for s in workflow.steps
            ],
            "results": workflow.results,
            "errors": workflow.errors,
            "variables": workflow.variables,
        }

    def _save_workflow_result(self, workflow: Workflow):
        """保存工作流结果"""
        try:
            result_path = f"{self.workspace}/results/{workflow.id}.json"
            data = {
                "id": workflow.id,
                "name": workflow.name,
                "status": workflow.status.value,
                "target": workflow.target,
                "start_time": workflow.start_time,
                "end_time": workflow.end_time,
                "duration": workflow.duration,
                "steps": [
                    {
                        "id": s.id,
                        "name": s.name,
                        "type": s.type,
                        "status": s.status.value,
                        "result": s.result,
                        "error": s.error,
                        "duration": s.duration,
                    }
                    for s in workflow.steps
                ],
                "errors": workflow.errors,
            }
            with open(result_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"保存工作流结果失败: {e}")


# 便捷函数
def create_workflow_engine() -> WorkflowEngine:
    """创建工作流引擎"""
    return WorkflowEngine()


async def run_template_workflow(template_id: str, target: str) -> Optional[Workflow]:
    """从模板运行工作流"""
    engine = WorkflowEngine()
    workflow = engine.create_workflow_from_template(template_id, target)
    if workflow:
        await engine.execute_workflow(workflow.id)
    return workflow


if __name__ == "__main__":
    # 测试
    print("=== 自动化渗透测试工作流引擎 ===")
    print()

    engine = WorkflowEngine()

    # 列出模板
    templates = engine.list_templates()
    print(f"可用工作流模板: {len(templates)}个")
    for t in templates:
        print(f"  - {t['name']} ({t['id']}): {t['description']}, {t['step_count']}步, 难度: {t['difficulty']}")
    print()

    # 从模板创建工作流
    workflow = engine.create_workflow_from_template("quick_scan", "http://testphp.vulnweb.com")
    if workflow:
        print(f"创建工作流: {workflow.name} ({workflow.id})")
        print(f"步骤数: {len(workflow.steps)}")
        for step in workflow.steps:
            print(f"  - {step.name} ({step.type}): 依赖={step.depends_on}")
