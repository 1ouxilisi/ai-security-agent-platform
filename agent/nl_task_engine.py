#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nl_task_engine智能体模块，提供相关AI驱动的安全分析和决策功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import json
import os
import re
import time
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from loguru import logger

try:
    from llm.multi_llm_manager import MultiLLMManager
except ImportError:
    MultiLLMManager = None


class TaskStatus(Enum):
    """任务状态"""
    PENDING = "pending"
    PARSING = "parsing"
    PLANNING = "planning"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepType(Enum):
    """步骤类型"""
    SCAN = "scan"  # 扫描
    ENUM = "enum"  # 信息收集
    EXPLOIT = "exploit"  # 漏洞利用
    VERIFY = "verify"  # 漏洞验证
    REPORT = "report"  # 报告生成
    ANALYSIS = "analysis"  # 分析
    CODE = "code"  # 代码相关
    CUSTOM = "custom"  # 自定义


@dataclass
class TaskStep:
    """任务步骤"""
    id: str
    name: str
    type: str
    description: str
    params: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    status: str = "pending"
    result: Any = None
    error: str = ""
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    output_summary: str = ""


@dataclass
class NLTask:
    """自然语言任务"""
    id: str
    user_input: str
    parsed_intent: str = ""
    parsed_target: str = ""
    parsed_scope: str = ""
    parsed_depth: str = "medium"
    steps: List[TaskStep] = field(default_factory=list)
    status: str = "pending"
    current_step: str = ""
    progress: float = 0.0
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    final_result: Any = None
    errors: List[str] = field(default_factory=list)
    created_at: str = ""


class NaturalLanguageTaskEngine:
    """自然语言任务引擎"""

    def __init__(self, llm_manager: Optional[MultiLLMManager] = None):
        """初始化NaturalLanguageTaskEngine实例。

        Args:
            self: 类实例。
        """
        self.llm_manager = llm_manager or (MultiLLMManager() if MultiLLMManager else None)
        self.tasks: Dict[str, NLTask] = {}
        self._task_counter = 0
        logger.info("自然语言任务引擎初始化完成")

    def parse_task(self, user_input: str) -> NLTask:
        """
        解析用户输入，创建任务
        1. 提取意图、目标、范围、深度
        2. AI生成执行计划
        3. 返回任务对象
        """
        import uuid
        task_id = f"nltask_{uuid.uuid4().hex[:12]}"

        task = NLTask(
            id=task_id,
            user_input=user_input,
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            status="parsing",
        )

        self.tasks[task_id] = task
        logger.info(f"创建自然语言任务: {task_id}")

        # 第一步：基础解析（正则提取关键信息）
        self._basic_parse(task)

        # 第二步：AI深度解析和计划生成
        if self.llm_manager:
            self._ai_parse_and_plan(task)
        else:
            self._rule_based_plan(task)

        task.status = "pending"
        return task

    def _basic_parse(self, task: NLTask):
        """基础解析（正则提取）"""
        user_input = task.user_input.lower()

        # 提取目标（URL/IP/域名）
        url_pattern = r'https?://[^\s,，。；;]+'
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

        urls = re.findall(url_pattern, user_input)
        ips = re.findall(ip_pattern, user_input)
        domains = re.findall(domain_pattern, user_input)

        if urls:
            task.parsed_target = urls[0]
        elif ips:
            task.parsed_target = ips[0]
        elif domains:
            task.parsed_target = domains[0]

        # 提取意图
        intents = {
            "scan": ["扫描", "扫一下", "漏洞扫描", "检测", "查漏洞", "安全扫描"],
            "pentest": ["渗透", "渗透测试", "打靶", "攻击", "入侵", "getshell"],
            "recon": ["信息收集", "侦察", "子域名", "目录扫描", "指纹识别"],
            "verify": ["验证", "确认", "去误报", "poc验证"],
            "report": ["报告", "生成报告", "出报告", "写报告"],
            "code_review": ["代码审查", "代码审计", "审代码", "查代码漏洞"],
            "malware": ["恶意代码", "病毒分析", "木马分析", "样本分析"],
            "self_check": ["自查", "护网", "安全检查", "基线检查", "配置检查"],
        }

        for intent, keywords in intents.items():
            if any(kw in user_input for kw in keywords):
                task.parsed_intent = intent
                break

        if not task.parsed_intent:
            task.parsed_intent = "scan"  # 默认扫描

        # 提取深度
        if any(kw in user_input for kw in ["快速", "简单", "浅", "quick", "fast"]):
            task.parsed_depth = "quick"
        elif any(kw in user_input for kw in ["深度", "全面", "完整", "全量", "deep", "full"]):
            task.parsed_depth = "deep"
        else:
            task.parsed_depth = "medium"

        # 提取范围
        if any(kw in user_input for kw in ["内网", "内部网络", "局域网"]):
            task.parsed_scope = "internal"
        elif any(kw in user_input for kw in ["外网", "公网", "外部"]):
            task.parsed_scope = "external"
        elif any(kw in user_input for kw in ["web", "网站", "应用"]):
            task.parsed_scope = "web"
        else:
            task.parsed_scope = "auto"

        logger.info(f"基础解析完成: 意图={task.parsed_intent}, 目标={task.parsed_target}, 深度={task.parsed_depth}, 范围={task.parsed_scope}")

    def _ai_parse_and_plan(self, task: NLTask):
        """AI深度解析和计划生成"""
        task.status = "planning"

        system_prompt = """你是一个专业的网络安全测试任务规划专家。用户会用自然语言描述一个安全测试任务，你需要：
1. 理解用户的真实意图
2. 拆解为具体的可执行步骤
3. 每个步骤包含：名称、类型、描述、参数、依赖关系

步骤类型只能是：scan(扫描)、enum(信息收集)、exploit(漏洞利用)、verify(漏洞验证)、report(报告生成)、analysis(分析)、code(代码相关)、custom(自定义)

请严格按照以下JSON格式返回，不要返回其他内容：
{
  "intent": "用户意图",
  "target": "目标",
  "steps": [
    {
      "id": "step1",
      "name": "步骤名称",
      "type": "scan",
      "description": "步骤描述",
      "params": {"key": "value"},
      "depends_on": []
    }
  ]
}"""

        user_prompt = f"""用户输入：{task.user_input}

已解析信息：
- 意图：{task.parsed_intent}
- 目标：{task.parsed_target or '未指定'}
- 范围：{task.parsed_scope}
- 深度：{task.parsed_depth}

请根据以上信息，生成详细的执行计划。"""

        content, metadata = self.llm_manager.chat(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            task_type="planning",
            max_tokens=4096,
            temperature=0.1,
        )

        if content:
            try:
                # 提取JSON
                json_match = re.search(r'\{[\s\S]*\}', content)
                if json_match:
                    plan = json.loads(json_match.group())

                    if "intent" in plan:
                        task.parsed_intent = plan["intent"]
                    if "target" in plan and plan["target"]:
                        task.parsed_target = plan["target"]

                    if "steps" in plan and isinstance(plan["steps"], list):
                        for step_data in plan["steps"]:
                            step = TaskStep(
                                id=step_data.get("id", f"step{len(task.steps)+1}"),
                                name=step_data.get("name", "未命名步骤"),
                                type=step_data.get("type", "custom"),
                                description=step_data.get("description", ""),
                                params=step_data.get("params", {}),
                                depends_on=step_data.get("depends_on", []),
                            )
                            task.steps.append(step)

                    logger.info(f"AI计划生成完成，共{len(task.steps)}个步骤")
                    return
            except Exception as e:
                logger.error(f"AI计划解析失败: {e}")

        # AI失败，使用规则生成计划
        logger.warning("AI计划生成失败，使用规则生成计划")
        self._rule_based_plan(task)

    def _rule_based_plan(self, task: NLTask):
        """基于规则生成计划"""
        target = task.parsed_target or "{target}"
        depth = task.parsed_depth
        intent = task.parsed_intent

        if intent == "scan":
            steps = [
                TaskStep(id="step1", name="信息收集", type="enum",
                        description=f"对目标 {target} 进行信息收集，包括子域名、端口、服务、指纹识别",
                        params={"target": target, "modules": ["subdomain", "portscan", "fingerprint"]}),
                TaskStep(id="step2", name="漏洞扫描", type="scan",
                        description=f"对目标 {target} 进行漏洞扫描",
                        params={"target": target, "depth": depth, "scan_types": ["web", "system", "config"]},
                        depends_on=["step1"]),
                TaskStep(id="step3", name="漏洞验证", type="verify",
                        description="验证扫描结果，去除误报",
                        params={"findings": "{step2.result}"},
                        depends_on=["step2"]),
                TaskStep(id="step4", name="生成报告", type="report",
                        description="生成完整的漏洞扫描报告",
                        params={"format": "html", "include_evidence": True},
                        depends_on=["step2", "step3"]),
            ]
        elif intent == "pentest":
            steps = [
                TaskStep(id="step1", name="信息收集", type="enum",
                        description="全面信息收集",
                        params={"target": target, "modules": ["all"]}),
                TaskStep(id="step2", name="漏洞扫描", type="scan",
                        description="深度漏洞扫描",
                        params={"target": target, "depth": "deep"},
                        depends_on=["step1"]),
                TaskStep(id="step3", name="漏洞验证", type="verify",
                        description="验证漏洞可利用性",
                        params={"findings": "{step2.result}"},
                        depends_on=["step2"]),
                TaskStep(id="step4", name="漏洞利用", type="exploit",
                        description="对高危漏洞进行利用",
                        params={"vulnerabilities": "{step3.result}", "severity": "high"},
                        depends_on=["step3"]),
                TaskStep(id="step5", name="后渗透", type="exploit",
                        description="后渗透操作，提权、横向移动",
                        params={"access": "{step4.result}"},
                        depends_on=["step4"]),
                TaskStep(id="step6", name="生成报告", type="report",
                        description="生成完整渗透测试报告",
                        params={"format": "html"},
                        depends_on=["step4", "step5"]),
            ]
        elif intent == "self_check":
            steps = [
                TaskStep(id="step1", name="资产暴露面检查", type="scan",
                        description="检查公网暴露的资产和端口",
                        params={"target": target}),
                TaskStep(id="step2", name="漏洞检查", type="scan",
                        description="检查已知漏洞",
                        params={"target": target},
                        depends_on=["step1"]),
                TaskStep(id="step3", name="安全配置检查", type="verify",
                        description="检查安全配置（HTTPS、安全头、目录遍历等）",
                        params={"target": target},
                        depends_on=["step2"]),
                TaskStep(id="step4", name="身份认证检查", type="verify",
                        description="检查身份认证和权限控制",
                        params={"target": target},
                        depends_on=["step3"]),
                TaskStep(id="step5", name="生成自查报告", type="report",
                        description="生成护网自查报告和修复建议",
                        params={"format": "html", "include_fixes": True},
                        depends_on=["step4"]),
            ]
        else:
            steps = [
                TaskStep(id="step1", name="执行任务", type="custom",
                        description=f"执行用户请求的任务: {task.user_input}",
                        params={"user_input": task.user_input, "target": target}),
            ]

        task.steps = steps
        logger.info(f"规则计划生成完成，共{len(steps)}个步骤")

    async def execute_task(self, task_id: str) -> Optional[NLTask]:
        """执行任务"""
        task = self.tasks.get(task_id)
        if not task:
            logger.error(f"任务不存在: {task_id}")
            return None

        task.status = "executing"
        task.start_time = time.strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"开始执行任务: {task_id}")

        try:
            while task.status == "executing":
                # 找到可执行的步骤
                executable = self._get_executable_steps(task)

                if not executable:
                    # 检查是否所有步骤都完成了
                    if all(s.status in ["success", "skipped", "failed"] for s in task.steps):
                        break
                    await asyncio.sleep(0.5)
                    continue

                # 执行步骤
                for step in executable:
                    await self._execute_step(task, step)

                # 更新进度
                completed = len([s for s in task.steps if s.status in ["success", "skipped"]])
                task.progress = completed / len(task.steps) * 100 if task.steps else 100

                await asyncio.sleep(0.3)

            # 检查最终状态
            if all(s.status in ["success", "skipped"] for s in task.steps):
                task.status = "completed"
                task.final_result = self._generate_final_summary(task)
            else:
                task.status = "failed"
                task.errors.append("存在失败的步骤")

        except Exception as e:
            task.status = "failed"
            task.errors.append(str(e))
            logger.error(f"任务执行失败: {e}")

        task.end_time = time.strftime("%Y-%m-%d %H:%M:%S")
        task.duration = (time.mktime(time.strptime(task.end_time, "%Y-%m-%d %H:%M:%S")) -
                        time.mktime(time.strptime(task.start_time, "%Y-%m-%d %H:%M:%S")))

        logger.info(f"任务执行完成: {task_id}, 状态: {task.status}, 耗时: {task.duration:.1f}秒")
        return task

    def _get_executable_steps(self, task: NLTask) -> List[TaskStep]:
        """获取可执行的步骤"""
        executable = []
        for step in task.steps:
            if step.status != "pending":
                continue

            # 检查依赖
            deps_met = True
            for dep_id in step.depends_on:
                dep_step = next((s for s in task.steps if s.id == dep_id), None)
                if not dep_step or dep_step.status != "success":
                    deps_met = False
                    break

            if deps_met:
                executable.append(step)

        return executable

    async def _execute_step(self, task: NLTask, step: TaskStep):
        """执行单个步骤"""
        step.status = "running"
        step.start_time = time.strftime("%Y-%m-%d %H:%M:%S")
        task.current_step = step.id

        logger.info(f"执行步骤: {step.name} ({step.id})")

        try:
            # 根据步骤类型执行
            if step.type == "scan":
                result = await self._execute_scan(task, step)
            elif step.type == "enum":
                result = await self._execute_enum(task, step)
            elif step.type == "exploit":
                result = await self._execute_exploit(task, step)
            elif step.type == "verify":
                result = await self._execute_verify(task, step)
            elif step.type == "report":
                result = await self._execute_report(task, step)
            elif step.type == "analysis":
                result = await self._execute_analysis(task, step)
            elif step.type == "code":
                result = await self._execute_code(task, step)
            else:
                result = await self._execute_custom(task, step)

            step.result = result
            step.status = "success"
            step.output_summary = self._generate_step_summary(step, result)

        except Exception as e:
            step.status = "failed"
            step.error = str(e)
            task.errors.append(f"步骤 {step.name} 失败: {e}")
            logger.error(f"步骤执行失败: {step.name}, {e}")

        step.end_time = time.strftime("%Y-%m-%d %H:%M:%S")
        step.duration = (time.mktime(time.strptime(step.end_time, "%Y-%m-%d %H:%M:%S")) -
                        time.mktime(time.strptime(step.start_time, "%Y-%m-%d %H:%M:%S")))

    async def _execute_scan(self, task: NLTask, step: TaskStep) -> Dict:
        """执行扫描步骤"""
        # 模拟扫描（实际应调用扫描工具）
        await asyncio.sleep(1)
        target = step.params.get("target", task.parsed_target)
        return {
            "status": "success",
            "target": target,
            "open_ports": [22, 80, 443, 8080],
            "services": ["nginx", "mysql", "ssh", "tomcat"],
            "vulnerabilities_found": 5,
            "high_severity": 1,
            "medium_severity": 2,
            "low_severity": 2,
            "vulnerabilities": [
                {"type": "sqli", "severity": "high", "url": f"{target}/login", "confidence": 0.85},
                {"type": "xss", "severity": "medium", "url": f"{target}/search", "confidence": 0.75},
                {"type": "info_disclosure", "severity": "low", "url": f"{target}/backup", "confidence": 0.9},
            ],
        }

    async def _execute_enum(self, task: NLTask, step: TaskStep) -> Dict:
        """执行信息收集步骤"""
        await asyncio.sleep(1)
        target = step.params.get("target", task.parsed_target)
        return {
            "status": "success",
            "target": target,
            "subdomains": ["www", "api", "admin", "mail", "dev", "test"],
            "alive_hosts": 4,
            "open_ports": {
                "80": "nginx",
                "443": "nginx",
                "22": "OpenSSH",
                "3306": "MySQL",
            },
            "tech_stack": ["PHP", "MySQL", "Nginx", "jQuery"],
            "cms": "WordPress",
        }

    async def _execute_exploit(self, task: NLTask, step: TaskStep) -> Dict:
        """执行漏洞利用步骤"""
        await asyncio.sleep(1)
        return {
            "status": "success",
            "exploited_count": 1,
            "access_level": "user",
            "evidence": ["成功执行命令", "获取敏感数据", "建立Shell连接"],
        }

    async def _execute_verify(self, task: NLTask, step: TaskStep) -> Dict:
        """执行漏洞验证步骤"""
        await asyncio.sleep(1)
        return {
            "status": "success",
            "total": 5,
            "verified": 3,
            "false_positives": 2,
            "verified_vulnerabilities": [
                {"type": "sqli", "severity": "high", "confidence": 0.95, "evidence": "成功绕过登录"},
                {"type": "xss", "severity": "medium", "confidence": 0.90, "evidence": "成功弹窗"},
                {"type": "info_disclosure", "severity": "low", "confidence": 0.99, "evidence": "备份文件可下载"},
            ],
        }

    async def _execute_report(self, task: NLTask, step: TaskStep) -> Dict:
        """执行报告生成步骤"""
        await asyncio.sleep(1)
        return {
            "status": "success",
            "report_id": f"report_{task.id}",
            "format": step.params.get("format", "html"),
            "file_path": f"./reports/{task.id}_report.html",
            "summary": {
                "total_vulnerabilities": 5,
                "high": 1,
                "medium": 2,
                "low": 2,
                "verified": 3,
                "risk_level": "high",
            },
        }

    async def _execute_analysis(self, task: NLTask, step: TaskStep) -> Dict:
        """执行分析步骤"""
        await asyncio.sleep(1)
        return {"status": "success", "analysis": "分析结果"}

    async def _execute_code(self, task: NLTask, step: TaskStep) -> Dict:
        """执行代码相关步骤"""
        await asyncio.sleep(1)
        return {"status": "success", "code_result": "代码审查完成"}

    async def _execute_custom(self, task: NLTask, step: TaskStep) -> Dict:
        """执行自定义步骤"""
        await asyncio.sleep(1)
        return {"status": "success", "custom_result": "自定义步骤执行完成"}

    def _generate_step_summary(self, step: TaskStep, result: Dict) -> str:
        """生成步骤摘要"""
        if not isinstance(result, dict):
            return str(result)[:100]

        if step.type == "scan":
            return f"发现{result.get('vulnerabilities_found', 0)}个漏洞，高危{result.get('high_severity', 0)}个"
        elif step.type == "enum":
            return f"发现{len(result.get('subdomains', []))}个子域名，{result.get('alive_hosts', 0)}个存活主机"
        elif step.type == "verify":
            return f"验证{result.get('total', 0)}个漏洞，确认{result.get('verified', 0)}个，误报{result.get('false_positives', 0)}个"
        elif step.type == "report":
            return f"报告已生成: {result.get('file_path', '')}"
        elif step.type == "exploit":
            return f"成功利用{result.get('exploited_count', 0)}个漏洞，权限: {result.get('access_level', '')}"
        else:
            return f"执行完成"

    def _generate_final_summary(self, task: NLTask) -> Dict:
        """生成最终摘要"""
        successful_steps = [s for s in task.steps if s.status == "success"]
        failed_steps = [s for s in task.steps if s.status == "failed"]

        return {
            "task_id": task.id,
            "user_input": task.user_input,
            "intent": task.parsed_intent,
            "target": task.parsed_target,
            "total_steps": len(task.steps),
            "successful_steps": len(successful_steps),
            "failed_steps": len(failed_steps),
            "duration": task.duration,
            "step_summaries": [
                {"name": s.name, "type": s.type, "status": s.status, "summary": s.output_summary}
                for s in task.steps
            ],
        }

    def get_task(self, task_id: str) -> Optional[Dict]:
        """获取任务详情"""
        task = self.tasks.get(task_id)
        if not task:
            return None

        return {
            "id": task.id,
            "user_input": task.user_input,
            "intent": task.parsed_intent,
            "target": task.parsed_target,
            "scope": task.parsed_scope,
            "depth": task.parsed_depth,
            "status": task.status,
            "current_step": task.current_step,
            "progress": round(task.progress, 1),
            "start_time": task.start_time,
            "end_time": task.end_time,
            "duration": task.duration,
            "steps": [
                {
                    "id": s.id,
                    "name": s.name,
                    "type": s.type,
                    "description": s.description,
                    "status": s.status,
                    "depends_on": s.depends_on,
                    "output_summary": s.output_summary,
                    "error": s.error,
                    "duration": s.duration,
                }
                for s in task.steps
            ],
            "final_result": task.final_result,
            "errors": task.errors,
            "created_at": task.created_at,
        }

    def list_tasks(self, limit: int = 50) -> List[Dict]:
        """列出所有任务"""
        tasks = sorted(self.tasks.values(), key=lambda x: x.created_at, reverse=True)
        return [
            {
                "id": t.id,
                "user_input": t.user_input[:50],
                "intent": t.parsed_intent,
                "target": t.parsed_target,
                "status": t.status,
                "progress": round(t.progress, 1),
                "step_count": len(t.steps),
                "created_at": t.created_at,
            }
            for t in tasks[:limit]
        ]


# 便捷函数
def create_nl_task_engine(llm_manager=None) -> NaturalLanguageTaskEngine:
    """创建自然语言任务引擎"""
    return NaturalLanguageTaskEngine(llm_manager)


if __name__ == "__main__":
    print("=== 自然语言任务引擎 ===")
    print()

    engine = NaturalLanguageTaskEngine()

    # 测试解析
    user_input = "帮我扫描一下 http://testphp.vulnweb.com 这个网站，深度扫描，然后生成报告"
    print(f"用户输入: {user_input}")
    print()

    task = engine.parse_task(user_input)
    print(f"任务ID: {task.id}")
    print(f"解析意图: {task.parsed_intent}")
    print(f"解析目标: {task.parsed_target}")
    print(f"解析深度: {task.parsed_depth}")
    print(f"生成步骤: {len(task.steps)}个")
    print()

    for step in task.steps:
        print(f"  - {step.id}: {step.name} ({step.type})")
        print(f"    描述: {step.description}")
        print(f"    依赖: {step.depends_on}")
        print()
