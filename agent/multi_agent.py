#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多智能体协作框架 - Multi-Agent Collaboration Framework v2.0
4个专业智能体真正协作：
- ReconAgent（侦察智能体）：情报收集、端口扫描、服务识别
- ExploitAgent（漏洞利用智能体）：漏洞扫描、漏洞验证、漏洞利用
- VerificationAgent（验证智能体）：漏洞验证、误报排除、风险评估
- ReportAgent（报告智能体）：报告生成、修复建议、风险评级

支持：消息传递、任务队列、结果汇总、协调器调度、LLM驱动决策
"""
import asyncio
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

from utils.logger import log


class AgentRole(str, Enum):
    """智能体角色"""
    RECON = "recon"
    EXPLOIT = "exploit"
    VERIFICATION = "verification"
    REPORT = "report"
    COORDINATOR = "coordinator"


class MessageType(str, Enum):
    """消息类型"""
    TASK_ASSIGN = "task_assign"  # 任务分配
    TASK_RESULT = "task_result"  # 任务结果
    TASK_REQUEST = "task_request"  # 请求任务
    INFO_SHARE = "info_share"  # 信息共享
    QUESTION = "question"  # 提问
    ANSWER = "answer"  # 回答
    STATUS_UPDATE = "status_update"  # 状态更新
    ERROR = "error"  # 错误


@dataclass
class AgentMessage:
    """智能体间消息"""
    message_id: str
    from_agent: str
    to_agent: str
    message_type: MessageType
    content: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    in_reply_to: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "message_id": self.message_id,
            "from": self.from_agent,
            "to": self.to_agent,
            "type": self.message_type.value,
            "content": self.content,
            "timestamp": self.timestamp,
            "in_reply_to": self.in_reply_to
        }


@dataclass
class AgentTask:
    """智能体任务"""
    task_id: str
    assigned_to: AgentRole
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"  # pending/running/completed/failed
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    priority: int = 0  # 数字越大优先级越高

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "task_id": self.task_id,
            "assigned_to": self.assigned_to.value,
            "description": self.description,
            "parameters": self.parameters,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "priority": self.priority
        }


class BaseAgent:
    """智能体基类"""

    def __init__(
        self,
        role: AgentRole,
        name: str,
        description: str,
        tools: List[str] = None,
        llm_analyzer: Optional[Callable] = None,
        tool_executor: Optional[Callable] = None
    ):
        """初始化BaseAgent实例。

        Args:
            self: 类实例。
        """
        self.role = role
        self.name = name
        self.description = description
        self.tools = tools or []
        self.llm_analyzer = llm_analyzer
        self.tool_executor = tool_executor
        self.message_inbox: List[AgentMessage] = []
        self.task_queue: List[AgentTask] = []
        self.completed_tasks: List[AgentTask] = []
        self.status = "idle"  # idle/running/error
        self.knowledge: Dict[str, Any] = {}  # 智能体知识库

    async def receive_message(self, message: AgentMessage):
        """接收消息"""
        self.message_inbox.append(message)
        log.info(f"[{self.name}] 收到消息: {message.message_type.value} from {message.from_agent}")

    async def process_messages(self) -> List[AgentMessage]:
        """处理收件箱中的消息，返回需要发送的回复"""
        replies = []
        while self.message_inbox:
            message = self.message_inbox.pop(0)
            reply = await self.handle_message(message)
            if reply:
                replies.append(reply)
        return replies

    async def handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理单条消息，子类可重写"""
        if message.message_type == MessageType.TASK_ASSIGN:
            task = AgentTask(
                task_id=message.content.get("task_id", str(uuid.uuid4())[:8]),
                assigned_to=self.role,
                description=message.content.get("description", ""),
                parameters=message.content.get("parameters", {}),
                priority=message.content.get("priority", 0)
            )
            self.task_queue.append(task)
            log.info(f"[{self.name}] 收到任务: {task.description}")
            return self._create_reply(message, MessageType.STATUS_UPDATE, {
                "status": "accepted",
                "task_id": task.task_id
            })

        elif message.message_type == MessageType.INFO_SHARE:
            # 共享信息到知识库
            for key, value in message.content.items():
                self.knowledge[key] = value
            log.info(f"[{self.name}] 接收信息: {list(message.content.keys())}")
            return None

        return None

    def _create_reply(self, original: AgentMessage, msg_type: MessageType, content: Dict[str, Any]) -> AgentMessage:
        """创建回复消息"""
        return AgentMessage(
            message_id=str(uuid.uuid4())[:8],
            from_agent=self.name,
            to_agent=original.from_agent,
            message_type=msg_type,
            content=content,
            in_reply_to=original.message_id
        )

    async def execute_next_task(self) -> Optional[AgentTask]:
        """执行下一个任务"""
        if not self.task_queue:
            return None

        # 按优先级排序
        self.task_queue.sort(key=lambda t: t.priority, reverse=True)
        task = self.task_queue.pop(0)
        task.status = "running"
        self.status = "running"

        log.info(f"[{self.name}] 开始执行任务: {task.description}")

        try:
            result = await self.execute_task(task)
            task.result = result
            task.status = "completed"
            task.completed_at = time.time()
            log.info(f"[{self.name}] 任务完成: {task.description}")
        except Exception as e:
            task.error = str(e)
            task.status = "failed"
            task.completed_at = time.time()
            log.error(f"[{self.name}] 任务失败: {task.description}, 错误: {e}")

        self.completed_tasks.append(task)
        self.status = "idle"
        return task

    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """执行具体任务，子类必须重写"""
        raise NotImplementedError("子类必须实现execute_task方法")

    async def analyze_with_llm(self, prompt: str, context: Dict[str, Any] = None) -> str:
        """使用LLM分析"""
        if self.llm_analyzer:
            try:
                return await self.llm_analyzer(prompt, context or {})
            except Exception as e:
                log.error(f"[{self.name}] LLM分析失败: {e}")
                return f"LLM分析失败: {str(e)}"
        return "LLM分析器未配置"

    async def call_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """调用工具"""
        if tool_name not in self.tools:
            return {"status": "error", "message": f"工具不在智能体的工具集中: {tool_name}"}
        if self.tool_executor:
            return await self.tool_executor(tool_name, parameters)
        return {"status": "error", "message": "工具执行器未配置"}

    def get_status(self) -> Dict[str, Any]:
        """获取智能体状态"""
        return {
            "role": self.role.value,
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "tools_count": len(self.tools),
            "pending_tasks": len(self.task_queue),
            "completed_tasks": len(self.completed_tasks),
            "inbox_messages": len(self.message_inbox),
            "knowledge_keys": list(self.knowledge.keys())
        }


class ReconAgent(BaseAgent):
    """侦察智能体"""

    def __init__(self, llm_analyzer=None, tool_executor=None):
        """初始化ReconAgent实例。

        Args:
            self: 类实例。
        """
        super().__init__(
            role=AgentRole.RECON,
            name="ReconAgent",
            description="侦察智能体：负责情报收集、端口扫描、服务识别、子域名枚举、技术栈识别",
            tools=["port_scan", "internal_port_scan", "dns_lookup", "http_headers", "subdomain_certificate_transparency",
                   "directory_scan", "netbios_enum", "smb_scan", "ldap_query", "kerberos_enum"],
            llm_analyzer=llm_analyzer,
            tool_executor=tool_executor
        )

    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """执行侦察任务"""
        target = task.parameters.get("target", "")
        task_type = task.parameters.get("task_type", "full_recon")

        results = {"target": target, "task_type": task_type, "findings": {}}

        if task_type in ("full_recon", "port_scan"):
            # 端口扫描
            port_result = await self.call_tool("port_scan", {"target": target, "ports": "1-10000"})
            results["findings"]["port_scan"] = port_result
            open_ports = port_result.get("result", {}).get("open_ports", []) if port_result.get("status") == "success" else []
            self.knowledge["open_ports"] = open_ports
            self.knowledge["target"] = target

        if task_type in ("full_recon", "service_identify"):
            # HTTP头分析
            if 80 in self.knowledge.get("open_ports", []) or 443 in self.knowledge.get("open_ports", []):
                http_result = await self.call_tool("http_headers", {"url": f"http://{target}"})
                results["findings"]["http_headers"] = http_result

        # AI分析侦察结果
        analysis = await self.analyze_with_llm(
            """你是一名资深渗透测试侦察专家。请分析以下侦察结果：
1. 目标开放了哪些端口和服务？
2. 目标可能是什么系统？（Windows/Linux/网络设备）
3. 技术栈是什么？
4. 下一步应该重点测试哪些方向？
5. 有哪些明显的安全隐患？
请用中文回答，结构清晰。""",
            {"target": target, "findings": results["findings"]}
        )
        results["ai_analysis"] = analysis

        return results


class ExploitAgent(BaseAgent):
    """漏洞利用智能体"""

    def __init__(self, llm_analyzer=None, tool_executor=None):
        """初始化ExploitAgent实例。

        Args:
            self: 类实例。
        """
        super().__init__(
            role=AgentRole.EXPLOIT,
            name="ExploitAgent",
            description="漏洞利用智能体：负责漏洞扫描、漏洞验证、SQL注入/XSS/命令注入/SSRF/IDOR测试、漏洞利用",
            tools=["sql_injection_test", "xss_test", "command_injection_test", "ssrf_test", "idor_test",
                   "file_upload_test", "xxe_test", "ssl_certificate_check", "smb_scan", "rdp_detect", "winrm_detect"],
            llm_analyzer=llm_analyzer,
            tool_executor=tool_executor
        )

    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """执行漏洞利用任务"""
        target = task.parameters.get("target", "")
        vuln_type = task.parameters.get("vuln_type", "all")
        open_ports = task.parameters.get("open_ports", [])

        results = {"target": target, "vulnerabilities": [], "tested": []}

        # 根据开放端口决定测试哪些漏洞
        if vuln_type in ("all", "web") and (80 in open_ports or 443 in open_ports):
            # SQL注入
            sqli_result = await self.call_tool("sql_injection_test", {"url": f"http://{target}/?id=1", "param": "id"})
            results["tested"].append("sql_injection")
            if sqli_result.get("status") == "success":
                vulns = sqli_result.get("result", {}).get("vulnerabilities", [])
                results["vulnerabilities"].extend(vulns)

            # XSS
            xss_result = await self.call_tool("xss_test", {"url": f"http://{target}/?q=test", "param": "q"})
            results["tested"].append("xss")
            if xss_result.get("status") == "success":
                vulns = xss_result.get("result", {}).get("vulnerabilities", [])
                results["vulnerabilities"].extend(vulns)

            # 命令注入
            cmd_result = await self.call_tool("command_injection_test", {"url": f"http://{target}/ping?host=127.0.0.1", "param": "host"})
            results["tested"].append("command_injection")

        # SSL检测
        if vuln_type in ("all", "ssl") and 443 in open_ports:
            ssl_result = await self.call_tool("ssl_certificate_check", {"host": target})
            results["tested"].append("ssl")

        # AI分析
        analysis = await self.analyze_with_llm(
            """你是一名资深漏洞利用专家。请分析以下漏洞测试结果：
1. 发现了哪些漏洞？严重程度如何？
2. 哪些漏洞可以被实际利用？
3. 漏洞利用的难度和前提条件？
4. 建议下一步验证哪些漏洞？
请用中文回答。""",
            {"target": target, "vulnerabilities": results["vulnerabilities"], "tested": results["tested"]}
        )
        results["ai_analysis"] = analysis

        return results


class VerificationAgent(BaseAgent):
    """验证智能体"""

    def __init__(self, llm_analyzer=None, tool_executor=None):
        """初始化VerificationAgent实例。

        Args:
            self: 类实例。
        """
        super().__init__(
            role=AgentRole.VERIFICATION,
            name="VerificationAgent",
            description="验证智能体：负责漏洞验证、误报排除、风险评估、可利用性判断、攻击路径分析",
            tools=["sql_injection_test", "xss_test", "ssrf_test", "idor_test", "command_injection_test",
                   "file_upload_test", "xxe_test", "pass_the_hash_detect"],
            llm_analyzer=llm_analyzer,
            tool_executor=tool_executor
        )

    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """执行验证任务"""
        target = task.parameters.get("target", "")
        vulnerabilities = task.parameters.get("vulnerabilities", [])

        results = {"target": target, "verified": [], "false_positives": [], "risk_assessment": {}}

        for vuln in vulnerabilities:
            vuln_name = vuln.get("name", "")
            vuln_type = vuln.get("type", "")

            # 简单验证逻辑：重新测试确认
            verification_result = await self._verify_vulnerability(target, vuln)
            if verification_result["confirmed"]:
                results["verified"].append({**vuln, "verification": verification_result})
            else:
                results["false_positives"].append({**vuln, "reason": verification_result.get("reason", "无法确认")})

        # 风险评估
        high_count = sum(1 for v in results["verified"] if v.get("severity", "").lower() in ("critical", "high"))
        medium_count = sum(1 for v in results["verified"] if v.get("severity", "").lower() == "medium")
        results["risk_assessment"] = {
            "total_verified": len(results["verified"]),
            "false_positives": len(results["false_positives"]),
            "high_risk_count": high_count,
            "medium_risk_count": medium_count,
            "overall_risk": "High" if high_count > 0 else "Medium" if medium_count > 0 else "Low"
        }

        # AI分析
        analysis = await self.analyze_with_llm(
            """你是一名资深漏洞验证专家。请分析以下验证结果：
1. 哪些漏洞被确认存在？哪些是误报？
2. 确认漏洞的实际影响和利用难度？
3. 攻击路径分析：攻击者如何利用这些漏洞？
4. 整体风险评级和修复优先级建议。
请用中文回答。""",
            results
        )
        results["ai_analysis"] = analysis

        return results

    async def _verify_vulnerability(self, target: str, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """验证单个漏洞"""
        vuln_name = vuln.get("name", "").lower()
        try:
            if "sql" in vuln_name or "注入" in vuln_name:
                result = await self.call_tool("sql_injection_test", {"url": f"http://{target}/?id=1", "param": "id"})
                return {"confirmed": result.get("status") == "success", "method": "重新测试SQL注入"}
            elif "xss" in vuln_name or "跨站" in vuln_name:
                result = await self.call_tool("xss_test", {"url": f"http://{target}/?q=test", "param": "q"})
                return {"confirmed": result.get("status") == "success", "method": "重新测试XSS"}
            else:
                return {"confirmed": True, "method": "基于扫描结果确认", "note": "需要手动验证"}
        except Exception as e:
            return {"confirmed": False, "reason": f"验证失败: {str(e)}"}


class ReportAgent(BaseAgent):
    """报告智能体"""

    def __init__(self, llm_analyzer=None, tool_executor=None):
        """初始化ReportAgent实例。

        Args:
            self: 类实例。
        """
        super().__init__(
            role=AgentRole.REPORT,
            name="ReportAgent",
            description="报告智能体：负责报告生成、修复建议、风险评级、执行摘要、技术细节整理",
            tools=[],
            llm_analyzer=llm_analyzer,
            tool_executor=tool_executor
        )

    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """执行报告生成任务"""
        target = task.parameters.get("target", "")
        recon_results = task.parameters.get("recon_results", {})
        exploit_results = task.parameters.get("exploit_results", {})
        verification_results = task.parameters.get("verification_results", {})

        # 汇总所有结果
        all_vulnerabilities = []
        all_vulnerabilities.extend(exploit_results.get("vulnerabilities", []))
        all_vulnerabilities.extend(verification_results.get("verified", []))

        # 去重
        seen = set()
        unique_vulns = []
        for v in all_vulnerabilities:
            key = v.get("name", "") + str(v.get("affected", ""))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)

        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        unique_vulns.sort(key=lambda v: severity_order.get(v.get("severity", "info").lower(), 5))

        results = {
            "target": target,
            "total_vulnerabilities": len(unique_vulns),
            "vulnerabilities": unique_vulns,
            "recon_summary": recon_results.get("findings", {}),
            "verification_summary": verification_results.get("risk_assessment", {}),
            "report": None
        }

        # 生成报告
        report = await self.analyze_with_llm(
            """你是一名专业的渗透测试报告撰写专家。请基于以下所有测试结果，生成一份完整的渗透测试报告：
1. 执行摘要（目标、时间、整体风险评级、关键发现）
2. 测试方法论（使用的工具、测试流程）
3. 情报收集结果（开放端口、服务、技术栈）
4. 漏洞清单（按严重程度排序，每个漏洞包含名称、严重程度、描述、影响、修复建议）
5. 风险分析（整体风险、业务影响、攻击路径）
6. 修复建议（紧急/高/中/低优先级）
请用中文撰写，专业、准确、可操作。""",
            results
        )
        results["report"] = report

        return results


class MultiAgentCoordinator:
    """多智能体协调器"""

    def __init__(self, llm_analyzer=None, tool_executor=None):
        """初始化MultiAgentCoordinator实例。

        Args:
            self: 类实例。
        """
        self.agents: Dict[AgentRole, BaseAgent] = {}
        self.message_log: List[AgentMessage] = []
        self.task_history: List[AgentTask] = []
        self.llm_analyzer = llm_analyzer
        self.tool_executor = tool_executor

        # 初始化4个智能体
        self._init_agents()

    def _init_agents(self):
        """初始化所有智能体"""
        self.agents[AgentRole.RECON] = ReconAgent(self.llm_analyzer, self.tool_executor)
        self.agents[AgentRole.EXPLOIT] = ExploitAgent(self.llm_analyzer, self.tool_executor)
        self.agents[AgentRole.VERIFICATION] = VerificationAgent(self.llm_analyzer, self.tool_executor)
        self.agents[AgentRole.REPORT] = ReportAgent(self.llm_analyzer, self.tool_executor)
        log.info("多智能体协调器初始化完成，4个智能体已就绪")

    async def send_message(self, from_agent: str, to_role: AgentRole, message_type: MessageType, content: Dict[str, Any]) -> AgentMessage:
        """发送消息给指定智能体"""
        message = AgentMessage(
            message_id=str(uuid.uuid4())[:8],
            from_agent=from_agent,
            to_agent=self.agents[to_role].name,
            message_type=message_type,
            content=content
        )
        await self.agents[to_role].receive_message(message)
        self.message_log.append(message)
        return message

    async def assign_task(self, role: AgentRole, description: str, parameters: Dict[str, Any] = None, priority: int = 0) -> AgentTask:
        """分配任务给指定智能体"""
        task = AgentTask(
            task_id=str(uuid.uuid4())[:8],
            assigned_to=role,
            description=description,
            parameters=parameters or {},
            priority=priority
        )
        self.agents[role].task_queue.append(task)
        self.task_history.append(task)

        # 发送任务分配消息
        await self.send_message(
            from_agent="Coordinator",
            to_role=role,
            message_type=MessageType.TASK_ASSIGN,
            content={
                "task_id": task.task_id,
                "description": description,
                "parameters": parameters or {},
                "priority": priority
            }
        )
        return task

    async def run_full_pentest(self, target: str) -> Dict[str, Any]:
        """运行完整的多智能体渗透测试流程"""
        log.info(f"多智能体渗透测试开始: {target}")
        start_time = time.time()

        results = {
            "target": target,
            "workflow": "multi_agent_collaboration",
            "phases": {},
            "overall_status": "running"
        }

        try:
            # ===== 阶段1: 侦察智能体 =====
            log.info("=== 阶段1: 侦察智能体 ===")
            recon_task = await self.assign_task(
                AgentRole.RECON,
                f"对目标 {target} 进行全面侦察",
                {"target": target, "task_type": "full_recon"},
                priority=10
            )
            recon_result = await self.agents[AgentRole.RECON].execute_next_task()
            results["phases"]["recon"] = recon_result.to_dict() if recon_result else {}

            # 共享侦察结果给其他智能体
            open_ports = recon_result.result.get("findings", {}).get("port_scan", {}).get("result", {}).get("open_ports", []) if recon_result and recon_result.result else []
            await self.send_message("Coordinator", AgentRole.EXPLOIT, MessageType.INFO_SHARE,
                                     {"target": target, "open_ports": open_ports})
            await self.send_message("Coordinator", AgentRole.VERIFICATION, MessageType.INFO_SHARE,
                                     {"target": target, "open_ports": open_ports})

            # ===== 阶段2: 漏洞利用智能体 =====
            log.info("=== 阶段2: 漏洞利用智能体 ===")
            exploit_task = await self.assign_task(
                AgentRole.EXPLOIT,
                f"对目标 {target} 进行漏洞扫描和利用测试",
                {"target": target, "vuln_type": "all", "open_ports": open_ports},
                priority=8
            )
            exploit_result = await self.agents[AgentRole.EXPLOIT].execute_next_task()
            results["phases"]["exploit"] = exploit_result.to_dict() if exploit_result else {}

            # ===== 阶段3: 验证智能体 =====
            log.info("=== 阶段3: 验证智能体 ===")
            vulnerabilities = exploit_result.result.get("vulnerabilities", []) if exploit_result and exploit_result.result else []
            verify_task = await self.assign_task(
                AgentRole.VERIFICATION,
                f"验证目标 {target} 的漏洞，排除误报",
                {"target": target, "vulnerabilities": vulnerabilities},
                priority=6
            )
            verify_result = await self.agents[AgentRole.VERIFICATION].execute_next_task()
            results["phases"]["verification"] = verify_result.to_dict() if verify_result else {}

            # ===== 阶段4: 报告智能体 =====
            log.info("=== 阶段4: 报告智能体 ===")
            report_task = await self.assign_task(
                AgentRole.REPORT,
                f"生成目标 {target} 的完整渗透测试报告",
                {
                    "target": target,
                    "recon_results": recon_result.result if recon_result else {},
                    "exploit_results": exploit_result.result if exploit_result else {},
                    "verification_results": verify_result.result if verify_result else {}
                },
                priority=4
            )
            report_result = await self.agents[AgentRole.REPORT].execute_next_task()
            results["phases"]["report"] = report_result.to_dict() if report_result else {}

            results["overall_status"] = "completed"
            results["final_report"] = report_result.result.get("report", "") if report_result and report_result.result else ""
            results["total_vulnerabilities"] = report_result.result.get("total_vulnerabilities", 0) if report_result and report_result.result else 0

        except Exception as e:
            results["overall_status"] = "failed"
            results["error"] = str(e)
            log.error(f"多智能体渗透测试失败: {e}")

        results["duration_seconds"] = round(time.time() - start_time, 2)
        log.info(f"多智能体渗透测试完成: {target}, 耗时: {results['duration_seconds']}秒")

        return results

    def get_all_agents_status(self) -> Dict[str, Any]:
        """获取所有智能体状态"""
        return {
            "agents": {role.value: agent.get_status() for role, agent in self.agents.items()},
            "total_messages": len(self.message_log),
            "total_tasks": len(self.task_history)
        }


# 全局实例
multi_agent_coordinator = MultiAgentCoordinator()
