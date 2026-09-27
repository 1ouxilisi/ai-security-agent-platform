#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decision_engine模块，提供相关安全测试功能。

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
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from utils.logger import log


class DecisionPhase(str, Enum):
    """决策阶段"""
    RECON = "recon"  # 信息收集
    ANALYSIS = "analysis"  # 分析评估
    EXPLOITATION = "exploitation"  # 漏洞利用
    PRIVILEGE_ESCALATION = "privilege_escalation"  # 权限提升
    POST_EXPLOITATION = "post_exploitation"  # 后渗透
    REPORTING = "reporting"  # 报告
    COMPLETED = "completed"  # 完成


class ActionPriority(str, Enum):
    """行动优先级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class TargetProfile:
    """目标画像"""
    target: str
    target_type: str = "unknown"  # web_server/database/cms/iot/network_device
    ip_address: str = ""
    domain: str = ""
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    cms: str = ""
    web_server: str = ""
    database: str = ""
    programming_language: str = ""
    operating_system: str = ""
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    attack_surface: int = 0
    risk_score: float = 0.0
    last_updated: float = field(default_factory=time.time)

    def update(self, data: Dict[str, Any]):
        """更新目标画像"""
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.last_updated = time.time()
        self._calculate_risk_score()

    def _calculate_risk_score(self):
        """计算风险分数"""
        score = 0.0
        # 开放端口
        score += len(self.open_ports) * 2
        # 高危服务
        high_risk_services = ["ssh", "rdp", "smb", "ftp", "telnet", "mysql", "redis", "mongodb"]
        for svc in self.services:
            if svc.get("name", "").lower() in high_risk_services:
                score += 10
        # 漏洞
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "low")
            score += {"critical": 50, "high": 25, "medium": 10, "low": 3}.get(severity, 0)
        # 攻击面
        self.attack_surface = len(self.open_ports) + len(self.technologies) + len(self.vulnerabilities)
        self.risk_score = min(score, 1000)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "target": self.target,
            "target_type": self.target_type,
            "ip_address": self.ip_address,
            "domain": self.domain,
            "open_ports": self.open_ports,
            "services": self.services,
            "technologies": self.technologies,
            "cms": self.cms,
            "web_server": self.web_server,
            "database": self.database,
            "programming_language": self.programming_language,
            "operating_system": self.operating_system,
            "vulnerabilities": self.vulnerabilities,
            "attack_surface": self.attack_surface,
            "risk_score": self.risk_score
        }


@dataclass
class DecisionAction:
    """决策行动"""
    action_id: str
    phase: DecisionPhase
    name: str
    description: str
    tool: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: ActionPriority = ActionPriority.MEDIUM
    expected_outcome: str = ""
    success_criteria: List[str] = field(default_factory=list)
    estimated_time: int = 60  # 秒
    dependencies: List[str] = field(default_factory=list)
    status: str = "pending"  # pending/running/completed/failed/skipped
    result: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "action_id": self.action_id,
            "phase": self.phase.value,
            "name": self.name,
            "description": self.description,
            "tool": self.tool,
            "parameters": self.parameters,
            "priority": self.priority.value,
            "expected_outcome": self.expected_outcome,
            "success_criteria": self.success_criteria,
            "estimated_time": self.estimated_time,
            "dependencies": self.dependencies,
            "status": self.status,
            "result": self.result,
            "started_at": self.started_at,
            "completed_at": self.completed_at
        }


@dataclass
class DecisionState:
    """决策状态"""
    session_id: str
    target: str
    current_phase: DecisionPhase = DecisionPhase.RECON
    target_profile: TargetProfile = None
    action_history: List[DecisionAction] = field(default_factory=list)
    pending_actions: List[DecisionAction] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    decision_log: List[Dict[str, Any]] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    max_actions: int = 50
    max_time: int = 3600  # 1小时

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "session_id": self.session_id,
            "target": self.target,
            "current_phase": self.current_phase.value,
            "target_profile": self.target_profile.to_dict() if self.target_profile else None,
            "action_count": len(self.action_history),
            "findings_count": len(self.findings),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "elapsed_time": time.time() - self.started_at
        }


class AutonomousDecisionEngine:
    """自主决策引擎"""

    def __init__(self):
        """初始化AutonomousDecisionEngine实例。

        Args:
            self: 类实例。
        """
        self.sessions: Dict[str, DecisionState] = {}
        self.decision_rules = self._init_decision_rules()

    def _init_decision_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """初始化决策规则"""
        return {
            "recon": [
                {
                    "condition": "no_open_ports",
                    "action": "port_scan",
                    "priority": "critical",
                    "description": "目标没有开放端口信息，先进行端口扫描"
                },
                {
                    "condition": "has_web_service",
                    "action": "web_recon",
                    "priority": "high",
                    "description": "发现Web服务，进行Web目录和技术栈探测"
                },
                {
                    "condition": "has_domain",
                    "action": "subdomain_enum",
                    "priority": "medium",
                    "description": "目标是域名，进行子域名枚举"
                }
            ],
            "analysis": [
                {
                    "condition": "has_vulnerabilities",
                    "action": "vulnerability_prioritization",
                    "priority": "high",
                    "description": "发现漏洞，进行优先级排序和可利用性评估"
                },
                {
                    "condition": "has_cms",
                    "action": "cms_vulnerability_lookup",
                    "priority": "high",
                    "description": "识别到CMS，查询已知漏洞和利用方式"
                }
            ],
            "exploitation": [
                {
                    "condition": "has_exploitable_vuln",
                    "action": "exploit_vulnerability",
                    "priority": "critical",
                    "description": "存在可利用漏洞，进行漏洞利用"
                },
                {
                    "condition": "has_sql_injection",
                    "action": "sql_injection_exploit",
                    "priority": "high",
                    "description": "存在SQL注入，提取数据库数据"
                },
                {
                    "condition": "has_file_upload",
                    "action": "webshell_upload",
                    "priority": "high",
                    "description": "存在文件上传漏洞，上传webshell获取权限"
                }
            ],
            "privilege_escalation": [
                {
                    "condition": "has_initial_access",
                    "action": "privilege_escalation_check",
                    "priority": "high",
                    "description": "已获取初始访问，检查权限提升路径"
                },
                {
                    "condition": "is_linux",
                    "action": "linux_privesc",
                    "priority": "medium",
                    "description": "Linux系统，检查内核漏洞和sudo配置"
                }
            ],
            "post_exploitation": [
                {
                    "condition": "has_admin_access",
                    "action": "data_exfiltration",
                    "priority": "high",
                    "description": "已获取管理员权限，提取敏感数据"
                },
                {
                    "condition": "has_network_access",
                    "action": "lateral_movement",
                    "priority": "medium",
                    "description": "已进入内网，进行横向移动"
                }
            ]
        }

    def start_session(self, target: str) -> DecisionState:
        """启动决策会话"""
        session_id = f"dec-{uuid.uuid4().hex[:8]}"
        state = DecisionState(
            session_id=session_id,
            target=target,
            target_profile=TargetProfile(target=target)
        )
        self.sessions[session_id] = state
        log.info(f"启动自主决策会话: {session_id}, 目标: {target}")
        return state

    def make_decision(self, session_id: str) -> Optional[DecisionAction]:
        """
        核心决策方法：根据当前状态决定下一步行动
        """
        state = self.sessions.get(session_id)
        if not state:
            return None

        # 检查是否达到限制
        if len(state.action_history) >= state.max_actions:
            state.current_phase = DecisionPhase.COMPLETED
            state.completed_at = time.time()
            return None

        if time.time() - state.started_at > state.max_time:
            state.current_phase = DecisionPhase.COMPLETED
            state.completed_at = time.time()
            return None

        # 根据当前阶段生成行动
        profile = state.target_profile

        if state.current_phase == DecisionPhase.RECON:
            action = self._recon_decision(state, profile)
        elif state.current_phase == DecisionPhase.ANALYSIS:
            action = self._analysis_decision(state, profile)
        elif state.current_phase == DecisionPhase.EXPLOITATION:
            action = self._exploitation_decision(state, profile)
        elif state.current_phase == DecisionPhase.PRIVILEGE_ESCALATION:
            action = self._privesc_decision(state, profile)
        elif state.current_phase == DecisionPhase.POST_EXPLOITATION:
            action = self._post_exploit_decision(state, profile)
        else:
            action = None

        if action:
            state.pending_actions.append(action)
            state.decision_log.append({
                "timestamp": time.time(),
                "phase": state.current_phase.value,
                "action": action.name,
                "reason": action.description
            })
            log.info(f"决策: [{state.current_phase.value}] {action.name} - {action.description}")

        return action

    def _recon_decision(self, state: DecisionState, profile: TargetProfile) -> Optional[DecisionAction]:
        """信息收集阶段决策"""
        # 没有端口信息，先扫描端口
        if not profile.open_ports:
            return DecisionAction(
                action_id=f"act-{uuid.uuid4().hex[:6]}",
                phase=DecisionPhase.RECON,
                name="端口扫描",
                description="目标没有开放端口信息，进行全面端口扫描",
                tool="port_scan",
                parameters={"target": profile.target, "ports": "1-10000", "scan_type": "tcp"},
                priority=ActionPriority.CRITICAL,
                expected_outcome="获取目标开放端口和运行服务",
                success_criteria=["发现至少1个开放端口"]
            )

        # 有Web服务，进行Web探测
        web_ports = [p for p in profile.open_ports if p.get("service", "").lower() in ["http", "https", "http-alt"]]
        if web_ports and not profile.technologies:
            port = web_ports[0]["port"]
            return DecisionAction(
                action_id=f"act-{uuid.uuid4().hex[:6]}",
                phase=DecisionPhase.RECON,
                name="Web技术栈探测",
                description=f"发现Web服务在端口{port}，探测技术栈和目录结构",
                tool="web_recon",
                parameters={"target": profile.target, "port": port, "dir_bruteforce": True},
                priority=ActionPriority.HIGH,
                expected_outcome="识别Web服务器、CMS、编程语言、目录结构",
                success_criteria=["识别至少1种技术", "发现至少5个目录"]
            )

        # 有域名，进行子域名枚举
        if profile.domain and not any("subdomain" in f.get("type", "") for f in state.findings):
            return DecisionAction(
                action_id=f"act-{uuid.uuid4().hex[:6]}",
                phase=DecisionPhase.RECON,
                name="子域名枚举",
                description="目标是域名，进行子域名枚举扩大攻击面",
                tool="subdomain_enum",
                parameters={"domain": profile.domain, "wordlist": "common"},
                priority=ActionPriority.MEDIUM,
                expected_outcome="发现子域名和关联资产",
                success_criteria=["发现至少1个子域名"]
            )

        # 信息收集完成，进入分析阶段
        if profile.open_ports and profile.technologies:
            state.current_phase = DecisionPhase.ANALYSIS
            state.decision_log.append({
                "timestamp": time.time(),
                "phase_transition": f"{DecisionPhase.RECON.value} -> {DecisionPhase.ANALYSIS.value}",
                "reason": "信息收集完成，进入分析评估阶段"
            })
            return self.make_decision(state.session_id)

        return None

    def _analysis_decision(self, state: DecisionState, profile: TargetProfile) -> Optional[DecisionAction]:
        """分析评估阶段决策"""
        # 有漏洞，进行优先级排序
        if profile.vulnerabilities:
            critical_vulns = [v for v in profile.vulnerabilities if v.get("severity") == "critical"]
            high_vulns = [v for v in profile.vulnerabilities if v.get("severity") == "high"]

            if critical_vulns or high_vulns:
                state.current_phase = DecisionPhase.EXPLOITATION
                state.decision_log.append({
                    "timestamp": time.time(),
                    "phase_transition": f"{DecisionPhase.ANALYSIS.value} -> {DecisionPhase.EXPLOITATION.value}",
                    "reason": f"发现{len(critical_vulns)}个严重漏洞和{len(high_vulns)}个高危漏洞，进入利用阶段"
                })
                return self.make_decision(state.session_id)

        # 识别到CMS，查询已知漏洞
        if profile.cms and not any("cms_vuln" in f.get("type", "") for f in state.findings):
            return DecisionAction(
                action_id=f"act-{uuid.uuid4().hex[:6]}",
                phase=DecisionPhase.ANALYSIS,
                name="CMS漏洞查询",
                description=f"识别到{profile.cms}，查询已知漏洞和利用方式",
                tool="vulnerability_lookup",
                parameters={"cms": profile.cms, "version": "all"},
                priority=ActionPriority.HIGH,
                expected_outcome="获取CMS已知漏洞列表和利用方法",
                success_criteria=["发现至少1个可利用漏洞"]
            )

        # 没有可利用漏洞，进入报告阶段
        if not profile.vulnerabilities and profile.cms:
            state.current_phase = DecisionPhase.REPORTING
            return None

        return None

    def _exploitation_decision(self, state: DecisionState, profile: TargetProfile) -> Optional[DecisionAction]:
        """漏洞利用阶段决策"""
        # 优先利用严重漏洞
        critical_vulns = [v for v in profile.vulnerabilities if v.get("severity") == "critical" and not v.get("exploited")]
        high_vulns = [v for v in profile.vulnerabilities if v.get("severity") == "high" and not v.get("exploited")]

        target_vulns = critical_vulns or high_vulns
        if target_vulns:
            vuln = target_vulns[0]
            vuln_type = vuln.get("type", "").lower()

            # SQL注入利用
            if "sql" in vuln_type:
                return DecisionAction(
                    action_id=f"act-{uuid.uuid4().hex[:6]}",
                    phase=DecisionPhase.EXPLOITATION,
                    name="SQL注入利用",
                    description=f"利用SQL注入漏洞提取数据库数据: {vuln.get('location', '')}",
                    tool="sql_injection_exploit",
                    parameters={"url": vuln.get("url", ""), "param": vuln.get("param", ""), "extract_data": True},
                    priority=ActionPriority.CRITICAL,
                    expected_outcome="提取数据库用户、密码、敏感数据",
                    success_criteria=["提取至少1个数据库表", "获取用户凭据"]
                )

            # 文件上传利用
            elif "upload" in vuln_type or "file_upload" in vuln_type:
                return DecisionAction(
                    action_id=f"act-{uuid.uuid4().hex[:6]}",
                    phase=DecisionPhase.EXPLOITATION,
                    name="Webshell上传",
                    description=f"利用文件上传漏洞上传webshell获取服务器权限",
                    tool="file_upload_exploit",
                    parameters={"url": vuln.get("url", ""), "upload_webshell": True},
                    priority=ActionPriority.CRITICAL,
                    expected_outcome="上传webshell并获取命令执行权限",
                    success_criteria=["webshell上传成功", "可执行系统命令"]
                )

            # 命令注入利用
            elif "command" in vuln_type or "rce" in vuln_type:
                return DecisionAction(
                    action_id=f"act-{uuid.uuid4().hex[:6]}",
                    phase=DecisionPhase.EXPLOITATION,
                    name="命令注入利用",
                    description=f"利用命令注入漏洞执行系统命令",
                    tool="command_injection_exploit",
                    parameters={"url": vuln.get("url", ""), "param": vuln.get("param", ""), "command": "id; whoami"},
                    priority=ActionPriority.CRITICAL,
                    expected_outcome="执行系统命令，获取服务器信息",
                    success_criteria=["命令执行成功", "获取当前用户信息"]
                )

            # 通用漏洞利用
            else:
                return DecisionAction(
                    action_id=f"act-{uuid.uuid4().hex[:6]}",
                    phase=DecisionPhase.EXPLOITATION,
                    name=f"漏洞利用: {vuln.get('name', 'Unknown')}",
                    description=f"利用发现的漏洞: {vuln.get('description', '')}",
                    tool="generic_exploit",
                    parameters={"vulnerability": vuln},
                    priority=ActionPriority.HIGH,
                    expected_outcome="成功利用漏洞获取访问权限",
                    success_criteria=["漏洞利用成功"]
                )

        # 所有漏洞都已利用，进入后渗透阶段
        if not any(not v.get("exploited") for v in profile.vulnerabilities if v.get("severity") in ["critical", "high"]):
            if any(v.get("exploited") for v in profile.vulnerabilities):
                state.current_phase = DecisionPhase.POST_EXPLOITATION
                return self.make_decision(state.session_id)
            else:
                state.current_phase = DecisionPhase.REPORTING
                return None

        return None

    def _privesc_decision(self, state: DecisionState, profile: TargetProfile) -> Optional[DecisionAction]:
        """权限提升阶段决策"""
        # 已获取初始访问，检查权限提升
        if any(v.get("exploited") for v in profile.vulnerabilities):
            return DecisionAction(
                action_id=f"act-{uuid.uuid4().hex[:6]}",
                phase=DecisionPhase.PRIVILEGE_ESCALATION,
                name="权限提升检查",
                description="已获取初始访问，检查权限提升路径",
                tool="privilege_escalation_check",
                parameters={"os": profile.operating_system, "check_kernel": True, "check_sudo": True},
                priority=ActionPriority.HIGH,
                expected_outcome="发现权限提升路径",
                success_criteria=["发现至少1个权限提升方法"]
            )

        state.current_phase = DecisionPhase.POST_EXPLOITATION
        return self.make_decision(state.session_id)

    def _post_exploit_decision(self, state: DecisionState, profile: TargetProfile) -> Optional[DecisionAction]:
        """后渗透阶段决策"""
        # 提取敏感数据
        if any(v.get("exploited") for v in profile.vulnerabilities):
            return DecisionAction(
                action_id=f"act-{uuid.uuid4().hex[:6]}",
                phase=DecisionPhase.POST_EXPLOITATION,
                name="敏感数据提取",
                description="已获取访问权限，提取敏感数据",
                tool="data_exfiltration",
                parameters={"target": profile.target, "extract_credentials": True, "extract_config": True},
                priority=ActionPriority.HIGH,
                expected_outcome="提取用户凭据、配置文件、敏感数据",
                success_criteria=["提取至少1组凭据", "发现敏感数据"]
            )

        # 完成，进入报告阶段
        state.current_phase = DecisionPhase.REPORTING
        state.completed_at = time.time()
        return None

    def record_action_result(self, session_id: str, action_id: str,
                              success: bool, result: Dict[str, Any],
                              findings: List[Dict[str, Any]] = None):
        """记录行动结果并更新状态"""
        state = self.sessions.get(session_id)
        if not state:
            return

        # 找到行动
        action = None
        for a in state.pending_actions:
            if a.action_id == action_id:
                action = a
                state.pending_actions.remove(a)
                break

        if not action:
            for a in state.action_history:
                if a.action_id == action_id:
                    action = a
                    break

        if action:
            action.status = "completed" if success else "failed"
            action.result = result
            action.completed_at = time.time()
            if action not in state.action_history:
                state.action_history.append(action)

        # 更新发现
        if findings:
            for finding in findings:
                state.findings.append(finding)
                # 更新目标画像
                if finding.get("type") == "open_port":
                    state.target_profile.open_ports.append(finding.get("data", {}))
                elif finding.get("type") == "vulnerability":
                    state.target_profile.vulnerabilities.append(finding.get("data", {}))
                elif finding.get("type") == "technology":
                    tech = finding.get("data", {})
                    if tech.get("name") not in state.target_profile.technologies:
                        state.target_profile.technologies.append(tech.get("name"))

        state.target_profile._calculate_risk_score()
        log.info(f"行动结果记录: {action_id}, 成功={success}, 发现={len(findings or [])}")

    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """获取会话状态"""
        state = self.sessions.get(session_id)
        if not state:
            return {"error": "会话不存在"}

        return {
            **state.to_dict(),
            "pending_actions": [a.to_dict() for a in state.pending_actions],
            "recent_actions": [a.to_dict() for a in state.action_history[-10:]],
            "recent_findings": state.findings[-10:],
            "decision_log": state.decision_log[-10:]
        }

    def get_statistics(self) -> Dict[str, Any]:
        """获取引擎统计"""
        total_sessions = len(self.sessions)
        completed_sessions = sum(1 for s in self.sessions.values() if s.completed_at)
        total_actions = sum(len(s.action_history) for s in self.sessions.values())
        total_findings = sum(len(s.findings) for s in self.sessions.values())

        return {
            "total_sessions": total_sessions,
            "completed_sessions": completed_sessions,
            "active_sessions": total_sessions - completed_sessions,
            "total_actions": total_actions,
            "total_findings": total_findings,
            "decision_rules_count": sum(len(rules) for rules in self.decision_rules.values()),
            "phases": [phase.value for phase in DecisionPhase]
        }


# 全局实例
decision_engine = AutonomousDecisionEngine()
