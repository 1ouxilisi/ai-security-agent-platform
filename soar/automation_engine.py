#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
automation_engine模块，提供相关安全测试功能。

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
import time
import uuid
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

from utils.logger import log


class ActionType(str, Enum):
    """动作类型"""
    IP_BLOCK = "ip_block"  # IP封禁
    IP_UNBLOCK = "ip_unblock"  # IP解封
    ACCOUNT_DISABLE = "account_disable"  # 账号禁用
    ACCOUNT_ENABLE = "account_enable"  # 账号启用
    ACCOUNT_LOCK = "account_lock"  # 账号锁定
    PASSWORD_RESET = "password_reset"  # 密码重置
    PROCESS_TERMINATE = "process_terminate"  # 进程终止
    FILE_QUARANTINE = "file_quarantine"  # 文件隔离
    HOST_ISOLATE = "host_isolate"  # 主机隔离
    HOST_UNISOLATE = "host_unisolate"  # 主机恢复
    ALERT_ESCALATE = "alert_escalate"  # 告警升级
    ALERT_SUPPRESS = "alert_suppress"  # 告警抑制
    TICKET_CREATE = "ticket_create"  # 创建工单
    NOTIFICATION_SEND = "notification_send"  # 发送通知
    EVIDENCE_COLLECT = "evidence_collect"  # 证据收集
    SCAN_TRIGGER = "scan_trigger"  # 触发扫描
    CUSTOM_SCRIPT = "custom_script"  # 自定义脚本


class PlaybookStatus(str, Enum):
    """剧本状态"""
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"


class ExecutionStatus(str, Enum):
    """执行状态"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    NEEDS_APPROVAL = "needs_approval"


@dataclass
class ResponseAction:
    """响应动作"""
    action_id: str
    action_type: str
    name: str
    description: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 300  # 超时时间（秒）
    require_approval: bool = False
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    execution_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "timeout": self.timeout,
            "require_approval": self.require_approval,
            "enabled": self.enabled,
            "execution_count": self.execution_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "tags": self.tags
        }


@dataclass
class ResponsePlaybook:
    """响应剧本"""
    playbook_id: str
    name: str
    description: str = ""
    trigger_condition: Dict[str, Any] = field(default_factory=dict)  # 触发条件
    steps: List[Dict[str, Any]] = field(default_factory=list)  # 执行步骤
    status: str = "active"
    severity: str = "medium"  # 适用的告警严重程度
    category: str = "general"  # 适用类别
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    execution_count: int = 0
    success_count: int = 0
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "trigger_condition": self.trigger_condition,
            "steps": self.steps,
            "status": self.status,
            "severity": self.severity,
            "category": self.category,
            "execution_count": self.execution_count,
            "success_count": self.success_count,
            "tags": self.tags
        }


@dataclass
class ExecutionRecord:
    """执行记录"""
    execution_id: str
    playbook_id: str = ""
    playbook_name: str = ""
    alert_id: str = ""
    trigger_type: str = "manual"  # manual/alert/scheduled
    status: str = "pending"
    steps_executed: int = 0
    steps_total: int = 0
    steps_success: int = 0
    steps_failed: int = 0
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    duration_seconds: float = 0
    triggered_by: str = ""
    results: List[Dict[str, Any]] = field(default_factory=list)
    error_message: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "execution_id": self.execution_id,
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook_name,
            "alert_id": self.alert_id,
            "trigger_type": self.trigger_type,
            "status": self.status,
            "steps_executed": self.steps_executed,
            "steps_total": self.steps_total,
            "steps_success": self.steps_success,
            "steps_failed": self.steps_failed,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": round(self.duration_seconds, 2),
            "triggered_by": self.triggered_by,
            "results": self.results,
            "error_message": self.error_message,
            "tags": self.tags
        }


class SOAREngine:
    """SOAR自动化响应引擎"""

    def __init__(self, data_dir: str = "data/soar"):
        """初始化SOAREngine实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.actions: Dict[str, ResponseAction] = {}
        self.playbooks: Dict[str, ResponsePlaybook] = {}
        self.executions: Dict[str, ExecutionRecord] = {}
        self.blocked_ips: Set[str] = set()
        self.disabled_accounts: Set[str] = set()
        os.makedirs(data_dir, exist_ok=True)
        self._load_data()
        self._init_default_actions()
        self._init_default_playbooks()

    def _load_data(self):
        """从文件加载数据"""
        # 加载动作
        actions_file = os.path.join(self.data_dir, "actions.json")
        if os.path.exists(actions_file):
            try:
                with open(actions_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for aid, adata in data.items():
                    self.actions[aid] = ResponseAction(
                        action_id=adata["action_id"],
                        action_type=adata["action_type"],
                        name=adata["name"],
                        description=adata.get("description", ""),
                        parameters=adata.get("parameters", {}),
                        timeout=adata.get("timeout", 300),
                        require_approval=adata.get("require_approval", False),
                        enabled=adata.get("enabled", True),
                        execution_count=adata.get("execution_count", 0),
                        success_count=adata.get("success_count", 0),
                        failure_count=adata.get("failure_count", 0),
                        tags=adata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载动作失败: {e}")

        # 加载剧本
        playbooks_file = os.path.join(self.data_dir, "playbooks.json")
        if os.path.exists(playbooks_file):
            try:
                with open(playbooks_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for pid, pdata in data.items():
                    self.playbooks[pid] = ResponsePlaybook(
                        playbook_id=pdata["playbook_id"],
                        name=pdata["name"],
                        description=pdata.get("description", ""),
                        trigger_condition=pdata.get("trigger_condition", {}),
                        steps=pdata.get("steps", []),
                        status=pdata.get("status", "active"),
                        severity=pdata.get("severity", "medium"),
                        category=pdata.get("category", "general"),
                        execution_count=pdata.get("execution_count", 0),
                        success_count=pdata.get("success_count", 0),
                        tags=pdata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载剧本失败: {e}")

        # 加载执行记录
        executions_file = os.path.join(self.data_dir, "executions.json")
        if os.path.exists(executions_file):
            try:
                with open(executions_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for eid, edata in data.items():
                    self.executions[eid] = ExecutionRecord(
                        execution_id=edata["execution_id"],
                        playbook_id=edata.get("playbook_id", ""),
                        playbook_name=edata.get("playbook_name", ""),
                        alert_id=edata.get("alert_id", ""),
                        trigger_type=edata.get("trigger_type", "manual"),
                        status=edata.get("status", "pending"),
                        steps_executed=edata.get("steps_executed", 0),
                        steps_total=edata.get("steps_total", 0),
                        steps_success=edata.get("steps_success", 0),
                        steps_failed=edata.get("steps_failed", 0),
                        started_at=edata.get("started_at", time.time()),
                        completed_at=edata.get("completed_at"),
                        duration_seconds=edata.get("duration_seconds", 0),
                        triggered_by=edata.get("triggered_by", ""),
                        results=edata.get("results", []),
                        error_message=edata.get("error_message", ""),
                        tags=edata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载执行记录失败: {e}")

        # 加载封禁IP和禁用账号
        blocked_file = os.path.join(self.data_dir, "blocked_ips.json")
        if os.path.exists(blocked_file):
            try:
                with open(blocked_file, 'r', encoding='utf-8') as f:
                    self.blocked_ips = set(json.load(f))
            except:
                pass

        disabled_file = os.path.join(self.data_dir, "disabled_accounts.json")
        if os.path.exists(disabled_file):
            try:
                with open(disabled_file, 'r', encoding='utf-8') as f:
                    self.disabled_accounts = set(json.load(f))
            except:
                pass

    def _save_data(self):
        """保存数据到文件"""
        # 保存动作
        actions_file = os.path.join(self.data_dir, "actions.json")
        try:
            data = {aid: a.to_dict() for aid, a in self.actions.items()}
            with open(actions_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存动作失败: {e}")

        # 保存剧本
        playbooks_file = os.path.join(self.data_dir, "playbooks.json")
        try:
            data = {pid: p.to_dict() for pid, p in self.playbooks.items()}
            with open(playbooks_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存剧本失败: {e}")

        # 保存执行记录（只保存最近1000条）
        executions_file = os.path.join(self.data_dir, "executions.json")
        try:
            sorted_execs = sorted(self.executions.values(), key=lambda x: x.started_at, reverse=True)[:1000]
            data = {e.execution_id: e.to_dict() for e in sorted_execs}
            with open(executions_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存执行记录失败: {e}")

        # 保存封禁IP
        blocked_file = os.path.join(self.data_dir, "blocked_ips.json")
        try:
            with open(blocked_file, 'w', encoding='utf-8') as f:
                json.dump(list(self.blocked_ips), f)
        except:
            pass

        # 保存禁用账号
        disabled_file = os.path.join(self.data_dir, "disabled_accounts.json")
        try:
            with open(disabled_file, 'w', encoding='utf-8') as f:
                json.dump(list(self.disabled_accounts), f)
        except:
            pass

    def _init_default_actions(self):
        """初始化默认响应动作"""
        if self.actions:
            return

        default_actions = [
            {
                "action_type": "ip_block",
                "name": "封禁IP地址",
                "description": "在防火墙/安全设备上封禁指定IP地址",
                "parameters": {"ip": "", "duration": 3600, "reason": ""},
                "timeout": 60,
                "require_approval": False
            },
            {
                "action_type": "ip_unblock",
                "name": "解封IP地址",
                "description": "解除对指定IP地址的封禁",
                "parameters": {"ip": "", "reason": ""},
                "timeout": 60,
                "require_approval": False
            },
            {
                "action_type": "account_disable",
                "name": "禁用用户账号",
                "description": "禁用指定用户账号，禁止登录",
                "parameters": {"username": "", "reason": ""},
                "timeout": 60,
                "require_approval": True
            },
            {
                "action_type": "account_lock",
                "name": "锁定用户账号",
                "description": "临时锁定用户账号，需要解锁才能登录",
                "parameters": {"username": "", "duration": 1800, "reason": ""},
                "timeout": 60,
                "require_approval": False
            },
            {
                "action_type": "password_reset",
                "name": "重置用户密码",
                "description": "强制重置指定用户的密码",
                "parameters": {"username": "", "reason": ""},
                "timeout": 60,
                "require_approval": True
            },
            {
                "action_type": "process_terminate",
                "name": "终止恶意进程",
                "description": "终止指定主机上的恶意进程",
                "parameters": {"hostname": "", "pid": "", "process_name": "", "reason": ""},
                "timeout": 120,
                "require_approval": True
            },
            {
                "action_type": "file_quarantine",
                "name": "隔离恶意文件",
                "description": "将恶意文件移动到隔离区",
                "parameters": {"hostname": "", "file_path": "", "reason": ""},
                "timeout": 120,
                "require_approval": True
            },
            {
                "action_type": "host_isolate",
                "name": "隔离受感染主机",
                "description": "将受感染主机从网络中隔离",
                "parameters": {"hostname": "", "ip": "", "reason": ""},
                "timeout": 120,
                "require_approval": True
            },
            {
                "action_type": "alert_escalate",
                "name": "升级告警",
                "description": "将告警升级到更高优先级，通知高级安全人员",
                "parameters": {"alert_id": "", "new_severity": "critical", "reason": ""},
                "timeout": 30,
                "require_approval": False
            },
            {
                "action_type": "ticket_create",
                "name": "创建工单",
                "description": "在工单系统中创建安全事件工单",
                "parameters": {"title": "", "description": "", "priority": "high", "assignee": ""},
                "timeout": 30,
                "require_approval": False
            },
            {
                "action_type": "notification_send",
                "name": "发送通知",
                "description": "发送安全事件通知（邮件/短信/即时消息）",
                "parameters": {"channel": "email", "recipient": "", "subject": "", "message": ""},
                "timeout": 30,
                "require_approval": False
            },
            {
                "action_type": "evidence_collect",
                "name": "收集证据",
                "description": "收集安全事件相关的证据（日志/文件/内存镜像）",
                "parameters": {"hostname": "", "evidence_type": "logs", "duration": 3600},
                "timeout": 300,
                "require_approval": False
            },
            {
                "action_type": "scan_trigger",
                "name": "触发漏洞扫描",
                "description": "对指定目标触发漏洞扫描",
                "parameters": {"target": "", "scan_type": "full", "reason": ""},
                "timeout": 600,
                "require_approval": False
            },
        ]

        for action_data in default_actions:
            action_id = f"act-{uuid.uuid4().hex[:8]}"
            action = ResponseAction(
                action_id=action_id,
                action_type=action_data["action_type"],
                name=action_data["name"],
                description=action_data["description"],
                parameters=action_data["parameters"],
                timeout=action_data["timeout"],
                require_approval=action_data["require_approval"]
            )
            self.actions[action_id] = action

        self._save_data()
        log.info(f"初始化 {len(default_actions)} 个默认响应动作")

    def _init_default_playbooks(self):
        """初始化默认响应剧本"""
        if self.playbooks:
            return

        default_playbooks = [
            {
                "name": "暴力破解自动响应",
                "description": "检测到暴力破解攻击时，自动封禁攻击IP并锁定目标账号",
                "severity": "high",
                "category": "auth",
                "trigger_condition": {"rule_name": "暴力破解检测", "category": "auth"},
                "steps": [
                    {"step": 1, "action_type": "ip_block", "name": "封禁攻击IP", "parameters": {"ip": "{{source_ip}}", "duration": 86400, "reason": "暴力破解攻击"}},
                    {"step": 2, "action_type": "account_lock", "name": "锁定目标账号", "parameters": {"username": "{{username}}", "duration": 1800, "reason": "暴力破解目标"}},
                    {"step": 3, "action_type": "notification_send", "name": "发送通知", "parameters": {"channel": "email", "recipient": "security@company.com", "subject": "暴力破解攻击已自动响应", "message": "检测到来自{{source_ip}}的暴力破解攻击，已自动封禁IP并锁定账号{{username}}"}},
                    {"step": 4, "action_type": "ticket_create", "name": "创建工单", "parameters": {"title": "暴力破解攻击事件", "description": "检测到来自{{source_ip}}的暴力破解攻击，已自动封禁IP并锁定账号{{username}}", "priority": "high"}}
                ]
            },
            {
                "name": "Web攻击自动响应",
                "description": "检测到Web攻击（SQL注入/XSS等）时，自动封禁攻击IP",
                "severity": "high",
                "category": "web",
                "trigger_condition": {"rule_name": "Web攻击检测", "category": "web"},
                "steps": [
                    {"step": 1, "action_type": "ip_block", "name": "封禁攻击IP", "parameters": {"ip": "{{source_ip}}", "duration": 43200, "reason": "Web攻击"}},
                    {"step": 2, "action_type": "evidence_collect", "name": "收集Web日志", "parameters": {"hostname": "web-server", "evidence_type": "logs", "duration": 3600}},
                    {"step": 3, "action_type": "notification_send", "name": "发送通知", "parameters": {"channel": "email", "recipient": "security@company.com", "subject": "Web攻击已自动响应", "message": "检测到来自{{source_ip}}的Web攻击，已自动封禁IP"}}
                ]
            },
            {
                "name": "可疑进程自动响应",
                "description": "检测到可疑进程时，自动收集证据并通知安全人员",
                "severity": "critical",
                "category": "process",
                "trigger_condition": {"rule_name": "可疑进程启动", "category": "process"},
                "steps": [
                    {"step": 1, "action_type": "evidence_collect", "name": "收集进程证据", "parameters": {"hostname": "{{hostname}}", "evidence_type": "process", "duration": 600}},
                    {"step": 2, "action_type": "alert_escalate", "name": "升级告警", "parameters": {"new_severity": "critical", "reason": "检测到可疑进程，可能是入侵"}},
                    {"step": 3, "action_type": "notification_send", "name": "紧急通知", "parameters": {"channel": "sms", "recipient": "oncall-security", "subject": "紧急：检测到可疑进程", "message": "主机{{hostname}}上检测到可疑进程，请立即处理"}},
                    {"step": 4, "action_type": "ticket_create", "name": "创建紧急工单", "parameters": {"title": "可疑进程事件-需要人工处理", "description": "主机{{hostname}}上检测到可疑进程，已收集证据，需要安全人员人工确认是否终止进程或隔离主机", "priority": "critical"}}
                ]
            },
            {
                "name": "异常数据外发自动响应",
                "description": "检测到异常数据外发时，自动隔离主机并通知安全人员",
                "severity": "critical",
                "category": "network",
                "trigger_condition": {"rule_name": "异常数据外发", "category": "network"},
                "steps": [
                    {"step": 1, "action_type": "host_isolate", "name": "隔离主机", "parameters": {"hostname": "{{hostname}}", "ip": "{{source_ip}}", "reason": "异常数据外发，可能是数据泄露"}},
                    {"step": 2, "action_type": "evidence_collect", "name": "收集网络证据", "parameters": {"hostname": "{{hostname}}", "evidence_type": "network", "duration": 1800}},
                    {"step": 3, "action_type": "alert_escalate", "name": "升级告警", "parameters": {"new_severity": "critical", "reason": "异常数据外发，可能是数据泄露"}},
                    {"step": 4, "action_type": "notification_send", "name": "紧急通知", "parameters": {"channel": "sms", "recipient": "oncall-security", "subject": "紧急：异常数据外发", "message": "主机{{hostname}}检测到异常数据外发，已自动隔离，请立即处理"}}
                ]
            },
            {
                "name": "端口扫描自动响应",
                "description": "检测到端口扫描时，自动封禁攻击IP",
                "severity": "medium",
                "category": "network",
                "trigger_condition": {"rule_name": "端口扫描检测", "category": "network"},
                "steps": [
                    {"step": 1, "action_type": "ip_block", "name": "封禁扫描IP", "parameters": {"ip": "{{source_ip}}", "duration": 7200, "reason": "端口扫描"}},
                    {"step": 2, "action_type": "notification_send", "name": "发送通知", "parameters": {"channel": "email", "recipient": "security@company.com", "subject": "端口扫描已自动响应", "message": "检测到来自{{source_ip}}的端口扫描，已自动封禁IP 2小时"}}
                ]
            },
            {
                "name": "钓鱼邮件自动响应",
                "description": "检测到钓鱼邮件时，自动禁用发件人并通知收件人",
                "severity": "high",
                "category": "phishing",
                "trigger_condition": {"category": "phishing"},
                "steps": [
                    {"step": 1, "action_type": "account_disable", "name": "禁用发件人账号", "parameters": {"username": "{{username}}", "reason": "发送钓鱼邮件"}},
                    {"step": 2, "action_type": "notification_send", "name": "通知收件人", "parameters": {"channel": "email", "recipient": "{{recipient}}", "subject": "安全提醒：您收到的邮件可能是钓鱼邮件", "message": "您收到的来自{{username}}的邮件被检测为钓鱼邮件，发件人账号已被禁用，请不要点击邮件中的任何链接或附件"}},
                    {"step": 3, "action_type": "ticket_create", "name": "创建工单", "parameters": {"title": "钓鱼邮件事件", "description": "检测到来自{{username}}的钓鱼邮件，已禁用发件人账号并通知收件人", "priority": "high"}}
                ]
            },
        ]

        for playbook_data in default_playbooks:
            playbook_id = f"pb-{uuid.uuid4().hex[:8]}"
            playbook = ResponsePlaybook(
                playbook_id=playbook_id,
                name=playbook_data["name"],
                description=playbook_data["description"],
                severity=playbook_data["severity"],
                category=playbook_data["category"],
                trigger_condition=playbook_data["trigger_condition"],
                steps=playbook_data["steps"]
            )
            self.playbooks[playbook_id] = playbook

        self._save_data()
        log.info(f"初始化 {len(default_playbooks)} 个默认响应剧本")

    # ===== 动作执行 =====
    def execute_action(self, action_type: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """执行单个响应动作"""
        parameters = parameters or {}
        action_id = f"exec-{uuid.uuid4().hex[:8]}"
        start_time = time.time()

        log.info(f"执行动作: {action_type}")

        result = {
            "action_id": action_id,
            "action_type": action_type,
            "status": "success",
            "started_at": start_time,
            "completed_at": None,
            "duration_seconds": 0,
            "result": {},
            "error": ""
        }

        try:
            if action_type == "ip_block":
                ip = parameters.get("ip", "")
                duration = parameters.get("duration", 3600)
                reason = parameters.get("reason", "")
                if ip:
                    self.blocked_ips.add(ip)
                    result["result"] = {
                        "ip": ip,
                        "blocked": True,
                        "duration_seconds": duration,
                        "reason": reason,
                        "message": f"IP {ip} 已被封禁 {duration} 秒，原因: {reason}"
                    }
                    log.warning(f"封禁IP: {ip}，原因: {reason}")
                else:
                    result["status"] = "failed"
                    result["error"] = "未指定IP地址"

            elif action_type == "ip_unblock":
                ip = parameters.get("ip", "")
                if ip and ip in self.blocked_ips:
                    self.blocked_ips.remove(ip)
                    result["result"] = {"ip": ip, "unblocked": True, "message": f"IP {ip} 已解封"}
                else:
                    result["result"] = {"ip": ip, "unblocked": False, "message": f"IP {ip} 不在封禁列表中"}

            elif action_type == "account_disable":
                username = parameters.get("username", "")
                reason = parameters.get("reason", "")
                if username:
                    self.disabled_accounts.add(username)
                    result["result"] = {
                        "username": username,
                        "disabled": True,
                        "reason": reason,
                        "message": f"账号 {username} 已被禁用，原因: {reason}"
                    }
                    log.warning(f"禁用账号: {username}，原因: {reason}")
                else:
                    result["status"] = "failed"
                    result["error"] = "未指定用户名"

            elif action_type == "account_lock":
                username = parameters.get("username", "")
                duration = parameters.get("duration", 1800)
                if username:
                    self.disabled_accounts.add(username)
                    result["result"] = {
                        "username": username,
                        "locked": True,
                        "duration_seconds": duration,
                        "message": f"账号 {username} 已被锁定 {duration} 秒"
                    }
                else:
                    result["status"] = "failed"
                    result["error"] = "未指定用户名"

            elif action_type == "account_enable":
                username = parameters.get("username", "")
                if username and username in self.disabled_accounts:
                    self.disabled_accounts.remove(username)
                    result["result"] = {"username": username, "enabled": True, "message": f"账号 {username} 已启用"}
                else:
                    result["result"] = {"username": username, "enabled": False, "message": f"账号 {username} 不在禁用列表中"}

            elif action_type == "password_reset":
                username = parameters.get("username", "")
                if username:
                    result["result"] = {
                        "username": username,
                        "password_reset": True,
                        "temporary_password": f"Temp@{uuid.uuid4().hex[:8]}",
                        "message": f"账号 {username} 的密码已重置，临时密码已生成"
                    }
                else:
                    result["status"] = "failed"
                    result["error"] = "未指定用户名"

            elif action_type == "process_terminate":
                hostname = parameters.get("hostname", "")
                pid = parameters.get("pid", "")
                process_name = parameters.get("process_name", "")
                result["result"] = {
                    "hostname": hostname,
                    "pid": pid,
                    "process_name": process_name,
                    "terminated": True,
                    "message": f"主机 {hostname} 上的进程 {process_name} (PID: {pid}) 已终止"
                }
                log.warning(f"终止进程: {process_name} (PID: {pid}) on {hostname}")

            elif action_type == "file_quarantine":
                hostname = parameters.get("hostname", "")
                file_path = parameters.get("file_path", "")
                result["result"] = {
                    "hostname": hostname,
                    "file_path": file_path,
                    "quarantined": True,
                    "quarantine_path": f"/quarantine/{uuid.uuid4().hex[:8]}",
                    "message": f"文件 {file_path} 已从主机 {hostname} 隔离"
                }

            elif action_type == "host_isolate":
                hostname = parameters.get("hostname", "")
                ip = parameters.get("ip", "")
                result["result"] = {
                    "hostname": hostname,
                    "ip": ip,
                    "isolated": True,
                    "message": f"主机 {hostname} ({ip}) 已从网络中隔离"
                }
                log.warning(f"隔离主机: {hostname} ({ip})")

            elif action_type == "host_unisolate":
                hostname = parameters.get("hostname", "")
                result["result"] = {
                    "hostname": hostname,
                    "unisolated": True,
                    "message": f"主机 {hostname} 已恢复网络连接"
                }

            elif action_type == "alert_escalate":
                alert_id = parameters.get("alert_id", "")
                new_severity = parameters.get("new_severity", "critical")
                result["result"] = {
                    "alert_id": alert_id,
                    "escalated": True,
                    "new_severity": new_severity,
                    "message": f"告警 {alert_id} 已升级为 {new_severity}"
                }

            elif action_type == "ticket_create":
                title = parameters.get("title", "安全事件")
                description = parameters.get("description", "")
                priority = parameters.get("priority", "high")
                ticket_id = f"TICKET-{uuid.uuid4().hex[:8].upper()}"
                result["result"] = {
                    "ticket_id": ticket_id,
                    "title": title,
                    "description": description,
                    "priority": priority,
                    "status": "open",
                    "created_at": time.time(),
                    "message": f"工单 {ticket_id} 已创建，优先级: {priority}"
                }

            elif action_type == "notification_send":
                channel = parameters.get("channel", "email")
                recipient = parameters.get("recipient", "")
                subject = parameters.get("subject", "")
                message = parameters.get("message", "")
                result["result"] = {
                    "channel": channel,
                    "recipient": recipient,
                    "subject": subject,
                    "message": message,
                    "sent": True,
                    "message_id": f"MSG-{uuid.uuid4().hex[:8]}",
                    "sent_at": time.time()
                }
                log.info(f"发送通知: {channel} -> {recipient}: {subject}")

            elif action_type == "evidence_collect":
                hostname = parameters.get("hostname", "")
                evidence_type = parameters.get("evidence_type", "logs")
                duration = parameters.get("duration", 3600)
                evidence_id = f"EVID-{uuid.uuid4().hex[:8]}"
                result["result"] = {
                    "evidence_id": evidence_id,
                    "hostname": hostname,
                    "evidence_type": evidence_type,
                    "duration_seconds": duration,
                    "collected": True,
                    "storage_path": f"/evidence/{evidence_id}",
                    "size_bytes": 1024000,  # 模拟1MB
                    "message": f"已从主机 {hostname} 收集 {evidence_type} 证据，保存到 /evidence/{evidence_id}"
                }

            elif action_type == "scan_trigger":
                target = parameters.get("target", "")
                scan_type = parameters.get("scan_type", "full")
                scan_id = f"SCAN-{uuid.uuid4().hex[:8]}"
                result["result"] = {
                    "scan_id": scan_id,
                    "target": target,
                    "scan_type": scan_type,
                    "status": "running",
                    "started_at": time.time(),
                    "message": f"已触发对 {target} 的 {scan_type} 扫描，扫描ID: {scan_id}"
                }

            elif action_type == "custom_script":
                script = parameters.get("script", "")
                result["result"] = {
                    "script_executed": True,
                    "output": "Custom script executed successfully",
                    "exit_code": 0
                }

            else:
                result["status"] = "failed"
                result["error"] = f"不支持的动作类型: {action_type}"

        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
            log.error(f"动作执行失败: {action_type}, 错误: {e}")

        result["completed_at"] = time.time()
        result["duration_seconds"] = round(result["completed_at"] - start_time, 2)

        # 更新动作统计
        for action in self.actions.values():
            if action.action_type == action_type:
                action.execution_count += 1
                if result["status"] == "success":
                    action.success_count += 1
                else:
                    action.failure_count += 1
                break

        self._save_data()
        return result

    # ===== 剧本执行 =====
    def execute_playbook(self, playbook_id: str, context: Dict[str, Any] = None,
                          alert_id: str = "", triggered_by: str = "manual") -> Dict[str, Any]:
        """执行响应剧本"""
        playbook = self.playbooks.get(playbook_id)
        if not playbook:
            return {"error": f"剧本不存在: {playbook_id}"}

        context = context or {}
        execution_id = f"exec-{uuid.uuid4().hex[:8]}"
        start_time = time.time()

        execution = ExecutionRecord(
            execution_id=execution_id,
            playbook_id=playbook_id,
            playbook_name=playbook.name,
            alert_id=alert_id,
            trigger_type=triggered_by,
            status="running",
            steps_total=len(playbook.steps),
            triggered_by=triggered_by
        )

        log.info(f"执行剧本: {playbook.name} ({playbook_id})")

        step_results = []
        needs_approval = False

        for step in playbook.steps:
            step_num = step.get("step", 0)
            action_type = step.get("action_type", "")
            step_name = step.get("name", "")
            step_params = step.get("parameters", {})

            # 替换模板变量
            resolved_params = self._resolve_template(step_params, context)

            # 检查是否需要审批
            action_def = next((a for a in self.actions.values() if a.action_type == action_type), None)
            if action_def and action_def.require_approval:
                execution.status = "needs_approval"
                needs_approval = True
                step_results.append({
                    "step": step_num,
                    "action_type": action_type,
                    "name": step_name,
                    "status": "needs_approval",
                    "message": f"动作 {step_name} 需要人工审批",
                    "parameters": resolved_params
                })
                log.warning(f"剧本执行需要审批: {step_name}")
                break

            # 执行动作
            execution.steps_executed += 1
            action_result = self.execute_action(action_type, resolved_params)

            if action_result["status"] == "success":
                execution.steps_success += 1
            else:
                execution.steps_failed += 1

            step_results.append({
                "step": step_num,
                "action_type": action_type,
                "name": step_name,
                "status": action_result["status"],
                "result": action_result.get("result", {}),
                "error": action_result.get("error", ""),
                "duration_seconds": action_result.get("duration_seconds", 0)
            })

        # 更新执行状态
        if not needs_approval:
            if execution.steps_failed == 0:
                execution.status = "success"
            elif execution.steps_success > 0:
                execution.status = "partial"
            else:
                execution.status = "failed"

        execution.results = step_results
        execution.completed_at = time.time()
        execution.duration_seconds = execution.completed_at - start_time

        self.executions[execution_id] = execution

        # 更新剧本统计
        playbook.execution_count += 1
        if execution.status == "success":
            playbook.success_count += 1

        self._save_data()

        return {
            "execution_id": execution_id,
            "playbook_id": playbook_id,
            "playbook_name": playbook.name,
            "status": execution.status,
            "steps_total": execution.steps_total,
            "steps_executed": execution.steps_executed,
            "steps_success": execution.steps_success,
            "steps_failed": execution.steps_failed,
            "duration_seconds": round(execution.duration_seconds, 2),
            "needs_approval": needs_approval,
            "step_results": step_results
        }

    def _resolve_template(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """解析模板变量"""
        resolved = {}
        for key, value in params.items():
            if isinstance(value, str):
                # 替换 {{variable}} 格式
                for var_name, var_value in context.items():
                    value = value.replace(f"{{{{{var_name}}}}}", str(var_value))
                resolved[key] = value
            elif isinstance(value, dict):
                resolved[key] = self._resolve_template(value, context)
            else:
                resolved[key] = value
        return resolved

    def approve_and_continue(self, execution_id: str) -> Dict[str, Any]:
        """审批并继续执行需要审批的剧本"""
        execution = self.executions.get(execution_id)
        if not execution or execution.status != "needs_approval":
            return {"error": "执行记录不存在或不需要审批"}

        playbook = self.playbooks.get(execution.playbook_id)
        if not playbook:
            return {"error": "剧本不存在"}

        # 找到需要审批的步骤，继续执行
        current_step = execution.steps_executed
        context = {}  # 从执行结果中提取上下文

        for step in playbook.steps[current_step:]:
            step_num = step.get("step", 0)
            action_type = step.get("action_type", "")
            step_name = step.get("name", "")
            step_params = step.get("parameters", {})

            execution.steps_executed += 1
            action_result = self.execute_action(action_type, step_params)

            if action_result["status"] == "success":
                execution.steps_success += 1
            else:
                execution.steps_failed += 1

            execution.results.append({
                "step": step_num,
                "action_type": action_type,
                "name": step_name,
                "status": action_result["status"],
                "result": action_result.get("result", {}),
                "error": action_result.get("error", "")
            })

        # 更新状态
        if execution.steps_failed == 0:
            execution.status = "success"
        elif execution.steps_success > 0:
            execution.status = "partial"
        else:
            execution.status = "failed"

        execution.completed_at = time.time()
        execution.duration_seconds = execution.completed_at - execution.started_at

        self._save_data()

        return {
            "execution_id": execution_id,
            "status": execution.status,
            "steps_total": execution.steps_total,
            "steps_success": execution.steps_success,
            "steps_failed": execution.steps_failed,
            "message": "审批通过，剧本执行完成"
        }

    # ===== 告警自动触发 =====
    def process_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """处理告警，自动触发匹配的剧本"""
        triggered_playbooks = []

        for playbook in self.playbooks.values():
            if playbook.status != "active":
                continue

            # 检查触发条件
            trigger = playbook.trigger_condition
            match = True

            if "rule_name" in trigger and alert.get("rule_name") != trigger["rule_name"]:
                match = False
            if "category" in trigger and alert.get("category") != trigger["category"]:
                match = False
            if "severity" in trigger and alert.get("severity") != trigger["severity"]:
                match = False

            if match:
                # 执行剧本
                context = {
                    "source_ip": alert.get("source_ip", ""),
                    "username": alert.get("username", ""),
                    "hostname": alert.get("hostname", ""),
                    "alert_id": alert.get("alert_id", "")
                }
                result = self.execute_playbook(
                    playbook.playbook_id,
                    context=context,
                    alert_id=alert.get("alert_id", ""),
                    triggered_by="alert"
                )
                triggered_playbooks.append(result)
                log.info(f"告警自动触发剧本: {playbook.name}")

        return {
            "alert_id": alert.get("alert_id", ""),
            "triggered_playbooks_count": len(triggered_playbooks),
            "triggered_playbooks": triggered_playbooks
        }

    # ===== 查询和统计 =====
    def get_playbooks(self, status: str = None, category: str = None,
                      severity: str = None) -> List[Dict[str, Any]]:
        """获取剧本列表"""
        results = []
        for playbook in self.playbooks.values():
            if status and playbook.status != status:
                continue
            if category and playbook.category != category:
                continue
            if severity and playbook.severity != severity:
                continue
            results.append(playbook.to_dict())
        return results

    def get_executions(self, status: str = None, playbook_id: str = None,
                       limit: int = 100) -> List[Dict[str, Any]]:
        """获取执行记录"""
        results = []
        for execution in self.executions.values():
            if status and execution.status != status:
                continue
            if playbook_id and execution.playbook_id != playbook_id:
                continue
            results.append(execution.to_dict())
        results.sort(key=lambda x: x["started_at"], reverse=True)
        return results[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total_actions = len(self.actions)
        enabled_actions = sum(1 for a in self.actions.values() if a.enabled)
        total_playbooks = len(self.playbooks)
        active_playbooks = sum(1 for p in self.playbooks.values() if p.status == "active")
        total_executions = len(self.executions)
        success_executions = sum(1 for e in self.executions.values() if e.status == "success")
        failed_executions = sum(1 for e in self.executions.values() if e.status == "failed")
        needs_approval = sum(1 for e in self.executions.values() if e.status == "needs_approval")

        # 动作执行统计
        action_stats = {}
        for action in self.actions.values():
            action_stats[action.action_type] = {
                "name": action.name,
                "execution_count": action.execution_count,
                "success_count": action.success_count,
                "failure_count": action.failure_count,
                "success_rate": round(action.success_count / action.execution_count * 100, 2) if action.execution_count > 0 else 0
            }

        return {
            "total_actions": total_actions,
            "enabled_actions": enabled_actions,
            "total_playbooks": total_playbooks,
            "active_playbooks": active_playbooks,
            "total_executions": total_executions,
            "success_executions": success_executions,
            "failed_executions": failed_executions,
            "needs_approval": needs_approval,
            "success_rate": round(success_executions / total_executions * 100, 2) if total_executions > 0 else 0,
            "blocked_ips_count": len(self.blocked_ips),
            "disabled_accounts_count": len(self.disabled_accounts),
            "action_stats": action_stats
        }

    def get_blocked_ips(self) -> List[str]:
        """获取封禁IP列表"""
        return list(self.blocked_ips)

    def get_disabled_accounts(self) -> List[str]:
        """获取禁用账号列表"""
        return list(self.disabled_accounts)


# 全局实例
soar = SOAREngine()
