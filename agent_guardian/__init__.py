#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent审批守卫（Agent Guardian / Jev模型）

对标CyberStrikeAI Jev模型：给Agent每一步操作加一层快速审批。
基于当前状态、候选动作、规则约束和风险信息，快速返回允许、确认、复核或拒绝。

设计参考：
- SingGuard-NSFA：开源guardrail，验证Agent传入指令和传出动作
- LlamaFirewall：AlignmentCheck评估器 + PromptGuard预扫描
- GuardClaw：LLM驱动judge分析命令意图和风险，多步攻击模式检测
- Aurora SRE Guardrails：7层防护，独立judge模型200-500ms
- IBM Granite Guardian：判断模型输入输出是否符合标准
"""

import re
import json
import time
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import os


class ApprovalDecision(Enum):
    """审批决策"""
    ALLOW = "allow"           # 直接允许（低风险）
    CONFIRM = "confirm"       # 需要确认（中风险）
    REVIEW = "review"         # 需要复核（高风险）
    DENY = "deny"             # 直接拒绝（危险操作）


class RiskLevel(Enum):
    """风险等级"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AgentAction:
    """Agent动作"""
    action_id: str
    action_type: str  # shell_exec/http_request/file_write/file_read/browser/tool_call/api_call
    description: str
    target: str = ""
    payload: str = ""
    parameters: Dict = field(default_factory=dict)
    timestamp: float = 0
    agent_name: str = ""


@dataclass
class ApprovalResult:
    """审批结果"""
    decision: ApprovalDecision
    risk_level: RiskLevel
    risk_score: float  # 0-100
    reason: str
    matched_rules: List[str] = field(default_factory=list)
    suggested_action: str = ""
    requires_human: bool = False
    audit_trail_id: str = ""


@dataclass
class AuditLog:
    """审计日志"""
    log_id: str
    timestamp: float
    agent_name: str
    action: AgentAction
    decision: ApprovalDecision
    risk_level: RiskLevel
    risk_score: float
    reason: str
    context: Dict = field(default_factory=dict)


class RuleEngine:
    """
    规则引擎

    基于规则的风险检测，包含：
    - 危险命令模式
    - 敏感文件访问
    - 网络渗出检测
    - 权限提升检测
    - 多步攻击模式检测
    """

    # 危险命令模式
    DANGEROUS_COMMANDS = [
        (r'\b(rm|del|erase)\s+(-rf?|/[sfq])?\s+(/|\*|~|C:\\)', "递归删除系统文件", "critical"),
        (r'\b(mkfs|format|diskpart)\b', "格式化磁盘", "critical"),
        (r'\b(dd)\s+if=.*of=/dev/(sd|hd)', "磁盘覆写", "critical"),
        (r'\b(chmod)\s+777\s+/', "全局权限修改", "high"),
        (r'\b(chown)\s+.*:\w+\s+/etc', "修改系统文件属主", "high"),
        (r'\b(curl|wget|Invoke-WebRequest)\b.*\|\s*(bash|sh|zsh|cmd|powershell)', "远程命令执行", "critical"),
        (r'\b(python|perl|ruby|node)\b.*-c.*(import os|exec|eval|system)', "代码执行", "high"),
        (r'\b(nc|netcat|ncat)\b.*-e', "反向Shell", "critical"),
        (r'\b(bash|sh|zsh)\s+-i\s+>&\s+/dev/tcp/', "反向Shell", "critical"),
        (r'\b(sudo|su|runas)\b', "权限提升", "medium"),
        (r'\b(ssh|telnet)\b.*@', "远程登录", "medium"),
        (r'\b(scp|rsync)\b.*@.*:', "文件传输", "low"),
    ]

    # 敏感文件模式
    SENSITIVE_FILES = [
        (r'/etc/(passwd|shadow|sudoers)', "系统认证文件", "high"),
        (r'/etc/(ssh|ssl)/', "SSH/SSL配置", "high"),
        (r'~/.ssh/(id_rsa|id_ed25519|authorized_keys)', "SSH私钥", "critical"),
        (r'~/.aws/(credentials|config)', "AWS凭证", "critical"),
        (r'~/.kube/config', "Kubernetes配置", "high"),
        (r'~/.docker/config.json', "Docker配置", "medium"),
        (r'\.env$', "环境变量文件", "high"),
        (r'(password|secret|key|token)\.(txt|json|yml|yaml)', "凭证文件", "high"),
        (r'C:\\Windows\\System32\\config\\', "Windows系统配置", "high"),
    ]

    # 数据渗出模式
    DATA_EXFILTRATION = [
        (r'(curl|wget|Invoke-WebRequest).*(http|https)://.*\?(data|file|content)=', "HTTP数据渗出", "high"),
        (r'(base64|xxd|openssl enc).*\|.*(curl|nc|ssh)', "编码后数据渗出", "high"),
        (r'(tar|zip|7z).*\|\s*(curl|nc|ssh)', "压缩后数据渗出", "medium"),
        (r'(scp|rsync).*@(?!localhost|127\.0\.0\.1)', "外部文件传输", "medium"),
    ]

    # 内网探测模式
    INTERNAL_PROBE = [
        (r'(nmap|masscan|zmap)\b.*(10\.|172\.1[6-9]\.|192\.168\.)', "内网端口扫描", "high"),
        (r'(ping|fping).*(10\.|172\.1[6-9]\.|192\.168\.)', "内网主机探测", "medium"),
        (r'(arp|netstat|ip addr|ifconfig)', "网络信息收集", "low"),
    ]

    def __init__(self):
        self.all_rules = []
        self._compile_rules()

    def _compile_rules(self):
        """编译所有规则"""
        for pattern, desc, severity in self.DANGEROUS_COMMANDS:
            self.all_rules.append({
                "category": "dangerous_command",
                "pattern": re.compile(pattern, re.IGNORECASE),
                "description": desc,
                "severity": severity,
            })
        for pattern, desc, severity in self.SENSITIVE_FILES:
            self.all_rules.append({
                "category": "sensitive_file",
                "pattern": re.compile(pattern, re.IGNORECASE),
                "description": desc,
                "severity": severity,
            })
        for pattern, desc, severity in self.DATA_EXFILTRATION:
            self.all_rules.append({
                "category": "data_exfiltration",
                "pattern": re.compile(pattern, re.IGNORECASE),
                "description": desc,
                "severity": severity,
            })
        for pattern, desc, severity in self.INTERNAL_PROBE:
            self.all_rules.append({
                "category": "internal_probe",
                "pattern": re.compile(pattern, re.IGNORECASE),
                "description": desc,
                "severity": severity,
            })

    def evaluate(self, action: AgentAction) -> Tuple[float, List[Dict]]:
        """
        评估动作风险

        Returns:
            (risk_score, matched_rules)
        """
        risk_score = 0
        matched = []

        # 组合所有文本进行匹配
        text = f"{action.description} {action.target} {action.payload} {json.dumps(action.parameters)}"

        for rule in self.all_rules:
            if rule["pattern"].search(text):
                matched.append({
                    "category": rule["category"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                })
                severity_weights = {"critical": 40, "high": 25, "medium": 15, "low": 8}
                risk_score += severity_weights.get(rule["severity"], 8)

        # 动作类型基础风险
        type_risks = {
            "shell_exec": 15,
            "file_write": 10,
            "file_read": 5,
            "http_request": 5,
            "browser": 3,
            "tool_call": 3,
            "api_call": 5,
        }
        risk_score += type_risks.get(action.action_type, 3)

        return min(100, risk_score), matched


class AIGuardian:
    """
    AI守卫（模拟Jev模型）

    基于AI的动作意图分析和风险评估。
    对标CyberStrikeAI Jev模型：基于当前状态、候选动作、规则约束和风险信息，快速返回决策。
    """

    def __init__(self):
        self.context_window: List[Dict] = []  # 最近动作上下文
        self.max_context = 20

    def analyze_intent(self, action: AgentAction, context: Dict = None) -> Dict[str, Any]:
        """
        分析动作意图

        Returns:
            {
                "intent": "legitimate/suspicious/malicious",
                "purpose": "动作目的描述",
                "risk_factors": [...],
                "confidence": 0.0-1.0
            }
        """
        result = {
            "intent": "legitimate",
            "purpose": "",
            "risk_factors": [],
            "confidence": 0.7,
        }

        text = f"{action.action_type} {action.description} {action.target}".lower()

        # 意图分析规则
        malicious_keywords = ["exploit", "backdoor", "reverse shell", "persistence", "privilege esc",
                              "dump", "exfiltrate", "ransom", "encrypt", "wipe", "deface"]
        suspicious_keywords = ["scan", "enumerate", "brute", "fuzz", "inject", "bypass",
                               "crack", "decode", "decrypt"]

        for kw in malicious_keywords:
            if kw in text:
                result["intent"] = "malicious"
                result["risk_factors"].append(f"恶意关键词: {kw}")
                result["confidence"] = 0.9

        if result["intent"] == "legitimate":
            for kw in suspicious_keywords:
                if kw in text:
                    result["intent"] = "suspicious"
                    result["risk_factors"].append(f"可疑关键词: {kw}")
                    result["confidence"] = 0.6

        # 多步攻击模式检测
        attack_patterns = self._detect_attack_patterns(action)
        if attack_patterns:
            result["risk_factors"].extend(attack_patterns)
            result["intent"] = "malicious" if len(attack_patterns) >= 2 else "suspicious"

        # 更新上下文
        self.context_window.append({
            "action_id": action.action_id,
            "type": action.action_type,
            "target": action.target,
            "timestamp": action.timestamp,
            "intent": result["intent"],
        })
        if len(self.context_window) > self.max_context:
            self.context_window.pop(0)

        return result

    def _detect_attack_patterns(self, action: AgentAction) -> List[str]:
        """检测多步攻击模式"""
        patterns = []
        if len(self.context_window) < 2:
            return patterns

        recent = self.context_window[-5:]
        types = [a["type"] for a in recent]

        # 侦察→利用模式
        if "http_request" in types and action.action_type == "shell_exec":
            if any("scan" in a.get("target", "").lower() for a in recent):
                patterns.append("侦察后执行命令（可能的攻击链）")

        # 信息收集→数据渗出模式
        if "file_read" in types and action.action_type == "http_request":
            if any("passwd" in a.get("target", "").lower() or "shadow" in a.get("target", "").lower()
                   for a in recent):
                patterns.append("读取敏感文件后发起HTTP请求（可能的数据渗出）")

        # 权限提升模式
        if "shell_exec" in types and action.action_type == "shell_exec":
            if any("sudo" in a.get("target", "").lower() for a in recent):
                patterns.append("连续权限提升操作")

        return patterns


class AgentGuardian:
    """
    Agent审批守卫（主类）

    整合规则引擎 + AI守卫 + 审计日志，提供完整的动作审批流程。
    对标CyberStrikeAI Jev模型。
    """

    def __init__(self, audit_log_path: str = None):
        self.rule_engine = RuleEngine()
        self.ai_guardian = AIGuardian()
        self.audit_logs: List[AuditLog] = []
        self.audit_log_path = audit_log_path or os.path.join(
            os.path.dirname(__file__), "..", "guardian_audit.jsonl"
        )
        self.stats = {
            "total_actions": 0,
            "allowed": 0,
            "confirmed": 0,
            "reviewed": 0,
            "denied": 0,
        }

    def evaluate_action(self, action: AgentAction,
                        context: Dict = None,
                        auto_approve_low_risk: bool = True) -> ApprovalResult:
        """
        评估并审批Agent动作

        流程：
        1. 规则引擎检测（快速，<10ms）
        2. AI守卫意图分析（模拟，<50ms）
        3. 综合风险评分
        4. 决策：允许/确认/复核/拒绝
        5. 审计日志记录
        """
        action.timestamp = time.time()
        self.stats["total_actions"] += 1

        # 1. 规则引擎评估
        risk_score, matched_rules = self.rule_engine.evaluate(action)

        # 2. AI意图分析
        ai_result = self.ai_guardian.analyze_intent(action, context)

        # AI意图加权
        intent_weights = {"legitimate": 0, "suspicious": 15, "malicious": 35}
        risk_score += intent_weights.get(ai_result["intent"], 0)
        risk_score = min(100, risk_score)

        # 3. 确定风险等级
        if risk_score >= 60:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 40:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 25:
            risk_level = RiskLevel.MEDIUM
        elif risk_score >= 10:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.NONE

        # 4. 决策
        if risk_level == RiskLevel.CRITICAL:
            decision = ApprovalDecision.DENY
            reason = f"检测到危险操作，风险评分{risk_score}/100。"
            if matched_rules:
                reason += f" 匹配规则: {', '.join(r['description'] for r in matched_rules[:3])}"
            requires_human = True
        elif risk_level == RiskLevel.HIGH:
            decision = ApprovalDecision.REVIEW
            reason = f"高风险操作，需要人工复核。风险评分{risk_score}/100。"
            if ai_result["intent"] == "suspicious":
                reason += " AI分析为可疑意图。"
            requires_human = True
        elif risk_level == RiskLevel.MEDIUM:
            decision = ApprovalDecision.CONFIRM
            reason = f"中风险操作，需要确认。风险评分{risk_score}/100。"
            requires_human = False
        else:
            decision = ApprovalDecision.ALLOW
            reason = f"低风险操作，自动允许。风险评分{risk_score}/100。"
            requires_human = False

        # 低风险自动批准
        if auto_approve_low_risk and decision == ApprovalDecision.ALLOW:
            pass  # 已允许

        # 5. 生成审计日志
        audit_id = self._generate_audit_id(action)
        audit_log = AuditLog(
            log_id=audit_id,
            timestamp=action.timestamp,
            agent_name=action.agent_name,
            action=action,
            decision=decision,
            risk_level=risk_level,
            risk_score=risk_score,
            reason=reason,
            context=context or {},
        )
        self.audit_logs.append(audit_log)
        self._write_audit_log(audit_log)

        # 更新统计
        stat_key_map = {"allow": "allowed", "confirm": "confirmed", "review": "reviewed", "deny": "denied"}
        self.stats[stat_key_map.get(decision.value, decision.value)] += 1

        return ApprovalResult(
            decision=decision,
            risk_level=risk_level,
            risk_score=risk_score,
            reason=reason,
            matched_rules=[r["description"] for r in matched_rules],
            suggested_action=self._get_suggestion(action, decision),
            requires_human=requires_human,
            audit_trail_id=audit_id,
        )

    def batch_evaluate(self, actions: List[AgentAction],
                       context: Dict = None) -> List[ApprovalResult]:
        """批量评估动作"""
        return [self.evaluate_action(a, context) for a in actions]

    def get_stats(self) -> Dict[str, Any]:
        """获取守卫统计"""
        return {
            **self.stats,
            "audit_logs_count": len(self.audit_logs),
            "rules_count": len(self.rule_engine.all_rules),
            "context_window_size": len(self.ai_guardian.context_window),
        }

    def get_recent_logs(self, limit: int = 20) -> List[Dict]:
        """获取最近审计日志"""
        logs = []
        for log in self.audit_logs[-limit:]:
            logs.append({
                "log_id": log.log_id,
                "timestamp": log.timestamp,
                "agent": log.agent_name,
                "action_type": log.action.action_type,
                "action_desc": log.action.description[:100],
                "decision": log.decision.value,
                "risk_level": log.risk_level.value,
                "risk_score": log.risk_score,
                "reason": log.reason,
            })
        return logs

    def _generate_audit_id(self, action: AgentAction) -> str:
        """生成审计ID"""
        content = f"{action.action_id}{action.timestamp}{action.description}"
        return "audit_" + hashlib.md5(content.encode()).hexdigest()[:12]

    def _write_audit_log(self, log: AuditLog):
        """写入审计日志文件"""
        try:
            log_entry = {
                "log_id": log.log_id,
                "timestamp": log.timestamp,
                "agent_name": log.agent_name,
                "action": {
                    "id": log.action.action_id,
                    "type": log.action.action_type,
                    "description": log.action.description,
                    "target": log.action.target,
                },
                "decision": log.decision.value,
                "risk_level": log.risk_level.value,
                "risk_score": log.risk_score,
                "reason": log.reason,
            }
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        except Exception:
            pass  # 审计日志写入失败不影响主流程

    def _get_suggestion(self, action: AgentAction, decision: ApprovalDecision) -> str:
        """获取操作建议"""
        if decision == ApprovalDecision.DENY:
            return "此操作被拒绝。请检查操作是否必要，如确需执行请联系管理员授权。"
        elif decision == ApprovalDecision.REVIEW:
            return "此操作需要人工复核。请确认操作目的和范围后再执行。"
        elif decision == ApprovalDecision.CONFIRM:
            return "请确认此操作的目标和参数是否正确。"
        else:
            return "操作已自动批准，可安全执行。"


# 单例模式
_guardian_instance: Optional[AgentGuardian] = None

def get_agent_guardian() -> AgentGuardian:
    """获取全局Agent守卫实例"""
    global _guardian_instance
    if _guardian_instance is None:
        _guardian_instance = AgentGuardian()
    return _guardian_instance
