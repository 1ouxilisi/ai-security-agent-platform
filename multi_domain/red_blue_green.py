#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
红蓝绿三角色对抗架构（Red-Blue-Green Framework）

借鉴Microsoft Project Perception设计：
- Red Team（红队）: 探测弱点，模拟攻击者移动，发现漏洞
- Blue Team（蓝队）: 调查信号，分类真实威胁， triage告警
- Green Team（绿队）: 采取纠正措施，编写和部署修复，关闭缺口

实现红蓝对抗闭环评估：红队攻击 → 蓝队检测 → 绿队修复 → 重新评估。
"""

import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class TeamRole(Enum):
    """团队角色"""
    RED = "red"  # 红队 - 攻击者
    BLUE = "blue"  # 蓝队 - 防御者
    GREEN = "green"  # 绿队 - 修复者


class AttackPhase(Enum):
    """攻击阶段（MITRE ATT&CK）"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class RedTeamAction:
    """红队行动"""
    action_id: str
    phase: AttackPhase
    technique: str
    description: str
    target: str
    tools: List[str] = field(default_factory=list)
    success: bool = False
    evidence: List[Dict] = field(default_factory=list)
    duration: float = 0.0


@dataclass
class BlueTeamAlert:
    """蓝队告警"""
    alert_id: str
    severity: str  # critical/high/medium/low/info
    title: str
    description: str
    source: str
    related_attack: Optional[str] = None  # 关联的红队行动ID
    detected: bool = False
    false_positive: bool = False
    triage_notes: str = ""


@dataclass
class GreenTeamFix:
    """绿队修复"""
    fix_id: str
    vulnerability: str
    description: str
    fix_type: str  # patch/config/monitor/isolate
    priority: str  # P0/P1/P2/P3
    applied: bool = False
    verification_result: str = ""


@dataclass
class EngagementResult:
    """对抗结果"""
    engagement_id: str
    target: str
    red_actions: List[RedTeamAction] = field(default_factory=list)
    blue_alerts: List[BlueTeamAlert] = field(default_factory=list)
    green_fixes: List[GreenTeamFix] = field(default_factory=list)
    red_score: float = 0.0  # 红队得分（攻击成功率）
    blue_score: float = 0.0  # 蓝队得分（检测率）
    green_score: float = 0.0  # 绿队得分（修复率）
    overall_risk_reduction: float = 0.0  # 整体风险降低百分比


class RedTeam:
    """红队 - 攻击者"""

    def __init__(self):
        self.techniques = self._init_techniques()

    def _init_techniques(self) -> Dict[AttackPhase, List[Dict]]:
        """初始化攻击技术库"""
        return {
            AttackPhase.RECONNAISSANCE: [
                {"technique": "T1595", "name": "主动扫描", "tools": ["nmap", "nuclei"]},
                {"technique": "T1592", "name": "收集受害者主机信息", "tools": ["whatweb", "httpx"]},
                {"technique": "T1589", "name": "收集受害者身份信息", "tools": ["theHarvester"]},
            ],
            AttackPhase.INITIAL_ACCESS: [
                {"technique": "T1190", "name": "利用面向公众的应用", "tools": ["sqlmap", "nuclei"]},
                {"technique": "T1133", "name": "外部远程服务", "tools": ["hydra", "medusa"]},
                {"technique": "T1566", "name": "钓鱼", "tools": ["gophish", "setoolkit"]},
            ],
            AttackPhase.EXECUTION: [
                {"technique": "T1059", "name": "命令和脚本解释器", "tools": ["bash", "powershell"]},
                {"technique": "T1203", "name": "客户端执行", "tools": ["metasploit"]},
            ],
            AttackPhase.PRIVILEGE_ESCALATION: [
                {"technique": "T1068", "name": "利用漏洞提权", "tools": ["metasploit", "linux-exploit-suggester"]},
                {"technique": "T1548", "name": "滥用权限控制机制", "tools": ["sudo", "setuid"]},
            ],
            AttackPhase.LATERAL_MOVEMENT: [
                {"technique": "T1021", "name": "远程服务", "tools": ["crackmapexec", "impacket"]},
                {"technique": "T1570", "name": "横向工具传输", "tools": ["scp", "smbclient"]},
            ],
            AttackPhase.CREDENTIAL_ACCESS: [
                {"technique": "T1003", "name": "凭证转储", "tools": ["mimikatz", "secretsdump"]},
                {"technique": "T1110", "name": "暴力破解", "tools": ["hydra", "john"]},
            ],
            AttackPhase.EXFILTRATION: [
                {"technique": "T1041", "name": "通过C2通道渗出", "tools": ["metasploit", "cobalt_strike"]},
                {"technique": "T1567", "name": "通过Web服务渗出", "tools": ["curl", "wget"]},
            ],
        }

    def plan_attack(self, target: str, findings: List[Dict]) -> List[RedTeamAction]:
        """基于发现规划攻击"""
        actions = []
        action_counter = 0

        # 基于发现生成攻击行动
        for finding in findings:
            ftype = finding.get('type', '').lower()
            severity = finding.get('severity', 'info').lower()

            if ftype in ['open_port', 'port']:
                action_counter += 1
                actions.append(RedTeamAction(
                    action_id=f"red_{action_counter:03d}",
                    phase=AttackPhase.RECONNAISSANCE,
                    technique="T1595",
                    description=f"扫描端口{finding.get('port', 'unknown')}的服务漏洞",
                    target=target,
                    tools=["nmap", "nuclei"],
                ))

            elif ftype in ['vulnerability', 'web_vuln']:
                action_counter += 1
                phase = AttackPhase.INITIAL_ACCESS if severity in ['critical', 'high'] else AttackPhase.EXECUTION
                actions.append(RedTeamAction(
                    action_id=f"red_{action_counter:03d}",
                    phase=phase,
                    technique="T1190",
                    description=f"利用漏洞{finding.get('name', 'unknown')}",
                    target=target,
                    tools=["metasploit", "sqlmap"],
                ))

            elif ftype in ['smb_open', 'internal_service']:
                action_counter += 1
                actions.append(RedTeamAction(
                    action_id=f"red_{action_counter:03d}",
                    phase=AttackPhase.LATERAL_MOVEMENT,
                    technique="T1021",
                    description=f"通过SMB进行横向移动",
                    target=target,
                    tools=["crackmapexec", "impacket"],
                ))

            elif ftype in ['hardcoded_key', 'credential']:
                action_counter += 1
                actions.append(RedTeamAction(
                    action_id=f"red_{action_counter:03d}",
                    phase=AttackPhase.CREDENTIAL_ACCESS,
                    technique="T1552",
                    description=f"利用泄露的凭证{finding.get('name', 'unknown')}",
                    target=target,
                    tools=["curl", "python"],
                ))

        return actions[:15]  # 最多15个行动

    def execute_attack(self, action: RedTeamAction, findings: List[Dict]) -> RedTeamAction:
        """执行攻击行动（模拟）"""
        # 基于发现的严重程度模拟成功率
        high_severity = sum(1 for f in findings
                           if f.get('severity', '').lower() in ['critical', 'high'])
        success_rate = min(0.9, 0.3 + high_severity * 0.1)

        import random
        action.success = random.random() < success_rate
        action.evidence = [
            {"type": "attack_attempt", "technique": action.technique, "success": action.success}
        ]
        return action


class BlueTeam:
    """蓝队 - 防御者"""

    def __init__(self):
        self.detection_rules = self._init_detection_rules()

    def _init_detection_rules(self) -> List[Dict]:
        """初始化检测规则"""
        return [
            {"id": "BR001", "name": "端口扫描检测", "phase": "reconnaissance",
             "pattern": ["nmap", "masscan", "scan"], "severity": "medium"},
            {"id": "BR002", "name": "SQL注入检测", "phase": "initial_access",
             "pattern": ["sqlmap", "union select", "1=1"], "severity": "high"},
            {"id": "BR003", "name": "暴力破解检测", "phase": "credential_access",
             "pattern": ["hydra", "brute force", "failed login"], "severity": "high"},
            {"id": "BR004", "name": "横向移动检测", "phase": "lateral_movement",
             "pattern": ["crackmapexec", "wmiexec", "psexec"], "severity": "critical"},
            {"id": "BR005", "name": "凭证转储检测", "phase": "credential_access",
             "pattern": ["mimikatz", "lsass", "procdump"], "severity": "critical"},
            {"id": "BR006", "name": "数据渗出检测", "phase": "exfiltration",
             "pattern": ["large upload", "dns tunnel", "encrypted outbound"], "severity": "high"},
            {"id": "BR007", "name": "异常进程检测", "phase": "execution",
             "pattern": ["powershell -enc", "cmd /c", "base64"], "severity": "medium"},
            {"id": "BR008", "name": "提权尝试检测", "phase": "privilege_escalation",
             "pattern": ["sudo", "setuid", "kernel exploit"], "severity": "high"},
        ]

    def detect_attacks(self, red_actions: List[RedTeamAction]) -> List[BlueTeamAlert]:
        """检测红队攻击"""
        alerts = []
        alert_counter = 0

        for action in red_actions:
            if not action.success:
                continue

            # 匹配检测规则
            for rule in self.detection_rules:
                if rule['phase'] == action.phase.value:
                    alert_counter += 1
                    detected = True  # 模拟检测成功
                    alerts.append(BlueTeamAlert(
                        alert_id=f"blue_{alert_counter:03d}",
                        severity=rule['severity'],
                        title=rule['name'],
                        description=f"检测到{action.technique}攻击: {action.description}",
                        source=rule['id'],
                        related_attack=action.action_id,
                        detected=detected,
                        triage_notes=f"关联攻击行动{action.action_id}",
                    ))
                    break

        return alerts

    def calculate_detection_rate(self, alerts: List[BlueTeamAlert],
                                red_actions: List[RedTeamAction]) -> float:
        """计算检测率"""
        successful_attacks = [a for a in red_actions if a.success]
        if not successful_attacks:
            return 0.0
        detected = sum(1 for a in alerts if a.detected and not a.false_positive)
        return min(1.0, detected / len(successful_attacks))


class GreenTeam:
    """绿队 - 修复者"""

    def __init__(self):
        self.remediation_library = self._init_remediation()

    def _init_remediation(self) -> Dict[str, Dict]:
        """初始化修复方案库"""
        return {
            "sql_injection": {
                "fix_type": "patch",
                "description": "使用参数化查询，输入验证，WAF规则",
                "priority": "P0",
                "code_example": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            },
            "xss": {
                "fix_type": "patch",
                "description": "输出编码，CSP策略，HttpOnly Cookie",
                "priority": "P1",
                "code_example": "echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');",
            },
            "open_port": {
                "fix_type": "config",
                "description": "关闭不必要端口，防火墙限制，端口敲门",
                "priority": "P2",
            },
            "smb_open": {
                "fix_type": "config",
                "description": "禁用SMBv1，启用签名，限制访问IP",
                "priority": "P1",
            },
            "hardcoded_key": {
                "fix_type": "patch",
                "description": "移除硬编码密钥，使用环境变量/密钥管理服务，轮换密钥",
                "priority": "P0",
            },
            "default_credential": {
                "fix_type": "config",
                "description": "修改默认凭证，强制密码策略，MFA",
                "priority": "P0",
            },
            "missing_security_headers": {
                "fix_type": "config",
                "description": "添加CSP/X-Frame-Options/X-Content-Type-Options头",
                "priority": "P2",
            },
            "weak_encryption": {
                "fix_type": "patch",
                "description": "升级到AES-256/RSA-2048，禁用弱算法",
                "priority": "P1",
            },
        }

    def generate_fixes(self, findings: List[Dict],
                       alerts: List[BlueTeamAlert]) -> List[GreenTeamFix]:
        """生成修复方案"""
        fixes = []
        fix_counter = 0

        for finding in findings:
            ftype = finding.get('type', '').lower()
            severity = finding.get('severity', 'info').lower()

            # 匹配修复方案
            for key, remediation in self.remediation_library.items():
                if key in ftype or key in str(finding.get('name', '')).lower():
                    fix_counter += 1
                    fixes.append(GreenTeamFix(
                        fix_id=f"green_{fix_counter:03d}",
                        vulnerability=finding.get('name', ftype),
                        description=remediation['description'],
                        fix_type=remediation['fix_type'],
                        priority=remediation['priority'],
                    ))
                    break

        # 按优先级排序
        priority_order = {'P0': 0, 'P1': 1, 'P2': 2, 'P3': 3}
        fixes.sort(key=lambda f: priority_order.get(f.priority, 4))

        return fixes

    def apply_fixes(self, fixes: List[GreenTeamFix]) -> List[GreenTeamFix]:
        """应用修复（模拟）"""
        for fix in fixes:
            fix.applied = True  # 模拟全部应用成功
            fix.verification_result = f"修复已应用，漏洞{fix.vulnerability}已关闭"
        return fixes


class RedBlueGreenEngine:
    """
    红蓝绿对抗引擎

    实现完整的对抗闭环：红队攻击 → 蓝队检测 → 绿队修复 → 风险评估。
    """

    def __init__(self):
        self.red_team = RedTeam()
        self.blue_team = BlueTeam()
        self.green_team = GreenTeam()

    def run_engagement(self, target: str,
                       findings: List[Dict]) -> EngagementResult:
        """运行完整对抗演练"""
        result = EngagementResult(
            engagement_id=f"eng_{int(datetime.now().timestamp())}",
            target=target,
        )

        # 1. 红队规划并执行攻击
        red_actions = self.red_team.plan_attack(target, findings)
        for action in red_actions:
            self.red_team.execute_attack(action, findings)
        result.red_actions = red_actions

        # 2. 蓝队检测攻击
        blue_alerts = self.blue_team.detect_attacks(red_actions)
        result.blue_alerts = blue_alerts

        # 3. 绿队生成并应用修复
        green_fixes = self.green_team.generate_fixes(findings, blue_alerts)
        self.green_team.apply_fixes(green_fixes)
        result.green_fixes = green_fixes

        # 4. 计算得分
        successful_attacks = [a for a in red_actions if a.success]
        result.red_score = len(successful_attacks) / len(red_actions) * 100 if red_actions else 0

        detection_rate = self.blue_team.calculate_detection_rate(blue_alerts, red_actions)
        result.blue_score = detection_rate * 100

        applied_fixes = [f for f in green_fixes if f.applied]
        result.green_score = len(applied_fixes) / len(green_fixes) * 100 if green_fixes else 0

        # 5. 计算风险降低
        initial_risk = sum(
            {'critical': 25, 'high': 15, 'medium': 8, 'low': 3, 'info': 1}.get(
                f.get('severity', 'info').lower(), 1)
            for f in findings
        )
        fixed_risk = sum(
            {'P0': 25, 'P1': 15, 'P2': 8, 'P3': 3}.get(f.priority, 0)
            for f in applied_fixes
        )
        result.overall_risk_reduction = min(100, fixed_risk / initial_risk * 100) if initial_risk else 0

        return result

    def to_dict(self, result: EngagementResult) -> Dict:
        """转换为字典"""
        return {
            "engagement_id": result.engagement_id,
            "target": result.target,
            "red_team": {
                "actions_count": len(result.red_actions),
                "successful": sum(1 for a in result.red_actions if a.success),
                "score": result.red_score,
                "actions": [
                    {"id": a.action_id, "phase": a.phase.value,
                     "technique": a.technique, "description": a.description,
                     "success": a.success}
                    for a in result.red_actions
                ],
            },
            "blue_team": {
                "alerts_count": len(result.blue_alerts),
                "detected": sum(1 for a in result.blue_alerts if a.detected),
                "score": result.blue_score,
                "alerts": [
                    {"id": a.alert_id, "severity": a.severity,
                     "title": a.title, "detected": a.detected}
                    for a in result.blue_alerts
                ],
            },
            "green_team": {
                "fixes_count": len(result.green_fixes),
                "applied": sum(1 for f in result.green_fixes if f.applied),
                "score": result.green_score,
                "fixes": [
                    {"id": f.fix_id, "vulnerability": f.vulnerability,
                     "priority": f.priority, "applied": f.applied}
                    for f in result.green_fixes
                ],
            },
            "overall_risk_reduction": result.overall_risk_reduction,
        }


# 单例模式
_engine_instance: Optional[RedBlueGreenEngine] = None

def get_rbg_engine() -> RedBlueGreenEngine:
    """获取全局红蓝绿引擎实例"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = RedBlueGreenEngine()
    return _engine_instance
