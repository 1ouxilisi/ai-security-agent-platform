#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能决策引擎（Intelligent Decision Engine）

基于发现和攻击链验证结果，AI自动规划下一步行动，生成执行计划。
支持自主决策模式，不需要人工干预。

核心能力：
1. 风险优先级排序 - 基于CVSS/攻击链/业务影响排序
2. 下一步行动推荐 - 根据当前发现推荐最优下一步
3. 执行计划生成 - 生成详细的执行步骤和工具调用
4. 资源分配优化 - 优化Agent和工具的分配
5. 自主决策模式 - 全自动执行，不需要人工干预
"""

import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class Priority(Enum):
    """优先级"""
    P0_CRITICAL = "P0_critical"  # 立即处理
    P1_HIGH = "P1_high"  # 24小时内
    P2_MEDIUM = "P2_medium"  # 本周内
    P3_LOW = "P3_low"  # 本月内
    P4_INFO = "P4_info"  # 记录即可


class ActionType(Enum):
    """行动类型"""
    SCAN = "scan"  # 扫描
    ENUMERATE = "enumerate"  # 枚举
    EXPLOIT = "exploit"  # 利用
    VALIDATE = "validate"  # 验证
    PRIVILEGE_ESCALATION = "privilege_escalation"  # 提权
    LATERAL_MOVEMENT = "lateral_movement"  # 横向移动
    EXFILTRATE = "exfiltrate"  # 数据渗出
    PERSIST = "persist"  # 持久化
    REPORT = "report"  # 报告
    REMEDIATE = "remediate"  # 修复


@dataclass
class Action:
    """行动"""
    action_id: str
    type: ActionType
    title: str
    description: str
    target: str
    tools: List[str] = field(default_factory=list)
    priority: Priority = Priority.P3_LOW
    expected_outcome: str = ""
    estimated_time: str = ""
    dependencies: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 0-1
    status: str = "pending"  # pending/in_progress/completed/failed


@dataclass
class ExecutionPlan:
    """执行计划"""
    plan_id: str
    created_at: str
    title: str
    description: str
    actions: List[Action] = field(default_factory=list)
    total_actions: int = 0
    critical_actions: int = 0
    high_actions: int = 0
    estimated_total_time: str = ""
    overall_risk: str = "medium"
    autonomous_mode: bool = False
    recommendations: List[str] = field(default_factory=list)


class IntelligentDecisionEngine:
    """
    智能决策引擎

    基于发现和攻击链验证结果，自动规划下一步行动。
    """

    def __init__(self):
        self.action_counter = 0

    def generate_plan(self, findings: List[Dict],
                      chain_results: List[Dict] = None,
                      target: str = "",
                      autonomous: bool = False) -> ExecutionPlan:
        """
        生成执行计划

        Args:
            findings: 所有发现
            chain_results: 攻击链验证结果
            target: 目标
            autonomous: 是否自主模式

        Returns:
            执行计划
        """
        self.action_counter = 0
        plan = ExecutionPlan(
            plan_id=f"plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            created_at=datetime.now().isoformat(),
            title=f"智能渗透执行计划 - {target}",
            description=f"基于{len(findings)}个发现和{len(chain_results or [])}条攻击链自动生成",
            autonomous_mode=autonomous,
        )

        # 1. 风险优先级排序
        sorted_findings = self._prioritize_findings(findings)

        # 2. 基于发现生成行动
        for finding in sorted_findings[:20]:  # 最多20个行动
            action = self._finding_to_action(finding, target)
            if action:
                plan.actions.append(action)

        # 3. 基于攻击链生成行动
        if chain_results:
            chain_actions = self._chains_to_actions(chain_results, target)
            plan.actions.extend(chain_actions)

        # 4. 去重和排序
        plan.actions = self._deduplicate_actions(plan.actions)
        plan.actions.sort(key=lambda a: self._priority_value(a.priority))

        # 5. 统计
        plan.total_actions = len(plan.actions)
        plan.critical_actions = sum(1 for a in plan.actions if a.priority == Priority.P0_CRITICAL)
        plan.high_actions = sum(1 for a in plan.actions if a.priority == Priority.P1_HIGH)

        # 6. 估算总时间
        total_minutes = 0
        for action in plan.actions:
            time_map = {"5分钟": 5, "10分钟": 10, "15分钟": 15, "30分钟": 30,
                       "1小时": 60, "2小时": 120, "未知": 15}
            total_minutes += time_map.get(action.estimated_time, 15)
        if total_minutes >= 60:
            plan.estimated_total_time = f"{total_minutes // 60}小时{total_minutes % 60}分钟"
        else:
            plan.estimated_total_time = f"{total_minutes}分钟"

        # 7. 整体风险
        if plan.critical_actions >= 3:
            plan.overall_risk = "critical"
        elif plan.critical_actions >= 1 or plan.high_actions >= 3:
            plan.overall_risk = "high"
        elif plan.high_actions >= 1:
            plan.overall_risk = "medium"
        else:
            plan.overall_risk = "low"

        # 8. 生成建议
        plan.recommendations = self._generate_recommendations(plan)

        return plan

    def _prioritize_findings(self, findings: List[Dict]) -> List[Dict]:
        """风险优先级排序"""
        def score(finding):
            severity = finding.get('severity', 'info').lower()
            severity_score = {'critical': 100, 'high': 75, 'medium': 50, 'low': 25, 'info': 10}
            base = severity_score.get(severity, 10)

            # 真实工具发现加分
            if finding.get('source') == 'real_tool':
                base += 10

            # 攻击链相关加分
            if finding.get('in_chain'):
                base += 15

            return base

        return sorted(findings, key=score, reverse=True)

    def _finding_to_action(self, finding: Dict, target: str) -> Optional[Action]:
        """将发现转换为行动"""
        ftype = finding.get('type', '').lower()
        severity = finding.get('severity', 'info').lower()
        name = finding.get('name', finding.get('type', 'unknown'))

        # 根据发现类型生成对应行动
        action_map = {
            'open_port': {
                'type': ActionType.ENUMERATE,
                'title': f'端口服务枚举 - {finding.get("port", "unknown")}',
                'description': f'对开放端口{finding.get("port", "unknown")}进行服务版本和漏洞枚举',
                'tools': ['nmap', 'nuclei', 'whatweb'],
                'expected_outcome': '服务版本信息和潜在漏洞',
                'estimated_time': '10分钟',
            },
            'vulnerability': {
                'type': ActionType.VALIDATE,
                'title': f'漏洞验证 - {name}',
                'description': f'验证漏洞{name}的可利用性和影响范围',
                'tools': ['nuclei', 'sqlmap', 'metasploit'],
                'expected_outcome': '漏洞可利用性确认和PoC',
                'estimated_time': '15分钟',
            },
            'subdomain': {
                'type': ActionType.SCAN,
                'title': f'子域名扫描 - {finding.get("domain", "unknown")}',
                'description': f'对子域名{finding.get("domain", "unknown")}进行端口和漏洞扫描',
                'tools': ['nmap', 'subfinder', 'httpx'],
                'expected_outcome': '子域名的开放端口和漏洞',
                'estimated_time': '30分钟',
            },
            'hardcoded_key': {
                'type': ActionType.EXPLOIT,
                'title': f'密钥利用测试 - {name}',
                'description': f'测试硬编码密钥{name}的权限和可利用性',
                'tools': ['curl', 'python', 'aws-cli'],
                'expected_outcome': '密钥权限范围和利用方式',
                'estimated_time': '15分钟',
            },
            'smb_open': {
                'type': ActionType.ENUMERATE,
                'title': 'SMB服务枚举',
                'description': '枚举SMB共享、用户和漏洞',
                'tools': ['crackmapexec', 'smbclient', 'enum4linux'],
                'expected_outcome': 'SMB共享列表和用户信息',
                'estimated_time': '15分钟',
            },
            'modbus_open': {
                'type': ActionType.EXPLOIT,
                'title': 'Modbus工控协议测试',
                'description': '测试Modbus协议的读写权限和控制能力',
                'tools': ['modpoll', 'nmap-ics', 'python'],
                'expected_outcome': 'PLC寄存器读写能力',
                'estimated_time': '30分钟',
            },
            'api_response': {
                'type': ActionType.ENUMERATE,
                'title': 'API端点枚举',
                'description': '枚举API端点和测试认证授权',
                'tools': ['postman', 'curl', 'burp'],
                'expected_outcome': 'API端点列表和权限问题',
                'estimated_time': '30分钟',
            },
            'missing_security_headers': {
                'type': ActionType.REMEDIATE,
                'title': '安全头修复建议',
                'description': '生成缺失安全头的修复配置',
                'tools': ['nginx', 'apache', 'iis'],
                'expected_outcome': '安全头配置文件',
                'estimated_time': '5分钟',
            },
        }

        config = action_map.get(ftype)
        if not config:
            # 默认行动
            config = {
                'type': ActionType.SCAN,
                'title': f'深入扫描 - {name}',
                'description': f'对发现{name}进行深入扫描和分析',
                'tools': ['nmap', 'nuclei'],
                'expected_outcome': '更详细的漏洞信息',
                'estimated_time': '15分钟',
            }

        # 优先级映射
        priority_map = {
            'critical': Priority.P0_CRITICAL,
            'high': Priority.P1_HIGH,
            'medium': Priority.P2_MEDIUM,
            'low': Priority.P3_LOW,
            'info': Priority.P4_INFO,
        }

        self.action_counter += 1
        return Action(
            action_id=f"action_{self.action_counter:03d}",
            type=config['type'],
            title=config['title'],
            description=config['description'],
            target=target,
            tools=config['tools'],
            priority=priority_map.get(severity, Priority.P3_LOW),
            expected_outcome=config['expected_outcome'],
            estimated_time=config['estimated_time'],
            confidence=0.7 if finding.get('source') == 'real_tool' else 0.5,
        )

    def _chains_to_actions(self, chain_results: List[Dict], target: str) -> List[Action]:
        """将攻击链结果转换为行动"""
        actions = []
        for chain in chain_results:
            status = chain.get('status', '')
            if status in ['verified', 'exploitable']:
                self.action_counter += 1
                actions.append(Action(
                    action_id=f"action_{self.action_counter:03d}",
                    type=ActionType.EXPLOIT,
                    title=f"攻击链利用 - {chain.get('name', 'unknown')}",
                    description=f"利用已验证的攻击链「{chain.get('name')}」进行深度渗透",
                    target=target,
                    tools=['metasploit', 'cobalt_strike', 'custom'],
                    priority=Priority.P0_CRITICAL if status == 'exploitable' else Priority.P1_HIGH,
                    expected_outcome='攻击链完整利用和权限获取',
                    estimated_time='2小时',
                    confidence=chain.get('completion_rate', 0.5),
                ))
            elif status == 'partially_verified':
                self.action_counter += 1
                actions.append(Action(
                    action_id=f"action_{self.action_counter:03d}",
                    type=ActionType.VALIDATE,
                    title=f"攻击链验证 - {chain.get('name', 'unknown')}",
                    description=f"验证部分完成的攻击链「{chain.get('name')}」的剩余阶段",
                    target=target,
                    tools=['nmap', 'nuclei', 'custom'],
                    priority=Priority.P1_HIGH,
                    expected_outcome='攻击链完整验证',
                    estimated_time='1小时',
                    confidence=chain.get('completion_rate', 0.3),
                ))
        return actions

    def _deduplicate_actions(self, actions: List[Action]) -> List[Action]:
        """去重行动"""
        seen = set()
        unique = []
        for action in actions:
            key = f"{action.type.value}_{action.title}"
            if key not in seen:
                seen.add(key)
                unique.append(action)
        return unique

    def _priority_value(self, priority: Priority) -> int:
        """优先级数值（用于排序）"""
        return {
            Priority.P0_CRITICAL: 0,
            Priority.P1_HIGH: 1,
            Priority.P2_MEDIUM: 2,
            Priority.P3_LOW: 3,
            Priority.P4_INFO: 4,
        }.get(priority, 5)

    def _generate_recommendations(self, plan: ExecutionPlan) -> List[str]:
        """生成建议"""
        recs = []
        recs.append(f"执行计划包含{plan.total_actions}个行动，预计耗时{plan.estimated_total_time}")

        if plan.critical_actions > 0:
            recs.append(f"⚠️ {plan.critical_actions}个P0紧急行动需立即处理")
        if plan.high_actions > 0:
            recs.append(f"{plan.high_actions}个P1高优先级行动建议24小时内处理")

        if plan.autonomous_mode:
            recs.append("自主决策模式已启用，系统将自动执行高置信度行动")
        else:
            recs.append("建议人工审核P0/P1行动后再执行")

        # 工具建议
        all_tools = set()
        for action in plan.actions:
            all_tools.update(action.tools)
        recs.append(f"涉及工具: {', '.join(sorted(all_tools)[:10])}")

        return recs

    def get_next_action(self, plan: ExecutionPlan) -> Optional[Action]:
        """获取下一个待执行的行动"""
        for action in plan.actions:
            if action.status == "pending":
                return action
        return None

    def to_dict(self, plan: ExecutionPlan) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "plan_id": plan.plan_id,
            "created_at": plan.created_at,
            "title": plan.title,
            "description": plan.description,
            "total_actions": plan.total_actions,
            "critical_actions": plan.critical_actions,
            "high_actions": plan.high_actions,
            "estimated_total_time": plan.estimated_total_time,
            "overall_risk": plan.overall_risk,
            "autonomous_mode": plan.autonomous_mode,
            "actions": [
                {
                    "action_id": a.action_id,
                    "type": a.type.value,
                    "title": a.title,
                    "description": a.description,
                    "target": a.target,
                    "tools": a.tools,
                    "priority": a.priority.value,
                    "expected_outcome": a.expected_outcome,
                    "estimated_time": a.estimated_time,
                    "confidence": a.confidence,
                    "status": a.status,
                }
                for a in plan.actions
            ],
            "recommendations": plan.recommendations,
        }


# 单例模式
_engine_instance: Optional[IntelligentDecisionEngine] = None

def get_decision_engine() -> IntelligentDecisionEngine:
    """获取全局决策引擎实例"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = IntelligentDecisionEngine()
    return _engine_instance
