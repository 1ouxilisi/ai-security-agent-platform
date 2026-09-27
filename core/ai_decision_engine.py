#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI自主决策引擎
AI Autonomous Decision Engine

功能：自主任务规划、智能决策、漏洞优先级、攻击路径规划、持续学习、策略优化
"""

import os
import json
import time
import uuid
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum
from collections import defaultdict, deque
from loguru import logger


class DecisionType(str, Enum):
    """决策类型"""
    TASK_PLANNING = "task_planning"          # 任务规划
    VULN_PRIORITIZATION = "vuln_prioritization"  # 漏洞优先级
    ATTACK_PATH = "attack_path"              # 攻击路径
    TOOL_SELECTION = "tool_selection"        # 工具选择
    RISK_ASSESSMENT = "risk_assessment"      # 风险评估
    REMEDIATION = "remediation"              # 修复建议
    ESCALATION = "escalation"                # 升级决策


class ConfidenceLevel(str, Enum):
    """置信度"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class LearningType(str, Enum):
    """学习类型"""
    REINFORCEMENT = "reinforcement"      # 强化学习
    SUPERVISED = "supervised"            # 监督学习
    UNSUPERVISED = "unsupervised"        # 无监督学习
    RULE_BASED = "rule_based"            # 规则学习
    EXPERIENCE = "experience"            # 经验学习


@dataclass
class Decision:
    """决策"""
    decision_id: str
    decision_type: DecisionType
    title: str
    description: str
    context: Dict[str, Any] = field(default_factory=dict)
    options: List[Dict[str, Any]] = field(default_factory=list)
    selected_option: Optional[int] = None
    reasoning: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    confidence_score: float = 0.0
    expected_outcome: str = ""
    actual_outcome: Optional[str] = None
    success: Optional[bool] = None
    created_at: float = field(default_factory=time.time)
    executed_at: Optional[float] = None
    completed_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'decision_id': self.decision_id,
            'decision_type': self.decision_type.value,
            'title': self.title,
            'description': self.description,
            'context': self.context,
            'options': self.options,
            'selected_option': self.selected_option,
            'reasoning': self.reasoning,
            'confidence': self.confidence.value,
            'confidence_score': self.confidence_score,
            'expected_outcome': self.expected_outcome,
            'actual_outcome': self.actual_outcome,
            'success': self.success,
            'created_at': self.created_at,
            'executed_at': self.executed_at,
            'completed_at': self.completed_at,
            'metadata': self.metadata,
        }


@dataclass
class AttackPath:
    """攻击路径"""
    path_id: str
    target: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    total_steps: int = 0
    current_step: int = 0
    estimated_time: float = 0.0
    estimated_success_rate: float = 0.0
    risk_level: str = "medium"
    prerequisites: List[str] = field(default_factory=list)
    expected_impact: str = ""
    created_at: float = field(default_factory=time.time)
    status: str = "planned"  # planned, in_progress, completed, failed, abandoned

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VulnerabilityPriority:
    """漏洞优先级"""
    priority_id: str
    vulnerability_id: str
    vulnerability_name: str
    severity: str
    cvss_score: float
    exploitability: float  # 可利用性 0-1
    impact: float  # 影响 0-1
    exposure: float  # 暴露程度 0-1
    business_impact: float  # 业务影响 0-1
    priority_score: float = 0.0
    priority_level: str = "medium"  # critical, high, medium, low
    remediation_effort: str = "medium"  # low, medium, high
    recommended_action: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LearningExperience:
    """学习经验"""
    experience_id: str
    learning_type: LearningType
    scenario: str
    action: str
    outcome: str
    success: bool
    reward: float = 0.0
    context: Dict[str, Any] = field(default_factory=dict)
    learned_pattern: str = ""
    confidence: float = 0.0
    created_at: float = field(default_factory=time.time)
    usage_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'experience_id': self.experience_id,
            'learning_type': self.learning_type.value,
            'scenario': self.scenario,
            'action': self.action,
            'outcome': self.outcome,
            'success': self.success,
            'reward': self.reward,
            'context': self.context,
            'learned_pattern': self.learned_pattern,
            'confidence': self.confidence,
            'created_at': self.created_at,
            'usage_count': self.usage_count,
        }


class KnowledgeBase:
    """知识库"""

    def __init__(self):
        self._rules: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._patterns: Dict[str, float] = {}
        self._init_builtin_rules()

    def _init_builtin_rules(self):
        """初始化内置规则"""
        # 漏洞优先级规则
        self._rules['vuln_priority'] = [
            {
                'id': 'cvss_based',
                'condition': 'cvss_score >= 9.0',
                'action': 'priority_level = critical',
                'weight': 0.4,
                'description': 'CVSS评分>=9.0为严重',
            },
            {
                'id': 'exploit_available',
                'condition': 'exploitability >= 0.8',
                'action': 'priority_score += 20',
                'weight': 0.3,
                'description': '有公开利用代码加20分',
            },
            {
                'id': 'internet_exposed',
                'condition': 'exposure >= 0.9',
                'action': 'priority_score += 15',
                'weight': 0.2,
                'description': '互联网暴露加15分',
            },
        ]

        # 工具选择规则
        self._rules['tool_selection'] = [
            {
                'id': 'web_app',
                'condition': 'target_type == web',
                'action': 'use sqlmap, nikto, dirb',
                'weight': 0.5,
            },
            {
                'id': 'network_device',
                'condition': 'target_type == network',
                'action': 'use nmap, masscan, metasploit',
                'weight': 0.5,
            },
        ]

        # 攻击路径规则
        self._rules['attack_path'] = [
            {
                'id': 'standard_approach',
                'condition': 'always',
                'action': 'recon -> scan -> exploit -> escalate -> persist',
                'weight': 0.6,
                'description': '标准攻击路径',
            },
        ]

    def get_rules(self, category: str) -> List[Dict[str, Any]]:
        """获取规则"""
        return self._rules.get(category, [])

    def add_rule(self, category: str, rule: Dict[str, Any]):
        """添加规则"""
        self._rules[category].append(rule)

    def add_pattern(self, pattern: str, success_rate: float):
        """添加模式"""
        if pattern in self._patterns:
            old = self._patterns[pattern]
            self._patterns[pattern] = (old + success_rate) / 2
        else:
            self._patterns[pattern] = success_rate

    def get_pattern_success_rate(self, pattern: str) -> float:
        """获取模式成功率"""
        return self._patterns.get(pattern, 0.5)


class AIDecisionEngine:
    """AI决策引擎"""

    def __init__(self, data_dir: str = "data/ai_engine"):
        self.data_dir = data_dir
        self.decisions_file = os.path.join(data_dir, "decisions.json")
        self.experiences_file = os.path.join(data_dir, "experiences.json")

        self._decisions: Dict[str, Decision] = {}
        self._experiences: List[LearningExperience] = []
        self._knowledge_base = KnowledgeBase()
        self._attack_paths: Dict[str, AttackPath] = {}
        self._vuln_priorities: Dict[str, VulnerabilityPriority] = {}

        self._total_decisions = 0
        self._successful_decisions = 0
        self._learning_enabled = True

        os.makedirs(data_dir, exist_ok=True)
        self._load_decisions()
        self._load_experiences()

        logger.info("AI决策引擎初始化完成")

    # ============== 任务规划 ==============

    def plan_task(self, target: str, task_type: str,
                  constraints: Dict[str, Any] = None) -> Decision:
        """自主任务规划"""
        constraints = constraints or {}

        # 生成规划选项
        options = self._generate_planning_options(target, task_type, constraints)

        # 选择最佳方案
        selected_idx = self._select_best_option(options, task_type)

        # 生成推理
        reasoning = self._generate_reasoning(options, selected_idx, task_type)

        # 计算置信度
        confidence_score = self._calculate_confidence(options, selected_idx)
        confidence = self._score_to_confidence(confidence_score)

        decision = Decision(
            decision_id=str(uuid.uuid4()),
            decision_type=DecisionType.TASK_PLANNING,
            title=f"{task_type}任务规划",
            description=f"为目标 {target} 规划 {task_type} 任务",
            context={'target': target, 'task_type': task_type, 'constraints': constraints},
            options=options,
            selected_option=selected_idx,
            reasoning=reasoning,
            confidence=confidence,
            confidence_score=confidence_score,
            expected_outcome=options[selected_idx].get('expected_outcome', '') if selected_idx is not None else '',
        )

        self._decisions[decision.decision_id] = decision
        self._total_decisions += 1
        self._save_decisions()

        logger.info(f"任务规划完成: {decision.title}, 置信度: {confidence.value}")
        return decision

    def _generate_planning_options(self, target: str, task_type: str,
                                     constraints: Dict[str, Any]) -> List[Dict[str, Any]]:
        """生成规划选项"""
        options = []

        if task_type == "penetration_test":
            options = [
                {
                    'name': '标准渗透测试流程',
                    'steps': ['信息收集', '漏洞扫描', '漏洞利用', '权限提升', '横向移动', '报告生成'],
                    'estimated_time': 240,
                    'estimated_success_rate': 0.75,
                    'risk_level': 'medium',
                    'tools': ['nmap', 'nikto', 'sqlmap', 'metasploit'],
                    'expected_outcome': '全面的渗透测试报告',
                },
                {
                    'name': '快速渗透测试',
                    'steps': ['快速扫描', '高危漏洞利用', '报告生成'],
                    'estimated_time': 60,
                    'estimated_success_rate': 0.6,
                    'risk_level': 'low',
                    'tools': ['nmap', 'nuclei'],
                    'expected_outcome': '快速漏洞报告',
                },
                {
                    'name': '深度渗透测试',
                    'steps': ['详细信息收集', '全面漏洞扫描', '0day挖掘', '复杂利用链', '持久化', '完整报告'],
                    'estimated_time': 480,
                    'estimated_success_rate': 0.85,
                    'risk_level': 'high',
                    'tools': ['nmap', 'burp', 'sqlmap', 'metasploit', 'cobalt_strike'],
                    'expected_outcome': '深度渗透测试报告，包含复杂攻击链',
                },
            ]
        elif task_type == "vulnerability_scan":
            options = [
                {
                    'name': '全面漏洞扫描',
                    'steps': ['端口扫描', '服务识别', '漏洞匹配', '验证测试'],
                    'estimated_time': 120,
                    'estimated_success_rate': 0.8,
                    'risk_level': 'low',
                    'tools': ['nmap', 'openvas', 'nuclei'],
                },
                {
                    'name': 'Web漏洞扫描',
                    'steps': ['爬虫', 'SQL注入测试', 'XSS测试', '配置错误检查'],
                    'estimated_time': 90,
                    'estimated_success_rate': 0.75,
                    'risk_level': 'medium',
                    'tools': ['nikto', 'sqlmap', 'xsser'],
                },
            ]
        else:
            options = [
                {
                    'name': '标准流程',
                    'steps': ['准备', '执行', '验证', '报告'],
                    'estimated_time': 60,
                    'estimated_success_rate': 0.7,
                    'risk_level': 'medium',
                    'tools': [],
                },
            ]

        return options

    def _select_best_option(self, options: List[Dict], task_type: str) -> int:
        """选择最佳选项"""
        if not options:
            return 0

        best_idx = 0
        best_score = -1

        for i, option in enumerate(options):
            # 综合评分：成功率 * 0.4 + (1/时间) * 0.2 + (1/风险) * 0.4
            success_rate = option.get('estimated_success_rate', 0.5)
            time_factor = 1.0 / max(1, option.get('estimated_time', 60) / 60)
            risk_map = {'low': 1.0, 'medium': 0.7, 'high': 0.4}
            risk_factor = risk_map.get(option.get('risk_level', 'medium'), 0.5)

            score = success_rate * 0.4 + time_factor * 0.2 + risk_factor * 0.4

            # 经验加成
            pattern = f"{task_type}_{option['name']}"
            experience_rate = self._knowledge_base.get_pattern_success_rate(pattern)
            score += experience_rate * 0.1

            if score > best_score:
                best_score = score
                best_idx = i

        return best_idx

    def _generate_reasoning(self, options: List[Dict], selected_idx: int, task_type: str) -> str:
        """生成推理过程"""
        if selected_idx is None or selected_idx >= len(options):
            return "无法生成推理"

        selected = options[selected_idx]
        reasoning = f"基于以下因素选择了'{selected['name']}'方案：\n"
        reasoning += f"1. 预期成功率: {selected.get('estimated_success_rate', 0) * 100:.0f}%\n"
        reasoning += f"2. 预计耗时: {selected.get('estimated_time', 0)}分钟\n"
        reasoning += f"3. 风险等级: {selected.get('risk_level', 'unknown')}\n"
        reasoning += f"4. 使用工具: {', '.join(selected.get('tools', []))}\n"

        # 比较其他选项
        for i, option in enumerate(options):
            if i != selected_idx:
                reasoning += f"\n相比'{option['name']}'："
                if selected.get('estimated_success_rate', 0) > option.get('estimated_success_rate', 0):
                    reasoning += "成功率更高"
                if selected.get('estimated_time', 0) < option.get('estimated_time', 0):
                    reasoning += "耗时更短"
                reasoning += "。"

        return reasoning

    def _calculate_confidence(self, options: List[Dict], selected_idx: int) -> float:
        """计算置信度"""
        if not options or selected_idx is None:
            return 0.0

        selected = options[selected_idx]
        base_confidence = selected.get('estimated_success_rate', 0.5)

        # 选项数量影响（选项越多，选择越可靠）
        option_factor = min(1.0, len(options) / 5)

        # 经验加成
        pattern = f"{selected.get('name', '')}"
        experience_rate = self._knowledge_base.get_pattern_success_rate(pattern)

        confidence = base_confidence * 0.6 + option_factor * 0.2 + experience_rate * 0.2
        return min(1.0, max(0.0, confidence))

    def _score_to_confidence(self, score: float) -> ConfidenceLevel:
        """分数转置信度"""
        if score >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif score >= 0.75:
            return ConfidenceLevel.HIGH
        elif score >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif score >= 0.25:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW

    # ============== 漏洞优先级 ==============

    def prioritize_vulnerability(self, vuln_id: str, vuln_name: str,
                                  severity: str, cvss_score: float,
                                  context: Dict[str, Any] = None) -> VulnerabilityPriority:
        """漏洞优先级排序"""
        context = context or {}

        exploitability = context.get('exploitability', 0.5)
        impact = context.get('impact', 0.5)
        exposure = context.get('exposure', 0.5)
        business_impact = context.get('business_impact', 0.5)

        # 计算优先级分数
        priority_score = (
            cvss_score * 0.3 +
            exploitability * 20 * 0.25 +
            impact * 20 * 0.2 +
            exposure * 20 * 0.15 +
            business_impact * 20 * 0.1
        )

        # 确定优先级等级
        if priority_score >= 80:
            priority_level = "critical"
        elif priority_score >= 60:
            priority_level = "high"
        elif priority_score >= 40:
            priority_level = "medium"
        else:
            priority_level = "low"

        # 修复建议
        if priority_level == "critical":
            recommended_action = "立即修复，24小时内完成"
            remediation_effort = "high"
        elif priority_level == "high":
            recommended_action = "优先修复，7天内完成"
            remediation_effort = "medium"
        elif priority_level == "medium":
            recommended_action = "计划修复，30天内完成"
            remediation_effort = "medium"
        else:
            recommended_action = "建议修复，下个维护周期处理"
            remediation_effort = "low"

        priority = VulnerabilityPriority(
            priority_id=str(uuid.uuid4()),
            vulnerability_id=vuln_id,
            vulnerability_name=vuln_name,
            severity=severity,
            cvss_score=cvss_score,
            exploitability=exploitability,
            impact=impact,
            exposure=exposure,
            business_impact=business_impact,
            priority_score=round(priority_score, 2),
            priority_level=priority_level,
            remediation_effort=remediation_effort,
            recommended_action=recommended_action,
        )

        self._vuln_priorities[priority.priority_id] = priority
        logger.info(f"漏洞优先级评估: {vuln_name} -> {priority_level} ({priority_score:.1f}分)")
        return priority

    # ============== 攻击路径规划 ==============

    def plan_attack_path(self, target: str, starting_point: str = "",
                          goal: str = "full_access") -> AttackPath:
        """规划攻击路径"""
        path_id = str(uuid.uuid4())

        # 生成攻击步骤
        steps = self._generate_attack_steps(target, starting_point, goal)

        # 计算估计
        total_time = sum(step.get('estimated_time', 30) for step in steps)
        avg_success = sum(step.get('success_rate', 0.5) for step in steps) / len(steps) if steps else 0.5
        overall_success = avg_success ** len(steps) if steps else 0

        # 风险等级
        if overall_success > 0.5:
            risk_level = "low"
        elif overall_success > 0.2:
            risk_level = "medium"
        else:
            risk_level = "high"

        path = AttackPath(
            path_id=path_id,
            target=target,
            steps=steps,
            total_steps=len(steps),
            current_step=0,
            estimated_time=total_time,
            estimated_success_rate=round(overall_success, 2),
            risk_level=risk_level,
            expected_impact=goal,
        )

        self._attack_paths[path_id] = path
        logger.info(f"攻击路径规划完成: {target}, {len(steps)}步, 成功率{overall_success:.0%}")
        return path

    def _generate_attack_steps(self, target: str, starting_point: str,
                                goal: str) -> List[Dict[str, Any]]:
        """生成攻击步骤"""
        steps = []

        # 标准攻击链
        standard_steps = [
            {
                'name': '信息收集',
                'description': f'收集 {target} 的子域名、IP、端口、服务信息',
                'tools': ['nmap', 'subfinder', 'amass', 'whois'],
                'estimated_time': 30,
                'success_rate': 0.9,
                'output': '目标信息清单',
            },
            {
                'name': '漏洞扫描',
                'description': '扫描目标系统和应用的已知漏洞',
                'tools': ['nuclei', 'openvas', 'nikto'],
                'estimated_time': 60,
                'success_rate': 0.8,
                'output': '漏洞列表',
            },
            {
                'name': '漏洞验证',
                'description': '验证扫描发现的漏洞是否可利用',
                'tools': ['sqlmap', 'metasploit', 'manual'],
                'estimated_time': 45,
                'success_rate': 0.7,
                'output': '可利用漏洞列表',
            },
            {
                'name': '初始访问',
                'description': '利用漏洞获取初始访问权限',
                'tools': ['metasploit', 'cobalt_strike', 'custom_exploit'],
                'estimated_time': 60,
                'success_rate': 0.6,
                'output': '初始shell/会话',
            },
            {
                'name': '权限提升',
                'description': '从普通用户提升到管理员/root权限',
                'tools': ['linpeas', 'winpeas', 'kernel_exploit'],
                'estimated_time': 45,
                'success_rate': 0.5,
                'output': '高权限会话',
            },
            {
                'name': '横向移动',
                'description': '在内部网络中横向移动，访问更多系统',
                'tools': ['mimikatz', 'crackmapexec', 'wmiexec'],
                'estimated_time': 60,
                'success_rate': 0.5,
                'output': '更多系统访问权限',
            },
            {
                'name': '持久化',
                'description': '建立持久化访问机制',
                'tools': ['cron', 'registry', 'service', 'webshell'],
                'estimated_time': 30,
                'success_rate': 0.8,
                'output': '持久化访问',
            },
            {
                'name': '数据收集',
                'description': '收集敏感数据和凭证',
                'tools': ['mimikatz', 'laZagne', 'file_scraper'],
                'estimated_time': 45,
                'success_rate': 0.7,
                'output': '敏感数据/凭证',
            },
            {
                'name': '痕迹清理',
                'description': '清理攻击痕迹和日志',
                'tools': ['log_cleaner', 'timestomp', 'anti_forensics'],
                'estimated_time': 20,
                'success_rate': 0.6,
                'output': '无痕迹退出',
            },
        ]

        # 根据目标调整
        if starting_point:
            # 从指定点开始，跳过前面的步骤
            start_idx = 0
            for i, step in enumerate(standard_steps):
                if starting_point.lower() in step['name'].lower():
                    start_idx = i
                    break
            steps = standard_steps[start_idx:]
        else:
            steps = standard_steps

        # 根据目标调整
        if goal == "initial_access":
            steps = steps[:4]  # 只到初始访问
        elif goal == "data_exfiltration":
            steps = steps[:8]  # 到数据收集

        return steps

    # ============== 持续学习 ==============

    def record_experience(self, scenario: str, action: str, outcome: str,
                           success: bool, reward: float = 0.0,
                           context: Dict[str, Any] = None,
                           learning_type: LearningType = LearningType.EXPERIENCE) -> LearningExperience:
        """记录学习经验"""
        # 生成学习模式
        learned_pattern = self._extract_pattern(scenario, action, outcome, success)

        # 计算置信度
        confidence = min(1.0, reward if reward > 0 else (0.8 if success else 0.3))

        experience = LearningExperience(
            experience_id=str(uuid.uuid4()),
            learning_type=learning_type,
            scenario=scenario,
            action=action,
            outcome=outcome,
            success=success,
            reward=reward,
            context=context or {},
            learned_pattern=learned_pattern,
            confidence=confidence,
        )

        self._experiences.append(experience)
        if len(self._experiences) > 10000:
            self._experiences = self._experiences[-10000:]

        # 更新知识库
        if learned_pattern:
            self._knowledge_base.add_pattern(learned_pattern, 1.0 if success else 0.0)

        self._save_experiences()
        logger.info(f"记录学习经验: {scenario} -> {'成功' if success else '失败'}, 模式: {learned_pattern}")
        return experience

    def _extract_pattern(self, scenario: str, action: str, outcome: str, success: bool) -> str:
        """提取学习模式"""
        # 简单的模式提取：场景+动作组合
        pattern = f"{scenario}_{action}"
        return pattern.lower().replace(' ', '_')

    def get_learning_stats(self) -> Dict[str, Any]:
        """获取学习统计"""
        total = len(self._experiences)
        success = len([e for e in self._experiences if e.success])
        failure = total - success

        by_type = defaultdict(int)
        for exp in self._experiences:
            by_type[exp.learning_type.value] += 1

        avg_reward = sum(e.reward for e in self._experiences) / total if total > 0 else 0
        avg_confidence = sum(e.confidence for e in self._experiences) / total if total > 0 else 0

        # 决策统计
        decision_success_rate = (self._successful_decisions / self._total_decisions * 100) if self._total_decisions > 0 else 0

        return {
            'total_experiences': total,
            'success_count': success,
            'failure_count': failure,
            'success_rate': round(success / total * 100, 1) if total > 0 else 0,
            'by_type': dict(by_type),
            'avg_reward': round(avg_reward, 2),
            'avg_confidence': round(avg_confidence, 2),
            'total_decisions': self._total_decisions,
            'decision_success_rate': round(decision_success_rate, 1),
            'attack_paths': len(self._attack_paths),
            'vuln_priorities': len(self._vuln_priorities),
            'learning_enabled': self._learning_enabled,
        }

    # ============== 决策反馈 ==============

    def feedback_decision(self, decision_id: str, success: bool,
                          actual_outcome: str = "", reward: float = 0.0) -> bool:
        """决策反馈"""
        decision = self._decisions.get(decision_id)
        if not decision:
            return False

        decision.success = success
        decision.actual_outcome = actual_outcome
        decision.completed_at = time.time()

        if success:
            self._successful_decisions += 1

        # 记录学习经验
        self.record_experience(
            scenario=decision.decision_type.value,
            action=decision.title,
            outcome=actual_outcome,
            success=success,
            reward=reward,
            context=decision.context,
        )

        self._save_decisions()
        return True

    # ============== 持久化 ==============

    def _load_decisions(self):
        if os.path.exists(self.decisions_file):
            try:
                with open(self.decisions_file, 'r', encoding='utf-8') as f:
                    for data in json.load(f):
                        decision = Decision(**{k: v for k, v in data.items() if k in Decision.__dataclass_fields__})
                        if isinstance(decision.decision_type, str):
                            decision.decision_type = DecisionType(decision.decision_type)
                        if isinstance(decision.confidence, str):
                            decision.confidence = ConfidenceLevel(decision.confidence)
                        self._decisions[decision.decision_id] = decision
                        self._total_decisions += 1
                        if decision.success:
                            self._successful_decisions += 1
            except Exception as e:
                logger.warning(f"加载决策数据失败: {e}")

    def _load_experiences(self):
        if os.path.exists(self.experiences_file):
            try:
                with open(self.experiences_file, 'r', encoding='utf-8') as f:
                    for data in json.load(f):
                        exp = LearningExperience(**{k: v for k, v in data.items() if k in LearningExperience.__dataclass_fields__})
                        if isinstance(exp.learning_type, str):
                            exp.learning_type = LearningType(exp.learning_type)
                        self._experiences.append(exp)
            except Exception as e:
                logger.warning(f"加载学习经验失败: {e}")

    def _save_decisions(self):
        try:
            with open(self.decisions_file, 'w', encoding='utf-8') as f:
                json.dump([d.to_dict() for d in list(self._decisions.values())[-1000:]], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存决策数据失败: {e}")

    def _save_experiences(self):
        try:
            with open(self.experiences_file, 'w', encoding='utf-8') as f:
                json.dump([e.to_dict() for e in self._experiences[-1000:]], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存学习经验失败: {e}")


# 全局AI决策引擎实例
_global_ai_engine: Optional[AIDecisionEngine] = None


def get_ai_engine() -> AIDecisionEngine:
    """获取全局AI决策引擎实例"""
    global _global_ai_engine
    if _global_ai_engine is None:
        _global_ai_engine = AIDecisionEngine()
    return _global_ai_engine
