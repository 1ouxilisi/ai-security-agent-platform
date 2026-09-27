#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多领域智能体编排层（Multi-Domain Agent Orchestrator）

借鉴架构：
- T3MP3ST (elder-plinius): 8角色多智能体红队编排，War Room界面
- RedAmon (samugit83): Fireteam模式，根智能体扇出为多个专家子智能体并行
- PentAGI (VXControl): 容器化沙箱，多智能体协作
- Strix (usestrix): 强化学习训练专用渗透模型

核心设计：
1. 12大安全领域：Web安全、移动安全、云安全、区块链安全、AI安全、
   内网渗透/AD、二进制逆向/恶意软件、无线网络、工控ICS/SCADA、
   物联网IoT、社会工程学、数字取证
2. 每个领域有专门的智能体编队（4-6个专家Agent），共59个Agent
3. 统一编排器支持：
   - 单领域执行
   - 多领域并行（Fireteam模式）
   - 跨领域协作（12条攻击链联动）
4. 8个通用角色映射MITRE ATT&CK：
   Recon(侦察) / Scanner(扫描) / Exploiter(利用) / Infiltrator(渗透)
   Exfiltrator(渗出) / Ghost(隐匿) / Coordinator(协调) / Analyst(分析)
5. 67个真实工具检测，跨平台工具可用性检测
"""

from .orchestrator import (
    MultiDomainOrchestrator,
    SecurityDomain,
    AgentRole,
    DomainAgent,
    DomainMission,
    DomainAgentFactory,
    get_orchestrator,
)
from .tool_detector import DomainToolDetector, ToolInfo, get_detector
from .real_executor import MultiDomainRealExecutor, ToolResult, ToolStatus, get_executor
from .attack_chain_validator import AttackChainValidator, AttackChain, ChainStatus, RiskLevel, get_validator
from .intelligent_decision_engine import IntelligentDecisionEngine, ExecutionPlan, Action, Priority, ActionType, get_decision_engine
from .professional_report_generator import ProfessionalReportGenerator, ReportSection, get_report_generator
from .knowledge_graph import KnowledgeGraph, Entity, Relation, EntityType, RelationType, AttackPath, get_knowledge_graph
from .red_blue_green import RedBlueGreenEngine, RedTeam, BlueTeam, GreenTeam, TeamRole, AttackPhase, EngagementResult, get_rbg_engine
from .mitre_skills import MITRESkillLibrary, MITRESkill, MITRETactic, get_mitre_library
from .poc_generator import PoCGenerator, PoCResult, FixSuggestion, VulnType, get_poc_generator
from .agentic_security import AgenticSecurityTester, AgenticTestResult, AgenticVulnType, get_agentic_tester
from .taskflow_engine import TaskflowEngine, Taskflow, Task, TaskStatus, get_taskflow_engine

__all__ = [
    'MultiDomainOrchestrator',
    'SecurityDomain',
    'AgentRole',
    'DomainAgent',
    'DomainMission',
    'DomainAgentFactory',
    'get_orchestrator',
    'DomainToolDetector',
    'ToolInfo',
    'get_detector',
    'MultiDomainRealExecutor',
    'ToolResult',
    'ToolStatus',
    'get_executor',
    'AttackChainValidator',
    'AttackChain',
    'ChainStatus',
    'RiskLevel',
    'get_validator',
    'IntelligentDecisionEngine',
    'ExecutionPlan',
    'Action',
    'Priority',
    'ActionType',
    'get_decision_engine',
    'ProfessionalReportGenerator',
    'ReportSection',
    'get_report_generator',
    'KnowledgeGraph',
    'Entity',
    'Relation',
    'EntityType',
    'RelationType',
    'AttackPath',
    'get_knowledge_graph',
    'RedBlueGreenEngine',
    'RedTeam',
    'BlueTeam',
    'GreenTeam',
    'TeamRole',
    'AttackPhase',
    'EngagementResult',
    'get_rbg_engine',
    'MITRESkillLibrary',
    'MITRESkill',
    'MITRETactic',
    'get_mitre_library',
    'PoCGenerator',
    'PoCResult',
    'FixSuggestion',
    'VulnType',
    'get_poc_generator',
    'AgenticSecurityTester',
    'AgenticTestResult',
    'AgenticVulnType',
    'get_agentic_tester',
    'TaskflowEngine',
    'Taskflow',
    'Task',
    'TaskStatus',
    'get_taskflow_engine',
]

__version__ = '4.0.0'
