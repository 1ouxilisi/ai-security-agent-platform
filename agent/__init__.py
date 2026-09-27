"""
AI智能体核心模块 - 规划、执行、记忆、报告
包含16专家Agent编队（对标Decepticon）和Kill Chain编排器

核心能力：
- specialist_agents: 16个专家Agent按MITRE Kill Chain分工
- orchestrator_v2: 作战计划生成(OPPLAN)+交战纪律(RoE)+自动编排
- base_agent: Agent基类
- multi_agent: 多Agent协作
- planner: 任务规划
- executor: 工具执行
- poc_verifier: PoC验证
"""

from .specialist_agents import (
    ALL_SPECIALIST_AGENTS,
    AGENTS_BY_PHASE,
    BaseSpecialistAgent,
    AgentResult,
    AgentTool,
    KillChainPhase,
    get_agent_by_name,
    list_all_agents,
    # 16个专家Agent
    ScoutAgent, MapperAgent, SpiderAgent, FingerprinterAgent,
    PhisherAgent, ExploiterAgent,
    ExecutionAgent,
    PersisterAgent,
    PrivescAgent,
    EvaderAgent,
    CredHunterAgent,
    DiscovererAgent,
    LateralMoverAgent,
    CollectorAgent,
    C2OperatorAgent,
    ExfiltratorAgent,
)

from .orchestrator_v2 import (
    AgentOrchestratorV2,
    EngagementPlan,
    EngagementResult,
    quick_recon,
    full_engagement,
)

__all__ = [
    # 专家Agent编队
    "ALL_SPECIALIST_AGENTS",
    "AGENTS_BY_PHASE",
    "BaseSpecialistAgent",
    "AgentResult",
    "AgentTool",
    "KillChainPhase",
    "get_agent_by_name",
    "list_all_agents",
    # 16个Agent
    "ScoutAgent", "MapperAgent", "SpiderAgent", "FingerprinterAgent",
    "PhisherAgent", "ExploiterAgent",
    "ExecutionAgent",
    "PersisterAgent",
    "PrivescAgent",
    "EvaderAgent",
    "CredHunterAgent",
    "DiscovererAgent",
    "LateralMoverAgent",
    "CollectorAgent",
    "C2OperatorAgent",
    "ExfiltratorAgent",
    # 编排器
    "AgentOrchestratorV2",
    "EngagementPlan",
    "EngagementResult",
    "quick_recon",
    "full_engagement",
]

__version__ = "2.0.0"
