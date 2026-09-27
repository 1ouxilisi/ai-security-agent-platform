"""
16专家Agent编排器 v2 - 按Kill Chain自动调度
对标Decepticon的OPPLAN作战计划编排
功能：自动生成作战计划、按阶段调度Agent、收集汇总结果、生成交战纪律(RoE)
"""
import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from .specialist_agents import (
    ALL_SPECIALIST_AGENTS,
    AGENTS_BY_PHASE,
    BaseSpecialistAgent,
    AgentResult,
    KillChainPhase,
    get_agent_by_name,
)


@dataclass
class EngagementPlan:
    """作战计划 (OPPLAN)"""
    target: str
    phases: list = field(default_factory=list)  # 按顺序的阶段列表
    agent_assignments: dict = field(default_factory=dict)  # phase -> [agent_names]
    rules_of_engagement: list = field(default_factory=list)  # RoE交战纪律
    scope: dict = field(default_factory=dict)  # 范围定义
    deconfliction: list = field(default_factory=list)  # 冲突消解
    created_at: float = 0.0


@dataclass
class EngagementResult:
    """作战结果"""
    target: str
    plan: Optional[EngagementPlan] = None
    phase_results: dict = field(default_factory=dict)  # phase -> [AgentResult]
    all_findings: list = field(default_factory=list)
    total_duration: float = 0.0
    status: str = "pending"  # pending/running/completed/failed
    summary: dict = field(default_factory=dict)


class AgentOrchestratorV2:
    """
    16专家Agent编排器
    按MITRE Kill Chain自动调度，生成作战计划和交战纪律
    对标Decepticon的OPPLAN + RoE八件套
    """

    # Kill Chain执行顺序
    KILL_CHAIN_ORDER = [
        KillChainPhase.RECONNAISSANCE,
        KillChainPhase.INITIAL_ACCESS,
        KillChainPhase.EXECUTION,
        KillChainPhase.PERSISTENCE,
        KillChainPhase.PRIVILEGE_ESCALATION,
        KillChainPhase.DEFENSE_EVASION,
        KillChainPhase.CREDENTIAL_ACCESS,
        KillChainPhase.DISCOVERY,
        KillChainPhase.LATERAL_MOVEMENT,
        KillChainPhase.COLLECTION,
        KillChainPhase.COMMAND_AND_CONTROL,
        KillChainPhase.EXFILTRATION,
    ]

    def __init__(self, llm_client=None, tool_registry=None,
                 max_concurrent_agents: int = 3,
                 enable_post_exploitation: bool = False):
        self.llm_client = llm_client
        self.tool_registry = tool_registry
        self.max_concurrent = max_concurrent_agents
        self.enable_post_exploitation = enable_post_exploitation  # 是否启用后渗透（默认关闭，安全考虑）
        self._agents = {}  # name -> agent instance
        self._semaphore = asyncio.Semaphore(max_concurrent_agents)

    def generate_engagement_plan(self, target: str,
                                 scope: dict = None,
                                 custom_phases: list = None) -> EngagementPlan:
        """
        生成作战计划 (OPPLAN)
        对标Decepticon动手前生成RoE/OPPLAN/Deconfliction八件套
        """
        plan = EngagementPlan(
            target=target,
            scope=scope or {"ip_ranges": [], "domains": [], "exclusions": []},
            created_at=time.time(),
        )

        # 确定执行阶段
        if custom_phases:
            plan.phases = custom_phases
        else:
            # 默认只执行到初始访问+利用，后渗透需显式启用
            plan.phases = [KillChainPhase.RECONNAISSANCE, KillChainPhase.INITIAL_ACCESS]
            if self.enable_post_exploitation:
                plan.phases = self.KILL_CHAIN_ORDER[:]

        # 分配Agent
        for phase in plan.phases:
            phase_name = phase.value
            agents_in_phase = AGENTS_BY_PHASE.get(phase_name, [])
            plan.agent_assignments[phase_name] = [a.name for a in agents_in_phase]

        # 生成交战纪律 (RoE)
        plan.rules_of_engagement = self._generate_roe(target, scope)

        # 冲突消解
        plan.deconfliction = self._generate_deconfliction()

        return plan

    def _generate_roe(self, target: str, scope: dict) -> list:
        """生成交战纪律 (Rules of Engagement)"""
        return [
            f"目标范围: {target}",
            f"授权范围: {json.dumps(scope, ensure_ascii=False)}",
            "仅在获得书面授权的范围内执行测试",
            "禁止对生产系统造成拒绝服务(DoS)",
            "禁止修改/删除目标系统数据（读取除外）",
            "发现高危漏洞立即停止并报告，不进行进一步利用",
            "所有操作记录日志，保留可复现证据",
            "测试结束后清理所有测试痕迹和后门",
            "遵守《网络安全法》《数据安全法》《个人信息保护法》",
            "敏感数据（个人信息/商业秘密）不得外传",
        ]

    def _generate_deconfliction(self) -> list:
        """生成冲突消解策略"""
        return [
            "多Agent并发时使用独立会话，避免相互干扰",
            "同一目标端口不进行重复扫描",
            "侦察阶段完成后才进入利用阶段",
            "发现已被其他Agent标记的漏洞时跳过",
            "速率限制：单目标每秒请求不超过10次",
        ]

    async def run_engagement(self, target: str,
                             scope: dict = None,
                             custom_phases: list = None) -> EngagementResult:
        """
        执行完整作战流程
        """
        result = EngagementResult(target=target, status="running")

        # 1. 生成作战计划
        result.plan = self.generate_engagement_plan(target, scope, custom_phases)

        start_time = time.time()

        # 2. 按阶段执行
        for phase in result.plan.phases:
            phase_name = phase.value
            phase_results = []

            agent_names = result.plan.agent_assignments.get(phase_name, [])

            # 并发执行该阶段的Agent
            tasks = []
            for agent_name in agent_names:
                task = self._run_agent(agent_name, target, result.all_findings)
                tasks.append(task)

            if tasks:
                phase_results = await asyncio.gather(*tasks, return_exceptions=True)

            # 处理结果
            valid_results = []
            for r in phase_results:
                if isinstance(r, AgentResult):
                    valid_results.append(r)
                    result.all_findings.extend(r.findings)
                elif isinstance(r, Exception):
                    valid_results.append(AgentResult(
                        agent_name="unknown",
                        phase=phase_name,
                        status="failed",
                        error=str(r),
                    ))

            result.phase_results[phase_name] = valid_results

        result.total_duration = time.time() - start_time
        result.status = "completed"
        result.summary = self._generate_summary(result)

        return result

    async def _run_agent(self, agent_name: str, target: str,
                         shared_findings: list) -> AgentResult:
        """运行单个Agent（带并发控制）"""
        async with self._semaphore:
            agent_cls = get_agent_by_name(agent_name)
            if not agent_cls:
                return AgentResult(
                    agent_name=agent_name,
                    phase="unknown",
                    status="failed",
                    error=f"Agent {agent_name} not found",
                )

            agent = agent_cls(
                llm_client=self.llm_client,
                tool_registry=self.tool_registry,
            )

            # 传递共享发现作为上下文
            context = {"previous_findings": shared_findings[-50:]}  # 最近50条

            start = time.time()
            try:
                result = await agent.execute(target, context)
                result.duration_seconds = time.time() - start
                return result
            except Exception as e:
                return AgentResult(
                    agent_name=agent_name,
                    phase=agent.phase.value,
                    status="failed",
                    duration_seconds=time.time() - start,
                    error=str(e),
                )

    def _generate_summary(self, result: EngagementResult) -> dict:
        """生成执行摘要"""
        total_agents = 0
        success_count = 0
        failed_count = 0
        findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for phase_name, agent_results in result.phase_results.items():
            for ar in agent_results:
                total_agents += 1
                if ar.status == "success":
                    success_count += 1
                elif ar.status == "failed":
                    failed_count += 1

                for f in ar.findings:
                    sev = f.get("severity", "info").lower()
                    if sev in findings_by_severity:
                        findings_by_severity[sev] += 1

        return {
            "target": result.target,
            "total_duration_seconds": round(result.total_duration, 2),
            "phases_executed": len(result.phase_results),
            "total_agents": total_agents,
            "agents_success": success_count,
            "agents_failed": failed_count,
            "total_findings": len(result.all_findings),
            "findings_by_severity": findings_by_severity,
            "status": result.status,
        }

    def generate_report(self, result: EngagementResult) -> dict:
        """生成完整作战报告"""
        return {
            "engagement_summary": result.summary,
            "rules_of_engagement": result.plan.rules_of_engagement if result.plan else [],
            "deconfliction": result.plan.deconfliction if result.plan else [],
            "phase_results": {
                phase: [
                    {
                        "agent": ar.agent_name,
                        "status": ar.status,
                        "findings_count": len(ar.findings),
                        "duration": round(ar.duration_seconds, 2),
                        "error": ar.error,
                        "findings": ar.findings[:10],  # 最多展示10条
                    }
                    for ar in results
                ]
                for phase, results in result.phase_results.items()
            },
            "all_findings": result.all_findings,
        }

    def to_json(self, result: EngagementResult, indent: int = 2) -> str:
        """导出JSON报告"""
        return json.dumps(self.generate_report(result), indent=indent, ensure_ascii=False, default=str)


# 便捷函数
async def quick_recon(target: str, llm_client=None) -> EngagementResult:
    """快速侦察模式：只执行侦察阶段4个Agent"""
    orchestrator = AgentOrchestratorV2(llm_client=llm_client)
    return await orchestrator.run_engagement(
        target,
        custom_phases=[KillChainPhase.RECONNAISSANCE],
    )


async def full_engagement(target: str, llm_client=None,
                          enable_post_exploit: bool = False) -> EngagementResult:
    """完整作战模式"""
    orchestrator = AgentOrchestratorV2(
        llm_client=llm_client,
        enable_post_exploitation=enable_post_exploit,
    )
    return await orchestrator.run_engagement(target)


if __name__ == "__main__":
    # 测试：列出所有Agent和阶段
    print("=" * 60)
    print("16专家Agent编排器 v2 - 对标Decepticon OPPLAN")
    print("=" * 60)

    orchestrator = AgentOrchestratorV2()
    plan = orchestrator.generate_engagement_plan("example.com")

    print(f"\n目标: {plan.target}")
    print(f"执行阶段: {[p.value for p in plan.phases]}")
    print(f"\n交战纪律 (RoE):")
    for i, rule in enumerate(plan.rules_of_engagement, 1):
        print(f"  {i}. {rule}")

    print(f"\nAgent分配:")
    for phase, agents in plan.agent_assignments.items():
        print(f"  [{phase}] {agents}")

    print(f"\n总计: {len(ALL_SPECIALIST_AGENTS)}个专家Agent, {len(AGENTS_BY_PHASE)}个Kill Chain阶段")
