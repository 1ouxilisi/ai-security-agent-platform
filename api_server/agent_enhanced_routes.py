"""
增强型AI智能体API路由（第二轮升级）
- /api/v1/agents-enhanced/run - 运行增强型智能体（自主规划+动态调整）
- /api/v1/agents-enhanced/plan - 仅生成执行计划
- /api/v1/agents-enhanced/orchestrator/pipeline - 多智能体流水线执行
- /api/v1/agents-enhanced/status - 获取智能体状态
"""

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.enhanced_agent import EnhancedAgent, AgentOrchestrator

router = APIRouter(prefix="/api/v1/agents-enhanced", tags=["增强型AI智能体"])

API_AUTH_KEY = os.getenv("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_AUTH_KEY:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return True


class AgentRunRequest(BaseModel):
    goal: str
    agent_type: str = "recon"  # recon/exploit/verification/report
    max_iterations: int = 10


class AgentPlanRequest(BaseModel):
    goal: str
    agent_type: str = "recon"


class PipelineRequest(BaseModel):
    tasks: List[Dict[str, str]]  # [{"agent_type": "recon", "goal": "..."}, ...]


@router.post("/run")
async def run_enhanced_agent(
    request: AgentRunRequest,
    x_api_key: Optional[str] = Header(None)
):
    """运行增强型AI智能体（自主规划+动态调整+多轮ReAct推理+反思机制）"""
    verify_api_key(x_api_key)
    try:
        agent = EnhancedAgent(agent_type=request.agent_type)
        result = agent.run(request.goal)
        return {
            "status": "success",
            "agent_type": request.agent_type,
            "goal": request.goal,
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/plan")
async def generate_plan(
    request: AgentPlanRequest,
    x_api_key: Optional[str] = Header(None)
):
    """仅生成执行计划（不实际执行）"""
    verify_api_key(x_api_key)
    try:
        agent = EnhancedAgent(agent_type=request.agent_type)
        plan = agent._plan_with_rules(request.goal)
        plan_data = [
            {
                "step_id": step.step_id,
                "description": step.description,
                "tool": step.tool,
                "parameters": step.parameters,
                "status": step.status
            }
            for step in plan
        ]
        return {
            "status": "success",
            "agent_type": request.agent_type,
            "goal": request.goal,
            "plan_steps": len(plan_data),
            "plan": plan_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/orchestrator/pipeline")
async def run_pipeline(
    request: PipelineRequest,
    x_api_key: Optional[str] = Header(None)
):
    """多智能体流水线执行（Recon→Exploit→Verification→Report）"""
    verify_api_key(x_api_key)
    try:
        orchestrator = AgentOrchestrator()
        result = orchestrator.run_pipeline(request.tasks)
        return {
            "status": "success",
            "task_count": len(request.tasks),
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_agent_status(x_api_key: Optional[str] = Header(None)):
    """获取智能体状态信息"""
    verify_api_key(x_api_key)
    try:
        agent = EnhancedAgent(agent_type="recon")
        return {
            "status": "success",
            "agent_state": agent.state.value,
            "agent_type": agent.agent_type,
            "memory_size": len(agent.memory.short_term) if hasattr(agent.memory, 'short_term') else 0,
            "features": [
                "自主规划（LLM+规则引擎兜底）",
                "动态调整策略",
                "多轮ReAct推理循环",
                "反思和自我纠正机制",
                "任务自动分解",
                "工具自动选择和调用",
                "重试机制（最多3次）"
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
