#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v4.7 新引擎 API路由（GitHub搜索升级）

- POST /api/v1/ai-v47/genetic-evolve — 遗传算法Prompt进化
- GET  /api/v1/ai-v47/genetic-result/{id} — 获取进化结果
- POST /api/v1/ai-v47/multi-turn — 多轮攻击编排
- GET  /api/v1/ai-v47/multi-turn-strategies — 查看攻击策略
- POST /api/v1/ai-v47/mcp-deep-scan — MCP服务器深度扫描
- GET  /api/v1/ai-v47/stats — 引擎统计
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import time

from ai_security_assessment import (
    get_evolver,
    get_multi_turn_orchestrator,
    EVOLVER_STRATEGIES,
    ENCODING_METHODS,
    CONTEXT_WRAPPERS,
    TARGET_INSTRUCTIONS,
    MULTI_TURN_STRATEGIES,
)
from mcp_security.deep_scanner import get_deep_mcp_scanner

router = APIRouter(prefix="/api/v1/ai-v47", tags=["v4.7 AI安全新引擎"])

_evolver = get_evolver()
_orchestrator = get_multi_turn_orchestrator()
_mcp_scanner = get_deep_mcp_scanner()

_genetic_results = {}
_multiturn_results = {}
_mcp_results = {}


# ============================================================
# 遗传算法 Prompt 进化
# ============================================================

class GeneticEvolveRequest(BaseModel):
    target: str = ""
    population_size: int = 20
    max_generations: int = 5
    mutation_rate: float = 0.3
    target_fitness: float = 0.7
    target_category: str = "reveal_system_prompt"


@router.post("/genetic-evolve")
async def genetic_evolve(req: GeneticEvolveRequest):
    """运行遗传算法Prompt进化"""
    try:
        result_id = f"genetic_{int(time.time()*1000)}"

        evolver = get_evolver()
        evolver.population_size = req.population_size
        evolver.max_generations = req.max_generations
        evolver.mutation_rate = req.mutation_rate
        evolver.target_fitness = req.target_fitness

        result = evolver.evolve(target_model=req.target or "unknown")
        _genetic_results[result_id] = result

        return {
            "success": True,
            "data": {
                "result_id": result_id,
                "generations_run": result.generations_run,
                "best_fitness": round(result.best_fitness, 3),
                "unique_attacks_found": result.unique_attacks_found,
                "fitness_history": [round(f, 3) for f in result.fitness_history],
                "best_attacks": evolver.get_best_attacks(10),
                "summary": evolver.get_evolution_summary(),
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/genetic-result/{result_id}")
async def get_genetic_result(result_id: str):
    """获取进化结果"""
    result = _genetic_results.get(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    return {
        "success": True,
        "data": {
            "generations_run": result.generations_run,
            "best_fitness": round(result.best_fitness, 3),
            "unique_attacks_found": result.unique_attacks_found,
            "successful_attacks": [
                {
                    "id": a.id,
                    "generation": a.generation,
                    "fitness": round(a.fitness, 3),
                    "success_type": a.success_type,
                    "gene": a.gene.to_dict(),
                    "prompt": a.prompt[:500],
                    "response_preview": a.response[:300] if a.response else "",
                }
                for a in result.successful_attacks[:20]
            ],
            "fitness_history": [round(f, 3) for f in result.fitness_history],
        }
    }


@router.get("/genetic-config")
async def get_genetic_config():
    """查看遗传算法配置选项"""
    return {
        "success": True,
        "data": {
            "attack_strategies": EVOLVER_STRATEGIES,
            "encoding_methods": ENCODING_METHODS,
            "context_wrappers": CONTEXT_WRAPPERS,
            "target_instructions": TARGET_INSTRUCTIONS,
            "total_gene_combinations": len(EVOLVER_STRATEGIES) * len(ENCODING_METHODS) * len(CONTEXT_WRAPPERS) * len(TARGET_INSTRUCTIONS),
        }
    }


# ============================================================
# 多轮攻击编排
# ============================================================

class MultiTurnRequest(BaseModel):
    strategy: str = "all"  # all / 具体策略名
    target: str = ""
    max_turns: int = 5
    adaptive: bool = True


@router.post("/multi-turn")
async def multi_turn_attack(req: MultiTurnRequest):
    """运行多轮攻击编排"""
    try:
        result_id = f"multiturn_{int(time.time()*1000)}"

        if req.strategy == "all":
            results = _orchestrator.run_all_strategies(target=req.target)
        else:
            if req.strategy not in MULTI_TURN_STRATEGIES:
                raise HTTPException(status_code=400, detail=f"Unknown strategy: {req.strategy}")
            result = _orchestrator.run_attack(
                strategy=req.strategy,
                target=req.target,
                max_turns=req.max_turns,
                adaptive=req.adaptive,
            )
            results = [result]

        _multiturn_results[result_id] = results

        return {
            "success": True,
            "data": {
                "result_id": result_id,
                "summary": _orchestrator.get_summary(),
                "results": [
                    {
                        "strategy": r.strategy,
                        "name": r.strategy_name,
                        "successful": r.is_successful,
                        "success_turn": r.success_turn,
                        "effectiveness": round(r.attack_effectiveness, 2),
                        "resistance": r.resistance_level,
                        "turns_count": len([t for t in r.turns if t.role == "user"]),
                    }
                    for r in results
                ],
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/multi-turn-strategies")
async def list_multi_turn_strategies():
    """查看多轮攻击策略"""
    strategies = []
    for key, val in MULTI_TURN_STRATEGIES.items():
        strategies.append({
            "id": key,
            "name": val["name"],
            "description": val["description"],
            "turns": len(val["turns"]),
        })
    return {"success": True, "data": {"strategies": strategies, "total": len(strategies)}}


@router.get("/multi-turn-result/{result_id}")
async def get_multi_turn_result(result_id: str):
    """获取多轮攻击详细结果"""
    results = _multiturn_results.get(result_id)
    if not results:
        raise HTTPException(status_code=404, detail="Result not found")
    return {
        "success": True,
        "data": {
            "results": [
                {
                    "strategy": r.strategy,
                    "name": r.strategy_name,
                    "successful": r.is_successful,
                    "extracted_data": r.extracted_data[:500],
                    "turns": [
                        {
                            "turn": t.turn_number,
                            "role": t.role,
                            "content": t.content[:300],
                            "goal": t.goal,
                            "analysis": t.response_analysis,
                            "progress": t.attack_progress,
                        }
                        for t in r.turns
                    ],
                }
                for r in results
            ]
        }
    }


# ============================================================
# MCP 服务器深度扫描
# ============================================================

class MCPDeepScanRequest(BaseModel):
    server_name: str
    tools: Optional[List[Dict]] = None
    source_code: str = ""
    config: str = ""


@router.post("/mcp-deep-scan")
async def mcp_deep_scan(req: MCPDeepScanRequest):
    """MCP服务器深度安全扫描"""
    try:
        result_id = f"mcp_{int(time.time()*1000)}"
        result = _mcp_scanner.scan_server(
            server_name=req.server_name,
            tools=req.tools,
            source_code=req.source_code,
            config=req.config,
        )
        _mcp_results[result_id] = result

        return {
            "success": True,
            "data": {
                "result_id": result_id,
                "server_name": result.server_name,
                "overall_risk": result.overall_risk_level,
                "risk_score": round(result.overall_risk_score, 2),
                "tools_found": result.tools_found,
                "tools": [t.to_dict() for t in result.tools],
                "taint_flows": [f.to_dict() for f in result.taint_flows],
                "attack_chains": [c.to_dict() for c in result.attack_chains],
                "malicious_patterns": result.malicious_patterns,
                "supply_chain_risks": result.supply_chain_risks,
                "recommendations": result.recommendations,
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mcp-report/{result_id}")
async def get_mcp_report(result_id: str):
    """获取MCP扫描报告"""
    result = _mcp_results.get(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    return {"success": True, "data": {"report": _mcp_scanner.get_report()}}


# ============================================================
# 统计
# ============================================================

@router.get("/stats")
async def get_v47_stats():
    """v4.7引擎统计"""
    return {
        "success": True,
        "data": {
            "genetic_evolver": {
                "attack_strategies": len(EVOLVER_STRATEGIES),
                "encoding_methods": len(ENCODING_METHODS),
                "context_wrappers": len(CONTEXT_WRAPPERS),
                "target_instructions": len(TARGET_INSTRUCTIONS),
                "total_combinations": len(EVOLVER_STRATEGIES) * len(ENCODING_METHODS) * len(CONTEXT_WRAPPERS) * len(TARGET_INSTRUCTIONS),
            },
            "multi_turn": {
                "strategies": len(MULTI_TURN_STRATEGIES),
                "strategy_names": [v["name"] for v in MULTI_TURN_STRATEGIES.values()],
            },
            "mcp_deep_scanner": {
                "dangerous_operations": 10,
                "attack_chain_templates": 5,
                "known_malicious_patterns": 7,
            },
        }
    }
