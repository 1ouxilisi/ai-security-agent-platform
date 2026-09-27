# -*- coding: utf-8 -*-
"""
security_kg_routes.py — 安全知识图谱与智能推理 REST API（第27轮升级方向1）。

路由前缀：/api/v1/security-kg
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹；TASKS 内存字典模拟异步任务。
覆盖 7 大模块 60+ 端点。
"""
from __future__ import annotations

import logging
import os
import re
import sys
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)

# ---------------- 模块导入（try-import 兜底） ----------------
_MOD_OK = False
try:
    from security_kg.kg_builder import (
        kg_builder, ENTITY_TYPES, RELATION_TYPES,
    )
    from security_kg.attack_path import attack_path_engine
    from security_kg.vuln_correlation import vuln_correlation
    from security_kg.threat_propagation import threat_propagation
    from security_kg.reasoning_engine import (
        reasoning_engine, ReasoningRule,
    )
    from security_kg.kg_qa import kg_qa
    from security_kg.kg_dashboard import kg_dashboard, SYSTEM_SETTINGS
    _MOD_OK = True
except Exception as _e:  # pragma: no cover
    logger.exception("security_kg_routes 模块加载失败: %s", _e)
    kg_builder = None  # type: ignore
    attack_path_engine = None  # type: ignore
    vuln_correlation = None  # type: ignore
    threat_propagation = None  # type: ignore
    reasoning_engine = None  # type: ignore
    kg_qa = None  # type: ignore
    kg_dashboard = None  # type: ignore
    SYSTEM_SETTINGS = {}  # type: ignore


router = APIRouter(prefix="/api/v1/security-kg",
                   tags=["安全知识图谱与智能推理"])


# ---------------- 响应工具 ----------------
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return _CTRL_RE.sub("", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(x) for x in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(err: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": str(err)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_OK:
        return fail("security_kg 模块未加载", 503)
    return None


# ---------------- 异步任务（内存字典） ----------------
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    tid = f"task-{uuid.uuid4().hex[:10]}"
    TASKS[tid] = {
        "id": tid, "kind": kind, "status": "queued",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "finished_at": None, "result": None, "error": None,
    }
    return tid


def _finish(tid: str, result: Any = None, err: Optional[str] = None) -> None:
    if tid in TASKS:
        TASKS[tid]["status"] = "done" if not err else "error"
        TASKS[tid]["result"] = result
        TASKS[tid]["error"] = err
        TASKS[tid]["finished_at"] = datetime.now().isoformat(timespec="seconds")


# ---------------- Pydantic 请求模型 ----------------
class EntityReq(BaseModel):
    etype: str
    name: str
    props: Dict[str, Any] = Field(default_factory=dict)


class EdgeReq(BaseModel):
    source: str
    target: str
    relation: str
    weight: float = 1.0
    confidence: float = 0.9
    props: Dict[str, Any] = Field(default_factory=dict)


class ExtractReq(BaseModel):
    text: str


class AlignReq(BaseModel):
    a: str
    b: str
    merge: bool = False


class PathReq(BaseModel):
    src: str
    dst: str
    max_depth: int = 6


class PathListReq(BaseModel):
    path: List[str]


class PredictReq(BaseModel):
    node: str
    top_k: int = 5


class VulnReq(BaseModel):
    id: Optional[str] = None
    cve: Optional[str] = None
    name: str = ""
    cvss: float = 5.0
    epss: float = 0.1
    vendor: str = ""
    product: str = ""
    cwe: str = ""
    type: str = "Unknown"
    asset: str = ""
    exposed: bool = False
    status: str = "open"
    fix_difficulty: float = 0.5
    business_value: float = 0.5


class SIRReq(BaseModel):
    beta: float = 0.5
    gamma: float = 0.1
    initial_infected: int = 1
    total: int = 100
    days: int = 60


class SEIRReq(BaseModel):
    beta: float = 0.5
    sigma: float = 0.3
    gamma: float = 0.1
    total: int = 100
    days: int = 80


class CascadeReq(BaseModel):
    seeds: List[str]
    threshold: float = 0.3
    rounds: int = 10


class MCSimReq(BaseModel):
    runs: int = 50
    beta: float = 0.5
    gamma: float = 0.1
    total: int = 50


class RuleReq(BaseModel):
    id: str
    name: str
    desc: str = ""
    condition: str = ""
    conclusion: str = ""
    confidence: float = 0.8
    priority: int = 5


class BackwardReq(BaseModel):
    goal: str


class MultiHopReq(BaseModel):
    start: str
    hops: int = 2
    relation: Optional[str] = None


class AskReq(BaseModel):
    question: str
    user: str = "anonymous"


class FAQReq(BaseModel):
    q: str
    a: str
    category: str = "通用"
    tags: List[str] = Field(default_factory=list)


class FeedbackReq(BaseModel):
    rating: int = 5
    comment: str = ""


class SearchReq(BaseModel):
    query: str
    top_k: int = 5


class SettingsReq(BaseModel):
    updates: Dict[str, Any] = Field(default_factory=dict)


# ============================================================
# 1. 控制台 / 总览（9 个）
# ============================================================
@router.get("/overview")
def overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_dashboard.overview())
    except Exception as e:  # noqa: BLE001
        logger.exception("overview error")
        return fail(str(e))


@router.get("/graph-section")
def graph_section():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_dashboard.graph_section())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/attack-path-section")
def attack_path_section():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_dashboard.attack_path_section())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/vuln-section")
def vuln_section():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_dashboard.vuln_section())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/propagation-section")
def propagation_section():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_dashboard.propagation_section())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/reasoning-section")
def reasoning_section():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_dashboard.reasoning_section())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/qa-section")
def qa_section():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_dashboard.qa_section())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/settings")
def get_settings():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_dashboard.settings())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/settings")
def update_settings(req: SettingsReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_dashboard.update_settings(req.updates))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# ============================================================
# 2. 实体管理（10 个）
# ============================================================
@router.get("/entity-types")
def entity_types():
    try:
        return ok(ENTITY_TYPES)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/entities")
def list_entities(etype: Optional[str] = None,
                  keyword: Optional[str] = None,
                  limit: int = 200):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.list_entities(etype=etype, keyword=keyword,
                                            limit=limit))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/entities")
def add_entity(req: EntityReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.add_entity(req.etype, req.name, req.props))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/entities/{eid}")
def get_entity(eid: str):
    try:
        g = _guard()
        if g:
            return g
        e = kg_builder.get_entity(eid)
        if not e:
            return fail("实体不存在", 404)
        return ok(e)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.put("/entities/{eid}")
def update_entity(eid: str, props: Dict[str, Any] = Body(...)):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.update_entity(eid, props))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.delete("/entities/{eid}")
def delete_entity(eid: str):
    try:
        g = _guard()
        if g:
            return g
        return ok({"deleted": kg_builder.delete_entity(eid)})
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/entities/{eid}/neighbors")
def entity_neighbors(eid: str, direction: str = "both"):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.neighbors(eid, direction))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/extract")
def extract(req: ExtractReq):
    try:
        g = _guard()
        if g:
            return g
        ents = kg_builder.extract_entities(req.text)
        rels = kg_builder.extract_relations(req.text)
        return ok({"entities": ents, "relations": rels})
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/entity-align")
def entity_align(req: AlignReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.entity_align(req.a, req.b, req.merge))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/entity-align-task")
def entity_align_task(req: AlignReq):
    try:
        g = _guard()
        if g:
            return g
        tid = _new_task("entity_align")
        result = kg_builder.entity_align(req.a, req.b, req.merge)
        _finish(tid, result)
        return ok({"task_id": tid})
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# ============================================================
# 3. 关系管理 / 图谱构建（8 个）
# ============================================================
@router.get("/relation-types")
def relation_types():
    return ok(RELATION_TYPES)


@router.get("/edges")
def list_edges(relation: Optional[str] = None,
              src: Optional[str] = None,
              dst: Optional[str] = None,
              limit: int = 500):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.list_edges(relation=relation, src=src,
                                         dst=dst, limit=limit))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/edges")
def add_edge(req: EdgeReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.add_relation(req.source, req.target,
                                            req.relation, req.weight,
                                            req.confidence, req.props))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/relation-align")
def relation_align():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.relation_align())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/completion")
def completion():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.knowledge_completion())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/cleanse")
def cleanse():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.knowledge_cleanse())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/validate")
def validate():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.knowledge_validate())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/stats")
def stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.stats())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/quality")
def quality():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.quality_report())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/snapshot")
def snapshot():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_builder.snapshot())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/reset")
def reset_graph():
    try:
        g = _guard()
        if g:
            return g
        kg_builder.reset()
        return ok({"reset": True})
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# ============================================================
# 4. 攻击路径（11 个）
# ============================================================
@router.post("/attack-path/shortest")
def ap_shortest(req: PathReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(attack_path_engine.shortest_path(req.src, req.dst))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/attack-path/astar")
def ap_astar(req: PathReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(attack_path_engine.astar_path(req.src, req.dst))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/attack-path/all")
def ap_all(req: PathReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(attack_path_engine.all_paths(req.src, req.dst,
                                               max_depth=req.max_depth))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/attack-path/probabilistic")
def ap_prob(req: PathReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(attack_path_engine.probabilistic_path(req.src, req.dst))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/attack-path/risk")
def ap_risk(req: PathReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(attack_path_engine.risk_path(req.src, req.dst))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/attack-path/analyze")
def ap_analyze(req: PathListReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(attack_path_engine.analyze_path(req.path))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/attack-path/predict-next")
def ap_predict(req: PredictReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(attack_path_engine.predict_next(req.node, req.top_k))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/attack-path/kill-chain")
def ap_kill_chain(req: PathListReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(attack_path_engine.map_kill_chain(req.path))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/attack-path/tree")
def ap_tree(req: PredictReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(attack_path_engine.attack_tree(req.node, max_depth=req.top_k))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/attack-path/validate")
def ap_validate(req: PathListReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(attack_path_engine.validate_path(req.path))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/attack-path/visualization")
def ap_visualization():
    try:
        g = _guard()
        if g:
            return g
        return ok(attack_path_engine.visualization_data())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# ============================================================
# 5. 漏洞关联（10 个）
# ============================================================
@router.get("/vulns")
def list_vulns(status: Optional[str] = None,
                severity: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(vuln_correlation.list_vulns(status=status,
                                               severity=severity))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/vulns")
def add_vuln(req: VulnReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(vuln_correlation.add_vuln(req.model_dump()))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/vulns/{vid}/correlate")
def correlate_vuln(vid: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(vuln_correlation.correlate(vid))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/vulns/{vid}/propagation")
def vuln_propagation(vid: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(vuln_correlation.propagation(vid))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/vulns/{vid}/impact")
def vuln_impact(vid: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(vuln_correlation.impact(vid))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/vulns-priorities")
def vuln_priorities():
    try:
        g = _guard()
        if g:
            return g
        return ok(vuln_correlation.prioritize())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/vulns-trend")
def vuln_trend():
    try:
        g = _guard()
        if g:
            return g
        return ok(vuln_correlation.trend())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/vulns-kb")
def vuln_kb(vid: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(vuln_correlation.knowledge_base(vid))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/vulns-combined")
def vuln_combined():
    try:
        g = _guard()
        if g:
            return g
        return ok(vuln_correlation.combined_priority())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/vulns/{vid}")
def get_vuln(vid: str):
    try:
        g = _guard()
        if g:
            return g
        v = vuln_correlation.vulns.get(vid)
        if not v:
            return fail("漏洞不存在", 404)
        return ok(v)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# ============================================================
# 6. 威胁传播（9 个）
# ============================================================
@router.post("/propagation/sir")
def prop_sir(req: SIRReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(threat_propagation.sir(beta=req.beta, gamma=req.gamma,
                                          initial_infected=req.initial_infected,
                                          total=req.total, days=req.days))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/propagation/seir")
def prop_seir(req: SEIRReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(threat_propagation.seir(beta=req.beta, sigma=req.sigma,
                                           gamma=req.gamma, total=req.total,
                                           days=req.days))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/propagation/cascade")
def prop_cascade(req: CascadeReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(threat_propagation.network_cascade(req.seeds,
                                                      threshold=req.threshold,
                                                      rounds=req.rounds))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/propagation/paths/{seed}")
def prop_paths(seed: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(threat_propagation.propagation_paths(seed))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/propagation/impact/{seed}")
def prop_impact(seed: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(threat_propagation.impact_assessment(seed))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/propagation/blocking")
def prop_blocking(seed: str = "Web"):
    try:
        g = _guard()
        if g:
            return g
        return ok(threat_propagation.blocking_strategies(seed))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/propagation/monte-carlo")
def prop_mc(req: MCSimReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(threat_propagation.monte_carlo(runs=req.runs,
                                                  beta=req.beta,
                                                  gamma=req.gamma,
                                                  total=req.total))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/propagation/sensitivity")
def prop_sensitivity():
    try:
        g = _guard()
        if g:
            return g
        return ok(threat_propagation.sensitivity())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/propagation/visualization")
def prop_visualization():
    try:
        g = _guard()
        if g:
            return g
        return ok(threat_propagation.visualization())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# ============================================================
# 7. 推理引擎（9 个）
# ============================================================
@router.get("/reasoning/rules")
def list_rules():
    try:
        g = _guard()
        if g:
            return g
        return ok(reasoning_engine.list_rules())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/reasoning/rules")
def add_rule(req: RuleReq):
    try:
        g = _guard()
        if g:
            return g
        r = ReasoningRule(req.id, req.name, req.desc, req.condition,
                          req.conclusion, req.confidence, req.priority)
        return ok(reasoning_engine.add_rule(r))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/reasoning/forward")
def forward():
    try:
        g = _guard()
        if g:
            return g
        return ok(reasoning_engine.forward_chain())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/reasoning/backward")
def backward(req: BackwardReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(reasoning_engine.backward_chain(req.goal))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/reasoning/multi-hop")
def multi_hop(req: MultiHopReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(reasoning_engine.multi_hop(req.start, req.hops,
                                              req.relation))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/reasoning/uncertainty")
def uncertainty():
    try:
        g = _guard()
        if g:
            return g
        return ok(reasoning_engine.uncertain_reasoning())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/reasoning/validate")
def reasoning_validate():
    try:
        g = _guard()
        if g:
            return g
        return ok(reasoning_engine.validate())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/reasoning/predict")
def reasoning_predict():
    try:
        g = _guard()
        if g:
            return g
        return ok(reasoning_engine.predict_attack())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/reasoning/recommendations")
def reasoning_recs():
    try:
        g = _guard()
        if g:
            return g
        return ok(reasoning_engine.recommendations())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# ============================================================
# 8. 智能问答（8 个）
# ============================================================
@router.post("/qa/ask")
def qa_ask(req: AskReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_qa.ask(req.question, req.user))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/qa/faq")
def qa_faq():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_qa.list_faq())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/qa/faq")
def qa_add_faq(req: FAQReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_qa.add_faq(req.q, req.a, req.category, req.tags))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/qa/history")
def qa_history(limit: int = 20):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_qa.history_list(limit=limit))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/qa/{qa_id}/feedback")
def qa_feedback(qa_id: str, req: FeedbackReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_qa.feedback(qa_id, req.rating, req.comment))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/qa/statistics")
def qa_stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_qa.statistics())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/qa/search")
def qa_search(req: SearchReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_qa.search(req.query, req.top_k))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/qa/multi-hop")
def qa_multi_hop(req: MultiHopReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(kg_qa.multi_hop_search(req.start, req.hops))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# ============================================================
# 9. 异步任务（3 个）
# ============================================================
@router.get("/tasks/{tid}")
def get_task(tid: str):
    try:
        if tid not in TASKS:
            return fail("任务不存在", 404)
        return ok(TASKS[tid])
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/tasks")
def list_tasks(limit: int = 50):
    try:
        items = list(TASKS.values())[-limit:]
        return ok(items)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/tasks/run")
def run_task(kind: str = Body(...),
              payload: Dict[str, Any] = Body(default_factory=dict)):
    try:
        g = _guard()
        if g:
            return g
        tid = _new_task(kind)
        # 简单执行器
        try:
            if kind == "extract":
                result = kg_builder.extract_entities(payload.get("text", ""))
            elif kind == "completion":
                result = kg_builder.knowledge_completion()
            elif kind == "cleanse":
                result = kg_builder.knowledge_cleanse()
            elif kind == "forward_chain":
                result = reasoning_engine.forward_chain()
            else:
                result = {"kind": kind, "echo": payload}
            _finish(tid, result)
        except Exception as e:  # noqa: BLE001
            _finish(tid, err=str(e))
        return ok(TASKS[tid])
    except Exception as e:  # noqa: BLE001
        return fail(str(e))
