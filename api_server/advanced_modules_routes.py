#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高级模块 API路由 v1.0
集成6大核心模块：知识图谱、红蓝绿三角色、MITRE技能库、
PoC生成器、Agent安全测试、声明式任务流引擎
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from multi_domain import (
    get_knowledge_graph, get_rbg_engine, get_mitre_library,
    get_poc_generator, get_agentic_tester, get_taskflow_engine,
    MITRETactic,
)

router = APIRouter(prefix="/api/v1/advanced", tags=["高级模块"])


# ============ 请求模型 ============

class FindingsRequest(BaseModel):
    findings: List[Dict[str, Any]]
    target: str = "example.com"


class PoCRequest(BaseModel):
    vuln_type: str
    target: str
    param: str = "id"


class TaskflowExecuteRequest(BaseModel):
    flow_name: str  # web_pentest/internal_pentest/mobile_security/cloud_security/ai_agent_security
    context: Dict[str, Any] = {}


class AgenticTestRequest(BaseModel):
    categories: List[str] = []  # 空=全部
    target_agent: str = "default"


# ============ 1. 知识图谱记忆系统 ============

@router.post("/knowledge-graph/ingest")
async def kg_ingest_findings(req: FindingsRequest):
    """将发现导入知识图谱"""
    try:
        kg = get_knowledge_graph()
        entities = kg.extract_entities_from_findings(req.findings, source="api")
        stats = kg.get_statistics()
        return {"success": True, "data": {"entities_ingested": len(entities), "stats": stats}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/knowledge-graph/stats")
async def kg_stats():
    """获取知识图谱统计"""
    try:
        kg = get_knowledge_graph()
        return {"success": True, "data": kg.get_statistics()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/knowledge-graph/attack-paths")
async def kg_attack_paths():
    """获取攻击路径"""
    try:
        kg = get_knowledge_graph()
        paths = kg.find_attack_paths()
        return {
            "success": True,
            "data": {
                "paths": [
                    {"path": p.path, "risk_score": p.risk_score,
                     "description": p.description, "entities": p.entities}
                    for p in paths
                ],
                "total": len(paths),
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/knowledge-graph/query")
async def kg_query(req: Dict[str, Any]):
    """查询知识图谱实体"""
    try:
        kg = get_knowledge_graph()
        entity_type = req.get("entity_type")
        entities = kg.get_entities_by_type(entity_type) if entity_type else list(kg.entities.values())
        return {"success": True, "data": {"entities": [e.to_dict() for e in entities[:50]], "total": len(entities)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============ 2. 红蓝绿三角色架构 ============

@router.post("/rbg/engagement")
async def rbg_run_engagement(req: FindingsRequest):
    """运行红蓝绿对抗演练"""
    try:
        rbg = get_rbg_engine()
        result = rbg.run_engagement(req.target, req.findings)
        return {"success": True, "data": rbg.to_dict(result)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rbg/techniques")
async def rbg_techniques():
    """获取红队技术库"""
    try:
        rbg = get_rbg_engine()
        return {"success": True, "data": {"red_techniques": len(rbg.red_team.techniques),
                                          "blue_rules": len(rbg.blue_team.detection_rules),
                                          "green_fixes": len(rbg.green_team.fix_library)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============ 3. MITRE技能库 ============

@router.get("/mitre/skills")
async def mitre_list_skills(tactic: Optional[str] = None):
    """列出MITRE技能，可按战术过滤"""
    try:
        mitre = get_mitre_library()
        if tactic:
            try:
                tactic_enum = MITRETactic(tactic)
                skills = mitre.get_skills_by_tactic(tactic_enum)
            except ValueError:
                skills = mitre.search_skills(tactic)
        else:
            skills = list(mitre.skills.values())
        return {
            "success": True,
            "data": {
                "skills": [
                    {"id": s.technique_id, "name": s.name, "tactic": s.tactic.value,
                     "severity": s.severity, "tools": s.tools}
                    for s in skills
                ],
                "total": len(skills),
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mitre/stats")
async def mitre_stats():
    """获取MITRE技能库统计"""
    try:
        mitre = get_mitre_library()
        return {"success": True, "data": mitre.get_statistics()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mitre/map")
async def mitre_map_findings(req: FindingsRequest):
    """将发现映射到MITRE ATT&CK"""
    try:
        mitre = get_mitre_library()
        mapped = mitre.map_findings_to_mitre(req.findings)
        return {"success": True, "data": {"mapped": mapped, "total": len(mapped)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============ 4. PoC自动生成与修复 ============

@router.post("/poc/generate")
async def poc_generate(req: PoCRequest):
    """生成单个漏洞的PoC"""
    try:
        poc_gen = get_poc_generator()
        poc = poc_gen.generate_poc(req.vuln_type, req.target, req.param)
        if not poc:
            raise HTTPException(status_code=400, detail=f"不支持的漏洞类型: {req.vuln_type}")
        return {
            "success": True,
            "data": {
                "vuln_type": poc.vuln_type,
                "target": poc.target,
                "language": poc.language,
                "poc_code": poc.poc_code,
                "confidence": poc.confidence,
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/poc/batch")
async def poc_batch_generate(req: FindingsRequest):
    """批量为发现生成PoC"""
    try:
        poc_gen = get_poc_generator()
        pocs = poc_gen.generate_poc_for_findings(req.findings)
        fixes = poc_gen.generate_fixes_for_findings(req.findings)
        return {
            "success": True,
            "data": {
                "pocs": [{"vuln_type": p.vuln_type, "target": p.target,
                          "language": p.language, "poc_code": p.poc_code[:500]} for p in pocs],
                "fixes": [{"vuln_type": f.vuln_type, "fix_type": f.fix_type,
                           "priority": f.priority, "description": f.description,
                           "code_before": f.code_before[:200], "code_after": f.code_after[:200]} for f in fixes],
                "poc_count": len(pocs),
                "fix_count": len(fixes),
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/poc/types")
async def poc_types():
    """获取支持的漏洞类型"""
    try:
        poc_gen = get_poc_generator()
        return {"success": True, "data": poc_gen.get_statistics()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============ 5. Agent安全专项测试 ============

@router.post("/agentic/test")
async def agentic_run_tests(req: AgenticTestRequest):
    """运行Agent安全测试"""
    try:
        tester = get_agentic_tester()
        results = tester.run_tests(req.target_agent, req.categories if req.categories else None)
        summary = tester.get_test_summary(results)
        return {
            "success": True,
            "data": {
                "summary": summary,
                "results": [
                    {"vuln_type": r.vuln_type, "title": r.title, "severity": r.severity,
                     "vulnerable": r.vulnerable, "remediation": r.remediation}
                    for r in results
                ],
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agentic/checklist")
async def agentic_checklist():
    """获取OWASP Agentic Top 10检查清单"""
    try:
        tester = get_agentic_tester()
        return {"success": True, "data": tester.get_owasp_top10_checklist()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============ 6. 声明式任务流引擎 ============

@router.get("/taskflow/list")
async def taskflow_list():
    """列出内置任务流"""
    try:
        engine = get_taskflow_engine()
        return {"success": True, "data": engine.list_builtin_flows()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/taskflow/execute")
async def taskflow_execute(req: TaskflowExecuteRequest):
    """执行任务流"""
    try:
        engine = get_taskflow_engine()
        flow = engine.get_builtin_flow(req.flow_name)
        if not flow:
            raise HTTPException(status_code=400, detail=f"未知任务流: {req.flow_name}")
        result = engine.execute_flow(flow, req.context)
        return {"success": True, "data": result}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/taskflow/{flow_name}")
async def taskflow_detail(flow_name: str):
    """获取任务流详情"""
    try:
        engine = get_taskflow_engine()
        flow = engine.get_builtin_flow(flow_name)
        if not flow:
            raise HTTPException(status_code=400, detail=f"未知任务流: {req.flow_name}")
        return {
            "success": True,
            "data": {
                "flow_id": flow.flow_id,
                "name": flow.name,
                "description": flow.description,
                "tasks": [
                    {"id": t.task_id, "name": t.name, "type": t.task_type,
                     "depends_on": t.depends_on, "description": t.description}
                    for t in flow.tasks
                ],
                "task_count": len(flow.tasks),
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
