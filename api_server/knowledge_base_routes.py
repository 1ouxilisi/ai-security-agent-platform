#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
知识库体系 API路由

- /api/v1/kb/pocs — PoC库
- /api/v1/kb/chains — 攻击链库
- /api/v1/kb/remediations — 修复方案库
- /api/v1/kb/fingerprints — 指纹库
- /api/v1/kb/search — 全库搜索
- /api/v1/kb/stats — 统计
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from knowledge_base import get_knowledge_base

router = APIRouter(prefix="/api/v1/kb", tags=["知识库体系"])


@router.get("/stats")
async def kb_stats():
    """获取知识库统计"""
    try:
        kb = get_knowledge_base()
        return {"success": True, "data": kb.get_full_stats()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pocs")
async def list_pocs(category: str = "", severity: str = "", keyword: str = ""):
    """获取PoC列表"""
    try:
        kb = get_knowledge_base()
        if keyword:
            pocs = kb.poc_lib.search(keyword)
        elif category:
            pocs = kb.poc_lib.get_by_category(category)
        elif severity:
            pocs = kb.poc_lib.get_by_severity(severity)
        else:
            pocs = list(kb.poc_lib.pocs.values())

        return {
            "success": True,
            "data": {
                "total": len(pocs),
                "pocs": [
                    {
                        "id": p.poc_id, "name": p.name, "category": p.category,
                        "severity": p.severity, "description": p.description,
                        "cwe": p.cwe, "cvss": p.cvss, "language": p.language,
                    }
                    for p in pocs
                ],
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pocs/{poc_id}")
async def get_poc(poc_id: str):
    """获取单个PoC详情（含代码）"""
    try:
        kb = get_knowledge_base()
        poc = kb.poc_lib.pocs.get(poc_id)
        if not poc:
            raise HTTPException(status_code=404, detail="PoC not found")
        return {
            "success": True,
            "data": {
                "id": poc.poc_id, "name": poc.name, "category": poc.category,
                "severity": poc.severity, "description": poc.description,
                "code": poc.code, "language": poc.language,
                "cwe": poc.cwe, "cvss": poc.cvss, "references": poc.references,
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/chains")
async def list_chains(target: str = ""):
    """获取攻击链列表"""
    try:
        kb = get_knowledge_base()
        if target:
            chains = kb.chain_lib.get_by_target(target)
        else:
            chains = list(kb.chain_lib.chains.values())
        return {
            "success": True,
            "data": {
                "total": len(chains),
                "chains": [
                    {
                        "id": c.chain_id, "name": c.name, "description": c.description,
                        "target_type": c.target_type, "difficulty": c.difficulty,
                        "stages_count": len(c.stages),
                        "mitre": c.mitre_techniques,
                    }
                    for c in chains
                ],
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/chains/{chain_id}")
async def get_chain(chain_id: str):
    """获取攻击链详情"""
    try:
        kb = get_knowledge_base()
        chain = kb.chain_lib.chains.get(chain_id)
        if not chain:
            raise HTTPException(status_code=404, detail="Chain not found")
        return {"success": True, "data": chain.__dict__}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/remediations")
async def list_remediations(vuln_type: str = ""):
    """获取修复方案列表"""
    try:
        kb = get_knowledge_base()
        if vuln_type:
            rems = kb.rem_lib.get_by_vuln_type(vuln_type)
        else:
            rems = list(kb.rem_lib.remediations.values())
        return {
            "success": True,
            "data": {
                "total": len(rems),
                "remediations": [
                    {
                        "id": r.rem_id, "vuln_type": r.vuln_type,
                        "title": r.title, "description": r.description,
                        "language": r.language,
                    }
                    for r in rems
                ],
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/remediations/{rem_id}")
async def get_remediation(rem_id: str):
    """获取修复方案详情（含代码前后对比）"""
    try:
        kb = get_knowledge_base()
        rem = kb.rem_lib.remediations.get(rem_id)
        if not rem:
            raise HTTPException(status_code=404, detail="Remediation not found")
        return {"success": True, "data": rem.__dict__}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/fingerprints")
async def list_fingerprints(category: str = ""):
    """获取指纹列表"""
    try:
        kb = get_knowledge_base()
        fps = list(kb.fp_db.fingerprints.values())
        if category:
            fps = [f for f in fps if f.category == category]
        return {
            "success": True,
            "data": {
                "total": len(fps),
                "fingerprints": [
                    {"id": f.fp_id, "name": f.name, "category": f.category,
                     "indicators_count": len(f.indicators),
                     "related_vulns": len(f.related_vulns)}
                    for f in fps
                ],
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class IdentifyRequest(BaseModel):
    headers: Dict[str, str] = {}
    body: str = ""
    url: str = ""


@router.post("/fingerprints/identify")
async def identify_fingerprint(req: IdentifyRequest):
    """识别目标指纹"""
    try:
        kb = get_knowledge_base()
        matched = kb.fp_db.identify(req.headers, req.body, req.url)
        return {
            "success": True,
            "data": {
                "matched_count": len(matched),
                "fingerprints": [
                    {"id": f.fp_id, "name": f.name, "category": f.category,
                     "related_vulns": f.related_vulns}
                    for f in matched
                ],
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/search")
async def search_kb(keyword: str):
    """全库搜索"""
    try:
        kb = get_knowledge_base()
        return {"success": True, "data": kb.search_all(keyword)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
