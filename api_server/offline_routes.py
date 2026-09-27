#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
离线模式 API 路由（8个端点）

前缀: /api/v1/offline
"""
import os
import sys
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offline.ai_fallback import get_fallback_manager  # noqa: E402
from offline.rules_engine import RuleEngine  # noqa: E402
from offline.local_knowledge import LocalKnowledge  # noqa: E402

router = APIRouter(prefix="/api/v1/offline", tags=["离线模式"])

_engine = RuleEngine()
_knowledge = LocalKnowledge()


class ModeIn(BaseModel):
    mode: str


class RuleUpdateIn(BaseModel):
    enabled: Optional[bool] = None
    severity: Optional[str] = None
    pattern: Optional[str] = None


class RuleTestIn(BaseModel):
    rule_id: str
    test_data: Dict[str, Any] = Field(default_factory=dict)


# ==================== 1. 离线状态 ====================
@router.get("/status", summary="获取离线模式状态")
async def offline_status():
    try:
        fb = get_fallback_manager()
        ai_check = fb.check_ai_availability()
        return {
            "success": True,
            "current_mode": fb.get_current_mode(),
            "ai_available": ai_check["available"],
            "ai_latency_ms": ai_check["latency_ms"],
            "local_rules_count": len(_engine.list_rules()),
            "knowledge_stats": _knowledge.get_stats(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 2. 切换模式 ====================
@router.post("/mode", summary="切换离线模式")
async def set_mode(body: ModeIn):
    try:
        fb = get_fallback_manager()
        result = fb.set_mode(body.mode)
        return {"success": True, **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 3. 规则列表 ====================
@router.get("/rules", summary="获取规则列表")
async def list_rules():
    try:
        return {"success": True, "rules": _engine.list_rules(), "stats": _engine.get_stats()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 4. 更新规则 ====================
@router.put("/rules/{rule_id}", summary="更新规则配置")
async def update_rule(rule_id: str, body: RuleUpdateIn):
    try:
        ok = _engine.update_rule(rule_id, body.model_dump(exclude_none=True))
        if not ok:
            raise HTTPException(status_code=404, detail="规则不存在")
        return {"success": True, "rule_id": rule_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 5. 测试规则 ====================
@router.post("/rules/test", summary="测试规则")
async def test_rule(body: RuleTestIn):
    try:
        result = _engine.test_rule(body.rule_id, body.test_data)
        return {"success": True, **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 6. 搜索知识库 ====================
@router.get("/knowledge/search", summary="搜索本地知识库")
async def search_knowledge(q: str = Query(..., description="搜索关键词"),
                           category: Optional[str] = Query(None)):
    try:
        results = _knowledge.search(q, category)
        return {"success": True, "query": q, "results": results, "count": len(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 7. 知识库统计 ====================
@router.get("/knowledge/stats", summary="知识库统计")
async def knowledge_stats():
    try:
        return {"success": True, **_knowledge.get_stats()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 8. 离线模式统计 ====================
@router.get("/stats", summary="离线模式统计")
async def offline_stats():
    try:
        fb = get_fallback_manager()
        return {"success": True, **fb.get_stats(), "rule_engine": _engine.get_stats()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
