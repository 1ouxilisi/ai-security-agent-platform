# -*- coding: utf-8 -*-
"""
api_server/ai_quality_routes.py — AI 输出质量 API

提供 AI 输出校验、质量统计、用户反馈、知识库增强查询等接口。
每个端点均做 try-except 兜底，模块导入失败不影响服务启动。
路由前缀 /api/v1，端点路径：
    POST /ai/validate
    GET  /ai/quality/stats
    POST /ai/feedback
    POST /ai/grounded-query
    GET  /ai/knowledge/stats
"""
import json
import os
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1", tags=["AI质量"])

# ---------------------------------------------------------------------------
# 模块导入（全部降级）
# ---------------------------------------------------------------------------
_MODULES: Dict[str, bool] = {}

try:
    from ai.output_validator import OutputValidator  # type: ignore
    _VALIDATOR = OutputValidator()
    _MODULES["output_validator"] = True
except Exception:  # pragma: no cover
    _VALIDATOR = None
    _MODULES["output_validator"] = False

try:
    from ai.knowledge_grounding import KnowledgeGrounding  # type: ignore
    _KG = KnowledgeGrounding()
    _MODULES["knowledge_grounding"] = True
except Exception:  # pragma: no cover
    _KG = None
    _MODULES["knowledge_grounding"] = False


# ---------------------------------------------------------------------------
# 质量统计（内存计数 + 反馈持久化）
# ---------------------------------------------------------------------------
_STATS_LOCK = threading.Lock()
_QUALITY_STATS: Dict[str, float] = {
    "total_validations": 0,
    "passed": 0,
    "total_score": 0.0,
    "score_count": 0,
    "total_risk_items": 0,
    "total_unknown_facts": 0,
    "last_reset": time.time(),
}

_FEEDBACK_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "ai_feedback.json"
)


def _record_validation(result: Dict[str, Any]) -> None:
    """把一次校验结果计入统计。"""
    with _STATS_LOCK:
        _QUALITY_STATS["total_validations"] += 1
        if result.get("overall_valid"):
            _QUALITY_STATS["passed"] += 1
        score = (result.get("completeness") or {}).get("score")
        if isinstance(score, (int, float)):
            _QUALITY_STATS["total_score"] += float(score)
            _QUALITY_STATS["score_count"] += 1
        risks = (result.get("safety") or {}).get("risk_items") or []
        _QUALITY_STATS["total_risk_items"] += len(risks)
        facts = (result.get("facts") or {}).get("issues") or []
        _QUALITY_STATS["total_unknown_facts"] += len(facts)


# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------
class ValidateRequest(BaseModel):
    """AI 输出校验请求体。"""
    text: str
    code: Optional[str] = None
    expected_type: str = "remediation"


class FeedbackRequest(BaseModel):
    """用户质量反馈请求体。"""
    output_id: str
    rating: int = Field(ge=1, le=5)
    comment: Optional[str] = ""
    issue_type: Optional[str] = ""


class GroundedQueryRequest(BaseModel):
    """知识库增强查询请求体。"""
    query: str
    top_k: int = 5


# ---------------------------------------------------------------------------
# 端点
# ---------------------------------------------------------------------------
@router.post("/ai/validate")
def validate_output(req: ValidateRequest) -> Dict[str, Any]:
    """校验 AI 输出：事实性/代码/安全/完整性 综合校验。"""
    try:
        if not _MODULES.get("output_validator"):
            return {"ok": False, "error": "OutputValidator 未加载"}
        result = _VALIDATOR.validate_all(
            req.text, code=req.code, expected_type=req.expected_type
        )
        # 追加免责声明
        result["text_with_disclaimer"] = _VALIDATOR.add_disclaimer(req.text)
        _record_validation(result)
        return {"ok": True, "result": result}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "error": f"校验失败: {e}"}


@router.get("/ai/quality/stats")
def quality_stats() -> Dict[str, Any]:
    """AI 输出质量统计。"""
    try:
        with _STATS_LOCK:
            s = dict(_QUALITY_STATS)
        total = s["total_validations"]
        passed = s["passed"]
        avg_score = (s["total_score"] / s["score_count"]) if s["score_count"] else 0.0
        # 幻觉率估算：事实性 issues 占比（未知 CVE/未知术语）
        hallucination_rate = (s["total_unknown_facts"] / total) if total else 0.0
        return {
            "ok": True,
            "total_validations": total,
            "pass_rate": round(passed / total, 4) if total else 0.0,
            "avg_completeness_score": round(avg_score, 1),
            "total_risk_items": s["total_risk_items"],
            "hallucination_rate_est": round(hallucination_rate, 4),
        }
    except Exception as e:  # pragma: no cover
        return {"ok": False, "error": str(e)}


@router.post("/ai/feedback")
def submit_feedback(req: FeedbackRequest) -> Dict[str, Any]:
    """用户反馈 AI 输出质量，持久化到 data/ai_feedback.json。"""
    try:
        os.makedirs(os.path.dirname(_FEEDBACK_FILE), exist_ok=True)
        history: List[Dict[str, Any]] = []
        if os.path.exists(_FEEDBACK_FILE):
            try:
                with open(_FEEDBACK_FILE, "r", encoding="utf-8") as f:
                    history = json.load(f)
            except Exception:
                history = []
        history.append({
            "output_id": req.output_id,
            "rating": req.rating,
            "comment": req.comment or "",
            "issue_type": req.issue_type or "",
            "ts": datetime.now().isoformat(timespec="seconds"),
        })
        with open(_FEEDBACK_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
        return {"ok": True, "saved": len(history)}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "error": str(e)}


@router.post("/ai/grounded-query")
def grounded_query(req: GroundedQueryRequest) -> Dict[str, Any]:
    """知识库增强查询：检索 + 模板/LLM 回答。"""
    try:
        if not _MODULES.get("knowledge_grounding"):
            return {"ok": False, "error": "KnowledgeGrounding 未加载"}
        result = _KG.grounded_generate(req.query)
        # top_k 生效：重新按 top_k 取 references
        result["references"] = _KG.search(req.query, top_k=req.top_k)
        return {"ok": True, **result}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "error": str(e)}


@router.get("/ai/knowledge/stats")
def knowledge_stats() -> Dict[str, Any]:
    """知识库覆盖统计。"""
    try:
        if not _MODULES.get("knowledge_grounding"):
            return {"ok": False, "error": "KnowledgeGrounding 未加载"}
        return {"ok": True, **_KG.get_coverage_stats()}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "error": str(e)}
