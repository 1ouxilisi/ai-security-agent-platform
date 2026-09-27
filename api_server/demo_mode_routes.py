# -*- coding: utf-8 -*-
"""
api_server/demo_mode_routes.py — 一键 Demo 模式 FastAPI 路由（40+ 端点）。

路由前缀: /api/v1/demo-mode
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo_mode import demo_dataset as ds  # noqa: E402
from demo_mode import demo_engine as eng  # noqa: E402
from demo_mode import interactive_guide as ig  # noqa: E402
from demo_mode import quick_experience as qe  # noqa: E402
from demo_mode import demo_branding as dbg  # noqa: E402
from demo_mode import demo_dashboard as dash  # noqa: E402

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/demo-mode", tags=["一键Demo模式"])


# --------------------------------------------------------------------------- #
# 统一响应 / 控制字符清理
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理控制字符与无效 Unicode，保证 JSON 可序列化。"""
    if isinstance(obj, str):
        return "".join(
            ch for ch in obj
            if ch in ("\n", "\t", "\r") or ord(ch) >= 32
        )
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, tuple):
        return [_clean(v) for v in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


# =========================================================================== #
# 一、Demo 场景库 / 数据集（17 个端点）
# =========================================================================== #

# 1. GET /scenarios
@router.get("/scenarios")
def api_list_scenarios(category: Optional[str] = Query(None),
                       keyword: Optional[str] = Query(None)):
    try:
        return ok(ds.list_scenarios(category=category, keyword=keyword))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 2. GET /scenarios/{scenario_id}
@router.get("/scenarios/{scenario_id}")
def api_get_scenario(scenario_id: str):
    try:
        s = ds.get_scenario(scenario_id)
        if not s:
            return fail("scenario not found", 404)
        return ok(s)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 3. POST /scenarios
@router.post("/scenarios")
def api_create_scenario(body: Dict[str, Any] = Body(...)):
    try:
        return ok(ds.create_scenario(body))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 4. PUT /scenarios/{scenario_id}
@router.put("/scenarios/{scenario_id}")
def api_update_scenario(scenario_id: str,
                        body: Dict[str, Any] = Body(...)):
    try:
        s = ds.update_scenario(scenario_id, body)
        if not s:
            return fail("scenario not found", 404)
        return ok(s)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 5. DELETE /scenarios/{scenario_id}
@router.delete("/scenarios/{scenario_id}")
def api_delete_scenario(scenario_id: str):
    try:
        return ok({"deleted": ds.delete_scenario(scenario_id)})
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 6. POST /scenarios/{scenario_id}/customize
@router.post("/scenarios/{scenario_id}/customize")
def api_customize_scenario(scenario_id: str,
                           body: Dict[str, Any] = Body(...)):
    try:
        s = ds.customize_scenario(scenario_id, body)
        if not s:
            return fail("scenario not found", 404)
        return ok(s)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 7. POST /datasets/generate
@router.post("/datasets/generate")
def api_generate_dataset(body: Dict[str, Any] = Body(...)):
    try:
        sid = body.get("scenario_id")
        if not sid:
            return fail("scenario_id required")
        return ok(ds.generate_dataset(sid, body.get("options")))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 8. GET /datasets
@router.get("/datasets")
def api_list_datasets():
    try:
        return ok(ds.list_datasets())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 9. GET /datasets/{dataset_id}
@router.get("/datasets/{dataset_id}")
def api_get_dataset(dataset_id: str):
    try:
        d = ds.get_dataset(dataset_id)
        if not d:
            return fail("dataset not found", 404)
        return ok(d)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 10. POST /datasets/{dataset_id}/export
@router.post("/datasets/{dataset_id}/export")
def api_export_dataset(dataset_id: str):
    try:
        pkg = ds.export_dataset(dataset_id)
        if not pkg:
            return fail("dataset not found", 404)
        return ok(pkg)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 11. POST /datasets/import
@router.post("/datasets/import")
def api_import_dataset(body: Dict[str, Any] = Body(...)):
    try:
        return ok(ds.import_dataset(body))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 12. POST /datasets/verify
@router.post("/datasets/verify")
def api_verify_package(body: Dict[str, Any] = Body(...)):
    try:
        return ok(ds.verify_package(body))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 13. POST /reset
@router.post("/reset")
def api_reset(body: Dict[str, Any] = Body(...)):
    try:
        return ok(ds.reset_demo(body.get("scope", "all"),
                                 body.get("scenario_id")))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 14. GET /backups
@router.get("/backups")
def api_list_backups():
    try:
        return ok(ds.list_backups())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 15. POST /backups/{backup_id}/restore
@router.post("/backups/{backup_id}/restore")
def api_restore_backup(backup_id: str):
    try:
        return ok(ds.restore_backup(backup_id))
    except KeyError:
        return fail("backup not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 16. GET /reset-history
@router.get("/reset-history")
def api_reset_history():
    try:
        return ok(ds.list_reset_history())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 17. GET /stats
@router.get("/stats")
def api_demo_stats():
    try:
        return ok(ds.get_stats())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# =========================================================================== #
# 二、自动演示引擎（17 个端点）
# =========================================================================== #

# 18. GET /scripts
@router.get("/scripts")
def api_list_scripts():
    try:
        return ok(eng.list_scripts())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 19. POST /scripts
@router.post("/scripts")
def api_create_script(body: Dict[str, Any] = Body(...)):
    try:
        return ok(eng.create_script(body))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 20. GET /scripts/{script_id}
@router.get("/scripts/{script_id}")
def api_get_script(script_id: str):
    try:
        s = eng.get_script(script_id)
        if not s:
            return fail("script not found", 404)
        return ok(s)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 21. PUT /scripts/{script_id}
@router.put("/scripts/{script_id}")
def api_update_script(script_id: str,
                      body: Dict[str, Any] = Body(...)):
    try:
        s = eng.update_script(script_id, body)
        if not s:
            return fail("script not found", 404)
        return ok(s)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 22. DELETE /scripts/{script_id}
@router.delete("/scripts/{script_id}")
def api_delete_script(script_id: str):
    try:
        return ok({"deleted": eng.delete_script(script_id)})
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 23. POST /executions
@router.post("/executions")
def api_start_execution(body: Dict[str, Any] = Body(...)):
    try:
        sid = body.get("script_id")
        if not sid:
            return fail("script_id required")
        return ok(eng.start_execution(sid, body.get("mode", "auto"),
                                     body.get("variables")))
    except KeyError as e:
        return fail(str(e), 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 24. POST /executions/{execution_id}/control
@router.post("/executions/{execution_id}/control")
def api_control_execution(execution_id: str,
                          body: Dict[str, Any] = Body(...)):
    try:
        return ok(eng.control_execution(execution_id,
                                        body.get("action", "play"),
                                        body))
    except KeyError:
        return fail("execution not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 25. GET /executions
@router.get("/executions")
def api_list_executions(status: Optional[str] = Query(None)):
    try:
        return ok(eng.list_executions(status=status))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 26. GET /executions/{execution_id}
@router.get("/executions/{execution_id}")
def api_get_execution(execution_id: str):
    try:
        e = eng.get_execution(execution_id)
        if not e:
            return fail("execution not found", 404)
        return ok(e)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 27. GET /control-presets
@router.get("/control-presets")
def api_control_presets():
    try:
        return ok(eng.list_control_presets())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 28. POST /recordings
@router.post("/recordings")
def api_start_recording(body: Dict[str, Any] = Body(...)):
    try:
        return ok(eng.start_recording(body.get("execution_id", ""),
                                      body))
    except KeyError:
        return fail("execution not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 29. POST /recordings/{recording_id}/stop
@router.post("/recordings/{recording_id}/stop")
def api_stop_recording(recording_id: str):
    try:
        return ok(eng.stop_recording(recording_id))
    except KeyError:
        return fail("recording not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 30. GET /recordings
@router.get("/recordings")
def api_list_recordings():
    try:
        return ok(eng.list_recordings())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 31. POST /narrations
@router.post("/narrations")
def api_generate_narration(body: Dict[str, Any] = Body(...)):
    try:
        return ok(eng.generate_narration(body.get("script_id", ""),
                                          body.get("lang", "zh-CN")))
    except KeyError:
        return fail("script not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 32. GET /narrations
@router.get("/narrations")
def api_list_narrations():
    try:
        return ok(eng.list_narrations())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 33. POST /polls
@router.post("/polls")
def api_create_poll(body: Dict[str, Any] = Body(...)):
    try:
        return ok(eng.create_poll(body.get("execution_id", ""),
                                  body.get("question", ""),
                                  body.get("options", [])))
    except KeyError:
        return fail("execution not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 34. POST /polls/{poll_id}/vote
@router.post("/polls/{poll_id}/vote")
def api_vote_poll(poll_id: str, body: Dict[str, Any] = Body(...)):
    try:
        return ok(eng.vote_poll(poll_id, int(body.get("option_index", 0))))
    except KeyError:
        return fail("poll not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 35. POST /questions
@router.post("/questions")
def api_ask_question(body: Dict[str, Any] = Body(...)):
    try:
        return ok(eng.ask_question(body.get("execution_id", ""),
                                   body.get("user", "anonymous"),
                                   body.get("question", "")))
    except KeyError:
        return fail("execution not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 36. POST /questions/{qa_id}/answer
@router.post("/questions/{qa_id}/answer")
def api_answer_question(qa_id: str, body: Dict[str, Any] = Body(...)):
    try:
        return ok(eng.answer_question(qa_id, body.get("answer", "")))
    except KeyError:
        return fail("question not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 37. POST /executions/{execution_id}/feedback
@router.post("/executions/{execution_id}/feedback")
def api_collect_feedback(execution_id: str,
                          body: Dict[str, Any] = Body(...)):
    try:
        return ok(eng.collect_feedback(execution_id,
                                       int(body.get("score", 5)),
                                       body.get("comment", "")))
    except KeyError:
        return fail("execution not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# =========================================================================== #
# 三、交互式引导（8 个端点）
# =========================================================================== #

# 38. GET /guides
@router.get("/guides")
def api_list_guides(kind: Optional[str] = Query(None)):
    try:
        return ok(ig.list_guides(kind=kind))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 39. GET /guides/{guide_id}
@router.get("/guides/{guide_id}")
def api_get_guide(guide_id: str):
    try:
        g = ig.get_guide(guide_id)
        if not g:
            return fail("guide not found", 404)
        return ok(g)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 40. POST /guides
@router.post("/guides")
def api_create_guide(body: Dict[str, Any] = Body(...)):
    try:
        return ok(ig.create_guide(body))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 41. POST /guides/{guide_id}/start
@router.post("/guides/{guide_id}/start")
def api_start_guide(guide_id: str,
                     body: Dict[str, Any] = Body(...)):
    try:
        return ok(ig.start_guide(guide_id, body.get("user", "anonymous")))
    except KeyError:
        return fail("guide not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 42. POST /progress/{progress_id}/advance
@router.post("/progress/{progress_id}/advance")
def api_advance_guide(progress_id: str,
                      body: Dict[str, Any] = Body(...)):
    try:
        return ok(ig.advance_guide(progress_id,
                                     body.get("action", "next")))
    except KeyError:
        return fail("progress not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 43. GET /guide-progress
@router.get("/guide-progress")
def api_list_guide_progress(user: Optional[str] = Query(None)):
    try:
        return ok(ig.list_guide_progress(user=user))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 44. GET /guide-effect
@router.get("/guide-effect")
def api_guide_effect(guide_id: Optional[str] = Query(None)):
    try:
        return ok(ig.get_effect_analysis(guide_id=guide_id))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 45. GET /help
@router.get("/help")
def api_search_help(keyword: str = Query(""),
                    category: Optional[str] = Query(None)):
    try:
        if keyword:
            return ok(ig.search_help(keyword))
        return ok(ig.list_help_docs(category=category))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# =========================================================================== #
# 四、3 分钟快速体验（6 个端点）
# =========================================================================== #

# 46. GET /quick-scenarios
@router.get("/quick-scenarios")
def api_list_quick_scenarios():
    try:
        return ok(qe.list_quick_scenarios())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 47. POST /quick-sessions
@router.post("/quick-sessions")
def api_start_quick_session(body: Dict[str, Any] = Body(...)):
    try:
        return ok(qe.start_session(body.get("scenario_id", ""),
                                    body.get("user", "anonymous")))
    except KeyError:
        return fail("scenario not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 48. POST /quick-sessions/{session_id}/advance
@router.post("/quick-sessions/{session_id}/advance")
def api_advance_quick(session_id: str,
                      body: Dict[str, Any] = Body(...)):
    try:
        return ok(qe.advance_session(session_id,
                                     body.get("action", "next")))
    except KeyError:
        return fail("session not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 49. GET /quick-sessions
@router.get("/quick-sessions")
def api_list_quick_sessions(status: Optional[str] = Query(None)):
    try:
        return ok(qe.list_sessions(status=status))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 50. POST /quick-sessions/{session_id}/convert
@router.post("/quick-sessions/{session_id}/convert")
def api_convert_quick(session_id: str,
                      body: Dict[str, Any] = Body(...)):
    try:
        return ok(qe.track_conversion(session_id,
                                       body.get("ctype", "register")))
    except KeyError:
        return fail("session not found", 404)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 51. GET /quick-analytics
@router.get("/quick-analytics")
def api_quick_analytics():
    try:
        return ok(qe.get_analytics())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# =========================================================================== #
# 五、品牌定制（10 个端点）
# =========================================================================== #

# 52. GET /brand
@router.get("/brand")
def api_get_brand():
    try:
        return ok(dbg.get_brand())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 53. PUT /brand
@router.put("/brand")
def api_update_brand(body: Dict[str, Any] = Body(...)):
    try:
        return ok(dbg.update_brand(body))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 54. GET /white-labels
@router.get("/white-labels")
def api_list_white_labels():
    try:
        return ok(dbg.list_white_labels())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 55. POST /white-labels
@router.post("/white-labels")
def api_create_white_label(body: Dict[str, Any] = Body(...)):
    try:
        return ok(dbg.create_white_label(body))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 56. GET /templates
@router.get("/templates")
def api_list_templates(industry: Optional[str] = Query(None),
                       role: Optional[str] = Query(None)):
    try:
        return ok(dbg.list_templates(industry=industry, role=role))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 57. POST /templates
@router.post("/templates")
def api_create_template(body: Dict[str, Any] = Body(...)):
    try:
        return ok(dbg.create_template(body))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 58. POST /shares
@router.post("/shares")
def api_create_share(body: Dict[str, Any] = Body(...)):
    try:
        return ok(dbg.create_share(body))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 59. GET /shares
@router.get("/shares")
def api_list_shares():
    try:
        return ok(dbg.list_shares())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 60. POST /embeds
@router.post("/embeds")
def api_create_embed(body: Dict[str, Any] = Body(...)):
    try:
        return ok(dbg.create_embed(body))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 61. GET /embeds
@router.get("/embeds")
def api_list_embeds():
    try:
        return ok(dbg.list_embeds())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# =========================================================================== #
# 六、管理控制台（8 个端点）
# =========================================================================== #

# 62. GET /overview
@router.get("/overview")
def api_overview():
    try:
        return ok(dash.get_overview())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 63. GET /demos
@router.get("/demos")
def api_list_demos(category: Optional[str] = Query(None),
                   keyword: Optional[str] = Query(None),
                   status: Optional[str] = Query(None)):
    try:
        return ok(dash.list_demos(category=category, keyword=keyword,
                                  status=status))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 64. POST /demos/{scenario_id}/publish
@router.post("/demos/{scenario_id}/publish")
def api_publish_demo(scenario_id: str):
    try:
        s = dash.publish_demo(scenario_id)
        if not s:
            return fail("scenario not found", 404)
        return ok(s)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 65. POST /demos/{scenario_id}/offline
@router.post("/demos/{scenario_id}/offline")
def api_offline_demo(scenario_id: str):
    try:
        s = dash.offline_demo(scenario_id)
        if not s:
            return fail("scenario not found", 404)
        return ok(s)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 66. POST /demos/batch
@router.post("/demos/batch")
def api_batch_demos(body: Dict[str, Any] = Body(...)):
    try:
        return ok(dash.batch_demo(body.get("action", "publish"),
                                   body.get("ids", [])))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 67. GET /analytics
@router.get("/analytics")
def api_full_analytics():
    try:
        return ok(dash.get_full_analytics())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 68. GET /settings
@router.get("/settings")
def api_get_settings():
    try:
        return ok(dash.get_settings())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 69. PUT /settings
@router.put("/settings")
def api_update_settings(body: Dict[str, Any] = Body(...)):
    try:
        return ok(dash.update_settings(body))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# 70. GET /audit-log
@router.get("/audit-log")
def api_audit_log(limit: int = Query(100, ge=1, le=500)):
    try:
        return ok(dash.list_audit_log(limit=limit))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


__all__ = ["router", "ok", "fail", "_clean"]
