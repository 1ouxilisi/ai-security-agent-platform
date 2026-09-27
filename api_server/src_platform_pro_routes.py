# -*- coding: utf-8 -*-
"""
src_platform_pro_routes.py — 方向2 SRC Pro REST API（60+ 端点 + WebSocket）。

路由前缀: /api/v1/src-platform-pro
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/src-platform-pro",
                   tags=["SRCPlatformPro-方向2"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from src_platform_pro import (
        get_orchestrator, get_dashboard, get_realtime_push,
        get_platform_management_phase, get_submission_phase,
        get_review_phase, get_bounty_phase, get_community_phase,
        get_enterprise_phase, get_knowledge_phase, get_analysis_phase,
        get_ai_analysis, get_report_generator,
        STAGES, REPORTS_DIR, OWASP_TOP10,
    )
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    _RT = get_realtime_push()
    _PM = get_platform_management_phase()
    _SUB = get_submission_phase()
    _REV = get_review_phase()
    _BM = get_bounty_phase()
    _COM = get_community_phase()
    _ENT = get_enterprise_phase()
    _KB = get_knowledge_phase()
    _ANA = get_analysis_phase()
    _AI = get_ai_analysis()
    _REP = get_report_generator()
    _MOD_AVAILABLE = True
    logger.info("src_platform_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("src_platform_pro_routes: load failed: %s", e)
    _ORCH = _DASH = _RT = None  # type: ignore
    _PM = _SUB = _REV = None  # type: ignore
    _BM = _COM = _ENT = _KB = _ANA = _AI = _REP = None  # type: ignore


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(c for c in obj if c == "\n" or c == "\t"
                       or ord(c) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data),
                         "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE or _ORCH is None:
        return fail("SRC Pro 模块未加载", 503)
    return None


# =========================================================================== #
# 0. 任务 / 编排
# =========================================================================== #
@router.post("/start")
def start_src(name: str = Body("SRC 全流程运营巡检", embed=True)):
    g = _guard()
    if g:
        return g
    t = _ORCH.create_task(name)
    threading.Thread(target=_ORCH.run_full,
                     args=(t.task_id,), daemon=True).start()
    return ok({"task_id": t.task_id, "name": name, "status": t.status,
               "stage": t.stage, "progress": t.progress})


@router.get("/tasks")
def list_tasks():
    g = _guard()
    if g:
        return g
    return ok({"tasks": _ORCH.list_tasks()})


@router.get("/task/{task_id}")
def task_detail(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok(t.to_dict())


@router.get("/stages")
def stages():
    g = _guard()
    if g:
        return g
    return ok({"stages": [{"key": k, "label": n, "progress": p}
                          for k, n, p in STAGES],
               "owasp_catalog": OWASP_TOP10})


# =========================================================================== #
# 1. 阶段1 平台管理
# =========================================================================== #
@router.post("/platforms")
def create_platform(name: str = Body(...), description: str = Body(""),
                    contact: str = Body(""), website: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_PM.create_platform(name, description, contact, website))


@router.get("/platforms")
def list_platforms():
    g = _guard()
    if g:
        return g
    return ok({"platforms": _PM.list_platforms()})


@router.get("/platforms/{pid}")
def get_platform(pid: str):
    g = _guard()
    if g:
        return g
    p = _PM.get_platform(pid)
    if p is None:
        return fail("platform not found", 404)
    return ok(p)


@router.put("/platforms/{pid}/config")
def upd_platform_config(pid: str, config: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    r = _PM.update_platform_config(pid, config)
    if r is None:
        return fail("platform not found", 404)
    return ok(r)


@router.post("/hackers")
def register_hacker(nickname: str = Body(...), bio: str = Body(""),
                   skills: List[str] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_PM.register_hacker(nickname, bio, skills))


@router.get("/hackers")
def list_hackers(status: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"hackers": _PM.list_hackers(status)})


@router.post("/hackers/{hid}/review")
def review_hacker(hid: str, approve: bool = Body(True, embed=True)):
    g = _guard()
    if g:
        return g
    r = _PM.review_hacker(hid, approve)
    if r is None:
        return fail("hacker not found", 404)
    return ok(r)


@router.post("/hackers/{hid}/ban")
def ban_hacker(hid: str, ban: bool = Body(True, embed=True)):
    g = _guard()
    if g:
        return g
    r = _PM.ban_hacker(hid, ban)
    if r is None:
        return fail("hacker not found", 404)
    return ok(r)


@router.post("/enterprises")
def register_enterprise(name: str = Body(...),
                        assets: List[str] = Body(default=[]),
                        contact: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_PM.register_enterprise(name, assets, contact))


@router.get("/enterprises")
def list_enterprises():
    g = _guard()
    if g:
        return g
    return ok({"enterprises": _PM.list_enterprises()})


@router.post("/enterprises/{eid}/review")
def review_enterprise(eid: str, approve: bool = Body(True, embed=True)):
    g = _guard()
    if g:
        return g
    r = _PM.review_enterprise(eid, approve)
    if r is None:
        return fail("enterprise not found", 404)
    return ok(r)


@router.get("/platform/rules")
def get_rules():
    g = _guard()
    if g:
        return g
    return ok(_PM.get_rules())


@router.put("/platform/rules")
def upd_rules(rules: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_PM.update_rules(rules))


@router.post("/platform/announcements")
def create_announcement(title: str = Body(...), content: str = Body(""),
                       publisher: str = Body("admin")):
    g = _guard()
    if g:
        return g
    return ok(_PM.create_announcement(title, content, publisher))


@router.get("/platform/announcements")
def list_announcements():
    g = _guard()
    if g:
        return g
    return ok({"announcements": _PM.list_announcements()})


@router.get("/platform/templates")
def list_templates():
    g = _guard()
    if g:
        return g
    return ok({"templates": _PM.list_templates()})


@router.get("/platform/stats")
def platform_stats():
    g = _guard()
    if g:
        return g
    return ok(_PM.stats())


# =========================================================================== #
# 2. 阶段2 漏洞提交
# =========================================================================== #
@router.post("/vulns")
def submit_vuln(title: str = Body(...), vuln_type: str = Body("自定义类型"),
                severity: str = Body("medium"),
                repro_steps: str = Body(""), poc: str = Body(""),
                impact: str = Body(""), fix_advice: str = Body(""),
                hacker_id: str = Body("hkr_seed"),
                enterprise_id: str = Body("ent_seed"),
                tags: List[str] = Body(default=[]),
                cwe: str = Body("")):
    g = _guard()
    if g:
        return g
    r = _SUB.submit(title, vuln_type, severity, repro_steps, poc,
                    impact, fix_advice, hacker_id, enterprise_id,
                    tags, cwe)
    if r.get("error"):
        return fail(r["message"], 429)
    return ok(r)


@router.post("/vulns/draft")
def save_draft(title: str = Body(""), vuln_type: str = Body(""),
               severity: str = Body("info"),
               repro_steps: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_SUB.save_draft(title=title, vuln_type=vuln_type,
                             severity=severity, repro_steps=repro_steps))


@router.get("/vulns")
def list_vulns(status: Optional[str] = Query(None),
               severity: Optional[str] = Query(None),
               hacker_id: Optional[str] = Query(None),
               limit: int = Query(200)):
    g = _guard()
    if g:
        return g
    return ok({"vulns": _SUB.list(status, severity, hacker_id, limit)})


@router.get("/vulns/{vid}")
def get_vuln(vid: str):
    g = _guard()
    if g:
        return g
    v = _SUB.get(vid)
    if v is None:
        return fail("vuln not found", 404)
    return ok(v)


@router.post("/vulns/{vid}/status")
def set_vuln_status(vid: str, status: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    r = _SUB.update_status(vid, status)
    if r is None:
        return fail("invalid status or vuln not found")
    return ok(r)


@router.post("/vulns/{vid}/attachments")
def upload_att(vid: str, filename: str = Body(...),
               kind: str = Body("image"), size: int = Body(0)):
    g = _guard()
    if g:
        return g
    return ok(_SUB.upload_attachment(vid, filename, kind, size))


@router.get("/vulns/stats/summary")
def vuln_stats():
    g = _guard()
    if g:
        return g
    return ok(_SUB.stats())


# =========================================================================== #
# 3. 阶段3 漏洞审核
# =========================================================================== #
@router.post("/review/{vid}/start")
def start_review(vid: str, reviewer: str = Body("alice", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_REV.start_review(vid, reviewer))


@router.get("/reviews")
def list_reviews(stage: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"reviews": _REV.list_reviews(stage)})


@router.post("/reviews/{rid}/comment")
def review_comment(rid: str, reviewer: str = Body(...),
                   opinion: str = Body(""), result: str = Body("")):
    g = _guard()
    if g:
        return g
    r = _REV.add_comment(rid, reviewer, opinion, result)
    if r is None:
        return fail("review not found", 404)
    return ok(r)


@router.post("/reviews/{rid}/cvss")
def review_cvss(rid: str, base_score: float = Body(...),
                vector: str = Body("")):
    g = _guard()
    if g:
        return g
    r = _REV.set_cvss(rid, base_score, vector)
    if r is None:
        return fail("review not found", 404)
    return ok(r)


@router.post("/reviews/{rid}/stage")
def review_stage(rid: str, stage: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    r = _REV.advance_stage(rid, stage)
    if r is None:
        return fail("review not found", 404)
    return ok(r)


@router.post("/reviews/{rid}/false-positive")
def review_fp(rid: str, reason: str = Body("", embed=True)):
    g = _guard()
    if g:
        return g
    r = _REV.mark_false_positive(rid, reason)
    if r is None:
        return fail("review not found", 404)
    return ok(r)


@router.post("/reviews/{rid}/duplicate")
def review_dup(rid: str, original_vuln_id: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    r = _REV.mark_duplicate(rid, original_vuln_id)
    if r is None:
        return fail("review not found", 404)
    return ok(r)


@router.post("/disputes")
def raise_dispute(review_id: str = Body(...), reason: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_REV.raise_dispute(review_id, reason))


@router.get("/disputes")
def list_disputes():
    g = _guard()
    if g:
        return g
    return ok({"disputes": _REV.list_disputes()})


@router.post("/disputes/{did}/rule")
def rule_dispute(did: str, ruling: str = Body(""),
                 accept: bool = Body(False, embed=True)):
    g = _guard()
    if g:
        return g
    r = _REV.rule_dispute(did, ruling, accept)
    if r is None:
        return fail("dispute not found", 404)
    return ok(r)


@router.get("/reviews/stats")
def review_stats():
    g = _guard()
    if g:
        return g
    return ok(_REV.stats())


# =========================================================================== #
# 4. 阶段4 赏金管理
# =========================================================================== #
@router.post("/bounty/calculate")
def calc_bounty(severity: str = Body(...), impact_score: int = Body(5),
                quality: int = Body(5), first_found: bool = Body(False)):
    g = _guard()
    if g:
        return g
    return ok(_BM.calculate(severity, impact_score, quality, first_found))


@router.post("/bounty/grant")
def grant_bounty(vuln_id: str = Body(...), hacker_id: str = Body(...),
                 gross: int = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_BM.grant(vuln_id, hacker_id, gross))


@router.post("/bounty/{pid}/adjust")
def adjust_bounty(pid: str, delta: int = Body(...),
                  reason: str = Body("")):
    g = _guard()
    if g:
        return g
    r = _BM.adjust(pid, delta, reason)
    if r is None:
        return fail("payment not found", 404)
    return ok(r)


@router.get("/bounty/payments")
def list_payments(hacker_id: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"payments": _BM.list_payments(hacker_id)})


@router.get("/bounty/leaderboard")
def leaderboard(by: str = Query("bounty"), limit: int = Query(10)):
    g = _guard()
    if g:
        return g
    return ok({"board": _BM.leaderboard(by, limit)})


@router.get("/bounty/stats")
def bounty_stats():
    g = _guard()
    if g:
        return g
    return ok(_BM.stats())


# =========================================================================== #
# 5. 阶段5 白帽社区
# =========================================================================== #
@router.get("/community/profile/{hacker_id}")
def hacker_profile(hacker_id: str):
    g = _guard()
    if g:
        return g
    return ok(_COM.profile(hacker_id))


@router.post("/community/profile/{hacker_id}/points")
def upgrade_points(hacker_id: str, add_points: int = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_COM.upgrade_level(hacker_id, add_points))


@router.post("/community/posts")
def create_post(title: str = Body(...), body: str = Body(""),
                category: str = Body("技术讨论"), author: str = Body("anon")):
    g = _guard()
    if g:
        return g
    return ok(_COM.create_post(title, body, category, author))


@router.get("/community/posts")
def list_posts(category: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"posts": _COM.list_posts(category)})


@router.post("/community/messages")
def send_message(sender: str = Body(...), receiver: str = Body(...),
                 content: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_COM.send_message(sender, receiver, content))


@router.get("/community/messages/{hacker}")
def list_messages(hacker: str):
    g = _guard()
    if g:
        return g
    return ok({"messages": _COM.list_messages(hacker)})


@router.post("/community/follow")
def follow(follower: str = Body(...), target: str = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_COM.follow(follower, target))


@router.get("/community/honor")
def honor_wall():
    g = _guard()
    if g:
        return g
    return ok({"honor": _COM.honor_wall()})


@router.get("/community/behavior")
def behavior():
    g = _guard()
    if g:
        return g
    return ok(_COM.behavior_analysis())


# =========================================================================== #
# 6. 阶段6 企业门户
# =========================================================================== #
@router.get("/enterprise/{eid}/dashboard")
def ent_dashboard(eid: str):
    g = _guard()
    if g:
        return g
    return ok(_ENT.dashboard(eid))


@router.get("/enterprise/{eid}/fix-progress")
def ent_fix(eid: str):
    g = _guard()
    if g:
        return g
    return ok(_ENT.fix_progress(eid))


@router.get("/enterprise/{eid}/trend")
def ent_trend(eid: str):
    g = _guard()
    if g:
        return g
    return ok({"trend": _ENT.trend(eid)})


@router.post("/enterprise/{eid}/notify")
def ent_notify(eid: str, title: str = Body(...), content: str = Body(""),
               level: str = Body("info")):
    g = _guard()
    if g:
        return g
    return ok(_ENT.notify(eid, title, content, level))


@router.get("/enterprise/{eid}/notifications")
def ent_notifs(eid: str):
    g = _guard()
    if g:
        return g
    return ok({"notifications": _ENT.list_notifications(eid)})


@router.get("/enterprise/{eid}/export")
def ent_export(eid: str, period: str = Query("month")):
    g = _guard()
    if g:
        return g
    return ok(_ENT.export_report(eid, period))


# =========================================================================== #
# 7. 阶段7 漏洞知识库
# =========================================================================== #
@router.post("/knowledge/cases")
def kb_add_case(title: str = Body(...), analysis: str = Body(""),
               repro: str = Body(""), fix: str = Body(""),
               vuln_type: str = Body(""),
               tags: List[str] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_KB.add_case(title, analysis, repro, fix, vuln_type, tags))


@router.post("/knowledge/pocs")
def kb_add_poc(title: str = Body(...), code: str = Body(""),
              lang: str = Body("python"), vuln_type: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_KB.add_poc(title, code, lang, vuln_type))


@router.get("/knowledge/search")
def kb_search(keyword: str = Query("")):
    g = _guard()
    if g:
        return g
    return ok(_KB.search(keyword))


@router.get("/knowledge/all")
def kb_all():
    g = _guard()
    if g:
        return g
    return ok(_KB.list_all())


@router.get("/knowledge/stats")
def kb_stats():
    g = _guard()
    if g:
        return g
    return ok(_KB.stats())


# =========================================================================== #
# 8. 阶段8 数据分析
# =========================================================================== #
@router.get("/analysis/trend")
def ana_trend(window: str = Query("30d")):
    g = _guard()
    if g:
        return g
    return ok(_ANA.trend(window))


@router.get("/analysis/type-distribution")
def ana_type():
    g = _guard()
    if g:
        return g
    return ok({"distribution": _ANA.type_distribution()})


@router.get("/analysis/fix-efficiency")
def ana_fix():
    g = _guard()
    if g:
        return g
    return ok(_ANA.fix_efficiency())


@router.get("/analysis/roi")
def ana_roi():
    g = _guard()
    if g:
        return g
    return ok(_ANA.roi())


@router.get("/analysis/risk")
def ana_risk():
    g = _guard()
    if g:
        return g
    return ok(_ANA.risk_assessment())


@router.get("/analysis/full")
def ana_full():
    g = _guard()
    if g:
        return g
    return ok(_ANA.full_report())


@router.get("/analysis/export")
def ana_export(fmt: str = Query("json")):
    g = _guard()
    if g:
        return g
    return ok(_ANA.export(fmt))


# =========================================================================== #
# 9. AI 分析
# =========================================================================== #
@router.post("/ai/review/{vid}")
def ai_review(vid: str):
    g = _guard()
    if g:
        return g
    v = _SUB.get(vid)
    if v is None:
        return fail("vuln not found", 404)
    return ok(_AI.review(v))


@router.post("/ai/batch")
def ai_batch(limit: int = Body(20, embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_AI.batch_review(_SUB.list(limit=limit)))


@router.get("/ai/forecast")
def ai_forecast():
    g = _guard()
    if g:
        return g
    return ok(_AI.trend_forecast())


@router.get("/ai/history")
def ai_history(limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok({"history": _AI.history(limit)})


# =========================================================================== #
# 10. SRC 大屏
# =========================================================================== #
@router.get("/dashboard/kpi")
def dash_kpi():
    g = _guard()
    if g:
        return g
    return ok(_DASH.kpi())


@router.get("/dashboard/full")
def dash_full():
    g = _guard()
    if g:
        return g
    return ok(_DASH.full_screen())


@router.get("/dashboard/recent")
def dash_recent(limit: int = Query(15)):
    g = _guard()
    if g:
        return g
    return ok({"vulns": _DASH.recent_vulns(limit)})


# =========================================================================== #
# 11. 报告生成
# =========================================================================== #
@router.post("/report/generate")
def report_gen(fmt: str = Body("both", embed=True)):
    g = _guard()
    if g:
        return g
    r = _REP.generate(fmt)
    return ok({k: v for k, v in r.items() if k != "html"})


@router.get("/report/latest")
def report_latest():
    g = _guard()
    if g:
        return g
    import os
    if not os.path.isdir(REPORTS_DIR):
        return ok({"files": []})
    files = sorted(os.listdir(REPORTS_DIR), reverse=True)
    return ok({"dir": REPORTS_DIR, "files": files[:20]})


# =========================================================================== #
# 12. WebSocket 实时推送
# =========================================================================== #
@router.websocket("/ws/{task_id}")
async def ws_endpoint(websocket: WebSocket, task_id: str):
    """实时推送进度/日志/思考/漏洞/赏金/结果。"""
    await websocket.accept()
    if not _MOD_AVAILABLE:
        await websocket.send_json({"type": "error",
                                   "message": "模块未加载"})
        await websocket.close()
        return
    _RT.subscribe(task_id, websocket)
    for ev in _RT.history(task_id):
        try:
            await websocket.send_json(ev)
        except Exception:
            break
    try:
        sent_index = len(_RT.history(task_id))
        while True:
            hist = _RT.history(task_id)
            if len(hist) > sent_index:
                for ev in hist[sent_index:]:
                    await websocket.send_json(ev)
                sent_index = len(hist)
            await websocket.send_json({"type": "ping",
                                       "ts": time.time()})
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _RT.unsubscribe(task_id, websocket)
