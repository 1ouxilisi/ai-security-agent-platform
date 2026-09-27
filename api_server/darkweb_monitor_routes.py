# -*- coding: utf-8 -*-
"""
darkweb_monitor_routes.py — 暗网监控与DRP REST API（第13轮升级）。

路由前缀：/api/v1/darkweb-monitor
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500。
任务用内存字典模拟异步任务（task_id -> status/results）。
"""

from __future__ import annotations

import os
import re
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging as log  # type: ignore

try:
    from darkweb_monitor.darkweb_intel import get_darkweb_intel_monitor
    from darkweb_monitor.credential_leak import get_credential_leak_detector
    from darkweb_monitor.brand_protection import get_brand_protection_detector
    from darkweb_monitor.data_breach_analysis import get_data_breach_analyzer
    from darkweb_monitor.threat_actor_analysis import get_threat_actor_analyzer
    from darkweb_monitor.drp_operations import get_drp_operator
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    log.warning("darkweb_monitor_routes: 模块导入失败: %s", _e)
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/darkweb-monitor", tags=["暗网监控与DRP"])


# ==================== 响应工具 ====================

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    """递归清理无效控制字符，避免 JSON 序列化异常"""
    if isinstance(obj, str):
        return _CTRL_RE.sub("", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(x) for x in obj]
    return obj


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": _clean(data), "error": str(err)})


# ==================== 内存任务存储 ====================

TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(task_type: str) -> str:
    tid = f"{task_type}-{uuid.uuid4().hex[:12]}"
    TASKS[tid] = {
        "task_id": tid, "type": task_type,
        "status": "pending", "result": None, "error": None,
        "created_at": datetime.now().isoformat(),
    }
    return tid


def _get_task(task_id: str) -> Optional[Dict[str, Any]]:
    return TASKS.get(task_id)


def _run_task(task_type: str, func, *args, **kwargs) -> str:
    tid = _new_task(task_type)
    TASKS[tid]["status"] = "running"
    try:
        result = func(*args, **kwargs)
        TASKS[tid]["status"] = "success"
        TASKS[tid]["result"] = result
    except Exception as e:
        TASKS[tid]["status"] = "failed"
        TASKS[tid]["error"] = str(e)
    return tid


def _require_modules() -> bool:
    return _MODULES_OK


# ==================== 请求模型 ====================

class IntelMonitorReq(BaseModel):
    brand: str = "ExampleCorp"
    domain: str = "example.com"
    keywords: List[str] = []


class CredentialCheckReq(BaseModel):
    emails: List[str] = []
    phones: List[str] = []
    domain: str = "example.com"
    text: str = ""


class BrandMonitorReq(BaseModel):
    brand: str = "ExampleCorp"
    domain: str = "example.com"


class BreachAnalyzeReq(BaseModel):
    brand: str = "ExampleCorp"
    text: str = ""


class ActorAnalyzeReq(BaseModel):
    actor_id: str = "TA-APT001"
    overlap: bool = False


class OperationsAssessReq(BaseModel):
    brand: str = "ExampleCorp"
    targets: List[str] = []


# ==================== 暗网情报 API ====================

@router.post("/intel/monitor")
def intel_monitor(req: IntelMonitorReq):
    """启动暗网情报监控任务"""
    try:
        if not _require_modules():
            return _fail("暗网监控模块未正确加载", {"task_id": None})
        m = get_darkweb_intel_monitor()
        if req.keywords:
            for kw in req.keywords:
                m.add_keyword(kw)
        tid = _run_task("intel", lambda: {
            "keyword": m.monitor_keywords(req.keywords or [req.brand]),
            "brand": m.monitor_brand(req.brand),
            "domain": m.monitor_domain(req.domain),
            "credential": m.monitor_credentials(),
            "breach": m.monitor_breaches(req.brand),
        })
        return _ok({"task_id": tid, "message": "暗网情报监控任务已启动"})
    except Exception as e:
        return _fail(f"情报监控启动失败: {e}")


@router.get("/intel/{task_id}/status")
def intel_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/intel/{task_id}/results")
def intel_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成，当前状态: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/intel/{task_id}/report")
def intel_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_darkweb_intel_monitor().generate_report())
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/intel/sources")
def intel_sources():
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_darkweb_intel_monitor().list_sources())
    except Exception as e:
        return _fail(f"获取源列表失败: {e}")


@router.get("/intel/alerts")
def intel_alerts(severity: Optional[str] = Query(None),
                 status: Optional[str] = Query(None)):
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_darkweb_intel_monitor().get_alerts(severity, status))
    except Exception as e:
        return _fail(f"获取告警失败: {e}")


@router.get("/intel/keywords")
def intel_keywords():
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok({"keywords": get_darkweb_intel_monitor().list_keywords()})
    except Exception as e:
        return _fail(f"获取关键词失败: {e}")


# ==================== 凭证泄露 API ====================

@router.post("/credential/check")
def credential_check(req: CredentialCheckReq):
    try:
        if not _require_modules():
            return _fail("凭证模块未加载", {"task_id": None})
        d = get_credential_leak_detector()
        tid = _run_task("credential", lambda: {
            "email_leak": d.check_email_leak(req.emails, req.domain),
            "phone_leak": d.check_phone_leak(req.phones),
            "api_keys": d.detect_api_keys(req.text),
            "tokens": d.detect_tokens(req.text),
            "private_keys": d.detect_private_keys(req.text),
        })
        return _ok({"task_id": tid, "message": "凭证泄露检测任务已启动"})
    except Exception as e:
        return _fail(f"凭证检测启动失败: {e}")


@router.get("/credential/{task_id}/status")
def credential_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/credential/{task_id}/results")
def credential_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/credential/{task_id}/report")
def credential_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_credential_leak_detector().generate_report())
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/credential/leaked")
def credential_leaked():
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_credential_leak_detector().get_leaked_db())
    except Exception as e:
        return _fail(f"获取泄露库失败: {e}")


@router.get("/credential/api-keys")
def credential_api_keys():
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok({"api_keys": get_credential_leak_detector().detect_api_keys(),
                    "tokens": get_credential_leak_detector().detect_tokens(),
                    "private_keys": get_credential_leak_detector().detect_private_keys()})
    except Exception as e:
        return _fail(f"获取密钥泄露检测失败: {e}")


@router.get("/credential/reset-suggestions")
def credential_reset_suggestions():
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_credential_leak_detector().reset_suggestions())
    except Exception as e:
        return _fail(f"获取重置建议失败: {e}")


# ==================== 品牌保护 API ====================

@router.post("/brand/monitor")
def brand_monitor(req: BrandMonitorReq):
    try:
        if not _require_modules():
            return _fail("品牌保护模块未加载", {"task_id": None})
        d = get_brand_protection_detector()
        tid = _run_task("brand", lambda: {
            "typosquatting": d.detect_typosquatting(req.domain),
            "phishing": d.detect_phishing(req.brand),
            "fake_apps": d.detect_fake_apps(req.brand),
            "fake_social": d.detect_fake_social(req.brand),
            "abuse": d.detect_brand_abuse(req.brand),
        })
        return _ok({"task_id": tid, "message": "品牌保护监控任务已启动"})
    except Exception as e:
        return _fail(f"品牌监控启动失败: {e}")


@router.get("/brand/{task_id}/status")
def brand_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/brand/{task_id}/results")
def brand_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/brand/{task_id}/report")
def brand_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_brand_protection_detector().generate_report())
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/brand/typosquatting")
def brand_typosquatting(domain: str = Query("example.com")):
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_brand_protection_detector().detect_typosquatting(domain))
    except Exception as e:
        return _fail(f"仿冒域名检测失败: {e}")


@router.get("/brand/phishing")
def brand_phishing(brand: str = Query("ExampleCorp")):
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_brand_protection_detector().detect_phishing(brand))
    except Exception as e:
        return _fail(f"钓鱼检测失败: {e}")


@router.get("/brand/fake-apps")
def brand_fake_apps(brand: str = Query("ExampleCorp")):
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_brand_protection_detector().detect_fake_apps(brand))
    except Exception as e:
        return _fail(f"假冒App检测失败: {e}")


@router.get("/brand/risk-score")
def brand_risk_score(brand: str = Query("ExampleCorp")):
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_brand_protection_detector().calculate_risk_score(brand))
    except Exception as e:
        return _fail(f"风险评分失败: {e}")


# ==================== 数据泄露分析 API ====================

@router.post("/breach/analyze")
def breach_analyze(req: BreachAnalyzeReq):
    try:
        if not _require_modules():
            return _fail("泄露分析模块未加载", {"task_id": None})
        a = get_data_breach_analyzer()
        tid = _run_task("breach", lambda: a.generate_report(req.text, req.brand))
        return _ok({"task_id": tid, "message": "数据泄露分析任务已启动"})
    except Exception as e:
        return _fail(f"泄露分析启动失败: {e}")


@router.get("/breach/{task_id}/status")
def breach_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/breach/{task_id}/results")
def breach_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/breach/{task_id}/report")
def breach_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取报告失败: {e}")


@router.get("/breach/timeline")
def breach_timeline():
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_data_breach_analyzer().build_timeline())
    except Exception as e:
        return _fail(f"获取时间线失败: {e}")


@router.get("/breach/impact")
def breach_impact(brand: str = Query("ExampleCorp")):
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_data_breach_analyzer().assess_impact(brand=brand))
    except Exception as e:
        return _fail(f"获取影响评估失败: {e}")


@router.get("/breach/compliance")
def breach_compliance():
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_data_breach_analyzer().compliance_assessment())
    except Exception as e:
        return _fail(f"获取合规评估失败: {e}")


# ==================== 威胁 Actor API ====================

@router.post("/actor/analyze")
def actor_analyze(req: ActorAnalyzeReq):
    try:
        if not _require_modules():
            return _fail("Actor分析模块未加载", {"task_id": None})
        a = get_threat_actor_analyzer()
        tid = _run_task("actor", lambda: {
            "profile": a.get_profile(req.actor_id),
            "ttps": a.get_ttps(req.actor_id),
            "threat_level": a.assess_threat_level(req.actor_id, req.overlap),
            "history": a.history(req.actor_id),
            "group": a.group_identification(req.actor_id),
        })
        return _ok({"task_id": tid, "message": "威胁Actor分析任务已启动"})
    except Exception as e:
        return _fail(f"Actor分析启动失败: {e}")


@router.get("/actor/{task_id}/status")
def actor_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/actor/{task_id}/results")
def actor_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/actor/{task_id}/report")
def actor_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_threat_actor_analyzer().generate_report())
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/actor/list")
def actor_list():
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_threat_actor_analyzer().list_actors())
    except Exception as e:
        return _fail(f"获取Actor列表失败: {e}")


@router.get("/actor/ttps")
def actor_ttps(actor_id: Optional[str] = Query(None)):
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_threat_actor_analyzer().get_ttps(actor_id))
    except Exception as e:
        return _fail(f"获取TTPs失败: {e}")


@router.get("/actor/{actor_id}/profile")
def actor_profile(actor_id: str):
    try:
        if not _require_modules():
            return _fail("模块未加载")
        p = get_threat_actor_analyzer().get_profile(actor_id)
        if not p:
            return _fail("Actor不存在")
        return _ok(p)
    except Exception as e:
        return _fail(f"获取Actor画像失败: {e}")


# ==================== 综合运营 API ====================

@router.post("/operations/assess")
def operations_assess(req: OperationsAssessReq):
    try:
        if not _require_modules():
            return _fail("DRP运营模块未加载", {"task_id": None})
        op = get_drp_operator()
        tid = _run_task("operations", lambda: op.run_assessment(req.brand, req.targets or None))
        return _ok({"task_id": tid, "message": "DRP综合评估任务已启动"})
    except Exception as e:
        return _fail(f"综合评估启动失败: {e}")


@router.get("/operations/{task_id}/status")
def operations_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/operations/{task_id}/results")
def operations_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/operations/{task_id}/report")
def operations_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取报告失败: {e}")


@router.get("/operations/dashboard")
def operations_dashboard(brand: str = Query("ExampleCorp")):
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_drp_operator().dashboard(brand))
    except Exception as e:
        return _fail(f"获取仪表盘失败: {e}")


@router.get("/operations/history")
def operations_history():
    try:
        if not _require_modules():
            return _fail("模块未加载")
        return _ok(get_drp_operator().history())
    except Exception as e:
        return _fail(f"获取历史失败: {e}")
