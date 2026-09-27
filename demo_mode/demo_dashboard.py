# -*- coding: utf-8 -*-
"""
demo_mode/demo_dashboard.py — Demo 管理控制台（聚合层）。

职责：
    1. Demo 总览（数量/使用次数/完成率/平均时长/满意度/热门场景/趋势）
    2. Demo 管理（创建/编辑/发布/下线/版本/分类/标签/搜索/筛选/批量）
    3. 演示管理（列表/状态/进度/录制/分享/统计）
    4. 引导管理（列表/状态/进度/效果/A-B/优化）
    5. 数据分析（访问量/用户数/完成率/转化率/留存率/满意度/NPS/趋势/漏斗）
    6. 系统设置（Demo配置/品牌/分享/嵌入/分析/通知/审计）
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from . import demo_dataset as ds
from . import demo_engine as eng
from . import interactive_guide as ig
from . import quick_experience as qe
from . import demo_branding as dbg


SETTINGS: Dict[str, Any] = {
    "demo_enabled": True,
    "default_scenario": "scen_pentest",
    "auto_narration": True,
    "auto_record": False,
    "share_expires_days": 7,
    "allow_anonymous": True,
    "notify_on_finish": True,
    "audit_log": True,
}

AUDIT_LOG: List[Dict[str, Any]] = []


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _rid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def _audit(action: str, detail: str = "") -> None:
    if SETTINGS.get("audit_log"):
        AUDIT_LOG.append({"at": _now(), "action": action, "detail": detail})


# --------------------------------------------------------------------------- #
# 1. Demo 总览
# --------------------------------------------------------------------------- #
def get_overview() -> Dict[str, Any]:
    ds_stats = ds.get_stats()
    qe_analytics = qe.get_analytics()
    brand_analytics = dbg.get_analytics()
    return {
        "scenario_count": ds_stats["scenario_count"],
        "dataset_count": ds_stats["dataset_count"],
        "usage_count": ds_stats["usage_count"],
        "completion_rate_pct": ds_stats["completion_rate_pct"],
        "avg_duration_sec": ds_stats["avg_duration_sec"],
        "avg_feedback": ds_stats["avg_feedback"],
        "hot_scenarios": ds_stats["hot_scenarios"],
        "trend": [
            {"day": "周一", "visits": 120},
            {"day": "周二", "visits": 180},
            {"day": "周三", "visits": 150},
            {"day": "周四", "visits": 220},
            {"day": "周五", "visits": 310},
        ],
        "quick_experience": {
            "total_sessions": qe_analytics["total_sessions"],
            "completion_rate_pct": qe_analytics["completion_rate_pct"],
        },
        "brand": {
            "shares": brand_analytics["shares"],
            "total_visits": brand_analytics["total_visits"],
        },
    }


# --------------------------------------------------------------------------- #
# 2. Demo 管理（场景 CRUD + 发布/下线 + 批量）
# --------------------------------------------------------------------------- #
def list_demos(category: Optional[str] = None,
               keyword: Optional[str] = None,
               status: Optional[str] = None) -> List[Dict[str, Any]]:
    items = ds.list_scenarios(category=category, keyword=keyword)
    if status:
        items = [x for x in items if x.get("status") == status]
    return items


def publish_demo(scenario_id: str) -> Optional[Dict[str, Any]]:
    r = ds.update_scenario(scenario_id, {"status": "published"})
    if r:
        _audit("publish_demo", scenario_id)
    return r


def offline_demo(scenario_id: str) -> Optional[Dict[str, Any]]:
    r = ds.update_scenario(scenario_id, {"status": "offline"})
    if r:
        _audit("offline_demo", scenario_id)
    return r


def batch_demo(action: str, ids: List[str]) -> Dict[str, Any]:
    ok_count = 0
    for sid in ids:
        if action == "publish" and publish_demo(sid):
            ok_count += 1
        elif action == "offline" and offline_demo(sid):
            ok_count += 1
        elif action == "delete":
            if ds.delete_scenario(sid):
                ok_count += 1
    _audit(f"batch_{action}", f"{ok_count}/{len(ids)}")
    return {"action": action, "requested": len(ids), "succeeded": ok_count}


# --------------------------------------------------------------------------- #
# 3. 演示管理
# --------------------------------------------------------------------------- #
def list_demos_running(status: Optional[str] = None) -> List[Dict[str, Any]]:
    return eng.list_executions(status=status)


def list_recordings() -> List[Dict[str, Any]]:
    return eng.list_recordings()


def list_demo_shares() -> List[Dict[str, Any]]:
    return dbg.list_shares()


# --------------------------------------------------------------------------- #
# 4. 引导管理
# --------------------------------------------------------------------------- #
def list_guides_admin(kind: Optional[str] = None) -> List[Dict[str, Any]]:
    return ig.list_guides(kind=kind)


def get_guide_effect(guide_id: Optional[str] = None) -> Dict[str, Any]:
    return ig.get_effect_analysis(guide_id=guide_id)


# --------------------------------------------------------------------------- #
# 5. 数据分析
# --------------------------------------------------------------------------- #
def get_full_analytics() -> Dict[str, Any]:
    ds_stats = ds.get_stats()
    qe_a = qe.get_analytics()
    brand_a = dbg.get_analytics()
    guide_a = ig.get_effect_analysis()
    nps_base = ds_stats["avg_feedback"]
    return {
        "visits": brand_a["total_visits"],
        "users": ds_stats["usage_count"],
        "completion_rate_pct": ds_stats["completion_rate_pct"],
        "conversion_pct": qe_a["funnel"]["conversion_pct"],
        "retention_pct": 42.5,
        "satisfaction": ds_stats["avg_feedback"],
        "nps": round((nps_base - 3) / 2 * 10, 1) if nps_base else 0.0,
        "funnel": qe_a["funnel"],
        "guide_effect": guide_a,
        "trend": get_overview()["trend"],
    }


# --------------------------------------------------------------------------- #
# 6. 系统设置
# --------------------------------------------------------------------------- #
def get_settings() -> Dict[str, Any]:
    return dict(SETTINGS)


def update_settings(patch: Dict[str, Any]) -> Dict[str, Any]:
    for k in SETTINGS:
        if k in patch:
            SETTINGS[k] = patch[k]
    _audit("update_settings", str(list(patch.keys())))
    return get_settings()


def list_audit_log(limit: int = 100) -> List[Dict[str, Any]]:
    return list(AUDIT_LOG)[-limit:]
