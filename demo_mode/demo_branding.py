# -*- coding: utf-8 -*-
"""
demo_mode/demo_branding.py — Demo 品牌定制。

职责：
    1. 品牌定制（Logo/名称/配色/字体/主题/水印/版权/联系方式）
    2. 白标方案（完全白标/部分白标/品牌替换/域名/邮件/文档定制）
    3. Demo 模板（行业/角色/场景/功能/自定义/模板市场）
    4. Demo 分享（分享链接/分享码/权限/有效期/统计/追踪）
    5. Demo 嵌入（iframe/API/组件/WordPress/Shopify/Chrome扩展）
    6. Demo 分析（访问/用户行为/转化/漏斗/留存/ROI）
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


BRAND: Dict[str, Any] = {
    "logo_url": "/assets/logo.svg",
    "brand_name": "AI Hacking Agent",
    "primary_color": "#58a6ff",
    "secondary_color": "#3fb950",
    "font_family": "Segoe UI, Microsoft YaHei, sans-serif",
    "theme": "dark",
    "watermark": "",
    "copyright": "© 2026 AI Hacking Agent",
    "contact": "demo@ai-hacking.local",
    "white_label": False,
}

WHITE_LABELS: Dict[str, Dict[str, Any]] = {}
TEMPLATES: Dict[str, Dict[str, Any]] = {}
SHARES: Dict[str, Dict[str, Any]] = {}
EMBEDS: Dict[str, Dict[str, Any]] = {}
VISITS: Dict[str, Dict[str, Any]] = {}


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _rid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- #
# 1. 品牌定制
# --------------------------------------------------------------------------- #
def get_brand() -> Dict[str, Any]:
    return dict(BRAND)


def update_brand(patch: Dict[str, Any]) -> Dict[str, Any]:
    for k in ("logo_url", "brand_name", "primary_color", "secondary_color",
              "font_family", "theme", "watermark", "copyright",
              "contact", "white_label"):
        if k in patch:
            BRAND[k] = patch[k]
    BRAND["updated_at"] = _now()
    return get_brand()


# --------------------------------------------------------------------------- #
# 2. 白标方案
# --------------------------------------------------------------------------- #
def create_white_label(payload: Dict[str, Any]) -> Dict[str, Any]:
    wid = payload.get("wl_id") or _rid("wl")
    wl = {
        "wl_id": wid,
        "name": payload.get("name", "未命名白标"),
        "mode": payload.get("mode", "full"),  # full | partial
        "replaced_brand": payload.get("replaced_brand", ""),
        "domain": payload.get("domain", "demo.example.com"),
        "email_sender": payload.get("email_sender", "noreply@example.com"),
        "docs_branded": bool(payload.get("docs_branded", True)),
        "created_at": _now(),
    }
    WHITE_LABELS[wid] = wl
    return wl


def list_white_labels() -> List[Dict[str, Any]]:
    return list(WHITE_LABELS.values())


# --------------------------------------------------------------------------- #
# 3. Demo 模板
# --------------------------------------------------------------------------- #
def _build_default_templates() -> None:
    raw = [
        {"id": "tpl_finance_pentest", "name": "金融行业渗透模板",
         "industry": "金融", "role": "安全负责人",
         "scenario": "渗透测试", "features": ["报告", "合规", "等保"]},
        {"id": "tpl_edu_rbrex", "name": "高校红蓝对抗模板",
         "industry": "教育", "role": "蓝队工程师",
         "scenario": "红蓝对抗", "features": ["演练", "复盘"]},
        {"id": "tpl_ecom_cloud", "name": "电商云安全模板",
         "industry": "电商", "role": "运维",
         "scenario": "云安全", "features": ["CSPM", "基线"]},
        {"id": "tpl_med_aisec", "name": "医疗 AI 安全模板",
         "industry": "医疗", "role": "合规官",
         "scenario": "AI安全", "features": ["LLM", "隐私"]},
    ]
    for t in raw:
        TEMPLATES[t["id"]] = t


def list_templates(industry: Optional[str] = None,
                   role: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(TEMPLATES.values())
    if industry:
        items = [x for x in items if x.get("industry") == industry]
    if role:
        items = [x for x in items if x.get("role") == role]
    return items


def create_template(payload: Dict[str, Any]) -> Dict[str, Any]:
    tid = payload.get("id") or _rid("tpl")
    t = {
        "id": tid,
        "name": payload.get("name", "未命名模板"),
        "industry": payload.get("industry", "通用"),
        "role": payload.get("role", "安全工程师"),
        "scenario": payload.get("scenario", "渗透测试"),
        "features": payload.get("features", []),
        "created_at": _now(),
    }
    TEMPLATES[tid] = t
    return t


# --------------------------------------------------------------------------- #
# 4. Demo 分享
# --------------------------------------------------------------------------- #
def create_share(payload: Dict[str, Any]) -> Dict[str, Any]:
    sid = _rid("sh")
    code = uuid.uuid4().hex[:8]
    s = {
        "share_id": sid,
        "code": code,
        "title": payload.get("title", "Demo 分享"),
        "scenario_id": payload.get("scenario_id"),
        "permission": payload.get("permission", "view"),  # view/edit/manage
        "expires_in_days": int(payload.get("expires_in_days", 7)),
        "password": payload.get("password"),
        "access_count": 0,
        "created_at": _now(),
        "url": f"/demo/s/{code}",
    }
    SHARES[sid] = s
    return s


def access_share(code: str) -> Dict[str, Any]:
    for s in SHARES.values():
        if s["code"] == code:
            s["access_count"] += 1
            VISITS[_rid("vis")] = {
                "share_id": s["share_id"], "code": code,
                "at": _now(),
            }
            return {"share_id": s["share_id"], "title": s["title"],
                    "scenario_id": s["scenario_id"],
                    "permission": s["permission"]}
    raise KeyError(code)


def list_shares() -> List[Dict[str, Any]]:
    return list(SHARES.values())


# --------------------------------------------------------------------------- #
# 5. Demo 嵌入
# --------------------------------------------------------------------------- #
def create_embed(payload: Dict[str, Any]) -> Dict[str, Any]:
    eid = _rid("emb")
    platform = payload.get("platform", "iframe")  # iframe/api/wordpress/shopify/chrome
    width = int(payload.get("width", 800))
    height = int(payload.get("height", 600))
    code_snippets = {
        "iframe": (f'<iframe src="/demo/embed/{eid}" width="{width}" '
                   f'height="{height}" frameborder="0"></iframe>'),
        "api": f'GET /api/v1/demo-mode/embed/{eid}/data',
        "wordpress": f'[ai-hacking-demo id="{eid}"]',
        "shopify": f'<script src="/embed/{eid}.js"></script>',
        "chrome": f'chrome.runtime.sendMessage("demo-{eid}")',
    }
    e = {
        "embed_id": eid,
        "platform": platform,
        "width": width, "height": height,
        "scenario_id": payload.get("scenario_id"),
        "snippet": code_snippets.get(platform, code_snippets["iframe"]),
        "created_at": _now(),
    }
    EMBEDS[eid] = e
    return e


def list_embeds() -> List[Dict[str, Any]]:
    return list(EMBEDS.values())


# --------------------------------------------------------------------------- #
# 6. Demo 分析
# --------------------------------------------------------------------------- #
def track_visit(share_id: Optional[str] = None,
                path: str = "/", referrer: str = "") -> Dict[str, Any]:
    vid = _rid("vis")
    v = {
        "visit_id": vid,
        "share_id": share_id,
        "path": path,
        "referrer": referrer,
        "at": _now(),
    }
    VISITS[vid] = v
    return v


def get_analytics() -> Dict[str, Any]:
    total = len(VISITS)
    by_share: Dict[str, int] = {}
    for v in VISITS.values():
        sid = v.get("share_id") or "direct"
        by_share[sid] = by_share.get(sid, 0) + 1
    return {
        "total_visits": total,
        "shares": len(SHARES),
        "embeds": len(EMBEDS),
        "top_shares": sorted(by_share.items(),
                             key=lambda x: x[1], reverse=True)[:5],
        "conversion_rate_pct": round(
            len([v for v in VISITS.values() if v.get("converted")])
            / max(1, total) * 100, 1),
        "roi": "待接入计费后计算",
    }


# 初始化
if not TEMPLATES:
    _build_default_templates()
