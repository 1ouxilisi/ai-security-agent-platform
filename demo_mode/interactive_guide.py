# -*- coding: utf-8 -*-
"""
demo_mode/interactive_guide.py — 交互式引导。

职责：
    1. 新手引导（首次启动/功能介绍/操作提示/下一步/跳过/完成）
    2. 功能引导（每个功能的引导/操作步骤/示例/提示/帮助/文档链接）
    3. 场景引导（典型场景端到端引导/从输入到输出/每步解释/最佳实践）
    4. 引导管理（列表/状态/进度/版本/A-B测试/效果分析）
    5. 提示系统（工具提示/内联/上下文/错误/成功/警告/通知）
    6. 帮助中心（上下文帮助/搜索/相关文档/视频/社区/工单）
"""

from __future__ import annotations

import copy
import time
import uuid
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# 内存存储
# --------------------------------------------------------------------------- #
GUIDES: Dict[str, Dict[str, Any]] = {}
GUIDE_PROGRESS: Dict[str, Dict[str, Any]] = {}
TOOLTIPS: Dict[str, Dict[str, Any]] = {}
HELP_DOCS: Dict[str, Dict[str, Any]] = {}
AB_TESTS: Dict[str, Dict[str, Any]] = {}


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _rid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- #
# 1. 新手引导
# --------------------------------------------------------------------------- #
def _build_default_guides() -> None:
    default_newbie = {
        "guide_id": "guide_newbie",
        "name": "首次启动新手引导",
        "kind": "newbie",
        "version": "1.0",
        "steps": [
            {"id": "n1", "title": "欢迎使用 AI Hacking Agent",
             "body": "一键 Demo 模式让你在 3 分钟内体验核心能力。",
             "target": "body", "placement": "center"},
            {"id": "n2", "title": "选择 Demo 场景",
             "body": "左侧选择渗透测试 / 移动安全 / 红蓝对抗等场景。",
             "target": "#scenario-list", "placement": "right"},
            {"id": "n3", "title": "一键生成数据",
             "body": "点击「生成数据集」即可获得真实感资产/漏洞/告警。",
             "target": "#btn-generate", "placement": "top"},
            {"id": "n4", "title": "开始演示",
             "body": "点击播放按钮，自动按脚本执行并旁白讲解。",
             "target": "#btn-play", "placement": "top"},
            {"id": "n5", "title": "完成！",
             "body": "你可以随时通过帮助中心查看文档或提交工单。",
             "target": "body", "placement": "center"},
        ],
    }
    GUIDES[default_newbie["guide_id"]] = default_newbie

    feature_scan = {
        "guide_id": "guide_feature_scan",
        "name": "功能引导：一键扫描",
        "kind": "feature",
        "version": "1.0",
        "steps": [
            {"id": "fs1", "title": "输入目标", "body": "输入域名/IP/URL。",
             "target": "#input-target", "placement": "bottom"},
            {"id": "fs2", "title": "选择模块", "body": "勾选端口/Web/弱口令。",
             "target": "#module-picker", "placement": "bottom"},
            {"id": "fs3", "title": "查看结果", "body": "实时展示资产与漏洞。",
             "target": "#result-panel", "placement": "top"},
        ],
    }
    GUIDES[feature_scan["guide_id"]] = feature_scan

    scenario_pentest = {
        "guide_id": "guide_scen_pentest",
        "name": "场景引导：渗透测试端到端",
        "kind": "scenario",
        "version": "1.0",
        "steps": [
            {"id": "sp1", "title": "信息收集", "body": "子域名/端口/指纹识别。",
             "target": "#step-recon", "placement": "left"},
            {"id": "sp2", "title": "漏洞探测", "body": "POC 批量验证。",
             "target": "#step-vuln", "placement": "left"},
            {"id": "sp3", "title": "漏洞利用", "body": "获取初始 Shell。",
             "target": "#step-exploit", "placement": "left"},
            {"id": "sp4", "title": "报告导出", "body": "一键生成 PDF 报告。",
             "target": "#step-report", "placement": "left"},
        ],
    }
    GUIDES[scenario_pentest["guide_id"]] = scenario_pentest


def list_guides(kind: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(GUIDES.values())
    if kind:
        items = [x for x in items if x.get("kind") == kind]
    return [{"guide_id": g["guide_id"], "name": g["name"], "kind": g["kind"],
             "version": g["version"], "steps": len(g.get("steps", []))}
            for g in items]


def get_guide(guide_id: str) -> Optional[Dict[str, Any]]:
    return GUIDES.get(guide_id)


def create_guide(payload: Dict[str, Any]) -> Dict[str, Any]:
    gid = payload.get("guide_id") or _rid("guide")
    g = {
        "guide_id": gid,
        "name": payload.get("name", "未命名引导"),
        "kind": payload.get("kind", "feature"),
        "version": payload.get("version", "1.0"),
        "steps": payload.get("steps", []),
        "created_at": _now(),
    }
    GUIDES[gid] = g
    return g


def update_guide(guide_id: str,
                 payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    g = GUIDES.get(guide_id)
    if not g:
        return None
    for k in ("name", "steps", "version"):
        if k in payload:
            g[k] = payload[k]
    g["updated_at"] = _now()
    return g


# --------------------------------------------------------------------------- #
# 2. 引导进度（用户真实追踪）
# --------------------------------------------------------------------------- #
def start_guide(guide_id: str, user: str = "anonymous") -> Dict[str, Any]:
    g = GUIDES.get(guide_id)
    if not g:
        raise KeyError(guide_id)
    pid = _rid("gp")
    prog = {
        "progress_id": pid,
        "guide_id": guide_id,
        "guide_name": g["name"],
        "user": user,
        "step_index": 0,
        "total_steps": len(g.get("steps", [])),
        "status": "in_progress",
        "started_at": _now(),
        "updated_at": _now(),
        "skipped": False,
    }
    GUIDE_PROGRESS[pid] = prog
    return prog


def advance_guide(progress_id: str,
                  action: str = "next") -> Dict[str, Any]:
    p = GUIDE_PROGRESS.get(progress_id)
    if not p:
        raise KeyError(progress_id)
    if action == "next":
        p["step_index"] = min(p["step_index"] + 1, p["total_steps"])
    elif action == "prev":
        p["step_index"] = max(p["step_index"] - 1, 0)
    elif action == "skip":
        p["status"] = "skipped"
        p["skipped"] = True
    elif action == "complete":
        p["step_index"] = p["total_steps"]
        p["status"] = "completed"
    p["updated_at"] = _now()
    if p["step_index"] >= p["total_steps"] and p["status"] != "skipped":
        p["status"] = "completed"
    return p


def list_guide_progress(user: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(GUIDE_PROGRESS.values())
    if user:
        items = [x for x in items if x.get("user") == user]
    return items


# --------------------------------------------------------------------------- #
# 3. 引导管理 / A-B 测试 / 效果分析
# --------------------------------------------------------------------------- #
def create_ab_test(payload: Dict[str, Any]) -> Dict[str, Any]:
    tid = payload.get("test_id") or _rid("ab")
    t = {
        "test_id": tid,
        "name": payload.get("name", "未命名 A/B 测试"),
        "guide_id_a": payload.get("guide_id_a"),
        "guide_id_b": payload.get("guide_id_b"),
        "traffic_split": int(payload.get("traffic_split", 50)),
        "status": payload.get("status", "running"),
        "started_at": _now(),
        "metrics": {"a_completions": 0, "b_completions": 0,
                    "a_users": 0, "b_users": 0},
    }
    AB_TESTS[tid] = t
    return t


def record_ab_conversion(test_id: str, variant: str) -> Dict[str, Any]:
    t = AB_TESTS.get(test_id)
    if not t:
        raise KeyError(test_id)
    if variant == "a":
        t["metrics"]["a_completions"] += 1
    else:
        t["metrics"]["b_completions"] += 1
    return t


def get_effect_analysis(guide_id: Optional[str] = None) -> Dict[str, Any]:
    items = list(GUIDE_PROGRESS.values())
    if guide_id:
        items = [x for x in items if x.get("guide_id") == guide_id]
    total = len(items)
    completed = sum(1 for x in items if x["status"] == "completed")
    skipped = sum(1 for x in items if x["status"] == "skipped")
    return {
        "total_sessions": total,
        "completed": completed,
        "skipped": skipped,
        "completion_rate_pct": round(completed / total * 100, 1) if total else 0.0,
        "skip_rate_pct": round(skipped / total * 100, 1) if total else 0.0,
        "a_tests": list(AB_TESTS.values()),
    }


# --------------------------------------------------------------------------- #
# 4. 提示系统（Tooltip / Inline / Context / Toast）
# --------------------------------------------------------------------------- #
def create_tooltip(payload: Dict[str, Any]) -> Dict[str, Any]:
    tid = payload.get("tooltip_id") or _rid("tip")
    tip = {
        "tooltip_id": tid,
        "selector": payload.get("selector", "body"),
        "kind": payload.get("kind", "tooltip"),  # tooltip/inline/context/toast
        "level": payload.get("level", "info"),  # info/success/warning/error
        "title": payload.get("title", ""),
        "body": payload.get("body", ""),
        "placement": payload.get("placement", "top"),
        "dismissible": bool(payload.get("dismissible", True)),
        "created_at": _now(),
    }
    TOOLTIPS[tid] = tip
    return tip


def list_tooltips(level: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(TOOLTIPS.values())
    if level:
        items = [x for x in items if x.get("level") == level]
    return items


def notify(level: str, title: str, body: str = "") -> Dict[str, Any]:
    return {
        "notify_id": _rid("ntf"),
        "level": level, "title": title, "body": body,
        "at": _now(),
    }


# --------------------------------------------------------------------------- #
# 5. 帮助中心
# --------------------------------------------------------------------------- #
def _build_default_help() -> None:
    docs = [
        {"doc_id": "help_getting_started", "title": "快速开始",
         "category": "入门", "body": "安装、登录、首次扫描的完整步骤。",
         "video_url": "/media/help/getting-started.mp4"},
        {"doc_id": "help_pentest", "title": "渗透测试模块",
         "category": "功能", "body": "Web/服务/内网渗透的使用说明。",
         "video_url": "/media/help/pentest.mp4"},
        {"doc_id": "help_report", "title": "报告导出",
         "category": "功能", "body": "PDF/Word/HTML 报告模板与导出。",
         "video_url": "/media/help/report.mp4"},
        {"doc_id": "help_faq", "title": "常见问题",
         "category": "FAQ", "body": "连接失败/授权/许可证等问题。",
         "video_url": ""},
    ]
    for d in docs:
        HELP_DOCS[d["doc_id"]] = d


def search_help(keyword: str) -> List[Dict[str, Any]]:
    kw = (keyword or "").lower()
    return [d for d in HELP_DOCS.values()
            if not kw or kw in d.get("title", "").lower()
            or kw in d.get("body", "").lower()]


def list_help_docs(category: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(HELP_DOCS.values())
    if category:
        items = [x for x in items if x.get("category") == category]
    return items


def get_help_doc(doc_id: str) -> Optional[Dict[str, Any]]:
    return HELP_DOCS.get(doc_id)


def submit_ticket(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ticket_id": _rid("tk"),
        "user": payload.get("user", "anonymous"),
        "subject": payload.get("subject", ""),
        "body": payload.get("body", ""),
        "priority": payload.get("priority", "normal"),
        "status": "open",
        "created_at": _now(),
    }


# 初始化
if not GUIDES:
    _build_default_guides()
if not HELP_DOCS:
    _build_default_help()
