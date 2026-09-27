#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
submission_workflow.py — 漏洞提交与审核流程。

覆盖：
    - 漏洞提交表单（标题/类型/严重程度/目标/复现步骤/影响/修复建议/附件/POC/截图/视频/参考）
    - 漏洞自动分类（基于类型/目标/严重程度的自动路由、标签、优先级）
    - 审核工作流（初审→技术验证→风险确认→奖励评定→修复确认→关闭，
      每步可评论/附件/状态变更/审核人/审核时间）
    - 重复漏洞检测（标题/目标/类型/指纹相似度，重复关联、原漏洞引用、奖励分配）
    - 漏洞状态管理（新建/审核中/已确认/修复中/已修复/已关闭/重复/无效/不予处理/需要更多信息）
    - 漏洞评分（CVSS、严重程度、影响范围、利用难度、报告质量、自动建议+人工调整）

全部内存字典模拟。
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# 状态与工作流常量
# --------------------------------------------------------------------------- #
VULN_STATUSES = [
    "new", "triage", "confirmed", "fixing", "fixed",
    "closed", "duplicate", "invalid", "wont_fix", "need_more_info",
]
REVIEW_STEPS = [
    "triage",         # 初审
    "tech_verify",    # 技术验证
    "risk_confirm",   # 风险确认
    "bounty_review",  # 奖励评定
    "fix_confirm",    # 修复确认
    "closed",         # 关闭
]
SEVERITY_BASE_SCORE = {"info": 1.0, "low": 3.0, "medium": 5.5, "high": 8.0, "critical": 9.5}


class _Store:
    def __init__(self) -> None:
        self.submissions: Dict[str, Dict[str, Any]] = {}
        self.comments: Dict[str, List[Dict[str, Any]]] = {}
        self.attachments: Dict[str, List[Dict[str, Any]]] = {}
        self.history: Dict[str, List[Dict[str, Any]]] = {}
        self.dup_links: Dict[str, List[str]] = {}  # vuln_id -> [original_id, ...]

    def reset(self) -> None:
        self.__init__()


STORE = _Store()


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def _tokenize(text: str) -> List[str]:
    return re.findall(r"[a-zA-Z0-9_\u4e00-\u9fa5]{2,}", (text or "").lower())


# --------------------------------------------------------------------------- #
# 自动分类
# --------------------------------------------------------------------------- #
def auto_classify(vuln_type: str, target: str,
                   severity: str) -> Dict[str, Any]:
    """根据类型/目标/严重程度自动打标签、路由和优先级。"""
    type_tags = {
        "sql_injection": ["注入", "数据库"],
        "xss": ["前端", "反射/存储"],
        "ssrf": ["内网", "云元数据"],
        "rce": ["远程代码执行", "高危"],
        "deserialization": ["反序列化"],
        "auth_bypass": ["身份认证"],
        "access_control": ["越权"],
        "info_disclosure": ["信息泄露"],
        "sensitive_data_exposure": ["敏感数据"],
    }
    tags = list(type_tags.get(vuln_type, [vuln_type]))
    if "api" in (target or "").lower() or "/api/" in (target or ""):
        tags.append("API")
    if any(x in (target or "").lower() for x in ("app", "android", "ios", "apk")):
        tags.append("移动端")
    priority_map = {"critical": "P0", "high": "P1", "medium": "P2",
                    "low": "P3", "info": "P4"}
    routing = "severe_team" if severity in ("critical", "high") else "regular_triage"
    return {
        "tags": tags,
        "priority": priority_map.get(severity, "P3"),
        "routing": routing,
    }


# --------------------------------------------------------------------------- #
# CVSS / 评分
# --------------------------------------------------------------------------- #
def suggest_score(severity: str, impact_scope: str, exploit_difficulty: str,
                  report_quality: str) -> Dict[str, Any]:
    """根据维度自动建议 CVSS 与综合分（0-10）。"""
    base = SEVERITY_BASE_SCORE.get(severity, 5.0)
    impact_adj = {"local": 0.0, "dept": 0.5, "corp": 1.0, "global": 1.5}.get(impact_scope, 0.5)
    diff_adj = {"trivial": 0.8, "easy": 0.4, "medium": 0.0, "hard": -0.6, "expert": -1.2}.get(exploit_difficulty, 0.0)
    quality_adj = {"poor": -0.3, "fair": 0.0, "good": 0.3, "excellent": 0.6}.get(report_quality, 0.0)
    score = round(max(0.0, min(10.0, base + impact_adj + diff_adj + quality_adj)), 1)
    return {
        "cvss_suggest": score,
        "severity_band": ("critical" if score >= 9.0 else "high" if score >= 7.0
                          else "medium" if score >= 4.0 else "low" if score >= 1.0 else "info"),
        "dimensions": {
            "severity_base": base, "impact_adj": impact_adj,
            "exploit_diff_adj": diff_adj, "quality_adj": quality_adj,
        },
        "human_adjusted": False,
    }


# --------------------------------------------------------------------------- #
# 重复检测
# --------------------------------------------------------------------------- #
def _similarity(a: str, b: str) -> float:
    ta, tb = set(_tokenize(a)), set(_tokenize(b))
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def detect_duplicate(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """基于标题+目标+类型+指纹做相似度匹配。返回最相似的历史漏洞。"""
    title = vuln.get("title", "")
    target = vuln.get("target", "")
    vtype = vuln.get("vuln_type", "")
    fingerprint = vuln.get("fingerprint", "")
    best: Tuple[float, Optional[str]] = (0.0, None)
    for vid, old in STORE.submissions.items():
        if old.get("status") in ("duplicate", "invalid", "wont_fix"):
            continue
        score = (
            0.35 * _similarity(title, old.get("title", "")) +
            0.25 * (1.0 if vtype == old.get("vuln_type") else 0.0) +
            0.20 * _similarity(target, old.get("target", "")) +
            0.20 * _similarity(fingerprint, old.get("fingerprint", ""))
        )
        if score > best[0]:
            best = (score, vid)
    threshold = 0.55
    return {
        "is_duplicate": best[0] >= threshold,
        "score": round(best[0], 3),
        "candidate_id": best[1],
        "threshold": threshold,
    }


# --------------------------------------------------------------------------- #
# 提交
# --------------------------------------------------------------------------- #
def submit_vuln(payload: Dict[str, Any]) -> Dict[str, Any]:
    vid = payload.get("id") or _uid("vuln")
    auto = auto_classify(payload.get("vuln_type", "other"),
                         payload.get("target", ""),
                         payload.get("severity", "medium"))
    score = suggest_score(payload.get("severity", "medium"),
                         payload.get("impact_scope", "dept"),
                         payload.get("exploit_difficulty", "medium"),
                         payload.get("report_quality", "good"))
    dup = detect_duplicate(payload)
    vuln = {
        "id": vid,
        "project_id": payload.get("project_id", ""),
        "reporter_id": payload.get("reporter_id", "anon"),
        "title": payload.get("title", ""),
        "vuln_type": payload.get("vuln_type", "other"),
        "severity": payload.get("severity", "medium"),
        "target": payload.get("target", ""),
        "repro_steps": payload.get("repro_steps", ""),
        "impact": payload.get("impact", ""),
        "fix_suggestion": payload.get("fix_suggestion", ""),
        "poc": payload.get("poc", ""),
        "screenshots": payload.get("screenshots", []),
        "video": payload.get("video", ""),
        "references": payload.get("references", []),
        "fingerprint": payload.get("fingerprint", ""),
        "impact_scope": payload.get("impact_scope", "dept"),
        "exploit_difficulty": payload.get("exploit_difficulty", "medium"),
        "report_quality": payload.get("report_quality", "good"),
        "tags": auto["tags"],
        "priority": auto["priority"],
        "routing": auto["routing"],
        "score": score,
        "duplicate_check": dup,
        "status": "new",
        "current_step": "triage",
        "review_history": [],
        "created_at": _now(),
        "updated_at": _now(),
    }
    STORE.submissions[vid] = vuln
    STORE.comments[vid] = []
    STORE.attachments[vid] = list(payload.get("attachments", []))
    STORE.history[vid] = [{
        "time": _now(), "actor": vuln["reporter_id"],
        "from_status": "", "to_status": "new", "note": "提交漏洞",
    }]
    return vuln


def list_submissions(project_id: Optional[str] = None,
                     status: Optional[str] = None,
                     hunter_id: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(STORE.submissions.values())
    if project_id:
        items = [v for v in items if v.get("project_id") == project_id]
    if status:
        items = [v for v in items if v.get("status") == status]
    if hunter_id:
        items = [v for v in items if v.get("reporter_id") == hunter_id]
    return items


def get_submission(vid: str) -> Optional[Dict[str, Any]]:
    return STORE.submissions.get(vid)


# --------------------------------------------------------------------------- #
# 审核工作流
# --------------------------------------------------------------------------- #
def review_step(vid: str, step: str, status: str, reviewer: str,
                note: str = "", attachments: Optional[List[Dict[str, Any]]] = None,
                override_score: Optional[float] = None) -> Dict[str, Any]:
    v = STORE.submissions.get(vid)
    if not v:
        return {"ok": False, "reason": "漏洞不存在"}
    old_status = v["status"]
    v["status"] = status if status in VULN_STATUSES else v["status"]
    v["current_step"] = step if step in REVIEW_STEPS else v["current_step"]
    v["updated_at"] = _now()
    v["review_history"].append({
        "step": step, "status": v["status"], "reviewer": reviewer,
        "note": note, "time": _now(),
    })
    if override_score is not None:
        v["score"]["cvss_suggest"] = float(override_score)
        v["score"]["human_adjusted"] = True
    if attachments:
        STORE.attachments.setdefault(vid, []).extend(attachments)
    STORE.history.setdefault(vid, []).append({
        "time": _now(), "actor": reviewer,
        "from_status": old_status, "to_status": v["status"], "note": note,
    })
    return {"ok": True, "vuln": v}


def link_duplicate(vid: str, original_id: str, reward_note: str = "") -> Dict[str, Any]:
    v = STORE.submissions.get(vid)
    orig = STORE.submissions.get(original_id)
    if not v or not orig:
        return {"ok": False, "reason": "漏洞或原漏洞不存在"}
    v["status"] = "duplicate"
    v["current_step"] = "closed"
    v["duplicate_of"] = original_id
    v["duplicate_note"] = reward_note
    STORE.dup_links.setdefault(original_id, []).append(vid)
    STORE.history.setdefault(vid, []).append({
        "time": _now(), "actor": "triage_bot",
        "from_status": "new", "to_status": "duplicate",
        "note": f"关联原漏洞 {original_id}; {reward_note}",
    })
    return {"ok": True, "vuln": v, "original": orig}


def add_comment(vid: str, author: str, body: str,
                kind: str = "comment") -> Dict[str, Any]:
    if vid not in STORE.submissions:
        return {"ok": False, "reason": "漏洞不存在"}
    c = {"id": _uid("cmt"), "author": author, "body": body,
         "kind": kind, "time": _now()}
    STORE.comments.setdefault(vid, []).append(c)
    return {"ok": True, "comment": c}


def list_comments(vid: str) -> List[Dict[str, Any]]:
    return STORE.comments.get(vid, [])


def list_attachments(vid: str) -> List[Dict[str, Any]]:
    return STORE.attachments.get(vid, [])


def status_history(vid: str) -> List[Dict[str, Any]]:
    return STORE.history.get(vid, [])


# --------------------------------------------------------------------------- #
# 种子
# --------------------------------------------------------------------------- #
def seed_demo() -> None:
    if STORE.submissions:
        return
    submit_vuln({
        "project_id": "demo_proj_1", "reporter_id": "hunter_001",
        "title": "商城订单接口存在 IDOR 越权查询",
        "vuln_type": "idor", "severity": "high",
        "target": "https://api.example-mall.com/order/detail",
        "repro_steps": "1) 登录 A 账号 2) 修改 order_id 3) 可查看 B 订单",
        "impact": "可越权查看任意订单与收货人信息",
        "fix_suggestion": "服务端校验订单归属",
        "fingerprint": "order_id=integer",
        "impact_scope": "corp", "exploit_difficulty": "easy",
        "report_quality": "excellent",
    })
    submit_vuln({
        "project_id": "demo_proj_1", "reporter_id": "hunter_002",
        "title": "登录接口反射型 XSS",
        "vuln_type": "xss", "severity": "medium",
        "target": "https://www.example-mall.com/login",
        "repro_steps": "搜索关键词回显未转义",
        "impact": "钓鱼/会话窃取",
        "fix_suggestion": "输出编码",
        "fingerprint": "keyword=reflect",
        "impact_scope": "local", "exploit_difficulty": "easy",
        "report_quality": "good",
    })
