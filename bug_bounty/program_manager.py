#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
program_manager.py — SRC 项目与范围管理。

覆盖：
    - SRC 项目 CRUD（名称/描述/目标范围/规则/奖励范围/时间线/状态/类型/行业/Logo）
    - 测试范围管理（允许测试的域名/IP/应用/API/排除范围/敏感操作限制/范围类型/优先级）
    - 奖励规则配置（漏洞类型/严重程度/奖励金额范围/重复漏洞处理/信息泄露处理/奖励倍数/上限）
    - 项目公告与更新（公告发布/更新日志/规则变更/范围变更/奖励变更/通知推送）
    - 项目统计（提交数/有效漏洞数/已修复数/总赏金/参与白帽数/平均响应/平均修复/有效率）
    - 项目生命周期（草稿/招募中/进行中/暂停/已结束/归档，状态流转/时间线/里程碑）

全部使用内存字典模拟，不创建数据库表。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
PROJECT_STATUSES = ["draft", "recruiting", "active", "paused", "closed", "archived"]
PROJECT_TYPES = ["public", "private", "invite_only", "vdp"]
PROJECT_INDUSTRIES = [
    "互联网", "金融", "电商", "游戏", "政务", "教育", "医疗",
    "能源", "物流", "出行", "社交", "硬件", "云服务", "其他",
]
SCOPE_TYPES = ["domain", "ip", "app", "api", "mobile", "iot", "hardware", "source"]
SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]
VULN_TYPES = [
    "sql_injection", "xss", "csrf", "ssrf", "rce", "xxe", "deserialization",
    "auth_bypass", "access_control", "info_disclosure", "sensitive_data_exposure",
    "crypto_weakness", "misconfiguration", "upload_rce", "log4j", "sslvpn",
    "business_logic", "race_condition", "idor", "redirect", "other",
]


# --------------------------------------------------------------------------- #
# 内存存储
# --------------------------------------------------------------------------- #
class _Store:
    def __init__(self) -> None:
        self.projects: Dict[str, Dict[str, Any]] = {}
        self.scopes: Dict[str, List[Dict[str, Any]]] = {}
        self.bounty_rules: Dict[str, Dict[str, Any]] = {}
        self.announcements: Dict[str, List[Dict[str, Any]]] = {}
        self.changelog: Dict[str, List[Dict[str, Any]]] = {}

    def reset(self) -> None:
        self.__init__()


STORE = _Store()


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- #
# 项目 CRUD
# --------------------------------------------------------------------------- #
def create_project(payload: Dict[str, Any]) -> Dict[str, Any]:
    """创建 SRC 项目。"""
    pid = payload.get("id") or _uid("proj")
    project = {
        "id": pid,
        "name": payload.get("name", "未命名项目"),
        "description": payload.get("description", ""),
        "type": payload.get("type", "public"),
        "industry": payload.get("industry", "互联网"),
        "logo": payload.get("logo", ""),
        "rules": payload.get("rules", ""),
        "reward_overview": payload.get("reward_overview", ""),
        "start_date": payload.get("start_date", _now()[:10]),
        "end_date": payload.get("end_date", ""),
        "status": payload.get("status", "draft"),
        "created_at": _now(),
        "updated_at": _now(),
        "owner": payload.get("owner", "platform"),
        "milestones": payload.get("milestones", []),
    }
    STORE.projects[pid] = project
    STORE.scopes[pid] = []
    STORE.bounty_rules[pid] = _default_bounty_rules()
    STORE.announcements[pid] = []
    STORE.changelog[pid] = []
    _append_changelog(pid, "创建项目", f"项目 {project['name']} 创建完成")
    return project


def list_projects(status: Optional[str] = None,
                 industry: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(STORE.projects.values())
    if status:
        items = [p for p in items if p.get("status") == status]
    if industry:
        items = [p for p in items if p.get("industry") == industry]
    return items


def get_project(pid: str) -> Optional[Dict[str, Any]]:
    return STORE.projects.get(pid)


def update_project(pid: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    p = STORE.projects.get(pid)
    if not p:
        return None
    for k, v in patch.items():
        if k in ("name", "description", "type", "industry", "logo", "rules",
                 "reward_overview", "start_date", "end_date", "owner", "milestones"):
            p[k] = v
    p["updated_at"] = _now()
    _append_changelog(pid, "项目信息更新", f"字段更新: {list(patch.keys())}")
    return p


def delete_project(pid: str) -> bool:
    for store in (STORE.projects, STORE.scopes, STORE.bounty_rules,
                  STORE.announcements, STORE.changelog):
        store.pop(pid, None)
    return True


# --------------------------------------------------------------------------- #
# 生命周期状态流转
# --------------------------------------------------------------------------- #
_TRANSITIONS = {
    "draft": {"recruiting", "archived"},
    "recruiting": {"active", "paused", "closed", "archived"},
    "active": {"paused", "closed"},
    "paused": {"active", "closed"},
    "closed": {"archived"},
    "archived": set(),
}


def transition_status(pid: str, new_status: str,
                      note: str = "") -> Dict[str, Any]:
    p = STORE.projects.get(pid)
    if not p:
        return {"ok": False, "reason": "项目不存在"}
    if new_status not in PROJECT_STATUSES:
        return {"ok": False, "reason": f"非法状态 {new_status}"}
    cur = p["status"]
    if new_status not in _TRANSITIONS.get(cur, set()):
        return {"ok": False, "reason": f"不允许从 {cur} 流转到 {new_status}"}
    p["status"] = new_status
    p["updated_at"] = _now()
    _append_changelog(pid, "状态流转", f"{cur} -> {new_status} {note}".strip())
    return {"ok": True, "old": cur, "new": new_status, "project": p}


# --------------------------------------------------------------------------- #
# 范围管理
# --------------------------------------------------------------------------- #
def add_scope(pid: str, scope: Dict[str, Any]) -> Dict[str, Any]:
    sid = scope.get("id") or _uid("scope")
    item = {
        "id": sid,
        "project_id": pid,
        "type": scope.get("type", "domain"),
        "value": scope.get("value", ""),
        "description": scope.get("description", ""),
        "priority": scope.get("priority", "normal"),
        "is_excluded": bool(scope.get("is_excluded", False)),
        "sensitive_restrictions": scope.get("sensitive_restrictions", []),
        "created_at": _now(),
    }
    STORE.scopes.setdefault(pid, []).append(item)
    _append_changelog(pid, "范围变更",
                       f"{'排除' if item['is_excluded'] else '加入'}范围: {item['value']}")
    return item


def list_scopes(pid: str, only_in_scope: bool = False) -> List[Dict[str, Any]]:
    items = STORE.scopes.get(pid, [])
    if only_in_scope:
        return [s for s in items if not s.get("is_excluded")]
    return items


def remove_scope(pid: str, sid: str) -> bool:
    items = STORE.scopes.get(pid, [])
    before = len(items)
    STORE.scopes[pid] = [s for s in items if s.get("id") != sid]
    return len(STORE.scopes[pid]) < before


# --------------------------------------------------------------------------- #
# 奖励规则
# --------------------------------------------------------------------------- #
def _default_bounty_rules() -> Dict[str, Any]:
    return {
        "version": 1,
        "updated_at": _now(),
        "amounts": {
            "critical": [50000, 200000],
            "high": [10000, 50000],
            "medium": [2000, 10000],
            "low": [500, 2000],
            "info": [0, 500],
        },
        "duplicate_policy": "first_reporter_full_others_20pct",
        "info_disclosure_policy": "ignore_unless_pii",
        "multiplier_by_level": {"newbie": 1.0, "certified": 1.1,
                                "advanced": 1.25, "core": 1.5},
        "max_per_vuln": 200000,
        "min_payout": 100,
    }


def get_bounty_rules(pid: str) -> Optional[Dict[str, Any]]:
    return STORE.bounty_rules.get(pid)


def update_bounty_rules(pid: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    rules = STORE.bounty_rules.setdefault(pid, _default_bounty_rules())
    for k in ("amounts", "duplicate_policy", "info_disclosure_policy",
              "multiplier_by_level", "max_per_vuln", "min_payout"):
        if k in patch:
            rules[k] = patch[k]
    rules["version"] = int(rules.get("version", 1)) + 1
    rules["updated_at"] = _now()
    _append_changelog(pid, "奖励变更",
                      f"奖励规则升级到 v{rules['version']}")
    return rules


# --------------------------------------------------------------------------- #
# 公告与更新
# --------------------------------------------------------------------------- #
def publish_announcement(pid: str, title: str, content: str,
                         level: str = "info") -> Dict[str, Any]:
    ann = {
        "id": _uid("ann"),
        "project_id": pid,
        "title": title,
        "content": content,
        "level": level,
        "pushed": True,
        "created_at": _now(),
    }
    STORE.announcements.setdefault(pid, []).append(ann)
    return ann


def list_announcements(pid: str) -> List[Dict[str, Any]]:
    return list(reversed(STORE.announcements.get(pid, [])))


def _append_changelog(pid: str, kind: str, detail: str) -> None:
    STORE.changelog.setdefault(pid, []).append({
        "id": _uid("log"), "kind": kind, "detail": detail, "time": _now(),
    })


def list_changelog(pid: str) -> List[Dict[str, Any]]:
    return list(reversed(STORE.changelog.get(pid, [])))


# --------------------------------------------------------------------------- #
# 项目统计（由外部数据回灌）
# --------------------------------------------------------------------------- #
def project_stats(pid: str, external: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    p = STORE.projects.get(pid)
    base = {
        "project_id": pid,
        "project_name": p["name"] if p else pid,
        "submissions": 0,
        "valid_count": 0,
        "fixed_count": 0,
        "total_bounty": 0,
        "hunters": 0,
        "avg_response_hours": 0.0,
        "avg_fix_hours": 0.0,
        "valid_rate": 0.0,
        "scope_count": len(STORE.scopes.get(pid, [])),
        "announcement_count": len(STORE.announcements.get(pid, [])),
    }
    if external:
        base.update({k: v for k, v in external.items() if k in base})
    if base["submissions"]:
        base["valid_rate"] = round(base["valid_count"] / base["submissions"], 4)
    return base


def all_project_stats() -> List[Dict[str, Any]]:
    return [project_stats(pid) for pid in STORE.projects]


# --------------------------------------------------------------------------- #
# 种子数据
# --------------------------------------------------------------------------- #
def seed_demo() -> None:
    if STORE.projects:
        return
    p1 = create_project({
        "name": "某电商 SRC 公开项目",
        "description": "面向白帽的公开漏洞赏金项目，覆盖主站、App、开放API",
        "type": "public", "industry": "电商",
        "rules": "禁止 DoS、社工、越权数据访问；POC 必须最小化。",
        "reward_overview": "高危 1w-5w，严重 5w-20w",
        "status": "active",
    })
    add_scope(p1["id"], {"type": "domain", "value": "*.example-mall.com",
                         "priority": "high"})
    add_scope(p1["id"], {"type": "app", "value": "com.example.mall",
                         "priority": "high"})
    add_scope(p1["id"], {"type": "domain", "value": "*.internal.example-mall.com",
                         "is_excluded": True,
                         "sensitive_restrictions": ["禁止测试生产数据库"]})
    publish_announcement(p1["id"], "项目上线公告",
                         "欢迎各位白帽提交漏洞，奖励按等级发放。", "info")

    p2 = create_project({
        "name": "某银行 VDP",
        "description": "自愿披露计划，无现金奖励，以致谢为主",
        "type": "vdp", "industry": "金融",
        "rules": "仅限合规披露，禁止触碰真实客户数据。",
        "reward_overview": "致谢/证书",
        "status": "recruiting",
    })
    add_scope(p2["id"], {"type": "domain", "value": "*.bank-example.cn",
                         "priority": "critical"})
