# -*- coding: utf-8 -*-
"""
platform_management_phase.py — 阶段1：SRC 平台管理。

功能:
    - SRC 平台创建（名称/Logo/描述/联系方式/官网）
    - 平台配置（测试范围/漏洞规则/赏金标准/等级体系/奖励规则）
    - 白帽管理（注册/审核/信息/状态/黑名单）
    - 企业管理（注册/审核/信息/资产范围/联系人）
    - 平台规则管理（提交规范/审核标准/赏金规则/争议处理）
    - 平台公告管理
    - 平台统计
    - 平台模板（可复用平台配置）
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]
HACKER_STATUSES = ["pending", "approved", "banned", "rejected"]
ENTERPRISE_STATUSES = ["pending", "approved", "suspended"]


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class PlatformManagementPhase:
    """阶段1：SRC 平台管理。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._platforms: Dict[str, Dict[str, Any]] = {}
        self._hackers: Dict[str, Dict[str, Any]] = {}
        self._enterprises: Dict[str, Dict[str, Any]] = {}
        self._announcements: Dict[str, Dict[str, Any]] = {}
        self._templates: Dict[str, Dict[str, Any]] = {}
        self._rules: Dict[str, Dict[str, Any]] = {}
        self._seed()

    # ------------------------------------------------------------------ #
    def _seed(self) -> None:
        pid = "plt_" + uuid.uuid4().hex[:8]
        self._platforms[pid] = {
            "platform_id": pid,
            "name": "示例企业安全应急响应中心",
            "logo": "",
            "description": "面向公众白帽的漏洞响应与赏金平台",
            "contact": "src@example.com",
            "website": "https://src.example.com",
            "config": {
                "scope": ["*.example.com", "*.app.example.cn"],
                "vuln_rules": ["OWASP Top10", "业务逻辑漏洞"],
                "bounty_standard": {
                    "critical": [5000, 50000],
                    "high": [1000, 5000],
                    "medium": [300, 1000],
                    "low": [50, 300],
                    "info": [0, 50],
                },
                "level_system": ["新手", "入门", "进阶", "高级", "专家", "大师"],
                "reward_rules": "首次发现加倍，重复提交递减",
            },
            "created_at": _now(),
            "status": "active",
        }
        self._rules["rule_" + uuid.uuid4().hex[:6]] = {
            "rule_id": "rule_default",
            "submit_spec": "标题简洁、复现步骤完整、附 POC 与截图",
            "review_standard": "可复现、有明确影响、在测试范围内",
            "bounty_rule": "按严重程度与影响范围发放",
            "dispute_rule": "7 日内可申请复议，平台终裁",
            "updated_at": _now(),
        }
        # 模板
        self._templates["tpl_standard"] = {
            "template_id": "tpl_standard",
            "name": "标准 SRC 模板",
            "config": self._platforms[pid]["config"],
            "created_at": _now(),
        }
        # 示例白帽
        for i, nick in enumerate(["白帽小王", "0xC0FFEE", "0dayHunter", "slowmist"]):
            hid = "hkr_" + uuid.uuid4().hex[:8]
            self._hackers[hid] = {
                "hacker_id": hid, "nickname": nick,
                "avatar": "", "bio": "热爱安全的白帽",
                "skills": ["Web安全", "逻辑漏洞"],
                "level": "进阶", "points": 1200 + i * 300,
                "status": "approved" if i else "pending",
                "blacklisted": False,
                "registered_at": _now(),
            }
        # 示例企业
        eid = "ent_" + uuid.uuid4().hex[:8]
        self._enterprises[eid] = {
            "enterprise_id": eid,
            "name": "示例科技有限公司",
            "assets": ["*.example.com", "10.0.0.0/8", "APP: com.example.app"],
            "contact": "sec@example.com",
            "status": "approved",
            "registered_at": _now(),
        }
        aid = "ann_" + uuid.uuid4().hex[:8]
        self._announcements[aid] = {
            "ann_id": aid, "title": "平台上线公告",
            "content": "欢迎各位白帽提交漏洞，祝一血！",
            "created_at": _now(), "publisher": "admin",
        }

    # ------------------------------------------------------------------ #
    # 平台 CRUD
    # ------------------------------------------------------------------ #
    def create_platform(self, name: str, description: str = "",
                        contact: str = "", website: str = "",
                        logo: str = "") -> Dict[str, Any]:
        pid = "plt_" + uuid.uuid4().hex[:10]
        with self._lock:
            self._platforms[pid] = {
                "platform_id": pid, "name": name, "logo": logo,
                "description": description, "contact": contact,
                "website": website,
                "config": {
                    "scope": [], "vuln_rules": [],
                    "bounty_standard": {k: [0, 0] for k in SEVERITY_LEVELS},
                    "level_system": ["新手", "入门", "进阶", "高级",
                                     "专家", "大师"],
                    "reward_rules": "",
                },
                "created_at": _now(), "status": "active",
            }
            return self._platforms[pid]

    def list_platforms(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._platforms.values())

    def get_platform(self, pid: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._platforms.get(pid)

    def update_platform_config(self, pid: str,
                               config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            p = self._platforms.get(pid)
            if not p:
                return None
            p["config"].update(config)
            p["updated_at"] = _now()
            return p

    # ------------------------------------------------------------------ #
    # 白帽管理
    # ------------------------------------------------------------------ #
    def register_hacker(self, nickname: str, bio: str = "",
                       skills: Optional[List[str]] = None) -> Dict[str, Any]:
        hid = "hkr_" + uuid.uuid4().hex[:10]
        with self._lock:
            self._hackers[hid] = {
                "hacker_id": hid, "nickname": nickname,
                "avatar": "", "bio": bio,
                "skills": skills or [],
                "level": "新手", "points": 0,
                "status": "pending", "blacklisted": False,
                "registered_at": _now(),
            }
            return self._hackers[hid]

    def review_hacker(self, hid: str, approve: bool) -> Optional[Dict[str, Any]]:
        with self._lock:
            h = self._hackers.get(hid)
            if not h:
                return None
            h["status"] = "approved" if approve else "rejected"
            return h

    def ban_hacker(self, hid: str, ban: bool = True) -> Optional[Dict[str, Any]]:
        with self._lock:
            h = self._hackers.get(hid)
            if not h:
                return None
            h["blacklisted"] = ban
            h["status"] = "banned" if ban else "approved"
            return h

    def list_hackers(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._hackers.values())
        if status:
            out = [h for h in out if h["status"] == status]
        return out

    # ------------------------------------------------------------------ #
    # 企业管理
    # ------------------------------------------------------------------ #
    def register_enterprise(self, name: str,
                           assets: Optional[List[str]] = None,
                           contact: str = "") -> Dict[str, Any]:
        eid = "ent_" + uuid.uuid4().hex[:10]
        with self._lock:
            self._enterprises[eid] = {
                "enterprise_id": eid, "name": name,
                "assets": assets or [], "contact": contact,
                "status": "pending", "registered_at": _now(),
            }
            return self._enterprises[eid]

    def review_enterprise(self, eid: str, approve: bool) -> Optional[Dict[str, Any]]:
        with self._lock:
            e = self._enterprises.get(eid)
            if not e:
                return None
            e["status"] = "approved" if approve else "suspended"
            return e

    def list_enterprises(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._enterprises.values())

    # ------------------------------------------------------------------ #
    # 规则 / 公告 / 模板
    # ------------------------------------------------------------------ #
    def update_rules(self, rules: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            r = self._rules.setdefault("rule_default",
                                       {"rule_id": "rule_default"})
            r.update(rules)
            r["updated_at"] = _now()
            return r

    def get_rules(self) -> Dict[str, Any]:
        with self._lock:
            return self._rules.get("rule_default", {})

    def create_announcement(self, title: str, content: str,
                           publisher: str = "admin") -> Dict[str, Any]:
        aid = "ann_" + uuid.uuid4().hex[:10]
        with self._lock:
            self._announcements[aid] = {
                "ann_id": aid, "title": title, "content": content,
                "publisher": publisher, "created_at": _now(),
            }
            return self._announcements[aid]

    def list_announcements(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._announcements.values())[::-1]

    def save_template(self, name: str,
                      config: Dict[str, Any]) -> Dict[str, Any]:
        tid = "tpl_" + uuid.uuid4().hex[:8]
        with self._lock:
            self._templates[tid] = {
                "template_id": tid, "name": name,
                "config": config, "created_at": _now(),
            }
            return self._templates[tid]

    def list_templates(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._templates.values())

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            hackers = list(self._hackers.values())
            enterprises = list(self._enterprises.values())
            return {
                "platforms": len(self._platforms),
                "hackers_total": len(hackers),
                "hackers_approved": sum(
                    1 for h in hackers if h["status"] == "approved"),
                "hackers_pending": sum(
                    1 for h in hackers if h["status"] == "pending"),
                "hackers_banned": sum(
                    1 for h in hackers if h["blacklisted"]),
                "enterprises_total": len(enterprises),
                "enterprises_approved": sum(
                    1 for e in enterprises if e["status"] == "approved"),
                "announcements": len(self._announcements),
                "templates": len(self._templates),
                "ts": _now(),
            }


_default: Optional[PlatformManagementPhase] = None


def get_platform_management_phase() -> PlatformManagementPhase:
    global _default
    if _default is None:
        _default = PlatformManagementPhase()
    return _default
