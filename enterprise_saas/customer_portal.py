# -*- coding: utf-8 -*-
"""
customer_portal.py — 客户自助门户核心模块。

覆盖：
- 个人中心（信息/密码/头像/偏好/通知/安全）
- 账户管理（信息/订阅/用量/账单/发票/支付方式）
- 团队管理（创建/邀请/成员/角色/配额/统计）
- 项目管理（创建/配置/成员/配额/统计/归档）
- 资源管理（资产/扫描/报告/知识库/插件/集成/API密钥）
- 帮助中心（文档/教程/FAQ/工单/客服/社区/状态页）

全部内存字典模拟。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _uid(prefix: str = "") -> str:
    return prefix + uuid.uuid4().hex[:12]


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(c for c in obj if c >= " " or c in "\n\r\t")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    return obj


# --------------------------------------------------------------------------- #
# 内存存储
# --------------------------------------------------------------------------- #
class PortalStore:
    def __init__(self) -> None:
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.notification_settings: Dict[str, Dict[str, bool]] = {}
        self.security_settings: Dict[str, Dict[str, Any]] = {}
        self.teams: Dict[str, Dict[str, Any]] = {}
        self.team_members: Dict[str, List[str]] = {}
        self.portal_projects: Dict[str, Dict[str, Any]] = {}
        self.resources: Dict[str, Dict[str, List[Dict]]] = {}
        self.api_keys: Dict[str, List[Dict[str, Any]]] = {}
        self.tickets: Dict[str, Dict[str, Any]] = {}
        self.faq_items: List[Dict[str, Any]] = []
        self._seed_faq()

    def _seed_faq(self) -> None:
        faqs = [
            {"id": "faq_1", "category": "账户", "question": "如何修改密码？",
             "answer": "进入个人中心 → 安全设置 → 修改密码，输入旧密码和新密码即可。"},
            {"id": "faq_2", "category": "计费", "question": "如何升级订阅计划？",
             "answer": "进入账户管理 → 订阅状态 → 选择升级计划，确认后立即生效。"},
            {"id": "faq_3", "category": "扫描", "question": "扫描失败怎么办？",
             "answer": "检查目标网络连通性，确认配额未超限，查看扫描日志中的错误详情。"},
            {"id": "faq_4", "category": "SSO", "question": "如何配置企业SSO？",
             "answer": "进入企业设置 → SSO配置，选择身份提供商类型，导入元数据后完成配置。"},
            {"id": "faq_5", "category": "API", "question": "API密钥如何创建？",
             "answer": "进入资源管理 → API密钥 → 创建密钥，设置权限范围和过期时间。"},
        ]
        self.faq_items = faqs


_store = PortalStore()


# --------------------------------------------------------------------------- #
# 1. 个人中心
# --------------------------------------------------------------------------- #
def init_profile(user_id: str, tenant_id: str,
                 email: str, name: str) -> Dict[str, Any]:
    profile = {
        "user_id": user_id, "tenant_id": tenant_id,
        "email": email, "name": name, "avatar": "",
        "preferences": {"language": "zh-CN", "theme": "dark",
                        "timezone": "Asia/Shanghai"},
        "notification_settings": {"email": True, "sms": False,
                                  "in_app": True, "weekly_report": True},
        "security_settings": {"mfa_enabled": False,
                              "login_alerts": True,
                              "session_timeout_min": 30},
        "created_at": _now(), "updated_at": _now(),
    }
    _store.profiles[user_id] = profile
    _store.notification_settings[user_id] = profile["notification_settings"]
    _store.security_settings[user_id] = profile["security_settings"]
    return profile


def get_profile(user_id: str) -> Optional[Dict[str, Any]]:
    return _store.profiles.get(user_id)


def update_profile(user_id: str,
                   updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    p = _store.profiles.get(user_id)
    if not p:
        return None
    for k in ("name", "avatar", "preferences"):
        if k in updates:
            if k == "preferences" and isinstance(updates[k], dict):
                p["preferences"].update(updates[k])
            else:
                p[k] = updates[k]
    p["updated_at"] = _now()
    return p


def change_password(user_id: str, old_pwd: str,
                    new_pwd: str) -> Dict[str, Any]:
    if len(new_pwd) < 8:
        return {"success": False, "error": "新密码长度至少8位"}
    p = _store.profiles.get(user_id)
    if not p:
        return {"success": False, "error": "用户不存在"}
    # 模拟密码验证（实际应哈希比对）
    p["password_updated_at"] = _now()
    return {"success": True, "message": "密码修改成功"}


def set_notification_prefs(user_id: str,
                          prefs: Dict[str, bool]) -> Optional[Dict]:
    _store.notification_settings[user_id] = prefs
    p = _store.profiles.get(user_id)
    if p:
        p["notification_settings"] = prefs
    return prefs


def set_security_prefs(user_id: str,
                       prefs: Dict[str, Any]) -> Optional[Dict]:
    _store.security_settings[user_id] = prefs
    p = _store.profiles.get(user_id)
    if p:
        p["security_settings"] = prefs
    return prefs


# --------------------------------------------------------------------------- #
# 2. 账户管理
# --------------------------------------------------------------------------- #
def get_account_overview(user_id: str) -> Dict[str, Any]:
    p = _store.profiles.get(user_id)
    if not p:
        return {}
    from . import billing_system
    sub = billing_system.get_subscription(p["tenant_id"])
    usage = billing_system.get_usage_summary(p["tenant_id"])
    return {
        "user_id": user_id, "name": p["name"], "email": p["email"],
        "tenant_id": p["tenant_id"],
        "subscription": sub,
        "usage_summary": usage,
        "preferences": p["preferences"],
    }


def get_billing_history(tenant_id: str) -> Dict[str, Any]:
    from . import billing_system
    return billing_system.list_invoices(tenant_id=tenant_id)


# --------------------------------------------------------------------------- #
# 3. 团队管理
# --------------------------------------------------------------------------- #
def create_team(tenant_id: str, name: str,
                description: str = "") -> Dict[str, Any]:
    tid = _uid("tm_")
    team = {
        "id": tid, "tenant_id": tenant_id, "name": name,
        "description": description, "members": [],
        "quota": {"max_members": 50}, "stats": {"member_count": 0},
        "created_at": _now(),
    }
    _store.teams[tid] = team
    _store.team_members[tid] = []
    return team


def list_teams(tenant_id: str) -> List[Dict[str, Any]]:
    return [t for t in _store.teams.values()
            if t["tenant_id"] == tenant_id]


def add_team_member(team_id: str, user_id: str,
                    role: str = "member") -> Optional[Dict]:
    team = _store.teams.get(team_id)
    if not team:
        return None
    member = {"user_id": user_id, "role": role,
              "joined_at": _now()}
    team["members"].append(member)
    team["stats"]["member_count"] = len(team["members"])
    if team_id not in _store.team_members:
        _store.team_members[team_id] = []
    _store.team_members[team_id].append(user_id)
    return member


def remove_team_member(team_id: str, user_id: str) -> bool:
    team = _store.teams.get(team_id)
    if not team:
        return False
    team["members"] = [m for m in team["members"] if m["user_id"] != user_id]
    team["stats"]["member_count"] = len(team["members"])
    if team_id in _store.team_members:
        _store.team_members[team_id] = [
            u for u in _store.team_members[team_id] if u != user_id]
    return True


def get_team_stats(team_id: str) -> Optional[Dict[str, Any]]:
    team = _store.teams.get(team_id)
    if not team:
        return None
    return {
        "team_id": team_id, "name": team["name"],
        "member_count": team["stats"]["member_count"],
        "quota": team["quota"],
        "members": team["members"],
    }


# --------------------------------------------------------------------------- #
# 4. 项目管理
# --------------------------------------------------------------------------- #
def create_portal_project(tenant_id: str, name: str,
                          config: Optional[Dict] = None) -> Dict[str, Any]:
    pid = _uid("pjp_")
    project = {
        "id": pid, "tenant_id": tenant_id, "name": name,
        "config": config or {}, "members": [],
        "quota": {"max_scans": 100, "max_storage_mb": 5000},
        "stats": {"scans_count": 0, "reports_count": 0},
        "status": "active", "archived": False,
        "created_at": _now(),
    }
    _store.portal_projects[pid] = project
    return project


def list_portal_projects(tenant_id: str,
                         include_archived: bool = False) -> List[Dict]:
    items = [p for p in _store.portal_projects.values()
             if p["tenant_id"] == tenant_id]
    if not include_archived:
        items = [p for p in items if not p["archived"]]
    return items


def archive_project(project_id: str) -> Optional[Dict]:
    p = _store.portal_projects.get(project_id)
    if not p:
        return None
    p["archived"] = True
    p["status"] = "archived"
    p["archived_at"] = _now()
    return p


# --------------------------------------------------------------------------- #
# 5. 资源管理
# --------------------------------------------------------------------------- #
def create_api_key(tenant_id: str, name: str,
                   permissions: Optional[List[str]] = None,
                   expires_days: int = 90) -> Dict[str, Any]:
    kid = _uid("key_")
    key = {
        "id": kid, "tenant_id": tenant_id, "name": name,
        "key": "ak_" + uuid.uuid4().hex[:32],
        "secret": "sk_" + uuid.uuid4().hex[:32],
        "permissions": permissions or ["scan.run", "report.view"],
        "created_at": _now(),
        "expires_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                     time.localtime(time.time() + expires_days * 86400)),
        "last_used": None, "status": "active",
    }
    if tenant_id not in _store.api_keys:
        _store.api_keys[tenant_id] = []
    _store.api_keys[tenant_id].append(key)
    return key


def list_api_keys(tenant_id: str) -> List[Dict[str, Any]]:
    return _store.api_keys.get(tenant_id, [])


def revoke_api_key(tenant_id: str, key_id: str) -> bool:
    keys = _store.api_keys.get(tenant_id, [])
    for k in keys:
        if k["id"] == key_id:
            k["status"] = "revoked"
            k["revoked_at"] = _now()
            return True
    return False


def list_resources(tenant_id: str,
                   resource_type: str = "") -> Dict[str, Any]:
    types = ["assets", "scans", "reports", "knowledge_base",
             "plugins", "integrations"]
    result: Dict[str, Any] = {}
    for t in types:
        if resource_type and t != resource_type:
            continue
        result[t] = _store.resources.get(tenant_id, {}).get(t, [])
    return result


# --------------------------------------------------------------------------- #
# 6. 帮助中心
# --------------------------------------------------------------------------- #
def list_faq(category: str = "") -> List[Dict[str, Any]]:
    if category:
        return [f for f in _store.faq_items if f["category"] == category]
    return _store.faq_items


def create_ticket(tenant_id: str, user_id: str, subject: str,
                  description: str, priority: str = "normal") -> Dict[str, Any]:
    tid = _uid("tk_")
    ticket = {
        "id": tid, "tenant_id": tenant_id, "user_id": user_id,
        "subject": subject, "description": description,
        "priority": priority, "status": "open",
        "messages": [{"sender": user_id, "content": description,
                       "timestamp": _now()}],
        "created_at": _now(),
    }
    _store.tickets[tid] = ticket
    return ticket


def list_tickets(tenant_id: str,
                 status: str = "") -> List[Dict[str, Any]]:
    items = [t for t in _store.tickets.values()
             if t["tenant_id"] == tenant_id]
    if status:
        items = [t for t in items if t["status"] == status]
    return items


def get_status_page() -> Dict[str, Any]:
    return {
        "overall_status": "operational",
        "services": [
            {"name": "API服务", "status": "operational", "uptime": "99.98%"},
            {"name": "扫描引擎", "status": "operational", "uptime": "99.95%"},
            {"name": "报告生成", "status": "operational", "uptime": "99.99%"},
            {"name": "SSO认证", "status": "operational", "uptime": "99.97%"},
            {"name": "数据存储", "status": "degraded", "uptime": "99.50%",
             "message": "部分区域写入延迟，正在处理"},
        ],
        "incidents": [],
        "last_updated": _now(),
    }


def get_store() -> PortalStore:
    return _store
