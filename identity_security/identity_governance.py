#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
identity_governance.py — 身份治理与目录。

覆盖：
    - 用户身份管理：账户/属性/状态/生命周期（入职/转岗/离职）CRUD
    - 身份目录集成：AD / LDAP / Okta / Azure AD / 本地目录 同步
    - 身份图谱：用户-角色-权限-资源关系、身份血缘、权限继承
    - 身份生命周期自动化：入职开通 / 转岗调整 / 离职回收 / 定期复核
    - 身份数据质量：孤儿/重复/过期/不完整账户、质量评分与清理建议

设计定位：仅做身份治理视角的盘点、建模与合规分析，输出报告与建议。
所有第三方库（ldap3、okta 等）try-import，缺失时回退模拟数据。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 目录类型库
# --------------------------------------------------------------------------- #
DIRECTORY_TYPES: Dict[str, Dict[str, Any]] = {
    "active_directory": {"name": "Microsoft AD", "vendor": "Microsoft",
                         "protocol": "LDAP/LDAPS", "sync_interval_min": 60},
    "ldap": {"name": "OpenLDAP / 通用 LDAP", "vendor": "OpenLDAP",
             "protocol": "LDAP/LDAPS", "sync_interval_min": 60},
    "okta": {"name": "Okta Universal Directory", "vendor": "Okta",
             "protocol": "SCIM/OAuth2", "sync_interval_min": 15},
    "azure_ad": {"name": "Azure AD / Entra ID", "vendor": "Microsoft",
                 "protocol": "SCIM/OIDC", "sync_interval_min": 30},
    "local": {"name": "本地目录（CSV/HR系统）", "vendor": "Local",
              "protocol": "File/HRIS API", "sync_interval_min": 1440},
}

LIFECYCLE_STAGES = ["prehire", "active", "transfer", "leave_notice", "terminated", "archived"]
ACCOUNT_STATES = ["active", "suspended", "disabled", "expired", "locked", "pending"]


# --------------------------------------------------------------------------- #
# 示例用户库（内存模拟）
# --------------------------------------------------------------------------- #
def _demo_users() -> List[Dict[str, Any]]:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    users = [
        {"uid": "U1001", "username": "zhang.wei", "name": "张伟", "email": "zhang.wei@corp.cn",
         "dept": "IT", "title": "系统管理员", "state": "active", "lifecycle": "active",
         "manager": "li.qiang", "mfa_enabled": True, "created_at": "2022-03-10 09:00:00",
         "last_login": "2026-09-13 22:14:00", "roles": ["ITAdmin", "VaultAdmin"],
         "sources": ["active_directory", "okta"]},
        {"uid": "U1002", "username": "li.na", "name": "李娜", "email": "li.na@corp.cn",
         "dept": "Finance", "title": "财务分析师", "state": "active", "lifecycle": "active",
         "manager": "wang.fang", "mfa_enabled": True, "created_at": "2023-06-01 10:00:00",
         "last_login": "2026-09-14 08:02:00", "roles": ["FinanceAnalyst"],
         "sources": ["azure_ad"]},
        {"uid": "U1003", "username": "wang.fang", "name": "王芳", "email": "wang.fang@corp.cn",
         "dept": "Finance", "title": "财务总监", "state": "active", "lifecycle": "active",
         "manager": "ceo", "mfa_enabled": True, "created_at": "2020-01-15 09:00:00",
         "last_login": "2026-09-14 07:55:00", "roles": ["FinanceDirector", "Approver"],
         "sources": ["azure_ad", "okta"]},
        {"uid": "U1004", "username": "zhao.lei", "name": "赵磊", "email": "zhao.lei@corp.cn",
         "dept": "Engineering", "title": "后端工程师", "state": "active", "lifecycle": "active",
         "manager": "chen.jun", "mfa_enabled": False, "created_at": "2024-02-20 09:00:00",
         "last_login": "2026-09-13 23:40:00", "roles": ["Developer"],
         "sources": ["active_directory"]},
        {"uid": "U1005", "username": "sun.qi", "name": "孙琪", "email": "sun.qi@corp.cn",
         "dept": "HR", "title": "HRBP", "state": "suspended", "lifecycle": "transfer",
         "manager": "hr.director", "mfa_enabled": True, "created_at": "2021-08-11 09:00:00",
         "last_login": "2026-09-01 18:20:00", "roles": [], "sources": ["local"]},
        {"uid": "U1006", "username": "zhou.tao", "name": "周涛", "email": "zhou.tao@corp.cn",
         "dept": "IT", "title": "运维工程师", "state": "active", "lifecycle": "active",
         "manager": "zhang.wei", "mfa_enabled": True, "created_at": "2022-11-05 09:00:00",
         "last_login": "2026-09-14 09:10:00", "roles": ["OpsEngineer", "DBReader"],
         "sources": ["active_directory", "ldap"]},
        {"uid": "U1007", "username": "wu.jing", "name": "吴静", "email": "wu.jing@corp.cn",
         "dept": "Sales", "title": "销售经理", "state": "terminated", "lifecycle": "terminated",
         "manager": "sales.director", "mfa_enabled": False, "created_at": "2019-04-01 09:00:00",
         "last_login": "2026-06-30 17:00:00", "roles": ["SalesRep"],
         "sources": ["azure_ad"]},
        {"uid": "U1008", "username": "zheng.hao", "name": "郑浩", "email": "zheng.hao@corp.cn",
         "dept": "Engineering", "title": "前端工程师", "state": "active", "lifecycle": "active",
         "manager": "chen.jun", "mfa_enabled": True, "created_at": "2025-01-08 09:00:00",
         "last_login": "2026-09-14 09:30:00", "roles": ["Developer"],
         "sources": ["okta"]},
        {"uid": "U1009", "username": "orphan.old", "name": "离职未回收", "email": "orphan@corp.cn",
         "dept": "Unknown", "title": "Unknown", "state": "active", "lifecycle": "archived",
         "manager": "unknown", "mfa_enabled": False, "created_at": "2018-05-20 09:00:00",
         "last_login": "2025-01-10 03:00:00", "roles": ["LegacyAppUser"],
         "sources": ["local"]},
        {"uid": "U1010", "username": "chen.jun", "name": "陈军", "email": "chen.jun@corp.cn",
         "dept": "Engineering", "title": "技术总监", "state": "active", "lifecycle": "active",
         "manager": "cto", "mfa_enabled": True, "created_at": "2018-09-01 09:00:00",
         "last_login": "2026-09-14 10:00:00", "roles": ["EngineeringDirector", "Approver"],
         "sources": ["azure_ad", "okta", "active_directory"]},
        {"uid": "S2001", "username": "svc-backup", "name": "备份服务账户",
         "email": "svc-backup@corp.cn", "dept": "IT", "title": "Service Account",
         "state": "active", "lifecycle": "active", "manager": "zhang.wei",
         "mfa_enabled": False, "created_at": "2021-01-01 00:00:00",
         "last_login": "2026-09-14 02:00:00", "roles": ["BackupService"],
         "sources": ["active_directory", "local"]},
        {"uid": "S2002", "username": "svc-etl", "name": "ETL 数据同步账户",
         "email": "svc-etl@corp.cn", "dept": "Data", "title": "Service Account",
         "state": "active", "lifecycle": "active", "manager": "data.lead",
         "mfa_enabled": False, "created_at": "2022-07-15 00:00:00",
         "last_login": "2026-09-14 06:30:00", "roles": ["ETLRunner"],
         "sources": ["active_directory"]},
    ]
    return users


class IdentityGovernance:
    """身份治理与目录。"""

    def __init__(self) -> None:
        self.directory_types = DIRECTORY_TYPES
        self.lifecycle_stages = LIFECYCLE_STAGES
        self.account_states = ACCOUNT_STATES
        self._users: List[Dict[str, Any]] = _demo_users()
        self._sync_log: List[Dict[str, Any]] = []
        self._lifecycle_events: List[Dict[str, Any]] = [
            {"event_id": "L001", "uid": "U1001", "stage": "prehire",
             "timestamp": "2022-03-01 09:00:00", "operator": "hr.auto",
             "action": "预创建账户", "result": "success"},
            {"event_id": "L002", "uid": "U1001", "stage": "active",
             "timestamp": "2022-03-10 09:05:00", "operator": "hr.auto",
             "action": "入职开通/分配默认角色", "result": "success"},
            {"event_id": "L003", "uid": "U1005", "stage": "transfer",
             "timestamp": "2026-08-20 14:00:00", "operator": "hr.bp",
             "action": "跨部门转岗，旧角色待回收", "result": "pending_review"},
            {"event_id": "L004", "uid": "U1007", "stage": "leave_notice",
             "timestamp": "2026-06-25 10:00:00", "operator": "hr.bp",
             "action": "提交离职通知", "result": "success"},
            {"event_id": "L005", "uid": "U1007", "stage": "terminated",
             "timestamp": "2026-06-30 18:00:00", "operator": "idm.auto",
             "action": "离职账户禁用（应回收仍 active）", "result": "delayed"},
            {"event_id": "L006", "uid": "U1009", "stage": "archived",
             "timestamp": "2025-01-15 00:00:00", "operator": "idm.auto",
             "action": "归档但未删除（孤儿）", "result": "warning"},
        ]
        self._directories: List[Dict[str, Any]] = [
            {"dir_id": "AD01", "type": "active_directory", "name": "corp.cn 主域",
             "server": "dc1.corp.cn:636", "sync_status": "ok",
             "last_sync": "2026-09-14 09:55:00", "next_sync": "2026-09-14 10:55:00",
             "users_total": 1240, "users_in_scope": 1240, "errors": 0,
             "connection": "LDAPS", "base_dn": "DC=corp,DC=cn"},
            {"dir_id": "OKTA01", "type": "okta", "name": "Okta UD",
             "server": "corp.okta.com", "sync_status": "ok",
             "last_sync": "2026-09-14 10:00:00", "next_sync": "2026-09-14 10:15:00",
             "users_total": 1240, "users_in_scope": 1240, "errors": 0,
             "connection": "SCIM", "base_dn": "okta://corp"},
            {"dir_id": "AAD01", "type": "azure_ad", "name": "Entra ID 租户",
             "server": "login.microsoftonline.com", "sync_status": "degraded",
             "last_sync": "2026-09-14 08:30:00", "next_sync": "2026-09-14 09:00:00",
             "users_total": 1198, "users_in_scope": 1198, "errors": 42,
             "connection": "OIDC", "base_dn": "tenant://contoso.onmicrosoft.com"},
            {"dir_id": "LDAP01", "type": "ldap", "name": "旧应用 LDAP",
             "server": "ldap.legacy:389", "sync_status": "stale",
             "last_sync": "2026-08-20 03:00:00", "next_sync": "2026-08-20 04:00:00",
             "users_total": 256, "users_in_scope": 12, "errors": 1,
             "connection": "LDAP", "base_dn": "ou=legacy,dc=corp,dc=cn"},
            {"dir_id": "HRIS01", "type": "local", "name": "HRIS 本地 CSV",
             "server": "hris://daily-csv", "sync_status": "ok",
             "last_sync": "2026-09-14 06:00:00", "next_sync": "2026-09-15 06:00:00",
             "users_total": 1240, "users_in_scope": 1240, "errors": 0,
             "connection": "FILE", "base_dn": "/hris/users.csv"},
        ]

    # ------------------------------------------------------------------ #
    # 用户 CRUD
    # ------------------------------------------------------------------ #
    def list_users(self, dept: Optional[str] = None,
                   state: Optional[str] = None,
                   q: Optional[str] = None) -> Dict[str, Any]:
        users = self._users
        if dept:
            users = [u for u in users if u.get("dept") == dept]
        if state:
            users = [u for u in users if u.get("state") == state]
        if q:
            ql = q.lower()
            users = [u for u in users
                     if ql in u.get("name", "").lower()
                     or ql in u.get("username", "").lower()
                     or ql in u.get("email", "").lower()]
        depts = sorted({u["dept"] for u in self._users})
        states = sorted({u["state"] for u in self._users})
        return {"users": users, "total": len(self._users),
                "filtered": len(users), "depts": depts, "states": states}

    def get_user(self, uid: str) -> Optional[Dict[str, Any]]:
        for u in self._users:
            if u["uid"] == uid or u["username"] == uid:
                return u
        return None

    def create_user(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        uid = attrs.get("uid") or ("U" + str(1100 + len(self._users)))
        user = {
            "uid": uid,
            "username": attrs.get("username", uid.lower()),
            "name": attrs.get("name", "未命名"),
            "email": attrs.get("email", ""),
            "dept": attrs.get("dept", "Unknown"),
            "title": attrs.get("title", ""),
            "state": attrs.get("state", "pending"),
            "lifecycle": attrs.get("lifecycle", "prehire"),
            "manager": attrs.get("manager", ""),
            "mfa_enabled": bool(attrs.get("mfa_enabled", False)),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "last_login": "",
            "roles": list(attrs.get("roles", [])),
            "sources": list(attrs.get("sources", ["local"])),
        }
        self._users.append(user)
        return user

    def update_user(self, uid: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        u = self.get_user(uid)
        if not u:
            return None
        for k, v in patch.items():
            if k in u:
                u[k] = v
        return u

    def delete_user(self, uid: str) -> bool:
        before = len(self._users)
        self._users = [u for u in self._users
                       if u["uid"] != uid and u["username"] != uid]
        return len(self._users) < before

    # ------------------------------------------------------------------ #
    # 目录集成
    # ------------------------------------------------------------------ #
    def list_directories(self) -> Dict[str, Any]:
        return {"directories": self._directories,
                "types": self.directory_types,
                "total": len(self._directories)}

    def sync_directory(self, dir_id: str) -> Dict[str, Any]:
        d = next((x for x in self._directories if x["dir_id"] == dir_id), None)
        if not d:
            return {"ok": False, "reason": "directory not found"}
        d["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
        d["sync_status"] = "ok"
        d["errors"] = 0
        log = {"log_id": "SYNC" + uuid.uuid4().hex[:8],
               "dir_id": dir_id, "timestamp": d["last_sync"],
               "result": "success", "users_updated": d["users_in_scope"],
               "duration_ms": 1200 + (len(dir_id) * 137)}
        self._sync_log.append(log)
        return {"ok": True, "log": log, "directory": d}

    # ------------------------------------------------------------------ #
    # 身份图谱
    # ------------------------------------------------------------------ #
    def build_identity_graph(self) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        role_set = sorted({r for u in self._users for r in u.get("roles", [])})
        for u in self._users:
            nodes.append({"id": u["uid"], "label": u["name"],
                          "kind": "user", "dept": u.get("dept"),
                          "state": u.get("state")})
        for r in role_set:
            nodes.append({"id": "ROLE:" + r, "label": r, "kind": "role"})
        for u in self._users:
            for r in u.get("roles", []):
                edges.append({"src": u["uid"], "dst": "ROLE:" + r,
                              "type": "has_role"})
            if u.get("manager"):
                m = next((x for x in self._users
                          if x["username"] == u["manager"]
                          or x["uid"] == u["manager"]), None)
                if m:
                    edges.append({"src": u["uid"], "dst": m["uid"],
                                  "type": "reports_to"})
        return {"nodes": nodes, "edges": edges,
                "user_count": len(self._users),
                "role_count": len(role_set),
                "edge_count": len(edges)}

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def lifecycle_events(self, uid: Optional[str] = None) -> Dict[str, Any]:
        evts = self._lifecycle_events
        if uid:
            evts = [e for e in evts if e.get("uid") == uid]
        rules = [
            {"rule_id": "R-ONB", "name": "入职自动开通",
             "trigger": "HRIS hire_date = today", "action": "创建账户+分配默认角色+触发MFA注册",
             "enabled": True, "sla_hours": 4},
            {"rule_id": "R-XFR", "name": "转岗自动调整",
             "trigger": "HRIS dept change",
             "action": "回收旧部门角色，按新岗位模板授予",
             "enabled": True, "sla_hours": 24},
            {"rule_id": "R-OFF", "name": "离职自动回收",
             "trigger": "HRIS termination_date = today",
             "action": "禁用账户+吊销SSO会话+回收邮箱",
             "enabled": True, "sla_hours": 2},
            {"rule_id": "R-RVW", "name": "季度权限复核",
             "trigger": "每90天", "action": "推送经理审批+系统Owner确认",
             "enabled": True, "sla_hours": 72},
        ]
        return {"events": evts, "rules": rules, "total": len(evts)}

    # ------------------------------------------------------------------ #
    # 数据质量
    # ------------------------------------------------------------------ #
    def data_quality(self) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        for u in self._users:
            if u["lifecycle"] == "terminated" and u["state"] == "active":
                issues.append({"uid": u["uid"], "name": u["name"],
                               "type": "orphan_account",
                               "severity": "high",
                               "desc": "已离职但账户仍 active，应立即禁用/删除"})
            if u["lifecycle"] == "archived" and u["state"] == "active":
                issues.append({"uid": u["uid"], "name": u["name"],
                               "type": "orphan_account",
                               "severity": "medium",
                               "desc": "归档但未禁用，疑似孤儿账户"})
            if not u.get("email") or u.get("dept") in ("Unknown", ""):
                issues.append({"uid": u["uid"], "name": u["name"],
                               "type": "incomplete_attribute",
                               "severity": "low",
                               "desc": "邮箱/部门缺失，影响生命周期自动化"})
            if not u.get("mfa_enabled") and u["state"] == "active" and not u["uid"].startswith("S"):
                issues.append({"uid": u["uid"], "name": u["name"],
                               "type": "no_mfa",
                               "severity": "high",
                               "desc": "活跃用户未启用 MFA"})
            # 重复账户检测（同邮箱/同名近似）
        emails = [u.get("email", "").lower() for u in self._users if u.get("email")]
        from collections import Counter
        dup = {e: c for e, c in Counter(emails).items() if c > 1}
        for e, c in dup.items():
            issues.append({"uid": "-", "name": e, "type": "duplicate_account",
                           "severity": "medium", "desc": f"邮箱出现 {c} 次，疑似重复账户"})

        total = len(self._users) or 1
        score = max(0, 100 - len(issues) * 5)
        summary = {
            "total_users": len(self._users),
            "issue_count": len(issues),
            "quality_score": score,
            "orphan_accounts": sum(1 for i in issues if i["type"] == "orphan_account"),
            "duplicate_accounts": sum(1 for i in issues if i["type"] == "duplicate_account"),
            "incomplete_profiles": sum(1 for i in issues
                                      if i["type"] == "incomplete_attribute"),
            "no_mfa_users": sum(1 for i in issues if i["type"] == "no_mfa"),
        }
        suggestions = [
            "对已离职仍 active 的账户立即执行禁用并审计其最近 30 天登录",
            "推动未启用 MFA 的活跃用户在 7 天内完成注册",
            "清理 LDAP01 旧目录与主目录的用户范围差异（1240 vs 12）",
            "为孤儿/重复账户建立季度自动复核任务",
        ]
        return {"summary": summary, "issues": issues,
                "suggestions": suggestions,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}


__all__ = ["IdentityGovernance", "DIRECTORY_TYPES", "LIFECYCLE_STAGES",
           "ACCOUNT_STATES"]
