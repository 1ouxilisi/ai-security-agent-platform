# -*- coding: utf-8 -*-
"""
multi_tenant.py — 多租户架构核心模块。

覆盖：
- 租户管理（创建/配置/状态/配额/标签/分级）
- 组织架构（组织/部门/团队/项目层级/层级权限/层级配额）
- 用户管理（注册/信息/状态/角色/分组/邀请）
- 角色权限（RBAC角色/权限点/角色映射/自定义角色/继承/审计）
- 数据隔离（租户级隔离/行级安全/schema隔离/加密隔离/缓存隔离）
- 租户生命周期（创建→配置→使用→续费→降级→冻结→注销）

全部内存字典模拟，不建数据库表。
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #
def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _uid(prefix: str = "") -> str:
    return prefix + uuid.uuid4().hex[:12]


def _clean(obj: Any) -> Any:
    """递归清理控制字符。"""
    if isinstance(obj, str):
        return "".join(c for c in obj if c >= " " or c in "\n\r\t")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(i) for i in obj)
    return obj


# --------------------------------------------------------------------------- #
# 内存数据存储
# --------------------------------------------------------------------------- #
class MultiTenantStore:
    """多租户架构内存存储中心。"""

    def __init__(self) -> None:
        self.tenants: Dict[str, Dict[str, Any]] = {}
        self.organizations: Dict[str, Dict[str, Any]] = {}
        self.departments: Dict[str, Dict[str, Any]] = {}
        self.teams: Dict[str, Dict[str, Any]] = {}
        self.projects: Dict[str, Dict[str, Any]] = {}
        self.users: Dict[str, Dict[str, Any]] = {}
        self.roles: Dict[str, Dict[str, Any]] = {}
        self.permissions: Dict[str, Dict[str, Any]] = {}
        self.role_permissions: Dict[str, List[str]] = {}
        self.user_roles: Dict[str, List[str]] = {}
        self.user_groups: Dict[str, Dict[str, Any]] = {}
        self.invitations: Dict[str, Dict[str, Any]] = {}
        self.audit_logs: List[Dict[str, Any]] = []
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        """预置默认权限点和系统角色。"""
        # 权限点
        perms = [
            ("tenant.view", "查看租户信息"), ("tenant.edit", "编辑租户配置"),
            ("tenant.delete", "删除租户"), ("user.view", "查看用户"),
            ("user.create", "创建用户"), ("user.edit", "编辑用户"),
            ("user.delete", "删除用户"), ("role.view", "查看角色"),
            ("role.edit", "编辑角色权限"), ("billing.view", "查看账单"),
            ("billing.edit", "管理计费"), ("scan.run", "执行扫描"),
            ("scan.view", "查看扫描结果"), ("report.view", "查看报告"),
            ("report.export", "导出报告"), ("audit.view", "查看审计日志"),
            ("audit.export", "导出审计日志"), ("settings.view", "查看设置"),
            ("settings.edit", "修改设置"), ("api.key.manage", "管理API密钥"),
            ("integration.manage", "管理集成"),
        ]
        for pid, pdesc in perms:
            self.permissions[pid] = {"id": pid, "name": pdesc, "created_at": _now()}

        # 系统角色
        sys_roles = [
            ("sys_admin", "系统管理员", ["tenant.view", "tenant.edit", "tenant.delete",
             "user.view", "user.create", "user.edit", "user.delete",
             "role.view", "role.edit", "billing.view", "billing.edit",
             "scan.run", "scan.view", "report.view", "report.export",
             "audit.view", "audit.export", "settings.view", "settings.edit",
             "api.key.manage", "integration.manage"]),
            ("tenant_admin", "租户管理员", ["user.view", "user.create", "user.edit",
             "role.view", "billing.view", "scan.run", "scan.view",
             "report.view", "report.export", "settings.view", "settings.edit",
             "api.key.manage"]),
            ("developer", "开发者", ["scan.run", "scan.view", "report.view",
             "report.export", "api.key.manage", "integration.manage"]),
            ("viewer", "只读用户", ["scan.view", "report.view"]),
            ("auditor", "审计员", ["audit.view", "audit.export", "scan.view", "report.view"]),
        ]
        for rid, rname, plist in sys_roles:
            self.roles[rid] = {
                "id": rid, "name": rname, "is_system": True,
                "permissions": list(plist), "created_at": _now(),
            }
            self.role_permissions[rid] = list(plist)

        # 默认租户
        tid = _uid("tnt_")
        self.tenants[tid] = {
            "id": tid, "name": "默认演示租户", "slug": "demo",
            "status": "active", "plan": "enterprise",
            "tier": "enterprise", "tags": ["demo", "default"],
            "quota": {"max_users": 500, "max_scans_monthly": 5000,
                      "max_storage_gb": 100, "max_api_calls_day": 100000},
            "config": {"data_isolation": "row_level", "encryption": True,
                       "cache_isolation": True, "session_timeout_min": 60},
            "created_at": _now(), "expires_at": None,
            "contact": {"email": "admin@demo.com", "phone": "13800000000"},
        }


# 全局单例
_store = MultiTenantStore()


# --------------------------------------------------------------------------- #
# 1. 租户管理
# --------------------------------------------------------------------------- #
def create_tenant(name: str, slug: str = "", plan: str = "basic",
                  tier: str = "basic", contact: Optional[Dict] = None,
                  tags: Optional[List[str]] = None) -> Dict[str, Any]:
    """创建新租户。"""
    tid = _uid("tnt_")
    if not slug:
        slug = name.lower().replace(" ", "_")[:20]
    quotas = {
        "free": {"max_users": 5, "max_scans_monthly": 50,
                 "max_storage_gb": 1, "max_api_calls_day": 1000},
        "basic": {"max_users": 20, "max_scans_monthly": 500,
                  "max_storage_gb": 10, "max_api_calls_day": 10000},
        "pro": {"max_users": 100, "max_scans_monthly": 2000,
                "max_storage_gb": 50, "max_api_calls_day": 50000},
        "enterprise": {"max_users": 500, "max_scans_monthly": 5000,
                       "max_storage_gb": 100, "max_api_calls_day": 100000},
        "custom": {"max_users": 9999, "max_scans_monthly": 99999,
                   "max_storage_gb": 999, "max_api_calls_day": 999999},
    }
    tid_quota = quotas.get(plan, quotas["basic"])
    tenant = {
        "id": tid, "name": name, "slug": slug,
        "status": "active", "plan": plan, "tier": tier,
        "tags": tags or [], "quota": tid_quota,
        "config": {"data_isolation": "row_level", "encryption": True,
                   "cache_isolation": True, "session_timeout_min": 60},
        "created_at": _now(), "expires_at": None,
        "contact": contact or {"email": "", "phone": ""},
        "lifecycle_stage": "active",
    }
    _store.tenants[tid] = tenant
    _log_audit(tid, None, "tenant_created", f"租户 {name} 创建")
    return tenant


def get_tenant(tenant_id: str) -> Optional[Dict[str, Any]]:
    return _store.tenants.get(tenant_id)


def list_tenants(status: str = "", tier: str = "",
                 page: int = 1, page_size: int = 20) -> Dict[str, Any]:
    items = list(_store.tenants.values())
    if status:
        items = [t for t in items if t["status"] == status]
    if tier:
        items = [t for t in items if t.get("tier") == tier]
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    return {"total": total, "page": page, "page_size": page_size,
            "items": items[start:end]}


def update_tenant_config(tenant_id: str, config: Dict[str, Any]) -> Optional[Dict]:
    t = _store.tenants.get(tenant_id)
    if not t:
        return None
    t["config"].update(config)
    t["updated_at"] = _now()
    _log_audit(tenant_id, None, "tenant_config_updated", "租户配置更新")
    return t


def update_tenant_quota(tenant_id: str, quota: Dict[str, Any]) -> Optional[Dict]:
    t = _store.tenants.get(tenant_id)
    if not t:
        return None
    t["quota"].update(quota)
    t["updated_at"] = _now()
    _log_audit(tenant_id, None, "tenant_quota_updated", "租户配额更新")
    return t


def set_tenant_status(tenant_id: str, status: str) -> Optional[Dict]:
    """设置租户状态：active/suspended/frozen/cancelled."""
    valid = ["active", "suspended", "frozen", "cancelled"]
    if status not in valid:
        return None
    t = _store.tenants.get(tenant_id)
    if not t:
        return None
    t["status"] = status
    t["lifecycle_stage"] = status
    t["status_changed_at"] = _now()
    _log_audit(tenant_id, None, f"tenant_status_{status}", f"租户状态变更为 {status}")
    return t


def set_tenant_tags(tenant_id: str, tags: List[str]) -> Optional[Dict]:
    t = _store.tenants.get(tenant_id)
    if not t:
        return None
    t["tags"] = tags
    t["updated_at"] = _now()
    return t


def set_tenant_tier(tenant_id: str, tier: str) -> Optional[Dict]:
    t = _store.tenants.get(tenant_id)
    if not t:
        return None
    t["tier"] = tier
    t["updated_at"] = _now()
    _log_audit(tenant_id, None, "tenant_tier_changed", f"租户分级变更为 {tier}")
    return t


# --------------------------------------------------------------------------- #
# 2. 组织架构管理
# --------------------------------------------------------------------------- #
def create_organization(tenant_id: str, name: str,
                        parent_id: str = "") -> Optional[Dict]:
    oid = _uid("org_")
    org = {
        "id": oid, "tenant_id": tenant_id, "name": name,
        "parent_id": parent_id, "type": "organization",
        "children": [], "quota": {"max_children": 50, "max_members": 1000},
        "created_at": _now(),
    }
    _store.organizations[oid] = org
    if parent_id and parent_id in _store.organizations:
        _store.organizations[parent_id]["children"].append(oid)
    return org


def create_department(tenant_id: str, org_id: str, name: str,
                      parent_id: str = "") -> Optional[Dict]:
    did = _uid("dep_")
    dept = {
        "id": did, "tenant_id": tenant_id, "org_id": org_id,
        "name": name, "parent_id": parent_id, "type": "department",
        "children": [], "quota": {"max_children": 30, "max_members": 200},
        "created_at": _now(),
    }
    _store.departments[did] = dept
    if parent_id and parent_id in _store.departments:
        _store.departments[parent_id]["children"].append(did)
    return dept


def create_team(tenant_id: str, dept_id: str, name: str) -> Optional[Dict]:
    tid = _uid("team_")
    team = {
        "id": tid, "tenant_id": tenant_id, "dept_id": dept_id,
        "name": name, "quota": {"max_members": 50, "max_projects": 20},
        "members": [], "created_at": _now(),
    }
    _store.teams[tid] = team
    return team


def create_project(tenant_id: str, team_id: str, name: str,
                   config: Optional[Dict] = None) -> Optional[Dict]:
    pid = _uid("prj_")
    project = {
        "id": pid, "tenant_id": tenant_id, "team_id": team_id,
        "name": name, "config": config or {},
        "quota": {"max_scans": 100, "max_storage_mb": 5000},
        "members": [], "status": "active", "archived": False,
        "created_at": _now(),
    }
    _store.projects[pid] = project
    return project


def get_org_tree(tenant_id: str) -> List[Dict[str, Any]]:
    """获取组织架构树。"""
    orgs = [o for o in _store.organizations.values() if o["tenant_id"] == tenant_id]
    result = []
    for org in orgs:
        if not org["parent_id"]:
            result.append(_build_org_node(org["id"]))
    return result


def _build_org_node(org_id: str) -> Dict[str, Any]:
    node = _store.organizations[org_id].copy()
    children_deps = [d for d in _store.departments.values() if d["org_id"] == org_id]
    node["departments"] = []
    for dep in children_deps:
        dep_node = dep.copy()
        dep_node["teams"] = [t for t in _store.teams.values() if t["dept_id"] == dep["id"]]
        dep_node["projects"] = []
        for team in dep_node["teams"]:
            team_projs = [p for p in _store.projects.values() if p["team_id"] == team["id"]]
            dep_node["projects"].extend(team_projs)
        node["departments"].append(dep_node)
    return node


# --------------------------------------------------------------------------- #
# 3. 用户管理
# --------------------------------------------------------------------------- #
def register_user(tenant_id: str, email: str, name: str,
                  role_id: str = "viewer") -> Optional[Dict]:
    uid = _uid("usr_")
    user = {
        "id": uid, "tenant_id": tenant_id, "email": email,
        "name": name, "status": "active", "roles": [role_id],
        "groups": [], "avatar": "", "preferences": {},
        "created_at": _now(), "last_login": None,
    }
    _store.users[uid] = user
    _store.user_roles[uid] = [role_id]
    _log_audit(tenant_id, uid, "user_registered", f"用户 {email} 注册")
    return user


def get_user(user_id: str) -> Optional[Dict[str, Any]]:
    return _store.users.get(user_id)


def list_users(tenant_id: str = "", status: str = "",
               page: int = 1, page_size: int = 20) -> Dict[str, Any]:
    items = list(_store.users.values())
    if tenant_id:
        items = [u for u in items if u["tenant_id"] == tenant_id]
    if status:
        items = [u for u in items if u["status"] == status]
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    return {"total": total, "page": page, "page_size": page_size,
            "items": items[start:end]}


def set_user_status(user_id: str, status: str) -> Optional[Dict]:
    valid = ["active", "inactive", "suspended", "invited"]
    if status not in valid:
        return None
    u = _store.users.get(user_id)
    if not u:
        return None
    u["status"] = status
    u["status_changed_at"] = _now()
    _log_audit(u["tenant_id"], user_id, f"user_status_{status}", f"用户状态变更为 {status}")
    return u


def assign_role(user_id: str, role_id: str) -> Optional[Dict]:
    u = _store.users.get(user_id)
    if not u or role_id not in _store.roles:
        return None
    if role_id not in u["roles"]:
        u["roles"].append(role_id)
        _store.user_roles[user_id] = u["roles"]
    _log_audit(u["tenant_id"], user_id, "role_assigned", f"角色 {role_id} 分配给用户")
    return u


def remove_role(user_id: str, role_id: str) -> Optional[Dict]:
    u = _store.users.get(user_id)
    if not u:
        return None
    if role_id in u["roles"] and len(u["roles"]) > 1:
        u["roles"].remove(role_id)
        _store.user_roles[user_id] = u["roles"]
    return u


def invite_user(tenant_id: str, email: str, role_id: str = "viewer",
                inviter_id: str = "") -> Dict[str, Any]:
    inv_id = _uid("inv_")
    invitation = {
        "id": inv_id, "tenant_id": tenant_id, "email": email,
        "role_id": role_id, "inviter_id": inviter_id,
        "status": "pending", "token": uuid.uuid4().hex[:32],
        "expires_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                     time.localtime(time.time() + 7 * 86400)),
        "created_at": _now(),
    }
    _store.invitations[inv_id] = invitation
    return invitation


def create_user_group(tenant_id: str, name: str,
                      member_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    gid = _uid("grp_")
    group = {
        "id": gid, "tenant_id": tenant_id, "name": name,
        "members": member_ids or [], "created_at": _now(),
    }
    _store.user_groups[gid] = group
    return group


# --------------------------------------------------------------------------- #
# 4. 角色权限 (RBAC)
# --------------------------------------------------------------------------- #
def list_roles(include_system: bool = True) -> List[Dict[str, Any]]:
    items = list(_store.roles.values())
    if not include_system:
        items = [r for r in items if not r.get("is_system")]
    return items


def create_custom_role(tenant_id: str, name: str,
                       permissions: List[str],
                       description: str = "") -> Dict[str, Any]:
    rid = _uid("role_")
    valid_perms = [p for p in permissions if p in _store.permissions]
    role = {
        "id": rid, "tenant_id": tenant_id, "name": name,
        "is_system": False, "permissions": valid_perms,
        "description": description, "created_at": _now(),
    }
    _store.roles[rid] = role
    _store.role_permissions[rid] = valid_perms
    _log_audit(tenant_id, None, "custom_role_created", f"自定义角色 {name} 创建")
    return role


def update_role_permissions(role_id: str,
                            permissions: List[str]) -> Optional[Dict]:
    r = _store.roles.get(role_id)
    if not r or r.get("is_system"):
        return None
    valid_perms = [p for p in permissions if p in _store.permissions]
    r["permissions"] = valid_perms
    _store.role_permissions[role_id] = valid_perms
    return r


def list_permissions() -> List[Dict[str, Any]]:
    return list(_store.permissions.values())


def check_permission(user_id: str, permission: str) -> bool:
    """检查用户是否拥有指定权限。"""
    role_ids = _store.user_roles.get(user_id, [])
    for rid in role_ids:
        perms = _store.role_permissions.get(rid, [])
        if permission in perms:
            return True
    return False


def get_user_permissions(user_id: str) -> List[str]:
    """获取用户所有权限点（合并角色+继承）。"""
    role_ids = _store.user_roles.get(user_id, [])
    perm_set = set()
    for rid in role_ids:
        perm_set.update(_store.role_permissions.get(rid, []))
    return sorted(perm_set)


# --------------------------------------------------------------------------- #
# 5. 数据隔离
# --------------------------------------------------------------------------- #
class DataIsolationManager:
    """多租户数据隔离管理器。"""

    def __init__(self) -> None:
        self.strategies: Dict[str, str] = {
            "row_level": "行级安全隔离 — 每行行内 tenant_id 过滤",
            "schema": "Schema隔离 — 每租户独立数据库schema",
            "encryption": "加密隔离 — 租户级密钥加密敏感数据",
            "cache": "缓存隔离 — 租户独立缓存命名空间",
        }
        self.tenant_data: Dict[str, Dict[str, List]] = {}

    def get_isolation_strategy(self, tenant_id: str) -> str:
        t = _store.tenants.get(tenant_id)
        if t:
            return t["config"].get("data_isolation", "row_level")
        return "row_level"

    def query_tenant_data(self, tenant_id: str,
                          data_type: str) -> List:
        """模拟租户级数据查询（行级隔离）。"""
        if tenant_id not in self.tenant_data:
            self.tenant_data[tenant_id] = {}
        return self.tenant_data[tenant_id].get(data_type, [])

    def insert_tenant_data(self, tenant_id: str, data_type: str,
                           record: Dict) -> None:
        """模拟租户级数据写入（自动附加 tenant_id）。"""
        if tenant_id not in self.tenant_data:
            self.tenant_data[tenant_id] = {}
        if data_type not in self.tenant_data[tenant_id]:
            self.tenant_data[tenant_id][data_type] = []
        record["_tenant_id"] = tenant_id
        record["_row_hash"] = hashlib.sha256(
            json.dumps(record, sort_keys=True).encode()).hexdigest()[:16]
        self.tenant_data[tenant_id][data_type].append(record)

    def verify_row_integrity(self, tenant_id: str,
                             data_type: str) -> Dict[str, Any]:
        """验证行级数据完整性哈希链。"""
        records = self.query_tenant_data(tenant_id, data_type)
        verified = 0
        for r in records:
            expected = hashlib.sha256(
                json.dumps({k: v for k, v in r.items() if k != "_row_hash"},
                           sort_keys=True).encode()).hexdigest()[:16]
            if r.get("_row_hash") == expected:
                verified += 1
        return {"total": len(records), "verified": verified,
                "integrity_pct": round(verified / max(len(records), 1) * 100, 2)}


_isolation = DataIsolationManager()


# --------------------------------------------------------------------------- #
# 6. 租户生命周期
# --------------------------------------------------------------------------- #
def tenant_lifecycle_transition(tenant_id: str,
                                action: str) -> Optional[Dict[str, Any]]:
    """租户生命周期状态机转换。

    流程: created → configured → active → renewing → downgrading →
          frozen → cancelled
    """
    t = _store.tenants.get(tenant_id)
    if not t:
        return None

    transitions = {
        "configure": ("created", "configured"),
        "activate": ("configured", "active"),
        "renew": ("active", "renewing"),
        "downgrade": ("active", "downgrading"),
        "freeze": ("downgrading", "frozen"),
        "unfreeze": ("frozen", "active"),
        "cancel": ("frozen", "cancelled"),
        "grace_period": ("cancelled", "grace"),
    }

    if action in transitions:
        from_stage, to_stage = transitions[action]
        old_stage = t.get("lifecycle_stage", "created")
        t["lifecycle_stage"] = to_stage
        t["status"] = "active" if to_stage == "active" else t["status"]
        t["lifecycle_history"] = t.get("lifecycle_history", [])
        t["lifecycle_history"].append({
            "from": from_stage, "to": to_stage,
            "timestamp": _now(), "action": action,
        })
        _log_audit(tenant_id, None, f"lifecycle_{action}",
                   f"租户生命周期: {from_stage} → {to_stage}")
    return t


def get_tenant_lifecycle(tenant_id: str) -> Optional[Dict[str, Any]]:
    t = _store.tenants.get(tenant_id)
    if not t:
        return None
    return {
        "tenant_id": tenant_id,
        "current_stage": t.get("lifecycle_stage", "created"),
        "history": t.get("lifecycle_history", []),
        "status": t["status"],
        "plan": t["plan"],
        "expires_at": t.get("expires_at"),
    }


# --------------------------------------------------------------------------- #
# 审计日志
# --------------------------------------------------------------------------- #
def _log_audit(tenant_id: str, user_id: Optional[str],
               action: str, detail: str) -> None:
    entry = {
        "id": _uid("log_"), "tenant_id": tenant_id,
        "user_id": user_id or "system", "action": action,
        "detail": detail, "timestamp": _now(),
    }
    _store.audit_logs.append(entry)
    # 保留最近10000条
    if len(_store.audit_logs) > 10000:
        _store.audit_logs = _store.audit_logs[-10000:]


def get_audit_logs(tenant_id: str = "", action: str = "",
                   page: int = 1, page_size: int = 50) -> Dict[str, Any]:
    items = list(_store.audit_logs)
    if tenant_id:
        items = [l for l in items if l["tenant_id"] == tenant_id]
    if action:
        items = [l for l in items if action in l["action"]]
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    return {"total": total, "page": page, "page_size": page_size,
            "items": items[start:end]}


# --------------------------------------------------------------------------- #
# 导出便捷函数
# --------------------------------------------------------------------------- #
def get_store() -> MultiTenantStore:
    return _store


def get_isolation_manager() -> DataIsolationManager:
    return _isolation


def tenant_stats(tenant_id: str) -> Dict[str, Any]:
    """租户统计信息。"""
    t = _store.tenants.get(tenant_id)
    if not t:
        return {}
    user_count = len([u for u in _store.users.values() if u["tenant_id"] == tenant_id])
    org_count = len([o for o in _store.organizations.values() if o["tenant_id"] == tenant_id])
    proj_count = len([p for p in _store.projects.values() if p["tenant_id"] == tenant_id])
    return {
        "tenant_id": tenant_id, "name": t["name"],
        "user_count": user_count, "organization_count": org_count,
        "project_count": proj_count, "status": t["status"],
        "plan": t["plan"], "tier": t["tier"],
        "quota_usage": {"users": user_count,
                        "users_max": t["quota"]["max_users"]},
    }
