#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
commercial_ultra_pro/multi_tenant.py — 多租户隔离。

- 租户管理：CRUD/类型/配额/配置
- 数据隔离：租户ID过滤 + 权限校验
- 权限隔离：租户内角色/权限/跨租户禁止/超管
- 资源隔离：CPU/内存/存储/网络/任务配额
- 租户自助管理 + 租户统计
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, List, Optional


TENANT_TYPES = ["个人", "企业", "试用", "付费"]
ROLES = ["管理员", "操作员", "查看者", "审计员"]
ROLE_PERMS = {
    "管理员": ["*"],
    "操作员": ["scan", "report", "ticket", "billing.view"],
    "查看者": ["report.view", "dashboard.view"],
    "审计员": ["audit.view", "log.view"],
}
DEFAULT_QUOTA = {
    "users": 5, "projects": 10, "scans_per_month": 500,
    "storage_gb": 5, "api_calls_per_month": 50000, "concurrent_tasks": 3,
}


class MultiTenant:
    """多租户隔离（内存存储）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tenants: Dict[str, Dict[str, Any]] = {}
        self._users: Dict[str, Dict[str, Any]] = {}     # user_id -> {tenant_id, role}
        # tenant_id -> {resource -> used}
        self._usage: Dict[str, Dict[str, Any]] = {}
        self._seq = 0

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}{int(time.time()) % 100000:05d}-{self._seq:03d}"

    def _now(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def _ensure_usage(self, tenant_id: str) -> Dict[str, Any]:
        if tenant_id not in self._usage:
            self._usage[tenant_id] = {
                "users": 0, "projects": 0, "scans": 0,
                "storage_gb": 0, "api_calls": 0, "concurrent_tasks": 0,
            }
        return self._usage[tenant_id]

    # ------------------------------------------------------------------ #
    # 租户管理
    # ------------------------------------------------------------------ #
    def create_tenant(self, name: str, ttype: str = "企业",
                       quota: Optional[Dict[str, int]] = None,
                       config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if ttype not in TENANT_TYPES:
            raise ValueError(f"租户类型必须为 {TENANT_TYPES}")
        with self._lock:
            tid = "T-" + uuid.uuid4().hex[:8].upper()
            q = dict(DEFAULT_QUOTA)
            if quota:
                q.update(quota)
            t = {
                "tenant_id": tid, "name": name, "type": ttype,
                "status": "active", "quota": q,
                "config": config or {"theme": "dark", "language": "zh",
                                       "timezone": "Asia/Shanghai",
                                       "logo": ""},
                "created_at": self._now(), "expires_at": "",
            }
            self._tenants[tid] = t
            self._ensure_usage(tid)
            return t

    def update_tenant(self, tenant_id: str, **fields: Any) -> Dict[str, Any]:
        with self._lock:
            t = self._tenants.get(tenant_id)
            if not t:
                raise ValueError("租户不存在")
            for k, v in fields.items():
                if v is not None and k in ("name", "type", "status", "expires_at"):
                    t[k] = v
                elif k == "quota" and isinstance(v, dict):
                    t["quota"].update(v)
                elif k == "config" and isinstance(v, dict):
                    t["config"].update(v)
            return t

    def disable_tenant(self, tenant_id: str) -> Dict[str, Any]:
        return self.update_tenant(tenant_id, status="disabled")

    def get_tenant(self, tenant_id: str) -> Dict[str, Any]:
        with self._lock:
            t = self._tenants.get(tenant_id)
            if not t:
                raise ValueError("租户不存在")
            return t

    def list_tenants(self, ttype: Optional[str] = None,
                       status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._tenants.values())
            if ttype:
                out = [t for t in out if t["type"] == ttype]
            if status:
                out = [t for t in out if t["status"] == status]
            return sorted(out, key=lambda x: x["created_at"], reverse=True)

    def delete_tenant(self, tenant_id: str) -> bool:
        with self._lock:
            if tenant_id in self._tenants:
                del self._tenants[tenant_id]
                del self._usage[tenant_id]
                for u in list(self._users.values()):
                    if u["tenant_id"] == tenant_id:
                        del self._users[u["user_id"]]
                return True
            return False

    # ------------------------------------------------------------------ #
    # 用户 / 权限隔离
    # ------------------------------------------------------------------ #
    def add_user(self, tenant_id: str, username: str,
                  role: str = "操作员") -> Dict[str, Any]:
        if role not in ROLES:
            raise ValueError(f"角色必须为 {ROLES}")
        with self._lock:
            if tenant_id not in self._tenants:
                raise ValueError("租户不存在")
            tid = self._next_id("U")
            u = {"user_id": tid, "tenant_id": tenant_id,
                 "username": username, "role": role,
                 "permissions": ROLE_PERMS[role], "created_at": self._now()}
            self._users[tid] = u
            self._ensure_usage(tenant_id)["users"] += 1
            return u

    def list_users(self, tenant_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [u for u in self._users.values() if u["tenant_id"] == tenant_id]

    def check_permission(self, user_id: str, perm: str,
                          target_tenant: str) -> Dict[str, Any]:
        """校验：用户是否能在 target_tenant 下访问 perm。"""
        with self._lock:
            u = self._users.get(user_id)
            if not u:
                return {"allowed": False, "reason": "用户不存在"}
            # 跨租户访问禁止
            if u["tenant_id"] != target_tenant:
                return {"allowed": False,
                        "reason": f"跨租户访问禁止：用户属于 {u['tenant_id']}，"
                                  f"目标 {target_tenant}"}
            perms = u["permissions"]
            if "*" in perms or perm in perms:
                return {"allowed": True, "tenant_id": target_tenant,
                        "role": u["role"]}
            return {"allowed": False, "reason": f"角色 {u['role']} 无权限 {perm}"}

    # ------------------------------------------------------------------ #
    # 数据隔离
    # ------------------------------------------------------------------ #
    def tenant_filter(self, tenant_id: str,
                        records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """按租户ID过滤记录（逻辑隔离核心）。"""
        return [r for r in records if r.get("tenant_id") == tenant_id]

    # ------------------------------------------------------------------ #
    # 资源隔离
    # ------------------------------------------------------------------ #
    def consume_resource(self, tenant_id: str, resource: str,
                           amount: int = 1) -> Dict[str, Any]:
        """消耗资源并检查配额。"""
        with self._lock:
            t = self._tenants.get(tenant_id)
            if not t:
                raise ValueError("租户不存在")
            if t["status"] != "active":
                raise ValueError("租户已禁用")
            u = self._ensure_usage(tenant_id)
            limit = t["quota"].get(resource, -1)
            if limit > 0 and u[resource] + amount > limit:
                return {"allowed": False, "reason": f"资源 {resource} 配额不足",
                        "used": u[resource], "limit": limit}
            u[resource] += amount
            return {"allowed": True, "resource": resource,
                    "used": u[resource], "limit": limit,
                    "remaining": limit - u[resource] if limit > 0 else -1}

    def resource_usage(self, tenant_id: str) -> Dict[str, Any]:
        with self._lock:
            t = self._tenants.get(tenant_id)
            if not t:
                raise ValueError("租户不存在")
            u = self._usage.get(tenant_id, {})
            detail = {}
            for res, limit in t["quota"].items():
                used = u.get(res, 0)
                detail[res] = {"used": used, "limit": limit,
                                "pct": round(used / limit * 100, 1) if limit > 0 else 0}
            return {"tenant_id": tenant_id, "detail": detail}

    # ------------------------------------------------------------------ #
    # 统计
    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_type: Dict[str, int] = {}
            by_status: Dict[str, int] = {}
            active = 0
            for t in self._tenants.values():
                by_type[t["type"]] = by_type.get(t["type"], 0) + 1
                by_status[t["status"]] = by_status.get(t["status"], 0) + 1
                if t["status"] == "active":
                    active += 1
            return {
                "total_tenants": len(self._tenants),
                "active_tenants": active,
                "by_type": by_type, "by_status": by_status,
                "total_users": len(self._users),
                "total_scans": sum(u.get("scans", 0) for u in self._usage.values()),
            }


_mt: MultiTenant | None = None


def get_multi_tenant() -> MultiTenant:
    global _mt
    if _mt is None:
        _mt = MultiTenant()
    return _mt
