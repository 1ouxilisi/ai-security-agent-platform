# -*- coding: utf-8 -*-
"""rbac.py — 完整 RBAC 权限体系。

角色:
  admin     管理员   — 全部功能 + 全部数据
  analyst   分析师   — 扫描/分析/报告生成
  auditor   审计员   — 只读全部日志，不能修改/操作
  viewer    只读用户 — 只能查看，不能操作

权限分两类:
  功能权限 (functional): 能否调用某类功能 API
  数据权限 (data):        能看到的数据范围

全部内存字典模拟存储。
"""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# 角色 / 权限定义
# --------------------------------------------------------------------------- #

# 功能权限点
PERMISSIONS: Dict[str, str] = {
    "user.manage": "用户管理（增删改角色）",
    "system.config": "系统配置",
    "scan.run": "发起扫描",
    "analysis.run": "漏洞分析",
    "report.generate": "生成报告",
    "report.export": "导出报告",
    "baseline.run": "运行安全基线检查",
    "compliance.generate": "生成合规报告",
    "audit.view": "查看审计日志",
    "audit.export": "导出审计报告",
    "secret.view": "查看/解密敏感凭据",
    "data.view": "查看业务数据",
}

# 数据范围
DATA_SCOPES = {
    "all": "全部数据",
    "own": "仅本人数据",
    "auditable": "仅审计可见（只读全量日志）",
    "none": "无",
}

# 角色 -> 功能权限集合
ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "admin": list(PERMISSIONS.keys()),  # 全部
    "analyst": [
        "scan.run", "analysis.run",
        "report.generate", "report.export",
        "baseline.run", "data.view",
    ],
    "auditor": [
        "audit.view", "audit.export",
        "data.view", "report.export",
    ],
    "viewer": [
        "data.view",
    ],
}

# 角色 -> 数据范围
ROLE_DATA_SCOPE: Dict[str, str] = {
    "admin": "all",
    "analyst": "own",
    "auditor": "auditable",
    "viewer": "own",
}

ROLES: Dict[str, Dict[str, str]] = {
    "admin": {"name": "管理员", "desc": "全部功能与数据权限"},
    "analyst": {"name": "分析师", "desc": "扫描/分析/报告生成"},
    "auditor": {"name": "审计员", "desc": "只读全部日志，禁止修改"},
    "viewer": {"name": "只读用户", "desc": "仅查看，不能操作"},
}

VALID_ROLES = tuple(ROLES.keys())


class PermissionDenied(Exception):
    """权限不足。"""


class RBACManager:
    """内存字典模拟的 RBAC 管理器。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._users: Dict[str, Dict[str, Any]] = {}
        self._next_id = 1
        # 内置种子用户
        self._seed()

    # ------------------------------------------------------------------ #
    def _seed(self) -> None:
        seeds = [
            ("admin", "admin", "admin@corp.local", "admin"),
            ("analyst_zhang", "分析师张", "zhang@corp.local", "analyst"),
            ("auditor_li", "审计员李", "li@corp.local", "auditor"),
            ("viewer_wang", "只读王", "wang@corp.local", "viewer"),
        ]
        for uname, name, email, role in seeds:
            self.create_user(name, role, email=email, username=uname)

    def _new_id(self) -> str:
        uid = f"U{self._next_id:05d}"
        self._next_id += 1
        return uid

    # ------------------------------------------------------------------ #
    # 用户 CRUD
    # ------------------------------------------------------------------ #
    def create_user(self, display_name: str, role: str,
                    email: str = "", username: str = "") -> Dict[str, Any]:
        if role not in ROLES:
            raise PermissionDenied(f"非法角色: {role}，可选 {list(ROLES)}")
        with self._lock:
            uid = self._new_id()
            user = {
                "user_id": uid,
                "username": username or f"user_{uid.lower()}",
                "display_name": display_name,
                "email": email,
                "role": role,
                "data_scope": ROLE_DATA_SCOPE[role],
                "is_active": True,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._users[uid] = user
            return self._public(user)

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        u = self._users.get(user_id)
        return self._public(u) if u else None

    def list_users(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [self._public(u) for u in self._users.values()]

    def update_role(self, user_id: str, new_role: str) -> Dict[str, Any]:
        if new_role not in ROLES:
            raise PermissionDenied(f"非法角色: {new_role}")
        with self._lock:
            u = self._users.get(user_id)
            if not u:
                raise KeyError(f"用户不存在: {user_id}")
            u["role"] = new_role
            u["data_scope"] = ROLE_DATA_SCOPE[new_role]
            return self._public(u)

    def set_active(self, user_id: str, active: bool) -> Dict[str, Any]:
        with self._lock:
            u = self._users.get(user_id)
            if not u:
                raise KeyError(f"用户不存在: {user_id}")
            u["is_active"] = active
            return self._public(u)

    def delete_user(self, user_id: str) -> bool:
        with self._lock:
            if user_id == "U00001":
                raise PermissionDenied("内置管理员不可删除")
            if user_id in self._users:
                del self._users[user_id]
                return True
            return False

    # ------------------------------------------------------------------ #
    # 权限判定
    # ------------------------------------------------------------------ #
    def has_permission(self, user_id: str, permission: str) -> bool:
        with self._lock:
            u = self._users.get(user_id)
            if not u or not u["is_active"]:
                return False
            return permission in ROLE_PERMISSIONS.get(u["role"], [])

    def require(self, user_id: str, permission: str) -> Dict[str, Any]:
        """返回用户信息，否则抛 PermissionDenied。"""
        with self._lock:
            u = self._users.get(user_id)
            if not u:
                raise PermissionDenied(f"用户不存在: {user_id}")
            if not u["is_active"]:
                raise PermissionDenied(f"用户已禁用: {user_id}")
            if permission not in ROLE_PERMISSIONS.get(u["role"], []):
                raise PermissionDenied(
                    f"角色[{ROLES[u['role']]['name']}]缺少功能权限[{permission}]"
                )
            return self._public(u)

    def can_view_data(self, user_id: str, owner_id: Optional[str] = None) -> bool:
        """数据权限判定。"""
        with self._lock:
            u = self._users.get(user_id)
            if not u:
                return False
            scope = u["data_scope"]
            if scope == "all":
                return True
            if scope == "auditable":
                return True  # 审计员可见全量日志
            if scope == "own":
                return owner_id is None or owner_id == user_id
            return False

    # ------------------------------------------------------------------ #
    def roles_meta(self) -> Dict[str, Any]:
        return {
            "roles": ROLES,
            "permissions": PERMISSIONS,
            "data_scopes": DATA_SCOPES,
            "role_permissions": ROLE_PERMISSIONS,
            "role_data_scope": ROLE_DATA_SCOPE,
        }

    def _public(self, u: Dict[str, Any]) -> Dict[str, Any]:
        """脱敏后的用户视图（不返回敏感字段，这里仅做拷贝）。"""
        out = dict(u)
        out["role_name"] = ROLES[u["role"]]["name"]
        return out
