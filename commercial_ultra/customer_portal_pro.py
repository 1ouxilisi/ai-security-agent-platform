# -*- coding: utf-8 -*-
"""
commercial_ultra/customer_portal_pro.py — 客户门户 Pro（商业产品体验极致）。

- 客户登录 / 注册（会话 token，内存字典）
- 项目管理：客户只看自己的项目
- 报告查看：在线看报告
- 账单管理：查看自己的账单
- 个人信息：资料 / 密码
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from typing import Any, Dict, List, Optional


def _hash_pwd(pwd: str) -> str:
    return hashlib.sha256(("portal_pro::" + pwd).encode()).hexdigest()


class CustomerPortalPro:
    """客户门户 Pro（全内存模拟，数据隔离）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._customers: Dict[str, Dict[str, Any]] = {}
        self._sessions: Dict[str, str] = {}
        self._projects: Dict[str, Dict[str, Any]] = {}
        self._reports: Dict[str, Dict[str, Any]] = {}
        self._seq = 0
        self._seed()

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{int(time.time()) % 100000:05d}{self._seq:03d}"

    def _seed(self) -> None:
        cid = self.register("pro@demo.com", "demo123", "演示企业", "王经理")["customer_id"]
        pid = self.create_project(cid, "线上业务系统", "https://shop.demo.com", "web")["project_id"]
        self.upload_report(pid, "2026-Q3 季度报告", {"high": 2, "medium": 5, "low": 9})

    # ------------------------------------------------------------------ #
    # 注册 / 登录
    # ------------------------------------------------------------------ #
    def register(self, email: str, password: str, company: str = "",
                 contact: str = "") -> Dict[str, Any]:
        email = (email or "").strip().lower()
        if not email or "@" not in email:
            raise ValueError("邮箱格式不正确")
        if not password or len(password) < 6:
            raise ValueError("密码至少 6 位")
        with self._lock:
            for c in self._customers.values():
                if c["email"] == email:
                    raise ValueError("该邮箱已注册")
            cid = self._next_id("C")
            self._customers[cid] = {
                "customer_id": cid, "email": email,
                "password_hash": _hash_pwd(password), "company": company,
                "contact": contact, "phone": "", "plan": "free",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            return {"customer_id": cid, "email": email, "registered": True}

    def login(self, email: str, password: str) -> Dict[str, Any]:
        email = (email or "").strip().lower()
        with self._lock:
            for c in self._customers.values():
                if c["email"] == email:
                    if not secrets.compare_digest(c["password_hash"], _hash_pwd(password)):
                        raise ValueError("密码错误")
                    token = secrets.token_urlsafe(24)
                    self._sessions[token] = c["customer_id"]
                    return {"token": token, "customer_id": c["customer_id"],
                            "email": c["email"], "company": c["company"],
                            "plan": c["plan"]}
        raise ValueError("用户不存在")

    def logout(self, token: str) -> bool:
        with self._lock:
            return self._sessions.pop(token, None) is not None

    def whoami(self, token: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            cid = self._sessions.get(token)
            if not cid:
                return None
            c = self._customers.get(cid)
            if not c:
                return None
            return {"customer_id": cid, "email": c["email"], "company": c["company"],
                    "contact": c["contact"], "phone": c["phone"], "plan": c["plan"]}

    # ------------------------------------------------------------------ #
    # 个人信息
    # ------------------------------------------------------------------ #
    def update_profile(self, customer_id: str, **fields: Any) -> Dict[str, Any]:
        allow = {"company", "contact", "phone"}
        with self._lock:
            c = self._customers.get(customer_id)
            if not c:
                raise ValueError("客户不存在")
            for k, v in fields.items():
                if k in allow and v is not None:
                    c[k] = v
            return {"customer_id": customer_id, "updated": sorted(allow & fields.keys())}

    def change_password(self, customer_id: str, old: str, new: str) -> bool:
        with self._lock:
            c = self._customers.get(customer_id)
            if not c:
                raise ValueError("客户不存在")
            if not secrets.compare_digest(c["password_hash"], _hash_pwd(old)):
                raise ValueError("原密码错误")
            if len(new) < 6:
                raise ValueError("新密码至少 6 位")
            c["password_hash"] = _hash_pwd(new)
            return True

    # ------------------------------------------------------------------ #
    # 项目管理
    # ------------------------------------------------------------------ #
    def create_project(self, customer_id: str, name: str, target: str,
                       kind: str = "web") -> Dict[str, Any]:
        with self._lock:
            pid = self._next_id("P")
            self._projects[pid] = {
                "project_id": pid, "owner": customer_id, "name": name,
                "target": target, "kind": kind, "status": "pending",
                "scan_count": 0,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            return {"project_id": pid, "name": name, "target": target}

    def list_projects(self, customer_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [p for p in self._projects.values() if p["owner"] == customer_id]

    def get_project(self, customer_id: str, project_id: str) -> Dict[str, Any]:
        with self._lock:
            p = self._projects.get(project_id)
            if not p or p["owner"] != customer_id:
                raise PermissionError("无权访问该项目或项目不存在")
            return p

    def delete_project(self, customer_id: str, project_id: str) -> bool:
        with self._lock:
            p = self._projects.get(project_id)
            if not p or p["owner"] != customer_id:
                raise PermissionError("无权删除该项目")
            self._projects.pop(project_id, None)
            for rid, r in list(self._reports.items()):
                if r["project_id"] == project_id:
                    self._reports.pop(rid, None)
            return True

    # ------------------------------------------------------------------ #
    # 报告查看
    # ------------------------------------------------------------------ #
    def upload_report(self, project_id: str, title: str,
                      summary: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if project_id not in self._projects:
                raise ValueError("项目不存在")
            rid = self._next_id("R")
            rec = {"report_id": rid, "project_id": project_id, "title": title,
                   "summary": summary, "status": "done",
                   "created_at": time.strftime("%Y-%m-%d %H:%M:%S")}
            self._reports[rid] = rec
            self._projects[project_id]["scan_count"] += 1
            self._projects[project_id]["status"] = "scanned"
            return rec

    def list_reports(self, customer_id: str, project_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            self.get_project(customer_id, project_id)
            return [r for r in self._reports.values() if r["project_id"] == project_id]

    def get_report(self, customer_id: str, report_id: str) -> Dict[str, Any]:
        with self._lock:
            r = self._reports.get(report_id)
            if not r:
                raise ValueError("报告不存在")
            self.get_project(customer_id, r["project_id"])
            return r

    # ------------------------------------------------------------------ #
    # 账单视图（与计费系统解耦，这里给门户一个只读摘要）
    # ------------------------------------------------------------------ #
    def billing_summary(self, customer_id: str) -> Dict[str, Any]:
        with self._lock:
            c = self._customers.get(customer_id)
            if not c:
                raise ValueError("客户不存在")
            return {"customer_id": customer_id, "plan": c["plan"],
                    "company": c["company"]}

    def overview(self, customer_id: str) -> Dict[str, Any]:
        projs = self.list_projects(customer_id)
        with self._lock:
            reports = sum(1 for r in self._reports.values()
                          if any(p["project_id"] == r["project_id"] for p in projs))
        return {"projects": len(projs), "reports": reports,
                "scans": sum(p["scan_count"] for p in projs)}


_portal: CustomerPortalPro | None = None


def get_customer_portal_pro() -> CustomerPortalPro:
    global _portal
    if _portal is None:
        _portal = CustomerPortalPro()
    return _portal
