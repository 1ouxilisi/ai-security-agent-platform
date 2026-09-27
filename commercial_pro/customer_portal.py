#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
commercial_pro/customer_portal.py — 客户门户。

- 客户注册 / 登录（会话 token，内存字典）
- 项目管理：客户只能看自己的项目
- 报告查看：客户在线看自己项目的扫描报告
- 个人信息管理：资料 / 修改密码 / 联系人
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from typing import Any, Dict, List, Optional


def _hash_pwd(pwd: str) -> str:
    return hashlib.sha256(("portal::" + pwd).encode()).hexdigest()


class CustomerPortal:
    """客户门户（全内存模拟）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # customers: id -> record
        self._customers: Dict[str, Dict[str, Any]] = {}
        # sessions: token -> customer_id
        self._sessions: Dict[str, str] = {}
        # projects: id -> project record (owner=customer_id)
        self._projects: Dict[str, Dict[str, Any]] = {}
        # reports: id -> report record (belongs to project)
        self._reports: Dict[str, Dict[str, Any]] = {}
        self._seq = 0
        self._seed()

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{int(time.time()) % 100000:05d}{self._seq:03d}"

    def _seed(self) -> None:
        # 预置一个客户 + 项目 + 报告
        cid = self.register("demo@hacking.ai", "demo123", "演示客户", "张三")["customer_id"]
        self.update_profile(cid, company="演示安全有限公司", phone="13800000000",
                            note="企业版试用客户")
        pid = self.create_project(cid, "官网渗透测试", "https://demo.example.com",
                                  "web")["project_id"]
        self.upload_report(pid, "首轮扫描报告", {"high": 3, "medium": 7, "low": 12})

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
                "password_hash": _hash_pwd(password),
                "company": company, "contact": contact, "phone": "",
                "note": "", "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
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
                            "email": c["email"], "company": c["company"]}
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
            return {"customer_id": cid, "email": c["email"],
                    "company": c["company"], "contact": c["contact"],
                    "phone": c["phone"], "note": c["note"]}

    # ------------------------------------------------------------------ #
    # 个人信息
    # ------------------------------------------------------------------ #
    def update_profile(self, customer_id: str, **fields: Any) -> Dict[str, Any]:
        allow = {"company", "contact", "phone", "note"}
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
    # 项目管理（数据隔离：只能看自己的）
    # ------------------------------------------------------------------ #
    def create_project(self, customer_id: str, name: str, target: str,
                       kind: str = "web") -> Dict[str, Any]:
        with self._lock:
            pid = self._next_id("P")
            self._projects[pid] = {
                "project_id": pid, "owner": customer_id, "name": name,
                "target": target, "kind": kind,
                "status": "pending", "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scan_count": 0,
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
            rec = {
                "report_id": rid, "project_id": project_id, "title": title,
                "summary": summary, "status": "done",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._reports[rid] = rec
            self._projects[project_id]["scan_count"] += 1
            self._projects[project_id]["status"] = "scanned"
            return rec

    def list_reports(self, customer_id: str, project_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            self.get_project(customer_id, project_id)   # 鉴权
            return [r for r in self._reports.values() if r["project_id"] == project_id]

    def get_report(self, customer_id: str, report_id: str) -> Dict[str, Any]:
        with self._lock:
            r = self._reports.get(report_id)
            if not r:
                raise ValueError("报告不存在")
            self.get_project(customer_id, r["project_id"])  # 鉴权
            return r

    # ------------------------------------------------------------------ #
    # 聚合
    # ------------------------------------------------------------------ #
    def portal_summary(self, customer_id: str) -> Dict[str, Any]:
        projs = self.list_projects(customer_id)
        with self._lock:
            total_reports = sum(1 for r in self._reports.values()
                                if any(p["project_id"] == r["project_id"] for p in projs))
        return {
            "projects": len(projs),
            "reports": total_reports,
            "scan_count": sum(p["scan_count"] for p in projs),
        }

    def admin_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "customers": len(self._customers),
                "projects": len(self._projects),
                "reports": len(self._reports),
                "active_sessions": len(self._sessions),
            }


_portal: CustomerPortal | None = None


def get_customer_portal() -> CustomerPortal:
    global _portal
    if _portal is None:
        _portal = CustomerPortal()
    return _portal
