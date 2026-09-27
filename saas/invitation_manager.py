#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
invitation_manager 模块 — 邀请管理器（SaaS 化基础模块 v10）

功能：
    - 创建邀请（邮箱/角色/有效期/最大使用次数/自定义消息），UUID+签名令牌
    - 发送邀请链接（预留邮件接口，生成邀请 URL）
    - 接受邀请（新用户建账户 / 已有用户加入租户），状态流转
    - 邀请管理（列表/状态/撤销/重发/批量）
    - 邀请统计（数量/接受率/待处理/已过期/趋势）

注意：本模块仅用于授权的安全产品。
"""

import os
import json
import time
import hmac
import uuid
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

try:
    from loguru import logger
except ImportError:  # pragma: no cover
    import logging
    logger = logging.getLogger(__name__)

from saas.user_manager import user_manager  # noqa: E402

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(_BASE_DIR, "data", "ai_hacking_agent.db")


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _get_conn(db_path: str = DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


class InvitationManager:
    """邀请管理器（单例）。"""

    def __init__(self, db_path: str = DB_PATH):
        """初始化邀请管理器并建表。"""
        self.db_path = db_path
        self._secret = secrets.token_bytes(32)
        self.email_sender = None  # callable(email, url, message) -> bool，预留
        self._init_db()
        logger.info("InvitationManager 初始化完成")

    def _init_db(self) -> None:
        conn = _get_conn(self.db_path)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_invitations (
                    invitation_id TEXT PRIMARY KEY,
                    token TEXT UNIQUE,
                    email TEXT,
                    role TEXT DEFAULT 'user',
                    tenant_id TEXT DEFAULT 'default',
                    status TEXT DEFAULT 'pending',
                    message TEXT DEFAULT '',
                    max_uses INTEGER DEFAULT 1,
                    used_count INTEGER DEFAULT 0,
                    expires_at TEXT,
                    invited_by TEXT DEFAULT '',
                    invited_user_id TEXT DEFAULT '',
                    accept_url TEXT DEFAULT '',
                    created_at TEXT,
                    accepted_at TEXT DEFAULT '',
                    revoked_at TEXT DEFAULT ''
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _conn(self) -> sqlite3.Connection:
        return _get_conn(self.db_path)

    def _sign(self, invitation_id: str, email: str) -> str:
        """对邀请 id + 邮箱生成签名。"""
        msg = f"{invitation_id}:{email}".encode("utf-8")
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def _make_token(self, invitation_id: str, email: str) -> str:
        raw = f"{invitation_id}.{uuid.uuid4().hex}.{self._sign(invitation_id, email)}"
        return base64_urlsafe_encode(raw)

    @staticmethod
    def _is_expired(row: sqlite3.Row) -> bool:
        try:
            return datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S") < datetime.now()
        except (ValueError, TypeError):
            return True

    # ---------------------------- 创建 ----------------------------
    def create_invitation(self, email: str, role: str = "user",
                          expires_in_days: int = 7, max_uses: int = 1,
                          message: Optional[str] = None,
                          tenant_id: str = "default",
                          invited_by: str = "") -> Dict[str, Any]:
        """创建邀请。"""
        invitation_id = f"inv_{uuid.uuid4().hex[:16]}"
        token = self._make_token(invitation_id, email)
        now = datetime.now()
        expires = (now + timedelta(days=expires_in_days)).strftime("%Y-%m-%d %H:%M:%S")
        accept_url = f"/accept-invitation?token={token}"
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO saas_invitations "
                "(invitation_id, token, email, role, tenant_id, status, message, max_uses, "
                " used_count, expires_at, invited_by, accept_url, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (invitation_id, token, email, role, tenant_id, "pending",
                 message or "", max_uses, 0, expires, invited_by, accept_url,
                 now.strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()
            logger.info(f"创建邀请: {email} -> {role} ({invitation_id})")
            return {
                "invitation_id": invitation_id,
                "token": token,
                "email": email,
                "role": role,
                "status": "pending",
                "expires_at": expires,
                "accept_url": accept_url,
            }
        finally:
            conn.close()

    # ---------------------------- 发送 ----------------------------
    def send_invitation(self, invitation_id: str) -> bool:
        """通过邮件发送邀请链接（预留邮件接口）。"""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM saas_invitations WHERE invitation_id=?", (invitation_id,)).fetchone()
            if not row:
                return False
            url = row["accept_url"]
            if self.email_sender:
                try:
                    self.email_sender(row["email"], url, row["message"] or "")
                except Exception as e:  # pragma: no cover
                    logger.error(f"邀请邮件发送失败: {e}")
            logger.info(f"邀请已发送: {row['email']} -> {url}")
            return True
        finally:
            conn.close()

    # ---------------------------- 接受 ----------------------------
    def accept_invitation(self, token: str, password: Optional[str] = None,
                          user_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """接受邀请：新用户建账户或已有用户加入租户。"""
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM saas_invitations WHERE token=?", (token,)).fetchone()
            if not row:
                raise ValueError("邀请令牌无效")
            inv = dict(row)
            if inv["status"] == "revoked":
                raise ValueError("邀请已被撤销")
            if self._is_expired(row):
                conn.execute(
                    "UPDATE saas_invitations SET status='expired' WHERE invitation_id=?",
                    (inv["invitation_id"],),
                )
                conn.commit()
                raise ValueError("邀请已过期")
            if inv["used_count"] >= inv["max_uses"]:
                raise ValueError("邀请已用完")

            user_data = user_data or {}
            existing = user_manager.get_user_by_email(inv["email"])
            if existing:
                user_id = existing["user_id"]
                result = "joined"
            else:
                if not password:
                    raise ValueError("新用户注册需提供密码")
                created = user_manager.create_user(
                    username=user_data.get("username") or inv["email"].split("@")[0],
                    email=inv["email"],
                    password=password,
                    display_name=user_data.get("display_name", ""),
                    tenant_id=inv["tenant_id"],
                    status="active",
                )
                user_id = created["user_id"]
                result = "created"

            user_manager.assign_role(user_id, inv["role"])
            new_used = inv["used_count"] + 1
            new_status = "accepted" if new_used >= inv["max_uses"] else "pending"
            conn.execute(
                "UPDATE saas_invitations SET used_count=?, status=?, invited_user_id=?, accepted_at=? WHERE invitation_id=?",
                (new_used, new_status, user_id, _now_str(), inv["invitation_id"]),
            )
            conn.commit()
            return {"result": result, "user_id": user_id, "role": inv["role"],
                    "status": new_status}
        finally:
            conn.close()

    # ---------------------------- 查询与管理 ----------------------------
    def get_invitation(self, invitation_id: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM saas_invitations WHERE invitation_id=?", (invitation_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def list_invitations(self, status: Optional[str] = None,
                         page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        conn = self._conn()
        try:
            where, args = "", []
            if status:
                where = " WHERE status=?"
                args.append(status)
            total = conn.execute(
                f"SELECT COUNT(*) c FROM saas_invitations{where}", args).fetchone()["c"]
            offset = (max(1, page) - 1) * page_size
            rows = conn.execute(
                f"SELECT * FROM saas_invitations{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                args + [page_size, offset]).fetchall()
            return {"total": total, "page": page, "page_size": page_size,
                    "items": [dict(r) for r in rows]}
        finally:
            conn.close()

    def revoke_invitation(self, invitation_id: str) -> bool:
        conn = self._conn()
        try:
            cur = conn.execute(
                "UPDATE saas_invitations SET status='revoked', revoked_at=? WHERE invitation_id=? AND status='pending'",
                (_now_str(), invitation_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def resend_invitation(self, invitation_id: str) -> bool:
        """重新发送邀请（重置有效期 7 天）。"""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM saas_invitations WHERE invitation_id=?", (invitation_id,)).fetchone()
            if not row:
                return False
            new_expires = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "UPDATE saas_invitations SET status='pending', expires_at=?, revoked_at='' WHERE invitation_id=?",
                (new_expires, invitation_id),
            )
            conn.commit()
        finally:
            conn.close()
        return self.send_invitation(invitation_id)

    # ---------------------------- 统计 ----------------------------
    def get_stats(self) -> Dict[str, Any]:
        conn = self._conn()
        try:
            total = conn.execute("SELECT COUNT(*) c FROM saas_invitations").fetchone()["c"]
            by_status = {}
            for r in conn.execute(
                    "SELECT status, COUNT(*) c FROM saas_invitations GROUP BY status").fetchall():
                by_status[r["status"]] = r["c"]
            accepted = by_status.get("accepted", 0)
            # 近 7 天趋势
            trend = []
            for i in range(6, -1, -1):
                day = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
                c = conn.execute(
                    "SELECT COUNT(*) c FROM saas_invitations WHERE created_at LIKE ?",
                    (day + "%",)).fetchone()["c"]
                trend.append({"date": day, "count": c})
            return {
                "total_invitations": total,
                "pending": by_status.get("pending", 0),
                "accepted": accepted,
                "expired": by_status.get("expired", 0),
                "revoked": by_status.get("revoked", 0),
                "accept_rate": round(accepted / total * 100, 2) if total else 0.0,
                "trend": trend,
            }
        finally:
            conn.close()


def base64_urlsafe_encode(raw: str) -> str:
    """字符串 -> urlsafe base64（去填充）。"""
    import base64 as _b64
    return _b64.urlsafe_b64encode(raw.encode("utf-8")).rstrip(b"=").decode("ascii")


# 模块级单例
invitation_manager = InvitationManager()


if __name__ == "__main__":
    print("InvitationManager 自检")
    inv = invitation_manager.create_invitation("newbie@example.com", role="user")
    print("create:", inv["invitation_id"], inv["status"])
    print("stats:", invitation_manager.get_stats())
