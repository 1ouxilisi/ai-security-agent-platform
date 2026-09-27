# -*- coding: utf-8 -*-
"""
rbac_routes.py - RBAC多用户权限管理 API 路由

用户/角色/权限/会话/登录/密码哈希（PBKDF2）。
预设角色：admin(超级管理员)/analyst(安全分析师)/auditor(审计员)/viewer(只读用户)。

路由前缀：/api/v1/rbac
"""
from __future__ import annotations
import os, sys, json, sqlite3, hashlib, hmac, secrets, time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import log

router = APIRouter(prefix="/api/v1/rbac", tags=["RBAC权限管理"])

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "rbac.db")
SESSION_TTL_HOURS = 24

def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"code": 0, "data": data})

def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"code": status, "error": message}, status_code=status)

def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _hash_password(password: str, salt: str = None) -> tuple:
    """PBKDF2密码哈希，返回 (salt, hash)"""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return salt, dk.hex()

def _verify_password(password: str, salt: str, expected_hash: str) -> bool:
    _, actual_hash = _hash_password(password, salt)
    return hmac.compare_digest(actual_hash, expected_hash)

def _init_db():
    conn = _get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        email TEXT DEFAULT '',
        full_name TEXT DEFAULT '',
        role TEXT DEFAULT 'viewer',
        status TEXT DEFAULT 'active',
        failed_logins INTEGER DEFAULT 0,
        last_login TEXT DEFAULT '',
        created_at TEXT,
        updated_at TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS roles (
        id TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        description TEXT DEFAULT '',
        permissions TEXT DEFAULT '[]',
        is_system INTEGER DEFAULT 0,
        created_at TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        username TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TEXT,
        expires_at TEXT,
        last_active TEXT,
        ip TEXT DEFAULT '',
        user_agent TEXT DEFAULT ''
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        username TEXT,
        action TEXT,
        resource TEXT,
        detail TEXT,
        ip TEXT DEFAULT '',
        created_at TEXT
    )""")
    # 初始化预设角色
    roles = [
        ("admin", "超级管理员", "所有权限", json.dumps(["*"]), 1),
        ("analyst", "安全分析师", "扫描/报告/漏洞管理/资产管理", json.dumps(["scan:read","scan:write","report:read","report:write","vuln:read","vuln:write","asset:read","asset:write","dashboard:read","recon:read","recon:write"]), 1),
        ("auditor", "审计员", "只读+审计日志", json.dumps(["dashboard:read","audit:read","report:read","vuln:read","asset:read","scan:read"]), 1),
        ("viewer", "只读用户", "仅查看仪表盘", json.dumps(["dashboard:read"]), 1),
    ]
    now = datetime.now().isoformat()
    for rid, name, desc, perms, is_sys in roles:
        c.execute("INSERT OR IGNORE INTO roles VALUES (?,?,?,?,?,?)", (rid, name, desc, perms, is_sys, now))
    # 初始化默认管理员
    admin_salt, admin_hash = _hash_password("admin123")
    c.execute("INSERT OR IGNORE INTO users VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("USR-ADMIN-001", "admin", admin_hash, admin_salt, "admin@localhost", "系统管理员", "admin", "active", 0, "", now, now))
    conn.commit()
    conn.close()

_init_db()

# 请求模型
class LoginReq(BaseModel):
    username: str
    password: str

class UserReq(BaseModel):
    username: str
    password: str
    email: str = ""
    full_name: str = ""
    role: str = "viewer"

class UpdateUserReq(BaseModel):
    email: str = ""
    full_name: str = ""
    role: str = ""
    status: str = ""
    password: str = ""

class RoleReq(BaseModel):
    name: str
    description: str = ""
    permissions: List[str] = []

# 权限常量
ALL_PERMISSIONS = [
    "dashboard:read",
    "scan:read", "scan:write",
    "recon:read", "recon:write",
    "report:read", "report:write",
    "vuln:read", "vuln:write",
    "asset:read", "asset:write",
    "audit:read",
    "user:read", "user:write",
    "role:read", "role:write",
    "config:read", "config:write",
    "soc:read", "soc:write",
    "cloud:read", "cloud:write",
    "compliance:read", "compliance:write",
    "api-security:read", "api-security:write",
    "mobile:read", "mobile:write",
    "workflow:read", "workflow:write",
    "*",
]

def _get_session(token: str) -> Optional[dict]:
    """验证会话Token"""
    if not token:
        return None
    conn = _get_db()
    s = conn.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
    conn.close()
    if not s:
        return None
    if datetime.fromisoformat(s["expires_at"]) < datetime.now():
        return None
    return dict(s)

def _audit(user_id, username, action, resource, detail="", ip=""):
    try:
        conn = _get_db()
        conn.execute("INSERT INTO audit_log VALUES (?,?,?,?,?,?,?,?)",
            (f"AUD-{secrets.token_hex(8).upper()}", user_id, username, action, resource, detail[:500], ip, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception:
        pass

# 依赖：获取当前用户
async def get_current_user(x_api_key: str = Header(default=""), authorization: str = Header(default="")):
    token = x_api_key or (authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else "")
    session = _get_session(token)
    if session:
        return session
    # 兼容旧的API Key认证（admin）
    if token == os.environ.get("API_AUTH_KEY", ""):
        return {"user_id": "USR-ADMIN-001", "username": "admin", "role": "admin"}
    return None

def require_permission(permission: str):
    """权限检查依赖工厂"""
    async def checker(user: dict = Depends(get_current_user)):
        if not user:
            raise _err(401, "未登录或会话已过期")
        if user["role"] == "admin":
            return user
        conn = _get_db()
        role = conn.execute("SELECT permissions FROM roles WHERE name=?", (user["role"],)).fetchone()
        conn.close()
        if not role:
            raise _err(403, "角色不存在")
        perms = json.loads(role["permissions"])
        if "*" in perms or permission in perms:
            return user
        raise _err(403, f"权限不足，需要: {permission}")
    return checker

# ==================== 认证 ====================

@router.post("/auth/login")
def login(req: LoginReq):
    """用户登录，返回会话Token"""
    try:
        conn = _get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (req.username,)).fetchone()
        if not user:
            conn.close()
            return _err(401, "用户名或密码错误")
        if user["status"] != "active":
            conn.close()
            return _err(403, "账户已被禁用")
        if user["failed_logins"] >= 5:
            conn.close()
            return _err(403, "账户已锁定，请联系管理员解锁")
        if not _verify_password(req.password, user["salt"], user["password_hash"]):
            conn.execute("UPDATE users SET failed_logins=failed_logins+1 WHERE id=?", (user["id"],))
            conn.commit()
            conn.close()
            return _err(401, "用户名或密码错误")
        # 登录成功
        token = secrets.token_hex(32)
        now = datetime.now()
        expires = (now + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
        conn.execute("UPDATE users SET failed_logins=0, last_login=?, updated_at=? WHERE id=?",
            (now.isoformat(), now.isoformat(), user["id"]))
        conn.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?)",
            (token, user["id"], user["username"], user["role"], now.isoformat(), expires, now.isoformat(), "", ""))
        conn.commit()
        conn.close()
        _audit(user["id"], user["username"], "login", "auth", "用户登录成功")
        return _ok({
            "token": token,
            "user": {"id": user["id"], "username": user["username"], "role": user["role"], "full_name": user["full_name"], "email": user["email"]},
            "expires_at": expires,
            "ttl_hours": SESSION_TTL_HOURS,
        })
    except Exception as e:
        log.exception("login 错误")
        return _err(500, f"登录失败: {e}")

@router.post("/auth/logout")
def logout(user: dict = Depends(get_current_user)):
    """用户登出"""
    if not user:
        return _err(401, "未登录")
    try:
        token = user.get("token", "")
        conn = _get_db()
        if token:
            conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
        return _ok({"status": "logged_out"})
    except Exception as e:
        return _err(500, f"登出失败: {e}")

@router.get("/auth/me")
def get_me(user: dict = Depends(get_current_user)):
    """获取当前用户信息"""
    if not user:
        return _err(401, "未登录或会话已过期")
    conn = _get_db()
    u = conn.execute("SELECT id,username,email,full_name,role,status,last_login,created_at FROM users WHERE id=?", (user["user_id"],)).fetchone()
    role = conn.execute("SELECT name,description,permissions FROM roles WHERE name=?", (user["role"],)).fetchone()
    conn.close()
    if not u:
        return _err(404, "用户不存在")
    result = dict(u)
    if role:
        result["role_info"] = {"name": role["name"], "description": role["description"], "permissions": json.loads(role["permissions"])}
    return _ok(result)

# ==================== 用户管理 ====================

@router.get("/users")
def list_users(user: dict = Depends(require_permission("user:read"))):
    """用户列表"""
    conn = _get_db()
    rows = conn.execute("SELECT id,username,email,full_name,role,status,failed_logins,last_login,created_at FROM users ORDER BY created_at").fetchall()
    conn.close()
    return _ok({"items": [dict(r) for r in rows], "total": len(rows)})

@router.post("/users")
def create_user(req: UserReq, user: dict = Depends(require_permission("user:write"))):
    """创建用户"""
    try:
        if len(req.password) < 6:
            return _err(400, "密码至少6位")
        conn = _get_db()
        if conn.execute("SELECT id FROM users WHERE username=?", (req.username,)).fetchone():
            conn.close()
            return _err(400, "用户名已存在")
        uid = f"USR-{secrets.token_hex(6).upper()}"
        salt, pwd_hash = _hash_password(req.password)
        now = datetime.now().isoformat()
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (uid, req.username, pwd_hash, salt, req.email, req.full_name, req.role, "active", 0, "", now, now))
        conn.commit()
        conn.close()
        _audit(user["user_id"], user["username"], "create_user", "users", f"创建用户: {req.username}")
        return _ok({"id": uid, "username": req.username, "status": "created"})
    except Exception as e:
        return _err(500, f"创建用户失败: {e}")

@router.put("/users/{user_id}")
def update_user(user_id: str, req: UpdateUserReq, user: dict = Depends(require_permission("user:write"))):
    """更新用户信息"""
    try:
        conn = _get_db()
        u = conn.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
        if not u:
            conn.close()
            return _err(404, "用户不存在")
        updates = []
        params = []
        if req.email: updates.append("email=?"); params.append(req.email)
        if req.full_name: updates.append("full_name=?"); params.append(req.full_name)
        if req.role: updates.append("role=?"); params.append(req.role)
        if req.status: updates.append("status=?"); params.append(req.status)
        if req.password:
            salt, pwd_hash = _hash_password(req.password)
            updates.append("salt=?"); params.append(salt)
            updates.append("password_hash=?"); params.append(pwd_hash)
        updates.append("updated_at=?"); params.append(datetime.now().isoformat())
        params.append(user_id)
        conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=?", params)
        conn.commit()
        conn.close()
        return _ok({"id": user_id, "status": "updated"})
    except Exception as e:
        return _err(500, f"更新用户失败: {e}")

@router.delete("/users/{user_id}")
def delete_user(user_id: str, user: dict = Depends(require_permission("user:write"))):
    """删除用户（不能删除admin）"""
    if user_id == "USR-ADMIN-001":
        return _err(400, "不能删除默认管理员账户")
    try:
        conn = _get_db()
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        conn.commit()
        conn.close()
        return _ok({"id": user_id, "status": "deleted"})
    except Exception as e:
        return _err(500, f"删除用户失败: {e}")

# ==================== 角色管理 ====================

@router.get("/roles")
def list_roles(user: dict = Depends(require_permission("role:read"))):
    """角色列表"""
    conn = _get_db()
    rows = conn.execute("SELECT * FROM roles ORDER BY is_system DESC, name").fetchall()
    conn.close()
    roles = []
    for r in rows:
        d = dict(r)
        d["permissions"] = json.loads(d["permissions"])
        roles.append(d)
    return _ok({"items": roles, "total": len(roles), "all_permissions": ALL_PERMISSIONS})

@router.post("/roles")
def create_role(req: RoleReq, user: dict = Depends(require_permission("role:write"))):
    """创建自定义角色"""
    try:
        rid = f"ROLE-{secrets.token_hex(6).upper()}"
        conn = _get_db()
        conn.execute("INSERT INTO roles VALUES (?,?,?,?,?,?)",
            (rid, req.name, req.description, json.dumps(req.permissions), 0, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return _ok({"id": rid, "name": req.name, "status": "created"})
    except Exception as e:
        return _err(500, f"创建角色失败: {e}")

# ==================== 会话管理 ====================

@router.get("/sessions")
def list_sessions(user: dict = Depends(require_permission("user:read"))):
    """活跃会话列表"""
    conn = _get_db()
    now = datetime.now().isoformat()
    rows = conn.execute("SELECT token,user_id,username,role,created_at,expires_at,last_active FROM sessions WHERE expires_at > ? ORDER BY created_at DESC", (now,)).fetchall()
    conn.close()
    return _ok({"items": [dict(r) for r in rows], "total": len(rows)})

@router.delete("/sessions/{token}")
def revoke_session(token: str, user: dict = Depends(require_permission("user:write"))):
    """撤销会话"""
    conn = _get_db()
    conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit()
    conn.close()
    return _ok({"token": token[:16] + "...", "status": "revoked"})

# ==================== 审计日志 ====================

@router.get("/audit")
def audit_logs(limit: int = 50, user: dict = Depends(require_permission("audit:read"))):
    """操作审计日志"""
    conn = _get_db()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return _ok({"items": [dict(r) for r in rows], "total": len(rows)})

# ==================== 统计 ====================

@router.get("/stats")
def rbac_stats(user: dict = Depends(get_current_user)):
    """RBAC统计"""
    conn = _get_db()
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active_users = conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0]
    total_roles = conn.execute("SELECT COUNT(*) FROM roles").fetchone()[0]
    active_sessions = conn.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > ?", (datetime.now().isoformat(),)).fetchone()[0]
    by_role = {}
    for r in conn.execute("SELECT role, COUNT(*) as c FROM users GROUP BY role").fetchall():
        by_role[r["role"]] = r["c"]
    conn.close()
    return _ok({
        "total_users": total_users, "active_users": active_users,
        "total_roles": total_roles, "active_sessions": active_sessions,
        "users_by_role": by_role,
    })
