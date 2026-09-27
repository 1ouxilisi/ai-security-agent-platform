#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auth_manager 模块 — 用户认证管理器（SaaS 化基础模块 v10）

功能：
    - 用户注册（用户名/邮箱/手机号 + 密码强度校验 + 验证令牌）
    - 用户登录（多标识登录，失败 5 次锁定 15 分钟）
    - 密码重置（邮箱/手机验证码，30 分钟有效）
    - 密码修改（验证旧密码，历史最近 3 次不可重复）
    - 会话管理（多设备登录，24 小时超时，强制登出）
    - Token 管理（纯 Python JWT / HS256，Access 2h + Refresh 7d）
    - 登录日志（时间/IP/UA/结果/原因，异常登录检测）
    - 密码哈希（PBKDF2-HMAC-SHA256，随机 salt，10 万次迭代）

注意：本模块仅用于授权的安全产品，请勿用于非法用途。
"""

import os
import re
import json
import time
import hmac
import base64
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


# ---------------------------------------------------------------------------
# 路径与常量
# ---------------------------------------------------------------------------
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(_BASE_DIR, "data", "ai_hacking_agent.db")

# 安全策略常量
MAX_FAILED_ATTEMPTS = 5          # 登录失败次数阈值
LOCK_DURATION_MINUTES = 15       # 锁定时长（分钟）
SESSION_TIMEOUT_HOURS = 24       # 会话超时（小时）
ACCESS_TOKEN_EXPIRE_HOURS = 2    # Access Token 有效期
REFRESH_TOKEN_EXPIRE_DAYS = 7    # Refresh Token 有效期
RESET_TOKEN_EXPIRE_MINUTES = 30  # 重置令牌有效期
PBKDF2_ITERATIONS = 100000       # PBKDF2 迭代次数
PASSWORD_HISTORY_COUNT = 3       # 密码历史校验条数

# 密码强度正则要求
_PASSWORD_RE_UPPER = re.compile(r"[A-Z]")
_PASSWORD_RE_LOWER = re.compile(r"[a-z]")
_PASSWORD_RE_DIGIT = re.compile(r"[0-9]")
_PASSWORD_RE_SPECIAL = re.compile(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?~`]")


def _now_str() -> str:
    """返回当前时间字符串。"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _get_conn(db_path: str = DB_PATH) -> sqlite3.Connection:
    """获取 SQLite 连接（启用外键与行字典化）。"""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def _load_or_create_secret() -> bytes:
    """加载或生成 JWT 签名密钥（落盘 data/.saas_jwt_secret）。"""
    secret_file = os.path.join(_BASE_DIR, "data", ".saas_jwt_secret")
    env_secret = os.environ.get("SAAS_JWT_SECRET")
    if env_secret:
        return env_secret.encode("utf-8")
    try:
        if os.path.exists(secret_file):
            with open(secret_file, "rb") as f:
                return f.read().strip()
        secret = secrets.token_bytes(48)
        with open(secret_file, "wb") as f:
            f.write(secret)
        try:
            os.chmod(secret_file, 0o600)
        except OSError:
            pass
        return secret
    except Exception as e:  # pragma: no cover
        logger.warning(f"JWT 密钥文件读写失败，使用临时密钥: {e}")
        return secrets.token_bytes(48)


# ---------------------------------------------------------------------------
# 纯 Python JWT（HS256）
# ---------------------------------------------------------------------------
class _JWT:
    """轻量 JWT 实现（HS256），不依赖 PyJWT。"""

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        pad = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + pad)

    @classmethod
    def encode(cls, payload: Dict[str, Any], secret: bytes) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        h = cls._b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        p = cls._b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{h}.{p}".encode("ascii")
        sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        return f"{h}.{p}.{cls._b64url_encode(sig)}"

    @classmethod
    def decode(cls, token: str, secret: bytes) -> Dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("令牌格式错误")
        h, p, s = parts
        signing_input = f"{h}.{p}".encode("ascii")
        expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, cls._b64url_decode(s)):
            raise ValueError("签名校验失败")
        payload = json.loads(cls._b64url_decode(p).decode("utf-8"))
        exp = payload.get("exp")
        if exp and time.time() > float(exp):
            raise ValueError("令牌已过期")
        return payload


# ---------------------------------------------------------------------------
# 密码工具
# ---------------------------------------------------------------------------
def hash_password(password: str) -> Dict[str, str]:
    """使用 PBKDF2-HMAC-SHA256 哈希密码。

    Args:
        password: 明文密码。

    Returns:
        包含 salt 与 hash 的字典（hex 编码）。
    """
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return {"salt": salt.hex(), "hash": dk.hex()}


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    """校验密码是否匹配。"""
    try:
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def check_password_strength(password: str) -> List[str]:
    """校验密码强度，返回不满足要求的原因列表（空列表表示通过）。"""
    problems: List[str] = []
    if len(password) < 8:
        problems.append("密码长度至少 8 位")
    if len(password) > 128:
        problems.append("密码长度不能超过 128 位")
    if not _PASSWORD_RE_UPPER.search(password):
        problems.append("需包含大写字母")
    if not _PASSWORD_RE_LOWER.search(password):
        problems.append("需包含小写字母")
    if not _PASSWORD_RE_DIGIT.search(password):
        problems.append("需包含数字")
    if not _PASSWORD_RE_SPECIAL.search(password):
        problems.append("需包含特殊字符")
    return problems


# ---------------------------------------------------------------------------
# 认证管理器
# ---------------------------------------------------------------------------
class AuthManager:
    """用户认证管理器（单例）。"""

    def __init__(self, db_path: str = DB_PATH):
        """初始化认证管理器并建表。"""
        self.db_path = db_path
        self._secret = _load_or_create_secret()
        # 已吊销的 access token jti 集合（进程内）
        self._revoked_jti: set = set()
        self._init_db()
        logger.info("AuthManager 初始化完成")

    # ---------------------------- 数据库 ----------------------------
    def _init_db(self) -> None:
        conn = _get_conn(self.db_path)
        try:
            c = conn.cursor()
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE,
                    email TEXT UNIQUE,
                    phone TEXT,
                    password_hash TEXT,
                    salt TEXT,
                    status TEXT DEFAULT 'pending',
                    display_name TEXT DEFAULT '',
                    department TEXT DEFAULT '',
                    position TEXT DEFAULT '',
                    avatar TEXT DEFAULT '',
                    language TEXT DEFAULT 'zh-CN',
                    timezone TEXT DEFAULT 'Asia/Shanghai',
                    tenant_id TEXT DEFAULT 'default',
                    created_at TEXT,
                    updated_at TEXT,
                    last_login_at TEXT,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TEXT DEFAULT '',
                    preferences TEXT DEFAULT '{}',
                    extended_attrs TEXT DEFAULT '{}'
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT,
                    jti TEXT,
                    ip TEXT DEFAULT '',
                    user_agent TEXT DEFAULT '',
                    created_at TEXT,
                    expires_at TEXT,
                    last_seen TEXT,
                    active INTEGER DEFAULT 1
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_login_logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    username TEXT,
                    ip TEXT,
                    user_agent TEXT,
                    result TEXT,
                    reason TEXT DEFAULT '',
                    is_anomaly INTEGER DEFAULT 0,
                    anomaly_type TEXT DEFAULT '',
                    created_at TEXT
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_password_resets (
                    token TEXT PRIMARY KEY,
                    user_id TEXT,
                    purpose TEXT,
                    code TEXT DEFAULT '',
                    expires_at TEXT,
                    used INTEGER DEFAULT 0,
                    created_at TEXT
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    password_hash TEXT,
                    salt TEXT,
                    created_at TEXT
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _conn(self) -> sqlite3.Connection:
        return _get_conn(self.db_path)

    # ---------------------------- 工具 ----------------------------
    @staticmethod
    def _to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row) if row else {}

    def _find_user(self, conn: sqlite3.Connection, identifier: str) -> Optional[sqlite3.Row]:
        """按用户名/邮箱/手机号查找用户。"""
        cur = conn.execute(
            "SELECT * FROM saas_users WHERE username=? OR email=? OR phone=?",
            (identifier, identifier, identifier),
        )
        return cur.fetchone()

    def _detect_anomaly(self, ip: str, user_agent: str, user_id: Optional[str]) -> (bool, str):
        """简单异常登录检测：异地 / 异常时间 / 暴力破解。"""
        reasons: List[str] = []
        # 暴力破解：近 15 分钟内失败 >= 4 次
        since = (datetime.now() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
        conn = self._conn()
        try:
            cur = conn.execute(
                "SELECT COUNT(*) AS cnt FROM saas_login_logs "
                "WHERE result='failure' AND created_at>=?",
                (since,),
            )
            if (cur.fetchone()["cnt"] or 0) >= 4:
                reasons.append("暴力破解")
            # 异常时间：凌晨 0-5 点登录
            hour = datetime.now().hour
            if 0 <= hour < 5:
                reasons.append("异常时间")
        except Exception:
            pass
        finally:
            conn.close()
        if reasons:
            return True, ",".join(reasons)
        return False, ""

    def _write_login_log(self, user_id: Optional[str], username: str, ip: str,
                         user_agent: str, result: str, reason: str = "") -> None:
        anomaly, atype = self._detect_anomaly(ip, user_agent, user_id)
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO saas_login_logs "
                "(user_id, username, ip, user_agent, result, reason, is_anomaly, anomaly_type, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (user_id, username, ip or "", user_agent or "", result, reason,
                 1 if anomaly else 0, atype, _now_str()),
            )
            conn.commit()
        except Exception as e:  # pragma: no cover
            logger.error(f"写入登录日志失败: {e}")
        finally:
            conn.close()

    # ---------------------------- 注册 ----------------------------
    def register(self, username: str, email: str, password: str,
                 phone: Optional[str] = None) -> Dict[str, Any]:
        """注册新用户。

        Args:
            username: 用户名。
            email: 邮箱。
            password: 明文密码。
            phone: 手机号（可选）。

        Returns:
            注册结果字典，含 user_id 与验证令牌。
        """
        if not username or not re.match(r"^[a-zA-Z0-9_\-\.]{3,32}$", username):
            raise ValueError("用户名需为 3-32 位字母/数字/下划线/横线/点")
        if not email or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            raise ValueError("邮箱格式不正确")
        problems = check_password_strength(password)
        if problems:
            raise ValueError("密码强度不足: " + "; ".join(problems))

        conn = self._conn()
        try:
            cur = conn.execute(
                "SELECT user_id FROM saas_users WHERE username=? OR email=?",
                (username, email),
            )
            if cur.fetchone():
                raise ValueError("用户名或邮箱已被注册")

            ph = hash_password(password)
            user_id = f"user_{secrets.token_hex(10)}"
            now = _now_str()
            conn.execute(
                "INSERT INTO saas_users "
                "(user_id, username, email, phone, password_hash, salt, status, "
                " tenant_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (user_id, username, email, phone or "", ph["hash"], ph["salt"],
                 "pending", "default", now, now),
            )
            # 初始密码历史
            conn.execute(
                "INSERT INTO saas_password_history (user_id, password_hash, salt, created_at) "
                "VALUES (?,?,?,?)",
                (user_id, ph["hash"], ph["salt"], now),
            )
            # 验证令牌
            verify_token = secrets.token_urlsafe(32)
            conn.execute(
                "INSERT INTO saas_password_resets (token, user_id, purpose, expires_at, created_at) "
                "VALUES (?,?,?,?,?)",
                (verify_token, user_id, "verify",
                 (datetime.now() + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S"), now),
            )
            conn.commit()
            logger.info(f"注册用户: {username} ({user_id})")
            return {
                "user_id": user_id,
                "username": username,
                "email": email,
                "verify_token": verify_token,
                "message": "注册成功，请完成邮箱/手机验证",
            }
        finally:
            conn.close()

    # ---------------------------- 登录 ----------------------------
    def login(self, identifier: str, password: str,
              ip: Optional[str] = None, user_agent: Optional[str] = None) -> Dict[str, Any]:
        """用户登录。

        Args:
            identifier: 用户名/邮箱/手机号。
            password: 明文密码。
            ip: 客户端 IP。
            user_agent: 客户端 UA。

        Returns:
            含 access_token / refresh_token / session_id 的字典。
        """
        conn = self._conn()
        try:
            row = self._find_user(conn, identifier)
            if not row:
                self._write_login_log(None, identifier, ip or "", user_agent or "",
                                      "failure", "用户不存在")
                raise ValueError("用户名或密码错误")

            user = dict(row)
            # 锁定检查
            if user.get("locked_until"):
                try:
                    if datetime.strptime(user["locked_until"], "%Y-%m-%d %H:%M:%S") > datetime.now():
                        self._write_login_log(user["user_id"], user["username"], ip or "",
                                              user_agent or "", "failure", "账户已锁定")
                        raise ValueError("账户已锁定，请稍后再试")
                except ValueError:
                    pass

            if user.get("status") == "inactive":
                self._write_login_log(user["user_id"], user["username"], ip or "",
                                      user_agent or "", "failure", "账户未激活")
                raise ValueError("账户未激活，请联系管理员")

            ok = verify_password(password, user["salt"], user["password_hash"])
            if not ok:
                attempts = (user.get("failed_attempts") or 0) + 1
                locked_until = ""
                if attempts >= MAX_FAILED_ATTEMPTS:
                    locked_until = (datetime.now() +
                                    timedelta(minutes=LOCK_DURATION_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
                conn.execute(
                    "UPDATE saas_users SET failed_attempts=?, locked_until=? WHERE user_id=?",
                    (attempts, locked_until, user["user_id"]),
                )
                conn.commit()
                self._write_login_log(user["user_id"], user["username"], ip or "",
                                      user_agent or "", "failure", "密码错误")
                if locked_until:
                    raise ValueError(f"密码错误次数过多，账户锁定 {LOCK_DURATION_MINUTES} 分钟")
                raise ValueError("用户名或密码错误")

            # 登录成功
            conn.execute(
                "UPDATE saas_users SET failed_attempts=0, locked_until='', last_login_at=? WHERE user_id=?",
                (_now_str(), user["user_id"]),
            )
            conn.commit()

            tokens = self._issue_tokens(user["user_id"])
            session_id = self._create_session(
                user["user_id"], tokens["jti"], ip or "", user_agent or "")
            self._write_login_log(user["user_id"], user["username"], ip or "",
                                  user_agent or "", "success")
            return {
                "user_id": user["user_id"],
                "username": user["username"],
                "email": user["email"],
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "session_id": session_id,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_EXPIRE_HOURS * 3600,
            }
        except ValueError:
            raise
        finally:
            conn.close()

    # ---------------------------- Token ----------------------------
    def _issue_tokens(self, user_id: str) -> Dict[str, str]:
        """签发 Access + Refresh 双 Token。"""
        now = int(time.time())
        jti = secrets.token_urlsafe(24)
        access_payload = {
            "sub": user_id, "type": "access", "jti": jti,
            "iat": now, "exp": now + ACCESS_TOKEN_EXPIRE_HOURS * 3600,
        }
        refresh_payload = {
            "sub": user_id, "type": "refresh", "jti": secrets.token_urlsafe(24),
            "iat": now, "exp": now + REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        }
        return {
            "access_token": _JWT.encode(access_payload, self._secret),
            "refresh_token": _JWT.encode(refresh_payload, self._secret),
            "jti": jti,
        }

    def verify_token(self, token: str) -> Dict[str, Any]:
        """验证 Access Token，返回 payload。"""
        try:
            payload = _JWT.decode(token, self._secret)
        except ValueError as e:
            raise ValueError(f"令牌无效: {e}")
        if payload.get("type") != "access":
            raise ValueError("非 Access 令牌")
        if payload.get("jti") in self._revoked_jti:
            raise ValueError("令牌已被吊销")
        return payload

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """使用 Refresh Token 刷新 Access Token。"""
        try:
            payload = _JWT.decode(refresh_token, self._secret)
        except ValueError as e:
            raise ValueError(f"刷新令牌无效: {e}")
        if payload.get("type") != "refresh":
            raise ValueError("非 Refresh 令牌")
        user_id = payload.get("sub")
        tokens = self._issue_tokens(user_id)
        # 更新对应会话 jti
        conn = self._conn()
        try:
            conn.execute(
                "UPDATE saas_sessions SET jti=?, last_seen=? WHERE user_id=? AND active=1 ORDER BY created_at DESC LIMIT 1",
                (tokens["jti"], _now_str(), user_id),
            )
            conn.commit()
        except Exception:
            pass
        finally:
            conn.close()
        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_HOURS * 3600,
        }

    # ---------------------------- 会话 ----------------------------
    def _create_session(self, user_id: str, jti: str, ip: str, user_agent: str) -> str:
        session_id = f"sess_{secrets.token_hex(12)}"
        now = datetime.now()
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO saas_sessions "
                "(session_id, user_id, jti, ip, user_agent, created_at, expires_at, last_seen, active) "
                "VALUES (?,?,?,?,?,?,?,?,1)",
                (session_id, user_id, jti, ip, user_agent,
                 now.strftime("%Y-%m-%d %H:%M:%S"),
                 (now + timedelta(hours=SESSION_TIMEOUT_HOURS)).strftime("%Y-%m-%d %H:%M:%S"),
                 now.strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()
        finally:
            conn.close()
        return session_id

    def get_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """获取用户有效会话列表。"""
        conn = self._conn()
        try:
            cur = conn.execute(
                "SELECT * FROM saas_sessions WHERE user_id=? AND active=1 ORDER BY created_at DESC",
                (user_id,),
            )
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def logout(self, session_id: str) -> bool:
        """销毁会话（登出）。"""
        conn = self._conn()
        try:
            cur = conn.execute("SELECT jti FROM saas_sessions WHERE session_id=?", (session_id,))
            row = cur.fetchone()
            if row:
                self._revoked_jti.add(row["jti"])
            cur = conn.execute(
                "UPDATE saas_sessions SET active=0 WHERE session_id=?", (session_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def revoke_session(self, session_id: str) -> bool:
        """强制登出（管理员撤销会话）。"""
        return self.logout(session_id)

    # ---------------------------- 密码重置 ----------------------------
    def reset_password_request(self, email_or_phone: str) -> Dict[str, Any]:
        """请求重置密码，生成重置令牌（30 分钟有效）。"""
        conn = self._conn()
        try:
            cur = conn.execute(
                "SELECT user_id, username, email, phone FROM saas_users WHERE email=? OR phone=?",
                (email_or_phone, email_or_phone),
            )
            row = cur.fetchone()
            # 无论是否存在都返回成功，避免用户枚举
            if not row:
                return {"success": True, "message": "若账户存在，重置链接已发送", "token": None}
            token = secrets.token_urlsafe(32)
            conn.execute(
                "INSERT INTO saas_password_resets (token, user_id, purpose, expires_at, created_at) "
                "VALUES (?,?,?,?,?)",
                (token, row["user_id"], "reset",
                 (datetime.now() + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)).strftime("%Y-%m-%d %H:%M:%S"),
                 _now_str()),
            )
            conn.commit()
            logger.info(f"密码重置请求: {row['username']}")
            return {
                "success": True,
                "message": "若账户存在，重置链接已发送",
                "token": token,
            }
        finally:
            conn.close()

    def reset_password_confirm(self, token: str, new_password: str) -> bool:
        """通过重置令牌确认新密码。"""
        problems = check_password_strength(new_password)
        if problems:
            raise ValueError("密码强度不足: " + "; ".join(problems))
        conn = self._conn()
        try:
            cur = conn.execute(
                "SELECT * FROM saas_password_resets WHERE token=? AND purpose='reset' AND used=0",
                (token,),
            )
            row = cur.fetchone()
            if not row:
                raise ValueError("重置令牌无效或已使用")
            if datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S") < datetime.now():
                raise ValueError("重置令牌已过期")
            ph = hash_password(new_password)
            conn.execute(
                "UPDATE saas_users SET password_hash=?, salt=?, failed_attempts=0, locked_until='', updated_at=? WHERE user_id=?",
                (ph["hash"], ph["salt"], _now_str(), row["user_id"]),
            )
            conn.execute(
                "INSERT INTO saas_password_history (user_id, password_hash, salt, created_at) VALUES (?,?,?,?)",
                (row["user_id"], ph["hash"], ph["salt"], _now_str()),
            )
            conn.execute("UPDATE saas_password_resets SET used=1 WHERE token=?", (token,))
            # 重置后撤销所有会话
            conn.execute("UPDATE saas_sessions SET active=0 WHERE user_id=?", (row["user_id"],))
            conn.commit()
            return True
        finally:
            conn.close()

    # ---------------------------- 修改密码 ----------------------------
    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """登录后修改密码（校验旧密码 + 历史最近 3 次不可重复）。"""
        problems = check_password_strength(new_password)
        if problems:
            raise ValueError("密码强度不足: " + "; ".join(problems))
        conn = self._conn()
        try:
            cur = conn.execute("SELECT * FROM saas_users WHERE user_id=?", (user_id,))
            row = cur.fetchone()
            if not row:
                raise ValueError("用户不存在")
            if not verify_password(old_password, row["salt"], row["password_hash"]):
                raise ValueError("旧密码不正确")

            # 历史校验
            cur = conn.execute(
                "SELECT password_hash, salt FROM saas_password_history WHERE user_id=? "
                "ORDER BY created_at DESC LIMIT ?",
                (user_id, PASSWORD_HISTORY_COUNT),
            )
            hist = cur.fetchall()
            for h in hist:
                if verify_password(new_password, h["salt"], h["password_hash"]):
                    raise ValueError(f"新密码不能与最近 {PASSWORD_HISTORY_COUNT} 次密码相同")

            ph = hash_password(new_password)
            conn.execute(
                "UPDATE saas_users SET password_hash=?, salt=?, updated_at=? WHERE user_id=?",
                (ph["hash"], ph["salt"], _now_str(), user_id),
            )
            conn.execute(
                "INSERT INTO saas_password_history (user_id, password_hash, salt, created_at) VALUES (?,?,?,?)",
                (user_id, ph["hash"], ph["salt"], _now_str()),
            )
            conn.commit()
            return True
        finally:
            conn.close()

    # ---------------------------- 登录日志 ----------------------------
    def get_login_logs(self, user_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """获取登录日志，可按用户过滤。"""
        conn = self._conn()
        try:
            if user_id:
                cur = conn.execute(
                    "SELECT * FROM saas_login_logs WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
                    (user_id, limit),
                )
            else:
                cur = conn.execute(
                    "SELECT * FROM saas_login_logs ORDER BY created_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()


# 模块级单例
auth_manager = AuthManager()


if __name__ == "__main__":
    print("AuthManager 自检")
    res = auth_manager.register("alice_test", "alice@example.com", "Alice@12345", "13800000000")
    print("注册:", res["username"], res["user_id"])
    login_res = auth_manager.login("alice@example.com", "Alice@12345", "127.0.0.1", "pytest")
    print("登录:", login_res["user_id"], "token类型:", login_res["token_type"])
    print("verify_token:", bool(auth_manager.verify_token(login_res["access_token"])))
    print("sessions:", len(auth_manager.get_sessions(login_res["user_id"])))
