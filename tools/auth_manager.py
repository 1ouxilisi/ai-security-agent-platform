"""
auth_manager安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import json
import time
import hmac
import hashlib
import base64
import secrets
import sqlite3
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from functools import wraps
from utils.logger import log


# ==================== 配置 ====================

AUTH_CONFIG = {
    "jwt_secret": os.environ.get("JWT_SECRET") or secrets.token_hex(32),
    "jwt_algorithm": "HS256",
    "access_token_expire_minutes": 60 * 24,  # 24小时
    "refresh_token_expire_days": 30,
    "password_min_length": 8,
    "password_require_upper": True,
    "password_require_lower": True,
    "password_require_digit": True,
    "password_require_special": False,
    "max_login_attempts": 5,
    "lockout_minutes": 30,
}


# ==================== JWT工具 ====================

def _base64url_encode(data: bytes) -> str:
    """编码相关数据。

        Args:
            data: 相关参数。

        Returns:
            操作结果。
    """
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def _base64url_decode(data: str) -> bytes:
    """解码相关数据。

        Args:
            data: 相关参数。

        Returns:
            操作结果。
    """
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

def create_jwt_token(payload: Dict[str, Any], expire_minutes: int = None) -> str:
    """创建JWT Token"""
    if expire_minutes is None:
        expire_minutes = AUTH_CONFIG["access_token_expire_minutes"]

    header = {"alg": AUTH_CONFIG["jwt_algorithm"], "typ": "JWT"}
    now = datetime.utcnow()
    payload_copy = payload.copy()
    payload_copy["iat"] = int(now.timestamp())
    payload_copy["exp"] = int((now + timedelta(minutes=expire_minutes)).timestamp())
    payload_copy["jti"] = secrets.token_hex(16)

    header_encoded = _base64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_encoded = _base64url_encode(json.dumps(payload_copy, separators=(',', ':')).encode())

    signature = hmac.new(
        AUTH_CONFIG["jwt_secret"].encode(),
        f"{header_encoded}.{payload_encoded}".encode(),
        hashlib.sha256
    ).digest()
    signature_encoded = _base64url_encode(signature)

    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """验证JWT Token"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header_encoded, payload_encoded, signature_encoded = parts

        # 验证签名
        expected_signature = hmac.new(
            AUTH_CONFIG["jwt_secret"].encode(),
            f"{header_encoded}.{payload_encoded}".encode(),
            hashlib.sha256
        ).digest()
        expected_signature_encoded = _base64url_encode(expected_signature)

        if not hmac.compare_digest(signature_encoded, expected_signature_encoded):
            return None

        # 解析payload
        payload = json.loads(_base64url_decode(payload_encoded))

        # 检查过期
        if "exp" in payload and payload["exp"] < int(datetime.utcnow().timestamp()):
            return None

        return payload
    except Exception as e:
        log.debug(f"JWT验证失败: {e}")
        return None


# ==================== 密码工具 ====================

def hash_password(password: str, salt: str = None) -> Tuple[str, str]:
    """哈希密码（PBKDF2-SHA256）"""
    if salt is None:
        salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # 迭代次数
    )
    return password_hash.hex(), salt

def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """验证密码"""
    calculated_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(calculated_hash, password_hash)

def validate_password_strength(password: str) -> Dict[str, Any]:
    """验证密码强度"""
    issues = []
    score = 0

    if len(password) >= AUTH_CONFIG["password_min_length"]:
        score += 25
    else:
        issues.append(f"密码长度至少{AUTH_CONFIG['password_min_length']}位")

    if any(c.isupper() for c in password):
        score += 25
    elif AUTH_CONFIG["password_require_upper"]:
        issues.append("需要包含大写字母")

    if any(c.islower() for c in password):
        score += 25
    elif AUTH_CONFIG["password_require_lower"]:
        issues.append("需要包含小写字母")

    if any(c.isdigit() for c in password):
        score += 25
    elif AUTH_CONFIG["password_require_digit"]:
        issues.append("需要包含数字")

    if any(not c.isalnum() for c in password):
        score += 10  # 额外加分

    return {
        "valid": len(issues) == 0,
        "score": min(100, score),
        "issues": issues,
        "strength": "strong" if score >= 80 else "medium" if score >= 50 else "weak",
    }


# ==================== 认证管理器 ====================

class AuthManager:
    """认证管理器"""

    def __init__(self, db_path: str = None):
        """初始化AuthManager实例。

        Args:
            self: 类实例。
        """
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data", "auth.db"
            )
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """初始化数据库"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 用户表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                phone TEXT,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                status TEXT DEFAULT 'active',
                avatar TEXT,
                bio TEXT,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                last_login_at TEXT,
                last_login_ip TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)

        # 会话表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT NOT NULL,
                refresh_token TEXT,
                ip_address TEXT,
                user_agent TEXT,
                expires_at TEXT,
                created_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)

        # API密钥表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT,
                api_key TEXT UNIQUE NOT NULL,
                api_key_hash TEXT NOT NULL,
                permissions TEXT,
                expires_at TEXT,
                last_used_at TEXT,
                usage_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                created_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)

        # 登录日志表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (
                log_id TEXT PRIMARY KEY,
                user_id TEXT,
                username TEXT,
                ip_address TEXT,
                user_agent TEXT,
                status TEXT,
                reason TEXT,
                created_at TEXT
            )
        """)

        # 索引
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_logs_user ON login_logs(user_id)")

        conn.commit()
        conn.close()

        # 创建默认管理员
        self._create_default_admin()

    def _create_default_admin(self):
        """创建默认管理员"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        if cursor.fetchone()[0] == 0:
            user_id = "u_" + secrets.token_hex(8)
            password_hash, salt = hash_password("Admin@2024")
            now = datetime.now().isoformat()
            cursor.execute("""
                INSERT INTO users (user_id, username, email, password_hash, salt, role, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, "admin", "admin@localhost", password_hash, salt, "admin", "active", now, now))
            log.info("默认管理员已创建: admin / Admin@2024")
        conn.commit()
        conn.close()

    # ==================== 用户注册 ====================

    def register(self, username: str, password: str, email: str = "",
                 phone: str = "", role: str = "user") -> Dict[str, Any]:
        """用户注册"""
        # 验证用户名
        if not username or len(username) < 3:
            return {"success": False, "error": "用户名至少3位"}

        # 验证密码强度
        password_check = validate_password_strength(password)
        if not password_check["valid"]:
            return {
                "success": False,
                "error": "密码强度不足",
                "issues": password_check["issues"],
            }

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 检查用户名是否存在
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return {"success": False, "error": "用户名已存在"}

        # 检查邮箱是否存在
        if email:
            cursor.execute("SELECT user_id FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                conn.close()
                return {"success": False, "error": "邮箱已注册"}

        # 创建用户
        user_id = "u_" + secrets.token_hex(8)
        password_hash, salt = hash_password(password)
        now = datetime.now().isoformat()

        cursor.execute("""
            INSERT INTO users (user_id, username, email, phone, password_hash, salt, role, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, email, phone, password_hash, salt, role, "active", now, now))

        conn.commit()
        conn.close()

        log.info(f"用户注册成功: {username} ({user_id})")

        return {
            "success": True,
            "user_id": user_id,
            "username": username,
            "role": role,
            "message": "注册成功",
        }

    # ==================== 用户登录 ====================

    def login(self, username: str, password: str, ip_address: str = "",
              user_agent: str = "") -> Dict[str, Any]:
        """用户登录"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 查找用户
        cursor.execute("""
            SELECT user_id, username, password_hash, salt, role, status, 
                   failed_login_attempts, locked_until
            FROM users WHERE username = ? OR email = ?
        """, (username, username))
        row = cursor.fetchone()

        if not row:
            self._log_login(None, username, ip_address, user_agent, "failed", "用户不存在")
            conn.close()
            return {"success": False, "error": "用户名或密码错误"}

        user_id, db_username, password_hash, salt, role, status, failed_attempts, locked_until = row

        # 检查账户锁定
        if locked_until and locked_until > datetime.now().isoformat():
            self._log_login(user_id, username, ip_address, user_agent, "failed", "账户已锁定")
            conn.close()
            return {
                "success": False,
                "error": f"账户已锁定，请在{locked_until}后重试",
            }

        # 检查账户状态
        if status != "active":
            self._log_login(user_id, username, ip_address, user_agent, "failed", f"账户状态: {status}")
            conn.close()
            return {"success": False, "error": f"账户状态异常: {status}"}

        # 验证密码
        if not verify_password(password, password_hash, salt):
            failed_attempts = (failed_attempts or 0) + 1
            if failed_attempts >= AUTH_CONFIG["max_login_attempts"]:
                locked_until = (datetime.now() + timedelta(minutes=AUTH_CONFIG["lockout_minutes"])).isoformat()
                cursor.execute("""
                    UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE user_id = ?
                """, (failed_attempts, locked_until, user_id))
            else:
                cursor.execute("""
                    UPDATE users SET failed_login_attempts = ? WHERE user_id = ?
                """, (failed_attempts, user_id))
            conn.commit()

            self._log_login(user_id, username, ip_address, user_agent, "failed", "密码错误")
            conn.close()
            return {
                "success": False,
                "error": "用户名或密码错误",
                "attempts_left": AUTH_CONFIG["max_login_attempts"] - failed_attempts,
            }

        # 登录成功，重置失败计数
        now = datetime.now().isoformat()
        cursor.execute("""
            UPDATE users SET failed_login_attempts = 0, locked_until = NULL,
                            last_login_at = ?, last_login_ip = ? WHERE user_id = ?
        """, (now, ip_address, user_id))

        # 生成Token
        access_token = create_jwt_token({
            "user_id": user_id,
            "username": db_username,
            "role": role,
            "type": "access",
        })
        refresh_token = create_jwt_token({
            "user_id": user_id,
            "username": db_username,
            "type": "refresh",
        }, expire_minutes=AUTH_CONFIG["refresh_token_expire_days"] * 24 * 60)

        # 保存会话
        session_id = "s_" + secrets.token_hex(16)
        expires_at = (datetime.now() + timedelta(minutes=AUTH_CONFIG["access_token_expire_minutes"])).isoformat()
        cursor.execute("""
            INSERT INTO sessions (session_id, user_id, token, refresh_token, ip_address, user_agent, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, user_id, access_token, refresh_token, ip_address, user_agent, expires_at, now))

        conn.commit()
        conn.close()

        self._log_login(user_id, db_username, ip_address, user_agent, "success", "登录成功")

        log.info(f"用户登录成功: {db_username} ({user_id})")

        return {
            "success": True,
            "user_id": user_id,
            "username": db_username,
            "role": role,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": AUTH_CONFIG["access_token_expire_minutes"] * 60,
        }

    def _log_login(self, user_id: str, username: str, ip_address: str,
                    user_agent: str, status: str, reason: str = ""):
        """记录登录日志"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            log_id = "log_" + secrets.token_hex(12)
            cursor.execute("""
                INSERT INTO login_logs (log_id, user_id, username, ip_address, user_agent, status, reason, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (log_id, user_id, username, ip_address, user_agent, status, reason, datetime.now().isoformat()))
            conn.commit()
            conn.close()
        except Exception as e:
            log.debug(f"记录登录日志失败: {e}")

    # ==================== Token验证 ====================

    def authenticate(self, token: str) -> Optional[Dict[str, Any]]:
        """验证Token并返回用户信息"""
        payload = verify_jwt_token(token)
        if not payload:
            return None

        if payload.get("type") != "access":
            return None

        user_id = payload.get("user_id")
        if not user_id:
            return None

        # 检查用户状态
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, username, role, status FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()

        if not row or row[3] != "active":
            return None

        return {
            "user_id": row[0],
            "username": row[1],
            "role": row[2],
            "authenticated": True,
        }

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """刷新Token"""
        payload = verify_jwt_token(refresh_token)
        if not payload or payload.get("type") != "refresh":
            return {"success": False, "error": "无效的刷新Token"}

        user_id = payload.get("user_id")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, username, role, status FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()

        if not row or row[3] != "active":
            return {"success": False, "error": "用户不存在或已禁用"}

        new_access_token = create_jwt_token({
            "user_id": row[0],
            "username": row[1],
            "role": row[2],
            "type": "access",
        })

        return {
            "success": True,
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": AUTH_CONFIG["access_token_expire_minutes"] * 60,
        }

    # ==================== 用户管理 ====================

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """获取用户信息"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, username, email, phone, role, status, avatar, bio,
                   last_login_at, last_login_ip, created_at
            FROM users WHERE user_id = ?
        """, (user_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return {
            "user_id": row[0],
            "username": row[1],
            "email": row[2],
            "phone": row[3],
            "role": row[4],
            "status": row[5],
            "avatar": row[6],
            "bio": row[7],
            "last_login_at": row[8],
            "last_login_ip": row[9],
            "created_at": row[10],
        }

    def change_password(self, user_id: str, old_password: str, new_password: str) -> Dict[str, Any]:
        """修改密码"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return {"success": False, "error": "用户不存在"}

        if not verify_password(old_password, row[0], row[1]):
            conn.close()
            return {"success": False, "error": "原密码错误"}

        password_check = validate_password_strength(new_password)
        if not password_check["valid"]:
            conn.close()
            return {"success": False, "error": "新密码强度不足", "issues": password_check["issues"]}

        new_hash, new_salt = hash_password(new_password)
        cursor.execute("""
            UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE user_id = ?
        """, (new_hash, new_salt, datetime.now().isoformat(), user_id))
        conn.commit()
        conn.close()

        return {"success": True, "message": "密码修改成功"}

    def list_users(self, limit: int = 50, offset: int = 0,
                   page: int = None, page_size: int = None) -> Dict[str, Any]:
        """列出用户。

        兼容两种调用方式：
            - list_users(limit=50, offset=0)    （api_server/auth_routes.py）
            - list_users(page=1, page_size=20)  （历史调用方）
        """
        if page is not None or page_size is not None:
            page = page or 1
            page_size = page_size or 20
            limit = page_size
            offset = (page - 1) * page_size
        else:
            page = (offset // limit) + 1 if limit else 1
            page_size = limit

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        total = cursor.fetchone()[0]
        cursor.execute("""
            SELECT user_id, username, email, role, status, last_login_at, created_at
            FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?
        """, (limit, offset))
        rows = cursor.fetchall()
        conn.close()

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "users": [
                {
                    "user_id": r[0], "username": r[1], "email": r[2],
                    "role": r[3], "status": r[4], "last_login_at": r[5], "created_at": r[6],
                }
                for r in rows
            ],
        }

    def list_api_keys(self, user_id: str) -> List[Dict[str, Any]]:
        """列出指定用户的所有 API 密钥（不返回明文 key，只返回元数据）。"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT key_id, user_id, name, permissions, expires_at, status,
                       usage_count, last_used_at, created_at
                FROM api_keys WHERE user_id = ? ORDER BY created_at DESC
            """, (user_id,))
            rows = cursor.fetchall()
            conn.close()
            result = []
            for r in rows:
                d = dict(r)
                try:
                    d["permissions"] = json.loads(d.get("permissions") or "[]")
                except Exception:
                    d["permissions"] = []
                result.append(d)
            return result
        except Exception as e:
            log.warning(f"list_api_keys 失败: {e}")
            return []

    def revoke_api_key(self, user_id: str = None, key_id: str = None) -> Dict[str, Any]:
        """吊销（软删除）指定 API 密钥。兼容 user_id+key_id 与单 key_id 两种调用。"""
        if not key_id:
            return {"success": False, "error": "key_id 不能为空"}
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            # 若传了 user_id 则限定范围，避免越权
            if user_id:
                cursor.execute(
                    "UPDATE api_keys SET status = 'revoked' WHERE key_id = ? AND user_id = ?",
                    (key_id, user_id),
                )
            else:
                cursor.execute(
                    "UPDATE api_keys SET status = 'revoked' WHERE key_id = ?",
                    (key_id,),
                )
            affected = cursor.rowcount
            conn.commit()
            conn.close()
            if affected == 0:
                return {"success": False, "error": "API 密钥不存在或已吊销"}
            return {"success": True, "key_id": key_id, "message": "API 密钥已吊销"}
        except Exception as e:
            log.warning(f"revoke_api_key 失败: {e}")
            return {"success": False, "error": f"吊销失败: {e}"}

    # ==================== API密钥管理 ====================

    def create_api_key(self, user_id: str, name: str = "",
                        permissions: List[str] = None,
                        expire_days: int = 365) -> Dict[str, Any]:
        """创建API密钥"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        key_id = "key_" + secrets.token_hex(8)
        api_key = "sk-" + secrets.token_hex(32)
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        expires_at = (datetime.now() + timedelta(days=expire_days)).isoformat()
        now = datetime.now().isoformat()

        cursor.execute("""
            INSERT INTO api_keys (key_id, user_id, name, api_key, api_key_hash, permissions, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (key_id, user_id, name or "default", api_key, api_key_hash,
              json.dumps(permissions or []), expires_at, now))
        conn.commit()
        conn.close()

        return {
            "success": True,
            "key_id": key_id,
            "api_key": api_key,
            "name": name,
            "expires_at": expires_at,
            "message": "API密钥创建成功，请妥善保存（只显示一次）",
        }

    def verify_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """验证API密钥"""
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT k.key_id, k.user_id, k.permissions, k.expires_at, k.status,
                   u.username, u.role
            FROM api_keys k JOIN users u ON k.user_id = u.user_id
            WHERE k.api_key_hash = ? AND k.status = 'active'
        """, (api_key_hash,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return None

        # 检查过期
        if row[3] and row[3] < datetime.now().isoformat():
            conn.close()
            return None

        # 更新使用计数
        cursor.execute("""
            UPDATE api_keys SET usage_count = usage_count + 1, last_used_at = ? WHERE key_id = ?
        """, (datetime.now().isoformat(), row[0]))
        conn.commit()
        conn.close()

        return {
            "key_id": row[0],
            "user_id": row[1],
            "permissions": json.loads(row[2]) if row[2] else [],
            "username": row[5],
            "role": row[6],
            "authenticated": True,
            "auth_type": "api_key",
        }

    # ==================== 统计 ====================

    def get_statistics(self) -> Dict[str, Any]:
        """获取认证系统统计"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active'")
        active_users = cursor.fetchone()[0]

        cursor.execute("SELECT role, COUNT(*) FROM users GROUP BY role")
        users_by_role = dict(cursor.fetchall())

        cursor.execute("SELECT COUNT(*) FROM api_keys WHERE status = 'active'")
        active_api_keys = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM login_logs WHERE status = 'success'")
        successful_logins = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM login_logs WHERE status = 'failed'")
        failed_logins = cursor.fetchone()[0]

        conn.close()

        return {
            "total_users": total_users,
            "active_users": active_users,
            "users_by_role": users_by_role,
            "active_api_keys": active_api_keys,
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
        }


# 全局认证管理器实例
auth_manager = AuthManager()


# ==================== 权限装饰器 ====================

def require_auth(f):
    """要求认证的装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # 从kwargs或args中获取token
        token = kwargs.pop("auth_token", None)
        if not token and args:
            token = args[0] if isinstance(args[0], str) else None

        if not token:
            return {"success": False, "error": "未提供认证Token", "code": 401}

        user = auth_manager.authenticate(token)
        if not user:
            return {"success": False, "error": "认证失败或Token已过期", "code": 401}

        kwargs["current_user"] = user
        return f(*args, **kwargs)
    return decorated

def require_role(roles: List[str]):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            pass
            current_user = kwargs.get("current_user")
            if not current_user:
                return {"success": False, "error": "未认证", "code": 401}

            if current_user.get("role") not in roles:
                return {"success": False, "error": "权限不足", "code": 403}

            return f(*args, **kwargs)
        return decorated
    return decorator
