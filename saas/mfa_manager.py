#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mfa_manager 模块 — 多因素认证管理器（SaaS 化基础模块 v10）

功能：
    - TOTP（RFC 6238）：30 秒窗口，6 位数字，HMAC-SHA1，base32 密钥 + otpauth:// 二维码 URL
    - HOTP（RFC 4226）：计数器-based，6 位数字
    - WebAuthn：安全密钥/平台认证器注册与验证流程框架（纯 Python 核心逻辑）
    - 短信验证码（6 位，5 分钟有效，预留短信 API）
    - 邮件验证码（6 位，15 分钟有效，预留邮件 API）
    - MFA 策略（强制/可选/按角色/IP 白名单）
    - 备份码（10 个一次性）与受信任设备管理

注意：本模块仅用于授权的安全产品。
"""

import os
import hmac
import json
import time
import base64
import hashlib
import struct
import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple

try:
    from loguru import logger
except ImportError:  # pragma: no cover
    import logging
    logger = logging.getLogger(__name__)

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(_BASE_DIR, "data", "ai_hacking_agent.db")

TOTP_PERIOD = 30          # TOTP 时间窗口（秒）
TOTP_DIGITS = 6           # TOTP 位数
TOTP_WINDOW = 1           # 时间偏差窗口（前后各 1 步）
HOTP_DIGITS = 6           # HOTP 位数
SMS_CODE_TTL = 300        # 短信验证码有效期（秒）
EMAIL_CODE_TTL = 900      # 邮件验证码有效期（秒）
BACKUP_CODE_COUNT = 10    # 备份码数量


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _get_conn(db_path: str = DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


# ---------------------------------------------------------------------------
# 纯 Python TOTP / HOTP 工具
# ---------------------------------------------------------------------------
def _base32_encode(raw: bytes) -> str:
    """base32 编码（不带填充）。"""
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _base32_decode(s: str) -> bytes:
    s = s.upper().replace(" ", "").replace("-", "")
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s)


def _hotp_raw(key: bytes, counter: int, digits: int) -> str:
    """RFC 4226 HOTP 计算。"""
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def generate_totp_secret() -> str:
    """生成 base32 编码的 TOTP 密钥。"""
    return _base32_encode(secrets.token_bytes(20))


def totp_now(secret_b32: str, for_time: Optional[int] = None) -> str:
    """计算当前时间对应的 TOTP。"""
    key = _base32_decode(secret_b32)
    t = int(for_time if for_time is not None else time.time())
    counter = t // TOTP_PERIOD
    return _hotp_raw(key, counter, TOTP_DIGITS)


def verify_totp_code(secret_b32: str, code: str, for_time: Optional[int] = None) -> bool:
    """校验 TOTP，允许 ±TOTP_WINDOW 步偏差。"""
    if not code or not code.isdigit():
        return False
    key = _base32_decode(secret_b32)
    t = int(for_time if for_time is not None else time.time())
    counter = t // TOTP_PERIOD
    for offset in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        if _hotp_raw(key, counter + offset, TOTP_DIGITS) == code:
            return True
    return False


def hotp_next(secret_b32: str, counter: int) -> str:
    """计算指定计数器的 HOTP。"""
    return _hotp_raw(_base32_decode(secret_b32), counter, HOTP_DIGITS)


def provisioning_uri(secret_b32: str, account_name: str, issuer: str = "AIHackingAgent") -> str:
    """生成 otpauth:// 二维码 URL。"""
    from urllib.parse import quote
    return (
        f"otpauth://totp/{quote(issuer)}:{quote(account_name)}"
        f"?secret={secret_b32}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )


# ---------------------------------------------------------------------------
# MFA 管理器
# ---------------------------------------------------------------------------
class MFAManager:
    """多因素认证管理器（单例）。"""

    def __init__(self, db_path: str = DB_PATH):
        """初始化 MFA 管理器并建表。"""
        self.db_path = db_path
        # 预留的短信/邮件发送回调（由外部注入）
        self.sms_sender = None       # callable(phone, code) -> bool
        self.email_sender = None     # callable(email, code) -> bool
        # WebAuthn 挑战暂存（进程内）
        self._webauthn_challenges: Dict[str, str] = {}
        # 验证码暂存（进程内，生产应放 Redis）
        self._sms_codes: Dict[str, Tuple[str, float]] = {}
        self._email_codes: Dict[str, Tuple[str, float]] = {}
        # MFA 策略（按租户）
        self._mfa_policies: Dict[str, Dict[str, Any]] = {
            "default": {
                "mode": "optional",            # mandatory / optional / by_role / by_ip
                "methods_priority": ["totp", "sms", "email", "webauthn", "hotp"],
                "roles_required": ["admin", "owner"],
                "ip_whitelist": [],
            }
        }
        self._init_db()
        logger.info("MFAManager 初始化完成")

    def _init_db(self) -> None:
        conn = _get_conn(self.db_path)
        try:
            c = conn.cursor()
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_mfa (
                    user_id TEXT PRIMARY KEY,
                    totp_secret TEXT DEFAULT '',
                    hotp_secret TEXT DEFAULT '',
                    hotp_counter INTEGER DEFAULT 0,
                    enabled_methods TEXT DEFAULT '[]',
                    enabled INTEGER DEFAULT 0,
                    webauthn_credentials TEXT DEFAULT '[]',
                    created_at TEXT,
                    updated_at TEXT
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_mfa_backup_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    code_hash TEXT,
                    used INTEGER DEFAULT 0,
                    created_at TEXT,
                    used_at TEXT DEFAULT ''
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_trusted_devices (
                    device_id TEXT PRIMARY KEY,
                    user_id TEXT,
                    device_name TEXT DEFAULT '',
                    user_agent TEXT DEFAULT '',
                    expires_at TEXT,
                    created_at TEXT,
                    revoked INTEGER DEFAULT 0
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _conn(self) -> sqlite3.Connection:
        return _get_conn(self.db_path)

    def _get_or_create_mfa_row(self, conn: sqlite3.Connection, user_id: str) -> sqlite3.Row:
        cur = conn.execute("SELECT * FROM saas_mfa WHERE user_id=?", (user_id,))
        row = cur.fetchone()
        if not row:
            conn.execute(
                "INSERT INTO saas_mfa (user_id, created_at, updated_at) VALUES (?,?,?)",
                (user_id, _now_str(), _now_str()),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM saas_mfa WHERE user_id=?", (user_id,)).fetchone()
        return row

    @staticmethod
    def _hash_code(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    # ---------------------------- TOTP ----------------------------
    def enable_totp(self, user_id: str) -> Dict[str, Any]:
        """启用 TOTP，返回密钥与 otpauth:// 二维码 URL（待验证后生效）。"""
        secret = generate_totp_secret()
        conn = self._conn()
        try:
            self._get_or_create_mfa_row(conn, user_id)
            conn.execute(
                "UPDATE saas_mfa SET totp_secret=?, updated_at=? WHERE user_id=?",
                (secret, _now_str(), user_id),
            )
            conn.commit()
        finally:
            conn.close()
        uri = provisioning_uri(secret, user_id, "AIHackingAgent")
        return {"secret": secret, "otpauth_url": uri, "message": "请用验证器扫描并输入验证码完成绑定"}

    def verify_totp(self, user_id: str, code: str) -> bool:
        """验证 TOTP 并正式启用 MFA。"""
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM saas_mfa WHERE user_id=?", (user_id,)).fetchone()
            if not row or not row["totp_secret"]:
                return False
            if not verify_totp_code(row["totp_secret"], code):
                return False
            methods = set(json.loads(row["enabled_methods"] or "[]"))
            methods.add("totp")
            conn.execute(
                "UPDATE saas_mfa SET enabled=1, enabled_methods=?, updated_at=? WHERE user_id=?",
                (json.dumps(list(methods)), _now_str(), user_id),
            )
            conn.commit()
            return True
        finally:
            conn.close()

    # ---------------------------- 备份码 ----------------------------
    def generate_backup_codes(self, user_id: str, count: int = BACKUP_CODE_COUNT) -> List[str]:
        """生成一次性备份码（明文仅本次返回，数据库存哈希）。"""
        codes = [f"{secrets.randbelow(100000000):08d}" for _ in range(count)]
        conn = self._conn()
        try:
            for code in codes:
                conn.execute(
                    "INSERT INTO saas_mfa_backup_codes (user_id, code_hash, created_at) VALUES (?,?,?)",
                    (user_id, self._hash_code(code), _now_str()),
                )
            conn.commit()
        finally:
            conn.close()
        return codes

    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """校验并消费一个备份码。"""
        conn = self._conn()
        try:
            target = self._hash_code(code.strip())
            cur = conn.execute(
                "SELECT id FROM saas_mfa_backup_codes WHERE user_id=? AND code_hash=? AND used=0",
                (user_id, target),
            )
            row = cur.fetchone()
            if not row:
                return False
            conn.execute(
                "UPDATE saas_mfa_backup_codes SET used=1, used_at=? WHERE id=?",
                (_now_str(), row["id"]),
            )
            conn.commit()
            return True
        finally:
            conn.close()

    # ---------------------------- HOTP ----------------------------
    def enable_hotp(self, user_id: str) -> Dict[str, Any]:
        """启用 HOTP，返回密钥（计数器初始化为 0）。"""
        secret = generate_totp_secret()
        conn = self._conn()
        try:
            self._get_or_create_mfa_row(conn, user_id)
            conn.execute(
                "UPDATE saas_mfa SET hotp_secret=?, hotp_counter=0, updated_at=? WHERE user_id=?",
                (secret, _now_str(), user_id),
            )
            conn.commit()
        finally:
            conn.close()
        return {"secret": secret, "algorithm": "HOTP", "digits": HOTP_DIGITS}

    def verify_hotp(self, user_id: str, code: str) -> bool:
        """验证 HOTP（允许当前及下一个计数器，防止重放）。"""
        if not code or not code.isdigit():
            return False
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM saas_mfa WHERE user_id=?", (user_id,)).fetchone()
            if not row or not row["hotp_secret"]:
                return False
            counter = row["hotp_counter"]
            for delta in (0, 1):
                if hotp_next(row["hotp_secret"], counter + delta) == code:
                    methods = set(json.loads(row["enabled_methods"] or "[]"))
                    methods.add("hotp")
                    conn.execute(
                        "UPDATE saas_mfa SET hotp_counter=?, enabled=1, enabled_methods=?, updated_at=? WHERE user_id=?",
                        (counter + delta + 1, json.dumps(list(methods)), _now_str(), user_id),
                    )
                    conn.commit()
                    return True
            return False
        finally:
            conn.close()

    # ---------------------------- WebAuthn（流程框架） ----------------------------
    def webauthn_register_begin(self, user_id: str) -> Dict[str, Any]:
        """WebAuthn 注册第一步：生成 challenge。"""
        challenge = secrets.token_urlsafe(32)
        self._webauthn_challenges[f"reg:{user_id}"] = challenge
        return {
            "challenge": challenge,
            "rp": {"name": "AI Hacking Agent", "id": "localhost"},
            "user": {"id": user_id, "name": user_id},
            "pub_key_cred_params": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
            "timeout": 60000,
            "authenticator_selection": {"authenticator_attachment": "cross-platform",
                                         "user_verification": "preferred"},
        }

    def webauthn_register_complete(self, user_id: str, credential: Dict[str, Any]) -> bool:
        """WebAuthn 注册第二步：校验 assertion 结构并存入凭据（框架）。"""
        expected = self._webauthn_challenges.get(f"reg:{user_id}")
        if not expected:
            return False
        cred_id = credential.get("id") or credential.get("rawId")
        if not cred_id:
            return False
        conn = self._conn()
        try:
            row = self._get_or_create_mfa_row(conn, user_id)
            creds = json.loads(row["webauthn_credentials"] or "[]")
            creds.append({
                "id": cred_id,
                "public_key": credential.get("response", {}).get("publicKey", ""),
                "sign_count": 0,
                "created_at": _now_str(),
            })
            methods = set(json.loads(row["enabled_methods"] or "[]"))
            methods.add("webauthn")
            conn.execute(
                "UPDATE saas_mfa SET webauthn_credentials=?, enabled=1, enabled_methods=?, updated_at=? WHERE user_id=?",
                (json.dumps(creds), json.dumps(list(methods)), _now_str(), user_id),
            )
            conn.commit()
            self._webauthn_challenges.pop(f"reg:{user_id}", None)
            return True
        finally:
            conn.close()

    def webauthn_verify_begin(self, user_id: str) -> Dict[str, Any]:
        """WebAuthn 验证第一步：生成登录 challenge。"""
        challenge = secrets.token_urlsafe(32)
        self._webauthn_challenges[f"auth:{user_id}"] = challenge
        return {"challenge": challenge, "timeout": 60000,
                "rp_id": "localhost", "user_verification": "preferred"}

    def webauthn_verify_complete(self, user_id: str, assertion: Dict[str, Any]) -> bool:
        """WebAuthn 验证第二步：校验 assertion（框架，校验凭据存在性）。"""
        expected = self._webauthn_challenges.get(f"auth:{user_id}")
        if not expected:
            return False
        cred_id = assertion.get("id") or assertion.get("rawId")
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM saas_mfa WHERE user_id=?", (user_id,)).fetchone()
            if not row:
                return False
            creds = json.loads(row["webauthn_credentials"] or "[]")
            ok = any(c.get("id") == cred_id for c in creds)
            if ok:
                self._webauthn_challenges.pop(f"auth:{user_id}", None)
            return ok
        finally:
            conn.close()

    # ---------------------------- 短信 / 邮件验证码 ----------------------------
    def send_sms_code(self, phone: str) -> Dict[str, Any]:
        """发送短信验证码（6 位，5 分钟有效），预留短信服务接口。"""
        code = f"{secrets.randbelow(1000000):06d}"
        self._sms_codes[phone] = (code, time.time() + SMS_CODE_TTL)
        if self.sms_sender:
            try:
                self.sms_sender(phone, code)
            except Exception as e:  # pragma: no cover
                logger.error(f"短信发送失败: {e}")
        return {"success": True, "phone": phone, "expires_in": SMS_CODE_TTL,
                "dev_code": code}  # 无短信服务时返回 dev_code 便于联调

    def verify_sms_code(self, phone: str, code: str) -> bool:
        """校验短信验证码。"""
        rec = self._sms_codes.get(phone)
        if not rec:
            return False
        stored, expire = rec
        if time.time() > expire:
            self._sms_codes.pop(phone, None)
            return False
        if hmac.compare_digest(stored, code):
            self._sms_codes.pop(phone, None)
            return True
        return False

    def send_email_code(self, email: str) -> Dict[str, Any]:
        """发送邮件验证码（6 位，15 分钟有效），预留邮件服务接口。"""
        code = f"{secrets.randbelow(1000000):06d}"
        self._email_codes[email] = (code, time.time() + EMAIL_CODE_TTL)
        if self.email_sender:
            try:
                self.email_sender(email, code)
            except Exception as e:  # pragma: no cover
                logger.error(f"邮件发送失败: {e}")
        return {"success": True, "email": email, "expires_in": EMAIL_CODE_TTL,
                "dev_code": code}

    def verify_email_code(self, email: str, code: str) -> bool:
        """校验邮件验证码。"""
        rec = self._email_codes.get(email)
        if not rec:
            return False
        stored, expire = rec
        if time.time() > expire:
            self._email_codes.pop(email, None)
            return False
        if hmac.compare_digest(stored, code):
            self._email_codes.pop(email, None)
            return True
        return False

    # ---------------------------- MFA 状态与管理 ----------------------------
    def get_mfa_status(self, user_id: str) -> Dict[str, Any]:
        """获取用户 MFA 配置状态。"""
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM saas_mfa WHERE user_id=?", (user_id,)).fetchone()
            if not row:
                return {"user_id": user_id, "enabled": False, "methods": []}
            return {
                "user_id": user_id,
                "enabled": bool(row["enabled"]),
                "methods": json.loads(row["enabled_methods"] or "[]"),
                "webauthn_count": len(json.loads(row["webauthn_credentials"] or "[]")),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        finally:
            conn.close()

    def disable_mfa(self, user_id: str) -> bool:
        """禁用 MFA（保留密钥但关闭）。"""
        conn = self._conn()
        try:
            cur = conn.execute(
                "UPDATE saas_mfa SET enabled=0, enabled_methods='[]', updated_at=? WHERE user_id=?",
                (_now_str(), user_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def reset_mfa(self, user_id: str) -> bool:
        """重置 MFA：清除所有密钥与备份码。"""
        conn = self._conn()
        try:
            conn.execute(
                "UPDATE saas_mfa SET totp_secret='', hotp_secret='', hotp_counter=0, "
                "enabled=0, enabled_methods='[]', webauthn_credentials='[]', updated_at=? WHERE user_id=?",
                (_now_str(), user_id),
            )
            conn.execute("DELETE FROM saas_mfa_backup_codes WHERE user_id=?", (user_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    # ---------------------------- 受信任设备 ----------------------------
    def get_trusted_devices(self, user_id: str) -> List[Dict[str, Any]]:
        """获取受信任设备列表。"""
        conn = self._conn()
        try:
            cur = conn.execute(
                "SELECT * FROM saas_trusted_devices WHERE user_id=? AND revoked=0",
                (user_id,),
            )
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def add_trusted_device(self, user_id: str, device_info: Dict[str, Any]) -> str:
        """添加受信任设备，返回 device_id。"""
        device_id = device_info.get("device_id") or f"dev_{secrets.token_hex(10)}"
        ttl_days = int(device_info.get("ttl_days", 30))
        now = datetime.now()
        conn = self._conn()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO saas_trusted_devices "
                "(device_id, user_id, device_name, user_agent, expires_at, created_at, revoked) "
                "VALUES (?,?,?,?,?,?,0)",
                (device_id, user_id, device_info.get("device_name", ""),
                 device_info.get("user_agent", ""),
                 (now + timedelta(days=ttl_days)).strftime("%Y-%m-%d %H:%M:%S"),
                 now.strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()
        finally:
            conn.close()
        return device_id

    def revoke_trusted_device(self, user_id: str, device_id: str) -> bool:
        """撤销受信任设备。"""
        conn = self._conn()
        try:
            cur = conn.execute(
                "UPDATE saas_trusted_devices SET revoked=1 WHERE user_id=? AND device_id=?",
                (user_id, device_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ---------------------------- MFA 策略 ----------------------------
    def set_mfa_policy(self, tenant_id: str, policy: Dict[str, Any]) -> Dict[str, Any]:
        """配置租户 MFA 策略。"""
        merged = dict(self._mfa_policies.get(tenant_id, self._mfa_policies["default"]))
        merged.update(policy)
        self._mfa_policies[tenant_id] = merged
        return merged

    def get_mfa_policy(self, tenant_id: str = "default") -> Dict[str, Any]:
        """获取租户 MFA 策略。"""
        return self._mfa_policies.get(tenant_id, self._mfa_policies["default"])


# 模块级单例
mfa_manager = MFAManager()


if __name__ == "__main__":
    print("MFAManager 自检")
    info = mfa_manager.enable_totp("user_demo")
    print("TOTP secret:", info["secret"])
    print("otpauth:", info["otpauth_url"][:60], "...")
    code = totp_now(info["secret"])
    print("verify_totp:", mfa_manager.verify_totp("user_demo", code))
    codes = mfa_manager.generate_backup_codes("user_demo", 3)
    print("backup_codes:", len(codes), "verify:", mfa_manager.verify_backup_code("user_demo", codes[0]))
    sc = mfa_manager.send_sms_code("13800000000")
    print("sms:", sc["dev_code"], "verify:", mfa_manager.verify_sms_code("13800000000", sc["dev_code"]))
