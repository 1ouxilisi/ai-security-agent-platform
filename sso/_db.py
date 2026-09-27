# -*- coding: utf-8 -*-
"""
_db.py — SSO/LDAP 模块共享数据库助手。

职责：
    - 统一指向 data/ai_hacking_agent.db
    - 提供线程安全（每次操作独立连接）的 SQLite 连接
    - 提供敏感信息 base64 编解码工具（不明文落库）
    - 统一初始化本模块所需的全部 sso_* 表

设计说明：
    本模块不依赖任何第三方库，仅使用标准库 sqlite3 / base64 / json。
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# 数据库路径
# --------------------------------------------------------------------------- #
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
DB_PATH = os.path.join(DATA_DIR, "ai_hacking_agent.db")

os.makedirs(DATA_DIR, exist_ok=True)

# 建表锁，避免并发初始化
_INIT_LOCK = threading.Lock()
_INITIALIZED = False


# --------------------------------------------------------------------------- #
# 敏感信息编解码（base64，仅做混淆，避免明文肉眼可见）
# --------------------------------------------------------------------------- #
def encode_secret(plain: Optional[str]) -> str:
    """将敏感字符串 base64 编码后存储。空值返回空串。"""
    if not plain:
        return ""
    try:
        return base64.b64encode(plain.encode("utf-8")).decode("ascii")
    except Exception:
        return ""


def decode_secret(encoded: Optional[str]) -> str:
    """将 base64 编码的敏感字符串解码还原。失败返回空串。"""
    if not encoded:
        return ""
    try:
        return base64.b64decode(encoded.encode("ascii")).decode("utf-8")
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# JSON 辅助
# --------------------------------------------------------------------------- #
def dumps_json(obj: Any) -> str:
    """安全序列化 JSON，失败返回空对象字符串。"""
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return "{}"


def loads_json(raw: Optional[str], default: Any = None) -> Any:
    """安全反序列化 JSON，失败返回 default。"""
    if default is None:
        default = {}
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


# --------------------------------------------------------------------------- #
# 连接管理
# --------------------------------------------------------------------------- #
def get_connection() -> sqlite3.Connection:
    """获取一个新的 SQLite 连接（调用方负责关闭）。"""
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# --------------------------------------------------------------------------- #
# 表结构初始化
# --------------------------------------------------------------------------- #
def init_tables() -> None:
    """创建 SSO 模块所需全部表（幂等）。"""
    global _INITIALIZED
    with _INIT_LOCK:
        if _INITIALIZED:
            return
        conn = get_connection()
        try:
            cur = conn.cursor()
            # 统一提供商注册表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sso_providers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    provider_type TEXT NOT NULL,
                    ref_config_id TEXT,
                    enabled INTEGER DEFAULT 1,
                    priority INTEGER DEFAULT 100,
                    tenant_id TEXT,
                    description TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            # SAML 配置
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sso_saml_configs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    entity_id TEXT,
                    sso_url TEXT,
                    slo_url TEXT,
                    certificate TEXT,
                    attribute_mapping TEXT,
                    sp_entity_id TEXT,
                    acs_url TEXT,
                    sls_url TEXT,
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            # OAuth2/OIDC 配置
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sso_oauth2_configs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    provider TEXT DEFAULT 'custom',
                    client_id TEXT,
                    client_secret TEXT,
                    auth_url TEXT,
                    token_url TEXT,
                    userinfo_url TEXT,
                    scopes TEXT,
                    redirect_uri TEXT,
                    attribute_mapping TEXT,
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            # LDAP 配置
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sso_ldap_configs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    host TEXT,
                    port INTEGER DEFAULT 389,
                    base_dn TEXT,
                    bind_dn TEXT,
                    bind_password TEXT,
                    use_ssl INTEGER DEFAULT 0,
                    use_tls INTEGER DEFAULT 0,
                    timeout INTEGER DEFAULT 10,
                    user_search_base TEXT,
                    user_filter TEXT,
                    attribute_mapping TEXT,
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            # SSO 会话
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sso_sessions (
                    id TEXT PRIMARY KEY,
                    session_id TEXT UNIQUE NOT NULL,
                    user_id TEXT,
                    username TEXT,
                    provider_id TEXT,
                    provider_type TEXT,
                    ip TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TEXT,
                    expires_at TEXT,
                    last_active TEXT
                )
            """)
            # SSO 策略
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sso_policies (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT,
                    policy_type TEXT DEFAULT 'optional',
                    priority INTEGER DEFAULT 100,
                    default_provider_id TEXT,
                    ip_ranges TEXT,
                    config TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            # SSO 登录日志
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sso_login_logs (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    username TEXT,
                    provider_id TEXT,
                    provider_type TEXT,
                    result TEXT,
                    failure_reason TEXT,
                    ip TEXT,
                    user_agent TEXT,
                    created_at TEXT
                )
            """)
            # 索引
            cur.execute("CREATE INDEX IF NOT EXISTS idx_providers_type ON sso_providers(provider_type)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_uid ON sso_sessions(user_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_status ON sso_sessions(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_time ON sso_login_logs(created_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_result ON sso_login_logs(result)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_policies_tenant ON sso_policies(tenant_id)")
            conn.commit()
            _INITIALIZED = True
        except Exception:
            # 建表失败不致命，调用层自行降级
            raise
        finally:
            conn.close()


def query_all(sql: str, params: Optional[tuple] = None) -> List[Dict[str, Any]]:
    """查询多行，返回字典列表。"""
    conn = get_connection()
    try:
        cur = conn.execute(sql, params or ())
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def query_one(sql: str, params: Optional[tuple] = None) -> Optional[Dict[str, Any]]:
    """查询单行，返回字典或 None。"""
    rows = query_all(sql, params)
    return rows[0] if rows else None


def execute(sql: str, params: Optional[tuple] = None) -> int:
    """执行写操作，返回 lastrowid（受影响行数）。"""
    conn = get_connection()
    try:
        cur = conn.execute(sql, params or ())
        conn.commit()
        return cur.lastrowid if cur.lastrowid else 0
    finally:
        conn.close()


__all__ = [
    "DB_PATH", "get_connection", "init_tables",
    "encode_secret", "decode_secret",
    "dumps_json", "loads_json",
    "query_all", "query_one", "execute",
]
