"""
enterprise_manager安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import sqlite3
import os
import json
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from utils.logger import log


# ==================== 数据模型 ====================

@dataclass
class Tenant:
    """租户"""
    tenant_id: str
    name: str
    description: str = ""
    plan: str = "free"  # free/pro/enterprise
    max_users: int = 5
    max_scans_per_day: int = 100
    status: str = "active"  # active/suspended/expired
    created_at: str = ""
    expires_at: str = ""
    settings: Dict[str, Any] = field(default_factory=dict)


@dataclass
class User:
    """用户"""
    user_id: str
    tenant_id: str
    username: str
    email: str
    role: str = "user"  # admin/analyst/user/viewer
    status: str = "active"  # active/disabled/locked
    created_at: str = ""
    last_login: str = ""
    api_key: str = ""
    permissions: List[str] = field(default_factory=list)


@dataclass
class Role:
    """角色"""
    role_id: str
    name: str
    description: str = ""
    permissions: List[str] = field(default_factory=list)
    is_system: bool = False


@dataclass
class AuditLog:
    """审计日志"""
    log_id: str
    tenant_id: str
    user_id: str
    username: str
    action: str
    resource_type: str
    resource_id: str
    details: str = ""
    ip_address: str = ""
    user_agent: str = ""
    status: str = "success"  # success/failure/denied
    timestamp: str = ""


# ==================== 权限定义 ====================

# 系统内置角色
SYSTEM_ROLES = {
    "admin": Role(
        role_id="admin",
        name="管理员",
        description="拥有系统所有权限",
        permissions=[
            "scan:create", "scan:read", "scan:update", "scan:delete",
            "report:create", "report:read", "report:export",
            "user:manage", "role:manage", "tenant:manage",
            "settings:read", "settings:update",
            "audit:read", "audit:export",
            "api:manage", "tool:execute",
        ],
        is_system=True,
    ),
    "analyst": Role(
        role_id="analyst",
        name="安全分析师",
        description="可以执行扫描、查看报告、导出结果",
        permissions=[
            "scan:create", "scan:read", "scan:update",
            "report:create", "report:read", "report:export",
            "settings:read",
            "tool:execute",
        ],
        is_system=True,
    ),
    "user": Role(
        role_id="user",
        name="普通用户",
        description="可以查看扫描结果和报告",
        permissions=[
            "scan:read",
            "report:read",
            "settings:read",
        ],
        is_system=True,
    ),
    "viewer": Role(
        role_id="viewer",
        name="只读用户",
        description="只能查看公开报告",
        permissions=[
            "report:read",
        ],
        is_system=True,
    ),
}

# 套餐配置
PLAN_CONFIGS = {
    "free": {
        "name": "免费版",
        "max_users": 5,
        "max_scans_per_day": 100,
        "features": ["基础扫描", "基础报告", "社区支持"],
        "price": 0,
    },
    "pro": {
        "name": "专业版",
        "max_users": 20,
        "max_scans_per_day": 1000,
        "features": ["全功能扫描", "专业报告", "API访问", "优先支持", "自定义模板"],
        "price": 999,
    },
    "enterprise": {
        "name": "企业版",
        "max_users": 100,
        "max_scans_per_day": 10000,
        "features": ["全功能", "私有化部署", "SSO集成", "专属支持", "SLA保障", "合规报告", "定制开发"],
        "price": 9999,
    },
}


# ==================== 企业级管理器 ====================

class EnterpriseManager:
    """企业级功能管理器"""

    def __init__(self, db_path: str = None):
        """初始化EnterpriseManager实例。

        Args:
            self: 类实例。
        """
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data", "enterprise.db"
            )
        self.db_path = db_path
        self._init_db()
        self._init_system_data()

    def _init_db(self):
        """初始化数据库"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 租户表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                tenant_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                plan TEXT DEFAULT 'free',
                max_users INTEGER DEFAULT 5,
                max_scans_per_day INTEGER DEFAULT 100,
                status TEXT DEFAULT 'active',
                created_at TEXT,
                expires_at TEXT,
                settings TEXT
            )
        """)

        # 用户表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                username TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                status TEXT DEFAULT 'active',
                created_at TEXT,
                last_login TEXT,
                api_key TEXT,
                permissions TEXT,
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
            )
        """)

        # 角色表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                role_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                permissions TEXT,
                is_system INTEGER DEFAULT 0
            )
        """)

        # 审计日志表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                user_id TEXT,
                username TEXT,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                status TEXT DEFAULT 'success',
                timestamp TEXT
            )
        """)

        # API密钥表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                user_id TEXT,
                name TEXT,
                api_key TEXT NOT NULL UNIQUE,
                permissions TEXT,
                expires_at TEXT,
                last_used TEXT,
                created_at TEXT,
                status TEXT DEFAULT 'active'
            )
        """)

        # 索引
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_logs(tenant_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_tenant ON users(tenant_id)")

        conn.commit()
        conn.close()

    def _init_system_data(self):
        """初始化系统数据"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 检查是否已有默认租户
        cursor.execute("SELECT COUNT(*) FROM tenants WHERE tenant_id = 'default'")
        if cursor.fetchone()[0] == 0:
            # 创建默认租户
            now = datetime.now().isoformat()
            cursor.execute("""
                INSERT INTO tenants (tenant_id, name, description, plan, max_users, 
                                     max_scans_per_day, status, created_at, settings)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "default", "默认租户", "系统默认租户", "enterprise",
                100, 10000, "active", now, json.dumps({})
            ))

            # 创建默认管理员用户
            admin_api_key = "sk-" + secrets.token_hex(24)
            cursor.execute("""
                INSERT INTO users (user_id, tenant_id, username, email, role, status,
                                   created_at, api_key, permissions)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "admin", "default", "admin", "admin@localhost",
                "admin", "active", now, admin_api_key,
                json.dumps(SYSTEM_ROLES["admin"].permissions)
            ))

        # 初始化系统角色
        for role in SYSTEM_ROLES.values():
            cursor.execute("SELECT COUNT(*) FROM roles WHERE role_id = ?", (role.role_id,))
            if cursor.fetchone()[0] == 0:
                cursor.execute("""
                    INSERT INTO roles (role_id, name, description, permissions, is_system)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    role.role_id, role.name, role.description,
                    json.dumps(role.permissions), 1 if role.is_system else 0
                ))

        conn.commit()
        conn.close()

    # ==================== 租户管理 ====================

    def create_tenant(self, name: str, plan: str = "free",
                      description: str = "") -> Dict[str, Any]:
        """创建租户"""
        try:
            plan_config = PLAN_CONFIGS.get(plan, PLAN_CONFIGS["free"])
            tenant_id = "t_" + secrets.token_hex(8)
            now = datetime.now().isoformat()
            expires = (datetime.now() + timedelta(days=365)).isoformat()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO tenants (tenant_id, name, description, plan, max_users,
                                     max_scans_per_day, status, created_at, expires_at, settings)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tenant_id, name, description, plan,
                plan_config["max_users"], plan_config["max_scans_per_day"],
                "active", now, expires, json.dumps({})
            ))
            conn.commit()
            conn.close()

            self.log_audit("default", "admin", "tenant:create",
                          "tenant", tenant_id, f"创建租户: {name}")

            return {
                "success": True,
                "tenant_id": tenant_id,
                "name": name,
                "plan": plan,
                "message": f"租户创建成功，套餐: {plan_config['name']}",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """获取租户信息"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,))
            row = cursor.fetchone()
            conn.close()

            if row:
                return Tenant(
                    tenant_id=row[0], name=row[1], description=row[2] or "",
                    plan=row[3], max_users=row[4], max_scans_per_day=row[5],
                    status=row[6], created_at=row[7] or "", expires_at=row[8] or "",
                    settings=json.loads(row[9]) if row[9] else {}
                )
            return None
        except Exception as e:
            log.debug(f"获取租户失败: {e}")
            return None

    def list_tenants(self) -> List[Dict[str, Any]]:
        """列出所有租户"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT tenant_id, name, plan, status, created_at FROM tenants ORDER BY created_at DESC")
            rows = cursor.fetchall()
            conn.close()

            return [
                {
                    "tenant_id": r[0], "name": r[1], "plan": r[2],
                    "status": r[3], "created_at": r[4]
                }
                for r in rows
            ]
        except Exception as e:
            return []

    # ==================== 用户管理 ====================

    def create_user(self, tenant_id: str, username: str, email: str = "",
                    role: str = "user") -> Dict[str, Any]:
        """创建用户"""
        try:
            # 检查租户用户数限制
            tenant = self.get_tenant(tenant_id)
            if not tenant:
                return {"success": False, "error": "租户不存在"}

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE tenant_id = ?", (tenant_id,))
            user_count = cursor.fetchone()[0]

            if user_count >= tenant.max_users:
                conn.close()
                return {
                    "success": False,
                    "error": f"用户数已达上限 ({tenant.max_users})，请升级套餐",
                }

            user_id = "u_" + secrets.token_hex(8)
            api_key = "sk-" + secrets.token_hex(24)
            now = datetime.now().isoformat()
            role_perms = SYSTEM_ROLES.get(role, SYSTEM_ROLES["user"]).permissions

            cursor.execute("""
                INSERT INTO users (user_id, tenant_id, username, email, role, status,
                                   created_at, api_key, permissions)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, tenant_id, username, email, role, "active",
                now, api_key, json.dumps(role_perms)
            ))
            conn.commit()
            conn.close()

            self.log_audit(tenant_id, user_id, "user:create", "user", user_id,
                          f"创建用户: {username}, 角色: {role}")

            return {
                "success": True,
                "user_id": user_id,
                "username": username,
                "role": role,
                "api_key": api_key,
                "message": "用户创建成功",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def check_permission(self, user_id: str, permission: str) -> bool:
        """检查用户权限"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT permissions, role FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            conn.close()

            if not row:
                return False

            permissions = json.loads(row[0]) if row[0] else []
            role = row[1]

            # 管理员拥有所有权限
            if role == "admin":
                return True

            return permission in permissions
        except Exception as e:
            log.debug(f"权限检查失败: {e}")
            return False

    # ==================== 审计日志 ====================

    def log_audit(self, tenant_id: str, user_id: str, action: str,
                  resource_type: str = "", resource_id: str = "",
                  details: str = "", ip_address: str = "",
                  user_agent: str = "", status: str = "success"):
        """记录审计日志"""
        try:
            log_id = "log_" + secrets.token_hex(12)
            timestamp = datetime.now().isoformat()

            # 获取用户名
            username = ""
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT username FROM users WHERE user_id = ?", (user_id,))
                row = cursor.fetchone()
                conn.close()
                if row:
                    username = row[0]
            except Exception:
                pass

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (log_id, tenant_id, user_id, username, action,
                                        resource_type, resource_id, details, ip_address,
                                        user_agent, status, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log_id, tenant_id, user_id, username, action,
                resource_type, resource_id, details, ip_address,
                user_agent, status, timestamp
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            log.debug(f"审计日志记录失败: {e}")

    def query_audit_logs(self, tenant_id: str = "", user_id: str = "",
                          action: str = "", status: str = "",
                          start_time: str = "", end_time: str = "",
                          limit: int = 100) -> List[Dict[str, Any]]:
        """查询审计日志"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            query = "SELECT * FROM audit_logs WHERE 1=1"
            params = []

            if tenant_id:
                query += " AND tenant_id = ?"
                params.append(tenant_id)
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            if action:
                query += " AND action LIKE ?"
                params.append(f"%{action}%")
            if status:
                query += " AND status = ?"
                params.append(status)
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()

            return [
                {
                    "log_id": r[0], "tenant_id": r[1], "user_id": r[2],
                    "username": r[3], "action": r[4], "resource_type": r[5],
                    "resource_id": r[6], "details": r[7], "ip_address": r[8],
                    "user_agent": r[9], "status": r[10], "timestamp": r[11],
                }
                for r in rows
            ]
        except Exception as e:
            return []

    def get_audit_statistics(self, tenant_id: str = "",
                              days: int = 30) -> Dict[str, Any]:
        """获取审计统计"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            start_date = (datetime.now() - timedelta(days=days)).isoformat()

            # 总日志数
            query = "SELECT COUNT(*) FROM audit_logs WHERE timestamp >= ?"
            params = [start_date]
            if tenant_id:
                query += " AND tenant_id = ?"
                params.append(tenant_id)
            cursor.execute(query, params)
            total = cursor.fetchone()[0]

            # 按状态统计
            query = "SELECT status, COUNT(*) FROM audit_logs WHERE timestamp >= ?"
            params = [start_date]
            if tenant_id:
                query += " AND tenant_id = ?"
                params.append(tenant_id)
            query += " GROUP BY status"
            cursor.execute(query, params)
            by_status = dict(cursor.fetchall())

            # 按操作类型统计
            query = "SELECT action, COUNT(*) FROM audit_logs WHERE timestamp >= ?"
            params = [start_date]
            if tenant_id:
                query += " AND tenant_id = ?"
                params.append(tenant_id)
            query += " GROUP BY action ORDER BY COUNT(*) DESC LIMIT 10"
            cursor.execute(query, params)
            top_actions = [{"action": r[0], "count": r[1]} for r in cursor.fetchall()]

            # 活跃用户
            query = "SELECT username, COUNT(*) FROM audit_logs WHERE timestamp >= ?"
            params = [start_date]
            if tenant_id:
                query += " AND tenant_id = ?"
                params.append(tenant_id)
            query += " GROUP BY username ORDER BY COUNT(*) DESC LIMIT 10"
            cursor.execute(query, params)
            top_users = [{"username": r[0], "count": r[1]} for r in cursor.fetchall()]

            conn.close()

            return {
                "period_days": days,
                "total_logs": total,
                "by_status": by_status,
                "top_actions": top_actions,
                "top_users": top_users,
            }
        except Exception as e:
            return {"error": str(e)}

    # ==================== API密钥管理 ====================

    def create_api_key(self, tenant_id: str, user_id: str, name: str = "",
                       permissions: List[str] = None,
                       expires_days: int = 365) -> Dict[str, Any]:
        """创建API密钥"""
        try:
            key_id = "key_" + secrets.token_hex(8)
            api_key = "sk-" + secrets.token_hex(32)
            now = datetime.now().isoformat()
            expires = (datetime.now() + timedelta(days=expires_days)).isoformat()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO api_keys (key_id, tenant_id, user_id, name, api_key,
                                      permissions, expires_at, created_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                key_id, tenant_id, user_id, name, api_key,
                json.dumps(permissions or []), expires, now, "active"
            ))
            conn.commit()
            conn.close()

            self.log_audit(tenant_id, user_id, "api_key:create",
                          "api_key", key_id, f"创建API密钥: {name}")

            return {
                "success": True,
                "key_id": key_id,
                "api_key": api_key,
                "name": name,
                "expires_at": expires,
                "message": "API密钥创建成功，请妥善保存",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """验证API密钥"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT k.key_id, k.tenant_id, k.user_id, k.permissions, k.expires_at,
                       u.username, u.role, t.plan, t.status as tenant_status
                FROM api_keys k
                JOIN users u ON k.user_id = u.user_id
                JOIN tenants t ON k.tenant_id = t.tenant_id
                WHERE k.api_key = ? AND k.status = 'active'
            """, (api_key,))
            row = cursor.fetchone()
            conn.close()

            if not row:
                return None

            # 检查过期
            if row[4] and row[4] < datetime.now().isoformat():
                return None

            # 检查租户状态
            if row[8] != "active":
                return None

            return {
                "key_id": row[0],
                "tenant_id": row[1],
                "user_id": row[2],
                "permissions": json.loads(row[3]) if row[3] else [],
                "username": row[5],
                "role": row[6],
                "plan": row[7],
            }
        except Exception as e:
            log.debug(f"API密钥验证失败: {e}")
            return None

    # ==================== 统计 ====================

    def get_statistics(self) -> Dict[str, Any]:
        """获取企业级功能统计"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM tenants")
            tenant_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM audit_logs")
            audit_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM api_keys WHERE status = 'active'")
            api_key_count = cursor.fetchone()[0]

            cursor.execute("SELECT plan, COUNT(*) FROM tenants GROUP BY plan")
            tenants_by_plan = dict(cursor.fetchall())

            conn.close()

            return {
                "total_tenants": tenant_count,
                "total_users": user_count,
                "total_audit_logs": audit_count,
                "active_api_keys": api_key_count,
                "tenants_by_plan": tenants_by_plan,
                "available_plans": list(PLAN_CONFIGS.keys()),
                "available_roles": list(SYSTEM_ROLES.keys()),
            }
        except Exception as e:
            return {"error": str(e)}


# 全局企业级管理器实例
enterprise_manager = EnterpriseManager()
