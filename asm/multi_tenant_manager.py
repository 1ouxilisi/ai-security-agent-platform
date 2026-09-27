"""
多租户SaaS化模块
- 组织管理（Organization）
- 团队管理（Team）
- 项目管理（Project）
- 用户角色权限（组织管理员/团队管理员/项目成员/查看者）
- 数据隔离（每个组织/团队/项目的数据完全隔离）
- 订阅计费（基础版/专业版/企业版，不同配额）
- 审计日志（记录所有操作）
"""

import json
import os
import time
import sqlite3
import hashlib
import secrets
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta


class UserRole(Enum):
    """用户角色"""
    ORG_ADMIN = "org_admin"  # 组织管理员
    TEAM_ADMIN = "team_admin"  # 团队管理员
    PROJECT_MEMBER = "project_member"  # 项目成员
    VIEWER = "viewer"  # 查看者（只读）


class SubscriptionPlan(Enum):
    """订阅计划"""
    FREE = "free"  # 免费版
    BASIC = "basic"  # 基础版
    PRO = "pro"  # 专业版
    ENTERPRISE = "enterprise"  # 企业版


# 订阅计划配额
PLAN_QUOTAS = {
    "free": {
        "name": "免费版",
        "max_users": 1,
        "max_teams": 1,
        "max_projects": 1,
        "max_scans_per_month": 10,
        "max_assets": 10,
        "max_report_export": 3,
        "api_access": False,
        "priority_support": False,
        "data_retention_days": 30,
        "price_monthly": 0,
        "price_yearly": 0,
    },
    "basic": {
        "name": "基础版",
        "max_users": 5,
        "max_teams": 3,
        "max_projects": 5,
        "max_scans_per_month": 100,
        "max_assets": 100,
        "max_report_export": 50,
        "api_access": True,
        "priority_support": False,
        "data_retention_days": 90,
        "price_monthly": 299,
        "price_yearly": 2990,
    },
    "pro": {
        "name": "专业版",
        "max_users": 20,
        "max_teams": 10,
        "max_projects": 20,
        "max_scans_per_month": 1000,
        "max_assets": 1000,
        "max_report_export": -1,  # 无限
        "api_access": True,
        "priority_support": True,
        "data_retention_days": 365,
        "price_monthly": 999,
        "price_yearly": 9990,
    },
    "enterprise": {
        "name": "企业版",
        "max_users": -1,  # 无限
        "max_teams": -1,
        "max_projects": -1,
        "max_scans_per_month": -1,
        "max_assets": -1,
        "max_report_export": -1,
        "api_access": True,
        "priority_support": True,
        "data_retention_days": -1,  # 永久
        "price_monthly": -1,  # 定制
        "price_yearly": -1,
        "custom_features": ["SSO单点登录", "专属部署", "SLA保障", "定制开发"],
    },
}


@dataclass
class Organization:
    """组织"""
    org_id: str
    name: str
    plan: str = "free"
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    status: str = "active"
    settings: Dict = field(default_factory=dict)


@dataclass
class Team:
    """团队"""
    team_id: str
    org_id: str
    name: str
    created_at: float = field(default_factory=time.time)
    settings: Dict = field(default_factory=dict)


@dataclass
class Project:
    """项目"""
    project_id: str
    org_id: str
    team_id: str
    name: str
    description: str = ""
    created_at: float = field(default_factory=time.time)
    status: str = "active"
    settings: Dict = field(default_factory=dict)


@dataclass
class User:
    """用户"""
    user_id: str
    email: str
    username: str
    password_hash: str
    org_id: Optional[str] = None
    role: str = "viewer"
    created_at: float = field(default_factory=time.time)
    last_login: Optional[float] = None
    status: str = "active"
    api_key: Optional[str] = None


class MultiTenantManager:
    """多租户管理器"""

    def __init__(self, db_path: str = ""):
        if not db_path:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(project_root, "data", "saas.db")

        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_database()

    def _init_database(self):
        """初始化数据库"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 组织表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id TEXT UNIQUE,
                name TEXT,
                plan TEXT DEFAULT 'free',
                created_at REAL,
                expires_at REAL,
                status TEXT DEFAULT 'active',
                settings TEXT DEFAULT '{}'
            )
        """)

        # 团队表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS teams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id TEXT UNIQUE,
                org_id TEXT,
                name TEXT,
                created_at REAL,
                settings TEXT DEFAULT '{}',
                FOREIGN KEY (org_id) REFERENCES organizations (org_id)
            )
        """)

        # 项目表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id TEXT UNIQUE,
                org_id TEXT,
                team_id TEXT,
                name TEXT,
                description TEXT DEFAULT '',
                created_at REAL,
                status TEXT DEFAULT 'active',
                settings TEXT DEFAULT '{}',
                FOREIGN KEY (org_id) REFERENCES organizations (org_id),
                FOREIGN KEY (team_id) REFERENCES teams (team_id)
            )
        """)

        # 用户表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE,
                email TEXT UNIQUE,
                username TEXT,
                password_hash TEXT,
                org_id TEXT,
                role TEXT DEFAULT 'viewer',
                created_at REAL,
                last_login REAL,
                status TEXT DEFAULT 'active',
                api_key TEXT,
                FOREIGN KEY (org_id) REFERENCES organizations (org_id)
            )
        """)

        # 团队成员表（用户-团队多对多）
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS team_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id TEXT,
                user_id TEXT,
                role TEXT DEFAULT 'member',
                joined_at REAL,
                UNIQUE(team_id, user_id),
                FOREIGN KEY (team_id) REFERENCES teams (team_id),
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        """)

        # 项目成员表（用户-项目多对多）
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS project_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id TEXT,
                user_id TEXT,
                role TEXT DEFAULT 'member',
                joined_at REAL,
                UNIQUE(project_id, user_id),
                FOREIGN KEY (project_id) REFERENCES projects (project_id),
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        """)

        # 使用量表（每月重置）
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id TEXT,
                month TEXT,
                scans_count INTEGER DEFAULT 0,
                assets_count INTEGER DEFAULT 0,
                reports_exported INTEGER DEFAULT 0,
                UNIQUE(org_id, month),
                FOREIGN KEY (org_id) REFERENCES organizations (org_id)
            )
        """)

        # 审计日志表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id TEXT,
                user_id TEXT,
                action TEXT,
                resource_type TEXT,
                resource_id TEXT,
                details TEXT,
                ip_address TEXT,
                timestamp REAL,
                FOREIGN KEY (org_id) REFERENCES organizations (org_id),
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        """)

        # 创建索引
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_teams_org ON teams(org_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(org_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_projects_team ON projects(team_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(org_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp)")

        conn.commit()
        conn.close()

    def _hash_password(self, password: str) -> str:
        """密码哈希"""
        return hashlib.sha256(password.encode()).hexdigest()

    def _generate_id(self, prefix: str) -> str:
        """生成ID"""
        return f"{prefix}_{secrets.token_hex(8)}"

    def _log_audit(self, org_id: str, user_id: str, action: str, resource_type: str, resource_id: str, details: Dict = None, ip: str = ""):
        """记录审计日志"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (org_id, user_id, action, resource_type, resource_id, details, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (org_id, user_id, action, resource_type, resource_id,
              json.dumps(details or {}, ensure_ascii=False), ip, time.time()))
        conn.commit()
        conn.close()

    # ========== 组织管理 ==========

    def create_organization(self, name: str, plan: str = "free", created_by: str = "") -> str:
        """创建组织"""
        org_id = self._generate_id("org")
        now = time.time()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO organizations (org_id, name, plan, created_at, status)
            VALUES (?, ?, ?, ?, 'active')
        """, (org_id, name, plan, now))
        conn.commit()
        conn.close()

        self._log_audit(org_id, created_by, "create_organization", "organization", org_id, {"name": name, "plan": plan})

        return org_id

    def get_organization(self, org_id: str) -> Optional[Dict]:
        """获取组织信息"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM organizations WHERE org_id = ?", (org_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return {
            "org_id": row["org_id"],
            "name": row["name"],
            "plan": row["plan"],
            "plan_info": PLAN_QUOTAS.get(row["plan"], {}),
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "status": row["status"],
            "settings": json.loads(row["settings"] or "{}"),
        }

    def update_organization_plan(self, org_id: str, plan: str, expires_at: float = None):
        """更新组织订阅计划"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE organizations SET plan = ?, expires_at = ? WHERE org_id = ?
        """, (plan, expires_at, org_id))
        conn.commit()
        conn.close()

        self._log_audit(org_id, "", "update_plan", "organization", org_id, {"new_plan": plan})

    # ========== 团队管理 ==========

    def create_team(self, org_id: str, name: str, created_by: str = "") -> Optional[str]:
        """创建团队"""
        # 检查配额
        org = self.get_organization(org_id)
        if not org:
            return None

        quota = PLAN_QUOTAS.get(org["plan"], {})
        max_teams = quota.get("max_teams", 1)

        if max_teams != -1:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM teams WHERE org_id = ?", (org_id,))
            current = cursor.fetchone()[0]
            conn.close()

            if current >= max_teams:
                return None  # 超出配额

        team_id = self._generate_id("team")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO teams (team_id, org_id, name, created_at)
            VALUES (?, ?, ?, ?)
        """, (team_id, org_id, name, time.time()))
        conn.commit()
        conn.close()

        self._log_audit(org_id, created_by, "create_team", "team", team_id, {"name": name})

        return team_id

    def get_teams(self, org_id: str) -> List[Dict]:
        """获取组织下的所有团队"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM teams WHERE org_id = ? ORDER BY created_at", (org_id,))
        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "team_id": row["team_id"],
                "name": row["name"],
                "created_at": row["created_at"],
                "settings": json.loads(row["settings"] or "{}"),
            }
            for row in rows
        ]

    # ========== 项目管理 ==========

    def create_project(self, org_id: str, team_id: str, name: str, description: str = "", created_by: str = "") -> Optional[str]:
        """创建项目"""
        # 检查配额
        org = self.get_organization(org_id)
        if not org:
            return None

        quota = PLAN_QUOTAS.get(org["plan"], {})
        max_projects = quota.get("max_projects", 1)

        if max_projects != -1:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM projects WHERE org_id = ?", (org_id,))
            current = cursor.fetchone()[0]
            conn.close()

            if current >= max_projects:
                return None

        project_id = self._generate_id("proj")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO projects (project_id, org_id, team_id, name, description, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?, 'active')
        """, (project_id, org_id, team_id, name, description, time.time()))
        conn.commit()
        conn.close()

        self._log_audit(org_id, created_by, "create_project", "project", project_id, {"name": name, "team_id": team_id})

        return project_id

    def get_projects(self, org_id: str, team_id: str = None) -> List[Dict]:
        """获取项目列表"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if team_id:
            cursor.execute("SELECT * FROM projects WHERE org_id = ? AND team_id = ? ORDER BY created_at", (org_id, team_id))
        else:
            cursor.execute("SELECT * FROM projects WHERE org_id = ? ORDER BY created_at", (org_id,))

        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "project_id": row["project_id"],
                "team_id": row["team_id"],
                "name": row["name"],
                "description": row["description"],
                "created_at": row["created_at"],
                "status": row["status"],
            }
            for row in rows
        ]

    # ========== 用户管理 ==========

    def register_user(self, email: str, username: str, password: str, org_id: str = None, role: str = "viewer") -> Optional[str]:
        """注册用户"""
        user_id = self._generate_id("user")
        password_hash = self._hash_password(password)
        api_key = secrets.token_hex(32)

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (user_id, email, username, password_hash, org_id, role, created_at, status, api_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)
            """, (user_id, email, username, password_hash, org_id, role, time.time(), api_key))
            conn.commit()
            conn.close()

            self._log_audit(org_id or "", user_id, "register_user", "user", user_id, {"email": email, "username": username})

            return user_id
        except sqlite3.IntegrityError:
            return None  # 邮箱已存在

    def authenticate_user(self, email: str, password: str) -> Optional[Dict]:
        """用户认证"""
        password_hash = self._hash_password(password)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM users WHERE email = ? AND password_hash = ? AND status = 'active'
        """, (email, password_hash))
        row = cursor.fetchone()

        if row:
            cursor.execute("UPDATE users SET last_login = ? WHERE user_id = ?", (time.time(), row["user_id"]))
            conn.commit()

        conn.close()

        if not row:
            return None

        return {
            "user_id": row["user_id"],
            "email": row["email"],
            "username": row["username"],
            "org_id": row["org_id"],
            "role": row["role"],
            "api_key": row["api_key"],
        }

    def get_user_role(self, user_id: str, org_id: str = None, team_id: str = None, project_id: str = None) -> str:
        """获取用户在特定资源中的角色"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # 先检查组织级角色
        cursor.execute("SELECT role FROM users WHERE user_id = ?", (user_id,))
        user = cursor.fetchone()

        if user and user["role"] == "org_admin":
            conn.close()
            return "org_admin"

        # 检查团队角色
        if team_id:
            cursor.execute("SELECT role FROM team_members WHERE team_id = ? AND user_id = ?", (team_id, user_id))
            team_member = cursor.fetchone()
            if team_member:
                conn.close()
                return team_member["role"]

        # 检查项目角色
        if project_id:
            cursor.execute("SELECT role FROM project_members WHERE project_id = ? AND user_id = ?", (project_id, user_id))
            project_member = cursor.fetchone()
            if project_member:
                conn.close()
                return project_member["role"]

        conn.close()
        return user["role"] if user else "viewer"

    def check_permission(self, user_id: str, action: str, resource_type: str, org_id: str = None, team_id: str = None, project_id: str = None) -> bool:
        """检查用户权限"""
        role = self.get_user_role(user_id, org_id, team_id, project_id)

        # 权限矩阵
        permissions = {
            "org_admin": ["create", "read", "update", "delete", "manage_users", "manage_billing", "export"],
            "team_admin": ["create", "read", "update", "delete", "manage_team_users", "export"],
            "project_member": ["create", "read", "update", "export"],
            "viewer": ["read"],
        }

        allowed_actions = permissions.get(role, [])
        return action in allowed_actions

    # ========== 使用量管理 ==========

    def increment_usage(self, org_id: str, scan_count: int = 0, asset_count: int = 0, report_count: int = 0):
        """增加使用量"""
        month = datetime.now().strftime("%Y-%m")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO usage (org_id, month, scans_count, assets_count, reports_exported)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(org_id, month) DO UPDATE SET
                scans_count = scans_count + ?,
                assets_count = assets_count + ?,
                reports_exported = reports_exported + ?
        """, (org_id, month, scan_count, asset_count, report_count,
              scan_count, asset_count, report_count))
        conn.commit()
        conn.close()

    def check_quota(self, org_id: str, resource: str) -> Tuple[bool, int, int]:
        """检查配额是否够用
        返回: (是否够用, 已使用, 配额上限)
        """
        org = self.get_organization(org_id)
        if not org:
            return False, 0, 0

        quota = PLAN_QUOTAS.get(org["plan"], {})
        max_value = quota.get(resource, 0)

        if max_value == -1:
            return True, 0, -1  # 无限

        month = datetime.now().strftime("%Y-%m")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if resource == "max_scans_per_month":
            cursor.execute("SELECT scans_count FROM usage WHERE org_id = ? AND month = ?", (org_id, month))
        elif resource == "max_assets":
            cursor.execute("SELECT assets_count FROM usage WHERE org_id = ? AND month = ?", (org_id, month))
        elif resource == "max_report_export":
            cursor.execute("SELECT reports_exported FROM usage WHERE org_id = ? AND month = ?", (org_id, month))
        else:
            # 用户/团队/项目数量
            table_map = {
                "max_users": "users",
                "max_teams": "teams",
                "max_projects": "projects",
            }
            table = table_map.get(resource)
            if table:
                cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE org_id = ?", (org_id,))
            else:
                conn.close()
                return False, 0, 0

        row = cursor.fetchone()
        conn.close()

        current = row[0] if row else 0
        return current < max_value, current, max_value

    # ========== 审计日志 ==========

    def get_audit_logs(self, org_id: str, limit: int = 100, user_id: str = None, action: str = None) -> List[Dict]:
        """获取审计日志"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM audit_logs WHERE org_id = ?"
        params = [org_id]

        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        if action:
            query += " AND action = ?"
            params.append(action)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "action": row["action"],
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "details": json.loads(row["details"] or "{}"),
                "user_id": row["user_id"],
                "ip_address": row["ip_address"],
                "timestamp": datetime.fromtimestamp(row["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"),
            }
            for row in rows
        ]

    # ========== 统计 ==========

    def get_statistics(self, org_id: str) -> Dict[str, Any]:
        """获取组织统计"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM users WHERE org_id = ?", (org_id,))
        users = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM teams WHERE org_id = ?", (org_id,))
        teams = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM projects WHERE org_id = ?", (org_id,))
        projects = cursor.fetchone()[0]

        month = datetime.now().strftime("%Y-%m")
        cursor.execute("SELECT scans_count, assets_count, reports_exported FROM usage WHERE org_id = ? AND month = ?", (org_id, month))
        usage = cursor.fetchone()

        conn.close()

        org = self.get_organization(org_id)

        return {
            "organization": org,
            "users": users,
            "teams": teams,
            "projects": projects,
            "monthly_usage": {
                "scans": usage[0] if usage else 0,
                "assets": usage[1] if usage else 0,
                "reports_exported": usage[2] if usage else 0,
            },
        }
