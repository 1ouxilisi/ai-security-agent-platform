"""
tenant_manager安全工具集成模块，提供相关安全工具的封装和调用。

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
import sys
import json
import sqlite3
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import log


@dataclass
class Tenant:
    """租户"""
    tenant_id: str
    name: str
    plan: str = "free"
    status: str = "active"  # active/suspended/expired
    created_at: str = ""
    expires_at: str = ""
    owner_user_id: str = ""
    settings: Dict[str, Any] = field(default_factory=dict)
    quota: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TenantMember:
    """租户成员"""
    tenant_id: str
    user_id: str
    role: str = "member"  # owner/admin/member/viewer
    joined_at: str = ""
    invited_by: str = ""


@dataclass
class UsageRecord:
    """用量记录"""
    tenant_id: str
    resource_type: str  # scans/targets/users/storage/api_calls
    amount: int
    period: str  # YYYY-MM
    recorded_at: str


class TenantManager:
    """租户管理器"""

    # 默认配额
    DEFAULT_QUOTAS = {
        "free": {
            "scans_per_month": 100,
            "max_targets": 5,
            "max_members": 1,
            "storage_gb": 1,
            "api_calls_per_day": 100,
            "concurrent_scans": 1,
        },
        "pro": {
            "scans_per_month": 1000,
            "max_targets": 50,
            "max_members": 10,
            "storage_gb": 10,
            "api_calls_per_day": 1000,
            "concurrent_scans": 5,
        },
        "enterprise": {
            "scans_per_month": -1,  # 无限
            "max_targets": -1,
            "max_members": -1,
            "storage_gb": 100,
            "api_calls_per_day": -1,
            "concurrent_scans": 20,
        },
    }

    def __init__(self, db_path: str = None):
        """初始化TenantManager实例。

        Args:
            self: 类实例。
        """
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data", "tenants.db"
            )
        self.db_path = db_path
        self._init_db()

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
                plan TEXT DEFAULT 'free',
                status TEXT DEFAULT 'active',
                created_at TEXT,
                expires_at TEXT,
                owner_user_id TEXT,
                settings TEXT,
                quota TEXT
            )
        """)

        # 租户成员表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tenant_members (
                tenant_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT DEFAULT 'member',
                joined_at TEXT,
                invited_by TEXT,
                PRIMARY KEY (tenant_id, user_id)
            )
        """)

        # 用量记录表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usage_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                amount INTEGER DEFAULT 0,
                period TEXT,
                recorded_at TEXT
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tenants_owner ON tenants(owner_user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_members_user ON tenant_members(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_usage_tenant ON usage_records(tenant_id, resource_type, period)")

        conn.commit()
        conn.close()

    # ==================== 租户管理 ====================

    def create_tenant(self, name: str, owner_user_id: str,
                      plan: str = "free") -> Dict[str, Any]:
        """创建租户"""
        import uuid
        tenant_id = "TEN" + uuid.uuid4().hex[:12].upper()
        now = datetime.now().isoformat()
        expires_at = (datetime.now() + timedelta(days=365)).isoformat()

        quota = self.DEFAULT_QUOTAS.get(plan, self.DEFAULT_QUOTAS["free"]).copy()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO tenants (tenant_id, name, plan, status, created_at, expires_at, owner_user_id, settings, quota)
            VALUES (?, ?, ?, 'active', ?, ?, ?, '{}', ?)
        """, (tenant_id, name, plan, now, expires_at, owner_user_id, json.dumps(quota)))

        # 添加所有者为成员
        cursor.execute("""
            INSERT INTO tenant_members (tenant_id, user_id, role, joined_at, invited_by)
            VALUES (?, ?, 'owner', ?, ?)
        """, (tenant_id, owner_user_id, now, owner_user_id))

        conn.commit()
        conn.close()

        log.info(f"租户创建: {tenant_id} 名称:{name} 所有者:{owner_user_id} 套餐:{plan}")

        return {
            "success": True,
            "tenant_id": tenant_id,
            "name": name,
            "plan": plan,
            "status": "active",
            "created_at": now,
            "expires_at": expires_at,
            "owner_user_id": owner_user_id,
            "quota": quota,
        }

    def get_tenant(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """获取租户信息"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return {
            "tenant_id": row[0],
            "name": row[1],
            "plan": row[2],
            "status": row[3],
            "created_at": row[4],
            "expires_at": row[5],
            "owner_user_id": row[6],
            "settings": json.loads(row[7]) if row[7] else {},
            "quota": json.loads(row[8]) if row[8] else {},
        }

    def list_user_tenants(self, user_id: str) -> List[Dict[str, Any]]:
        """列出用户所属的所有租户"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.*, m.role FROM tenants t
            JOIN tenant_members m ON t.tenant_id = m.tenant_id
            WHERE m.user_id = ?
            ORDER BY t.created_at DESC
        """, (user_id,))
        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "tenant_id": r[0],
                "name": r[1],
                "plan": r[2],
                "status": r[3],
                "created_at": r[4],
                "expires_at": r[5],
                "owner_user_id": r[6],
                "role": r[10],
            }
            for r in rows
        ]

    def update_tenant_plan(self, tenant_id: str, plan: str) -> Dict[str, Any]:
        """更新租户套餐"""
        if plan not in self.DEFAULT_QUOTAS:
            return {"success": False, "error": f"不支持的套餐: {plan}"}

        quota = self.DEFAULT_QUOTAS[plan].copy()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE tenants SET plan = ?, quota = ? WHERE tenant_id = ?
        """, (plan, json.dumps(quota), tenant_id))
        conn.commit()
        conn.close()

        log.info(f"租户套餐更新: {tenant_id} -> {plan}")
        return {"success": True, "tenant_id": tenant_id, "plan": plan, "quota": quota}

    def suspend_tenant(self, tenant_id: str, reason: str = "") -> Dict[str, Any]:
        """暂停租户"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE tenants SET status = 'suspended' WHERE tenant_id = ?", (tenant_id,))
        conn.commit()
        conn.close()

        log.info(f"租户暂停: {tenant_id} 原因:{reason}")
        return {"success": True, "tenant_id": tenant_id, "status": "suspended"}

    # ==================== 成员管理 ====================

    def add_member(self, tenant_id: str, user_id: str,
                   role: str = "member", invited_by: str = "") -> Dict[str, Any]:
        """添加租户成员"""
        # 检查成员数量限制
        members = self.list_members(tenant_id)
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return {"success": False, "error": "租户不存在"}

        max_members = tenant["quota"].get("max_members", 1)
        if max_members != -1 and len(members) >= max_members:
            return {"success": False, "error": f"成员数量已达上限 ({max_members})"}

        now = datetime.now().isoformat()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO tenant_members (tenant_id, user_id, role, joined_at, invited_by)
                VALUES (?, ?, ?, ?, ?)
            """, (tenant_id, user_id, role, now, invited_by))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return {"success": False, "error": "用户已是该租户成员"}
        conn.close()

        log.info(f"租户成员添加: {tenant_id} 用户:{user_id} 角色:{role}")
        return {"success": True, "tenant_id": tenant_id, "user_id": user_id, "role": role}

    def list_members(self, tenant_id: str) -> List[Dict[str, Any]]:
        """列出租户成员"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, role, joined_at, invited_by FROM tenant_members
            WHERE tenant_id = ? ORDER BY joined_at
        """, (tenant_id,))
        rows = cursor.fetchall()
        conn.close()

        return [
            {"user_id": r[0], "role": r[1], "joined_at": r[2], "invited_by": r[3]}
            for r in rows
        ]

    def remove_member(self, tenant_id: str, user_id: str) -> Dict[str, Any]:
        """移除租户成员"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tenant_members WHERE tenant_id = ? AND user_id = ?",
                       (tenant_id, user_id))
        conn.commit()
        conn.close()

        log.info(f"租户成员移除: {tenant_id} 用户:{user_id}")
        return {"success": True, "tenant_id": tenant_id, "user_id": user_id}

    # ==================== 配额与用量 ====================

    def check_quota(self, tenant_id: str, resource_type: str,
                     amount: int = 1) -> Dict[str, Any]:
        """检查配额是否足够"""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return {"allowed": False, "error": "租户不存在"}

        if tenant["status"] != "active":
            return {"allowed": False, "error": f"租户状态异常: {tenant['status']}"}

        quota = tenant["quota"].get(resource_type, 0)
        if quota == -1:
            return {"allowed": True, "quota": -1, "used": 0, "remaining": -1}

        used = self.get_current_usage(tenant_id, resource_type)
        remaining = quota - used

        return {
            "allowed": remaining >= amount,
            "quota": quota,
            "used": used,
            "remaining": remaining,
            "requested": amount,
        }

    def record_usage(self, tenant_id: str, resource_type: str,
                     amount: int = 1) -> Dict[str, Any]:
        """记录用量"""
        now = datetime.now()
        period = now.strftime("%Y-%m")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO usage_records (tenant_id, resource_type, amount, period, recorded_at)
            VALUES (?, ?, ?, ?, ?)
        """, (tenant_id, resource_type, amount, period, now.isoformat()))
        conn.commit()
        conn.close()

        return {"success": True, "tenant_id": tenant_id, "resource_type": resource_type, "amount": amount}

    def get_current_usage(self, tenant_id: str, resource_type: str) -> int:
        """获取当前周期用量"""
        period = datetime.now().strftime("%Y-%m")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COALESCE(SUM(amount), 0) FROM usage_records
            WHERE tenant_id = ? AND resource_type = ? AND period = ?
        """, (tenant_id, resource_type, period))
        result = cursor.fetchone()[0]
        conn.close()
        return result

    def get_usage_summary(self, tenant_id: str) -> Dict[str, Any]:
        """获取租户用量汇总"""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return {"error": "租户不存在"}

        quota = tenant["quota"]
        summary = {}
        for resource_type in ["scans_per_month", "max_targets", "api_calls_per_day"]:
            if resource_type in quota:
                used = self.get_current_usage(tenant_id, resource_type)
                limit = quota[resource_type]
                summary[resource_type] = {
                    "limit": limit,
                    "used": used,
                    "remaining": limit - used if limit != -1 else -1,
                    "usage_percent": round(used / limit * 100, 1) if limit > 0 else 0,
                }

        return {
            "tenant_id": tenant_id,
            "plan": tenant["plan"],
            "usage": summary,
        }

    # ==================== 统计 ====================

    def get_statistics(self) -> Dict[str, Any]:
        """获取多租户系统统计"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM tenants")
        total_tenants = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM tenants WHERE status = 'active'")
        active_tenants = cursor.fetchone()[0]

        cursor.execute("SELECT plan, COUNT(*) FROM tenants GROUP BY plan")
        tenants_by_plan = dict(cursor.fetchall())

        cursor.execute("SELECT COUNT(*) FROM tenant_members")
        total_members = cursor.fetchone()[0]

        conn.close()

        return {
            "total_tenants": total_tenants,
            "active_tenants": active_tenants,
            "tenants_by_plan": tenants_by_plan,
            "total_members": total_members,
        }


# 全局租户管理器实例
tenant_manager = TenantManager()
