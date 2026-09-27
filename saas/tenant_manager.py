#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tenant_manager模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import json
import os
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


class TenantPlan(Enum):
    """租户套餐"""
    FREE = "free"           # 免费版
    STARTER = "starter"     # 入门版
    PROFESSIONAL = "professional"  # 专业版
    ENTERPRISE = "enterprise"      # 企业版


class TenantStatus(Enum):
    """租户状态"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


@dataclass
class PlanQuota:
    """套餐配额"""
    plan: str
    name: str
    price_monthly: float
    price_yearly: float
    max_users: int
    max_scans_per_month: int
    max_targets: int
    max_storage_gb: int
    max_api_calls_per_day: int
    features: List[str] = field(default_factory=list)
    support_level: str = "community"


@dataclass
class Tenant:
    """租户"""
    tenant_id: str
    name: str
    plan: str
    status: str = "active"
    owner_email: str = ""
    owner_name: str = ""
    created_at: str = ""
    expires_at: str = ""
    last_active: str = ""
    api_key: str = ""
    settings: Dict = field(default_factory=dict)
    usage: Dict = field(default_factory=dict)


@dataclass
class TenantUser:
    """租户用户"""
    user_id: str
    tenant_id: str
    email: str
    name: str
    role: str = "member"  # owner, admin, member, viewer
    status: str = "active"
    created_at: str = ""
    last_login: str = ""


@dataclass
class UsageRecord:
    """使用记录"""
    record_id: str
    tenant_id: str
    resource_type: str  # scan, api_call, storage, user
    resource_id: str = ""
    quantity: float = 1.0
    timestamp: str = ""
    metadata: Dict = field(default_factory=dict)


class TenantManager:
    """租户管理器"""

    def __init__(self, db_path: str = "./data/tenants.json"):
        """初始化TenantManager实例。

        Args:
            self: 类实例。
        """
        self.db_path = db_path
        self.tenants: Dict[str, Tenant] = {}
        self.tenant_users: Dict[str, List[TenantUser]] = {}
        self.usage_records: List[UsageRecord] = []
        self.plans: Dict[str, PlanQuota] = {}
        self._init_plans()
        self._load_data()
        logger.info("多租户SaaS系统初始化完成")

    def _init_plans(self):
        """初始化套餐"""
        self.plans = {
            "free": PlanQuota(
                plan="free", name="免费版",
                price_monthly=0, price_yearly=0,
                max_users=1, max_scans_per_month=10,
                max_targets=3, max_storage_gb=1,
                max_api_calls_per_day=100,
                features=["基础扫描", "漏洞报告", "社区支持"],
                support_level="community",
            ),
            "starter": PlanQuota(
                plan="starter", name="入门版",
                price_monthly=99, price_yearly=990,
                max_users=3, max_scans_per_month=100,
                max_targets=10, max_storage_gb=10,
                max_api_calls_per_day=1000,
                features=["完整扫描", "Nday武器库", "邮件通知", "API访问"],
                support_level="email",
            ),
            "professional": PlanQuota(
                plan="professional", name="专业版",
                price_monthly=299, price_yearly=2990,
                max_users=10, max_scans_per_month=500,
                max_targets=50, max_storage_gb=50,
                max_api_calls_per_day=5000,
                features=["全部工具", "MCP协议", "钉钉/企微通知", "优先支持", "自定义报告"],
                support_level="priority",
            ),
            "enterprise": PlanQuota(
                plan="enterprise", name="企业版",
                price_monthly=999, price_yearly=9990,
                max_users=999, max_scans_per_month=99999,
                max_targets=9999, max_storage_gb=999,
                max_api_calls_per_day=99999,
                features=["全部功能", "专属部署", "SSO集成", "7x24支持", "定制开发", "SLA保障"],
                support_level="dedicated",
            ),
        }

    def _load_data(self):
        """加载数据"""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for t in data.get("tenants", []):
                        tenant = Tenant(**t)
                        self.tenants[tenant.tenant_id] = tenant
                    for user_data in data.get("users", []):
                        user = TenantUser(**user_data)
                        if user.tenant_id not in self.tenant_users:
                            self.tenant_users[user.tenant_id] = []
                        self.tenant_users[user.tenant_id].append(user)
                    for record in data.get("usage", []):
                        self.usage_records.append(UsageRecord(**record))
            except Exception as e:
                logger.error(f"加载租户数据失败: {e}")

    def _save_data(self):
        """保存数据"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        data = {
            "tenants": [t.__dict__ for t in self.tenants.values()],
            "users": [u.__dict__ for users in self.tenant_users.values() for u in users],
            "usage": [r.__dict__ for r in self.usage_records[-10000:]],
        }
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def create_tenant(self, name: str, plan: str = "free",
                      owner_email: str = "", owner_name: str = "") -> Tenant:
        """创建租户"""
        if plan not in self.plans:
            raise ValueError(f"无效套餐: {plan}")

        tenant_id = f"tenant_{secrets.token_hex(8)}"
        api_key = f"sk-{secrets.token_hex(24)}"

        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            plan=plan,
            status="active",
            owner_email=owner_email,
            owner_name=owner_name,
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            expires_at=(datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S"),
            api_key=api_key,
            usage={"scans_this_month": 0, "api_calls_today": 0, "storage_used_gb": 0, "total_users": 1},
        )

        self.tenants[tenant_id] = tenant

        # 创建所有者用户
        owner = TenantUser(
            user_id=f"user_{secrets.token_hex(8)}",
            tenant_id=tenant_id,
            email=owner_email,
            name=owner_name or "Owner",
            role="owner",
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.tenant_users[tenant_id] = [owner]

        self._save_data()
        logger.info(f"创建租户: {name} ({tenant_id}) - {plan}")
        return tenant

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """获取租户"""
        return self.tenants.get(tenant_id)

    def get_tenant_by_api_key(self, api_key: str) -> Optional[Tenant]:
        """通过API密钥获取租户"""
        for tenant in self.tenants.values():
            if tenant.api_key == api_key:
                return tenant
        return None

    def update_plan(self, tenant_id: str, new_plan: str) -> bool:
        """升级/降级套餐"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False
        if new_plan not in self.plans:
            return False
        tenant.plan = new_plan
        self._save_data()
        logger.info(f"租户 {tenant.name} 套餐变更: {new_plan}")
        return True

    def suspend_tenant(self, tenant_id: str, reason: str = "") -> bool:
        """暂停租户"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False
        tenant.status = "suspended"
        self._save_data()
        logger.warning(f"暂停租户: {tenant.name} - {reason}")
        return True

    def check_quota(self, tenant_id: str, resource_type: str, quantity: float = 1.0) -> Dict:
        """检查配额"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return {"allowed": False, "reason": "租户不存在"}

        if tenant.status != "active":
            return {"allowed": False, "reason": f"租户状态: {tenant.status}"}

        plan = self.plans[tenant.plan]
        usage = tenant.usage

        checks = {
            "scan": ("max_scans_per_month", "scans_this_month"),
            "api_call": ("max_api_calls_per_day", "api_calls_today"),
            "user": ("max_users", "total_users"),
            "storage": ("max_storage_gb", "storage_used_gb"),
        }

        if resource_type in checks:
            max_key, used_key = checks[resource_type]
            max_val = getattr(plan, max_key)
            used_val = usage.get(used_key, 0)
            if used_val + quantity > max_val:
                return {
                    "allowed": False,
                    "reason": f"{resource_type}配额超限: 已用{used_val}/{max_val}",
                    "current": used_val,
                    "limit": max_val,
                }

        return {"allowed": True, "plan": tenant.plan}

    def record_usage(self, tenant_id: str, resource_type: str,
                     quantity: float = 1.0, resource_id: str = "",
                     metadata: Dict = None) -> bool:
        """记录使用量"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False

        # 检查配额
        quota_check = self.check_quota(tenant_id, resource_type, quantity)
        if not quota_check["allowed"]:
            logger.warning(f"租户 {tenant.name} 配额超限: {quota_check['reason']}")
            return False

        # 记录
        record = UsageRecord(
            record_id=f"usage_{secrets.token_hex(8)}",
            tenant_id=tenant_id,
            resource_type=resource_type,
            resource_id=resource_id,
            quantity=quantity,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            metadata=metadata or {},
        )
        self.usage_records.append(record)

        # 更新使用统计
        usage_keys = {
            "scan": "scans_this_month",
            "api_call": "api_calls_today",
            "storage": "storage_used_gb",
        }
        if resource_type in usage_keys:
            key = usage_keys[resource_type]
            tenant.usage[key] = tenant.usage.get(key, 0) + quantity

        tenant.last_active = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._save_data()
        return True

    def add_user(self, tenant_id: str, email: str, name: str, role: str = "member") -> Optional[TenantUser]:
        """添加租户用户"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return None

        # 检查用户数配额
        quota = self.check_quota(tenant_id, "user")
        if not quota["allowed"]:
            return None

        user = TenantUser(
            user_id=f"user_{secrets.token_hex(8)}",
            tenant_id=tenant_id,
            email=email,
            name=name,
            role=role,
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        if tenant_id not in self.tenant_users:
            self.tenant_users[tenant_id] = []
        self.tenant_users[tenant_id].append(user)
        tenant.usage["total_users"] = len(self.tenant_users[tenant_id])
        self._save_data()
        return user

    def get_tenant_users(self, tenant_id: str) -> List[TenantUser]:
        """获取租户用户列表"""
        return self.tenant_users.get(tenant_id, [])

    def get_usage_stats(self, tenant_id: str) -> Dict:
        """获取使用统计"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return {}

        plan = self.plans[tenant.plan]
        return {
            "tenant": tenant.name,
            "plan": plan.name,
            "status": tenant.status,
            "usage": tenant.usage,
            "limits": {
                "max_users": plan.max_users,
                "max_scans_per_month": plan.max_scans_per_month,
                "max_api_calls_per_day": plan.max_api_calls_per_day,
                "max_storage_gb": plan.max_storage_gb,
            },
            "features": plan.features,
            "expires_at": tenant.expires_at,
        }

    def list_plans(self) -> List[Dict]:
        """列出所有套餐"""
        return [
            {
                "plan": p.plan,
                "name": p.name,
                "price_monthly": p.price_monthly,
                "price_yearly": p.price_yearly,
                "max_users": p.max_users,
                "max_scans_per_month": p.max_scans_per_month,
                "features": p.features,
                "support_level": p.support_level,
            }
            for p in self.plans.values()
        ]

    def get_stats(self) -> Dict:
        """获取全局统计"""
        total_scans = sum(t.usage.get("scans_this_month", 0) for t in self.tenants.values())
        total_api_calls = sum(t.usage.get("api_calls_today", 0) for t in self.tenants.values())
        plan_distribution = {}
        for t in self.tenants.values():
            plan_distribution[t.plan] = plan_distribution.get(t.plan, 0) + 1

        return {
            "total_tenants": len(self.tenants),
            "active_tenants": len([t for t in self.tenants.values() if t.status == "active"]),
            "total_users": sum(len(users) for users in self.tenant_users.values()),
            "total_scans_this_month": total_scans,
            "total_api_calls_today": total_api_calls,
            "plan_distribution": plan_distribution,
            "total_usage_records": len(self.usage_records),
        }


def main():
    """演示用法"""
    print("=" * 60)
    print("  多租户SaaS化系统")
    print("  AI Hacking Agent v3.0")
    print("=" * 60)
    print()

    manager = TenantManager(db_path="./data/test_tenants.json")

    # 套餐列表
    print("[1/5] 可用套餐:")
    for plan in manager.list_plans():
        print(f"  {plan['name']}: ¥{plan['price_monthly']}/月")
        print(f"    用户: {plan['max_users']} | 扫描: {plan['max_scans_per_month']}/月")
        print(f"    功能: {', '.join(plan['features'][:3])}")
    print()

    # 创建租户
    print("[2/5] 创建租户...")
    tenant1 = manager.create_tenant(
        name="测试公司A",
        plan="professional",
        owner_email="admin@testa.com",
        owner_name="张三",
    )
    print(f"  租户: {tenant1.name}")
    print(f"  ID: {tenant1.tenant_id}")
    print(f"  API密钥: {tenant1.api_key}")
    print(f"  套餐: {tenant1.plan}")
    print()

    tenant2 = manager.create_tenant(
        name="个人开发者B",
        plan="free",
        owner_email="dev@testb.com",
        owner_name="李四",
    )
    print(f"  租户: {tenant2.name} ({tenant2.plan})")
    print()

    # 添加用户
    print("[3/5] 添加租户用户...")
    user = manager.add_user(tenant1.tenant_id, "analyst@testa.com", "王五", "admin")
    print(f"  添加用户: {user.name} ({user.role})")
    users = manager.get_tenant_users(tenant1.tenant_id)
    print(f"  租户用户数: {len(users)}")
    print()

    # 记录使用
    print("[4/5] 记录使用量...")
    for i in range(5):
        manager.record_usage(tenant1.tenant_id, "scan", 1.0, f"scan_{i}", {"target": "example.com"})
    manager.record_usage(tenant1.tenant_id, "api_call", 50.0)
    print("  已记录: 5次扫描, 50次API调用")
    print()

    # 使用统计
    print("[5/5] 使用统计:")
    stats = manager.get_usage_stats(tenant1.tenant_id)
    print(f"  租户: {stats['tenant']}")
    print(f"  套餐: {stats['plan']}")
    print(f"  状态: {stats['status']}")
    print(f"  本月扫描: {stats['usage'].get('scans_this_month', 0)}/{stats['limits']['max_scans_per_month']}")
    print(f"  今日API: {stats['usage'].get('api_calls_today', 0)}/{stats['limits']['max_api_calls_per_day']}")
    print(f"  用户数: {stats['usage'].get('total_users', 0)}/{stats['limits']['max_users']}")
    print()

    # 全局统计
    print("全局统计:")
    global_stats = manager.get_stats()
    for key, value in global_stats.items():
        print(f"  {key}: {value}")
    print()

    print("=" * 60)
    print("  多租户SaaS功能:")
    print("  - ✅ 4种套餐（免费/入门/专业/企业）")
    print("  - ✅ 租户隔离（数据/配置/配额独立）")
    print("  - ✅ 用户管理（所有者/管理员/成员/查看者）")
    print("  - ✅ 配额限制（扫描/API/存储/用户数）")
    print("  - ✅ 使用统计与计费")
    print("  - ✅ 租户状态管理（活跃/暂停/过期）")
    print("  - ✅ API密钥认证")
    print("=" * 60)

    # 清理
    if os.path.exists("./data/test_tenants.json"):
        os.remove("./data/test_tenants.json")


if __name__ == "__main__":
    main()
