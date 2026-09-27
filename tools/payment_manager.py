"""
payment_manager安全工具集成模块，提供相关安全工具的封装和调用。

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
import time
import uuid
import sqlite3
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import log


class PaymentStatus(Enum):
    """支付状态"""
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    REFUNDED = "refunded"
    CANCELLED = "cancelled"


class SubscriptionStatus(Enum):
    """订阅状态"""
    ACTIVE = "active"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    TRIAL = "trial"


@dataclass
class Plan:
    """套餐"""
    plan_id: str
    name: str
    description: str
    price_monthly: float
    price_yearly: float
    features: List[str] = field(default_factory=list)
    limits: Dict[str, Any] = field(default_factory=dict)
    is_active: bool = True


@dataclass
class Order:
    """订单"""
    order_id: str
    user_id: str
    plan_id: str
    amount: float
    currency: str
    payment_method: str
    status: str
    created_at: str
    paid_at: Optional[str] = None
    transaction_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Subscription:
    """订阅"""
    subscription_id: str
    user_id: str
    plan_id: str
    status: str
    current_period_start: str
    current_period_end: str
    created_at: str
    cancelled_at: Optional[str] = None


class PaymentManager:
    """支付管理器"""

    # 预定义套餐
    PLANS = [
        Plan(
            plan_id="free",
            name="免费版",
            description="适合个人学习和体验",
            price_monthly=0,
            price_yearly=0,
            features=["基础扫描功能", "每日10次扫描", "社区支持", "基础报告"],
            limits={"scans_per_day": 10, "max_targets": 3, "report_export": False},
        ),
        Plan(
            plan_id="pro",
            name="专业版",
            description="适合安全从业者和小团队",
            price_monthly=99,
            price_yearly=999,
            features=["全部扫描功能", "每日100次扫描", "无限目标", "高级报告导出", "邮件支持", "API访问"],
            limits={"scans_per_day": 100, "max_targets": -1, "report_export": True, "api_access": True},
        ),
        Plan(
            plan_id="enterprise",
            name="企业版",
            description="适合企业级安全团队",
            price_monthly=999,
            price_yearly=9999,
            features=["全部功能", "无限扫描", "私有化部署", "专属客户经理", "7x24支持", "定制开发", "SLA保障"],
            limits={"scans_per_day": -1, "max_targets": -1, "report_export": True, "api_access": True, "priority_support": True},
        ),
    ]

    def __init__(self, db_path: str = None):
        """初始化PaymentManager实例。

        Args:
            self: 类实例。
        """
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data", "payment.db"
            )
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """初始化数据库"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 订单表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                order_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                plan_id TEXT NOT NULL,
                amount REAL NOT NULL,
                currency TEXT DEFAULT 'CNY',
                payment_method TEXT,
                status TEXT DEFAULT 'pending',
                created_at TEXT,
                paid_at TEXT,
                transaction_id TEXT,
                metadata TEXT
            )
        """)

        # 订阅表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                subscription_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                plan_id TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                current_period_start TEXT,
                current_period_end TEXT,
                created_at TEXT,
                cancelled_at TEXT
            )
        """)

        # 支付渠道配置表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payment_channels (
                channel_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                config TEXT,
                created_at TEXT
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id)")

        conn.commit()
        conn.close()

    # ==================== 套餐管理 ====================

    def list_plans(self) -> List[Dict[str, Any]]:
        """列出所有套餐"""
        return [
            {
                "plan_id": p.plan_id,
                "name": p.name,
                "description": p.description,
                "price_monthly": p.price_monthly,
                "price_yearly": p.price_yearly,
                "features": p.features,
                "limits": p.limits,
                "is_active": p.is_active,
            }
            for p in self.PLANS if p.is_active
        ]

    def get_plan(self, plan_id: str) -> Optional[Dict[str, Any]]:
        """获取指定套餐"""
        for p in self.PLANS:
            if p.plan_id == plan_id:
                return {
                    "plan_id": p.plan_id,
                    "name": p.name,
                    "description": p.description,
                    "price_monthly": p.price_monthly,
                    "price_yearly": p.price_yearly,
                    "features": p.features,
                    "limits": p.limits,
                }
        return None

    # ==================== 订单管理 ====================

    def create_order(self, user_id: str, plan_id: str,
                     billing_cycle: str = "monthly",
                     payment_method: str = "alipay") -> Dict[str, Any]:
        """创建订单"""
        plan = self.get_plan(plan_id)
        if not plan:
            return {"success": False, "error": "套餐不存在"}

        amount = plan["price_monthly"] if billing_cycle == "monthly" else plan["price_yearly"]
        if amount == 0:
            # 免费套餐直接激活
            self._activate_subscription(user_id, plan_id, billing_cycle)
            return {
                "success": True,
                "order_id": "free_" + uuid.uuid4().hex[:12],
                "amount": 0,
                "message": "免费套餐已激活",
            }

        order_id = "ORD" + uuid.uuid4().hex[:16].upper()
        now = datetime.now().isoformat()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO orders (order_id, user_id, plan_id, amount, currency, payment_method, status, created_at, metadata)
            VALUES (?, ?, ?, ?, 'CNY', ?, 'pending', ?, ?)
        """, (order_id, user_id, plan_id, amount, payment_method, now,
              json.dumps({"billing_cycle": billing_cycle})))
        conn.commit()
        conn.close()

        log.info(f"订单创建: {order_id} 用户:{user_id} 套餐:{plan_id} 金额:{amount}")

        return {
            "success": True,
            "order_id": order_id,
            "user_id": user_id,
            "plan_id": plan_id,
            "plan_name": plan["name"],
            "amount": amount,
            "currency": "CNY",
            "billing_cycle": billing_cycle,
            "payment_method": payment_method,
            "status": "pending",
            "created_at": now,
            "message": "订单已创建，请完成支付",
        }

    def confirm_payment(self, order_id: str, transaction_id: str = "") -> Dict[str, Any]:
        """确认支付（回调处理）"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM orders WHERE order_id = ?", (order_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return {"success": False, "error": "订单不存在"}

        if row[6] == "paid":
            conn.close()
            return {"success": True, "message": "订单已支付"}

        now = datetime.now().isoformat()
        cursor.execute("""
            UPDATE orders SET status = 'paid', paid_at = ?, transaction_id = ?
            WHERE order_id = ?
        """, (now, transaction_id, order_id))
        conn.commit()
        conn.close()

        # 激活订阅
        metadata = json.loads(row[10]) if row[10] else {}
        billing_cycle = metadata.get("billing_cycle", "monthly")
        self._activate_subscription(row[1], row[2], billing_cycle)

        log.info(f"支付确认: {order_id} 交易号:{transaction_id}")
        return {"success": True, "order_id": order_id, "message": "支付成功，订阅已激活"}

    def _activate_subscription(self, user_id: str, plan_id: str,
                                billing_cycle: str = "monthly"):
        """激活订阅"""
        subscription_id = "SUB" + uuid.uuid4().hex[:16].upper()
        now = datetime.now()
        if billing_cycle == "yearly":
            end_date = now + timedelta(days=365)
        else:
            end_date = now + timedelta(days=30)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 取消旧订阅
        cursor.execute("""
            UPDATE subscriptions SET status = 'cancelled', cancelled_at = ?
            WHERE user_id = ? AND status = 'active'
        """, (now.isoformat(), user_id))

        # 创建新订阅
        cursor.execute("""
            INSERT INTO subscriptions (subscription_id, user_id, plan_id, status, current_period_start, current_period_end, created_at)
            VALUES (?, ?, ?, 'active', ?, ?, ?)
        """, (subscription_id, user_id, plan_id, now.isoformat(), end_date.isoformat(), now.isoformat()))
        conn.commit()
        conn.close()

        log.info(f"订阅激活: {subscription_id} 用户:{user_id} 套餐:{plan_id} 到期:{end_date.isoformat()}")

    # ==================== 订阅管理 ====================

    def get_user_subscription(self, user_id: str) -> Optional[Dict[str, Any]]:
        """获取用户当前订阅"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM subscriptions WHERE user_id = ? AND status = 'active'
            ORDER BY created_at DESC LIMIT 1
        """, (user_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        plan = self.get_plan(row[2])
        return {
            "subscription_id": row[0],
            "user_id": row[1],
            "plan_id": row[2],
            "plan_name": plan["name"] if plan else row[2],
            "status": row[3],
            "current_period_start": row[4],
            "current_period_end": row[5],
            "created_at": row[6],
            "features": plan["features"] if plan else [],
            "limits": plan["limits"] if plan else {},
        }

    def check_access(self, user_id: str, feature: str) -> Dict[str, Any]:
        """检查用户是否有权限使用某功能"""
        subscription = self.get_user_subscription(user_id)
        if not subscription:
            # 免费用户
            free_plan = self.get_plan("free")
            limits = free_plan["limits"] if free_plan else {}
            return {
                "allowed": limits.get(feature, False),
                "plan": "free",
                "message": "该功能需要升级套餐",
            }

        limits = subscription.get("limits", {})
        allowed = limits.get(feature, False)
        if allowed == -1 or allowed is True:
            return {"allowed": True, "plan": subscription["plan_name"]}
        return {"allowed": bool(allowed), "plan": subscription["plan_name"]}

    # ==================== 支付渠道管理 ====================

    def add_payment_channel(self, name: str, channel_type: str,
                             config: Dict[str, Any]) -> Dict[str, Any]:
        """添加支付渠道"""
        channel_id = "PAY" + uuid.uuid4().hex[:8].upper()
        now = datetime.now().isoformat()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO payment_channels (channel_id, name, type, enabled, config, created_at)
            VALUES (?, ?, ?, 1, ?, ?)
        """, (channel_id, name, channel_type, json.dumps(config), now))
        conn.commit()
        conn.close()

        return {"success": True, "channel_id": channel_id, "name": name, "type": channel_type}

    def list_payment_channels(self) -> List[Dict[str, Any]]:
        """列出支付渠道"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT channel_id, name, type, enabled, created_at FROM payment_channels")
        rows = cursor.fetchall()
        conn.close()

        return [
            {"channel_id": r[0], "name": r[1], "type": r[2], "enabled": bool(r[3]), "created_at": r[4]}
            for r in rows
        ]

    # ==================== 统计 ====================

    def get_statistics(self) -> Dict[str, Any]:
        """获取支付系统统计"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM orders")
        total_orders = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM orders WHERE status = 'paid'")
        paid_orders = cursor.fetchone()[0]

        cursor.execute("SELECT COALESCE(SUM(amount), 0) FROM orders WHERE status = 'paid'")
        total_revenue = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM subscriptions WHERE status = 'active'")
        active_subscriptions = cursor.fetchone()[0]

        conn.close()

        return {
            "total_orders": total_orders,
            "paid_orders": paid_orders,
            "total_revenue": total_revenue,
            "active_subscriptions": active_subscriptions,
            "plans": len(self.PLANS),
        }


# 全局支付管理器实例
payment_manager = PaymentManager()
