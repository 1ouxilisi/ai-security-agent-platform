# -*- coding: utf-8 -*-
"""
feature_gating.py — 功能分级 / 权限闸门（v30.0 真实 License 系统）。

根据 License payload 中的 tier / features / modules 决定：
    * 某个模块是否可访问
    * 某个高级功能是否解锁
    * 每日 API 调用配额
    * 是否支持多租户 / 优先支持
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from .license_generator import REAL_TIERS


class FeatureGate:
    """功能分级闸门。"""

    # Free 版未激活时的默认状态
    DEFAULT_TIER: Dict[str, Any] = {
        "tier": "free",
        "tier_name": "免费版 (Free)",
        "modules": ["dashboard", "basic_scan"],
        "features": ["basic_scan", "single_report"],
        "max_api_calls_per_day": 100,
        "multi_tenant": False,
        "priority_support": False,
    }

    def __init__(self) -> None:
        self._quota_usage: Dict[str, Dict[str, int]] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ #
    def resolve_tier(self, payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """根据 License payload 解析出当前生效的等级定义。"""
        if not payload or payload.get("tier") not in REAL_TIERS:
            return dict(self.DEFAULT_TIER)
        tier = payload["tier"]
        base = dict(REAL_TIERS[tier])
        # License 中可覆盖 features / modules
        if payload.get("features"):
            base["features"] = list(payload["features"])
        if payload.get("modules"):
            base["modules"] = list(payload["modules"])
        base["tier"] = tier
        base["tier_name"] = payload.get("tier_name", base["name"])
        return base

    # ------------------------------------------------------------------ #
    def has_module(self, payload: Optional[Dict[str, Any]], module: str) -> bool:
        tier = self.resolve_tier(payload)
        modules: List[str] = tier.get("modules", [])
        return "*" in modules or module in modules

    def has_feature(self, payload: Optional[Dict[str, Any]], feature: str) -> bool:
        tier = self.resolve_tier(payload)
        feats: List[str] = tier.get("features", [])
        return "*" in feats or feature in feats

    def can_multi_tenant(self, payload: Optional[Dict[str, Any]]) -> bool:
        return bool(self.resolve_tier(payload).get("multi_tenant"))

    # ------------------------------------------------------------------ #
    def check_quota(self, payload: Optional[Dict[str, Any]],
                    customer: str = "default") -> Dict[str, Any]:
        """检查今日 API 配额使用情况。"""
        tier = self.resolve_tier(payload)
        limit = int(tier.get("max_api_calls_per_day", 100))
        today = time.strftime("%Y-%m-%d")
        with self._lock:
            bucket = self._quota_usage.setdefault(customer, {})
            used = bucket.get(today, 0)
        remaining = max(0, limit - used)
        return {
            "limit": limit,
            "used": used,
            "remaining": remaining,
            "exceeded": used >= limit,
            "date": today,
        }

    def consume_quota(self, payload: Optional[Dict[str, Any]],
                      customer: str = "default", amount: int = 1) -> Dict[str, Any]:
        """消耗 API 配额。"""
        with self._lock:
            today = time.strftime("%Y-%m-%d")
            bucket = self._quota_usage.setdefault(customer, {})
            bucket[today] = int(bucket.get(today, 0)) + int(amount)
        return self.check_quota(payload, customer)

    # ------------------------------------------------------------------ #
    def describe(self, payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """返回当前版本的完整能力描述（用于前端展示 / API）。"""
        tier = self.resolve_tier(payload)
        return {
            "tier": tier.get("tier", "free"),
            "tier_name": tier.get("tier_name", "免费版 (Free)"),
            "modules": tier.get("modules", []),
            "features": tier.get("features", []),
            "max_api_calls_per_day": tier.get("max_api_calls_per_day", 100),
            "multi_tenant": tier.get("multi_tenant", False),
            "priority_support": tier.get("priority_support", False),
            "quota": self.check_quota(payload),
        }


# --------------------------------------------------------------------------- #
# 全量版本对比表
# --------------------------------------------------------------------------- #
TIER_COMPARISON: List[Dict[str, Any]] = [
    {
        "code": "free",
        "name": "免费版 (Free)",
        "price": "¥0 / 永久",
        "summary": "体验基础扫描与仪表盘，适合个人学习",
        "limits": [
            "每日 API 调用 ≤ 100 次",
            "仅基础扫描模块",
            "单用户 / 单设备",
            "社区支持",
        ],
    },
    {
        "code": "pro",
        "name": "专业版 (Pro)",
        "price": "¥9,999 / 年",
        "summary": "解锁全部扫描与 AI 分析能力，无 API 限制",
        "limits": [
            "每日 API 调用 ≤ 100,000 次",
            "全部扫描 / AI 分析 / 合规报告",
            "最多 20 用户 / 10 设备",
            "邮件支持",
        ],
    },
    {
        "code": "enterprise",
        "name": "企业版 (Enterprise)",
        "price": "联系销售",
        "summary": "多租户 + 分布式 + 优先支持 + SLA",
        "limits": [
            "API 配额不限",
            "全部功能 + 多租户 / 分布式扫描 / 定制集成",
            "最多 200 用户 / 50 设备",
            "7×24 优先支持 + SLA",
        ],
    },
]


_gate: Optional[FeatureGate] = None
_gate_lock = threading.RLock()


def get_gate() -> FeatureGate:
    global _gate
    with _gate_lock:
        if _gate is None:
            _gate = FeatureGate()
        return _gate
