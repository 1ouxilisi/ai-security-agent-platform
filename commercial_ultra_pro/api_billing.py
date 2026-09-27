#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
commercial_ultra_pro/api_billing.py — API 计费。

- 计费模式：按次/按量/套餐/超额
- API 密钥管理：创建/禁用/权限/配额/轮换
- API 调用统计：按密钥/端点/时间/状态码
- 计费账单：月度自动生成
- 限流控制：速率/并发/配额
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import Any, Dict, List, Optional


PLANS_API = {
    "free": {"price_per_1k": 0.5, "rate_per_sec": 5, "concurrent": 2,
              "daily_quota": 1000, "monthly_quota": 30000},
    "pro": {"price_per_1k": 0.2, "rate_per_sec": 20, "concurrent": 10,
             "daily_quota": 50000, "monthly_quota": 1000000},
    "enterprise": {"price_per_1k": 0.05, "rate_per_sec": 200, "concurrent": 100,
                     "daily_quota": -1, "monthly_quota": -1},
}
KEY_PERMISSIONS = ["read", "write", "admin"]


class APIBilling:
    """API 计费（内存存储）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._keys: Dict[str, Dict[str, Any]] = {}       # key_value -> record
        self._usage: List[Dict[str, Any]] = []            # 调用记录
        self._bills: Dict[str, Dict[str, Any]] = {}
        self._seq = 0

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}{int(time.time()) % 100000:05d}-{self._seq:03d}"

    def _now(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    # ------------------------------------------------------------------ #
    # API 密钥
    # ------------------------------------------------------------------ #
    def create_key(self, customer_id: str, name: str,
                    permission: str = "read",
                    daily_limit: int = 10000,
                    monthly_limit: int = -1) -> Dict[str, Any]:
        if permission not in KEY_PERMISSIONS:
            raise ValueError(f"权限必须为 {KEY_PERMISSIONS}")
        with self._lock:
            kv = "sk-" + secrets.token_urlsafe(32)
            rec = {
                "key_id": self._next_id("KEY"), "key_name": name,
                "key_value": kv, "customer_id": customer_id,
                "permission": permission, "status": "active",
                "daily_limit": daily_limit, "monthly_limit": monthly_limit,
                "concurrent": 0, "created_at": self._now(),
                "last_used": "", "rotated_count": 0,
            }
            self._keys[kv] = rec
            return rec

    def list_keys(self, customer_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._keys.values())
            if customer_id:
                out = [k for k in out if k["customer_id"] == customer_id]
            # 脱敏 key_value
            for k in out:
                k = dict(k)
                k["key_value"] = k["key_value"][:8] + "..." + k["key_value"][-4:]
            return out

    def disable_key(self, key_value: str) -> Dict[str, Any]:
        with self._lock:
            k = self._keys.get(key_value)
            if not k:
                raise ValueError("密钥不存在")
            k["status"] = "disabled"
            return k

    def rotate_key(self, key_value: str) -> Dict[str, Any]:
        with self._lock:
            k = self._keys.get(key_value)
            if not k:
                raise ValueError("密钥不存在")
            old = k["key_value"]
            new = "sk-" + secrets.token_urlsafe(32)
            k["key_value"] = new
            k["rotated_count"] += 1
            self._keys[new] = k
            del self._keys[old]
            return {"key_id": k["key_id"], "old_masked": old[:8] + "...",
                    "new_key": new, "rotated_count": k["rotated_count"]}

    # ------------------------------------------------------------------ #
    # 调用 + 限流
    # ------------------------------------------------------------------ #
    def record_call(self, key_value: str, endpoint: str,
                     status_code: int = 200,
                     response_bytes: int = 0) -> Dict[str, Any]:
        """记录一次 API 调用，返回是否被限流。"""
        with self._lock:
            k = self._keys.get(key_value)
            if not k:
                raise ValueError("密钥不存在")
            if k["status"] != "active":
                return {"allowed": False, "reason": "密钥已禁用",
                        "status_code": 401}
            # 日配额
            today = time.strftime("%Y-%m-%d")
            today_calls = sum(1 for u in self._usage
                               if u["key_id"] == k["key_id"]
                               and u["date"] == today)
            if k["daily_limit"] > 0 and today_calls >= k["daily_limit"]:
                return {"allowed": False, "reason": "日配额超限",
                        "status_code": 429}
            month = time.strftime("%Y-%m")
            month_calls = sum(1 for u in self._usage
                               if u["key_id"] == k["key_id"]
                               and u["date"].startswith(month))
            if k["monthly_limit"] > 0 and month_calls >= k["monthly_limit"]:
                return {"allowed": False, "reason": "月配额超限",
                        "status_code": 429}
            rec = {
                "call_id": self._next_id("CALL"), "key_id": k["key_id"],
                "customer_id": k["customer_id"], "endpoint": endpoint,
                "status_code": status_code, "response_bytes": response_bytes,
                "date": today, "month": month, "at": self._now(),
            }
            self._usage.append(rec)
            k["last_used"] = self._now()
            if len(self._usage) > 50000:
                self._usage = self._usage[-50000:]
            return {"allowed": True, "record": rec,
                    "today_calls": today_calls + 1}

    # ------------------------------------------------------------------ #
    # 调用统计
    # ------------------------------------------------------------------ #
    def usage_stats(self, customer_id: Optional[str] = None,
                     key_id: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            out = list(self._usage)
            if customer_id:
                out = [u for u in out if u["customer_id"] == customer_id]
            if key_id:
                out = [u for u in out if u["key_id"] == key_id]
            by_endpoint: Dict[str, int] = {}
            by_status: Dict[int, int] = {}
            total_bytes = 0
            errors = 0
            for u in out:
                by_endpoint[u["endpoint"]] = by_endpoint.get(u["endpoint"], 0) + 1
                by_status[u["status_code"]] = by_status.get(u["status_code"], 0) + 1
                total_bytes += u["response_bytes"]
                if u["status_code"] >= 400:
                    errors += 1
            top_ep = sorted(by_endpoint.items(), key=lambda x: -x[1])[:10]
            return {
                "total_calls": len(out),
                "errors": errors,
                "error_rate": round(errors / len(out) * 100, 2) if out else 0,
                "total_response_mb": round(total_bytes / 1024 / 1024, 2),
                "by_endpoint": dict(top_ep),
                "by_status_code": by_status,
            }

    # ------------------------------------------------------------------ #
    # 计费账单
    # ------------------------------------------------------------------ #
    def generate_monthly_bill(self, customer_id: str,
                               plan: str = "pro") -> Dict[str, Any]:
        """按月生成 API 调用账单。"""
        if plan not in PLANS_API:
            raise ValueError(f"套餐必须为 {list(PLANS_API.keys())}")
        with self._lock:
            month = time.strftime("%Y-%m")
            calls = [u for u in self._usage
                      if u["customer_id"] == customer_id and u["month"] == month]
            price_per_1k = PLANS_API[plan]["price_per_1k"]
            amount = round(len(calls) / 1000.0 * price_per_1k, 2)
            bill_id = self._next_id("APIBILL")
            bill = {
                "bill_id": bill_id, "customer_id": customer_id,
                "month": month, "plan": plan,
                "calls": len(calls), "price_per_1k": price_per_1k,
                "amount": amount, "status": "unpaid",
                "created_at": self._now(),
            }
            self._bills[bill_id] = bill
            return bill

    def list_bills(self, customer_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._bills.values())
            if customer_id:
                out = [b for b in out if b["customer_id"] == customer_id]
            return sorted(out, key=lambda x: x["created_at"], reverse=True)

    # ------------------------------------------------------------------ #
    # 限流配置
    # ------------------------------------------------------------------ #
    def rate_limit_config(self) -> Dict[str, Any]:
        return {"plans": PLANS_API,
                "permissions": KEY_PERMISSIONS}

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            active_keys = sum(1 for k in self._keys.values()
                               if k["status"] == "active")
            return {
                "total_keys": len(self._keys),
                "active_keys": active_keys,
                "total_calls": len(self._usage),
                "bills": len(self._bills),
                "total_bill_amount": round(
                    sum(b["amount"] for b in self._bills.values()), 2),
            }


_api_billing: APIBilling | None = None


def get_api_billing() -> APIBilling:
    global _api_billing
    if _api_billing is None:
        _api_billing = APIBilling()
    return _api_billing
