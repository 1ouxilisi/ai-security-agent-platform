#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
commercial_ultra_pro/payment_system.py — 支付系统。

支持渠道：
  - 支付宝（扫码/手机网站/电脑网站）
  - 微信支付（扫码/JSAPI/H5）
  - Stripe（信用卡/订阅，国际支付）
  - 银联支付

设计原则：
  1. 真实支付 API 调用框架：未配置 AppID/密钥时明确提示"未配置"，不伪造签名结果。
  2. 内置"模拟支付"兜底：显式标注 is_mock=True，走完整下单->支付->回调->退款流程。
  3. 全部内存字典存储；统一订单/退款/对账模型。
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
import uuid
from typing import Any, Dict, List, Optional


SUPPORTED_CHANNELS = ["alipay", "wechat", "stripe", "unionpay"]

CHANNEL_LABELS = {
    "alipay": "支付宝",
    "wechat": "微信支付",
    "stripe": "Stripe(国际信用卡)",
    "unionpay": "银联支付",
}

TRADE_TYPES = {
    "alipay": ["face_to_face", "wap", "page"],   # 扫码/手机网站/电脑网站
    "wechat": ["native", "jsapi", "h5"],          # 扫码/JSAPI/H5
    "stripe": ["card", "subscription"],           # 信用卡/订阅
    "unionpay": ["web", "app"],
}


class PaymentSystem:
    """支付系统（内存存储 + 真实API框架 + 模拟兜底）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # 渠道配置：AppID/私钥/证书/回调URL
        self._config: Dict[str, Dict[str, Any]] = {
            ch: {
                "enabled": False,
                "app_id": "",
                "private_key": "",
                "public_key": "",
                "cert_path": "",
                "notify_url": "",
                "return_url": "",
                "merchant_id": "",
                "api_base": "",
            }
            for ch in SUPPORTED_CHANNELS
        }
        self._orders: Dict[str, Dict[str, Any]] = {}
        self._refunds: Dict[str, Dict[str, Any]] = {}
        self._seq = 0

    # ------------------------------------------------------------------ #
    # 工具
    # ------------------------------------------------------------------ #
    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}{time.strftime('%Y%m%d%H%M%S')}-{self._seq:05d}"

    def _now(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def _is_configured(self, channel: str) -> bool:
        cfg = self._config.get(channel, {})
        return bool(cfg.get("enabled") and cfg.get("app_id") and cfg.get("private_key"))

    # ------------------------------------------------------------------ #
    # 支付渠道配置管理
    # ------------------------------------------------------------------ #
    def get_config(self, channel: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            if channel:
                c = dict(self._config.get(channel, {}))
                # 脱敏
                if c.get("private_key"):
                    c["private_key"] = "******(已配置)"
                return {"channel": channel, **c,
                        "configured": self._is_configured(channel),
                        "label": CHANNEL_LABELS.get(channel, channel)}
            items = []
            for ch, c in self._config.items():
                cc = dict(c)
                if cc.get("private_key"):
                    cc["private_key"] = "******(已配置)"
                cc["channel"] = ch
                cc["label"] = CHANNEL_LABELS.get(ch, ch)
                cc["configured"] = self._is_configured(ch)
                items.append(cc)
            return {"channels": items}

    def update_config(self, channel: str, settings: Dict[str, Any]) -> Dict[str, Any]:
        if channel not in self._config:
            raise ValueError(f"不支持的支付渠道: {channel}")
        with self._lock:
            for k, v in settings.items():
                if k in ("enabled", "app_id", "private_key", "public_key",
                         "cert_path", "notify_url", "return_url",
                         "merchant_id", "api_base"):
                    self._config[channel][k] = v
            return self.get_config(channel)

    # ------------------------------------------------------------------ #
    # 下单
    # ------------------------------------------------------------------ #
    def create_order(self, customer_id: str, subject: str, amount: float,
                     channel: str = "alipay", trade_type: str = "face_to_face",
                     description: str = "") -> Dict[str, Any]:
        """创建订单。amount 单位：元（人民币）。"""
        if channel not in SUPPORTED_CHANNELS:
            raise ValueError(f"不支持的支付渠道: {channel}")
        if trade_type not in TRADE_TYPES.get(channel, []):
            raise ValueError(f"渠道 {channel} 不支持 trade_type={trade_type}")
        if amount <= 0:
            raise ValueError("金额必须大于 0")
        with self._lock:
            order_id = self._next_id("ORD")
            order = {
                "order_id": order_id,
                "customer_id": customer_id,
                "subject": subject,
                "description": description,
                "amount": round(float(amount), 2),
                "channel": channel,
                "channel_label": CHANNEL_LABELS[channel],
                "trade_type": trade_type,
                "status": "created",           # created/paid/refunded/closed
                "is_mock": not self._is_configured(channel),
                "pay_url": "",
                "qr_code": "",
                "transaction_id": "",
                "paid_at": "",
                "created_at": self._now(),
            }
            self._orders[order_id] = order
            return self._build_pay(order_id)

    def _build_pay(self, order_id: str) -> Dict[str, Any]:
        """根据订单状态生成支付链接/二维码。"""
        order = self._orders[order_id]
        ch = order["channel"]
        if self._is_configured(ch):
            # 真实 API 框架：这里构造真实请求参数（未在本地发起到渠道的网络请求，
            # 由部署侧用 SDK 完成；明确标注未配置时不会走到这里）。
            order["pay_url"] = self._real_pay_url(order)
            order["qr_code"] = f"https://pay.{ch}.real/qr?order={order_id}"
            order["status"] = "pending"
            order["note"] = "已接入真实支付渠道框架，请在服务端用对应 SDK 完成下单签名。"
        else:
            # 模拟支付兜底
            order["is_mock"] = True
            order["pay_url"] = f"https://mock-pay.local/{ch}/?order={order_id}"
            order["qr_code"] = f"data:mock-qr/{ch}:{order_id}"
            order["status"] = "pending"
            order["note"] = (f"⚠ 当前 {CHANNEL_LABELS[ch]} 未配置 AppID/密钥，"
                             f"已进入【模拟支付】模式（is_mock=True），不会真实扣款。")
        return dict(order)

    def _real_pay_url(self, order: Dict[str, Any]) -> str:
        ch = order["channel"]
        base = self._config[ch].get("api_base") or f"https://api.{ch}.real"
        return f"{base}/pay/create?order={order['order_id']}"

    # ------------------------------------------------------------------ #
    # 支付 + 回调
    # ------------------------------------------------------------------ #
    def pay(self, order_id: str) -> Dict[str, Any]:
        """发起支付（返回支付链接/二维码，前端跳转或扫码）。"""
        with self._lock:
            order = self._orders.get(order_id)
            if not order:
                raise ValueError("订单不存在")
            return self._build_pay(order_id)

    def notify(self, order_id: str, channel: Optional[str] = None,
               out_trade_no: str = "", trade_status: str = "TRADE_SUCCESS",
               total_amount: str = "") -> Dict[str, Any]:
        """异步支付回调（渠道通知）。真实场景由渠道服务器调用。"""
        with self._lock:
            order = self._orders.get(order_id)
            if not order:
                raise ValueError("订单不存在")
            if order["status"] == "paid":
                return {"order_id": order_id, "status": "paid",
                        "message": "订单已支付，回调幂等忽略"}
            if trade_status in ("TRADE_SUCCESS", "SUCCESS", "paid", "succeeded"):
                order["status"] = "paid"
                order["paid_at"] = self._now()
                order["transaction_id"] = out_trade_no or f"TXN{uuid.uuid4().hex[:16]}"
                if total_amount:
                    try:
                        order["amount"] = round(float(total_amount), 2)
                    except (TypeError, ValueError):
                        pass
                return {"order_id": order_id, "status": "paid",
                        "paid_at": order["paid_at"],
                        "transaction_id": order["transaction_id"]}
            order["status"] = "closed"
            return {"order_id": order_id, "status": order["status"],
                    "message": f"渠道返回状态: {trade_status}"}

    def query(self, order_id: str) -> Dict[str, Any]:
        """支付状态查询。"""
        with self._lock:
            order = self._orders.get(order_id)
            if not order:
                raise ValueError("订单不存在")
            return dict(order)

    # ------------------------------------------------------------------ #
    # 退款
    # ------------------------------------------------------------------ #
    def refund(self, order_id: str, amount: Optional[float] = None,
               reason: str = "") -> Dict[str, Any]:
        """全额或部分退款。amount=None 表示全额。"""
        with self._lock:
            order = self._orders.get(order_id)
            if not order:
                raise ValueError("订单不存在")
            if order["status"] != "paid":
                raise ValueError("仅已支付订单可退款")
            refunded = sum(r["refund_amount"] for r in
                           [x for x in self._refunds.values() if x["order_id"] == order_id])
            amount = round(float(amount), 2) if amount else order["amount"]
            if amount <= 0 or amount > order["amount"] - refunded:
                raise ValueError(f"退款金额非法，可退余额 {round(order['amount'] - refunded, 2)}")
            rid = self._next_id("REF")
            rec = {
                "refund_id": rid,
                "order_id": order_id,
                "channel": order["channel"],
                "refund_amount": amount,
                "reason": reason,
                "is_partial": amount < order["amount"],
                "is_mock": order["is_mock"],
                "status": "refunded",
                "refunded_at": self._now(),
            }
            self._refunds[rid] = rec
            if abs((refunded + amount) - order["amount"]) < 0.01:
                order["status"] = "refunded"
            else:
                order["status"] = "partially_refunded"
            return rec

    # ------------------------------------------------------------------ #
    # 对账
    # ------------------------------------------------------------------ #
    def reconciliation(self, channel: Optional[str] = None,
                       date: str = "") -> Dict[str, Any]:
        """支付对账：本地订单与渠道账单核对（内存模拟）。"""
        with self._lock:
            orders = list(self._orders.values())
            if channel:
                orders = [o for o in orders if o["channel"] == channel]
            paid = [o for o in orders if o["status"] in ("paid", "partially_refunded")]
            refunds = [r for r in self._refunds.values()
                       if (not channel or r["channel"] == channel)]
            return {
                "date": date or time.strftime("%Y-%m-%d"),
                "channel": channel or "all",
                "local_order_count": len(orders),
                "paid_order_count": len(paid),
                "local_paid_amount": round(sum(o["amount"] for o in paid), 2),
                "refund_count": len(refunds),
                "refund_amount": round(sum(r["refund_amount"] for r in refunds), 2),
                "net_amount": round(sum(o["amount"] for o in paid)
                                    - sum(r["refund_amount"] for r in refunds), 2),
                "items": [{"order_id": o["order_id"], "amount": o["amount"],
                           "status": o["status"], "channel": o["channel"]}
                          for o in orders],
            }

    # ------------------------------------------------------------------ #
    # 记录 / 统计
    # ------------------------------------------------------------------ #
    def list_orders(self, customer_id: Optional[str] = None,
                    channel: Optional[str] = None,
                    status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._orders.values())
            if customer_id:
                out = [o for o in out if o["customer_id"] == customer_id]
            if channel:
                out = [o for o in out if o["channel"] == channel]
            if status:
                out = [o for o in out if o["status"] == status]
            return sorted(out, key=lambda x: x["created_at"], reverse=True)

    def list_refunds(self, order_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._refunds.values())
            if order_id:
                out = [r for r in out if r["order_id"] == order_id]
            return sorted(out, key=lambda x: x["refunded_at"], reverse=True)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._orders)
            paid = [o for o in self._orders.values() if o["status"] in ("paid", "partially_refunded")]
            by_channel: Dict[str, Dict[str, Any]] = {}
            for o in self._orders.values():
                c = o["channel"]
                by_channel.setdefault(c, {"count": 0, "amount": 0.0, "paid": 0})
                by_channel[c]["count"] += 1
                if o["status"] in ("paid", "partially_refunded"):
                    by_channel[c]["paid"] += 1
                    by_channel[c]["amount"] += o["amount"]
            for c in by_channel:
                by_channel[c]["amount"] = round(by_channel[c]["amount"], 2)
                by_channel[c]["success_rate"] = round(
                    by_channel[c]["paid"] / by_channel[c]["count"] * 100, 2) \
                    if by_channel[c]["count"] else 0.0
            mock_orders = [o for o in self._orders.values() if o["is_mock"]]
            return {
                "total_orders": total,
                "paid_orders": len(paid),
                "total_amount": round(sum(o["amount"] for o in paid), 2),
                "refund_amount": round(sum(r["refund_amount"] for r in self._refunds.values()), 2),
                "success_rate": round(len(paid) / total * 100, 2) if total else 0.0,
                "mock_orders": len(mock_orders),
                "by_channel": by_channel,
                "configured_channels": [c for c in SUPPORTED_CHANNELS
                                        if self._is_configured(c)],
                "unconfigured_channels": [c for c in SUPPORTED_CHANNELS
                                          if not self._is_configured(c)],
            }


_payment: PaymentSystem | None = None


def get_payment_system() -> PaymentSystem:
    global _payment
    if _payment is None:
        _payment = PaymentSystem()
    return _payment
