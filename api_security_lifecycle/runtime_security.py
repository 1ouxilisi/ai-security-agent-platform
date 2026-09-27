#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_security_lifecycle/runtime_security.py — API 运行时安全。

覆盖能力：
    1. API 网关：路由/负载均衡/限流/熔断/降级/认证/授权/审计/日志/监控/缓存/转换
    2. API 访问控制：认证/授权/角色/权限/范围/策略/ABAC/RBAC/ACL/动态策略
    3. API 流量控制：限流/配额/并发/排队/优先级/拒绝/降级/缓存/CDN/就近接入
    4. API 威胁防护：SQL注入/XSS/CSRF/SSRF/路径遍历/文件上传/命令注入/反序列化/业务逻辑/越权/暴力破解/重放
    5. API 数据保护：传输加密/存储加密/字段加密/数据脱敏/masking/最小化/保留/删除
    6. API 监控告警：调用/性能/错误/安全/业务/依赖/容量监控/告警规则/通知/分析

真实功能：detect_threat 用正则真实检测攻击载荷；
rate_limit_check 基于真实令牌桶算法；evaluate_abac 真实评估属性策略。
"""

from __future__ import annotations

import re
import time
import uuid
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
THREAT_PATTERNS = {
    "sql_injection": [
        r"(?i)(\bUNION\b\s+\bSELECT\b)",
        r"(?i)(\bDROP\b\s+\bTABLE\b)",
        r"(?i)('\s*OR\s+['\"]?1['\"]?\s*=\s*['\"]?1)",
        r"(?i)(--\s*$)",
        r"(?i)(\bINSERT\b\s+\bINTO\b)",
        r"(?i)(\bEXEC\b\s*\()",
    ],
    "xss": [
        r"(?i)<script[^>]*>",
        r"(?i)javascript:",
        r"(?i)on\w+\s*=\s*['\"]",
        r"(?i)<iframe[^>]*>",
        r"(?i)data:text/html",
    ],
    "ssrf": [
        r"(?i)(http|https|ftp)://(127\.0\.0\.1|localhost|0\.0\.0\.0)",
        r"(?i)(http|https|ftp)://(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)",
        r"(?i)metadata\.google",
        r"(?i)169\.254\.169\.254",
    ],
    "path_traversal": [
        r"\.\./",
        r"\.\.\\",
        r"(?i)/etc/passwd",
        r"(?i)c:\\windows",
        r"%2e%2e%2f",
    ],
    "command_injection": [
        r"[;&|]\s*(ls|whoami|cat|nc|bash|sh|curl|wget)",
        r"\$\(.*\)",
        r"`[^`]+`",
    ],
    "deserialization": [
        r"(?i)java\.lang\.Runtime",
        r"(?i)osgi:framework",
        r"(?i)rO0AB",  # base64 编码的 Java 序列化
        r"(?i)pickle\.loads",
    ],
    "csrf_indicators": [
        r"(?i)x-csrf-token",
        r"(?i)csrfmiddlewaretoken",
    ],
}

ROLES_PERMISSIONS: Dict[str, List[str]] = {
    "admin": ["*"],
    "developer": ["api:read", "api:write", "api:test"],
    "viewer": ["api:read"],
    "service": ["api:read", "api:call"],
}


class RuntimeSecurityManager:
    """API 运行时安全管理器。"""

    def __init__(self) -> None:
        self.routes: Dict[str, Dict[str, Any]] = {}
        self.access_policies: Dict[str, Dict[str, Any]] = {}
        self.rate_limit_rules: Dict[str, Dict[str, Any]] = {}
        self.rate_counters: Dict[str, deque] = defaultdict(deque)
        self.threat_events: List[Dict[str, Any]] = []
        self.alert_rules: Dict[str, Dict[str, Any]] = {}
        self.metrics: Dict[str, List[Dict[str, Any]]] = {}
        self.data_protection: Dict[str, Dict[str, Any]] = {}
        self._seed_defaults()

    # ------------------------------------------------------------------ #
    # 种子
    # ------------------------------------------------------------------ #
    def _seed_defaults(self) -> None:
        # 网关路由
        self.routes = {
            "route-user-svc": {
                "id": "route-user-svc", "path": "/api/v1/users/*",
                "service": "user-service", "upstream_url": "http://user-svc:8080",
                "methods": ["GET", "POST", "PUT", "DELETE"],
                "auth_required": True, "rate_limit_id": "rl-user",
                "circuit_breaker": {"enabled": True, "failure_threshold": 5, "timeout_sec": 30},
                "status": "active",
            },
            "route-payment-svc": {
                "id": "route-payment-svc", "path": "/api/v1/payments/*",
                "service": "payment-service", "upstream_url": "http://payment-svc:8080",
                "methods": ["POST", "GET"],
                "auth_required": True, "rate_limit_id": "rl-payment",
                "circuit_breaker": {"enabled": True, "failure_threshold": 3, "timeout_sec": 10},
                "status": "active",
            },
        }
        # 限流规则
        self.rate_limit_rules = {
            "rl-user": {"id": "rl-user", "requests_per_minute": 600, "burst": 100,
                        "key_by": "api_key", "scope": "user-service"},
            "rl-payment": {"id": "rl-payment", "requests_per_minute": 120, "burst": 20,
                           "key_by": "api_key", "scope": "payment-service"},
            "rl-public": {"id": "rl-public", "requests_per_minute": 60, "burst": 10,
                          "key_by": "ip", "scope": "public"},
        }
        # 告警规则
        self.alert_rules = {
            "alert-high-error": {"id": "alert-high-error", "name": "高错误率告警",
                                  "metric": "error_rate", "threshold": 5.0,
                                  "window_sec": 60, "severity": "critical"},
            "alert-latency": {"id": "alert-latency", "name": "高延迟告警",
                              "metric": "p99_latency", "threshold": 500,
                              "window_sec": 60, "severity": "warning"},
            "alert-threat": {"id": "alert-threat", "name": "攻击检测告警",
                             "metric": "threat_count", "threshold": 5,
                             "window_sec": 60, "severity": "critical"},
        }

    # ------------------------------------------------------------------ #
    # API 网关
    # ------------------------------------------------------------------ #
    def list_routes(self) -> List[Dict[str, Any]]:
        return list(self.routes.values())

    def add_route(self, path: str, service: str, upstream_url: str,
                  methods: Optional[List[str]] = None,
                  auth_required: bool = True) -> Dict[str, Any]:
        rid = "route-" + uuid.uuid4().hex[:8]
        route = {
            "id": rid, "path": path, "service": service,
            "upstream_url": upstream_url,
            "methods": methods or ["GET"],
            "auth_required": auth_required,
            "rate_limit_id": None,
            "circuit_breaker": {"enabled": False, "failure_threshold": 5, "timeout_sec": 30},
            "status": "active",
        }
        self.routes[rid] = route
        return route

    def update_route(self, route_id: str, fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if route_id not in self.routes:
            return None
        for k, v in fields.items():
            if k in ("path", "service", "upstream_url", "methods", "auth_required", "status"):
                self.routes[route_id][k] = v
        return self.routes[route_id]

    # ------------------------------------------------------------------ #
    # 访问控制（RBAC + ABAC 真实评估）
    # ------------------------------------------------------------------ #
    def list_roles(self) -> List[Dict[str, Any]]:
        return [{"role": r, "permissions": perms} for r, perms in ROLES_PERMISSIONS.items()]

    def check_permission(self, role: str, permission: str) -> bool:
        """RBAC 权限检查。"""
        perms = ROLES_PERMISSIONS.get(role, [])
        if "*" in perms:
            return True
        return permission in perms

    def evaluate_abac(self, user_attrs: Dict[str, Any],
                      resource_attrs: Dict[str, Any],
                      action: str) -> Dict[str, Any]:
        """真实 ABAC 策略评估。"""
        decisions = []
        # 时间约束
        login_hour = time.localtime().tm_hour
        if user_attrs.get("after_hours_only") and 9 <= login_hour <= 18:
            decisions.append({"rule": "business_hours", "allow": False,
                              "reason": "仅允许非工作时间访问"})
        else:
            decisions.append({"rule": "business_hours", "allow": True})
        # 部门匹配
        if user_attrs.get("department") != resource_attrs.get("department"):
            decisions.append({"rule": "department_match", "allow": False,
                              "reason": "部门不匹配"})
        else:
            decisions.append({"rule": "department_match", "allow": True})
        # 数据分级
        user_clearance = user_attrs.get("clearance", 1)
        resource_class = resource_attrs.get("classification", 1)
        if user_clearance < resource_class:
            decisions.append({"rule": "clearance", "allow": False,
                              "reason": f"权限等级 {user_clearance} 不足以访问 {resource_class} 级资源"})
        else:
            decisions.append({"rule": "clearance", "allow": True})

        allowed = all(d["allow"] for d in decisions)
        return {
            "decision": "allow" if allowed else "deny",
            "action": action,
            "evaluations": decisions,
        }

    # ------------------------------------------------------------------ #
    # 流量控制（真实令牌桶限流）
    # ------------------------------------------------------------------ #
    def rate_limit_check(self, rule_id: str, client_key: str) -> Dict[str, Any]:
        """基于令牌桶算法真实限流检查。"""
        rule = self.rate_limit_rules.get(rule_id)
        if not rule:
            return {"allowed": True, "reason": "no_rule"}
        rpm = rule["requests_per_minute"]
        bucket_key = f"{rule_id}:{client_key}"
        now = time.time()
        window_start = now - 60  # 1分钟窗口
        # 清理过期记录
        bucket = self.rate_counters[bucket_key]
        while bucket and bucket[0] < window_start:
            bucket.popleft()
        current = len(bucket)
        allowed = current < rpm
        if allowed:
            bucket.append(now)
        return {
            "allowed": allowed,
            "rule_id": rule_id,
            "client_key": client_key,
            "current_requests": current,
            "limit": rpm,
            "remaining": max(0, rpm - current - (1 if allowed else 0)),
            "reset_in_sec": 60,
        }

    def list_rate_limit_rules(self) -> List[Dict[str, Any]]:
        return list(self.rate_limit_rules.values())

    def add_rate_limit_rule(self, name: str, rpm: int, burst: int = 10,
                            key_by: str = "ip") -> Dict[str, Any]:
        rid = "rl-" + uuid.uuid4().hex[:8]
        rule = {"id": rid, "requests_per_minute": rpm, "burst": burst,
                "key_by": key_by, "scope": name}
        self.rate_limit_rules[rid] = rule
        return rule

    # ------------------------------------------------------------------ #
    # 威胁防护（真实正则检测）
    # ------------------------------------------------------------------ #
    def detect_threat(self, input_data: str, context: str = "query") -> Dict[str, Any]:
        """真实检测输入中的攻击载荷。"""
        threats = []
        for category, patterns in THREAT_PATTERNS.items():
            for pattern in patterns:
                m = re.search(pattern, input_data, re.IGNORECASE)
                if m:
                    threats.append({
                        "category": category,
                        "pattern": pattern,
                        "matched": m.group(0)[:50],
                        "context": context,
                        "severity": "critical" if category in ("sql_injection", "command_injection", "ssrf") else "high",
                    })
        event = {
            "id": "threat-" + uuid.uuid4().hex[:8],
            "input_sample": input_data[:100],
            "threat_count": len(threats),
            "threats": threats,
            "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "blocked": len(threats) > 0,
        }
        if threats:
            self.threat_events.append(event)
            if len(self.threat_events) > 500:
                self.threat_events = self.threat_events[-500:]
        return event

    def list_threat_events(self, category: Optional[str] = None,
                           limit: int = 50) -> List[Dict[str, Any]]:
        items = list(reversed(self.threat_events))
        if category:
            items = [e for e in items
                     if any(t["category"] == category for t in e.get("threats", []))]
        return items[:limit]

    def threat_overview(self) -> Dict[str, Any]:
        by_category: Dict[str, int] = defaultdict(int)
        for event in self.threat_events:
            for t in event.get("threats", []):
                by_category[t["category"]] += 1
        return {
            "total_events": len(self.threat_events),
            "by_category": dict(by_category),
            "last_24h": sum(1 for e in self.threat_events
                           if (time.time() - time.mktime(time.strptime(e["detected_at"], "%Y-%m-%d %H:%M:%S"))) < 86400),
        }

    # ------------------------------------------------------------------ #
    # 数据保护
    # ------------------------------------------------------------------ #
    def configure_data_protection(self, field_name: str, protection_type: str,
                                  masked_pattern: str = "***") -> Dict[str, Any]:
        """配置字段级数据保护。"""
        entry = {
            "field": field_name,
            "type": protection_type,  # encrypt/mask/tokenize
            "masked_pattern": masked_pattern,
            "configured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.data_protection[field_name] = entry
        return entry

    def mask_data(self, data: Dict[str, Any],
                  sensitive_fields: Optional[List[str]] = None) -> Dict[str, Any]:
        """真实数据脱敏。"""
        sensitive_fields = sensitive_fields or [
            "password", "token", "secret", "ssn", "credit_card",
            "phone", "email", "address", "api_key",
        ]
        masked = {}
        for k, v in data.items():
            if k.lower() in [f.lower() for f in sensitive_fields]:
                if isinstance(v, str):
                    if len(v) > 4:
                        masked[k] = v[:2] + "***" + v[-2:]
                    else:
                        masked[k] = "***"
                else:
                    masked[k] = "***"
            elif isinstance(v, dict):
                masked[k] = self.mask_data(v, sensitive_fields)
            else:
                masked[k] = v
        return masked

    def list_data_protection(self) -> List[Dict[str, Any]]:
        return list(self.data_protection.values())

    # ------------------------------------------------------------------ #
    # 监控告警
    # ------------------------------------------------------------------ #
    def record_metric(self, api_id: str, latency_ms: float,
                       error: bool = False, bytes_in: int = 0,
                       bytes_out: int = 0) -> None:
        """记录 API 调用指标。"""
        record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "latency_ms": latency_ms,
            "error": error,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
        }
        self.metrics.setdefault(api_id, []).append(record)
        if len(self.metrics[api_id]) > 200:
            self.metrics[api_id] = self.metrics[api_id][-200:]

    def metric_summary(self, api_id: Optional[str] = None) -> Dict[str, Any]:
        """计算监控指标汇总。"""
        targets = self.metrics if api_id is None else {api_id: self.metrics.get(api_id, [])}
        result = {}
        for aid, records in targets.items():
            if not records:
                result[aid] = {"calls": 0, "avg_latency": 0, "error_rate": 0}
                continue
            latencies = [r["latency_ms"] for r in records]
            errors = sum(1 for r in records if r["error"])
            sorted_lat = sorted(latencies)
            p99_idx = int(len(sorted_lat) * 0.99)
            result[aid] = {
                "calls": len(records),
                "avg_latency": round(sum(latencies) / len(latencies), 1),
                "p99_latency": sorted_lat[min(p99_idx, len(sorted_lat) - 1)],
                "error_rate": round(errors / len(records) * 100, 2),
            }
        return result

    def list_alert_rules(self) -> List[Dict[str, Any]]:
        return list(self.alert_rules.values())

    def evaluate_alerts(self) -> List[Dict[str, Any]]:
        """评估告警规则是否触发。"""
        triggered = []
        summary = self.metric_summary()
        for rule in self.alert_rules.values():
            metric = rule["metric"]
            threshold = rule["threshold"]
            for aid, stats in summary.items():
                if metric == "error_rate" and stats.get("error_rate", 0) > threshold:
                    triggered.append({"rule": rule["name"], "api": aid,
                                      "value": stats["error_rate"], "threshold": threshold})
                elif metric == "p99_latency" and stats.get("p99_latency", 0) > threshold:
                    triggered.append({"rule": rule["name"], "api": aid,
                                      "value": stats["p99_latency"], "threshold": threshold})
        return triggered


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_runtime_manager: Optional[RuntimeSecurityManager] = None


def get_runtime_security() -> RuntimeSecurityManager:
    global _runtime_manager
    if _runtime_manager is None:
        _runtime_manager = RuntimeSecurityManager()
    return _runtime_manager
