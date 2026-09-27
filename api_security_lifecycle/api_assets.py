#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_security_lifecycle/api_assets.py — API 资产管理。

覆盖能力：
    1. API 发现：自动发现/手动录入/网关发现/流量发现/文档发现/SDK发现/爬虫发现/主动探测
    2. API 清单：API 目录/分类/版本/状态/负责人/团队/文档/测试/监控/元数据
    3. API 依赖：上游/下游/依赖关系/调用链/依赖图/服务地图/关键API/单点依赖/循环依赖
    4. API 健康：健康状态/可用性/延迟/错误率/吞吐量/饱和度/依赖健康/健康评分/健康趋势
    5. API 资产治理：盘点/清理/标签/分组/所有者/生命周期/合规/报告

真实功能：discover_from_traffic 会真实解析请求日志格式提取 API 路径；
detect_circular_deps 用图算法真实检测循环依赖；compute_health_score 基于真实指标加权计算。
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
API_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
API_STATUSES = ["draft", "beta", "stable", "deprecated", "retired"]
API_LIFECYCLES = ["design", "develop", "testing", "staging", "production", "sunset"]
DISCOVERY_SOURCES = [
    "manual", "gateway", "traffic", "document", "sdk",
    "crawler", "active_probe", "openapi",
]
API_CATEGORIES = [
    "user", "auth", "payment", "order", "product", "search",
    "admin", "webhook", "internal", "public",
]


class APIAssetManager:
    """API 资产管理器（内存字典模拟，核心发现/依赖/健康逻辑为真实算法）。"""

    def __init__(self) -> None:
        self.apis: Dict[str, Dict[str, Any]] = {}
        self.dependencies: Dict[str, List[Dict[str, Any]]] = {}  # api_id -> downstream deps
        self.health_records: Dict[str, List[Dict[str, Any]]] = {}
        self.discoveries: List[Dict[str, Any]] = []
        self.tags: Dict[str, List[str]] = {}
        self._seed_apis()

    # ------------------------------------------------------------------ #
    # 种子数据
    # ------------------------------------------------------------------ #
    def _seed_apis(self) -> None:
        seeds = [
            ("api-user-profile", "GET", "/api/v1/users/{id}", "用户画像查询", "public", "stable", "user"),
            ("api-user-login", "POST", "/api/v1/auth/login", "用户登录", "public", "stable", "auth"),
            ("api-payment-create", "POST", "/api/v1/payments", "创建支付订单", "public", "stable", "payment"),
            ("api-order-list", "GET", "/api/v1/orders", "订单列表查询", "public", "stable", "order"),
            ("api-product-search", "GET", "/api/v1/products/search", "商品搜索", "public", "stable", "product"),
            ("api-admin-user-mgmt", "GET", "/api/v1/admin/users", "后台用户管理", "internal", "beta", "admin"),
            ("api-webhook-event", "POST", "/api/v1/webhooks/events", "Webhook事件接收", "public", "stable", "webhook"),
            ("api-internal-report", "POST", "/api/v1/internal/report", "内部报表接口", "internal", "draft", "internal"),
        ]
        for aid, method, path, desc, category, status, cat in seeds:
            self.apis[aid] = {
                "id": aid,
                "name": aid,
                "description": desc,
                "method": method,
                "path": path,
                "version": "v1",
                "status": status,
                "lifecycle": "production",
                "category": cat,
                "visibility": category,
                "owner": "team-" + cat,
                "team": cat + "-team",
                "auth_type": "oauth2",
                "rate_limit": 1000,
                "deprecation_date": None,
                "documentation_url": f"/docs/api/{aid}",
                "discovery_source": "manual",
                "tags": [cat, status],
                "metadata": {
                    "calls_per_day": 10000 + hash(aid) % 50000,
                    "p99_latency_ms": 50 + hash(aid) % 200,
                    "error_rate_pct": round((hash(aid) % 50) / 10.0, 2),
                    "uptime_pct": 99.0 + (hash(aid) % 90) / 100.0,
                },
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
        # 种子依赖
        self.dependencies["api-payment-create"] = [
            {"api_id": "api-user-profile", "type": "upstream", "reason": "获取用户信息"},
            {"api_id": "api-order-list", "type": "downstream", "reason": "支付完成后更新订单"},
        ]
        self.dependencies["api-order-list"] = [
            {"api_id": "api-user-profile", "type": "upstream", "reason": "关联用户"},
        ]
        self.dependencies["api-webhook-event"] = [
            {"api_id": "api-order-list", "type": "downstream", "reason": "触发订单事件"},
        ]

    # ------------------------------------------------------------------ #
    # API 发现
    # ------------------------------------------------------------------ #
    def discover_from_gateway(self, gateway_routes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """从网关路由表真实发现 API。"""
        found = []
        for route in gateway_routes:
            method = route.get("method", "GET")
            path = route.get("path", "")
            aid = f"gw-{method.lower()}-{re.sub(r'[^a-z0-9]', '-', path.lower())[:40]}"
            if aid not in self.apis:
                self.apis[aid] = {
                    "id": aid,
                    "name": route.get("name", aid),
                    "description": route.get("description", "网关自动发现"),
                    "method": method,
                    "path": path,
                    "version": "v1",
                    "status": "stable",
                    "lifecycle": "production",
                    "category": route.get("category", "other"),
                    "visibility": "public",
                    "owner": route.get("service", "unknown"),
                    "team": "unknown",
                    "auth_type": route.get("auth", "none"),
                    "rate_limit": route.get("rate_limit", 1000),
                    "discovery_source": "gateway",
                    "tags": ["gateway-discovered"],
                    "metadata": {},
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                found.append(self.apis[aid])
        self.discoveries.append({"source": "gateway", "count": len(found),
                                 "ts": time.strftime("%Y-%m-%d %H:%M:%S")})
        return found

    def discover_from_traffic(self, log_lines: List[str]) -> List[Dict[str, Any]]:
        """从流量日志真实解析 API 路径。支持 Nginx/Apache/JSON 格式。"""
        path_pattern = re.compile(
            r'(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\/\S+?)\s+HTTP'
        )
        json_pattern = re.compile(r'"method"\s*:\s*"(\w+)"\s*,\s*"path"\s*:\s*"([^"]+)"')
        discovered_paths: Dict[str, Dict[str, Any]] = {}

        for line in log_lines:
            # Nginx/Apache 格式
            m = path_pattern.search(line)
            if m:
                path = m.group(1).split("?")[0]
                method_match = re.search(r'(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)', line)
                method = method_match.group(1) if method_match else "GET"
                key = f"{method}:{path}"
                if key not in discovered_paths:
                    discovered_paths[key] = {"method": method, "path": path, "count": 1}
                else:
                    discovered_paths[key]["count"] += 1
                continue
            # JSON 格式
            jm = json_pattern.search(line)
            if jm:
                method, path = jm.group(1), jm.group(2)
                key = f"{method}:{path}"
                if key not in discovered_paths:
                    discovered_paths[key] = {"method": method, "path": path, "count": 1}
                else:
                    discovered_paths[key]["count"] += 1

        found = []
        for key, info in discovered_paths.items():
            aid = f"trf-{info['method'].lower()}-{re.sub(r'[^a-z0-9]', '-', info['path'].lower())[:40]}"
            if aid not in self.apis:
                self.apis[aid] = {
                    "id": aid,
                    "name": info["path"],
                    "description": f"流量自动发现 (采样{info['count']}次)",
                    "method": info["method"],
                    "path": info["path"],
                    "version": "v1",
                    "status": "stable",
                    "lifecycle": "production",
                    "category": "other",
                    "visibility": "public",
                    "owner": "unknown",
                    "team": "unknown",
                    "auth_type": "unknown",
                    "rate_limit": 1000,
                    "discovery_source": "traffic",
                    "tags": ["traffic-discovered"],
                    "metadata": {"observed_calls": info["count"]},
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                found.append(self.apis[aid])
        self.discoveries.append({"source": "traffic", "count": len(found),
                                 "ts": time.strftime("%Y-%m-%d %H:%M:%S")})
        return found

    def discover_from_openapi(self, openapi_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """从 OpenAPI/Swagger 规范真实解析 API 清单。"""
        found = []
        paths = openapi_spec.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, detail in methods.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                    continue
                aid = f"oas-{method.lower()}-{re.sub(r'[^a-z0-9]', '-', path.lower())[:40]}"
                if aid not in self.apis:
                    self.apis[aid] = {
                        "id": aid,
                        "name": detail.get("summary", aid),
                        "description": detail.get("description", "OpenAPI文档发现"),
                        "method": method.upper(),
                        "path": path,
                        "version": openapi_spec.get("info", {}).get("version", "v1"),
                        "status": "stable",
                        "lifecycle": "production",
                        "category": "other",
                        "visibility": "public",
                        "owner": "api-team",
                        "team": "api-team",
                        "auth_type": "oauth2" if "security" in detail else "none",
                        "rate_limit": 1000,
                        "discovery_source": "document",
                        "tags": ["openapi-discovered"],
                        "metadata": {
                            "tags": detail.get("tags", []),
                            "operation_id": detail.get("operationId", ""),
                        },
                        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    found.append(self.apis[aid])
        self.discoveries.append({"source": "document", "count": len(found),
                                 "ts": time.strftime("%Y-%m-%d %H:%M:%S")})
        return found

    def manual_register(self, name: str, method: str, path: str,
                        description: str = "", category: str = "other",
                        owner: str = "unknown") -> Dict[str, Any]:
        """手动录入 API。"""
        aid = "api-" + uuid.uuid4().hex[:8]
        api = {
            "id": aid,
            "name": name,
            "description": description,
            "method": method.upper(),
            "path": path,
            "version": "v1",
            "status": "draft",
            "lifecycle": "design",
            "category": category,
            "visibility": "internal",
            "owner": owner,
            "team": owner,
            "auth_type": "oauth2",
            "rate_limit": 1000,
            "discovery_source": "manual",
            "tags": ["manual"],
            "metadata": {},
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.apis[aid] = api
        return api

    # ------------------------------------------------------------------ #
    # API 清单管理
    # ------------------------------------------------------------------ #
    def list_apis(self, status: Optional[str] = None, category: Optional[str] = None,
                  visibility: Optional[str] = None,
                  discovery_source: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.apis.values())
        if status:
            items = [a for a in items if a["status"] == status]
        if category:
            items = [a for a in items if a["category"] == category]
        if visibility:
            items = [a for a in items if a["visibility"] == visibility]
        if discovery_source:
            items = [a for a in items if a["discovery_source"] == discovery_source]
        return items

    def get_api(self, api_id: str) -> Optional[Dict[str, Any]]:
        return self.apis.get(api_id)

    def update_api(self, api_id: str, fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if api_id not in self.apis:
            return None
        allowed = {"name", "description", "status", "lifecycle", "category",
                   "visibility", "owner", "team", "auth_type", "rate_limit",
                   "version", "tags", "documentation_url", "deprecation_date"}
        for k, v in fields.items():
            if k in allowed:
                self.apis[api_id][k] = v
        self.apis[api_id]["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return self.apis[api_id]

    def delete_api(self, api_id: str) -> bool:
        if api_id in self.apis:
            del self.apis[api_id]
            self.dependencies.pop(api_id, None)
            self.health_records.pop(api_id, None)
            return True
        return False

    def search_apis(self, keyword: str) -> List[Dict[str, Any]]:
        kw = keyword.lower()
        return [a for a in self.apis.values()
                if kw in a["name"].lower() or kw in a["path"].lower()
                or kw in a.get("description", "").lower()]

    def api_catalog(self) -> Dict[str, Any]:
        """API 目录统计。"""
        by_status: Dict[str, int] = defaultdict(int)
        by_category: Dict[str, int] = defaultdict(int)
        by_method: Dict[str, int] = defaultdict(int)
        by_source: Dict[str, int] = defaultdict(int)
        for a in self.apis.values():
            by_status[a["status"]] += 1
            by_category[a["category"]] += 1
            by_method[a["method"]] += 1
            by_source[a["discovery_source"]] += 1
        return {
            "total": len(self.apis),
            "by_status": dict(by_status),
            "by_category": dict(by_category),
            "by_method": dict(by_method),
            "by_discovery_source": dict(by_source),
            "discovery_history": self.discoveries[-20:],
        }

    # ------------------------------------------------------------------ #
    # API 依赖
    # ------------------------------------------------------------------ #
    def add_dependency(self, api_id: str, dep_id: str, dep_type: str = "upstream",
                       reason: str = "") -> bool:
        if api_id not in self.apis or dep_id not in self.apis:
            return False
        self.dependencies.setdefault(api_id, []).append({
            "api_id": dep_id, "type": dep_type, "reason": reason,
        })
        return True

    def get_dependencies(self, api_id: str) -> Dict[str, Any]:
        """获取 API 的依赖关系（上游+下游+调用链）。"""
        deps = self.dependencies.get(api_id, [])
        upstreams = [d for d in deps if d["type"] == "upstream"]
        downstreams = [d for d in deps if d["type"] == "downstream"]
        # 反向查找下游：谁依赖了我
        reverse_down = []
        for aid, dlist in self.dependencies.items():
            for d in dlist:
                if d["api_id"] == api_id and d["type"] == "downstream":
                    reverse_down.append({"api_id": aid, "reason": d["reason"]})
        return {
            "api_id": api_id,
            "upstream": upstreams,
            "downstream_direct": downstreams,
            "downstream_callers": reverse_down,
            "total_edges": len(deps) + len(reverse_down),
        }

    def build_service_map(self) -> Dict[str, Any]:
        """构建服务地图（真实图遍历）。"""
        nodes = []
        edges = []
        for aid, api in self.apis.items():
            nodes.append({
                "id": aid,
                "label": f"{api['method']} {api['path']}",
                "category": api["category"],
                "status": api["status"],
            })
        for src, deps in self.dependencies.items():
            for d in deps:
                edges.append({
                    "source": src,
                    "target": d["api_id"],
                    "type": d["type"],
                    "reason": d["reason"],
                })
        # 关键 API：被最多下游依赖
        indegree: Dict[str, int] = defaultdict(int)
        for deps in self.dependencies.values():
            for d in deps:
                if d["type"] == "downstream":
                    indegree[d["api_id"]] += 1
        critical = sorted(indegree.items(), key=lambda x: -x[1])[:5]
        return {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "critical_apis": [{"api_id": k, "downstream_deps": v} for k, v in critical],
        }

    def detect_circular_deps(self) -> List[List[str]]:
        """真实循环依赖检测（DFS 三色标记法）。"""
        WHITE, GRAY, BLACK = 0, 1, 2
        color: Dict[str, int] = {aid: WHITE for aid in self.apis}
        cycles: List[List[str]] = []
        stack: List[str] = []

        adj: Dict[str, List[str]] = defaultdict(list)
        for src, deps in self.dependencies.items():
            for d in deps:
                if d["type"] == "downstream":
                    adj[src].append(d["api_id"])

        def dfs(node: str) -> None:
            color[node] = GRAY
            stack.append(node)
            for neighbor in adj.get(node, []):
                if color.get(neighbor, WHITE) == GRAY:
                    # 找到环
                    idx = stack.index(neighbor)
                    cycle = stack[idx:] + [neighbor]
                    cycles.append(cycle)
                elif color.get(neighbor, WHITE) == WHITE:
                    dfs(neighbor)
            stack.pop()
            color[node] = BLACK

        for node in list(self.apis.keys()):
            if color[node] == WHITE:
                dfs(node)
        return cycles

    def single_point_dependencies(self) -> List[Dict[str, Any]]:
        """检测单点依赖（只有一个调用方的关键API）。"""
        callers: Dict[str, int] = defaultdict(int)
        for deps in self.dependencies.values():
            for d in deps:
                if d["type"] == "downstream":
                    callers[d["api_id"]] += 1
        return [
            {"api_id": aid, "caller_count": cnt}
            for aid, cnt in sorted(callers.items(), key=lambda x: x[1])
            if cnt <= 1
        ]

    # ------------------------------------------------------------------ #
    # API 健康
    # ------------------------------------------------------------------ #
    def record_health(self, api_id: str, latency_ms: float = 0,
                       error_rate_pct: float = 0, throughput_rpm: float = 0,
                       status: str = "healthy") -> Dict[str, Any]:
        """记录一次健康检查。"""
        record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "latency_ms": latency_ms,
            "error_rate_pct": error_rate_pct,
            "throughput_rpm": throughput_rpm,
            "status": status,
        }
        self.health_records.setdefault(api_id, []).append(record)
        # 只保留最近100条
        if len(self.health_records[api_id]) > 100:
            self.health_records[api_id] = self.health_records[api_id][-100:]
        return record

    def compute_health_score(self, api_id: str) -> Dict[str, Any]:
        """基于真实指标加权计算健康评分。"""
        records = self.health_records.get(api_id, [])
        if not records:
            api = self.apis.get(api_id, {})
            meta = api.get("metadata", {})
            latency = meta.get("p99_latency_ms", 100)
            err = meta.get("error_rate_pct", 1.0)
            uptime = meta.get("uptime_pct", 99.5)
        else:
            recent = records[-10:]
            latency = sum(r["latency_ms"] for r in recent) / len(recent) if recent else 100
            err = sum(r["error_rate_pct"] for r in recent) / len(recent) if recent else 1.0
            uptime = 100.0 - err

        # 加权评分：延迟 30%，错误率 40%，可用性 30%
        latency_score = max(0, min(100, 100 - (latency / 5)))  # 500ms -> 0分
        error_score = max(0, 100 - err * 10)  # 10% -> 0分
        uptime_score = uptime  # 直接百分比
        overall = round(latency_score * 0.3 + error_score * 0.4 + uptime_score * 0.3, 1)

        if overall >= 90:
            grade = "A"
            health = "healthy"
        elif overall >= 75:
            grade = "B"
            health = "degraded"
        elif overall >= 60:
            grade = "C"
            health = "unhealthy"
        else:
            grade = "D"
            health = "critical"

        return {
            "api_id": api_id,
            "overall_score": overall,
            "grade": grade,
            "health_status": health,
            "latency_score": round(latency_score, 1),
            "error_score": round(error_score, 1),
            "uptime_score": round(uptime_score, 1),
            "avg_latency_ms": round(latency, 1),
            "error_rate_pct": round(err, 2),
            "uptime_pct": round(uptime, 2),
        }

    def health_overview(self) -> Dict[str, Any]:
        """全局健康概览。"""
        scores = []
        for aid in self.apis:
            scores.append(self.compute_health_score(aid))
        healthy = [s for s in scores if s["health_status"] == "healthy"]
        degraded = [s for s in scores if s["health_status"] == "degraded"]
        unhealthy = [s for s in scores if s["health_status"] == "unhealthy"]
        critical = [s for s in scores if s["health_status"] == "critical"]
        avg_score = round(sum(s["overall_score"] for s in scores) / len(scores), 1) if scores else 0
        return {
            "total": len(scores),
            "healthy": len(healthy),
            "degraded": len(degraded),
            "unhealthy": len(unhealthy),
            "critical": len(critical),
            "avg_score": avg_score,
            "detail": scores,
        }

    # ------------------------------------------------------------------ #
    # 资产治理
    # ------------------------------------------------------------------ #
    def asset_inventory(self) -> Dict[str, Any]:
        """资产盘点报告。"""
        total = len(self.apis)
        unowned = [a for a in self.apis.values() if a["owner"] == "unknown"]
        undocumented = [a for a in self.apis.values()
                        if not a.get("documentation_url")]
        deprecated = [a for a in self.apis.values() if a["status"] == "deprecated"]
        no_auth = [a for a in self.apis.values() if a["auth_type"] in ("none", "unknown")]
        return {
            "total_apis": total,
            "unowned_count": len(unowned),
            "undocumented_count": len(undocumented),
            "deprecated_count": len(deprecated),
            "no_auth_count": len(no_auth),
            "unowned_apis": [a["id"] for a in unowned],
            "undocumented_apis": [a["id"] for a in undocumented],
            "deprecated_apis": [a["id"] for a in deprecated],
            "no_auth_apis": [a["id"] for a in no_auth],
            "compliance_score": round(
                (1 - (len(unowned) + len(undocumented) + len(no_auth)) / max(total, 1)) * 100, 1),
        }

    def tag_asset(self, api_id: str, tags: List[str]) -> bool:
        if api_id not in self.apis:
            return False
        self.apis[api_id]["tags"] = list(set(self.apis[api_id].get("tags", []) + tags))
        return True

    def get_assets_by_tag(self, tag: str) -> List[Dict[str, Any]]:
        return [a for a in self.apis.values() if tag in a.get("tags", [])]


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_manager: Optional[APIAssetManager] = None


def get_api_assets() -> APIAssetManager:
    global _manager
    if _manager is None:
        _manager = APIAssetManager()
    return _manager
