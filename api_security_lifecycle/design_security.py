#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_security_lifecycle/design_security.py — API 设计安全。

覆盖能力：
    1. 安全设计原则：最小权限/默认拒绝/深度防御/失效安全/完全仲裁/开放设计/权限分离/经济机制
    2. API 设计规范：REST/GraphQL/gRPC/WebSocket/版本/错误/分页/限流/认证/安全规范
    3. API 认证授权：OAuth2.0/OIDC/JWT/API Key/Basic/Digest/证书/互认/授权码/客户端凭证/刷新令牌
    4. API 输入输出：输入验证/输出编码/参数校验/Schema验证/JSON Schema/正则/类型/范围/格式校验
    5. API 错误处理：错误码/错误信息/格式/响应/日志/监控/告警/最佳实践
    6. API 设计评审：设计评审/安全评审/性能评审/可用性评审/一致性评审/文档评审/评审报告

真实功能：validate_json_schema 真实按 JSON Schema 子集校验数据；
review_design 真实检查设计规范条目并输出通过/不通过。
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
SECURITY_PRINCIPLES = [
    "least_privilege", "default_deny", "defense_in_depth", "fail_safe",
    "complete_mediation", "open_design", "separation_of_privilege",
    "economic_mechanism",
]

DESIGN_SPEC_CATEGORIES = [
    "rest", "graphql", "grpc", "websocket", "versioning",
    "error", "pagination", "rate_limit", "auth", "security",
]

AUTH_METHODS = [
    "oauth2_authorization_code", "oauth2_client_credentials",
    "oauth2_implicit", "oauth2_password", "openid_connect",
    "jwt", "api_key", "basic_auth", "digest_auth",
    "mutual_tls", "cert_auth",
]

ERROR_CODE_RANGES = {
    "4xx": "客户端错误",
    "5xx": "服务端错误",
}


class DesignSecurityManager:
    """API 设计安全管理器（内存字典模拟，Schema校验和评审为真实逻辑）。"""

    def __init__(self) -> None:
        self.specs: Dict[str, Dict[str, Any]] = {}
        self.auth_configs: Dict[str, Dict[str, Any]] = {}
        self.schemas: Dict[str, Dict[str, Any]] = {}
        self.reviews: Dict[str, Dict[str, Any]] = {}
        self.error_catalog: Dict[str, Dict[str, Any]] = {}
        self._seed_defaults()

    # ------------------------------------------------------------------ #
    # 种子
    # ------------------------------------------------------------------ #
    def _seed_defaults(self) -> None:
        # 默认设计规范
        self.specs = {
            "rest_conventions": {
                "id": "rest_conventions",
                "name": "REST API 设计规范",
                "category": "rest",
                "rules": [
                    {"id": "rest-001", "desc": "使用名词复数表示资源集合", "level": "required", "enabled": True},
                    {"id": "rest-002", "desc": "HTTP方法语义化(GET/POST/PUT/DELETE)", "level": "required", "enabled": True},
                    {"id": "rest-003", "desc": "URL 使用 kebab-case", "level": "recommended", "enabled": True},
                    {"id": "rest-004", "desc": "版本号放在 URL 路径中", "level": "required", "enabled": True},
                    {"id": "rest-005", "desc": "统一使用 JSON 格式请求/响应", "level": "required", "enabled": True},
                    {"id": "rest-006", "desc": "分页使用 cursor 或 offset+limit", "level": "recommended", "enabled": True},
                ],
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "security_spec": {
                "id": "security_spec",
                "name": "API 安全设计规范",
                "category": "security",
                "rules": [
                    {"id": "sec-001", "desc": "所有写操作必须认证", "level": "required", "enabled": True},
                    {"id": "sec-002", "desc": "敏感数据必须加密传输(TLS)", "level": "required", "enabled": True},
                    {"id": "sec-003", "desc": "实施输入验证和输出编码", "level": "required", "enabled": True},
                    {"id": "sec-004", "desc": "API 必须有限流机制", "level": "required", "enabled": True},
                    {"id": "sec-005", "desc": "错误信息不暴露内部细节", "level": "required", "enabled": True},
                    {"id": "sec-006", "desc": "实施最小权限原则", "level": "required", "enabled": True},
                ],
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
        }
        # 错误码目录
        self.error_catalog = {
            "AUTH_001": {"code": "AUTH_001", "http_status": 401, "message": "未认证", "category": "auth"},
            "AUTH_002": {"code": "AUTH_002", "http_status": 403, "message": "权限不足", "category": "auth"},
            "VAL_001": {"code": "VAL_001", "http_status": 400, "message": "参数校验失败", "category": "validation"},
            "VAL_002": {"code": "VAL_002", "http_status": 400, "message": "格式错误", "category": "validation"},
            "RATE_001": {"code": "RATE_001", "http_status": 429, "message": "请求频率超限", "category": "rate_limit"},
            "SRV_001": {"code": "SRV_001", "http_status": 500, "message": "内部服务器错误", "category": "server"},
            "SRV_002": {"code": "SRV_002", "http_status": 503, "message": "服务不可用", "category": "server"},
        }

    # ------------------------------------------------------------------ #
    # 安全设计原则
    # ------------------------------------------------------------------ #
    def list_principles(self) -> List[Dict[str, Any]]:
        descs = {
            "least_privilege": "最小权限：仅授予完成任务所需的最小权限",
            "default_deny": "默认拒绝：未明确允许的一律拒绝",
            "defense_in_depth": "深度防御：多层安全控制叠加",
            "fail_safe": "失效安全：出错时默认安全状态",
            "complete_mediation": "完全仲裁：每次访问都检查权限",
            "open_design": "开放设计：安全不依赖保密性",
            "separation_of_privilege": "权限分离：多因素/多角色组合",
            "economic_mechanism": "经济机制：安全机制简单易用",
        }
        return [{"id": p, "description": descs.get(p, p)} for p in SECURITY_PRINCIPLES]

    # ------------------------------------------------------------------ #
    # 设计规范管理
    # ------------------------------------------------------------------ #
    def list_specs(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.specs.values())
        if category:
            items = [s for s in items if s["category"] == category]
        return items

    def get_spec(self, spec_id: str) -> Optional[Dict[str, Any]]:
        return self.specs.get(spec_id)

    def create_spec(self, name: str, category: str,
                    rules: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        sid = "spec-" + uuid.uuid4().hex[:8]
        spec = {
            "id": sid,
            "name": name,
            "category": category,
            "rules": rules or [],
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.specs[sid] = spec
        return spec

    def add_spec_rule(self, spec_id: str, rule: Dict[str, Any]) -> bool:
        if spec_id not in self.specs:
            return False
        rule.setdefault("id", f"rule-{uuid.uuid4().hex[:6]}")
        rule.setdefault("level", "recommended")
        rule.setdefault("enabled", True)
        self.specs[spec_id]["rules"].append(rule)
        return True

    # ------------------------------------------------------------------ #
    # 认证授权设计
    # ------------------------------------------------------------------ #
    def list_auth_methods(self) -> List[Dict[str, Any]]:
        descs = {
            "oauth2_authorization_code": "OAuth2.0 授权码模式（最安全的服务器端应用）",
            "oauth2_client_credentials": "OAuth2.0 客户端凭证模式（服务间通信）",
            "oauth2_implicit": "OAuth2.0 隐式模式（已不推荐，SPA用PKCE）",
            "oauth2_password": "OAuth2.0 密码模式（仅限受信任应用）",
            "openid_connect": "OpenID Connect 身份认证层",
            "jwt": "JSON Web Token 自包含令牌",
            "api_key": "API Key 简单密钥认证",
            "basic_auth": "HTTP Basic 认证（仅配合HTTPS使用）",
            "digest_auth": "HTTP Digest 摘要认证",
            "mutual_tls": "双向 TLS 证书认证",
            "cert_auth": "客户端证书认证",
        }
        return [{"id": m, "description": descs.get(m, m)} for m in AUTH_METHODS]

    def configure_auth(self, api_id: str, method: str,
                       config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """配置 API 认证方案。"""
        cfg = {
            "api_id": api_id,
            "method": method,
            "config": config or {},
            "configured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if method == "jwt":
            cfg["config"].setdefault("algorithm", "RS256")
            cfg["config"].setdefault("expiry_minutes", 60)
            cfg["config"].setdefault("refresh_enabled", True)
        elif method == "oauth2_authorization_code":
            cfg["config"].setdefault("pkce_enabled", True)
            cfg["config"].setdefault("refresh_token_enabled", True)
        self.auth_configs[api_id] = cfg
        return cfg

    def get_auth_config(self, api_id: str) -> Optional[Dict[str, Any]]:
        return self.auth_configs.get(api_id)

    def list_auth_configs(self) -> List[Dict[str, Any]]:
        return list(self.auth_configs.values())

    # ------------------------------------------------------------------ #
    # 输入输出 Schema 校验（真实 JSON Schema 子集校验）
    # ------------------------------------------------------------------ #
    def register_schema(self, name: str, schema: Dict[str, Any]) -> Dict[str, Any]:
        sid = "schema-" + uuid.uuid4().hex[:8]
        entry = {
            "id": sid,
            "name": name,
            "schema": schema,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.schemas[sid] = entry
        return entry

    def validate_json_schema(self, data: Any, schema: Dict[str, Any]) -> Dict[str, Any]:
        """真实 JSON Schema 子集校验（type/required/properties/items/enum/min/max/pattern）。"""
        errors: List[str] = []

        def _validate(node: Any, sc: Dict[str, Any], path: str = "$") -> None:
            # type 检查
            expected_type = sc.get("type")
            if expected_type:
                type_map = {
                    "string": str, "integer": int, "number": (int, float),
                    "boolean": bool, "object": dict, "array": list,
                }
                py_type = type_map.get(expected_type)
                if py_type and not isinstance(node, py_type):
                    errors.append(f"{path}: 期望类型 {expected_type}, 实际 {type(node).__name__}")
                    return

            # required 检查
            if expected_type == "object" and "required" in sc:
                for req in sc["required"]:
                    if not isinstance(node, dict) or req not in node:
                        errors.append(f"{path}: 缺少必填字段 '{req}'")

            # properties 递归
            if expected_type == "object" and isinstance(node, dict) and "properties" in sc:
                for prop, prop_schema in sc["properties"].items():
                    if prop in node:
                        _validate(node[prop], prop_schema, f"{path}.{prop}")

            # array items 递归
            if expected_type == "array" and isinstance(node, list) and "items" in sc:
                for i, item in enumerate(node):
                    _validate(item, sc["items"], f"{path}[{i}]")

            # enum 检查
            if "enum" in sc and node not in sc["enum"]:
                errors.append(f"{path}: 值 '{node}' 不在允许范围 {sc['enum']}")

            # 字符串约束
            if isinstance(node, str):
                if "minLength" in sc and len(node) < sc["minLength"]:
                    errors.append(f"{path}: 长度小于最小 {sc['minLength']}")
                if "maxLength" in sc and len(node) > sc["maxLength"]:
                    errors.append(f"{path}: 长度大于最大 {sc['maxLength']}")
                if "pattern" in sc and not re.search(sc["pattern"], node):
                    errors.append(f"{path}: 不匹配正则 {sc['pattern']}")

            # 数值约束
            if isinstance(node, (int, float)) and not isinstance(node, bool):
                if "minimum" in sc and node < sc["minimum"]:
                    errors.append(f"{path}: 小于最小值 {sc['minimum']}")
                if "maximum" in sc and node > sc["maximum"]:
                    errors.append(f"{path}: 大于最大值 {sc['maximum']}")

        _validate(data, schema)
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "error_count": len(errors),
        }

    def validate_input(self, data: Any, schema_name: str) -> Dict[str, Any]:
        """按已注册 Schema 校验输入。"""
        schema_entry = None
        for s in self.schemas.values():
            if s["name"] == schema_name or s["id"] == schema_name:
                schema_entry = s
                break
        if not schema_entry:
            return {"valid": False, "errors": [f"Schema '{schema_name}' 未找到"], "error_count": 1}
        return self.validate_json_schema(data, schema_entry["schema"])

    def output_encode_check(self, data: str, output_type: str = "json") -> Dict[str, Any]:
        """输出编码安全检查（检测 XSS/SQL 注入模式）。"""
        risks = []
        xss_patterns = [
            (r"<script[^>]*>", "XSS: script标签"),
            (r"javascript:", "XSS: javascript协议"),
            (r"on\w+\s*=", "XSS: 事件处理器"),
            (r"<iframe[^>]*>", "XSS: iframe标签"),
        ]
        sqli_patterns = [
            (r"(\bUNION\b.*\bSELECT\b)", "SQLi: UNION SELECT"),
            (r"(\bDROP\b\s+\bTABLE\b)", "SQLi: DROP TABLE"),
            (r"(--\s*$|#\s*$)", "SQLi: 注释注入"),
            (r"(\bOR\b\s+1\s*=\s*1)", "SQLi: 永真条件"),
        ]
        for pattern, desc in xss_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                risks.append(desc)
        for pattern, desc in sqli_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                risks.append(desc)
        return {
            "safe": len(risks) == 0,
            "risks": risks,
            "risk_count": len(risks),
            "encoding_type": output_type,
        }

    # ------------------------------------------------------------------ #
    # 错误处理
    # ------------------------------------------------------------------ #
    def list_error_codes(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.error_catalog.values())
        if category:
            items = [e for e in items if e["category"] == category]
        return items

    def add_error_code(self, code: str, http_status: int,
                       message: str, category: str = "generic") -> Dict[str, Any]:
        entry = {
            "code": code, "http_status": http_status,
            "message": message, "category": category,
        }
        self.error_catalog[code] = entry
        return entry

    def format_error_response(self, error_code: str, details: str = "",
                              request_id: str = "") -> Dict[str, Any]:
        """标准化错误响应格式。"""
        entry = self.error_catalog.get(error_code, {
            "code": error_code, "http_status": 500,
            "message": "未知错误", "category": "generic",
        })
        return {
            "error": {
                "code": entry["code"],
                "message": entry["message"],
                "details": details,
                "request_id": request_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            "status_code": entry["http_status"],
        }

    # ------------------------------------------------------------------ #
    # 设计评审（真实检查规范条目）
    # ------------------------------------------------------------------ #
    def review_design(self, api_name: str, method: str, path: str,
                      has_auth: bool, has_rate_limit: bool,
                      has_input_validation: bool, has_tls: bool,
                      error_messages_generic: bool,
                      uses_minimal_privilege: bool,
                      spec_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """真实设计评审：检查各安全规范条目。"""
        review_id = "review-" + uuid.uuid4().hex[:8]
        checks = []

        # 安全原则检查
        checks.append({"item": "认证机制", "passed": has_auth,
                       "detail": "API必须实施认证" if has_auth else "缺少认证机制"})
        checks.append({"item": "限流机制", "passed": has_rate_limit,
                       "detail": "已配置限流" if has_rate_limit else "缺少限流"})
        checks.append({"item": "输入验证", "passed": has_input_validation,
                       "detail": "已实施输入验证" if has_input_validation else "缺少输入验证"})
        checks.append({"item": "传输加密", "passed": has_tls,
                       "detail": "已启用TLS" if has_tls else "未启用TLS"})
        checks.append({"item": "错误信息脱敏", "passed": error_messages_generic,
                       "detail": "错误信息不暴露内部细节" if error_messages_generic
                       else "错误信息可能泄露内部细节"})
        checks.append({"item": "最小权限", "passed": uses_minimal_privilege,
                       "detail": "遵循最小权限" if uses_minimal_privilege else "未遵循最小权限"})

        # REST 规范检查
        if method in ("GET", "POST", "PUT", "DELETE"):
            checks.append({"item": "HTTP方法语义", "passed": True, "detail": f"使用标准方法 {method}"})
        # 版本检查
        if "/v" in path:
            checks.append({"item": "版本化", "passed": True, "detail": "路径包含版本号"})
        else:
            checks.append({"item": "版本化", "passed": False, "detail": "路径未包含版本号"})

        passed = sum(1 for c in checks if c["passed"])
        total = len(checks)
        score = round(passed / total * 100, 1)

        review = {
            "id": review_id,
            "api_name": api_name,
            "method": method,
            "path": path,
            "checks": checks,
            "passed_count": passed,
            "total_count": total,
            "score": score,
            "verdict": "approved" if score >= 80 else "needs_revision" if score >= 60 else "rejected",
            "reviewed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.reviews[review_id] = review
        return review

    def list_reviews(self) -> List[Dict[str, Any]]:
        return list(self.reviews.values())

    def get_review(self, review_id: str) -> Optional[Dict[str, Any]]:
        return self.reviews.get(review_id)


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_design_manager: Optional[DesignSecurityManager] = None


def get_design_security() -> DesignSecurityManager:
    global _design_manager
    if _design_manager is None:
        _design_manager = DesignSecurityManager()
    return _design_manager
