#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
openapi_parser.py — OpenAPI 3.0/3.1 规范解析器。

支持 JSON 与 YAML 格式；YAML 解析依赖可选的 PyYAML 包，
不可用时仅支持 JSON 格式并给出明确提示。

设计定位：
    - 仅做规范解析、端点/参数/认证方式提取与分类，不主动发起对目标的扫描请求。
    - 本模块仅用于授权的安全评估与合规检查。
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional


# 可选 YAML 支持
try:
    import yaml  # type: ignore
    _YAML_AVAILABLE = True
except Exception:  # pragma: no cover
    yaml = None  # type: ignore
    _YAML_AVAILABLE = False


_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}


class OpenAPIParser:
    """OpenAPI 规范解析器。"""

    def __init__(self) -> None:
        self.spec: Dict[str, Any] = {}
        self._parsed: Dict[str, Any] = {}
        self._errors: List[str] = []

    # ------------------------------------------------------------------ #
    # 加载入口
    # ------------------------------------------------------------------ #
    def parse_from_url(self, url: str) -> Dict[str, Any]:
        """从 URL 下载并解析 OpenAPI 规范（urllib，超时 10 秒）。"""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "APISecurityParser/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            ct = (resp.headers.get("Content-Type") or "").lower()
            content_type = "yaml" if "yaml" in ct or "yml" in ct else "json"
            return self.parse_from_string(raw, content_type)
        except Exception as e:
            return {"valid": False, "errors": [f"URL下载失败: {e}"], "spec": {}}

    def parse_from_file(self, file_path: str) -> Dict[str, Any]:
        """从本地文件解析 OpenAPI 规范。"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            content_type = "yaml" if file_path.lower().endswith((".yaml", ".yml")) else "json"
            return self.parse_from_string(content, content_type)
        except Exception as e:
            return {"valid": False, "errors": [f"文件读取失败: {e}"], "spec": {}}

    def parse_from_string(self, content: str, content_type: str = "json") -> Dict[str, Any]:
        """从字符串解析 OpenAPI 规范（json / yaml）。"""
        self._errors = []
        try:
            ct = (content_type or "json").lower()
            spec: Dict[str, Any] = {}
            if ct in ("yaml", "yml"):
                if not _YAML_AVAILABLE:
                    self._errors.append("PyYAML 不可用，无法解析 YAML；请安装 pyyaml 或改用 JSON 格式")
                    return {"valid": False, "errors": self._errors, "spec": {}}
                spec = yaml.safe_load(content)  # type: ignore[union-attr]
            else:
                spec = json.loads(content)

            if not isinstance(spec, dict):
                self._errors.append("规范根节点必须是对象(dict)")
                return {"valid": False, "errors": self._errors, "spec": {}}

            self.spec = spec
            validation = self.validate(spec)
            if not validation.get("valid"):
                self._errors.extend(validation.get("errors", []))

            self._parsed = self._build_parsed(spec)
            return {
                "valid": validation.get("valid", False),
                "errors": self._errors,
                "spec": spec,
                "parsed": self._parsed,
            }
        except json.JSONDecodeError as e:
            self._errors.append(f"JSON 解析失败: {e}")
            return {"valid": False, "errors": self._errors, "spec": {}}
        except Exception as e:
            self._errors.append(f"解析失败: {e}")
            return {"valid": False, "errors": self._errors, "spec": {}}

    # ------------------------------------------------------------------ #
    # 校验
    # ------------------------------------------------------------------ #
    def validate(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """验证 OpenAPI 规范是否有效（检查 openapi/info/paths 必填字段）。"""
        errors: List[str] = []
        try:
            if not isinstance(spec, dict):
                return {"valid": False, "errors": ["spec 不是字典"]}

            if "openapi" not in spec and "swagger" not in spec:
                errors.append("缺少必填字段: openapi")
            if "info" not in spec or not isinstance(spec.get("info"), dict):
                errors.append("缺少必填字段: info")
            elif "title" not in spec.get("info", {}):
                errors.append("info 缺少 title")
            if "paths" not in spec or not isinstance(spec.get("paths"), dict):
                errors.append("缺少必填字段: paths")
        except Exception as e:
            errors.append(f"校验异常: {e}")
        return {"valid": len(errors) == 0, "errors": errors}

    # ------------------------------------------------------------------ #
    # 信息提取
    # ------------------------------------------------------------------ #
    def get_api_info(self, spec: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """返回 API 基本信息：title, version, description, servers。"""
        try:
            spec = spec or self.spec
            info = spec.get("info", {}) if isinstance(spec, dict) else {}
            servers = spec.get("servers", []) if isinstance(spec, dict) else []
            server_urls = [s.get("url", "") for s in servers if isinstance(s, dict)]
            return {
                "title": info.get("title", ""),
                "version": info.get("version", ""),
                "description": info.get("description", ""),
                "servers": server_urls,
            }
        except Exception as e:
            return {"title": "", "version": "", "description": f"get_api_info错误: {e}", "servers": []}

    def get_auth_methods(self, spec: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """识别认证方式：API Key / Bearer Token / Basic Auth / OAuth2 / Cookie。"""
        methods: List[Dict[str, Any]] = []
        try:
            spec = spec or self.spec
            components = (spec or {}).get("components", {})
            sec_schemes = components.get("securitySchemes", {}) or {}
            for name, scheme in sec_schemes.items():
                if not isinstance(scheme, dict):
                    continue
                stype = scheme.get("type", "")
                detail: Dict[str, Any] = {"name": name, "type": stype}
                if stype == "apiKey":
                    detail["in"] = scheme.get("in", "")
                    detail["key_name"] = scheme.get("name", "")
                    detail["detected"] = "api_key"
                elif stype == "http":
                    scheme_scheme = (scheme.get("scheme") or "").lower()
                    if scheme_scheme == "bearer":
                        detail["detected"] = "bearer_token"
                    elif scheme_scheme == "basic":
                        detail["detected"] = "basic_auth"
                    else:
                        detail["detected"] = f"http_{scheme_scheme}"
                elif stype == "oauth2":
                    detail["detected"] = "oauth2"
                    flows = scheme.get("flows", {}) or {}
                    detail["flows"] = list(flows.keys())
                elif stype == "openIdConnect":
                    detail["detected"] = "oidc"
                else:
                    detail["detected"] = stype or "unknown"

                # Cookie 推断
                if detail.get("in") == "cookie":
                    detail["detected"] = "cookie"
                methods.append(detail)
        except Exception:
            pass
        return methods

    # ------------------------------------------------------------------ #
    # 端点提取
    # ------------------------------------------------------------------ #
    def get_parameters(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取参数详情：路径/查询/请求头/Cookie/请求体字段。"""
        params: List[Dict[str, Any]] = []
        try:
            raw_params = endpoint.get("parameters", []) or []
            for p in raw_params:
                if not isinstance(p, dict):
                    continue
                schema = p.get("schema", {}) or {}
                params.append({
                    "name": p.get("name", ""),
                    "location": p.get("in", ""),
                    "type": schema.get("type", self._schema_type(schema)),
                    "required": bool(p.get("required", False)),
                    "description": p.get("description", ""),
                    "schema": schema,
                    "enum": schema.get("enum", []),
                })

            # 请求体字段
            rb = endpoint.get("request_body", {}) or {}
            content = rb.get("content", {}) or {}
            for media_type, media_obj in content.items():
                if not isinstance(media_obj, dict):
                    continue
                schema = media_obj.get("schema", {}) or {}
                for fname, fdef in (schema.get("properties", {}) or {}).items():
                    if not isinstance(fdef, dict):
                        continue
                    params.append({
                        "name": fname,
                        "location": "body",
                        "type": fdef.get("type", self._schema_type(fdef)),
                        "required": fname in (schema.get("required", []) or []),
                        "description": fdef.get("description", ""),
                        "schema": fdef,
                        "enum": fdef.get("enum", []),
                    })
        except Exception:
            pass
        return params

    def get_endpoints(self, spec: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """返回所有端点列表。"""
        endpoints: List[Dict[str, Any]] = []
        try:
            spec = spec or self.spec
            paths = (spec or {}).get("paths", {}) or {}
            global_security = (spec or {}).get("security", []) or []
            for path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                for method, detail in methods.items():
                    m = method.lower()
                    if m not in _HTTP_METHODS or not isinstance(detail, dict):
                        continue
                    ep_security = detail.get("security", global_security)
                    auth_required = bool(ep_security)
                    endpoint = {
                        "method": m.upper(),
                        "path": path,
                        "operation_id": detail.get("operationId", ""),
                        "summary": detail.get("summary", ""),
                        "description": detail.get("description", ""),
                        "tags": detail.get("tags", []) or [],
                        "parameters": detail.get("parameters", []) or [],
                        "request_body": detail.get("request_body", {}) or {},
                        "responses": detail.get("responses", {}) or {},
                        "security": ep_security,
                        "auth_required": auth_required,
                    }
                    endpoint["param_details"] = self.get_parameters(endpoint)
                    endpoints.append(endpoint)
        except Exception as e:
            endpoints.append({"method": "ERROR", "path": "", "errors": [str(e)]})
        return endpoints

    def classify_endpoints(self, endpoints: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """端点分类：public / authenticated / admin / user。"""
        result: Dict[str, List[Dict[str, Any]]] = {
            "public": [], "authenticated": [], "admin": [], "user": [],
        }
        try:
            for ep in endpoints:
                path = (ep.get("path") or "").lower()
                tags = [t.lower() for t in (ep.get("tags") or [])]
                if "admin" in path or "admin" in tags:
                    result["admin"].append(ep)
                elif "user" in path or "me" in path:
                    result["user"].append(ep)
                elif ep.get("auth_required"):
                    result["authenticated"].append(ep)
                else:
                    result["public"].append(ep)
        except Exception:
            pass
        return result

    def get_data_types(self, schema: Any) -> List[str]:
        """识别数据类型：string/integer/number/boolean/array/object/enum，递归解析。"""
        types: List[str] = []
        try:
            if not isinstance(schema, dict):
                return types
            if "enum" in schema and schema["enum"] is not None:
                types.append("enum")
            t = schema.get("type")
            if isinstance(t, str):
                types.append(t)
            elif isinstance(t, list):
                types.extend([x for x in t if isinstance(x, str)])
            if "allOf" in schema:
                for sub in schema.get("allOf", []):
                    types.extend(self.get_data_types(sub))
            if "oneOf" in schema:
                for sub in schema.get("oneOf", []):
                    types.extend(self.get_data_types(sub))
            if "anyOf" in schema:
                for sub in schema.get("anyOf", []):
                    types.extend(self.get_data_types(sub))
            if isinstance(schema.get("items"), dict):
                types.extend(self.get_data_types(schema["items"]))
            for sub in (schema.get("properties", {}) or {}).values():
                if isinstance(sub, dict):
                    types.extend(self.get_data_types(sub))
        except Exception:
            pass
        # 去重保序
        seen = set()
        uniq: List[str] = []
        for t in types:
            if t and t not in seen:
                seen.add(t)
                uniq.append(t)
        return uniq

    # ------------------------------------------------------------------ #
    # 内部工具
    # ------------------------------------------------------------------ #
    @staticmethod
    def _schema_type(schema: Dict[str, Any]) -> str:
        try:
            if not isinstance(schema, dict):
                return "string"
            if "enum" in schema:
                return "enum"
            return schema.get("type", "string")
        except Exception:
            return "string"

    def _build_parsed(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """构建完整解析结果。"""
        try:
            endpoints = self.get_endpoints(spec)
            return {
                "api_info": self.get_api_info(spec),
                "auth_methods": self.get_auth_methods(spec),
                "endpoints": endpoints,
                "endpoint_count": len(endpoints),
                "endpoint_classes": {k: len(v) for k, v in self.classify_endpoints(endpoints).items()},
                "yaml_available": _YAML_AVAILABLE,
            }
        except Exception as e:
            return {"error": str(e)}

    def get_parsed_result(self) -> Dict[str, Any]:
        """返回完整解析结果。"""
        return {
            "spec": self.spec,
            "errors": self._errors,
            "parsed": self._parsed,
        }


__all__ = ["OpenAPIParser"]
