#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
openapi_parser.py — OpenAPI/Swagger 深度解析器（专业级深化）。

支持 OpenAPI 3.0 / 3.1 / Swagger 2.0，解析 JSON / YAML。
提供端点提取、参数分析、认证方式识别、数据模型解析、缺失文档检测、
规范合规性检查与解析报告生成。

设计定位：仅做规范解析与合规分析，不发起对目标的主动请求。
"""

from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Set, Tuple

# 可选 YAML 支持
try:  # pragma: no cover
    import yaml  # type: ignore
    _YAML_AVAILABLE = True
except Exception:
    yaml = None  # type: ignore
    _YAML_AVAILABLE = False


_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "trace"}

# 常见命名规范（驼峰 / 下划线 / 中划线）
_RE_CAMEL = re.compile(r"^[a-z][a-zA-Z0-9]*$")
_RE_SNAKE = re.compile(r"^[a-z][a-z0-9_]*$")
_RE_KEBAB = re.compile(r"^[a-z][a-z0-9-]*$")


class OpenAPIProParser:
    """OpenAPI / Swagger 规范深度解析器。"""

    def __init__(self) -> None:
        self.spec: Dict[str, Any] = {}
        self.spec_version: str = "unknown"
        self.doc_format: str = "json"
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self._ref_cache: Dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # 加载入口
    # ------------------------------------------------------------------ #
    def parse_from_url(self, url: str) -> Dict[str, Any]:
        """从 URL 下载并解析 OpenAPI 规范。"""
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "APISecurityProParser/12.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            ct = (resp.headers.get("Content-Type") or "").lower()
            content_type = "yaml" if ("yaml" in ct or "yml" in ct) else "json"
            return self.parse_from_string(raw, content_type)
        except Exception as e:
            return {"valid": False, "errors": [f"URL 下载失败: {e}"], "endpoints": []}

    def parse_from_file(self, file_path: str) -> Dict[str, Any]:
        """从本地文件解析。"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            content_type = "yaml" if file_path.lower().endswith((".yaml", ".yml")) else "json"
            return self.parse_from_string(content, content_type)
        except Exception as e:
            return {"valid": False, "errors": [f"文件读取失败: {e}"], "endpoints": []}

    def parse_from_string(self, content: str, content_type: str = "json") -> Dict[str, Any]:
        """从字符串解析 OpenAPI 规范。"""
        self.errors = []
        self.warnings = []
        self._ref_cache = {}
        try:
            ct = (content_type or "json").lower()
            if ct in ("yaml", "yml"):
                if not _YAML_AVAILABLE:
                    self.errors.append("PyYAML 不可用，无法解析 YAML；请安装 pyyaml")
                    return self._build_report(valid=False)
                self.spec = yaml.safe_load(content)  # type: ignore[union-attr]
            else:
                self.spec = json.loads(content)
            self.doc_format = ct
        except Exception as e:
            self.errors.append(f"规范解析失败: {e}")
            return self._build_report(valid=False)

        if not isinstance(self.spec, dict):
            self.errors.append("规范根节点不是对象（dict）")
            return self._build_report(valid=False)

        self.spec_version = self._detect_version()
        return self._build_report(valid=True)

    # ------------------------------------------------------------------ #
    # 版本检测
    # ------------------------------------------------------------------ #
    def _detect_version(self) -> str:
        if "openapi" in self.spec:
            ver = str(self.spec.get("openapi", ""))
            if ver.startswith("3.1"):
                return "OpenAPI 3.1"
            if ver.startswith("3.0"):
                return "OpenAPI 3.0"
            return f"OpenAPI {ver}"
        if "swagger" in self.spec:
            return f"Swagger {self.spec.get('swagger', '2.0')}"
        if "swaggerVersion" in self.spec:
            return f"Swagger {self.spec.get('swaggerVersion')}"
        self.warnings.append("无法识别 OpenAPI 规范版本，按 OpenAPI 3.0 解析")
        return "OpenAPI 3.0 (推断)"

    # ------------------------------------------------------------------ #
    # 端点提取
    # ------------------------------------------------------------------ #
    def extract_endpoints(self) -> List[Dict[str, Any]]:
        """提取所有端点（HTTP方法/路径/操作ID/标签/摘要/描述/参数/请求体/响应）。"""
        endpoints: List[Dict[str, Any]] = []
        paths = self.spec.get("paths", {}) or {}
        global_params = self.spec.get("parameters", {}) or {}

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method, op in path_item.items():
                if method.lower() not in _HTTP_METHODS:
                    continue
                if not isinstance(op, dict):
                    continue
                endpoint = self._build_endpoint(path, method.lower(), op, global_params)
                endpoints.append(endpoint)
        return endpoints

    def _build_endpoint(
        self, path: str, method: str, op: Dict[str, Any], global_params: Dict[str, Any]
    ) -> Dict[str, Any]:
        parameters = self._extract_parameters(op, global_params)
        request_body = self._extract_request_body(op)
        responses = self._extract_responses(op)
        return {
            "path": path,
            "method": method.upper(),
            "operation_id": op.get("operationId", ""),
            "summary": op.get("summary", ""),
            "description": op.get("description", ""),
            "tags": op.get("tags", []) or [],
            "deprecated": bool(op.get("deprecated", False)),
            "parameters": parameters,
            "request_body": request_body,
            "responses": responses,
            "security": op.get("security", None),
        }

    # ------------------------------------------------------------------ #
    # 参数分析
    # ------------------------------------------------------------------ #
    def _extract_parameters(
        self, op: Dict[str, Any], global_params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        params: List[Dict[str, Any]] = []
        raw_params = op.get("parameters", []) or []
        for p in raw_params:
            if not isinstance(p, dict):
                continue
            # 解析 $ref
            if "$ref" in p:
                p = self._resolve_ref(p["$ref"]) or {}
            name = p.get("name", "")
            location = p.get("in", "")
            schema = p.get("schema", {}) or {}
            if isinstance(schema, dict) and "$ref" in schema:
                schema = self._resolve_ref(schema["$ref"]) or schema
            params.append({
                "name": name,
                "in": location,
                "required": bool(p.get("required", location == "path")),
                "type": schema.get("type", p.get("type", "")),
                "format": schema.get("format", p.get("format", "")),
                "default": p.get("default", schema.get("default")),
                "enum": schema.get("enum", p.get("enum", [])),
                "pattern": schema.get("pattern", p.get("pattern", "")),
                "min_length": schema.get("minLength", p.get("minLength")),
                "max_length": schema.get("maxLength", p.get("maxLength")),
                "minimum": schema.get("minimum", p.get("minimum")),
                "maximum": schema.get("maximum", p.get("maximum")),
                "description": p.get("description", ""),
            })
        # 合并全局参数
        for ref_name, gp in global_params.items():
            if isinstance(gp, dict):
                params.append({
                    "name": gp.get("name", ref_name),
                    "in": gp.get("in", ""),
                    "required": bool(gp.get("required", False)),
                    "type": (gp.get("schema") or {}).get("type", gp.get("type", "")),
                    "format": (gp.get("schema") or {}).get("format", gp.get("format", "")),
                    "default": gp.get("default"),
                    "enum": [],
                    "pattern": "",
                    "min_length": None,
                    "max_length": None,
                    "minimum": None,
                    "maximum": None,
                    "description": gp.get("description", ""),
                    "scope": "global",
                })
        return params

    # ------------------------------------------------------------------ #
    # 请求体 / 响应
    # ------------------------------------------------------------------ #
    def _extract_request_body(self, op: Dict[str, Any]) -> Dict[str, Any]:
        rb = op.get("requestBody", {}) or {}
        if "$ref" in rb:
            rb = self._resolve_ref(rb["$ref"]) or {}
        content = rb.get("content", {}) or {}
        media_types = list(content.keys())
        schemas: Dict[str, Any] = {}
        for mt, mt_obj in content.items():
            schema = (mt_obj or {}).get("schema", {}) or {}
            if "$ref" in schema:
                schema = self._resolve_ref(schema["$ref"]) or schema
            schemas[mt] = self._summarize_schema(schema)
        return {
            "required": bool(rb.get("required", False)),
            "media_types": media_types,
            "schemas": schemas,
            "description": rb.get("description", ""),
        }

    def _extract_responses(self, op: Dict[str, Any]) -> Dict[str, Any]:
        responses: Dict[str, Any] = {}
        raw_resp = op.get("responses", {}) or {}
        for code, r in raw_resp.items():
            if isinstance(r, dict) and "$ref" in r:
                r = self._resolve_ref(r["$ref"]) or r
            desc = ""
            media_types: List[str] = []
            if isinstance(r, dict):
                desc = r.get("description", "")
                content = r.get("content", {}) or {}
                media_types = list(content.keys())
            responses[str(code)] = {
                "description": desc,
                "media_types": media_types,
            }
        return responses

    # ------------------------------------------------------------------ #
    # 数据模型 / Schema
    # ------------------------------------------------------------------ #
    def extract_schemas(self) -> Dict[str, Any]:
        """解析组件 Schema（对象/数组/枚举/组合 allOf/oneOf/anyOf/嵌套引用）。"""
        schemas: Dict[str, Any] = {}
        components = self.spec.get("components", {}) or {}
        defs = components.get("schemas", {}) or self.spec.get("definitions", {}) or {}
        for name, schema in defs.items():
            if isinstance(schema, dict):
                schemas[name] = self._summarize_schema(schema, depth=0)
        return schemas

    def _summarize_schema(self, schema: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
        if depth > 4 or not isinstance(schema, dict):
            return {"type": "unknown"}
        result: Dict[str, Any] = {"type": schema.get("type", "object")}
        if schema.get("enum"):
            result["enum"] = list(schema["enum"])
        if schema.get("format"):
            result["format"] = schema["format"]
        # 组合关键字
        for combo in ("allOf", "oneOf", "anyOf"):
            if combo in schema:
                sub = [self._summarize_schema(s, depth + 1) for s in schema[combo] if isinstance(s, dict)]
                result[combo] = sub
        # 对象属性
        props = schema.get("properties", {}) or {}
        if props:
            result["properties"] = {
                k: self._summarize_schema(v, depth + 1) for k, v in props.items() if isinstance(v, dict)
            }
            result["required"] = list(schema.get("required", []) or [])
        # 数组
        if schema.get("type") == "items" or "items" in schema:
            items = schema.get("items", {})
            if isinstance(items, dict):
                result["items"] = self._summarize_schema(items, depth + 1)
        # 约束
        for k in ("minLength", "maxLength", "minimum", "maximum", "pattern", "default"):
            if k in schema:
                result[k] = schema[k]
        return result

    # ------------------------------------------------------------------ #
    # 认证方式识别
    # ------------------------------------------------------------------ #
    def extract_security_schemes(self) -> Dict[str, Any]:
        """识别全局与端点级认证方式（API Key/Bearer JWT/OAuth2/Basic/Digest/mTLS/Cookie）。"""
        schemes: Dict[str, Any] = {}
        components = self.spec.get("components", {}) or {}
        sec_defs = components.get("securitySchemes", {}) or self.spec.get("securityDefinitions", {}) or {}
        for name, sd in sec_defs.items():
            if not isinstance(sd, dict):
                continue
            stype = (sd.get("type") or "").lower()
            scheme = (sd.get("scheme") or "").lower()
            descriptor = "unknown"
            if stype == "apikey":
                descriptor = f"API Key ({sd.get('in', '')} {sd.get('name', '')})"
            elif stype == "http":
                if scheme == "bearer":
                    descriptor = "Bearer JWT"
                elif scheme == "basic":
                    descriptor = "Basic Auth"
                elif scheme == "digest":
                    descriptor = "Digest Auth"
                elif scheme == "mutual":
                    descriptor = "Mutual TLS"
                else:
                    descriptor = f"HTTP {scheme}"
            elif stype == "oauth2":
                flows = list((sd.get("flows") or {}).keys())
                descriptor = f"OAuth2 ({', '.join(flows) or 'unknown flows'})"
            elif stype == "openIdConnect":
                descriptor = "OpenID Connect"
            elif stype == "apiKey" and sd.get("in") == "cookie":
                descriptor = "Cookie Session"
            schemes[name] = {
                "type": stype,
                "scheme": scheme,
                "description": sd.get("description", ""),
                "descriptor": descriptor,
                "bearer_format": sd.get("bearerFormat", ""),
                "in": sd.get("in", ""),
                "name": sd.get("name", ""),
            }
        return schemes

    # ------------------------------------------------------------------ #
    # $ref 解析
    # ------------------------------------------------------------------ #
    def _resolve_ref(self, ref: str) -> Optional[Dict[str, Any]]:
        if ref in self._ref_cache:
            return self._ref_cache[ref]
        result: Any = self.spec
        try:
            if not ref.startswith("#/"):
                return None
            parts = ref[2:].split("/")
            for part in parts:
                part = part.replace("~1", "/").replace("~0", "~")
                if isinstance(result, dict):
                    result = result.get(part)
                else:
                    return None
            if isinstance(result, dict):
                self._ref_cache[ref] = result
                return result
        except Exception:
            return None
        return None

    # ------------------------------------------------------------------ #
    # 缺失文档检测
    # ------------------------------------------------------------------ #
    def detect_documentation_gaps(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """检测未描述端点/参数/响应/错误码/示例等缺失。"""
        gaps: List[Dict[str, Any]] = []
        for ep in endpoints:
            label = f"{ep['method']} {ep['path']}"
            if not ep.get("operation_id"):
                gaps.append({"endpoint": label, "gap": "缺少 operationId", "severity": "low"})
            if not ep.get("summary"):
                gaps.append({"endpoint": label, "gap": "缺少 summary 摘要", "severity": "low"})
            if not ep.get("description"):
                gaps.append({"endpoint": label, "gap": "缺少 description 详细描述", "severity": "info"})
            if not ep.get("tags"):
                gaps.append({"endpoint": label, "gap": "缺少 tags 标签分组", "severity": "info"})
            for p in ep.get("parameters", []):
                if not p.get("description"):
                    gaps.append({
                        "endpoint": label,
                        "gap": f"参数 {p.get('name')}({p.get('in')}) 缺少描述",
                        "severity": "low",
                    })
                if p.get("in") in ("query",) and not p.get("required") and p.get("type") in ("string", ""):
                    # 可选字符串参数建议提供默认/枚举
                    if not p.get("enum") and p.get("default") is None:
                        gaps.append({
                            "endpoint": label,
                            "gap": f"参数 {p.get('name')} 缺少默认值/枚举/格式约束",
                            "severity": "info",
                        })
            responses = ep.get("responses", {}) or {}
            has_4xx = any(str(c).startswith(("4", "5")) for c in responses.keys())
            if not has_4xx:
                gaps.append({"endpoint": label, "gap": "未定义任何错误响应（4xx/5xx）", "severity": "medium"})
            if "200" not in responses and "201" not in responses and "204" not in responses:
                gaps.append({"endpoint": label, "gap": "未定义成功响应（2xx）", "severity": "medium"})
            rb = ep.get("request_body", {}) or {}
            if rb.get("required") and not rb.get("schemas"):
                gaps.append({"endpoint": label, "gap": "请求体已声明但无 Schema/示例", "severity": "medium"})
        return {
            "total_gaps": len(gaps),
            "by_severity": self._count_by(gaps, "severity"),
            "gaps": gaps,
        }

    # ------------------------------------------------------------------ #
    # 规范合规性检查
    # ------------------------------------------------------------------ #
    def compliance_check(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """OpenAPI 规范合规性检查：版本/必填字段/命名规范/版本管理。"""
        findings: List[Dict[str, Any]] = []
        info = self.spec.get("info", {}) or {}
        if not info.get("title"):
            findings.append({"check": "info.title", "status": "fail", "message": "缺少 API 标题"})
        if not info.get("version"):
            findings.append({"check": "info.version", "status": "fail", "message": "缺少 API 版本号"})
        elif not str(info.get("version", "")).strip():
            findings.append({"check": "info.version", "status": "warn", "message": "API 版本号为空"})
        if self.spec_version.startswith("Swagger 2"):
            findings.append({
                "check": "spec_version",
                "status": "warn",
                "message": "使用 Swagger 2.0，建议迁移到 OpenAPI 3.0/3.1",
            })
        # servers 检查
        servers = self.spec.get("servers", []) or []
        if not servers and "host" not in self.spec:
            findings.append({"check": "servers", "status": "warn", "message": "未定义 servers/host，客户端无法定位服务"})
        # 路径命名规范
        bad_paths: List[str] = []
        for ep in endpoints:
            p = ep["path"]
            # 检查路径段是否符合 kebab-case / 下划线
            segments = [s for s in p.strip("/").split("/") if s and not s.startswith("{")]
            for seg in segments:
                if not (_RE_KEBAB.match(seg) or _RE_SNAKE.match(seg) or _RE_CAMEL.match(seg)):
                    bad_paths.append(f"{ep['method']} {p}: '{seg}'")
        if bad_paths:
            findings.append({
                "check": "path_naming",
                "status": "warn",
                "message": f"{len(bad_paths)} 个路径段命名不规范（建议 kebab-case）",
                "examples": bad_paths[:5],
            })
        # 版本管理：路径是否含版本
        has_version_path = any(re.search(r"/v\d+", ep["path"]) for ep in endpoints)
        info_ver = str(info.get("version", ""))
        if not has_version_path and not info_ver:
            findings.append({
                "check": "versioning",
                "status": "warn",
                "message": "API 路径与 info.version 均未体现版本管理",
            })
        # 重复 operationId
        op_ids: Dict[str, int] = {}
        for ep in endpoints:
            oid = ep.get("operation_id")
            if oid:
                op_ids[oid] = op_ids.get(oid, 0) + 1
        dups = [k for k, v in op_ids.items() if v > 1]
        if dups:
            findings.append({
                "check": "operation_id_unique",
                "status": "fail",
                "message": f"重复的 operationId: {', '.join(dups[:5])}",
            })
        return findings

    # ------------------------------------------------------------------ #
    # 统计
    # ------------------------------------------------------------------ #
    @staticmethod
    def _count_by(items: List[Dict[str, Any]], key: str) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for it in items:
            k = str(it.get(key, "unknown"))
            out[k] = out.get(k, 0) + 1
        return out

    # ------------------------------------------------------------------ #
    # 报告生成
    # ------------------------------------------------------------------ #
    def _build_report(self, valid: bool) -> Dict[str, Any]:
        endpoints = self.extract_endpoints() if valid else []
        schemas = self.extract_schemas() if valid else {}
        schemes = self.extract_security_schemes() if valid else {}
        gaps = self.detect_documentation_gaps(endpoints) if valid else {"total_gaps": 0, "gaps": []}
        compliance = self.compliance_check(endpoints) if valid else []

        methods: Dict[str, int] = {}
        tags: Dict[str, int] = {}
        for ep in endpoints:
            methods[ep["method"]] = methods.get(ep["method"], 0) + 1
            for t in ep.get("tags", []):
                tags[t] = tags.get(t, 0) + 1

        report = {
            "valid": valid,
            "spec_version": self.spec_version,
            "doc_format": self.doc_format,
            "errors": self.errors,
            "warnings": self.warnings,
            "summary": {
                "total_endpoints": len(endpoints),
                "by_method": methods,
                "by_tag": dict(sorted(tags.items(), key=lambda x: -x[1])),
                "total_schemas": len(schemas),
                "total_security_schemes": len(schemes),
                "deprecated_endpoints": sum(1 for e in endpoints if e.get("deprecated")),
            },
            "endpoints": endpoints,
            "schemas": schemas,
            "security_schemes": schemes,
            "documentation_gaps": gaps,
            "compliance": compliance,
            "info": self.spec.get("info", {}) if valid else {},
            "servers": self.spec.get("servers", []) if valid else [],
        }
        return report

    # ------------------------------------------------------------------ #
    # 便捷接口
    # ------------------------------------------------------------------ #
    def get_endpoint_list(self) -> List[Dict[str, Any]]:
        """返回扁平的端点列表（供路由层 /openapi/endpoints 使用）。"""
        return self.extract_endpoints()

    def get_report_markdown(self, report: Optional[Dict[str, Any]] = None) -> str:
        """生成 Markdown 解析报告。"""
        if report is None:
            report = self._build_report(valid=True)
        lines = [
            f"# OpenAPI 解析报告",
            f"",
            f"- 规范版本: {report.get('spec_version')}",
            f"- 文档格式: {report.get('doc_format')}",
            f"- 解析状态: {'成功' if report.get('valid') else '失败'}",
            f"- 端点数: {report.get('summary', {}).get('total_endpoints', 0)}",
            f"- 数据模型数: {report.get('summary', {}).get('total_schemas', 0)}",
            f"- 认证方式数: {report.get('summary', {}).get('total_security_schemes', 0)}",
            f"",
            f"## 方法分布",
        ]
        for m, c in report.get("summary", {}).get("by_method", {}).items():
            lines.append(f"- {m}: {c}")
        lines.append("")
        lines.append("## 文档缺失")
        dg = report.get("documentation_gaps", {})
        lines.append(f"- 总计: {dg.get('total_gaps', 0)}")
        for gap in (dg.get("gaps") or [])[:10]:
            lines.append(f"  - [{gap.get('severity')}] {gap.get('endpoint')}: {gap.get('gap')}")
        lines.append("")
        lines.append("## 合规性检查")
        for f in report.get("compliance", []):
            lines.append(f"- [{f.get('status')}] {f.get('check')}: {f.get('message')}")
        return "\n".join(lines)
