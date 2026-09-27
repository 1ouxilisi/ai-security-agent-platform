# -*- coding: utf-8 -*-
"""
api_security_hardening.py — API 安全加固分析。

能力：
    * API 认证强化（JWT / 令牌过期 / 刷新 / 撤销 / 密钥轮换）
    * API 授权强化（RBAC / ABAC / 权限矩阵 / 最小权限）
    * 输入验证与消毒（Schema / 类型 / 长度 / 输出编码 / 参数化）
    * 速率限制与防暴力破解
    * API 安全头（CSP / HSTS / X-Frame-Options / 等）
    * 基于项目路由的真实加固机会识别
"""

from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional

from . import common


class APISecurityHardener:
    """API 安全加固分析器（只读扫描路由与中间件）。"""

    def __init__(self) -> None:
        self.root = common.PROJECT_ROOT

    # ------------------------------------------------------------------ #
    # 分析项目中的路由
    # ------------------------------------------------------------------ #
    def _collect_routes(self) -> List[Dict[str, Any]]:
        routes_dir = os.path.join(self.root, "api_server")
        endpoints = []
        for fn in os.listdir(routes_dir):
            if not fn.endswith("_routes.py"):
                continue
            path = os.path.join(routes_dir, fn)
            txt = common.read_text_safe(path)
            prefix_m = re.search(r"APIRouter\(\s*prefix\s*=\s*[\"']([^\"']+)", txt)
            prefix = prefix_m.group(1) if prefix_m else ""
            for m in re.finditer(r"@router\.(get|post|put|delete|patch)\s*\(\s*[\"']([^\"']+)", txt):
                method, sub = m.group(1).upper(), m.group(2)
                endpoints.append({
                    "method": method,
                    "path": prefix + sub,
                    "module": fn,
                    "has_auth_dep": bool(re.search(
                        r"Depends\s*\(\s*(get_current_user|require_auth|verify_token|auth)",
                        txt)),
                })
            if len(endpoints) >= 2000:
                break
        return endpoints

    # ------------------------------------------------------------------ #
    # 1) 认证强化
    # ------------------------------------------------------------------ #
    def auth_hardening(self) -> Dict[str, Any]:
        files = list(common.iter_project_files(".py", 800))
        jwt_findings = []
        for path in files:
            rel = common.relpath(path)
            txt = common.read_text_safe(path)
            if re.search(r"jwt\.encode|jwt\.decode|JOSE|jose", txt):
                if re.search(r"algorithm\s*=\s*[\"']none[\"']", txt, re.I):
                    jwt_findings.append({"file": rel, "line": 0,
                                         "issue": "JWT 使用 none 算法",
                                         "severity": "critical"})
                if not re.search(r"options.*verify_exp|verify_signature|leeway", txt, re.I):
                    jwt_findings.append({"file": rel, "line": 0,
                                         "issue": "未显式校验过期时间",
                                         "severity": "high"})
                if not re.search(r"SECRET_KEY|JWT_SECRET", txt):
                    jwt_findings.append({"file": rel, "line": 0,
                                         "issue": "未发现 JWT 密钥配置",
                                         "severity": "medium"})
        return {
            "jwt_findings": jwt_findings,
            "recommendations": [
                {"item": "算法白名单", "advice": "decode 时指定 algorithms=[\"HS256\",\"RS256\"]，禁止 none"},
                {"item": "过期时间", "advice": "access_token 15min，refresh_token 7d"},
                {"item": "令牌撤销", "advice": "维护 Redis 黑名单，登出即失效"},
                {"item": "密钥轮换", "advice": "至少 90 天轮换一次 JWT_SECRET"},
                {"item": "强度", "advice": "SECRET_KEY >= 32 字节随机，禁止硬编码"},
            ],
        }

    # ------------------------------------------------------------------ #
    # 2) 授权强化
    # ------------------------------------------------------------------ #
    def authz_hardening(self) -> Dict[str, Any]:
        routes = self._collect_routes()
        without_auth = [r for r in routes if not r["has_auth_dep"]]
        # 公共端点白名单（健康检查 / 文档 / 登录）
        public_prefixes = ("/docs", "/openapi", "/health", "/metrics", "/login", "/auth")
        truly_exposed = [r for r in without_auth
                         if not any(r["path"].startswith(p) for p in public_prefixes)]
        return {
            "total_endpoints_scanned": len(routes),
            "endpoints_without_auth": len(without_auth),
            "possibly_exposed_endpoints": len(truly_exposed),
            "samples": truly_exposed[:20],
            "rbac_recommendation": {
                "model": "RBAC + 资源级 ABAC",
                "roles": ["admin", "analyst", "auditor", "readonly"],
                "policy": "默认拒绝，显式授权；资源级校验 owner == current_user",
            },
            "audit": "所有写操作记录 who/what/when/from-ip",
        }

    # ------------------------------------------------------------------ #
    # 3) 输入验证
    # ------------------------------------------------------------------ #
    def input_validation(self) -> Dict[str, Any]:
        files = list(common.iter_project_files(".py", 800))
        pydantic_usage = 0
        raw_request = 0
        no_type_hint_route = 0
        for path in files:
            txt = common.read_text_safe(path)
            if "BaseModel" in txt:
                pydantic_usage += 1
            if re.search(r"Request\s*:\s*Request|request\.(query_params|json\(\)|form\(\))", txt):
                raw_request += 1
        return {
            "files_using_pydantic": pydantic_usage,
            "files_using_raw_request": raw_request,
            "recommendations": [
                "所有入参使用 Pydantic Schema，声明类型 / 长度 / 正则",
                "禁止直接 request.query_params 拼接 SQL",
                "输出统一 JSON，HTML 场景启用 autoescape",
                "数值参数加 ge/le 边界，字符串加 max_length",
            ],
            "validation_score": max(0, 100 - raw_request * 2),
        }

    # ------------------------------------------------------------------ #
    # 4) 速率限制
    # ------------------------------------------------------------------ #
    def rate_limit_analysis(self) -> Dict[str, Any]:
        files = list(common.iter_project_files(".py", 400))
        limit_hits = 0
        for path in files:
            txt = common.read_text_safe(path)
            if re.search(r"slowapi|Limiter|rate_limit|RateLimit", txt):
                limit_hits += 1
        return {
            "files_with_rate_limit": limit_hits,
            "recommendations": [
                {"scope": "按 IP", "rule": "登录 5 次/分钟，验证码触发"},
                {"scope": "按用户", "rule": "写操作 60 次/分钟"},
                {"scope": "按端点", "rule": "敏感导出接口 10 次/小时"},
                {"scope": "账户锁定", "rule": "连续失败 5 次锁定 15 分钟"},
            ],
            "brute_force_detected_patterns": "无（离线分析）",
        }

    # ------------------------------------------------------------------ #
    # 5) 安全响应头
    # ------------------------------------------------------------------ #
    def security_headers(self) -> Dict[str, Any]:
        app_py = os.path.join(self.root, "api_server", "app.py")
        txt = common.read_text_safe(app_py) if os.path.exists(app_py) else ""
        headers = [
            ("Content-Security-Policy", "CSP", "限制脚本/样式源，防 XSS"),
            ("Strict-Transport-Security", "HSTS", "强制 HTTPS"),
            ("X-Frame-Options", "XFO", "防点击劫持"),
            ("X-Content-Type-Options", "XCTO", "禁止 MIME 嗅探"),
            ("Referrer-Policy", "RP", "限制 Referer 泄露"),
            ("Permissions-Policy", "PP", "关闭不必要浏览器能力"),
        ]
        result = []
        for hname, short, desc in headers:
            present = hname.lower() in txt.lower()
            result.append({"header": hname, "short": short, "present": present,
                           "desc": desc,
                           "status": "PASS" if present else "MISSING"})
        return {
            "headers": result,
            "missing_count": sum(1 for r in result if not r["present"]),
            "recommended_middleware": "add_middleware 在 app 工厂中统一注入",
        }

    # ------------------------------------------------------------------ #
    # 汇总
    # ------------------------------------------------------------------ #
    def hardening_overview(self) -> Dict[str, Any]:
        started = time.time()
        return {
            "overview_id": time.strftime("api_harden_%Y%m%d_%H%M%S"),
            "auth": self.auth_hardening(),
            "authz": self.authz_hardening(),
            "input_validation": self.input_validation(),
            "rate_limit": self.rate_limit_analysis(),
            "security_headers": self.security_headers(),
            "elapsed": round(time.time() - started, 2),
        }


_hardener: Optional[APISecurityHardener] = None


def get_hardener() -> APISecurityHardener:
    global _hardener
    if _hardener is None:
        _hardener = APISecurityHardener()
    return _hardener
