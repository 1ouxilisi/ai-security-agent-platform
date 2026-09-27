# -*- coding: utf-8 -*-
"""
application_api_security.py — 应用与API安全评估器（第13轮升级 · 零信任模块）。

功能：
- 应用级访问控制：应用权限模型 / RBAC / ABAC / 资源级权限 / 功能级权限 /
  数据级权限
- API 网关：API 网关覆盖率 / 认证授权 / 限流 / 熔断 / 日志 / 监控 / WAF 集成
- 服务间认证(mTLS)：服务间 TLS 配置 / 证书管理 / 双向认证 / 服务身份 /
  零信任服务网格
- 服务网格评估：Istio / Linkerd / Consul Connect 部署评估 / 策略执行 /
  可观测性 / 安全特性
- 最小权限服务账户：服务账户识别 / 权限范围 / 过度权限 / 密钥轮换 /
  工作负载身份
- 应用安全配置：安全头 / CORS / Cookie 安全 / 会话管理 / 错误处理 /
  敏感数据泄露
- 应用与API安全报告

说明：仅做配置评估，不实际发送攻击 payload、不越权访问任何 API。
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any, Dict, List, Optional


# ==================== 内嵌策略库 ====================

SECURITY_HEADERS_BASELINE = {
    "Strict-Transport-Security": "max-age>=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
}

SERVICE_MESH_OPTIONS = {
    "istio":      {"maturity": 85, "mTLS": True,  "authorization": True, "observability": True},
    "linkerd":    {"maturity": 75, "mTLS": True,  "authorization": True, "observability": True},
    "consul":     {"maturity": 65, "mTLS": True,  "authorization": True, "observability": False},
    "none":       {"maturity": 0,  "mTLS": False, "authorization": False, "observability": False},
}

SAMPLE_SERVICES = [
    {"name": "auth-service",     "cluster": "prod", "mTLS": True,  "sa": "sa-auth",     "scope": "auth:*"},
    {"name": "order-service",   "cluster": "prod", "mTLS": True,  "sa": "sa-order",    "scope": "order:read"},
    {"name": "pay-service",      "cluster": "prod", "mTLS": False, "sa": "sa-pay",      "scope": "*"},
    {"name": "report-job",      "cluster": "prod", "mTLS": False, "sa": "sa-report",   "scope": "db:*"},
    {"name": "dev-debug",        "cluster": "dev",  "mTLS": False, "sa": "sa-debug",    "scope": "*"},
]


# ==================== 主评估器 ====================

class ApplicationAPISecurityManager:
    """应用与API安全评估器（评估视角）。"""

    def __init__(self) -> None:
        self.services = SAMPLE_SERVICES
        self.mesh = "istio"
        self.api_gateways = [
            {"name": "public-gw",   "coverage": 1.0, "waf": True,  "rate_limit": True, "circuit_break": True, "auth": "oauth2", "logging": True},
            {"name": "internal-gw", "coverage": 0.4, "waf": False, "rate_limit": False, "circuit_break": False, "auth": "none", "logging": False},
        ]

    # ---------- 应用访问控制 ----------

    def access_control_assessment(self) -> Dict[str, Any]:
        return {
            "models": {
                "RBAC": {"implemented": True, "maturity": 75,
                         "desc": "基于角色的粗粒度控制"},
                "ABAC": {"implemented": False, "maturity": 20,
                         "desc": "未实现属性级（部门/密级/时间）动态控制"},
            },
            "granularity": {
                "function_level": "已覆盖",
                "resource_level": "部分覆盖",
                "data_level": "未覆盖（行级/列级未做）",
            },
            "findings": [
                {"severity": "high", "desc": "数据级权限缺失，普通员工可查询全量客户订单"},
                {"severity": "medium", "desc": "ABAC 未落地，无法按部门/密级动态授权"},
            ],
            "recommendations": [
                "引入 ABAC，结合部门/密级/设备状态做动态授权",
                "数据库侧启用行列级安全（RLS/CLS）",
            ],
        }

    # ---------- API 网关 ----------

    def api_gateway_assessment(self) -> Dict[str, Any]:
        total = len(self.api_gateways)
        waf_on = sum(1 for g in self.api_gateways if g["waf"])
        avg_cov = round(sum(g["coverage"] for g in self.api_gateways) / total, 2)
        return {
            "gateways": self.api_gateways,
            "total": total,
            "waf_integrated": waf_on,
            "avg_coverage": avg_cov,
            "findings": [
                {"severity": "high", "desc": "internal-gw 无认证无 WAF 无日志，任何内网主机可直连"},
                {"severity": "medium", "desc": "未统一限流策略，单租户可耗尽后端"},
            ],
            "recommendations": [
                "internal-gw 强制 mTLS + JWT 校验",
                "全网关统一接入 WAF 与审计日志",
                "配置全局限流与熔断",
            ],
        }

    # ---------- mTLS 与服务网格 ----------

    def mtls_and_mesh(self) -> Dict[str, Any]:
        mtls_services = [s for s in self.services if s["mTLS"]]
        non_mtls = [s for s in self.services if not s["mTLS"]]
        mesh_info = SERVICE_MESH_OPTIONS.get(self.mesh, SERVICE_MESH_OPTIONS["none"])
        return {
            "mesh": self.mesh,
            "mesh_info": mesh_info,
            "mtls_enabled_services": len(mtls_services),
            "total_services": len(self.services),
            "mtls_coverage_pct": round(len(mtls_services) / len(self.services) * 100, 1),
            "non_mtls_services": non_mtls,
            "certificate_management": {
                "issuer": "内部 CA",
                "rotation_days": 90,
                "spiffe_ids": True,
            },
            "findings": [
                {"severity": "critical", "desc": "pay-service 未启用 mTLS，支付链路明文"},
                {"severity": "high", "desc": "report-job 未启用 mTLS 且直连生产库"},
            ],
            "recommendations": [
                "网格内服务全部强制 mTLS（PERMISSIVE -> STRICT）",
                "证书自动轮换至 SPIFFE/SPIRE",
                "为每个工作负载分配 SPIFFE 身份",
            ],
        }

    # ---------- 服务账户 ----------

    def service_accounts(self) -> Dict[str, Any]:
        over_perm = [s for s in self.services if s["scope"] == "*"]
        stale = [s for s in self.services if s["name"] in ("dev-debug",)]
        return {
            "accounts": self.services,
            "total": len(self.services),
            "over_permissive": over_perm,
            "over_permissive_count": len(over_perm),
            "stale_or_dev": stale,
            "rotation": {
                "auto_rotation": True,
                "rotation_days": 90,
                "workload_identity": True,
            },
            "recommendations": [
                "立即收紧 pay-service / dev-debug 的通配权限",
                "删除或隔离 dev-debug 服务账户",
                "全部改用工作负载身份（SPIFFE）而非静态密钥",
            ],
        }

    # ---------- 应用安全配置 ----------

    def security_config(self) -> Dict[str, Any]:
        present = list(SECURITY_HEADERS_BASELINE.keys())[:4]
        missing = list(SECURITY_HEADERS_BASELINE.keys())[4:]
        return {
            "headers_present": present,
            "headers_missing": missing,
            "cors": {"policy": "allow_origin_star", "risk": "high",
                     "reco": "收紧至明确域名列表"},
            "cookie": {"secure_flag": False, "httponly": True, "samesite": "Lax",
                       "risk": "high", "reco": "全部 Cookie 设置 Secure 标志"},
            "session": {"idle_timeout_min": 30, "absolute_hours": 8,
                        "rotation": True, "secure": True},
            "error_handling": {"stack_trace_leak": True, "risk": "high",
                               "reco": "生产环境关闭堆栈泄露"},
            "sensitive_leak": {"graphql_introspection": True, "risk": "medium",
                               "reco": "生产关闭 GraphQL 内省"},
            "recommendations": [
                "补齐安全头（Referrer-Policy / Permissions-Policy）",
                "CORS 收紧至白名单域名",
                "生产关闭堆栈泄露与 GraphQL 内省",
            ],
        }

    # ---------- 服务清单 ----------

    def list_services(self) -> List[Dict[str, Any]]:
        return [dict(s) for s in self.services]

    def list_api_gateways(self) -> List[Dict[str, Any]]:
        return [dict(g) for g in self.api_gateways]

    # ---------- 综合报告 ----------

    def full_report(self) -> Dict[str, Any]:
        ac = self.access_control_assessment()
        gw = self.api_gateway_assessment()
        mesh = self.mtls_and_mesh()
        sa = self.service_accounts()
        cfg = self.security_config()
        score = int(round(
            (mesh["mtls_coverage_pct"]) * 0.3
            + (100 - sa["over_permissive_count"] * 25) * 0.25
            + (gw["avg_coverage"] * 100) * 0.25
            + 60 * 0.2
        ))
        return {
            "report_title": "应用与API安全报告",
            "generated_at": datetime.now().isoformat(),
            "overall_score": score,
            "access_control": ac,
            "api_gateway": gw,
            "mtls_mesh": mesh,
            "service_accounts": sa,
            "security_config": cfg,
            "summary": (
                f"服务总数 {len(self.services)}；mTLS 覆盖 {mesh['mtls_coverage_pct']}%；"
                f"过权服务账户 {sa['over_permissive_count']} 个；"
                f"API 网关平均覆盖 {gw['avg_coverage']*100:.0f}%；"
                f"缺失安全头 {len(cfg['headers_missing'])} 项。"
            ),
        }


# ==================== 工厂函数 ====================

_apa_singleton: Optional[ApplicationAPISecurityManager] = None


def get_application_api_security_manager() -> ApplicationAPISecurityManager:
    global _apa_singleton
    if _apa_singleton is None:
        _apa_singleton = ApplicationAPISecurityManager()
    return _apa_singleton
