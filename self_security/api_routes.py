# -*- coding: utf-8 -*-
"""
api_routes.py — self_security 包内的路由聚合工厂。

供 api_server/self_security_routes.py 使用；本身不依赖 FastAPI，
保证本包在无 Web 框架环境下也能独立 import。

对外暴露：
    * build_handlers() -> 一个 dict，聚合六个模块的 handler 函数
    * list_endpoints() -> 静态端点清单（供文档 / 冒烟测试）
"""

from __future__ import annotations

from typing import Any, Callable, Dict

from . import (api_security_hardening, code_security_audit,
               data_security_privacy, runtime_protection,
               security_dashboard, self_pentest)


def build_handlers() -> Dict[str, Callable[..., Any]]:
    """聚合各模块的核心 handler，返回 name -> callable 的字典。"""
    pen = self_pentest.get_pentest_scanner()
    aud = code_security_audit.get_auditor()
    hard = api_security_hardening.get_hardener()
    priv = data_security_privacy.get_privacy_guard()
    prot = runtime_protection.get_protector()
    dash = security_dashboard.get_dashboard()
    return {
        # self_pentest
        "pentest.scan": pen.run_full_scan,
        "pentest.injection": pen.injection_detection,
        "pentest.authz": pen.authz_test,
        "pentest.disclosure": pen.sensitive_disclosure,
        "pentest.config": pen.config_audit,
        # code_security_audit
        "audit.deps": aud.dependency_scan,
        "audit.sast_rules": aud.sast_rules_library,
        "audit.sast_scan": aud.static_analysis,
        "audit.complexity": aud.complexity_analysis,
        "audit.standards": aud.coding_standards_check,
        "audit.full": aud.full_audit,
        # api_security_hardening
        "api_harden.auth": hard.auth_hardening,
        "api_harden.authz": hard.authz_hardening,
        "api_harden.input": hard.input_validation,
        "api_harden.rate": hard.rate_limit_analysis,
        "api_harden.headers": hard.security_headers,
        "api_harden.overview": hard.hardening_overview,
        # data_security_privacy
        "data.discover": priv.discover_sensitive_data,
        "data.encryption": priv.encryption_assessment,
        "data.masking": priv.masking_demo,
        "data.access_audit": priv.access_audit,
        "data.privacy": priv.privacy_compliance,
        # runtime_protection
        "waf.rules": prot.waf_rules,
        "waf.inspect": prot.waf_inspect,
        "ids": prot.intrusion_detection,
        "logs": prot.log_audit,
        "ueba": prot.ueba,
        "ir": prot.incident_response,
        "runtime.overview": prot.protection_overview,
        # security_dashboard
        "dash.posture": dash.posture_overview,
        "dash.score": dash.compute_score,
        "dash.vulns": dash.vuln_management,
        "dash.report": dash.report,
        "dash.baseline": dash.baseline_check,
        "dash.training": dash.training,
    }


ENDPOINT_INDEX = [
    ("GET", "/pentest/scan", "启动/读取自身渗透扫描"),
    ("GET", "/pentest/injection", "注入检测"),
    ("GET", "/pentest/authz", "认证授权测试"),
    ("GET", "/pentest/disclosure", "敏感信息泄露"),
    ("GET", "/pentest/config", "配置安全检查"),
    ("GET", "/audit/deps", "依赖漏洞扫描"),
    ("GET", "/audit/sast-rules", "SAST 规则库"),
    ("GET", "/audit/sast-scan", "代码静态分析"),
    ("GET", "/audit/complexity", "代码复杂度分析"),
    ("GET", "/audit/standards", "安全编码规范"),
    ("GET", "/audit/full", "完整审计"),
    ("GET", "/hardening/auth", "API 认证强化"),
    ("GET", "/hardening/authz", "API 授权强化"),
    ("GET", "/hardening/input", "输入验证"),
    ("GET", "/hardening/rate-limit", "速率限制"),
    ("GET", "/hardening/headers", "安全响应头"),
    ("GET", "/hardening/overview", "加固总览"),
    ("GET", "/data/discover", "敏感数据识别"),
    ("GET", "/data/encryption", "数据加密"),
    ("GET", "/data/masking", "数据脱敏"),
    ("GET", "/data/access-audit", "访问审计"),
    ("GET", "/data/privacy", "隐私合规"),
    ("GET", "/runtime/waf", "WAF 规则"),
    ("POST", "/runtime/waf/inspect", "WAF 输入检测"),
    ("GET", "/runtime/ids", "入侵检测"),
    ("GET", "/runtime/logs", "日志审计"),
    ("GET", "/runtime/ueba", "异常行为"),
    ("GET", "/runtime/incident", "应急响应"),
    ("GET", "/runtime/overview", "防护总览"),
    ("GET", "/dashboard/posture", "安全态势大屏"),
    ("GET", "/dashboard/score", "综合评分"),
    ("GET", "/dashboard/vulns", "漏洞管理"),
    ("GET", "/dashboard/report", "安全报告"),
    ("GET", "/dashboard/baseline", "基线检查"),
    ("GET", "/dashboard/training", "安全培训"),
]
