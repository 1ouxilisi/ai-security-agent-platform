#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_security_pro — API 安全专业级深化模块（第 12 轮升级）。

与第 8 轮基础模块 api_security/ 共存，提供：
    - openapi_parser        OpenAPI/Swagger 深度解析与规范合规检查
    - auth_authorization    认证与授权深度测试（JWT/OAuth2/Session/BOLA/BFLA/IDOR）
    - injection_tester      注入测试（SQL/NoSQL/命令/XXE/SSRF/SSTI/反序列化等）
    - business_logic        业务逻辑漏洞检测
    - security_config       API 安全配置与防护检查
    - fuzz_engine           API Fuzz 测试引擎
    - api_scan_workflow     综合扫描工作流编排

设计定位：
    - 仅做检测、评估、防御视角的安全分析，不提供攻击利用工具。
    - 所有功能仅用于经过授权的 API 安全评估，输出检测报告与修复建议。
    - 第三方库一律 try-import，不可用时自动回退到内嵌模拟/离线数据。
"""

from __future__ import annotations

__version__ = "12.0.0"
__round__ = 12

# 核心类与工厂函数（try-import，避免单个模块缺失导致整个包不可用）
try:
    from api_security_pro.openapi_parser import OpenAPIProParser
except Exception:  # pragma: no cover
    OpenAPIProParser = None  # type: ignore

try:
    from api_security_pro.auth_authorization import AuthAuthorizationTester
except Exception:  # pragma: no cover
    AuthAuthorizationTester = None  # type: ignore

try:
    from api_security_pro.injection_tester import InjectionTester, INJECTION_PAYLOAD_LIBRARY
except Exception:  # pragma: no cover
    InjectionTester = None  # type: ignore
    INJECTION_PAYLOAD_LIBRARY = {}

try:
    from api_security_pro.business_logic import BusinessLogicDetector
except Exception:  # pragma: no cover
    BusinessLogicDetector = None  # type: ignore

try:
    from api_security_pro.security_config import SecurityConfigChecker
except Exception:  # pragma: no cover
    SecurityConfigChecker = None  # type: ignore

try:
    from api_security_pro.fuzz_engine import FuzzEngine, FUZZ_PAYLOAD_LIBRARY
except Exception:  # pragma: no cover
    FuzzEngine = None  # type: ignore
    FUZZ_PAYLOAD_LIBRARY = {}

try:
    from api_security_pro.api_scan_workflow import APISecurityProWorkflow, get_pro_workflow
except Exception:  # pragma: no cover
    APISecurityProWorkflow = None  # type: ignore
    get_pro_workflow = None  # type: ignore

__all__ = [
    "__version__",
    "__round__",
    "OpenAPIProParser",
    "AuthAuthorizationTester",
    "InjectionTester",
    "INJECTION_PAYLOAD_LIBRARY",
    "BusinessLogicDetector",
    "SecurityConfigChecker",
    "FuzzEngine",
    "FUZZ_PAYLOAD_LIBRARY",
    "APISecurityProWorkflow",
    "get_pro_workflow",
]
