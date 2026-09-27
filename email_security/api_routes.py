# -*- coding: utf-8 -*-
"""api_routes.py — email_security 包的门面聚合与路由工厂。

- EmailSecurityFacade: 统一持有六大检测引擎的单例。
- build_router(): 当 fastapi 可用时返回一个挂在 /api/v1/email-security
  下的聚合 APIRouter；不可用时返回 None（由 api_server 侧兜底）。

注意：对外的完整 REST 路由实现见 api_server/email_security_routes.py；
本文件仅做包内聚合与可选的快速挂载。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .phishing_detector import PhishingDetector
from .bec_detector import BECDetector
from .email_authentication import EmailAuthenticationSuite
from .attachment_sandbox import AttachmentSandbox
from .email_threat_intel import EmailThreatIntel
from .email_dashboard import EmailDashboard

logger = logging.getLogger(__name__)


class EmailSecurityFacade:
    """统一门面：对外暴露六大引擎。"""

    _instance: Optional["EmailSecurityFacade"] = None

    def __init__(self) -> None:
        self.phishing = PhishingDetector()
        self.bec = BECDetector()
        self.auth = EmailAuthenticationSuite()
        self.sandbox = AttachmentSandbox()
        self.intel = EmailThreatIntel()
        self.dashboard = EmailDashboard()

    @classmethod
    def instance(cls) -> "EmailSecurityFacade":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def health(self) -> Dict[str, Any]:
        return {
            "package": "email_security",
            "engines": {
                "phishing": type(self.phishing).__name__,
                "bec": type(self.bec).__name__,
                "auth": type(self.auth).__name__,
                "sandbox": type(self.sandbox).__name__,
                "intel": type(self.intel).__name__,
                "dashboard": type(self.dashboard).__name__,
            },
            "bec_rules": len(self.bec.list_rules()),
            "yara_rules": len(self.sandbox.list_yara_rules()),
            "ioc_count": self.intel.list_iocs()["total"],
            "ok": True,
        }


def build_router():
    """若 fastapi 可用则返回一个聚合 router，否则 None。"""
    try:
        from fastapi import APIRouter  # type: ignore
    except Exception:  # pragma: no cover
        logger.warning("email_security.api_routes: fastapi 不可用，跳过聚合路由")
        return None

    router = APIRouter(prefix="/api/v1/email-security", tags=["邮件安全"])
    facade = EmailSecurityFacade.instance()

    @router.get("/health")
    def _health():
        return {"success": True, "data": facade.health(), "error": None}

    return router
