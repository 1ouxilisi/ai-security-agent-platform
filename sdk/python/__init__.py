"""
AI Hacking Agent Python SDK
============================

官方Python SDK，用于与AI Hacking Agent API服务交互。
支持全域安全评估、漏洞验证、AI分析、工作流编排、报告生成等功能。

所有功能仅限授权安全测试使用，未经授权不得对第三方系统进行扫描或攻击。
"""

from .ai_hacking_sdk import (
    AIAgentClient,
    APIError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)

__version__ = "1.0.0"
__author__ = "AI Hacking Agent Team"
__all__ = [
    "AIAgentClient",
    "APIError",
    "AuthenticationError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "ValidationError",
]
