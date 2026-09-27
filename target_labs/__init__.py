# -*- coding: utf-8 -*-
"""
target_labs - 靶场管理模块（授权安全测试环境）

本模块提供漏洞靶场（DVWA / OWASP Juice Shop / WebGoat / bWAPP / Mutillidae II）
的元数据定义、Docker 生命周期管理、Docker Compose 生成器以及预定义测试场景库。

重要声明：
    本模块仅用于授权环境下的安全测试、教学与演示，严禁用于未授权目标。
    所有漏洞验证行为只做检测，不做实际利用。
"""

from __future__ import annotations

__version__ = "8.0.0"
__all__ = [
    "LabManager",
    "SUPPORTED_LABS",
    "DockerComposeGenerator",
    "ScenarioLibrary",
]

try:  # 主管理器
    from target_labs.manager import LabManager, SUPPORTED_LABS  # noqa: F401
except Exception:  # pragma: no cover - 包级容错
    LabManager = None  # type: ignore
    SUPPORTED_LABS = {}  # type: ignore

try:  # docker compose 生成器
    from target_labs.docker_compose import DockerComposeGenerator  # noqa: F401
except Exception:  # pragma: no cover
    DockerComposeGenerator = None  # type: ignore

try:  # 测试场景库
    from target_labs.scenarios import ScenarioLibrary  # noqa: F401
except Exception:  # pragma: no cover
    ScenarioLibrary = None  # type: ignore
