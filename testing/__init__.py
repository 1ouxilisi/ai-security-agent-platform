# -*- coding: utf-8 -*-
"""
testing — 测试体系与 CI/CD 子系统（第19轮升级方向4）。

包含 6 个核心模块：
  - unit_testing        单元测试体系
  - integration_testing 集成测试体系
  - performance_testing 性能测试体系
  - security_testing    安全测试体系
  - cicd_pipeline       CI/CD 流水线
  - test_dashboard      测试管理与仪表盘

所有模块仅依赖标准库；第三方测试工具（pytest / playwright / locust /
bandit 等）均采用 try-import，缺失时自动回退到内置模拟数据。
"""

from __future__ import annotations

__version__ = "19.4.0"
__all__ = [
    "unit_testing",
    "integration_testing",
    "performance_testing",
    "security_testing",
    "cicd_pipeline",
    "test_dashboard",
]
