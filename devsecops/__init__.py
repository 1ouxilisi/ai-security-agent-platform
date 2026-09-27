# -*- coding: utf-8 -*-
"""devsecops — DevSecOps 全链路安全评估包。

模块：
    - pipeline_security: CI/CD 流水线安全审计
    - repo_security: 代码仓库安全
    - build_artifact_security: 构建与制品安全
    - deployment_runtime_security: 部署与运行时安全
    - security_gate: 安全门禁与质量门
    - devsecops_maturity: DevSecOps 成熟度评估
    - devsecops_workflow: 全链路综合评估工作流

设计定位：纯防御/评估/检测视角，输出审计报告与加固建议，不执行任何攻击或绕过动作。
"""

from __future__ import annotations

__version__ = "14.0.0"
__all__ = [
    "pipeline_security",
    "repo_security",
    "build_artifact_security",
    "deployment_runtime_security",
    "security_gate",
    "devsecops_maturity",
    "devsecops_workflow",
]
