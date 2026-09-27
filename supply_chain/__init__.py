#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
supply_chain — 企业级供应链安全深化模块（第 15 轮升级方向 1）。

提供供应链安全管理/评估/检测视角的一体化能力：
    - sbom_manager               SBOM 软件物料清单（SPDX/CycloneDX 双格式）
    - component_analyzer         组件与依赖分析（指纹/图谱/冲突/废弃检测）
    - vulnerability_detector     供应链漏洞检测（CVE/GHSA 匹配/传播路径）
    - license_compliance         许可证合规管理（200+ 许可证识别/兼容性）
    - supplier_risk              供应商风险评估（画像/评分卡/地缘风险）
    - supply_chain_workflow      供应链安全综合评估工作流编排

设计定位：
    - 仅做供应链安全检测、评估、治理视角的分析，不提供攻击/投毒工具。
    - 所有功能仅用于经过授权的供应链安全治理，输出检测报告与修复建议。
    - 第三方库一律 try-import，不可用时自动回退到内嵌模拟/离线数据。
    - Python 3.14 兼容。
"""

from __future__ import annotations

__version__ = "15.1.0"
__round__ = 15

# 核心类与工厂函数（try-import，避免单个模块缺失导致整个包不可用）
try:
    from supply_chain.sbom_manager import SBOMManager, SBOM_FORMATS, SAMPLE_SBOMS
except Exception:  # pragma: no cover
    SBOMManager = None  # type: ignore
    SBOM_FORMATS = {}
    SAMPLE_SBOMS = {}

try:
    from supply_chain.component_analyzer import ComponentAnalyzer, COMPONENT_HEALTH_CRITERIA
except Exception:  # pragma: no cover
    ComponentAnalyzer = None  # type: ignore
    COMPONENT_HEALTH_CRITERIA = {}

try:
    from supply_chain.vulnerability_detector import VulnerabilityDetector, VULN_SEVERITY_LEVELS
except Exception:  # pragma: no cover
    VulnerabilityDetector = None  # type: ignore
    VULN_SEVERITY_LEVELS = {}

try:
    from supply_chain.license_compliance import LicenseComplianceChecker, LICENSE_LIBRARY
except Exception:  # pragma: no cover
    LicenseComplianceChecker = None  # type: ignore
    LICENSE_LIBRARY = {}

try:
    from supply_chain.supplier_risk import SupplierRiskAssessor, SUPPLIER_RISK_FACTORS
except Exception:  # pragma: no cover
    SupplierRiskAssessor = None  # type: ignore
    SUPPLIER_RISK_FACTORS = {}

try:
    from supply_chain.supply_chain_workflow import (
        SupplyChainWorkflow, get_supply_chain_workflow, SUPPLY_CHAIN_STEPS,
    )
except Exception:  # pragma: no cover
    SupplyChainWorkflow = None  # type: ignore
    get_supply_chain_workflow = None  # type: ignore
    SUPPLY_CHAIN_STEPS = []

__all__ = [
    "__version__",
    "__round__",
    "SBOMManager",
    "SBOM_FORMATS",
    "SAMPLE_SBOMS",
    "ComponentAnalyzer",
    "COMPONENT_HEALTH_CRITERIA",
    "VulnerabilityDetector",
    "VULN_SEVERITY_LEVELS",
    "LicenseComplianceChecker",
    "LICENSE_LIBRARY",
    "SupplierRiskAssessor",
    "SUPPLIER_RISK_FACTORS",
    "SupplyChainWorkflow",
    "get_supply_chain_workflow",
    "SUPPLY_CHAIN_STEPS",
]
