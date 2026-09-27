#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
endpoint_security — 终端安全EDR模块（第17轮升级方向4）。

提供终端安全检测/监控/响应视角的一体化能力：
    - endpoint_asset       终端资产管理（发现/清单/分组/监控/生命周期）
    - process_behavior     进程与行为监控（进程树/行为分析/命令行审计/注入/持久化）
    - malware_detection   恶意软件检测（签名/行为/YARA/启发式/沙箱）
    - threat_response      威胁检测与响应（规则/告警/响应动作/狩猎/事件响应）
    - vulnerability_patch  漏洞与补丁管理（扫描/补丁/风险评估/基线/修复跟踪）
    - edr_dashboard        EDR运营仪表盘（态势/告警流/威胁地图/健康/度量）

设计定位：
    - 仅做检测、监控、分析、管理视角的终端安全分析，不包含实际攻击代码。
    - 所有功能仅用于经过授权的终端安全运营，输出检测报告与响应建议。
    - 第三方库一律 try-import，不可用时自动回退到内嵌模拟/离线数据。
    - Python 3.14 兼容。
"""

from __future__ import annotations

__version__ = "17.4.0"
__round__ = 17
__direction__ = "endpoint_security_edr"

# 核心类与工厂函数（try-import，避免单个模块缺失导致整个包不可用）
try:
    from endpoint_security.endpoint_asset import (
        EndpointAssetManager, get_asset_manager,
        OS_LIST, DEPARTMENTS, LOCATIONS, RISK_LEVELS, LIFECYCLE_STATES,
    )
except Exception:  # pragma: no cover
    EndpointAssetManager = None  # type: ignore
    get_asset_manager = None  # type: ignore
    OS_LIST, DEPARTMENTS, LOCATIONS = [], [], []
    RISK_LEVELS, LIFECYCLE_STATES = [], []

try:
    from endpoint_security.process_behavior import (
        ProcessBehaviorMonitor, get_process_monitor,
        SUSPICIOUS_CMDS, INJECTION_TYPES, PERSISTENCE_TYPES,
    )
except Exception:  # pragma: no cover
    ProcessBehaviorMonitor = None  # type: ignore
    get_process_monitor = None  # type: ignore
    SUSPICIOUS_CMDS, INJECTION_TYPES, PERSISTENCE_TYPES = [], [], []

try:
    from endpoint_security.malware_detection import (
        MalwareDetectionEngine, get_malware_engine,
        MALWARE_FAMILIES, YARA_RULES, RANSOMWARE_INDICATORS,
    )
except Exception:  # pragma: no cover
    MalwareDetectionEngine = None  # type: ignore
    get_malware_engine = None  # type: ignore
    MALWARE_FAMILIES, YARA_RULES, RANSOMWARE_INDICATORS = [], [], []

try:
    from endpoint_security.threat_response import (
        ThreatResponseManager, get_threat_manager,
        DETECTION_RULES, RESPONSE_ACTIONS,
    )
except Exception:  # pragma: no cover
    ThreatResponseManager = None  # type: ignore
    get_threat_manager = None  # type: ignore
    DETECTION_RULES, RESPONSE_ACTIONS = [], []

try:
    from endpoint_security.vulnerability_patch import (
        VulnerabilityPatchManager, get_vuln_manager,
        SAMPLE_CVES, BASELINE_CHECKS, PATCH_LIST,
    )
except Exception:  # pragma: no cover
    VulnerabilityPatchManager = None  # type: ignore
    get_vuln_manager = None  # type: ignore
    SAMPLE_CVES, BASELINE_CHECKS, PATCH_LIST = [], [], []

try:
    from endpoint_security.edr_dashboard import EDRDashboard, get_dashboard
except Exception:  # pragma: no cover
    EDRDashboard = None  # type: ignore
    get_dashboard = None  # type: ignore

__all__ = [
    "__version__", "__round__", "__direction__",
    "EndpointAssetManager", "get_asset_manager",
    "OS_LIST", "DEPARTMENTS", "LOCATIONS", "RISK_LEVELS", "LIFECYCLE_STATES",
    "ProcessBehaviorMonitor", "get_process_monitor",
    "SUSPICIOUS_CMDS", "INJECTION_TYPES", "PERSISTENCE_TYPES",
    "MalwareDetectionEngine", "get_malware_engine",
    "MALWARE_FAMILIES", "YARA_RULES", "RANSOMWARE_INDICATORS",
    "ThreatResponseManager", "get_threat_manager",
    "DETECTION_RULES", "RESPONSE_ACTIONS",
    "VulnerabilityPatchManager", "get_vuln_manager",
    "SAMPLE_CVES", "BASELINE_CHECKS", "PATCH_LIST",
    "EDRDashboard", "get_dashboard",
]
