# -*- coding: utf-8 -*-
"""
威胁情报与攻击面管理包（第23轮升级方向3）。

模块：
- intel_sources    威胁情报源接入与标准化
- ioc_manager      IOC管理与检测
- attack_surface   攻击面管理
- vuln_intel       漏洞情报管理
- threat_actor     威胁Actor与TTPs
- intel_dashboard  威胁情报控制台聚合

兼容：保留旧版 IOCManager / ThreatActorManager / SampleAnalyzer / ThreatHuntingManager 延迟导入。
"""

from __future__ import annotations

__all__ = [
    "IntelSourceManager", "IOCManager", "AttackSurfaceManager",
    "VulnIntelManager", "ThreatActorManager", "IntelDashboard",
    # 兼容旧版
    "SampleAnalyzer", "ThreatHuntingManager",
]


def __getattr__(name):
    """延迟加载。"""
    if name == "IntelSourceManager":
        from threat_intel.intel_sources import IntelSourceManager
        return IntelSourceManager
    if name == "IOCManager":
        from threat_intel.ioc_manager import IOCManager
        return IOCManager
    if name == "AttackSurfaceManager":
        from threat_intel.attack_surface import AttackSurfaceManager
        return AttackSurfaceManager
    if name == "VulnIntelManager":
        from threat_intel.vuln_intel import VulnIntelManager
        return VulnIntelManager
    if name == "ThreatActorManager":
        from threat_intel.threat_actor import ThreatActorManager
        return ThreatActorManager
    if name == "IntelDashboard":
        from threat_intel.intel_dashboard import IntelDashboard
        return IntelDashboard
    if name == "SampleAnalyzer":
        from threat_intel.sample_analyzer import SampleAnalyzer
        return SampleAnalyzer
    if name == "ThreatHuntingManager":
        from threat_intel.threat_hunting import ThreatHuntingManager
        return ThreatHuntingManager
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
