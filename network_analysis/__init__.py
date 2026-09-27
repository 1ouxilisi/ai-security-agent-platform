#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
network_analysis — 网络流量分析 NTA/NDR 模块（第 17 轮升级方向 2）。

提供网络流量检测/监控/分析视角的一体化能力：
    - traffic_capture      流量捕获与解析（PCAP离线/实时监控/协议解析/统计/重组）
    - anomaly_detection    异常流量检测（基线学习/突增突降/隧道/DGA/端口扫描）
    - network_behavior     网络行为分析（实体画像/通信图谱/拓扑发现/横向移动/数据渗出）
    - threat_rules         威胁检测规则（签名/行为/YARA/情报匹配/自定义规则引擎）
    - traffic_forensics    流量取证与回放（PCAP管理/搜索/会话回放/文件提取/证据包）
    - ndr_dashboard        NDR运营仪表盘（实时大屏/告警管理/威胁地图/健康状态/度量）

设计定位：
    - 仅做检测、监控、分析、管理视角的网络安全运营，不提供攻击/渗透工具。
    - 所有功能仅用于经过授权的网络流量安全分析，输出检测报告与告警。
    - 第三方库（scapy等）一律 try-import，不可用时自动回退到内嵌模拟/离线数据。
    - Python 3.14 兼容。
"""

from __future__ import annotations

__version__ = "17.2.0"
__round__ = 17
__direction__ = 2

# 核心类与工厂函数（try-import，避免单个模块缺失导致整个包不可用）
try:
    from network_analysis.traffic_capture import (
        TrafficCaptureEngine, PCAP_PROTOCOLS, BPF_FILTER_PRESETS,
    )
except Exception:  # pragma: no cover
    TrafficCaptureEngine = None  # type: ignore
    PCAP_PROTOCOLS = {}
    BPF_FILTER_PRESETS = {}

try:
    from network_analysis.anomaly_detection import (
        AnomalyDetectionEngine, TUNNEL_SIGNATURES, DGA_FEATURES,
    )
except Exception:  # pragma: no cover
    AnomalyDetectionEngine = None  # type: ignore
    TUNNEL_SIGNATURES = {}
    DGA_FEATURES = {}

try:
    from network_analysis.network_behavior import (
        NetworkBehaviorAnalyzer, LATERAL_MOVEMENT_INDICATORS,
    )
except Exception:  # pragma: no cover
    NetworkBehaviorAnalyzer = None  # type: ignore
    LATERAL_MOVEMENT_INDICATORS = {}

try:
    from network_analysis.threat_rules import (
        ThreatRuleEngine, SNORT_RULE_LIBRARY, YARA_RULE_LIBRARY,
    )
except Exception:  # pragma: no cover
    ThreatRuleEngine = None  # type: ignore
    SNORT_RULE_LIBRARY = []
    YARA_RULE_LIBRARY = []

try:
    from network_analysis.traffic_forensics import (
        TrafficForensicsManager, EVIDENCE_PACK_TEMPLATES,
    )
except Exception:  # pragma: no cover
    TrafficForensicsManager = None  # type: ignore
    EVIDENCE_PACK_TEMPLATES = {}

try:
    from network_analysis.ndr_dashboard import (
        NDRDashboard, NDR_METRICS_DEFINITIONS,
    )
except Exception:  # pragma: no cover
    NDRDashboard = None  # type: ignore
    NDR_METRICS_DEFINITIONS = {}

__all__ = [
    "__version__", "__round__", "__direction__",
    "TrafficCaptureEngine", "PCAP_PROTOCOLS", "BPF_FILTER_PRESETS",
    "AnomalyDetectionEngine", "TUNNEL_SIGNATURES", "DGA_FEATURES",
    "NetworkBehaviorAnalyzer", "LATERAL_MOVEMENT_INDICATORS",
    "ThreatRuleEngine", "SNORT_RULE_LIBRARY", "YARA_RULE_LIBRARY",
    "TrafficForensicsManager", "EVIDENCE_PACK_TEMPLATES",
    "NDRDashboard", "NDR_METRICS_DEFINITIONS",
]
