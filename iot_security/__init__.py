# -*- coding: utf-8 -*-
"""
iot_security — IoT安全深化模块（第12轮升级）。

提供：设备发现与指纹、固件分析、协议安全、默认凭据检测、
通信安全分析、漏洞检测、综合评估工作流。

所有功能为防御/评估/检测视角，仅对授权网络和设备进行安全评估，
不实际入侵或破坏设备；弱口令检测仅评估风险，不实际破解。
"""

from __future__ import annotations

__version__ = "12.0.0"
__all__ = [
    "device_discovery",
    "firmware_analyzer",
    "protocol_security",
    "default_credentials",
    "communication_security",
    "vulnerability_detector",
    "iot_assessment_workflow",
]
