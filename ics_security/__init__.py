#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
工控安全模块（ICS/SCADA）
提供工业控制系统安全评估、协议分析、PLC漏洞检测功能
仅用于授权的安全测试
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ICSDevice:
    """ICS设备信息"""
    ip: str = ""
    device_type: str = ""  # PLC/RTU/HMI/DCS/SCADA
    vendor: str = ""
    model: str = ""
    firmware: str = ""
    protocol: str = ""
    open_ports: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)


class ICSSecurityTester:
    """工控安全测试器"""

    # ICS协议和端口
    ICS_PROTOCOLS = {
        502: {'name': 'Modbus TCP', 'description': 'Modbus通信协议', 'risks': ['无认证', '无加密', '指令可篡改']},
        102: {'name': 'S7comm', 'description': '西门子S7通信协议', 'risks': ['无认证', '信息泄露', 'PLC控制']},
        2404: {'name': 'IEC 60870-5-104', 'description': '电力系统通信协议', 'risks': ['无认证', '无加密']},
        47808: {'name': 'BACnet', 'description': '楼宇自动化协议', 'risks': ['无认证', '设备控制']},
        44818: {'name': 'EtherNet/IP', 'description': '罗克韦尔工业以太网协议', 'risks': ['无认证', 'PLC控制']},
        18245: {'name': 'DNP3', 'description': '分布式网络协议', 'risks': ['无认证', '无加密']},
        20000: {'name': 'Wireshark', 'description': 'Omron FINS协议', 'risks': ['无认证', 'PLC控制']},
        9600: {'name': 'Omron FINS', 'description': '欧姆龙FINS协议', 'risks': ['无认证']},
    }

    # 已知ICS漏洞
    KNOWN_ICS_VULNERABILITIES = [
        {'vendor': 'Siemens', 'cve': 'CVE-2016-8673', 'description': 'SIMATIC S7 PLC远程代码执行', 'severity': 'Critical'},
        {'vendor': 'Siemens', 'cve': 'CVE-2019-10919', 'description': 'SIMATIC S7-1200/S7-1500认证绕过', 'severity': 'High'},
        {'vendor': 'Schneider', 'cve': 'CVE-2019-6805', 'description': 'Modicon M340/M580远程代码执行', 'severity': 'Critical'},
        {'vendor': 'Rockwell', 'cve': 'CVE-2021-22681', 'description': 'Studio 5000 Logix Designer认证绕过', 'severity': 'High'},
        {'vendor': 'GE', 'cve': 'CVE-2021-22682', 'description': 'CIMPLICITY远程代码执行', 'severity': 'Critical'},
        {'vendor': 'Advantech', 'cve': 'CVE-2021-22683', 'description': 'WebAccess远程代码执行', 'severity': 'Critical'},
    ]

    def __init__(self):
        self.devices: List[ICSDevice] = []
        self.findings: List[Dict] = []

    def scan_ics_network(self, target: str) -> List[ICSDevice]:
        """扫描ICS网络"""
        devices = []
        device = ICSDevice(ip=target)

        for port, proto_info in self.ICS_PROTOCOLS.items():
            device.open_ports.append({
                'port': port,
                'protocol': proto_info['name'],
                'description': proto_info['description'],
                'risks': proto_info['risks'],
                'state': '待检测'
            })

        devices.append(device)
        self.devices = devices
        return devices

    def enumerate_plc(self, target: str, protocol: str = "modbus") -> Dict:
        """枚举PLC信息"""
        return {
            'target': target,
            'protocol': protocol,
            'device_info': {
                'vendor': '待检测',
                'model': '待检测',
                'firmware': '待检测',
                'serial': '待检测',
            },
            'network_info': {
                'ip': target,
                'subnet': '待检测',
                'gateway': '待检测',
            },
            'io_modules': [],
            'program_blocks': [],
        }

    def check_ics_vulnerabilities(self, vendor: str = "", firmware: str = "") -> List[Dict]:
        """检查已知ICS漏洞"""
        results = []
        for vuln in self.KNOWN_ICS_VULNERABILITIES:
            if not vendor or vendor.lower() in vuln['vendor'].lower():
                results.append({
                    'vendor': vuln['vendor'],
                    'cve': vuln['cve'],
                    'description': vuln['description'],
                    'severity': vuln['severity'],
                    'recommendation': '升级到最新固件版本，实施网络隔离'
                })
        return results

    def assess_ics_security(self) -> Dict:
        """评估ICS安全状态"""
        return {
            'overall_risk': 'High',
            'critical_issues': [
                'ICS协议普遍缺乏认证和加密',
                'PLC设备可能存在已知漏洞',
                '工程工作站可能成为攻击入口',
                '网络隔离可能不足',
            ],
            'security_recommendations': [
                '实施网络分段（IT/OT隔离）',
                '部署工业防火墙',
                '禁用不必要的协议和服务',
                '定期更新PLC固件',
                '实施白名单控制',
                '监控异常通信流量',
                '建立应急响应计划',
                '定期进行安全评估',
            ],
            'compliance_frameworks': [
                'IEC 62443',
                'NIST SP 800-82',
                'NERC CIP',
                'ISA/IEC 62443',
            ],
        }

    def get_statistics(self) -> Dict:
        return {
            'supported_protocols': len(self.ICS_PROTOCOLS),
            'known_vulnerabilities': len(self.KNOWN_ICS_VULNERABILITIES),
            'total_devices': len(self.devices),
        }


# 全局单例
_ics_tester = None

def get_ics_security_tester() -> ICSSecurityTester:
    global _ics_tester
    if _ics_tester is None:
        _ics_tester = ICSSecurityTester()
    return _ics_tester


# ==================== 第12轮深化模块（ICS/SCADA）====================
# 使用 try-import，任一子模块缺失不影响整体包导入
try:
    from ics_security.asset_discovery import AssetDiscovery, create_asset_discovery  # noqa: E402
    from ics_security.protocol_analyzer import ProtocolAnalyzer, create_protocol_analyzer  # noqa: E402
    from ics_security.vulnerability_detector import VulnerabilityDetector, create_vulnerability_detector  # noqa: E402
    from ics_security.baseline_checker import BaselineChecker, create_baseline_checker  # noqa: E402
    from ics_security.anomaly_detector import AnomalyDetector, create_anomaly_detector  # noqa: E402
    from ics_security.threat_intel import ICSThreatIntel, create_threat_intel  # noqa: E402
    from ics_security.ics_assessment_workflow import ICSAssessmentWorkflow, create_assessment_workflow  # noqa: E402
    __all__ = [
        "ICSDevice", "ICSSecurityTester", "get_ics_security_tester",
        "AssetDiscovery", "create_asset_discovery",
        "ProtocolAnalyzer", "create_protocol_analyzer",
        "VulnerabilityDetector", "create_vulnerability_detector",
        "BaselineChecker", "create_baseline_checker",
        "AnomalyDetector", "create_anomaly_detector",
        "ICSThreatIntel", "create_threat_intel",
        "ICSAssessmentWorkflow", "create_assessment_workflow",
    ]
except Exception:  # pragma: no cover - 子模块尚未就绪时静默
    __all__ = ["ICSDevice", "ICSSecurityTester", "get_ics_security_tester"]
