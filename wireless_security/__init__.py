#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
无线网络安全模块
提供WiFi扫描、弱密码检测、无线网络安全评估功能
"""

import os
import re
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class WiFiNetwork:
    """WiFi网络信息"""
    bssid: str = ""
    ssid: str = ""
    signal_strength: int = 0
    channel: int = 0
    frequency: int = 0
    encryption: str = ""
    cipher: str = ""
    authentication: str = ""
    is_hidden: bool = False
    is_wps_enabled: bool = False
    vendor: str = ""
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class WiFiVulnerability:
    """WiFi漏洞"""
    bssid: str = ""
    ssid: str = ""
    vulnerability: str = ""
    severity: str = ""
    description: str = ""
    recommendation: str = ""
    evidence: str = ""


class WirelessSecurityScanner:
    """无线网络安全扫描器"""

    # 常见弱密码
    WEAK_PASSWORDS = [
        '12345678', 'password', '123456789', 'qwerty', 'abc123',
        '11111111', '1234567', 'iloveyou', 'admin', 'welcome',
        'monkey', 'dragon', 'master', 'login', 'princess',
        'qwerty123', 'solo', 'passw0rd', 'starwars',
        '00000000', '88888888', '66666666', '123123123',
        'a1234567', '1234qwer', 'q1w2e3r4', 'asdfghjk',
        'zxcvbnm,', '1qaz2wsx', '1q2w3e4r', 'qazwsxed',
    ]

    # 默认密码（路由器厂商）
    DEFAULT_PASSWORDS = {
        'TP-Link': ['admin', 'password', '12345678'],
        'D-Link': ['admin', 'password', ''],
        'Netgear': ['admin', 'password', '12345678'],
        'Linksys': ['admin', 'password', ''],
        'ASUS': ['admin', 'password', '12345678'],
        'Huawei': ['admin', 'admin@huawei.com', ''],
        'Xiaomi': ['admin', '12345678', ''],
        'Tenda': ['admin', '12345678', ''],
        'Mercury': ['admin', 'admin', '12345678'],
        'Fast': ['admin', 'admin', '12345678'],
    }

    def __init__(self):
        self.networks: List[WiFiNetwork] = []
        self.vulnerabilities: List[WiFiVulnerability] = []

    def scan_wifi(self, interface: str = "wlan0", duration: int = 10) -> List[WiFiNetwork]:
        """扫描WiFi网络"""
        networks = []

        try:
            # Windows系统使用netsh
            if os.name == 'nt':
                networks = self._scan_wifi_windows()
            # Linux系统使用iwlist
            else:
                networks = self._scan_wifi_linux(interface, duration)

        except Exception as e:
            print(f"WiFi扫描错误: {e}")

        self.networks = networks
        return networks

    def _scan_wifi_windows(self) -> List[WiFiNetwork]:
        """Windows系统扫描WiFi"""
        networks = []

        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True, text=True, timeout=30,
                encoding='gbk', errors='ignore'
            )
            output = result.stdout

            current_network = None
            for line in output.split('\n'):
                line = line.strip()

                if line.startswith('SSID') and 'BSSID' not in line:
                    if current_network:
                        networks.append(current_network)
                    ssid = line.split(':', 1)[1].strip() if ':' in line else ''
                    current_network = WiFiNetwork(ssid=ssid)

                elif current_network and 'BSSID' in line:
                    bssid = line.split(':', 1)[1].strip() if ':' in line else ''
                    current_network.bssid = bssid

                elif current_network and '信号' in line or 'Signal' in line:
                    match = re.search(r'(\d+)%', line)
                    if match:
                        current_network.signal_strength = int(match.group(1))

                elif current_network and ('频道' in line or 'Channel' in line):
                    match = re.search(r'(\d+)', line)
                    if match:
                        current_network.channel = int(match.group(1))

                elif current_network and ('身份验证' in line or 'Authentication' in line):
                    current_network.authentication = line.split(':', 1)[1].strip() if ':' in line else ''

                elif current_network and ('加密' in line or 'Cipher' in line):
                    current_network.encryption = line.split(':', 1)[1].strip() if ':' in line else ''

            if current_network:
                networks.append(current_network)

        except Exception as e:
            print(f"Windows WiFi扫描错误: {e}")

        return networks

    def _scan_wifi_linux(self, interface: str, duration: int) -> List[WiFiNetwork]:
        """Linux系统扫描WiFi"""
        networks = []

        try:
            result = subprocess.run(
                ['iwlist', interface, 'scan'],
                capture_output=True, text=True, timeout=30
            )
            output = result.stdout

            current_network = None
            for line in output.split('\n'):
                line = line.strip()

                if line.startswith('Cell'):
                    if current_network:
                        networks.append(current_network)
                    match = re.search(r'([0-9A-Fa-f:]{17})', line)
                    current_network = WiFiNetwork(bssid=match.group(1) if match else '')

                elif current_network and 'ESSID' in line:
                    match = re.search(r'ESSID:"([^"]*)"', line)
                    if match:
                        current_network.ssid = match.group(1)
                        current_network.is_hidden = match.group(1) == ''

                elif current_network and 'Signal level' in line:
                    match = re.search(r'Signal level=(-?\d+)', line)
                    if match:
                        current_network.signal_strength = int(match.group(1))

                elif current_network and 'Channel' in line:
                    match = re.search(r'Channel:(\d+)', line)
                    if match:
                        current_network.channel = int(match.group(1))

                elif current_network and 'Encryption key' in line:
                    current_network.encryption = 'WPA/WPA2' if 'on' in line else 'Open'

            if current_network:
                networks.append(current_network)

        except Exception as e:
            print(f"Linux WiFi扫描错误: {e}")

        return networks

    def assess_security(self, network: WiFiNetwork) -> List[WiFiVulnerability]:
        """评估单个WiFi网络的安全性"""
        vulns = []

        # 开放网络
        if not network.encryption or network.encryption.lower() in ['open', 'none', '']:
            vulns.append(WiFiVulnerability(
                bssid=network.bssid,
                ssid=network.ssid,
                vulnerability='开放网络',
                severity='Critical',
                description='该网络未启用任何加密，任何人都可以连接并窃听流量',
                recommendation='启用WPA2/WPA3加密，设置强密码',
                evidence=f'加密方式: {network.encryption or "无"}'
            ))

        # WEP加密（已破解）
        elif 'wep' in network.encryption.lower():
            vulns.append(WiFiVulnerability(
                bssid=network.bssid,
                ssid=network.ssid,
                vulnerability='WEP加密',
                severity='Critical',
                description='WEP加密已被完全破解，攻击者可以在几分钟内破解密码',
                recommendation='升级到WPA2/WPA3加密',
                evidence=f'加密方式: {network.encryption}'
            ))

        # WPA（旧版本）
        elif network.encryption.lower() == 'wpa' and 'wpa2' not in network.encryption.lower():
            vulns.append(WiFiVulnerability(
                bssid=network.bssid,
                ssid=network.ssid,
                vulnerability='WPA加密',
                severity='High',
                description='WPA加密存在已知漏洞（KRACK），建议升级到WPA2/WPA3',
                recommendation='升级到WPA2/WPA3加密',
                evidence=f'加密方式: {network.encryption}'
            ))

        # 弱密码检测（基于SSID特征）
        if self._is_likely_weak_password(network):
            vulns.append(WiFiVulnerability(
                bssid=network.bssid,
                ssid=network.ssid,
                vulnerability='可能使用弱密码',
                severity='Medium',
                description='根据SSID特征，该网络可能使用常见弱密码或默认密码',
                recommendation='使用强密码（至少12位，包含大小写字母、数字、特殊字符）',
                evidence=f'SSID: {network.ssid}'
            ))

        # WPS启用
        if network.is_wps_enabled:
            vulns.append(WiFiVulnerability(
                bssid=network.bssid,
                ssid=network.ssid,
                vulnerability='WPS启用',
                severity='High',
                description='WPS存在暴力破解漏洞，攻击者可以在几小时内破解WPS PIN',
                recommendation='禁用WPS功能',
                evidence='WPS已启用'
            ))

        # 隐藏网络（安全错觉）
        if network.is_hidden:
            vulns.append(WiFiVulnerability(
                bssid=network.bssid,
                ssid=network.ssid,
                vulnerability='隐藏SSID',
                severity='Low',
                description='隐藏SSID不能提供真正的安全，攻击者仍可以通过监控发现网络',
                recommendation='不要依赖隐藏SSID作为安全措施，使用强加密和强密码',
                evidence='SSID已隐藏'
            ))

        # 信号过强（可能泄露到外部）
        if network.signal_strength > -50:
            vulns.append(WiFiVulnerability(
                bssid=network.bssid,
                ssid=network.ssid,
                vulnerability='信号过强',
                severity='Low',
                description='WiFi信号过强可能泄露到建筑物外部，增加攻击面',
                recommendation='调整发射功率，限制信号覆盖范围',
                evidence=f'信号强度: {network.signal_strength} dBm'
            ))

        self.vulnerabilities.extend(vulns)
        return vulns

    def _is_likely_weak_password(self, network: WiFiNetwork) -> bool:
        """判断是否可能使用弱密码（基于SSID特征）"""
        ssid_lower = network.ssid.lower()

        # 常见路由器默认SSID
        default_ssids = ['tp-link', 'd-link', 'netgear', 'linksys', 'asus',
                         'huawei', 'xiaomi', 'tenda', 'mercury', 'fast',
                         'cmcc', 'china-net', 'tp_', 'tenda_', 'mercury_']

        for default in default_ssids:
            if default in ssid_lower:
                return True

        # SSID包含电话号码、生日等（可能密码也是）
        if re.search(r'\d{8,}', network.ssid):
            return True

        # SSID过于简单
        if len(network.ssid) < 5:
            return True

        return False

    def audit_all_networks(self) -> List[WiFiVulnerability]:
        """审计所有扫描到的网络"""
        all_vulns = []
        for network in self.networks:
            vulns = self.assess_security(network)
            all_vulns.extend(vulns)
        return all_vulns

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {
            'total_networks': len(self.networks),
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_encryption': {},
            'by_severity': {},
            'open_networks': 0,
            'wep_networks': 0,
            'wpa_networks': 0,
            'wpa2_networks': 0,
            'hidden_networks': 0,
        }

        for network in self.networks:
            enc = network.encryption.lower() if network.encryption else 'open'
            stats['by_encryption'][network.encryption or 'Open'] = \
                stats['by_encryption'].get(network.encryption or 'Open', 0) + 1

            if not network.encryption or 'open' in enc or 'none' in enc:
                stats['open_networks'] += 1
            elif 'wep' in enc:
                stats['wep_networks'] += 1
            elif 'wpa2' in enc or 'wpa3' in enc:
                stats['wpa2_networks'] += 1
            elif 'wpa' in enc:
                stats['wpa_networks'] += 1

            if network.is_hidden:
                stats['hidden_networks'] += 1

        for vuln in self.vulnerabilities:
            stats['by_severity'][vuln.severity] = stats['by_severity'].get(vuln.severity, 0) + 1

        return stats

    def generate_report(self) -> Dict:
        """生成无线网络安全报告"""
        return {
            'report_title': '无线网络安全评估报告',
            'generated_time': datetime.now().isoformat(),
            'statistics': self.get_statistics(),
            'networks': [
                {
                    'bssid': n.bssid,
                    'ssid': n.ssid or '(隐藏)',
                    'signal_strength': n.signal_strength,
                    'channel': n.channel,
                    'encryption': n.encryption,
                    'is_hidden': n.is_hidden,
                    'is_wps_enabled': n.is_wps_enabled,
                }
                for n in self.networks
            ],
            'vulnerabilities': [
                {
                    'bssid': v.bssid,
                    'ssid': v.ssid,
                    'vulnerability': v.vulnerability,
                    'severity': v.severity,
                    'description': v.description,
                    'recommendation': v.recommendation,
                    'evidence': v.evidence,
                }
                for v in self.vulnerabilities
            ],
            'security_recommendations': [
                '使用WPA3或WPA2-AES加密，不要使用WEP或开放网络',
                '使用强密码（至少12位，包含大小写字母、数字、特殊字符）',
                '禁用WPS功能',
                '定期更换WiFi密码',
                '调整发射功率，限制信号覆盖范围',
                '启用MAC地址过滤（辅助措施）',
                '禁用远程管理功能',
                '定期更新路由器固件',
                '使用访客网络隔离访客设备',
                '监控连接设备，发现异常设备及时处理',
            ]
        }


# 全局单例
_wireless_scanner = None

def get_wireless_security_scanner() -> WirelessSecurityScanner:
    """获取无线网络安全扫描器单例"""
    global _wireless_scanner
    if _wireless_scanner is None:
        _wireless_scanner = WirelessSecurityScanner()
    return _wireless_scanner


# ===== 第12轮深化模块导出 =====
try:
    from .wifi_scanner import WiFiScanner  # noqa: E402
    from .wifi_security import WiFiSecurityAssessor, WEAK_PASSWORD_DICTIONARY  # noqa: E402
    from .evil_twin_detector import EvilTwinDetector  # noqa: E402
    from .bluetooth_security import BluetoothSecurityAnalyzer  # noqa: E402
    from .zigbee_security import ZigbeeSecurityAnalyzer  # noqa: E402
    from .spectrum_analyzer import SpectrumAnalyzer  # noqa: E402
    from .wireless_assessment_workflow import WirelessAssessmentWorkflow  # noqa: E402
except Exception:  # pragma: no cover
    WiFiScanner = None  # type: ignore
    WiFiSecurityAssessor = None  # type: ignore
    WEAK_PASSWORD_DICTIONARY = []  # type: ignore
    EvilTwinDetector = None  # type: ignore
    BluetoothSecurityAnalyzer = None  # type: ignore
    ZigbeeSecurityAnalyzer = None  # type: ignore
    SpectrumAnalyzer = None  # type: ignore
    WirelessAssessmentWorkflow = None  # type: ignore

__all__ = [
    "WiFiNetwork", "WiFiVulnerability", "WirelessSecurityScanner",
    "get_wireless_security_scanner",
    "WiFiScanner", "WiFiSecurityAssessor", "WEAK_PASSWORD_DICTIONARY",
    "EvilTwinDetector", "BluetoothSecurityAnalyzer",
    "ZigbeeSecurityAnalyzer", "SpectrumAnalyzer",
    "WirelessAssessmentWorkflow",
]
