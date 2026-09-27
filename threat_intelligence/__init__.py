#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
威胁情报模块
提供IOC查询、威胁情报聚合、IP/域名信誉评估、恶意软件情报功能
"""

import os
import re
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class IOC:
    """失陷指标"""
    ioc_type: str = ""  # ip/domain/url/hash/md5/sha256
    value: str = ""
    threat_type: str = ""
    severity: str = ""
    confidence: str = ""
    first_seen: str = ""
    last_seen: str = ""
    source: str = ""
    description: str = ""
    related_ttps: List[str] = field(default_factory=list)


class ThreatIntelligence:
    """威胁情报分析器"""

    # 内置威胁情报库（示例数据）
    BUILTIN_IOCS = [
        {'type': 'ip', 'value': '192.168.1.100', 'threat': 'C2服务器', 'severity': 'High'},
        {'type': 'domain', 'value': 'malicious-example.com', 'threat': '钓鱼域名', 'severity': 'High'},
        {'type': 'md5', 'value': 'd41d8cd98f00b204e9800998ecf8427e', 'threat': '恶意软件', 'severity': 'Critical'},
        {'type': 'sha256', 'value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'threat': '勒索软件', 'severity': 'Critical'},
        {'type': 'url', 'value': 'http://malicious-example.com/payload.exe', 'threat': '恶意下载', 'severity': 'High'},
    ]

    # MITRE ATT&CK 战术
    ATTACK_TACTICS = [
        {'id': 'TA0001', 'name': '初始访问', 'techniques': ['钓鱼', '漏洞利用', '供应链攻击', '有效账户']},
        {'id': 'TA0002', 'name': '执行', 'techniques': ['命令行', 'PowerShell', '计划任务', '服务执行']},
        {'id': 'TA0003', 'name': '持久化', 'techniques': ['注册表运行键', '计划任务', '服务', '启动文件夹']},
        {'id': 'TA0004', 'name': '权限提升', 'techniques': ['令牌窃取', '进程注入', '漏洞利用', 'UAC绕过']},
        {'id': 'TA0005', 'name': '防御规避', 'techniques': ['禁用安全工具', '混淆', '反调试', '根工具包']},
        {'id': 'TA0006', 'name': '凭证访问', 'techniques': ['凭证转储', '键盘记录', '暴力破解', '凭证窃取']},
        {'id': 'TA0007', 'name': '发现', 'techniques': ['系统信息发现', '网络发现', '文件发现', '账户发现']},
        {'id': 'TA0008', 'name': '横向移动', 'techniques': ['SMB/Windows管理共享', '远程桌面', 'WMI', 'PsExec']},
        {'id': 'TA0009', 'name': '收集', 'techniques': ['数据从本地系统收集', '剪贴板数据', '输入捕获', '邮件收集']},
        {'id': 'TA0010', 'name': '数据渗出', 'techniques': ['通过C2通道渗出', '通过可移动介质渗出', '数据压缩', '数据加密']},
        {'id': 'TA0011', 'name': '命令与控制', 'techniques': ['应用层协议', 'Web服务', '域名生成算法', '代理']},
        {'id': 'TA0040', 'name': '影响', 'techniques': ['数据销毁', '拒绝服务', '勒索软件', '磁盘结构擦除']},
    ]

    # 知名威胁组织
    THREAT_GROUPS = [
        {'name': 'APT28', 'alias': 'Fancy Bear', 'origin': '俄罗斯', 'targets': '政府、军事、媒体'},
        {'name': 'APT29', 'alias': 'Cozy Bear', 'origin': '俄罗斯', 'targets': '政府、智库、医疗'},
        {'name': 'APT31', 'alias': 'Zirconium', 'origin': '中国', 'targets': '政府、人权组织'},
        {'name': 'Lazarus', 'alias': 'Hidden Cobra', 'origin': '朝鲜', 'targets': '金融、加密货币'},
        {'name': 'APT33', 'alias': 'Elfin', 'origin': '伊朗', 'targets': '航空、能源'},
        {'name': 'APT34', 'alias': 'OilRig', 'origin': '伊朗', 'targets': '金融、政府、能源'},
        {'name': 'Conti', 'alias': '', 'origin': '俄罗斯', 'targets': '勒索软件即服务'},
        {'name': 'LockBit', 'alias': '', 'origin': '俄罗斯', 'targets': '勒索软件即服务'},
    ]

    def __init__(self):
        self.iocs: List[IOC] = []

    def query_ioc(self, ioc_value: str, ioc_type: str = "auto") -> List[Dict]:
        """查询IOC"""
        results = []

        # 自动检测IOC类型
        if ioc_type == "auto":
            ioc_type = self._detect_ioc_type(ioc_value)

        # 查询内置情报库
        for ioc in self.BUILTIN_IOCS:
            if ioc['value'].lower() == ioc_value.lower() or ioc['value'].lower() in ioc_value.lower():
                results.append({
                    'ioc_type': ioc['type'],
                    'value': ioc['value'],
                    'threat_type': ioc['threat'],
                    'severity': ioc['severity'],
                    'confidence': 'High',
                    'source': '内置威胁情报库',
                    'status': '匹配'
                })

        if not results:
            results.append({
                'ioc_type': ioc_type,
                'value': ioc_value,
                'threat_type': '未知',
                'severity': 'Unknown',
                'confidence': 'Low',
                'source': '本地查询',
                'status': '未匹配',
                'recommendation': '建议查询在线威胁情报平台（VirusTotal、AbuseIPDB、ThreatConnect等）'
            })

        return results

    def _detect_ioc_type(self, value: str) -> str:
        """自动检测IOC类型"""
        # IP地址
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return 'ip'
        # MD5
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return 'md5'
        # SHA256
        if re.match(r'^[a-fA-F0-9]{64}$', value):
            return 'sha256'
        # SHA1
        if re.match(r'^[a-fA-F0-9]{40}$', value):
            return 'sha1'
        # URL
        if value.startswith('http://') or value.startswith('https://'):
            return 'url'
        # 域名
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$', value):
            return 'domain'
        return 'unknown'

    def assess_ip_reputation(self, ip: str) -> Dict:
        """评估IP信誉"""
        return {
            'ip': ip,
            'reputation_score': 50,
            'risk_level': 'Medium',
            'factors': [
                {'factor': '地理位置', 'status': '待查询'},
                {'factor': '是否为代理/VPN', 'status': '待查询'},
                {'factor': '是否为Tor节点', 'status': '待查询'},
                {'factor': '恶意软件报告', 'status': '待查询'},
                {'factor': '垃圾邮件报告', 'status': '待查询'},
                {'factor': '端口扫描行为', 'status': '待查询'},
            ],
            'recommendations': [
                '查询AbuseIPDB获取IP滥用报告',
                '查询VirusTotal获取IP安全评级',
                '查询Shodan获取IP开放服务信息',
                '检查IP是否在威胁情报黑名单中',
            ]
        }

    def assess_domain_reputation(self, domain: str) -> Dict:
        """评估域名信誉"""
        return {
            'domain': domain,
            'reputation_score': 50,
            'risk_level': 'Medium',
            'factors': [
                {'factor': '域名年龄', 'status': '待查询'},
                {'factor': '注册商', 'status': '待查询'},
                {'factor': 'DNS记录', 'status': '待查询'},
                {'factor': '是否为新注册域名', 'status': '待查询'},
                {'factor': '是否使用隐私保护', 'status': '待查询'},
                {'factor': '关联恶意软件', 'status': '待查询'},
            ],
            'suspicious_indicators': [
                '域名注册时间不足30天',
                '使用免费域名注册商',
                '域名包含品牌词（钓鱼特征）',
                '使用动态DNS服务',
                'DNS记录频繁变更',
            ],
            'recommendations': [
                '查询WHOIS获取域名注册信息',
                '查询VirusTotal获取域名安全评级',
                '查询URLScan.io获取域名历史截图',
                '检查域名是否在钓鱼网站黑名单中',
            ]
        }

    def get_attack_tactics(self) -> List[Dict]:
        """获取MITRE ATT&CK战术"""
        return self.ATTACK_TACTICS

    def get_threat_groups(self) -> List[Dict]:
        """获取威胁组织信息"""
        return self.THREAT_GROUPS

    def generate_threat_report(self) -> Dict:
        """生成威胁情报报告"""
        return {
            'report_title': '威胁情报报告',
            'generated_time': datetime.now().isoformat(),
            'summary': {
                'total_iocs_queried': len(self.iocs),
                'malicious_iocs': len([i for i in self.iocs if i.severity in ['Critical', 'High']]),
                'suspicious_iocs': len([i for i in self.iocs if i.severity == 'Medium']),
                'clean_iocs': len([i for i in self.iocs if i.severity == 'Low']),
            },
            'iocs': [
                {
                    'type': i.ioc_type,
                    'value': i.value,
                    'threat_type': i.threat_type,
                    'severity': i.severity,
                    'confidence': i.confidence,
                    'source': i.source,
                    'description': i.description,
                }
                for i in self.iocs
            ],
            'recommendations': [
                '建立威胁情报订阅机制',
                '将IOC集成到安全设备（防火墙、IDS/IPS）',
                '定期进行威胁狩猎',
                '建立威胁情报共享渠道',
                '关注新兴威胁和漏洞披露',
            ],
        }


# 全局单例
_threat_intel = None

def get_threat_intelligence() -> ThreatIntelligence:
    global _threat_intel
    if _threat_intel is None:
        _threat_intel = ThreatIntelligence()
    return _threat_intel
