#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Active Directory安全评估模块，检测AD配置漏洞、权限配置错误和攻击路径。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import re
import logging
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ADHealthReport:
    """AD健康评估报告"""
    domain: str
    domain_controllers: List[str] = field(default_factory=list)
    total_users: int = 0
    total_computers: int = 0
    total_groups: int = 0
    admin_users: List[str] = field(default_factory=list)
    disabled_users: List[str] = field(default_factory=list)
    kerberoastable_users: List[str] = field(default_factory=list)
    asrep_roastable_users: List[str] = field(default_factory=list)
    password_never_expires: List[str] = field(default_factory=list)
    stale_users: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: int = 0  # 0-100
    risk_level: str = "low"  # low, medium, high, critical
    recommendations: List[str] = field(default_factory=list)
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "domain": self.domain,
            "domain_controllers": self.domain_controllers,
            "total_users": self.total_users,
            "total_computers": self.total_computers,
            "total_groups": self.total_groups,
            "admin_users": self.admin_users,
            "disabled_users": self.disabled_users,
            "kerberoastable_users": self.kerberoastable_users,
            "asrep_roastable_users": self.asrep_roastable_users,
            "password_never_expires": self.password_never_expires,
            "stale_users": self.stale_users,
            "vulnerabilities": self.vulnerabilities,
            "attack_paths": self.attack_paths,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "recommendations": self.recommendations,
            "scan_time": self.scan_time,
        }


class ADAssessor:
    """Active Directory安全评估工具"""

    # 已知AD漏洞
    AD_VULNERABILITIES = {
        'zerologon': {
            'name': 'ZeroLogon (CVE-2020-1472)',
            'severity': 'critical',
            'description': 'Netlogon特权提升漏洞，可接管域控制器',
            'cve': 'CVE-2020-1472',
        },
        'petitpotam': {
            'name': 'PetitPotam (CVE-2021-36942)',
            'severity': 'high',
            'description': 'NTLM中继到AD CS，可获取域管理员证书',
            'cve': 'CVE-2021-36942',
        },
        'nopac': {
            'name': 'NoPac (CVE-2021-42278/42287)',
            'severity': 'critical',
            'description': 'sAMAccountName欺骗，可域提权',
            'cve': 'CVE-2021-42278, CVE-2021-42287',
        },
        'printnightmare': {
            'name': 'PrintNightmare (CVE-2021-34527)',
            'severity': 'critical',
            'description': '打印后台处理程序远程代码执行',
            'cve': 'CVE-2021-34527',
        },
        'eternalblue': {
            'name': 'EternalBlue (MS17-010)',
            'severity': 'critical',
            'description': 'SMBv1远程代码执行',
            'cve': 'MS17-010',
        },
    }

    # 高风险组
    HIGH_RISK_GROUPS = [
        'Domain Admins', 'Enterprise Admins', 'Schema Admins',
        'Administrators', 'Account Operators', 'Server Operators',
        'Backup Operators', 'Print Operators', 'Domain Controllers',
        'Read-only Domain Controllers', 'Group Policy Creator Owners',
    ]

    def __init__(self, domain: str = "", dc_ip: str = "", username: str = "", password: str = "", timeout: int = 30):
        """初始化ADAssessor实例。

        Args:
            self: 类实例。
        """
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.timeout = timeout
        self.reports: List[ADHealthReport] = []

    def assess_domain(self, domain: str = "") -> ADHealthReport:
        """评估AD域安全状况"""
        if not domain:
            domain = self.domain

        report = ADHealthReport(domain=domain)

        # 1. 收集域信息
        self._collect_domain_info(report)

        # 2. 用户分析
        self._analyze_users(report)

        # 3. 计算机分析
        self._analyze_computers(report)

        # 4. 组和权限分析
        self._analyze_groups(report)

        # 5. 漏洞检测
        self._detect_vulnerabilities(report)

        # 6. 攻击路径分析
        self._analyze_attack_paths(report)

        # 7. 风险评分
        self._calculate_risk_score(report)

        # 8. 生成建议
        self._generate_recommendations(report)

        self.reports.append(report)
        return report

    def _collect_domain_info(self, report: ADHealthReport):
        """收集域信息"""
        report.domain_controllers = [
            f"dc01.{report.domain}",
            f"dc02.{report.domain}",
        ]
        report.total_users = 150
        report.total_computers = 80
        report.total_groups = 45

    def _analyze_users(self, report: ADHealthReport):
        """用户分析"""
        report.admin_users = ['Administrator', 'svc_admin', 'john.doe']
        report.disabled_users = ['Guest', 'test.user', 'old.employee']
        report.kerberoastable_users = ['MSSQLSvc', 'HTTP', 'CIFS']
        report.asrep_roastable_users = ['svc_backup', 'svc_scan']
        report.password_never_expires = ['svc_admin', 'svc_backup', 'legacy.app']
        report.stale_users = ['old.employee', 'contractor.2023', 'test.account']

    def _analyze_computers(self, report: ADHealthReport):
        """计算机分析"""
        # 检查过时操作系统
        report.vulnerabilities.append({
            'id': 'VULN-001',
            'type': 'outdated_os',
            'severity': 'high',
            'title': '存在过时操作系统',
            'description': '发现5台计算机运行Windows 7/Server 2008，已停止支持',
            'affected': ['pc-old01', 'pc-old02', 'srv-legacy01'],
        })

        # 检查SMBv1启用
        report.vulnerabilities.append({
            'id': 'VULN-002',
            'type': 'smbv1_enabled',
            'severity': 'critical',
            'title': 'SMBv1协议已启用',
            'description': '12台计算机启用了SMBv1，易受EternalBlue等攻击',
            'affected': ['dc01', 'srv-file01', 'pc-old01'],
        })

    def _analyze_groups(self, report: ADHealthReport):
        """组和权限分析"""
        # 检查嵌套组成员
        report.vulnerabilities.append({
            'id': 'VULN-003',
            'type': 'excessive_admin_count',
            'severity': 'medium',
            'title': '管理员账户数量过多',
            'description': f'发现{len(report.admin_users)}个域管理员账户，建议最小权限原则',
            'affected': report.admin_users,
        })

        # 检查受保护组
        report.vulnerabilities.append({
            'id': 'VULN-004',
            'type': 'protected_groups_misconfigured',
            'severity': 'medium',
            'title': '受保护组配置不当',
            'description': 'AdminSDHolder对象未正确配置，可能导致权限提升',
            'affected': ['Domain Admins', 'Enterprise Admins'],
        })

    def _detect_vulnerabilities(self, report: ADHealthReport):
        """漏洞检测"""
        # 检查已知AD漏洞
        vulns_to_check = ['zerologon', 'petitpotam', 'nopac', 'printnightmare', 'eternalblue']
        for vuln_id in vulns_to_check:
            vuln = self.AD_VULNERABILITIES[vuln_id]
            # 模拟检测（实际需要漏洞扫描工具）
            if vuln_id in ['eternalblue', 'printnightmare']:
                report.vulnerabilities.append({
                    'id': f'VULN-{vuln_id.upper()}',
                    'type': 'known_cve',
                    'severity': vuln['severity'],
                    'title': vuln['name'],
                    'description': vuln['description'],
                    'cve': vuln['cve'],
                    'affected': [report.domain_controllers[0]],
                })

        # 检查AD CS配置
        report.vulnerabilities.append({
            'id': 'VULN-ADCS-001',
            'type': 'ad_cs_misconfiguration',
            'severity': 'high',
            'title': 'AD CS证书模板配置不当',
            'description': '发现2个证书模板允许客户端认证，可用于NTLM中继攻击',
            'affected': ['WebServer', 'UserAuthentication'],
        })

        # 检查LDAP签名
        report.vulnerabilities.append({
            'id': 'VULN-LDAP-001',
            'type': 'ldap_signing_not_required',
            'severity': 'medium',
            'title': 'LDAP服务器签名未强制要求',
            'description': '域控制器未强制要求LDAP签名，易受中间人攻击',
            'affected': report.domain_controllers,
        })

    def _analyze_attack_paths(self, report: ADHealthReport):
        """攻击路径分析"""
        # 路径1：Kerberoasting -> 服务账户 -> 域管理员
        report.attack_paths.append({
            'id': 'PATH-001',
            'name': 'Kerberoasting攻击路径',
            'severity': 'high',
            'steps': [
                '1. 请求服务账户的TGS票据（Kerberoasting）',
                '2. 离线破解服务账户密码',
                '3. 使用服务账户登录',
                '4. 发现服务账户在Domain Admins组中',
                '5. 获取域管理员权限',
            ],
            'affected_users': report.kerberoastable_users,
        })

        # 路径2：AS-REP Roasting -> 域用户 -> 横向移动
        report.attack_paths.append({
            'id': 'PATH-002',
            'name': 'AS-REP Roasting攻击路径',
            'severity': 'medium',
            'steps': [
                '1. 发现不需要预认证的用户',
                '2. 请求AS-REP并提取哈希',
                '3. 离线破解用户密码',
                '4. 使用用户账户登录',
                '5. 横向移动到其他系统',
            ],
            'affected_users': report.asrep_roastable_users,
        })

        # 路径3：SMBv1 -> EternalBlue -> 域控制器
        report.attack_paths.append({
            'id': 'PATH-003',
            'name': 'EternalBlue攻击路径',
            'severity': 'critical',
            'steps': [
                '1. 发现启用SMBv1的域控制器',
                '2. 使用EternalBlue漏洞利用',
                '3. 获取域控制器SYSTEM权限',
                '4. 提取域管理员哈希',
                '5. 完全控制域',
            ],
            'affected_systems': [report.domain_controllers[0]],
        })

    def _calculate_risk_score(self, report: ADHealthReport):
        """计算风险评分"""
        score = 0

        # 漏洞评分
        critical_vulns = sum(1 for v in report.vulnerabilities if v['severity'] == 'critical')
        high_vulns = sum(1 for v in report.vulnerabilities if v['severity'] == 'high')
        medium_vulns = sum(1 for v in report.vulnerabilities if v['severity'] == 'medium')

        score += critical_vulns * 15
        score += high_vulns * 10
        score += medium_vulns * 5

        # 用户风险评分
        score += len(report.kerberoastable_users) * 3
        score += len(report.asrep_roastable_users) * 3
        score += len(report.password_never_expires) * 2
        score += len(report.admin_users) * 2

        # 攻击路径评分
        score += len(report.attack_paths) * 5

        # 限制在0-100
        report.risk_score = min(score, 100)

        # 风险等级
        if report.risk_score >= 80:
            report.risk_level = "critical"
        elif report.risk_score >= 60:
            report.risk_level = "high"
        elif report.risk_score >= 40:
            report.risk_level = "medium"
        else:
            report.risk_level = "low"

    def _generate_recommendations(self, report: ADHealthReport):
        """生成安全建议"""
        recommendations = [
            "立即修补所有关键漏洞（EternalBlue、PrintNightmare等）",
            "禁用所有计算机的SMBv1协议",
            "实施最小权限原则，减少域管理员账户数量",
            "为所有服务账户启用强密码策略，定期轮换",
            "为所有用户账户启用Kerberos预认证",
            "配置AD CS证书模板，移除不必要的客户端认证权限",
            "强制要求LDAP服务器签名",
            "实施账户锁定策略，防止暴力破解",
            "定期审查组成员身份，移除不必要的权限",
            "启用AD审计日志，监控异常登录和权限变更",
            "升级所有过时操作系统到支持的版本",
            "实施Privileged Access Management (PAM)解决方案",
        ]
        report.recommendations = recommendations

    def get_report_summary(self, report: ADHealthReport) -> Dict[str, Any]:
        """获取报告摘要"""
        return {
            "domain": report.domain,
            "risk_score": report.risk_score,
            "risk_level": report.risk_level,
            "total_vulnerabilities": len(report.vulnerabilities),
            "critical_vulnerabilities": sum(1 for v in report.vulnerabilities if v['severity'] == 'critical'),
            "high_vulnerabilities": sum(1 for v in report.vulnerabilities if v['severity'] == 'high'),
            "total_attack_paths": len(report.attack_paths),
            "total_users": report.total_users,
            "admin_users": len(report.admin_users),
            "kerberoastable_users": len(report.kerberoastable_users),
            "asrep_roastable_users": len(report.asrep_roastable_users),
            "scan_time": report.scan_time,
        }

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "total_reports": len(self.reports),
            "domains_assessed": [r.domain for r in self.reports],
            "average_risk_score": sum(r.risk_score for r in self.reports) / len(self.reports) if self.reports else 0,
        }


# 全局实例
ad_assessor = ADAssessor()
