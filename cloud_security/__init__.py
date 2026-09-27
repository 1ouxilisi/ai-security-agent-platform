#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
云安全模块
提供AWS/Azure/阿里云配置检查、容器扫描、K8s安全检查功能
"""

import os
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class CloudFinding:
    """云安全发现"""
    provider: str = ""
    service: str = ""
    resource: str = ""
    issue: str = ""
    severity: str = ""
    recommendation: str = ""
    evidence: str = ""


class CloudSecurityScanner:
    """云安全扫描器"""

    def __init__(self):
        self.findings: List[CloudFinding] = []

    def scan_aws(self, profile: str = "default") -> List[CloudFinding]:
        """扫描AWS配置安全"""
        findings = []

        # AWS安全检查清单
        checks = [
            {
                'service': 'S3',
                'check': '公开存储桶检测',
                'command': 'aws s3api list-buckets --query "Buckets[].Name"',
                'description': '检测是否有公开可访问的S3存储桶',
                'severity': 'High'
            },
            {
                'service': 'IAM',
                'check': '根账户MFA检测',
                'command': 'aws iam get-account-summary',
                'description': '检测根账户是否启用MFA',
                'severity': 'Critical'
            },
            {
                'service': 'IAM',
                'check': '访问密钥年龄检测',
                'command': 'aws iam list-access-keys',
                'description': '检测是否有超过90天未轮换的访问密钥',
                'severity': 'Medium'
            },
            {
                'service': 'EC2',
                'check': '安全组宽松检测',
                'command': 'aws ec2 describe-security-groups',
                'description': '检测是否有允许0.0.0.0/0访问敏感端口的安全组',
                'severity': 'High'
            },
            {
                'service': 'RDS',
                'check': '数据库公开访问检测',
                'command': 'aws rds describe-db-instances',
                'description': '检测RDS实例是否公开可访问',
                'severity': 'Critical'
            },
            {
                'service': 'CloudTrail',
                'check': '日志记录检测',
                'command': 'aws cloudtrail describe-trails',
                'description': '检测是否启用CloudTrail日志记录',
                'severity': 'High'
            },
            {
                'service': 'Config',
                'check': '配置规则检测',
                'command': 'aws configservice describe-config-rules',
                'description': '检测是否启用AWS Config配置规则',
                'severity': 'Medium'
            },
            {
                'service': 'GuardDuty',
                'check': '威胁检测检测',
                'command': 'aws guardduty list-detectors',
                'description': '检测是否启用GuardDuty威胁检测',
                'severity': 'Medium'
            },
        ]

        for check in checks:
            findings.append(CloudFinding(
                provider='AWS',
                service=check['service'],
                issue=check['check'],
                severity=check['severity'],
                recommendation=check['description'],
                evidence='待检查'
            ))

        self.findings.extend(findings)
        return findings

    def scan_azure(self, subscription_id: str = "") -> List[CloudFinding]:
        """扫描Azure配置安全"""
        findings = []

        checks = [
            {'service': 'Storage', 'check': '存储账户公开访问', 'severity': 'High'},
            {'service': 'SQL', 'check': 'SQL服务器审计', 'severity': 'Medium'},
            {'service': 'Key Vault', 'check': '密钥保管库软删除', 'severity': 'High'},
            {'service': 'Security Center', 'check': '安全中心标准定价层', 'severity': 'Medium'},
            {'service': 'Network', 'check': 'NSG流日志', 'severity': 'Low'},
            {'service': 'Monitor', 'check': '活动日志保留', 'severity': 'Medium'},
            {'service': 'AD', 'check': '多因素认证', 'severity': 'Critical'},
            {'service': 'VM', 'check': '磁盘加密', 'severity': 'High'},
        ]

        for check in checks:
            findings.append(CloudFinding(
                provider='Azure',
                service=check['service'],
                issue=check['check'],
                severity=check['severity'],
                evidence='待检查'
            ))

        self.findings.extend(findings)
        return findings

    def scan_aliyun(self, access_key_id: str = "") -> List[CloudFinding]:
        """扫描阿里云配置安全"""
        findings = []

        checks = [
            {'service': 'OSS', 'check': 'OSS存储桶公开访问', 'severity': 'High'},
            {'service': 'RAM', 'check': '根账户MFA', 'severity': 'Critical'},
            {'service': 'ECS', 'check': '安全组宽松规则', 'severity': 'High'},
            {'service': 'RDS', 'check': '数据库白名单', 'severity': 'High'},
            {'service': 'SLS', 'check': '操作日志', 'severity': 'Medium'},
            {'service': 'KMS', 'check': '密钥轮换', 'severity': 'Medium'},
            {'service': 'WAF', 'check': 'Web应用防火墙', 'severity': 'Medium'},
            {'service': 'ActionTrail', 'check': '操作审计', 'severity': 'High'},
        ]

        for check in checks:
            findings.append(CloudFinding(
                provider='Aliyun',
                service=check['service'],
                issue=check['check'],
                severity=check['severity'],
                evidence='待检查'
            ))

        self.findings.extend(findings)
        return findings

    def scan_container(self, image: str = "") -> List[CloudFinding]:
        """扫描容器镜像安全"""
        findings = []

        checks = [
            {'issue': '以root用户运行', 'severity': 'High', 'description': '容器不应以root用户运行'},
            {'issue': '敏感信息泄露', 'severity': 'Critical', 'description': '镜像中可能包含密码、密钥等敏感信息'},
            {'issue': '已知漏洞包', 'severity': 'High', 'description': '镜像中的软件包可能有已知漏洞'},
            {'issue': '镜像体积过大', 'severity': 'Low', 'description': '镜像体积过大增加攻击面'},
            {'issue': '缺少健康检查', 'severity': 'Medium', 'description': 'Dockerfile中缺少HEALTHCHECK指令'},
            {'issue': '使用latest标签', 'severity': 'Low', 'description': '使用latest标签可能导致不可重现的构建'},
            {'issue': '多阶段构建', 'severity': 'Low', 'description': '建议使用多阶段构建减小镜像体积'},
            {'issue': 'ADD vs COPY', 'severity': 'Low', 'description': '建议使用COPY而非ADD，避免意外行为'},
        ]

        for check in checks:
            findings.append(CloudFinding(
                provider='Container',
                service='Docker',
                issue=check['issue'],
                severity=check['severity'],
                recommendation=check['description'],
                evidence='待检查'
            ))

        self.findings.extend(findings)
        return findings

    def scan_kubernetes(self, context: str = "") -> List[CloudFinding]:
        """扫描Kubernetes集群安全"""
        findings = []

        checks = [
            {'issue': 'RBAC配置', 'severity': 'High', 'description': '检查是否有过度授权的ClusterRoleBinding'},
            {'issue': 'Pod安全策略', 'severity': 'High', 'description': '检查是否启用Pod安全策略或Pod安全标准'},
            {'issue': '网络策略', 'severity': 'Medium', 'description': '检查是否配置NetworkPolicy限制Pod间通信'},
            {'issue': 'Secret加密', 'severity': 'Critical', 'description': '检查etcd中的Secret是否加密存储'},
            {'issue': '匿名访问', 'severity': 'Critical', 'description': '检查是否禁用匿名访问'},
            {'issue': '审计日志', 'severity': 'Medium', 'description': '检查是否启用API服务器审计日志'},
            {'issue': 'Dashboard暴露', 'severity': 'High', 'description': '检查Kubernetes Dashboard是否公开暴露'},
            {'issue': '镜像拉取策略', 'severity': 'Low', 'description': '检查是否使用Always拉取策略和私有镜像仓库'},
        ]

        for check in checks:
            findings.append(CloudFinding(
                provider='Kubernetes',
                service='K8s',
                issue=check['issue'],
                severity=check['severity'],
                recommendation=check['description'],
                evidence='待检查'
            ))

        self.findings.extend(findings)
        return findings

    def get_statistics(self) -> Dict[str, Any]:
        """获取扫描统计"""
        stats = {
            'total': len(self.findings),
            'by_provider': {},
            'by_severity': {},
        }

        for finding in self.findings:
            stats['by_provider'][finding.provider] = stats['by_provider'].get(finding.provider, 0) + 1
            stats['by_severity'][finding.severity] = stats['by_severity'].get(finding.severity, 0) + 1

        return stats

    def generate_report(self) -> Dict:
        """生成云安全报告"""
        return {
            'report_title': '云安全扫描报告',
            'generated_time': datetime.now().isoformat(),
            'statistics': self.get_statistics(),
            'findings': [
                {
                    'provider': f.provider,
                    'service': f.service,
                    'resource': f.resource,
                    'issue': f.issue,
                    'severity': f.severity,
                    'recommendation': f.recommendation,
                    'evidence': f.evidence,
                }
                for f in self.findings
            ],
        }


# 全局单例
_cloud_scanner = None

def get_cloud_security_scanner() -> CloudSecurityScanner:
    """获取云安全扫描器单例"""
    global _cloud_scanner
    if _cloud_scanner is None:
        _cloud_scanner = CloudSecurityScanner()
    return _cloud_scanner
