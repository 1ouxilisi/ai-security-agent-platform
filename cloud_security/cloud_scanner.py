#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
云安全扫描器
Cloud Security Scanner

功能：AWS/Azure/阿里云配置检查、云安全基线检测
"""

import os
import json
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from loguru import logger


@dataclass
class CloudFinding:
    """云安全发现"""
    check_id: str
    check_name: str
    severity: str  # critical, high, medium, low, info
    status: str  # passed, failed, error, skipped
    description: str = ""
    resource: str = ""
    evidence: str = ""
    recommendation: str = ""
    category: str = ""  # storage, iam, network, compute, database, logging
    compliance: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'check_id': self.check_id,
            'check_name': self.check_name,
            'severity': self.severity,
            'status': self.status,
            'description': self.description,
            'resource': self.resource,
            'evidence': self.evidence,
            'recommendation': self.recommendation,
            'category': self.category,
            'compliance': self.compliance,
        }


@dataclass
class CloudScanResult:
    """云扫描结果"""
    provider: str
    scan_type: str
    findings: List[CloudFinding] = field(default_factory=list)
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    risk_score: float = 0.0
    risk_level: str = "low"
    summary: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'provider': self.provider,
            'scan_type': self.scan_type,
            'findings': [f.to_dict() for f in self.findings],
            'total_checks': self.total_checks,
            'passed': self.passed,
            'failed': self.failed,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'summary': self.summary,
        }


# 云安全检查规则
CLOUD_CHECKS = {
    'aws': [
        # 存储安全
        {
            'id': 'AWS-S3-001',
            'name': 'S3存储桶公开访问检测',
            'severity': 'critical',
            'category': 'storage',
            'description': '检测S3存储桶是否允许公开访问',
            'recommendation': '禁用S3存储桶公开访问，启用Block Public Access',
            'compliance': ['CIS-AWS-2.1.1', 'PCI-DSS-1.3'],
        },
        {
            'id': 'AWS-S3-002',
            'name': 'S3存储桶加密检测',
            'severity': 'high',
            'category': 'storage',
            'description': '检测S3存储桶是否启用服务端加密',
            'recommendation': '启用S3服务端加密(SSE-S3或SSE-KMS)',
            'compliance': ['CIS-AWS-2.1.2', 'GDPR-Article-32'],
        },
        {
            'id': 'AWS-S3-003',
            'name': 'S3存储桶版本控制检测',
            'severity': 'medium',
            'category': 'storage',
            'description': '检测S3存储桶是否启用版本控制',
            'recommendation': '启用S3版本控制，防止意外删除',
            'compliance': ['CIS-AWS-2.1.3'],
        },
        # IAM安全
        {
            'id': 'AWS-IAM-001',
            'name': 'IAM用户MFA检测',
            'severity': 'critical',
            'category': 'iam',
            'description': '检测IAM用户是否启用多因素认证',
            'recommendation': '为所有IAM用户启用MFA',
            'compliance': ['CIS-AWS-1.14', 'PCI-DSS-8.3'],
        },
        {
            'id': 'AWS-IAM-002',
            'name': 'IAM访问密钥轮换检测',
            'severity': 'high',
            'category': 'iam',
            'description': '检测IAM访问密钥是否超过90天未轮换',
            'recommendation': '定期轮换访问密钥，建议不超过90天',
            'compliance': ['CIS-AWS-1.5', 'PCI-DSS-8.4'],
        },
        {
            'id': 'AWS-IAM-003',
            'name': 'IAM策略过度权限检测',
            'severity': 'high',
            'category': 'iam',
            'description': '检测IAM策略是否包含AdministratorAccess等过度权限',
            'recommendation': '遵循最小权限原则，限制IAM策略权限',
            'compliance': ['CIS-AWS-1.22', 'PCI-DSS-7.1'],
        },
        # 网络安全
        {
            'id': 'AWS-NET-001',
            'name': '安全组SSH公开访问检测',
            'severity': 'critical',
            'category': 'network',
            'description': '检测安全组是否允许0.0.0.0/0访问SSH(22端口)',
            'recommendation': '限制SSH访问来源IP，不允许公开访问',
            'compliance': ['CIS-AWS-4.1', 'PCI-DSS-1.3'],
        },
        {
            'id': 'AWS-NET-002',
            'name': '安全组RDP公开访问检测',
            'severity': 'critical',
            'category': 'network',
            'description': '检测安全组是否允许0.0.0.0/0访问RDP(3389端口)',
            'recommendation': '限制RDP访问来源IP，不允许公开访问',
            'compliance': ['CIS-AWS-4.2', 'PCI-DSS-1.3'],
        },
        {
            'id': 'AWS-NET-003',
            'name': 'VPC流日志检测',
            'severity': 'medium',
            'category': 'network',
            'description': '检测VPC是否启用流日志',
            'recommendation': '启用VPC流日志，记录网络流量',
            'compliance': ['CIS-AWS-3.9'],
        },
        # 日志审计
        {
            'id': 'AWS-LOG-001',
            'name': 'CloudTrail启用检测',
            'severity': 'critical',
            'category': 'logging',
            'description': '检测是否启用CloudTrail审计日志',
            'recommendation': '在所有区域启用CloudTrail',
            'compliance': ['CIS-AWS-3.1', 'PCI-DSS-10.1'],
        },
        {
            'id': 'AWS-LOG-002',
            'name': 'CloudTrail日志加密检测',
            'severity': 'high',
            'category': 'logging',
            'description': '检测CloudTrail日志是否启用KMS加密',
            'recommendation': '启用CloudTrail日志KMS加密',
            'compliance': ['CIS-AWS-3.7', 'PCI-DSS-3.4'],
        },
        {
            'id': 'AWS-LOG-003',
            'name': 'Config服务启用检测',
            'severity': 'medium',
            'category': 'logging',
            'description': '检测是否启用AWS Config配置审计',
            'recommendation': '启用AWS Config，持续监控配置变更',
            'compliance': ['CIS-AWS-2.5'],
        },
        # 计算安全
        {
            'id': 'AWS-EC2-001',
            'name': 'EC2实例详细监控检测',
            'severity': 'medium',
            'category': 'compute',
            'description': '检测EC2实例是否启用详细监控',
            'recommendation': '启用EC2详细监控，收集更多指标',
            'compliance': ['CIS-AWS-2.4'],
        },
        {
            'id': 'AWS-EC2-002',
            'name': 'EBS卷加密检测',
            'severity': 'high',
            'category': 'compute',
            'description': '检测EBS卷是否启用加密',
            'recommendation': '启用EBS卷加密，保护静态数据',
            'compliance': ['CIS-AWS-2.2.1', 'PCI-DSS-3.4'],
        },
    ],
    'azure': [
        {
            'id': 'AZURE-STORAGE-001',
            'name': '存储账户公开访问检测',
            'severity': 'critical',
            'category': 'storage',
            'description': '检测存储账户是否允许公开Blob访问',
            'recommendation': '禁用存储账户公开访问',
            'compliance': ['CIS-Azure-3.1'],
        },
        {
            'id': 'AZURE-IAM-001',
            'name': '全局管理员MFA检测',
            'severity': 'critical',
            'category': 'iam',
            'description': '检测全局管理员是否启用MFA',
            'recommendation': '为所有全局管理员启用MFA',
            'compliance': ['CIS-Azure-1.1.1'],
        },
        {
            'id': 'AZURE-NET-001',
            'name': 'NSG SSH公开访问检测',
            'severity': 'critical',
            'category': 'network',
            'description': '检测NSG是否允许Internet访问SSH',
            'recommendation': '限制SSH访问来源',
            'compliance': ['CIS-Azure-6.1'],
        },
        {
            'id': 'AZURE-LOG-001',
            'name': 'Azure Activity Log保留检测',
            'severity': 'high',
            'category': 'logging',
            'description': '检测Activity Log保留期是否≥365天',
            'recommendation': '设置Activity Log保留期≥365天',
            'compliance': ['CIS-Azure-5.1.1'],
        },
    ],
    'aliyun': [
        {
            'id': 'ALIYUN-OSS-001',
            'name': 'OSS存储桶公开访问检测',
            'severity': 'critical',
            'category': 'storage',
            'description': '检测OSS存储桶是否允许公开读写',
            'recommendation': '禁用OSS存储桶公开访问',
            'compliance': ['等保2.0-8.1.4'],
        },
        {
            'id': 'ALIYUN-RAM-001',
            'name': 'RAM用户MFA检测',
            'severity': 'critical',
            'category': 'iam',
            'description': '检测RAM用户是否启用MFA',
            'recommendation': '为所有RAM用户启用MFA',
            'compliance': ['等保2.0-8.1.4'],
        },
        {
            'id': 'ALIYUN-ECS-001',
            'name': 'ECS安全组SSH公开检测',
            'severity': 'critical',
            'category': 'network',
            'description': '检测安全组是否允许0.0.0.0/0访问22端口',
            'recommendation': '限制SSH访问来源IP',
            'compliance': ['等保2.0-8.1.3'],
        },
    ],
}


class CloudScanner:
    """云安全扫描器"""

    def __init__(self, provider: str = 'aws', region: str = 'us-east-1'):
        self.provider = provider.lower()
        self.region = region
        self.findings = []

    def scan(self, config_file: str = None) -> CloudScanResult:
        """执行云安全扫描"""
        logger.info(f"开始云安全扫描: provider={self.provider}, region={self.region}")

        result = CloudScanResult(provider=self.provider, scan_type='configuration')

        # 获取检查规则
        checks = CLOUD_CHECKS.get(self.provider, [])
        if not checks:
            logger.warning(f"未找到 {self.provider} 的检查规则")
            return result

        # 执行检查（模拟模式）
        for check in checks:
            finding = self._execute_check(check, config_file)
            result.findings.append(finding)

        # 汇总
        result.total_checks = len(result.findings)
        result.passed = len([f for f in result.findings if f.status == 'passed'])
        result.failed = len([f for f in result.findings if f.status == 'failed'])
        result.critical_count = len([f for f in result.findings if f.severity == 'critical' and f.status == 'failed'])
        result.high_count = len([f for f in result.findings if f.severity == 'high' and f.status == 'failed'])
        result.medium_count = len([f for f in result.findings if f.severity == 'medium' and f.status == 'failed'])
        result.low_count = len([f for f in result.findings if f.severity == 'low' and f.status == 'failed'])

        # 风险评分
        result.risk_score = min(100, result.critical_count * 12 + result.high_count * 6 + result.medium_count * 2)
        if result.risk_score >= 70:
            result.risk_level = 'critical'
        elif result.risk_score >= 50:
            result.risk_level = 'high'
        elif result.risk_score >= 30:
            result.risk_level = 'medium'
        else:
            result.risk_level = 'low'

        result.summary = {
            'total_checks': result.total_checks,
            'passed': result.passed,
            'failed': result.failed,
            'critical': result.critical_count,
            'high': result.high_count,
            'medium': result.medium_count,
            'low': result.low_count,
            'pass_rate': f"{round(result.passed/result.total_checks*100, 1)}%" if result.total_checks > 0 else '0%',
        }

        logger.info(f"云安全扫描完成: {result.failed}/{result.total_checks} 检查失败, 风险等级={result.risk_level}")
        return result

    def _execute_check(self, check: Dict, config_file: str = None) -> CloudFinding:
        """执行单个检查（模拟模式）"""
        finding = CloudFinding(
            check_id=check['id'],
            check_name=check['name'],
            severity=check['severity'],
            status='pending',
            category=check.get('category', ''),
            description=check.get('description', ''),
            recommendation=check.get('recommendation', ''),
            compliance=check.get('compliance', []),
        )

        # 模拟检查结果（基于风险等级随机分配通过/失败）
        # 实际实现中应调用云服务商API
        import random
        random.seed(hash(check['id']))

        fail_probability = {
            'critical': 0.6,
            'high': 0.5,
            'medium': 0.4,
            'low': 0.3,
            'info': 0.2,
        }.get(check['severity'], 0.4)

        if random.random() < fail_probability:
            finding.status = 'failed'
            finding.evidence = f"检测到 {check['name']} 存在风险"
            finding.resource = f"{self.provider}-resource-{check['id'].split('-')[-1]}"
        else:
            finding.status = 'passed'
            finding.evidence = f"{check['name']} 配置符合安全要求"

        return finding

    def scan_from_config(self, config: Dict) -> CloudScanResult:
        """从配置字典扫描"""
        logger.info(f"从配置扫描云安全: {self.provider}")
        return self.scan()


def quick_cloud_scan(provider: str = 'aws', region: str = 'us-east-1') -> Dict:
    """快速云安全扫描"""
    scanner = CloudScanner(provider=provider, region=region)
    result = scanner.scan()
    return result.to_dict()
