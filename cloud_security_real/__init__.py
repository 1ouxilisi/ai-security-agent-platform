# -*- coding: utf-8 -*-
"""
cloud_security_real — 方向3 云安全真实化（6.5 -> 8.5）。

在 cloud_security_pro（40 端点五阶段框架）基础上，做实真实云 API 对接:
    - 真实 AWS 检查: IAM/S3/EC2/RDS/VPC/CloudTrail/GuardDuty/Config (boto3)
    - 真实 Azure 检查: AD/Storage/VM/SQL/KeyVault/SecurityCenter (azure SDK)
    - 真实阿里云检查: RAM/OSS/ECS/RDS/VPC/ActionTrail (aliyun SDK)
    - 真实容器检查: K8s/Docker/trivy 镜像扫描
    - CIS 真实基线: AWS/Azure/Alibaba/K8s
    - 真实报告落盘 + 编排器 + 仪表盘

核心原则: SDK 未装 / 凭证未配 -> 明确提示安装与配置，绝不 mock。
"""

from __future__ import annotations

from ._base import Finding, CheckReport, not_ready_report, SEV_LABEL
from .aws_security_check import (
    AWSSecurityChecker, get_aws_checker, detect_aws_status,
    INSTALL_HINT as AWS_INSTALL, CONFIG_HINT as AWS_CONFIG,
)
from .azure_security_check import (
    AzureSecurityChecker, get_azure_checker, detect_azure_status,
    INSTALL_HINT as AZURE_INSTALL, CONFIG_HINT as AZURE_CONFIG,
)
from .aliyun_security_check import (
    AliyunSecurityChecker, get_aliyun_checker, detect_aliyun_status,
    INSTALL_HINT as ALIYUN_INSTALL, CONFIG_HINT as ALIYUN_CONFIG,
)
from .container_security_check import (
    ContainerSecurityOrchestrator, get_container_checker,
    detect_k8s_status, detect_docker_status, detect_scanner, scan_image,
)
from .cis_benchmark import CISBenchmark, get_cis_benchmark, FRAMEWORKS
from .real_report_generator import (
    RealReportData, RealReportGenerator, get_real_report_generator,
    REPORTS_DIR,
)
from .real_orchestrator import (
    RealOrchestrator, RealTask, get_real_orchestrator, STAGES,
)
from .real_dashboard import RealDashboard, get_real_dashboard

__all__ = [
    "Finding", "CheckReport", "not_ready_report", "SEV_LABEL",
    "AWSSecurityChecker", "get_aws_checker", "detect_aws_status",
    "AWS_INSTALL", "AWS_CONFIG",
    "AzureSecurityChecker", "get_azure_checker", "detect_azure_status",
    "AZURE_INSTALL", "AZURE_CONFIG",
    "AliyunSecurityChecker", "get_aliyun_checker", "detect_aliyun_status",
    "ALIYUN_INSTALL", "ALIYUN_CONFIG",
    "ContainerSecurityOrchestrator", "get_container_checker",
    "detect_k8s_status", "detect_docker_status", "detect_scanner",
    "scan_image",
    "CISBenchmark", "get_cis_benchmark", "FRAMEWORKS",
    "RealReportData", "RealReportGenerator", "get_real_report_generator",
    "REPORTS_DIR",
    "RealOrchestrator", "RealTask", "get_real_orchestrator", "STAGES",
    "RealDashboard", "get_real_dashboard",
]
