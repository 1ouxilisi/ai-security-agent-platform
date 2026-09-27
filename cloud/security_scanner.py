#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_scanner模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import os
import json
import re
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from collections import Counter
from datetime import datetime

from utils.logger import log


@dataclass
class CloudSecurityFinding:
    """云安全发现"""
    finding_id: str
    provider: str  # aws/azure/gcp/alicloud
    service: str  # s3/ec2/iam/k8s/docker等
    category: str  # 配置错误/权限过宽/数据暴露/未加密等
    severity: str  # critical/high/medium/low/info
    title: str
    description: str
    impact: str
    remediation: str
    resource: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "finding_id": self.finding_id,
            "provider": self.provider,
            "service": self.service,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "resource": self.resource,
            "evidence": self.evidence,
            "references": self.references,
            "created_at": self.created_at
        }


class CloudSecurityScanner:
    """云安全扫描器"""

    def __init__(self, data_dir: str = "data/cloud_security"):
        """初始化CloudSecurityScanner实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.findings: List[CloudSecurityFinding] = []
        self.finding_counter = 0
        os.makedirs(data_dir, exist_ok=True)

    def _add_finding(self, **kwargs) -> CloudSecurityFinding:
        """添加发现，返回finding对象"""
        self.finding_counter += 1
        finding_id = f"CSF-{self.finding_counter:04d}"
        finding = CloudSecurityFinding(finding_id=finding_id, **kwargs)
        self.findings.append(finding)
        return finding

    # ===== AWS安全检查 =====
    def check_aws_s3_bucket(self, bucket_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """检查AWS S3存储桶配置"""
        findings = []
        bucket_name = bucket_config.get("name", "unknown")

        # 1. 公开访问
        public_access = bucket_config.get("public_access_block", {})
        if not public_access.get("block_public_acls", True):
            findings.append(self._add_finding(
                provider="aws", service="s3", category="数据暴露",
                severity="critical", title="S3存储桶公开ACL未阻止",
                description=f"存储桶 {bucket_name} 未配置阻止公开ACL，可能导致数据公开访问",
                impact="存储桶数据可能被公开访问，导致敏感数据泄露",
                remediation="启用BlockPublicAcls配置，设置BlockPublicPolicy=true",
                resource=bucket_name
            ).to_dict())

        if not public_access.get("block_public_policy", True):
            findings.append(self._add_finding(
                provider="aws", service="s3", category="数据暴露",
                severity="critical", title="S3存储桶公开策略未阻止",
                description=f"存储桶 {bucket_name} 未配置阻止公开策略",
                impact="恶意策略可能导致存储桶公开访问",
                remediation="启用BlockPublicPolicy配置",
                resource=bucket_name
            ).to_dict())

        # 2. 未加密
        encryption = bucket_config.get("encryption") or {}
        if not encryption.get("enabled", False):
            findings.append(self._add_finding(
                provider="aws", service="s3", category="未加密",
                severity="high", title="S3存储桶未启用服务器端加密",
                description=f"存储桶 {bucket_name} 未启用SSE（服务器端加密）",
                impact="存储桶数据未加密存储，可能导致数据泄露",
                remediation="启用SSE-S3或SSE-KMS加密",
                resource=bucket_name
            ).to_dict())

        # 3. 版本控制未启用
        if not bucket_config.get("versioning", {}).get("enabled", False):
            findings.append(self._add_finding(
                provider="aws", service="s3", category="数据保护",
                severity="medium", title="S3存储桶未启用版本控制",
                description=f"存储桶 {bucket_name} 未启用版本控制",
                impact="数据被误删或篡改后无法恢复",
                remediation="启用版本控制，配置生命周期规则",
                resource=bucket_name
            ).to_dict())

        # 4. 日志记录未启用
        if not bucket_config.get("logging", {}).get("enabled", False):
            findings.append(self._add_finding(
                provider="aws", service="s3", category="审计",
                severity="low", title="S3存储桶未启用访问日志",
                description=f"存储桶 {bucket_name} 未启用访问日志记录",
                impact="无法审计存储桶访问行为，安全事件无法追溯",
                remediation="启用S3访问日志，记录到独立的日志存储桶",
                resource=bucket_name
            ).to_dict())

        return findings

    def check_aws_iam_policy(self, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """检查AWS IAM策略"""
        findings = []
        policy_name = policy.get("name", "unknown")
        statements = policy.get("statement", [])

        for stmt in statements:
            # 1. 通配符权限
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            effect = stmt.get("Effect", "Allow")

            if effect == "Allow":
                # 检查*权限
                if "*" in actions:
                    findings.append(self._add_finding(
                        provider="aws", service="iam", category="权限过宽",
                        severity="critical", title="IAM策略包含通配符Action",
                        description=f"策略 {policy_name} 包含Action: *，授予所有服务的所有权限",
                        impact="账户被完全控制，所有资源可被访问/修改/删除",
                        remediation="遵循最小权限原则，只授予必要的具体操作权限",
                        resource=policy_name
                    ).to_dict())

                # 检查*资源
                if "*" in resources and any(a != "*" for a in actions):
                    findings.append(self._add_finding(
                        provider="aws", service="iam", category="权限过宽",
                        severity="high", title="IAM策略应用到所有资源",
                        description=f"策略 {policy_name} 的权限应用到Resource: *",
                        impact="权限范围过大，可能访问非预期资源",
                        remediation="限制资源范围，指定具体的资源ARN",
                        resource=policy_name
                    ).to_dict())

                # 检查危险操作
                dangerous_actions = [
                    "iam:CreateAccessKey", "iam:CreateLoginProfile",
                    "iam:AttachUserPolicy", "iam:PutUserPolicy",
                    "sts:AssumeRole", "iam:PassRole",
                    "s3:DeleteBucket", "ec2:RunInstances",
                    "lambda:CreateFunction", "lambda:InvokeFunction"
                ]
                for action in actions:
                    if action in dangerous_actions or any(action.startswith(d.split(":")[0] + ":*") for d in dangerous_actions):
                        findings.append(self._add_finding(
                            provider="aws", service="iam", category="危险权限",
                            severity="high", title=f"IAM策略包含危险操作: {action}",
                            description=f"策略 {policy_name} 包含危险操作 {action}",
                            impact="可能导致权限提升、资源创建、数据删除等严重后果",
                            remediation="审查该权限的必要性，考虑使用条件限制或拒绝策略",
                            resource=policy_name
                        ).to_dict())

        # 2. 密码策略
        password_policy = policy.get("password_policy", {})
        if password_policy:
            if password_policy.get("minimum_password_length", 8) < 12:
                findings.append(self._add_finding(
                    provider="aws", service="iam", category="弱密码策略",
                    severity="medium", title="IAM密码策略最小长度不足",
                    description=f"密码最小长度为{password_policy.get('minimum_password_length', 8)}，建议至少12位",
                    impact="账户容易被暴力破解",
                    remediation="设置最小密码长度至少12位，要求复杂度，启用MFA"
                ).to_dict())

        return findings

    # ===== 容器安全检查 =====
    def check_dockerfile(self, dockerfile_content: str) -> List[Dict[str, Any]]:
        """检查Dockerfile安全配置"""
        findings = []
        lines = dockerfile_content.split('\n')

        # 1. 使用root用户
        has_user_instruction = any(line.strip().upper().startswith('USER') for line in lines)
        if not has_user_instruction:
            findings.append(self._add_finding(
                provider="docker", service="dockerfile", category="权限",
                severity="high", title="Dockerfile未指定非root用户",
                description="容器将以root用户运行，容器逃逸后可获得宿主机root权限",
                impact="容器逃逸风险增加，攻击者获得容器root权限",
                remediation="使用USER指令指定非root用户运行容器，创建专用用户"
            ).to_dict())

        # 2. 基础镜像使用latest
        for line in lines:
            if line.strip().upper().startswith('FROM') and ':latest' in line:
                findings.append(self._add_finding(
                    provider="docker", service="dockerfile", category="不可重现",
                    severity="medium", title="基础镜像使用latest标签",
                    description="使用latest标签的基础镜像，构建不可重现，可能引入未知漏洞",
                    impact="构建不可重现，安全漏洞无法追踪",
                    remediation="使用具体版本标签（如ubuntu:22.04），使用digest固定镜像"
                ).to_dict())
                break

        # 3. 暴露敏感端口
        sensitive_ports = ['22', '3306', '5432', '6379', '27017', '9200']
        for line in lines:
            if line.strip().upper().startswith('EXPOSE'):
                for port in sensitive_ports:
                    if port in line:
                        findings.append(self._add_finding(
                            provider="docker", service="dockerfile", category="端口暴露",
                            severity="medium", title=f"Dockerfile暴露敏感端口: {port}",
                            description=f"容器暴露了敏感服务端口 {port}（SSH/数据库/缓存等）",
                            impact="敏感服务可能被直接访问",
                            remediation=f"不要在Dockerfile中EXPOSE端口{port}，使用docker network隔离"
                        ).to_dict())

        # 4. 添加敏感文件
        for line in lines:
            if line.strip().upper().startswith(('ADD', 'COPY')):
                if any(ext in line for ext in ['.env', '.pem', '.key', 'id_rsa', 'credentials']):
                    findings.append(self._add_finding(
                        provider="docker", service="dockerfile", category="敏感信息",
                        severity="critical", title="Dockerfile复制敏感文件到镜像",
                        description=f"镜像中包含敏感文件: {line.strip()}",
                        impact="敏感凭证/密钥泄露，镜像被拉取后可提取",
                        remediation="不要将敏感文件打包到镜像中，使用环境变量或Secret管理"
                    ).to_dict())

        # 5. 健康检查缺失
        has_healthcheck = any(line.strip().upper().startswith('HEALTHCHECK') for line in lines)
        if not has_healthcheck:
            findings.append(self._add_finding(
                provider="docker", service="dockerfile", category="可观测性",
                severity="low", title="Dockerfile缺少健康检查",
                description="容器没有配置HEALTHCHECK，编排系统无法判断容器健康状态",
                impact="容器异常时无法自动重启，影响服务可用性",
                remediation="添加HEALTHCHECK指令，配置合理的检查命令和间隔"
            ).to_dict())

        # 6. apt-get/yum未清理
        for line in lines:
            if 'apt-get install' in line or 'yum install' in line:
                if 'rm -rf /var/lib/apt/lists' not in dockerfile_content and 'yum clean all' not in dockerfile_content:
                    findings.append(self._add_finding(
                        provider="docker", service="dockerfile", category="镜像优化",
                        severity="info", title="包管理器缓存未清理",
                        description="安装包后未清理缓存，镜像体积过大",
                        impact="镜像体积大，拉取慢，攻击面可能增加",
                        remediation="安装后执行rm -rf /var/lib/apt/lists/*或yum clean all"
                    ).to_dict())
                    break

        return findings

    # ===== K8s安全检查 =====
    def check_k8s_pod_spec(self, pod_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """检查K8s Pod安全配置"""
        findings = []
        pod_name = pod_spec.get("metadata", {}).get("name", "unknown")
        spec = pod_spec.get("spec", {})
        containers = spec.get("containers", [])

        # 1. 特权容器
        for container in containers:
            security_context = container.get("securityContext", {})
            if security_context.get("privileged", False):
                findings.append(self._add_finding(
                    provider="kubernetes", service="pod", category="权限",
                    severity="critical", title="容器以特权模式运行",
                    description=f"Pod {pod_name} 中的容器 {container.get('name')} 以privileged模式运行",
                    impact="容器拥有宿主机所有设备访问权限，可轻易逃逸到宿主机",
                    remediation="移除privileged: true，使用具体的capabilities授权",
                    resource=f"{pod_name}/{container.get('name')}"
                ).to_dict())

        # 2. 允许特权升级
        for container in containers:
            security_context = container.get("securityContext", {})
            if security_context.get("allowPrivilegeEscalation", True) is not False:
                findings.append(self._add_finding(
                    provider="kubernetes", service="pod", category="权限",
                    severity="high", title="容器允许特权升级",
                    description=f"Pod {pod_name} 中的容器 {container.get('name')} 未设置allowPrivilegeEscalation: false",
                    impact="容器内进程可以通过setuid等机制提升权限",
                    remediation="设置securityContext.allowPrivilegeEscalation: false",
                    resource=f"{pod_name}/{container.get('name')}"
                ).to_dict())

        # 3. root用户运行
        for container in containers:
            security_context = container.get("securityContext", {})
            run_as_user = security_context.get("runAsUser")
            if run_as_user is None or run_as_user == 0:
                findings.append(self._add_finding(
                    provider="kubernetes", service="pod", category="权限",
                    severity="high", title="容器以root用户运行",
                    description=f"Pod {pod_name} 中的容器 {container.get('name')} 以root用户(UID 0)运行",
                    impact="容器内进程拥有root权限，容器逃逸后危害更大",
                    remediation="设置securityContext.runAsUser为非0用户，设置runAsNonRoot: true",
                    resource=f"{pod_name}/{container.get('name')}"
                ).to_dict())

        # 4. 只读根文件系统
        for container in containers:
            security_context = container.get("securityContext", {})
            if not security_context.get("readOnlyRootFilesystem", False):
                findings.append(self._add_finding(
                    provider="kubernetes", service="pod", category="文件系统",
                    severity="medium", title="容器根文件系统可写",
                    description=f"Pod {pod_name} 中的容器 {container.get('name')} 未设置只读根文件系统",
                    impact="攻击者可以在容器内写入恶意文件，持久化攻击",
                    remediation="设置securityContext.readOnlyRootFilesystem: true，需要写入的目录使用emptyDir",
                    resource=f"{pod_name}/{container.get('name')}"
                ).to_dict())

        # 5. 资源限制未设置
        for container in containers:
            resources = container.get("resources", {})
            if not resources.get("limits"):
                findings.append(self._add_finding(
                    provider="kubernetes", service="pod", category="资源管理",
                    severity="medium", title="容器未设置资源限制",
                    description=f"Pod {pod_name} 中的容器 {container.get('name')} 未设置CPU/内存限制",
                    impact="容器可能消耗过多资源，导致其他容器或节点拒绝服务",
                    remediation="设置resources.limits.cpu和resources.limits.memory",
                    resource=f"{pod_name}/{container.get('name')}"
                ).to_dict())

        # 6. 主机网络/IPC/PID
        if spec.get("hostNetwork", False):
            findings.append(self._add_finding(
                provider="kubernetes", service="pod", category="网络隔离",
                severity="high", title="Pod使用主机网络",
                description=f"Pod {pod_name} 设置了hostNetwork: true",
                impact="Pod可以访问宿主机网络栈，嗅探网络流量，访问节点本地服务",
                remediation="移除hostNetwork: true，使用Service和NetworkPolicy管理网络"
            ).to_dict())

        if spec.get("hostPID", False):
            findings.append(self._add_finding(
                provider="kubernetes", service="pod", category="进程隔离",
                severity="high", title="Pod使用主机PID命名空间",
                description=f"Pod {pod_name} 设置了hostPID: true",
                impact="Pod可以看到并操作宿主机所有进程",
                remediation="移除hostPID: true"
            ).to_dict())

        # 7. 敏感主机路径挂载
        volumes = spec.get("volumes", [])
        for volume in volumes:
            host_path = volume.get("hostPath", {}).get("path", "")
            if host_path.startswith(("/etc", "/var/run/docker.sock", "/root", "/home", "/proc", "/sys")):
                findings.append(self._add_finding(
                    provider="kubernetes", service="pod", category="数据暴露",
                    severity="critical", title="Pod挂载敏感主机路径",
                    description=f"Pod {pod_name} 挂载了敏感主机路径: {host_path}",
                    impact="可以读取/修改宿主机敏感文件，容器逃逸",
                    remediation="不要挂载敏感主机路径，使用Secret/ConfigMap传递配置",
                    resource=f"{pod_name}/{volume.get('name')}"
                ).to_dict())

        # 8. 镜像使用latest
        for container in containers:
            image = container.get("image", "")
            if image.endswith(":latest") or (":" not in image and "latest" not in image):
                findings.append(self._add_finding(
                    provider="kubernetes", service="pod", category="不可重现",
                    severity="low", title="容器镜像使用latest或无标签",
                    description=f"Pod {pod_name} 中的容器 {container.get('name')} 使用镜像: {image}",
                    impact="镜像版本不确定，可能引入未知漏洞，构建不可重现",
                    remediation="使用具体版本标签或digest",
                    resource=f"{pod_name}/{container.get('name')}"
                ).to_dict())

        return findings

    # ===== 综合扫描 =====
    def scan_cloud_config(self, config: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """综合扫描云配置"""
        findings = []

        if config_type == "aws_s3":
            findings = self.check_aws_s3_bucket(config)
        elif config_type == "aws_iam":
            findings = self.check_aws_iam_policy(config)
        elif config_type == "dockerfile":
            findings = self.check_dockerfile(config.get("content", ""))
        elif config_type == "k8s_pod":
            findings = self.check_k8s_pod_spec(config)
        else:
            return {"error": f"不支持的配置类型: {config_type}"}

        by_severity = Counter(f["severity"] for f in findings)
        risk_score = self._calculate_risk_score(by_severity)

        return {
            "scan_type": config_type,
            "total_findings": len(findings),
            "by_severity": dict(by_severity),
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "findings": findings,
            "scan_time": datetime.now().isoformat()
        }

    def _calculate_risk_score(self, by_severity: Counter) -> int:
        """计算风险评分"""
        score = 0
        score += by_severity.get("critical", 0) * 25
        score += by_severity.get("high", 0) * 15
        score += by_severity.get("medium", 0) * 8
        score += by_severity.get("low", 0) * 3
        score += by_severity.get("info", 0) * 1
        return min(score, 100)

    def _get_risk_level(self, score: int) -> str:
        """获取风险等级"""
        if score >= 75:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        elif score >= 10:
            return "low"
        else:
            return "info"

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        by_severity = Counter(f.severity for f in self.findings)
        by_provider = Counter(f.provider for f in self.findings)
        by_service = Counter(f.service for f in self.findings)
        by_category = Counter(f.category for f in self.findings)

        return {
            "total_findings": len(self.findings),
            "by_severity": dict(by_severity),
            "by_provider": dict(by_provider),
            "by_service": dict(by_service),
            "by_category": dict(by_category),
            "supported_checks": [
                "AWS S3存储桶安全", "AWS IAM策略安全", "Dockerfile安全",
                "K8s Pod安全配置", "容器特权检查", "资源限制检查",
                "网络隔离检查", "敏感路径挂载检查", "镜像安全检查"
            ],
            "supported_providers": ["aws", "azure", "gcp", "alicloud", "kubernetes", "docker"]
        }


# 全局实例
cloud_security_scanner = CloudSecurityScanner()
