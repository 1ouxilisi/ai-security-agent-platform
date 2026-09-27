#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_cloud单元测试模块，包含相关功能的测试用例和验证逻辑。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCloudSecurityScanner:
    """云安全扫描器测试"""

    def test_scanner_import(self):
        """测试云安全扫描器导入"""
        from cloud.security_scanner import cloud_security_scanner
        assert cloud_security_scanner is not None

    def test_scanner_statistics(self):
        """测试扫描器统计信息"""
        from cloud.security_scanner import cloud_security_scanner
        stats = cloud_security_scanner.get_statistics()
        assert isinstance(stats, dict)
        assert "supported_checks" in stats

    # ===== AWS S3 检查 =====

    def test_aws_s3_public_access(self):
        """测试S3公开访问检查"""
        from cloud.security_scanner import cloud_security_scanner
        # 配置为公开访问的S3桶
        s3_config = {
            "name": "test-bucket",
            "public_access_block": {
                "block_public_acls": False,
                "block_public_policy": False,
                "ignore_public_acls": False,
                "restrict_public_buckets": False
            }
        }
        findings = cloud_security_scanner.check_aws_s3_bucket(s3_config)
        assert isinstance(findings, list)
        assert len(findings) > 0, "公开访问的S3桶应该被检测出问题"

    def test_aws_s3_secure(self):
        """测试安全配置的S3桶"""
        from cloud.security_scanner import cloud_security_scanner
        s3_config = {
            "name": "secure-bucket",
            "public_access_block": {
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True
            },
            "versioning": {"Status": "Enabled"},
            "encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
        }
        findings = cloud_security_scanner.check_aws_s3_bucket(s3_config)
        assert isinstance(findings, list)

    def test_aws_s3_encryption(self):
        """测试S3加密检查"""
        from cloud.security_scanner import cloud_security_scanner
        s3_config = {
            "name": "unencrypted-bucket",
            "public_access_block": {"block_public_acls": True},
            "encryption": None
        }
        findings = cloud_security_scanner.check_aws_s3_bucket(s3_config)
        assert isinstance(findings, list)

    # ===== Dockerfile 检查 =====

    def test_dockerfile_latest_tag(self):
        """测试Dockerfile latest标签检查"""
        from cloud.security_scanner import cloud_security_scanner
        dockerfile = "FROM ubuntu:latest\nRUN apt-get update"
        findings = cloud_security_scanner.check_dockerfile(dockerfile)
        assert isinstance(findings, list)
        # latest标签应该被检测
        assert any("latest" in f.get("description", "").lower() or "latest" in f.get("title", "").lower() for f in findings)

    def test_dockerfile_root_user(self):
        """测试Dockerfile root用户检查"""
        from cloud.security_scanner import cloud_security_scanner
        dockerfile = "FROM ubuntu:20.04\nUSER root\nCMD [\"bash\"]"
        findings = cloud_security_scanner.check_dockerfile(dockerfile)
        assert isinstance(findings, list)

    def test_dockerfile_ssh_exposed(self):
        """测试Dockerfile SSH端口暴露检查"""
        from cloud.security_scanner import cloud_security_scanner
        dockerfile = "FROM ubuntu:20.04\nEXPOSE 22\nCMD [\"/usr/sbin/sshd\"]"
        findings = cloud_security_scanner.check_dockerfile(dockerfile)
        assert isinstance(findings, list)
        assert len(findings) > 0, "暴露22端口应该被检测出问题"

    def test_dockerfile_secure(self):
        """测试安全的Dockerfile"""
        from cloud.security_scanner import cloud_security_scanner
        dockerfile = """FROM python:3.11-slim
RUN useradd -m appuser
USER appuser
WORKDIR /app
COPY --chown=appuser:appuser . .
EXPOSE 8000
CMD ["python", "app.py"]"""
        findings = cloud_security_scanner.check_dockerfile(dockerfile)
        assert isinstance(findings, list)

    # ===== Kubernetes Pod 检查 =====

    def test_k8s_privileged_container(self):
        """测试K8s特权容器检查"""
        from cloud.security_scanner import cloud_security_scanner
        pod_spec = {
            "spec": {
                "containers": [{
                    "name": "test",
                    "image": "nginx:latest",
                    "securityContext": {"privileged": True}
                }]
            }
        }
        findings = cloud_security_scanner.check_k8s_pod_spec(pod_spec)
        assert isinstance(findings, list)
        assert len(findings) > 0, "特权容器应该被检测出问题"

    def test_k8s_host_network(self):
        """测试K8s主机网络检查"""
        from cloud.security_scanner import cloud_security_scanner
        pod_spec = {
            "spec": {
                "hostNetwork": True,
                "containers": [{"name": "test", "image": "nginx:latest"}]
            }
        }
        findings = cloud_security_scanner.check_k8s_pod_spec(pod_spec)
        assert isinstance(findings, list)
        assert len(findings) > 0, "主机网络应该被检测出问题"

    def test_k8s_latest_image(self):
        """测试K8s latest镜像标签检查"""
        from cloud.security_scanner import cloud_security_scanner
        pod_spec = {
            "spec": {
                "containers": [{"name": "test", "image": "nginx:latest"}]
            }
        }
        findings = cloud_security_scanner.check_k8s_pod_spec(pod_spec)
        assert isinstance(findings, list)

    def test_k8s_secure_pod(self):
        """测试安全的K8s Pod配置"""
        from cloud.security_scanner import cloud_security_scanner
        pod_spec = {
            "spec": {
                "containers": [{
                    "name": "test",
                    "image": "nginx:1.25.3",
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 1000,
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True
                    },
                    "resources": {
                        "limits": {"cpu": "500m", "memory": "256Mi"},
                        "requests": {"cpu": "100m", "memory": "128Mi"}
                    }
                }]
            }
        }
        findings = cloud_security_scanner.check_k8s_pod_spec(pod_spec)
        assert isinstance(findings, list)


class TestCloudFinding:
    """云安全发现结果测试"""

    def test_cloud_finding_structure(self):
        """测试云安全发现结果结构（实际是字典格式）"""
        from cloud.security_scanner import cloud_security_scanner
        # 执行一个检查，验证返回结果的结构
        findings = cloud_security_scanner.check_dockerfile("FROM ubuntu:latest\nEXPOSE 22")
        assert isinstance(findings, list)
        if findings:
            finding = findings[0]
            assert isinstance(finding, dict)
            assert "severity" in finding
            assert "title" in finding
            assert "description" in finding
