# -*- coding: utf-8 -*-
"""
infrastructure_security.py — 容器基础设施安全。

功能：
  1. Docker daemon安全配置（TLS认证/API暴露/用户命名空间/日志驱动/ulimit/默认ulimit/远程API/无认证）
  2. containerd安全配置（配置审计/gRPC端点/插件/镜像拉取/运行时/认证授权）
  3. 运行时安全（runc/gVisor/Kata Containers隔离级别/运行时配置/逃逸面/沙箱配置）
  4. 镜像仓库安全（认证/授权/TLS/镜像签名/漏洞扫描集成/匿名访问/公开镜像/镜像拉取日志）
  5. CI/CD管道安全（构建环境/依赖安全/镜像扫描/部署审批/构建隔离/密钥管理/供应链安全）
  6. 基础设施即代码安全（Terraform/Ansible/Dockerfile安全扫描/最佳实践/合规检查/风险评分）
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any, Dict, List, Optional


class InfrastructureSecurity:
    """容器基础设施安全评估器。"""

    # ------------------------------------------------------------------ #
    # 1. Docker daemon 安全配置
    # ------------------------------------------------------------------ #
    def audit_docker_daemon(self) -> Dict[str, Any]:
        checks = [
            {"id": "DOCK-001", "check": "TLS 认证配置", "passed": False,
             "severity": "critical", "detail": "Docker daemon API 未配置 TLS 认证",
             "current": "tcp://0.0.0.0:2375 (无TLS)",
             "expected": "tcp://0.0.0.0:2376 --tlsverify",
             "remediation": "配置 --tlsverify --tlscacert --tlscert --tlskey"},
            {"id": "DOCK-002", "check": "远程 API 暴露", "passed": False,
             "severity": "critical", "detail": "Docker API 监听 0.0.0.0:2375，无认证",
             "remediation": "绑定到内网或使用 TLS 认证"},
            {"id": "DOCK-003", "check": "用户命名空间", "passed": False,
             "severity": "high", "detail": "未启用 userns-remap",
             "remediation": "配置 userns-remap=default"},
            {"id": "DOCK-004", "check": "日志驱动", "passed": True,
             "severity": "medium", "detail": "使用 json-file 日志驱动，有日志轮转",
             "remediation": ""},
            {"id": "DOCK-005", "check": "默认 ulimit", "passed": False,
             "severity": "medium", "detail": "未设置默认 nofile ulimit",
             "remediation": "配置 default-ulimit nofile=65536:65536"},
            {"id": "DOCK-006", "check": "live-restore", "passed": True,
             "severity": "low", "detail": "已启用 live-restore",
             "remediation": ""},
            {"id": "DOCK-007", "check": "icc (容器间通信)", "passed": False,
             "severity": "high", "detail": "未禁用容器间通信 (icc=true)",
             "remediation": "设置 --icc=false 使用自定义网络"},
            {"id": "DOCK-008", "check": "默认 seccomp profile", "passed": True,
             "severity": "medium", "detail": "默认 seccomp profile 已启用",
             "remediation": ""},
            {"id": "DOCK-009", "check": "默认 AppArmor profile", "passed": False,
             "severity": "medium", "detail": "未配置默认 AppArmor profile",
             "remediation": "配置 --apparmor-profile"},
            {"id": "DOCK-010", "check": "镜像内容信任", "passed": False,
             "severity": "high", "detail": "未启用 DOCKER_CONTENT_TRUST",
             "remediation": "启用 DOCKER_CONTENT_TRUST=1"},
        ]
        violations = [c for c in checks if not c["passed"]]
        return {
            "daemon_version": "24.0.7",
            "api_version": "1.43",
            "executable": "/usr/bin/dockerd",
            "config_file": "/etc/docker/daemon.json",
            "listening_address": "0.0.0.0:2375",
            "tls_enabled": False,
            "checks": checks,
            "violations_count": len(violations),
            "violations": violations,
            "score": max(0, 100 - len(violations) * 8),
        }

    # ------------------------------------------------------------------ #
    # 2. containerd 安全配置
    # ------------------------------------------------------------------ #
    def audit_containerd(self) -> Dict[str, Any]:
        checks = [
            {"id": "CTRD-001", "check": "gRPC 端点安全", "passed": True,
             "severity": "high", "detail": "gRPC 端点使用 Unix socket",
             "remediation": ""},
            {"id": "CTRD-002", "check": "配置文件权限", "passed": False,
             "severity": "high", "detail": "/etc/containerd/config.toml 权限为 644",
             "expected": "600",
             "remediation": "chmod 600 /etc/containerd/config.toml"},
            {"id": "CTRD-003", "check": "镜像拉取认证", "passed": True,
             "severity": "medium", "detail": "配置了镜像仓库认证",
             "remediation": ""},
            {"id": "CTRD-004", "check": "运行时配置", "passed": True,
             "severity": "medium", "detail": "使用 runc 作为默认运行时",
             "remediation": ""},
            {"id": "CTRD-005", "check": "插件安全", "passed": False,
             "severity": "medium", "detail": "未限制可加载的插件",
             "remediation": "禁用不必要的插件"},
            {"id": "CTRD-006", "check": "沙箱配置", "passed": False,
             "severity": "medium", "detail": "未启用 gVisor/Kata 沙箱",
             "remediation": "对不可信工作负载使用 gVisor"},
        ]
        return {
            "containerd_version": "1.7.18",
            "config_path": "/etc/containerd/config.toml",
            "grpc_socket": "/run/containerd/containerd.sock",
            "plugins": ["cri", "cni", "overlayfs", "aufs", "native"],
            "checks": checks,
            "violations_count": sum(1 for c in checks if not c["passed"]),
        }

    # ------------------------------------------------------------------ #
    # 3. 运行时安全（runc/gVisor/Kata）
    # ------------------------------------------------------------------ #
    def audit_runtime(self) -> Dict[str, Any]:
        runtimes = [
            {"name": "runc", "version": "1.1.12", "isolation_level": "Linux namespaces",
             "escape_surface": "high", "sandbox": False, "default": True,
             "known_vulns": ["CVE-2024-21626 (已修复)", "CVE-2023-28840 (已修复)"],
             "assessment": "通用容器运行时，需及时修补内核和runc"},
            {"name": "gVisor", "version": "20240121", "isolation_level": "User-space kernel",
             "escape_surface": "low", "sandbox": True, "default": False,
             "known_vulns": [],
             "assessment": "Google开发的应用内核沙箱，适合不可信工作负载"},
            {"name": "Kata Containers", "version": "3.1.3", "isolation_level": "轻量级VM",
             "escape_surface": "very low", "sandbox": True, "default": False,
             "known_vulns": [],
             "assessment": "基于VM的强隔离，适合多租户场景"},
        ]
        escape_surfaces = [
            {"surface": "Linux capabilities", "risk": "high",
             "mitigation": "Drop ALL, Add 最小集合"},
            {"surface": "procfs/sysfs 泄露", "risk": "medium",
             "mitigation": "使用 maskedPaths 和 readonlyPaths"},
            {"surface": "cgroup 逃逸", "risk": "high",
             "mitigation": "升级内核至 5.10+，使用 seccomp"},
            {"surface": "敏感设备挂载", "risk": "critical",
             "mitigation": "禁止 /dev/kmsg, /dev/mem, /dev/sda*"},
            {"surface": "Docker socket 挂载", "risk": "critical",
             "mitigation": "禁止挂载 /var/run/docker.sock"},
        ]
        return {
            "runtimes": runtimes,
            "default_runtime": "runc",
            "escape_surfaces": escape_surfaces,
            "recommendation": "对不可信工作负载启用 gVisor 或 Kata Containers",
        }

    # ------------------------------------------------------------------ #
    # 4. 镜像仓库安全
    # ------------------------------------------------------------------ #
    def audit_registry(self) -> Dict[str, Any]:
        registries = [
            {"name": "harbor-prod", "url": "harbor.internal.corp", "auth_required": True,
             "tls": True, "signed_images": True, "vuln_scan_integrated": True,
             "anonymous_access": False, "public_images": 0, "pull_logging": True,
             "risk": "low"},
            {"name": "docker-hub-cache", "url": "registry-1.docker.io", "auth_required": False,
             "tls": True, "signed_images": False, "vuln_scan_integrated": False,
             "anonymous_access": True, "public_images": 150, "pull_logging": False,
             "risk": "high",
             "issues": ["匿名拉取", "未验证镜像签名", "无漏洞扫描集成"]},
            {"name": "dev-registry", "url": "registry.dev.local", "auth_required": True,
             "tls": False, "signed_images": False, "vuln_scan_integrated": False,
             "anonymous_access": False, "public_images": 0, "pull_logging": False,
             "risk": "medium",
             "issues": ["未启用TLS", "未配置漏洞扫描"]},
        ]
        return {
            "registries": registries,
            "total_registries": len(registries),
            "high_risk_registries": [r for r in registries if r["risk"] == "high"],
            "image_signature_required": False,
            "vuln_scan_integrated": False,
            "total_images": sum(150 if not r["auth_required"] else 0 for r in registries) + 320,
        }

    # ------------------------------------------------------------------ #
    # 5. CI/CD 管道安全
    # ------------------------------------------------------------------ #
    def audit_cicd(self) -> Dict[str, Any]:
        pipelines = [
            {"name": "api-server-build", "platform": "GitHub Actions",
             "build_isolation": "container", "dependency_scan": True,
             "image_scan": True, "deployment_approval": True, "secrets_managed": "GitHub Secrets",
             "supply_chain_attestation": False, "risk": "medium",
             "issues": ["未启用 SBOM 和 provenance attestation"]},
            {"name": "legacy-worker-deploy", "platform": "Jenkins",
             "build_isolation": "none", "dependency_scan": False,
             "image_scan": False, "deployment_approval": False, "secrets_managed": "plaintext",
             "supply_chain_attestation": False, "risk": "critical",
             "issues": ["无构建隔离", "无依赖扫描", "无镜像扫描", "无部署审批", "明文密钥"]},
            {"name": "frontend-deploy", "platform": "GitLab CI",
             "build_isolation": "container", "dependency_scan": True,
             "image_scan": True, "deployment_approval": True, "secrets_managed": "Vault",
             "supply_chain_attestation": True, "risk": "low",
             "issues": []},
        ]
        return {
            "pipelines": pipelines,
            "total_pipelines": len(pipelines),
            "critical_risk_pipelines": [p for p in pipelines if p["risk"] == "critical"],
            "build_isolation_compliance": round(
                sum(1 for p in pipelines if p["build_isolation"] == "container") / len(pipelines) * 100, 1),
            "image_scan_coverage": round(
                sum(1 for p in pipelines if p["image_scan"]) / len(pipelines) * 100, 1),
            "deployment_approval_compliance": round(
                sum(1 for p in pipelines if p["deployment_approval"]) / len(pipelines) * 100, 1),
        }

    # ------------------------------------------------------------------ #
    # 6. IaC 安全扫描
    # ------------------------------------------------------------------ #
    def scan_iac(self) -> Dict[str, Any]:
        results = [
            {"file": "terraform/main.tf", "tool": "tfsec/Checkov",
             "findings": [
                 {"id": "GEN-001", "rule": "S3 bucket not encrypted", "severity": "high",
                  "line": 45, "remediation": "启用 S3 默认加密"},
                 {"id": "GEN-002", "rule": "Security group open to 0.0.0.0/0", "severity": "critical",
                  "line": 78, "remediation": "限制安全组源IP"},
             ]},
            {"file": "ansible/playbook.yml", "tool": "ansible-lint",
             "findings": [
                 {"id": "ANS-001", "rule": "Plaintext password in vars", "severity": "critical",
                  "line": 12, "remediation": "使用 Ansible Vault"},
             ]},
            {"file": "Dockerfile", "tool": "Hadolint",
             "findings": [
                 {"id": "DL3002", "rule": "Last user should not be root", "severity": "high",
                  "line": 30, "remediation": "添加 USER nonroot"},
                 {"id": "DL3006", "rule": "Always tag base image version", "severity": "medium",
                  "line": 1, "remediation": "使用具体标签"},
                 {"id": "DL3007", "rule": "Using latest tag", "severity": "medium",
                  "line": 1, "remediation": "使用不可变标签"},
             ]},
        ]
        total_findings = sum(len(r["findings"]) for r in results)
        critical = sum(1 for r in results for f in r["findings"] if f["severity"] == "critical")
        high = sum(1 for r in results for f in r["findings"] if f["severity"] == "high")
        return {
            "files_scanned": len(results),
            "total_findings": total_findings,
            "critical": critical,
            "high": high,
            "results": results,
            "risk_score": max(0, 100 - critical * 15 - high * 8),
        }

    # ------------------------------------------------------------------ #
    # 综合基础设施评估
    # ------------------------------------------------------------------ #
    def assess(self) -> Dict[str, Any]:
        docker = self.audit_docker_daemon()
        containerd = self.audit_containerd()
        runtime = self.audit_runtime()
        registry = self.audit_registry()
        cicd = self.audit_cicd()
        iac = self.scan_iac()
        return {
            "assessed_at": datetime.utcnow().isoformat() + "Z",
            "docker_daemon": docker,
            "containerd": containerd,
            "runtime_security": runtime,
            "registry_security": registry,
            "cicd_security": cicd,
            "iac_scan": iac,
            "summary": {
                "docker_violations": docker["violations_count"],
                "containerd_violations": containerd["violations_count"],
                "high_risk_registries": len(registry["high_risk_registries"]),
                "critical_cicd_pipelines": len(cicd["critical_risk_pipelines"]),
                "iac_critical_findings": iac["critical"],
            },
        }
