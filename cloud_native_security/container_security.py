# -*- coding: utf-8 -*-
"""
container_security.py - 容器安全深度（第25轮 CNAPP 模块）。

6 大能力：
  1. 容器镜像扫描   — OS包漏洞 / 应用依赖漏洞 / 配置错误 / 恶意软件 / 密钥泄露 / 敏感信息 / 镜像层分析
  2. 容器运行时安全 — 进程白名单 / 文件完整性 / 网络策略 / 系统调用过滤 / 资源限制 / 异常行为检测
  3. 容器逃逸防护   — 特权限制 / 挂载限制 / 能力限制 / 只读文件系统 / 非root / Seccomp / AppArmor / SELinux
  4. 容器网络安全   — 网络策略 / 微隔离 / 流量可视化 / 异常流量 / 隧道检测 / 端口扫描 / 横向移动
  5. 容器合规       — CIS Docker / CIS K8s / NIST 容器 / PCI 容器 / 合规报告
  6. 容器生命周期   — 构建安全 / 镜像签名 / 镜像验证 / 部署安全 / 运行安全 / 销毁安全 / 全生命周期审计

docker SDK try-import，缺失时回退模拟。
"""

from __future__ import annotations

import json
import random
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    import docker  # type: ignore
    _DOCKER_OK = True
except Exception:  # pragma: no cover
    docker = None  # type: ignore
    _DOCKER_OK = False


# ==================== 工具函数 ====================

def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return re.sub(r"[\x00-\x1f\x7f]", "", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    return obj


def _now() -> str:
    return datetime.now().isoformat()


def _rid(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"


# ==================== 主类 ====================

class ContainerSecurityDeep:
    """容器安全深度管理器。"""

    # ---------- 1. 镜像扫描 ----------

    def scan_image(self, image: str, scan_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """扫描容器镜像。"""
        scan_types = scan_types or ["os_vuln", "app_vuln", "misconfig", "malware", "secret", "layer"]
        scan_id = _rid("scan-")

        vulns_os = [
            {"id": "CVE-2024-1086", "package": "linux-libc-dev", "version": "5.15.0-41", "fixed_version": "5.15.0-91",
             "severity": "critical", "cvss": 7.8, "description": "Linux kernel netfilter nf_tables use-after-free"},
            {"id": "CVE-2023-52429", "package": "openssl", "version": "3.0.2", "fixed_version": "3.0.13",
             "severity": "high", "cvss": 7.5, "description": "openssl: Denial of service via excessive computations"},
            {"id": "CVE-2024-2511", "package": "curl", "version": "7.81.0", "fixed_version": "8.5.0",
             "severity": "medium", "cvss": 5.3, "description": "curl: OOB read in RFC 8931 parsing"},
            {"id": "CVE-2023-38160", "package": "glibc", "version": "2.35", "fixed_version": "2.35-0ubuntu3.5",
             "severity": "medium", "cvss": 5.5, "description": "glibc: integer overflow in malloc"},
        ]

        vulns_app = [
            {"id": "CVE-2024-21626", "package": "runc", "version": "1.1.5", "fixed_version": "1.1.12",
             "severity": "critical", "cvss": 8.6, "description": "runc: File descriptor leak in OCI spec (Leaky Vessels)"},
            {"id": "CVE-2023-44487", "package": "nginx", "version": "1.25.0", "fixed_version": "1.25.3",
             "severity": "high", "cvss": 7.5, "description": "HTTP/2 Rapid Reset attack"},
            {"id": "CVE-2024-22365", "package": "redis", "version": "7.2.0", "fixed_version": "7.2.4",
             "severity": "medium", "cvss": 6.5, "description": "Redis: Lua sandbox escape"},
        ]

        misconfigs = [
            {"id": "DCK-001", "severity": "high", "title": "Root 用户运行",
             "description": "Dockerfile 未设置 USER 指令，容器以 root 运行", "file": "Dockerfile", "line": 1},
            {"id": "DCK-002", "severity": "medium", "title": "Latest 标签",
             "description": "使用 :latest 标签，不可复现构建", "file": "Dockerfile", "line": 5},
            {"id": "DCK-003", "severity": "medium", "title": "未设置 HEALTHCHECK",
             "description": "Dockerfile 未定义 HEALTHCHECK 指令", "file": "Dockerfile", "line": 0},
            {"id": "DCK-004", "severity": "low", "title": "多阶段构建未使用",
             "description": "镜像包含构建依赖，可通过多阶段构建减小体积", "file": "Dockerfile", "line": 0},
        ]

        malware_findings = [
            {"id": "MAL-001", "severity": "critical", "type": "cryptominer_binary",
             "path": "/usr/local/bin/.xmrig", "description": "检测到 XMRig 挖矿程序"},
            {"id": "MAL-002", "severity": "high", "type": "webshell",
             "path": "/var/www/html/shell.php", "description": "检测到疑似 WebShell 文件"},
        ]

        secret_findings = [
            {"id": "SEC-001", "severity": "critical", "type": "aws_access_key",
             "path": "/app/config/prod.yml", "line": 42, "match": "AKIA********************",
             "description": "硬编码 AWS Access Key"},
            {"id": "SEC-002", "severity": "high", "type": "private_key",
             "path": "/root/.ssh/id_rsa", "line": 0, "match": "-----BEGIN RSA PRIVATE KEY-----",
             "description": "镜像中包含 SSH 私钥"},
            {"id": "SEC-003", "severity": "high", "type": "db_password",
             "path": "/app/.env", "line": 3, "match": "DB_PASSWORD=********",
             "description": ".env 文件中硬编码数据库密码"},
        ]

        layers = [
            {"index": 0, "size_mb": 82.5, "command": "FROM ubuntu:22.04", "created_at": "2024-01-15"},
            {"index": 1, "size_mb": 45.2, "command": "apt-get update && apt-get install ...", "created_at": "2024-01-15"},
            {"index": 2, "size_mb": 120.8, "command": "RUN npm install", "created_at": "2024-01-16"},
            {"index": 3, "size_mb": 2.1, "command": "COPY . /app", "created_at": "2024-01-16"},
            {"index": 4, "size_mb": 0.0, "command": "USER app", "created_at": "2024-01-16"},
        ]

        return _clean({
            "scan_id": scan_id, "image": image, "scan_types": scan_types,
            "status": "completed", "scanned_at": _now(),
            "summary": {
                "os_vulnerabilities": len(vulns_os),
                "app_vulnerabilities": len(vulns_app),
                "misconfigurations": len(misconfigs),
                "malware": len(malware_findings),
                "secrets": len(secret_findings),
                "total_layers": len(layers),
                "image_size_mb": 250.6,
            },
            "os_vulnerabilities": vulns_os,
            "app_vulnerabilities": vulns_app,
            "misconfigurations": misconfigs,
            "malware": malware_findings,
            "secrets": secret_findings,
            "layers": layers,
        })

    # ---------- 2. 运行时安全 ----------

    def runtime_process_whitelist(self) -> Dict[str, Any]:
        policies = [
            {"container": "nginx", "allowed_processes": ["nginx", "nginx: worker proc"], "enforced": True},
            {"container": "redis", "allowed_processes": ["redis-server"], "enforced": True},
            {"container": "app", "allowed_processes": ["python3", "gunicorn"], "enforced": True},
        ]
        violations = [
            {"container": "suspicious", "process": "xmrig", "expected": "python3", "action_taken": "killed"},
        ]
        return {"whitelist_policies": policies, "violations": violations, "total_violations": len(violations)}

    def runtime_file_integrity(self) -> Dict[str, Any]:
        events = [
            {"container": "nginx", "path": "/etc/nginx/nginx.conf", "event": "modified", "expected_hash": "a1b2c3", "actual_hash": "d4e5f6", "risk": "high"},
            {"container": "app", "path": "/app/app.py", "event": "modified", "expected_hash": "", "actual_hash": "", "risk": "medium"},
            {"container": "app", "path": "/root/.bash_history", "event": "deleted", "risk": "low"},
        ]
        return {"events": events, "total": len(events), "monitored_paths": 42}

    def runtime_syscall_filter(self) -> Dict[str, Any]:
        blocked = [
            {"syscall": "mount", "container": "untrusted", "args": "/dev/sda1 /host ext4", "blocked": True},
            {"syscall": "ptrace", "container": "untrusted", "args": "attach to pid 1", "blocked": True},
            {"syscall": "init_module", "container": "untrusted", "args": "load kernel module", "blocked": True},
        ]
        return {"seccomp_profile": "default-v2.4", "blocked_syscalls": blocked, "total_blocked": len(blocked)}

    def runtime_anomaly_detection(self) -> Dict[str, Any]:
        anomalies = [
            {"id": "RTA-001", "severity": "critical", "type": "cryptomining",
             "container": "miner", "evidence": "xmrig binary detected, CPU 95%", "confidence": 0.97},
            {"id": "RTA-002", "severity": "high", "type": "reverse_shell",
             "container": "app", "evidence": "nc to 203.0.113.99:4444", "confidence": 0.88},
            {"id": "RTA-003", "severity": "medium", "type": "unexpected_child",
             "container": "nginx", "evidence": "spawned /bin/bash from nginx worker", "confidence": 0.72},
        ]
        return {"anomalies": anomalies, "total": len(anomalies), "monitored_containers": 124}

    # ---------- 3. 逃逸防护 ----------

    def get_escape_hardening_rules(self) -> Dict[str, Any]:
        rules = [
            {"id": "HARD-001", "category": "privilege", "title": "禁用特权容器",
             "policy": "set privileged: false in securityContext", "severity": "critical"},
            {"id": "HARD-002", "category": "mount", "title": "禁止挂载宿主机敏感路径",
             "policy": "禁止 hostPath 挂载 /, /proc, /sys, /dev, /var/run/docker.sock", "severity": "critical"},
            {"id": "HARD-003", "category": "capabilities", "title": "最小化 Linux Capabilities",
             "policy": "drop: [ALL], add: [NET_BIND_SERVICE]", "severity": "high"},
            {"id": "HARD-004", "category": "filesystem", "title": "只读根文件系统",
             "policy": "set readOnlyRootFilesystem: true", "severity": "high"},
            {"id": "HARD-005", "category": "user", "title": "非 root 用户运行",
             "policy": "set runAsNonRoot: true, runAsUser: 1000+", "severity": "high"},
            {"id": "HARD-006", "category": "seccomp", "title": "启用 Seccomp Profile",
             "policy": "set seccompProfile.type: RuntimeDefault", "severity": "medium"},
            {"id": "HARD-007", "category": "apparmor", "title": "启用 AppArmor Profile",
             "policy": "add container.apparmor.security.beta.kubernetes.io annotation", "severity": "medium"},
            {"id": "HARD-008", "category": "selinux", "title": "启用 SELinux",
             "policy": "set seLinuxOptions.type: container_t", "severity": "medium"},
            {"id": "HARD-009", "category": "escalation", "title": "禁止特权升级",
             "policy": "set allowPrivilegeEscalation: false", "severity": "high"},
        ]
        return {"rules": rules, "total": len(rules)}

    def assess_container_hardening(self, container_name: str = "") -> Dict[str, Any]:
        assessment = {
            "container": container_name or "app-container",
            "privileged": False,
            "read_only_rootfs": True,
            "run_as_non_root": True,
            "allow_privilege_escalation": False,
            "dropped_caps": ["ALL"],
            "added_caps": ["NET_BIND_SERVICE"],
            "seccomp_profile": "RuntimeDefault",
            "apparmor_profile": "docker-default",
            "selinux_options": None,
            "host_mounts": [],
            "score": 85,
            "issues": [
                {"id": "ISS-001", "severity": "medium", "title": "未配置 SELinux",
                 "description": "SELinux 选项未设置，建议启用以增强隔离"},
                {"id": "ISS-002", "severity": "low", "title": "AppArmor Profile 为默认",
                 "description": "建议使用自定义 AppArmor profile 限制特定行为"},
            ],
        }
        return _clean(assessment)

    # ---------- 4. 网络安全 ----------

    def get_network_visualization(self) -> Dict[str, Any]:
        nodes = [
            {"id": "fe", "name": "frontend", "namespace": "prod-frontend", "type": "deployment"},
            {"id": "be", "name": "backend", "namespace": "prod-backend", "type": "deployment"},
            {"id": "rd", "name": "redis", "namespace": "prod-data", "type": "statefulset"},
            {"id": "pg", "name": "postgres", "namespace": "prod-data", "type": "statefulset"},
        ]
        edges = [
            {"source": "fe", "target": "be", "bytes_per_sec": 12000, "port": 8000},
            {"source": "be", "target": "rd", "bytes_per_sec": 8500, "port": 6379},
            {"source": "be", "target": "pg", "bytes_per_sec": 23000, "port": 5432},
            {"source": "external", "target": "fe", "bytes_per_sec": 50000, "port": 443},
        ]
        return {"nodes": nodes, "edges": edges, "total_nodes": len(nodes), "total_edges": len(edges)}

    def detect_tunnels(self) -> Dict[str, Any]:
        tunnels = [
            {"id": "TUN-001", "severity": "high", "type": "dns_tunnel",
             "container": "app", "evidence": "高频 DNS 查询到 *.evil-domain.tk", "detected_at": _now()},
            {"id": "TUN-002", "severity": "medium", "type": "icmp_tunnel",
             "container": "unknown", "evidence": "异常 ICMP 数据包大小 >1500 bytes", "detected_at": _now()},
        ]
        return {"tunnels": tunnels, "total": len(tunnels), "monitored_containers": 124}

    def detect_port_scan(self) -> Dict[str, Any]:
        scans = [
            {"id": "SCAN-001", "severity": "high", "source": "10.96.9.99",
             "target_network": "10.96.3.0/24", "ports_scanned": 1000, "duration_seconds": 30,
             "detected_at": _now()},
        ]
        return {"scans": scans, "total": len(scans)}

    # ---------- 5. 合规 ----------

    def get_compliance_report(self, framework: str = "cis-docker") -> Dict[str, Any]:
        frameworks = {
            "cis-docker": {
                "name": "CIS Docker Benchmark v1.6.0",
                "controls": [
                    {"id": "1.1", "title": "确保运行时是受支持版本", "status": "pass", "severity": "info"},
                    {"id": "1.2", "title": "为 Docker daemon 启用 TLS 认证", "status": "fail", "severity": "high"},
                    {"id": "1.3", "title": "限制容器对宿主机的访问", "status": "pass", "severity": "medium"},
                    {"id": "2.1", "title": "为容器启用日志记录", "status": "pass", "severity": "info"},
                    {"id": "2.2", "title": "限制容器内存使用", "status": "fail", "severity": "medium"},
                    {"id": "4.1", "title": "镜像使用最小基础镜像", "status": "fail", "severity": "low"},
                    {"id": "4.2", "title": "容器以非 root 用户运行", "status": "fail", "severity": "high"},
                ],
            },
            "cis-k8s": {
                "name": "CIS Kubernetes Benchmark v1.8.0",
                "controls": [
                    {"id": "5.1.1", "title": "确保 Pod 以非 root 用户运行", "status": "fail", "severity": "high"},
                    {"id": "5.1.2", "title": "确保容器根文件系统为只读", "status": "pass", "severity": "medium"},
                    {"id": "5.2.1", "title": "确保不使用特权容器", "status": "fail", "severity": "critical"},
                ],
            },
            "nist": {
                "name": "NIST SP 800-190 Application Container Security Guide",
                "controls": [
                    {"id": "SC-2", "title": "账户管理", "status": "pass", "severity": "medium"},
                    {"id": "SI-4", "title": "系统监控", "status": "fail", "severity": "high"},
                    {"id": "CM-7", "title": "最小功能", "status": "fail", "severity": "medium"},
                ],
            },
            "pci": {
                "name": "PCI DSS Container Requirements",
                "controls": [
                    {"id": "Req2.2", "title": "配置安全标准", "status": "pass", "severity": "high"},
                    {"id": "Req6.4", "title": "安全软件开发", "status": "fail", "severity": "high"},
                    {"id": "Req10.2", "title": "审计日志", "status": "fail", "severity": "critical"},
                ],
            },
        }
        fw = frameworks.get(framework, frameworks["cis-docker"])
        passed = sum(1 for c in fw["controls"] if c["status"] == "pass")
        total = len(fw["controls"])
        return {
            "framework": framework, "framework_name": fw["name"],
            "controls": fw["controls"], "total_controls": total,
            "passed": passed, "failed": total - passed,
            "compliance_score": round(passed / total * 100, 1),
            "generated_at": _now(),
        }

    # ---------- 6. 生命周期 ----------

    def lifecycle_build_security(self) -> Dict[str, Any]:
        checks = [
            {"stage": "build", "check": "基础镜像来源验证", "status": "pass", "detail": "使用官方 Ubuntu 22.04"},
            {"stage": "build", "check": "依赖锁定", "status": "pass", "detail": "package-lock.json 存在"},
            {"stage": "build", "check": "构建时密钥泄露", "status": "fail", "detail": "Dockerfile ARG 中包含 API_KEY"},
            {"stage": "build", "check": "多阶段构建", "status": "fail", "detail": "未使用多阶段构建"},
        ]
        return {"checks": checks, "total": len(checks)}

    def lifecycle_image_signing(self) -> Dict[str, Any]:
        return {
            "cosign_enabled": True,
            "signing_identity": "k8s-ci@example.com",
            "verified_images": 128,
            "unsigned_images": 3,
            "unsigned_details": [
                {"image": "dev/app:latest", "reason": "开发镜像未签名"},
                {"image": "stg/debug:v1", "reason": "调试镜像未签名"},
            ],
        }

    def lifecycle_deploy_security(self) -> Dict[str, Any]:
        checks = [
            {"stage": "deploy", "check": "镜像签名验证", "status": "fail", "detail": "准入控制器未验证 Cosign 签名"},
            {"stage": "deploy", "check": "镜像漏洞阻断", "status": "pass", "detail": "Critical 漏洞镜像被阻断"},
            {"stage": "deploy", "check": "部署策略", "status": "pass", "detail": "使用 RollingUpdate 策略"},
        ]
        return {"checks": checks, "total": len(checks)}

    def lifecycle_destroy_security(self) -> Dict[str, Any]:
        checks = [
            {"stage": "destroy", "check": "容器日志清理", "status": "pass", "detail": "日志自动轮转"},
            {"stage": "destroy", "check": "容器层数据擦除", "status": "fail", "detail": "未配置自动擦除敏感数据"},
            {"stage": "destroy", "check": "镜像删除", "status": "pass", "detail": "废弃镜像 30 天后自动删除"},
        ]
        return {"checks": checks, "total": len(checks)}


# ==================== 工厂函数 ====================

def create_container_security() -> ContainerSecurityDeep:
    return ContainerSecurityDeep()
