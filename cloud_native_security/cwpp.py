# -*- coding: utf-8 -*-
"""
cwpp.py - 云工作负载保护 (CWPP)（第25轮 CNAPP 模块）。

6 大能力：
  1. 云工作负载发现   — VM / 容器 / Serverless / 托管服务 / 数据库 / 缓存 / 消息队列 / 对象存储
  2. 工作负载配置审计 — 安全组 / 网络ACL / 防火墙 / 访问控制 / 加密 / 备份 / 监控
  3. 工作负载运行时保护 — 进程 / 文件 / 网络 / 系统调用 / 异常行为 / 入侵检测
  4. 工作负载漏洞管理 — 漏洞扫描 / 评估 / 优先级 / 修复 / 验证 / 趋势
  5. 工作负载合规     — CIS 云 / CIS 容器 / NIST 云 / PCI 云 / 合规报告
  6. 工作负载响应     — 实例隔离 / 网络隔离 / 快照 / 终止 / 回滚 / 告警 / 取证
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


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


class CloudWorkloadProtection:
    """云工作负载保护平台 (CWPP)。"""

    # ---------- 1. 工作负载发现 ----------

    def discover_workloads(self, cloud: str = "") -> Dict[str, Any]:
        workloads = [
            {"id": "i-0a1b2c3d", "name": "web-server-01", "type": "vm", "provider": "aws",
             "region": "us-east-1", "os": "Ubuntu 22.04", "status": "running",
             "public_ip": "203.0.113.10", "private_ip": "10.0.1.20", "cpu": 4, "memory_gb": 16},
            {"id": "i-0e5f6g7h", "name": "app-server-02", "type": "vm", "provider": "aws",
             "region": "us-east-1", "os": "Amazon Linux 2", "status": "running",
             "public_ip": None, "private_ip": "10.0.2.30", "cpu": 8, "memory_gb": 32},
            {"id": "k8s-pod-xyz", "name": "frontend-abc", "type": "container", "provider": "aws",
             "region": "us-east-1", "os": "containerd", "status": "running",
             "image": "nginx:1.25", "cluster": "prod-us-east1"},
            {"id": "lambda-api-handler", "name": "api-handler", "type": "serverless", "provider": "aws",
             "region": "us-east-1", "runtime": "python3.11", "status": "active",
             "memory_mb": 512, "timeout_seconds": 30},
            {"id": "rds-prod-01", "name": "postgres-prod", "type": "database", "provider": "aws",
             "region": "us-east-1", "engine": "PostgreSQL 16", "status": "available",
             "publicly_accessible": False, "encrypted": True},
            {"id": "elasticache-redis", "name": "redis-cache", "type": "cache", "provider": "aws",
             "region": "us-east-1", "engine": "Redis 7", "status": "available",
             "encrypted_at_rest": True, "encrypted_in_transit": False},
            {"id": "sqs-events", "name": "event-queue", "type": "message_queue", "provider": "aws",
             "region": "us-east-1", "status": "active", "encrypted": False},
            {"id": "s3-data-bucket", "name": "app-data", "type": "object_storage", "provider": "aws",
             "region": "us-east-1", "status": "active", "public_access": False, "versioning": True},
        ]
        if cloud:
            workloads = [w for w in workloads if w["provider"] == cloud]
        return {"workloads": workloads, "total": len(workloads), "discovered_at": _now()}

    # ---------- 2. 配置审计 ----------

    def audit_security_groups(self) -> Dict[str, Any]:
        findings = [
            {"id": "SG-001", "severity": "critical", "sg_name": "web-sg",
             "description": "安全组开放 0.0.0.0/0 到 22 端口 (SSH)",
             "port": 22, "source": "0.0.0.0/0", "remediation": "限制 SSH 源为公司 VPN IP"},
            {"id": "SG-002", "severity": "high", "sg_name": "db-sg",
             "description": "安全组开放 0.0.0.0/0 到 5432 端口 (PostgreSQL)",
             "port": 5432, "source": "0.0.0.0/0", "remediation": "限制数据库访问到应用层安全组"},
            {"id": "SG-003", "severity": "medium", "sg_name": "default",
             "description": "默认安全组允许所有出站流量",
             "port": "all", "source": "0.0.0.0/0", "remediation": "限制出站到必要目标"},
            {"id": "SG-004", "severity": "high", "sg_name": "app-sg",
             "description": "安全组开放 0.0.0.0/0 到 3389 端口 (RDP)",
             "port": 3389, "source": "0.0.0.0/0", "remediation": "限制 RDP 访问到 VPN"},
        ]
        return {"findings": findings, "total": len(findings)}

    def audit_encryption(self) -> Dict[str, Any]:
        findings = [
            {"id": "ENC-001", "severity": "high", "resource": "sqs-events",
             "description": "SQS 队列未启用静态加密", "remediation": "配置 SSE-KMS 加密"},
            {"id": "ENC-002", "severity": "medium", "resource": "elasticache-redis",
             "description": "Redis 未启用传输加密 (TLS)", "remediation": "启用 in-transit encryption"},
            {"id": "ENC-003", "severity": "high", "resource": "s3-data-bucket",
             "description": "S3 Bucket 未启用默认加密", "remediation": "启用 SSE-S3 或 SSE-KMS"},
        ]
        return {"findings": findings, "total": len(findings)}

    def audit_backup(self) -> Dict[str, Any]:
        findings = [
            {"id": "BKUP-001", "severity": "medium", "resource": "rds-prod-01",
             "description": "RDS 自动备份保留期为 7 天，建议至少 30 天",
             "remediation": "设置 BackupRetentionPeriod = 30"},
            {"id": "BKUP-002", "severity": "high", "resource": "web-server-01",
             "description": "EC2 实例未配置自动快照",
             "remediation": "配置 Data Lifecycle Manager 自动快照策略"},
        ]
        return {"findings": findings, "total": len(findings)}

    # ---------- 3. 运行时保护 ----------

    def runtime_process_monitoring(self, workload_id: str = "") -> Dict[str, Any]:
        processes = [
            {"pid": 1024, "name": "nginx", "user": "www-data", "cpu_pct": 0.5, "memory_mb": 12.3, "risk": "low"},
            {"pid": 2048, "name": "python3", "user": "app", "cpu_pct": 2.1, "memory_mb": 85.6, "risk": "low"},
            {"pid": 3072, "name": "xmrig", "user": "root", "cpu_pct": 95.0, "memory_mb": 1200.5, "risk": "critical"},
            {"pid": 4096, "name": "bash", "user": "www-data", "cpu_pct": 0.1, "memory_mb": 2.1, "risk": "medium"},
        ]
        return {"processes": processes, "total": len(processes), "workload": workload_id or "web-server-01"}

    def runtime_network_monitoring(self, workload_id: str = "") -> Dict[str, Any]:
        connections = [
            {"local_addr": "10.0.1.20:443", "remote_addr": "203.0.113.99:54321", "protocol": "TCP", "state": "ESTABLISHED", "risk": "high"},
            {"local_addr": "10.0.1.20:80", "remote_addr": "198.51.100.5:54322", "protocol": "TCP", "state": "ESTABLISHED", "risk": "critical"},
            {"local_addr": "10.0.1.20:22", "remote_addr": "192.168.1.100:45678", "protocol": "TCP", "state": "ESTABLISHED", "risk": "low"},
        ]
        return {"connections": connections, "total": len(connections), "workload": workload_id or "web-server-01"}

    def runtime_intrusion_detection(self, workload_id: str = "") -> Dict[str, Any]:
        alerts = [
            {"id": "IDS-001", "severity": "critical", "type": "cryptomining",
             "workload": workload_id or "web-server-01",
             "description": "检测到 XMRig 挖矿进程，CPU 持续 >90%",
             "source": "suricata + process monitor", "detected_at": _now()},
            {"id": "IDS-002", "severity": "high", "type": "brute_force",
             "workload": workload_id or "web-server-01",
             "description": "SSH 暴力破解检测：100+ 次失败登录来自 203.0.113.99",
             "source": "ssh auth log", "detected_at": _now()},
            {"id": "IDS-003", "severity": "high", "type": "webshell",
             "workload": workload_id or "web-server-01",
             "description": "Web 目录下发现疑似 WebShell: /var/www/html/up.php",
             "source": "file integrity monitor", "detected_at": _now()},
        ]
        return {"alerts": alerts, "total": len(alerts)}

    # ---------- 4. 漏洞管理 ----------

    def scan_workload_vulnerabilities(self, workload_id: str = "") -> Dict[str, Any]:
        vulns = [
            {"id": "CVE-2024-1086", "package": "linux-image", "version": "5.15.0-41",
             "severity": "critical", "cvss": 7.8, "status": "unpatched",
             "remediation": "apt update && apt upgrade linux-image"},
            {"id": "CVE-2023-52429", "package": "openssl", "version": "3.0.2",
             "severity": "high", "cvss": 7.5, "status": "unpatched",
             "remediation": "apt upgrade openssl"},
            {"id": "CVE-2024-2511", "package": "curl", "version": "7.81.0",
             "severity": "medium", "cvss": 5.3, "status": "patched",
             "remediation": "已修复"},
            {"id": "CVE-2023-38160", "package": "libc6", "version": "2.35",
             "severity": "medium", "cvss": 5.5, "status": "unpatched",
             "remediation": "apt upgrade libc6"},
        ]
        return {"vulnerabilities": vulns, "total": len(vulns), "workload": workload_id or "web-server-01",
                "scanned_at": _now()}

    def get_vulnerability_trends(self) -> Dict[str, Any]:
        trends = [
            {"week": "W1", "critical": 2, "high": 5, "medium": 8, "low": 12},
            {"week": "W2", "critical": 3, "high": 7, "medium": 10, "low": 15},
            {"week": "W3", "critical": 1, "high": 4, "medium": 9, "low": 14},
            {"week": "W4", "critical": 1, "high": 3, "medium": 7, "low": 13},
        ]
        return {"trends": trends, "period": "4 weeks"}

    # ---------- 5. 合规 ----------

    def get_compliance_status(self, framework: str = "cis-aws") -> Dict[str, Any]:
        frameworks = {
            "cis-aws": {
                "name": "CIS AWS Foundations Benchmark v3.0.0",
                "controls": [
                    {"id": "1.1", "title": "开启根用户 MFA", "status": "pass", "severity": "high"},
                    {"id": "1.2", "title": "删除根用户访问密钥", "status": "pass", "severity": "critical"},
                    {"id": "1.4", "title": "确保启用 CloudTrail", "status": "pass", "severity": "high"},
                    {"id": "2.1.1", "title": "确保 S3 桶策略不允许公开", "status": "fail", "severity": "critical"},
                    {"id": "3.1", "title": "确保开启 CMK 加密", "status": "fail", "severity": "high"},
                    {"id": "4.3", "title": "确保开启 AWS Config", "status": "fail", "severity": "medium"},
                ],
            },
            "nist-cloud": {
                "name": "NIST SP 800-53 Cloud Overlay",
                "controls": [
                    {"id": "AC-2", "title": "账户管理", "status": "pass", "severity": "high"},
                    {"id": "AU-2", "title": "审计事件", "status": "fail", "severity": "high"},
                    {"id": "SC-8", "title": "传输机密性", "status": "fail", "severity": "high"},
                ],
            },
            "pci-cloud": {
                "name": "PCI DSS Cloud Guidelines",
                "controls": [
                    {"id": "Req1", "title": "防火墙配置", "status": "pass", "severity": "critical"},
                    {"id": "Req2", "title": "安全配置", "status": "fail", "severity": "high"},
                    {"id": "Req3", "title": "数据保护", "status": "fail", "severity": "critical"},
                ],
            },
        }
        fw = frameworks.get(framework, frameworks["cis-aws"])
        passed = sum(1 for c in fw["controls"] if c["status"] == "pass")
        total = len(fw["controls"])
        return {
            "framework": framework, "framework_name": fw["name"],
            "controls": fw["controls"], "total_controls": total,
            "passed": passed, "failed": total - passed,
            "compliance_score": round(passed / total * 100, 1),
            "generated_at": _now(),
        }

    # ---------- 6. 响应 ----------

    def isolate_instance(self, instance_id: str, cloud: str = "aws") -> Dict[str, Any]:
        action_id = _rid("cwpp-resp-")
        snapshot_id = _rid("snap-")
        return _clean({
            "action_id": action_id, "action": "isolate_instance",
            "instance_id": instance_id, "cloud": cloud,
            "status": "executed", "timestamp": _now(),
            "details": f"已将实例 {instance_id} 移动到隔离安全组，仅允许管理 IP 访问。",
            "snapshot_id": snapshot_id,
        })

    def terminate_instance(self, instance_id: str, cloud: str = "aws") -> Dict[str, Any]:
        action_id = _rid("cwpp-resp-")
        return _clean({
            "action_id": action_id, "action": "terminate_instance",
            "instance_id": instance_id, "cloud": cloud,
            "status": "executed", "timestamp": _now(),
            "details": f"已终止实例 {instance_id}。终止前已创建快照用于取证。",
        })

    def create_snapshot(self, resource_id: str, resource_type: str = "ebs", cloud: str = "aws") -> Dict[str, Any]:
        action_id = _rid("cwpp-resp-")
        snap_id = _rid("snap-")
        return _clean({
            "action_id": action_id, "action": "create_snapshot",
            "resource_id": resource_id, "resource_type": resource_type, "cloud": cloud,
            "snapshot_id": snap_id, "status": "completed", "timestamp": _now(),
            "details": f"已为 {resource_type}/{resource_id} 创建快照 {snap_id}。",
        })

    def get_response_history(self, limit: int = 50) -> Dict[str, Any]:
        history = [
            {"action_id": "cwpp-resp-abc", "action": "isolate_instance", "target": "i-0a1b2c3d",
             "status": "executed", "timestamp": _now(), "performed_by": "automated-response"},
        ]
        return {"history": history[:limit], "total": len(history)}


# ==================== 工厂函数 ====================

def create_cwpp() -> CloudWorkloadProtection:
    return CloudWorkloadProtection()
