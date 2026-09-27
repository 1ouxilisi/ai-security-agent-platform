# -*- coding: utf-8 -*-
"""
container_dashboard.py — 容器安全运营仪表盘。

功能：
  1. 容器资产全景（镜像/容器/Pod/节点/集群/命名空间/工作负载/注册表）
  2. 安全态势（风险镜像数/风险容器数/配置违规数/运行时告警数/漏洞数/高危漏洞数/合规率）
  3. 实时告警（镜像漏洞/运行时威胁/K8s配置违规/异常API调用/容器逃逸/异常Pod/告警分诊）
  4. 漏洞管理（镜像漏洞列表/受影响镜像/修复版本/修复优先级/修复跟踪/漏洞趋势/CVE详情）
  5. 合规状态（CIS Docker/CIS K8s/Pod安全标准/合规率/违规项/修复建议/合规趋势/审计报告）
  6. 容器安全度量（漏洞修复率/配置合规率/运行时拦截率/MTTR/镜像扫描覆盖率/告警量趋势/Top威胁/Top风险镜像）
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


class ContainerDashboard:
    """容器安全运营仪表盘聚合引擎。"""

    # ------------------------------------------------------------------ #
    # 1. 容器资产全景
    # ------------------------------------------------------------------ #
    def asset_overview(self) -> Dict[str, Any]:
        return {
            "images": [
                {"name": "nginx:1.25", "risk_score": 62, "risk_level": "high",
                 "vulns": 18, "size_gb": 0.15, "pull_count": 1200},
                {"name": "python:3.11-slim", "risk_score": 78, "risk_level": "medium",
                 "vulns": 9, "size_gb": 0.12, "pull_count": 850},
                {"name": "node:20", "risk_score": 45, "risk_level": "critical",
                 "vulns": 32, "size_gb": 0.23, "pull_count": 2300},
                {"name": "redis:7-alpine", "risk_score": 85, "risk_level": "low",
                 "vulns": 3, "size_gb": 0.05, "pull_count": 670},
                {"name": "mysql:8.0", "risk_score": 55, "risk_level": "high",
                 "vulns": 21, "size_gb": 0.6, "pull_count": 980},
            ],
            "containers": [
                {"name": "web-frontend", "status": "running", "image": "nginx:1.25",
                 "risk": "medium", "restarts": 0},
                {"name": "worker-queue", "status": "running", "image": "node:20",
                 "risk": "critical", "restarts": 3},
            ],
            "pods": 24,
            "nodes": 3,
            "clusters": 1,
            "namespaces": 6,
            "workloads": 18,
            "registries": 3,
            "summary": {
                "total_images": 156, "risk_images": 23,
                "total_containers": 48, "risk_containers": 5,
                "total_pods": 24, "anomalous_pods": 2,
            },
        }

    # ------------------------------------------------------------------ #
    # 2. 安全态势
    # ------------------------------------------------------------------ #
    def security_posture(self) -> Dict[str, Any]:
        return {
            "risk_images": 23,
            "risk_containers": 5,
            "config_violations": 47,
            "runtime_alerts": 12,
            "total_vulnerabilities": 156,
            "critical_vulns": 8,
            "high_vulns": 34,
            "medium_vulns": 78,
            "low_vulns": 36,
            "compliance_rate": 68.5,
            "cis_docker_compliance": 72.0,
            "cis_k8s_compliance": 65.3,
            "pod_security_compliance": 58.0,
            "overall_risk": "high",
            "trend": "worsening",
        }

    # ------------------------------------------------------------------ #
    # 3. 实时告警
    # ------------------------------------------------------------------ #
    def realtime_alerts(self) -> List[Dict[str, Any]]:
        return [
            {"id": "ALT-001", "type": "runtime_threat", "severity": "critical",
             "title": "容器内挖矿行为", "source": "worker-queue",
             "timestamp": "2024-09-14T10:23:01Z", "status": "open",
             "detail": "检测到 xmrig 进程，外联 pool.minexmr.com"},
            {"id": "ALT-002", "type": "config_violation", "severity": "critical",
             "title": "特权Pod创建", "source": "kube-system/priv-debug-pod",
             "timestamp": "2024-09-14T10:24:15Z", "status": "triaged",
             "detail": "匿名用户创建特权Pod"},
            {"id": "ALT-003", "type": "image_vulnerability", "severity": "high",
             "title": "新镜像Critical漏洞", "source": "node:20",
             "timestamp": "2024-09-14T09:00:00Z", "status": "open",
             "detail": "CVE-2024-21626 runc容器逃逸"},
            {"id": "ALT-004", "type": "anomalous_api", "severity": "critical",
             "title": "ServiceAccount提权", "source": "prod:deployer",
             "timestamp": "2024-09-14T10:25:30Z", "status": "open",
             "detail": "创建ClusterRoleBinding绑定cluster-admin"},
            {"id": "ALT-005", "type": "container_escape", "severity": "critical",
             "title": "疑似容器逃逸", "source": "worker-queue",
             "timestamp": "2024-09-14T10:26:00Z", "status": "investigating",
             "detail": "检测到mount/setns系统调用"},
            {"id": "ALT-006", "type": "anomalous_pod", "severity": "medium",
             "title": "CrashLoopBackOff", "source": "default/legacy-worker",
             "timestamp": "2024-09-14T08:00:00Z", "status": "resolved",
             "detail": "Pod重启25次"},
        ]

    # ------------------------------------------------------------------ #
    # 4. 漏洞管理
    # ------------------------------------------------------------------ #
    def vulnerability_management(self) -> Dict[str, Any]:
        vulns = [
            {"cve": "CVE-2024-21626", "severity": "critical", "cvss": 8.6,
             "package": "runc", "affected_images": ["node:20", "python:3.11-slim"],
             "fixed_version": "1.1.12", "priority": "P0", "status": "open"},
            {"cve": "CVE-2024-23334", "severity": "high", "cvss": 7.5,
             "package": "aiohttp", "affected_images": ["python:3.11-slim"],
             "fixed_version": "3.9.2", "priority": "P1", "status": "open"},
            {"cve": "CVE-2023-44487", "severity": "high", "cvss": 7.5,
             "package": "nginx", "affected_images": ["nginx:1.25"],
             "fixed_version": "1.25.3", "priority": "P1", "status": "fixing"},
            {"cve": "CVE-2022-0811", "severity": "critical", "cvss": 8.8,
             "package": "systemd", "affected_images": ["ubuntu:22.04"],
             "fixed_version": "247.3", "priority": "P0", "status": "open"},
            {"cve": "CVE-2024-1086", "severity": "high", "cvss": 7.8,
             "package": "kernel", "affected_images": ["node:20"],
             "fixed_version": "6.7.1", "priority": "P1", "status": "tracking"},
        ]
        trend = [
            {"date": "2024-09-08", "critical": 6, "high": 30, "medium": 70, "low": 30},
            {"date": "2024-09-09", "critical": 7, "high": 32, "medium": 72, "low": 32},
            {"date": "2024-09-10", "critical": 8, "high": 34, "medium": 78, "low": 36},
            {"date": "2024-09-11", "critical": 8, "high": 33, "medium": 76, "low": 35},
            {"date": "2024-09-12", "critical": 8, "high": 34, "medium": 78, "low": 36},
            {"date": "2024-09-13", "critical": 8, "high": 34, "medium": 78, "low": 36},
            {"date": "2024-09-14", "critical": 8, "high": 34, "medium": 78, "low": 36},
        ]
        return {
            "vulnerabilities": vulns,
            "total": 156,
            "by_priority": {"P0": 2, "P1": 3, "P2": 12, "P3": 139},
            "fix_rate": 42.0,
            "trend": trend,
            "top_affected_images": [
                {"image": "node:20", "vulns": 32, "critical": 3},
                {"image": "mysql:8.0", "vulns": 21, "critical": 2},
                {"image": "nginx:1.25", "vulns": 18, "critical": 1},
            ],
        }

    # ------------------------------------------------------------------ #
    # 5. 合规状态
    # ------------------------------------------------------------------ #
    def compliance_status(self) -> Dict[str, Any]:
        return {
            "cis_docker": {"framework": "CIS Docker Benchmark v1.6",
                           "total_checks": 21, "passed": 15, "failed": 6,
                           "compliance_pct": 71.4},
            "cis_k8s": {"framework": "CIS Kubernetes Benchmark v1.9",
                        "total_checks": 80, "passed": 52, "failed": 28,
                        "compliance_pct": 65.0},
            "pod_security": {"framework": "Pod Security Standards",
                             "total_namespaces": 6, "restricted": 2, "baseline": 3, "privileged": 1,
                             "compliance_pct": 83.3},
            "compliance_trend": [
                {"date": "2024-09-08", "cis_docker": 65, "cis_k8s": 58, "pod_security": 70},
                {"date": "2024-09-10", "cis_docker": 68, "cis_k8s": 61, "pod_security": 75},
                {"date": "2024-09-12", "cis_docker": 70, "cis_k8s": 63, "pod_security": 80},
                {"date": "2024-09-14", "cis_docker": 71.4, "cis_k8s": 65.0, "pod_security": 83.3},
            ],
            "audit_report_ready": True,
        }

    # ------------------------------------------------------------------ #
    # 6. 安全度量
    # ------------------------------------------------------------------ #
    def security_metrics(self) -> Dict[str, Any]:
        return {
            "vuln_fix_rate": 42.0,
            "config_compliance_rate": 68.5,
            "runtime_intercept_rate": 95.2,
            "mttr_hours": 4.5,
            "image_scan_coverage": 87.0,
            "alert_volume_trend": [
                {"date": "2024-09-08", "alerts": 18},
                {"date": "2024-09-09", "alerts": 22},
                {"date": "2024-09-10", "alerts": 15},
                {"date": "2024-09-11", "alerts": 25},
                {"date": "2024-09-12", "alerts": 19},
                {"date": "2024-09-13", "alerts": 21},
                {"date": "2024-09-14", "alerts": 12},
            ],
            "top_threats": [
                {"type": "mining", "count": 5, "severity": "critical"},
                {"type": "reverse_shell", "count": 3, "severity": "critical"},
                {"type": "privilege_escalation", "count": 2, "severity": "high"},
                {"type": "container_escape", "count": 1, "severity": "critical"},
            ],
            "top_risk_images": [
                {"image": "node:20", "risk_score": 45, "vulns": 32},
                {"image": "mysql:8.0", "risk_score": 55, "vulns": 21},
                {"image": "nginx:1.25", "risk_score": 62, "vulns": 18},
            ],
        }

    # ------------------------------------------------------------------ #
    # 综合仪表盘
    # ------------------------------------------------------------------ #
    def dashboard(self) -> Dict[str, Any]:
        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "asset_overview": self.asset_overview(),
            "security_posture": self.security_posture(),
            "realtime_alerts": self.realtime_alerts(),
            "vulnerability_management": self.vulnerability_management(),
            "compliance_status": self.compliance_status(),
            "security_metrics": self.security_metrics(),
        }
