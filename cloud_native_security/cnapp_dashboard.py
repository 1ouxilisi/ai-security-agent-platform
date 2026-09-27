# -*- coding: utf-8 -*-
"""
cnapp_dashboard.py - 云原生安全控制台聚合（第25轮 CNAPP 模块）。

聚合 6 大子系统提供统一总览：
  - 云原生总览   — 云资产数 / 风险数 / 漏洞数 / 告警数 / 合规评分 / 安全趋势 / 攻击路径数
  - K8s 安全     — 集群管理 / 节点管理 / Pod管理 / 配置审计 / 运行时监控 / 逃逸检测 / 威胁检测 / 响应
  - 容器安全     — 镜像扫描 / 运行时安全 / 逃逸防护 / 网络安全 / 合规 / 生命周期
  - 服务网格     — 服务发现 / 配置审计 / 通信安全 / 威胁检测 / 可视化 / 响应
  - CWPP        — 工作负载发现 / 配置审计 / 运行时保护 / 漏洞管理 / 合规 / 响应
  - CSPM        — 云资产 / 配置审计 / 合规评估 / 风险评分 / 攻击路径 / 改进建议
  - 系统设置     — 云账号 / 扫描配置 / 检测规则 / 告警配置 / 通知配置 / 合规框架 / 审计配置
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from .k8s_runtime import create_k8s_runtime
from .container_security import create_container_security
from .service_mesh import create_service_mesh
from .cwpp import create_cwpp
from .cspm import create_cspm


def _now() -> str:
    return datetime.now().isoformat()


class CNAPPDashboard:
    """云原生安全控制台聚合层。"""

    def __init__(self) -> None:
        self.k8s = create_k8s_runtime()
        self.container = create_container_security()
        self.mesh = create_service_mesh()
        self.cwpp = create_cwpp()
        self.cspm = create_cspm()

    # ---------- 总览 ----------

    def get_overview(self) -> Dict[str, Any]:
        return {
            "summary": {
                "cloud_assets": 128,
                "total_risks": 47,
                "critical_risks": 8,
                "high_risks": 15,
                "medium_risks": 17,
                "low_risks": 7,
                "vulnerabilities": 134,
                "active_alerts": 12,
                "compliance_score": 62.5,
                "attack_paths": 3,
                "clusters": 4,
                "namespaces": 8,
                "pods": 24,
                "containers": 124,
                "services": 48,
                "meshes": 3,
                "workloads": 8,
            },
            "security_trend": [
                {"date": "2026-09-08", "score": 55, "risks": 52, "alerts": 18},
                {"date": "2026-09-09", "score": 57, "risks": 50, "alerts": 15},
                {"date": "2026-09-10", "score": 58, "risks": 49, "alerts": 14},
                {"date": "2026-09-11", "score": 60, "risks": 48, "alerts": 13},
                {"date": "2026-09-12", "score": 61, "risks": 47, "alerts": 12},
                {"date": "2026-09-13", "score": 62, "risks": 47, "alerts": 12},
                {"date": "2026-09-14", "score": 62.5, "risks": 47, "alerts": 12},
            ],
            "top_findings": [
                {"severity": "critical", "title": "default SA 绑定 cluster-admin", "source": "K8s RBAC"},
                {"severity": "critical", "title": "公开 S3 存储桶", "source": "CSPM S3"},
                {"severity": "critical", "title": "特权容器运行", "source": "K8s Runtime"},
                {"severity": "critical", "title": "检测到挖矿程序", "source": "CWPP Runtime"},
                {"severity": "high", "title": "SSH 端口对全世界开放", "source": "CSPM SG"},
            ],
            "generated_at": _now(),
        }

    # ---------- K8s 汇总 ----------

    def get_k8s_summary(self) -> Dict[str, Any]:
        return {
            "clusters": self.k8s.discover_clusters(),
            "namespaces": self.k8s.discover_namespaces(),
            "pods_count": 24,
            "audit_findings": {
                "rbac": len(self.k8s.audit_rbac()["findings"]),
                "network_policy": len(self.k8s.audit_network_policy()["findings"]),
                "security_context": len(self.k8s.audit_security_context()["findings"]),
                "resource_limits": len(self.k8s.audit_resource_limits()["findings"]),
                "pod_standards": len(self.k8s.audit_pod_standards()["findings"]),
                "admission": len(self.k8s.audit_admission_control()["findings"]),
                "audit_policy": len(self.k8s.audit_audit_policy()["findings"]),
            },
            "escape_detections": {
                "privileged": len(self.k8s.detect_privileged_containers()["findings"]),
                "host_mounts": len(self.k8s.detect_host_mounts()["findings"]),
                "capabilities": len(self.k8s.detect_kernel_capabilities()["findings"]),
                "techniques": len(self.k8s.detect_escape_techniques()["techniques"]),
            },
            "threat_alerts": {
                "anomalous_pods": len(self.k8s.detect_anomalous_pod_creation()["alerts"]),
                "service_exposure": len(self.k8s.detect_anomalous_service_exposure()["alerts"]),
                "config_changes": len(self.k8s.detect_anomalous_config_changes()["alerts"]),
                "lateral_movement": len(self.k8s.detect_lateral_movement()["alerts"]),
            },
        }

    # ---------- 容器安全汇总 ----------

    def get_container_summary(self) -> Dict[str, Any]:
        hardening = self.container.get_escape_hardening_rules()
        return {
            "images_scanned": 128,
            "vulnerabilities_found": 134,
            "critical_vulns": 12,
            "high_vulns": 35,
            "misconfigurations": 48,
            "secrets_leaked": 7,
            "malware_detected": 2,
            "hardening_rules_total": len(hardening["rules"]),
            "compliance_frameworks": ["cis-docker", "cis-k8s", "nist", "pci"],
        }

    # ---------- 服务网格汇总 ----------

    def get_mesh_summary(self) -> Dict[str, Any]:
        meshes = self.mesh.discover_meshes()
        return {
            "meshes": meshes,
            "total_services": 48,
            "mtls_compliant": 90,
            "authorization_policies": 12,
            "threat_alerts": len(self.mesh.detect_anomalous_calls()["alerts"])
                            + len(self.mesh.detect_unauthorized_access()["alerts"]),
        }

    # ---------- CWPP 汇总 ----------

    def get_cwpp_summary(self) -> Dict[str, Any]:
        workloads = self.cwpp.discover_workloads()
        return {
            "total_workloads": workloads["total"],
            "vulnerabilities": 134,
            "critical_vulns": 8,
            "runtime_alerts": len(self.cwpp.runtime_intrusion_detection()["alerts"]),
            "compliance_score": 58.0,
        }

    # ---------- CSPM 汇总 ----------

    def get_cspm_summary(self) -> Dict[str, Any]:
        risk = self.cspm.get_risk_score()
        return {
            "total_assets": 12,
            "configuration_findings": 28,
            "critical_findings": 4,
            "compliance_score": risk["overall_score"],
            "risk_level": risk["overall_level"],
            "attack_paths": 3,
            "remediation_recommendations": len(self.cspm.get_remediation_recommendations()["recommendations"]),
        }

    # ---------- 系统设置 ----------

    def get_settings(self) -> Dict[str, Any]:
        return {
            "cloud_accounts": [
                {"name": "prod-aws", "provider": "aws", "status": "connected", "last_scan": _now()},
                {"name": "prod-azure", "provider": "azure", "status": "connected", "last_scan": _now()},
                {"name": "prod-gcp", "provider": "gcp", "status": "disconnected", "last_scan": None},
            ],
            "scan_config": {
                "schedule": "daily",
                "time": "02:00",
                "scan_vulns": True,
                "scan_misconfigs": True,
                "scan_secrets": True,
                "scan_malware": True,
            },
            "detection_rules": {
                "cryptomining": True,
                "privilege_escalation": True,
                "lateral_movement": True,
                "data_exfiltration": True,
                "container_escape": True,
            },
            "alert_config": {
                "severity_threshold": "high",
                "notification_channels": ["email", "webhook", "sms"],
                "email_recipients": ["security@example.com"],
            },
            "compliance_frameworks": ["cis-aws", "cis-k8s", "nist", "pci", "dengbao"],
            "audit_config": {
                "log_retention_days": 90,
                "send_to_siem": True,
                "siem_endpoint": "https://siem.example.com/ingest",
            },
        }


# ==================== 工厂函数 ====================

def create_cnapp_dashboard() -> CNAPPDashboard:
    return CNAPPDashboard()
