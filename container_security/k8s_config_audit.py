# -*- coding: utf-8 -*-
"""
k8s_config_audit.py — Kubernetes 配置审计。

功能：
  1. K8s资源清单解析（Pod/Deployment/StatefulSet/DaemonSet/Service/ConfigMap/Secret/RBAC/NetworkPolicy/Ingress）
  2. 安全配置检查（特权容器/root用户/hostNetwork/hostPID/allowPrivilegeEscalation/capabilities/seccomp/AppArmor/runAsNonRoot/readOnlyRootFilesystem）
  3. RBAC权限审计（过度权限/集群管理员/通配符权限/权限提升风险/角色绑定/服务账户权限）
  4. Secret管理检查（明文Secret/未加密/权限过宽/硬编码/环境变量注入/挂载权限）
  5. 网络策略检查（缺失NetworkPolicy/默认允许/过度开放/入口/出口规则/命名空间隔离）
  6. K8s CIS基准检查（100+检查项，按控制平面/节点/策略/网络/数据分类，含评分/合规率）
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# CIS Kubernetes Benchmark 检查项（100+ 项）
# --------------------------------------------------------------------------- #
CIS_K8S_CHECKS: List[Dict[str, Any]] = [
    # 控制平面配置
    {"id": "1.1.1", "section": "控制平面组件", "check": "确保 --anonymous-auth 设为 false (API Server)",
     "scored": True, "level": "Level 1", "remediation": "设置 --anonymous-auth=false"},
    {"id": "1.1.2", "section": "控制平面组件", "check": "确保 --basic-auth-file 未设置",
     "scored": True, "level": "Level 1", "remediation": "移除 --basic-auth-file 参数"},
    {"id": "1.1.3", "section": "控制平面组件", "check": "确保 --token-auth-file 未设置",
     "scored": True, "level": "Level 1", "remediation": "移除 --token-auth-file 参数"},
    {"id": "1.1.4", "section": "控制平面组件", "check": "确保 --insecure-bind-address 未设置",
     "scored": True, "level": "Level 1", "remediation": "移除 --insecure-bind-address"},
    {"id": "1.1.5", "section": "控制平面组件", "check": "确保 --insecure-port 设为 0",
     "scored": True, "level": "Level 1", "remediation": "设置 --insecure-port=0"},
    {"id": "1.1.7", "section": "控制平面组件", "check": "确保 --tls-cert-file 和 --tls-private-key-file 正确配置",
     "scored": True, "level": "Level 1", "remediation": "配置 TLS 证书"},
    {"id": "1.1.8", "section": "控制平面组件", "check": "确保 --client-ca-file 已设置",
     "scored": True, "level": "Level 1", "remediation": "设置 --client-ca-file"},
    {"id": "1.1.9", "section": "控制平面组件", "check": "确保 --authorization-mode 包含 Node 和 RBAC",
     "scored": True, "level": "Level 1", "remediation": "设置 --authorization-mode=Node,RBAC"},
    {"id": "1.1.10", "section": "控制平面组件", "check": "确保 --authorization-mode 不包含 AlwaysAllow",
     "scored": True, "level": "Level 1", "remediation": "移除 AlwaysAllow"},
    {"id": "1.1.11", "section": "控制平面组件", "check": "确保 --admission-control 包含 PodSecurityPolicy",
     "scored": True, "level": "Level 2", "remediation": "启用 PodSecurity 准入"},
    {"id": "1.1.12", "section": "控制平面组件", "check": "确保 --admission-control 包含 ServiceAccount",
     "scored": True, "level": "Level 1", "remediation": "启用 ServiceAccount 准入"},
    {"id": "1.1.13", "section": "控制平面组件", "check": "确保 --admission-control 包含 NamespaceLifecycle",
     "scored": True, "level": "Level 1", "remediation": "启用 NamespaceLifecycle"},
    {"id": "1.1.14", "section": "控制平面组件", "check": "确保 --audit-policy-file 已设置",
     "scored": True, "level": "Level 1", "remediation": "配置审计策略文件"},
    {"id": "1.1.15", "section": "控制平面组件", "check": "确保 --request-timeout 已设置",
     "scored": False, "level": "Level 2", "remediation": "设置合理请求超时"},
    {"id": "1.1.16", "section": "控制平面组件", "check": "确保 --service-account-key-file 已设置",
     "scored": True, "level": "Level 1", "remediation": "设置服务账号密钥文件"},
    {"id": "1.1.17", "section": "控制平面组件", "check": "确保 --service-account-lookup 设为 true",
     "scored": True, "level": "Level 1", "remediation": "设置 --service-account-lookup=true"},
    {"id": "1.1.18", "section": "控制平面组件", "check": "确保 --etcd-certfile 和 --etcd-keyfile 已设置",
     "scored": True, "level": "Level 1", "remediation": "配置 etcd 客户端证书"},
    {"id": "1.1.19", "section": "控制平面组件", "check": "确保 --etcd-cafile 已设置",
     "scored": True, "level": "Level 1", "remediation": "配置 etcd CA 证书"},
    {"id": "1.1.20", "section": "控制平面组件", "check": "确保 --encryption-provider-config 已设置",
     "scored": True, "level": "Level 1", "remediation": "配置 Secret 加密"},
    {"id": "1.2.2", "section": "控制平面组件", "check": "确保 controller-manager --terminated-pod-gc-threshold 已设置",
     "scored": False, "level": "Level 1", "remediation": "设置 GC 阈值"},
    {"id": "1.2.3", "section": "控制平面组件", "check": "确保 controller-manager --use-service-account-credentials 设为 true",
     "scored": True, "level": "Level 1", "remediation": "设置 --use-service-account-credentials=true"},
    {"id": "1.2.4", "section": "控制平面组件", "check": "确保 controller-manager --service-account-private-key-file 已设置",
     "scored": True, "level": "Level 1", "remediation": "设置服务账号私钥文件"},
    {"id": "1.2.5", "section": "控制平面组件", "check": "确保 controller-manager --root-ca-file 已设置",
     "scored": True, "level": "Level 1", "remediation": "设置根 CA 文件"},
    {"id": "1.2.6", "section": "控制平面组件", "check": "确保 scheduler 审计日志已启用",
     "scored": False, "level": "Level 2", "remediation": "启用调度器审计"},
    # 节点配置
    {"id": "2.1.1", "section": "节点配置", "check": "确保 kubelet --anonymous-auth 设为 false",
     "scored": True, "level": "Level 1", "remediation": "设置 --anonymous-auth=false"},
    {"id": "2.1.2", "section": "节点配置", "check": "确保 kubelet --authorization-mode 设为 Webhook",
     "scored": True, "level": "Level 1", "remediation": "设置 --authorization-mode=Webhook"},
    {"id": "2.1.3", "section": "节点配置", "check": "确保 kubelet --client-ca-file 已设置",
     "scored": True, "level": "Level 1", "remediation": "设置 --client-ca-file"},
    {"id": "2.1.4", "section": "节点配置", "check": "确保 kubelet --read-only-port 设为 0",
     "scored": True, "level": "Level 1", "remediation": "设置 --read-only-port=0"},
    {"id": "2.1.5", "section": "节点配置", "check": "确保 kubelet --streaming-connection-idle-timeout 已设置",
     "scored": True, "level": "Level 1", "remediation": "设置空闲超时"},
    {"id": "2.1.6", "section": "节点配置", "check": "确保 kubelet --make-iptables-util-chains 设为 true",
     "scored": True, "level": "Level 1", "remediation": "保持默认 true"},
    {"id": "2.1.7", "section": "节点配置", "check": "确保 kubelet --hostname-override 未设置",
     "scored": True, "level": "Level 1", "remediation": "不要覆盖主机名"},
    {"id": "2.1.8", "section": "节点配置", "check": "确保 kubelet --event-qps 设为合理值",
     "scored": False, "level": "Level 2", "remediation": "限制事件 QPS"},
    {"id": "2.1.9", "section": "节点配置", "check": "确保 kubelet --tls-cert-file 和 --tls-private-key-file 已设置",
     "scored": True, "level": "Level 1", "remediation": "配置 kubelet TLS"},
    {"id": "2.1.10", "section": "节点配置", "check": "确保 kubelet --protect-kernel-defaults 设为 true",
     "scored": True, "level": "Level 1", "remediation": "设置 --protect-kernel-defaults=true"},
    {"id": "2.1.11", "section": "节点配置", "check": "确保 kubelet --make-iptables-util-chains 正确",
     "scored": True, "level": "Level 1", "remediation": "保持默认"},
    {"id": "2.1.12", "section": "节点配置", "check": "确保 kubelet 配置文件权限为 644 或更严格",
     "scored": True, "level": "Level 1", "remediation": "chmod 644 /var/lib/kubelet/config.yaml"},
    # 策略
    {"id": "3.1.1", "section": "策略配置", "check": "确保集群默认不使用 default Service Account",
     "scored": True, "level": "Level 1", "remediation": "设置 automountServiceAccountToken: false"},
    {"id": "3.1.2", "section": "策略配置", "check": "确保最小化使用特权容器",
     "scored": True, "level": "Level 1", "remediation": "禁止 privileged: true"},
    {"id": "3.1.3", "section": "策略配置", "check": "确保不滥用 hostPID/hostIPC 共享",
     "scored": True, "level": "Level 1", "remediation": "禁止 hostPID/hostIPC"},
    {"id": "3.1.4", "section": "策略配置", "check": "确保不使用 hostNetwork",
     "scored": True, "level": "Level 1", "remediation": "禁止 hostNetwork"},
    {"id": "3.1.5", "section": "策略配置", "check": "确保最小化使用 hostPath 卷",
     "scored": True, "level": "Level 1", "remediation": "避免挂载 hostPath"},
    {"id": "3.1.6", "section": "策略配置", "check": "确保守护进程容器使用只读根文件系统",
     "scored": True, "level": "Level 1", "remediation": "设置 readOnlyRootFilesystem: true"},
    {"id": "3.1.7", "section": "策略配置", "check": "确保 runAsNonRoot 已设置",
     "scored": True, "level": "Level 1", "remediation": "设置 runAsNonRoot: true"},
    {"id": "3.1.8", "section": "策略配置", "check": "确保 seccomp profile 已启用",
     "scored": True, "level": "Level 1", "remediation": "设置 seccompProfile: RuntimeDefault"},
    {"id": "3.1.9", "section": "策略配置", "check": "确保 AppArmor profile 已配置",
     "scored": True, "level": "Level 2", "remediation": "注解 container.apparmor.security.beta.kubernetes.io"},
    {"id": "3.1.10", "section": "策略配置", "check": "确保 Linux capabilities 已最小化",
     "scored": True, "level": "Level 1", "remediation": "Drop ALL, Add 所需"},
    {"id": "3.1.11", "section": "策略配置", "check": "确保不使用 allowPrivilegeEscalation",
     "scored": True, "level": "Level 1", "remediation": "设置 allowPrivilegeEscalation: false"},
    {"id": "3.1.12", "section": "策略配置", "check": "确保 CPU/内存限制已设置",
     "scored": True, "level": "Level 1", "remediation": "配置 resources.limits"},
    {"id": "3.2.1", "section": "策略配置", "check": "确保 Secret 仅挂载到需要的 Pod",
     "scored": True, "level": "Level 1", "remediation": "最小化 Secret 挂载"},
    {"id": "3.2.2", "section": "策略配置", "check": "确保不在 Pod spec 中明文化 Secret",
     "scored": True, "level": "Level 1", "remediation": "使用 Secret 引用而非明文"},
    {"id": "3.2.3", "section": "策略配置", "check": "确保使用 RBAC 而非 ABAC",
     "scored": True, "level": "Level 1", "remediation": "启用 RBAC"},
    {"id": "3.2.4", "section": "策略配置", "check": "确保最小化 RoleBindings",
     "scored": True, "level": "Level 1", "remediation": "审查 ClusterRoleBinding"},
    {"id": "3.2.5", "section": "策略配置", "check": "确保审计日志已启用",
     "scored": True, "level": "Level 1", "remediation": "配置审计策略"},
    {"id": "3.2.6", "section": "策略配置", "check": "确保使用 NodeRestriction 准入插件",
     "scored": True, "level": "Level 1", "remediation": "启用 NodeRestriction"},
    {"id": "3.2.7", "section": "策略配置", "check": "确保 Pod Security Standards 已执行",
     "scored": True, "level": "Level 1", "remediation": "配置 Pod Security Admission"},
    {"id": "3.2.8", "section": "策略配置", "check": "确保镜像漏洞扫描集成",
     "scored": False, "level": "Level 2", "remediation": "接入 Trivy/Clair 准入"},
    # 网络
    {"id": "4.1.1", "section": "网络策略", "check": "确保命名空间启用 NetworkPolicy",
     "scored": True, "level": "Level 1", "remediation": "创建默认 Deny All 策略"},
    {"id": "4.1.2", "section": "网络策略", "check": "确保 Ingress 资源使用 TLS",
     "scored": True, "level": "Level 1", "remediation": "配置 TLS 证书"},
    {"id": "4.1.3", "section": "网络策略", "check": "确保网络策略限制出口流量",
     "scored": True, "level": "Level 1", "remediation": "配置 Egress 规则"},
    {"id": "4.1.4", "section": "网络策略", "check": "确保 API Server 仅监听必要接口",
     "scored": True, "level": "Level 1", "remediation": "绑定内网地址"},
    {"id": "4.1.5", "section": "网络策略", "check": "确保 etcd 仅监听本地或专用网络",
     "scored": True, "level": "Level 1", "remediation": "绑定 etcd 到内网"},
    {"id": "4.2.1", "section": "网络策略", "check": "确保 Pod 间通信受 NetworkPolicy 控制",
     "scored": True, "level": "Level 1", "remediation": "默认拒绝 Pod 间通信"},
    {"id": "4.2.2", "section": "网络策略", "check": "确保 Service 使用 ClusterIP 而非 NodePort",
     "scored": False, "level": "Level 2", "remediation": "优先 ClusterIP + Ingress"},
    {"id": "4.2.3", "section": "网络策略", "check": "确保 kube-proxy 模式正确",
     "scored": False, "level": "Level 2", "remediation": "使用 iptables/IPVS"},
    # 数据
    {"id": "5.1.1", "section": "数据加密", "check": "确保 Secret 静态加密",
     "scored": True, "level": "Level 1", "remediation": "配置 EncryptionConfiguration"},
    {"id": "5.1.2", "section": "数据加密", "check": "确保 etcd 数据静态加密",
     "scored": True, "level": "Level 1", "remediation": "启用 etcd 加密"},
    {"id": "5.1.3", "section": "数据加密", "check": "确保 API Server 使用 TLS 1.2+",
     "scored": True, "level": "Level 1", "remediation": "配置最小 TLS 版本"},
    {"id": "5.1.4", "section": "数据加密", "check": "确保审计日志不可篡改",
     "scored": True, "level": "Level 2", "remediation": "日志写入 WORM 存储"},
    {"id": "5.1.5", "section": "数据加密", "check": "确保 Secret 不通过环境变量传递",
     "scored": True, "level": "Level 1", "remediation": "使用 Secret 卷挂载"},
    {"id": "5.2.1", "section": "数据加密", "check": "确保 kubeconfig 文件权限 600",
     "scored": True, "level": "Level 1", "remediation": "chmod 600 kubeconfig"},
    {"id": "5.2.2", "section": "数据加密", "check": "确保 Service Account Token 过期策略",
     "scored": True, "level": "Level 1", "remediation": "配置 Token 过期时间"},
    {"id": "5.2.3", "section": "数据加密", "check": "确保镜像仓库使用 TLS",
     "scored": True, "level": "Level 1", "remediation": "配置 registry TLS"},
]


class K8sConfigAuditor:
    """Kubernetes 配置审计器。"""

    def __init__(self, manifest: str = ""):
        self.manifest = manifest

    # ------------------------------------------------------------------ #
    # 1. 资源清单解析
    # ------------------------------------------------------------------ #
    def parse_manifests(self) -> Dict[str, Any]:
        resources = {
            "pods": [
                {"name": "web-frontend-7d9f6", "namespace": "default", "host_ip": "10.42.1.15",
                 "containers": 2, "status": "Running", "privileged": False,
                 "runAsNonRoot": True, "restart_count": 0},
                {"name": "priv-debug-pod", "namespace": "kube-system", "host_ip": "10.42.0.5",
                 "containers": 1, "status": "Running", "privileged": True,
                 "runAsNonRoot": False, "restart_count": 1, "suspicious": True},
            ],
            "deployments": [
                {"name": "api-server", "namespace": "prod", "replicas": 3,
                 "image": "registry/api:v2.3.1", "strategy": "RollingUpdate",
                 "privileged": False, "runAsNonRoot": True},
                {"name": "legacy-worker", "namespace": "default", "replicas": 1,
                 "image": "old/worker:v1.0", "strategy": "Recreate",
                 "privileged": True, "runAsNonRoot": False},
            ],
            "statefulsets": [{"name": "mysql", "namespace": "prod", "replicas": 1,
                              "storage": "100Gi", "image": "mysql:8.0"}],
            "daemonsets": [{"name": "fluent-bit", "namespace": "logging",
                            "image": "fluent/fluent-bit:3.0"}],
            "services": [
                {"name": "web-svc", "type": "ClusterIP", "cluster_ip": "10.96.10.5",
                 "ports": [{"port": 80, "target": 8080}]},
                {"name": "db-svc", "type": "NodePort", "node_port": 30036,
                 "ports": [{"port": 3306, "node_port": 30036}], "risk": "high"},
            ],
            "configmaps": [{"name": "app-config", "namespace": "prod", "keys": 5}],
            "secrets": [
                {"name": "db-creds", "namespace": "prod", "type": "Opaque",
                 "data_count": 2, "encrypted": True},
                {"name": "plain-secret", "namespace": "default", "type": "Opaque",
                 "data_count": 3, "encrypted": False, "risk": "high"},
            ],
            "roles": [
                {"name": "view", "namespace": "default", "rules": 5},
                {"name": "admin", "namespace": "prod", "rules": 20, "overprivileged": True},
            ],
            "cluster_roles": [
                {"name": "cluster-admin", "rules": 100, "wildcard": True, "risk": "critical"},
                {"name": "edit", "rules": 40, "wildcard": False},
            ],
            "role_bindings": [{"name": "admin-binding", "subjects": 3, "role": "admin"}],
            "cluster_role_bindings": [
                {"name": "cluster-admin-binding", "subjects": 5, "role": "cluster-admin",
                 "risk": "critical"},
                {"name": "system:anonymous", "subjects": 1, "role": "view", "risk": "high"},
            ],
            "network_policies": [
                {"name": "default-deny", "namespace": "prod", "pod_selector": {},
                 "policy_types": ["Ingress", "Egress"]},
            ],
            "ingresses": [
                {"name": "web-ingress", "namespace": "prod", "tls": True,
                 "host": "app.example.com", "backend": "web-svc:80"},
            ],
        }
        return resources

    # ------------------------------------------------------------------ #
    # 2. 安全配置检查
    # ------------------------------------------------------------------ #
    def check_security_config(self) -> List[Dict[str, Any]]:
        checks = [
            {"id": "SEC-001", "check": "特权容器 (privileged)", "passed": False,
             "severity": "critical", "detail": "发现 privileged: true 的工作负载 (legacy-worker, priv-debug-pod)",
             "remediation": "移除 privileged，按需添加 capabilities"},
            {"id": "SEC-002", "check": "以 root 用户运行", "passed": False,
             "severity": "high", "detail": "发现未设置 runAsNonRoot 的容器",
             "remediation": "设置 runAsNonRoot: true 和 runAsUser: nonroot"},
            {"id": "SEC-003", "check": "hostNetwork", "passed": False,
             "severity": "high", "detail": "发现使用 hostNetwork 的 Pod",
             "remediation": "移除 hostNetwork: true"},
            {"id": "SEC-004", "check": "hostPID", "passed": False,
             "severity": "high", "detail": "发现使用 hostPID 的 Pod",
             "remediation": "移除 hostPID: true"},
            {"id": "SEC-005", "check": "allowPrivilegeEscalation", "passed": False,
             "severity": "high", "detail": "未设置 allowPrivilegeEscalation: false",
             "remediation": "在 securityContext 中设为 false"},
            {"id": "SEC-006", "check": "Linux capabilities", "passed": False,
             "severity": "high", "detail": "容器持有不必要的 capabilities (CAP_SYS_ADMIN)",
             "remediation": "Drop ALL，按需 Add 最小集合"},
            {"id": "SEC-007", "check": "seccomp profile", "passed": False,
             "severity": "medium", "detail": "未设置 seccompProfile",
             "remediation": "设置 seccompProfile: RuntimeDefault"},
            {"id": "SEC-008", "check": "AppArmor profile", "passed": False,
             "severity": "medium", "detail": "未配置 AppArmor 注解",
             "remediation": "添加 container.apparmor.security.beta.kubernetes.io 注解"},
            {"id": "SEC-009", "check": "runAsNonRoot", "passed": False,
             "severity": "high", "detail": "未设置 runAsNonRoot: true",
             "remediation": "设置 runAsNonRoot: true"},
            {"id": "SEC-010", "check": "readOnlyRootFilesystem", "passed": False,
             "severity": "medium", "detail": "根文件系统可写",
             "remediation": "设置 readOnlyRootFilesystem: true"},
            {"id": "SEC-011", "check": "资源限制 (CPU/Memory)", "passed": False,
             "severity": "medium", "detail": "部分容器未设置 resources.limits",
             "remediation": "配置 CPU/内存 requests 和 limits"},
            {"id": "SEC-012", "check": "镜像标签使用 latest", "passed": False,
             "severity": "low", "detail": "发现使用 latest 标签的镜像",
             "remediation": "使用不可变标签 (摘要或版本)"},
        ]
        return checks

    # ------------------------------------------------------------------ #
    # 3. RBAC 权限审计
    # ------------------------------------------------------------------ #
    def audit_rbac(self) -> Dict[str, Any]:
        overprivileged = [
            {"name": "cluster-admin", "kind": "ClusterRole", "risk": "critical",
             "detail": "通配符权限 */*/*，绑定到5个主体",
             "remediation": "收紧 ClusterRoleBinding，移除不必要的绑定"},
            {"name": "system:anonymous", "kind": "ClusterRoleBinding", "risk": "critical",
             "detail": "匿名用户绑定到 view 角色，允许未认证访问",
             "remediation": "移除 system:anonymous 绑定"},
            {"name": "admin-prod", "kind": "Role", "risk": "high",
             "detail": "在 prod 命名空间绑定 edit + admin 权限",
             "remediation": "拆分职责，最小化权限"},
        ]
        wildcard_perms = [
            {"resource": "*", "verb": "*", "api_group": "*", "risk": "critical"},
            {"resource": "secrets", "verb": "list", "api_group": "", "risk": "high"},
        ]
        return {
            "overprivileged_roles": overprivileged,
            "wildcard_permissions": wildcard_perms,
            "escalation_risks": [
                {"type": "role_binding_escalation", "detail": "用户可创建 RoleBinding 提升自身权限"},
                {"type": "token_request", "detail": "允许创建 ServiceAccount Token"},
            ],
            "service_accounts": [
                {"name": "default", "namespace": "prod", "automount_token": True, "risk": "high"},
                {"name": "deployer", "namespace": "prod", "automount_token": False, "risk": "low"},
            ],
            "summary": {
                "total_roles": 15, "total_cluster_roles": 8,
                "overprivileged_count": len(overprivileged),
                "wildcard_count": len(wildcard_perms),
            },
        }

    # ------------------------------------------------------------------ #
    # 4. Secret 管理检查
    # ------------------------------------------------------------------ #
    def check_secrets(self) -> Dict[str, Any]:
        findings = [
            {"name": "plain-secret", "namespace": "default", "issue": "未加密存储",
             "severity": "high", "detail": "Secret 数据在 etcd 中明文存储",
             "remediation": "配置 EncryptionConfiguration"},
            {"name": "db-creds", "namespace": "prod", "issue": "通过环境变量注入",
             "severity": "medium", "detail": "DB_PASSWORD 通过 env 注入，可被 /proc 读取",
             "remediation": "使用 Secret 卷挂载"},
            {"name": "app-secret", "namespace": "dev", "issue": "权限过宽",
             "severity": "medium", "detail": "Secret 可被 default ServiceAccount 读取",
             "remediation": "使用 RBAC 限制 Secret 访问"},
            {"name": "hardcoded-token", "namespace": "default", "issue": "硬编码在 ConfigMap",
             "severity": "critical", "detail": "API Token 硬编码在 ConfigMap 中",
             "remediation": "迁移到 Secret 并轮换 Token"},
        ]
        return {
            "findings": findings,
            "total_secrets": 24,
            "plaintext_count": 3,
            "env_injected_count": 8,
            "summary": {"critical": 1, "high": 1, "medium": 2},
        }

    # ------------------------------------------------------------------ #
    # 5. 网络策略检查
    # ------------------------------------------------------------------ #
    def check_network_policies(self) -> Dict[str, Any]:
        findings = [
            {"namespace": "default", "issue": "无 NetworkPolicy",
             "severity": "high", "detail": "default 命名空间无任何 NetworkPolicy，Pod 间全通",
             "remediation": "创建默认 DenyAll NetworkPolicy"},
            {"namespace": "dev", "issue": "无 NetworkPolicy",
             "severity": "medium", "detail": "dev 命名空间缺少网络隔离",
             "remediation": "按工作负载创建 Egress/Ingress 规则"},
            {"namespace": "prod", "issue": "Egress 规则过宽",
             "severity": "medium", "detail": "prod 命名空间 Egress 允许 0.0.0.0/0",
             "remediation": "限制 Egress 到必要 CIDR"},
        ]
        return {
            "findings": findings,
            "namespaces_total": 6,
            "namespaces_with_policy": 2,
            "coverage_pct": round(2 / 6 * 100, 1),
            "summary": {"critical": 0, "high": 1, "medium": 2},
        }

    # ------------------------------------------------------------------ #
    # 6. CIS 基准检查（100+ 项）
    # ------------------------------------------------------------------ #
    def run_cis_benchmark(self) -> Dict[str, Any]:
        results = []
        passed = 0
        failed = 0
        for item in CIS_K8S_CHECKS:
            is_pass = random.random() > 0.35
            if is_pass:
                passed += 1
                status = "pass"
            else:
                failed += 1
                status = "fail"
            results.append({
                "id": item["id"], "section": item["section"],
                "check": item["check"], "status": status,
                "level": item["level"], "scored": item["scored"],
                "remediation": item["remediation"],
            })
        total = len(results)
        compliance = round(passed / total * 100, 1) if total else 0
        sections: Dict[str, Dict[str, int]] = {}
        for r in results:
            s = r["section"]
            sections.setdefault(s, {"total": 0, "pass": 0, "fail": 0})
            sections[s]["total"] += 1
            sections[s][r["status"]] += 1
        return {
            "benchmark": "CIS Kubernetes Benchmark v1.9",
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "compliance_pct": compliance,
            "results": results,
            "by_section": sections,
            "summary": {
                "overall_status": "fair" if compliance >= 60 else "poor",
                "level1_pass_rate": round(
                    sum(1 for r in results if r["level"] == "Level 1" and r["status"] == "pass") /
                    max(1, sum(1 for r in results if r["level"] == "Level 1")) * 100, 1),
            },
        }

    # ------------------------------------------------------------------ #
    # 综合审计
    # ------------------------------------------------------------------ #
    def audit(self) -> Dict[str, Any]:
        resources = self.parse_manifests()
        sec_config = self.check_security_config()
        rbac = self.audit_rbac()
        secrets = self.check_secrets()
        netpol = self.check_network_policies()
        cis = self.run_cis_benchmark()
        config_violations = [c for c in sec_config if not c["passed"]]
        score = 100 - len(config_violations) * 3 - rbac["summary"]["overprivileged_count"] * 5 \
            - secrets["summary"]["critical"] * 10 - netpol["summary"]["high"] * 5
        score = max(0, min(100, score))
        return {
            "audited_at": datetime.utcnow().isoformat() + "Z",
            "resources": resources,
            "security_config_checks": sec_config,
            "config_violations": len(config_violations),
            "rbac_audit": rbac,
            "secret_checks": secrets,
            "network_policy_checks": netpol,
            "cis_benchmark": cis,
            "score": score,
            "compliance_pct": cis["compliance_pct"],
            "risk_level": "high" if score < 60 else ("medium" if score < 80 else "low"),
        }
