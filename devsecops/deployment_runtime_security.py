# -*- coding: utf-8 -*-
"""
deployment_runtime_security.py — 部署与运行时安全。

覆盖：
    - K8s 部署配置审计（Deployment / StatefulSet / DaemonSet）
    - RBAC 评估
    - 网络策略
    - Pod Security Standards (PSS)
    - Secrets 管理
    - 运行时威胁检测
    - Istio 安全配置

设计定位：仅做 YAML/配置审计与建议，不修改集群。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


PSS_LEVELS: Dict[str, Dict[str, Any]] = {
    "privileged": {"name": "Privileged", "risk": "允许特权，无限制",
                    "usage": "仅系统组件"},
    "baseline": {"name": "Baseline", "risk": "禁止已知提权",
                  "usage": "通用业务"},
    "restricted": {"name": "Restricted", "risk": "遵循 pod 安全最佳实践",
                    "usage": "强隔离业务"},
}

RUNTIME_THREATS: List[Dict[str, str]] = [
    {"id": "t1", "name": "异常进程（shell in container）", "severity": "high",
     "signal": "container 内出现 sh/bash 子进程"},
    {"id": "t2", "name": "可疑外联", "severity": "high",
     "signal": "Pod 连接已知 C2 IP"},
    {"id": "t3", "name": "crypto-mining", "severity": "critical",
     "signal": "高 CPU + 连接矿池"},
    {"id": "t4", "name": "敏感文件访问", "severity": "medium",
     "signal": "/etc/shadow /var/run/docker.sock 被读"},
    {"id": "t5", "name": "权限提升尝试", "severity": "critical",
     "signal": "capsh / setuid / chmod u+s"},
    {"id": "t6", "name": " lateral movement", "severity": "high",
     "signal": "Pod 跨 namespace 扫描"},
]


class DeploymentRuntimeSecurity:
    """K8s 部署与运行时安全评估器。"""

    def __init__(self) -> None:
        self.reports: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # Deployment / StatefulSet / DaemonSet 审计
    # ------------------------------------------------------------------ #
    def audit_workload(self, kind: str = "Deployment",
                       manifest: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        m = manifest or {}
        spec = (((m.get("spec") or {}).get("template") or {})
                .get("spec") or {})
        meta = m.get("metadata", {})
        findings: List[Dict[str, Any]] = []

        ssc = spec.get("securityContext") or {}
        pod_supp = bool(ssc.get("runAsNonRoot", False))
        for c in spec.get("containers", []):
            csc = c.get("securityContext") or {}
            if csc.get("privileged", False):
                findings.append({"severity": "critical", "title": f"{c['name']}: privileged:true"})
            caps = csc.get("capabilities") or {}
            if "ADD" in caps and "SYS_ADMIN" in caps["ADD"]:
                findings.append({"severity": "critical", "title": f"{c['name']}: CAP_SYS_ADMIN"})
            if csc.get("readOnlyRootFilesystem") is not True:
                findings.append({"severity": "medium", "title": f"{c['name']}: rootfs 可写"})
            if csc.get("runAsNonRoot") is not True and not pod_supp:
                findings.append({"severity": "high", "title": f"{c['name']}: 未 runAsNonRoot"})
            for env in c.get("env", []) or []:
                if "PASSWORD" in env.get("name", "").upper() \
                        or "SECRET" in env.get("name", "").upper():
                    if env.get("value"):
                        findings.append({"severity": "critical",
                                         "title": f"{c['name']}: env 硬编码 {env['name']}"})

        if not spec.get("resources", {}).get("limits"):
            findings.append({"severity": "medium", "title": "未设置 resources.limits"})
        if not spec.get("automountServiceAccountToken", True) is False:
            findings.append({"severity": "medium", "title": "未禁用自动挂载 SA token"})
        if spec.get("hostPID") or spec.get("hostIPC") or spec.get("hostNetwork"):
            findings.append({"severity": "high", "title": "共享 host namespace"})

        score = max(0, 100 - sum({"critical": 25, "high": 12,
                                  "medium": 5, "low": 1}.get(f["severity"], 0)
                                 for f in findings))
        result = {
            "kind": kind, "name": meta.get("name", "unknown"),
            "namespace": meta.get("namespace", "default"),
            "findings": findings, "findings_count": len(findings),
            "score": score,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.reports.append(result)
        return result

    # ------------------------------------------------------------------ #
    # RBAC 评估
    # ------------------------------------------------------------------ #
    def assess_rbac(self, roles: Optional[List[Dict[str, Any]]] = None
                    ) -> Dict[str, Any]:
        roles = roles or [
            {"name": "edit", "verbs": ["create", "update", "patch", "delete"],
             "resources": ["deployments", "pods", "secrets"], "binding": "dev"},
            {"name": "admin", "verbs": ["*"], "resources": ["*"],
             "binding": "platform"},
            {"name": "sa-default", "verbs": ["get", "list"],
             "resources": ["pods"], "binding": "default"},
        ]
        risky = []
        for r in roles:
            if "*" in r.get("verbs", []) or "*" in r.get("resources", []):
                risky.append({**r, "risk": "critical"})
            elif "secrets" in r.get("resources", []) and \
                    set(r.get("verbs", [])) & {"get", "list", "watch"}:
                risky.append({**r, "risk": "high"})
        return {
            "roles": roles, "total": len(roles),
            "overprivileged": risky,
            "overprivileged_count": len(risky),
            "recommendation": "按 namespace / 资源最小化；避免 ClusterRole 通配",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 网络策略
    # ------------------------------------------------------------------ #
    def assess_network_policy(self, namespaces: Optional[List[str]] = None,
                                has_default_deny: bool = False) -> Dict[str, Any]:
        nss = namespaces or ["default", "prod", "staging", "kube-system"]
        uncovered = [n for n in nss if n != "kube-system" and not has_default_deny]
        return {
            "namespaces": nss,
            "default_deny_installed": has_default_deny,
            "uncovered_namespaces": uncovered,
            "recommendation": "对每个 namespace 安装 default-deny-all 再显式放行",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # PSS
    # ------------------------------------------------------------------ #
    def assess_pss(self, enforced: str = "baseline",
                    exemptions: Optional[List[str]] = None) -> Dict[str, Any]:
        return {
            "enforced_level": enforced,
            "enforced_name": PSS_LEVELS.get(enforced, PSS_LEVELS["baseline"])["name"],
            "audit_level": "restricted",
            "warn_level": "restricted",
            "exemptions": exemptions or [],
            "recommendation": "生产建议 enforced=restricted",
            "levels": PSS_LEVELS,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # Secrets 管理
    # ------------------------------------------------------------------ #
    def assess_secrets(self, signals: Optional[Dict[str, Any]] = None
                       ) -> Dict[str, Any]:
        s = signals or {}
        checks = [
            ("encryption_at_rest", "etcd 静态加密", s.get("encryption_at_rest", False)),
            ("external_store", "外部 secret store (Vault / KMS)", s.get("external_store", False)),
            ("no_env", "未通过 env 暴露 secret", s.get("no_env", False)),
            ("short_ttl", "短期 Token / Bound SA Token", s.get("short_ttl", True)),
            ("rotation", "自动轮换", s.get("rotation", False)),
            ("audit", "secret 访问审计", s.get("audit", True)),
        ]
        passed = sum(1 for c in checks if c[2])
        return {
            "checks": [{"id": c[0], "passed": c[2]} for c in checks],
            "passed": passed, "total": len(checks),
            "score": int(100 * passed / len(checks)),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 运行时威胁检测
    # ------------------------------------------------------------------ #
    def assess_runtime_detection(self, alerts: Optional[List[Dict[str, Any]]] = None
                                 ) -> Dict[str, Any]:
        alerts = alerts or [
            {"id": "t3", "pod": "api-7f9d", "namespace": "prod",
             "severity": "critical", "time": "2026-09-14 10:23",
             "action": "隔离 Pod 并取证"},
        ]
        return {
            "alerts": alerts,
            "total": len(alerts),
            "catalog": RUNTIME_THREATS,
            "blocking_alert": any(a["severity"] == "critical" for a in alerts),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # Istio 安全
    # ------------------------------------------------------------------ #
    def assess_istio(self, signals: Optional[Dict[str, Any]] = None
                     ) -> Dict[str, Any]:
        s = signals or {}
        checks = [
            ("mtls_strict", "PeerAuthentication 为 STRICT", s.get("mtls_strict", False)),
            ("authz_default_deny", "AuthorizationPolicy 默认 deny", s.get("authz_default_deny", False)),
            ("egress_allowlist", "Egress 白名单", s.get("egress_allowlist", False)),
            ("mTLS_13", "TLS 1.3 only", s.get("mTLS_13", True)),
            ("jwt", "RequestAuthentication JWT", s.get("jwt", False)),
        ]
        passed = sum(1 for c in checks if c[2])
        return {
            "checks": [{"id": c[0], "passed": c[2]} for c in checks],
            "passed": passed, "total": len(checks),
            "score": int(100 * passed / len(checks)),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


_instance: Optional[DeploymentRuntimeSecurity] = None


def get_deployment_runtime_security() -> DeploymentRuntimeSecurity:
    global _instance
    if _instance is None:
        _instance = DeploymentRuntimeSecurity()
    return _instance
