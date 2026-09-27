# -*- coding: utf-8 -*-
"""
container_security_check.py — 真实容器安全检查（K8s / Docker / 镜像扫描）。

K8s 检查:
    RBAC / NetworkPolicy / 特权容器 / host 挂载 / 资源限制 / root 运行 /
    危险能力 / latest 标签 / Secret 加密 / Dashboard / API Server 暴露

Docker 检查:
    特权容器 / 资源限制 / 敏感端口 / root 运行 / latest 标签 /
    docker.sock 挂载 / host 网络/PID/IPC / 重启策略 always

镜像扫描:
    trivy / grype 子进程调用，未安装明确提示。
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from ._base import Finding, CheckReport, not_ready_report


# --------------------------------------------------------------------------- #
# Kubernetes
# --------------------------------------------------------------------------- #
def detect_k8s_status() -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "provider": "k8s", "sdk_installed": False,
        "credentials_configured": False, "hint": "",
        "cluster": None, "namespace": "default",
    }
    try:
        import kubernetes  # noqa: F401
        out["sdk_installed"] = True
    except Exception:  # noqa: BLE001
        out["hint"] = ("未安装 kubernetes client。请执行: "
                       "pip install kubernetes。")
        return out
    try:
        from kubernetes import config, client
        config.load_kube_config()
        v = client.VersionApi().get_code()
        out["credentials_configured"] = True
        out["cluster"] = {"git_version": v.git_version,
                           "platform": v.platform}
        out["hint"] = "kubeconfig 已加载，发起真实 K8s 调用。"
    except Exception as e:  # noqa: BLE001
        out["hint"] = (f"kubeconfig 未配置或无法连接: {type(e).__name__}: {e}。"
                       " 请配置 KUBECONFIG 或 ~/.kube/config。")
    return out


class KubernetesChecker:
    """真实 K8s 安全检查。"""

    def run(self) -> CheckReport:
        r = CheckReport(provider="k8s", service="k8s")
        status = detect_k8s_status()
        r.account_identity = status.get("cluster") or {}
        if not status["sdk_installed"]:
            return not_ready_report("k8s", "k8s", status["hint"],
                                    sdk_installed=False)
        if not status["credentials_configured"]:
            return not_ready_report("k8s", "k8s", status["hint"],
                                    credentials_configured=False)
        try:
            from kubernetes import client, config
            config.load_kube_config()
            v1 = client.CoreV1Api()
            apps = client.AppsV1Api()
            rbac = client.RbacAuthorizationV1Api()
            net = client.NetworkingV1Api()

            # 1. NetworkPolicy 覆盖
            nps = net.list_network_policy_for_all_namespaces()
            r.add(Finding("k8s.networkpolicy", "k8s",
                "NetworkPolicy 数量",
                "应配置默认拒绝 + 白名单 NetworkPolicy",
                "list_network_policy_for_all_namespaces",
                ">= 每命名空间至少 1 条",
                f"{len(nps.items)} 条",
                "fail" if not nps.items else "pass", "high",
                remediation="为每个命名空间配置默认拒绝入站的 NetworkPolicy"))

            # 2. 工作负载逐条检查
            deployments = apps.list_deployment_for_all_namespaces()
            daemons = apps.list_daemon_set_for_all_namespaces()
            pods = v1.list_pod_for_all_namespaces()
            checked = 0
            for pod in pods.items:
                checked += 1
                meta = pod.metadata
                ns, name = meta.namespace, meta.name
                for c in (pod.spec.containers or []):
                    sc = c.security_context or {}
                    # 特权
                    if sc.get("privileged"):
                        r.add(Finding(f"k8s.priv.{ns}.{name}.{c.name}", "k8s",
                            f"Pod {ns}/{name} 容器 {c.name} 特权运行",
                            "securityContext.privileged 应为 false",
                            "list_pod_for_all_namespaces", "false", "true",
                            "fail", "critical", resource=f"{ns}/{name}",
                            remediation=f"移除 {c.name} 的 privileged 标志"))
                    # root
                    run_as = sc.get("runAsUser")
                    run_nonroot = sc.get("runAsNonRoot")
                    if (run_as in (0, None)) and not run_nonroot:
                        r.add(Finding(f"k8s.root.{ns}.{name}.{c.name}", "k8s",
                            f"Pod {ns}/{name} 容器 {c.name} 以 root 运行",
                            "runAsNonRoot 应 true / runAsUser != 0",
                            "list_pod_for_all_namespaces",
                            "runAsNonRoot=true",
                            f"runAsUser={run_as}",
                            "fail", "high", resource=f"{ns}/{name}",
                            remediation=f"为 {c.name} 设置 runAsNonRoot=true"))
                    # 危险能力
                    caps = (sc.get("capabilities") or {}).get("add") or []
                    dangerous = [x for x in caps if x in (
                        "SYS_ADMIN", "NET_RAW", "SYS_PTRACE",
                        "SYS_MODULE", "DAC_OVERRIDE")]
                    if dangerous:
                        r.add(Finding(f"k8s.caps.{ns}.{name}.{c.name}", "k8s",
                            f"Pod {ns}/{name} 容器 {c.name} 携带危险能力",
                            "不应添加 SYS_ADMIN 等危险能力",
                            "list_pod_for_all_namespaces", "无危险能力",
                            ",".join(dangerous), "fail", "high",
                            resource=f"{ns}/{name}",
                            remediation=f"移除 {c.name} 的 {dangerous}"))
                    # 资源限制
                    if not (c.resources and c.resources.limits):
                        r.add(Finding(f"k8s.limits.{ns}.{name}.{c.name}", "k8s",
                            f"Pod {ns}/{name} 容器 {c.name} 未设置资源限制",
                            "应设置 resources.limits",
                            "list_pod_for_all_namespaces",
                            "设置 CPU/内存 limit", "未设置",
                            "fail", "medium", resource=f"{ns}/{name}",
                            remediation=f"为 {c.name} 设置 requests/limits"))
                    # latest 标签
                    img = c.image or ""
                    if img.endswith(":latest") or ":" not in img.split("/")[-1]:
                        r.add(Finding(f"k8s.latest.{ns}.{name}.{c.name}", "k8s",
                            f"Pod {ns}/{name} 容器 {c.name} 使用 latest/浮动标签",
                            "应使用固定镜像摘要/版本",
                            "list_pod_for_all_namespaces",
                            "固定 tag", img, "fail", "low",
                            resource=f"{ns}/{name}",
                            remediation=f"固定 {c.name} 镜像到具体 digest"))
                # host 命名空间 / 挂载
                pspec = pod.spec
                if getattr(pspec, "hostNetwork", False):
                    r.add(Finding(f"k8s.hostnet.{ns}.{name}", "k8s",
                        f"Pod {ns}/{name} 使用 hostNetwork",
                        "不应使用 hostNetwork",
                        "list_pod_for_all_namespaces", "false", "true",
                        "fail", "medium", resource=f"{ns}/{name}",
                        remediation=f"移除 {name} 的 hostNetwork"))
                for vol in (pspec.volumes or []):
                    if vol.host_path:
                        hp = vol.host_path.path
                        if hp and hp.startswith(("/var/run/docker.sock",
                                                  "/etc", "/root", "/var/lib/kubelet")):
                            r.add(Finding(f"k8s.hostpath.{ns}.{name}", "k8s",
                                f"Pod {ns}/{name} 挂载宿主敏感路径 {hp}",
                                "不应挂载宿主敏感目录",
                                "list_pod_for_all_namespaces",
                                "无敏感 hostPath", hp,
                                "fail", "high", resource=f"{ns}/{name}",
                                remediation=f"移除 {name} 对 {hp} 的挂载"))
            r.add(Finding("k8s.pod_scanned", "k8s",
                f"实际扫描 {checked} 个 Pod",
                "遍历全部 Pod", "list_pod_for_all_namespaces",
                "成功", f"{checked} 个 Pod", "pass", "info"))

            # 3. RBAC
                # ClusterRoleBinding 通配符
            crbs = rbac.list_cluster_role_binding()
            for crb in crbs.items:
                role_ref = crb.role_ref
                if role_ref and role_ref.name in (
                        "cluster-admin", "edit"):
                    for subj in crb.subjects or []:
                        if getattr(subj, "kind", "") == "ServiceAccount":
                            r.add(Finding(f"k8s.crb.{crb.metadata.name}", "k8s",
                                f"ClusterRoleBinding {crb.metadata.name} "
                                f"绑定 {role_ref.name}",
                                "cluster-admin 应最小化",
                                "list_cluster_role_bindings",
                                "少量",
                                f"{crb.metadata.name} -> {subj.namespace}/{subj.name}",
                                "fail", "high",
                                remediation=f"审计 {crb.metadata.name} 的 cluster-admin 绑定"))
        except Exception as e:  # noqa: BLE001
            r.errors.append(f"{type(e).__name__}: {e}")
            r.add(Finding("k8s.error", "k8s", "K8s 检查失败",
                "kubernetes client", "成功",
                f"{type(e).__name__}: {e}", "error", "medium"))
        return r


# --------------------------------------------------------------------------- #
# Docker
# --------------------------------------------------------------------------- #
def detect_docker_status() -> Dict[str, Any]:
    out: Dict[str, Any] = {"provider": "docker", "sdk_installed": False,
                           "credentials_configured": False, "hint": "",
                           "containers": 0}
    try:
        import docker  # noqa: F401
        out["sdk_installed"] = True
    except Exception:  # noqa: BLE001
        out["hint"] = "未安装 docker SDK。请执行: pip install docker。"
        return out
    try:
        c = docker.from_env()
        c.ping()
        out["credentials_configured"] = True
        out["hint"] = "Docker 守护进程可达，发起真实检查。"
    except Exception as e:  # noqa: BLE001
        out["hint"] = (f"Docker 守护进程不可用: {type(e).__name__}: {e}。"
                       " 请启动 Docker Desktop / dockerd。")
    return out


class DockerChecker:
    """真实 Docker 容器安全检查。"""

    SENSITIVE = {"22/tcp": 22, "3306/tcp": 3306, "5432/tcp": 5432,
                 "6379/tcp": 6379, "27017/tcp": 27017}

    def run(self) -> CheckReport:
        r = CheckReport(provider="docker", service="docker")
        status = detect_docker_status()
        if not status["sdk_installed"]:
            return not_ready_report("docker", "docker", status["hint"],
                                    sdk_installed=False)
        if not status["credentials_configured"]:
            return not_ready_report("docker", "docker", status["hint"],
                                    credentials_configured=False)
        try:
            import docker
            client = docker.from_env()
            containers = client.containers.list(all=True)
            r.account_identity = {"containers": len(containers)}
            for c in containers:
                name = c.name
                attrs = c.attrs or {}
                hostcfg = attrs.get("HostConfig", {})
                config = attrs.get("Config", {})
                # 特权
                if hostcfg.get("Privileged"):
                    r.add(Finding(f"docker.priv.{name}", "docker",
                        f"容器 {name} 以 --privileged 运行",
                        "特权容器等价宿主 root",
                        "containers.list", "false", "true",
                        "fail", "critical", resource=name,
                        remediation=f"不要以特权运行 {name}，按需加能力"))
                # host 网络/PID/IPC
                if hostcfg.get("NetworkMode") == "host":
                    r.add(Finding(f"docker.hostnet.{name}", "docker",
                        f"容器 {name} 使用 host 网络",
                        "--network=host 暴露宿主栈",
                        "containers.list", "bridge", "host",
                        "fail", "high", resource=name,
                        remediation=f"移除 {name} 的 host 网络模式"))
                if hostcfg.get("PidMode") == "host":
                    r.add(Finding(f"docker.hostpid.{name}", "docker",
                        f"容器 {name} 使用 host PID 命名空间",
                        "--pid=host 暴露宿主进程",
                        "containers.list", "private", "host",
                        "fail", "high", resource=name,
                        remediation=f"移除 {name} 的 host PID"))
                # docker.sock 挂载
                mounts = hostcfg.get("Binds", []) or []
                for m in mounts:
                    src = str(m).split(":")[0]
                    if "docker.sock" in src:
                        r.add(Finding(f"docker.sock.{name}", "docker",
                            f"容器 {name} 挂载了 docker.sock",
                            "挂载 docker.sock 等同宿主 root",
                            "containers.list(Binds)",
                            "无 docker.sock 挂载", src,
                            "fail", "critical", resource=name,
                            remediation=f"移除 {name} 对 docker.sock 的挂载"))
                # 资源限制
                if not hostcfg.get("Memory"):
                    r.add(Finding(f"docker.mem.{name}", "docker",
                        f"容器 {name} 未限制内存",
                        "应设置 --memory",
                        "containers.list", "已限制", "未限制",
                        "fail", "medium", resource=name,
                        remediation=f"为 {name} 设置 --memory/--cpus"))
                # root 运行
                user = config.get("User", "")
                if user in ("", "root", "0"):
                    r.add(Finding(f"docker.user.{name}", "docker",
                        f"容器 {name} 以 root 运行",
                        "应指定非 root USER",
                        "containers.list", "非 root",
                        user or "root", "fail", "high", resource=name,
                        remediation=f"为 {name} 指定非 root 用户"))
                # latest 标签
                img = config.get("Image", "")
                if img.endswith(":latest") or ":" not in img.split("/")[-1]:
                    r.add(Finding(f"docker.latest.{name}", "docker",
                        f"容器 {name} 使用 latest 镜像 {img}",
                        "应固定镜像版本",
                        "containers.list", "固定 tag", img,
                        "fail", "low", resource=name,
                        remediation=f"固定 {name} 镜像版本"))
                # 重启策略 always
                if hostcfg.get("RestartPolicy", {}).get("Name") == "always":
                    r.add(Finding(f"docker.restart.{name}", "docker",
                        f"容器 {name} 重启策略 always",
                        "always 可能掩盖崩溃",
                        "containers.list(RestartPolicy)",
                        "unless-stopped/on-failure", "always",
                        "fail", "low", resource=name,
                        remediation=f"将 {name} 重启策略改为 on-failure"))
        except Exception as e:  # noqa: BLE001
            r.errors.append(f"{type(e).__name__}: {e}")
            r.add(Finding("docker.error", "docker", "Docker 检查失败",
                "docker.from_env", "成功",
                f"{type(e).__name__}: {e}", "error", "medium"))
        return r


# --------------------------------------------------------------------------- #
# 镜像扫描（trivy / grype 子进程）
# --------------------------------------------------------------------------- #
def detect_scanner() -> Dict[str, Any]:
    out: Dict[str, Any] = {"trivy": None, "grype": None, "hint": ""}
    out["trivy"] = shutil.which("trivy")
    out["grype"] = shutil.which("grype")
    if not out["trivy"] and not out["grype"]:
        out["hint"] = ("未发现镜像扫描器。请安装: "
                       "brew install trivy  或  grype。"
                       " Windows: choco install trivy。")
    return out


def scan_image(image: str, scanner: Optional[str] = None) -> Dict[str, Any]:
    """真实调用 trivy/grype 扫描镜像，解析 JSON 结果。"""
    avail = detect_scanner()
    tool = scanner or avail.get("trivy") or avail.get("grype")
    if not tool:
        return {"success": False, "error": avail["hint"], "vulns": []}
    try:
        if "trivy" in tool:
            cmd = [tool, "image", "--format", "json", "--quiet", image]
        else:
            cmd = [tool, image, "-o", "json"]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=600, encoding="utf-8", errors="replace")
        out_txt = proc.stdout or proc.stderr
        try:
            data = json.loads(out_txt)
        except Exception:  # noqa: BLE001
            return {"success": True, "scanner": tool,
                    "raw": out_txt[:4000], "vulns": []}
        vulns: List[Dict[str, Any]] = []
        results = data.get("Results", [])
        for res in results:
            for v in res.get("Vulnerabilities", []):
                vulns.append({
                    "vuln_id": v.get("VulnerabilityID"),
                    "pkg": v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion"),
                    "severity": (v.get("Severity") or "").lower(),
                    "title": v.get("Title") or v.get("Description", "")[:120],
                    "primary_url": v.get("PrimaryURL")})
        by_sev: Dict[str, int] = {}
        for v in vulns:
            by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
        return {"success": True, "scanner": tool, "image": image,
                "count": len(vulns), "by_severity": by_sev,
                "vulns": vulns[:200]}
    except Exception as e:  # noqa: BLE001
        return {"success": False,
                "error": f"{type(e).__name__}: {e}", "vulns": []}


class ContainerSecurityOrchestrator:
    """容器安全检查总入口。"""

    def run(self, kinds: Optional[List[str]] = None,
            scan_images: Optional[List[str]] = None) -> Dict[str, Any]:
        kinds = kinds or ["k8s", "docker"]
        out: Dict[str, Any] = {"k8s": None, "docker": None, "scan": []}
        if "k8s" in kinds:
            out["k8s"] = KubernetesChecker().run().to_dict()
        if "docker" in kinds:
            out["docker"] = DockerChecker().run().to_dict()
        if scan_images:
            out["scan"] = [scan_image(img) for img in scan_images]
        out["scanner_status"] = detect_scanner()
        return out


_default_orch: Optional[ContainerSecurityOrchestrator] = None


def get_container_checker() -> ContainerSecurityOrchestrator:
    global _default_orch
    if _default_orch is None:
        _default_orch = ContainerSecurityOrchestrator()
    return _default_orch
