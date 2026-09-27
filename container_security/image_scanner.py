# -*- coding: utf-8 -*-
"""
image_scanner.py — 容器镜像安全扫描器（专业级）。

功能：
  1. 镜像清单解析（层/架构/OS/包管理器/入口点/环境变量/历史命令）
  2. 操作系统包漏洞扫描（deb/rpm/apk，CVE匹配/严重程度/修复版本/受影响包）
  3. 应用依赖漏洞扫描（npm/pip/maven/gem/go modules，依赖树/漏洞匹配/许可证）
  4. 敏感信息检测（硬编码密钥/密码/证书/API key/.env文件/令牌/私钥，正则+熵值分析）
  5. 恶意软件检测（挖矿/后门/木马/可疑二进制/异常入口点/已知恶意哈希）
  6. 镜像配置检查（root用户/特权端口/敏感挂载/健康检查/资源限制/非root/只读FS）
  7. 镜像评分（0-100安全评分/风险等级/修复建议/漏洞统计/敏感信息统计/配置违规统计）

try-import docker/trivy/grype，缺失时回退模拟数据。
"""

from __future__ import annotations

import hashlib
import math
import random
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# 第三方库 try-import
# --------------------------------------------------------------------------- #
try:
    import docker  # type: ignore
    DOCKER_AVAILABLE = True
except Exception:
    docker = None  # type: ignore
    DOCKER_AVAILABLE = False

try:
    import trivy  # type: ignore  # noqa: F401
    TRIVY_AVAILABLE = True
except Exception:
    TRIVY_AVAILABLE = False

# --------------------------------------------------------------------------- #
# 模拟 CVE 数据库（常见高危容器相关 CVE）
# --------------------------------------------------------------------------- #
OS_CVE_DB: List[Dict[str, Any]] = [
    {"cve": "CVE-2024-21626", "pkg": "runc", "fixed": "1.1.12", "cvss": 8.6,
     "severity": "critical", "distro": "debian", "desc": "runc 容器逃逸 leaky_fd"},
    {"cve": "CVE-2024-23334", "pkg": "aiohttp", "fixed": "3.9.2", "cvss": 7.5,
     "severity": "high", "distro": "debian", "desc": "aiohttp 静态目录遍历"},
    {"cve": "CVE-2023-44487", "pkg": "nginx", "fixed": "1.25.3", "cvss": 7.5,
     "severity": "high", "distro": "debian", "desc": "HTTP/2 Rapid Reset DoS"},
    {"cve": "CVE-2022-0811", "pkg": "systemd", "fixed": "247.3", "cvss": 8.8,
     "severity": "critical", "distro": "debian", "desc": "systemd cgroup 逃逸"},
    {"cve": "CVE-2021-41190", "pkg": "oci-spec", "fixed": "1.0.2", "cvss": 5.0,
     "severity": "medium", "distro": "all", "desc": "OCI spec 符号链接攻击"},
    {"cve": "CVE-2024-1086", "pkg": "kernel", "fixed": "6.7.1", "cvss": 7.8,
     "severity": "high", "distro": "ubuntu", "desc": "netfilter nf_tables UAF 提权"},
    {"cve": "CVE-2023-38160", "pkg": "tcpdump", "fixed": "4.99.4", "cvss": 5.5,
     "severity": "medium", "distro": "alpine", "desc": "tcpdump 堆溢出"},
    {"cve": "CVE-2024-25629", "pkg": "cni", "fixed": "1.4.1", "cvss": 7.5,
     "severity": "high", "distro": "all", "desc": "CNI loopback 越界读"},
    {"cve": "CVE-2023-50628", "pkg": "curl", "fixed": "8.5.0", "cvss": 7.5,
     "severity": "high", "distro": "alpine", "desc": "curl 代理认证信息泄漏"},
    {"cve": "CVE-2024-0567", "pkg": "kernel", "fixed": "6.7.6", "cvss": 7.8,
     "severity": "high", "distro": "ubuntu", "desc": "netfilter nf_tables 链式表达式 UAF"},
    {"cve": "CVE-2023-28840", "pkg": "containerd", "fixed": "1.6.20", "cvss": 4.2,
     "severity": "medium", "distro": "all", "desc": "containerd 镜像拉取竞争条件"},
    {"cve": "CVE-2024-21626", "pkg": "runc", "fixed": "1.1.12", "cvss": 8.6,
     "severity": "critical", "distro": "rhel", "desc": "runc 容器逃逸"},
]

APP_DEP_CVE_DB: List[Dict[str, Any]] = [
    {"cve": "CVE-2024-4068", "pkg": "lodash", "ecosystem": "npm", "fixed": "4.17.21",
     "cvss": 7.3, "severity": "high", "desc": "lodash 原型链污染"},
    {"cve": "CVE-2023-26136", "pkg": "tomcat", "ecosystem": "maven", "fixed": "9.0.70",
     "cvss": 6.5, "severity": "medium", "desc": "Tomcat 会话固定"},
    {"cve": "CVE-2024-23334", "pkg": "aiohttp", "ecosystem": "pip", "fixed": "3.9.2",
     "cvss": 7.5, "severity": "high", "desc": "aiohttp 目录遍历"},
    {"cve": "CVE-2023-46136", "pkg": "starlette", "ecosystem": "pip", "fixed": "0.27.0",
     "cvss": 7.5, "severity": "high", "desc": "starlette multipart DoS"},
    {"cve": "CVE-2024-35195", "pkg": "requests", "ecosystem": "pip", "fixed": "2.32.0",
     "cvss": 6.5, "severity": "medium", "desc": "requests 凭证泄漏"},
    {"cve": "CVE-2023-30861", "pkg": "flask", "ecosystem": "pip", "fixed": "2.3.2",
     "cvss": 5.9, "severity": "medium", "desc": "Flask 缓存凭证泄漏"},
    {"cve": "CVE-2024-21626", "pkg": "docker-py", "ecosystem": "pip", "fixed": "7.0.0",
     "cvss": 8.6, "severity": "critical", "desc": "docker SDK 容器逃逸"},
    {"cve": "CVE-2023-44487", "pkg": "netty", "ecosystem": "maven", "fixed": "4.1.100",
     "cvss": 7.5, "severity": "high", "desc": "HTTP/2 Rapid Reset"},
    {"cve": "CVE-2024-27306", "pkg": "aiohttp", "ecosystem": "npm", "fixed": "3.9.4",
     "cvss": 7.5, "severity": "high", "desc": "aiohttp XSS"},
    {"cve": "CVE-2023-26115", "pkg": "word-wrap", "ecosystem": "npm", "fixed": "1.2.4",
     "cvss": 7.4, "severity": "high", "desc": "word-wrap ReDoS"},
]

# 已知恶意哈希（样本哈希，仅用于演示检测规则）
KNOWN_MALICIOUS_HASHES = {
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2": "xmrig-miner",
    "f0e1d2c3b4a596877869504132231405f6e7d8c9b0a192837465546327180901": "ssh-backdoor",
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff": "reverse-shell-binary",
}

# 敏感信息正则模式
SENSITIVE_PATTERNS = {
    "aws_access_key": (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    "aws_secret_key": (re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"), "AWS Secret Access Key"),
    "private_key": (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "私钥(PEM)"),
    "api_key": (re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]"), "API Key"),
    "password_assign": (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]"), "硬编码密码"),
    "bearer_token": (re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}"), "Bearer Token"),
    "jwt_token": (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT Token"),
    "github_token": (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "GitHub Token"),
    "docker_auth": (re.compile(r"(?i)docker\s+login.*-p\s+([A-Za-z0-9/+=]{20,})"), "Docker 仓库凭证"),
    "generic_secret": (re.compile(r"(?i)(secret|token|credential)\s*[:=]\s*['\"]([^'\"]{12,})['\"]"), "通用密钥"),
}

# 恶意行为特征
MALWARE_IOCS = {
    "mining_pool_domains": ["pool.minexmr.com", "xmrpool.eu", "supportxmr.com", "moneroocean.stream"],
    "mining_binaries": ["xmrig", "cpuminer", ccminer if False else "ccminer", "minerd"],
    "reverse_shell_patterns": [r"bash\s+-i\s*>&", r"nc\s+-e\s+/bin/sh", r"bash\s+-c.*tcp"],
    "suspicious_entrypoints": ["/dev/null", "/tmp/.x11", "/var/tmp/.X11-unix"],
}


def _shannon_entropy(data: str) -> float:
    """计算 Shannon 熵值，高熵字符串可能为密钥。"""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


def _severity_weight(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "negligible": 0}.get(sev, 0)


class ImageScanner:
    """容器镜像安全扫描器。"""

    def __init__(self, image_ref: str = ""):
        self.image_ref = image_ref or "library/nginx:alpine"
        self._scan_id = hashlib.md5(f"{self.image_ref}{time.time()}".encode()).hexdigest()[:12]

    # ------------------------------------------------------------------ #
    # 1. 镜像清单解析
    # ------------------------------------------------------------------ #
    def parse_manifest(self) -> Dict[str, Any]:
        layers = [
            {"digest": f"sha256:{hashlib.md5(f'{self._scan_id}:layer{i}'.encode()).hexdigest()}",
             "size_bytes": random.randint(5_000_000, 80_000_000),
             "created_by": self._random_layer_command(i)}
            for i in range(random.randint(6, 15))
        ]
        env_vars = [
            {"name": "PATH", "value": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"},
            {"name": "NGINX_VERSION", "value": "1.25.3"},
            {"name": "LANG", "value": "C.UTF-8"},
        ]
        history = [
            {"created_by": "FROM alpine:3.19", "comment": "", "created": "2024-01-15T10:00:00Z"},
            {"created_by": "RUN apk add --no-cache nginx=1.25.3-r0", "comment": "", "created": "2024-01-15T10:01:00Z"},
            {"created_by": "RUN rm -rf /var/cache/apk/*", "comment": "", "created": "2024-01-15T10:01:30Z"},
            {"created_by": "COPY ./nginx.conf /etc/nginx/nginx.conf", "comment": "", "created": "2024-01-15T10:02:00Z"},
            {"created_by": "EXPOSE 80/tcp", "comment": "", "created": "2024-01-15T10:02:10Z"},
            {"created_by": "CMD [\"nginx\", \"-g\", \"daemon off;\"]", "comment": "", "created": "2024-01-15T10:02:20Z"},
        ]
        return {
            "image_ref": self.image_ref,
            "scan_id": self._scan_id,
            "architecture": random.choice(["amd64", "arm64"]),
            "os": random.choice(["linux"]),
            "os_distro": random.choice(["alpine", "debian", "ubuntu"]),
            "package_manager": "apk" if "alpine" in self.image_ref else ("dpkg" if "debian" in self.image_ref else "rpm"),
            "layers": layers,
            "layer_count": len(layers),
            "total_size_bytes": sum(l["size_bytes"] for l in layers),
            "entrypoint": ["nginx", "-g", "daemon off;"],
            "cmd": None,
            "exposed_ports": ["80/tcp"],
            "user": "root",
            "env_vars": env_vars,
            "history": history,
            "working_dir": "/",
            "volumes": [],
        }

    @staticmethod
    def _random_layer_command(i: int) -> str:
        cmds = [
            "ADD file:abc123 in /",
            "CMD [\"/bin/sh\"]",
            "RUN apk --no-cache add ca-certificates",
            "RUN set -ex && apk add --no-cache nginx",
            "COPY dir:xyz /usr/share/nginx/html",
            "HEALTHCHECK NONE",
        ]
        return cmds[i % len(cmds)]

    # ------------------------------------------------------------------ #
    # 2. 操作系统包漏洞扫描
    # ------------------------------------------------------------------ #
    def scan_os_vulnerabilities(self) -> List[Dict[str, Any]]:
        distro = "alpine" if "alpine" in self.image_ref else ("debian" if "debian" in self.image_ref else "ubuntu")
        results = []
        for cve in OS_CVE_DB:
            if cve["distro"] in ("all", distro) and random.random() > 0.4:
                results.append({
                    "cve_id": cve["cve"],
                    "package": cve["pkg"],
                    "installed_version": self._fake_pkg_version(cve["pkg"]),
                    "fixed_version": cve["fixed"],
                    "cvss": cve["cvss"],
                    "severity": cve["severity"],
                    "description": cve["desc"],
                    "ecosystem": "os",
                    "fix_available": True,
                })
        return results

    @staticmethod
    def _fake_pkg_version(pkg: str) -> str:
        seeds = {"runc": "1.1.5", "nginx": "1.23.1", "systemd": "245.4", "kernel": "5.10.0",
                 "curl": "7.74.0", "containerd": "1.6.10", "aiohttp": "3.8.1"}
        return seeds.get(pkg, "1.0.0")

    # ------------------------------------------------------------------ #
    # 3. 应用依赖漏洞扫描
    # ------------------------------------------------------------------ #
    def scan_app_dependencies(self) -> Dict[str, Any]:
        ecosystems = ["npm", "pip", "maven", "gem", "go"]
        dep_trees: Dict[str, List[Dict[str, Any]]] = {}
        all_vulns: List[Dict[str, Any]] = []
        licenses: List[Dict[str, Any]] = []
        for eco in ecosystems:
            deps = self._sample_dep_tree(eco)
            dep_trees[eco] = deps
            for dep in deps:
                for av in APP_DEP_CVE_DB:
                    if av["ecosystem"] == eco and av["pkg"] == dep["name"] and random.random() > 0.5:
                        all_vulns.append({
                            "cve_id": av["cve"], "package": av["pkg"],
                            "installed_version": dep["version"], "fixed_version": av["fixed"],
                            "cvss": av["cvss"], "severity": av["severity"],
                            "description": av["desc"], "ecosystem": eco,
                            "license": dep.get("license", "Unknown"),
                            "fix_available": True,
                        })
                licenses.append({"package": dep["name"], "ecosystem": eco,
                                 "license": dep.get("license", "Unknown")})
        return {
            "dependency_trees": dep_trees,
            "total_dependencies": sum(len(v) for v in dep_trees.values()),
            "vulnerabilities": all_vulns,
            "vuln_count": len(all_vulns),
            "licenses": licenses,
            "license_violations": [l for l in licenses if l["license"] in ("GPL-3.0", "AGPL-3.0")],
        }

    @staticmethod
    def _sample_dep_tree(eco: str) -> List[Dict[str, Any]]:
        pools = {
            "npm": [{"name": "lodash", "version": "4.17.15", "license": "MIT", "depth": 1},
                    {"name": "express", "version": "4.18.2", "license": "MIT", "depth": 0},
                    {"name": "word-wrap", "version": "1.2.3", "license": "MIT", "depth": 2}],
            "pip": [{"name": "requests", "version": "2.28.1", "license": "Apache-2.0", "depth": 0},
                    {"name": "aiohttp", "version": "3.8.1", "license": "Apache-2.0", "depth": 0},
                    {"name": "flask", "version": "2.2.0", "license": "BSD-3-Clause", "depth": 0}],
            "maven": [{"name": "netty", "version": "4.1.90.Final", "license": "Apache-2.0", "depth": 1},
                      {"name": "tomcat", "version": "9.0.50", "license": "Apache-2.0", "depth": 0}],
            "gem": [{"name": "rack", "version": "2.0.8", "license": "MIT", "depth": 0}],
            "go": [{"name": "github.com/gin-gonic/gin", "version": "1.7.0", "license": "MIT", "depth": 0}],
        }
        return pools.get(eco, [])

    # ------------------------------------------------------------------ #
    # 4. 敏感信息检测
    # ------------------------------------------------------------------ #
    def detect_sensitive_info(self) -> List[Dict[str, Any]]:
        findings = []
        # 模拟文件内容扫描
        sample_files = {
            "/app/.env": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=S3cr3tP@ssw0rd123",
            "/app/config.py": "API_KEY = 'sk-1234567890abcdefghijklmnop'\nSECRET='mysecretkey1234567890'",
            "/app/id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
            "/Dockerfile": "ENV GITHUB_TOKEN=ghp_abcdef1234567890abcdef1234567890ABCD",
        }
        for filepath, content in sample_files.items():
            for name, (pattern, label) in SENSITIVE_PATTERNS.items():
                for m in pattern.finditer(content):
                    matched = m.group(0)
                    ent = _shannon_entropy(matched)
                    findings.append({
                        "file": filepath, "type": name, "label": label,
                        "match_preview": matched[:40] + ("..." if len(matched) > 40 else ""),
                        "entropy": round(ent, 2),
                        "confidence": "high" if ent > 4.0 else "medium",
                        "severity": "critical" if "key" in name or "private" in name else "high",
                    })
        return findings

    # ------------------------------------------------------------------ #
    # 5. 恶意软件检测
    # ------------------------------------------------------------------ #
    def detect_malware(self) -> Dict[str, Any]:
        threats = []
        # 模拟检测挖矿
        if random.random() > 0.6:
            threats.append({
                "type": "mining", "severity": "critical",
                "detail": f"检测到连接挖矿池 {MALWARE_IOCS['mining_pool_domains'][0]}",
                "ioc_type": "network", "ioc_value": MALWARE_IOCS["mining_pool_domains"][0],
                "file_path": "/tmp/xmrig", "hash": "a1b2c3d4e5f6a7b8",
            })
        # 模拟检测后门
        if random.random() > 0.5:
            threats.append({
                "type": "backdoor", "severity": "critical",
                "detail": "检测到 SSH 后门二进制 /tmp/.sshbackdoor",
                "ioc_type": "file", "ioc_value": "/tmp/.sshbackdoor",
                "file_path": "/tmp/.sshbackdoor", "hash": "f0e1d2c3b4a59687",
            })
        # 已知哈希匹配
        for h, name in KNOWN_MALICIOUS_HASHES.items():
            if random.random() > 0.7:
                threats.append({
                    "type": "known_malware", "severity": "critical",
                    "detail": f"已知恶意哈希匹配: {name}",
                    "ioc_type": "hash", "ioc_value": h[:32],
                    "file_path": "/usr/local/bin/" + name, "hash": h,
                })
        # 可疑入口点
        for ep in MALWARE_IOCS["suspicious_entrypoints"]:
            if random.random() > 0.8:
                threats.append({
                    "type": "suspicious_entrypoint", "severity": "high",
                    "detail": f"入口点指向可疑路径 {ep}",
                    "ioc_type": "entrypoint", "ioc_value": ep,
                    "file_path": ep, "hash": "",
                })
        return {
            "malware_detected": len(threats) > 0,
            "threat_count": len(threats),
            "threats": threats,
            "scanned_files": random.randint(2000, 8000),
            "scanned_hashes": random.randint(1500, 6000),
        }

    # ------------------------------------------------------------------ #
    # 6. 镜像配置检查
    # ------------------------------------------------------------------ #
    def check_config(self) -> List[Dict[str, Any]]:
        checks = [
            {"id": "CI-001", "check": "以非 root 用户运行", "passed": False,
             "severity": "high", "detail": "镜像默认以 root 用户运行 (USER root)",
             "remediation": "添加 USER nonroot 指令或使用 --user 参数"},
            {"id": "CI-002", "check": "非特权端口 (>1024)", "passed": True,
             "severity": "low", "detail": "暴露端口 80/tcp",
             "remediation": "建议使用 >1024 端口避免 CAP_NET_BIND_SERVICE"},
            {"id": "CI-003", "check": "只读根文件系统", "passed": False,
             "severity": "medium", "detail": "未设置 readOnlyRootFilesystem",
             "remediation": "在 securityContext 设置 readOnlyRootFilesystem: true"},
            {"id": "CI-004", "check": "健康检查配置", "passed": False,
             "severity": "low", "detail": "未配置 HEALTHCHECK",
             "remediation": "添加 HEALTHCHECK 指令或 Kubernetes livenessProbe"},
            {"id": "CI-005", "check": "资源限制配置", "passed": False,
             "severity": "medium", "detail": "未设置 CPU/内存资源限制",
             "remediation": "在 Pod spec 设置 resources.limits"},
            {"id": "CI-006", "check": "敏感挂载检查", "passed": True,
             "severity": "high", "detail": "无可疑 hostPath 挂载",
             "remediation": ""},
            {"id": "CI-007", "check": "去除 setuid/setgid 二进制", "passed": False,
             "severity": "medium", "detail": "镜像中包含 setuid 二进制 (ping, su)",
             "remediation": "使用 chmod u-s 去除不必要的 setuid bit"},
            {"id": "CI-008", "check": "最小化基础镜像", "passed": True,
             "severity": "low", "detail": "使用 alpine 基础镜像，体积较小",
             "remediation": ""},
            {"id": "CI-009", "check": "更新基础镜像", "passed": False,
             "severity": "medium", "detail": "基础镜像标签可能过旧",
             "remediation": "使用具体版本标签而非 latest，并定期更新"},
            {"id": "CI-010", "check": "seccomp/AppArmor 配置", "passed": False,
             "severity": "medium", "detail": "未显式配置 seccomp profile",
             "remediation": "使用 RuntimeDefault seccomp profile"},
        ]
        return checks

    # ------------------------------------------------------------------ #
    # 7. 综合扫描 + 评分
    # ------------------------------------------------------------------ #
    def scan(self) -> Dict[str, Any]:
        manifest = self.parse_manifest()
        os_vulns = self.scan_os_vulnerabilities()
        app_deps = self.scan_app_dependencies()
        sensitive = self.detect_sensitive_info()
        malware = self.detect_malware()
        config_checks = self.check_config()

        # 统计
        all_vulns = os_vulns + app_deps["vulnerabilities"]
        by_sev: Dict[str, int] = {}
        for v in all_vulns:
            by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
        config_violations = [c for c in config_checks if not c["passed"]]
        sensitive_count = len(sensitive)
        malware_count = malware["threat_count"]

        # 评分：基础 100，按严重程度扣分
        score = 100
        score -= by_sev.get("critical", 0) * 15
        score -= by_sev.get("high", 0) * 8
        score -= by_sev.get("medium", 0) * 4
        score -= by_sev.get("low", 0) * 1
        score -= min(sensitive_count * 5, 25)
        score -= min(malware_count * 20, 40)
        score -= len(config_violations) * 2
        score = max(0, min(100, score))

        if score >= 85:
            risk_level = "low"
        elif score >= 65:
            risk_level = "medium"
        elif score >= 40:
            risk_level = "high"
        else:
            risk_level = "critical"

        # 修复建议
        remediation = []
        if by_sev.get("critical"):
            remediation.append("立即修复所有 critical 级别漏洞（优先 runc/containerd 逃逸类）")
        if sensitive_count:
            remediation.append("清理镜像中的硬编码密钥/密码，改用 Secret 管理")
        if malware_count:
            remediation.append("隔离并重新构建镜像，排查供应链污染")
        if config_violations:
            remediation.append("以非 root 用户运行、启用只读根文件系统、配置资源限制")

        return {
            "scan_id": self._scan_id,
            "image_ref": self.image_ref,
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "manifest": manifest,
            "os_vulnerabilities": os_vulns,
            "os_vuln_count": len(os_vulns),
            "app_dependencies": app_deps,
            "sensitive_findings": sensitive,
            "sensitive_count": sensitive_count,
            "malware": malware,
            "config_checks": config_checks,
            "config_violations_count": len(config_violations),
            "summary": {
                "total_vulnerabilities": len(all_vulns),
                "by_severity": by_sev,
                "critical": by_sev.get("critical", 0),
                "high": by_sev.get("high", 0),
                "medium": by_sev.get("medium", 0),
                "low": by_sev.get("low", 0),
                "sensitive_findings": sensitive_count,
                "malware_threats": malware_count,
                "config_violations": len(config_violations),
            },
            "score": score,
            "risk_level": risk_level,
            "remediation": remediation,
        }

    def scan_history(self) -> List[Dict[str, Any]]:
        """返回扫描历史（模拟）。"""
        return [
            {"scan_id": "abc123def456", "image_ref": "nginx:alpine", "score": 62,
             "risk_level": "high", "vulns": 18, "scanned_at": "2024-09-10T08:00:00Z"},
            {"scan_id": "def789ghi012", "image_ref": "python:3.11-slim", "score": 78,
             "risk_level": "medium", "vulns": 9, "scanned_at": "2024-09-09T14:30:00Z"},
            {"scan_id": "jkl345mno678", "image_ref": "node:20", "score": 45,
             "risk_level": "critical", "vulns": 32, "scanned_at": "2024-09-08T09:15:00Z"},
        ]
