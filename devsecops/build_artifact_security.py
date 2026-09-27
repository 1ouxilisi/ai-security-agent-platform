# -*- coding: utf-8 -*-
"""
build_artifact_security.py — 构建与制品安全。

覆盖：
    - Dockerfile 安全扫描（18 条规则）
    - 镜像漏洞扫描结果评估
    - 基础镜像评估
    - 构建缓存安全
    - 制品库管理（Nexus / Artifactory）
    - 供应链攻击检测

设计定位：静态扫描与策略评估，不执行镜像构建。
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional


# Dockerfile 规则（>=15 条）
DOCKERFILE_RULES: List[Dict[str, Any]] = [
    {"id": "DL3001", "name": "避免使用 latest 标签",
     "severity": "medium", "pattern": r"^FROM\s+[^\s:]+:latest\s*$",
     "advice": "固定到具体版本摘要 @sha256:..."},
    {"id": "DL3002", "name": "最后用户非 root",
     "severity": "high", "pattern": r"^FROM\s+", "negate_needs_user": True,
     "advice": "添加 USER appuser 且非 root"},
    {"id": "DL3003", "name": "避免 apt upgrade/dist-upgrade",
     "severity": "medium", "pattern": r"apt(-get)?\s+(dist-)?upgrade",
     "advice": "在基础镜像侧升级，构建内固定版本"},
    {"id": "DL3004", "name": "apt 后执行 clean",
     "severity": "low", "pattern": r"apt-get\s+install(?!.*rm\s+-rf\s+/var/lib/apt/lists)",
     "advice": "apt-get install && rm -rf /var/lib/apt/lists/*"},
    {"id": "DL3005", "name": "不要安装不必要的包",
     "severity": "low", "pattern": r"apt(-get)?\s+install\s+.*(sudo|curl|wget)",
     "advice": "减少运行时工具攻击面"},
    {"id": "DL3006", "name": "禁止 ADD 远程 URL",
     "severity": "high", "pattern": r"^ADD\s+https?://",
     "advice": "使用 RUN curl + 校验哈希"},
    {"id": "DL3007", "name": "ADD 本地目录需谨慎",
     "severity": "medium", "pattern": r"^ADD\s+\.",
     "advice": "使用 COPY 并配 .dockerignore"},
    {"id": "DL3008", "name": "COPY 整个上下文",
     "severity": "medium", "pattern": r"^COPY\s+\./",
     "advice": "按需拷贝，利用 .dockerignore 减小上下文"},
    {"id": "DL3009", "name": "敏感信息以 ENV 传入",
     "severity": "critical",
     "pattern": r"ENV\s+\w*(PASSWORD|SECRET|TOKEN|KEY)\w*\s*=\s*['\"]?[A-Za-z0-9]{6,}",
     "advice": "不要在 Dockerfile 中写死密钥；运行时注入"},
    {"id": "DL3010", "name": "EXPOSE 过大端口范围",
     "severity": "low", "pattern": r"EXPOSE\s+\d+-\d+",
     "advice": "只暴露必要端口"},
    {"id": "DL3011", "name": "HEALTHCHECK 缺失",
     "severity": "medium", "pattern": None,
     "advice": "添加 HEALTHCHECK 指令"},
    {"id": "DL3012", "name": "多阶段构建未使用",
     "severity": "medium", "pattern": None,
     "advice": "使用多阶段减小最终镜像"},
    {"id": "DL3013", "name": "ROOT 运行服务",
     "severity": "high", "pattern": None,
     "advice": "USER 非 root"},
    {"id": "DL3014", "name": "RUN 中 curl|sh",
     "severity": "critical",
     "pattern": r"RUN\s+.*curl[^|]*\|\s*(sudo\s*)?(ba)?sh",
     "advice": "下载后校验再执行"},
    {"id": "DL3015", "name": "未设置 no-install-recommends",
     "severity": "low",
     "pattern": r"apt-get\s+install(?!.*--no-install-recommends)",
     "advice": "apt-get install --no-install-recommends"},
    {"id": "DL3016", "name": "ARG 传递秘密",
     "severity": "high",
     "pattern": r"ARG\s+\w*(TOKEN|SECRET|PASSWORD|KEY)\w*",
     "advice": "--build-arg 会留在历史中，使用 RUN --mount=type=secret"},
    {"id": "DL3017", "name": "VOLUME 在敏感路径",
     "severity": "medium", "pattern": r"VOLUME\s+/(var/run/docker\.sock|root)",
     "advice": "避免挂载 docker.sock"},
    {"id": "DL3018", "name": "基础镜像未固定摘要",
     "severity": "high",
     "pattern": r"^FROM\s+(?!.*@sha256:)",
     "advice": "使用 image:tag@sha256:digest 锁定"},
]

VULN_SEVERITY = ["critical", "high", "medium", "low"]


class BuildArtifactSecurity:
    """构建与制品安全评估器。"""

    def __init__(self) -> None:
        self.reports: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # Dockerfile 扫描
    # ------------------------------------------------------------------ #
    def scan_dockerfile(self, content: str, filename: str = "Dockerfile"
                        ) -> Dict[str, Any]:
        text = content or ""
        findings: List[Dict[str, Any]] = []
        has_user = bool(re.search(r"^\s*USER\s+", text, re.M))
        has_healthcheck = bool(re.search(r"^\s*HEALTHCHECK\b", text, re.M))
        stage_count = len(re.findall(r"^FROM\s+", text, re.M))
        root_user = not has_user or bool(
            re.search(r"^\s*USER\s+(root|0)\s*$", text, re.M))

        for rule in DOCKERFILE_RULES:
            pat = rule.get("pattern")
            rid = rule["id"]
            hit = False
            if rid == "DL3002":
                hit = not has_user
            elif rid == "DL3011":
                hit = not has_healthcheck
            elif rid == "DL3012":
                hit = stage_count < 2
            elif rid == "DL3013":
                hit = root_user
            elif pat:
                try:
                    hit = re.search(pat, text, re.M) is not None
                except re.error:
                    hit = False
            if hit:
                findings.append({
                    "rule_id": rid, "severity": rule["severity"],
                    "title": rule["name"], "advice": rule["advice"],
                    "file": filename,
                })

        score = self._score(findings)
        result = {
            "scan_id": uuid.uuid4().hex[:12],
            "file": filename,
            "rules_total": len(DOCKERFILE_RULES),
            "findings": findings,
            "findings_count": len(findings),
            "severity_dist": self._sev_dist(findings),
            "score": score,
            "stage_count": stage_count,
            "non_root_user": has_user and not root_user,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.reports.append(result)
        return result

    # ------------------------------------------------------------------ #
    # 镜像漏洞扫描
    # ------------------------------------------------------------------ #
    def scan_image_vulns(self, image: str = "app:latest",
                         vulns: Optional[List[Dict[str, Any]]] = None
                         ) -> Dict[str, Any]:
        vulns = vulns or [
            {"id": "CVE-2024-24980", "pkg": "sudo", "installed": "1.9.5p2",
             "fixed": "1.9.5p2-2ubuntu0.1", "severity": "high"},
            {"id": "CVE-2023-52425", "pkg": "expat", "installed": "2.5.0",
             "fixed": "2.6.0", "severity": "medium"},
            {"id": "CVE-2024-0727", "pkg": "openssl", "installed": "3.0.2",
             "fixed": "3.0.13", "severity": "critical"},
        ]
        dist: Dict[str, int] = {}
        for v in vulns:
            dist[v["severity"]] = dist.get(v["severity"], 0) + 1
        score = max(0, 100 - dist.get("critical", 0) * 30
                    - dist.get("high", 0) * 10 - dist.get("medium", 0) * 3)
        return {
            "image": image, "vulns": vulns, "total": len(vulns),
            "severity_dist": dist, "score": score,
            "blocking": dist.get("critical", 0) > 0,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 基础镜像评估
    # ------------------------------------------------------------------ #
    def assess_base_image(self, base: str = "ubuntu:22.04") -> Dict[str, Any]:
        known = {
            "ubuntu:22.04": {"size_mb": 78, "os": "Ubuntu", "eol": "2027-04",
                              "dist": "LTS"},
            "ubuntu:24.04": {"size_mb": 80, "os": "Ubuntu", "eol": "2029-04",
                              "dist": "LTS"},
            "debian:12-slim": {"size_mb": 71, "os": "Debian", "eol": "2028-06",
                               "dist": "stable"},
            "alpine:3.20": {"size_mb": 7, "os": "Alpine", "eol": "2026-04",
                            "dist": "stable"},
            "gcr.io/distroless/static": {"size_mb": 2, "os": "Distroless",
                                         "eol": "滚动", "dist": "distroless"},
        }
        info = known.get(base, {"size_mb": 100, "os": "未知",
                                "eol": "未知", "dist": "未知"})
        recommendation = "推荐 distroless / alpine-slim 作为运行时基础镜像" \
            if info["dist"] not in ("distroless",) else "已是最小基础镜像"
        return {
            "base_image": base, **info,
            "recommendation": recommendation,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 构建缓存安全
    # ------------------------------------------------------------------ #
    def assess_build_cache(self, signals: Optional[Dict[str, Any]] = None
                           ) -> Dict[str, Any]:
        s = signals or {}
        checks = [
            ("cache_no_secrets", "缓存层不含密钥", s.get("cache_no_secrets", False)),
            ("cache_immutable_tags", "基础镜像 tag 不可变", s.get("cache_immutable_tags", False)),
            ("cache_nsisolated", "多租户构建缓存隔离", s.get("cache_nsisolated", False)),
            ("cache_ttl", "缓存 TTL 不超过 7 天", s.get("cache_ttl", True)),
            ("cache_no_fallback", "缓存失效不回退到未签名镜像",
             s.get("cache_no_fallback", False)),
        ]
        passed = sum(1 for c in checks if c[2])
        return {
            "checks": [{"id": c[0], "name": c[0], "passed": c[2]} for c in checks],
            "passed": passed, "total": len(checks),
            "score": int(100 * passed / len(checks)),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 制品库管理
    # ------------------------------------------------------------------ #
    def assess_registry(self, registry_type: str = "nexus",
                        signals: Optional[Dict[str, Any]] = None
                        ) -> Dict[str, Any]:
        s = signals or {}
        checks = [
            ("rbac", "仓库启用 RBAC", s.get("rbac", True)),
            ("vuln_scan", "上传前自动漏洞扫描", s.get("vuln_scan", False)),
            ("retention", "保留策略清理过期制品", s.get("retention", False)),
            ("immutable_tags", "release tag 不可变", s.get("immutable_tags", False)),
            ("tls", "传输 TLS1.2+", s.get("tls", True)),
            ("audit_log", "完整审计日志", s.get("audit_log", True)),
            ("proxy_cache", "代理上游仓库并校验", s.get("proxy_cache", True)),
            ("mirror_allowlist", "上游仓库白名单", s.get("mirror_allowlist", False)),
        ]
        passed = sum(1 for c in checks if c[2])
        return {
            "registry_type": registry_type,
            "checks": [{"id": c[0], "passed": c[2]} for c in checks],
            "passed": passed, "total": len(checks),
            "score": int(100 * passed / len(checks)),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 供应链攻击检测
    # ------------------------------------------------------------------ #
    def detect_supply_chain(self, signals: Optional[Dict[str, Any]] = None
                             ) -> Dict[str, Any]:
        s = signals or {}
        indicators = [
            ("typosquat", "疑似拼写劫持包", s.get("typosquat", False),
             "npm/pypi 名称近似包（reqeusts -> requests）"),
            ("maintainer_new", "包维护者近期新建", s.get("maintainer_new", False),
             "检查维护者历史与下载量"),
            ("postinstall", "postinstall 脚本外联", s.get("postinstall", False),
             "审查 install 脚本是否外联"),
            ("version_jump", "版本号异常跳跃", s.get("version_jump", False),
             "0.1.0 -> 2.0.0 或突然大量改动"),
            ("new_release", "刚发布 <24h", s.get("new_release", False),
             "观察一段时间再采纳"),
            ("typosquat_dl", "疑似恶意包高下载量", s.get("typosquat_dl", False),
             "立即下架并复盘"),
        ]
        hits = [{"id": i[0], "name": i[1], "triggered": i[2], "advice": i[3]}
                for i in indicators]
        triggered = sum(1 for h in hits if h["triggered"])
        return {
            "indicators": hits,
            "triggered_count": triggered,
            "risk": "高" if triggered >= 2 else "中" if triggered == 1 else "低",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    @staticmethod
    def _sev_dist(items: List[Dict[str, Any]]) -> Dict[str, int]:
        d: Dict[str, int] = {}
        for it in items:
            s = it.get("severity", "info")
            d[s] = d.get(s, 0) + 1
        return d

    @staticmethod
    def _score(findings: List[Dict[str, Any]]) -> int:
        w = {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}
        return max(0, 100 - sum(w.get(f.get("severity", "info"), 0)
                                 for f in findings))


_instance: Optional[BuildArtifactSecurity] = None


def get_build_artifact_security() -> BuildArtifactSecurity:
    global _instance
    if _instance is None:
        _instance = BuildArtifactSecurity()
    return _instance
