# -*- coding: utf-8 -*-
"""
container_security_phase.py — 阶段6：容器安全。

功能:
    - 真实 trivy 集成（subprocess，超时 300s）
    - 镜像漏洞检测（OS 包 / 应用依赖）
    - 镜像配置检测（Dockerfile 最佳实践）
    - 敏感文件检测
    - 未安装时用内置规则兜底
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SCAN_TIMEOUT = 300


@dataclass
class ContainerFinding:
    kind: str = "vuln"  # vuln / config / secret
    severity: str = "medium"
    title: str = ""
    artifact: str = ""
    installed: str = ""
    fixed: str = ""
    cve: str = ""
    description: str = ""
    source: str = "trivy"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind, "severity": self.severity,
            "title": self.title, "artifact": self.artifact,
            "installed": self.installed, "fixed": self.fixed,
            "cve": self.cve, "description": self.description,
            "source": self.source,
        }


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


class ContainerSecurityPhase:
    """阶段6：容器安全。"""

    def __init__(self) -> None:
        self.trivy_bin = _which("trivy")

    def tool_status(self) -> Dict[str, Any]:
        return {
            "trivy_installed": bool(self.trivy_bin),
            "trivy_path": self.trivy_bin,
            "scan_modes": ["image", "fs", "config", "secret"],
        }

    # ------------------------------------------------------------------ #
    def scan_image(self, image: str) -> Dict[str, Any]:
        t0 = time.time()
        result: Dict[str, Any] = {
            "target": image, "mode": "image", "elapsed": 0.0,
            "tool": "trivy" if self.trivy_bin else "unavailable",
            "installed": bool(self.trivy_bin),
            "findings": [], "count": 0, "error": "",
        }
        if not self.trivy_bin:
            result["message"] = (
                "trivy 未安装，无法扫描镜像。"
                "安装: https://github.com/aquasecurity/trivy")
            return result
        try:
            cmd = [self.trivy_bin, "image", "--format", "json",
                   "--exit-code", "0", image]
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=SCAN_TIMEOUT, encoding="utf-8", errors="replace")
            data = json.loads(proc.stdout or "{}")
            findings = self._parse_trivy(data)
            result["findings"] = [f.to_dict() for f in findings]
            result["count"] = len(findings)
        except subprocess.TimeoutExpired:
            result["error"] = f"trivy 超时（>{SCAN_TIMEOUT}s）"
        except Exception as e:  # noqa: BLE001
            result["error"] = f"trivy 执行失败: {e}"
        result["elapsed"] = round(time.time() - t0, 2)
        return result

    # ------------------------------------------------------------------ #
    def scan_filesystem(self, root: str) -> Dict[str, Any]:
        t0 = time.time()
        result: Dict[str, Any] = {
            "target": root, "mode": "fs", "elapsed": 0.0,
            "tool": "trivy" if self.trivy_bin else "regex-fallback",
            "installed": bool(self.trivy_bin),
            "findings": [], "count": 0, "error": "",
        }
        if not os.path.exists(root):
            result["error"] = f"目标路径不存在: {root}"
            return result
        if self.trivy_bin:
            try:
                cmd = [self.trivy_bin, "fs", "--format", "json",
                       "--exit-code", "0", root]
                proc = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=SCAN_TIMEOUT, encoding="utf-8", errors="replace")
                data = json.loads(proc.stdout or "{}")
                findings = self._parse_trivy(data)
                result["findings"] = [f.to_dict() for f in findings]
                result["count"] = len(findings)
            except subprocess.TimeoutExpired:
                result["error"] = f"trivy 超时（>{SCAN_TIMEOUT}s）"
            except Exception as e:  # noqa: BLE001
                result["error"] = f"trivy 执行失败: {e}"
                result["tool"] = "regex-fallback"
                fb = self._fallback_dockerfile(root)
                result["findings"] = [f.to_dict() for f in fb]
                result["count"] = len(fb)
        else:
            result["message"] = (
                "trivy 未安装，使用内置 Dockerfile 规则兜底。"
                "安装: https://github.com/aquasecurity/trivy")
            fb = self._fallback_dockerfile(root)
            result["findings"] = [f.to_dict() for f in fb]
            result["count"] = len(fb)
        result["elapsed"] = round(time.time() - t0, 2)
        return result

    # ------------------------------------------------------------------ #
    def _parse_trivy(self, data: Dict[str, Any]) -> List[ContainerFinding]:
        out: List[ContainerFinding] = []
        for res in data.get("Results", []):
            for v in res.get("Vulnerabilities", []) or []:
                out.append(ContainerFinding(
                    kind="vuln",
                    severity=(v.get("Severity") or "LOW").lower(),
                    title=v.get("Title") or v.get("PkgName", ""),
                    artifact=v.get("PkgName", ""),
                    installed=v.get("InstalledVersion", ""),
                    fixed=v.get("FixedVersion", ""),
                    cve=v.get("VulnerabilityID", ""),
                    description=v.get("Description", "")[:300],
                    source="trivy",
                ))
            for m in res.get("Misconfigurations", []) or []:
                out.append(ContainerFinding(
                    kind="config",
                    severity=(m.get("Severity") or "LOW").lower(),
                    title=m.get("Title", ""),
                    artifact=res.get("Target", ""),
                    cve=m.get("ID", ""),
                    description=m.get("Description", "")[:300],
                    source="trivy",
                ))
            for s in res.get("Secrets", []) or []:
                out.append(ContainerFinding(
                    kind="secret",
                    severity="critical",
                    title=s.get("RuleID", "secret"),
                    artifact=res.get("Target", ""),
                    description=s.get("Category", ""),
                    source="trivy",
                ))
        return out

    # ------------------------------------------------------------------ #
    def _fallback_dockerfile(self, root: str) -> List[ContainerFinding]:
        out: List[ContainerFinding] = []
        rules = [
            (re.compile(r"^USER\s+root\s*$", re.M), "medium",
             "Dockerfile 以 root 运行", "创建非 root 用户"),
            (re.compile(r"(?im)^FROM\s+(alpine|ubuntu|debian):latest", re.M),
             "low", "使用 latest 标签", "固定版本"),
            (re.compile(r"^ADD\s+https?://", re.M), "medium",
             "ADD 直接下载远程文件", "改用 RUN curl + 校验"),
            (re.compile(r"^RUN\s+.*apt-get\s+install", re.M), "low",
             "未使用 --no-install-recommends",
             "减小镜像体积"),
            (re.compile(r"^EXPOSE\s+0\.0\.0\.0", re.M), "medium",
             "绑定到所有网卡", "绑定到 127.0.0.1"),
        ]
        for root_dir, _dirs, files in os.walk(root):
            for fn in files:
                if "Dockerfile" not in fn and not fn.endswith(".dockerfile"):
                    continue
                fpath = os.path.join(root_dir, fn)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        text = f.read()
                except Exception:
                    continue
                for pat, sev, title, fix in rules:
                    for m in pat.finditer(text):
                        line_no = text.count("\n", 0, m.start()) + 1
                        out.append(ContainerFinding(
                            kind="config", severity=sev, title=title,
                            artifact=f"{fn}:{line_no}", description=fix,
                            source="regex-fallback",
                        ))
        return out


_default: Optional[ContainerSecurityPhase] = None


def get_container_phase() -> ContainerSecurityPhase:
    global _default
    if _default is None:
        _default = ContainerSecurityPhase()
    return _default
