# -*- coding: utf-8 -*-
"""
tool_detector.py — 真实安全工具检测（30+ 工具）。

用 shutil.which + subprocess 真实探测系统安装情况，不 mock。
未安装工具给出安装命令。支持可用性评分与依赖检查。
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, List, Optional

# 工具清单：命令名 -> (分类, 安装命令提示)
TOOL_CATALOG: Dict[str, Dict[str, str]] = {
    # 扫描类
    "nmap": {"cat": "扫描类", "install": "apt install nmap / choco install nmap"},
    "nuclei": {"cat": "扫描类", "install": "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"},
    "nikto": {"cat": "扫描类", "install": "apt install nikto / git clone https://github.com/sullo/nikto"},
    "gobuster": {"cat": "扫描类", "install": "go install github.com/OJ/gobuster/v3@latest"},
    "dirb": {"cat": "扫描类", "install": "apt install dirb"},
    "ffuf": {"cat": "扫描类", "install": "go install github.com/ffuf/ffuf/v2@latest"},
    # 注入类
    "sqlmap": {"cat": "注入类", "install": "git clone --depth 1 https://github.com/sqlmapproject/sqlmap"},
    "commix": {"cat": "注入类", "install": "pip install commix"},
    "xsser": {"cat": "注入类", "install": "git clone https://github.com/epsylon/xsser"},
    # 漏洞利用
    "msfconsole": {"cat": "漏洞利用", "install": "Download from rapid7.com metasploit-framework"},
    "searchsploit": {"cat": "漏洞利用", "install": "git clone https://github.com/offensive-security/exploitdb"},
    "hydra": {"cat": "漏洞利用", "install": "apt install hydra / choco install hydra"},
    "medusa": {"cat": "漏洞利用", "install": "apt install medusa"},
    # 内网
    "smbclient": {"cat": "内网", "install": "apt install smbclient"},
    "rpcclient": {"cat": "内网", "install": "apt install smbclient (包含 rpcclient)"},
    "ldapsearch": {"cat": "内网", "install": "apt install ldap-utils"},
    "impacket-secretsdump": {"cat": "内网", "install": "pip install impacket"},
    "impacket-psexec": {"cat": "内网", "install": "pip install impacket"},
    "evil-winrm": {"cat": "内网", "install": "gem install evil-winrm"},
    # Web
    "curl": {"cat": "Web", "install": "apt install curl / choco install curl"},
    "wget": {"cat": "Web", "install": "apt install wget / choco install wget"},
    "whatweb": {"cat": "Web", "install": "apt install whatweb"},
    # 取证
    "tshark": {"cat": "取证", "install": "choco install wireshark (含 tshark) / apt install tshark"},
    "wireshark": {"cat": "取证", "install": "choco install wireshark"},
    "binwalk": {"cat": "取证", "install": "pip install binwalk"},
    "foremost": {"cat": "取证", "install": "apt install foremost"},
    # 供应链
    "syft": {"cat": "供应链", "install": "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh"},
    "grype": {"cat": "供应链", "install": "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh"},
    "trivy": {"cat": "供应链", "install": "choco install trivy / apt install trivy"},
    # DevSecOps
    "semgrep": {"cat": "DevSecOps", "install": "pip install semgrep"},
    "gitleaks": {"cat": "DevSecOps", "install": "choco install gitleaks"},
    "checkov": {"cat": "DevSecOps", "install": "pip install checkov"},
    "terrascan": {"cat": "DevSecOps", "install": "choco install terrascan"},
    # 基础
    "docker": {"cat": "基础", "install": "Install Docker Desktop / apt install docker.io"},
    "git": {"cat": "基础", "install": "choco install git / apt install git"},
    "python3": {"cat": "基础", "install": "python.org / apt install python3"},
    "node": {"cat": "基础", "install": "choco install nodejs / apt install nodejs"},
}

# 依赖关系：工具 -> 依赖工具
DEPS: Dict[str, List[str]] = {
    "nuclei": ["git"],
    "ffuf": [],
    "impacket-secretsdump": ["python3"],
    "gitleaks": ["git"],
    "trivy": ["docker"],
}


def _detect_one(cmd: str) -> Dict[str, Any]:
    path = shutil.which(cmd)
    info: Dict[str, Any] = {
        "tool": cmd, "installed": bool(path),
        "path": path or "", "version": "", "install_hint": "",
    }
    if not path:
        info["install_hint"] = TOOL_CATALOG.get(cmd, {}).get("install", "")
        return info
    # 尝试取版本（短超时）
    version_args = [
        [cmd, "--version"], [cmd, "-V"], [cmd, "version"],
    ]
    for args in version_args:
        try:
            out = subprocess.run(
                args, capture_output=True, text=True, timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            ver = (out.stdout or out.stderr).strip().splitlines()
            if ver:
                info["version"] = ver[0][:120]
                break
        except Exception:
            continue
    return info


class ToolDetector:
    """真实工具检测器。"""

    def detect_all(self) -> Dict[str, Any]:
        results: List[Dict[str, Any]] = []
        for cmd, meta in TOOL_CATALOG.items():
            r = _detect_one(cmd)
            r["category"] = meta["cat"]
            results.append(r)
        installed = [r for r in results if r["installed"]]
        missing = [r for r in results if not r["installed"]]
        score = round(len(installed) / len(results) * 100, 1)

        # 依赖检查
        dep_status = []
        for tool, deps in DEPS.items():
            have = {r["tool"] for r in installed}
            missing_deps = [d for d in deps if d not in have]
            dep_status.append({"tool": tool, "deps": deps,
                              "missing_deps": missing_deps,
                              "ok": not missing_deps})

        return {
            "total": len(results), "installed_count": len(installed),
            "missing_count": len(missing), "score": score,
            "by_category": self._by_cat(results),
            "installed": installed, "missing": missing,
            "dep_status": dep_status,
        }

    @staticmethod
    def _by_cat(results: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
        out: Dict[str, Dict[str, int]] = {}
        for r in results:
            c = r["category"]
            out.setdefault(c, {"installed": 0, "total": 0})
            out[c]["total"] += 1
            if r["installed"]:
                out[c]["installed"] += 1
        return out

    def detect_one(self, tool: str) -> Dict[str, Any]:
        if tool not in TOOL_CATALOG:
            return {"tool": tool, "installed": False,
                    "install_hint": "未知工具，未在目录中", "category": "其他"}
        r = _detect_one(tool)
        r["category"] = TOOL_CATALOG[tool]["cat"]
        return r


_detector: Optional[ToolDetector] = None


def get_tool_detector() -> ToolDetector:
    global _detector
    if _detector is None:
        _detector = ToolDetector()
    return _detector
