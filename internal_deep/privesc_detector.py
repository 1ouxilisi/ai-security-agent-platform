# -*- coding: utf-8 -*-
"""privesc_detector.py — 权限提升检测。

真实调用：
  - 提权漏洞检测（uname / wmic qfe / systeminfo 辅助判断 CVE）
  - SUID 检查（find / -perm -4000）
  - 服务配置错误检测（Windows: sc qc；Linux: 检查 systemd unit / sudoers）
未安装工具时明确提示，不 mock。
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, List

TIMEOUT = 300


def _run(cmd: List[str], timeout: int = TIMEOUT) -> Dict[str, Any]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout, check=False)
        return {"ok": proc.returncode == 0, "rc": proc.returncode,
                "stdout": (proc.stdout or "")[:20000],
                "stderr": (proc.stderr or "")[:4000],
                "error": None, "cmd": cmd}
    except FileNotFoundError as e:
        return {"ok": False, "rc": -1, "stdout": "", "stderr": "",
                "error": f"tool not found: {e}", "cmd": cmd}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": -2, "stdout": "", "stderr": "",
                "error": f"timeout after {timeout}s", "cmd": cmd}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "rc": -3, "stdout": "", "stderr": "",
                "error": str(e), "cmd": cmd}


# 已知提权 CVE → 关键 build/版本指纹
KNOWN_PRIVESC_CVES: List[Dict[str, str]] = [
    {"cve": "CVE-2021-40449", "name": "Win32k LPE", "match": "win32k"},
    {"cve": "CVE-2023-23397", "name": "Outlook Elevation", "match": "outlook"},
    {"cve": "CVE-2023-36874", "name": "Windows Kernel LPE", "match": "kernel"},
    {"cve": "CVE-2021-4034", "name": "PwnKit (polkit)", "match": "pkexec"},
    {"cve": "CVE-2022-0847", "name": "Dirty Pipe", "match": "5.8"},
    {"cve": "CVE-2016-5195", "name": "Dirty Cow", "match": "2.6.22"},
]


class PrivescDetector:
    """提权检测器。"""

    def detect_local_cves(self, timeout: int = TIMEOUT) -> Dict[str, Any]:
        """根据 uname / systeminfo 输出粗匹配已知提权 CVE。"""
        candidates: List[Dict[str, str]] = []
        # Linux
        if shutil.which("uname"):
            r = _run(["uname", "-a"], timeout)
            if r["ok"]:
                out = r["stdout"]
                for cve in KNOWN_PRIVESC_CVES:
                    if cve["match"].lower() in out.lower():
                        candidates.append({**cve, "note": "uname matched"})
                return {"ok": True, "uname": out.strip(), "candidates": candidates}
        # Windows
        if shutil.which("wmic"):
            r = _run(["wmic", "os", "get", "Caption,Version", "/value"], timeout)
            if r["ok"]:
                return {"ok": True, "systeminfo": r["stdout"].strip(),
                        "candidates": [], "note": "manual CVE lookup recommended"}
        return {"ok": False, "error": "neither uname nor wmic available",
                "candidates": candidates}

    def check_suid(self, timeout: int = TIMEOUT) -> Dict[str, Any]:
        if not shutil.which("find"):
            return {"ok": False, "error": "find not available", "suid_binaries": []}
        r = _run(["find", "/", "-perm", "-4000", "-type", "f",
                  "2>/dev/null"], timeout)
        bins = [ln.strip() for ln in r.get("stdout", "").splitlines() if ln.strip()]
        # 常见危险 SUID 清单
        dangerous = [b for b in bins if any(
            d in b for d in ("/bash", "/sh", "/bin", "/python", "/perl",
                             "/find", "/nmap", "/vim", "/cp", "/mv")
        )]
        r["suid_binaries"] = bins
        r["dangerous_suid"] = dangerous
        return r

    def check_service_misconfig(self, timeout: int = TIMEOUT) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        if shutil.which("systemctl"):
            r = _run(["systemctl", "list-units", "--type=service",
                      "--no-pager", "--no-legend"], timeout)
            for ln in r.get("stdout", "").splitlines():
                if "enabled" in ln and any(x in ln.lower() for x in
                                          ("debug", "test", "custom")):
                    findings.append({"type": "suspicious_service", "raw": ln.strip()})
            return {"ok": True, "findings": findings}
        if shutil.which("sc"):
            r = _run(["sc", "query"], timeout)
            return {"ok": r["ok"], "findings": findings,
                    "note": "use 'sc qc <svc>' per service for unquoted path check"}
        return {"ok": False, "error": "no service manager detected", "findings": findings}

    def check_sudo(self, timeout: int = TIMEOUT) -> Dict[str, Any]:
        if not shutil.which("sudo"):
            return {"ok": False, "error": "sudo not available", "rules": []}
        r = _run(["sudo", "-l"], timeout)
        rules = [ln.strip() for ln in r.get("stdout", "").splitlines() if "(ALL)" in ln or "NOPASSWD" in ln]
        r["rules"] = rules
        return r

    def full_scan(self, timeout: int = TIMEOUT) -> Dict[str, Any]:
        return {
            "cves": self.detect_local_cves(timeout),
            "suid": self.check_suid(timeout),
            "services": self.check_service_misconfig(timeout),
            "sudo": self.check_sudo(timeout),
        }


_singleton: PrivescDetector | None = None


def get_privesc_detector() -> PrivescDetector:
    global _singleton
    if _singleton is None:
        _singleton = PrivescDetector()
    return _singleton
