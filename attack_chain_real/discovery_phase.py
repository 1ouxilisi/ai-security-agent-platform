# -*- coding: utf-8 -*-
"""漏洞发现阶段：真实 nuclei / sqlmap / nikto 扫描。"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

DEFAULT_TIMEOUT = 300


def _run(cmd: List[str], timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    exe = shutil.which(cmd[0]) if cmd else None
    if not exe:
        return {"success": False, "error": f"工具 {cmd[0]} 未安装", "cmd": cmd}
    try:
        p = subprocess.run(
            [exe] + cmd[1:],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return {
            "success": p.returncode == 0,
            "cmd": cmd,
            "stdout": p.stdout,
            "stderr": p.stderr,
            "returncode": p.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"超时 ({timeout}s)", "cmd": cmd}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e), "cmd": cmd}


class DiscoveryPhase:
    """真实漏洞发现：nuclei / sqlmap / nikto。"""

    name = "discovery"

    # ---------- Nuclei ----------
    def nuclei(
        self,
        url: str,
        severity: str = "critical,high,medium",
        tags: Optional[str] = None,
        timeout: int = 300,
    ) -> Dict[str, Any]:
        outdir = tempfile.mkdtemp(prefix="nuclei_")
        outfile = os.path.join(outdir, "nuclei.json")
        cmd = [
            "nuclei",
            "-u", url,
            "-severity", severity,
            "-json",
            "-o", outfile,
            "-silent",
        ]
        if tags:
            cmd += ["-tags", tags]
        r = _run(cmd, timeout=timeout)
        findings: List[Dict[str, Any]] = []
        if os.path.exists(outfile):
            try:
                with open(outfile, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            findings.append(json.loads(line))
                        except Exception:  # noqa: BLE001
                            pass
            except Exception:  # noqa: BLE001
                pass
        r["findings"] = findings
        r["count"] = len(findings)
        return r

    # ---------- sqlmap ----------
    def sqlmap_probe(
        self,
        url: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        timeout: int = 300,
    ) -> Dict[str, Any]:
        cmd = ["sqlmap", "-u", url, "--batch", "--smart", "--dbs"]
        if data:
            cmd += ["--data", data]
        if cookie:
            cmd += ["--cookie", cookie]
        r = _run(cmd, timeout=timeout)
        out = r.get("stdout") or ""
        # 解析是否存在注入
        vulnerable = "is vulnerable" in out.lower() or "Parameter" in out and "vulnerable" in out.lower()
        databases: List[str] = []
        in_db_block = False
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("available databases"):
                in_db_block = True
                continue
            if in_db_block:
                if not line:
                    break
                # sqlmap 输出形如: [*] master
                m = re.match(r"\[\*\]\s+(.*)", line)
                if m:
                    databases.append(m.group(1).strip())
        r["vulnerable"] = vulnerable
        r["databases"] = databases
        return r

    # ---------- Nikto ----------
    def nikto(self, host: str, timeout: int = 300) -> Dict[str, Any]:
        cmd = ["nikto", "-h", host, "-nointeractive"]
        r = _run(cmd, timeout=timeout)
        out = r.get("stdout") or ""
        findings: List[str] = []
        for line in out.splitlines():
            if line.startswith("+"):
                findings.append(line.strip())
        r["findings"] = findings
        r["count"] = len(findings)
        return r

    # ---------- 目录枚举（用 ffuf 或 gobuster） ----------
    def dir_bruteforce(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", timeout: int = 180) -> Dict[str, Any]:
        for tool in ("ffuf", "gobuster", "dirb"):
            if shutil.which(tool):
                if tool == "ffuf":
                    cmd = ["ffuf", "-u", url.rstrip("/") + "/FUZZ", "-w", wordlist, "-silent", "-mc", "200,301,302,403"]
                elif tool == "gobuster":
                    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"]
                else:
                    cmd = ["dirb", url, wordlist]
                r = _run(cmd, timeout=timeout)
                paths = [l for l in (r.get("stdout") or "").splitlines() if l.strip()]
                r["paths"] = paths
                r["count"] = len(paths)
                return r
        return {"success": False, "error": "未安装 ffuf/gobuster/dirb", "paths": []}

    # ---------- 一站式 ----------
    def run_full(self, target: str, timeout: int = 300) -> Dict[str, Any]:
        result: Dict[str, Any] = {"target": target}
        if target.startswith("http"):
            result["nuclei"] = self.nuclei(target, timeout=timeout)
            result["nikto"] = self.nikto(target, timeout=min(timeout, 180))
        else:
            result["nuclei"] = {"success": False, "skipped": "target 不是 http URL"}
            result["nikto"] = {"success": False, "skipped": "target 不是 http URL"}
        return result
