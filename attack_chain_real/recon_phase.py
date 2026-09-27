# -*- coding: utf-8 -*-
"""信息收集阶段：真实子域名枚举 + 端口扫描 + 服务识别 + 指纹。"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

DEFAULT_TIMEOUT = 300


def _run(cmd: List[str], timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """真实子进程执行，绝不 mock。工具缺失时返回明确错误。"""
    exe = shutil.which(cmd[0]) if cmd else None
    if not exe:
        return {"success": False, "error": f"工具 {cmd[0]} 未安装", "cmd": cmd, "stdout": "", "stderr": ""}
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


def _http_get(url: str, timeout: int = 30) -> Dict[str, Any]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            return {"success": True, "status": r.status, "headers": dict(r.headers), "body": body}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}


class ReconPhase:
    """信息收集：真实执行，无 mock。"""

    name = "recon"

    # ---------- 子域名 ----------
    def subfinder(self, domain: str, timeout: int = 180) -> Dict[str, Any]:
        r = _run(["subfinder", "-d", domain, "-silent"], timeout=timeout)
        subs: List[str] = []
        if r.get("success") or r.get("stdout"):
            for line in (r.get("stdout") or "").splitlines():
                line = line.strip()
                if line and "." in line:
                    subs.append(line.lower())
        r["subdomains"] = sorted(set(subs))
        r["count"] = len(r["subdomains"])
        return r

    def crt_sh(self, domain: str, timeout: int = 60) -> Dict[str, Any]:
        url = f"https://crt.sh/?q={urllib.parse.quote('%.' + domain)}&output=json"
        r = _http_get(url, timeout=timeout)
        subs: List[str] = []
        if r.get("success"):
            try:
                data = json.loads(r["body"])
                for item in data:
                    for name in (item.get("name_value") or "").splitlines():
                        name = name.strip().lower()
                        if name and "*" not in name and domain in name:
                            subs.append(name)
            except Exception as e:  # noqa: BLE001
                r["parse_error"] = str(e)
        r["subdomains"] = sorted(set(subs))
        r["count"] = len(r["subdomains"])
        return r

    # ---------- 端口扫描 ----------
    def port_scan(self, target: str, ports: str = "--top-ports 1000", timeout: int = 300) -> Dict[str, Any]:
        cmd = ["nmap", "-Pn", "-sS", "--open"] + ports.split() + [target]
        r = _run(cmd, timeout=timeout)
        open_ports: List[Dict[str, Any]] = []
        for line in (r.get("stdout") or "").splitlines():
            m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line)
            if m:
                open_ports.append({"port": int(m.group(1)), "service": m.group(2), "protocol": "tcp"})
        r["open_ports"] = open_ports
        r["count"] = len(open_ports)
        return r

    def service_detect(self, target: str, ports: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
        cmd = ["nmap", "-Pn", "-sV"]
        if ports:
            cmd += ["-p", ports]
        cmd.append(target)
        r = _run(cmd, timeout=timeout)
        services: List[Dict[str, Any]] = []
        for line in (r.get("stdout") or "").splitlines():
            m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s+(.*)", line)
            if m:
                services.append({
                    "port": int(m.group(1)),
                    "service": m.group(2),
                    "version_info": m.group(3).strip(),
                })
        r["services"] = services
        return r

    # ---------- Web 指纹 ----------
    def http_fingerprint(self, url: str, timeout: int = 30) -> Dict[str, Any]:
        if not url.startswith("http"):
            url = "http://" + url
        r = _http_get(url, timeout=timeout)
        if not r.get("success"):
            return r
        headers = r.get("headers") or {}
        body = r.get("body") or ""
        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        # 简易指纹
        fingerprints: List[str] = []
        if "wp-content" in body or "wp-includes" in body:
            fingerprints.append("WordPress")
        if "Drupal" in body:
            fingerprints.append("Drupal")
        if "Joomla" in body:
            fingerprints.append("Joomla")
        if "Laravel" in headers.get("Set-Cookie", ""):
            fingerprints.append("Laravel")
        if "ASP.NET" in server or "X-AspNet-Version" in headers:
            fingerprints.append("ASP.NET")
        if "nginx" in server.lower():
            fingerprints.append("Nginx")
        if "apache" in server.lower():
            fingerprints.append("Apache")
        r["fingerprints"] = fingerprints
        r["server"] = server
        r["powered_by"] = powered
        r["title"] = self._extract_title(body)
        return r

    @staticmethod
    def _extract_title(body: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else ""

    # ---------- 一站式 ----------
    def run_full(self, target: str, timeout: int = 300) -> Dict[str, Any]:
        is_domain = bool(re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target))
        result: Dict[str, Any] = {"target": target}
        if is_domain:
            result["crt_sh"] = self.crt_sh(target, timeout=60)
            result["subfinder"] = self.subfinder(target, timeout=min(timeout, 180))
        result["port_scan"] = self.port_scan(target, timeout=timeout)
        result["service_detect"] = self.service_detect(target, timeout=timeout)
        result["http_fingerprint"] = self.http_fingerprint(target, timeout=30)
        return result
