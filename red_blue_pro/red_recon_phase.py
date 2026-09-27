# -*- coding: utf-8 -*-
"""
red_recon_phase.py — 红队阶段1：侦察（真实 OSINT 信息收集框架）。

功能:
    - 子域名枚举（subfinder / crt.sh）
    - 邮箱收集（theHarvester 框架）
    - 员工信息收集（LinkedIn / GitHub 启发式框架）
    - 泄露凭证检测（HaveIBeenPwned API 框架）
    - 真实 subprocess 调用，超时 300 秒
    - 未安装工具明确提示，不 mock

纯内存字典结果。
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

RECON_TIMEOUT = 300  # 秒


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


@dataclass
class ReconResult:
    target: str = ""
    module: str = ""
    tool: str = ""
    available: bool = False
    command: str = ""
    elapsed: float = 0.0
    subdomains: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    employees: List[Dict[str, str]] = field(default_factory=list)
    breached: List[Dict[str, Any]] = field(default_factory=list)
    raw: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target, "module": self.module,
            "tool": self.tool, "available": self.available,
            "command": self.command,
            "elapsed": round(self.elapsed, 2),
            "subdomain_count": len(self.subdomains),
            "subdomains": self.subdomains[:500],
            "email_count": len(self.emails),
            "emails": self.emails[:300],
            "employee_count": len(self.employees),
            "employees": self.employees[:100],
            "breach_count": len(self.breached),
            "breached": self.breached[:50],
            "raw_tail": self.raw[-1500:] if self.raw else "",
            "error": self.error,
        }


class RedReconPhase:
    """红队阶段1：侦察。"""

    def __init__(self) -> None:
        self.subfinder_bin = _which("subfinder")
        self.harvester_bin = _which("theHarvester") or _which(
            "theHarvester.py") or _which("theHarvester.py")

    # ------------------------------------------------------------------ #
    def _run_cmd(self, cmd: List[str], target: str, module: str
                 ) -> ReconResult:
        r = ReconResult(target=target, module=module,
                        tool=shutil.os.path.basename(cmd[0]) if cmd else "")
        if not cmd:
            r.available = False
            r.error = "命令为空"
            return r
        r.available = True
        r.command = " ".join(cmd)
        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=RECON_TIMEOUT,
                encoding="utf-8", errors="replace", shell=False)
            r.elapsed = time.time() - t0
            out = proc.stdout or ""
            err = proc.stderr or ""
            r.raw = out + "\n[stderr]\n" + err
        except subprocess.TimeoutExpired:
            r.elapsed = time.time() - t0
            r.error = f"超时（>{RECON_TIMEOUT}s）"
        except FileNotFoundError:
            r.available = False
            r.error = f"工具不存在: {cmd[0]}"
        except Exception as e:  # noqa: BLE001
            r.elapsed = time.time() - t0
            r.error = f"{type(e).__name__}: {e}"
        return r

    # ------------------------------------------------------------------ #
    def subfinder_enum(self, domain: str) -> ReconResult:
        """子域名枚举（subfinder）。未安装则走 crt.sh 在线接口。"""
        r = ReconResult(target=domain, module="subfinder", tool="subfinder")
        if self.subfinder_bin:
            cmd = [self.subfinder_bin, "-d", domain, "-silent"]
            res = self._run_cmd(cmd, domain, "subfinder")
            for line in (res.raw or "").splitlines():
                line = line.strip()
                if line and "." in line and " " not in line:
                    res.subdomains.append(line)
            r = res
            if not r.subdomains:
                r.subdomains = self._crtsh(domain)
        else:
            r.available = True
            r.tool = "crt.sh"
            r.subdomains = self._crtsh(domain)
            if not r.subdomains and not r.error:
                r.error = ("subfinder 未安装（go install "
                           "github.com/projectdiscovery/subfinder/v2/cmd/"
                           "subfinder@latest），已降级使用 crt.sh。")
        r.subdomains = sorted(set(r.subdomains))
        return r

    # ------------------------------------------------------------------ #
    def _crtsh(self, domain: str) -> List[str]:
        """crt.sh 证书透明日志查子域名。"""
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            subs: List[str] = []
            for item in data:
                nv = item.get("name_value", "")
                for line in nv.splitlines():
                    line = line.strip().lower()
                    if line.endswith(domain) and "*" not in line:
                        subs.append(line)
            return sorted(set(subs))
        except urllib.error.URLError as e:
            return []
        except Exception:
            return []

    # ------------------------------------------------------------------ #
    def harvester_emails(self, domain: str,
                         limit: int = 100) -> ReconResult:
        """theHarvester 邮箱与主机收集。"""
        if not self.harvester_bin:
            r = ReconResult(target=domain, module="theHarvester",
                            tool="theHarvester", available=False)
            r.error = ("theHarvester 未安装（pip install theHarvester 或 "
                       "Kali 自带）。已返回空结果，不 mock。")
            return r
        cmd = [self.harvester_bin, "-d", domain, "-b", "all",
               "-l", str(limit)]
        res = self._run_cmd(cmd, domain, "theHarvester")
        import re
        for m in re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+",
                            res.raw or ""):
            if m.endswith(domain):
                res.emails.append(m.lower())
        res.emails = sorted(set(res.emails))
        return res

    # ------------------------------------------------------------------ #
    def employee_enum(self, domain: str,
                      company: str = "") -> ReconResult:
        """员工信息收集（框架：LinkedIn/GitHub 启发式）。"""
        r = ReconResult(target=domain, module="employees",
                        tool="osint-framework", available=True)
        # 框架性输出：基于邮箱前缀推断命名约定，不抓取真实个人数据
        r.employees = [
            {"source": "linkedin_guess", "pattern": "first.last",
             "company": company or domain,
             "note": "命名约定推断（需人工在 LinkedIn 核实）"},
            {"source": "github_org", "pattern": f"https://github.com/{domain.split('.')[0]}",
             "company": company or domain,
             "note": "GitHub 组织成员枚举入口"},
        ]
        r.raw = "员工信息收集框架就绪：未安装 linkedin2username / " \
                "github-sectools 时仅输出命名约定推断。"
        return r

    # ------------------------------------------------------------------ #
    def hibp_check(self, email: str,
                   api_key: str = "") -> ReconResult:
        """HaveIBeenPwned 泄露凭证检测（框架）。"""
        r = ReconResult(target=email, module="hibp", tool="HIBP",
                        available=bool(api_key))
        if not api_key:
            r.error = ("HaveIBeenPwned API 需要 api-key（付费）。"
                       "未提供 key 时返回框架提示，不 mock。")
            return r
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}" \
              f"?truncateResponse=false"
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "ai-hacking-agent",
                "hibp-api-key": api_key})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            for b in data:
                r.breached.append({
                    "name": b.get("Name", ""),
                    "title": b.get("Title", ""),
                    "date": b.get("BreachDate", ""),
                    "classes": b.get("DataClasses", []),
                })
        except urllib.error.HTTPError as e:
            if e.code == 404:
                r.breached = []
            else:
                r.error = f"HIBP HTTP {e.code}"
        except Exception as e:  # noqa: BLE001
            r.error = f"{type(e).__name__}: {e}"
        return r

    # ------------------------------------------------------------------ #
    def osint_dashboard(self, domain: str) -> ReconResult:
        """一键 OSINT：子域名 + 邮箱 + 员工框架。"""
        r = ReconResult(target=domain, module="osint", tool="multi",
                        available=True)
        sf = self.subfinder_enum(domain)
        r.subdomains = sf.subdomains
        hv = self.harvester_emails(domain)
        r.emails = hv.emails
        emp = self.employee_enum(domain)
        r.employees = emp.employees
        r.raw = (sf.raw[-800:] + "\n---\n" + hv.raw[-800:])
        return r

    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        return {
            "subfinder": self.subfinder_bin or "not_found",
            "subfinder_available": bool(self.subfinder_bin),
            "theHarvester": self.harvester_bin or "not_found",
            "theHarvester_available": bool(self.harvester_bin),
            "crt.sh_online": True,
            "hibp_requires_api_key": True,
            "recon_timeout": RECON_TIMEOUT,
        }


_default: Optional[RedReconPhase] = None


def get_red_recon_phase() -> RedReconPhase:
    global _default
    if _default is None:
        _default = RedReconPhase()
    return _default
