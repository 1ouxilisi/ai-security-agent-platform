#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能工具安装器（模块二：2.1）。

职责：
    - detect_tool：检测工具是否真正可用（PATH / 配置路径 / --version）
    - get_install_options：返回多种安装方案
    - install_tool：自动选择最佳方案执行安装（国内镜像优先）
    - check_all_tools / generate_install_report：批量检测与报告

安全说明：本模块只在用户明确调用 install_tool 时执行安装命令；
默认不自动联网安装任何工具。
"""

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from loguru import logger
except Exception:  # pragma: no cover
    import logging

    logger = logging.getLogger("tool_installer")

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CONFIG_PATH = os.path.join(_PROJECT_ROOT, "config", "tools_config.json")
_REPORT_PATH = os.path.join(_PROJECT_ROOT, "data", "tool_install_report.json")

# 国内镜像常量
TSINGHUA_PYPI = "https://pypi.tuna.tsinghua.edu.cn/simple"
GITEE_MIRROR = "https://gitee.com"
GHPROXY = "https://ghproxy.com"

# 内置工具清单（>=15 个）
BUILTIN_TOOLS = [
    "nmap", "sqlmap", "nuclei", "nikto", "masscan",
    "CrackMapExec", "Impacket", "BloodHound", "hydra", "john",
    "dirb", "gobuster", "wfuzz", "amass", "subfinder",
    "metasploit",
]

# 每个工具的安装方案定义
_INSTALL_PLANS: Dict[str, List[Dict[str, Any]]] = {
    "nmap": [
        {"method": "download",
         "commands": [],
         "description": "下载 Windows 预编译安装包",
         "url": "https://nmap.org/dist/",
         "estimated_time": "3-5 分钟"},
        {"method": "chocolatey",
         "commands": ["choco install nmap -y"],
         "description": "通过 Chocolatey 安装",
         "estimated_time": "2-3 分钟"},
        {"method": "manual",
         "commands": [],
         "description": "手动下载并配置 PATH",
         "url": "https://nmap.org/download.html",
         "estimated_time": "5 分钟"},
    ],
    "sqlmap": [
        {"method": "pip",
         "commands": [f"pip install sqlmap -i {TSINGHUA_PYPI}"],
         "description": "pip 安装（清华镜像）",
         "estimated_time": "<1 分钟"},
        {"method": "download",
         "commands": ["git clone https://gitee.com/mirrors/sqlmap.git "
                      "%USERPROFILE%\\tools\\sqlmap"],
         "description": "从 Gitee 克隆 sqlmap 源码",
         "estimated_time": "1-2 分钟"},
        {"method": "wsl",
         "commands": ["sudo apt install -y sqlmap"],
         "description": "在 WSL 中 apt 安装",
         "estimated_time": "1 分钟"},
    ],
    "nuclei": [
        {"method": "download",
         "commands": [
             f"curl -L -o %USERPROFILE%\\tools\\nuclei.exe "
             f"{GHPROXY}/https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_amd64_windows.zip",
             "powershell -Command Expand-Archive %USERPROFILE%\\tools\\nuclei.zip -DestinationPath %USERPROFILE%\\tools"],
         "description": "通过 ghproxy 代理下载预编译二进制",
         "estimated_time": "1-2 分钟"},
        {"method": "manual",
         "commands": [],
         "description": "手动从 GitHub Releases 下载",
         "url": "https://github.com/projectdiscovery/nuclei/releases",
         "estimated_time": "3 分钟"},
    ],
    "nikto": [
        {"method": "download",
         "commands": ["git clone https://gitee.com/mirrors/Nikto.git "
                      "%USERPROFILE%\\tools\\nikto"],
         "description": "从 Gitee 克隆 Nikto（需要 Perl）",
         "estimated_time": "2 分钟"},
        {"method": "wsl",
         "commands": ["sudo apt install -y nikto"],
         "description": "在 WSL 中 apt 安装",
         "estimated_time": "1 分钟"},
    ],
    "masscan": [
        {"method": "wsl",
         "commands": ["sudo apt install -y masscan"],
         "description": "在 WSL 中编译安装 masscan",
         "estimated_time": "3-5 分钟"},
        {"method": "manual",
         "commands": [],
         "description": "Windows 原生支持差，建议 WSL",
         "estimated_time": "5 分钟"},
    ],
    "CrackMapExec": [
        {"method": "wsl",
         "commands": ["pipx install crackmapexec"],
         "description": "在 WSL 中用 pipx 安装",
         "estimated_time": "2 分钟"},
        {"method": "pip",
         "commands": [f"pip install crackmapexec -i {TSINGHUA_PYPI}"],
         "description": "pip 安装（可能不完整）",
         "estimated_time": "1 分钟"},
    ],
    "Impacket": [
        {"method": "pip",
         "commands": [f"pip install impacket -i {TSINGHUA_PYPI}"],
         "description": "pip 安装 Impacket",
         "estimated_time": "<1 分钟"},
    ],
    "BloodHound": [
        {"method": "pip",
         "commands": [f"pip install bloodhound -i {TSINGHUA_PYPI}"],
         "description": "pip 安装 BloodHound.py",
         "estimated_time": "1 分钟"},
        {"method": "wsl",
         "commands": ["pipx install bloodhound"],
         "description": "在 WSL 中 pipx 安装",
         "estimated_time": "1 分钟"},
    ],
    "hydra": [
        {"method": "wsl",
         "commands": ["sudo apt install -y hydra"],
         "description": "在 WSL 中 apt 安装",
         "estimated_time": "1 分钟"},
        {"method": "manual",
         "commands": [],
         "description": "Windows 需编译或预编译版本",
         "estimated_time": "5 分钟"},
    ],
    "john": [
        {"method": "wsl",
         "commands": ["sudo apt install -y john"],
         "description": "在 WSL 中 apt 安装",
         "estimated_time": "1 分钟"},
        {"method": "download",
         "commands": [],
         "description": "下载 John the Ripper 官方构建",
         "url": "https://www.openwall.com/john/",
         "estimated_time": "3 分钟"},
    ],
    "dirb": [
        {"method": "wsl",
         "commands": ["sudo apt install -y dirb"],
         "description": "在 WSL 中 apt 安装",
         "estimated_time": "1 分钟"},
    ],
    "gobuster": [
        {"method": "download",
         "commands": [
             f"curl -L -o %USERPROFILE%\\tools\\gobuster.exe "
             f"{GHPROXY}/https://github.com/OJ/gobuster/releases/latest/download/gobuster_windows_amd64.zip"],
         "description": "通过 ghproxy 下载预编译二进制",
         "estimated_time": "1 分钟"},
        {"method": "wsl",
         "commands": ["sudo apt install -y gobuster"],
         "description": "在 WSL 中安装",
         "estimated_time": "1 分钟"},
    ],
    "wfuzz": [
        {"method": "pip",
         "commands": [f"pip install wfuzz -i {TSINGHUA_PYPI}"],
         "description": "pip 安装 wfuzz",
         "estimated_time": "<1 分钟"},
    ],
    "amass": [
        {"method": "download",
         "commands": [
             f"curl -L -o %USERPROFILE%\\tools\\amass.zip "
             f"{GHPROXY}/https://github.com/owasp-amass/amass/releases/latest/download/amass_windows_amd64.zip"],
         "description": "通过 ghproxy 下载 Amass",
         "estimated_time": "2 分钟"},
    ],
    "subfinder": [
        {"method": "download",
         "commands": [
             f"curl -L -o %USERPROFILE%\\tools\\subfinder.exe "
             f"{GHPROXY}/https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder-windows-amd64.zip"],
         "description": "通过 ghproxy 下载 subfinder",
         "estimated_time": "1 分钟"},
    ],
    "metasploit": [
        {"method": "download",
         "commands": [],
         "description": "下载 Metasploit Framework 安装包",
         "url": "https://www.metasploit.com/download",
         "estimated_time": "10-15 分钟"},
        {"method": "manual",
         "commands": [],
         "description": "Windows 安装后需手动配置 PATH 与 msfrpcd",
         "estimated_time": "15 分钟"},
    ],
}


class ToolInstaller:
    """智能工具安装器。"""

    def __init__(self, config_path: Optional[str] = None,
                 report_path: Optional[str] = None):
        self.config_path = config_path or _CONFIG_PATH
        self.report_path = report_path or _REPORT_PATH
        self.config: Dict[str, Any] = {}
        self._load_config()

    def _load_config(self) -> None:
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as f:
                    self.config = json.load(f)
        except Exception as e:
            logger.warning(f"加载工具配置失败: {e}")
            self.config = {}

    # ------------------------------------------------------------------
    # 1. detect_tool
    # ------------------------------------------------------------------
    def detect_tool(self, tool_name: str) -> Dict[str, Any]:
        """检测工具安装状态。返回 {installed, path, version, error}。"""
        result = {"tool": tool_name, "installed": False, "path": "",
                  "version": "", "error": ""}
        try:
            # 1) 配置文件中声明的路径
            tools = self.config.get("tools", {}) if isinstance(self.config, dict) else {}
            tcfg = tools.get(tool_name, {}) if isinstance(tools, dict) else {}
            candidates: List[str] = []
            for key in ("windows_path", "path", "linux_path"):
                p = tcfg.get(key, "")
                if p:
                    # 展开环境变量
                    p = os.path.expandvars(p)
                    candidates.append(p)

            # 2) PATH 中查找
            which = shutil.which(tool_name)
            if which:
                candidates.insert(0, which)

            chosen = ""
            for c in candidates:
                if c and os.path.exists(c):
                    chosen = c
                    break
                # 也尝试按 basename 在 PATH 找
                if c:
                    w = shutil.which(os.path.basename(c))
                    if w:
                        chosen = w
                        break

            if not chosen and which:
                chosen = which

            if not chosen:
                result["error"] = "未在 PATH 或配置中找到可执行文件"
                return result

            result["path"] = chosen

            # 3) 运行 --version 验证
            version_args = tcfg.get("version_check_command", ["--version"]) if tcfg else ["--version"]
            wrapper = tcfg.get("wrapper") if tcfg else None
            cmd = []
            if wrapper == "python":
                cmd = [sys.executable, chosen] + list(version_args)
            else:
                cmd = [chosen] + list(version_args)
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, timeout=15,
                    text=True,
                )
                out = (proc.stdout or "") + (proc.stderr or "")
                # 提取版本号
                m = re.search(r"(\d+\.\d+(?:\.\d+)*)", out)
                if m:
                    result["version"] = m.group(1)
                result["installed"] = (proc.returncode == 0) or bool(m)
                if not result["installed"]:
                    result["error"] = f"--version 返回码 {proc.returncode}"
            except Exception as e:
                # 即使 --version 失败，可执行文件存在也算半安装
                result["installed"] = os.path.exists(chosen)
                result["error"] = f"--version 执行失败: {e}"
            return result
        except Exception as e:
            result["error"] = str(e)
            return result

    # ------------------------------------------------------------------
    # 2. get_install_options
    # ------------------------------------------------------------------
    def get_install_options(self, tool_name: str) -> List[Dict[str, Any]]:
        """返回该工具的多种安装方案。"""
        return list(_INSTALL_PLANS.get(tool_name, []))

    # ------------------------------------------------------------------
    # 3. install_tool
    # ------------------------------------------------------------------
    def install_tool(self, tool_name: str, method: str = "auto") -> Dict[str, Any]:
        """执行安装。method=auto 时自动选择第一个可行方案。"""
        options = self.get_install_options(tool_name)
        if not options:
            return {"tool": tool_name, "success": False,
                    "message": f"未内置 {tool_name} 的安装方案"}

        chosen = None
        if method == "auto":
            # 优先 pip（最快），其次 download，其次 wsl/choco/manual
            priority = {"pip": 0, "download": 1, "wsl": 2,
                        "chocolatey": 3, "manual": 4}
            options = sorted(options,
                             key=lambda o: priority.get(o["method"], 9))
            chosen = options[0]
        else:
            for o in options:
                if o["method"] == method:
                    chosen = o
                    break
            if chosen is None:
                chosen = options[0]

        result = {"tool": tool_name, "method": chosen["method"],
                  "success": False, "commands_ran": [],
                  "outputs": [], "message": ""}
        try:
            for cmd in chosen.get("commands", []):
                result["commands_ran"].append(cmd)
                try:
                    proc = subprocess.run(
                        cmd, shell=True, capture_output=True, text=True,
                        timeout=600,
                    )
                    result["outputs"].append(
                        {"cmd": cmd, "rc": proc.returncode,
                         "out": (proc.stdout or "")[-500:],
                         "err": (proc.stderr or "")[-500:]})
                except Exception as e:
                    result["outputs"].append(
                        {"cmd": cmd, "rc": -1, "err": str(e)})
                    break
            # 安装后验证
            detect = self.detect_tool(tool_name)
            result["detect_after"] = detect
            result["success"] = bool(detect["installed"])
            result["message"] = ("安装成功" if result["success"]
                                  else "安装命令已执行，但 detect_tool 未确认可用")
            # 更新配置中的 installed 字段
            self._update_config_status(tool_name, detect)
            return result
        except Exception as e:
            result["message"] = f"安装异常: {e}"
            return result

    def _update_config_status(self, tool_name: str,
                              detect: Dict[str, Any]) -> None:
        try:
            if not isinstance(self.config, dict):
                return
            tools = self.config.setdefault("tools", {})
            if tool_name not in tools:
                tools[tool_name] = {}
            tools[tool_name]["installed"] = bool(detect.get("installed"))
            tools[tool_name]["version"] = detect.get("version", "")
            tools[tool_name]["last_check"] = datetime.now().isoformat()
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"更新工具配置状态失败: {e}")

    # ------------------------------------------------------------------
    # 4. check_all_tools
    # ------------------------------------------------------------------
    def check_all_tools(self) -> Dict[str, Any]:
        """检测所有已配置 + 内置工具的安装状态。"""
        all_names = set(BUILTIN_TOOLS)
        if isinstance(self.config, dict):
            all_names.update((self.config.get("tools") or {}).keys())
        report: Dict[str, Any] = {}
        for name in sorted(all_names):
            try:
                report[name] = self.detect_tool(name)
            except Exception as e:
                report[name] = {"tool": name, "installed": False,
                                "error": str(e)}
        return report

    # ------------------------------------------------------------------
    # 5. generate_install_report
    # ------------------------------------------------------------------
    def generate_install_report(self) -> Dict[str, Any]:
        """生成安装报告并保存到 data/tool_install_report.json。"""
        check = self.check_all_tools()
        installed = [k for k, v in check.items() if v.get("installed")]
        missing = [k for k, v in check.items() if not v.get("installed")]
        report = {
            "generated_at": datetime.now().isoformat(),
            "total": len(check),
            "installed_count": len(installed),
            "missing_count": len(missing),
            "installed": installed,
            "missing": missing,
            "details": check,
            "next_steps": [
                f"缺失工具: {', '.join(missing) if missing else '无'}. "
                f"调用 install_tool('{m}') 安装" for m in missing[:5]
            ],
        }
        try:
            os.makedirs(os.path.dirname(_REPORT_PATH), exist_ok=True)
            with open(_REPORT_PATH, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"保存安装报告失败: {e}")
        return report
