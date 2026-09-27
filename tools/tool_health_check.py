"""工具健康检查引擎。

对 8 个外部安全工具进行安装状态、版本、可用性与依赖检查，并输出
彩色诊断报告与安装/配置建议。可独立运行：

    python -m tools.tool_health_check

注意：本模块仅用于授权的安全测试环境自检。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

from utils.logger import log

try:
    from tools.integration import DEEP_INSTALL_GUIDES, _load_tools_config, _get_tool_path
except Exception:  # pragma: no cover - 兼容直接以脚本方式运行
    DEEP_INSTALL_GUIDES = {}
    _load_tools_config = lambda: {}  # noqa: E731
    _get_tool_path = lambda name: None  # noqa: E731


# ---------------------------------------------------------------------------
# 终端彩色输出（Windows 10+ VT 模式 / 所有现代终端均支持）
# ---------------------------------------------------------------------------
class _C:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"


def _enable_vt() -> None:
    """在 Windows 上启用 ANSI 转义序列支持。"""
    if os.name != "nt":
        return
    try:
        kernel32 = __import__("ctypes").windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 工具定义：版本探测命令 / 依赖 / 探测方式
# ---------------------------------------------------------------------------
# 每项: (version_cmd, help_cmd, deps, how)
# how: "binary" 表示直接执行可执行文件；"script" 表示通过解释器运行脚本；
#      "rpc" 表示需要连接 msfrpcd。
_TOOL_DEFS: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "version_cmd": ["--version"],
        "help_cmd": [],
        "deps": [],
        "how": "binary",
    },
    "nuclei": {
        "version_cmd": ["-version"],
        "help_cmd": ["-h"],
        "deps": [],
        "how": "binary",
    },
    "sqlmap": {
        "version_cmd": ["--version"],
        "help_cmd": ["-h"],
        "deps": ["python"],
        "how": "script",
        "script_name": "sqlmap.py",
    },
    "nikto": {
        "version_cmd": ["-Version"],
        "help_cmd": ["-h"],
        "deps": ["perl"],
        "how": "script",
        "script_name": "nikto.pl",
    },
    "masscan": {
        "version_cmd": ["--version"],
        "help_cmd": [],
        "deps": [],
        "how": "binary_or_wsl",
    },
    "metasploit": {
        "version_cmd": [],
        "help_cmd": [],
        "deps": [],
        "how": "rpc",
    },
    "hashcat": {
        "version_cmd": ["--version"],
        "help_cmd": ["--help"],
        "deps": [],
        "how": "binary",
    },
    "dirsearch": {
        "version_cmd": ["--version"],
        "help_cmd": ["-h"],
        "deps": ["python"],
        "how": "script",
        "script_name": "dirsearch.py",
    },
}


def _which(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt":
        for ext in (".exe", ".cmd", ".bat"):
            found = shutil.which(name + ext)
            if found:
                return found
    return None


def _run(cmd: List[str], timeout: int = 20) -> Dict[str, Any]:
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        out = (p.stdout or "") + (p.stderr or "")
        return {"rc": p.returncode, "output": out, "exception": None}
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + (e.stderr or "")
        return {"rc": -1, "output": out if isinstance(out, str) else "",
                "exception": f"timeout({timeout}s)"}
    except FileNotFoundError as e:
        return {"rc": -1, "output": "", "exception": f"not found: {e}"}
    except Exception as e:
        return {"rc": -1, "output": "", "exception": str(e)}


class ToolHealthChecker:
    """8 个安全工具的健康检查引擎。"""

    TOOL_ORDER = ["nmap", "nuclei", "sqlmap", "nikto",
                  "masscan", "metasploit", "hashcat", "dirsearch"]

    def __init__(self) -> None:
        self._enable_vt_done = False

    # ------------------------------------------------------------------
    # 单工具检查
    # ------------------------------------------------------------------
    def _resolve_command(self, name: str, defn: Dict[str, Any]) -> Optional[List[str]]:
        """返回可执行命令列表；找不到返回 None。"""
        # 1) 配置路径
        cfg_path = _get_tool_path(name)
        if cfg_path and os.path.exists(cfg_path):
            if defn["how"] == "script":
                wrapper = _load_tools_config().get("tools", {}).get(name, {}).get("wrapper")
                if cfg_path.lower().endswith(".py"):
                    return [wrapper or sys.executable, cfg_path]
                if cfg_path.lower().endswith(".pl"):
                    return [wrapper or "perl", cfg_path]
            return [cfg_path]

        # 2) PATH
        binary = name
        if defn["how"] == "script":
            # sqlmap / nikto / dirsearch 通常以脚本形式存在
            script_name = defn.get("script_name", "")
            if script_name:
                # Windows: 解释器 + 脚本名（在 PATH 或当前目录）
                found_script = shutil.which(script_name)
                if found_script:
                    wrapper = sys.executable if script_name.endswith(".py") else "perl"
                    return [wrapper, found_script]
                return None
            return None
        if defn["how"] == "binary_or_wsl":
            found = _which("masscan")
            if found:
                return [found]
            if os.name == "nt" and _which("wsl"):
                probe = _run(["wsl", "masscan", "--version"], timeout=15)
                if probe["rc"] == 0:
                    return ["wsl", "masscan"]
            return None
        found = _which(binary)
        if found:
            return [found]
        # Windows 下也尝试 -exe 后缀
        found = _which(binary + ".exe")
        return [found] if found else None

    def check_tool(self, tool_name: str) -> Dict[str, Any]:
        """检查单个工具，返回结构化结果。"""
        tool_name = tool_name.lower()
        defn = _TOOL_DEFS.get(tool_name)
        result: Dict[str, Any] = {
            "tool": tool_name,
            "installed": False,
            "path": None,
            "version": "",
            "usable": False,
            "deps": {},
            "install_guide": DEEP_INSTALL_GUIDES.get(tool_name, ""),
            "notes": "",
        }

        if defn is None:
            result["notes"] = "未知工具"
            return result

        # 依赖检查
        for dep in defn.get("deps", []):
            result["deps"][dep] = _which(dep) is not None

        # Metasploit 走 RPC，不检查二进制
        if defn["how"] == "rpc":
            return self._check_metasploit(result)

        cmd = self._resolve_command(tool_name, defn)
        if not cmd:
            result["notes"] = "未找到可执行文件（既无配置路径也不在 PATH）"
            if defn["how"] == "binary_or_wsl":
                result["notes"] += "；Windows 下推荐使用 WSL 运行 masscan"
            return result

        result["installed"] = True
        result["path"] = cmd[-1]

        # 版本
        ver_args = defn.get("version_cmd") or []
        if ver_args:
            vr = _run(cmd + ver_args, timeout=25)
            out = (vr["output"] or "").strip()
            # 取第一行作为版本
            result["version"] = out.splitlines()[0][:120] if out else (vr["exception"] or "")
            result["usable"] = vr["rc"] == 0 or bool(out)

        # 可用性 --help
        help_args = defn.get("help_cmd") or []
        if help_args:
            hr = _run(cmd + help_args, timeout=25)
            if not result["usable"]:
                result["usable"] = hr["rc"] == 0 or bool((hr["output"] or "").strip())

        if not result["deps"].get("python", True):
            result["notes"] = "依赖 python 未在 PATH 中检测到"
        if not result["deps"].get("perl", True):
            result["notes"] = (result["notes"] + "；" if result["notes"] else "") + \
                              "依赖 perl 未安装，nikto 无法运行，请安装 Strawberry Perl"
        return result

    def _check_metasploit(self, result: Dict[str, Any]) -> Dict[str, Any]:
        cfg = _load_tools_config().get("tools", {}).get("metasploit", {})
        rpc = cfg.get("rpc", {}) if isinstance(cfg.get("rpc"), dict) else {}
        host = rpc.get("msfrpcd_host", cfg.get("msfrpcd_host", "127.0.0.1"))
        port = int(rpc.get("msfrpcd_port", cfg.get("msfrpcd_port", 55553)))
        result["path"] = f"rpc://{host}:{port}"
        try:
            from tools.integration import MetasploitClient  # 延迟导入
            client = MetasploitClient(
                host=host, port=port,
                user=rpc.get("msfrpcd_user", cfg.get("msfrpcd_user", "msf")),
                password=rpc.get("msfrpcd_password", cfg.get("msfrpcd_password", "msf")),
                timeout=int(rpc.get("timeout", 5)),
            )
            if client.connect():
                result["installed"] = True
                result["usable"] = True
                result["version"] = "msfrpcd connected"
                result["notes"] = "RPC 连接成功（仅允许 auxiliary/scanner 与 auxiliary/gather）"
            else:
                result["notes"] = "msfrpcd 未运行或认证失败: " + client.last_error[:200]
        except Exception as e:
            result["notes"] = f"RPC 探测失败: {e}"
        return result

    # ------------------------------------------------------------------
    # 聚合
    # ------------------------------------------------------------------
    def check_all(self) -> List[Dict[str, Any]]:
        return [self.check_tool(name) for name in self.TOOL_ORDER]

    def get_install_guide(self, tool_name: str) -> str:
        return DEEP_INSTALL_GUIDES.get(tool_name.lower(), "未收录该工具的安装指引")

    def get_recommendations(self) -> List[str]:
        recs: List[str] = []
        results = {r["tool"]: r for r in self.check_all()}

        missing = [n for n, r in results.items() if not r["installed"]]
        if missing:
            recs.append(f"以下工具未安装: {', '.join(missing)}")
            recs.append("在项目根目录运行 install_all_tools.bat 一键安装（国内镜像源优先）")
        else:
            recs.append("全部 8 个工具均已检测到，环境完整。")

        if not results.get("sqlmap", {}).get("deps", {}).get("python", True):
            recs.append("sqlmap/dirsearch 依赖 python，请将 Python 加入 PATH")
        if not results.get("nikto", {}).get("deps", {}).get("perl", True):
            recs.append("nikto 依赖 Perl，请安装 Strawberry Perl: https://strawberryperl.com/")
        if results.get("masscan", {}).get("installed") and "wsl" in str(results.get("masscan", {}).get("path", "")):
            recs.append("masscan 运行在 WSL 中，注意发包速率(rate)与虚拟网卡配置")
        if not results.get("metasploit", {}).get("usable"):
            recs.append("metasploit RPC 未连接；如需启用，请先启动 msfrpcd: "
                        "msfrpcd -P <强密码> -S -a 127.0.0.1 -p 55553")
        if not _which("git"):
            recs.append("未检测到 git，部分工具（sqlmap/nikto/dirsearch）需 git clone 安装")
        return recs

    # ------------------------------------------------------------------
    # 报告输出
    # ------------------------------------------------------------------
    def _enable_vt_once(self) -> None:
        if not self._enable_vt_done:
            _enable_vt()
            self._enable_vt_done = True

    def print_report(self) -> None:
        self._enable_vt_once()
        results = self.check_all()
        print()
        print(f"{_C.BOLD}{_C.CYAN}===== AI Hacking Agent 工具健康检查报告 ====={_C.RESET}")
        print(f"{_C.CYAN}{'工具':<12}{'状态':<10}{'路径 / 版本'}{_C.RESET}")
        print("-" * 78)
        ok = 0
        for r in results:
            if r["installed"]:
                mark = f"{_C.GREEN}✔ installed{_C.RESET}"
                ok += 1
            else:
                mark = f"{_C.RED}✘ missing{_C.RESET}"
            path = r["path"] or "-"
            ver = (r["version"] or "")[:60]
            detail = f"{path}  {ver}"
            print(f"{r['tool']:<12}{mark}    {detail}")
            if r.get("notes"):
                print(f"{'':<12}  {_C.YELLOW}↳ {r['notes']}{_C.RESET}")
        print("-" * 78)
        print(f"已安装 {_C.GREEN}{ok}{_C.RESET} / {len(results)} 个工具")
        print()
        print(f"{_C.BOLD}{_C.CYAN}配置建议:{_C.RESET}")
        for rec in self.get_recommendations():
            print(f"  {_C.YELLOW}•{_C.RESET} {rec}")
        print()
        missing = [r for r in results if not r["installed"]]
        if missing:
            print(f"{_C.BOLD}{_C.CYAN}缺失工具安装指引:{_C.RESET}")
            for r in missing:
                print(f"  {_C.YELLOW}[{r['tool']}]{_C.RESET}")
                for line in (r["install_guide"] or "").splitlines():
                    print(f"      {line}")
        print()


def main() -> None:
    checker = ToolHealthChecker()
    checker.print_report()


if __name__ == "__main__":
    main()
