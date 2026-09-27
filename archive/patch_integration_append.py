# -*- coding: utf-8 -*-
"""向 tools/integration.py 末尾追加模块二 2.3 的增强代码（不修改现有逻辑）。"""
import io

p = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent\tools\integration.py"

APPEND = '''


# =====================================================================
# 模块二 2.3：工具可用性增强（追加，不修改上方已有逻辑）
# =====================================================================

import os as _os_for_health
import shutil as _shutil_for_health
import subprocess as _subprocess_for_health
from datetime import datetime as _dt_for_health


# 每个主要工具的安装指引文本
TOOL_INSTALL_GUIDES: Dict[str, str] = {
    "nmap": "下载安装包 https://nmap.org/dist/ 或 choco install nmap，安装后确认 nmap --version。",
    "sqlmap": "pip install sqlmap -i https://pypi.tuna.tsinghua.edu.cn/simple，"
              "或 git clone https://gitee.com/mirrors/sqlmap.git。",
    "nuclei": "https://github.com/projectdiscovery/nuclei/releases 下载 Windows 二进制，"
              "放入 %USERPROFILE%\\\\tools\\\\ 并加入 PATH。",
    "nikto": "需要 Perl 环境；或在 WSL 中 sudo apt install nikto。",
    "masscan": "Windows 原生支持差，建议在 WSL 中 sudo apt install masscan。",
    "metasploit": "下载 https://www.metasploit.com/download 完整安装包，"
                  "仅允许 auxiliary/scanner 与 auxiliary/gather 模块。",
    "hashcat": "https://hashcat.net/hashcat/ 下载 Windows 版本。",
    "dirsearch": "git clone https://github.com/maurosoria/dirsearch 后用 python 运行。",
    "hydra": "WSL 中 sudo apt install hydra；Windows 需自行编译。",
}


def tool_is_available(tool_name: str,
                       exe_path: str = "",
                       version_args: Optional[List[str]] = None) -> bool:
    """检查工具是否真正可执行：路径存在 + --version 退出码为 0。"""
    try:
        exe = exe_path or _shutil_for_health.which(tool_name) or tool_name
        if not _os_for_health.path.exists(exe) and not _shutil_for_health.which(exe):
            return False
        args = version_args or ["--version"]
        proc = _subprocess_for_health.run(
            [exe] + list(args),
            capture_output=True, timeout=15,
            stdout=_subprocess_for_health.PIPE,
            stderr=_subprocess_for_health.STDOUT,
            text=True,
        )
        # 有些工具 --version 返回非 0 但仍输出版本号
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode == 0 or any(
            ch.isdigit() for ch in out)
    except Exception:
        return False


def tool_install_guide(tool_name: str) -> str:
    """返回指定工具的安装指引字符串。"""
    return TOOL_INSTALL_GUIDES.get(
        tool_name,
        f"工具 {tool_name} 未内置安装指引，请参考官方文档。")


# 为 ToolIntegration 的主要工具类补充 is_available / install_guide 增强函数
def _enhance_tool_class(cls):
    """给工具类动态挂上 is_available / install_guide 方法（monkey-patch）。"""
    if not hasattr(cls, "is_available"):
        def _is_avail(self, *a, **kw):  # type: ignore
            name = getattr(self, "name", cls.__name__)
            path = getattr(self, "path", "") or getattr(self, "exe", "")
            return tool_is_available(name, path)
        cls.is_available = _is_avail  # type: ignore[attr-defined]
    if not hasattr(cls, "install_guide"):
        def _guide(self, *a, **kw):  # type: ignore
            name = getattr(self, "name", cls.__name__)
            return tool_install_guide(name)
        cls.install_guide = _guide  # type: ignore[attr-defined]
    return cls


# 对项目中已存在的工具类做轻量增强（容错：找不到类就跳过）
for _candidate_name in (
    "NmapScanner", "SQLMapScanner", "NucleiScanner", "MasscanScanner",
    "NiktoScanner", "MetasploitClient", "HashCracker", "DirSearch",
):
    try:
        _cls = globals().get(_candidate_name)
        if _cls is not None:
            _enhance_tool_class(_cls)
    except Exception:
        pass


def _fallback_result(tool_name: str, reason: str) -> Dict[str, Any]:
    """工具不可用时的统一降级返回。"""
    return {
        "status": "fallback",
        "tool": tool_name,
        "message": f"工具不可用，已降级为基础检测：{reason}",
        "result": {"note": "降级为基础 socket/HTTP 探测，结果仅供参考"},
        "install_guide": tool_install_guide(tool_name),
    }


class ToolHealthChecker:
    """工具健康检查器：批量检测所有工具可用性，生成健康报告。"""

    def __init__(self, tools: Optional[List[str]] = None):
        self.tools = tools or [
            "nmap", "sqlmap", "nuclei", "masscan", "nikto",
            "metasploit", "hashcat", "dirsearch", "hydra",
        ]
        self._cache: Dict[str, Dict[str, Any]] = {}

    def check_all(self) -> Dict[str, Dict[str, Any]]:
        """检测所有工具可用性。"""
        self._cache = {}
        for name in self.tools:
            try:
                ok = tool_is_available(name)
                self._cache[name] = {
                    "tool": name,
                    "available": ok,
                    "checked_at": _dt_for_health.now().isoformat(),
                    "install_guide": tool_install_guide(name),
                }
            except Exception as e:
                self._cache[name] = {
                    "tool": name, "available": False,
                    "error": str(e),
                    "install_guide": tool_install_guide(name),
                }
        return self._cache

    def get_unavailable_tools(self) -> List[str]:
        """返回不可用工具名列表。"""
        if not self._cache:
            self.check_all()
        return [k for k, v in self._cache.items()
                if not v.get("available")]

    def get_health_report(self) -> Dict[str, Any]:
        """生成工具健康报告。"""
        if not self._cache:
            self.check_all()
        available = [k for k, v in self._cache.items() if v.get("available")]
        unavailable = self.get_unavailable_tools()
        return {
            "generated_at": _dt_for_health.now().isoformat(),
            "total": len(self._cache),
            "available_count": len(available),
            "unavailable_count": len(unavailable),
            "available": available,
            "unavailable": unavailable,
            "details": self._cache,
            "next_steps": [
                f"运行 install_tool('{u}') 或手动安装：{TOOL_INSTALL_GUIDES.get(u, '')}"
                for u in unavailable[:5]
            ],
        }


# 全局健康检查实例
tool_health_checker = ToolHealthChecker()
'''

with io.open(p, "r", encoding="utf-8") as f:
    s = f.read()

if "class ToolHealthChecker" in s:
    print("ALREADY APPENDED")
else:
    if not s.endswith("\n"):
        s += "\n"
    s += APPEND
    with io.open(p, "w", encoding="utf-8") as f:
        f.write(s)
    print("APPENDED OK, new length:", len(s))
