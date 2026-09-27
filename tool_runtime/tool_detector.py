# -*- coding: utf-8 -*-
"""
tool_detector.py — 外部安全工具可用性真实检测器。

通过 subprocess 调用 where(Windows)/which(POSIX) 真实检测可执行文件是否存在，
并尝试通过 --version / -version / -v 等参数抓取版本号。结果在内存中缓存，可手动刷新。

设计定位：仅用于授权安全测试环境的工具链自检与降级决策。
"""

from __future__ import annotations

import logging
import os
import platform
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

IS_WINDOWS = platform.system().lower().startswith("win")


# --------------------------------------------------------------------------- #
# 工具注册表（30+ 工具，按分类组织）
# exe_candidates: 优先尝试的可执行文件名列表（Windows 会自动加 .exe）
# version_args:   依次尝试的版本参数
# --------------------------------------------------------------------------- #
TOOL_REGISTRY: List[Dict[str, Any]] = [
    # ---- 网络扫描 ----
    {"name": "nmap", "category": "网络扫描", "exe_candidates": ["nmap"],
     "version_args": ["--version", "-V"], "website": "https://nmap.org/",
     "docs": "https://nmap.org/docs.html",
     "description": "端口扫描与服务/操作系统指纹识别"},
    {"name": "masscan", "category": "网络扫描", "exe_candidates": ["masscan"],
     "version_args": ["--version"], "website": "https://github.com/robertdavidgraham/masscan",
     "docs": "https://github.com/robertdavidgraham/masscan",
     "description": "高速异步端口扫描器"},
    {"name": "zmap", "category": "网络扫描", "exe_candidates": ["zmap"],
     "version_args": ["--version"], "website": "https://zmap.io/",
     "docs": "https://github.com/zmap/zmap", "description": "互联网级大范围扫描"},

    # ---- 漏洞利用 ----
    {"name": "msfconsole", "category": "漏洞利用", "exe_candidates": ["msfconsole", "msfconsole.bat"],
     "version_args": ["--version"], "website": "https://www.metasploit.com/",
     "docs": "https://docs.metasploit.com/", "description": "Metasploit 渗透测试框架"},
    {"name": "sqlmap", "category": "漏洞利用", "exe_candidates": ["sqlmap", "sqlmap.py"],
     "version_args": ["--version"], "website": "https://sqlmap.org/",
     "docs": "https://github.com/sqlmapproject/sqlmap/wiki",
     "description": "SQL 注入自动化检测与利用"},
    {"name": "nikto", "category": "漏洞利用", "exe_candidates": ["nikto", "nikto.pl"],
     "version_args": ["-Version"], "website": "https://cirt.net/Nikto2",
     "docs": "https://cirt.net/Nikto2", "description": "Web 服务器扫描器"},
    {"name": "wpscan", "category": "漏洞利用", "exe_candidates": ["wpscan"],
     "version_args": ["--version"], "website": "https://wpscan.com/",
     "docs": "https://github.com/wpscanteam/wpscan",
     "description": "WordPress 安全扫描器"},
    {"name": "gobuster", "category": "漏洞利用", "exe_candidates": ["gobuster"],
     "version_args": ["--version"], "website": "https://github.com/OJ/gobuster",
     "docs": "https://github.com/OJ/gobuster", "description": "目录/DNS/虚拟主机爆破"},
    {"name": "dirb", "category": "漏洞利用", "exe_candidates": ["dirb"],
     "version_args": ["--version"], "website": "http://dirb.sourceforge.net/",
     "docs": "http://dirb.sourceforge.net/", "description": "Web 内容扫描"},
    {"name": "dirsearch", "category": "漏洞利用", "exe_candidates": ["dirsearch", "dirsearch.py"],
     "version_args": ["--version"], "website": "https://github.com/maurosoria/dirsearch",
     "docs": "https://github.com/maurosoria/dirsearch", "description": "Web 路径扫描"},

    # ---- 密码破解 ----
    {"name": "hydra", "category": "密码破解", "exe_candidates": ["hydra"],
     "version_args": ["-h", "--version"], "website": "https://github.com/vanhauser-thc/thc-hydra",
     "docs": "https://github.com/vanhauser-thc/thc-hydra", "description": "在线服务密码暴力破解"},
    {"name": "john", "category": "密码破解", "exe_candidates": ["john"],
     "version_args": ["--list=build-info"], "website": "https://www.openwall.com/john/",
     "docs": "https://www.openwall.com/john/doc/", "description": "John the Ripper 离线密码破解"},
    {"name": "hashcat", "category": "密码破解", "exe_candidates": ["hashcat"],
     "version_args": ["--version"], "website": "https://hashcat.net/hashcat/",
     "docs": "https://hashcat.net/wiki/", "description": "GPU 加速密码破解"},
    {"name": "medusa", "category": "密码破解", "exe_candidates": ["medusa"],
     "version_args": ["--version"], "website": "https://github.com/jmk-foofus/medusa",
     "docs": "https://github.com/jmk-foofus/medusa", "description": "并行登录暴力破解"},

    # ---- 无线安全 ----
    {"name": "aircrack-ng", "category": "无线安全", "exe_candidates": ["aircrack-ng"],
     "version_args": ["--help"], "website": "https://www.aircrack-ng.org/",
     "docs": "https://www.aircrack-ng.org/documentation.html",
     "description": "WEP/WPA 密钥破解套件"},
    {"name": "airodump-ng", "category": "无线安全", "exe_candidates": ["airodump-ng"],
     "version_args": ["--help"], "website": "https://www.aircrack-ng.org/",
     "docs": "https://www.aircrack-ng.org/", "description": "无线数据包捕获"},
    {"name": "aireplay-ng", "category": "无线安全", "exe_candidates": ["aireplay-ng"],
     "version_args": ["--help"], "website": "https://www.aircrack-ng.org/",
     "docs": "https://www.aircrack-ng.org/", "description": "无线数据包注入"},
    {"name": "kismet", "category": "无线安全", "exe_candidates": ["kismet"],
     "version_args": ["--version"], "website": "https://www.kismetwireless.net/",
     "docs": "https://www.kismetwireless.net/documentation/",
     "description": "无线网络侦测与嗅探"},

    # ---- 移动安全 ----
    {"name": "jadx", "category": "移动安全", "exe_candidates": ["jadx", "jadx.bat"],
     "version_args": ["--version"], "website": "https://github.com/skylot/jadx",
     "docs": "https://github.com/skylot/jadx/wiki",
     "description": "Android DEX/GUI 反编译"},
    {"name": "apktool", "category": "移动安全", "exe_candidates": ["apktool", "apktool.bat"],
     "version_args": ["--version"], "website": "https://apktool.org/",
     "docs": "https://apktool.org/docs/", "description": "APK 反编译与重打包"},
    {"name": "frida", "category": "移动安全", "exe_candidates": ["frida"],
     "version_args": ["--version"], "website": "https://frida.re/",
     "docs": "https://frida.re/docs/", "description": "动态插桩工具"},
    {"name": "objection", "category": "移动安全", "exe_candidates": ["objection"],
     "version_args": ["--version"], "website": "https://github.com/sensepost/objection",
     "docs": "https://github.com/sensepost/objection/wiki",
     "description": "基于 Frida 的运行时探索工具"},
    {"name": "drozer", "category": "移动安全", "exe_candidates": ["drozer"],
     "version_args": ["--version"], "website": "https://github.com/FSecureLABS/drozer",
     "docs": "https://github.com/FSecureLABS/drozer", "description": "Android 安全评估框架"},

    # ---- 逆向工程 ----
    {"name": "ghidra", "category": "逆向工程", "exe_candidates": ["ghidraRun", "ghidra"],
     "version_args": [], "website": "https://ghidra-sre.org/",
     "docs": "https://ghidra-sre.org/InstallationGuide.html",
     "description": "NSA 开源逆向工程套件"},
    {"name": "r2", "category": "逆向工程", "exe_candidates": ["r2", "radare2"],
     "version_args": ["-v"], "website": "https://www.radare.org/",
     "docs": "https://book.rada.re/", "description": "radare2 逆向框架"},
    {"name": "binwalk", "category": "逆向工程", "exe_candidates": ["binwalk"],
     "version_args": ["--version"], "website": "https://github.com/ReFirmLabs/binwalk",
     "docs": "https://github.com/ReFirmLabs/binwalk/blob/master/USAGE.md",
     "description": "固件分析与提取"},
    {"name": "strings", "category": "逆向工程", "exe_candidates": ["strings"],
     "version_args": ["--version"], "website": "https://www.gnu.org/software/binutils/",
     "docs": "https://linux.die.net/man/1/strings", "description": "二进制可打印字符串提取"},
    {"name": "objdump", "category": "逆向工程", "exe_candidates": ["objdump", "gobjdump"],
     "version_args": ["--version"], "website": "https://www.gnu.org/software/binutils/",
     "docs": "https://linux.die.net/man/1/objdump", "description": "目标文件反汇编"},

    # ---- 取证分析 ----
    {"name": "volatility", "category": "取证分析", "exe_candidates": ["volatility", "vol"],
     "version_args": ["--help"], "website": "https://www.volatilityfoundation.org/",
     "docs": "https://github.com/volatilityfoundation/volatility3",
     "description": "内存取证框架"},
    {"name": "autopsy", "category": "取证分析", "exe_candidates": ["autopsy"],
     "version_args": [], "website": "https://www.autopsy.com/",
     "docs": "https://www.autopsy.com/support/", "description": "数字取证平台"},
    {"name": "tshark", "category": "取证分析", "exe_candidates": ["tshark"],
     "version_args": ["--version"], "website": "https://www.wireshark.org/",
     "docs": "https://www.wireshark.org/docs/man-pages/tshark.html",
     "description": "Wireshark 命令行抓包"},
    {"name": "wireshark", "category": "取证分析", "exe_candidates": ["wireshark", "wireshark.exe"],
     "version_args": [], "website": "https://www.wireshark.org/",
     "docs": "https://www.wireshark.org/", "description": "图形化网络协议分析"},

    # ---- 云原生 ----
    {"name": "docker", "category": "云原生", "exe_candidates": ["docker"],
     "version_args": ["--version"], "website": "https://www.docker.com/",
     "docs": "https://docs.docker.com/", "description": "容器运行时"},
    {"name": "docker-compose", "category": "云原生", "exe_candidates": ["docker-compose", "docker-compose.bat"],
     "version_args": ["--version"], "website": "https://github.com/docker/compose",
     "docs": "https://docs.docker.com/compose/", "description": "多容器编排"},
    {"name": "kubectl", "category": "云原生", "exe_candidates": ["kubectl"],
     "version_args": ["--client", "version", "version"], "website": "https://kubernetes.io/",
     "docs": "https://kubernetes.io/docs/reference/kubectl/",
     "description": "Kubernetes 命令行"},
    {"name": "trivy", "category": "云原生", "exe_candidates": ["trivy"],
     "version_args": ["--version"], "website": "https://trivy.dev/",
     "docs": "https://trivy.dev/docs/", "description": "容器/文件系统漏洞扫描"},
    {"name": "helm", "category": "云原生", "exe_candidates": ["helm"],
     "version_args": ["version", "--version"], "website": "https://helm.sh/",
     "docs": "https://helm.sh/docs/", "description": "Kubernetes 包管理"},

    # ---- 代码安全 ----
    {"name": "semgrep", "category": "代码安全", "exe_candidates": ["semgrep"],
     "version_args": ["--version"], "website": "https://semgrep.dev/",
     "docs": "https://semgrep.dev/docs", "description": "多语言静态分析"},
    {"name": "sonar-scanner", "category": "代码安全", "exe_candidates": ["sonar-scanner", "sonar-scanner.bat"],
     "version_args": ["--version"], "website": "https://www.sonarsource.com/",
     "docs": "https://docs.sonarsource.com/sonarqube/latest/",
     "description": "SonarQube 代码扫描"},
    {"name": "gitleaks", "category": "代码安全", "exe_candidates": ["gitleaks"],
     "version_args": ["version"], "website": "https://github.com/gitleaks/gitleaks",
     "docs": "https://github.com/gitleaks/gitleaks",
     "description": "Git 仓库密钥泄露扫描"},

    # ---- 其他/基础 ----
    {"name": "python3", "category": "其他", "exe_candidates": ["python", "python3", "py"],
     "version_args": ["--version"], "website": "https://www.python.org/",
     "docs": "https://docs.python.org/3/", "description": "Python 运行时"},
    {"name": "pip", "category": "其他", "exe_candidates": ["pip", "pip3"],
     "version_args": ["--version"], "website": "https://pip.pypa.io/",
     "docs": "https://pip.pypa.io/", "description": "Python 包管理"},
    {"name": "git", "category": "其他", "exe_candidates": ["git"],
     "version_args": ["--version"], "website": "https://git-scm.com/",
     "docs": "https://git-scm.com/doc", "description": "版本控制"},
    {"name": "curl", "category": "其他", "exe_candidates": ["curl"],
     "version_args": ["--version"], "website": "https://curl.se/",
     "docs": "https://curl.se/docs/", "description": "HTTP 传输工具"},
    {"name": "wget", "category": "其他", "exe_candidates": ["wget"],
     "version_args": ["--version"], "website": "https://www.gnu.org/software/wget/",
     "docs": "https://www.gnu.org/software/wget/manual/", "description": "文件下载工具"},
    {"name": "openssl", "category": "其他", "exe_candidates": ["openssl"],
     "version_args": ["version"], "website": "https://www.openssl.org/",
     "docs": "https://www.openssl.org/docs/", "description": "SSL/TLS 与加密工具"},
]

CATEGORIES = [
    "网络扫描", "漏洞利用", "密码破解", "无线安全", "移动安全",
    "逆向工程", "取证分析", "云原生", "代码安全", "其他",
]

_VERSION_RE = re.compile(
    r"\b\d+(?:\.\d+){1,3}(?:[-._][A-Za-z0-9]+)?(?:\+[A-Za-z0-9.-]+)?\b"
)


def _run(cmd: List[str], timeout: int = 6) -> subprocess.CompletedProcess:
    """统一包装 subprocess：bytes 读取后用 utf-8/replace 解码，避免 cp936 崩溃。"""
    kwargs: Dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "timeout": timeout,
    }
    if IS_WINDOWS:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.run(cmd, **kwargs)
    try:
        out = proc.stdout.decode("utf-8", errors="replace")
    except Exception:
        out = ""
    try:
        err = proc.stderr.decode("utf-8", errors="replace")
    except Exception:
        err = ""
    # 包装成类似 CompletedProcess 的简单对象，保持接口一致
    class _R:
        def __init__(self, rc: int, o: str, e: str) -> None:
            self.returncode = rc
            self.stdout = o
            self.stderr = e
    return _R(proc.returncode, out, err)  # type: ignore[return-value]


def _which(exe_name: str) -> List[str]:
    """真实执行 where/which 返回可执行文件绝对路径列表。"""
    try:
        if IS_WINDOWS:
            proc = _run(["where.exe", exe_name])
            out = (proc.stdout or "").strip()
            if proc.returncode == 0 and out:
                return [line.strip() for line in out.splitlines() if line.strip()]
            return []
        else:
            proc = _run(["which", exe_name])
            out = (proc.stdout or "").strip()
            if proc.returncode == 0 and out:
                return [line.strip() for line in out.splitlines() if line.strip()]
            return []
    except Exception as e:  # pragma: no cover
        logger.debug("_which(%s) failed: %s", exe_name, e)
        return []


_ERR_HINTS = ("error", "can't open", "cannot find", "no such file",
              "usage", "unrecognized", "not recognized", "Traceback")


def _probe_version(exe_path: str, args: List[str]) -> str:
    """尝试调用版本参数抓取版本号，失败返回空串。"""
    for arg in args:
        try:
            proc = _run([exe_path, arg], timeout=8)
            out = (proc.stdout or "") + (proc.stderr or "")
            line = out.strip().splitlines()[0] if out.strip() else ""
            if not line:
                continue
            low = line.lower()
            if any(h in low for h in _ERR_HINTS):
                continue
            m = _VERSION_RE.search(line)
            if m:
                return m.group(0)
            if any(ch.isdigit() for ch in line):
                return line[:80]
        except Exception:
            continue
    return ""


def _file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except Exception:
        return 0


def _file_mtime(path: str) -> str:
    try:
        return time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(path))
        )
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# 检测器
# --------------------------------------------------------------------------- #
class ToolDetector:
    """启动时真实检测全部外部工具，内存缓存，可刷新。"""

    def __init__(self) -> None:
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._last_scan_at: str = ""
        self._scan_duration_ms: float = 0.0

    # ---- 单工具检测 ----
    def detect_one(self, meta: Dict[str, Any]) -> Dict[str, Any]:
        name = meta["name"]
        paths: List[str] = []
        used_exe = ""
        for cand in meta["exe_candidates"]:
            found = _which(cand)
            if found:
                paths = found
                used_exe = cand
                break

        available = bool(paths)
        primary = paths[0] if paths else ""
        version = ""
        if available and meta.get("version_args"):
            version = _probe_version(primary, meta["version_args"])

        entry = {
            "name": name,
            "category": meta["category"],
            "available": available,
            "executable_path": primary,
            "all_paths": paths,
            "used_exe": used_exe,
            "version": version,
            "size_bytes": _file_size(primary) if available else 0,
            "install_time": _file_mtime(primary) if available else "",
            "website": meta.get("website", ""),
            "docs": meta.get("docs", ""),
            "description": meta.get("description", ""),
            "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._cache[name] = entry
        return entry

    # ---- 全量并行检测 ----
    def detect_all(self, parallel: bool = True) -> Dict[str, Dict[str, Any]]:
        start = time.perf_counter()
        if parallel:
            results: Dict[str, Dict[str, Any]] = {}
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = {pool.submit(self.detect_one, m): m["name"] for m in TOOL_REGISTRY}
                for fut in as_completed(futures):
                    try:
                        entry = fut.result()
                        results[entry["name"]] = entry
                    except Exception as e:  # pragma: no cover
                        logger.exception("detect_one failed: %s", e)
            self._cache = results
        else:
            self._cache = {m["name"]: self.detect_one(m) for m in TOOL_REGISTRY}
        self._last_scan_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self._scan_duration_ms = round((time.perf_counter() - start) * 1000, 1)
        return self._cache

    # ---- 查询接口 ----
    def ensure_detected(self) -> Dict[str, Dict[str, Any]]:
        if not self._cache:
            self.detect_all()
        return self._cache

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        self.ensure_detected()
        return self._cache.get(name)

    def all_tools(self) -> List[Dict[str, Any]]:
        self.ensure_detected()
        return list(self._cache.values())

    def by_category(self) -> Dict[str, List[Dict[str, Any]]]:
        self.ensure_detected()
        out: Dict[str, List[Dict[str, Any]]] = {c: [] for c in CATEGORIES}
        for entry in self._cache.values():
            out.setdefault(entry["category"], []).append(entry)
        return out

    def summary(self) -> Dict[str, Any]:
        self.ensure_detected()
        total = len(self._cache)
        ok_n = sum(1 for e in self._cache.values() if e["available"])
        by_cat: Dict[str, Dict[str, int]] = {}
        for cat in CATEGORIES:
            items = [e for e in self._cache.values() if e["category"] == cat]
            by_cat[cat] = {
                "total": len(items),
                "available": sum(1 for e in items if e["available"]),
            }
        return {
            "total": total,
            "available": ok_n,
            "missing": total - ok_n,
            "coverage": round(ok_n / total * 100, 1) if total else 0.0,
            "categories": by_cat,
            "last_scan_at": self._last_scan_at,
            "scan_duration_ms": self._scan_duration_ms,
        }


# 单例
_detector: Optional[ToolDetector] = None


def get_detector() -> ToolDetector:
    global _detector
    if _detector is None:
        _detector = ToolDetector()
    return _detector
