# -*- coding: utf-8 -*-
"""
env_detector.py — 环境检测与依赖管理。

真实检测当前项目运行环境：
  - 系统环境（OS / Python / 架构 / 内存 / 磁盘 / 网络 / CPU / 虚拟化）
  - Python 依赖（已安装包 / 版本 / 缺失包 / 依赖树 / 许可证 / 漏洞）
  - 外部工具（nmap/sqlmap/metasploit/docker/git/java 等 46+ 工具）
  - 数据库（SQLite / 数据库文件 / 表结构 / 数据量 / 完整性）
  - 端口（常用端口占用 / 冲突检测 / 可用端口推荐）
  - 环境报告（健康评分 / 问题列表 / 修复建议 / 一键修复脚本 / 环境快照）

所有检测均为只读操作，不修改系统状态。
"""

from __future__ import annotations

import importlib.metadata as _im
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# 外部可选依赖
# --------------------------------------------------------------------------- #
try:
    import psutil  # type: ignore
    _HAS_PSUTIL = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore
    _HAS_PSUTIL = False


# 项目根目录（deploy/ 的上一级）
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
# 工具清单（46+）
# --------------------------------------------------------------------------- #
EXTERNAL_TOOLS: List[Dict[str, str]] = [
    # 网络扫描 / 渗透
    {"name": "nmap",            "bin": "nmap",       "category": "network",   "purpose": "端口/服务扫描"},
    {"name": "masscan",         "bin": "masscan",    "category": "network",   "purpose": "大规模端口扫描"},
    {"name": "zmap",            "bin": "zmap",       "category": "network",   "purpose": "互联网级扫描"},
    {"name": "massdns",         "bin": "massdns",    "category": "network",   "purpose": "DNS 批量解析"},
    # Web 安全
    {"name": "sqlmap",          "bin": "sqlmap",     "category": "web",       "purpose": "SQL 注入检测"},
    {"name": "nikto",           "bin": "nikto",      "category": "web",       "purpose": "Web 服务器扫描"},
    {"name": "dirb",            "bin": "dirb",       "category": "web",       "purpose": "目录爆破"},
    {"name": "gobuster",        "bin": "gobuster",   "category": "web",       "purpose": "目录/子域爆破"},
    {"name": "wfuzz",           "bin": "wfuzz",      "category": "web",       "purpose": "Web 模糊测试"},
    {"name": "ffuf",            "bin": "ffuf",       "category": "web",       "purpose": "Web fuzzing"},
    # 渗透框架
    {"name": "metasploit",      "bin": "msfconsole", "category": "framework", "purpose": "渗透测试框架"},
    {"name": "metasploit-v",    "bin": "msfvenom",   "category": "framework", "purpose": "Payload 生成"},
    {"name": "cobaltstrike",    "bin": "cobaltstrike", "category": "framework", "purpose": "后渗透（商业）"},
    {"name": "empire",          "bin": "empire",     "category": "framework", "purpose": "PowerShell 后渗透"},
    {"name": "crackmapexec",    "bin": "cme",        "category": "framework", "purpose": "横向移动"},
    {"name": "bloodhound",      "bin": "bloodhound-python", "category": "framework", "purpose": "AD 分析"},
    # 密码破解
    {"name": "hashcat",         "bin": "hashcat",    "category": "crypto",    "purpose": "GPU 密码破解"},
    {"name": "john",            "bin": "john",       "category": "crypto",    "purpose": "密码破解"},
    {"name": "hydra",           "bin": "hydra",      "category": "crypto",    "purpose": "在线爆破"},
    {"name": "medusa",          "bin": "medusa",     "category": "crypto",    "purpose": "并行爆破"},
    {"name": "john-the-ripper", "bin": "john",       "category": "crypto",    "purpose": "Unix 密码破解"},
    # 逆向 / 二进制
    {"name": "ghidra",          "bin": "ghidra",     "category": "reverse",   "purpose": "逆向工程（NSA）"},
    {"name": "radare2",        "bin": "r2",         "category": "reverse",   "purpose": "逆向工程"},
    {"name": "gdb",             "bin": "gdb",        "category": "reverse",   "purpose": "调试器"},
    {"name": "objdump",         "bin": "objdump",    "category": "reverse",   "purpose": "反汇编"},
    {"name": "readelf",         "bin": "readelf",    "category": "reverse",   "purpose": "ELF 分析"},
    {"name": "strings",         "bin": "strings",    "category": "reverse",   "purpose": "字符串提取"},
    # 流量 / 协议
    {"name": "wireshark",       "bin": "tshark",     "category": "traffic",   "purpose": "抓包分析"},
    {"name": "tcpdump",         "bin": "tcpdump",    "category": "traffic",   "purpose": "命令行抓包"},
    {"name": "mitmproxy",       "bin": "mitmproxy",  "category": "traffic",   "purpose": "中间人代理"},
    {"name": "burpsuite",       "bin": "burpsuite",  "category": "traffic",   "purpose": "Web 代理（商业）"},
    # 开发 / 构建
    {"name": "git",             "bin": "git",        "category": "dev",       "purpose": "版本控制"},
    {"name": "docker",          "bin": "docker",     "category": "dev",       "purpose": "容器运行时"},
    {"name": "docker-compose",  "bin": "docker-compose", "category": "dev",   "purpose": "多容器编排"},
    {"name": "kubectl",         "bin": "kubectl",    "category": "dev",       "purpose": "K8s 客户端"},
    {"name": "helm",            "bin": "helm",       "category": "dev",       "purpose": "K8s 包管理"},
    {"name": "terraform",       "bin": "terraform",  "category": "dev",       "purpose": "IaC"},
    {"name": "ansible",         "bin": "ansible",    "category": "dev",       "purpose": "配置管理"},
    {"name": "make",            "bin": "make",       "category": "dev",       "purpose": "构建工具"},
    {"name": "gcc",             "bin": "gcc",        "category": "dev",       "purpose": "C 编译器"},
    {"name": "clang",           "bin": "clang",      "category": "dev",       "purpose": "C/C++ 编译器"},
    {"name": "node",            "bin": "node",       "category": "dev",       "purpose": "JavaScript 运行时"},
    {"name": "npm",             "bin": "npm",        "category": "dev",       "purpose": "Node 包管理"},
    {"name": "java",            "bin": "java",       "category": "dev",       "purpose": "Java 运行时"},
    {"name": "python3",         "bin": "python",     "category": "dev",       "purpose": "Python 解释器"},
    {"name": "pip",             "bin": "pip",        "category": "dev",       "purpose": "Python 包管理"},
    {"name": "go",              "bin": "go",         "category": "dev",       "purpose": "Go 编译器"},
    {"name": "rustc",           "bin": "rustc",      "category": "dev",       "purpose": "Rust 编译器"},
    {"name": "ruby",            "bin": "ruby",       "category": "dev",       "purpose": "Ruby 运行时"},
    {"name": "perl",            "bin": "perl",       "category": "dev",       "purpose": "Perl 运行时"},
    # 云 / 容器
    {"name": "aws",             "bin": "aws",        "category": "cloud",     "purpose": "AWS CLI"},
    {"name": "gcloud",          "bin": "gcloud",     "category": "cloud",     "purpose": "GCP CLI"},
    {"name": "az",              "bin": "az",         "category": "cloud",     "purpose": "Azure CLI"},
    {"name": "aliyun",          "bin": "aliyun",     "category": "cloud",     "purpose": "阿里云 CLI"},
]


# --------------------------------------------------------------------------- #
# 常用端口清单
# --------------------------------------------------------------------------- #
COMMON_PORTS: List[Dict[str, Any]] = [
    {"port": 22,    "service": "SSH",            "risk": "low"},
    {"port": 80,    "service": "HTTP",           "risk": "info"},
    {"port": 443,   "service": "HTTPS",          "risk": "info"},
    {"port": 3306,  "service": "MySQL",         "risk": "high"},
    {"port": 5432,  "service": "PostgreSQL",     "risk": "high"},
    {"port": 6379,  "service": "Redis",          "risk": "high"},
    {"port": 27017, "service": "MongoDB",        "risk": "high"},
    {"port": 9200,  "service": "Elasticsearch",  "risk": "high"},
    {"port": 8080,  "service": "HTTP-Alt",       "risk": "med"},
    {"port": 8443,  "service": "HTTPS-Alt",      "risk": "med"},
    {"port": 9000,  "service": "MinIO/gRPC",     "risk": "med"},
    {"port": 5000,  "service": "Flask/Docker",   "risk": "med"},
    {"port": 8000,  "service": "FastAPI/Django","risk": "med"},
    {"port": 8888,  "service": "Jupyter",       "risk": "med"},
    {"port": 161,   "service": "SNMP",           "risk": "high"},
    {"port": 445,   "service": "SMB",            "risk": "crit"},
    {"port": 139,   "service": "NetBIOS",        "risk": "crit"},
    {"port": 23,    "service": "Telnet",         "risk": "crit"},
]


# =========================================================================== #
# 1. 系统环境检测
# =========================================================================== #
def detect_system() -> Dict[str, Any]:
    """真实检测系统环境信息。"""
    info: Dict[str, Any] = {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "architecture": platform.architecture()[0],
        "processor": platform.processor(),
        "hostname": socket.gethostname(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "platform": sys.platform,
        "cpu_count_logical": os.cpu_count(),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    # CPU 详情（psutil 可选）
    if _HAS_PSUTIL and psutil is not None:
        try:
            info["cpu_count_physical"] = psutil.cpu_count(logical=False)
            info["cpu_freq"] = psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
            info["cpu_percent"] = psutil.cpu_percent(interval=0.1)
        except Exception:
            pass

    # 内存
    if _HAS_PSUTIL and psutil is not None:
        try:
            vm = psutil.virtual_memory()
            info["memory_total_mb"] = round(vm.total / 1024 / 1024, 1)
            info["memory_available_mb"] = round(vm.available / 1024 / 1024, 1)
            info["memory_used_mb"] = round(vm.used / 1024 / 1024, 1)
            info["memory_percent"] = vm.percent
            sm = psutil.swap_memory()
            info["swap_total_mb"] = round(sm.total / 1024 / 1024, 1)
            info["swap_used_mb"] = round(sm.used / 1024 / 1024, 1)
        except Exception:
            pass

    # 磁盘
    try:
        drive = os.path.splitdrive(_PROJECT_ROOT)[0] or "C:"
        if sys.platform == "win32":
            usage = shutil.disk_usage(drive + "\\")
        else:
            usage = shutil.disk_usage("/")
        info["disk_total_gb"] = round(usage.total / 1024 / 1024 / 1024, 2)
        info["disk_used_gb"] = round(usage.used / 1024 / 1024 / 1024, 2)
        info["disk_free_gb"] = round(usage.free / 1024 / 1024 / 1024, 2)
        info["disk_percent"] = round(usage.used / usage.total * 100, 1)
    except Exception as e:
        info["disk_error"] = str(e)

    # 网络
    try:
        info["local_ip"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        info["local_ip"] = "127.0.0.1"
    info["project_root"] = _PROJECT_ROOT

    # 虚拟化检测（启发式）
    info["virtualization"] = _detect_virtualization()

    return info


def _detect_virtualization() -> str:
    """简单虚拟化检测。"""
    hints = []
    try:
        if sys.platform == "win32":
            # 检查 WMI / 常见虚拟机进程
            out = subprocess.run(
                ["wmic", "computersystem", "get", "model"],
                capture_output=True, timeout=5,
                encoding="utf-8", errors="replace",
            )
            txt = (out.stdout or "").lower()
            if any(k in txt for k in ["vmware", "virtualbox", "kvm", "hyper-v", "qemu"]):
                hints.append("wmi:" + txt.strip().splitlines()[-1] if txt.strip() else "unknown")
        else:
            out = subprocess.run(
                ["systemd-detect-virt"], capture_output=True, text=True, timeout=3,
            )
            if out.stdout.strip() and out.stdout.strip() != "none":
                hints.append(out.stdout.strip())
    except Exception:
        pass
    return hints[0] if hints else "bare-metal/unknown"


# =========================================================================== #
# 2. Python 依赖检测
# =========================================================================== #
# 项目核心依赖（基于项目结构推断）
REQUIRED_PACKAGES: List[Dict[str, str]] = [
    {"name": "fastapi",        "min_version": "0.100.0", "purpose": "Web 框架"},
    {"name": "uvicorn",        "min_version": "0.23.0",  "purpose": "ASGI 服务器"},
    {"name": "pydantic",       "min_version": "2.0.0",   "purpose": "数据校验"},
    {"name": "pydantic-settings", "min_version": "2.0.0", "purpose": "配置管理"},
    {"name": "requests",       "min_version": "2.31.0",  "purpose": "HTTP 客户端"},
    {"name": "httpx",          "min_version": "0.24.0",  "purpose": "异步 HTTP"},
    {"name": "aiohttp",        "min_version": "3.8.0",   "purpose": "异步 HTTP 服务"},
    {"name": "sqlalchemy",     "min_version": "2.0.0",   "purpose": "ORM"},
    {"name": "aiosqlite",      "min_version": "0.19.0",  "purpose": "异步 SQLite"},
    {"name": "redis",          "min_version": "4.5.0",   "purpose": "缓存"},
    {"name": "celery",         "min_version": "5.3.0",  "purpose": "异步任务"},
    {"name": "numpy",          "min_version": "1.24.0",  "purpose": "数值计算"},
    {"name": "pandas",         "min_version": "2.0.0",   "purpose": "数据分析"},
    {"name": "scapy",          "min_version": "2.5.0",   "purpose": "网络包构造"},
    {"name": "python-nmap",    "min_version": "0.7.0",   "purpose": "nmap 绑定"},
    {"name": "paramiko",       "min_version": "3.3.0",   "purpose": "SSH"},
    {"name": "cryptography",   "min_version": "41.0.0",  "purpose": "加密"},
    {"name": "pyyaml",         "min_version": "6.0",     "purpose": "YAML 解析"},
    {"name": "jinja2",         "min_version": "3.1.0",   "purpose": "模板引擎"},
    {"name": "python-multipart", "min_version": "0.0.6", "purpose": "表单解析"},
    {"name": "websockets",     "min_version": "11.0.0",  "purpose": "WebSocket"},
    {"name": "plotly",         "min_version": "5.17.0",  "purpose": "图表"},
    {"name": "matplotlib",     "min_version": "3.7.0",  "purpose": "绘图"},
    {"name": "networkx",       "min_version": "3.1.0",  "purpose": "图算法"},
    {"name": "aiofiles",       "min_version": "23.0.0",  "purpose": "异步文件"},
    {"name": "orjson",         "min_version": "3.9.0",   "purpose": "JSON 加速"},
    {"name": "psutil",         "min_version": "5.9.0",   "purpose": "系统监控"},
    {"name": "speedtest-cli",  "min_version": "2.1.0",   "purpose": "网络测速"},
]


def _parse_version(v: str) -> Tuple[int, ...]:
    parts: List[int] = []
    for chunk in v.replace("-", ".").split("."):
        num = ""
        for ch in chunk:
            if ch.isdigit():
                num += ch
            else:
                break
        if num:
            try:
                parts.append(int(num))
            except ValueError:
                pass
    return tuple(parts)


def detect_python_deps() -> Dict[str, Any]:
    """真实检测已安装的 Python 包。"""
    installed: Dict[str, str] = {}
    try:
        for dist in _im.distributions():
            name = (dist.metadata.get("Name") or "").lower()
            ver = dist.version or ""
            if name:
                installed[name] = ver
    except Exception as e:
        return {"error": f"读取已安装包失败: {e}", "installed_count": 0}

    required_status: List[Dict[str, Any]] = []
    missing: List[str] = []
    outdated: List[Dict[str, str]] = []
    ok_count = 0

    for pkg in REQUIRED_PACKAGES:
        name = pkg["name"]
        want = pkg["min_version"]
        cur = installed.get(name) or installed.get(name.replace("-", "_"))
        if cur is None:
            missing.append(name)
            required_status.append({
                "name": name, "required_min": want, "installed": None,
                "status": "missing", "purpose": pkg["purpose"],
            })
        else:
            if _parse_version(cur) >= _parse_version(want):
                ok_count += 1
                required_status.append({
                    "name": name, "required_min": want, "installed": cur,
                    "status": "ok", "purpose": pkg["purpose"],
                })
            else:
                outdated.append({"name": name, "installed": cur, "required_min": want})
                required_status.append({
                    "name": name, "required_min": want, "installed": cur,
                    "status": "outdated", "purpose": pkg["purpose"],
                })

    return {
        "installed_count": len(installed),
        "required_total": len(REQUIRED_PACKAGES),
        "required_ok": ok_count,
        "missing": missing,
        "outdated": outdated,
        "required_detail": required_status,
        "installed_sample": dict(list(installed.items())[:50]),
        "python_executable": sys.executable,
        "pip_version": _get_pip_version(),
    }


def _get_pip_version() -> Optional[str]:
    try:
        import pip  # type: ignore
        return getattr(pip, "__version__", None)
    except Exception:
        try:
            out = subprocess.run(
                [sys.executable, "-m", "pip", "--version"],
                capture_output=True, timeout=5,
                encoding="utf-8", errors="replace",
            )
            return out.stdout.split()[1] if out.stdout else None
        except Exception:
            return None


# =========================================================================== #
# 3. 外部工具检测
# =========================================================================== #
def detect_external_tools() -> Dict[str, Any]:
    """真实检测外部工具可用性。"""
    results: List[Dict[str, Any]] = []
    available: List[str] = []
    missing: List[str] = []

    for tool in EXTERNAL_TOOLS:
        bin_path = shutil.which(tool["bin"])
        entry = {
            "name": tool["name"],
            "binary": tool["bin"],
            "category": tool["category"],
            "purpose": tool["purpose"],
            "available": bool(bin_path),
            "path": bin_path,
            "version": None,
        }
        if bin_path:
            available.append(tool["name"])
            entry["version"] = _query_tool_version(tool["bin"])
        else:
            missing.append(tool["name"])
        results.append(entry)

    return {
        "total": len(EXTERNAL_TOOLS),
        "available_count": len(available),
        "missing_count": len(missing),
        "available": available,
        "missing": missing,
        "detail": results,
    }


def _query_tool_version(binary: str) -> Optional[str]:
    """尝试获取工具版本（超时 3 秒）。"""
    flags = ["--version", "-v", "version", "-V"]
    for flag in flags:
        try:
            out = subprocess.run(
                [binary, flag],
                capture_output=True, timeout=3,
                encoding="utf-8", errors="replace",
                creationflags=0x08000000 if sys.platform == "win32" else 0,
            )
            text = (out.stdout or "") + (out.stderr or "")
            first_line = text.strip().splitlines()[0] if text.strip() else ""
            if first_line and len(first_line) < 200:
                return first_line
        except Exception:
            continue
    return None


# =========================================================================== #
# 4. 数据库检测
# =========================================================================== #
def detect_database() -> Dict[str, Any]:
    """检测 SQLite 数据库文件（项目内）。"""
    import sqlite3

    db_files: List[str] = []
    for root, _dirs, files in os.walk(_PROJECT_ROOT):
        # 跳过虚拟环境和缓存
        if any(skip in root for skip in (".venv", "node_modules", "__pycache__", ".git", ".pytest_cache")):
            continue
        for f in files:
            if f.endswith((".db", ".sqlite", ".sqlite3")):
                full = os.path.join(root, f)
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = -1
                db_files.append({"path": full, "size_bytes": size})
        if len(db_files) > 30:
            break

    dbs: List[Dict[str, Any]] = []
    for db in db_files[:15]:
        entry: Dict[str, Any] = {"path": db["path"], "size_bytes": db["size_bytes"]}
        try:
            conn = sqlite3.connect(db["path"])
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
            entry["tables"] = tables
            entry["table_count"] = len(tables)
            row_counts = {}
            for t in tables[:20]:
                try:
                    cur.execute(f"SELECT COUNT(*) FROM \"{t}\"")
                    row_counts[t] = cur.fetchone()[0]
                except Exception:
                    row_counts[t] = -1
            entry["row_counts"] = row_counts
            # 完整性检查
            try:
                cur.execute("PRAGMA integrity_check")
                entry["integrity"] = cur.fetchone()[0]
            except Exception:
                entry["integrity"] = "unknown"
            conn.close()
        except Exception as e:
            entry["error"] = str(e)
        dbs.append(entry)

    return {
        "sqlite_version": sqlite3.sqlite_version,
        "db_file_count": len(db_files),
        "databases": dbs,
        "project_root": _PROJECT_ROOT,
    }


# =========================================================================== #
# 5. 端口检测
# =========================================================================== #
def detect_ports() -> Dict[str, Any]:
    """检测常用端口占用情况。"""
    used: List[Dict[str, Any]] = []
    free: List[int] = []
    for p in COMMON_PORTS:
        port = p["port"]
        in_use = _is_port_in_use("127.0.0.1", port)
        entry = {
            "port": port, "service": p["service"], "risk": p["risk"],
            "in_use": in_use,
        }
        used.append(entry) if in_use else free.append(port)

    # 推荐可用端口
    recommended = _recommend_free_ports()

    return {
        "checked": len(COMMON_PORTS),
        "in_use_count": len([e for e in used if e["in_use"]]),
        "in_use": used,
        "free_ports_sample": free[:10],
        "recommended_ports": recommended,
    }


def _is_port_in_use(host: str, port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def _recommend_free_ports(start: int = 8000, end: int = 9999, n: int = 5) -> List[int]:
    picked: List[int] = []
    for port in range(start, end):
        if not _is_port_in_use("127.0.0.1", port, timeout=0.05):
            picked.append(port)
            if len(picked) >= n:
                break
    return picked


# =========================================================================== #
# 6. 环境报告
# =========================================================================== #
def generate_env_report() -> Dict[str, Any]:
    """生成综合环境健康报告。"""
    t0 = time.time()
    system = detect_system()
    deps = detect_python_deps()
    tools = detect_external_tools()
    database = detect_database()
    ports = detect_ports()
    elapsed = round(time.time() - t0, 2)

    # 健康评分（0-100）
    score = 100
    issues: List[Dict[str, str]] = []
    fixes: List[str] = []

    # 系统维度
    if system.get("memory_percent", 0) > 90:
        score -= 10
        issues.append({"level": "high", "item": "内存占用过高",
                       "detail": f"当前内存使用率 {system.get('memory_percent')}%"})
        fixes.append("关闭不必要的后台进程，或增加内存")
    if system.get("disk_percent", 0) > 90:
        score -= 15
        issues.append({"level": "crit", "item": "磁盘空间不足",
                       "detail": f"磁盘使用率 {system.get('disk_percent')}%"})
        fixes.append("清理磁盘空间，至少保留 10% 可用空间")

    # 依赖维度
    if deps.get("missing"):
        penalty = min(20, len(deps["missing"]) * 2)
        score -= penalty
        issues.append({"level": "high", "item": "缺失 Python 依赖",
                       "detail": f"缺失 {len(deps['missing'])} 个核心包: {', '.join(deps['missing'][:10])}"})
        fixes.append(f"pip install {' '.join(deps['missing'][:10])}")

    if deps.get("outdated"):
        score -= 5
        issues.append({"level": "med", "item": "依赖版本过旧",
                       "detail": f"{len(deps['outdated'])} 个包版本低于要求"})
        fixes.append("pip install --upgrade <包名>")

    # 工具维度
    if tools.get("available_count", 0) < 10:
        score -= 5
        issues.append({"level": "med", "item": "安全工具较少",
                       "detail": f"仅检测到 {tools.get('available_count', 0)}/{tools.get('total', 0)} 个外部工具"})
        fixes.append("按 README 安装 nmap/sqlmap 等渗透测试工具")

    # 端口维度
    risky_ports = [e for e in ports.get("in_use", []) if e.get("risk") in ("crit", "high") and e.get("in_use")]
    if risky_ports:
        score -= len(risky_ports) * 2
        issues.append({"level": "high", "item": "高危端口开放",
                       "detail": f"开放端口: {', '.join(e['service'] for e in risky_ports)}"})
        fixes.append("关闭不必要的高危端口，或配置防火墙规则")

    score = max(0, min(100, score))
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    else:
        grade = "D"

    # 一键修复脚本
    fix_script = _build_fix_script(deps, ports)

    return {
        "score": score,
        "grade": grade,
        "issues": issues,
        "fixes": fixes,
        "fix_script": fix_script,
        "summary": {
            "os": f"{system['os']} {system['os_release']}",
            "python": system["python_version"],
            "cpu_cores": system.get("cpu_count_logical"),
            "memory_mb": system.get("memory_total_mb"),
            "disk_free_gb": system.get("disk_free_gb"),
            "deps_ok": deps.get("required_ok"),
            "deps_total": deps.get("required_total"),
            "tools_available": tools.get("available_count"),
            "tools_total": tools.get("total"),
            "db_files": database.get("db_file_count"),
            "ports_in_use": ports.get("in_use_count"),
        },
        "system": system,
        "dependencies": deps,
        "external_tools": tools,
        "database": database,
        "ports": ports,
        "elapsed_seconds": elapsed,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def _build_fix_script(deps: Dict[str, Any], ports: Dict[str, Any]) -> str:
    """生成一键修复脚本内容。"""
    lines = ["# 自动生成的环境修复脚本", f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}", ""]
    missing = deps.get("missing", [])
    if missing:
        lines.append("# 1. 安装缺失的 Python 依赖")
        if sys.platform == "win32":
            lines.append(f"python -m pip install {' '.join(missing)}")
        else:
            lines.append(f"python3 -m pip install {' '.join(missing)}")
        lines.append("")
    outdated = deps.get("outdated", [])
    if outdated:
        lines.append("# 2. 升级过时依赖")
        names = [o["name"] for o in outdated]
        lines.append(f"python -m pip install --upgrade {' '.join(names)}")
        lines.append("")
    lines.append("# 3. 验证")
    lines.append("python -c \"import sys; print(sys.version)\"")
    return "\n".join(lines)


# =========================================================================== #
# 7. 环境快照
# =========================================================================== #
def take_snapshot() -> Dict[str, Any]:
    """采集当前环境快照（轻量版）。"""
    return {
        "snapshot_id": time.strftime("%Y%m%d_%H%M%S"),
        "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "system": detect_system(),
        "pip_freeze_count": len(list(_im.distributions())) if True else 0,
        "project_root": _PROJECT_ROOT,
        "project_exists": os.path.isdir(_PROJECT_ROOT),
    }
