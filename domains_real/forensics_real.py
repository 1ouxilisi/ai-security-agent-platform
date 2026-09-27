# -*- coding: utf-8 -*-
"""forensics_real.py — 取证分析做实模块。

真实取证工具集成框架：
    - 内存取证（Volatility3 框架）
    - 磁盘取证（文件系统分析）
    - 网络取证（流量分析 - tshark）
    - 日志取证（日志分析）
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

# 内存存储
FORENSIC_CASES: Dict[str, Dict[str, Any]] = {}
MEMORY_ANALYSES: Dict[str, Dict[str, Any]] = {}
DISK_ANALYSES: Dict[str, Dict[str, Any]] = {}
NETWORK_ANALYSES: Dict[str, Dict[str, Any]] = {}
LOG_ANALYSES: Dict[str, Dict[str, Any]] = {}

DEFAULT_TIMEOUT = 300
_TOOL_CACHE: Dict[str, Optional[str]] = {}


def _which(name: str) -> Optional[str]:
    if name not in _TOOL_CACHE:
        _TOOL_CACHE[name] = shutil.which(name)
    return _TOOL_CACHE[name]


def _run_cmd(cmd: List[str], timeout: Optional[int] = None) -> Dict[str, Any]:
    to = timeout or DEFAULT_TIMEOUT
    started = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=to,
            encoding="utf-8", errors="replace",
        )
        return {
            "success": proc.returncode == 0,
            "cmd": cmd,
            "returncode": proc.returncode,
            "stdout": (proc.stdout or "")[:30000],
            "stderr": (proc.stderr or "")[:5000],
            "elapsed": round(time.time() - started, 2),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "success": False, "cmd": cmd, "returncode": None,
            "stdout": (e.stdout or "") if isinstance(e.stdout, str) else "",
            "stderr": f"执行超时（{to}s）",
            "elapsed": round(time.time() - started, 2), "timed_out": True,
        }
    except FileNotFoundError as e:
        return {
            "success": False, "cmd": cmd, "returncode": None,
            "stdout": "", "stderr": f"命令未找到: {e}",
            "elapsed": round(time.time() - started, 2), "timed_out": False,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "success": False, "cmd": cmd, "returncode": None,
            "stdout": "", "stderr": f"执行异常: {e}",
            "elapsed": round(time.time() - started, 2), "timed_out": False,
        }


def tool_availability() -> Dict[str, Dict[str, Any]]:
    """检测取证相关工具。"""
    tools = [
        "vol", "volatility3",  # Volatility
        "tshark", "tcpdump", "wireshark",  # 网络取证
        "fls", "ils", "mmls", "icat",  # Sleuth Kit 磁盘取证
        "strings", "foremost", "scalpel",  # 文件恢复
        "hashdeep", "md5sum", "sha256sum",  # 哈希校验
    ]
    result: Dict[str, Dict[str, Any]] = {}
    for t in tools:
        path = _which(t)
        result[t] = {"available": bool(path), "path": path}
    return result


# ============================================================
# 案件管理
# ============================================================
def create_case(case_name: str, description: str = "") -> Dict[str, Any]:
    """创建取证案件。"""
    case_id = f"case_{int(time.time())}"
    case = {
        "id": case_id,
        "name": case_name,
        "description": description,
        "status": "active",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "evidence": [],
        "analyses": [],
    }
    FORENSIC_CASES[case_id] = case
    return {"success": True, "case": case}


def list_cases() -> List[Dict[str, Any]]:
    return list(FORENSIC_CASES.values())


def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    return FORENSIC_CASES.get(case_id)


def add_evidence(case_id: str, evidence_path: str, evidence_type: str = "disk_image") -> Dict[str, Any]:
    """添加证据文件到案件。"""
    case = FORENSIC_CASES.get(case_id)
    if not case:
        return {"success": False, "error": f"案件不存在: {case_id}"}
    evidence_id = f"ev_{int(time.time())}"
    evidence = {
        "id": evidence_id,
        "path": evidence_path,
        "type": evidence_type,
        "added_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    case["evidence"].append(evidence)
    return {"success": True, "evidence": evidence}


# ============================================================
# 内存取证（Volatility3）
# ============================================================
VOLATILITY_PLUGINS: List[Dict[str, Any]] = [
    {"name": "windows.pslist", "description": "列出进程"},
    {"name": "windows.pstree", "description": "进程树"},
    {"name": "windows.netscan", "description": "网络连接"},
    {"name": "windows.cmdline", "description": "命令行参数"},
    {"name": "windows.dlllist", "description": "DLL 列表"},
    {"name": "windows.handles", "description": "句柄列表"},
    {"name": "windows.malfind", "description": "恶意代码检测"},
    {"name": "windows.hashdump", "description": "密码哈希提取"},
    {"name": "linux.pslist", "description": "Linux 进程列表"},
    {"name": "linux.bash", "description": "Bash 历史"},
]


def list_volatility_plugins() -> List[Dict[str, Any]]:
    return VOLATILITY_PLUGINS


def memory_analyze(
    memory_image: str,
    plugin: str = "windows.pslist",
    timeout: int = 300,
) -> Dict[str, Any]:
    """使用 Volatility3 分析内存镜像。"""
    vol = _which("vol") or _which("volatility3")
    if not vol:
        return {
            "success": False,
            "error": "Volatility3 未安装。安装方法：pip install volatility3",
            "memory_image": memory_image,
        }
    if not os.path.exists(memory_image):
        return {"success": False, "error": f"内存镜像文件不存在: {memory_image}"}

    cmd = [vol, "-f", memory_image, plugin]
    r = _run_cmd(cmd, timeout=timeout)

    analysis_id = f"mem_{int(time.time())}"
    record = {
        "id": analysis_id,
        "memory_image": memory_image,
        "plugin": plugin,
        "output": r.get("stdout", "")[:15000],
        "success": r["success"],
        "elapsed": r.get("elapsed"),
        "analyzed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    MEMORY_ANALYSES[analysis_id] = record
    return {"success": r["success"], "analysis": record, "raw": r}


def list_memory_analyses() -> List[Dict[str, Any]]:
    return list(MEMORY_ANALYSES.values())


# ============================================================
# 磁盘取证（Sleuth Kit / 文件系统分析）
# ============================================================
def disk_list_partitions(image_path: str, timeout: int = 120) -> Dict[str, Any]:
    """使用 mmls 列出磁盘镜像分区表。"""
    mmls = _which("mmls")
    if not mmls:
        return {
            "success": False,
            "error": "mmls (Sleuth Kit) 未安装。安装方法：https://www.sleuthkit.org/",
            "image_path": image_path,
        }
    if not os.path.exists(image_path):
        return {"success": False, "error": f"磁盘镜像不存在: {image_path}"}

    r = _run_cmd([mmls, image_path], timeout=timeout)
    partitions: List[str] = []
    for line in r.get("stdout", "").splitlines():
        if line.strip() and not line.start(" DOS") and not line.start(" -----"):
            partitions.append(line.strip())

    analysis_id = f"disk_{int(time.time())}"
    record = {
        "id": analysis_id,
        "image_path": image_path,
        "operation": "list_partitions",
        "partitions": partitions,
        "raw_output": r.get("stdout", "")[:10000],
        "success": r["success"],
        "elapsed": r.get("elapsed"),
    }
    DISK_ANALYSES[analysis_id] = record
    return {"success": r["success"], "analysis": record, "raw": r}


def disk_list_files(image_path: str, offset: int = 0, timeout: int = 120) -> Dict[str, Any]:
    """使用 fls 列出文件系统内容。"""
    fls = _which("fls")
    if not fls:
        return {
            "success": False,
            "error": "fls (Sleuth Kit) 未安装",
            "image_path": image_path,
        }
    if not os.path.exists(image_path):
        return {"success": False, "error": f"磁盘镜像不存在: {image_path}"}

    cmd = [fls, "-r", "-o", str(offset), image_path]
    r = _run_cmd(cmd, timeout=timeout)
    files: List[str] = []
    for line in r.get("stdout", "").splitlines():
        if line.strip():
            files.append(line.strip())

    analysis_id = f"disk_files_{int(time.time())}"
    record = {
        "id": analysis_id,
        "image_path": image_path,
        "operation": "list_files",
        "file_count": len(files),
        "files": files[:1000],
        "success": r["success"],
        "elapsed": r.get("elapsed"),
    }
    DISK_ANALYSES[analysis_id] = record
    return {"success": r["success"], "analysis": record, "raw": r}


def disk_extract_file(image_path: str, inode: int, offset: int = 0, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """使用 icat 从磁盘镜像提取指定 inode 的文件。"""
    icat = _which("icat")
    if not icat:
        return {"success": False, "error": "icat (Sleuth Kit) 未安装"}
    if not os.path.exists(image_path):
        return {"success": False, "error": f"磁盘镜像不存在: {image_path}"}

    if not output_dir:
        output_dir = os.path.join(os.environ.get("TEMP", "/tmp"), "forensics_extracted")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"inode_{inode}.bin")

    cmd = [icat, "-o", str(offset), image_path, str(inode)]
    try:
        with open(output_file, "wb") as out_f:
            proc = subprocess.run(cmd, stdout=out_f, stderr=subprocess.PIPE, timeout=120)
        success = proc.returncode == 0
        size = os.path.getsize(output_file) if os.path.exists(output_file) else 0
        return {
            "success": success,
            "inode": inode,
            "output_file": output_file,
            "file_size_bytes": size,
        }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"文件提取失败: {e}"}


def list_disk_analyses() -> List[Dict[str, Any]]:
    return list(DISK_ANALYSES.values())


# ============================================================
# 网络取证（tshark 流量分析）
# ============================================================
PCAP_STAT_TEMPLATES: List[Dict[str, Any]] = [
    {"name": "capinfos", "description": "获取 pcap 基本信息（包数/时间/链路层）"},
    {"name": "http", "description": "HTTP 请求/响应分析"},
    {"name": "dns", "description": "DNS 查询分析"},
    {"name": "dns-tunneling", "description": "DNS 隧道检测"},
    {"name": "conversations", "description": "会话统计（IP对/端口对）"},
    {"name": "endpoints", "description": "端点统计"},
    {"name": "io-stat", "description": "I/O 图表统计"},
]


def list_pcap_analysis_types() -> List[Dict[str, Any]]:
    return PCAP_STAT_TEMPLATES


def network_pcap_info(pcap_file: str, timeout: int = 120) -> Dict[str, Any]:
    """获取 pcap 文件基本信息（capinfos）。"""
    ci = _which("capinfos")
    if not ci:
        return {
            "success": False,
            "error": "capinfos (Wireshark) 未安装。安装方法：https://www.wireshark.org/",
            "pcap_file": pcap_file,
        }
    if not os.path.exists(pcap_file):
        return {"success": False, "error": f"pcap 文件不存在: {pcap_file}"}

    r = _run_cmd([ci, pcap_file], timeout=timeout)
    info: Dict[str, str] = {}
    for line in r.get("stdout", "").splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            info[key.strip()] = val.strip()

    analysis_id = f"net_{int(time.time())}"
    record = {
        "id": analysis_id,
        "pcap_file": pcap_file,
        "operation": "pcap_info",
        "info": info,
        "success": r["success"],
    }
    NETWORK_ANALYSES[analysis_id] = record
    return {"success": r["success"], "analysis": record, "raw": r}


def network_pcap_protocol_stats(pcap_file: str, timeout: int = 300) -> Dict[str, Any]:
    """使用 tshark 统计协议分布。"""
    ts = _which("tshark")
    if not ts:
        return {
            "success": False,
            "error": "tshark (Wireshark) 未安装",
            "pcap_file": pcap_file,
        }
    if not os.path.exists(pcap_file):
        return {"success": False, "error": f"pcap 文件不存在: {pcap_file}"}

    r = _run_cmd([ts, "-r", pcap_file, "-q", "-z", "io,phs"], timeout=timeout)
    analysis_id = f"net_proto_{int(time.time())}"
    record = {
        "id": analysis_id,
        "pcap_file": pcap_file,
        "operation": "protocol_hierarchy",
        "output": r.get("stdout", "")[:15000],
        "success": r["success"],
    }
    NETWORK_ANALYSES[analysis_id] = record
    return {"success": r["success"], "analysis": record, "raw": r}


def network_extract_http(pcap_file: str, timeout: int = 300) -> Dict[str, Any]:
    """使用 tshark 提取 HTTP 请求记录。"""
    ts = _which("tshark")
    if not ts:
        return {"success": False, "error": "tshark 未安装", "pcap_file": pcap_file}
    if not os.path.exists(pcap_file):
        return {"success": False, "error": f"pcap 文件不存在: {pcap_file}"}

    cmd = [ts, "-r", pcap_file, "-Y", "http.request", "-T",
           "fields", "-e", "frame.time", "-e", "ip.src", "-e", "http.host",
           "-e", "http.request.method", "-e", "http.request.uri"]
    r = _run_cmd(cmd, timeout=timeout)
    http_records: List[Dict[str, str]] = []
    for line in r.get("stdout", "").splitlines():
        parts = line.split("\t")
        if len(parts) >= 5:
            http_records.append({
                "time": parts[0],
                "src_ip": parts[1],
                "host": parts[2],
                "method": parts[3],
                "uri": parts[4],
            })

    analysis_id = f"net_http_{int(time.time())}"
    record = {
        "id": analysis_id,
        "pcap_file": pcap_file,
        "operation": "http_extract",
        "http_count": len(http_records),
        "records": http_records[:500],
        "success": r["success"],
    }
    NETWORK_ANALYSES[analysis_id] = record
    return {"success": r["success"], "analysis": record, "raw": r}


def list_network_analyses() -> List[Dict[str, Any]]:
    return list(NETWORK_ANALYSES.values())


# ============================================================
# 日志取证
# ============================================================
def analyze_log_file(
    log_file: str,
    pattern: Optional[str] = None,
    top_n: int = 20,
    timeout: int = 60,
) -> Dict[str, Any]:
    """分析日志文件：错误统计 / 异常模式提取。"""
    if not os.path.exists(log_file):
        return {"success": False, "error": f"日志文件不存在: {log_file}"}

    # 读取日志文件
    try:
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"日志读取失败: {e}"}

    total_lines = len(lines)
    error_lines: List[str] = []
    warning_lines: List[str] = []
    ip_counts: Dict[str, int] = {}

    import re
    for line in lines:
        lower = line.lower()
        if any(kw in lower for kw in ["error", "fail", "critical", "fatal", "exception"]):
            error_lines.append(line.strip()[:500])
        if any(kw in lower for kw in ["warn", "notice"]):
            warning_lines.append(line.strip()[:500])
        # 提取 IP 地址
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        for ip in ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    # 如果指定了 pattern，过滤
    if pattern:
        error_lines = [l for l in error_lines if re.search(pattern, l, re.IGNORECASE)]
        warning_lines = [l for l in warning_lines if re.search(pattern, l, re.IGNORECASE)]

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

    analysis_id = f"log_{int(time.time())}"
    record = {
        "id": analysis_id,
        "log_file": log_file,
        "total_lines": total_lines,
        "error_count": len(error_lines),
        "warning_count": len(warning_lines),
        "top_errors": error_lines[:50],
        "top_warnings": warning_lines[:30],
        "top_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
        "analyzed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    LOG_ANALYSES[analysis_id] = record
    return {"success": True, "analysis": record}


def list_log_analyses() -> List[Dict[str, Any]]:
    return list(LOG_ANALYSES.values())
