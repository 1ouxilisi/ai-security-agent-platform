# -*- coding: utf-8 -*-
"""
smart_fallback.py — 外部工具不可用时的智能降级与提示。

每个外部工具对应一个纯 Python 原生替代方案；
记录每次降级事件；对外提供降级映射、功能差异与性能对比。
仅用于授权测试场景下的工具链降级决策。
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# 降级映射表：外部工具 -> Python 原生替代
# --------------------------------------------------------------------------- #
FALLBACK_MAP: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "python_impl": "socket 连接扫描 + banner 抓取",
        "deps": ["socket", "ipaddress", "re"],
        "notice": "当前使用 Python 原生扫描（nmap 未安装），扫描速度较慢，"
                  "且无法识别服务版本与操作系统指纹，建议安装 nmap 以获得更好体验。",
    },
    "masscan": {
        "python_impl": "asyncio + socket 异步端口扫描",
        "deps": ["asyncio", "socket"],
        "notice": "masscan 未安装，已切换到 asyncio 异步扫描，速率远低于 masscan。",
    },
    "zmap": {
        "python_impl": "scapy raw socket SYN 扫描",
        "deps": ["scapy"],
        "notice": "zmap 未安装，已使用 scapy 模拟 SYN 探测，需要 root 权限。",
    },
    "msfconsole": {
        "python_impl": "requests 调用 Exploit-DB 元数据 + 手工 payload 提示",
        "deps": ["requests"],
        "notice": "Metasploit 未安装，无法自动调用 exploit 模块，仅提供 CVE 检索与复现步骤。",
    },
    "sqlmap": {
        "python_impl": "requests + 正则注入探测（布尔/时间盲注）",
        "deps": ["requests", "re"],
        "notice": "sqlmap 未安装，已切换到 requests 基础注入检测，覆盖范围远小于 sqlmap。",
    },
    "nikto": {
        "python_impl": "requests 字典式敏感文件探测",
        "deps": ["requests"],
        "notice": "nikto 未安装，已切换到 Python 敏感路径探测，规则库较小。",
    },
    "wpscan": {
        "python_impl": "requests 枚举 WP 版本/插件/theme",
        "deps": ["requests", "re"],
        "notice": "wpscan 未安装，已切换到 requests 枚举，漏洞库未同步。",
    },
    "gobuster": {
        "python_impl": "requests + 字典目录爆破",
        "deps": ["requests", "concurrent.futures"],
        "notice": "gobuster 未安装，已切换到 Python 线程目录爆破，速度较慢。",
    },
    "dirb": {
        "python_impl": "requests + 字典目录爆破",
        "deps": ["requests"],
        "notice": "dirb 未安装，已切换到 Python 原生目录爆破。",
    },
    "dirsearch": {
        "python_impl": "requests + 字典目录爆破",
        "deps": ["requests"],
        "notice": "dirsearch 未安装，已切换到 Python 原生目录爆破。",
    },
    "hydra": {
        "python_impl": "socket + 字典协议暴力破解（SSH/FTP/HTTP 表单）",
        "deps": ["socket", "threading"],
        "notice": "hydra 未安装，已切换到 Python 多线程暴力破解，速率低且协议支持有限。",
    },
    "john": {
        "python_impl": "hashlib + 字典哈希比对",
        "deps": ["hashlib", "itertools"],
        "notice": "john 未安装，已切换到 Python 字典比对，不支持 GPU 加速。",
    },
    "hashcat": {
        "python_impl": "hashlib + 字典哈希比对",
        "deps": ["hashlib"],
        "notice": "hashcat 未安装，已切换到 CPU 纯 Python 字典比对，性能极差。",
    },
    "medusa": {
        "python_impl": "socket + 字典协议暴力破解",
        "deps": ["socket", "threading"],
        "notice": "medusa 未安装，已切换到 Python 多线程暴力破解。",
    },
    "aircrack-ng": {
        "python_impl": "scapy 捕获 + pyshark 解析（无法破解 WPA 握手）",
        "deps": ["scapy"],
        "notice": "aircrack-ng 未安装，仅能做抓包展示，无法完成 WEP/WPA 密钥破解。",
    },
    "airodump-ng": {
        "python_impl": "scapy 监听模式嗅探",
        "deps": ["scapy"],
        "notice": "airodump-ng 未安装，已切换到 scapy 被动嗅探。",
    },
    "aireplay-ng": {
        "python_impl": "scapy 手工构造 Deauth 帧",
        "deps": ["scapy"],
        "notice": "aireplay-ng 未安装，已切换到 scapy 手工构造注入帧。",
    },
    "kismet": {
        "python_impl": "scapy 被动监听汇总",
        "deps": ["scapy"],
        "notice": "kismet 未安装，仅能做基础 AP 列表汇总。",
    },
    "jadx": {
        "python_impl": "androguard + dex 解析",
        "deps": ["androguard"],
        "notice": "jadx 未安装，已切换到 androguard 反编译，可读性较差。",
    },
    "apktool": {
        "python_impl": "androguard 解包 + 资源抽取",
        "deps": ["androguard"],
        "notice": "apktool 未安装，已切换到 androguard，重打包能力有限。",
    },
    "frida": {
        "python_impl": "ctypes + ctypes 注入占位（无动态插桩）",
        "deps": ["ctypes"],
        "notice": "frida 未安装，动态插桩能力不可用。",
    },
    "objection": {
        "python_impl": "基于 frida 的脚本占位（不可用）",
        "deps": ["frida"],
        "notice": "objection 未安装，依赖 frida，动态探索不可用。",
    },
    "drozer": {
        "python_impl": "adb dumpsys 手工分析",
        "deps": ["subprocess", "adb"],
        "notice": "drozer 未安装，仅能通过 adb 手工导出组件信息。",
    },
    "ghidra": {
        "python_impl": "capstone 反汇编 + pefile/elftools 解析",
        "deps": ["capstone", "pefile"],
        "notice": "ghidra 未安装，已切换到 capstone 线性反汇编，无交叉引用分析。",
    },
    "r2": {
        "python_impl": "capstone 线性反汇编",
        "deps": ["capstone"],
        "notice": "radare2 未安装，已切换到 capstone 线性反汇编。",
    },
    "binwalk": {
        "python_impl": "python-lzma/zipfile/tarfile 递归识别",
        "deps": ["zipfile", "tarfile"],
        "notice": "binwalk 未安装，已切换到 Python 标准库递归解包，签名识别有限。",
    },
    "strings": {
        "python_impl": "re 扫描二进制可打印字符",
        "deps": ["re"],
        "notice": "strings 未安装，已切换到 Python 正则提取可打印串。",
    },
    "objdump": {
        "python_impl": "capstone 反汇编",
        "deps": ["capstone"],
        "notice": "objdump 未安装，已切换到 capstone 反汇编。",
    },
    "volatility": {
        "python_impl": "纯 Python 内存文件头部解析（功能极少）",
        "deps": ["struct"],
        "notice": "volatility 未安装，内存取证功能严重受限。",
    },
    "autopsy": {
        "python_impl": "命令行取证脚本集合占位",
        "deps": ["subprocess"],
        "notice": "autopsy 未安装，图形化取证界面不可用。",
    },
    "tshark": {
        "python_impl": "scapy/pyshark pcap 解析",
        "deps": ["scapy"],
        "notice": "tshark 未安装，已切换到 scapy pcap 解析。",
    },
    "wireshark": {
        "python_impl": "scapy pcap 解析",
        "deps": ["scapy"],
        "notice": "wireshark 未安装，图形化协议分析不可用。",
    },
    "docker": {
        "python_impl": "subprocess 调用 podman/containerd 占位",
        "deps": ["subprocess"],
        "notice": "docker 未安装，容器相关功能不可用。",
    },
    "docker-compose": {
        "python_impl": "subprocess 手工编排多容器占位",
        "deps": ["subprocess"],
        "notice": "docker-compose 未安装，多容器编排不可用。",
    },
    "kubectl": {
        "python_impl": "kubernetes client 库调用",
        "deps": ["kubernetes"],
        "notice": "kubectl 未安装，已切换到 kubernetes Python client。",
    },
    "trivy": {
        "python_impl": "调用 OSV/GHSA API 查询 CVE",
        "deps": ["requests"],
        "notice": "trivy 未安装，已切换到在线 CVE 查询，离线能力缺失。",
    },
    "helm": {
        "python_impl": "手动渲染 templates 目录占位",
        "deps": [],
        "notice": "helm 未安装，Chart 渲染能力不可用。",
    },
    "semgrep": {
        "python_impl": "正则 + AST 规则占位",
        "deps": ["ast", "re"],
        "notice": "semgrep 未安装，静态分析规则覆盖大幅下降。",
    },
    "sonar-scanner": {
        "python_impl": "ruff/bandit 规则集合占位",
        "deps": [],
        "notice": "sonar-scanner 未安装，已切换到本地 lint 工具集合。",
    },
    "gitleaks": {
        "python_impl": "正则密钥模式扫描 git history",
        "deps": ["re", "subprocess"],
        "notice": "gitleaks 未安装，已切换到正则密钥扫描，误报较高。",
    },
}


# --------------------------------------------------------------------------- #
# 功能差异对比（外部工具 vs Python 原生）
# --------------------------------------------------------------------------- #
DIFF_TABLE: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "external_features": [
            "TCP SYN/Connect/ACK 全系列扫描", "服务版本识别 (-sV)",
            "操作系统指纹识别 (-O)", "NSE 脚本引擎", "速率/时序精细控制",
        ],
        "python_features": [
            "TCP Connect 端口开放检测", "基础 banner 抓取",
        ],
        "accuracy_external": "高", "accuracy_python": "中（仅开放/关闭二值）",
        "speed_external": "快（数千包/秒）", "speed_python": "慢（几十连接/秒）",
        "resource_external": "低", "resource_python": "中（线程开销大）",
    },
    "sqlmap": {
        "external_features": [
            "布尔/时间/报错/联合/堆查询全类型", "二阶注入",
            "OS 命令执行 / 取数据 / 提权", "tamper 脚本绕过 WAF",
        ],
        "python_features": ["布尔盲注探测", "时间盲注探测", "基础错误回显提取"],
        "accuracy_external": "高", "accuracy_python": "低（规则覆盖窄）",
        "speed_external": "快（多线程）", "speed_python": "慢（串行请求）",
        "resource_external": "低", "resource_python": "中",
    },
    "hydra": {
        "external_features": [
            "50+ 协议", "动态分片", "会话管理",
        ],
        "python_features": ["SSH/FTP/HTTP 表单三类", "多线程字典"],
        "accuracy_external": "高", "accuracy_python": "中（协议易误判）",
        "speed_external": "快", "speed_python": "慢",
        "resource_external": "低", "resource_python": "中",
    },
    "gobuster": {
        "external_features": [
            "目录/DNS/vhost/S3 四种模式", "递归", "状态码过滤",
        ],
        "python_features": ["目录字典爆破", "状态码过滤"],
        "accuracy_external": "高", "accuracy_python": "高",
        "speed_external": "极快（Go 协程）", "speed_python": "慢（线程池）",
        "resource_external": "低", "resource_python": "中",
    },
}

# 默认性能对比（未单独列出的工具使用通用值）
DEFAULT_DIFF = {
    "external_features": ["完整专业功能集"],
    "python_features": ["基础核心功能"],
    "accuracy_external": "高", "accuracy_python": "中",
    "speed_external": "快", "speed_python": "慢",
    "resource_external": "低", "resource_python": "中",
}


# --------------------------------------------------------------------------- #
# 降级记录
# --------------------------------------------------------------------------- #
class FallbackRecorder:
    def __init__(self, max_records: int = 500) -> None:
        self._records: List[Dict[str, Any]] = []
        self._max = max_records
        self._lock = threading.Lock()
        self._trigger_count: Dict[str, int] = {}

    def record(self, tool: str, reason: str, alternative: str,
               context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        entry = {
            "id": len(self._records) + 1,
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tool": tool,
            "reason": reason,
            "alternative": alternative,
            "context": context or {},
        }
        with self._lock:
            self._records.append(entry)
            if len(self._records) > self._max:
                self._records = self._records[-self._max:]
            self._trigger_count[tool] = self._trigger_count.get(tool, 0) + 1
        logger.warning("FALLBACK: %s -> %s (%s)", tool, alternative, reason)
        return entry

    def list_records(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return list(reversed(self._records[-limit:]))

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total": len(self._records),
                "by_tool": dict(self._trigger_count),
                "recent": list(reversed(self._records[-10:])),
            }


_recorder = FallbackRecorder()


# --------------------------------------------------------------------------- #
# 对外接口
# --------------------------------------------------------------------------- #
def get_fallback_info(tool: str) -> Optional[Dict[str, Any]]:
    return FALLBACK_MAP.get(tool)


def get_all_mappings() -> Dict[str, Dict[str, Any]]:
    return FALLBACK_MAP


def get_diff(tool: str) -> Dict[str, Any]:
    info = FALLBACK_MAP.get(tool)
    diff = DIFF_TABLE.get(tool, DEFAULT_DIFF)
    return {
        "tool": tool,
        "python_impl": info["python_impl"] if info else DEFAULT_DIFF,
        **diff,
    }


def record_fallback(tool: str, reason: str = "not_installed",
                    context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    info = FALLBACK_MAP.get(tool)
    alt = info["python_impl"] if info else "纯 Python 占位"
    return _recorder.record(tool, reason, alt, context)


def list_records(limit: int = 100) -> List[Dict[str, Any]]:
    return _recorder.list_records(limit)


def fallback_stats() -> Dict[str, Any]:
    return _recorder.stats()


def performance_compare() -> List[Dict[str, Any]]:
    """外部工具 vs Python 原生性能对比摘要。"""
    out = []
    for tool, diff in DIFF_TABLE.items():
        out.append({
            "tool": tool,
            "speed_external": diff["speed_external"],
            "speed_python": diff["speed_python"],
            "accuracy_external": diff["accuracy_external"],
            "accuracy_python": diff["accuracy_python"],
            "resource_external": diff["resource_external"],
            "resource_python": diff["resource_python"],
        })
    return out
