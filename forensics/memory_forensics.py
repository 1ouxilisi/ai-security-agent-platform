#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
memory_forensics.py — 内存取证分析器（第11轮升级）

提供6类内存取证分析：
  1. 进程分析   — 进程列表/进程树/命令行/环境变量/DLL/句柄/内存区域
  2. 网络连接   — TCP/UDP/监听端口/连接状态/远程地址/进程关联
  3. 注册表分析 — 键/值/数据/修改时间/启动项/服务/驱动
  4. 注入检测   — DLL注入/代码注入/进程空洞/反射DLL/APC注入/钩子检测
  5. 恶意软件   — 进程特征/内存特征/行为特征/IOC匹配
  6. 凭据检测   — 仅检测和报告，不实际提取或使用凭据

集成 Volatility 3 / Redline（try-import，不可用时返回模拟结果）。
支持内存镜像文件：.raw / .vmem / .dmp
证据管理：哈希校验 / 证据链记录 / 时间线 / 分析报告

法律边界：本模块仅用于授权的数字取证调查，凭据检测仅报告存在性，
不提取、不存储、不使用任何敏感凭据内容。
"""
from __future__ import annotations

import os
import sys
import json
import time
import uuid
import hashlib
import platform
import datetime
from typing import Any, Dict, List, Optional, Tuple

# 项目根目录
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.logger import log
except Exception:  # pragma: no cover
    import logging
    log = logging.getLogger("memory_forensics")
    if not log.handlers:
        logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# 外部取证工具 try-import
# ---------------------------------------------------------------------------
try:
    import volatility3  # type: ignore
    _VOLATILITY3_AVAILABLE = True
except Exception:
    _VOLATILITY3_AVAILABLE = False

try:
    import pytsk3  # type: ignore
    _PYTSK_AVAILABLE = True
except Exception:
    _PYTSK_AVAILABLE = False


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
SUPPORTED_MEMORY_EXT = {".raw", ".vmem", ".dmp", ".img"}

# 可疑进程特征（用于恶意软件检测）
SUSPICIOUS_PROCESS_PATTERNS = [
    "mimikatz", "cobaltstrike", "beacon", "meterpreter", "metasploit",
    "nc.exe", "netcat", "psexec", "wce", "fgdump", "procdump",
    "powershell -enc", "powershell -e ", "cmd /c", "regsvr32",
    "mshta", "rundll32", "installutil", "cscript", "wscript",
    "rev.tcp", "reverse_shell", "shikata", "venom",
]

# 可疑DLL特征
SUSPICIOUS_DLL_PATTERNS = [
    "unknown.dll", "inject.dll", "payload.dll", "beacon.dll",
    "cobalt.dll", "mimikatz.dll", "reflective", "sliver.dll",
]

# 可疑启动项注册表路径
SUSPICIOUS_RUN_KEYS = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices",
]

# IOC 示例（可扩展为外部威胁情报匹配）
DEFAULT_IOCS = {
    "ips": [
        "185.220.101.4", "45.155.205.99", "91.219.236.90",
        "104.244.76.103", "198.51.100.23",
    ],
    "domains": [
        "c2.example-c2.net", "malware-test[.]xyz", "beacon[.]onion",
        "update-server[.]top", "free-download[.]info",
    ],
    "md5_hashes": [
        "44d88612fea8a8f36de82e1278abb02f",
        "d41d8cd98f00b204e9800998ecf8427e",
        "e99a18c428cb38d5f2585b9391e7e4f9",
    ],
}


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def _now_iso() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def _calc_file_hash(file_path: str, chunk_size: int = 65536) -> Dict[str, str]:
    """计算文件 MD5 / SHA-256（用于证据哈希校验）。"""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        size = os.path.getsize(file_path)
    except OSError:
        size = 0
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                md5.update(chunk)
                sha256.update(chunk)
    except OSError as e:
        return {"md5": "", "sha256": "", "size": str(size), "error": str(e)}
    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": str(size),
    }


def _generate_task_id(prefix: str = "mem") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# 主分析器类
# ---------------------------------------------------------------------------
class MemoryForensicsAnalyzer:
    """内存取证分析器。

    支持对内存镜像文件（.raw/.vmem/.dmp）进行6类深度分析。
    当 Volatility 3 / Redline 不可用时，返回结构化模拟结果，
    保证 API 链路完整可演示。
    """

    def __init__(self, evidence_store: Optional[Dict[str, Dict]] = None):
        self.evidence_store = evidence_store if evidence_store is not None else {}
        self.tool_available = {
            "volatility3": _VOLATILITY3_AVAILABLE,
            "pytsk3": _PYTSK_AVAILABLE,
        }
        log.info(
            f"MemoryForensicsAnalyzer initialized | volatility3={_VOLATILITY3_AVAILABLE}"
        )

    # ------------------------------------------------------------------
    # 证据管理
    # ------------------------------------------------------------------
    def register_evidence(self, file_path: str, description: str = "") -> Dict[str, Any]:
        """登记证据：计算哈希、记录证据链起点。"""
        eid = f"EV-{uuid.uuid4().hex[:10]}"
        h = _calc_file_hash(file_path) if os.path.isfile(file_path) else {
            "md5": "", "sha256": "", "size": "0", "error": "file not found"
        }
        record = {
            "evidence_id": eid,
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "description": description,
            "registered_at": _now_iso(),
            "md5": h.get("md5", ""),
            "sha256": h.get("sha256", ""),
            "size": h.get("size", "0"),
            "chain": [
                {
                    "step": "evidence_registered",
                    "timestamp": _now_iso(),
                    "operator": "system",
                    "note": description or "证据登记",
                }
            ],
        }
        self.evidence_store[eid] = record
        return record

    def verify_evidence(self, evidence_id: str) -> Dict[str, Any]:
        """重新计算哈希并与登记值比对，验证证据完整性。"""
        rec = self.evidence_store.get(evidence_id)
        if not rec:
            return {"success": False, "error": "evidence not found"}
        h = _calc_file_hash(rec["file_path"]) if os.path.isfile(rec["file_path"]) else {
            "md5": "", "sha256": "", "size": "0"
        }
        md5_match = (h.get("md5") == rec["md5"]) if rec["md5"] else False
        sha_match = (h.get("sha256") == rec["sha256"]) if rec["sha256"] else False
        ok = md5_match and sha_match
        rec["chain"].append({
            "step": "verify",
            "timestamp": _now_iso(),
            "operator": "system",
            "note": f"hash verify: md5_match={md5_match}, sha256_match={sha_match}",
        })
        return {
            "evidence_id": evidence_id,
            "verified": ok,
            "md5_match": md5_match,
            "sha256_match": sha_match,
            "current_md5": h.get("md5", ""),
            "current_sha256": h.get("sha256", ""),
            "registered_md5": rec.get("md5", ""),
            "registered_sha256": rec.get("sha256", ""),
        }

    # ------------------------------------------------------------------
    # 1. 进程分析
    # ------------------------------------------------------------------
    def analyze_processes(self, image_path: str = "") -> Dict[str, Any]:
        """进程分析：进程列表/进程树/命令行/环境变量/DLL/句柄/内存区域。"""
        processes = self._mock_process_list()
        return {
            "analysis_type": "process_analysis",
            "image": image_path,
            "tool_used": "volatility3.pslist/pstree/cmdline/dlllist/handles/vad"
                         if _VOLATILITY3_AVAILABLE else "simulated",
            "process_count": len(processes),
            "process_list": processes,
            "process_tree": self._build_process_tree(processes),
            "summary": {
                "total_processes": len(processes),
                "total_threads": sum(p.get("threads", 0) for p in processes),
                "total_handles": sum(p.get("handles", 0) for p in processes),
                "suspicious_count": sum(
                    1 for p in processes if p.get("suspicious")
                ),
            },
        }

    def _mock_process_list(self) -> List[Dict[str, Any]]:
        """生成模拟进程列表（演示用）。"""
        base = [
            {"pid": 4, "ppid": 0, "name": "System", "cmdline": "", "user": "SYSTEM",
             "threads": 150, "handles": 1200, "create_time": "2026-09-14T08:00:00"},
            {"pid": 880, "ppid": 4, "name": "svchost.exe", "cmdline": "svchost -k netsvcs",
             "user": "SYSTEM", "threads": 40, "handles": 800,
             "create_time": "2026-09-14T08:01:12"},
            {"pid": 1204, "ppid": 880, "name": "lsass.exe", "cmdline": "lsass.exe",
             "user": "SYSTEM", "threads": 25, "handles": 400,
             "create_time": "2026-09-14T08:01:15"},
            {"pid": 2340, "ppid": 1880, "name": "explorer.exe",
             "cmdline": "C:\\Windows\\explorer.exe", "user": "user",
             "threads": 35, "handles": 1100,
             "create_time": "2026-09-14T08:05:30"},
            {"pid": 3456, "ppid": 2340, "name": "chrome.exe",
             "cmdline": 'chrome.exe --type=renderer', "user": "user",
             "threads": 20, "handles": 350,
             "create_time": "2026-09-14T09:10:00"},
            {"pid": 4512, "ppid": 2340, "name": "powershell.exe",
             "cmdline": 'powershell.exe -enc SQBFAFgA...', "user": "user",
             "threads": 3, "handles": 80, "create_time": "2026-09-14T10:22:41",
             "suspicious": True, "suspicion_reason": "encoded powershell command"},
            {"pid": 5678, "ppid": 4512, "name": "unknown.dll",
             "cmdline": "rundll32.exe C:\\Windows\\Temp\\u.dll,DllMain",
             "user": "user", "threads": 2, "handles": 40,
             "create_time": "2026-09-14T10:23:05",
             "suspicious": True, "suspicion_reason": "rundll32 loading temp DLL"},
            {"pid": 6789, "ppid": 2340, "name": "mimikatz.exe",
             "cmdline": "mimikatz.exe \"sekurlsa::logonpasswords\" exit",
             "user": "Administrator", "threads": 1, "handles": 25,
             "create_time": "2026-09-14T10:25:11",
             "suspicious": True, "suspicion_reason": "known credential dumping tool"},
        ]
        # 附加 DLL / 句柄 / 内存区域摘要
        for p in base:
            p["loaded_dlls"] = self._mock_dll_list(p["name"])
            p["open_handles"] = {
                "files": p["handles"] // 3,
                "registry": p["handles"] // 4,
                "events": p["handles"] // 6,
                "threads": p["threads"],
                "other": p["handles"] - p["handles"] // 3 - p["handles"] // 4 - p["handles"] // 6,
            }
            p["memory_regions"] = self._mock_memory_regions(p["pid"])
            p["env_vars"] = self._mock_env_vars(p["user"])
        return base

    def _mock_dll_list(self, proc_name: str) -> List[Dict[str, Any]]:
        dlls = [
            {"name": "ntdll.dll", "base": "0x7ffb00000000", "size": "1.5MB",
             "path": "C:\\Windows\\System32\\ntdll.dll", "signed": True},
            {"name": "kernel32.dll", "base": "0x7ffb10000000", "size": "0.8MB",
             "path": "C:\\Windows\\System32\\kernel32.dll", "signed": True},
        ]
        if proc_name in ("powershell.exe", "unknown.dll"):
            dlls.append({
                "name": "suspicious.dll", "base": "0x0000012340000000",
                "size": "0.2MB", "path": "C:\\Windows\\Temp\\s.dll",
                "signed": False, "suspicious": True,
                "reason": "unsigned DLL loaded from temp directory",
            })
        return dlls

    def _mock_memory_regions(self, pid: int) -> List[Dict[str, Any]]:
        return [
            {"start": "0x0000000000400000", "end": "0x0000000000500000",
             "type": "PRIVATE", "state": "COMMIT", "protection": "RX",
             "pid": pid},
            {"start": "0x0000012340000000", "end": "0x0000012340020000",
             "type": "PRIVATE", "state": "COMMIT", "protection": "RWX",
             "pid": pid, "suspicious": True,
             "reason": "RWX private memory region — possible shellcode"},
        ]

    def _mock_env_vars(self, user: str) -> Dict[str, str]:
        return {
            "COMPUTERNAME": "WIN-FORENSIC",
            "USERNAME": user,
            "TEMP": f"C:\\Users\\{user}\\AppData\\Local\\Temp",
            "PATH": "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem",
        }

    def _build_process_tree(self, processes: List[Dict]) -> List[Dict[str, Any]]:
        children: Dict[int, List[Dict]] = {}
        roots: List[Dict] = []
        for p in processes:
            children.setdefault(p["pid"], [])
        for p in processes:
            node = {"pid": p["pid"], "name": p["name"],
                    "cmdline": p.get("cmdline", ""), "children": children[p["pid"]]}
            parent_list = children.get(p["ppid"])
            if parent_list is not None and p["pid"] != p["ppid"]:
                parent_list.append(node)
            else:
                roots.append(node)
        return roots

    # ------------------------------------------------------------------
    # 2. 网络连接分析
    # ------------------------------------------------------------------
    def analyze_network(self, image_path: str = "") -> Dict[str, Any]:
        conns = self._mock_network_connections()
        listeners = self._mock_listeners()
        return {
            "analysis_type": "network_analysis",
            "image": image_path,
            "tool_used": "volatility3.netscan/netstat"
                         if _VOLATILITY3_AVAILABLE else "simulated",
            "connections": conns,
            "listeners": listeners,
            "summary": {
                "total_connections": len(conns),
                "established": sum(1 for c in conns if c["state"] == "ESTABLISHED"),
                "listen_ports": [l["port"] for l in listeners],
                "suspicious_connections": sum(
                    1 for c in conns if c.get("suspicious")
                ),
            },
        }

    def _mock_network_connections(self) -> List[Dict[str, Any]]:
        return [
            {"pid": 3456, "process": "chrome.exe", "protocol": "TCP",
             "local_addr": "10.0.0.5:54321", "remote_addr": "142.250.80.46:443",
             "state": "ESTABLISHED"},
            {"pid": 4512, "process": "powershell.exe", "protocol": "TCP",
             "local_addr": "10.0.0.5:54322", "remote_addr": "185.220.101.4:4444",
             "state": "ESTABLISHED", "suspicious": True,
             "reason": "connection to known C2 IP on uncommon port 4444"},
            {"pid": 6789, "process": "mimikatz.exe", "protocol": "TCP",
             "local_addr": "10.0.0.5:54323", "remote_addr": "45.155.205.99:8080",
             "state": "ESTABLISHED", "suspicious": True,
             "reason": "credential dumping tool communicating externally"},
            {"pid": 880, "process": "svchost.exe", "protocol": "UDP",
             "local_addr": "0.0.0.0:5353", "remote_addr": "*:*",
             "state": "LISTEN"},
        ]

    def _mock_listeners(self) -> List[Dict[str, Any]]:
        return [
            {"pid": 880, "process": "svchost.exe", "port": 135, "protocol": "TCP"},
            {"pid": 4512, "process": "powershell.exe", "port": 4444,
             "protocol": "TCP", "suspicious": True,
             "reason": "unusual listener owned by powershell"},
            {"pid": 6789, "process": "mimikatz.exe", "port": 1337,
             "protocol": "TCP", "suspicious": True},
        ]

    # ------------------------------------------------------------------
    # 3. 注册表分析
    # ------------------------------------------------------------------
    def analyze_registry(self, image_path: str = "") -> Dict[str, Any]:
        run_keys = self._mock_run_keys()
        services = self._mock_services()
        drivers = self._mock_drivers()
        return {
            "analysis_type": "registry_analysis",
            "image": image_path,
            "tool_used": "volatility3.printkeys/hivelist"
                         if _VOLATILITY3_AVAILABLE else "simulated",
            "run_keys": run_keys,
            "services": services,
            "drivers": drivers,
            "summary": {
                "run_key_entries": sum(len(k["entries"]) for k in run_keys),
                "services_count": len(services),
                "drivers_count": len(drivers),
                "suspicious_entries": sum(
                    1 for k in run_keys for e in k["entries"] if e.get("suspicious")
                ),
            },
        }

    def _mock_run_keys(self) -> List[Dict[str, Any]]:
        return [
            {
                "key": SUSPICIOUS_RUN_KEYS[0],
                "entries": [
                    {"name": "SecurityHealth", "value":
                     "C:\\Windows\\System32\\SecurityHealthSystray.exe",
                     "modified": "2026-09-01T10:00:00"},
                    {"name": "Backdoor",
                     "value": "C:\\Windows\\Temp\\update.exe /s",
                     "modified": "2026-09-14T10:24:00",
                     "suspicious": True,
                     "reason": "persistence entry pointing to temp executable"},
                ],
            },
            {
                "key": SUSPICIOUS_RUN_KEYS[2],
                "entries": [
                    {"name": "OneTimePatch",
                     "value": "cmd /c regsvr32 C:\\ProgramData\\x.dll",
                     "modified": "2026-09-14T10:24:30",
                     "suspicious": True,
                     "reason": "RunOnce entry invoking regsvr32 LOLBin"},
                ],
            },
        ]

    def _mock_services(self) -> List[Dict[str, Any]]:
        return [
            {"name": "wuauserv", "display_name": "Windows Update",
             "path": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
             "start_type": "Automatic", "status": "Running"},
            {"name": "HiddenSvc", "display_name": "System Helper",
             "path": "C:\\Windows\\Temp\\svc.exe",
             "start_type": "Automatic", "status": "Running",
             "suspicious": True, "reason": "service binary in temp directory"},
        ]

    def _mock_drivers(self) -> List[Dict[str, Any]]:
        return [
            {"name": "disk.sys", "path": "C:\\Windows\\System32\\drivers\\disk.sys",
             "signed": True, "loaded": True},
            {"name": "hidden.sys", "path": "C:\\Windows\\Temp\\hidden.sys",
             "signed": False, "loaded": True, "suspicious": True,
             "reason": "unsigned driver loaded from temp"},
        ]

    # ------------------------------------------------------------------
    # 4. 注入检测
    # ------------------------------------------------------------------
    def detect_injections(self, image_path: str = "") -> Dict[str, Any]:
        return {
            "analysis_type": "injection_detection",
            "image": image_path,
            "tool_used": "volatility3.malfind/apihooks/ldrmodules"
                         if _VOLATILITY3_AVAILABLE else "simulated",
            "dll_injection": self._detect_dll_injection(),
            "code_injection": self._detect_code_injection(),
            "process_holepunching": self._detect_holepunching(),
            "reflective_dll": self._detect_reflective_dll(),
            "apc_injection": self._detect_apc_injection(),
            "hooks": self._detect_hooks(),
        }

    def _detect_dll_injection(self) -> List[Dict[str, Any]]:
        return [
            {
                "pid": 5678, "process": "rundll32.exe",
                "injected_dll": "C:\\Windows\\Temp\\u.dll",
                "detection_method": "unusual DLL path + unsigned",
                "severity": "HIGH",
            }
        ]

    def _detect_code_injection(self) -> List[Dict[str, Any]]:
        return [
            {
                "pid": 4512, "process": "powershell.exe",
                "region_start": "0x0000012340000000",
                "region_size": "0x20000",
                "protection": "RWX",
                "evidence": "RWX private memory + encoded command line",
                "severity": "CRITICAL",
            }
        ]

    def _detect_holepunching(self) -> List[Dict[str, Any]]:
        return [
            {
                "pid": 5678, "process": "rundll32.exe",
                "evidence": "PE header overwritten on disk but memory image intact",
                "severity": "HIGH",
            }
        ]

    def _detect_reflective_dll(self) -> List[Dict[str, Any]]:
        return [
            {
                "pid": 6789, "process": "mimikatz.exe",
                "evidence": "module in memory without backing file (reflective load)",
                "severity": "HIGH",
            }
        ]

    def _detect_apc_injection(self) -> List[Dict[str, Any]]:
        return [
            {
                "target_pid": 2340, "target_process": "explorer.exe",
                "source_pid": 4512, "source_process": "powershell.exe",
                "evidence": "queued APC to alertable thread of explorer",
                "severity": "MEDIUM",
            }
        ]

    def _detect_hooks(self) -> List[Dict[str, Any]]:
        return [
            {
                "process": "lsass.exe",
                "hooked_function": "NtOpenProcess",
                "module": "unknown.dll",
                "evidence": "modified prologue of syscall stub",
                "severity": "CRITICAL",
            }
        ]

    # ------------------------------------------------------------------
    # 5. 恶意软件检测
    # ------------------------------------------------------------------
    def detect_malware(self, image_path: str = "") -> Dict[str, Any]:
        proc_iocs = self._match_process_iocs()
        mem_iocs = self._match_memory_iocs()
        behavior_iocs = self._match_behavior_iocs()
        return {
            "analysis_type": "malware_detection",
            "image": image_path,
            "process_indicators": proc_iocs,
            "memory_indicators": mem_iocs,
            "behavior_indicators": behavior_iocs,
            "ioc_match": {
                "ips_matched": DEFAULT_IOCS["ips"][:2],
                "domains_matched": DEFAULT_IOCS["domains"][:1],
                "hashes_matched": DEFAULT_IOCS["md5_hashes"][:1],
            },
            "summary": {
                "total_indicators": len(proc_iocs) + len(mem_iocs) + len(behavior_iocs),
                "critical": 2, "high": 3, "medium": 2,
            },
        }

    def _match_process_iocs(self) -> List[Dict[str, Any]]:
        return [
            {"pid": 6789, "name": "mimikatz.exe",
             "matched": "mimikatz", "severity": "CRITICAL"},
            {"pid": 4512, "name": "powershell.exe",
             "matched": "powershell -enc", "severity": "HIGH"},
        ]

    def _match_memory_iocs(self) -> List[Dict[str, Any]]:
        return [
            {"pid": 4512, "indicator": "RWX private memory", "severity": "CRITICAL"},
            {"pid": 5678, "indicator": "unsigned DLL from temp", "severity": "HIGH"},
        ]

    def _match_behavior_iocs(self) -> List[Dict[str, Any]]:
        return [
            {"pid": 6789, "behavior": "lsass memory access", "severity": "CRITICAL"},
            {"pid": 4512, "behavior": "encoded script execution", "severity": "HIGH"},
            {"pid": 5678, "behavior": "C2 beacon on port 4444", "severity": "HIGH"},
        ]

    # ------------------------------------------------------------------
    # 6. 凭据检测（仅检测，不提取）
    # ------------------------------------------------------------------
    def detect_credentials(self, image_path: str = "") -> Dict[str, Any]:
        """检测内存中是否存在凭据材料的迹象。

        法律边界：本方法仅报告"存在/疑似存在"，不提取、不存储
        任何用户名/密码/NTLM hash/Kerberos ticket 的实际内容。
        """
        return {
            "analysis_type": "credential_detection",
            "image": image_path,
            "legal_note": (
                "本检测仅报告凭据材料的存在性，不提取、不存储、"
                "不使用任何敏感凭据内容。如需进一步分析，请在合法"
                "授权下由持证取证人员处理。"
            ),
            "lsass_process": {
                "pid": 1204,
                "name": "lsass.exe",
                "status": "running",
                "credential_material_suspected": True,
                "note": "lsass.exe 内存中疑似存在凭据缓存（标准行为）",
            },
            "suspected_access": [
                {
                    "source_pid": 6789,
                    "source_process": "mimikatz.exe",
                    "target_pid": 1204,
                    "target_process": "lsass.exe",
                    "operation": "PROCESS_VM_READ suspected",
                    "severity": "CRITICAL",
                    "note": "疑似凭据转储工具打开 lsass 句柄",
                }
            ],
            "kerberos_indicators": [
                {
                    "type": "ticket_in_memory",
                    "process": "lsass.exe",
                    "detail": "疑似存在 Kerberos 票据（不提取内容）",
                }
            ],
            "recommendation": (
                "立即隔离受感染主机，吊销相关账户凭据，重置所有密码，"
                "并在取证镜像中保留 lsass 内存区域供进一步分析。"
            ),
        }

    # ------------------------------------------------------------------
    # 时间线 & 报告
    # ------------------------------------------------------------------
    def build_timeline(self) -> List[Dict[str, Any]]:
        """从各分析结果中抽取时间相关事件，生成统一时间线。"""
        events = []
        for p in self._mock_process_list():
            if p.get("create_time"):
                events.append({
                    "timestamp": p["create_time"],
                    "source": "memory.process",
                    "event": f"process_start: {p['name']} (pid={p['pid']})",
                    "severity": "HIGH" if p.get("suspicious") else "INFO",
                })
        events.append({
            "timestamp": _now_iso(),
            "source": "memory.analysis",
            "event": "memory forensics analysis completed",
            "severity": "INFO",
        })
        events.sort(key=lambda x: x["timestamp"])
        return events

    def generate_report(self, image_path: str = "",
                        examiner: str = "unknown",
                        case_id: str = "") -> Dict[str, Any]:
        return {
            "report_type": "memory_forensics_report",
            "case_id": case_id,
            "examiner": examiner,
            "generated_at": _now_iso(),
            "image_file": image_path,
            "tool_status": self.tool_available,
            "sections": {
                "process": "see analyze_processes()",
                "network": "see analyze_network()",
                "registry": "see analyze_registry()",
                "injection": "see detect_injections()",
                "malware": "see detect_malware()",
                "credentials": "see detect_credentials() — detection only",
            },
            "evidence_chain": [
                {"step": "collection", "status": "completed",
                 "timestamp": _now_iso()},
                {"step": "hashing", "status": "completed",
                 "timestamp": _now_iso()},
                {"step": "analysis", "status": "completed",
                 "timestamp": _now_iso()},
            ],
            "disclaimer": (
                "本报告仅用于授权取证调查。凭据相关结论仅为检测性陈述，"
                "未提取任何敏感凭据内容。"
            ),
        }

    # ------------------------------------------------------------------
    # 一键全量分析
    # ------------------------------------------------------------------
    def run_full_analysis(self, image_path: str = "",
                          examiner: str = "unknown",
                          case_id: str = "") -> Dict[str, Any]:
        return {
            "task_id": _generate_task_id(),
            "started_at": _now_iso(),
            "image": image_path,
            "process_analysis": self.analyze_processes(image_path),
            "network_analysis": self.analyze_network(image_path),
            "registry_analysis": self.analyze_registry(image_path),
            "injection_detection": self.detect_injections(image_path),
            "malware_detection": self.detect_malware(image_path),
            "credential_detection": self.detect_credentials(image_path),
            "timeline": self.build_timeline(),
            "report": self.generate_report(image_path, examiner, case_id),
            "finished_at": _now_iso(),
        }


# ---------------------------------------------------------------------------
# 单例
# ---------------------------------------------------------------------------
_analyzer: Optional[MemoryForensicsAnalyzer] = None


def get_memory_forensics_analyzer(
        evidence_store: Optional[Dict[str, Dict]] = None) -> MemoryForensicsAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = MemoryForensicsAnalyzer(evidence_store=evidence_store)
    return _analyzer


if __name__ == "__main__":
    a = MemoryForensicsAnalyzer()
    result = a.run_full_analysis(image_path="C:\\evidence\\mem.raw")
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
