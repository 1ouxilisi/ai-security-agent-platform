# -*- coding: utf-8 -*-
"""
nmap_deep.py — Nmap 深度集成模块（真实执行版 / P0-1 修复）。

核心原则（P0-1）：
- 所有扫描类 API 必须真实调用 nmap 命令（subprocess.run），禁止 mock。
- 通过 shutil.which + `nmap --version` 双重探测工具是否真正可用。
- 工具未安装或探测失败时，明确返回 {"success": False, "error": "工具未安装: nmap ..."}。
- 真实解析 nmap XML 输出（-oX -）：主机状态 / 端口状态 / 服务名称 / 服务版本 /
  操作系统 / NSE 脚本输出 / 跟踪路由。
- 全部 subprocess 调用带超时（默认 300 秒）。

设计定位：仅用于经过授权的网络安全评估与渗透测试环境。
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# 第三方库 try-import
# --------------------------------------------------------------------------- #
try:
    import xml.etree.ElementTree as ET  # noqa: F401
    _HAVE_XML = True
except Exception:  # pragma: no cover
    ET = None  # type: ignore
    _HAVE_XML = False


# --------------------------------------------------------------------------- #
# 常量定义
# --------------------------------------------------------------------------- #

SCAN_TYPES = {
    "syn": "-sS",
    "connect": "-sT",
    "udp": "-sU",
    "ack": "-sA",
    "window": "-sW",
    "maimon": "-sM",
    "null": "-sN",
    "fin": "-sF",
    "xmas": "-sX",
}

OUTPUT_FORMATS = {
    "xml": "-oX",
    "normal": "-oN",
    "grepable": "-oG",
    "all": "-oA",
}

NSE_CATEGORIES = [
    "auth", "broadcast", "brute", "default", "discovery",
    "dos", "exploit", "external", "fuzzer", "intrusive",
    "malware", "safe", "version", "vuln",
]

COMMON_NSE_SCRIPTS = {
    "http-enum": "HTTP枚举目录和文件",
    "http-title": "获取HTTP页面标题",
    "http-headers": "获取HTTP响应头",
    "ssl-cert": "获取SSL证书信息",
    "dns-brute": "DNS子域名暴力枚举",
    "smb-os-discovery": "SMB操作系统发现",
    "smb-enum-shares": "SMB共享枚举",
    "ftp-anon": "FTP匿名登录检测",
    "ssh-hostkey": "SSH主机密钥获取",
    "mysql-info": "MySQL服务器信息",
    "mongodb-info": "MongoDB信息枚举",
    "redis-info": "Redis信息获取",
    "vulners": "漏洞库查询",
    "vuln": "漏洞扫描脚本集合",
    "backdoor": "后门检测",
    "malware": "恶意软件检测",
}

RISK_LEVELS = {
    "critical": {"score": 9.0, "color": "#ff0000", "label": "严重"},
    "high": {"score": 7.0, "color": "#ff6600", "label": "高危"},
    "medium": {"score": 4.0, "color": "#ffcc00", "label": "中危"},
    "low": {"score": 1.0, "color": "#33cc33", "label": "低危"},
    "info": {"score": 0.1, "color": "#58a6ff", "label": "信息"},
}

DEFAULT_TIMEOUT = 300


# --------------------------------------------------------------------------- #
# 通用工具执行辅助
# --------------------------------------------------------------------------- #
def run_command(args: List[str], timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """真实执行命令并捕获 stdout/stderr/returncode。

    - 超时由调用方传入，默认 300s。
    - 返回结构化执行结果，永不抛异常（错误放入 result['error']）。
    """
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "timed_out": False,
            "error": None,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "returncode": -1,
            "stdout": (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""),
            "stderr": (e.stderr or b"").decode("utf-8", "replace") if isinstance(e.stderr, bytes) else (e.stderr or ""),
            "timed_out": True,
            "error": f"命令执行超时（>{timeout}s）",
        }
    except FileNotFoundError as e:
        return {"returncode": -1, "stdout": "", "stderr": "", "timed_out": False,
                "error": f"工具未找到: {e}"}
    except Exception as e:  # noqa: BLE001
        return {"returncode": -1, "stdout": "", "stderr": "", "timed_out": False,
                "error": f"命令执行异常: {e}"}


# --------------------------------------------------------------------------- #
# Nmap 命令构建器
# --------------------------------------------------------------------------- #
class NmapCommandBuilder:
    """真实构建 Nmap 命令行参数（列表形式，避免 shell 注入）。"""

    def __init__(self) -> None:
        self.args: List[str] = []
        self.targets: List[str] = []

    def reset(self) -> "NmapCommandBuilder":
        self.args = []
        self.targets = []
        return self

    def add_target(self, target: str) -> "NmapCommandBuilder":
        self.targets.append(target)
        return self

    def set_scan_type(self, scan_type: str) -> "NmapCommandBuilder":
        flag = SCAN_TYPES.get(scan_type.lower())
        if flag:
            self.args.append(flag)
        return self

    def set_port_range(self, ports: str) -> "NmapCommandBuilder":
        self.args.extend(["-p", ports])
        return self

    def set_version_detection(self) -> "NmapCommandBuilder":
        self.args.append("-sV")
        return self

    def set_os_detection(self) -> "NmapCommandBuilder":
        self.args.append("-O")
        return self

    def set_aggressive(self) -> "NmapCommandBuilder":
        self.args.append("-A")
        return self

    def set_timing_template(self, level: int) -> "NmapCommandBuilder":
        if 0 <= level <= 5:
            self.args.append(f"-T{level}")
        return self

    def set_script(self, script: str) -> "NmapCommandBuilder":
        self.args.extend(["--script", script])
        return self

    def set_script_args(self, args: str) -> "NmapCommandBuilder":
        self.args.extend(["--script-args", args])
        return self

    def set_host_discovery(self, method: str) -> "NmapCommandBuilder":
        methods = {"ping": "-PE", "arp": "-PR", "udp": "-PU",
                   "syn": "-PS", "ack": "-PA", "none": "-Pn"}
        flag = methods.get(method.lower())
        if flag:
            self.args.append(flag)
        return self

    def set_top_ports(self, count: int) -> "NmapCommandBuilder":
        self.args.extend(["--top-ports", str(count)])
        return self

    def set_traceroute(self) -> "NmapCommandBuilder":
        self.args.append("--traceroute")
        return self

    def set_host_timeout(self, seconds: int) -> "NmapCommandBuilder":
        self.args.extend(["--host-timeout", f"{seconds}s"])
        return self

    def build(self) -> str:
        return "nmap " + " ".join(self.args + self.targets)

    def build_args_list(self) -> List[str]:
        return self.args + self.targets


# --------------------------------------------------------------------------- #
# Nmap XML 解析器（真实解析 -oX - 输出）
# --------------------------------------------------------------------------- #
class NmapXMLParser:
    """解析真实 nmap XML 输出。解析失败返回空结构并带解析错误，绝不伪造数据。"""

    @staticmethod
    def parse(xml_content: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "scan_info": {},
            "hosts": [],
            "summary": {},
            "parse_error": None,
        }
        if not xml_content or not _HAVE_XML:
            result["parse_error"] = "XML内容为空或ElementTree不可用"
            return result
        try:
            root = ET.fromstring(xml_content)
            si = root.find("scaninfo")
            if si is not None:
                result["scan_info"] = dict(si.attrib)

            for host_el in root.findall("host"):
                host_data: Dict[str, Any] = {
                    "status": "unknown", "addresses": [], "hostnames": [],
                    "ports": [], "os": None, "traceroute": None, "scripts": [],
                }
                status_el = host_el.find("status")
                if status_el is not None:
                    host_data["status"] = status_el.attrib.get("state", "unknown")
                for addr in host_el.findall("address"):
                    host_data["addresses"].append(dict(addr.attrib))
                hns = host_el.find("hostnames")
                if hns is not None:
                    for hn in hns.findall("hostname"):
                        host_data["hostnames"].append(dict(hn.attrib))
                ports_el = host_el.find("ports")
                if ports_el is not None:
                    for port_el in ports_el.findall("port"):
                        port_data = dict(port_el.attrib)
                        st = port_el.find("state")
                        if st is not None:
                            port_data["state"] = st.attrib.get("state", "")
                        svc = port_el.find("service")
                        if svc is not None:
                            port_data["service"] = dict(svc.attrib)
                        for sc in port_el.findall("script"):
                            port_data.setdefault("scripts", []).append({
                                "id": sc.attrib.get("id", ""),
                                "output": sc.attrib.get("output", ""),
                            })
                        host_data["ports"].append(port_data)
                os_el = host_el.find("os")
                if os_el is not None:
                    os_data: Dict[str, Any] = {"matches": []}
                    for osm in os_el.findall("osmatch"):
                        match = dict(osm.attrib)
                        classes = [dict(osc.attrib) for osc in osm.findall("osclass")]
                        match["classes"] = classes
                        os_data["matches"].append(match)
                    host_data["os"] = os_data
                tr = host_el.find("trace")
                if tr is not None:
                    host_data["traceroute"] = {
                        "hops": [dict(h.attrib) for h in tr.findall("hop")]
                    }
                hs = host_el.find("hostscript")
                if hs is not None:
                    for sc in hs.findall("script"):
                        host_data["scripts"].append({
                            "id": sc.attrib.get("id", ""),
                            "output": sc.attrib.get("output", ""),
                        })
                result["hosts"].append(host_data)

            rs = root.find("runstats")
            if rs is not None:
                fin = rs.find("finished")
                if fin is not None:
                    result["summary"] = dict(fin.attrib)
        except Exception as e:  # noqa: BLE001
            logger.warning("nmap XML parse error: %s", e)
            result["parse_error"] = str(e)
        return result


# --------------------------------------------------------------------------- #
# Nmap 扫描器（真实执行）
# --------------------------------------------------------------------------- #
class NmapScanner:
    """真实调用 nmap。工具未安装时所有方法返回明确错误，绝不伪造结果。"""

    def __init__(self, nmap_path: str = "nmap") -> None:
        self.nmap_path = nmap_path
        self.available: bool = False
        self.version: str = ""
        self.probe_error: str = ""
        self.actual_path: str = ""
        self.last_scan_result: Dict[str, Any] = {}
        self._check_availability()

    # -- 可用性检测 --------------------------------------------------------- #
    def _check_availability(self) -> None:
        """真实探测：shutil.which + `nmap --version`。"""
        resolved = shutil.which(self.nmap_path)
        self.actual_path = resolved or self.nmap_path
        if not resolved:
            self.available = False
            self.probe_error = f"未在 PATH 中找到 {self.nmap_path}"
            return
        out = run_command([resolved, "--version"], timeout=30)
        text = (out["stdout"] + "\n" + out["stderr"]).strip()
        if out["returncode"] == 0 and "nmap version" in text.lower():
            self.available = True
            first = text.splitlines()[0] if text else ""
            self.version = first.replace("Nmap version", "").strip() or "unknown"
            self.probe_error = ""
        else:
            self.available = False
            self.probe_error = (text[:200] or out["error"] or "探测失败").strip()

    def is_available(self) -> bool:
        return self.available

    # -- 扫描执行 ----------------------------------------------------------- #
    def scan(self, targets: List[str], scan_type: str = "connect",
             ports: str = "1-1000", timing: int = 3,
             version_detection: bool = True, os_detection: bool = False,
             scripts: str = "", host_timeout: int = DEFAULT_TIMEOUT,
             extra_args: Optional[List[str]] = None,
             timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        """真实执行 nmap 扫描。默认 -sT（connect），避免 Windows 下 -sS 需要管理员权限。"""
        if not self.available:
            return {
                "success": False,
                "data": None,
                "error": f"工具未安装: nmap（{self.probe_error or 'nmap 不可用'}）",
            }

        builder = NmapCommandBuilder().reset()
        for t in targets:
            builder.add_target(t)
        builder.set_scan_type(scan_type)
        builder.set_port_range(ports)
        builder.set_timing_template(timing)
        if version_detection:
            builder.set_version_detection()
        if os_detection:
            builder.set_os_detection()
        if scripts:
            builder.set_script(scripts)
        builder.set_host_timeout(host_timeout)
        if extra_args:
            builder.args.extend(extra_args)

        # -oX - 输出 XML 到 stdout
        full_args = [self.actual_path] + builder.build_args_list() + ["-oX", "-"]
        command = builder.build()

        started = time.time()
        ex = run_command(full_args, timeout=timeout)
        duration = round(time.time() - started, 2)

        parsed = NmapXMLParser.parse(ex["stdout"])
        result = {
            "success": ex["returncode"] in (0, 1, 2) and not ex["timed_out"],
            "data": {
                "command": command,
                "parsed": parsed,
                "stderr": ex["stderr"][:2000],
                "returncode": ex["returncode"],
                "mode": "real",
                "timed_out": ex["timed_out"],
                "duration_sec": duration,
                "executed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "error": ex["error"],
        }
        if ex["timed_out"]:
            result["success"] = False
        self.last_scan_result = result
        return result


# --------------------------------------------------------------------------- #
# NSE 脚本管理
# --------------------------------------------------------------------------- #
class NSEScriptManager:
    def __init__(self) -> None:
        self.script_db: Dict[str, Dict[str, Any]] = {}
        self._load_builtin_scripts()

    def _load_builtin_scripts(self) -> None:
        for name, desc in COMMON_NSE_SCRIPTS.items():
            if name.startswith("http"):
                cats = ["discovery", "safe"]
            elif name.startswith("ssl"):
                cats = ["safe", "version"]
            elif name.startswith("smb"):
                cats = ["discovery", "safe"]
            elif name in ("vulners", "vuln"):
                cats = ["vuln", "safe"]
            else:
                cats = ["default", "safe"]
            self.script_db[name] = {
                "name": name, "description": desc, "categories": cats,
                "author": "nmap-dev", "type": "builtin",
            }

    def list_scripts(self, category: str = "") -> List[Dict[str, Any]]:
        if not category:
            return list(self.script_db.values())
        return [s for s in self.script_db.values() if category in s.get("categories", [])]

    def search_scripts(self, keyword: str) -> List[Dict[str, Any]]:
        kw = keyword.lower()
        return [s for s in self.script_db.values()
                if kw in s["name"].lower() or kw in s.get("description", "").lower()]


# --------------------------------------------------------------------------- #
# Nmap 报告生成器（基于真实解析结果，不伪造 CVE）
# --------------------------------------------------------------------------- #
class NmapReportGenerator:
    @staticmethod
    def generate(scan_result: Dict[str, Any], report_name: str = "") -> Dict[str, Any]:
        parsed = (scan_result.get("data") or scan_result.get("parsed") or {}).get("parsed", {}) \
            if scan_result.get("data") else scan_result.get("parsed", {})
        hosts = parsed.get("hosts", []) if isinstance(parsed, dict) else []

        port_list: List[Dict[str, Any]] = []
        service_list: List[Dict[str, Any]] = []
        os_list: List[Dict[str, Any]] = []
        script_findings: List[Dict[str, Any]] = []

        for host in hosts:
            addr = host.get("addresses", [{}])[0].get("addr", "") if host.get("addresses") else ""
            for port in host.get("ports", []):
                try:
                    port_id = int(port.get("portid", 0))
                except (TypeError, ValueError):
                    port_id = 0
                state = port.get("state", "")
                svc = port.get("service", {}) or {}
                service_list.append({
                    "host": addr, "port": port_id, "protocol": port.get("protocol", "tcp"),
                    "state": state, "name": svc.get("name", "unknown"),
                    "product": svc.get("product", ""), "version": svc.get("version", ""),
                })
                port_list.append({
                    "host": addr, "port": port_id, "protocol": port.get("protocol", "tcp"),
                    "state": state, "service": svc.get("name", "unknown"),
                })
                for sc in port.get("scripts", []):
                    script_findings.append({
                        "host": addr, "port": port_id, "script": sc.get("id", ""),
                        "output": sc.get("output", ""),
                    })
            for sc in host.get("scripts", []):
                script_findings.append({"host": addr, "port": 0,
                                        "script": sc.get("id", ""), "output": sc.get("output", "")})
            os_data = host.get("os")
            if os_data and os_data.get("matches"):
                best = os_data["matches"][0]
                os_list.append({"host": addr, "os_name": best.get("name", "Unknown"),
                                "accuracy": best.get("accuracy", "0")})

        open_ports = [p for p in port_list if p["state"] == "open"]
        risk = "critical" if len(open_ports) > 50 else \
               "high" if len(open_ports) > 20 else \
               "medium" if len(open_ports) > 5 else \
               "low" if open_ports else "info"

        return {
            "report_id": uuid.uuid4().hex[:12],
            "report_name": report_name or f"Nmap扫描报告_{time.strftime('%Y%m%d_%H%M%S')}",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mode": "real",
            "summary": {
                "hosts_up": len(hosts),
                "total_open_ports": len(open_ports),
                "total_services": len(service_list),
                "total_os_detected": len(os_list),
                "total_script_findings": len(script_findings),
                "risk_level": risk,
                "risk_label": RISK_LEVELS.get(risk, {}).get("label", "未知"),
            },
            "port_list": port_list,
            "service_list": service_list,
            "os_list": os_list,
            "script_findings": script_findings,
        }

    @staticmethod
    def export_report(report: Dict[str, Any], fmt: str = "json") -> str:
        if fmt == "csv":
            lines = ["host,port,protocol,state,service,product,version"]
            for svc in report.get("service_list", []):
                lines.append(f"{svc['host']},{svc['port']},{svc.get('protocol','tcp')},"
                             f"{svc.get('state','')},{svc.get('name','')},"
                             f"{svc.get('product','')},{svc.get('version','')}")
            return "\n".join(lines)
        return json.dumps(report, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------- #
# 工具管理
# --------------------------------------------------------------------------- #
class NmapToolManager:
    def __init__(self) -> None:
        self.config: Dict[str, Any] = {
            "nmap_path": "nmap", "default_timing": 3,
            "default_timeout": DEFAULT_TIMEOUT,
        }
        self.error_logs: List[Dict[str, Any]] = []

    def detect_version(self) -> Dict[str, Any]:
        scanner = NmapScanner(self.config["nmap_path"])
        return {
            "tool": "nmap", "available": scanner.available,
            "version": scanner.version, "path": scanner.actual_path,
            "probe_error": scanner.probe_error,
            "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def is_available(self) -> bool:
        return NmapScanner(self.config["nmap_path"]).available


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_nmap_scanner: Optional[NmapScanner] = None
_nse_manager: Optional[NSEScriptManager] = None
_report_gen: Optional[NmapReportGenerator] = None
_tool_mgr: Optional[NmapToolManager] = None


def get_scanner() -> NmapScanner:
    global _nmap_scanner
    if _nmap_scanner is None:
        _nmap_scanner = NmapScanner()
    return _nmap_scanner


def get_nse_manager() -> NSEScriptManager:
    global _nse_manager
    if _nse_manager is None:
        _nse_manager = NSEScriptManager()
    return _nse_manager


def get_report_generator() -> NmapReportGenerator:
    global _report_gen
    if _report_gen is None:
        _report_gen = NmapReportGenerator()
    return _report_gen


def get_tool_manager() -> NmapToolManager:
    global _tool_mgr
    if _tool_mgr is None:
        _tool_mgr = NmapToolManager()
    return _tool_mgr
