# -*- coding: utf-8 -*-
"""真实 Nmap 扫描：主机发现 / 端口扫描 / 服务识别，真实解析 XML 输出。"""
from __future__ import annotations

import os
import re
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from .runner import ToolRunner, detect_tool


class NmapReal:
    """全部通过真实 nmap 二进制执行，结果来自 XML 解析。"""

    def __init__(self, timeout: int = 300) -> None:
        self.runner = ToolRunner(timeout)

    # ---------- 内部工具 ----------
    def _parse_xml(self, xml_path: str) -> Dict[str, Any]:
        hosts: List[Dict[str, Any]] = []
        if not os.path.exists(xml_path):
            return {"hosts": [], "raw_xml": ""}
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except Exception as e:  # noqa: BLE001
            return {"hosts": [], "parse_error": str(e), "raw_xml": ""}

        run_stats = root.find("runstats")
        finished_el = root.find("runstats/finished")
        summary = finished_el.get("summary") if finished_el is not None else ""
        elapsed = finished_el.get("elapsed") if finished_el is not None else None

        for host in root.findall("host"):
            status_el = host.find("status")
            host_status = status_el.get("state") if status_el is not None else "unknown"
            addr_el = host.find("address")
            ip = addr_el.get("addr") if addr_el is not None else ""
            addr_type = addr_el.get("addrtype") if addr_el is not None else ""
            mac = ""
            hostnames = [h.get("name") for h in host.findall("hostnames/hostname")]
            for a in host.findall("address"):
                if a.get("addrtype") == "mac":
                    mac = a.get("addr", "")
            ports: List[Dict[str, Any]] = []
            extraports = []
            ep = host.find("ports/extraports")
            if ep is not None:
                extraports.append({"state": ep.get("state"), "count": ep.get("count")})
            for port in host.findall("ports/port"):
                proto = port.get("protocol", "")
                portid = port.get("portid", "")
                state_el = port.find("state")
                state = state_el.get("state") if state_el is not None else ""
                reason = state_el.get("reason") if state_el is not None else ""
                svc_el = port.find("service")
                name = svc_el.get("name") if svc_el is not None else ""
                product = svc_el.get("product") if svc_el is not None else ""
                version = svc_el.get("version") if svc_el is not None else ""
                extrainfo = svc_el.get("extrainfo") if svc_el is not None else ""
                cpe = [c.text for c in svc_el.findall("cpe")] if svc_el is not None else []
                scripts = []
                for se in port.findall("script"):
                    scripts.append({"id": se.get("id"), "output": se.get("output", "")})
                ports.append({
                    "port": int(portid) if portid.isdigit() else portid,
                    "protocol": proto,
                    "state": state,
                    "reason": reason,
                    "service": name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "cpe": cpe,
                    "scripts": scripts,
                })
            os_el = host.find("os")
            os_match = ""
            if os_el is not None:
                osm = os_el.find("osmatch")
                if osm is not None:
                    os_match = osm.get("name", "")
            hosts.append({
                "ip": ip,
                "addrtype": addr_type,
                "mac": mac,
                "hostnames": hostnames,
                "status": host_status,
                "ports": ports,
                "extraports": extraports,
                "os": os_match,
            })
        return {
            "hosts": hosts,
            "summary": summary,
            "elapsed": elapsed,
            "stats": run_stats.attrib if run_stats is not None else {},
        }

    def _run_nmap(self, args: List[str], timeout: Optional[int] = None) -> Dict[str, Any]:
        chk = self.runner.ensure("nmap")
        if not chk["success"]:
            return {"success": False, "data": None, "error": chk["error"]}
        tmp = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
        tmp.close()
        cmd = ["nmap", "-oX", tmp.name] + args
        res = self.runner.run(cmd, timeout=timeout)
        parsed = self._parse_xml(tmp.name)
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        return {
            "success": res["success"],
            "data": parsed,
            "error": res["stderr"] or None,
            "elapsed": res["elapsed"],
            "returncode": res["returncode"],
            "timed_out": res["timed_out"],
            "cmd": cmd,
        }

    # ---------- 对外能力 ----------
    def host_discovery(self, cidr: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """-sn 主机发现（不做端口扫描）。"""
        return self._run_nmap(["-sn", cidr], timeout=timeout)

    def port_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        technique: str = "sS",
        top_ports: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """端口扫描：-sS / -sT。"""
        args = [f"-{technique}", "-Pn"]
        if top_ports:
            args += ["--top-ports", str(top_ports)]
        if ports:
            args += ["-p", ports]
        args.append(target)
        return self._run_nmap(args, timeout=timeout)

    def service_version(self, target: str, ports: Optional[str] = None,
                        intensity: int = 7, timeout: Optional[int] = None) -> Dict[str, Any]:
        """服务/版本识别：-sV。"""
        args = ["-sV", f"--version-intensity", str(intensity), "-Pn"]
        if ports:
            args += ["-p", ports]
        args.append(target)
        return self._run_nmap(args, timeout=timeout)

    def os_detection(self, target: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """OS 识别（需要 root/管理员）。"""
        return self._run_nmap(["-O", "-Pn", target], timeout=timeout)

    def script_scan(self, target: str, scripts: str = "default",
                    ports: Optional[str] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
        """NSE 脚本扫描。"""
        args = ["-Pn", "--script", scripts]
        if ports:
            args += ["-p", ports]
        args.append(target)
        return self._run_nmap(args, timeout=timeout)

    def full_quick(self, target: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """快速综合扫描：top1000 端口 + 服务识别 + 默认脚本。"""
        return self._run_nmap(
            ["-sV", "-Pn", "--top-ports", "1000", "--script", "default", target],
            timeout=timeout,
        )
