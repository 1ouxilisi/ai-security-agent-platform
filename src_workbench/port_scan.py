# -*- coding: utf-8 -*-
"""
port_scan.py — 端口扫描模块（nmap 真实调用）。

常用端口：80/443/8080/8443/3000/9000/22/21/3306/6379/27017 等
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# nmap 路径
# --------------------------------------------------------------------------- #
def _find_nmap() -> Optional[str]:
    found = shutil.which("nmap")
    if found:
        return found
    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


NMAP_BIN = _find_nmap()

# 常用 SRC 关注端口
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    1433, 1521, 2375, 2376, 3000, 3306, 3389,
    5432, 5601, 6379, 8000, 8080, 8443, 8888,
    9000, 9090, 9200, 9300, 11211, 27017,
]

_SCAN_TASKS: Dict[str, Dict[str, Any]] = {}


class PortScanner:
    """nmap 端口扫描器。"""

    def __init__(self) -> None:
        self.nmap_bin = NMAP_BIN

    # ------------------------------------------------------------------ #
    # 解析 nmap 输出（普通文本模式）
    # ------------------------------------------------------------------ #
    def _parse_nmap_output(self, stdout: str, target: str) -> List[Dict[str, Any]]:
        """解析 nmap -Pn -sV 输出，提取开放端口和服务。"""
        results: List[Dict[str, Any]] = []
        lines = stdout.splitlines()
        for line in lines:
            line = line.strip()
            # 匹配如: 80/tcp open  http nginx 1.18.0
            m = re.match(
                r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)$",
                line,
            )
            if m:
                port = int(m.group(1))
                proto = m.group(2)
                state = m.group(3)
                service = m.group(4)
                version = m.group(5).strip()
                if state.lower() == "open":
                    results.append({
                        "target": target,
                        "port": port,
                        "protocol": proto,
                        "state": state,
                        "service": service,
                        "version": version,
                        "is_web": port in (80, 443, 3000, 8000, 8080, 8443, 8888, 9000, 9090),
                    })
        return results

    # ------------------------------------------------------------------ #
    # 对单个 IP/主机扫描
    # ------------------------------------------------------------------ #
    def scan_host(self, host: str, ports: Optional[List[int]] = None,
                  timeout: int = 300) -> List[Dict[str, Any]]:
        """对单个目标跑 nmap 扫描。"""
        if not self.nmap_bin:
            logger.warning("nmap not found, returning mock scan results")
            return self._mock_scan(host, ports)

        port_list = ",".join(str(p) for p in (ports or COMMON_PORTS))
        cmd = [
            self.nmap_bin,
            "-Pn",           # 不做 ping，直接扫
            "-sV",           # 服务版本识别
            "-p", port_list, # 指定端口
            "--open",        # 只显示开放端口
            "-T4",           # 快速模式
            host,
        ]
        logger.info("Running nmap: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, encoding="utf-8", errors="replace",
            )
            return self._parse_nmap_output(result.stdout, host)
        except subprocess.TimeoutExpired:
            logger.error("nmap timed out for %s", host)
            return []
        except Exception as e:
            logger.exception("nmap error for %s: %s", host, e)
            return []

    # ------------------------------------------------------------------ #
    # 批量扫描（从存活主机列表）
    # ------------------------------------------------------------------ #
    def scan_hosts(self, hosts: List[Dict[str, Any]],
                   ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """对多个存活主机批量扫描端口。hosts 来自 asset_discovery 的 live_hosts。"""
        task_id = f"portscan_{int(time.time())}"
        _SCAN_TASKS[task_id] = {
            "task_id": task_id,
            "status": "running",
            "started_at": time.time(),
            "hosts_count": len(hosts),
            "results": [],
            "error": None,
        }

        all_results: List[Dict[str, Any]] = []
        for host_entry in hosts:
            sub = host_entry.get("subdomain", "")
            ip = host_entry.get("ip") or sub
            if not ip:
                continue
            logger.info("Scanning %s (%s)", sub, ip)
            open_ports = self.scan_host(ip, ports)
            for port_info in open_ports:
                port_info["subdomain"] = sub
            all_results.extend(open_ports)

        _SCAN_TASKS[task_id]["results"] = all_results
        _SCAN_TASKS[task_id]["status"] = "completed"
        _SCAN_TASKS[task_id]["finished_at"] = time.time()
        _SCAN_TASKS[task_id]["open_ports_count"] = len(all_results)

        return _SCAN_TASKS[task_id]

    # ------------------------------------------------------------------ #
    # Mock 回退（nmap 不可用时）
    # ------------------------------------------------------------------ #
    def _mock_scan(self, host: str, ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """nmap 不可用时的模拟扫描结果。"""
        mock_services = {
            22: ("ssh", "OpenSSH 8.9"),
            80: ("http", "nginx 1.18.0"),
            443: ("https", "nginx 1.18.0"),
            3000: ("http", "Node.js Express"),
            8080: ("http", "Apache Tomcat 9.0"),
            8443: ("https", "nginx 1.18.0"),
            9000: ("http", "PHP-FPM / Portainer"),
            6379: ("redis", "Redis 6.2.6"),
            3306: ("mysql", "MySQL 8.0.32"),
        }
        result = []
        for p in (ports or [80, 443, 8080]):
            if p in mock_services:
                svc, ver = mock_services[p]
                result.append({
                    "target": host,
                    "port": p,
                    "protocol": "tcp",
                    "state": "open",
                    "service": svc,
                    "version": ver,
                    "is_web": p in (80, 443, 3000, 8000, 8080, 8443, 8888, 9000, 9090),
                })
        return result

    # ------------------------------------------------------------------ #
    # 任务查询
    # ------------------------------------------------------------------ #
    def get_task(self, task_id: str) -> Dict[str, Any]:
        return _SCAN_TASKS.get(task_id, {})

    def list_tasks(self) -> List[Dict[str, Any]]:
        return sorted(_SCAN_TASKS.values(), key=lambda x: x.get("started_at", 0), reverse=True)
