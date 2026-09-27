# -*- coding: utf-8 -*-
"""iot_ics_real.py — 工控/IoT 做实模块。

真实工控协议分析：
    - Modbus 协议分析
    - S7 协议分析
    - 工控设备发现

真实 IoT 设备发现：
    - IoT 设备扫描
    - 常见 IoT 漏洞检测
    - 设备指纹识别
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import struct
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

# 内存存储
ICS_DISCOVERY_RECORDS: Dict[str, Dict[str, Any]] = {}
IoT_DISCOVERY_RECORDS: Dict[str, Dict[str, Any]] = {}
MODBUS_ANALYSES: Dict[str, Dict[str, Any]] = {}
S7_ANALYSES: Dict[str, Dict[str, Any]] = {}

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
    """检测工控/IoT 相关工具。"""
    tools = [
        "nmap", "masscan",  # 扫描
        "modbus-tcp-client", "mbpoll",  # Modbus
        "plcscan", "s7scan",  # S7 扫描
        "shodan",  # IoT 搜索
        "nuclei",  # 漏洞扫描
    ]
    result: Dict[str, Dict[str, Any]] = {}
    for t in tools:
        path = _which(t)
        result[t] = {"available": bool(path), "path": path}
    return result


# ============================================================
# Modbus TCP 协议分析
# ============================================================
# Modbus 功能码
MODBUS_FUNCTION_CODES: Dict[int, str] = {
    0x01: "读取线圈状态 (Read Coils)",
    0x02: "读取离散输入 (Read Discrete Inputs)",
    0x03: "读取保持寄存器 (Read Holding Registers)",
    0x04: "读取输入寄存器 (Read Input Registers)",
    0x05: "写单个线圈 (Write Single Coil)",
    0x06: "写单个寄存器 (Write Single Register)",
    0x0F: "写多个线圈 (Write Multiple Coils)",
    0x10: "写多个寄存器 (Write Multiple Registers)",
    0x11: "报告从站 ID (Report Slave ID)",
}

# Modbus 异常码
MODBUS_EXCEPTION_CODES: Dict[int, str] = {
    0x01: "非法功能 (Illegal Function)",
    0x02: "非法数据地址 (Illegal Data Address)",
    0x03: "非法数据值 (Illegal Data Value)",
    0x04: "从站设备故障 (Slave Device Failure)",
    0x05: "确认 (Acknowledge)",
    0x06: "从站设备忙 (Slave Device Busy)",
}


def modbus_read_holding_registers(
    host: str,
    port: int = 502,
    slave_id: int = 1,
    start_addr: int = 0,
    quantity: int = 10,
    timeout: int = 10,
) -> Dict[str, Any]:
    """通过 TCP socket 真实读取 Modbus 保持寄存器。"""
    # 构建 Modbus TCP 请求帧
    transaction_id = 0x0001
    protocol_id = 0x0000
    length = 6  # unit_id + func + addr + count
    unit_id = slave_id
    func_code = 0x03  # Read Holding Registers

    request = struct.pack(">HHHBBBBHH",
        transaction_id, protocol_id, length,
        unit_id, func_code,
        (start_addr >> 8) & 0xFF, start_addr & 0xFF,
        (quantity >> 8) & 0xFF, quantity & 0xFF,
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(request)
        response = sock.recv(1024)
        sock.close()

        if len(response) >= 9:
            trans_id, proto_id, resp_len, unit, func = struct.unpack(">HHHBB", response[:7])
            byte_count = response[8]
            values = []
            for i in range(byte_count // 2):
                offset = 9 + i * 2
                if offset + 1 < len(response):
                    val = struct.unpack(">H", response[offset:offset + 2])[0]
                    values.append(val)

            analysis_id = f"modbus_{int(time.time())}"
            record = {
                "id": analysis_id,
                "host": host,
                "port": port,
                "slave_id": slave_id,
                "start_address": start_addr,
                "quantity": quantity,
                "function_code": f"0x{func_code:02X}",
                "function_name": MODBUS_FUNCTION_CODES.get(func_code, "未知"),
                "register_values": values,
                "raw_response_hex": response.hex(),
                "success": True,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            MODBUS_ANALYSES[analysis_id] = record
            return {"success": True, "analysis": record}
        else:
            return {"success": False, "error": f"响应长度异常: {len(response)} 字节", "raw_hex": response.hex() if response else ""}
    except socket.timeout:
        return {"success": False, "error": f"连接超时 ({timeout}s)", "host": host, "port": port}
    except ConnectionRefusedError:
        return {"success": False, "error": "连接被拒绝（端口未开放）", "host": host, "port": port}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Modbus 通信异常: {e}"}


def modbus_scan_devices(cidr: str, port: int = 502, timeout: int = 5) -> Dict[str, Any]:
    """扫描网段内的 Modbus TCP 设备（端口 502 开放检测）。"""
    # 用 nmap 做端口扫描
    nm = _which("nmap")
    if nm:
        r = _run_cmd([nm, "-p", str(port), "--open", "-Pn", cidr, "-oG", "-"], timeout=120)
        devices: List[Dict[str, Any]] = []
        for line in r.get("stdout", "").splitlines():
            if "open" in line and port and "/open" in line:
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[1]
                    devices.append({"ip": ip, "port": port, "protocol": "modbus-tcp"})
        return {"success": r["success"], "devices_found": len(devices), "devices": devices, "scanner": "nmap"}
    else:
        # 退化：简单 socket 连接检测
        devices: List[Dict[str, Any]] = []
        # 解析 CIDR（简化版）
        parts = cidr.split("/")
        base_ip = parts[0]
        prefix = int(parts[1]) if len(parts) > 1 else 24
        ip_base = ".".join(base_ip.split(".")[:3])
        for i in range(1, min(255, 2 ** (32 - prefix))):
            ip = f"{ip_base}.{i}"
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    devices.append({"ip": ip, "port": port, "protocol": "modbus-tcp"})
            except Exception:
                pass
        return {"success": True, "devices_found": len(devices), "devices": devices, "scanner": "socket"}


def list_modbus_analyses() -> List[Dict[str, Any]]:
    return list(MODBUS_ANALYSES.values())


# ============================================================
# S7 协议分析（西门子 PLC）
# ============================================================
S7_COMMON_FUNCTIONS: List[Dict[str, Any]] = [
    {"code": "0x04", "name": "Read SZL", "description": "读取系统状态列表"},
    {"code": "0x01", "name": "Read Var", "description": "读取变量"},
    {"code": "0x05", "name": "Block Function", "description": "块函数调用"},
    {"code": "0x1A", "name": "CPU Status", "description": "CPU 状态读取"},
]


def s7_device_detect(host: str, port: int = 102, timeout: int = 10) -> Dict[str, Any]:
    """检测 S7 设备（通过 S7COMM 连接请求）。"""
    try:
        # S7COMM 连接请求 (COTP + S7COMM)
        # TPKT header
        tpkt = struct.pack(">!BBH", 3, 0, 22)  # version 3, reserved 0, length 22
        # COTP Connection Request
        cotp = struct.pack("!BBBBBB", 17, 224, 1, 0, 0, 240)  # len=17? Actually COTP CR
        # Simplified: send a basic S7 setup communication request
        # S7COMM Setup Communication
        s7_header = bytes([
            0x32,  # Protocol ID
            0x01,  # ROSCR = Job
            0x00, 0x00,  # Redundancy identification
            0x00, 0x01,  # PDU reference
            0x00, 0x00,  # Parameter length
            0x00, 0x00,  # Data length
            0xF0,  # Function = Setup Communication
            0x00,  # Reserved
            0x00, 0x01,  # Max AMQ 1
            0x00, 0x01,  # Max AMQ 2
            0x01, 0xE0,  # PDU length = 480
        ])

        full_packet = tpkt + cotp + s7_header

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(full_packet)
        response = sock.recv(1024)
        sock.close()

        is_s7 = False
        device_info: Dict[str, Any] = {}
        if len(response) >= 4 and response[0] == 0x03:
            # TPKT valid
            if len(response) >= 10 and response[5] == 0x32:
                is_s7 = True
                # Try to extract ROSCR type
                device_info["protocol"] = "S7COMM"
                device_info["tpkt_valid"] = True

        analysis_id = f"s7_{int(time.time())}"
        record = {
            "id": analysis_id,
            "host": host,
            "port": port,
            "is_s7_device": is_s7,
            "device_info": device_info,
            "raw_response_hex": response.hex() if response else "",
            "success": True,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        S7_ANALYSES[analysis_id] = record
        return {"success": True, "analysis": record}

    except socket.timeout:
        return {"success": False, "error": f"连接超时 ({timeout}s)", "host": host, "port": port}
    except ConnectionRefusedError:
        return {"success": False, "error": "连接被拒绝（端口102未开放）", "host": host, "port": port}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"S7 检测异常: {e}"}


def list_s7_analyses() -> List[Dict[str, Any]]:
    return list(S7_ANALYSES.values())


# ============================================================
# 工控设备发现
# ============================================================
ICS_PORTS: Dict[int, str] = {
    102: "S7comm (Siemens)",
    502: "Modbus TCP",
    20000: "DNP3",
    2404: "IEC 60870-5-104",
    44818: "EtherNet/IP",
    50100: "Siemens S7",
    18245: "GE SRTP",
    1911: "Tridium Fox",
    47808: "BACnet/IP",
}


def discover_ics_devices(cidr: str, timeout: int = 120) -> Dict[str, Any]:
    """扫描网段内的工控设备（检测常见工控端口）。"""
    nm = _which("nmap")
    ports_str = ",".join(str(p) for p in ICS_PORTS.keys())

    if nm:
        r = _run_cmd([nm, "-p", ports_str, "--open", "-Pn", "-sV", cidr, "-oG", "-"], timeout=timeout)
        devices: List[Dict[str, Any]] = []
        for line in r.get("stdout", "").splitlines():
            if "open" not in line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[1]
                open_ports = []
                for p in ICS_PORTS:
                    if f"{p}/open" in line or f"{p}/tcp/open" in line:
                        open_ports.append({"port": p, "protocol": ICS_PORTS[p]})
                if open_ports:
                    devices.append({"ip": ip, "open_ics_ports": open_ports})
    else:
        # 简化 socket 扫描
        devices = []
        parts = cidr.split("/")
        base_ip = parts[0]
        ip_base = ".".join(base_ip.split(".")[:3])
        for i in range(1, min(255, 2 ** (32 - int(parts[1] if len(parts) > 1 else 24)))):
            ip = f"{ip_base}.{i}"
            open_ports = []
            for port, proto_name in ICS_PORTS.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    if result == 0:
                        open_ports.append({"port": port, "protocol": proto_name})
                except Exception:
                    pass
            if open_ports:
                devices.append({"ip": ip, "open_ics_ports": open_ports})

    record_id = f"ics_disc_{int(time.time())}"
    record = {
        "id": record_id,
        "cidr": cidr,
        "devices_found": len(devices),
        "devices": devices,
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    ICS_DISCOVERY_RECORDS[record_id] = record
    return {"success": True, "discovery": record}


def list_ics_discoveries() -> List[Dict[str, Any]]:
    return list(ICS_DISCOVERY_RECORDS.values())


# ============================================================
# IoT 设备发现与漏洞检测
# ============================================================
COMMON_IOT_PORTS: Dict[int, str] = {
    23: "Telnet (IoT 设备常见)",
    80: "HTTP (Web 管理界面)",
    443: "HTTPS",
    554: "RTSP (摄像头)",
    1883: "MQTT",
    8883: "MQTT over TLS",
    5683: "CoAP",
    9100: "打印机 RAW",
    6668: "IRC (IoT 僵尸网络)",
}

COMMON_IOT_VULNS: List[Dict[str, Any]] = [
    {"cve": "CVE-2023-23397", "device_type": "Microsoft Outlook", "severity": "critical", "description": "Outlook 远程代码执行"},
    {"cve": "CVE-2021-27219", "device_type": "glibc", "severity": "high", "description": "glibc 堆缓冲区溢出"},
    {"cve": "CVE-2020-10263", "device_type": "IoT 摄像头", "severity": "high", "description": "摄像头硬编码密码"},
    {"cve": "CVE-2018-10561", "device_type": "Dasan GPON", "severity": "critical", "description": "GPON 路由器认证绕过"},
    {"cve": "CVE-2021-20090", "device_type": "Archer A7", "severity": "critical", "description": "路由器认证绕过"},
]


def discover_iot_devices(cidr: str, timeout: int = 120) -> Dict[str, Any]:
    """扫描网段内的 IoT 设备。"""
    nm = _which("nmap")
    ports_str = ",".join(str(p) for p in COMMON_IOT_PORTS.keys())

    if nm:
        r = _run_cmd([nm, "-p", ports_str, "--open", "-Pn", "-sV", cidr, "-O", "-oG", "-"], timeout=timeout)
        devices: List[Dict[str, Any]] = []
        # 简化解析
        current_ip = None
        for line in r.get("stdout", "").splitlines():
            if line.startswith("Host:") and "Ports:" in line:
                parts = line.split()
                if len(parts) >= 2:
                    current_ip = parts[1]
                    open_ports = []
                    for p in COMMON_IOT_PORTS:
                        if f"{p}/open" in line:
                            open_ports.append({"port": p, "service": COMMON_IOT_PORTS[p]})
                    if open_ports:
                        devices.append({"ip": current_ip, "open_ports": open_ports, "device_type": "unknown"})
    else:
        devices = []
        parts = cidr.split("/")
        base_ip = parts[0]
        ip_base = ".".join(base_ip.split(".")[:3])
        for i in range(1, min(255, 2 ** (32 - int(parts[1] if len(parts) > 1 else 24)))):
            ip = f"{ip_base}.{i}"
            open_ports = []
            for port, svc in COMMON_IOT_PORTS.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    if result == 0:
                        open_ports.append({"port": port, "service": svc})
                except Exception:
                    pass
            if open_ports:
                devices.append({"ip": ip, "open_ports": open_ports, "device_type": "unknown"})

    record_id = f"iot_disc_{int(time.time())}"
    record = {
        "id": record_id,
        "cidr": cidr,
        "devices_found": len(devices),
        "devices": devices,
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    IoT_DISCOVERY_RECORDS[record_id] = record
    return {"success": True, "discovery": record}


def iot_device_fingerprint(ip: str, port: int = 80, timeout: int = 10) -> Dict[str, Any]:
    """通过 HTTP Banner 识别 IoT 设备指纹。"""
    try:
        import urllib.request
        url = f"http://{ip}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (IoT Scanner)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = dict(resp.headers)
            body = resp.read(4096).decode("utf-8", errors="replace")
            server = headers.get("Server", "")
            www_auth = headers.get("WWW-Authenticate", "")

            # 指纹匹配
            fingerprints: List[str] = []
            server_lower = server.lower()
            body_lower = body.lower()

            if "apache" in server_lower:
                fingerprints.append("Apache Web Server")
            if "nginx" in server_lower:
                fingerprints.append("Nginx Web Server")
            if "boa" in server_lower or "goahead" in server_lower:
                fingerprints.append("Embedded Web Server (Boa/GoAhead)")
            if "lighttpd" in server_lower:
                fingerprints.append("Lighttpd (Embedded)")
            if "camera" in body_lower or "hikvision" in body_lower:
                fingerprints.append("Hikvision Camera")
            if "dahua" in body_lower:
                fingerprints.append("Dahua Camera")
            if "router" in body_lower:
                fingerprints.append("Router")
            if "login" in body_lower or "password" in body_lower:
                fingerprints.append("Web Login Interface")

            return {
                "success": True,
                "ip": ip,
                "port": port,
                "server_header": server,
                "www_authenticate": www_auth,
                "fingerprints": fingerprints,
                "title": re.search(r"<title>(.*?)</title>", body, re.IGNORECASE).group(1) if re.search(r"<title>(.*?)</title>", body, re.IGNORECASE) else "",
            }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"指纹识别失败: {e}", "ip": ip, "port": port}


def list_common_iot_vulns() -> List[Dict[str, Any]]:
    """列出常见 IoT 设备已知漏洞。"""
    return COMMON_IOT_VULNS


def list_iot_discoveries() -> List[Dict[str, Any]]:
    return list(IoT_DISCOVERY_RECORDS.values())
