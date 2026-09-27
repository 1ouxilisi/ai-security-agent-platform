# -*- coding: utf-8 -*-
"""
device_discovery.py — IoT设备发现与指纹识别器（第12轮升级）。

功能：
- 主动扫描：常见IoT端口扫描与服务识别
- 被动监听：网络流量被动识别IoT设备
- MAC OUI识别：基于MAC地址前3字节识别厂商（内置50+常见IoT厂商OUI库）
- 设备类型识别：摄像头/路由器/智能音箱/智能家居/工业网关/可穿戴等
- 设备指纹：IP/MAC/厂商/型号/固件版本/开放端口/运行服务/操作系统
- 设备分类与风险评级

说明：第三方库（scapy等）用try-import，不可用时返回模拟数据。
仅用于授权安全评估。
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    import scapy.all as scapy  # type: ignore
    _SCAPY_OK = True
except Exception:  # pragma: no cover
    scapy = None  # type: ignore
    _SCAPY_OK = False


# ==================== 常量库 ====================

# 常见IoT端口 -> (服务名, 协议, 默认风险)
IOT_COMMON_PORTS: Dict[int, Dict[str, Any]] = {
    21:   {"service": "FTP",          "proto": "tcp",  "risk": "high",   "desc": "文件传输协议，常被用于固件更新或配置上传"},
    22:   {"service": "SSH",         "proto": "tcp",  "risk": "medium", "desc": "安全Shell远程管理"},
    23:   {"service": "Telnet",      "proto": "tcp",  "risk": "critical", "desc": "明文远程终端，IoT设备高发风险点"},
    53:   {"service": "DNS",         "proto": "udp/tcp", "risk": "medium", "desc": "DNS服务，可能被用于DNS隧道"},
    69:   {"service": "TFTP",        "proto": "udp",  "risk": "high",   "desc": "简单文件传输，常用于固件恢复"},
    80:   {"service": "HTTP",        "proto": "tcp",  "risk": "high",   "desc": "Web管理界面"},
    443:  {"service": "HTTPS",       "proto": "tcp",  "risk": "medium", "desc": "加密Web管理界面"},
    554:  {"service": "RTSP",        "proto": "tcp",  "risk": "high",   "desc": "实时流协议，摄像头流媒体"},
    161:  {"service": "SNMP",        "proto": "udp",  "risk": "high",   "desc": "简单网络管理，默认community风险"},
    1883: {"service": "MQTT",        "proto": "tcp",  "risk": "high",   "desc": "MQTT消息 broker"},
    8883: {"service": "MQTT-TLS",    "proto": "tcp",  "risk": "medium", "desc": "TLS加密MQTT"},
    5683: {"service": "CoAP",        "proto": "udp",  "risk": "high",   "desc": "受限应用协议"},
    5684: {"service": "CoAP-DTLS",   "proto": "udp",  "risk": "medium", "desc": "DTLS加密CoAP"},
    502:  {"service": "Modbus-TCP",  "proto": "tcp",  "risk": "critical", "desc": "工业Modbus协议，无认证"},
    102:  {"service": "S7comm",      "proto": "tcp",  "risk": "critical", "desc": "西门子S7 PLC通信"},
    2404: {"service": "IEC104",      "proto": "tcp",  "risk": "high",   "desc": "电力远动规约"},
    1900: {"service": "SSDP/UPnP",   "proto": "udp",  "risk": "high",   "desc": "SSDP服务发现"},
    5353: {"service": "mDNS",        "proto": "udp",  "risk": "low",    "desc": "组播DNS服务发现"},
    8080: {"service": "HTTP-Alt",    "proto": "tcp",  "risk": "high",   "desc": "备用HTTP管理端口"},
    8443: {"service": "HTTPS-Alt",   "proto": "tcp",  "risk": "medium", "desc": "备用HTTPS管理端口"},
    8181: {"service": "HTTP-Debug", "proto": "tcp",  "risk": "critical", "desc": "调试/监控Web接口"},
    9000: {"service": "Portainer/调试", "proto": "tcp", "risk": "high", "desc": "容器管理或调试端口"},
    47808: {"service": "BACnet",     "proto": "udp",  "risk": "high",   "desc": "楼宇自动化协议"},
    44818: {"service": "EtherNet/IP", "proto": "tcp",  "risk": "high",   "desc": "工业以太网/IP"},
    5500: {"service": "VNC",         "proto": "tcp",  "risk": "critical", "desc": "远程桌面，弱认证高发"},
    6668: {"service": "IRC/IoT-C2",  "proto": "tcp",  "risk": "critical", "desc": "可疑C2端口"},
    27015: {"service": "SRCDS/IoT",  "proto": "udp",  "risk": "medium", "desc": "游戏/IoT控制端口"},
}

# MAC OUI 厂商库（前3字节 -> 厂商），覆盖50+常见IoT厂商
MAC_OUI_VENDORS: Dict[str, str] = {
    "00:0D:4B": "Axis Communications",
    "00:40:8C": "Cisco Systems",
    "00:01:42": "Cisco-Linksys",
    "00:06:25": "Cisco-Linksys",
    "00:13:10": "Cisco-Linksys",
    "00:1A:70": "Netgear",
    "00:1E:2A": "Netgear",
    "00:27:19": "Netgear",
    "00:0F:B5": "D-Link",
    "00:13:46": "D-Link",
    "00:15:E9": "D-Link",
    "00:17:9A": "D-Link",
    "00:50:BA": "D-Link",
    "00:0C:42": "TP-Link",
    "00:14:78": "TP-Link",
    "00:1D:0F": "TP-Link",
    "00:25:86": "TP-Link",
    "00:27:19": "TP-Link",
    "00:60:64": "TP-Link",
    "14:E6:E4": "TP-Link",
    "1C:61:B4": "TP-Link",
    "50:C7:BF": "TP-Link",
    "00:0E:08": "ASUSTek Computer",
    "00:11:2F": "ASUSTek Computer",
    "00:13:D4": "ASUSTek Computer",
    "00:14:85": "ASUSTek Computer",
    "00:15:F2": "ASUSTek Computer",
    "00:16:CF": "ASUSTek Computer",
    "00:17:31": "ASUSTek Computer",
    "00:18:3F": "ASUSTek Computer",
    "00:90:4C": "Huawei",
    "00:E0:FC": "Huawei",
    "00:25:9E": "Huawei",
    "0C:96:E6": "Huawei",
    "34:6B:D3": "Huawei",
    "48:7B:6B": "Huawei",
    "A4:C2:49": "Xiaomi",
    "64:09:80": "Xiaomi",
    "F0:B4:29": "Xiaomi",
    "FC:64:BA": "Xiaomi",
    "00:40:8C": "Hikvision",
    "3C:EF:8C": "Hikvision",
    "4C:11:BF": "Hikvision",
    "54:E1:AD": "Hikvision",
    "C0:A0:BA": "Hikvision",
    "00:0C:76": "Dahua Technology",
    "3C:E3:6B": "Dahua Technology",
    "44:14:CF": "Dahua Technology",
    "D4:6E:0E": "Dahua Technology",
    "E0:50:8B": "Dahua Technology",
    "00:0B:81": "Bosch Security Systems",
    "00:19:4B": "Samsung Techwin",
    "00:16:6C": "Sony",
    "00:13:14": "Panasonic",
    "00:80:F0": "Apple (HomeKit)",
    "00:17:88": "Apple",
    "AC:DE:48": "Apple",
    "F0:18:98": "Apple",
    "00:1A:7D": "Espressif (ESP8266/ESP32)",
    "24:6F:28": "Espressif (ESP8266/ESP32)",
    "2E:3A:E8": "Espressif (ESP8266/ESP32)",
    "30:AE:A4": "Espressif (ESP8266/ESP32)",
    "40:91:51": "Espressif (ESP8266/ESP32)",
    "48:3F:DA": "Espressif (ESP8266/ESP32)",
    "5C:CF:7F": "Espressif (ESP8266/ESP32)",
    "60:01:94": "Espressif (ESP8266/ESP32)",
    "84:0D:8E": "Espressif (ESP8266/ESP32)",
    "8C:AA:B5": "Espressif (ESP8266/ESP32)",
    "94:B5:55": "Espressif (ESP8266/ESP32)",
    "A0:20:A6": "Espressif (ESP8266/ESP32)",
    "A4:7B:9D": "Espressif (ESP8266/ESP32)",
    "A8:03:2A": "Espressif (ESP8266/ESP32)",
    "A8:48:FA": "Espressif (ESP8266/ESP32)",
    "AC:67:B2": "Espressif (ESP8266/ESP32)",
    "B4:E6:2D": "Espressif (ESP8266/ESP32)",
    "BC:DD:C2": "Espressif (ESP8266/ESP32)",
    "C4:4F:33": "Espressif (ESP8266/ESP32)",
    "CC:50:E3": "Espressif (ESP8266/ESP32)",
    "D8:A0:1D": "Espressif (ESP8266/ESP32)",
    "DC:54:75": "Espressif (ESP8266/ESP32)",
    "E8:68:E7": "Espressif (ESP8266/ESP32)",
    "EC:62:60": "Espressif (ESP8266/ESP32)",
    "F4:CF:A2": "Espressif (ESP8266/ESP32)",
    "F8:FF:C2": "Espressif (ESP8266/ESP32)",
    "FC:F5:C4": "Espressif (ESP8266/ESP32)",
    "00:17:88": "Amazon (Echo/Alexa)",
    "44:65:0D": "Amazon",
    "68:54:FD": "Amazon",
    "74:75:48": "Amazon",
    "84:D6:d0": "Amazon",
    "B0:BE:76": "Amazon",
    "F0:7D:68": "Amazon",
    "00:17:88": "Google Nest",
    "54:60:09": "Google",
    "64:16:66": "Google",
    "94:65:2D": "Google",
    "A4:77:33": "Google",
    "F8:8F:CA": "Google",
    "00:04:4B": "Schneider Electric",
    "00:60:6E": "Schneider Electric",
    "00:0C:01": "Siemens",
    "08:00:06": "Siemens",
    "00:08:DC": "Siemens",
    "00:1A:7E": "ABB",
    "00:01:96": "Rockwell Automation",
    "00:00:BC": "Rockwell",
    "00:09:63": "Omron",
    "00:00:00": "未分配/未知",
}

# 设备类型指纹：基于开放端口组合推断
DEVICE_TYPE_RULES: List[Dict[str, Any]] = [
    {
        "type": "IP摄像头",
        "icon": "📹",
        "match_ports": [554, 80, 8080],
        "any_ports": [554, 8554],
        "vendor_hint": ["Hikvision", "Dahua", "Axis", "Bosch", "Samsung", "Sony", "Panasonic"],
    },
    {
        "type": "网络路由器",
        "icon": "📡",
        "match_ports": [80, 443, 22, 23],
        "any_ports": [7547],
        "vendor_hint": ["Cisco", "Netgear", "TP-Link", "D-Link", "ASUS", "Linksys", "Huawei"],
    },
    {
        "type": "智能音箱",
        "icon": "🔊",
        "match_ports": [5353, 443],
        "any_ports": [1900],
        "vendor_hint": ["Amazon", "Google", "Xiaomi", "Apple"],
    },
    {
        "type": "智能家居网关",
        "icon": "🏠",
        "match_ports": [1883, 5353, 8080],
        "any_ports": [5683, 8883],
        "vendor_hint": ["Xiaomi", "Tuya", "SmartThings", "Amazon", "Google"],
    },
    {
        "type": "工业网关/PLC",
        "icon": "🏭",
        "match_ports": [502, 102, 2404],
        "any_ports": [44818, 47808, 18245],
        "vendor_hint": ["Siemens", "Schneider", "ABB", "Rockwell", "Omron"],
    },
    {
        "type": "可穿戴设备",
        "icon": "⌚",
        "match_ports": [5353, 443],
        "any_ports": [1900],
        "vendor_hint": ["Apple", "Samsung", "Xiaomi", "Huawei"],
    },
    {
        "type": "网络打印机",
        "icon": "🖨️",
        "match_ports": [80, 443, 9100],
        "any_ports": [515, 631],
        "vendor_hint": ["HP", "Canon", "Epson", "Brother", "Xerox"],
    },
    {
        "type": "NAS存储",
        "icon": "💾",
        "match_ports": [80, 443, 21, 22],
        "any_ports": [5000, 5001, 9000],
        "vendor_hint": ["Synology", "QNAP", "Western Digital", "Netgear"],
    },
    {
        "type": "智能电视",
        "icon": "📺",
        "match_ports": [5353, 1900, 8008],
        "any_ports": [3001, 8009],
        "vendor_hint": ["Samsung", "LG", "Sony", "Xiaomi", "TCL"],
    },
    {
        "type": "边缘计算网关",
        "icon": "🖥️",
        "match_ports": [22, 80, 443, 1883],
        "any_ports": [8883, 5683, 9090],
        "vendor_hint": ["Huawei", "HPE", "Dell", "Advantech", "Moxa"],
    },
]

# 风险评级权重
RISK_WEIGHTS = {
    "open_port_critical": 30,
    "open_port_high": 15,
    "open_port_medium": 5,
    "telnet_open": 25,
    "anonymous_mqtt": 20,
    "modbus_no_auth": 25,
    "rtsp_anonymous": 15,
    "snmp_default": 15,
    "debug_port_open": 20,
}


# ==================== 数据结构 ====================

@dataclass
class IoTFingerprint:
    """设备指纹"""
    ip: str = ""
    mac: str = ""
    vendor: str = "未知"
    model: str = "未知"
    firmware_version: str = "未知"
    os: str = "未知"
    device_type: str = "未知设备"
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    running_services: List[str] = field(default_factory=list)
    risk_level: str = "low"   # critical/high/medium/low
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==================== 设备发现器 ====================

class IoTDeviceDiscovery:
    """IoT设备发现与指纹识别器"""

    def __init__(self) -> None:
        self.devices: Dict[str, IoTFingerprint] = {}
        self._scan_history: List[Dict[str, Any]] = []

    # ---------- MAC OUI 识别 ----------

    @staticmethod
    def lookup_mac_vendor(mac: str) -> str:
        """根据MAC地址前3字节识别厂商"""
        if not mac or len(mac) < 8:
            return "未知"
        norm = mac.upper().replace("-", ":")
        oui = ":".join(norm.split(":")[:3])
        return MAC_OUI_VENDORS.get(oui, "未知厂商")

    # ---------- 设备类型推断 ----------

    def _infer_device_type(self, open_ports: List[int], vendor: str) -> Dict[str, Any]:
        """基于开放端口组合和厂商推断设备类型"""
        open_set = set(open_ports)
        best_match = {"type": "未知设备", "icon": "❓", "confidence": 0}

        for rule in DEVICE_TYPE_RULES:
            score = 0
            required = rule.get("match_ports", [])
            any_of = rule.get("any_ports", [])
            for p in required:
                if p in open_set:
                    score += 2
            for p in any_of:
                if p in open_set:
                    score += 1
            if any(vendor and v.lower() in vendor.lower() for v in rule.get("vendor_hint", [])):
                score += 3
            if score > best_match["confidence"]:
                best_match = {"type": rule["type"], "icon": rule["icon"], "confidence": score}

        return best_match

    # ---------- 风险评级 ----------

    def _calc_risk(self, open_ports: List[Dict[str, Any]]) -> Tuple[str, int, List[str]]:
        """计算设备风险等级"""
        score = 0
        factors: List[str] = []
        port_map = {p["port"]: p for p in open_ports}

        for pinfo in open_ports:
            risk = pinfo.get("risk", "low")
            if risk == "critical":
                score += RISK_WEIGHTS["open_port_critical"]
                factors.append(f"高危端口 {pinfo['port']}({pinfo['service']})")
            elif risk == "high":
                score += RISK_WEIGHTS["open_port_high"]
                factors.append(f"中高危端口 {pinfo['port']}({pinfo['service']})")
            elif risk == "medium":
                score += RISK_WEIGHTS["open_port_medium"]

        if 23 in port_map:
            score += RISK_WEIGHTS["telnet_open"]
            factors.append("Telnet明文远程管理开放")
        if 1883 in port_map:
            score += RISK_WEIGHTS["anonymous_mqtt"]
            factors.append("MQTT Broker可能允许匿名访问")
        if 502 in port_map:
            score += RISK_WEIGHTS["modbus_no_auth"]
            factors.append("Modbus TCP无认证协议暴露")
        if 554 in port_map:
            score += RISK_WEIGHTS["rtsp_anonymous"]
            factors.append("RTSP流媒体可能允许匿名访问")
        if 161 in port_map:
            score += RISK_WEIGHTS["snmp_default"]
            factors.append("SNMP可能使用默认community")
        if 8181 in port_map or 9000 in port_map:
            score += RISK_WEIGHTS["debug_port_open"]
            factors.append("调试/监控端口暴露")

        if score >= 60:
            level = "critical"
        elif score >= 35:
            level = "high"
        elif score >= 15:
            level = "medium"
        else:
            level = "low"

        return level, min(score, 100), factors

    # ---------- 主动扫描 ----------

    def active_scan(self, target: str,
                    ports: Optional[List[int]] = None,
                    timeout: float = 0.5) -> Dict[str, Any]:
        """
        主动扫描目标网络/主机。
        若scapy不可用，返回模拟数据；若目标不可达也返回模拟结果。
        """
        if ports is None:
            ports = list(IOT_COMMON_PORTS.keys())

        started = time.time()
        results: List[IoTFingerprint] = []

        # 支持CIDR或单IP
        try:
            net = ipaddress.ip_network(target, strict=False)
            hosts = [str(h) for h in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
        except ValueError:
            hosts = [target]

        # 限制扫描规模，避免演示卡死
        hosts = hosts[:64]

        for ip in hosts:
            fp = self._scan_host(ip, ports, timeout)
            results.append(fp)
            self.devices[fp.ip] = fp

        elapsed = round(time.time() - started, 2)
        summary = {
            "target": target,
            "hosts_scanned": len(hosts),
            "devices_found": len([r for r in results if r.open_ports]),
            "critical_devices": len([r for r in results if r.risk_level == "critical"]),
            "high_devices": len([r for r in results if r.risk_level == "high"]),
            "elapsed_seconds": elapsed,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scanner": "scapy" if _SCAPY_OK else "simulated",
        }
        self._scan_history.append(summary)
        return {"summary": summary, "devices": [r.to_dict() for r in results]}

    def _scan_host(self, ip: str, ports: List[int], timeout: float) -> IoTFingerprint:
        """扫描单个主机"""
        open_port_list: List[Dict[str, Any]] = []
        open_nums: List[int] = []

        if _SCAPY_OK:
            for port in ports:
                try:
                    pkt = scapy.IP(dst=ip) / scapy.TCP(dport=port, flags="S")  # type: ignore
                    resp = scapy.sr1(pkt, timeout=timeout, verbose=0)  # type: ignore
                    if resp and resp.haslayer(scapy.TCP):  # type: ignore
                        if resp[scapy.TCP].flags == 0x12:  # type: ignore
                            info = IOT_COMMON_PORTS.get(port, {"service": f"tcp/{port}", "risk": "low", "desc": "", "proto": "tcp"})
                            open_port_list.append({
                                "port": port, "service": info["service"],
                                "risk": info["risk"], "desc": info["desc"],
                                "proto": info.get("proto", "tcp"),
                            })
                            open_nums.append(port)
                except Exception:
                    continue
        else:
            # 模拟：基于IP尾号生成确定性结果，便于演示
            self._simulate_open_ports(ip, ports, open_port_list, open_nums)

        # MAC识别（模拟）
        mac = self._simulate_mac(ip)
        vendor = self.lookup_mac_vendor(mac)

        # 设备类型推断
        dtype = self._infer_device_type(open_nums, vendor)

        # 风险评级
        level, score, factors = self._calc_risk(open_port_list)

        fp = IoTFingerprint(
            ip=ip, mac=mac, vendor=vendor,
            device_type=dtype["type"],
            open_ports=open_port_list,
            running_services=[p["service"] for p in open_port_list],
            risk_level=level, risk_score=score, risk_factors=factors,
            first_seen=time.strftime("%Y-%m-%d %H:%M:%S"),
            last_seen=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        return fp

    def _simulate_open_ports(self, ip: str, ports: List[int],
                             out_list: List[Dict[str, Any]],
                             out_nums: List[int]) -> None:
        """基于IP生成确定性的模拟开放端口（演示用）"""
        try:
            last_octet = int(ip.split(".")[-1])
        except Exception:
            last_octet = random.randint(1, 254)

        # 每个IP确定性地开放若干端口
        profile = last_octet % 8
        profiles = {
            0: [80, 443, 22],
            1: [80, 554, 8080],
            2: [1883, 5683, 8080],
            3: [502, 102],
            4: [23, 80, 443],
            5: [5353, 1900, 443],
            6: [80, 8080, 8181],
            7: [22, 23, 80, 443, 1883],
        }
        selected = profiles.get(profile, [80])
        for p in selected:
            if p in ports and p in IOT_COMMON_PORTS:
                info = IOT_COMMON_PORTS[p]
                out_list.append({
                    "port": p, "service": info["service"],
                    "risk": info["risk"], "desc": info["desc"],
                    "proto": info.get("proto", "tcp"),
                })
                out_nums.append(p)

    @staticmethod
    def _simulate_mac(ip: str) -> str:
        """基于IP生成确定性模拟MAC地址"""
        try:
            octets = [int(x) for x in ip.split(".")]
            seed = sum(octets)
            rng = random.Random(seed)
            oui_choices = list(MAC_OUI_VENDORS.keys())
            oui = rng.choice(oui_choices)
            suffix = ":".join(f"{rng.randint(0, 255):02X}" for _ in range(3))
            return f"{oui}:{suffix}"
        except Exception:
            return "00:00:00:00:00:00"

    # ---------- 被动监听 ----------

    def passive_listen(self, interface: str = "eth0", duration: int = 10) -> Dict[str, Any]:
        """
        被动监听网络流量识别IoT设备。
        scapy不可用时返回模拟结果。
        """
        discovered: List[Dict[str, Any]] = []

        if _SCAPY_OK:
            try:
                packets = scapy.sniff(iface=interface, timeout=duration, store=True)  # type: ignore
                seen_ips: Dict[str, set] = {}
                for pkt in packets:
                    if pkt.haslayer(scapy.IP):  # type: ignore
                        src = pkt[scapy.IP].src  # type: ignore
                        dst = pkt[scapy.IP].dst  # type: ignore
                        if pkt.haslayer(scapy.TCP):  # type: ignore
                            dport = pkt[scapy.TCP].dport  # type: ignore
                            seen_ips.setdefault(src, set()).add(dport)
                for ip, ports in seen_ips.items():
                    fp = self._scan_host(ip, list(ports)[:30], 0.2)
                    discovered.append(fp.to_dict())
            except Exception as e:
                return {"success": False, "error": f"被动监听失败: {e}", "devices": []}
        else:
            # 模拟被动监听结果
            sample_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30",
                          "192.168.1.45", "192.168.1.60"]
            for sip in sample_ips:
                fp = self._scan_host(sip, list(IOT_COMMON_PORTS.keys()), 0.1)
                discovered.append(fp.to_dict())

        return {
            "interface": interface,
            "duration_seconds": duration,
            "devices_found": len(discovered),
            "devices": discovered,
            "mode": "live" if _SCAPY_OK else "simulated",
        }

    # ---------- 查询接口 ----------

    def list_devices(self) -> List[Dict[str, Any]]:
        return [d.to_dict() for d in self.devices.values()]

    def get_device(self, ip: str) -> Optional[Dict[str, Any]]:
        d = self.devices.get(ip)
        return d.to_dict() if d else None

    def get_scan_history(self) -> List[Dict[str, Any]]:
        return list(self._scan_history)

    def statistics(self) -> Dict[str, Any]:
        devs = list(self.devices.values())
        type_count: Dict[str, int] = {}
        risk_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        vendor_count: Dict[str, int] = {}
        for d in devs:
            type_count[d.device_type] = type_count.get(d.device_type, 0) + 1
            risk_count[d.risk_level] = risk_count.get(d.risk_level, 0) + 1
            vendor_count[d.vendor] = vendor_count.get(d.vendor, 0) + 1
        return {
            "total_devices": len(devs),
            "by_type": type_count,
            "by_risk": risk_count,
            "by_vendor": vendor_count,
            "scan_history_count": len(self._scan_history),
        }


# ==================== 工厂函数 ====================

_discovery_singleton: Optional[IoTDeviceDiscovery] = None


def get_device_discovery() -> IoTDeviceDiscovery:
    global _discovery_singleton
    if _discovery_singleton is None:
        _discovery_singleton = IoTDeviceDiscovery()
    return _discovery_singleton
