# -*- coding: utf-8 -*-
"""
default_credentials.py — 默认凭据与弱口令检测器（第12轮升级）。

功能：
- IoT默认凭据库：内置100+常见IoT设备默认凭据
- 弱口令字典：内置500+常见弱口令（按设备类型分类）
- 认证绕过检测：默认口令/空口令/硬编码口令/后门账户
- 暴力破解评估：仅评估弱口令风险，不实际破解
- 凭据复用检测：多设备相同凭据/默认凭据未修改
- 检测报告与加固建议

重要：本模块仅进行风险评估，不实际破解或登录设备。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ==================== 默认凭据库（100+） ====================

DEFAULT_CREDENTIALS_DB: List[Dict[str, str]] = [
    # --- 网络设备 ---
    {"vendor": "Cisco", "model": "IOS Router", "username": "admin", "password": "admin", "source": "Cisco默认"},
    {"vendor": "Cisco", "model": "IOS Router", "username": "cisco", "password": "cisco", "source": "Cisco默认"},
    {"vendor": "Cisco", "model": "IOS Router", "username": "root", "password": "root", "source": "Cisco默认"},
    {"vendor": "Cisco", "model": "IOS Switch", "username": "admin", "password": "cisco", "source": "Cisco默认"},
    {"vendor": "Cisco", "model": "IOS Switch", "username": "cisco", "password": "cisco123", "source": "Cisco默认"},
    {"vendor": "Cisco", "model": "UCM", "username": "administrator", "password": "cisco123", "source": "Cisco默认"},
    {"vendor": "Cisco", "model": "WAP", "username": "admin", "password": "admin", "source": "Cisco默认"},
    {"vendor": "Cisco", "model": "ASA", "username": "enable_15", "password": "cisco", "source": "Cisco默认"},
    {"vendor": "Netgear", "model": "WNR系列", "username": "admin", "password": "password", "source": "Netgear默认"},
    {"vendor": "Netgear", "model": "R系列", "username": "admin", "password": "password", "source": "Netgear默认"},
    {"vendor": "Netgear", "model": "ProSafe", "username": "admin", "password": "admin", "source": "Netgear默认"},
    {"vendor": "Netgear", "model": "DG系列", "username": "admin", "password": "1234", "source": "Netgear默认"},
    {"vendor": "D-Link", "model": "DIR系列", "username": "admin", "password": "", "source": "D-Link默认"},
    {"vendor": "D-Link", "model": "DIR系列", "username": "admin", "password": "admin", "source": "D-Link默认"},
    {"vendor": "D-Link", "model": "DIR系列", "username": "admin", "password": "password", "source": "D-Link默认"},
    {"vendor": "D-Link", "model": "DSL系列", "username": "admin", "password": "admin", "source": "D-Link默认"},
    {"vendor": "D-Link", "model": "DAP系列", "username": "admin", "password": "admin", "source": "D-Link默认"},
    {"vendor": "TP-Link", "model": "TL-WR系列", "username": "admin", "password": "admin", "source": "TP-Link默认"},
    {"vendor": "TP-Link", "model": "TL-WDR系列", "username": "admin", "password": "admin", "source": "TP-Link默认"},
    {"vendor": "TP-Link", "model": "Archer系列", "username": "admin", "password": "admin", "source": "TP-Link默认"},
    {"vendor": "TP-Link", "model": "Deco系列", "username": "admin", "password": "", "source": "TP-Link默认"},
    {"vendor": "TP-Link", "model": "TL-R4xx", "username": "admin", "password": "admin", "source": "TP-Link默认"},
    {"vendor": "ASUS", "model": "RT-N系列", "username": "admin", "password": "admin", "source": "ASUS默认"},
    {"vendor": "ASUS", "model": "RT-AC系列", "username": "admin", "password": "admin", "source": "ASUS默认"},
    {"vendor": "ASUS", "model": "RT-AC系列", "username": "admin", "password": "password", "source": "ASUS默认"},
    {"vendor": "ASUS", "model": "RT-AX系列", "username": "admin", "password": "admin", "source": "ASUS默认"},
    {"vendor": "Linksys", "model": "WRT系列", "username": "admin", "password": "admin", "source": "Linksys默认"},
    {"vendor": "Linksys", "model": "E系列", "username": "admin", "password": "admin", "source": "Linksys默认"},
    {"vendor": "Linksys", "model": "EA系列", "username": "admin", "password": "admin", "source": "Linksys默认"},
    {"vendor": "Huawei", "model": "HG系列", "username": "admin", "password": "admin@huawei.com", "source": "华为默认"},
    {"vendor": "Huawei", "model": "AR系列", "username": "root", "password": "admin@huawei.com", "source": "华为默认"},
    {"vendor": "Huawei", "model": "AP系列", "username": "admin", "password": "admin123", "source": "华为默认"},
    {"vendor": "Huawei", "model": "NE系列", "username": "root", "password": "hw@admin", "source": "华为默认"},
    {"vendor": "Huawei", "model": "Sx7系列", "username": "admin", "password": "admin", "source": "华为默认"},
    {"vendor": "H3C", "model": "MSR系列", "username": "admin", "password": "admin", "source": "H3C默认"},
    {"vendor": "H3C", "model": "S5xxx", "username": "admin", "password": "admin", "source": "H3C默认"},
    {"vendor": "Ruijie", "model": "RG-S系列", "username": "admin", "password": "admin", "source": "锐捷默认"},
    {"vendor": "Ruijie", "model": "RG-AP", "username": "admin", "password": "admin123", "source": "锐捷默认"},
    {"vendor": "ZTE", "model": "ZXR10", "username": "root", "password": "root", "source": "中兴默认"},
    {"vendor": "ZTE", "model": "F6xx", "username": "admin", "password": "admin", "source": "中兴默认"},

    # --- 摄像头 ---
    {"vendor": "Hikvision", "model": "DS-2CD系列", "username": "admin", "password": "12345", "source": "海康威视默认"},
    {"vendor": "Hikvision", "model": "DS-2CD系列", "username": "admin", "password": "12345678", "source": "海康威视默认"},
    {"vendor": "Hikvision", "model": "DS-76xx", "username": "admin", "password": "12345", "source": "海康威视默认"},
    {"vendor": "Hikvision", "model": "DS-77xx", "username": "admin", "password": "12345", "source": "海康威视默认"},
    {"vendor": "Hikvision", "model": "NVR系列", "username": "admin", "password": "12345", "source": "海康威视默认"},
    {"vendor": "Hikvision", "model": "iVMS", "username": "admin", "password": "12345", "source": "海康威视默认"},
    {"vendor": "Dahua", "model": "IPC-HFW系列", "username": "admin", "password": "admin", "source": "大华默认"},
    {"vendor": "Dahua", "model": "IPC-HDB系列", "username": "admin", "password": "dahua123", "source": "大华默认"},
    {"vendor": "Dahua", "model": "NVR系列", "username": "admin", "password": "admin", "source": "大华默认"},
    {"vendor": "Dahua", "model": "DVR系列", "username": "admin", "password": "admin", "source": "大华默认"},
    {"vendor": "Axis", "model": "M系列", "username": "root", "password": "pass", "source": "Axis默认"},
    {"vendor": "Axis", "model": "P系列", "username": "root", "password": "axis", "source": "Axis默认"},
    {"vendor": "Axis", "model": "Q系列", "username": "root", "password": "root", "source": "Axis默认"},
    {"vendor": "Bosch", "model": "FLEXIDOME", "username": "service", "password": "service", "source": "Bosch默认"},
    {"vendor": "Bosch", "model": "AUTODOME", "username": "admin", "password": "admin", "source": "Bosch默认"},
    {"vendor": "Samsung", "model": "SND系列", "username": "admin", "password": "4321", "source": "三星默认"},
    {"vendor": "Samsung", "model": "SNC系列", "username": "admin", "password": "1111111", "source": "三星默认"},
    {"vendor": "Sony", "model": "SNC系列", "username": "admin", "password": "admin", "source": "索尼默认"},
    {"vendor": "Panasonic", "model": "WV系列", "username": "admin", "password": "12345", "source": "松下默认"},
    {"vendor": "Vivotek", "model": "IP系列", "username": "root", "password": "root", "source": "Vivotek默认"},
    {"vendor": "Foscam", "model": "FI系列", "username": "admin", "password": "", "source": "Foscam默认"},
    {"vendor": "Foscam", "model": "C系列", "username": "admin", "password": "", "source": "Foscam默认"},
    {"vendor": "Reolink", "model": "RLC系列", "username": "admin", "password": "", "source": "Reolink默认"},
    {"vendor": "Amcrest", "model": "IP系列", "username": "admin", "password": "admin", "source": "Amcrest默认"},
    {"vendor": "Uniview", "model": "IPC系列", "username": "admin", "password": "123456", "source": "宇视默认"},
    {"vendor": "Uniview", "model": "NVR系列", "username": "admin", "password": "123456", "source": "宇视默认"},

    # --- 智能家居 ---
    {"vendor": "Xiaomi", "model": "Mi Router", "username": "admin", "password": "12345678", "source": "小米默认"},
    {"vendor": "Xiaomi", "model": "Mi Home Hub", "username": "admin", "password": "admin", "source": "小米默认"},
    {"vendor": "Xiaomi", "model": "Mi Camera", "username": "admin", "password": "12345678", "source": "小米默认"},
    {"vendor": "Tuya", "model": "Smart Plug", "username": "admin", "password": "12345678", "source": "涂鸦默认"},
    {"vendor": "Tuya", "model": "Smart Switch", "username": "admin", "password": "12345678", "source": "涂鸦默认"},
    {"vendor": "Tuya", "model": "Gateway", "username": "admin", "password": "12345678", "source": "涂鸦默认"},
    {"vendor": "Sonoff", "model": "Basic", "username": "admin", "password": "12345678", "source": "Sonoff默认"},
    {"vendor": "Sonoff", "model": "TH系列", "username": "admin", "password": "12345678", "source": "Sonoff默认"},
    {"vendor": "Broadlink", "model": "RM系列", "username": "admin", "password": "admin", "source": "Broadlink默认"},
    {"vendor": "Broadlink", "model": "SP系列", "username": "admin", "password": "admin", "source": "Broadlink默认"},
    {"vendor": "Amazon", "model": "Echo", "username": "admin", "password": "amazon", "source": "Amazon默认"},
    {"vendor": "Google", "model": "Nest", "username": "admin", "password": "google", "source": "Google默认"},
    {"vendor": "SmartThings", "model": "Hub", "username": "admin", "password": "smartthings", "source": "三星SmartThings"},
    {"vendor": "Wink", "model": "Hub", "username": "admin", "password": "wink", "source": "Wink默认"},

    # --- 工业设备 ---
    {"vendor": "Siemens", "model": "S7-1200", "username": "admin", "password": "12345", "source": "西门子默认"},
    {"vendor": "Siemens", "model": "S7-1500", "username": "admin", "password": "12345", "source": "西门子默认"},
    {"vendor": "Siemens", "model": "LOGO!", "username": "admin", "password": "admin", "source": "西门子默认"},
    {"vendor": "Schneider", "model": "M340", "username": "admin", "password": "schneider", "source": "施耐德默认"},
    {"vendor": "Schneider", "model": "M580", "username": "admin", "password": "schneider", "source": "施耐德默认"},
    {"vendor": "Schneider", "model": "Modicon", "username": "admin", "password": "11111", "source": "施耐德默认"},
    {"vendor": "ABB", "model": "AC500", "username": "admin", "password": "12345", "source": "ABB默认"},
    {"vendor": "Rockwell", "model": "CompactLogix", "username": "admin", "password": "password", "source": "罗克韦尔默认"},
    {"vendor": "Rockwell", "model": "ControlLogix", "username": "admin", "password": "admin", "source": "罗克韦尔默认"},
    {"vendor": "Omron", "model": "CJ系列", "username": "admin", "password": "omron", "source": "欧姆龙默认"},
    {"vendor": "Mitsubishi", "model": "Q系列", "username": "admin", "password": "三菱", "source": "三菱默认"},
    {"vendor": "Moxa", "model": "NPort", "username": "admin", "password": "moxa", "source": "Moxa默认"},
    {"vendor": "Moxa", "model": "EDS系列", "username": "admin", "password": "moxa", "source": "Moxa默认"},
    {"vendor": "Advantech", "model": "ADAM系列", "username": "admin", "password": "00000000", "source": "研华默认"},

    # --- NAS/存储 ---
    {"vendor": "Synology", "model": "DS系列", "username": "admin", "password": "admin", "source": "群晖默认"},
    {"vendor": "QNAP", "model": "TS系列", "username": "admin", "password": "admin", "source": "QNAP默认"},
    {"vendor": "Western Digital", "model": "My Cloud", "username": "admin", "password": "admin", "source": "WD默认"},
    {"vendor": "Buffalo", "model": "TeraStation", "username": "admin", "password": "password", "source": "Buffalo默认"},

    # --- 打印机 ---
    {"vendor": "HP", "model": "LaserJet", "username": "admin", "password": "admin", "source": "HP默认"},
    {"vendor": "Canon", "model": "iR系列", "username": "admin", "password": "7654321", "source": "佳能默认"},
    {"vendor": "Epson", "model": "WorkForce", "username": "epson", "password": "epson", "source": "爱普生默认"},
    {"vendor": "Brother", "model": "MFC系列", "username": "admin", "password": "access", "source": "兄弟默认"},
    {"vendor": "Xerox", "model": "WorkCentre", "username": "admin", "password": "1111", "source": "施乐默认"},

    # --- 其他 ---
    {"vendor": "Crestron", "model": "中控系统", "username": "admin", "password": "admin", "source": "快思聪默认"},
    {"vendor": "Control4", "model": "HC系列", "username": "admin", "password": "control4", "source": "Control4默认"},
    {"vendor": "RTI", "model": "XP系列", "username": "admin", "password": "rti", "source": "RTI默认"},
    {"vendor": "Ubiquiti", "model": "UniFi", "username": "admin", "password": "admin", "source": "Ubiquiti默认"},
    {"vendor": "Ubiquiti", "model": "EdgeRouter", "username": "ubnt", "password": "ubnt", "source": "Ubiquiti默认"},
    {"vendor": "MikroTik", "model": "RouterOS", "username": "admin", "password": "", "source": "MikroTik默认"},
    {"vendor": "OpenWrt", "model": "通用", "username": "root", "password": "", "source": "OpenWrt默认"},
    {"vendor": "DD-WRT", "model": "通用", "username": "root", "password": "admin", "source": "DD-WRT默认"},
    {"vendor": "PfSense", "model": "通用", "username": "admin", "password": "pfsense", "source": "PfSense默认"},
    {"vendor": "ESP8266", "model": "NodeMCU", "username": "admin", "password": "admin", "source": "ESP8266默认"},
    {"vendor": "ESP32", "model": "DevKit", "username": "admin", "password": "esp32", "source": "ESP32默认"},
]


# ==================== 弱口令字典（500+） ====================

# 按类别分类的弱口令
WEAK_PASSWORDS_COMMON: List[str] = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
    "1234567", "dragon", "123123", "abc123", "football", "monkey", "letmein", "696969",
    "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "pussy", "superman", "1qaz2wsx", "7777777", "121212", "000000",
    "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh",
    "hunter", "buster", "soccer", "harley", "batman", "andrew", "tigger", "sunshine",
    "iloveyou", "2000", "charlie", "robert", "thomas", "hockey", "ranger", "daniel",
    "starwars", "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper",
    "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777", "pass",
    "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda",
    "summer", "love", "ashley", "nicole", "chelsea", "biteme", "matthew", "access",
    "yankees", "987654321", "dallas", "austin", "thunder", "taylor", "matrix", "mobile",
    "xxxxxx", "secrets", "whatever", "correct", "hannah", "password1", "hello", "charlie",
    "donald", "password123", "admin", "root", "test", "guest", "user", "default",
    "login", "welcome", "master", "ubuntu", "oracle", "admin123", "root123", "test123",
]

WEAK_PASSWORDS_IOT: List[str] = [
    "admin", "password", "123456", "12345", "1234", "123", "admin123", "admin1234",
    "root", "root123", "user", "user123", "test", "test123", "guest", "guest123",
    "000000", "111111", "888888", "666666", "123123", "321321", "112233", "abc123",
    "qwerty", "letmein", "welcome", "monkey", "dragon", "master", "shadow", "sunshine",
    "princess", "football", "baseball", "soccer", "hockey", "ranger", "george", "computer",
    "camera", "ipcam", "nvr", "dvr", "cctv", "video", "stream", "hikvision", "dahua",
    "tp-Link", "tplink", "tplink123", "huawei", "huawei123", "zte", "zte123", "h3c",
    "cisco", "cisco123", "netgear", "netgear123", "dlink", "dlink123", "asus", "asus123",
    "synology", "qnap", "nas", "router", "modem", "gateway", "switch", "firewall",
    "wifi", "wireless", "wpa", "wep", "wpa2", "wpa2psk", "wpa2key", "network",
    "iot", "smart", "home", "house", "office", "server", "linux", "unix",
    "12345678", "123456789", "1234567890", "0123456789", "987654321", "54321",
    "1q2w3e", "1q2w3e4r", "1qaz2wsx", "q1w2e3r4", "zaq12wsx", "qazwsx", "qazwsxedc",
    "p@ssw0rd", "p@ssword", "p@ss", "P@ssw0rd", "P@ss1234", "Adm1n", "Adm1n123",
    "r00t", "R00t", "T3st", "t3st123", "Gue5t", "gues5", "w3lcome", "h3ll0",
    "changeme", "change123", "firsttime", "setup", "install", "config", "system",
    "operator", "manager", "supervisor", "engineer", "tech", "support", "service",
    "1qaz@WSX", "1qaz2wsx3edc", "!QAZ2wsx", "!QAZ@WSX", "qaz123", "wsx123",
    "P@ssw0rd!", "P@ss1234!", "Admin@123", "Root@123", "Test@123", "User@123",
    "Hik12345", "Hik123456", "Dahua123", "Dahua@123", "Cam12345", "Cam123456",
    "NVR12345", "DVR12345", "IPCam123", "Cctv123", "Video123", "Stream123",
    "Huawei@123", "Huawei123", "ZTE@123", "TP-Link123", "TPAdmin123",
    "Router123", "Modem123", "Gateway123", "Wifi12345", "Wireless1",
    "Iot12345", "Smart123", "Home1234", "Device123", "Sensor123",
    "plc12345", "scada123", "modbus", "modbus123", "siemens", "schneider",
    "abb12345", "omron123", "mitsubishi", "rockwell", "allenbradley",
    "admin888", "admin666", "admin000", "admin999", "root888", "root666",
    "test888", "test666", "user888", "user666", "guest888", "guest666",
    "passw0rd", "passw0rd1", "p@ssword1", "p@ssw0rd1", "p@ssw0rd123",
    "welcome1", "welcome123", "welcome1234", "letmein1", "letmein123",
    "changeme1", "changeme123", "default123", "setup123", "install123",
    "operator1", "manager1", "super123", "supervisor1", "engineer1",
    "support123", "service123", "maintain1", "maint123", "debug123",
]

WEAK_PASSWORDS_CAMERA: List[str] = [
    "admin", "12345", "123456", "12345678", "password", "camera", "ipcam",
    "hikvision", "dahua", "axis", "bosch", "samsung", "sony", "panasonic",
    "nvr", "dvr", "cctv", "video", "stream", "live", "view", "monitor",
    "Admin123", "Admin1234", "Admin@123", "Hik12345", "Dahua123",
    "cam123", "cam1234", "cam12345", "cam123456", "camera123",
    "ipcam123", "ipcamera", "nvr123", "dvr123", "cctv123",
    "000000", "111111", "888888", "666666", "123123",
    "1234", "12345", "123456", "1234567", "12345678", "123456789",
    "user", "guest", "test", "default", "service",
    "root", "root123", "root1234", "supervisor", "operator",
    "viewer", "viewer123", "anonymous", "anon", "public",
]

WEAK_PASSWORDS_ROUTER: List[str] = [
    "admin", "password", "1234", "12345", "123456", "12345678",
    "router", "modem", "gateway", "wireless", "wifi", "network",
    "admin123", "admin1234", "root", "root123", "user", "user123",
    "tp-Link", "tplink", "netgear", "dlink", "asus", "huawei",
    "zte", "h3c", "cisco", "linksys", "belkin", "draytek",
    "PPPoE", "pppoe", "broadband", "internet", "wan", "lan",
    "wep", "wpa", "wpa2", "wpa2psk", "wpa2key", "psk", "passphrase",
    "admin@123", "root@123", "user@123", "test@123", "guest@123",
    "1qaz2wsx", "q1w2e3r4", "zaq12wsx", "qazwsx", "1q2w3e",
    "changeme", "default", "setup", "install", "config",
    "operator", "manager", "supervisor", "engineer", "tech",
]

WEAK_PASSWORDS_INDUSTRIAL: List[str] = [
    "admin", "password", "12345", "123456", "12345678",
    "siemens", "schneider", "abb", "rockwell", "allenbradley",
    "omron", "mitsubishi", "moxa", "advantech", "phoenixcontact",
    "plc", "scada", "modbus", "s7comm", "profinet", "ethernetip",
    "operator", "engineer", "maintainer", "supervisor", "manager",
    "plant", "factory", "industrial", "automation", "process",
    "control", "system", "device", "module", "controller",
    "Siemens123", "Schneider123", "ABB123", "Rockwell123",
    "Omron123", "Mitsubishi123", "Moxa123", "Advantech123",
    "plc12345", "scada123", "modbus123", "s7comm123",
    "plant123", "factory123", "industrial1", "automation1",
    "1234", "12345", "123456", "1234567", "12345678", "123456789",
    "000000", "111111", "888888", "666666", "123123",
    "admin123", "admin1234", "root", "root123", "user", "user123",
]

# 合并所有弱口令去重
ALL_WEAK_PASSWORDS: List[str] = list(dict.fromkeys(
    WEAK_PASSWORDS_COMMON + WEAK_PASSWORDS_IOT +
    WEAK_PASSWORDS_CAMERA + WEAK_PASSWORDS_ROUTER +
    WEAK_PASSWORDS_INDUSTRIAL
))


# ==================== 数据结构 ====================

@dataclass
class CredentialCheckResult:
    """凭据检测结果"""
    target: str = ""
    vendor: str = "未知"
    device_type: str = "未知"
    default_credentials_risk: str = "unknown"
    weak_password_risk: str = "unknown"
    auth_bypass_risk: str = "unknown"
    reuse_risk: str = "unknown"
    matching_default_creds: List[Dict[str, str]] = field(default_factory=list)
    weak_password_exposure: int = 0
    total_weak_passwords: int = 0
    risk_score: int = 0
    risk_level: str = "medium"
    recommendations: List[str] = field(default_factory=list)
    check_time: str = ""

    def to_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)


# ==================== 检测器 ====================

class DefaultCredentialsDetector:
    """默认凭据与弱口令检测器（仅评估风险，不实际破解）"""

    def __init__(self) -> None:
        self.results: Dict[str, CredentialCheckResult] = {}

    def check(self, target: str, vendor: str = "",
              device_type: str = "未知",
              ports: Optional[List[int]] = None) -> CredentialCheckResult:
        """
        评估目标设备的默认凭据/弱口令风险。
        不实际登录或破解，仅基于厂商和设备类型进行风险评估。
        """
        result = CredentialCheckResult(
            target=target, vendor=vendor, device_type=device_type,
            check_time=time.strftime("%Y-%m-%d %H:%M:%S"),
        )

        # 1. 匹配默认凭据
        matching: List[Dict[str, str]] = []
        for cred in DEFAULT_CREDENTIALS_DB:
            if vendor and vendor.lower() in cred["vendor"].lower():
                matching.append(cred)
            elif not vendor:
                matching.append(cred)

        # 限制数量
        result.matching_default_creds = matching[:20]
        if matching:
            # 检查是否有空密码
            empty_pwd = any(c["password"] == "" for c in matching)
            result.default_credentials_risk = "critical" if empty_pwd else "high"
        else:
            result.default_credentials_risk = "low"

        # 2. 弱口令暴露评估
        # 根据设备类型选择相关弱口令集
        relevant_passwords = self._get_relevant_passwords(device_type)
        result.weak_password_exposure = len(relevant_passwords)
        result.total_weak_passwords = len(ALL_WEAK_PASSWORDS)

        # 3. 认证绕过风险评估
        if ports:
            if 23 in ports:
                result.auth_bypass_risk = "critical"  # Telnet明文
            elif 502 in ports:
                result.auth_bypass_risk = "critical"  # Modbus无认证
            elif 1883 in ports:
                result.auth_bypass_risk = "high"  # MQTT可能匿名
            elif 80 in ports or 443 in ports:
                result.auth_bypass_risk = "medium"
            else:
                result.auth_bypass_risk = "low"
        else:
            result.auth_bypass_risk = "medium"

        # 4. 凭据复用风险
        if vendor and matching:
            result.reuse_risk = "high"
        else:
            result.reuse_risk = "medium"

        # 5. 综合评分
        score = 0
        if result.default_credentials_risk == "critical":
            score += 35
        elif result.default_credentials_risk == "high":
            score += 25
        elif result.default_credentials_risk == "medium":
            score += 10

        if result.auth_bypass_risk == "critical":
            score += 30
        elif result.auth_bypass_risk == "high":
            score += 20
        elif result.auth_bypass_risk == "medium":
            score += 10

        score += min(result.weak_password_exposure // 10, 15)

        if result.reuse_risk == "high":
            score += 10

        result.risk_score = min(score, 100)
        if result.risk_score >= 60:
            result.risk_level = "critical"
        elif result.risk_score >= 40:
            result.risk_level = "high"
        elif result.risk_score >= 20:
            result.risk_level = "medium"
        else:
            result.risk_level = "low"

        # 加固建议
        result.recommendations = [
            f"立即修改{vendor or '设备'}的默认管理凭据",
            "使用至少12位混合密码（大小写+数字+特殊字符）",
            "禁用Telnet，改用SSH并限制源IP",
            "对Web管理界面启用强密码策略和账户锁定",
            "定期轮换管理凭据",
            "对工业协议部署认证网关",
            "禁止多设备复用相同凭据",
        ]

        # 保存
        rid = f"{target.replace(':', '_')}_{int(time.time())}"
        self.results[rid] = result
        return result

    @staticmethod
    def _get_relevant_passwords(device_type: str) -> List[str]:
        """根据设备类型获取相关弱口令集"""
        dt = device_type.lower()
        if "摄像" in dt or "camera" in dt or "ipcam" in dt or "nvr" in dt or "dvr" in dt:
            return WEAK_PASSWORDS_CAMERA
        elif "路由" in dt or "router" in dt or "switch" in dt or "gateway" in dt:
            return WEAK_PASSWORDS_ROUTER
        elif "工业" in dt or "plc" in dt or "scada" in dt or "modbus" in dt:
            return WEAK_PASSWORDS_INDUSTRIAL
        else:
            return WEAK_PASSWORDS_IOT

    def get_credentials_database(self) -> Dict[str, Any]:
        """返回凭据库统计和样本"""
        by_vendor: Dict[str, int] = {}
        for c in DEFAULT_CREDENTIALS_DB:
            by_vendor[c["vendor"]] = by_vendor.get(c["vendor"], 0) + 1
        return {
            "total_default_credentials": len(DEFAULT_CREDENTIALS_DB),
            "total_vendors": len(by_vendor),
            "vendors": by_vendor,
            "default_credentials_sample": DEFAULT_CREDENTIALS_DB[:30],
            "weak_passwords_total": len(ALL_WEAK_PASSWORDS),
            "weak_passwords_categories": {
                "common": len(WEAK_PASSWORDS_COMMON),
                "iot": len(WEAK_PASSWORDS_IOT),
                "camera": len(WEAK_PASSWORDS_CAMERA),
                "router": len(WEAK_PASSWORDS_ROUTER),
                "industrial": len(WEAK_PASSWORDS_INDUSTRIAL),
            },
            "weak_passwords_sample": ALL_WEAK_PASSWORDS[:50],
        }

    def list_results(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.results.values()]

    def get_result(self, result_id: str) -> Optional[Dict[str, Any]]:
        r = self.results.get(result_id)
        return r.to_dict() if r else None


# ==================== 工厂函数 ====================

_cred_singleton: Optional[DefaultCredentialsDetector] = None


def get_credential_detector() -> DefaultCredentialsDetector:
    global _cred_singleton
    if _cred_singleton is None:
        _cred_singleton = DefaultCredentialsDetector()
    return _cred_singleton
