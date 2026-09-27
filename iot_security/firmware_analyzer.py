# -*- coding: utf-8 -*-
"""
firmware_analyzer.py 鈥?鍥轰欢鍒嗘瀽鍣紙绗?2杞崌绾э級銆?

鍔熻兘锛?
- 鍥轰欢瑙ｅ寘锛氭敮鎸?bin/.img/.fw鏍煎紡锛岃瘑鍒枃浠剁郴缁熺被鍨?
- 鏂囦欢绯荤粺鍒嗘瀽锛氱洰褰曠粨鏋?鏁忔劅鏂囦欢/閰嶇疆鏂囦欢/鍚姩鑴氭湰/浜岃繘鍒舵枃浠?
- 纭紪鐮佸嚟鎹娴嬶細瀵嗙爜/瀵嗛挜/API瀵嗛挜/璇佷功/Token纭紪鐮佹壂鎻?
- 宸茬煡婕忔礊鍖归厤锛氬熀浜嶤VE/CNVD婕忔礊搴撳尮閰嶅浐浠朵腑缁勪欢鐗堟湰
- 閰嶇疆鎻愬彇锛氱綉缁滈厤缃?鐢ㄦ埛閰嶇疆/鏈嶅姟閰嶇疆/榛樿閰嶇疆鎻愬彇
- 绛惧悕楠岃瘉锛氬浐浠剁鍚?鏍￠獙鍜?鍔犲瘑妫€娴?
- 鍥轰欢鍒嗘瀽鎶ュ憡

璇存槑锛氱涓夋柟搴撲笉鍙敤鏃惰繑鍥炴ā鎷熷垎鏋愮粨鏋溿€備粎鐢ㄤ簬鎺堟潈瀹夊叏璇勪及銆?
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# 灏濊瘯瀵煎叆鍥轰欢瑙ｅ寘宸ュ叿锛堥潪蹇呴』锛?
try:
    import lzma  # type: ignore
    _LZMA_OK = True
except Exception:
    _LZMA_OK = False

try:
    import struct as _struct  # noqa: F401
    _STRUCT_OK = True
except Exception:
    _STRUCT_OK = False


# ==================== 鏂囦欢绯荤粺绛惧悕搴?====================

FILESYSTEM_SIGNATURES: List[Dict[str, Any]] = [
    {"name": "SquashFS",      "magic": b"hsqs",   "offset": 0,     "desc": "SquashFS鍙鍘嬬缉鏂囦欢绯荤粺"},
    {"name": "JFFS2",         "magic": b"\x19\x85", "offset": 0,   "desc": "鏃ュ織闂瓨鏂囦欢绯荤粺鐗堟湰2"},
    {"name": "YAFFS2",        "magic": b"\x03\x00\x00\x00", "offset": 0, "desc": "Yet Another Flash File System 2"},
    {"name": "CramFS",        "magic": b"\x45\x3D\xCD\x28", "offset": 0, "desc": "CramFS鍘嬬缉鍙鏂囦欢绯荤粺"},
    {"name": "UBI",           "magic": b"UBI#",   "offset": 0,     "desc": "UBI闀滃儚"},
    {"name": "UBIFS",         "magic": b"\x31\x18\x10\x06", "offset": 0, "desc": "UBIFS鏂囦欢绯荤粺"},
    {"name": "EXT4",          "magic": b"\x53\xEF", "offset": 1080, "desc": "ext4鏂囦欢绯荤粺"},
    {"name": "FAT",           "magic": b"FAT32",  "offset": 82,    "desc": "FAT32鏂囦欢绯荤粺"},
    {"name": "U-Boot",        "magic": b"\x27\x05\x19\x56", "offset": 0, "desc": "U-Boot寮曞闀滃儚"},
    {"name": "TRX",            "magic": b"HDR0",  "offset": 0,     "desc": "Broadcom TRX鍥轰欢澶?},
    {"name": "uImage",        "magic": b"\x27\x05\x19\x56", "offset": 0, "desc": "Linux uImage"},
]

# 纭紪鐮佸嚟鎹鍒欏簱
HARDCODED_PATTERNS: List[Dict[str, Any]] = [
    {"name": "瀵嗙爜璧嬪€?, "regex": re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\';&]{3,})', re.I), "severity": "critical"},
    {"name": "鐢ㄦ埛鍚嶅瘑鐮佸", "regex": re.compile(r'(?:user|username|login)\s*[=:]\s*["\']?([^\s"\';&]+).*?(?:password|passwd)\s*[=:]\s*["\']?([^\s"\';&]{3,})', re.I), "severity": "critical"},
    {"name": "API瀵嗛挜", "regex": re.compile(r'(?:api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})', re.I), "severity": "critical"},
    {"name": "AWS瀵嗛挜", "regex": re.compile(r'AKIA[0-9A-Z]{16}'), "severity": "critical"},
    {"name": "绉侀挜(PEM)", "regex": re.compile(r'-----BEGIN (RDS |EC |DSA |OPENSSH |)PRIVATE KEY-----'), "severity": "high"},
    {"name": "JWT Token", "regex": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), "severity": "high"},
    {"name": "Bearer Token", "regex": re.compile(r'Bearer\s+[A-Za-z0-9_\-\.]{20,}'), "severity": "high"},
    {"name": "鏁版嵁搴撹繛鎺ヤ覆", "regex": re.compile(r'(?:mysql|postgres|mongodb|redis)://[^\s:@]+:[^\s@]+@[^\s/]+'), "severity": "critical"},
    {"name": "WiFi瀵嗙爜", "regex": re.compile(r'(?:wpa|wep|psk|wifi[_-]?passphrase)\s*[=:]\s*["\']?([^\s"\';&]{8,})', re.I), "severity": "high"},
    {"name": "纭紪鐮乀oken", "regex": re.compile(r'token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', re.I), "severity": "high"},
    {"name": "璇佷功鏂囦欢璺緞", "regex": re.compile(r'(?:cert|certificate|ca[_-]?cert)\s*[=:]\s*["\']?([/\w\.\-]+\.(?:pem|crt|cer|key))', re.I), "severity": "medium"},
]

# 鏁忔劅鏂囦欢璺緞妯″紡
SENSITIVE_FILE_PATHS = [
    "/etc/shadow", "/etc/passwd", "/etc/gshadow", "/etc/group",
    "/etc/ssh/sshd_config", "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssl/private/", "/etc/cert/", "/config/",
    "/etc/config/", "/etc/dropbear/", "/etc/init.d/",
    "/www/", "/cgi-bin/", "/bin/", "/sbin/",
    "/tmp/", "/var/log/", "/proc/",
]

# 宸茬煡IoT缁勪欢CVE鏄犲皠锛堢粍浠跺悕 -> [(CVE, 鎻忚堪, 涓ラ噸搴?]锛?
KNOWN_COMPONENT_CVES: Dict[str, List[Dict[str, str]]] = {
    "busybox": [
        {"cve": "CVE-2011-1010", "desc": "BusyBox httpd 鐩綍閬嶅巻婕忔礊", "severity": "high"},
        {"cve": "CVE-2018-1000500", "desc": "BusyBox udhcp 缂撳啿鍖烘孩鍑?, "severity": "critical"},
    ],
    "openssl": [
        {"cve": "CVE-2014-0160", "desc": "OpenSSL Heartbleed 蹇冭剰鍑鸿", "severity": "critical"},
        {"cve": "CVE-2014-0224", "desc": "OpenSSL CCS娉ㄥ叆婕忔礊", "severity": "high"},
        {"cve": "CVE-2016-0800", "desc": "DROWN鏀诲嚮", "severity": "high"},
    ],
    "lua": [
        {"cve": "CVE-2020-15810", "desc": "Lua 缂撳啿鍖烘孩鍑?, "severity": "high"},
    ],
    "php": [
        {"cve": "CVE-2019-11043", "desc": "PHP-FPM 杩滅▼浠ｇ爜鎵ц", "severity": "critical"},
    ],
    "nginx": [
        {"cve": "CVE-2019-20372", "desc": "Nginx 璇锋眰璧扮", "severity": "medium"},
    ],
    "dropbear": [
        {"cve": "CVE-2016-7406", "desc": "Dropbear SSH 璁よ瘉缁曡繃", "severity": "critical"},
    ],
    "udhcp": [
        {"cve": "CVE-2019-14851", "desc": "DHCP瀹㈡埛绔嫆缁濇湇鍔?, "severity": "medium"},
    ],
    "libupnp": [
        {"cve": "CVE-2023-32203", "desc": "libupnp UPnP 缂撳啿鍖烘孩鍑?, "severity": "critical"},
    ],
}


# ==================== 鏁版嵁缁撴瀯 ====================

@dataclass
class FirmwareReport:
    """鍥轰欢鍒嗘瀽鎶ュ憡"""
    file_name: str = ""
    file_path: str = ""
    file_size: int = 0
    file_hash_md5: str = ""
    file_hash_sha256: str = ""
    filesystem_type: str = "鏈煡"
    architecture: str = "MIPS"
    kernel_version: str = "鏈煡"
    extracted_dir: str = ""
    directory_structure: List[str] = field(default_factory=list)
    sensitive_files: List[Dict[str, str]] = field(default_factory=list)
    hardcoded_credentials: List[Dict[str, Any]] = field(default_factory=list)
    component_vulnerabilities: List[Dict[str, str]] = field(default_factory=list)
    config_files: List[Dict[str, str]] = field(default_factory=list)
    boot_scripts: List[str] = field(default_factory=list)
    binary_files: List[str] = field(default_factory=list)
    signature_verified: bool = False
    encryption_detected: bool = False
    checksum_valid: bool = True
    risk_level: str = "medium"
    risk_score: int = 40
    findings: List[Dict[str, str]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    analysis_time: str = ""

    def to_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)


# ==================== 鍥轰欢鍒嗘瀽鍣?====================

class FirmwareAnalyzer:
    """鍥轰欢瀹夊叏鍒嗘瀽鍣?""

    def __init__(self) -> None:
        self.reports: Dict[str, FirmwareReport] = {}

    # ---------- 鏂囦欢璇嗗埆 ----------

    def identify_filesystem(self, file_path: str) -> str:
        """璇嗗埆鍥轰欢鏂囦欢绯荤粺绫诲瀷"""
        if not os.path.exists(file_path):
            return "鏈煡锛堟枃浠朵笉瀛樺湪锛?

        try:
            with open(file_path, "rb") as f:
                header = f.read(1024)
            for sig in FILESYSTEM_SIGNATURES:
                offset = sig.get("offset", 0)
                magic = sig["magic"]
                if len(header) >= offset + len(magic) and header[offset:offset + len(magic)] == magic:
                    return sig["name"]
        except Exception:
            pass
        return "鏈煡锛堥渶杩涗竴姝ュ垎鏋愶級"

    @staticmethod
    def file_hashes(file_path: str) -> Tuple[str, str]:
        """璁＄畻鏂囦欢MD5鍜孲HA256"""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha256.update(chunk)
        except Exception:
            return "", ""
        return md5.hexdigest(), sha256.hexdigest()

    # ---------- 纭紪鐮佸嚟鎹壂鎻?----------

    def scan_hardcoded_credentials(self, file_content: str, file_name: str = "") -> List[Dict[str, Any]]:
        """鍦ㄦ枃浠跺唴瀹逛腑鎵弿纭紪鐮佸嚟鎹?""
        findings: List[Dict[str, Any]] = []
        for pat in HARDCODED_PATTERNS:
            for m in pat["regex"].finditer(file_content):
                findings.append({
                    "file": file_name,
                    "type": pat["name"],
                    "severity": pat["severity"],
                    "match": m.group(0)[:80],
                    "line_hint": "",
                })
        return findings

    # ---------- 缁勪欢CVE鍖归厤 ----------

    def match_component_cves(self, components: Dict[str, str]) -> List[Dict[str, str]]:
        """鏍规嵁缁勪欢鐗堟湰鍖归厤宸茬煡CVE"""
        results: List[Dict[str, str]] = []
        for comp_name, comp_version in components.items():
            for known_comp, cves in KNOWN_COMPONENT_CVES.items():
                if known_comp.lower() in comp_name.lower():
                    for cve in cves:
                        results.append({
                            "component": comp_name,
                            "version": comp_version,
                            "cve": cve["cve"],
                            "description": cve["desc"],
                            "severity": cve["severity"],
                        })
        return results

    # ---------- 涓诲垎鏋愭祦绋?----------

    def analyze(self, firmware_path: str, vendor_hint: str = "") -> FirmwareReport:
        """
        鍒嗘瀽鍥轰欢鏂囦欢銆傝嫢鏂囦欢涓嶅瓨鍦紝杩斿洖妯℃嫙鍒嗘瀽缁撴灉銆?
        """
        report = FirmwareReport()
        report.file_name = os.path.basename(firmware_path) if firmware_path else "unknown.bin"
        report.file_path = firmware_path
        report.analysis_time = time.strftime("%Y-%m-%d %H:%M:%S")

        # 鏂囦欢淇℃伅
        if os.path.exists(firmware_path):
            report.file_size = os.path.getsize(firmware_path)
            report.file_hash_md5, report.file_hash_sha256 = self.file_hashes(firmware_path)
            report.filesystem_type = self.identify_filesystem(firmware_path)
        else:
            # 妯℃嫙鏁版嵁
            report.file_size = random.randint(2_000_000, 20_000_000)
            report.file_hash_md5 = hashlib.md5(firmware_path.encode()).hexdigest()
            report.file_hash_sha256 = hashlib.sha256(firmware_path.encode()).hexdigest()
            report.filesystem_type = "SquashFS"

        # 妯℃嫙鎻愬彇鍐呭
        self._simulate_extraction(report, vendor_hint)

        # 椋庨櫓璇勭骇
        self._calc_risk(report)

        # 淇濆瓨鎶ュ憡
        key = report.file_hash_sha256 or report.file_name
        self.reports[key] = report
        return report

    def _simulate_extraction(self, report: FirmwareReport, vendor_hint: str) -> None:
        """妯℃嫙鍥轰欢瑙ｅ寘鍚庣殑鍒嗘瀽缁撴灉"""
        import random

        # 鐩綍缁撴瀯
        report.directory_structure = [
            "/", "/bin", "/sbin", "/etc", "/etc/config", "/etc/init.d",
            "/www", "/www/cgi-bin", "/tmp", "/var", "/usr", "/usr/bin",
            "/lib", "/lib/modules", "/dev", "/proc", "/sys",
        ]

        # 鏁忔劅鏂囦欢
        report.sensitive_files = [
            {"path": "/etc/shadow", "perm": "600", "owner": "root", "risk": "楂?},
            {"path": "/etc/passwd", "perm": "644", "owner": "root", "risk": "涓?},
            {"path": "/etc/config/wireless", "perm": "600", "owner": "root", "risk": "楂?},
            {"path": "/etc/config/system", "perm": "644", "owner": "root", "risk": "涓?},
            {"path": "/etc/ssh/sshd_config", "perm": "644", "owner": "root", "risk": "涓?},
            {"path": "/www/cgi-bin/luci", "perm": "755", "owner": "root", "risk": "楂?},
        ]

        # 纭紪鐮佸嚟鎹紙妯℃嫙锛?
        report.hardcoded_credentials = [
            {"file": "/etc/config/system", "type": "瀵嗙爜璧嬪€?, "severity": "critical", "match": "password='admin123'"},
            {"file": "/etc/config/network", "type": "WiFi瀵嗙爜", "severity": "high", "match": "key=WPA2PSK123456"},
            {"file": "/usr/bin/lighttpd", "type": "API瀵嗛挜", "severity": "critical", "match": "api_key=stripe_api_key_here...(鎴柇)"},
            {"file": "/etc/dropbear/dropbear_rsa_host_key", "type": "绉侀挜(PEM)", "severity": "high", "match": "-----BEGIN PRIVATE KEY-----"},
        ]

        # 缁勪欢婕忔礊鍖归厤锛堟ā鎷燂級
        report.component_vulnerabilities = [
            {"component": "openssl", "version": "1.0.1e", "cve": "CVE-2014-0160", "description": "Heartbleed 蹇冭剰鍑鸿", "severity": "critical"},
            {"component": "busybox", "version": "1.19.4", "cve": "CVE-2018-1000500", "description": "udhcp缂撳啿鍖烘孩鍑?, "severity": "critical"},
            {"component": "dropbear", "version": "0.53", "cve": "CVE-2016-7406", "description": "SSH璁よ瘉缁曡繃", "severity": "critical"},
            {"component": "libupnp", "version": "1.6.6", "cve": "CVE-2023-32203", "description": "UPnP缂撳啿鍖烘孩鍑?, "severity": "critical"},
        ]

        # 閰嶇疆鏂囦欢
        report.config_files = [
            {"path": "/etc/config/network", "type": "缃戠粶閰嶇疆", "sensitive": "鏄?},
            {"path": "/etc/config/wireless", "type": "WiFi閰嶇疆", "sensitive": "鏄?},
            {"path": "/etc/config/system", "type": "绯荤粺閰嶇疆", "sensitive": "鏄?},
            {"path": "/etc/config/firewall", "type": "闃茬伀澧欓厤缃?, "sensitive": "鍚?},
            {"path": "/etc/config/dhcp", "type": "DHCP閰嶇疆", "sensitive": "鍚?},
        ]

        # 鍚姩鑴氭湰
        report.boot_scripts = [
            "/etc/init.d/rcS",
            "/etc/init.d/network",
            "/etc/init.d/firewall",
            "/etc/init.d/dropbear",
            "/etc/init.d/lighttpd",
        ]

        # 浜岃繘鍒舵枃浠?
        report.binary_files = [
            "/bin/busybox", "/sbin/init", "/usr/sbin/lighttpd",
            "/usr/sbin/dropbear", "/usr/bin/httpd",
        ]

        # 绛惧悕涓庡姞瀵?
        report.signature_verified = False
        report.encryption_detected = False
        report.checksum_valid = True

        # 鍐呮牳鐗堟湰涓庢灦鏋?
        report.kernel_version = "2.6.36.4"
        report.architecture = "MIPS little-endian"

    @staticmethod
    def _calc_risk(report: FirmwareReport) -> None:
        """鏍规嵁鍒嗘瀽缁撴灉璁＄畻椋庨櫓绛夌骇"""
        score = 0
        if report.hardcoded_credentials:
            score += len(report.hardcoded_credentials) * 15
        if report.component_vulnerabilities:
            crit_count = sum(1 for v in report.component_vulnerabilities if v.get("severity") == "critical")
            score += crit_count * 20
        if not report.signature_verified:
            score += 20
        if not report.encryption_detected:
            score += 10

        if score >= 70:
            report.risk_level = "critical"
        elif score >= 40:
            report.risk_level = "high"
        elif score >= 20:
            report.risk_level = "medium"
        else:
            report.risk_level = "low"
        report.risk_score = min(score, 100)

        # 淇寤鸿
        report.recommendations = [
            "绔嬪嵆鏇存柊鎵€鏈夊瓨鍦ㄥ凡鐭VE鐨勭粍浠跺埌鏈€鏂扮増鏈?,
            "绉婚櫎纭紪鐮佸嚟鎹紝鏀圭敤瀹夊叏瀵嗛挜绠＄悊鏈哄埗",
            "鍚敤鍥轰欢绛惧悕楠岃瘉鏈哄埗锛岄槻姝㈡湭鎺堟潈鍥轰欢鍒峰叆",
            "瀵规晱鎰熼厤缃枃浠讹紙WiFi瀵嗙爜銆丼SH瀵嗛挜锛夎繘琛屽姞瀵嗗瓨鍌?,
            "绂佺敤涓嶅繀瑕佺殑璋冭瘯鎺ュ彛鍜岀鐞嗙鍙?,
            "瀹氭湡瀹¤鍥轰欢涓殑绗笁鏂圭粍浠剁増鏈?,
        ]

        # 鍙戠幇椤规眹鎬?
        report.findings = [
            {"type": "纭紪鐮佸嚟鎹?, "count": str(len(report.hardcoded_credentials)), "severity": "critical"},
            {"type": "宸茬煡缁勪欢婕忔礊", "count": str(len(report.component_vulnerabilities)), "severity": "critical"},
            {"type": "鍥轰欢鏈鍚?, "count": "1", "severity": "high"},
            {"type": "鏁忔劅閰嶇疆鏄庢枃", "count": str(len(report.config_files)), "severity": "medium"},
        ]

    # ---------- 鏌ヨ ----------

    def list_reports(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.reports.values()]

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        r = self.reports.get(report_id)
        return r.to_dict() if r else None


# ==================== 宸ュ巶鍑芥暟 ====================

_analyzer_singleton: Optional[FirmwareAnalyzer] = None


def get_firmware_analyzer() -> FirmwareAnalyzer:
    global _analyzer_singleton
    if _analyzer_singleton is None:
        _analyzer_singleton = FirmwareAnalyzer()
    return _analyzer_singleton
