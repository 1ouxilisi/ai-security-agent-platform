#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
12大领域真实工具检测器

检测系统中安装的安全工具，为每个领域标记可用的真实工具。
支持Windows/Linux/macOS跨平台检测。
"""

import shutil
import os
import platform
from typing import Dict, List, Set
from dataclasses import dataclass, field


@dataclass
class ToolInfo:
    """工具信息"""
    name: str
    domain: str  # 所属领域
    category: str  # 类别：recon/scanner/exploit/forensics/analysis
    windows_names: List[str] = field(default_factory=list)  # Windows下的可执行文件名
    linux_names: List[str] = field(default_factory=list)  # Linux下的可执行文件名
    description: str = ""
    installed: bool = False
    path: str = ""


class DomainToolDetector:
    """12大领域工具检测器"""

    def __init__(self):
        self.os_type = platform.system().lower()  # windows / linux / darwin
        self.tools: List[ToolInfo] = self._init_tools()
        self._detect_all()

    def _init_tools(self) -> List[ToolInfo]:
        """初始化所有领域的工具列表"""
        return [
            # ========== Web安全 ==========
            ToolInfo("nmap", "web_security", "scanner",
                     ["nmap.exe"], ["nmap"], "端口扫描、服务识别、OS检测"),
            ToolInfo("nuclei", "web_security", "scanner",
                     ["nuclei.exe"], ["nuclei"], "基于模板的漏洞扫描器"),
            ToolInfo("sqlmap", "web_security", "exploit",
                     ["sqlmap.py", "sqlmap.exe"], ["sqlmap"], "SQL注入检测与利用"),
            ToolInfo("nikto", "web_security", "scanner",
                     ["nikto.pl", "nikto.exe"], ["nikto"], "Web服务器漏洞扫描"),
            ToolInfo("subfinder", "web_security", "recon",
                     ["subfinder.exe"], ["subfinder"], "子域名枚举"),
            ToolInfo("httpx", "web_security", "recon",
                     ["httpx.exe"], ["httpx"], "HTTP服务探测"),
            ToolInfo("dirsearch", "web_security", "scanner",
                     ["dirsearch.py", "dirsearch.exe"], ["dirsearch"], "目录爆破"),
            ToolInfo("gobuster", "web_security", "scanner",
                     ["gobuster.exe"], ["gobuster"], "目录/子域名爆破"),

            # ========== 移动安全 ==========
            ToolInfo("apktool", "mobile_security", "analysis",
                     ["apktool.bat", "apktool.jar"], ["apktool"], "APK反编译/回编译"),
            ToolInfo("jadx", "mobile_security", "analysis",
                     ["jadx.bat", "jadx-gui.bat"], ["jadx", "jadx-gui"], "APK反编译为Java"),
            ToolInfo("frida", "mobile_security", "exploit",
                     ["frida.exe"], ["frida"], "动态插桩框架"),
            ToolInfo("adb", "mobile_security", "analysis",
                     ["adb.exe"], ["adb"], "Android调试桥"),
            ToolInfo("aapt", "mobile_security", "analysis",
                     ["aapt.exe"], ["aapt"], "APK资源解析"),
            ToolInfo("objection", "mobile_security", "exploit",
                     ["objection.exe"], ["objection"], "移动应用安全测试工具"),

            # ========== 云安全 ==========
            ToolInfo("aws-cli", "cloud_security", "analysis",
                     ["aws.exe"], ["aws"], "AWS命令行工具"),
            ToolInfo("az-cli", "cloud_security", "analysis",
                     ["az.exe"], ["az"], "Azure命令行工具"),
            ToolInfo("gcloud", "cloud_security", "analysis",
                     ["gcloud.cmd", "gcloud.exe"], ["gcloud"], "GCP命令行工具"),
            ToolInfo("kube-hunter", "cloud_security", "scanner",
                     ["kube-hunter.exe"], ["kube-hunter"], "Kubernetes渗透测试"),
            ToolInfo("trivy", "cloud_security", "scanner",
                     ["trivy.exe"], ["trivy"], "容器/镜像漏洞扫描"),
            ToolInfo("docker", "cloud_security", "analysis",
                     ["docker.exe"], ["docker"], "容器运行时"),

            # ========== 区块链安全 ==========
            ToolInfo("slither", "blockchain_security", "scanner",
                     ["slither.exe"], ["slither"], "智能合约静态分析"),
            ToolInfo("mythril", "blockchain_security", "scanner",
                     ["myth.exe", "mythril.exe"], ["myth", "mythril"], "智能合约符号执行"),
            ToolInfo("ganache", "blockchain_security", "analysis",
                     ["ganache.exe"], ["ganache"], "本地区块链测试环境"),

            # ========== AI安全 ==========
            ToolInfo("garak", "ai_security", "scanner",
                     ["garak.exe"], ["garak"], "LLM安全扫描器"),
            ToolInfo("promptmap", "ai_security", "scanner",
                     ["promptmap.exe"], ["promptmap"], "提示注入测试工具"),

            # ========== 内网渗透/AD ==========
            ToolInfo("bloodhound", "internal_pentest", "analysis",
                     ["bloodhound.exe", "SharpHound.exe"], ["bloodhound"], "AD攻击路径分析"),
            ToolInfo("impacket", "internal_pentest", "exploit",
                     ["wmiexec.py", "psexec.py", "smbexec.py"], ["wmiexec.py", "psexec.py"], "内网渗透工具集"),
            ToolInfo("crackmapexec", "internal_pentest", "scanner",
                     ["cme.exe", "crackmapexec.exe"], ["crackmapexec", "cme"], "SMB/AD枚举与攻击"),
            ToolInfo("enum4linux", "internal_pentest", "recon",
                     ["enum4linux.pl", "enum4linux.exe"], ["enum4linux"], "SMB/Windows枚举"),
            ToolInfo("responder", "internal_pentest", "exploit",
                     ["responder.exe"], ["responder"], "LLMNR/NBT-NS投毒"),
            ToolInfo("mimikatz", "internal_pentest", "exploit",
                     ["mimikatz.exe"], ["mimikatz"], "凭据转储"),
            ToolInfo("rubeus", "internal_pentest", "exploit",
                     ["Rubeus.exe"], ["rubeus"], "Kerberos攻击工具"),

            # ========== 二进制逆向/恶意软件 ==========
            ToolInfo("radare2", "binary_reverse", "analysis",
                     ["r2.exe", "radare2.exe"], ["r2", "radare2"], "逆向工程框架"),
            ToolInfo("ghidra", "binary_reverse", "analysis",
                     ["ghidraRun.bat", "ghidraRun"], ["ghidraRun"], "NSA逆向工具"),
            ToolInfo("gdb", "binary_reverse", "analysis",
                     ["gdb.exe"], ["gdb"], "GNU调试器"),
            ToolInfo("pwntools", "binary_reverse", "exploit",
                     [], ["python3 -c 'import pwn'"], "CTF漏洞利用框架"),
            ToolInfo("strings", "binary_reverse", "recon",
                     ["strings.exe"], ["strings"], "字符串提取"),
            ToolInfo("yara", "binary_reverse", "scanner",
                     ["yara.exe"], ["yara"], "恶意软件规则匹配"),
            ToolInfo("capa", "binary_reverse", "analysis",
                     ["capa.exe"], ["capa"], "恶意软件能力识别"),

            # ========== 无线网络安全 ==========
            ToolInfo("aircrack-ng", "wireless_security", "exploit",
                     ["aircrack-ng.exe"], ["aircrack-ng"], "WiFi密码破解"),
            ToolInfo("airodump-ng", "wireless_security", "recon",
                     ["airodump-ng.exe"], ["airodump-ng"], "WiFi数据包捕获"),
            ToolInfo("hashcat", "wireless_security", "exploit",
                     ["hashcat.exe"], ["hashcat"], "高速密码破解"),
            ToolInfo("bettercap", "wireless_security", "exploit",
                     ["bettercap.exe"], ["bettercap"], "中间人攻击框架"),
            ToolInfo("kismet", "wireless_security", "recon",
                     ["kismet.exe"], ["kismet"], "无线网络检测"),
            ToolInfo("reaver", "wireless_security", "exploit",
                     ["reaver.exe"], ["reaver"], "WPS PIN破解"),

            # ========== 工控ICS/SCADA ==========
            ToolInfo("nmap-ics", "ics_scada_security", "scanner",
                     ["nmap.exe"], ["nmap"], "Nmap ICS脚本（modbus/s7-enum）"),
            ToolInfo("wireshark", "ics_scada_security", "analysis",
                     ["Wireshark.exe", "tshark.exe"], ["wireshark", "tshark"], "网络协议分析"),
            ToolInfo("scapy", "ics_scada_security", "exploit",
                     [], ["python3 -c 'import scapy'"], "数据包构造工具"),
            ToolInfo("modbus-cli", "ics_scada_security", "exploit",
                     ["modbus-cli.exe"], ["modbus-cli"], "Modbus协议工具"),
            ToolInfo("s7scan", "ics_scada_security", "recon",
                     ["s7scan.exe"], ["s7scan"], "S7 PLC扫描"),

            # ========== 物联网IoT ==========
            ToolInfo("binwalk", "iot_security", "analysis",
                     ["binwalk.exe"], ["binwalk"], "固件分析提取"),
            ToolInfo("firmwalker", "iot_security", "scanner",
                     ["firmwalker.sh"], ["firmwalker"], "固件漏洞扫描"),
            ToolInfo("emba", "iot_security", "scanner",
                     ["emba.sh"], ["emba"], "嵌入式固件审计"),
            ToolInfo("shodan", "iot_security", "recon",
                     ["shodan.exe"], ["shodan"], "IoT设备搜索引擎"),
            ToolInfo("mqtt-explorer", "iot_security", "analysis",
                     ["MQTT-Explorer.exe"], ["mqtt-explorer"], "MQTT客户端"),

            # ========== 社会工程学 ==========
            ToolInfo("gophish", "social_engineering", "exploit",
                     ["gophish.exe"], ["gophish"], "钓鱼模拟平台"),
            ToolInfo("setoolkit", "social_engineering", "exploit",
                     ["setoolkit.exe"], ["setoolkit"], "社会工程学工具包"),
            ToolInfo("theharvester", "social_engineering", "recon",
                     ["theHarvester.py", "theharvester.exe"], ["theHarvester.py"], "OSINT信息收集"),
            ToolInfo("recon-ng", "social_engineering", "recon",
                     ["recon-ng.exe"], ["recon-ng"], "OSINT侦察框架"),
            ToolInfo("maltego", "social_engineering", "analysis",
                     ["maltego.exe"], ["maltego"], "可视化OSINT分析"),

            # ========== 数字取证 ==========
            ToolInfo("volatility", "digital_forensics", "analysis",
                     ["vol.exe", "volatility.exe"], ["vol.py", "volatility"], "内存取证框架"),
            ToolInfo("autopsy", "digital_forensics", "analysis",
                     ["autopsy.exe"], ["autopsy"], "数字取证平台"),
            ToolInfo("sleuthkit", "digital_forensics", "analysis",
                     ["fls.exe", "istat.exe"], ["fls", "istat"], "文件系统取证工具集"),
            ToolInfo("regripper", "digital_forensics", "analysis",
                     ["rip.exe", "regripper.exe"], ["regripper"], "注册表分析"),
            ToolInfo("bulk_extractor", "digital_forensics", "scanner",
                     ["bulk_extractor.exe"], ["bulk_extractor"], "批量证据提取"),
            ToolInfo("foremost", "digital_forensics", "analysis",
                     ["foremost.exe"], ["foremost"], "文件恢复工具"),
            ToolInfo("wireshark-forensics", "digital_forensics", "analysis",
                     ["Wireshark.exe", "tshark.exe"], ["wireshark", "tshark"], "网络流量取证"),
        ]

    def _detect_all(self):
        """检测所有工具是否安装"""
        for tool in self.tools:
            names = tool.windows_names if self.os_type == "windows" else tool.linux_names
            for name in names:
                path = shutil.which(name)
                if path:
                    tool.installed = True
                    tool.path = path
                    break

    def get_domain_tools(self, domain: str) -> List[ToolInfo]:
        """获取指定领域的所有工具"""
        return [t for t in self.tools if t.domain == domain]

    def get_installed_tools(self, domain: str = None) -> List[ToolInfo]:
        """获取已安装的工具"""
        tools = self.tools if domain is None else self.get_domain_tools(domain)
        return [t for t in tools if t.installed]

    def get_domain_coverage(self) -> Dict[str, Dict]:
        """获取每个领域的工具覆盖率"""
        coverage = {}
        domains = set(t.domain for t in self.tools)
        for domain in sorted(domains):
            domain_tools = self.get_domain_tools(domain)
            installed = [t for t in domain_tools if t.installed]
            coverage[domain] = {
                "total": len(domain_tools),
                "installed": len(installed),
                "coverage": round(len(installed) / len(domain_tools) * 100, 1) if domain_tools else 0,
                "installed_tools": [t.name for t in installed],
                "missing_tools": [t.name for t in domain_tools if not t.installed],
            }
        return coverage

    def get_summary(self) -> Dict:
        """获取工具检测总览"""
        total = len(self.tools)
        installed = len([t for t in self.tools if t.installed])
        return {
            "os": self.os_type,
            "total_tools": total,
            "installed_tools": installed,
            "coverage": round(installed / total * 100, 1),
            "domains": len(set(t.domain for t in self.tools)),
            "domain_coverage": self.get_domain_coverage(),
        }


# 全局单例
_detector: DomainToolDetector = None


def get_detector() -> DomainToolDetector:
    """获取工具检测器单例"""
    global _detector
    if _detector is None:
        _detector = DomainToolDetector()
    return _detector


if __name__ == "__main__":
    detector = get_detector()
    summary = detector.get_summary()
    print(f"OS: {summary['os']}")
    print(f"工具总数: {summary['total_tools']}")
    print(f"已安装: {summary['installed_tools']}")
    print(f"总覆盖率: {summary['coverage']}%")
    print(f"领域数: {summary['domains']}")
    print("\n各领域覆盖率:")
    for domain, cov in summary['domain_coverage'].items():
        print(f"  {domain:30s} {cov['installed']:2d}/{cov['total']:2d} ({cov['coverage']:5.1f}%)")
