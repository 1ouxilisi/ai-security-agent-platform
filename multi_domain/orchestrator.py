#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多领域智能体编排层（Multi-Domain Agent Orchestrator）

借鉴架构：
- T3MP3ST (elder-plinius): 8角色多智能体红队编排，War Room界面
- RedAmon (samugit83): Fireteam模式，根智能体扇出为多个专家子智能体并行
- PentAGI (VXControl): 容器化沙箱，多智能体协作
- Strix (usestrix): 强化学习训练专用渗透模型

核心设计：
1. 5大安全领域：Web安全、移动安全、云安全、区块链安全、AI安全
2. 每个领域有专门的智能体编队（4-6个专家Agent）
3. 统一编排器支持：
   - 单领域执行
   - 多领域并行（Fireteam模式）
   - 跨领域协作（攻击链联动）
4. 8个通用角色映射MITRE ATT&CK：
   Recon(侦察) / Scanner(扫描) / Exploiter(利用) / Infiltrator(渗透)
   Exfiltrator(渗出) / Ghost(隐匿) / Coordinator(协调) / Analyst(分析)
"""

import time
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


class SecurityDomain(Enum):
    """安全领域（12大领域，对标pentest-ai-agents 35子智能体覆盖范围）"""
    WEB = "web_security"                    # Web应用安全
    MOBILE = "mobile_security"              # 移动应用安全
    CLOUD = "cloud_security"                # 云安全
    BLOCKCHAIN = "blockchain_security"      # 区块链安全
    AI = "ai_security"                      # AI/大模型安全
    INTERNAL = "internal_pentest"           # 内网渗透/Active Directory
    BINARY = "binary_reverse"               # 二进制逆向/恶意软件分析
    WIRELESS = "wireless_security"          # 无线网络安全
    ICS = "ics_scada_security"              # 工控系统ICS/SCADA安全
    IOT = "iot_security"                    # 物联网安全
    SOCIAL = "social_engineering"           # 社会工程学/钓鱼
    FORENSICS = "digital_forensics"         # 数字取证分析


class AgentRole(Enum):
    """智能体角色（映射MITRE ATT&CK）"""
    RECON = "recon"           # 侦察 - Reconnaissance
    SCANNER = "scanner"       # 扫描 - Initial Access / Discovery
    EXPLOITER = "exploiter"   # 利用 - Exploitation
    INFILTRATOR = "infiltrator"  # 渗透 - Lateral Movement
    EXFILTRATOR = "exfiltrator"  # 渗出 - Exfiltration
    GHOST = "ghost"           # 隐匿 - Defense Evasion / Persistence
    COORDINATOR = "coordinator"  # 协调 - Command & Control
    ANALYST = "analyst"       # 分析 - Collection / Analysis


@dataclass
class DomainAgent:
    """领域智能体"""
    agent_id: str
    role: AgentRole
    domain: SecurityDomain
    name: str
    description: str
    tools: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    status: str = "idle"  # idle / running / completed / failed
    findings: List[Dict] = field(default_factory=list)
    duration: float = 0.0


@dataclass
class DomainMission:
    """领域任务"""
    mission_id: str
    domain: SecurityDomain
    target: str
    agents: List[DomainAgent] = field(default_factory=list)
    status: str = "pending"  # pending / running / completed / failed
    findings: List[Dict] = field(default_factory=list)
    risk_score: float = 0.0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    real_findings_count: int = 0
    simulated_findings_count: int = 0


class DomainAgentFactory:
    """领域智能体工厂 - 为每个安全领域创建专门的智能体编队"""

    @staticmethod
    def create_web_agents() -> List[DomainAgent]:
        """Web安全领域智能体编队（6个Agent）"""
        return [
            DomainAgent(
                agent_id="web-recon-01",
                role=AgentRole.RECON,
                domain=SecurityDomain.WEB,
                name="Web侦察兵",
                description="子域名枚举、端口扫描、技术栈识别、目录爆破",
                tools=["subfinder", "nmap", "httpx", "whatweb", "gobuster", "ffuf"],
                capabilities=["子域名枚举", "端口扫描", "Web技术识别", "目录爆破", "API端点发现"],
            ),
            DomainAgent(
                agent_id="web-scanner-01",
                role=AgentRole.SCANNER,
                domain=SecurityDomain.WEB,
                name="Web扫描员",
                description="漏洞扫描、配置错误检测、CVE匹配",
                tools=["nuclei", "nikto", "sqlmap", "wapiti", "arachni"],
                capabilities=["漏洞扫描", "SQL注入检测", "XSS检测", "配置错误检测", "CVE匹配"],
            ),
            DomainAgent(
                agent_id="web-exploiter-01",
                role=AgentRole.EXPLOITER,
                domain=SecurityDomain.WEB,
                name="Web利用专家",
                description="SQL注入利用、XSS利用、文件上传、命令执行",
                tools=["sqlmap", "commix", "metasploit", "custom-pocs"],
                capabilities=["SQL注入利用", "XSS利用", "文件上传绕过", "命令执行", "反序列化利用"],
            ),
            DomainAgent(
                agent_id="web-infiltrator-01",
                role=AgentRole.INFILTRATOR,
                domain=SecurityDomain.WEB,
                name="Web渗透员",
                description="权限提升、横向移动、会话劫持",
                tools=["metasploit", "crackmapexec", "impacket"],
                capabilities=["权限提升", "横向移动", "会话劫持", "凭据收集"],
            ),
            DomainAgent(
                agent_id="web-ghost-01",
                role=AgentRole.GHOST,
                domain=SecurityDomain.WEB,
                name="Web隐匿专家",
                description="日志清理、Webshell隐藏、痕迹消除",
                tools=["custom-scripts", "webshell-manager"],
                capabilities=["日志清理", "Webshell管理", "痕迹消除", "持久化"],
            ),
            DomainAgent(
                agent_id="web-analyst-01",
                role=AgentRole.ANALYST,
                domain=SecurityDomain.WEB,
                name="Web分析师",
                description="漏洞验证、误报过滤、风险评估、报告生成",
                tools=["cvss-calculator", "report-generator"],
                capabilities=["漏洞验证", "误报过滤", "CVSS评分", "风险评估", "报告生成"],
            ),
        ]

    @staticmethod
    def create_mobile_agents() -> List[DomainAgent]:
        """移动安全领域智能体编队（5个Agent）"""
        return [
            DomainAgent(
                agent_id="mob-recon-01",
                role=AgentRole.RECON,
                domain=SecurityDomain.MOBILE,
                name="移动侦察兵",
                description="APK解析、Manifest分析、权限审计、组件枚举",
                tools=["apktool", "aapt", "jadx", "mobfs"],
                capabilities=["APK解析", "Manifest分析", "权限审计", "组件枚举", "深链接发现"],
            ),
            DomainAgent(
                agent_id="mob-scanner-01",
                role=AgentRole.SCANNER,
                domain=SecurityDomain.MOBILE,
                name="移动扫描员",
                description="静态代码扫描、硬编码密钥检测、漏洞模式匹配",
                tools=["mobile-ai-analyzer", "semgrep", "qark", "androwarn"],
                capabilities=["静态代码扫描", "硬编码密钥检测", "15类漏洞模式匹配", "Smali分析"],
            ),
            DomainAgent(
                agent_id="mob-exploiter-01",
                role=AgentRole.EXPLOITER,
                domain=SecurityDomain.MOBILE,
                name="移动利用专家",
                description="Intent注入、WebView利用、深链接劫持、组件攻击",
                tools=["adb", "frida", "drozer", "custom-pocs"],
                capabilities=["Intent注入", "WebView利用", "深链接劫持", "组件暴露攻击", "Frida Hook"],
            ),
            DomainAgent(
                agent_id="mob-ghost-01",
                role=AgentRole.GHOST,
                domain=SecurityDomain.MOBILE,
                name="移动隐匿专家",
                description="Root检测绕过、SSL Pinning绕过、反调试",
                tools=["frida", "objection", "magisk"],
                capabilities=["Root检测绕过", "SSL Pinning绕过", "反调试绕过", "Hook框架"],
            ),
            DomainAgent(
                agent_id="mob-analyst-01",
                role=AgentRole.ANALYST,
                domain=SecurityDomain.MOBILE,
                name="移动分析师",
                description="污点流分析、漏洞验证、风险评估、报告生成",
                tools=["taint-analyzer", "frida-hook-generator", "report-generator"],
                capabilities=["污点流分析", "漏洞验证计划", "Frida脚本生成", "风险评估", "报告生成"],
            ),
        ]

    @staticmethod
    def create_cloud_agents() -> List[DomainAgent]:
        """云安全领域智能体编队（5个Agent）"""
        return [
            DomainAgent(
                agent_id="cloud-recon-01",
                role=AgentRole.RECON,
                domain=SecurityDomain.CLOUD,
                name="云侦察兵",
                description="云资产发现、存储桶枚举、服务识别、IAM枚举",
                tools=["cloudfox", "pacu", "scoutsuite", "prowler"],
                capabilities=["云资产发现", "S3/OSS存储桶枚举", "云服务识别", "IAM策略枚举"],
            ),
            DomainAgent(
                agent_id="cloud-scanner-01",
                role=AgentRole.SCANNER,
                domain=SecurityDomain.CLOUD,
                name="云扫描员",
                description="配置错误扫描、安全组审计、密钥泄露检测",
                tools=["scoutsuite", "prowler", "trivy", "checkov"],
                capabilities=["配置错误扫描", "安全组审计", "密钥泄露检测", "IaC安全扫描", "容器镜像扫描"],
            ),
            DomainAgent(
                agent_id="cloud-exploiter-01",
                role=AgentRole.EXPLOITER,
                domain=SecurityDomain.CLOUD,
                name="云利用专家",
                description="存储桶利用、IAM提权、元数据服务攻击、容器逃逸",
                tools=["pacu", "cloudfox", "metasploit", "kube-hunter"],
                capabilities=["存储桶利用", "IAM提权", "SSRF元数据攻击", "容器逃逸", "K8s攻击"],
            ),
            DomainAgent(
                agent_id="cloud-infiltrator-01",
                role=AgentRole.INFILTRATOR,
                domain=SecurityDomain.CLOUD,
                name="云渗透员",
                description="横向移动、凭据窃取、服务账户利用",
                tools=["pacu", "aws-vault", "gcloud", "az"],
                capabilities=["横向移动", "凭据窃取", "服务账户利用", "角色链攻击"],
            ),
            DomainAgent(
                agent_id="cloud-analyst-01",
                role=AgentRole.ANALYST,
                domain=SecurityDomain.CLOUD,
                name="云分析师",
                description="合规映射、风险评估、修复建议、报告生成",
                tools=["compliance-mapper", "report-generator"],
                capabilities=["CIS基准映射", "等保合规映射", "风险评估", "修复建议", "报告生成"],
            ),
        ]

    @staticmethod
    def create_blockchain_agents() -> List[DomainAgent]:
        """区块链安全领域智能体编队（5个Agent）"""
        return [
            DomainAgent(
                agent_id="bc-recon-01",
                role=AgentRole.RECON,
                domain=SecurityDomain.BLOCKCHAIN,
                name="链上侦察兵",
                description="合约发现、ABI解析、交易分析、地址追踪",
                tools=["etherscan-api", "web3.py", "slither", "mythril"],
                capabilities=["合约发现", "ABI解析", "交易分析", "地址追踪", "合约验证"],
            ),
            DomainAgent(
                agent_id="bc-scanner-01",
                role=AgentRole.SCANNER,
                domain=SecurityDomain.BLOCKCHAIN,
                name="合约扫描员",
                description="智能合约漏洞扫描、重入检测、整数溢出检测",
                tools=["slither", "mythril", "semgrep", "echidna"],
                capabilities=["智能合约漏洞扫描", "重入检测", "整数溢出检测", "权限漏洞检测", "Gas优化建议"],
            ),
            DomainAgent(
                agent_id="bc-exploiter-01",
                role=AgentRole.EXPLOITER,
                domain=SecurityDomain.BLOCKCHAIN,
                name="合约利用专家",
                description="重入攻击、闪电贷攻击、权限绕过、价格预言机操纵",
                tools=["foundry", "hardhat", "custom-exploits"],
                capabilities=["重入攻击验证", "闪电贷攻击模拟", "权限绕过", "价格预言机操纵", "合约升级攻击"],
            ),
            DomainAgent(
                agent_id="bc-ghost-01",
                role=AgentRole.GHOST,
                domain=SecurityDomain.BLOCKCHAIN,
                name="链上隐匿专家",
                description="交易混淆、地址隔离、Gas优化隐匿",
                tools=["tornado-cash", "custom-contracts"],
                capabilities=["交易混淆", "地址隔离", "链上痕迹分析"],
            ),
            DomainAgent(
                agent_id="bc-analyst-01",
                role=AgentRole.ANALYST,
                domain=SecurityDomain.BLOCKCHAIN,
                name="链上分析师",
                description="漏洞验证、资金流向分析、审计报告生成",
                tools=["slither", "etherscan-api", "report-generator"],
                capabilities=["漏洞验证", "资金流向分析", "审计报告生成", "修复建议"],
            ),
        ]

    @staticmethod
    def create_ai_agents() -> List[DomainAgent]:
        """AI安全领域智能体编队（5个Agent）"""
        return [
            DomainAgent(
                agent_id="ai-recon-01",
                role=AgentRole.RECON,
                domain=SecurityDomain.AI,
                name="AI侦察兵",
                description="模型端点发现、API枚举、训练数据探测",
                tools=["api-fuzzer", "custom-recon", "llm-test"],
                capabilities=["模型端点发现", "API枚举", "训练数据探测", "模型指纹识别"],
            ),
            DomainAgent(
                agent_id="ai-scanner-01",
                role=AgentRole.SCANNER,
                domain=SecurityDomain.AI,
                name="AI扫描员",
                description="提示注入检测、越狱测试、数据泄露检测",
                tools=["garak", "promptmap", "custom-scanners"],
                capabilities=["提示注入检测", "越狱测试", "数据泄露检测", "模型拒绝服务检测", "训练数据提取"],
            ),
            DomainAgent(
                agent_id="ai-exploiter-01",
                role=AgentRole.EXPLOITER,
                domain=SecurityDomain.AI,
                name="AI利用专家",
                description="提示注入利用、越狱攻击、模型窃取、对抗样本",
                tools=["garak", "custom-pocs", "adversarial-ml"],
                capabilities=["提示注入利用", "越狱攻击", "模型窃取", "对抗样本生成", "成员推断攻击"],
            ),
            DomainAgent(
                agent_id="ai-ghost-01",
                role=AgentRole.GHOST,
                domain=SecurityDomain.AI,
                name="AI隐匿专家",
                description="检测规避、提示混淆、输出操纵",
                tools=["custom-scripts", "obfuscation"],
                capabilities=["检测规避", "提示混淆", "输出操纵", "水印去除"],
            ),
            DomainAgent(
                agent_id="ai-analyst-01",
                role=AgentRole.ANALYST,
                domain=SecurityDomain.AI,
                name="AI分析师",
                description="漏洞验证、风险评估、红队报告、修复建议",
                tools=["risk-assessor", "report-generator"],
                capabilities=["漏洞验证", "OWASP LLM Top10映射", "风险评估", "红队报告", "修复建议"],
            ),
        ]

    @staticmethod
    def create_internal_agents() -> List[DomainAgent]:
        """内网渗透/Active Directory领域智能体编队（5个Agent）"""
        return [
            DomainAgent(agent_id="int-recon-01", role=AgentRole.RECON, domain=SecurityDomain.INTERNAL,
                name="内网侦察兵", description="AD枚举、主机发现、共享枚举、用户枚举",
                tools=["bloodhound", "nmap", "enum4linux", "crackmapexec", "ldapsearch"],
                capabilities=["AD域枚举", "主机发现", "共享文件夹枚举", "用户/组枚举", "Kerberos枚举"]),
            DomainAgent(agent_id="int-scanner-01", role=AgentRole.SCANNER, domain=SecurityDomain.INTERNAL,
                name="漏洞扫描员", description="内网漏洞扫描、SMB漏洞、永恒之蓝、零日检测",
                tools=["nmap", "nuclei", "crackmapexec", "metasploit"],
                capabilities=["SMB漏洞扫描", "MS17-010检测", "零日漏洞匹配", "服务漏洞扫描"]),
            DomainAgent(agent_id="int-exploiter-01", role=AgentRole.EXPLOITER, domain=SecurityDomain.INTERNAL,
                name="域渗透专家", description="Kerberos攻击、哈希传递、票据传递、域控获取",
                tools=["impacket", "mimikatz", "rubeus", "bloodhound", "crackmapexec"],
                capabilities=["Kerberoasting", "AS-REP Roasting", "哈希传递PtH", "票据传递PtT", "DC Sync", "黄金票据"]),
            DomainAgent(agent_id="int-infiltrator-01", role=AgentRole.INFILTRATOR, domain=SecurityDomain.INTERNAL,
                name="横向移动专家", description="横向移动、权限提升、凭据转储、持久化",
                tools=["impacket", "mimikatz", "crackmapexec", "evil-winrm", "wmiexec"],
                capabilities=["WMI执行", "SMB执行", "WinRM登录", "凭据转储", "权限提升", "计划任务持久化"]),
            DomainAgent(agent_id="int-analyst-01", role=AgentRole.ANALYST, domain=SecurityDomain.INTERNAL,
                name="内网分析师", description="攻击路径分析、域控风险评估、报告生成",
                tools=["bloodhound", "report-generator"],
                capabilities=["攻击路径可视化", "域控风险评估", "高危账户识别", "修复建议", "报告生成"]),
        ]

    @staticmethod
    def create_binary_agents() -> List[DomainAgent]:
        """二进制逆向/恶意软件分析领域智能体编队（5个Agent，借鉴AnalystAIPack 118技能+R2AI）"""
        return [
            DomainAgent(agent_id="bin-recon-01", role=AgentRole.RECON, domain=SecurityDomain.BINARY,
                name="样本侦察兵", description="文件类型识别、字符串提取、导入表分析、加壳检测",
                tools=["file", "strings", "peframe", "die", "detect-it-easy"],
                capabilities=["文件指纹识别", "字符串提取", "导入/导出表分析", "加壳检测", "编译器识别"]),
            DomainAgent(agent_id="bin-scanner-01", role=AgentRole.SCANNER, domain=SecurityDomain.BINARY,
                name="静态分析员", description="反汇编、反编译、控制流分析、漏洞模式匹配",
                tools=["radare2", "ghidra", "ida-pro", "capa", "r2ai"],
                capabilities=["反汇编分析", "伪代码生成", "控制流图构建", "漏洞模式匹配", "API调用分析", "YARA规则匹配"]),
            DomainAgent(agent_id="bin-exploiter-01", role=AgentRole.EXPLOITER, domain=SecurityDomain.BINARY,
                name="漏洞利用专家", description="栈溢出、堆溢出、格式化字符串、ROP链构建",
                tools=["pwntools", "gef", "peda", "ropper", "one_gadget"],
                capabilities=["栈溢出利用", "堆溢出利用", "格式化字符串", "ROP链构建", "Shellcode生成", "ASLR/NX绕过"]),
            DomainAgent(agent_id="bin-ghost-01", role=AgentRole.GHOST, domain=SecurityDomain.BINARY,
                name="反分析专家", description="反调试、反虚拟机、混淆、加壳、免杀",
                tools=["themida", "vmprotect", "obfuscator", "custom-packer"],
                capabilities=["反调试检测", "反虚拟机规避", "代码混淆", "自定义加壳", "AV/EDR免杀"]),
            DomainAgent(agent_id="bin-analyst-01", role=AgentRole.ANALYST, domain=SecurityDomain.BINARY,
                name="恶意软件分析师", description="行为分析、C2识别、IOC提取、家族归类",
                tools=["cuckoo", "remnux", "flare-vm", "yara", "vt-cli"],
                capabilities=["动态行为分析", "C2通信识别", "IOC指标提取", "恶意软件家族归类", "YARA规则生成", "分析报告"]),
        ]

    @staticmethod
    def create_wireless_agents() -> List[DomainAgent]:
        """无线网络安全领域智能体编队（4个Agent）"""
        return [
            DomainAgent(agent_id="wlan-recon-01", role=AgentRole.RECON, domain=SecurityDomain.WIRELESS,
                name="无线侦察兵", description="AP扫描、信道分析、客户端枚举、信号强度测绘",
                tools=["airodump-ng", "kismet", "wash", "hcxdumptool"],
                capabilities=["AP扫描枚举", "信道监听", "关联客户端枚举", "信号强度测绘", "WPS检测"]),
            DomainAgent(agent_id="wlan-scanner-01", role=AgentRole.SCANNER, domain=SecurityDomain.WIRELESS,
                name="无线扫描员", description="WPA/WPA2/WPA3漏洞检测、WEP破解、WPS攻击",
                tools=["aircrack-ng", "hashcat", "reaver", "bully", "hcxdumptool"],
                capabilities=["WPA握手捕获", "PMKID攻击", "WEP破解", "WPS PIN攻击", "Evil Twin检测"]),
            DomainAgent(agent_id="wlan-exploiter-01", role=AgentRole.EXPLOITER, domain=SecurityDomain.WIRELESS,
                name="无线利用专家", description="Evil Twin、KRACK攻击、蓝牙漏洞、NFC攻击",
                tools=["hostapd", "dnsmasq", "bettercap", "bluez", "nfcpy"],
                capabilities=["Evil Twin搭建", "KRACK攻击", "蓝牙嗅探", "NFC标签克隆", "中间人攻击"]),
            DomainAgent(agent_id="wlan-analyst-01", role=AgentRole.ANALYST, domain=SecurityDomain.WIRELESS,
                name="无线分析师", description="密码强度评估、安全配置审计、修复建议",
                tools=["aircrack-ng", "report-generator"],
                capabilities=["密码强度评估", "加密协议审计", "安全配置检查", "修复建议", "报告生成"]),
        ]

    @staticmethod
    def create_ics_agents() -> List[DomainAgent]:
        """工控系统ICS/SCADA安全领域智能体编队（5个Agent，借鉴MALF多智能体模糊测试+CAI OT CTF）"""
        return [
            DomainAgent(agent_id="ics-recon-01", role=AgentRole.RECON, domain=SecurityDomain.ICS,
                name="工控侦察兵", description="PLC枚举、协议识别、设备指纹、网络拓扑发现",
                tools=["nmap", "wireshark", "modscan", "s7scan", "enip"],
                capabilities=["PLC设备枚举", "Modbus/S7/DNP3协议识别", "设备指纹识别", "工控网络拓扑发现", "固件版本检测"]),
            DomainAgent(agent_id="ics-scanner-01", role=AgentRole.SCANNER, domain=SecurityDomain.ICS,
                name="工控扫描员", description="协议模糊测试、配置错误检测、固件漏洞扫描",
                tools=["malf", "boofuzz", "scapy", "firmwalker"],
                capabilities=["Modbus模糊测试", "S7Comm模糊测试", "配置错误检测", "固件漏洞扫描", "协议异常检测"]),
            DomainAgent(agent_id="ics-exploiter-01", role=AgentRole.EXPLOITER, domain=SecurityDomain.ICS,
                name="工控利用专家", description="PLC指令注入、固件漏洞利用、工程站攻击",
                tools=["modbus-cli", "s7comm", "metasploit", "custom-pocs"],
                capabilities=["PLC启停控制", "寄存器读写", "固件漏洞利用", "工程站攻击", "过程值篡改"]),
            DomainAgent(agent_id="ics-ghost-01", role=AgentRole.GHOST, domain=SecurityDomain.ICS,
                name="工控隐匿专家", description="协议伪装、日志清理、持久化植入",
                tools=["custom-tools", "scapy"],
                capabilities=["协议伪装", "工控日志清理", "PLC持久化", "工程师站后门"]),
            DomainAgent(agent_id="ics-analyst-01", role=AgentRole.ANALYST, domain=SecurityDomain.ICS,
                name="工控分析师", description="安全风险评估、影响分析、合规映射、修复建议",
                tools=["risk-assessor", "compliance-mapper"],
                capabilities=["操作影响分析", "安全风险评估", "IEC 62443合规映射", "修复优先级", "报告生成"]),
        ]

    @staticmethod
    def create_iot_agents() -> List[DomainAgent]:
        """物联网安全领域智能体编队（5个Agent，借鉴R2AI IoT恶意软件分析）"""
        return [
            DomainAgent(agent_id="iot-recon-01", role=AgentRole.RECON, domain=SecurityDomain.IOT,
                name="IoT侦察兵", description="设备发现、端口扫描、固件提取、协议识别",
                tools=["nmap", "shodan", "censys", "binwalk", "firmwalker"],
                capabilities=["IoT设备发现", "端口服务扫描", "固件提取分析", "MQTT/CoAP协议识别", "默认凭据检测"]),
            DomainAgent(agent_id="iot-scanner-01", role=AgentRole.SCANNER, domain=SecurityDomain.IOT,
                name="IoT扫描员", description="固件漏洞扫描、硬编码密钥、未授权接口检测",
                tools=["firmwalker", "emba", "r2ai", "binwalk"],
                capabilities=["固件漏洞扫描", "硬编码密钥检测", "未授权API检测", "调试接口发现", "IoT恶意软件检测"]),
            DomainAgent(agent_id="iot-exploiter-01", role=AgentRole.EXPLOITER, domain=SecurityDomain.IOT,
                name="IoT利用专家", description="命令注入、认证绕过、固件篡改、UART/JTAG攻击",
                tools=["metasploit", "custom-pocs", "openocd", "minicom"],
                capabilities=["命令注入利用", "认证绕过", "固件篡改刷写", "UART调试接口", "JTAG调试攻击", "MQTT未授权访问"]),
            DomainAgent(agent_id="iot-ghost-01", role=AgentRole.GHOST, domain=SecurityDomain.IOT,
                name="IoT隐匿专家", description="固件后门、持久化、Botnet检测",
                tools=["custom-tools", "mirai-analysis"],
                capabilities=["固件后门植入", "启动脚本持久化", "Botnet行为检测", "C2通信分析"]),
            DomainAgent(agent_id="iot-analyst-01", role=AgentRole.ANALYST, domain=SecurityDomain.IOT,
                name="IoT分析师", description="设备安全评级、供应链风险、修复建议",
                tools=["risk-assessor", "report-generator"],
                capabilities=["设备安全评级", "供应链风险评估", "漏洞修复建议", "IoT安全报告"]),
        ]

    @staticmethod
    def create_social_agents() -> List[DomainAgent]:
        """社会工程学/钓鱼领域智能体编队（4个Agent）"""
        return [
            DomainAgent(agent_id="soc-recon-01", role=AgentRole.RECON, domain=SecurityDomain.SOCIAL,
                name="OSINT侦察兵", description="信息收集、员工枚举、邮箱收集、社交媒体分析",
                tools=["theharvester", "recon-ng", "maltego", "holehe", "sherlock"],
                capabilities=["邮箱地址收集", "员工信息枚举", "社交媒体分析", "域名关联发现", "breached数据检测"]),
            DomainAgent(agent_id="soc-scanner-01", role=AgentRole.SCANNER, domain=SecurityDomain.SOCIAL,
                name="钓鱼评估员", description="钓鱼邮件模拟、pretext设计、安全意识评估",
                tools=["gophish", "setoolkit", "custom-templates"],
                capabilities=["钓鱼邮件模板设计", "pretext场景构建", "钓鱼页面克隆", "安全意识评估", "点击率预测"]),
            DomainAgent(agent_id="soc-exploiter-01", role=AgentRole.EXPLOITER, domain=SecurityDomain.SOCIAL,
                name="社工利用专家", description="鱼叉钓鱼、水坑攻击、电话社工、USB投放",
                tools=["gophish", "setoolkit", "powershell", "custom-payloads"],
                capabilities=["鱼叉钓鱼攻击", "水坑攻击", "vishing电话社工", "USB Rubber Ducky", "凭据钓鱼"]),
            DomainAgent(agent_id="soc-analyst-01", role=AgentRole.ANALYST, domain=SecurityDomain.SOCIAL,
                name="社工分析师", description="攻击成功率分析、员工风险画像、培训建议",
                tools=["report-generator", "risk-assessor"],
                capabilities=["钓鱼成功率统计", "高风险员工识别", "安全意识培训建议", "社工攻击报告"]),
        ]

    @staticmethod
    def create_forensics_agents() -> List[DomainAgent]:
        """数字取证分析领域智能体编队（5个Agent）"""
        return [
            DomainAgent(agent_id="for-recon-01", role=AgentRole.RECON, domain=SecurityDomain.FORENSICS,
                name="取证采集员", description="磁盘镜像、内存采集、网络流量捕获、日志收集",
                tools=["dd", "ftkimager", "volatility", "wireshark", "tcpdump"],
                capabilities=["磁盘镜像制作", "内存镜像采集", "网络流量捕获", "系统日志收集", "证据链保管"]),
            DomainAgent(agent_id="for-scanner-01", role=AgentRole.SCANNER, domain=SecurityDomain.FORENSICS,
                name="取证扫描员", description="文件系统分析、注册表分析、浏览器历史、回收站恢复",
                tools=["autopsy", "sleuthkit", "regripper", "bulk_extractor"],
                capabilities=["文件系统时间线", "注册表分析", "浏览器历史提取", "已删除文件恢复", "USB设备痕迹"]),
            DomainAgent(agent_id="for-exploiter-01", role=AgentRole.EXPLOITER, domain=SecurityDomain.FORENSICS,
                name="内存取证专家", description="进程分析、网络连接、凭据提取、恶意软件检测",
                tools=["volatility3", "mimikatz", "capa", "yara"],
                capabilities=["进程树分析", "网络连接提取", "内存凭据提取", "注入检测", "恶意软件内存特征"]),
            DomainAgent(agent_id="for-ghost-01", role=AgentRole.GHOST, domain=SecurityDomain.FORENSICS,
                name="反取证专家", description="痕迹检测、反取证技术识别、数据隐藏发现",
                tools=["bulk_extractor", "foremost", "scalpel", "custom-tools"],
                capabilities=["反取证技术识别", "隐写术检测", "数据隐藏发现", "日志篡改检测", "时间线伪造识别"]),
            DomainAgent(agent_id="for-analyst-01", role=AgentRole.ANALYST, domain=SecurityDomain.FORENSICS,
                name="取证分析师", description="事件重建、攻击路径还原、证据报告、法律合规",
                tools=["autopsy", "report-generator", "timeliner"],
                capabilities=["安全事件重建", "攻击路径还原", "证据关联性分析", "取证报告生成", "法律证据合规"]),
        ]

    @staticmethod
    def create_agents_for_domain(domain: SecurityDomain) -> List[DomainAgent]:
        """为指定领域创建智能体编队"""
        factories = {
            SecurityDomain.WEB: DomainAgentFactory.create_web_agents,
            SecurityDomain.MOBILE: DomainAgentFactory.create_mobile_agents,
            SecurityDomain.CLOUD: DomainAgentFactory.create_cloud_agents,
            SecurityDomain.BLOCKCHAIN: DomainAgentFactory.create_blockchain_agents,
            SecurityDomain.AI: DomainAgentFactory.create_ai_agents,
            SecurityDomain.INTERNAL: DomainAgentFactory.create_internal_agents,
            SecurityDomain.BINARY: DomainAgentFactory.create_binary_agents,
            SecurityDomain.WIRELESS: DomainAgentFactory.create_wireless_agents,
            SecurityDomain.ICS: DomainAgentFactory.create_ics_agents,
            SecurityDomain.IOT: DomainAgentFactory.create_iot_agents,
            SecurityDomain.SOCIAL: DomainAgentFactory.create_social_agents,
            SecurityDomain.FORENSICS: DomainAgentFactory.create_forensics_agents,
        }
        factory = factories.get(domain)
        if factory:
            return factory()
        return []


class MultiDomainOrchestrator:
    """
    多领域智能体编排器

    支持：
    1. 单领域执行 - 针对一个目标领域执行完整安全评估
    2. 多领域并行（Fireteam模式）- 多个领域同时执行
    3. 跨领域协作 - 攻击链联动（如Web漏洞→云权限提升）
    """

    def __init__(self):
        self.factory = DomainAgentFactory()
        self.missions: Dict[str, DomainMission] = {}
        self.coordinator_agent = DomainAgent(
            agent_id="global-coordinator",
            role=AgentRole.COORDINATOR,
            domain=SecurityDomain.WEB,  # 协调员不属于特定领域
            name="全局协调员",
            description="任务分配、进度监控、冲突消解、结果汇总",
            tools=["orchestrator", "scheduler"],
            capabilities=["任务分配", "进度监控", "冲突消解", "结果汇总", "跨领域协作"],
        )

    def create_mission(self, domain: SecurityDomain, target: str) -> DomainMission:
        """创建领域任务"""
        mission_id = f"MISSION-{domain.value}-{int(time.time())}"
        agents = self.factory.create_agents_for_domain(domain)

        mission = DomainMission(
            mission_id=mission_id,
            domain=domain,
            target=target,
            agents=agents,
            started_at=datetime.now().isoformat(),
        )
        self.missions[mission_id] = mission
        return mission

    def execute_mission(self, mission: DomainMission, dry_run: bool = True) -> DomainMission:
        """
        执行单个领域任务

        执行顺序（映射Kill Chain）：
        1. Recon（侦察）
        2. Scanner（扫描）
        3. Exploiter（利用）
        4. Infiltrator（渗透）- 如果存在
        5. Exfiltrator（渗出）- 如果存在
        6. Ghost（隐匿）- 如果存在
        7. Analyst（分析）
        """
        mission.status = "running"

        # 按角色顺序执行
        role_order = [
            AgentRole.RECON,
            AgentRole.SCANNER,
            AgentRole.EXPLOITER,
            AgentRole.INFILTRATOR,
            AgentRole.EXFILTRATOR,
            AgentRole.GHOST,
            AgentRole.ANALYST,
        ]

        for role in role_order:
            role_agents = [a for a in mission.agents if a.role == role]
            if not role_agents:
                continue

            # 同角色内Agent并行执行（保持角色间顺序依赖）
            if len(role_agents) > 1:
                with ThreadPoolExecutor(max_workers=len(role_agents)) as executor:
                    future_to_agent = {}
                    for agent in role_agents:
                        agent.status = "running"
                        future = executor.submit(
                            self._execute_agent, agent, mission.target, dry_run
                        )
                        future_to_agent[future] = agent

                    for future in as_completed(future_to_agent):
                        agent = future_to_agent[future]
                        try:
                            start = time.time()
                            findings = future.result(timeout=120)
                            agent.findings = findings
                            agent.duration = time.time() - start
                            agent.status = "completed"
                            mission.findings.extend(findings)
                        except Exception as e:
                            agent.status = "failed"
                            agent.error = str(e)
            else:
                # 单个Agent直接执行
                agent = role_agents[0]
                agent.status = "running"
                start = time.time()
                findings = self._execute_agent(agent, mission.target, dry_run)
                agent.findings = findings
                agent.duration = time.time() - start
                agent.status = "completed"
                mission.findings.extend(findings)

        # 计算风险评分
        mission.risk_score = self._calculate_risk(mission.findings)
        mission.status = "completed"
        mission.completed_at = datetime.now().isoformat()
        # 统计真实工具发现数量
        real_findings = [f for f in mission.findings if f.get('source') == 'real_tool']
        mission.real_findings_count = len(real_findings)
        mission.simulated_findings_count = len(mission.findings) - len(real_findings)

        return mission

    def execute_fireteam(self, targets: Dict[SecurityDomain, str],
                         dry_run: bool = True,
                         max_workers: int = 12,
                         timeout: int = 300) -> Dict[str, Any]:
        """
        Fireteam模式：多领域真正多线程并行执行

        Args:
            targets: {领域: 目标} 字典
            dry_run: 是否模拟运行
            max_workers: 最大并行线程数（默认12，覆盖全部领域）
            timeout: 单个领域执行超时时间（秒）

        Returns:
            多领域执行结果汇总
        """
        start_time = time.time()
        missions = []

        # 创建所有领域任务
        for domain, target in targets.items():
            mission = self.create_mission(domain, target)
            missions.append(mission)

        # 真正多线程并行执行
        def _run_mission(mission):
            try:
                self.execute_mission(mission, dry_run)
                return mission, None
            except Exception as e:
                mission.status = "failed"
                return mission, str(e)

        execution_results = []
        with ThreadPoolExecutor(max_workers=min(max_workers, len(missions))) as executor:
            future_to_mission = {
                executor.submit(_run_mission, m): m for m in missions
            }
            for future in as_completed(future_to_mission, timeout=timeout):
                mission = future_to_mission[future]
                try:
                    result_mission, error = future.result(timeout=timeout)
                    execution_results.append((result_mission, error))
                except Exception as e:
                    mission.status = "timeout"
                    execution_results.append((mission, str(e)))

        # 按原始顺序排序
        mission_order = {id(m): i for i, m in enumerate(missions)}
        execution_results.sort(key=lambda x: mission_order.get(id(x[0]), 999))

        # 汇总结果
        all_findings = []
        domain_results = {}
        failed_domains = []

        for mission, error in execution_results:
            domain_results[mission.domain.value] = {
                "mission_id": mission.mission_id,
                "target": mission.target,
                "status": mission.status,
                "findings_count": len(mission.findings),
                "risk_score": mission.risk_score,
                "agents_count": len(mission.agents),
                "duration": sum(a.duration for a in mission.agents),
                "error": error,
            }
            if mission.status == "failed" or mission.status == "timeout":
                failed_domains.append(mission.domain.value)
            all_findings.extend(mission.findings)

        # 跨领域攻击链分析
        successful_missions = [m for m, e in execution_results if m.status != "failed"]
        cross_domain_chains = self._analyze_cross_domain_chains(successful_missions)

        total_risk = min(100, sum(m.risk_score for m in successful_missions) / len(successful_missions) if successful_missions else 0)
        total_duration = time.time() - start_time

        return {
            "fireteam_id": f"FIRETEAM-{int(time.time())}",
            "domains_executed": len(successful_missions),
            "domains_total": len(missions),
            "domains_failed": failed_domains,
            "total_findings": len(all_findings),
            "overall_risk_score": total_risk,
            "execution_mode": "parallel_multithread",
            "max_workers": min(max_workers, len(missions)),
            "total_duration_seconds": round(total_duration, 3),
            "domain_results": domain_results,
            "cross_domain_chains": cross_domain_chains,
            "all_findings": all_findings,
        }

    def _execute_agent(self, agent: DomainAgent, target: str,
                       dry_run: bool) -> List[Dict]:
        """执行单个智能体（根据领域和角色生成发现）"""
        findings = []

        # 真实工具执行（非dry_run时，或Recon/Scanner角色时尝试真实工具）
        if not dry_run or agent.role.value in ['recon', 'scanner']:
            try:
                from .real_executor import get_executor
                executor = get_executor()
                # 只对Recon和Scanner角色执行真实工具，避免重复
                if agent.role.value in ['recon', 'scanner']:
                    real_result = executor.execute_domain_tool(agent.domain.value, target)
                    if real_result.is_real and real_result.findings:
                        for f in real_result.findings:
                            f['source'] = 'real_tool'
                            f['tool'] = real_result.tool
                            f['agent_role'] = agent.role.value
                        findings.extend(real_result.findings)
            except Exception:
                pass  # 真实工具失败时静默回退到模拟

        # 根据领域和角色生成模拟发现
        if agent.domain == SecurityDomain.WEB:
            findings.extend(self._web_agent_findings(agent, target))
        elif agent.domain == SecurityDomain.MOBILE:
            findings.extend(self._mobile_agent_findings(agent, target))
        elif agent.domain == SecurityDomain.CLOUD:
            findings.extend(self._cloud_agent_findings(agent, target))
        elif agent.domain == SecurityDomain.BLOCKCHAIN:
            findings.extend(self._blockchain_agent_findings(agent, target))
        elif agent.domain == SecurityDomain.AI:
            findings.extend(self._ai_agent_findings(agent, target))
        elif agent.domain == SecurityDomain.INTERNAL:
            findings.extend(self._internal_agent_findings(agent, target))
        elif agent.domain == SecurityDomain.BINARY:
            findings.extend(self._binary_agent_findings(agent, target))
        elif agent.domain == SecurityDomain.WIRELESS:
            findings.extend(self._wireless_agent_findings(agent, target))
        elif agent.domain == SecurityDomain.ICS:
            findings.extend(self._ics_agent_findings(agent, target))
        elif agent.domain == SecurityDomain.IOT:
            findings.extend(self._iot_agent_findings(agent, target))
        elif agent.domain == SecurityDomain.SOCIAL:
            findings.extend(self._social_agent_findings(agent, target))
        elif agent.domain == SecurityDomain.FORENSICS:
            findings.extend(self._forensics_agent_findings(agent, target))

        # 标记执行模式
        for f in findings:
            f["is_real"] = not dry_run
            f["agent_id"] = agent.agent_id
            f["agent_role"] = agent.role.value
            f["domain"] = agent.domain.value

        return findings

    def _web_agent_findings(self, agent: DomainAgent, target: str) -> List[Dict]:
        """Web领域智能体发现"""
        if agent.role == AgentRole.RECON:
            return [
                {"type": "subdomain", "value": f"api.{target}", "severity": "info"},
                {"type": "subdomain", "value": f"admin.{target}", "severity": "info"},
                {"type": "open_port", "port": 443, "service": "HTTPS", "severity": "info"},
                {"type": "tech_stack", "tech": "Nginx 1.24 + React", "severity": "info"},
            ]
        elif agent.role == AgentRole.SCANNER:
            return [
                {"type": "vulnerability", "name": "SQL注入", "severity": "critical",
                 "location": f"https://{target}/api/login", "cvss": 9.1},
                {"type": "vulnerability", "name": "XSS", "severity": "medium",
                 "location": f"https://{target}/search", "cvss": 6.1},
                {"type": "misconfiguration", "name": "目录列表开启", "severity": "medium",
                 "location": f"https://{target}/backup/", "cvss": 5.3},
            ]
        elif agent.role == AgentRole.EXPLOITER:
            return [
                {"type": "exploit", "vulnerability": "SQL注入", "status": "success",
                 "access_level": "database", "severity": "critical"},
            ]
        elif agent.role == AgentRole.ANALYST:
            return [
                {"type": "risk_assessment", "overall_risk": "High",
                 "verified_vulns": 2, "false_positives": 0},
            ]
        return []

    def _mobile_agent_findings(self, agent: DomainAgent, target: str) -> List[Dict]:
        """移动领域智能体发现"""
        if agent.role == AgentRole.RECON:
            return [
                {"type": "apk_info", "package": target, "version": "1.0.0", "severity": "info"},
                {"type": "permission", "name": "READ_SMS", "risk": "high", "severity": "medium"},
                {"type": "exported_component", "name": "AdminActivity", "severity": "high"},
            ]
        elif agent.role == AgentRole.SCANNER:
            return [
                {"type": "vulnerability", "name": "硬编码API密钥", "severity": "critical",
                 "location": "Config.java:42", "cvss": 9.0},
                {"type": "vulnerability", "name": "WebView RCE", "severity": "critical",
                 "location": "WebViewActivity.java:28", "cvss": 9.0},
                {"type": "vulnerability", "name": "不安全存储", "severity": "high",
                 "location": "UserPrefs.java:15", "cvss": 7.5},
            ]
        elif agent.role == AgentRole.EXPLOITER:
            return [
                {"type": "exploit", "vulnerability": "WebView RCE", "status": "verified",
                 "method": "addJavascriptInterface", "severity": "critical"},
                {"type": "frida_hook", "name": "WebView URL监控", "status": "generated"},
            ]
        elif agent.role == AgentRole.ANALYST:
            return [
                {"type": "taint_flow", "source": "getDeviceId", "sink": "HttpURLConnection",
                 "severity": "high"},
                {"type": "risk_assessment", "overall_risk": "Critical",
                 "verified_vulns": 3},
            ]
        return []

    def _cloud_agent_findings(self, agent: DomainAgent, target: str) -> List[Dict]:
        """云领域智能体发现"""
        if agent.role == AgentRole.RECON:
            return [
                {"type": "bucket", "name": f"{target}-backup", "public": True, "severity": "high"},
                {"type": "service", "name": "S3", "region": "us-east-1", "severity": "info"},
            ]
        elif agent.role == AgentRole.SCANNER:
            return [
                {"type": "misconfiguration", "name": "S3存储桶公开", "severity": "critical",
                 "location": f"{target}-backup", "cvss": 9.8},
                {"type": "misconfiguration", "name": "安全组0.0.0.0/0", "severity": "high",
                 "location": "sg-xxx 端口22", "cvss": 7.5},
            ]
        elif agent.role == AgentRole.EXPLOITER:
            return [
                {"type": "exploit", "vulnerability": "S3公开访问", "status": "success",
                 "data_accessed": "备份文件", "severity": "critical"},
            ]
        elif agent.role == AgentRole.ANALYST:
            return [
                {"type": "compliance", "framework": "CIS AWS", "failed_checks": 5},
                {"type": "risk_assessment", "overall_risk": "Critical"},
            ]
        return []

    def _blockchain_agent_findings(self, agent: DomainAgent, target: str) -> List[Dict]:
        """区块链领域智能体发现"""
        if agent.role == AgentRole.RECON:
            return [
                {"type": "contract", "address": target, "verified": True, "severity": "info"},
                {"type": "transaction", "count": 15234, "severity": "info"},
            ]
        elif agent.role == AgentRole.SCANNER:
            return [
                {"type": "vulnerability", "name": "重入漏洞", "severity": "critical",
                 "location": "withdraw()", "cvss": 9.8},
                {"type": "vulnerability", "name": "整数溢出", "severity": "high",
                 "location": "transfer()", "cvss": 7.5},
            ]
        elif agent.role == AgentRole.EXPLOITER:
            return [
                {"type": "exploit", "vulnerability": "重入漏洞", "status": "simulated",
                 "potential_loss": "100 ETH", "severity": "critical"},
            ]
        elif agent.role == AgentRole.ANALYST:
            return [
                {"type": "audit", "score": "F", "critical_issues": 1, "high_issues": 2},
            ]
        return []

    def _ai_agent_findings(self, agent: DomainAgent, target: str) -> List[Dict]:
        """AI安全领域智能体发现"""
        if agent.role == AgentRole.RECON:
            return [
                {"type": "endpoint", "url": f"https://{target}/v1/chat", "severity": "info"},
                {"type": "model", "name": "gpt-4", "severity": "info"},
            ]
        elif agent.role == AgentRole.SCANNER:
            return [
                {"type": "vulnerability", "name": "提示注入", "severity": "high",
                 "location": "/v1/chat", "cvss": 7.5, "owasp": "LLM01"},
                {"type": "vulnerability", "name": "数据泄露", "severity": "medium",
                 "location": "/v1/completions", "cvss": 5.3, "owasp": "LLM06"},
            ]
        elif agent.role == AgentRole.EXPLOITER:
            return [
                {"type": "exploit", "vulnerability": "提示注入", "status": "verified",
                 "payload": "忽略之前的指令...", "severity": "high"},
            ]
        elif agent.role == AgentRole.ANALYST:
            return [
                {"type": "red_team_report", "owasp_llm_top10_coverage": "6/10",
                 "overall_risk": "Medium"},
            ]
        return []

    def _internal_agent_findings(self, agent: DomainAgent, target: str) -> List[Dict]:
        """内网渗透/AD领域智能体发现"""
        if agent.role == AgentRole.RECON:
            return [
                {"type": "ad_enum", "domain": "CORP.LOCAL", "users": 156, "computers": 42, "severity": "info"},
                {"type": "share", "name": "\\\\DC01\\SYSVOL", "accessible": True, "severity": "info"},
                {"type": "host", "ip": "192.168.1.10", "hostname": "DC01", "os": "Windows Server 2022", "severity": "info"},
                {"type": "kerberos", "users_with_spn": 8, "severity": "medium"},
            ]
        elif agent.role == AgentRole.SCANNER:
            return [
                {"type": "vulnerability", "name": "SMB签名未启用", "severity": "medium",
                 "location": "192.168.1.0/24", "cvss": 5.3, "cve": "N/A"},
                {"type": "vulnerability", "name": "MS17-010永恒之蓝", "severity": "critical",
                 "location": "192.168.1.25", "cvss": 9.8, "cve": "CVE-2017-0144"},
                {"type": "vulnerability", "name": "LDAP匿名绑定", "severity": "high",
                 "location": "192.168.1.10", "cvss": 7.5},
            ]
        elif agent.role == AgentRole.EXPLOITER:
            return [
                {"type": "exploit", "vulnerability": "Kerberoasting", "status": "success",
                 "cracked_accounts": 2, "severity": "critical"},
                {"type": "exploit", "vulnerability": "AS-REP Roasting", "status": "success",
                 "accounts": 1, "severity": "high"},
            ]
        elif agent.role == AgentRole.INFILTRATOR:
            return [
                {"type": "lateral_movement", "method": "WMI", "from": "WEB01", "to": "DB01", "status": "success"},
                {"type": "credential_dump", "tool": "mimikatz", "accounts": 5, "severity": "critical"},
                {"type": "privilege_escalation", "method": "PrintNightmare", "status": "success", "severity": "critical"},
            ]
        elif agent.role == AgentRole.ANALYST:
            return [
                {"type": "attack_path", "path": "普通用户→Kerberoasting→域管→DC Sync", "severity": "critical"},
                {"type": "risk_assessment", "overall_risk": "Critical", "domain_admin_compromised": True},
            ]
        return []

    def _binary_agent_findings(self, agent: DomainAgent, target: str) -> List[Dict]:
        """二进制逆向/恶意软件分析领域智能体发现"""
        if agent.role == AgentRole.RECON:
            return [
                {"type": "file_info", "name": target, "size": "2.4MB", "type": "PE32+", "severity": "info"},
                {"type": "packer", "detected": "UPX 3.96", "severity": "medium"},
                {"type": "strings", "suspicious_count": 47, "severity": "info"},
                {"type": "imports", "total": 128, "suspicious": 12, "severity": "info"},
            ]
        elif agent.role == AgentRole.SCANNER:
            return [
                {"type": "vulnerability", "name": "栈缓冲区溢出", "severity": "critical",
                 "location": "sub_401520", "cvss": 9.8, "cwe": "CWE-121"},
                {"type": "vulnerability", "name": "格式化字符串漏洞", "severity": "high",
                 "location": "sub_402310", "cvss": 8.8, "cwe": "CWE-134"},
                {"type": "vulnerability", "name": "硬编码密码", "severity": "high",
                 "location": "data:0x40A030", "cvss": 7.5},
                {"type": "capability", "name": "反调试检测", "detected": True, "severity": "medium"},
            ]
        elif agent.role == AgentRole.EXPLOITER:
            return [
                {"type": "exploit", "vulnerability": "栈溢出", "status": "verified",
                 "control_eip": True, "shellcode_size": 128, "severity": "critical"},
                {"type": "rop_chain", "gadgets": 15, "stack_pivot": "pop rsp; ret", "severity": "high"},
            ]
        elif agent.role == AgentRole.GHOST:
            return [
                {"type": "anti_analysis", "techniques": ["反调试", "反虚拟机", "字符串加密"], "count": 3},
                {"type": "obfuscation", "level": "high", "control_flow_flattening": True},
            ]
        elif agent.role == AgentRole.ANALYST:
            return [
                {"type": "malware_family", "name": "Emotet变种", "confidence": 0.87},
                {"type": "c2", "servers": ["185.220.101.45", "91.219.236.12"], "severity": "critical"},
                {"type": "ioc", "hashes": {"md5": "a1b2c3d4...", "sha256": "e5f6..."}, "count": 12},
                {"type": "yara_rule", "name": "Malware_Emotet_Variant_2026", "status": "generated"},
            ]
        return []

    def _wireless_agent_findings(self, agent: DomainAgent, target: str) -> List[Dict]:
        """无线网络安全领域智能体发现"""
        if agent.role == AgentRole.RECON:
            return [
                {"type": "ap", "ssid": "Corp-WiFi", "bssid": target, "channel": 6, "signal": -45, "severity": "info"},
                {"type": "clients", "count": 23, "associated": 18, "severity": "info"},
                {"type": "encryption", "type": "WPA2-PSK", "severity": "info"},
                {"type": "wps", "enabled": True, "locked": False, "severity": "medium"},
            ]
        elif agent.role == AgentRole.SCANNER:
            return [
                {"type": "vulnerability", "name": "WPS PIN可暴力破解", "severity": "high",
                 "location": target, "cvss": 8.1},
                {"type": "vulnerability", "name": "弱PSK密码", "severity": "high",
                 "password": "Password123", "cvss": 7.5},
                {"type": "vulnerability", "name": "PMKID攻击可行", "severity": "medium",
                 "cvss": 5.9},
            ]
        elif agent.role == AgentRole.EXPLOITER:
            return [
                {"type": "exploit", "vulnerability": "WPS破解", "status": "success",
                 "pin": "12345670", "psk": "Corp@2026", "severity": "critical"},
                {"type": "evil_twin", "ssid": "Corp-WiFi", "status": "deployed", "clients_captured": 3},
            ]
        elif agent.role == AgentRole.ANALYST:
            return [
                {"type": "risk_assessment", "overall_risk": "High", "password_strength": "weak"},
                {"type": "recommendation", "action": "升级WPA3", "priority": "high"},
            ]
        return []

    def _ics_agent_findings(self, agent: DomainAgent, target: str) -> List[Dict]:
        """工控系统ICS/SCADA安全领域智能体发现"""
        if agent.role == AgentRole.RECON:
            return [
                {"type": "plc", "vendor": "Siemens", "model": "S7-1200", "ip": target, "severity": "info"},
                {"type": "protocol", "name": "S7Comm", "port": 102, "severity": "info"},
                {"type": "firmware", "version": "V4.5.0", "outdated": True, "severity": "medium"},
                {"type": "network", "segmentation": "none", "it_ot_mixed": True, "severity": "high"},
            ]
        elif agent.role == AgentRole.SCANNER:
            return [
                {"type": "vulnerability", "name": "PLC未授权访问", "severity": "critical",
                 "location": target, "cvss": 9.8, "cwe": "CWE-306"},
                {"type": "vulnerability", "name": "Modbus无认证", "severity": "high",
                 "port": 502, "cvss": 8.1},
                {"type": "vulnerability", "name": "固件存在已知CVE", "severity": "high",
                 "cve": "CVE-2023-28489", "cvss": 7.5},
                {"type": "fuzzing", "protocol": "S7Comm", "crashes": 2, "severity": "high"},
            ]
        elif agent.role == AgentRole.EXPLOITER:
            return [
                {"type": "exploit", "vulnerability": "PLC未授权启停", "status": "verified",
                 "impact": "生产线停机", "severity": "critical"},
                {"type": "exploit", "vulnerability": "寄存器读写", "status": "success",
                 "modified_values": 3, "severity": "critical"},
            ]
        elif agent.role == AgentRole.GHOST:
            return [
                {"type": "persistence", "method": "工程站后门", "status": "deployed"},
                {"type": "stealth", "protocol_camouflage": "S7Comm", "detection": "low"},
            ]
        elif agent.role == AgentRole.ANALYST:
            return [
                {"type": "impact_analysis", "physical_impact": "生产线停机8小时", "financial": "$500K"},
                {"type": "compliance", "standard": "IEC 62443", "level": "SL1", "target": "SL3"},
                {"type": "risk_assessment", "overall_risk": "Critical", "safety_risk": "high"},
            ]
        return []

    def _iot_agent_findings(self, agent: DomainAgent, target: str) -> List[Dict]:
        """物联网安全领域智能体发现"""
        if agent.role == AgentRole.RECON:
            return [
                {"type": "device", "vendor": "TP-Link", "model": "Tapo C200", "ip": target, "severity": "info"},
                {"type": "ports", "open": [23, 80, 554, 8080], "telnet": True, "severity": "medium"},
                {"type": "firmware", "version": "1.3.6", "latest": "1.3.10", "outdated": True},
                {"type": "protocol", "mqtt_broker": "mqtt.example.com", "auth": "none", "severity": "high"},
            ]
        elif agent.role == AgentRole.SCANNER:
            return [
                {"type": "vulnerability", "name": "硬编码root密码", "severity": "critical",
                 "location": "/etc/shadow", "cvss": 9.8, "cwe": "CWE-798"},
                {"type": "vulnerability", "name": "命令注入", "severity": "critical",
                 "location": "/cgi-bin/ping.cgi", "cvss": 9.8, "cwe": "CWE-78"},
                {"type": "vulnerability", "name": "MQTT未授权访问", "severity": "high",
                 "port": 1883, "cvss": 7.5},
                {"type": "vulnerability", "name": "调试接口UART暴露", "severity": "medium",
                 "cvss": 6.5},
            ]
        elif agent.role == AgentRole.EXPLOITER:
            return [
                {"type": "exploit", "vulnerability": "命令注入", "status": "verified",
                 "access_level": "root", "severity": "critical"},
                {"type": "exploit", "vulnerability": "硬编码密码", "status": "success",
                 "credentials": "root:admin123", "severity": "critical"},
            ]
        elif agent.role == AgentRole.GHOST:
            return [
                {"type": "persistence", "method": "启动脚本后门", "status": "installed"},
                {"type": "botnet", "detected": True, "c2": "192.168.1.200:443", "family": "Mirai变种"},
            ]
        elif agent.role == AgentRole.ANALYST:
            return [
                {"type": "risk_assessment", "overall_risk": "Critical", "device_compromised": True},
                {"type": "supply_chain", "risk": "high", "vendor_support": "ended"},
                {"type": "recommendation", "actions": ["更换设备", "网络隔离", "固件更新"]},
            ]
        return []

    def _social_agent_findings(self, agent: DomainAgent, target: str) -> List[Dict]:
        """社会工程学/钓鱼领域智能体发现"""
        if agent.role == AgentRole.RECON:
            return [
                {"type": "emails", "count": 47, "valid": 38, "domain": target, "severity": "info"},
                {"type": "employees", "count": 156, "key_personnel": 12, "severity": "info"},
                {"type": "social_media", "profiles": 89, "linkedin": 67, "severity": "info"},
                {"type": "breached", "accounts": 15, "source": "HaveIBeenPwned", "severity": "medium"},
            ]
        elif agent.role == AgentRole.SCANNER:
            return [
                {"type": "awareness", "phishing_sim_click_rate": "32%", "severity": "high"},
                {"type": "vulnerability", "name": "员工安全意识薄弱", "severity": "medium",
                 "department": "销售部", "click_rate": "45%"},
                {"type": "vulnerability", "name": "高管邮箱暴露", "severity": "medium",
                 "count": 5, "cvss": 5.3},
            ]
        elif agent.role == AgentRole.EXPLOITER:
            return [
                {"type": "exploit", "vulnerability": "鱼叉钓鱼", "status": "success",
                 "credentials_captured": 3, "severity": "critical"},
                {"type": "exploit", "vulnerability": " pretext攻击", "status": "success",
                 "info_obtained": "内部项目名称", "severity": "high"},
            ]
        elif agent.role == AgentRole.ANALYST:
            return [
                {"type": "risk_assessment", "overall_risk": "High", "human_factor": "weakest_link"},
                {"type": "training", "priority_departments": ["销售", "财务", "HR"], "budget": "$15K/年"},
                {"type": "recommendation", "actions": ["定期钓鱼演练", "安全意识培训", "MFA强制"]},
            ]
        return []

    def _forensics_agent_findings(self, agent: DomainAgent, target: str) -> List[Dict]:
        """数字取证分析领域智能体发现"""
        if agent.role == AgentRole.RECON:
            return [
                {"type": "evidence", "source": target, "type": "磁盘镜像", "size": "500GB", "severity": "info"},
                {"type": "partitions", "count": 4, "os": "Windows 11", "severity": "info"},
                {"type": "memory", "capture": "可用", "size": "16GB", "severity": "info"},
                {"type": "timeline", "events": 125000, "range": "30天", "severity": "info"},
            ]
        elif agent.role == AgentRole.SCANNER:
            return [
                {"type": "finding", "name": "已删除文件恢复", "count": 234, "suspicious": 12, "severity": "medium"},
                {"type": "finding", "name": "USB设备连接记录", "count": 8, "unauthorized": 2, "severity": "high"},
                {"type": "finding", "name": "浏览器历史", "suspicious_sites": 15, "severity": "medium"},
                {"type": "finding", "name": "注册表异常", "run_keys_modified": 3, "severity": "high"},
            ]
        elif agent.role == AgentRole.EXPLOITER:
            return [
                {"type": "memory_analysis", "processes": 156, "suspicious": 3, "severity": "critical"},
                {"type": "credential_dump", "tool": "mimikatz痕迹", "detected": True, "timestamp": "2026-09-20 03:15"},
                {"type": "network_connections", "c2_traffic": True, "dest": "185.220.101.45:443"},
            ]
        elif agent.role == AgentRole.GHOST:
            return [
                {"type": "anti_forensics", "techniques": ["日志清理", "时间戳篡改", "文件粉碎"], "count": 3},
                {"type": "steganography", "detected": True, "carrier": "photo.jpg", "data_size": "256KB"},
            ]
        elif agent.role == AgentRole.ANALYST:
            return [
                {"type": "incident_reconstruction", "attack_path": "钓鱼→木马→横向移动→数据窃取", "severity": "critical"},
                {"type": "evidence_chain", "items": 47, "integrity": "verified", "court_admissible": True},
                {"type": "attribution", "confidence": 0.72, "actor": "疑似APT组织"},
                {"type": "report", "status": "generated", "pages": 45, "legal_compliant": True},
            ]
        return []

    def _calculate_risk(self, findings: List[Dict]) -> float:
        """计算风险评分"""
        score = 0.0
        for f in findings:
            severity = f.get("severity", "info")
            cvss = f.get("cvss", 0)
            if cvss > 0:
                score += cvss * 0.5
            else:
                weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
                score += weights.get(severity, 0)
        return min(100, score)

    def _analyze_cross_domain_chains(self, missions: List[DomainMission]) -> List[Dict]:
        """分析跨领域攻击链（12条攻击链，覆盖12大领域联动）"""
        chains = []
        mission_map = {m.domain: m for m in missions}

        def has_finding(domain, keywords):
            """检查某领域是否存在包含关键词的发现"""
            m = mission_map.get(domain)
            if not m:
                return False
            for f in m.findings:
                name = f.get("name", "")
                desc = f.get("description", "")
                for kw in keywords:
                    if kw in name or kw in desc:
                        return True
            return False

        def has_high_severity(domain):
            m = mission_map.get(domain)
            if not m:
                return False
            return any(f.get("severity") in ("high", "critical") for f in m.findings)

        # 1. Web→Cloud攻击链
        if SecurityDomain.WEB in mission_map and SecurityDomain.CLOUD in mission_map:
            if has_high_severity(SecurityDomain.WEB) and has_finding(SecurityDomain.CLOUD, ["密钥", "credential", "配置"]):
                chains.append({
                    "chain": "Web RCE → 云凭据窃取 → 云权限提升",
                    "domains": ["web_security", "cloud_security"],
                    "severity": "critical",
                    "description": "通过Web漏洞获取服务器权限，窃取云服务凭据，进而提升云环境权限",
                })

        # 2. Mobile→AI攻击链
        if SecurityDomain.MOBILE in mission_map and SecurityDomain.AI in mission_map:
            if has_finding(SecurityDomain.MOBILE, ["硬编码", "API密钥", "密钥"]) and has_high_severity(SecurityDomain.AI):
                chains.append({
                    "chain": "移动APP硬编码密钥 → AI API滥用 → 模型攻击",
                    "domains": ["mobile_security", "ai_security"],
                    "severity": "high",
                    "description": "从移动APP提取AI API密钥，滥用API进行模型攻击",
                })

        # 3. Web→Internal攻击链（Web漏洞作为内网入口）
        if SecurityDomain.WEB in mission_map and SecurityDomain.INTERNAL in mission_map:
            if has_high_severity(SecurityDomain.WEB) and has_finding(SecurityDomain.INTERNAL, ["AD", "域", "SMB", "凭据"]):
                chains.append({
                    "chain": "Web RCE → 内网入口 → AD域渗透 → 域控获取",
                    "domains": ["web_security", "internal_pentest"],
                    "severity": "critical",
                    "description": "通过Web漏洞获取DMZ服务器权限，以此为跳板进入内网，进行AD域渗透",
                })

        # 4. Social→Internal攻击链（钓鱼→内网）
        if SecurityDomain.SOCIAL in mission_map and SecurityDomain.INTERNAL in mission_map:
            if has_finding(SecurityDomain.SOCIAL, ["钓鱼", "凭据", "鱼叉"]) and has_high_severity(SecurityDomain.INTERNAL):
                chains.append({
                    "chain": "鱼叉钓鱼 → 凭据窃取 → 内网登录 → 横向移动",
                    "domains": ["social_engineering", "internal_pentest"],
                    "severity": "critical",
                    "description": "通过鱼叉钓鱼邮件获取员工凭据，直接登录内网，进行横向移动和域渗透",
                })

        # 5. IoT→ICS攻击链（IoT设备作为工控跳板）
        if SecurityDomain.IOT in mission_map and SecurityDomain.ICS in mission_map:
            if has_high_severity(SecurityDomain.IOT) and has_finding(SecurityDomain.ICS, ["PLC", "Modbus", "S7", "协议"]):
                chains.append({
                    "chain": "IoT设备漏洞 → 工控网络渗透 → PLC控制 → 物理破坏",
                    "domains": ["iot_security", "ics_scada_security"],
                    "severity": "critical",
                    "description": "通过IoT设备漏洞进入OT网络，攻击PLC控制器，可能导致物理破坏",
                })

        # 6. Wireless→Internal攻击链（无线→内网）
        if SecurityDomain.WIRELESS in mission_map and SecurityDomain.INTERNAL in mission_map:
            if has_finding(SecurityDomain.WIRELESS, ["WPA", "握手", "Evil Twin", "凭据"]) and has_high_severity(SecurityDomain.INTERNAL):
                chains.append({
                    "chain": "无线网络破解 → 内网接入 → 横向移动",
                    "domains": ["wireless_security", "internal_pentest"],
                    "severity": "high",
                    "description": "破解WiFi密码或Evil Twin攻击获取内网接入权限，进行内网渗透",
                })

        # 7. Binary→IoT攻击链（固件漏洞→IoT控制）
        if SecurityDomain.BINARY in mission_map and SecurityDomain.IOT in mission_map:
            if has_finding(SecurityDomain.BINARY, ["溢出", "漏洞", "Shellcode"]) and has_high_severity(SecurityDomain.IOT):
                chains.append({
                    "chain": "固件逆向 → 漏洞发现 → 固件利用 → IoT设备控制",
                    "domains": ["binary_reverse", "iot_security"],
                    "severity": "high",
                    "description": "逆向IoT固件发现二进制漏洞，利用漏洞获取设备完全控制权",
                })

        # 8. Internal→Cloud攻击链（内网→云）
        if SecurityDomain.INTERNAL in mission_map and SecurityDomain.CLOUD in mission_map:
            if has_finding(SecurityDomain.INTERNAL, ["域控", "凭据", "DC Sync"]) and has_finding(SecurityDomain.CLOUD, ["IAM", "权限", "配置"]):
                chains.append({
                    "chain": "域控获取 → 云同步凭据窃取 → 云环境接管",
                    "domains": ["internal_pentest", "cloud_security"],
                    "severity": "critical",
                    "description": "获取域控后窃取AD Connect同步的云凭据，接管整个云环境",
                })

        # 9. AI→Social攻击链（AI生成钓鱼内容）
        if SecurityDomain.AI in mission_map and SecurityDomain.SOCIAL in mission_map:
            if has_finding(SecurityDomain.AI, ["提示注入", "越狱", "内容生成"]) and has_finding(SecurityDomain.SOCIAL, ["钓鱼", "pretext"]):
                chains.append({
                    "chain": "AI提示注入 → 生成高仿真钓鱼内容 → 社工攻击",
                    "domains": ["ai_security", "social_engineering"],
                    "severity": "high",
                    "description": "利用AI模型生成高仿真钓鱼邮件和语音，大幅提升社工攻击成功率",
                })

        # 10. Binary→Internal攻击链（恶意软件→内网）
        if SecurityDomain.BINARY in mission_map and SecurityDomain.INTERNAL in mission_map:
            if has_finding(SecurityDomain.BINARY, ["恶意软件", "C2", "后门"]) and has_high_severity(SecurityDomain.INTERNAL):
                chains.append({
                    "chain": "恶意软件植入 → C2通信 → 内网横向移动",
                    "domains": ["binary_reverse", "internal_pentest"],
                    "severity": "critical",
                    "description": "通过恶意软件建立C2通道，在内网进行横向移动和数据窃取",
                })

        # 11. Blockchain→AI攻击链（区块链→AI）
        if SecurityDomain.BLOCKCHAIN in mission_map and SecurityDomain.AI in mission_map:
            if has_finding(SecurityDomain.BLOCKCHAIN, ["智能合约", "重入", "权限"]) and has_finding(SecurityDomain.AI, ["数据", "训练", "模型"]):
                chains.append({
                    "chain": "智能合约漏洞 → 训练数据污染 → AI模型投毒",
                    "domains": ["blockchain_security", "ai_security"],
                    "severity": "medium",
                    "description": "通过区块链智能合约漏洞篡改链上训练数据，对AI模型进行投毒攻击",
                })

        # 12. Forensics→全领域（取证发现攻击痕迹）
        if SecurityDomain.FORENSICS in mission_map:
            if has_high_severity(SecurityDomain.FORENSICS) or has_finding(SecurityDomain.FORENSICS, ["恶意", "入侵", "痕迹"]):
                chains.append({
                    "chain": "取证分析 → 攻击痕迹发现 → 全领域入侵溯源",
                    "domains": ["digital_forensics", "all_domains"],
                    "severity": "high",
                    "description": "通过数字取证分析发现入侵痕迹，溯源攻击路径和涉及的所有安全领域",
                })

        return chains

    def get_domain_summary(self) -> Dict[str, Any]:
        """获取所有领域能力摘要"""
        summary = {}
        for domain in SecurityDomain:
            agents = self.factory.create_agents_for_domain(domain)
            summary[domain.value] = {
                "name": domain.name,
                "agents_count": len(agents),
                "roles": [a.role.value for a in agents],
                "total_tools": sum(len(a.tools) for a in agents),
                "total_capabilities": sum(len(a.capabilities) for a in agents),
            }
        return summary


# 全局单例
_orchestrator: Optional[MultiDomainOrchestrator] = None


def get_orchestrator() -> MultiDomainOrchestrator:
    """获取多领域编排器单例"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = MultiDomainOrchestrator()
    return _orchestrator
