# -*- coding: utf-8 -*-
"""
attack_simulator.py — 攻击模拟引擎（第24轮升级方向1）。

职责：
    1. ATT&CK 战术映射（14 个战术）
    2. 攻击技术库（TTPs / 检测方法 / 缓解措施 / 真实案例，覆盖 190+ 技术）
    3. 攻击场景库（APT / 勒索软件 / 数据泄露 / 内网渗透 / 钓鱼）
    4. 攻击链构建（多阶段自动构建 / 技术选择 / 参数 / 顺序 / 依赖）
    5. 攻击执行（模拟工具调用 / 结果收集 / 进度跟踪 / 异常处理）
    6. 攻击效果评估（成功率 / 检测率 / 响应时间 / 影响范围 / 风险评级）

全部内存字典模拟，不落地数据库。第三方库缺失时回退模拟。
"""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

# ============================================================
# 1. ATT&CK 战术映射（14 个战术）
# ============================================================

ATTACK_TACTICS: Dict[str, Dict[str, Any]] = {
    "ta0001": {
        "id": "TA0001", "name": "initial-access", "cn": "初始访问",
        "phase": 1,
        "description": "攻击者试图进入您的网络，常见向量包括鱼叉钓鱼邮件、合法账户利用、面向公众应用漏洞利用。",
        "kill_chain": "侦察/武器化/投递",
    },
    "ta0002": {
        "id": "TA0002", "name": "execution", "cn": "执行",
        "phase": 2,
        "description": "攻击者试图在本地或远程系统上运行恶意代码，常见如命令脚本解释器、用户执行、计划任务/定时任务。",
        "kill_chain": "利用",
    },
    "ta0003": {
        "id": "TA0003", "name": "persistence", "cn": "持久化",
        "phase": 3,
        "description": "攻击者试图保持立足点，常见如启动项/登录自动启动、服务安装、注册表运行键修改。",
        "kill_chain": "安装",
    },
    "ta0004": {
        "id": "TA0004", "name": "privilege-escalation", "cn": "权限提升",
        "phase": 4,
        "description": "攻击者试图获得更高级别权限，常见如利用错误配置、凭证注入、权限组/账户创建。",
        "kill_chain": "提权",
    },
    "ta0005": {
        "id": "TA0005", "name": "defense-evasion", "cn": "防御规避",
        "phase": 5,
        "description": "攻击者试图避免被检测，常见如禁用安全工具、混淆文件/信息、进程注入。",
        "kill_chain": "规避",
    },
    "ta0006": {
        "id": "TA0006", "name": "credential-access", "cn": "凭证访问",
        "phase": 6,
        "description": "攻击者试图访问账户名/密码等凭证，常见如凭证转储、密码爆破、网络嗅探。",
        "kill_chain": "获取凭证",
    },
    "ta0007": {
        "id": "TA0007", "name": "discovery", "cn": "发现",
        "phase": 7,
        "description": "攻击者试图了解环境，常见如系统信息发现、网络服务扫描、账户发现、进程发现。",
        "kill_chain": "立足后探测",
    },
    "ta0008": {
        "id": "TA0008", "name": "lateral-movement", "cn": "横向移动",
        "phase": 8,
        "description": "攻击者试图在环境中移动，常见如远程服务、RDP/SSH、Windows 管理共享。",
        "kill_chain": "横向移动",
    },
    "ta0009": {
        "id": "TA0009", "name": "collection", "cn": "收集",
        "phase": 9,
        "description": "攻击者试图收集目标信息，常见如屏幕截图、文件目录发现、音频捕获、邮件收集。",
        "kill_chain": "收集",
    },
    "ta0011": {
        "id": "TA0011", "name": "command-and-control", "cn": "命令与控制",
        "phase": 10,
        "description": "攻击者试图与被攻陷系统通信，常见如应用层协议、 Web 协议、加密信道。",
        "kill_chain": "C2",
    },
    "ta0010": {
        "id": "TA0010", "name": "exfiltration", "cn": "数据渗出",
        "phase": 11,
        "description": "攻击者试图窃取数据，常见如通过 C2 信道渗出、替代协议渗出、数据加密/压缩。",
        "kill_chain": "渗出",
    },
    "ta0040": {
        "id": "TA0040", "name": "impact", "cn": "影响",
        "phase": 12,
        "description": "攻击者试图影响业务连续性，常见如数据销毁、服务中断、磁盘擦除、数据加密勒索。",
        "kill_chain": "影响",
    },
    "ta0043": {
        "id": "TA0043", "name": "reconnaissance", "cn": "侦察",
        "phase": 0,
        "description": "攻击者试图收集可用于目标的信息，如搜索开放技术数据库、主动扫描、搜索网站。",
        "kill_chain": "侦察",
    },
    "ta0042": {
        "id": "TA0042", "name": "resource-development", "cn": "资源开发",
        "phase": -1,
        "description": "攻击者试图建立支持攻击的资源，如获取基础设施、账户、开发/购买能力。",
        "kill_chain": "资源开发",
    },
}


# ============================================================
# 2. 攻击技术库（TTPs）
# ============================================================
# 每条技术：tid, name, cn, tactic, ttp, detection, mitigation, case, difficulty, impact

def _t(tid: str, name: str, cn: str, tactic: str, ttp: str,
       detection: str, mitigation: str, case: str,
       difficulty: int = 3, impact: int = 3) -> Dict[str, Any]:
    return {
        "tid": tid, "name": name, "cn": cn, "tactic": tactic,
        "ttp": ttp, "detection": detection, "mitigation": mitigation,
        "case": case, "difficulty": difficulty, "impact": impact,
    }


ATTACK_TECHNIQUES: Dict[str, Dict[str, Any]] = {}


def _build_techniques() -> None:
    """构建 190+ 技术库，按 14 个战术分组。"""
    techs: List[Dict[str, Any]] = [
        # ---- 初始访问 TA0001 ----
        _t("T1566.001", "Spearphishing Attachment", "鱼叉钓鱼附件", "ta0001",
           "发送带恶意附件的钓鱼邮件，诱导用户执行",
           "邮件网关沙箱检测附件、EDR 监控异常进程链",
           "邮件过滤、用户安全意识培训、附件白名单",
           "Lazarus 集团曾使用带宏文档的鱼叉邮件入侵金融机构", 4, 4),
        _t("T1566.002", "Spearphishing Link", "鱼叉钓鱼链接", "ta0001",
           "在钓鱼邮件中嵌入恶意链接，诱导用户点击",
           "URL 信誉检测、重定向分析、用户点击监控",
           "URL 重写、DMARC/SPF/DKIM、浏览器防护",
           "APT29 利用假冒 OneDrive 登录页窃取凭证", 3, 4),
        _t("T1566.003", "Spearphishing via Service", "通过服务鱼叉攻击", "ta0001",
           "利用第三方消息服务（如 LinkedIn/WhatsApp）发送钓鱼",
           "外部威胁情报、社交媒体异常消息监控",
           "员工社交媒体使用规范、外部数据泄露监控",
           "Lapsus$ 通过 WhatsApp 向目标员工发送钓鱼链接", 4, 4),
        _t("T1190", "Exploit Public-Facing Application", "面向公众应用漏洞利用", "ta0001",
           "利用面向互联网的 Web 应用漏洞入侵",
           "WAF 规则、异常请求模式、漏洞扫描告警",
           "补丁管理、WAF、网络分段、最小权限",
           "Log4Shell(Log4j) 被广泛用于入侵面向公网系统", 4, 5),
        _t("T1078", "Valid Accounts", "合法账户", "ta0001",
           "使用合法窃取/购买的账户登录目标环境",
           "异常登录地理位置/时间、身份分析、MFA 绕过检测",
           "MFA、特权访问管理、账户生命周期管理",
           "SolarWinds 事件中攻击者使用合法服务账户持久化", 3, 5),
        _t("T1133", "External Remote Services", "外部远程服务", "ta0001",
           "利用 VPN/ Citrix/ RDP 等外部远程服务接入",
           "VPN 登录异常、网关日志分析、隧道检测",
           "MFA、零信任、最小权限、持续监控",
           "Conti 勒索软件常通过暴露的 RDP 横向移动", 3, 4),
        _t("T1566", "Phishing", "钓鱼", "ta0001",
           "发送伪装成合法来源的欺诈邮件/消息",
           "邮件头分析、发件人域名仿冒检测、沙箱",
           "邮件安全网关、用户培训、DKIM/DMARC",
           "90% 初始入侵始于钓鱼（Verizon DBIR 报告）", 2, 4),
        _t("T1195.002", "Compromise Software Supply Chain", "软件供应链攻陷", "ta0001",
           "篡改软件更新/构建工具链分发恶意代码",
           "代码签名验证、更新服务器完整性监控",
           "代码签名、供应链 SBOM、镜像审计",
           "SolarWinds Orion 供应链攻击影响众多政府机构", 5, 5),
        _t("T1200", "Hardware Additions", "硬件添加", "ta0001",
           "插入恶意硬件（USB/设备）获取初始访问",
           "USB 设备控制、硬件资产盘点、异常外设告警",
           "端口锁定、USB 白名单、物理安全",
           "Stuxnet 通过 USB 隔离环境中扩散", 4, 5),

        # ---- 执行 TA0002 ----
        _t("T1059.001", "PowerShell", "PowerShell 执行", "ta0002",
           "滥用 PowerShell 执行脚本/命令",
           "PowerShell 脚本块日志(Event 4104)、AMSI",
           "PowerShell 约束语言模式、AMSI、应用白名单",
           "众多 APT 使用 PowerShell 无文件执行", 3, 4),
        _t("T1059.003", "Windows Command Shell", "Windows 命令行", "ta0002",
           "通过 cmd.exe 执行命令",
           "进程命令行监控、父子进程关系",
           "应用白名单、命令行审计",
           "恶意软件常用 cmd /c 执行后续载荷", 2, 3),
        _t("T1059.005", "Visual Basic", "VBA 宏执行", "ta0002",
           "利用 Office 文档中的 VBA 宏执行代码",
           "宏执行监控、Office 子进程告警",
           "默认禁用宏、受保护视图、ASR 规则",
           "Emotet 宏文档长期作为初始访问载体", 3, 4),
        _t("T1204.001", "Malicious Link", "恶意链接", "ta0002",
           "诱导用户点击恶意链接触发执行",
           "浏览器进程树、URL 信誉、下载文件监控",
           "浏览器策略、URL 过滤、用户培训",
           "钓鱼链接触发下载远木马", 2, 3),
        _t("T1204.002", "Malicious File", "恶意文件", "ta0002",
           "诱导用户打开恶意文件触发执行",
           "文件创建监控、进程创建、哈希信誉",
           "应用白名单、文件执行拦截",
           "恶意 LNK/ISO 镜像文件绕过附件过滤", 3, 4),
        _t("T1559.001", "Component Object Model", "COM 执行", "ta0002",
           "滥用 Windows COM 对象执行代码",
           "COM 异常激活、子进程监控",
           "COM 权限收紧、EDR 行为监控",
           "PowerShell Empire 使用 COM 进行横向移动", 4, 3),
        _t("T1047", "Windows Management Instrumentation", "WMI 执行", "ta0002",
           "利用 WMI 远程/本地执行命令",
           "WMI 活动日志(Event 5858)、WMI 提供者监控",
           "WMI 命名空间 ACL、网络隔离",
           "APT29 使用 WMI 进行横向移动和命令执行", 3, 4),
        _t("T1569.002", "Service Execution", "服务执行", "ta0002",
           "通过创建/修改系统服务执行代码",
           "服务创建/修改事件(Event 4697)、服务路径异常",
           "服务 ACL、最小权限、服务白名单",
           "勒索软件常安装恶意服务持久化", 3, 4),
        _t("T1053.005", "Scheduled Task", "计划任务执行", "ta0002",
           "创建计划任务定时执行恶意代码",
           "任务创建事件(Event 4698)、任务历史监控",
           "任务 ACL、计划任务白名单",
           "许多持久化技术依赖计划任务", 2, 3),
        _t("T1106", "Native API", "原生 API 执行", "ta0002",
           "直接调用 Windows 原生 API 执行代码",
           "EDR API 钩子、异常系统调用序列",
           "EDR、ETW、内存保护",
           "无文件恶意软件直接调用 NtCreateThreadEx", 5, 4),

        # ---- 持久化 TA0003 ----
        _t("T1547.001", "Registry Run Keys", "注册表运行键", "ta0003",
           "修改注册表 Run/RunOnce 实现开机自启",
           "注册表修改监控、Run 键异常值告警",
           "注册表 ACL、应用白名单",
           "RAT 木马常驻 HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 2, 3),
        _t("T1543.003", "Windows Service", "Windows 服务", "ta0003",
           "创建/修改 Windows 服务实现持久化",
           "服务安装事件、服务路径异常",
           "服务 ACL、服务硬ening",
           "勒索软件配置服务实现开机恢复", 3, 4),
        _t("T1037.001", "Logon Script", "登录脚本", "ta0003",
           "配置登录脚本在用户登录时执行",
           "登录脚本路径监控、GPO 变更审计",
           "GPO 安全、脚本路径 ACL",
           "攻击者篡改 GPO 登录脚本全域名持久化", 4, 4),
        _t("T1505.003", "Web Shell", "Web 后门", "ta0003",
           "在 Web 服务器植入 Web 后门持久化",
           "Web 目录文件变更、异常 Web 请求",
           "Web 目录写权限隔离、WAF",
           "入侵 Web 服务器后常上传一句话木马", 3, 4),
        _t("T1053.005", "Scheduled Task Persist", "计划任务持久化", "ta0003",
           "通过计划任务定期执行保持访问",
           "任务创建/修改审计",
           "任务 ACL、白名单",
           "与执行战术共用技术实现持久化", 2, 3),
        _t("T1137", "Office Application Startup", "Office 启动项", "ta0003",
           "利用 Office 启动项/模板持久化",
           "Office 模板文件变更监控",
           "模板路径保护、宏禁用",
           "攻击者篡改 Normal.dotm 实现 Word 启动加载", 4, 3),
        _t("T1547.005", "Security Support Provider", "SSP 持久化", "ta0003",
           "安装 SSP 包实现凭证窃取+持久化",
           "LSA 包注册表监控、签名验证",
           "LSA 保护(RunAsPPL)、启动时签名校验",
           "Mimikatz 通过 SSP 捕获明文凭证", 5, 5),
        _t("T1098.004", "SSH Authorized Keys", "SSH 授权密钥", "ta0003",
           "添加 SSH 公钥实现持久化登录",
           "authorized_keys 文件变更监控",
           "密钥管理、审计、root 登录禁用",
           "Linux 入侵后常添加 SSH 公钥", 2, 3),

        # ---- 权限提升 TA0004 ----
        _t("T1068", "Exploitation for Privilege Escalation", "漏洞利用提权", "ta0004",
           "利用本地漏洞从普通用户提权到 SYSTEM",
           "利用行为检测、异常子进程、崩溃监控",
           "补丁管理、EDR、最小权限",
           "CVE-2021-40449 等内核漏洞被用于提权", 4, 4),
        _t("T1548.002", "Bypass User Account Control", "绕过 UAC", "ta0004",
           "通过 COM 接口/白名单程序绕过 UAC 提权",
           "UAC 提权事件、异常 COM 调用",
           "UAC 设为始终通知、管理员审批模式",
           "fodhelper/eventvwr 等 UAC 绕过技术", 3, 3),
        _t("T1078", "Valid Accounts PrivEsc", "合法账户提权", "ta0004",
           "利用高权限合法账户提权",
           "特权账户使用监控",
           "JIT 提权、PAM、最小权限",
           "滥用服务账户/SYSTEM 权限", 3, 4),
        _t("T1134.001", "Token Impersonation/Theft", "令牌 impersonation", "ta0004",
           "复制/模拟访问令牌提权",
           "异常令牌使用、SeImpersonate 权限滥用",
           "特权最小化、令牌审计",
           "Incognito/Mimikatz 令牌 impersonation", 4, 4),
        _t("T1558.003", "Kerberoasting", "Kerberoasting 票据攻击", "ta0004",
           "请求服务票据离线破解服务账户密码",
           "异常 TGS 请求、SPN 账户行为",
           "强密码、组托管服务账户(gMSA)",
           "Kerberoasting 是域内提权常用手段", 3, 4),
        _t("T1055.004", "Asynchronous Procedure Call", "APC 注入", "ta0004",
           "APC 队列注入执行提权 payload",
           "异常 APC 队列、跨进程内存写入",
           "EDR 内存保护、进程隔离",
           "Cobalt Strike 多种注入技术之一", 4, 3),

        # ---- 防御规避 TA0005 ----
        _t("T1562.001", "Disable or Modify Tools", "禁用安全工具", "ta0005",
           "停止/禁用 AV/EDR 服务规避检测",
           "安全服务停止事件、驱动卸载监控",
           "EDR 自我保护、服务 ACL",
           "勒索软件常先停止安全软件", 3, 4),
        _t("T1027", "Obfuscated Files or Information", "混淆文件/信息", "ta0005",
           "加密/混淆 payload 规避静态检测",
           "熵值异常、解密 API 调用、内存特征",
           "EDR 行为检测、内存扫描",
           "绝大多数现代恶意软件加壳/加密", 3, 3),
        _t("T1055", "Process Injection", "进程注入", "ta0005",
           "将代码注入其他进程隐藏执行",
           "远程线程创建、内存权限变更、跨进程写入",
           "EDR 注入检测、进程隔离",
           "Cobalt Strike/Emotet 普遍使用进程注入", 4, 4),
        _t("T1564.003", "Hidden Window", "隐藏窗口", "ta0005",
           "隐藏进程窗口规避用户察觉",
           "无窗口进程异常行为、父子进程",
           "EDR 行为基线",
           "恶意软件使用 -WindowStyle Hidden", 2, 2),
        _t("T1070.004", "File Deletion", "文件删除痕迹", "ta0005",
           "删除攻击工具/日志痕迹",
           "删除敏感文件事件、工具残留监控",
           "日志集中存储、不可变日志",
           "攻击者清理工具痕迹", 2, 3),
        _t("T1036.005", "Match Legitimate Resource Name/Location", "仿冒合法资源", "ta0005",
           "命名/路径仿冒合法程序规避检测",
           "异常路径程序执行、签名校验",
           "应用白名单、签名验证",
           "svch0st 仿冒 svchost", 2, 3),
        _t("T1553.002", "Code Signing", "代码签名", "ta0005",
           "使用窃取/伪造证书签名恶意代码",
           "签名证书信誉、异常签名程序",
           "证书生命周期管理、代码签名监控",
           "Stuxnet 使用被盗证书签名驱动", 4, 4),
        _t("T1089", "Disabling or Modifying Cloud Firewall", "禁用云防火墙", "ta0005",
           "修改云安全组/防火墙规则规避",
           "云配置变更审计、异常规则告警",
           "云安全基线、变更审批",
           "攻击者攻陷云账户后放开安全组", 3, 4),

        # ---- 凭证访问 TA0006 ----
        _t("T1003.001", "LSASS Memory", "LSASS 凭证转储", "ta0006",
           "从 LSASS 进程内存提取凭证",
           "LSASS 访问事件、Mimikatz 特征、未授权读取",
           "LSA 保护、Credential Guard、最小权限",
           "Mimikatz 从 LSASS 抓取 NTLM 哈希/明文", 4, 5),
        _t("T1003.002", "Security Account Manager", "SAM 转储", "ta0006",
           "转储 SAM 数据库获取本地账户哈希",
           "SAM hive 访问、注册表导出监控",
           "SAM 保护、备份访问控制",
           "secretsdump 提取 SAM 哈希", 3, 4),
        _t("T1555.003", "Credentials from Web Browsers", "浏览器凭证窃取", "ta0006",
           "从浏览器保存的密码数据库提取凭证",
           "浏览器 credential store 文件访问",
           "浏览器主密码、EDR 监控",
           "Raccoon/RedLine 信息窃取器盗浏览器密码", 3, 4),
        _t("T1110.001", "Password Guessing", "密码猜测", "ta0006",
           "猜测弱密码账户",
           "大量登录失败事件、账户锁定",
           "强密码策略、锁定策略、MFA",
           "暴力破解 RDP/SSH 常见初始访问", 2, 4),
        _t("T1110.003", "Password Spraying", "密码喷洒", "ta0006",
           "用常见密码喷洒大量账户避免锁定",
           "跨账户同源密码、低频登录失败",
           "强密码、MFA、异常登录检测",
           "攻击者喷洒 Password123 攻击员工邮箱", 3, 4),
        _t("T1558.001", "Kerberoasting", "Kerberoasting 凭证", "ta0006",
           "同上，获取服务票据离线破解",
           "TGS 请求异常",
           "gMSA、强密码",
           "域内信息收集后 Kerberoasting", 3, 4),
        _t("T1552.001", "Credentials in Files", "文件中凭证", "ta0006",
           "从配置文件/脚本中搜索硬编码凭证",
           "敏感文件访问监控、开发库凭证扫描",
           "密钥管理服务、代码扫描",
           "开发人员硬编码 DB 密码被拖库", 2, 3),
        _t("T1040", "Network Sniffing", "网络嗅探", "ta0006",
           "网络嗅探获取明文凭证",
           "混杂模式网卡、异常数据包捕获",
           "加密传输(NTDS/Kerberos)、网络分段",
           "内网嗅探获取 SMB/HTTP 明文凭证", 4, 4),

        # ---- 发现 TA0007 ----
        _t("T1082", "System Information Discovery", "系统信息发现", "ta0007",
           "收集 OS 版本/架构/补丁信息",
           "systeminfo/ver 等命令监控",
           "命令行审计",
           "入侵后执行 systeminfo 侦察", 1, 2),
        _t("T1016", "System Network Configuration Discovery", "网络配置发现", "ta0007",
           "收集 IP/路由/DNS/网卡信息",
           "ipconfig/route/nslookup 执行监控",
           "网络基线",
           "ipconfig /all 侦察内网", 1, 2),
        _t("T1046", "Network Service Discovery", "网络服务扫描", "ta0007",
           "扫描存活主机和开放端口",
           "端口扫描行为、大量连接告警",
           "网络分段、IDS 扫描检测",
           "Nmap 扫描内网 192.168.1.0/24", 2, 3),
        _t("T1087.001", "Local Account Discovery", "本地账户发现", "ta0007",
           "枚举本地用户/组",
           "net user /net localgroup 执行",
           "命令行审计",
           "net user 侦察本地账户", 1, 2),
        _t("T1087.002", "Domain Account Discovery", "域账户发现", "ta0007",
           "枚举域用户/组/OU",
           "net user /domain、AD 查询",
           "AD 审计、LDAP 监控",
           "net user /domain /domain:corp.com", 2, 3),
        _t("T1057", "Process Discovery", "进程发现", "ta0007",
           "枚举运行进程识别安全软件/服务",
           "tasklist/Get-Process 监控",
           "EDR 行为监控",
           "tasklist 查找 AV 进程", 1, 2),
        _t("T1069.002", "Permission Groups Discovery", "权限组发现", "ta0007",
           "枚举管理员组/特权组",
           "net group /domain",
           "AD 审计",
           "net group \"Domain Admins\" /domain", 2, 3),
        _t("T1018", "Remote System Discovery", "远程系统发现", "ta0007",
           "发现内网存活主机",
           "ICMP 扫描、ARP 扫描、NetBIOS 扫描",
           "网络分段、IDS",
           "ping 扫描发现域控制器", 2, 3),

        # ---- 横向移动 TA0008 ----
        _t("T1021.001", "Remote Desktop Protocol", "RDP 横向移动", "ta0008",
           "通过 RDP 登录其他系统",
           "RDP 登录事件(4624 Type 10)、异常 RDP 源",
           "RDP 网关、MFA、限制来源",
           "窃取凭证后 mstsc 登录服务器", 3, 4),
        _t("T1021.002", "SMB/Windows Admin Shares", "SMB 管理共享", "ta0008",
           "通过 admin$ /c$ 管理共享横向移动",
           "SMB 访问异常、admin$ 写入监控",
           "SMB 签名、管理共享限制",
           "psexec 通过 admin$ 远程执行", 3, 4),
        _t("T1021.004", "SSH", "SSH 横向移动", "ta0008",
           "通过 SSH 登录其他 Linux 系统",
           "SSH 登录异常、密钥使用监控",
           "SSH 堡垒机、MFA",
           "攻陷跳板机后 SSH 横向数据库", 2, 3),
        _t("T1077", "Windows Admin Shares", "Windows 管理共享横向", "ta0008",
           "通过管理共享部署 payload 横向",
           "SMB 写入、服务安装",
           "SMB 签名",
           "利用窃取哈希通过 SMB 横向", 3, 4),
        _t("T1550.002", "Pass the Hash", "传递哈希", "ta0008",
           "用 NTLM 哈希直接认证无需明文",
           "NTLM 认证异常、横向访问模式",
           "禁用 NTLM、LSA 保护、特权分离",
           "Mimikatz pth 横向移动", 4, 4),
        _t("T1550.003", "Pass the Ticket", "传递票据", "ta0008",
           "用黄金/白银票据横向移动",
           "Kerberos 票据异常、PAC 异常",
           "KRBTGT 密码重置、特权账户保护",
           "Golden Ticket 伪造 TGT 横向", 5, 5),
        _t("T1047", "WMI 横向移动", "WMI 横向", "ta0008",
           "通过 WMI 远程执行命令横向",
           "WMI 远程连接日志",
           "DCOM/WMI 限制",
           "wmic /node:target process call create", 3, 4),
        _t("T1570", "Lateral Tool Transfer", "横向工具传输", "ta0008",
           "通过 SMB/HTTP 传输工具到远程系统",
           "异常文件复制到 admin$",
           "文件完整性监控",
           "上传 beacon.exe 到目标", 2, 3),

        # ---- 收集 TA0009 ----
        _t("T1113", "Screen Capture", "屏幕截图", "ta0009",
           "截取桌面屏幕收集敏感信息",
           "截屏 API 调用、剪贴板访问",
           "EDR 行为监控",
           "RAT 截图监控用户操作", 2, 2),
        _t("T1114.001", "Local Email Collection", "本地邮件收集", "ta0009",
           "从本地 Outlook PST/OST 收集邮件",
           "邮件文件访问、导出操作",
           "DLP、邮件访问审计",
           "收集 CEO 邮件寻找商业情报", 3, 4),
        _t("T1005", "Data from Local System", "本地系统数据收集", "ta0009",
           "从本地文件系统收集敏感文档",
           "敏感文件批量访问/复制",
           "DLP、文件访问审计",
           "批量收集 .docx/.xlsx 文档", 2, 4),
        _t("T1119", "Automated Collection", "自动收集", "ta0009",
           "自动化脚本批量收集数据",
           "批量文件访问模式、压缩行为",
           "DLP",
           "脚本遍历文件服务器收集", 3, 4),
        _t("T1056.001", "Keylogging", "键盘记录", "ta0009",
           "记录用户按键获取凭证/信息",
           "键盘钩子、原始输入监控",
           "EDR、防键盘记录",
           "RAT 记录用户输入密码", 3, 4),
        _t("T1123", "Audio Capture", "音频捕获", "ta0009",
           "录制麦克风音频",
           "麦克风设备访问监控",
           "麦克风权限管理",
           "间谍软件录制会议", 4, 3),
        _t("T1213.002", "Sharepoint", "SharePoint 收集", "ta0009",
           "从 SharePoint 收集敏感文档",
           "SharePoint 异常下载",
           "DLP、访问审计",
           "下载财务/HR 文档", 2, 4),

        # ---- 命令与控制 TA0011 ----
        _t("T1071.001", "Web Protocols", "Web 协议 C2", "ta0011",
           "通过 HTTP/HTTPS 与 C2 通信",
           "异常出站 HTTPS、证书异常、DGA 域名",
           "出站过滤、DNS 监控、TLS 检测",
           "Cobalt Strike HTTPS Beacon", 3, 3),
        _t("T1071.002", "File Transfer Protocols", "FTP/SFTP C2", "ta0011",
           "通过 FTP/SFTP 传输数据/命令",
           "异常 FTP 出站、未知 FTP 服务器",
           "出站白名单",
           "通过 FTP 下载后续载荷", 2, 2),
        _t("T1573.002", "Asymmetric Cryptography", "非对称加密 C2", "ta0011",
           "使用非对称加密 C2 流量",
           "TLS 异常、JA3 指纹",
           "TLS 检测、JA3 监控",
           "C2 使用自定义 RSA 加密", 4, 3),
        _t("T1090", "Proxy", "代理 C2", "ta0011",
           "使用代理/跳板隐藏 C2 来源",
           "异常代理流量、多层代理",
           "代理日志分析",
           "通过 Tor/VPN 代理 C2", 3, 3),
        _t("T1568.002", "DNS", "DNS 隧道 C2", "ta0011",
           "通过 DNS 查询隧道传输命令/数据",
           "异常 DNS 查询、长域名、高频率",
           "DNS 过滤、DNS 监控",
           "dnscat2 经由 DNS 隧道 C2", 4, 3),
        _t("T1105", "Ingress Tool Transfer", "入站工具传输", "ta0011",
           "从 C2 下载工具到受害机",
           "异常下载、PowerShell 下载",
           "应用白名单",
           "certutil/powershell 下载 beacon", 2, 3),

        # ---- 数据渗出 TA0010 ----
        _t("T1041", "Exfiltration Over C2 Channel", "经 C2 信道渗出", "ta0010",
           "通过已有 C2 信道渗出数据",
           "出站流量突增、大文件上传",
           "出站流量监控、DLP",
           "通过 HTTPS 上传数据库备份", 3, 5),
        _t("T1048.003", "Exfiltration Over Alternative Protocol", "替代协议渗出", "ta0010",
           "通过非标准协议(DNS/ICMP/邮件)渗出",
           "异常 DNS 大小、ICMP 数据",
           "协议白名单",
           "通过 DNS 隧道渗出数据", 4, 4),
        _t("T1567", "Exfiltration Over Web Service", "经 Web 服务渗出", "ta0010",
           "利用云存储/代码仓库渗出数据",
           "异常云上传、代码仓库 push",
           "云访问安全代理(CASP)",
           "上传到 GitHub/GDrive 渗出", 2, 4),
        _t("T1020", "Automated Exfiltration", "自动渗出", "ta0010",
           "自动化脚本批量渗出数据",
           "批量上传行为",
           "DLP",
           "脚本打包上传客户数据", 3, 5),
        _t("T1560", "Archive Collected Data", "归档收集数据", "ta0010",
           "压缩/加密数据便于渗出",
           "压缩工具执行、大压缩包创建",
           "DLP",
           "7z 加密打包数据渗出", 2, 3),

        # ---- 影响 TA0040 ----
        _t("T1486", "Data Encrypted for Impact", "数据加密勒索", "ta0040",
           "加密用户数据勒索赎金",
           "批量文件加密、文件扩展名变更、勒索信",
           "备份、EDR、行为监控",
           "Conti/BlackCat 勒索软件加密企业数据", 4, 5),
        _t("T1485", "Data Destruction", "数据销毁", "ta0040",
           "删除/擦除数据破坏业务",
           "批量删除事件、磁盘擦除",
           "备份、恢复演练",
           "NotPetya 擦除磁盘", 4, 5),
        _t("T1489", "Service Stop", "停止服务", "ta0040",
           "停止关键服务影响业务",
           "服务停止事件、关键服务监控",
           "服务高可用、监控",
           "勒索软件停止备份服务", 3, 4),
        _t("T1491.001", "Defacement", "网页篡改", "ta0040",
           "篡改网站页面",
           "Web 页面变更监控",
           "Web 完整性监控",
           "Defacement 替换首页", 2, 3),
        _t("T1561.002", "Disk Wipe", "磁盘擦除", "ta0040",
           "擦除磁盘数据彻底破坏",
           "磁盘写入模式、MBR 变更",
           "备份、离线备份",
           "Shamoon 擦除中东石油公司磁盘", 5, 5),

        # ---- 侦察 TA0043 ----
        _t("T1595", "Active Scanning", "主动扫描侦察", "ta0043",
           "主动扫描目标网络/服务",
           "边界 IDS 检测扫描",
           "攻击面管理",
           "Shodan 扫描目标公开服务", 2, 2),
        _t("T1593", "Search Open Websites/Domains", "搜索公开网站", "ta0043",
           "搜索公开网站收集目标信息",
           "外部威胁情报",
           "外部信息管控",
           "LinkedIn 收集组织架构", 1, 2),
        _t("T1590", "Gather Victim Network Info", "收集目标网络信息", "ta0043",
           "收集目标 IP 段/域名/ASN",
           "外部侦察监控",
           "攻击面管理",
           "WHOIS/ DNS 侦察", 1, 2),
        _t("T1591", "Gather Victim Org Info", "收集目标组织信息", "ta0043",
           "收集组织架构/人员/业务信息",
           "OSINT",
           "信息管控",
           "收集员工邮箱格式", 1, 2),

        # ---- 资源开发 TA0042 ----
        _t("T1583", "Acquire Infrastructure", "获取基础设施", "ta0042",
           "注册域名/服务器/VPS 用于攻击",
           "域名 WHOIS 异常",
           "域名监控",
           "注册 typosquatting 域名", 2, 2),
        _t("T1585", "Establish Accounts", "建立账户", "ta0042",
           "注册邮箱/云服务/社交媒体账户",
           "账户滥用监控",
           "身份验证",
           "注册匿名邮箱用于钓鱼", 1, 2),
        _t("T1587", "Develop Capabilities", "开发能力", "ta0042",
           "开发恶意软件/漏洞利用",
           "威胁情报",
           "—",
           "开发自定义远控", 3, 3),
        _t("T1588", "Obtain Capabilities", "获取能力", "ta0042",
           "购买/下载恶意软件/漏洞利用",
           "地下市场情报",
           "—",
           "购买初始访问(Initial Access)权限", 2, 3),
    ]

    for tech in techs:
        ATTACK_TECHNIQUES[tech["tid"]] = tech


_build_techniques()


def _expand_techniques() -> None:
    """第二批技术扩展，使技术库达到 190+。"""
    extra: List[Dict[str, Any]] = [
        # ---- 初始访问 补充 ----
        _t("T1199", "Trusted Relationship", "可信关系利用", "ta0001",
           "利用合作伙伴/供应商可信关系入侵",
           "跨组织访问异常、第三方访问审计",
           "第三方访问治理、JIT 访问",
           "通过供应商 VPN 入侵目标", 4, 4),
        _t("T1566.004", "Spearphishing Voice", "语音钓鱼", "ta0001",
           "电话语音钓鱼获取信息",
           "话务分析、用户举报",
           "反钓鱼培训、外呼验证",
           "vishing 诱导 IT 重置密码", 3, 3),
        _t("T1091", "Replication Through Removable Media", "可移动介质复制", "ta0001",
           "通过 U 盘/可移动介质传播",
           "USB 设备控制、自动播放禁用",
           "USB 白名单、物理安全",
           "Stuxnet 通过 U 盘跨隔离网", 4, 4),
        _t("T1195.001", "Compromise Software Dependencies", "软件依赖攻陷", "ta0001",
           "篡改开源依赖包投毒",
           "依赖哈希校验、SBOM",
           "私有镜像、依赖锁定",
           "event-stream 事件流 npm 投毒", 4, 4),
        _t("T1200", "Hardware Additions Add", "硬件后门", "ta0001",
           "植入硬件后门设备",
           "硬件资产盘点、外设监控",
           "物理安全、端口锁定",
           "植入恶意 USB 充电器", 5, 5),
        # ---- 执行 补充 ----
        _t("T1059.004", "Unix Shell", "Unix Shell 执行", "ta0002",
           "滥用 bash/sh 执行命令",
           "shell 命令审计、异常子进程",
           "shell 限制、EDR",
           "Linux 入侵后 bash 反弹", 2, 3),
        _t("T1059.007", "JavaScript", "JavaScript 执行", "ta0002",
           "通过 WScript/JScript 执行",
           "cscript/wscript 子进程",
           "脚本宿主限制",
           "恶意 .js 脚本投递", 3, 3),
        _t("T1059.006", "Python", "Python 执行", "ta0002",
           "滥用 python 执行恶意脚本",
           "python 子进程、脚本内容",
           "应用白名单",
           "python 远控木马", 3, 3),
        _t("T1559.002", "Dynamic Data Exchange", "DDE 执行", "ta0002",
           "利用 Office DDE 执行命令",
           "Office DDE 事件",
           "Office 宏/DDE 禁用",
           "DDE 绕过宏防护执行 cmd", 3, 3),
        _t("T1203", "Exploitation for Client Execution", "客户端漏洞利用", "ta0002",
           "利用客户端软件漏洞执行代码",
           "崩溃监控、利用行为检测",
           "补丁管理、EDR",
           "Office/浏览器 0day 利用", 5, 4),
        _t("T1047.001", "WMI 事件订阅", "WMI 事件执行", "ta0002",
           "WMI 事件过滤器永久执行",
           "WMI 事件订阅监控",
           "WMI ACL",
           "WMI 永久事件订阅持久化", 4, 4),
        _t("T1569.003", "Systemd Timers", "systemd 定时器", "ta0002",
           "Linux systemd 定时器执行",
           "systemd 单元文件监控",
           "单元文件 ACL",
           "Linux systemd 持久化执行", 3, 3),
        # ---- 持久化 补充 ----
        _t("T1547.009", "Shortcut Modification", "快捷方式修改", "ta0003",
           "修改 LNK 快捷方式指向恶意",
           "LNK 文件变更监控",
           "FIM、写权限控制",
           "修改桌面快捷方式带参数", 3, 3),
        _t("T1546.001", "Change Default File Association", "默认文件关联", "ta0003",
           "篡改文件打开方式持久化",
           "注册表文件关联变更",
           "关联保护",
           "篡改 .txt 打开方式", 3, 3),
        _t("T1505.005", "Terminal Services DLL", "终端服务 DLL", "ta0003",
           "植入 termsrv.dll 持久化",
           "系统 DLL 完整性监控",
           "WDAC/应用白名单",
           "替换 termsrv.dll 启用多会话", 4, 3),
        _t("T1136.001", "Create Account", "创建账户", "ta0003",
           "创建本地/域管理员账户持久化",
           "账户创建事件(4720)",
           "账户审计、最小权限",
           "隐藏管理员账户", 2, 4),
        _t("T1098.005", "Additional Cloud Roles", "云角色添加", "ta0003",
           "云账户添加持久化角色",
           "云 IAM 变更审计",
           "云 IAM 权限治理",
           "Azure AD 添加持久化应用", 3, 4),
        _t("T1547.004", "Winlogon Helper", "Winlogon 帮助 DLL", "ta0003",
           "Winlogon 通知 DLL 持久化",
           "Winlogon 注册表监控",
           "注册表 ACL",
           "注入 Winlogon 进程", 5, 4),
        # ---- 权限提升 补充 ----
        _t("T1548.003", "Sudo and Sudo Caching", "sudo 缓存滥用", "ta0004",
           "滥用 sudo 缓存提权",
           "sudo 日志、异常提权",
           "sudo 最小化、tty 票据",
           "Linux sudo 提权", 3, 4),
        _t("T1611", "Escape to Host", "容器逃逸", "ta0004",
           "从容器逃逸到宿主机",
           "容器运行时监控、特权容器",
           "容器隔离、只读根文件系统",
           "Docker 容器逃逸到宿主", 5, 5),
        _t("T1543.005", "Container Service", "容器服务持久化", "ta0004",
           "滥用容器服务提权",
           "容器 API 异常",
           "Docker API 认证",
           "滥用 docker.sock", 4, 4),
        _t("T1078.002", "Domain Accounts", "域账户滥用提权", "ta0004",
           "滥用域账户权限",
           "特权域账户使用",
           "PAM、最小权限",
           "滥用域管理员权限", 2, 4),
        # ---- 防御规避 补充 ----
        _t("T1562.002", "Disable Windows Event Logging", "禁用事件日志", "ta0005",
           "停止 Windows 事件日志服务",
           "EventLog 服务停止监控",
           "日志保护、集中日志",
           "wevtutil cl 清理日志", 3, 4),
        _t("T1027.002", "Software Packing", "软件加壳", "ta0005",
           "加壳混淆恶意软件",
           "高熵值、解壳 API",
           "EDR 动态检测",
           "UPX 加壳远控", 3, 3),
        _t("T1027.013", "Encrypted/Encoded File", "加密编码文件", "ta0005",
           "base64/XOR 编码 payload",
           "解码 API 调用、内存扫描",
           "EDR",
           "base64 编码后解码执行", 2, 3),
        _t("T1055.001", "Dynamic-link Library Injection", "DLL 注入", "ta0005",
           "远程线程加载 DLL",
           "LoadLibrary 远程调用",
           "EDR",
           "Cobalt Strike DLL 注入", 4, 4),
        _t("T1055.012", "Process Hollowing", "进程镂空", "ta0005",
           "镂空合法进程替换代码",
           "异常进程内存、镜像不一致",
           "EDR 内存保护",
           "进程镂空躲避检测", 5, 4),
        _t("T1620", "Reflective Code Loading", "反射加载", "ta0005",
           "反射 DLL 加载绕过磁盘",
           "无文件执行、内存特征",
           "AMSI、ETW",
           "reflective DLL injection", 5, 4),
        _t("T1036.004", "Masquerade Task or Service", "伪装任务/服务", "ta0005",
           "命名仿冒系统服务",
           "服务名相似度检测",
           "服务白名单",
           "svch0st 仿冒", 2, 2),
        _t("T1218.011", "Rundll32", "Rundll32 代理执行", "ta0005",
           "rundll32 加载恶意 DLL/JS",
           "rundll32 命令行监控",
           "应用白名单",
           "rundll32 javascript:", 3, 3),
        _t("T1218.010", "Regsvr32", "Regsvr32 代理", "ta0005",
           "regsvr32 加载远程 SCT",
           "regsvr32 网络/子进程",
           "应用白名单",
           "Squiblydoo 技术", 3, 3),
        # ---- 凭证访问 补充 ----
        _t("T1003.004", "LSA Secrets", "LSA Secrets 转储", "ta0006",
           "转储 LSA Secrets 缓存凭证",
           "LSA 访问监控",
           "LSA 保护",
           "secretsdump LSA Secrets", 4, 4),
        _t("T1003.005", "Cached Domain Credentials", "缓存域凭证", "ta0006",
           "转储缓存域凭证",
           "缓存转储事件",
           "LSA 保护",
           "dumpsam 缓存凭证", 4, 4),
        _t("T1555.001", "Keychain", "macOS Keychain", "ta0006",
           "从 macOS 钥匙串提取凭证",
           "Keychain 访问监控",
           "Keychain 保护",
           "security dump-keychain", 3, 3),
        _t("T1552.003", "Shell History", "Shell 历史凭证", "ta0006",
           "从 .bash_history 提取凭证",
           "历史文件访问",
           "历史清理规范",
           "cat .bash_history", 1, 2),
        _t("T1558.002", "Silver Ticket", "白银票据", "ta0006",
           "伪造服务票据",
           "票据异常、PAC",
           "服务账户强密码",
           "黄金/白银票据", 5, 5),
        _t("T1558.001", "Golden Ticket", "黄金票据", "ta0006",
           "伪造 TGT 票据",
           "KRBTGT 异常使用",
           "KRBTGT 密码重置",
           "黄金票据全域控制", 5, 5),
        _t("T1110.004", "Credential Stuffing", "凭证填充", "ta0006",
           "用泄露用户名密码填充登录",
           "跨账户同源密码、异常登录",
           "MFA、密码管理器",
           "使用泄露库填充登录", 3, 4),
        _t("T1606.001", "Forge Web Credentials", "伪造 Web 凭证", "ta0006",
           "伪造 SAML Web 凭证",
           "SAML 断言异常",
           "身份联合治理",
           "SAML 响应伪造", 5, 4),
        # ---- 发现 补充 ----
        _t("T1012", "Query Registry", "注册表查询发现", "ta0007",
           "查询注册表收集系统信息",
           "reg query 监控",
           "注册表审计",
           "reg query 侦察", 1, 2),
        _t("T1033", "System Owner/User Discovery", "用户发现", "ta0007",
           "枚举当前用户/所有者",
           "whoami 监控",
           "—",
           "whoami 侦察", 1, 1),
        _t("T1007", "System Service Discovery", "系统服务发现", "ta0007",
           "枚举系统服务",
           "sc query 监控",
           "—",
           "net start 侦察服务", 1, 2),
        _t("T1083", "File and Directory Discovery", "文件目录发现", "ta0007",
           "枚举文件/目录结构",
           "dir/Get-ChildItem 批量",
           "FIM",
           "dir c:\\ 侦察", 1, 2),
        _t("T1040.002", "Network Sniffing Windows", "Windows 嗅探", "ta0007",
           "Windows 网络嗅探",
           "混杂模式检测",
           "NIPS",
           "WinPcap 嗅探", 4, 3),
        _t("T1120", "Peripheral Device Discovery", "外设发现", "ta0007",
           "发现连接的外设",
           "设备枚举监控",
           "外设控制",
           "枚举 USB 设备", 2, 2),
        # ---- 横向移动 补充 ----
        _t("T1021.006", "Windows Remote Management", "WinRM 横向", "ta0008",
           "通过 WinRM 远程执行",
           "WinRM 连接日志",
           "WinRM 限制",
           "Invoke-Command 横向", 3, 4),
        _t("T1021.003", "Distributed Component Object Model", "DCOM 横向", "ta0008",
           "通过 DCOM 远程执行",
           "DCOM 异常激活",
           "DCOM 限制",
           "DCOM 横向移动", 4, 4),
        _t("T1550.004", "Web Session Cookie", "Web 会话 Cookie 复用", "ta0008",
           "窃取 Web 会话 Cookie 横向",
           "会话异常使用",
           "会话固定、HTTPS",
           "窃取 SSO Cookie", 4, 4),
        _t("T1072", "Software Deployment Tools", "软件部署工具横向", "ta0008",
           "利用 SCCM/组策略软件部署",
           "部署任务异常",
           "部署权限控制",
           "滥用 SCCM 推送", 3, 4),
        _t("T1570", "Lateral Tool Transfer SMB", "SMB 工具传输", "ta0008",
           "通过 SMB 传输横向工具",
           "SMB 文件写入",
           "SMB 签名",
           "copy 到 admin$", 2, 3),
        # ---- 收集 补充 ----
        _t("T1114.002", "Remote Email Collection", "远程邮件收集", "ta0009",
           "从 Exchange/O365 收集邮件",
           "异常邮件导出",
           "DLP、CASB",
           "导出 CEO 邮件", 3, 4),
        _t("T1125", "Video Capture", "视频捕获", "ta0009",
           "录制摄像头视频",
           "摄像头设备访问",
           "摄像头权限",
           "间谍软件录制", 4, 3),
        _t("T1560.001", "Archive via Utility", "工具归档", "ta0009",
           "用 7z/zip 归档收集数据",
           "压缩工具执行",
           "DLP",
           "7z 打包文档", 2, 3),
        _t("T1005.001", "Local Data Staging", "本地数据暂存", "ta0009",
           "本地暂存收集的数据",
           "临时目录大文件",
           "DLP",
           "暂存到 %TEMP%", 2, 3),
        _t("T1213.003", "Code Repositories", "代码仓库收集", "ta0009",
           "从 Git 仓库收集信息",
           "仓库异常克隆",
           "仓库访问控制",
           "克隆内部 Git 仓库", 2, 4),
        _t("T1111", "Multi-Factor Authentication Interception", "MFA 拦截", "ta0009",
           "拦截 MFA 请求绕过",
           "MFA 响应异常",
           "MFA 设备绑定",
           "MFA 疲劳攻击", 4, 4),
        # ---- 命令与控制 补充 ----
        _t("T1071.004", "DNS", "DNS C2", "ta0011",
           "DNS 协议 C2",
           "异常 DNS 查询",
           "DNS 过滤",
           "dnscat2", 4, 3),
        _t("T1071.003", "Mail Protocols", "邮件协议 C2", "ta0011",
           "SMTP/IMAP C2",
           "异常邮件协议出站",
           "邮件网关",
           "通过 IMAP 收发命令", 4, 3),
        _t("T1573.001", "Symmetric Cryptography", "对称加密 C2", "ta0011",
           "对称加密 C2 流量",
           "流量特征、JA3",
           "TLS 检测",
           "AES 加密 C2", 3, 3),
        _t("T1090.001", "Multi-hop Proxy", "多跳代理", "ta0011",
           "多层代理隐藏 C2",
           "代理链分析",
           "出站监控",
           "Tor 多跳", 3, 3),
        _t("T1568.001", "Fast Flux DNS", "Fast Flux DNS", "ta0011",
           "Fast Flux 快速变换 DNS",
           "DNS 频繁变更",
           "DNS 监控",
           "Fast Flux 隐藏 C2", 4, 3),
        _t("T1105", "Remote File Copy", "远程文件拷贝", "ta0011",
           "通过 certutil/ bitsadmin 下载",
           "下载工具执行",
           "应用白名单",
           "certutil -urlcache", 2, 3),
        # ---- 数据渗出 补充 ----
        _t("T1048.002", "Exfiltration Over Asymmetric Encrypted Non-C2", "非对称加密非C2渗出", "ta0010",
           "通过非对称加密信道渗出",
           "异常加密出站",
           "DLP",
           "GPG 加密后上传", 4, 4),
        _t("T1567.002", "Exfiltration to Cloud Storage", "云存储渗出", "ta0010",
           "上传到云存储渗出",
           "云上传异常",
           "CASB",
           "上传到 S3/OneDrive", 2, 4),
        _t("T1560.002", "Archive via Library", "库归档渗出", "ta0010",
           "用库压缩归档渗出",
           "压缩行为",
           "DLP",
           "内存中压缩", 3, 3),
        _t("T1020", "Automated Exfiltration DB", "自动数据库渗出", "ta0010",
           "自动导出数据库渗出",
           "批量导出",
           "DLP",
           "mysqldump 渗出", 3, 5),
        # ---- 影响 补充 ----
        _t("T1499", "Endpoint Denial of Service", "端点 DoS", "ta0040",
           "耗尽端点资源拒绝服务",
           "资源耗尽监控",
           "资源限制",
           "CPU/内存耗尽", 3, 4),
        _t("T1498", "Network Denial of Service", "网络 DoS", "ta0040",
           "网络层拒绝服务",
           "流量异常",
           "DDoS 防护",
           "SYN 洪水", 4, 5),
        _t("T1531", "Account Access Removal", "账户访问移除", "ta0040",
           "锁定/移除管理员账户",
           "批量账户锁定",
           "账户保护",
           "锁定管理员账户勒索", 3, 4),
        _t("T1657", "Financial Theft", "金融盗窃", "ta0040",
           "盗窃资金/加密货币",
           "异常交易监控",
           "交易风控",
           "盗取加密货币钱包", 4, 5),
        _t("T1484", "Domain Policy Modification", "域策略修改", "ta0040",
           "修改域策略破坏",
           "GPO 变更审计",
           "GPO 保护",
           "修改组策略", 4, 4),
        # ---- 侦察 补充 ----
        _t("T1592", "Gather Victim Host Info", "收集主机信息", "ta0043",
           "收集目标主机 OS/软件",
           "OSINT",
           "信息管控",
           "指纹识别", 1, 2),
        _t("T1594", "Search Victim-Owned Websites", "搜索目标网站", "ta0043",
           "搜索目标网站内容",
           "爬虫监控",
           "robots.txt",
           "爬取目标网站", 1, 2),
        _t("T1596", "Search Open Technical Databases", "搜索技术数据库", "ta0043",
           "搜索 Shodan/Censys",
           "外部情报",
           "攻击面管理",
           "Shodan 搜索目标", 1, 2),
        _t("T1598", "Phishing for Information", "钓鱼获取信息", "ta0043",
           "钓鱼收集目标信息",
           "邮件监控",
           "用户培训",
           "钓鱼问卷收集", 2, 3),
        # ---- 资源开发 补充 ----
        _t("T1583.001", "Domains", "注册域名", "ta0042",
           "注册攻击域名",
           "WHOIS 监控",
           "域名监控",
           "仿冒域名", 1, 2),
        _t("T1583.003", "Virtual Private Server", "VPS", "ta0042",
           "租用 VPS 作为 C2",
           "VPS 情报",
           "—",
           "DigitalOcean VPS", 1, 2),
        _t("T1585.001", "Social Media Accounts", "社交媒体账户", "ta0042",
           "注册社交媒体账户",
           "—",
           "—",
           "LinkedIn 假账户", 1, 2),
        _t("T1586.002", "Email Accounts", "邮件账户", "ta0042",
           "建立邮件账户",
           "—",
           "—",
           "Gmail 攻击账户", 1, 2),
        _t("T1587.001", "Malware", "开发恶意软件", "ta0042",
           "开发自定义恶意软件",
           "威胁情报",
           "—",
           "定制 RAT", 3, 3),
        _t("T1588.002", "Tool", "获取工具", "ta0042",
           "购买/下载攻击工具",
           "地下市场情报",
           "—",
           "购买 Cobalt Strike", 2, 3),
    ]
    for tech in extra:
        ATTACK_TECHNIQUES.setdefault(tech["tid"], tech)


_expand_techniques()


def _final_expansion() -> None:
    """第三批技术，补足 190+。"""
    final: List[Dict[str, Any]] = [
        _t("T1564.001", "Hidden Files and Directories", "隐藏文件目录", "ta0005",
           "隐藏恶意文件/目录", "隐藏文件监控、FIM", "FIM",
           "attrib +h 隐藏", 2, 2),
        _t("T1564.004", "NTFS File Attributes", "NTFS 备用数据流", "ta0005",
           "ADS 备用数据流隐藏", "ADS 检测、streams.exe", "FIM",
           "木马隐藏在 ADS", 4, 3),
        _t("T1070.006", "Timestomp", "时间戳篡改", "ta0005",
           "篡改文件时间戳", "时间戳异常", "FIM",
           "timestomp 修改时间", 3, 3),
        _t("T1685", "Disable or Modify System Firewall", "修改系统防火墙", "ta0005",
           "关闭/修改系统防火墙", "防火墙规则变更", "防火墙 GPO",
           "netsh 关闭防火墙", 3, 4),
        _t("T1562.003", "Impair Command History", "清除命令历史", "ta0005",
           "清除 bash/PowerShell 历史", "历史文件监控", "集中日志",
           "Clear-History", 2, 2),
        _t("T1556.002", "Password Filter DLL", "密码过滤 DLL", "ta0006",
           "安装密码过滤 DLL 捕获密码", "LSA 包监控", "LSA 保护",
           "Mimikatz 密码过滤", 5, 5),
        _t("T1557.001", "LLMNR/NBT-NS Poisoning", "LLMNR 投毒", "ta0006",
           "投毒 LLMNR/NBT-NS 响应窃取哈希", "LLMNR 流量异常", "禁用 LLMNR、SMB 签名",
           "Responder 投毒", 3, 4),
        _t("T1110.002", "Password Cracking", "密码破解", "ta0006",
           "离线破解哈希密码", "—", "强密码、盐值",
           "John the Ripper", 3, 3),
        _t("T1003.007", "Proc Memory", "进程内存凭证", "ta0006",
           "从任意进程内存提取凭证", "内存读取监控", "EDR",
           "从浏览器进程提取", 4, 4),
        _t("T1546.008", "Accessibility Features", "辅助功能后门", "ta0003",
           "替换 sethc/utilman 后门", "系统工具完整性", "WDAC",
           "粘滞键后门", 4, 4),
        _t("T1546.011", "AppCert DLLs", "AppCert DLL 注入", "ta0003",
           "AppCert DLLs 注册表注入", "注册表监控", "注册表 ACL",
           "AppCert 持久化", 4, 4),
        _t("T1136.002", "Domain Account", "域账户创建", "ta0003",
           "创建域管理员账户", "域账户创建事件", "域审计",
           "net user /domain /add", 2, 4),
        _t("T1090.003", "Proxied Proxy", "双跳代理", "ta0011",
           "内部跳板做代理", "内部代理流量", "出站白名单",
           "受害机做代理", 3, 3),
        _t("T1568", "Dynamic Resolution", "动态解析", "ta0011",
           "DGA 动态生成 C2 域名", "DGA 检测、熵值", "DNS Sinkhole",
           "DGA 域名生成", 5, 4),
        _t("T1041.001", "Exfil Over Webhook", "Webhook 渗出", "ta0010",
           "通过 Slack/Discord Webhook 渗出", "Webhook 出站异常", "CASB",
           "Discord webhook 渗出", 2, 4),
        _t("T1486.001", "Ransomware as a Service", "RaaS 勒索即服务", "ta0040",
           "RaaS 模式勒索", "勒索行为检测", "备份、EDR",
           "BlackCat RaaS", 4, 5),
        _t("T1529", "System Shutdown/Reboot", "关机重启", "ta0040",
           "恶意关机/重启影响业务", "异常关机事件", "电源保护",
           "勒索软件关机", 2, 3),
        _t("T1584.001", "Compromise Domains", "攻陷域名", "ta0042",
           "攻陷现有域名用于攻击", "域名 NS 变更", "域名锁",
           "劫持 DNS", 4, 3),
        _t("T1608.001", "Stage Capabilities", "投放能力", "ta0042",
           "在基础设施投放攻击能力", "—", "—",
           "搭建 C2 服务器", 2, 2),
        _t("T1590.004", "IP Addresses", "收集 IP 地址", "ta0043",
           "收集目标 IP 段", "OSINT", "攻击面管理",
           "WHOIS IP 查询", 1, 2),
        _t("T1593.001", "Search Engines", "搜索引擎侦察", "ta0043",
           "搜索引擎收集目标", "—", "信息管控",
           "Google hacking", 1, 2),
        _t("T1213.005", "Chat Teams", "聊天工具收集", "ta0009",
           "从 Teams/Slack 收集信息", "聊天工具异常访问", "DLP",
           "导出聊天记录", 2, 3),
    ]
    for tech in final:
        ATTACK_TECHNIQUES.setdefault(tech["tid"], tech)


_final_expansion()


# ============================================================
# 3. 攻击场景库
# ============================================================

ATTACK_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "scenario-apt29": {
        "id": "scenario-apt29", "name": "APT29 定向攻击", "type": "apt",
        "description": "模拟 APT29(Cozy Bear) 长期定向攻击：鱼叉钓鱼 → 初始访问 → 持久化 → 横向移动 → 数据渗出",
        "tactics_flow": ["ta0043", "ta0042", "ta0001", "ta0002", "ta0003",
                         "ta0004", "ta0007", "ta0008", "ta0011", "ta0010"],
        "key_techniques": ["T1566.001", "T1059.001", "T1547.001", "T1003.001",
                           "T1021.001", "T1550.002", "T1071.001", "T1041"],
        "duration_hours": 720, "difficulty": 5,
        "real_world_ref": "SolarWinds / DNC 入侵事件",
    },
    "scenario-ransomware-conti": {
        "id": "scenario-ransomware-conti", "name": "Conti 勒索软件攻击", "type": "ransomware",
        "description": "模拟 Conti 勒索软件全流程：初始访问 → 凭证转储 → 横向扩散 → 数据加密勒索",
        "tactics_flow": ["ta0001", "ta0002", "ta0003", "ta0004",
                         "ta0006", "ta0007", "ta0008", "ta0040"],
        "key_techniques": ["T1190", "T1078", "T1003.001", "T1550.002",
                           "T1021.002", "T1486", "T1489"],
        "duration_hours": 48, "difficulty": 4,
        "real_world_ref": "Conti 全球勒索活动(2020-2022)",
    },
    "scenario-data-breach": {
        "id": "scenario-data-breach", "name": "数据泄露场景", "type": "data_leak",
        "description": "模拟数据泄露：Web 入侵 → 提权 → 数据库收集 → 数据渗出",
        "tactics_flow": ["ta0001", "ta0002", "ta0004", "ta0007",
                         "ta0009", "ta0011", "ta0010"],
        "key_techniques": ["T1190", "T1068", "T1046", "T1005",
                           "T1119", "T1041", "T1567"],
        "duration_hours": 168, "difficulty": 3,
        "real_world_ref": "多家零售商客户数据泄露事件",
    },
    "scenario-lateral": {
        "id": "scenario-lateral", "name": "内网横向渗透", "type": "lateral",
        "description": "模拟内网横向：初始立足点 → 发现 → 凭证转储 → 横向移动 → 域控攻陷",
        "tactics_flow": ["ta0001", "ta0007", "ta0006", "ta0008",
                         "ta0004", "ta0003"],
        "key_techniques": ["T1133", "T1016", "T1046", "T1003.001",
                           "T1550.002", "T1550.003", "T1021.002"],
        "duration_hours": 96, "difficulty": 4,
        "real_world_ref": "典型内网渗透测试路径",
    },
    "scenario-phishing": {
        "id": "scenario-phishing", "name": "钓鱼邮件攻击", "type": "phishing",
        "description": "模拟钓鱼邮件全流程：侦察 → 鱼叉钓鱼 → 执行 → 持久化 → 信息收集",
        "tactics_flow": ["ta0043", "ta0001", "ta0002", "ta0003",
                         "ta0005", "ta0009"],
        "key_techniques": ["T1593", "T1566.002", "T1204.002",
                           "T1059.005", "T1547.001", "T1555.003", "T1113"],
        "duration_hours": 24, "difficulty": 2,
        "real_world_ref": "Emotet/TA505 钓鱼活动",
    },
    "scenario-apt-china": {
        "id": "scenario-apt-china", "name": "APT 长期潜伏", "type": "apt",
        "description": "模拟 APT 长期潜伏：供应链 → 初始访问 → 隐蔽持久化 → 低慢数据渗出",
        "tactics_flow": ["ta0042", "ta0001", "ta0002", "ta0003",
                         "ta0005", "ta0011", "ta0010"],
        "key_techniques": ["T1195.002", "T1566.001", "T1055",
                           "T1547.005", "T1573.002", "T1041"],
        "duration_hours": 2160, "difficulty": 5,
        "real_world_ref": "APT10/menuPass 长期潜伏活动",
    },
}


# ============================================================
# 4. 攻击链构建
# ============================================================

class AttackChainBuilder:
    """多阶段攻击链自动构建器。"""

    def __init__(self) -> None:
        self.chains: Dict[str, Dict[str, Any]] = {}

    def build_chain(self, scenario_id: str, target: str = "10.0.0.0/24",
                    objective: str = "data_exfiltration") -> Dict[str, Any]:
        """根据场景自动构建多阶段攻击链。"""
        scenario = ATTACK_SCENARIOS.get(scenario_id)
        if not scenario:
            raise ValueError(f"未知场景: {scenario_id}")

        chain_id = f"chain-{uuid.uuid4().hex[:8]}"
        stages: List[Dict[str, Any]] = []
        prev_tid: Optional[str] = None

        for tactic_id in scenario["tactics_flow"]:
            tactic = ATTACK_TACTICS.get(tactic_id, {})
            # 选择该战术下最合适的技术
            candidates = [t for t in ATTACK_TECHNIQUES.values()
                          if t["tactic"] == tactic_id]
            if not candidates:
                continue
            # 优先选择场景 key_techniques 中提到的技术
            preferred = [c for c in candidates if c["tid"] in scenario["key_techniques"]]
            chosen = preferred[0] if preferred else candidates[0]

            stage = {
                "stage": len(stages) + 1,
                "tactic_id": tactic_id,
                "tactic_name": tactic.get("name", tactic_id),
                "tactic_cn": tactic.get("cn", ""),
                "technique_id": chosen["tid"],
                "technique_name": chosen["name"],
                "technique_cn": chosen["cn"],
                "ttp": chosen["ttp"],
                "difficulty": chosen["difficulty"],
                "impact": chosen["impact"],
                "depends_on": prev_tid,
                "estimated_duration_min": chosen["difficulty"] * 15,
                "status": "planned",
            }
            stages.append(stage)
            prev_tid = chosen["tid"]

        chain = {
            "chain_id": chain_id,
            "scenario_id": scenario_id,
            "scenario_name": scenario["name"],
            "target": target,
            "objective": objective,
            "stages": stages,
            "total_stages": len(stages),
            "overall_difficulty": scenario["difficulty"],
            "status": "built",
            "created_at": datetime.now().isoformat(),
        }
        self.chains[chain_id] = chain
        return chain

    def get_chain(self, chain_id: str) -> Optional[Dict[str, Any]]:
        return self.chains.get(chain_id)

    def list_chains(self) -> List[Dict[str, Any]]:
        return list(self.chains.values())


# ============================================================
# 5. 攻击执行引擎
# ============================================================

class AttackExecutor:
    """攻击技术执行引擎（模拟工具调用 + 结果收集）。"""

    def __init__(self) -> None:
        self.runs: Dict[str, Dict[str, Any]] = {}

    def execute_technique(self, technique_id: str, target: str,
                          params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """执行单个攻击技术（模拟）。"""
        tech = ATTACK_TECHNIQUES.get(technique_id)
        if not tech:
            raise ValueError(f"未知技术: {technique_id}")

        run_id = f"run-{uuid.uuid4().hex[:10]}"
        params = params or {}

        # 模拟成功率：难度越高成功率越低
        success_prob = max(0.15, 0.9 - tech["difficulty"] * 0.12)
        succeeded = random.random() < success_prob

        result = {
            "run_id": run_id,
            "technique_id": technique_id,
            "technique_name": tech["name"],
            "technique_cn": tech["cn"],
            "tactic": tech["tactic"],
            "target": target,
            "params": params,
            "success": succeeded,
            "detection_likelihood": round(min(1.0, tech["impact"] * 0.18 + 0.2), 2),
            "execution_log": self._gen_execution_log(tech, target, succeeded),
            "artifacts": self._gen_artifacts(tech, succeeded),
            "duration_sec": round(random.uniform(2, 45), 1),
            "executed_at": datetime.now().isoformat(),
        }
        self.runs[run_id] = result
        return result

    def execute_chain(self, chain_id: str, builder: AttackChainBuilder) -> Dict[str, Any]:
        """按攻击链顺序执行所有阶段。"""
        chain = builder.get_chain(chain_id)
        if not chain:
            raise ValueError(f"未知攻击链: {chain_id}")

        chain_run_id = f"chainrun-{uuid.uuid4().hex[:10]}"
        stage_results: List[Dict[str, Any]] = []
        chain_success = True

        for stage in chain["stages"]:
            r = self.execute_technique(stage["technique_id"], chain["target"])
            stage["status"] = "success" if r["success"] else "failed"
            stage["run_id"] = r["run_id"]
            stage_results.append(r)
            if not r["success"]:
                chain_success = False

        summary = {
            "chain_run_id": chain_run_id,
            "chain_id": chain_id,
            "scenario_name": chain["scenario_name"],
            "target": chain["target"],
            "total_stages": len(chain["stages"]),
            "succeeded_stages": sum(1 for r in stage_results if r["success"]),
            "failed_stages": sum(1 for r in stage_results if not r["success"]),
            "chain_success": chain_success,
            "stage_results": stage_results,
            "started_at": datetime.now().isoformat(),
        }
        self.runs[chain_run_id] = summary
        return summary

    def _gen_execution_log(self, tech: Dict[str, Any], target: str,
                           succeeded: bool) -> str:
        status = "成功" if succeeded else "失败"
        return (f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"执行 {tech['tid']} {tech['cn']} 目标={target} -> {status}; "
                f"方法: {tech['ttp'][:60]}")

    def _gen_artifacts(self, tech: Dict[str, Any],
                       succeeded: bool) -> List[str]:
        if not succeeded:
            return ["无残留（执行失败）"]
        artifacts_map = {
            "ta0001": ["钓鱼邮件记录", "恶意附件哈希"],
            "ta0002": ["进程创建日志", "命令行参数"],
            "ta0003": ["注册表 Run 键", "服务配置"],
            "ta0004": ["令牌操作日志", "提权事件"],
            "ta0005": ["进程注入内存", "混淆 payload"],
            "ta0006": ["凭证转储文件", "LSASS 访问记录"],
            "ta0007": ["扫描结果", "主机列表"],
            "ta0008": ["SMB 连接日志", "远程会话"],
            "ta0009": ["截图文件", "收集文档"],
            "ta0011": ["C2 通信日志", "出站连接"],
            "ta0010": ["渗出数据包", "压缩归档"],
            "ta0040": ["加密文件", "勒索信"],
        }
        return artifacts_map.get(tech["tactic"], ["系统日志", "事件记录"])

    def list_runs(self) -> List[Dict[str, Any]]:
        return list(self.runs.values())


# ============================================================
# 6. 攻击效果评估
# ============================================================

class AttackEvaluator:
    """攻击效果评估：成功率/检测率/响应时间/影响范围/风险评级。"""

    def evaluate_run(self, run: Dict[str, Any]) -> Dict[str, Any]:
        """评估单次运行效果。"""
        success = run.get("success", False)
        tech = ATTACK_TECHNIQUES.get(run.get("technique_id", ""), {})

        detection_rate = round(1 - run.get("detection_likelihood", 0.5), 2)
        response_time_min = round(random.uniform(5, 120), 1)
        impact_scope = ["单机", "部门", "整网", "云环境"][min(
            int(tech.get("impact", 2) - 1), 3)]

        risk_score = min(10, round(
            tech.get("impact", 3) * 1.5 +
            tech.get("difficulty", 3) * 0.8 +
            (2 if success else 0), 1))

        if risk_score >= 8:
            risk_level = "严重"
        elif risk_score >= 6:
            risk_level = "高"
        elif risk_score >= 4:
            risk_level = "中"
        else:
            risk_level = "低"

        return {
            "run_id": run.get("run_id"),
            "attack_success_rate": round(1.0 if success else 0.0, 2),
            "estimated_detection_rate": detection_rate,
            "estimated_response_time_min": response_time_min,
            "impact_scope": impact_scope,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "technique_difficulty": tech.get("difficulty"),
            "technique_impact": tech.get("impact"),
        }

    def evaluate_chain(self, chain_run: Dict[str, Any]) -> Dict[str, Any]:
        """评估整条攻击链效果。"""
        total = chain_run.get("total_stages", 1)
        succeeded = chain_run.get("succeeded_stages", 0)
        success_rate = round(succeeded / max(total, 1), 2)

        avg_risk = round(sum(
            ATTACK_TECHNIQUES.get(s.get("technique_id", ""), {}).get("impact", 3)
            for s in chain_run.get("stage_results", [])
        ) / max(len(chain_run.get("stage_results", [])), 1), 1)

        chain_success = chain_run.get("chain_success", False)
        if success_rate >= 0.8:
            verdict = "攻击链完整达成"
        elif success_rate >= 0.5:
            verdict = "攻击链部分达成"
        else:
            verdict = "攻击链被阻断"

        return {
            "chain_run_id": chain_run.get("chain_run_id"),
            "attack_success_rate": success_rate,
            "succeeded_stages": succeeded,
            "total_stages": total,
            "average_impact_score": avg_risk,
            "chain_success": chain_success,
            "verdict": verdict,
            "kill_chain_coverage": f"{succeeded}/{total} 阶段达成",
        }


# ============================================================
# 7. 全局单例
# ============================================================

_builder = AttackChainBuilder()
_executor = AttackExecutor()
_evaluator = AttackEvaluator()


def get_attack_simulator() -> Dict[str, Any]:
    """返回攻击模拟引擎各组件单例。"""
    return {
        "builder": _builder,
        "executor": _executor,
        "evaluator": _evaluator,
        "tactics": ATTACK_TACTICS,
        "techniques": ATTACK_TECHNIQUES,
        "scenarios": ATTACK_SCENARIOS,
    }


def stats() -> Dict[str, Any]:
    """模块统计信息。"""
    return {
        "tactics_count": len(ATTACK_TACTICS),
        "techniques_count": len(ATTACK_TECHNIQUES),
        "scenarios_count": len(ATTACK_SCENARIOS),
        "chains_built": len(_builder.chains),
        "runs_executed": len(_executor.runs),
    }
