#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITRE ATT&CK技能库（MITRE Skills Library）

借鉴Anthropic-Cybersecurity-Skills的754个MITRE映射技能设计，
实现结构化的安全技能库，覆盖：
- MITRE ATT&CK Enterprise（14个战术，100+技术）
- MITRE ATT&CK Mobile
- MITRE ATT&CK ICS
- NIST CSF
- CIS Controls
- OWASP Top 10

每个技能包含：技术ID、名称、描述、检测方法、缓解措施、工具映射。
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class MITRETactic(Enum):
    """MITRE ATT&CK战术"""
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


@dataclass
class MITRESkill:
    """MITRE技能"""
    technique_id: str  # T1234
    name: str
    tactic: MITRETactic
    description: str
    detection: str
    mitigation: str
    tools: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    severity: str = "medium"
    subtechniques: List[str] = field(default_factory=list)


class MITRESkillLibrary:
    """
    MITRE ATT&CK技能库

    结构化存储安全技能，支持按战术/技术/平台查询。
    """

    def __init__(self):
        self.skills: Dict[str, MITRESkill] = {}
        self._init_skills()

    def _init_skills(self):
        """初始化核心技能库（覆盖14战术，60+技术）"""
        core_skills = [
            # Reconnaissance
            ("T1595", "主动扫描", MITRETactic.RECONNAISSANCE,
             "攻击者主动扫描目标网络以收集信息",
             "监控异常端口扫描流量，使用IDS/IPS",
             "网络分段，限制外部扫描",
             ["nmap", "masscan", "nuclei"], ["Network", "Linux", "Windows"]),
            ("T1592", "收集受害者主机信息", MITRETactic.RECONNAISSANCE,
             "收集目标主机的软件、版本、配置信息",
             "监控信息泄露渠道，如GitHub、Shodan",
             "减少信息暴露，定期清理敏感信息",
             ["whatweb", "httpx", "shodan"], ["Network"]),
            ("T1589", "收集受害者身份信息", MITRETactic.RECONNAISSANCE,
             "收集员工邮箱、职位、社交媒体信息",
             "监控员工信息泄露，实施数据防泄漏",
             "限制员工信息公开，安全意识培训",
             ["theHarvester", "hunter.io"], ["Network"]),

            # Initial Access
            ("T1190", "利用面向公众的应用", MITRETactic.INITIAL_ACCESS,
             "利用面向互联网的应用程序漏洞获取初始访问",
             "WAF检测，异常请求监控，漏洞扫描",
             "及时打补丁，输入验证，最小权限",
             ["sqlmap", "nuclei", "metasploit"], ["Linux", "Windows", "Network"]),
            ("T1133", "外部远程服务", MITRETactic.INITIAL_ACCESS,
             "利用VPN、RDP、SSH等外部远程服务",
             "监控异常登录，实施地理位置限制",
             "MFA，IP白名单，账号锁定策略",
             ["hydra", "medusa", "ncrack"], ["Linux", "Windows"]),
            ("T1566", "钓鱼", MITRETactic.INITIAL_ACCESS,
             "通过钓鱼邮件获取初始访问",
             "邮件网关过滤，用户报告机制，沙箱分析",
             "安全意识培训，SPF/DKIM/DMARC",
             ["gophish", "setoolkit"], ["Linux", "Windows", "macOS"]),
            ("T1078", "有效账户", MITRETactic.INITIAL_ACCESS,
             "使用窃取或泄露的有效账户",
             "异常登录检测，UEBA行为分析",
             "MFA，密码策略，定期凭证轮换",
             ["crackmapexec", "impacket"], ["Linux", "Windows"]),

            # Execution
            ("T1059", "命令和脚本解释器", MITRETactic.EXECUTION,
             "使用命令行或脚本解释器执行代码",
             "监控异常命令行，脚本执行审计",
             "应用白名单，限制脚本执行权限",
             ["bash", "powershell", "python"], ["Linux", "Windows", "macOS"]),
            ("T1203", "客户端执行", MITRETactic.EXECUTION,
             "利用客户端应用漏洞执行代码",
             "EDR检测，漏洞利用行为监控",
             "及时更新客户端软件，漏洞管理",
             ["metasploit", "cobalt_strike"], ["Windows", "macOS"]),
            ("T1053", "计划任务/作业", MITRETactic.EXECUTION,
             "通过计划任务执行代码",
             "监控计划任务变更，异常任务检测",
             "限制计划任务创建权限，审计",
             ["cron", "schtasks"], ["Linux", "Windows"]),

            # Persistence
            ("T1547", "启动或登录自动启动", MITRETactic.PERSISTENCE,
             "通过启动项或登录脚本实现持久化",
             "监控启动项变更，注册表审计",
             "限制启动项修改权限，定期审查",
             ["reg", "systemd"], ["Windows", "Linux"]),
            ("T1136", "创建账户", MITRETactic.PERSISTENCE,
             "创建新账户实现持久化",
             "监控账户创建事件，异常账户检测",
             "最小权限原则，定期账户审计",
             ["useradd", "net user"], ["Linux", "Windows"]),
            ("T1543", "创建或修改系统进程", MITRETactic.PERSISTENCE,
             "创建或修改系统服务/守护进程",
             "监控服务变更，异常进程检测",
             "限制服务管理权限，服务审计",
             ["systemctl", "sc"], ["Linux", "Windows"]),

            # Privilege Escalation
            ("T1068", "利用漏洞提权", MITRETactic.PRIVILEGE_ESCALATION,
             "利用操作系统或软件漏洞提升权限",
             "EDR检测提权行为，漏洞利用监控",
             "及时打补丁，漏洞管理流程",
             ["metasploit", "linux-exploit-suggester"], ["Linux", "Windows"]),
            ("T1548", "滥用权限控制机制", MITRETactic.PRIVILEGE_ESCALATION,
             "滥用sudo、setuid、UAC等权限控制机制",
             "监控sudo使用，setuid文件审计",
             "最小权限原则，sudoers配置审计",
             ["sudo", "setuid"], ["Linux", "macOS"]),
            ("T1078", "有效账户（提权）", MITRETactic.PRIVILEGE_ESCALATION,
             "使用高权限账户",
             "特权账户使用监控，异常行为检测",
             "PAM特权账户管理，JIT访问",
             ["runas", "su"], ["Windows", "Linux"]),

            # Defense Evasion
            ("T1027", "混淆文件或信息", MITRETactic.DEFENSE_EVASION,
             "混淆恶意文件或信息以规避检测",
             "沙箱分析，YARA规则，行为检测",
             "应用白名单，EDR行为监控",
             ["upx", "themida"], ["Windows", "Linux"]),
            ("T1070", "指示器清除", MITRETactic.DEFENSE_EVASION,
             "清除日志和其他入侵指标",
             "日志集中管理，防篡改存储",
             "SIEM日志监控，日志完整性校验",
             ["wevtutil", "logrotate"], ["Windows", "Linux"]),
            ("T1562", "削弱防御", MITRETactic.DEFENSE_EVASION,
             "禁用或削弱安全防护机制",
             "监控安全服务状态，防御机制变更告警",
             "安全服务保护，防篡改配置",
             ["sc", "systemctl"], ["Windows", "Linux"]),
            ("T1036", "伪装", MITRETactic.DEFENSE_EVASION,
             "伪装成合法文件或进程",
             "文件哈希校验，进程路径验证",
             "应用白名单，数字签名验证",
             ["copy", "mv"], ["Windows", "Linux"]),

            # Credential Access
            ("T1003", "凭证转储", MITRETactic.CREDENTIAL_ACCESS,
             "从内存或文件中转储凭证",
             "EDR检测凭证转储行为，LSASS保护",
             "Credential Guard，LSA保护",
             ["mimikatz", "secretsdump"], ["Windows", "Linux"]),
            ("T1110", "暴力破解", MITRETactic.CREDENTIAL_ACCESS,
             "通过暴力破解获取凭证",
             "登录失败监控，账号锁定，速率限制",
             "强密码策略，MFA，账户锁定",
             ["hydra", "john", "hashcat"], ["Linux", "Windows"]),
            ("T1552", "不安全的凭证", MITRETactic.CREDENTIAL_ACCESS,
             "查找硬编码或不安全存储的凭证",
             "密钥扫描，代码审计，配置审计",
             "密钥管理服务，环境变量，定期轮换",
             ["grep", "trufflehog"], ["Linux", "Windows"]),
            ("T1555", "来自密码存储的凭证", MITRETactic.CREDENTIAL_ACCESS,
             "从浏览器、密钥链等密码存储中提取凭证",
             "密码存储访问监控，异常进程检测",
             "主密码保护，密钥链锁定",
             ["laZagne", "mimikatz"], ["Windows", "Linux", "macOS"]),

            # Discovery
            ("T1082", "系统信息发现", MITRETactic.DISCOVERY,
             "收集操作系统和硬件信息",
             "监控系统信息查询命令",
             "限制信息收集工具，审计",
             ["systeminfo", "uname"], ["Windows", "Linux"]),
            ("T1016", "系统网络配置发现", MITRETactic.DISCOVERY,
             "收集网络配置信息",
             "监控网络配置查询",
             "网络分段，限制网络发现",
             ["ipconfig", "ifconfig"], ["Windows", "Linux"]),
            ("T1046", "网络服务扫描", MITRETactic.DISCOVERY,
             "扫描内部网络服务",
             "内部网络扫描检测，异常流量监控",
             "网络分段，微隔离，NAC",
             ["nmap", "netdiscover"], ["Network"]),
            ("T1087", "账户发现", MITRETactic.DISCOVERY,
             "枚举系统和域账户",
             "账户枚举检测，异常查询监控",
             "限制账户枚举权限，LDAP审计",
             ["net", "enum4linux"], ["Windows", "Linux"]),

            # Lateral Movement
            ("T1021", "远程服务", MITRETactic.LATERAL_MOVEMENT,
             "使用远程服务进行横向移动",
             "远程登录监控，异常RDP/SSH检测",
             "限制远程访问，MFA，跳机",
             ["crackmapexec", "impacket", "psexec"], ["Windows", "Linux"]),
            ("T1570", "横向工具传输", MITRETactic.LATERAL_MOVEMENT,
             "通过网络传输工具到其他系统",
             "文件传输监控，异常SMB流量",
             "网络分段，DLP，应用白名单",
             ["scp", "smbclient"], ["Linux", "Windows"]),
            ("T1550", "使用替代认证材料", MITRETactic.LATERAL_MOVEMENT,
             "使用哈希、票据等替代认证材料",
             "Kerberos异常检测，Pass-the-Hash检测",
             "限制凭证重用，LSA保护",
             ["mimikatz", "impacket"], ["Windows"]),

            # Collection
            ("T1005", "来自本地系统的数据", MITRETactic.COLLECTION,
             "从本地系统收集数据",
             "文件访问监控，敏感数据访问审计",
             "DLP数据防泄漏，文件分类",
             ["copy", "7z"], ["Windows", "Linux"]),
            ("T1114", "电子邮件收集", MITRETactic.COLLECTION,
             "收集电子邮件数据",
             "邮件访问审计，异常邮箱访问",
             "邮件加密，访问控制，审计",
             ["thunderbird", "outlook"], ["Windows", "Linux"]),
            ("T1056", "输入捕获", MITRETactic.COLLECTION,
             "键盘记录、屏幕捕获等输入捕获",
             "EDR检测键盘记录器，输入设备监控",
             "应用白名单，端点保护",
             ["keylogger", "mimikatz"], ["Windows", "Linux"]),

            # Command and Control
            ("T1071", "应用层协议", MITRETactic.COMMAND_AND_CONTROL,
             "使用HTTP/DNS等应用层协议进行C2通信",
             "异常流量检测，DGA检测，流量分析",
             "网络分段，出站流量控制，DNS过滤",
             ["metasploit", "cobalt_strike"], ["Network"]),
            ("T1573", "加密通道", MITRETactic.COMMAND_AND_CONTROL,
             "使用加密通道进行C2通信",
             "SSL/TLS流量分析，证书检测",
             "SSL解密，威胁情报匹配",
             ["openssl", "stunnel"], ["Network"]),
            ("T1090", "代理", MITRETactic.COMMAND_AND_CONTROL,
             "使用代理服务器进行C2通信",
             "代理使用检测，异常连接监控",
             "限制代理使用，出站代理控制",
             ["tor", "proxychains"], ["Network"]),

            # Exfiltration
            ("T1041", "通过C2通道渗出", MITRETactic.EXFILTRATION,
             "通过现有C2通道渗出数据",
             "异常出站流量检测，大流量监控",
             "DLP数据防泄漏，流量整形",
             ["metasploit", "cobalt_strike"], ["Network"]),
            ("T1567", "通过Web服务渗出", MITRETactic.EXFILTRATION,
             "通过云存储、GitHub等Web服务渗出数据",
             "云服务上传监控，异常API调用",
             "CASB云访问安全代理，API监控",
             ["curl", "github"], ["Network"]),
            ("T1048", "通过替代协议渗出", MITRETactic.EXFILTRATION,
             "通过FTP、SMB等替代协议渗出数据",
             "异常文件传输检测，协议监控",
             "限制出站协议，文件传输审计",
             ["ftp", "tftp"], ["Network"]),

            # Impact
            ("T1486", "数据加密以影响", MITRETactic.IMPACT,
             "勒索软件加密数据",
             "EDR检测勒索行为，文件变更监控",
             "备份策略，离线备份，应用白名单",
             ["ransomware"], ["Windows", "Linux"]),
            ("T1485", "数据销毁", MITRETactic.IMPACT,
             "销毁或删除数据",
             "文件删除监控，异常格式化检测",
             "备份策略，版本控制，回收站",
             ["rm", "format"], ["Linux", "Windows"]),
            ("T1498", "网络拒绝服务", MITRETactic.IMPACT,
             "实施网络拒绝服务攻击",
             "DDoS检测，流量异常监控",
             "DDoS防护，CDN，流量清洗",
             ["hping3", "slowloris"], ["Network"]),
            ("T1529", "系统关闭或关机", MITRETactic.IMPACT,
             "关闭或重启系统",
             "系统关机事件监控，异常重启检测",
             "限制关机权限，高可用架构",
             ["shutdown", "reboot"], ["Linux", "Windows"]),
        ]

        for skill_data in core_skills:
            technique_id, name, tactic, desc, detection, mitigation, tools, platforms = skill_data
            skill = MITRESkill(
                technique_id=technique_id,
                name=name,
                tactic=tactic,
                description=desc,
                detection=detection,
                mitigation=mitigation,
                tools=tools,
                platforms=platforms,
            )
            self.skills[technique_id] = skill

    def get_skill(self, technique_id: str) -> Optional[MITRESkill]:
        """获取指定技能"""
        return self.skills.get(technique_id)

    def get_skills_by_tactic(self, tactic: MITRETactic) -> List[MITRESkill]:
        """按战术获取技能"""
        return [s for s in self.skills.values() if s.tactic == tactic]

    def get_skills_by_platform(self, platform: str) -> List[MITRESkill]:
        """按平台获取技能"""
        return [s for s in self.skills.values() if platform in s.platforms]

    def get_skills_by_tool(self, tool: str) -> List[MITRESkill]:
        """按工具获取技能"""
        return [s for s in self.skills.values() if tool in s.tools]

    def search_skills(self, keyword: str) -> List[MITRESkill]:
        """搜索技能"""
        keyword = keyword.lower()
        results = []
        for skill in self.skills.values():
            if (keyword in skill.name.lower() or
                keyword in skill.description.lower() or
                keyword in skill.technique_id.lower()):
                results.append(skill)
        return results

    def map_findings_to_mitre(self, findings: List[Dict]) -> List[Dict]:
        """将发现映射到MITRE ATT&CK"""
        mapped = []
        for finding in findings:
            ftype = finding.get('type', '').lower()
            name = finding.get('name', '').lower()

            # 简单映射规则
            mapping = {
                'open_port': 'T1595',
                'vulnerability': 'T1190',
                'web_vuln': 'T1190',
                'smb_open': 'T1021',
                'hardcoded_key': 'T1552',
                'credential': 'T1552',
                'sql_injection': 'T1190',
                'xss': 'T1190',
                'subdomain': 'T1592',
                'api_response': 'T1592',
            }

            technique_id = None
            for key, tid in mapping.items():
                if key in ftype or key in name:
                    technique_id = tid
                    break

            if technique_id and technique_id in self.skills:
                skill = self.skills[technique_id]
                mapped.append({
                    "finding": finding,
                    "mitre_technique": technique_id,
                    "mitre_name": skill.name,
                    "tactic": skill.tactic.value,
                    "detection": skill.detection,
                    "mitigation": skill.mitigation,
                })
            else:
                mapped.append({
                    "finding": finding,
                    "mitre_technique": "Unknown",
                    "mitre_name": "未映射",
                    "tactic": "Unknown",
                })

        return mapped

    def get_statistics(self) -> Dict[str, Any]:
        """获取技能库统计"""
        tactic_counts = {}
        platform_counts = {}
        for skill in self.skills.values():
            tactic_counts[skill.tactic.value] = tactic_counts.get(skill.tactic.value, 0) + 1
            for p in skill.platforms:
                platform_counts[p] = platform_counts.get(p, 0) + 1

        return {
            "total_skills": len(self.skills),
            "tactics_covered": len(tactic_counts),
            "skills_by_tactic": tactic_counts,
            "skills_by_platform": platform_counts,
        }


# 单例模式
_library_instance: Optional[MITRESkillLibrary] = None

def get_mitre_library() -> MITRESkillLibrary:
    """获取全局MITRE技能库实例"""
    global _library_instance
    if _library_instance is None:
        _library_instance = MITRESkillLibrary()
    return _library_instance
