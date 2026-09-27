"""
cve_extended安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

EXTENDED_CVES = [
    # ===== Web服务器 =====
    {"cve_id": "CVE-2021-41773", "name": "Apache HTTP Server 路径穿越", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-22"], "product": "apache_http_server", "desc": "Apache HTTP Server 2.4.49版本路径穿越和目录遍历漏洞，攻击者可读取服务器任意文件"},
    {"cve_id": "CVE-2021-42013", "name": "Apache HTTP Server RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-22"], "product": "apache_http_server", "desc": "Apache HTTP Server 2.4.50版本路径穿越修复不完整，可导致远程代码执行"},
    {"cve_id": "CVE-2022-22720", "name": "Apache HTTP Server 请求走私", "severity": "high", "cvss_v31": 7.5, "cwe": ["CWE-444"], "product": "apache_http_server", "desc": "Apache HTTP Server HTTP请求走私漏洞，可导致缓存污染和会话劫持"},
    {"cve_id": "CVE-2023-25690", "name": "Apache HTTP Server 请求走私", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-444"], "product": "apache_http_server", "desc": "Apache HTTP Server mod_proxy请求走私漏洞，可导致未授权访问和缓存污染"},
    {"cve_id": "CVE-2019-0211", "name": "Apache HTTP Server 本地提权", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-269"], "product": "apache_http_server", "desc": "Apache HTTP Server 本地权限提升漏洞，低权限用户可执行任意代码"},

    # ===== Nginx =====
    {"cve_id": "CVE-2021-23017", "name": "Nginx DNS解析器堆溢出", "severity": "high", "cvss_v31": 7.7, "cwe": ["CWE-193"], "product": "nginx", "desc": "Nginx DNS解析器离线-by-one漏洞，可导致DNS响应处理时堆内存破坏"},
    {"cve_id": "CVE-2019-20372", "name": "Nginx 请求走私", "severity": "medium", "cvss_v31": 5.3, "cwe": ["CWE-444"], "product": "nginx", "desc": "Nginx HTTP请求走私漏洞，可导致缓存污染"},

    # ===== IIS =====
    {"cve_id": "CVE-2017-7269", "name": "IIS 6.0 WebDAV RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-119"], "product": "microsoft_iis", "desc": "Microsoft IIS 6.0 WebDAV缓冲区溢出漏洞，可导致远程代码执行"},
    {"cve_id": "CVE-2015-1635", "name": "IIS HTTP.sys 远程代码执行", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-119"], "product": "microsoft_iis", "desc": "Microsoft Windows HTTP.sys远程代码执行漏洞，可导致系统完全沦陷"},

    # ===== Tomcat =====
    {"cve_id": "CVE-2020-1938", "name": "Apache Tomcat Ghostcat 文件包含", "severity": "high", "cvss_v31": 7.5, "cwe": ["CWE-22"], "product": "apache_tomcat", "desc": "Apache Tomcat AJP协议文件包含/读取漏洞（Ghostcat），可读取webapp目录下任意文件"},
    {"cve_id": "CVE-2017-12615", "name": "Apache Tomcat PUT方法RCE", "severity": "high", "cvss_v31": 8.1, "cwe": ["CWE-434"], "product": "apache_tomcat", "desc": "Apache Tomcat PUT方法上传任意文件漏洞，可上传JSP webshell导致RCE"},
    {"cve_id": "CVE-2019-0232", "name": "Apache Tomcat CGI RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-78"], "product": "apache_tomcat", "desc": "Apache Tomcat CGI Servlet远程代码执行漏洞（Windows平台）"},
    {"cve_id": "CVE-2022-29885", "name": "Apache Tomcat 集群反序列化", "severity": "high", "cvss_v31": 7.5, "cwe": ["CWE-502"], "product": "apache_tomcat", "desc": "Apache Tomcat集群通信反序列化漏洞，可导致未授权代码执行"},
    {"cve_id": "CVE-2023-28708", "name": "Apache Tomcat 信息泄露", "severity": "medium", "cvss_v31": 4.3, "cwe": ["CWE-200"], "product": "apache_tomcat", "desc": "Apache Tomcat请求参数信息泄露漏洞，可导致会话劫持"},

    # ===== JBoss/WebLogic/WebSphere =====
    {"cve_id": "CVE-2017-10271", "name": "Oracle WebLogic WLS-WSAT反序列化", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-502"], "product": "oracle_weblogic", "desc": "Oracle WebLogic Server WLS-WSAT组件反序列化漏洞，可导致远程代码执行"},
    {"cve_id": "CVE-2019-2725", "name": "Oracle WebLogic 反序列化RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-502"], "product": "oracle_weblogic", "desc": "Oracle WebLogic Server wls9-async组件反序列化漏洞，可导致远程代码执行"},
    {"cve_id": "CVE-2020-14882", "name": "Oracle WebLogic 控制台RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-94"], "product": "oracle_weblogic", "desc": "Oracle WebLogic Server控制台未授权远程代码执行漏洞"},
    {"cve_id": "CVE-2015-7501", "name": "JBoss 反序列化RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-502"], "product": "jboss", "desc": "JBoss Java反序列化漏洞，可导致远程代码执行"},
    {"cve_id": "CVE-2013-4810", "name": "HP OpenView 缓冲区溢出", "severity": "critical", "cvss_v31": 10.0, "cwe": ["CWE-119"], "product": "hp_openview", "desc": "HP OpenView Network Node Manager缓冲区溢出漏洞"},

    # ===== 数据库 =====
    {"cve_id": "CVE-2012-2122", "name": "MySQL 身份认证绕过", "severity": "high", "cvss_v31": 8.1, "cwe": ["CWE-287"], "product": "mysql", "desc": "MySQL身份认证绕过漏洞，攻击者可在知道用户名的情况下无需密码登录"},
    {"cve_id": "CVE-2016-6662", "name": "MySQL 本地提权", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-269"], "product": "mysql", "desc": "MySQL基于SQL注入的本地权限提升漏洞"},
    {"cve_id": "CVE-2020-2922", "name": "Oracle MySQL 未授权访问", "severity": "high", "cvss_v31": 7.5, "cwe": ["CWE-306"], "product": "mysql", "desc": "Oracle MySQL Server未授权访问漏洞"},
    {"cve_id": "CVE-2019-9193", "name": "PostgreSQL 命令执行", "severity": "high", "cvss_v31": 8.8, "cwe": ["CWE-78"], "product": "postgresql", "desc": "PostgreSQL COPY FROM PROGRAM功能可导致任意命令执行"},
    {"cve_id": "CVE-2020-1472", "name": "Oracle MySQL 拒绝服务", "severity": "medium", "cvss_v31": 5.3, "cwe": ["CWE-400"], "product": "mysql", "desc": "Oracle MySQL Server拒绝服务漏洞"},
    {"cve_id": "CVE-2018-1123", "name": "Redis 远程代码执行", "severity": "high", "cvss_v31": 7.5, "cwe": ["CWE-78"], "product": "redis", "desc": "Redis Lua沙箱绕过可导致远程代码执行"},
    {"cve_id": "CVE-2022-0543", "name": "Redis Lua沙箱逃逸RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-94"], "product": "redis", "desc": "Redis Debian/Ubuntu包Lua沙箱逃逸漏洞，可导致远程代码执行"},
    {"cve_id": "CVE-2015-4335", "name": "Redis 未授权访问", "severity": "high", "cvss_v31": 8.6, "cwe": ["CWE-306"], "product": "redis", "desc": "Redis未授权访问漏洞，可导致数据泄露和远程代码执行"},
    {"cve_id": "CVE-2019-3792", "name": "MongoDB 权限提升", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-269"], "product": "mongodb", "desc": "MongoDB权限提升漏洞"},
    {"cve_id": "CVE-2013-1892", "name": "MongoDB 远程代码执行", "severity": "high", "cvss_v31": 8.4, "cwe": ["CWE-94"], "product": "mongodb", "desc": "MongoDB Spidermonkey引擎远程代码执行漏洞"},
    {"cve_id": "CVE-2016-3088", "name": "ActiveMQ 文件上传RCE", "severity": "high", "cvss_v31": 8.1, "cwe": ["CWE-434"], "product": "apache_activemq", "desc": "Apache ActiveMQ Fileserver文件上传漏洞，可导致远程代码执行"},
    {"cve_id": "CVE-2023-46604", "name": "ActiveMQ 反序列化RCE", "severity": "critical", "cvss_v31": 10.0, "cwe": ["CWE-502"], "product": "apache_activemq", "desc": "Apache ActiveMQ OpenWire协议反序列化漏洞，可导致远程代码执行"},

    # ===== 中间件/网关 =====
    {"cve_id": "CVE-2021-22986", "name": "F5 BIG-IP iControl REST RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-918"], "product": "f5_bigip", "desc": "F5 BIG-IP iControl REST身份认证绕过和远程代码执行漏洞"},
    {"cve_id": "CVE-2022-1388", "name": "F5 BIG-IP iControl REST 认证绕过", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-287"], "product": "f5_bigip", "desc": "F5 BIG-IP iControl REST身份认证绕过漏洞，可导致未授权远程代码执行"},
    {"cve_id": "CVE-2023-46747", "name": "F5 BIG-IP APM 认证绕过RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-287"], "product": "f5_bigip", "desc": "F5 BIG-IP APM身份认证绕过漏洞，可导致未授权远程代码执行"},
    {"cve_id": "CVE-2020-5902", "name": "F5 BIG-IP TMUI RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-22"], "product": "f5_bigip", "desc": "F5 BIG-IP TMUI目录穿越和远程代码执行漏洞"},
    {"cve_id": "CVE-2018-13379", "name": "Fortinet FortiOS 路径穿越", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-22"], "product": "fortinet_fortios", "desc": "Fortinet FortiOS SSL VPN路径穿越漏洞，可读取系统文件包含用户名密码"},
    {"cve_id": "CVE-2019-19781", "name": "Citrix ADC 目录遍历RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-22"], "product": "citrix_adc", "desc": "Citrix ADC/Gateway目录遍历漏洞，可导致未授权远程代码执行"},
    {"cve_id": "CVE-2023-3519", "name": "Citrix ADC 未授权RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-94"], "product": "citrix_adc", "desc": "Citrix ADC/Gateway未授权远程代码执行漏洞"},
    {"cve_id": "CVE-2022-22954", "name": "VMware Workspace ONE SSTI RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-94"], "product": "vmware_workspace_one", "desc": "VMware Workspace ONE Access服务端模板注入漏洞，可导致远程代码执行"},
    {"cve_id": "CVE-2021-21972", "name": "VMware vCenter 未授权RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-434"], "product": "vmware_vcenter", "desc": "VMware vCenter Server未授权文件上传漏洞，可导致远程代码执行"},
    {"cve_id": "CVE-2021-21985", "name": "VMware vCenter RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-94"], "product": "vmware_vcenter", "desc": "VMware vCenter Server远程代码执行漏洞"},
    {"cve_id": "CVE-2020-3992", "name": "VMware ESXi 远程代码执行", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-416"], "product": "vmware_esxi", "desc": "VMware ESXi OpenSLP远程代码执行漏洞"},
    {"cve_id": "CVE-2021-21974", "name": "VMware ESXi 堆溢出RCE", "severity": "high", "cvss_v31": 8.8, "cwe": ["CWE-787"], "product": "vmware_esxi", "desc": "VMware ESXi OpenSLP堆溢出漏洞，可导致远程代码执行"},

    # ===== 操作系统 =====
    {"cve_id": "CVE-2023-23397", "name": "Microsoft Outlook NTLM凭证泄露", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-294"], "product": "microsoft_outlook", "desc": "Microsoft Outlook NTLM凭证泄露漏洞，可导致NTLM中继攻击"},
    {"cve_id": "CVE-2023-36884", "name": "Microsoft Office 远程代码执行", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-94"], "product": "microsoft_office", "desc": "Microsoft Office远程代码执行漏洞（Storm-0978利用）"},
    {"cve_id": "CVE-2021-40444", "name": "Microsoft MSHTML 远程代码执行", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-94"], "product": "microsoft_mshtml", "desc": "Microsoft MSHTML远程代码执行漏洞，可通过恶意Office文档触发"},
    {"cve_id": "CVE-2022-30190", "name": "Microsoft MSDT 远程代码执行", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-94"], "product": "microsoft_msdt", "desc": "Microsoft支持诊断工具(MSDT)远程代码执行漏洞（Follina）"},
    {"cve_id": "CVE-2023-28252", "name": "Windows CLFS 提权", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-269"], "product": "microsoft_windows", "desc": "Windows通用日志文件系统驱动程序权限提升漏洞"},
    {"cve_id": "CVE-2023-32019", "name": "Windows Kernel 信息泄露", "severity": "medium", "cvss_v31": 5.5, "cwe": ["CWE-200"], "product": "microsoft_windows", "desc": "Windows内核信息泄露漏洞"},
    {"cve_id": "CVE-2022-21882", "name": "Windows Kernel 提权", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-269"], "product": "microsoft_windows", "desc": "Windows内核模式驱动程序权限提升漏洞"},
    {"cve_id": "CVE-2021-36934", "name": "Windows HiveNightmare 提权", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-269"], "product": "microsoft_windows", "desc": "Windows权限提升漏洞（HiveNightmare/SeriousSAM），可读取SAM文件"},
    {"cve_id": "CVE-2020-0787", "name": "Windows BITS 提权", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-269"], "product": "microsoft_windows", "desc": "Windows后台智能传输服务(BITS)权限提升漏洞"},
    {"cve_id": "CVE-2019-1458", "name": "Windows WizardOpium 提权", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-269"], "product": "microsoft_windows", "desc": "Windows权限提升漏洞（WizardOpium）"},
    {"cve_id": "CVE-2021-3156", "name": "Sudo Baron Samedit 提权", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-193"], "product": "linux_sudo", "desc": "Sudo堆缓冲区溢出漏洞（Baron Samedit），可本地提权到root"},
    {"cve_id": "CVE-2022-0847", "name": "Linux Dirty Pipe 提权", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-269"], "product": "linux_kernel", "desc": "Linux内核管道缓冲区污染漏洞（Dirty Pipe），可覆盖任意只读文件"},
    {"cve_id": "CVE-2016-5195", "name": "Linux Dirty COW 提权", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-362"], "product": "linux_kernel", "desc": "Linux内核竞争条件漏洞（Dirty COW），可本地提权到root"},
    {"cve_id": "CVE-2023-32233", "name": "Linux NetFilter 提权", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-416"], "product": "linux_kernel", "desc": "Linux NetFilter nf_tables use-after-free漏洞，可本地提权到root"},
    {"cve_id": "CVE-2022-2588", "name": "Linux Route4Me 提权", "severity": "high", "cvss_v31": 7.8, "cwe": ["CWE-416"], "product": "linux_kernel", "desc": "Linux内核route4网络协议use-after-free漏洞，可本地提权"},

    # ===== 网络设备 =====
    {"cve_id": "CVE-2023-20198", "name": "Cisco IOS XE Web UI 未授权RCE", "severity": "critical", "cvss_v31": 10.0, "cwe": ["CWE-306"], "product": "cisco_ios_xe", "desc": "Cisco IOS XE Web UI未授权远程代码执行漏洞，可创建特权用户"},
    {"cve_id": "CVE-2023-20273", "name": "Cisco IOS XE 权限提升", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-269"], "product": "cisco_ios_xe", "desc": "Cisco IOS XE权限提升漏洞，可提升到root权限"},
    {"cve_id": "CVE-2018-0171", "name": "Cisco IOS Smart Install RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-20"], "product": "cisco_ios", "desc": "Cisco IOS Smart Install远程代码执行漏洞"},
    {"cve_id": "CVE-2019-1653", "name": "Cisco RV320 信息泄露", "severity": "high", "cvss_v31": 7.5, "cwe": ["CWE-200"], "product": "cisco_rv320", "desc": "Cisco RV320/RV325路由器配置信息泄露漏洞"},
    {"cve_id": "CVE-2022-1026", "name": "Kyocera打印机 未授权访问", "severity": "high", "cvss_v31": 8.1, "cwe": ["CWE-306"], "product": "kyocera_printer", "desc": "Kyocera打印机未授权访问漏洞，可获取地址簿和文档"},
    {"cve_id": "CVE-2022-31474", "name": "D-Link 路由器 命令注入", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-78"], "product": "dlink_router", "desc": "D-Link路由器命令注入漏洞，可导致远程代码执行"},

    # ===== 企业应用 =====
    {"cve_id": "CVE-2022-26134", "name": "Confluence OGNL注入RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-94"], "product": "atlassian_confluence", "desc": "Atlassian Confluence Server OGNL注入漏洞，可导致未授权远程代码执行"},
    {"cve_id": "CVE-2023-22515", "name": "Confluence 未授权创建管理员", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-306"], "product": "atlassian_confluence", "desc": "Atlassian Confluence Data Center未授权创建管理员账户漏洞"},
    {"cve_id": "CVE-2021-26084", "name": "Confluence OGNL注入RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-94"], "product": "atlassian_confluence", "desc": "Atlassian Confluence Server OGNL注入漏洞，可导致远程代码执行"},
    {"cve_id": "CVE-2019-11581", "name": "Jira 服务端模板注入RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-94"], "product": "atlassian_jira", "desc": "Atlassian Jira服务端模板注入漏洞，可导致远程代码执行"},
    {"cve_id": "CVE-2020-14179", "name": "Jira 信息泄露", "severity": "medium", "cvss_v31": 5.3, "cwe": ["CWE-200"], "product": "atlassian_jira", "desc": "Atlassian Jira信息泄露漏洞，可获取用户和项目信息"},
    {"cve_id": "CVE-2023-26360", "name": "Adobe ColdFusion 反序列化RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-502"], "product": "adobe_coldfusion", "desc": "Adobe ColdFusion不安全反序列化漏洞，可导致远程代码执行"},
    {"cve_id": "CVE-2023-29298", "name": "Adobe ColdFusion 访问控制绕过", "severity": "high", "cvss_v31": 7.5, "cwe": ["CWE-284"], "product": "adobe_coldfusion", "desc": "Adobe ColdFusion访问控制绕过漏洞"},
    {"cve_id": "CVE-2022-22965", "name": "Spring Framework RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-94"], "product": "spring_framework", "desc": "Spring Framework远程代码执行漏洞（Spring4Shell）"},
    {"cve_id": "CVE-2022-22963", "name": "Spring Cloud Function SpEL注入", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-94"], "product": "spring_cloud", "desc": "Spring Cloud Function SpEL表达式注入漏洞，可导致远程代码执行"},
    {"cve_id": "CVE-2022-22950", "name": "Spring Expression DoS", "severity": "medium", "cvss_v31": 5.3, "cwe": ["CWE-400"], "product": "spring_framework", "desc": "Spring Expression拒绝服务漏洞"},
    {"cve_id": "CVE-2023-20860", "name": "Spring Security 认证绕过", "severity": "high", "cvss_v31": 7.5, "cwe": ["CWE-287"], "product": "spring_security", "desc": "Spring Security认证绕过漏洞"},
    {"cve_id": "CVE-2020-13942", "name": "Apache Unomi OGNL注入RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-94"], "product": "apache_unomi", "desc": "Apache Unomi远程代码执行漏洞，可通过OGNL表达式注入执行任意代码"},
    {"cve_id": "CVE-2020-13927", "name": "Airflow 默认密钥RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-306"], "product": "apache_airflow", "desc": "Apache Airflow默认密钥导致未授权访问和远程代码执行"},
    {"cve_id": "CVE-2020-11978", "name": "Airflow 示例DAG RCE", "severity": "high", "cvss_v31": 8.8, "cwe": ["CWE-78"], "product": "apache_airflow", "desc": "Apache Airflow示例DAG命令注入漏洞，可导致远程代码执行"},
    {"cve_id": "CVE-2022-25598", "name": "Apache DolphinScheduler RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-78"], "product": "apache_dolphinscheduler", "desc": "Apache DolphinScheduler远程代码执行漏洞"},
    {"cve_id": "CVE-2023-25676", "name": "Apache Superset 认证绕过", "severity": "high", "cvss_v31": 7.5, "cwe": ["CWE-306"], "product": "apache_superset", "desc": "Apache Superset默认密钥认证绕过漏洞"},
    {"cve_id": "CVE-2023-27524", "name": "Apache Superset 会话伪造", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-330"], "product": "apache_superset", "desc": "Apache Superset会话伪造漏洞，可登录管理员账户"},
    {"cve_id": "CVE-2021-41282", "name": "Grafana 权限提升", "severity": "high", "cvss_v31": 8.8, "cwe": ["CWE-269"], "product": "grafana", "desc": "Grafana权限提升漏洞，可提升到管理员权限"},
    {"cve_id": "CVE-2021-43798", "name": "Grafana 目录穿越", "severity": "high", "cvss_v31": 7.5, "cwe": ["CWE-22"], "product": "grafana", "desc": "Grafana目录穿越漏洞，可读取服务器任意文件"},
    {"cve_id": "CVE-2022-39324", "name": "Grafana 存储型XSS", "severity": "medium", "cvss_v31": 5.4, "cwe": ["CWE-79"], "product": "grafana", "desc": "Grafana存储型跨站脚本漏洞"},
    {"cve_id": "CVE-2021-32637", "name": "Nexus Repository 认证绕过", "severity": "high", "cvss_v31": 7.5, "cwe": ["CWE-287"], "product": "sonatype_nexus", "desc": "Sonatype Nexus Repository Manager认证绕过漏洞"},
    {"cve_id": "CVE-2019-7238", "name": "Nexus Repository RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-94"], "product": "sonatype_nexus", "desc": "Sonatype Nexus Repository Manager远程代码执行漏洞"},
    {"cve_id": "CVE-2020-10199", "name": "Nexus Repository 反序列化RCE", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-502"], "product": "sonatype_nexus", "desc": "Sonatype Nexus Repository Manager反序列化远程代码执行漏洞"},
    {"cve_id": "CVE-2023-23301", "name": "Nexus Repository 信息泄露", "severity": "medium", "cvss_v31": 5.3, "cwe": ["CWE-200"], "product": "sonatype_nexus", "desc": "Sonatype Nexus Repository信息泄露漏洞"},
    {"cve_id": "CVE-2022-35916", "name": "OpenMetadata 认证绕过", "severity": "critical", "cvss_v31": 9.8, "cwe": ["CWE-306"], "product": "openmetadata", "desc": "OpenMetadata未授权访问漏洞，可获取JWT令牌"},
    {"cve_id": "CVE-2023-25813", "name": "Sequelize SQL注入", "severity": "high", "cvss_v31": 8.1, "cwe": ["CWE-89"], "product": "sequelize", "desc": "Sequelize ORM SQL注入漏洞"},
    {"cve_id": "CVE-2022-21664", "name": "WordPress SQL注入", "severity": "high", "cvss_v31": 8.8, "cwe": ["CWE-89"], "product": "wordpress", "desc": "WordPress SQL注入漏洞（WP_Query）"},
    {"cve_id": "CVE-2023-32243", "name": "WordPress Elementor 权限提升", "severity": "high", "cvss_v31": 8.8, "cwe": ["CWE-269"], "product": "wordpress_elementor", "desc": "WordPress Elementor插件权限提升漏洞"},
    {"cve_id": "CVE-2023-34022", "name": "WordPress Litespeed 信息泄露", "severity": "medium", "cvss_v31": 5.3, "cwe": ["CWE-200"], "product": "wordpress_litespeed", "desc": "WordPress Litespeed缓存插件信息泄露漏洞"},
    {"cve_id": "CVE-2022-45362", "name": "WordPress Paytm 支付绕过", "severity": "high", "cvss_v31": 8.8, "cwe": ["CWE-287"], "product": "wordpress_paytm", "desc": "WordPress Paytm支付插件支付绕过漏洞"},
]
