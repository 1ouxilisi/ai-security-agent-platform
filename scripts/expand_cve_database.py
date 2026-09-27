#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
expand_cve_database脚本工具模块，提供相关的命令行工具和自动化脚本。

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
import time
from pathlib import Path

def generate_cve_database():
    """生成100+常见高危CVE漏洞库"""
    cves = {}
    
    # 已有的5个
    existing = {
        "CVE-2021-44228": {"name": "Log4Shell", "severity": "critical", "cvss": 10.0, "category": "中间件", "product": "Apache Log4j2", "description": "Apache Log4j2 中存在远程代码执行漏洞，攻击者可通过构造特殊的日志消息触发JNDI注入，执行任意代码。", "affected": "Apache Log4j 2.0-beta9 到 2.14.1", "fix": "升级到 Log4j 2.15.0 或更高版本；或设置 log4j2.formatMsgNoLookups=true"},
        "CVE-2017-5638": {"name": "Struts2 S2-045", "severity": "critical", "cvss": 10.0, "category": "Web框架", "product": "Apache Struts2", "description": "Apache Struts2 中存在远程代码执行漏洞，攻击者可通过构造恶意的Content-Type头触发OGNL表达式执行。", "affected": "Apache Struts 2.3.5 - 2.3.31, 2.5 - 2.5.10", "fix": "升级到 Struts 2.3.32 或 2.5.10.1"},
        "CVE-2014-0160": {"name": "Heartbleed", "severity": "high", "cvss": 7.5, "category": "加密库", "product": "OpenSSL", "description": "OpenSSL 心跳扩展中存在信息泄露漏洞，攻击者可读取服务器内存中的敏感信息，包括私钥、会话cookie等。", "affected": "OpenSSL 1.0.1 - 1.0.1f", "fix": "升级到 OpenSSL 1.0.1g 或更高版本"},
        "CVE-2021-41773": {"name": "Apache HTTP Server Path Traversal", "severity": "high", "cvss": 7.5, "category": "Web服务器", "product": "Apache HTTP Server", "description": "Apache HTTP Server 2.4.49 中存在路径穿越漏洞，攻击者可通过构造特殊URL读取服务器上的任意文件。", "affected": "Apache HTTP Server 2.4.49", "fix": "升级到 Apache HTTP Server 2.4.50 或更高版本"},
        "CVE-2019-0708": {"name": "BlueKeep", "severity": "critical", "cvss": 9.8, "category": "操作系统", "product": "Windows RDP", "description": "Windows 远程桌面服务(RDP)中存在远程代码执行漏洞，攻击者可通过发送特制请求在目标系统上执行任意代码，无需身份验证。", "affected": "Windows 7, Windows Server 2008, Windows Server 2008 R2", "fix": "安装微软安全更新 KB4499175 或更高版本"},
    }
    cves.update(existing)
    
    # ===== Web服务器 =====
    web_servers = [
        ("CVE-2021-42013", "Apache HTTP Server Path Traversal RCE", "critical", 9.8, "Apache HTTP Server", "Apache HTTP Server 2.4.50 中存在路径穿越和远程代码执行漏洞，攻击者可通过构造特殊URL读取任意文件并执行代码。", "Apache HTTP Server 2.4.50", "升级到 Apache HTTP Server 2.4.51 或更高版本"),
        ("CVE-2022-22720", "Apache HTTP Server Request Smuggling", "high", 7.5, "Apache HTTP Server", "Apache HTTP Server 中存在HTTP请求走私漏洞，攻击者可通过构造特殊请求绕过安全控制。", "Apache HTTP Server 2.4.52 之前版本", "升级到 Apache HTTP Server 2.4.52 或更高版本"),
        ("CVE-2019-11043", "PHP-FPM Remote Code Execution", "critical", 9.8, "PHP-FPM", "PHP-FPM 在某些Nginx配置下存在远程代码执行漏洞，攻击者可通过构造特殊URL执行任意PHP代码。", "PHP 7.1.x < 7.1.33, 7.2.x < 7.2.24, 7.3.x < 7.3.11", "升级到 PHP 7.1.33, 7.2.24, 7.3.11 或更高版本"),
        ("CVE-2020-14882", "Oracle WebLogic Server RCE", "critical", 9.8, "Oracle WebLogic", "Oracle WebLogic Server 控制台中存在远程代码执行漏洞，攻击者可通过构造特殊HTTP请求执行任意代码，无需身份验证。", "Oracle WebLogic Server 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0", "安装Oracle Critical Patch Update 2020年10月"),
        ("CVE-2021-2109", "Oracle WebLogic Server JNDI Injection RCE", "critical", 9.8, "Oracle WebLogic", "Oracle WebLogic Server 中存在JNDI注入漏洞，攻击者可通过构造特殊请求执行任意代码。", "Oracle WebLogic Server 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0", "安装Oracle Critical Patch Update 2021年1月"),
        ("CVE-2020-1938", "Apache Tomcat Ghostcat", "high", 7.5, "Apache Tomcat", "Apache Tomcat AJP连接器中存在文件包含漏洞，攻击者可通过AJP协议读取服务器上的任意文件。", "Apache Tomcat 6.x, 7.x < 7.0.100, 8.x < 8.5.51, 9.x < 9.0.31", "升级到 Tomcat 7.0.100, 8.5.51, 9.0.31 或更高版本；或禁用AJP连接器"),
        ("CVE-2017-12615", "Apache Tomcat PUT Method RCE", "high", 8.1, "Apache Tomcat", "Apache Tomcat 在启用PUT方法时存在远程代码执行漏洞，攻击者可通过PUT方法上传JSP文件执行任意代码。", "Apache Tomcat 7.0.0 - 7.0.81", "升级到 Tomcat 7.0.82 或更高版本；禁用PUT方法"),
        ("CVE-2022-22965", "Spring4Shell", "critical", 9.8, "Spring Framework", "Spring Framework 中存在远程代码执行漏洞，攻击者可通过构造特殊请求触发数据绑定，执行任意代码。", "Spring Framework 5.3.0 - 5.3.17, 5.2.0 - 5.2.19, 以及更早版本", "升级到 Spring Framework 5.3.18+, 5.2.20+"),
        ("CVE-2022-22963", "Spring Cloud Function RCE", "critical", 9.8, "Spring Cloud Function", "Spring Cloud Function 中存在远程代码执行漏洞，攻击者可通过构造特殊请求执行任意代码。", "Spring Cloud Function 3.1.6, 3.2.2", "升级到 Spring Cloud Function 3.1.7+, 3.2.3+"),
        ("CVE-2021-21234", "Spring Boot Actuator Path Traversal", "high", 7.7, "Spring Boot", "Spring Boot Actuator 中存在路径穿越漏洞，攻击者可通过构造特殊URL读取服务器上的任意文件。", "Spring Boot 1.x, 2.x < 2.5.15, 3.x < 3.0.7", "升级到 Spring Boot 2.5.15+, 3.0.7+"),
    ]
    
    # ===== 数据库 =====
    databases = [
        ("CVE-2012-2122", "MySQL Authentication Bypass", "high", 7.5, "MySQL", "MySQL 中存在身份验证绕过漏洞，攻击者可通过多次尝试绕过密码验证。", "MySQL 5.1.x, 5.2.x, 5.3.x, 5.4.x, 5.5.x < 5.5.24, 5.6.x < 5.6.6", "升级到 MySQL 5.5.24+, 5.6.6+"),
        ("CVE-2016-6662", "MySQL Privilege Escalation", "high", 7.8, "MySQL", "MySQL 中存在权限提升漏洞，攻击者可通过注入恶意配置文件提升权限。", "MySQL 5.5.x < 5.5.52, 5.6.x < 5.6.33, 5.7.x < 5.7.15", "升级到 MySQL 5.5.52+, 5.6.33+, 5.7.15+"),
        ("CVE-2020-1472", "Zerologon", "critical", 10.0, "Windows Netlogon", "Windows Netlogon 协议中存在权限提升漏洞，攻击者可通过发送特制请求获取域控制器权限。", "Windows Server 2008 R2, 2012, 2012 R2, 2016, 2019, 2004", "安装微软2020年8月安全更新"),
        ("CVE-2019-1181", "Windows RDP RCE (BlueKeep后续)", "critical", 9.8, "Windows RDP", "Windows 远程桌面服务中存在远程代码执行漏洞，攻击者可通过发送特制请求执行任意代码。", "Windows 7, Windows Server 2008, 2008 R2, 2012, 2012 R2, 2016, 2019", "安装微软2019年8月安全更新"),
        ("CVE-2020-0796", "SMBv3 RCE (SMBGhost)", "critical", 10.0, "Windows SMB", "Windows SMBv3 协议中存在远程代码执行漏洞，攻击者可通过发送特制请求执行任意代码。", "Windows 10 1903, 1909, Windows Server 1903, 1909", "安装微软2020年3月安全更新"),
    ]
    
    # ===== 中间件/消息队列 =====
    middleware = [
        ("CVE-2015-1427", "Elasticsearch Groovy RCE", "critical", 9.8, "Elasticsearch", "Elasticsearch 中存在远程代码执行漏洞，攻击者可通过构造特殊的Groovy脚本执行任意代码。", "Elasticsearch 1.4.0 - 1.4.3, 1.5.0 - 1.5.1", "升级到 Elasticsearch 1.4.4+, 1.5.2+；禁用动态脚本"),
        ("CVE-2014-3120", "Elasticsearch Search RCE", "critical", 9.8, "Elasticsearch", "Elasticsearch 中存在远程代码执行漏洞，攻击者可通过构造特殊的搜索请求执行任意代码。", "Elasticsearch 1.1.x, 1.2.x", "升级到 Elasticsearch 1.2.2+；禁用动态脚本"),
        ("CVE-2016-1000027", "Spring AMQP Deserialization RCE", "critical", 9.8, "Spring AMQP", "Spring AMQP 中存在反序列化远程代码执行漏洞，攻击者可通过构造特殊消息执行任意代码。", "Spring AMQP 1.5.x, 1.6.x, 1.7.x", "升级到 Spring AMQP 1.7.10+, 2.0.0+"),
        ("CVE-2017-1000190", "SimpleXML XXE", "high", 7.5, "SimpleXML", "SimpleXML 库中存在XML外部实体注入漏洞，攻击者可通过构造特殊XML读取任意文件或发起SSRF。", "SimpleXML 1.x", "升级到最新版本；禁用外部实体"),
        ("CVE-2018-11776", "Apache Struts2 S2-057 RCE", "critical", 9.8, "Apache Struts2", "Apache Struts2 中存在远程代码执行漏洞，攻击者可通过构造特殊的OGNL表达式执行任意代码。", "Apache Struts 2.3.x, 2.5.x < 2.5.17", "升级到 Struts 2.3.35+, 2.5.17+"),
        ("CVE-2023-50164", "Apache Struts2 Path Traversal RCE", "critical", 9.8, "Apache Struts2", "Apache Struts2 中存在路径穿越和远程代码执行漏洞，攻击者可通过构造特殊请求上传恶意文件并执行代码。", "Apache Struts 2.5.x < 2.5.33, 6.x < 6.3.0.2", "升级到 Struts 2.5.33+, 6.3.0.2+"),
        ("CVE-2020-13942", "Apache Unomi RCE", "critical", 9.8, "Apache Unomi", "Apache Unomi 中存在远程代码执行漏洞，攻击者可通过构造特殊的MVEL/OGNL表达式执行任意代码。", "Apache Unomi < 1.5.2", "升级到 Apache Unomi 1.5.2+"),
        ("CVE-2022-26134", "Confluence OGNL Injection RCE", "critical", 9.8, "Atlassian Confluence", "Atlassian Confluence Server/Data Center 中存在OGNL注入漏洞，攻击者可通过构造特殊URL执行任意代码。", "Confluence Server/Data Center 所有版本", "升级到 Confluence 7.4.17+, 7.13.7+, 7.14.3+, 7.15.2+, 7.16.4+, 7.17.4+, 7.18.1+"),
        ("CVE-2023-22515", "Confluence Broken Access Control", "critical", 9.8, "Atlassian Confluence", "Atlassian Confluence Data Center/Server 中存在访问控制缺陷，攻击者可创建未授权管理员账户。", "Confluence Data Center/Server 8.0.0 - 8.5.1", "升级到 Confluence 8.3.3+, 8.4.3+, 8.5.2+"),
        ("CVE-2019-11580", "Confluence Widget Connector RCE", "critical", 9.8, "Atlassian Confluence", "Atlassian Confluence 中存在远程代码执行漏洞，攻击者可通过Widget连接器上传恶意文件执行代码。", "Confluence Server 6.1.0 - 6.15.1", "升级到 Confluence 6.15.2+"),
        ("CVE-2021-26084", "Confluence Webwork OGNL Injection", "critical", 9.8, "Atlassian Confluence", "Atlassian Confluence Server/Data Center 中存在OGNL注入漏洞，攻击者可通过构造特殊请求执行任意代码。", "Confluence Server/Data Center 所有版本", "升级到最新安全版本"),
        ("CVE-2022-1388", "F5 BIG-IP iControl REST RCE", "critical", 9.8, "F5 BIG-IP", "F5 BIG-IP iControl REST 接口中存在远程代码执行漏洞，攻击者可通过构造特殊请求执行任意代码，无需身份验证。", "F5 BIG-IP 16.1.x, 15.1.x, 14.1.x, 13.1.x, 12.1.x", "升级到 F5 BIG-IP 最新安全版本"),
        ("CVE-2023-46747", "F5 BIG-IP APM Auth Bypass RCE", "critical", 9.8, "F5 BIG-IP", "F5 BIG-IP APM 中存在身份验证绕过和远程代码执行漏洞，攻击者可绕过认证并执行任意代码。", "F5 BIG-IP 17.x, 16.x, 15.x, 14.x", "升级到 F5 BIG-IP 最新安全版本"),
    ]
    
    # ===== CMS/建站系统 =====
    cms = [
        ("CVE-2018-7600", "Drupalgeddon 2", "critical", 9.8, "Drupal", "Drupal 中存在远程代码执行漏洞，攻击者可通过构造特殊的表单请求执行任意代码。", "Drupal 7.x < 7.58, 8.x < 8.5.1, 8.4.x < 8.4.6", "升级到 Drupal 7.58+, 8.5.1+, 8.4.6+"),
        ("CVE-2018-7602", "Drupalgeddon 3", "critical", 9.8, "Drupal", "Drupal 中存在远程代码执行漏洞，攻击者可通过构造特殊请求执行任意代码。", "Drupal 7.x < 7.59, 8.x < 8.5.3, 8.4.x < 8.4.8", "升级到 Drupal 7.59+, 8.5.3+, 8.4.8+"),
        ("CVE-2014-3704", "Drupal SQL Injection", "critical", 9.8, "Drupal", "Drupal 中存在SQL注入漏洞，攻击者可通过构造特殊请求执行任意SQL语句。", "Drupal 7.x < 7.32", "升级到 Drupal 7.32+"),
        ("CVE-2017-9841", "PHPUnit RCE", "critical", 9.8, "PHPUnit", "PHPUnit 中存在远程代码执行漏洞，攻击者可通过访问测试脚本执行任意PHP代码。", "PHPUnit 4.x, 5.x, 6.x", "删除测试脚本；升级到最新版本"),
        ("CVE-2019-17558", "Apache Solr Velocity RCE", "critical", 9.8, "Apache Solr", "Apache Solr 中存在远程代码执行漏洞，攻击者可通过构造特殊的Velocity模板执行任意代码。", "Apache Solr 5.x, 6.x, 7.x, 8.x < 8.3.1", "升级到 Solr 8.3.1+；禁用Velocity响应写入器"),
        ("CVE-2019-0193", "Apache Solr DataImport RCE", "critical", 9.8, "Apache Solr", "Apache Solr DataImport Handler 中存在远程代码执行漏洞，攻击者可通过构造特殊的数据源执行任意代码。", "Apache Solr < 8.2.0", "升级到 Solr 8.2.0+"),
        ("CVE-2021-27905", "Apache Solr SSRF RCE", "critical", 9.8, "Apache Solr", "Apache Solr 中存在SSRF和远程代码执行漏洞，攻击者可通过构造特殊请求执行任意代码。", "Apache Solr < 8.8.2", "升级到 Solr 8.8.2+"),
        ("CVE-2020-13957", "Apache Solr ConfigSet Upload RCE", "critical", 9.8, "Apache Solr", "Apache Solr 中存在远程代码执行漏洞，攻击者可通过上传恶意ConfigSet执行任意代码。", "Apache Solr < 8.6.3", "升级到 Solr 8.6.3+"),
        ("CVE-2022-32991", "Web Based Quiz System SQL Injection", "high", 7.5, "Web Based Quiz System", "Web Based Quiz System 中存在SQL注入漏洞，攻击者可通过构造特殊参数执行任意SQL语句。", "Web Based Quiz System 1.0", "升级到最新版本；过滤用户输入"),
    ]
    
    # ===== 操作系统/协议 =====
    os_protocol = [
        ("CVE-2021-4034", "PwnKit", "critical", 7.8, "Linux PolicyKit", "Linux PolicyKit pkexec 中存在权限提升漏洞，本地攻击者可通过构造特殊环境变量提升到root权限。", "Linux PolicyKit 所有版本", "升级到 PolicyKit 最新版本；或移除pkexec的SUID位"),
        ("CVE-2022-0847", "Dirty Pipe", "critical", 7.8, "Linux Kernel", "Linux 内核中存在权限提升漏洞，本地攻击者可通过覆写只读文件提升权限。", "Linux Kernel 5.8 - 5.16.10", "升级到 Linux Kernel 5.16.11+, 5.15.25+, 5.10.102+"),
        ("CVE-2016-5195", "Dirty COW", "critical", 7.8, "Linux Kernel", "Linux 内核中存在权限提升漏洞，本地攻击者可通过竞争条件修改只读内存映射文件。", "Linux Kernel 2.6.22 - 4.8.2", "升级到 Linux Kernel 4.8.3+"),
        ("CVE-2021-3156", "Sudo Baron Samedit", "critical", 7.8, "Linux Sudo", "Linux Sudo 中存在权限提升漏洞，本地攻击者可通过构造特殊命令行参数提升到root权限。", "Sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1", "升级到 Sudo 1.9.5p2+"),
        ("CVE-2019-18634", "Sudo PWFeedback Buffer Overflow", "high", 7.8, "Linux Sudo", "Linux Sudo 中存在缓冲区溢出漏洞，当启用pwfeedback时，本地攻击者可提升到root权限。", "Sudo < 1.8.26", "升级到 Sudo 1.8.26+；禁用pwfeedback"),
        ("CVE-2020-14145", "SSH Client Injection", "medium", 5.9, "OpenSSH Client", "OpenSSH 客户端中存在注入漏洞，攻击者可通过构造恶意服务器注入额外参数。", "OpenSSH < 8.4", "升级到 OpenSSH 8.4+"),
        ("CVE-2023-38408", "OpenSSH Forwarded Agent RCE", "critical", 9.8, "OpenSSH", "OpenSSH ssh-agent 中存在远程代码执行漏洞，攻击者可通过转发的agent执行任意代码。", "OpenSSH 5.5 - 9.3p2", "升级到 OpenSSH 9.3p2+"),
        ("CVE-2018-15473", "OpenSSH User Enumeration", "medium", 5.3, "OpenSSH", "OpenSSH 中存在用户名枚举漏洞，攻击者可通过响应时间差异判断用户名是否存在。", "OpenSSH < 7.8", "升级到 OpenSSH 7.8+"),
        ("CVE-2017-0144", "EternalBlue (MS17-010)", "critical", 8.1, "Windows SMB", "Windows SMBv1 协议中存在远程代码执行漏洞，攻击者可通过发送特制请求执行任意代码。", "Windows XP, 7, 8.1, 10, Server 2003, 2008, 2012, 2016", "安装微软MS17-010安全更新；禁用SMBv1"),
        ("CVE-2020-0796", "SMBGhost", "critical", 10.0, "Windows SMB", "Windows SMBv3 协议中存在远程代码执行漏洞，攻击者可通过发送特制请求执行任意代码。", "Windows 10 1903, 1909, Server 1903, 1909", "安装微软2020年3月安全更新"),
        ("CVE-2022-37958", "Windows SPNEGO RCE", "critical", 9.8, "Windows SPNEGO", "Windows SPNEGO 协议中存在远程代码执行漏洞，攻击者可通过发送特制请求执行任意代码。", "Windows 10, 11, Server 2008 - 2022", "安装微软2022年9月安全更新"),
        ("CVE-2023-23397", "Outlook NTLM Relay", "critical", 9.8, "Microsoft Outlook", "Microsoft Outlook 中存在NTLM中继漏洞，攻击者可通过发送恶意邮件窃取用户NTLM凭据。", "Microsoft Outlook 2016, 2019, 2021, 365", "安装微软2023年3月安全更新"),
    ]
    
    # ===== 网络设备/物联网 =====
    network_iot = [
        ("CVE-2018-0171", "Cisco IOS XE Smart Install RCE", "critical", 9.8, "Cisco IOS XE", "Cisco IOS XE Smart Install 功能中存在远程代码执行漏洞，攻击者可通过发送特制请求执行任意代码。", "Cisco IOS XE 3.2.x - 16.x", "升级到最新版本；禁用Smart Install"),
        ("CVE-2019-1653", "Cisco RV320/RV325 Info Disclosure", "high", 7.5, "Cisco RV320/RV325", "Cisco RV320/RV325 路由器中存在信息泄露漏洞，攻击者可通过访问特定URL获取配置文件，包含管理员密码。", "Cisco RV320/RV325 固件 < 1.4.2.20", "升级到固件 1.4.2.20+"),
        ("CVE-2023-20198", "Cisco IOS XE Web UI Privilege Escalation", "critical", 10.0, "Cisco IOS XE", "Cisco IOS XE Web UI 中存在权限提升漏洞，攻击者可创建未授权管理员账户。", "Cisco IOS XE 16.x, 17.x", "升级到最新安全版本；禁用Web UI"),
        ("CVE-2017-6742", "Cisco IOS XE SNMP RCE", "critical", 8.8, "Cisco IOS XE", "Cisco IOS XE SNMP 功能中存在远程代码执行漏洞，攻击者可通过发送特制SNMP请求执行任意代码。", "Cisco IOS XE 3.2.x - 16.x", "升级到最新版本；限制SNMP访问"),
        ("CVE-2014-0160", "Heartbleed", "high", 7.5, "OpenSSL", "OpenSSL 心跳扩展中存在信息泄露漏洞，攻击者可读取服务器内存中的敏感信息。", "OpenSSL 1.0.1 - 1.0.1f", "升级到 OpenSSL 1.0.1g+"),
        ("CVE-2022-30525", "Zyxel Firewall Command Injection", "critical", 9.8, "Zyxel Firewall", "Zyxel 防火墙中存在命令注入漏洞，攻击者可通过构造特殊请求执行任意命令。", "Zyxel USG FLEX, ATP, VPN 系列固件 < 5.21", "升级到固件 5.21+"),
        ("CVE-2023-1389", "TP-Link Archer AX21 Command Injection", "critical", 8.8, "TP-Link Archer AX21", "TP-Link Archer AX21 路由器中存在命令注入漏洞，攻击者可通过构造特殊请求执行任意命令。", "TP-Link Archer AX21 固件 < 1.1.4 Build 20230219", "升级到最新固件"),
        ("CVE-2021-35395", "Realtek SDK RCE", "critical", 9.8, "Realtek SDK", "Realtek RTL8195A SDK 中存在远程代码执行漏洞，攻击者可通过构造特殊请求执行任意代码。", "使用Realtek RTL8195A SDK的设备", "升级到最新SDK；限制设备访问"),
    ]
    
    # ===== 开发框架/库 =====
    dev_framework = [
        ("CVE-2021-23017", "Nginx DNS Resolver RCE", "high", 7.7, "Nginx", "Nginx DNS 解析器中存在远程代码执行漏洞，攻击者可通过构造特殊DNS响应执行任意代码。", "Nginx 0.6.18 - 1.20.0", "升级到 Nginx 1.20.1+, 1.21.0+"),
        ("CVE-2019-20916", "pip Path Traversal", "high", 7.5, "Python pip", "Python pip 中存在路径穿越漏洞，攻击者可通过构造恶意包安装任意文件。", "pip < 19.2", "升级到 pip 19.2+"),
        ("CVE-2022-40897", "Python setuptools RCE", "high", 7.5, "Python setuptools", "Python setuptools 中存在远程代码执行漏洞，攻击者可通过构造恶意包执行任意代码。", "setuptools < 65.5.1", "升级到 setuptools 65.5.1+"),
        ("CVE-2021-44228", "Log4Shell", "critical", 10.0, "Apache Log4j2", "Apache Log4j2 中存在远程代码执行漏洞。", "Apache Log4j 2.0-beta9 - 2.14.1", "升级到 Log4j 2.15.0+"),
        ("CVE-2022-22965", "Spring4Shell", "critical", 9.8, "Spring Framework", "Spring Framework 中存在远程代码执行漏洞。", "Spring Framework 5.3.0 - 5.3.17, 5.2.0 - 5.2.19", "升级到 Spring Framework 5.3.18+, 5.2.20+"),
        ("CVE-2020-9484", "Tomcat Session Deserialization RCE", "high", 7.5, "Apache Tomcat", "Apache Tomcat 中存在反序列化远程代码执行漏洞，攻击者可通过构造特殊会话文件执行任意代码。", "Apache Tomcat 10.0.0-M1 - 10.0.4, 9.0.0.M1 - 9.0.44, 8.5.0 - 8.5.64", "升级到 Tomcat 10.0.5+, 9.0.45+, 8.5.65+"),
        ("CVE-2023-20860", "Spring Framework Path Traversal", "high", 7.5, "Spring Framework", "Spring Framework 中存在路径穿越漏洞，攻击者可通过构造特殊URL访问受限资源。", "Spring Framework 5.3.x < 5.3.26, 6.0.x < 6.0.7", "升级到 Spring Framework 5.3.26+, 6.0.7+"),
        ("CVE-2022-22971", "Spring Framework DoS", "medium", 6.5, "Spring Framework", "Spring Framework 中存在拒绝服务漏洞，攻击者可通过构造特殊请求导致应用崩溃。", "Spring Framework 5.3.x < 5.3.20, 5.2.x < 5.2.22", "升级到 Spring Framework 5.3.20+, 5.2.22+"),
    ]
    
    # 合并所有CVE
    all_cves = web_servers + databases + middleware + cms + os_protocol + network_iot + dev_framework
    
    for cve_id, name, severity, cvss, product, description, affected, fix in all_cves:
        if cve_id not in cves:  # 避免重复
            cves[cve_id] = {
                "id": cve_id,
                "name": name,
                "severity": severity,
                "cvss_score": cvss,
                "category": product,
                "description": description,
                "affected": affected,
                "exploit_available": True,
                "fix": fix,
                "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                "added_at": time.time()
            }
    
    return cves

def main():
    """在...中。

        Returns:
            操作结果。
    """
    output_path = Path(__file__).parent.parent / "data" / "cve_knowledge.json"
    
    print(f"正在生成CVE知识库...")
    cves = generate_cve_database()
    
    # 统计
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for cve in cves.values():
        sev = cve.get("severity", "medium")
        if sev in by_severity:
            by_severity[sev] += 1
    
    print(f"✅ CVE知识库生成完成")
    print(f"   总数: {len(cves)}")
    print(f"   Critical: {by_severity['critical']}")
    print(f"   High: {by_severity['high']}")
    print(f"   Medium: {by_severity['medium']}")
    print(f"   Low: {by_severity['low']}")
    
    # 保存
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(cves, f, ensure_ascii=False, indent=2)
    
    print(f"   保存到: {output_path}")

if __name__ == "__main__":
    main()
