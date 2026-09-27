#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
expand_cve_phase2脚本工具模块，提供相关的命令行工具和自动化脚本。

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

def generate_more_cves():
    """生成更多常见CVE漏洞"""
    cves = {}
    
    # ===== 更多Web服务器/中间件 =====
    more_web = [
        ("CVE-2021-36260", "Hikvision Web Server RCE", "critical", 9.8, "Hikvision", "海康威视Web服务器中存在远程代码执行漏洞，攻击者可通过构造特殊请求执行任意代码。", "Hikvision 产品固件 < 5.5.82", "升级到最新固件"),
        ("CVE-2022-22947", "Spring Cloud Gateway RCE", "critical", 10.0, "Spring Cloud Gateway", "Spring Cloud Gateway 中存在远程代码执行漏洞，攻击者可通过构造特殊请求执行任意代码。", "Spring Cloud Gateway 3.1.x < 3.1.1, 3.0.x < 3.0.7", "升级到 Spring Cloud Gateway 3.1.1+, 3.0.7+"),
        ("CVE-2022-22950", "Spring Expression DoS", "medium", 6.5, "Spring Expression", "Spring Expression 中存在拒绝服务漏洞，攻击者可通过构造特殊表达式导致应用崩溃。", "Spring Framework 5.3.x < 5.3.18, 5.2.x < 5.2.20", "升级到最新版本"),
        ("CVE-2021-21234", "Spring Boot Actuator Path Traversal", "high", 7.7, "Spring Boot", "Spring Boot Actuator 中存在路径穿越漏洞，攻击者可读取服务器任意文件。", "Spring Boot < 2.5.15", "升级到 Spring Boot 2.5.15+"),
        ("CVE-2020-5410", "Spring Cloud Config Path Traversal", "high", 7.5, "Spring Cloud Config", "Spring Cloud Config Server 中存在路径穿越漏洞，攻击者可读取服务器任意文件。", "Spring Cloud Config 2.2.x < 2.2.3, 2.1.x < 2.1.9", "升级到最新版本"),
        ("CVE-2019-3799", "Spring Cloud Config Path Traversal", "high", 7.5, "Spring Cloud Config", "Spring Cloud Config Server 中存在路径穿越漏洞。", "Spring Cloud Config 2.1.x < 2.1.2, 2.0.x < 2.0.4, 1.4.x < 1.4.6", "升级到最新版本"),
        ("CVE-2018-1271", "Spring MVC Path Traversal", "high", 7.5, "Spring MVC", "Spring MVC 中存在路径穿越漏洞，攻击者可读取服务器任意文件。", "Spring Framework 5.0.x < 5.0.5, 4.3.x < 4.3.15", "升级到最新版本"),
        ("CVE-2016-1000027", "Spring AMQP Deserialization RCE", "critical", 9.8, "Spring AMQP", "Spring AMQP 中存在反序列化远程代码执行漏洞。", "Spring AMQP 1.5.x, 1.6.x, 1.7.x", "升级到 Spring AMQP 1.7.10+, 2.0.0+"),
    ]
    
    # ===== 更多数据库/缓存 =====
    more_db = [
        ("CVE-2022-21661", "WordPress SQL Injection", "critical", 9.8, "WordPress", "WordPress WP_Query 中存在SQL注入漏洞，攻击者可通过构造特殊请求执行任意SQL语句。", "WordPress < 5.8.3", "升级到 WordPress 5.8.3+"),
        ("CVE-2022-21662", "WordPress XSS", "high", 6.1, "WordPress", "WordPress 中存在跨站脚本漏洞，攻击者可通过构造特殊URL执行恶意脚本。", "WordPress < 5.8.3", "升级到 WordPress 5.8.3+"),
        ("CVE-2022-21663", "WordPress Object Injection", "high", 7.2, "WordPress", "WordPress 中存在对象注入漏洞，攻击者可通过构造特殊请求执行任意代码。", "WordPress < 5.8.3", "升级到 WordPress 5.8.3+"),
        ("CVE-2021-24847", "WordPress SQL Injection", "critical", 9.8, "WordPress", "WordPress 插件中存在SQL注入漏洞。", "WordPress 插件", "升级到最新版本"),
        ("CVE-2020-25213", "WordPress File Manager RCE", "critical", 9.8, "WordPress File Manager", "WordPress File Manager 插件中存在远程代码执行漏洞，攻击者可上传恶意文件并执行。", "WordPress File Manager < 6.9", "升级到 File Manager 6.9+"),
        ("CVE-2019-17671", "WordPress Unauthenticated Access", "high", 7.5, "WordPress", "WordPress 中存在未授权访问漏洞，攻击者可查看私有文章。", "WordPress < 5.2.4", "升级到 WordPress 5.2.4+"),
        ("CVE-2018-6389", "WordPress DoS", "high", 7.5, "WordPress", "WordPress load-scripts.php 中存在拒绝服务漏洞。", "WordPress < 4.9.3", "升级到 WordPress 4.9.3+"),
    ]
    
    # ===== 更多操作系统/协议 =====
    more_os = [
        ("CVE-2023-23397", "Outlook NTLM Relay", "critical", 9.8, "Microsoft Outlook", "Microsoft Outlook 中存在NTLM中继漏洞，攻击者可通过发送恶意邮件窃取用户NTLM凭据。", "Microsoft Outlook 2016, 2019, 2021, 365", "安装微软2023年3月安全更新"),
        ("CVE-2023-21716", "Word RCE", "critical", 9.8, "Microsoft Word", "Microsoft Word 中存在远程代码执行漏洞，攻击者可通过构造恶意文档执行任意代码。", "Microsoft Office 2016, 2019, 2021, 365", "安装微软2023年2月安全更新"),
        ("CVE-2021-40444", "MSHTML RCE", "critical", 9.8, "Microsoft MSHTML", "Microsoft MSHTML 引擎中存在远程代码执行漏洞，攻击者可通过构造恶意文档执行任意代码。", "Windows 10, 11, Server 2008 - 2022", "安装微软2021年9月安全更新"),
        ("CVE-2021-36934", "HiveNightmare", "high", 7.8, "Windows VSS", "Windows 卷影复制服务中存在权限提升漏洞，本地攻击者可读取SAM、SYSTEM、SECURITY注册表文件。", "Windows 10 1809 - 21H1, 11", "安装微软2021年7月安全更新"),
        ("CVE-2020-0668", "Windows Service Tracing EoP", "high", 7.8, "Windows Service Tracing", "Windows Service Tracing 中存在权限提升漏洞，本地攻击者可提升到SYSTEM权限。", "Windows 10, Server 2016, 2019", "安装微软2020年2月安全更新"),
        ("CVE-2019-0841", "Windows AppX EoP", "high", 7.8, "Windows AppX", "Windows AppX 部署服务中存在权限提升漏洞，本地攻击者可提升到SYSTEM权限。", "Windows 10, Server 2016, 2019", "安装微软2019年4月安全更新"),
        ("CVE-2018-8120", "Win32k EoP", "high", 7.8, "Windows Win32k", "Windows Win32k 中存在权限提升漏洞，本地攻击者可提升到SYSTEM权限。", "Windows 7, 10, Server 2008, 2012, 2016", "安装微软2018年5月安全更新"),
        ("CVE-2017-0213", "Windows COM EoP", "high", 7.8, "Windows COM", "Windows COM 中存在权限提升漏洞，本地攻击者可提升到SYSTEM权限。", "Windows 10, Server 2016", "安装微软2017年4月安全更新"),
    ]
    
    # ===== 更多网络设备/物联网 =====
    more_network = [
        ("CVE-2023-27532", "Veeam Backup RCE", "critical", 9.8, "Veeam Backup", "Veeam Backup & Replication 中存在远程代码执行漏洞，攻击者可通过构造特殊请求执行任意代码。", "Veeam Backup & Replication < 12", "升级到 Veeam Backup & Replication 12+"),
        ("CVE-2022-26134", "Confluence OGNL RCE", "critical", 9.8, "Atlassian Confluence", "Atlassian Confluence 中存在OGNL注入漏洞，攻击者可执行任意代码。", "Confluence Server/Data Center 所有版本", "升级到最新安全版本"),
        ("CVE-2022-26138", "Confluence Hardcoded Credentials", "critical", 9.8, "Atlassian Confluence", "Atlassian Confluence Questions for Confluence 插件中存在硬编码凭据，攻击者可使用默认账户登录。", "Questions for Confluence 2.7.34, 2.7.35, 3.0.2", "升级到最新版本；删除默认账户"),
        ("CVE-2021-26084", "Confluence OGNL Injection", "critical", 9.8, "Atlassian Confluence", "Atlassian Confluence 中存在OGNL注入漏洞。", "Confluence Server/Data Center 所有版本", "升级到最新安全版本"),
        ("CVE-2019-3396", "Confluence Path Traversal RCE", "critical", 9.8, "Atlassian Confluence", "Atlassian Confluence Widget Connector 中存在路径穿越和远程代码执行漏洞。", "Confluence Server 6.1.0 - 6.15.1", "升级到 Confluence 6.15.2+"),
        ("CVE-2018-1335", "Apache Tika RCE", "critical", 9.8, "Apache Tika", "Apache Tika 中存在远程代码执行漏洞，攻击者可通过上传恶意文件执行任意代码。", "Apache Tika 1.7 - 1.17", "升级到 Apache Tika 1.18+"),
        ("CVE-2018-1337", "Apache Tika XXE", "high", 7.5, "Apache Tika", "Apache Tika 中存在XML外部实体注入漏洞。", "Apache Tika < 1.18", "升级到 Apache Tika 1.18+"),
    ]
    
    # ===== 更多企业应用 =====
    more_enterprise = [
        ("CVE-2023-34362", "MOVEit Transfer SQL Injection RCE", "critical", 9.8, "MOVEit Transfer", "MOVEit Transfer 中存在SQL注入和远程代码执行漏洞，攻击者可通过构造特殊请求执行任意代码。", "MOVEit Transfer 2023.0.0, 2022.1.x, 2022.0.x, 2021.0.x, 2020.1.x", "升级到最新安全版本；安装紧急补丁"),
        ("CVE-2021-44228", "Log4Shell", "critical", 10.0, "Apache Log4j2", "Apache Log4j2 中存在远程代码执行漏洞。", "Apache Log4j 2.0-beta9 - 2.14.1", "升级到 Log4j 2.15.0+"),
        ("CVE-2022-22965", "Spring4Shell", "critical", 9.8, "Spring Framework", "Spring Framework 中存在远程代码执行漏洞。", "Spring Framework 5.3.0 - 5.3.17, 5.2.0 - 5.2.19", "升级到 Spring Framework 5.3.18+, 5.2.20+"),
        ("CVE-2020-14882", "WebLogic RCE", "critical", 9.8, "Oracle WebLogic", "Oracle WebLogic Server 控制台中存在远程代码执行漏洞。", "Oracle WebLogic Server 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0", "安装Oracle Critical Patch Update"),
        ("CVE-2020-14750", "WebLogic RCE", "critical", 9.8, "Oracle WebLogic", "Oracle WebLogic Server 中存在远程代码执行漏洞。", "Oracle WebLogic Server 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0", "安装Oracle Critical Patch Update"),
        ("CVE-2019-2725", "WebLogic RCE", "critical", 9.8, "Oracle WebLogic", "Oracle WebLogic Server 中存在远程代码执行漏洞，攻击者可通过构造特殊XML请求执行任意代码。", "Oracle WebLogic Server 10.3.6.0.0, 12.1.3.0.0", "安装Oracle Critical Patch Update 2019年4月"),
        ("CVE-2018-2894", "WebLogic RCE", "critical", 9.8, "Oracle WebLogic", "Oracle WebLogic Server 中存在远程代码执行漏洞，攻击者可通过上传恶意文件执行任意代码。", "Oracle WebLogic Server 12.1.3.0.0, 12.2.1.2.0, 12.2.1.3.0", "安装Oracle Critical Patch Update 2018年7月"),
        ("CVE-2017-10271", "WebLogic WLS-WSAT RCE", "critical", 9.8, "Oracle WebLogic", "Oracle WebLogic Server WLS-WSAT 组件中存在远程代码执行漏洞。", "Oracle WebLogic Server 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0, 12.2.1.2.0", "安装Oracle Critical Patch Update 2017年10月"),
    ]
    
    # 合并
    all_cves = more_web + more_db + more_os + more_network + more_enterprise
    
    for cve_id, name, severity, cvss, product, description, affected, fix in all_cves:
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
    
    # 读取现有CVE库
    with open(output_path, "r", encoding="utf-8") as f:
        existing = json.load(f)
    
    print(f"现有CVE数量: {len(existing)}")
    
    # 生成新CVE
    new_cves = generate_more_cves()
    
    # 合并（去重）
    merged = {**existing, **new_cves}
    
    # 统计
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for cve in merged.values():
        sev = cve.get("severity", "medium")
        if sev in by_severity:
            by_severity[sev] += 1
    
    print(f"✅ CVE库扩充完成")
    print(f"   总数: {len(merged)}")
    print(f"   新增: {len(merged) - len(existing)}")
    print(f"   Critical: {by_severity['critical']}")
    print(f"   High: {by_severity['high']}")
    print(f"   Medium: {by_severity['medium']}")
    print(f"   Low: {by_severity['low']}")
    
    # 保存
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
    
    print(f"   保存到: {output_path}")

if __name__ == "__main__":
    main()
