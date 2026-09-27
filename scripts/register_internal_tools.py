#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
register_internal_tools脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

"""注册内网渗透工具到TOOL_DEFINITIONS"""

filepath = 'mcp_server/server.py'
with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# 1. 添加import
old_import = "from mcp_server.desktop_tools import desktop_tools"
new_import = """from mcp_server.desktop_tools import desktop_tools
from mcp_server.internal_tools import internal_tools"""

if old_import in content and "internal_tools" not in content:
    content = content.replace(old_import, new_import)
    print("✓ 已添加internal_tools import")
else:
    print("  import已存在或未找到")

# 2. 在TOOL_DEFINITIONS末尾添加12个内网工具
internal_tools_def = '''    # ===== 内网渗透工具（12个） =====
    {
        "name": "internal_port_scan",
        "description": "内网端口扫描 - 扫描40+内网常用端口（SMB/RDP/WinRM/LDAP/Kerberos/MSSQL/SSH/FTP/SNMP等），自动识别服务和漏洞。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或主机名"},
                "ports": {"type": "string", "description": "端口范围: common(常用40+端口)/full(1-10000)/自定义如1-1000", "default": "common"}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: internal_tools.internal_port_scan(**kwargs)
    },
    {
        "name": "smb_scan",
        "description": "SMB服务扫描 - 检测SMB服务版本、协议类型、匿名访问、永恒之蓝(MS17-010)风险。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或主机名"}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: internal_tools.smb_scan(**kwargs)
    },
    {
        "name": "netbios_enum",
        "description": "NetBIOS枚举 - 查询NetBIOS名称、MAC地址、工作组/域信息。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或主机名"}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: internal_tools.netbios_enum(**kwargs)
    },
    {
        "name": "ldap_query",
        "description": "LDAP/AD查询 - 检测LDAP服务、匿名绑定、Active Directory信息收集。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或主机名"},
                "base_dn": {"type": "string", "description": "基础DN，可选"},
                "query": {"type": "string", "description": "LDAP查询过滤器，可选", "default": "(objectClass=*)"}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: internal_tools.ldap_query(**kwargs)
    },
    {
        "name": "kerberos_enum",
        "description": "Kerberos枚举 - 检测Kerberos服务、域控制器识别、AS-REP Roasting风险评估。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或主机名"},
                "domain": {"type": "string", "description": "域名，可选"}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: internal_tools.kerberos_enum(**kwargs)
    },
    {
        "name": "rdp_detect",
        "description": "RDP远程桌面检测 - 检测RDP服务版本、NLA支持、加密级别、BlueKeep(CVE-2019-0708)风险。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或主机名"}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: internal_tools.rdp_detect(**kwargs)
    },
    {
        "name": "winrm_detect",
        "description": "WinRM远程管理检测 - 检测Windows远程管理服务(5985/5986)、认证方式、远程命令执行风险。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或主机名"}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: internal_tools.winrm_detect(**kwargs)
    },
    {
        "name": "mssql_scan",
        "description": "MSSQL数据库扫描 - 检测MSSQL服务、弱口令风险、xp_cmdshell风险。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或主机名"},
                "port": {"type": "integer", "description": "端口号，默认1433", "default": 1433}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: internal_tools.mssql_scan(**kwargs)
    },
    {
        "name": "ssh_scan",
        "description": "SSH服务扫描 - 检测SSH版本、协议类型、弱口令风险、已知漏洞。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或主机名"},
                "port": {"type": "integer", "description": "端口号，默认22", "default": 22}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: internal_tools.ssh_scan(**kwargs)
    },
    {
        "name": "ftp_scan",
        "description": "FTP服务扫描 - 检测FTP版本、匿名登录、弱口令风险。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或主机名"},
                "port": {"type": "integer", "description": "端口号，默认21", "default": 21}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: internal_tools.ftp_scan(**kwargs)
    },
    {
        "name": "snmp_enum",
        "description": "SNMP枚举 - 检测SNMP服务、默认社区字符串(public/private)、系统信息泄露。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或主机名"},
                "community": {"type": "string", "description": "社区字符串，默认public", "default": "public"}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: internal_tools.snmp_enum(**kwargs)
    },
    {
        "name": "pass_the_hash_detect",
        "description": "哈希传递(Pass-the-Hash)风险检测 - 评估目标是否存在哈希传递攻击风险，检测SMB/RDP/WinRM等攻击面。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或主机名"}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: internal_tools.pass_the_hash_detect(**kwargs)
    },
]'''

# 找到TOOL_DEFINITIONS的结束位置（最后一个]在handle_list_tools之前）
old_end = '''    },
]


async def handle_list_tools'''

new_end = internal_tools_def + '''


async def handle_list_tools'''

if old_end in content:
    content = content.replace(old_end, new_end)
    print("✓ 已添加12个内网渗透工具到TOOL_DEFINITIONS")
else:
    print("✗ 未找到TOOL_DEFINITIONS结束位置")
    # 尝试查找
    if "handle_list_tools" in content:
        idx = content.find("async def handle_list_tools")
        print(f"  handle_list_tools在位置: {idx}")
        print(f"  前后50字符: ...{content[idx-50:idx+50]}...")

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)

print("\n=== 完成 ===")
