#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
register_api_security_tools脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

"""注册API安全工具到TOOL_DEFINITIONS"""

filepath = 'mcp_server/server.py'
with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# 1. 添加import
old_import = "from mcp_server.internal_tools import internal_tools"
new_import = """from mcp_server.internal_tools import internal_tools
from mcp_server.api_security_tools import api_security_tools"""

if old_import in content and "api_security_tools" not in content:
    content = content.replace(old_import, new_import)
    print("✓ 已添加api_security_tools import")
else:
    print("  import已存在或未找到")

# 2. 在TOOL_DEFINITIONS末尾添加API安全工具
api_tools_def = '''    # ===== API安全工具（5个） =====
    {
        "name": "openapi_parse",
        "description": "OpenAPI/Swagger文档解析 - 解析API文档，提取所有端点、参数、认证方式、敏感端点。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "OpenAPI文档URL（JSON格式）"}
            },
            "required": ["url"]
        },
        "handler": lambda **kwargs: api_security_tools.parse_openapi(**kwargs)
    },
    {
        "name": "parameter_fuzz",
        "description": "API参数Fuzz测试 - 对API参数进行模糊测试，检测SQL注入/XSS/命令注入/路径遍历/SSRF/重定向等漏洞。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "目标API URL"},
                "param_name": {"type": "string", "description": "要fuzz的参数名"},
                "fuzz_type": {"type": "string", "description": "fuzz类型: sql_injection/xss/command_injection/path_traversal/ssrf/open_redirect/nosql_injection/all", "default": "all"},
                "method": {"type": "string", "description": "HTTP方法", "default": "GET"}
            },
            "required": ["target_url", "param_name"]
        },
        "handler": lambda **kwargs: api_security_tools.parameter_fuzz(**kwargs)
    },
    {
        "name": "bola_test",
        "description": "BOLA/IDOR越权测试 - 测试API对象级授权漏洞（OWASP API Security #1），遍历对象ID检测越权访问。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "目标API URL（不含参数）"},
                "param_name": {"type": "string", "description": "对象ID参数名", "default": "id"},
                "start_id": {"type": "integer", "description": "起始ID", "default": 1},
                "end_id": {"type": "integer", "description": "结束ID", "default": 10}
            },
            "required": ["target_url"]
        },
        "handler": lambda **kwargs: api_security_tools.test_broken_object_level_authorization(**kwargs)
    },
    {
        "name": "mass_assignment_test",
        "description": "批量赋值漏洞测试 - 测试API批量赋值（Mass Assignment）漏洞（OWASP API Security #6），尝试注入is_admin/role/balance等敏感参数。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "目标API URL"},
                "method": {"type": "string", "description": "HTTP方法", "default": "POST"}
            },
            "required": ["target_url"]
        },
        "handler": lambda **kwargs: api_security_tools.test_mass_assignment(**kwargs)
    },
    {
        "name": "sensitive_info_leak_detect",
        "description": "API敏感信息泄露检测 - 检测API响应中的API密钥/密码/Token/私钥/堆栈跟踪等敏感信息泄露。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "目标API URL"}
            },
            "required": ["target_url"]
        },
        "handler": lambda **kwargs: api_security_tools.detect_sensitive_info_leak(**kwargs)
    },
]'''

# 找到TOOL_DEFINITIONS的结束位置
old_end = '''    },
]


async def handle_list_tools'''

new_end = api_tools_def + '''


async def handle_list_tools'''

if old_end in content:
    content = content.replace(old_end, new_end)
    print("✓ 已添加5个API安全工具到TOOL_DEFINITIONS")
else:
    print("✗ 未找到TOOL_DEFINITIONS结束位置")

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)

print("\n=== 完成 ===")
