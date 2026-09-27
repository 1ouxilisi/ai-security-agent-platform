#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
register_cloud_security_tools脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

"""注册云安全工具到TOOL_DEFINITIONS（安全版本）"""

filepath = 'mcp_server/server.py'
with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# 1. 添加import
old_import = "from mcp_server.api_security_tools import api_security_tools"
new_import = """from mcp_server.api_security_tools import api_security_tools
from mcp_server.cloud_security_tools import cloud_security_tools"""

if old_import in content and "cloud_security_tools" not in content:
    content = content.replace(old_import, new_import)
    print("✓ 已添加cloud_security_tools import")
else:
    print("  import已存在或未找到")

# 2. 找到最后一个工具定义的结束位置，在]前插入
# 找到 'async def handle_list_tools' 之前的 ']'
marker = "\n\n\nasync def handle_list_tools"
marker_pos = content.find(marker)
if marker_pos == -1:
    print("✗ 未找到handle_list_tools标记")
    exit(1)

# 从marker_pos往前找最近的 ']'
bracket_pos = content.rfind("]", 0, marker_pos)
if bracket_pos == -1:
    print("✗ 未找到TOOL_DEFINITIONS结束括号")
    exit(1)

# 检查括号前是否有 '},'（上一个工具的结束）
before_bracket = content[bracket_pos-10:bracket_pos].strip()
print(f"  括号前内容: {repr(before_bracket)}")

cloud_tools_def = '''    # ===== 云安全工具（5个） =====
    {
        "name": "cloud_provider_detect",
        "description": "云服务提供商检测 - 检测目标运行在哪个云平台（AWS/Azure/阿里云/腾讯云/华为云/GCP）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标域名或IP"}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: cloud_security_tools.detect_cloud_provider(**kwargs)
    },
    {
        "name": "s3_public_bucket_check",
        "description": "S3公开存储桶检测 - 检测AWS S3存储桶是否公开可读或公开可写，列出公开文件。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bucket_name": {"type": "string", "description": "S3存储桶名称"}
            },
            "required": ["bucket_name"]
        },
        "handler": lambda **kwargs: cloud_security_tools.check_s3_public_bucket(**kwargs)
    },
    {
        "name": "container_security_scan",
        "description": "容器安全扫描 - 检测Docker配置安全（API暴露/Registry暴露/特权模式）和镜像漏洞，提供容器安全最佳实践检查清单",
        "inputSchema": {
            "type": "object",
            "properties": {
                "image_name": {"type": "string", "description": "Docker镜像名称（可选）", "default": ""}
            }
        },
        "handler": lambda **kwargs: cloud_security_tools.container_security_scan(**kwargs)
    },
    {
        "name": "cloud_service_exposure_scan",
        "description": "云服务暴露扫描 - 检测目标是否暴露数据库/缓存/消息队列/Docker API等云服务端口，评估公网暴露风险。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或域名"}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: cloud_security_tools.cloud_service_exposure_scan(**kwargs)
    },
    {
        "name": "iam_config_audit",
        "description": "IAM配置审计 - 检查云IAM配置最佳实践（MFA/最小权限/密钥轮换/密码策略等），支持AWS/Azure/阿里云",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cloud_provider": {"type": "string", "description": "云服务商: aws/azure/aliyun", "default": "aws"}
            }
        },
        "handler": lambda **kwargs: cloud_security_tools.iam_config_audit(**kwargs)
    },
'''

# 在括号前插入
content = content[:bracket_pos] + cloud_tools_def + content[bracket_pos:]

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)

print("✓ 已添加5个云安全工具到TOOL_DEFINITIONS")
print("\n=== 完成 ===")
