"""
server模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import asyncio
import inspect
import json
from typing import Any, Dict, List
from mcp.server import Server
from mcp.types import Tool, TextContent, PaginatedRequestParams, ListToolsResult, CallToolRequestParams, CallToolResult
from utils.logger import log
from mcp_server.recon_tools import recon_tools
from mcp_server.web_tools import web_tools
from mcp_server.advanced_tools import (
    ssl_tls_audit, whois_lookup, cms_fingerprint, security_headers_audit,
    cors_test, clickjacking_test, ssh_audit, tech_stack_detect, full_recon
)

from mcp_server.advanced_web_tools import advanced_web_tools
from mcp_server.subdomain_tools import subdomain_tools
from mcp_server.browser_tools import browser_tools
from mcp_server.desktop_tools import desktop_tools
from mcp_server.internal_tools import internal_tools
from mcp_server.api_security_tools import api_security_tools
from mcp_server.cloud_security_tools import cloud_security_tools

# 创建MCP服务器
server = Server("ai-hacking-agent-mcp-v2")

# 工具定义列表
TOOL_DEFINITIONS = [
    # ===== 侦察工具 =====
    {
        "name": "port_scan",
        "description": "端口扫描 - 扫描目标主机的开放端口和运行服务。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标主机IP或域名，例如 127.0.0.1"},
                "ports": {"type": "string", "description": "端口范围，例如 1-1000 或 22,80,443"},
                "timeout": {"type": "number", "description": "超时时间(秒)，默认2.0"}
            },
            "required": ["target"]
        },
        "handler": lambda **kwargs: recon_tools.port_scan(**kwargs)
    },
    {
        "name": "dns_lookup",
        "description": "DNS解析 - 解析域名对应的IP地址",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "要解析的域名"}
            },
            "required": ["domain"]
        },
        "handler": lambda **kwargs: recon_tools.dns_lookup(**kwargs)
    },
    {
        "name": "http_headers",
        "description": "获取HTTP响应头 - 识别服务器类型、技术栈、安全头配置",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标URL"}
            },
            "required": ["url"]
        },
        "handler": lambda **kwargs: recon_tools.http_headers(**kwargs)
    },
    # ===== 子域名枚举工具 =====
    {
        "name": "subdomain_dns_bruteforce",
        "description": "子域名DNS爆破 - 通过字典爆破发现子域名。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "目标主域名"},
                "max_concurrent": {"type": "integer", "description": "最大并发数，默认20"}
            },
            "required": ["domain"]
        },
        "handler": lambda **kwargs: subdomain_tools.dns_bruteforce(**kwargs)
    },
    {
        "name": "subdomain_certificate_transparency",
        "description": "证书透明度查询 - 通过查询证书透明度日志发现子域名。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "目标主域名"}
            },
            "required": ["domain"]
        },
        "handler": lambda **kwargs: subdomain_tools.certificate_transparency(**kwargs)
    },
    {
        "name": "subdomain_enumerate_all",
        "description": "全方法子域名枚举 - 组合多种方法发现子域名。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "目标主域名"}
            },
            "required": ["domain"]
        },
        "handler": lambda **kwargs: subdomain_tools.enumerate_all(**kwargs)
    },
    # ===== Web安全工具 =====
    {
        "name": "directory_scan",
        "description": "目录扫描 - 发现网站隐藏目录和敏感文件。仅允许扫描授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标URL"},
                "wordlist": {"type": "array", "items": {"type": "string"}, "description": "自定义路径字典"}
            },
            "required": ["url"]
        },
        "handler": lambda **kwargs: web_tools.directory_scan(**kwargs)
    },
    {
        "name": "sql_injection_test",
        "description": "SQL注入测试 - 测试URL参数是否存在SQL注入漏洞。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标URL，需包含查询参数"},
                "param": {"type": "string", "description": "要测试的参数名"}
            },
            "required": ["url", "param"]
        },
        "handler": lambda **kwargs: web_tools.sql_injection_test(**kwargs)
    },
    {
        "name": "xss_test",
        "description": "XSS测试 - 测试URL参数是否存在跨站脚本漏洞。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标URL，需包含查询参数"},
                "param": {"type": "string", "description": "要测试的参数名"}
            },
            "required": ["url", "param"]
        },
        "handler": lambda **kwargs: web_tools.xss_test(**kwargs)
    },
    {
        "name": "ssl_certificate_check",
        "description": "SSL证书检测 - 检查HTTPS证书有效性、过期时间、颁发者",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "目标主机"},
                "port": {"type": "integer", "description": "端口，默认443"}
            },
            "required": ["host"]
        },
        "handler": lambda **kwargs: web_tools.ssl_certificate_check(**kwargs)
    },
    # ===== 高级Web安全工具 =====
    {
        "name": "ssrf_test",
        "description": "SSRF测试 - 测试URL参数是否存在服务端请求伪造漏洞。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标URL，需包含查询参数"},
                "param": {"type": "string", "description": "要测试的参数名"}
            },
            "required": ["url", "param"]
        },
        "handler": lambda **kwargs: advanced_web_tools.ssrf_test(**kwargs)
    },
    {
        "name": "idor_test",
        "description": "IDOR测试 - 测试通过修改ID参数是否能访问未授权资源。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标URL，需包含ID查询参数"},
                "param": {"type": "string", "description": "ID参数名"},
                "start_id": {"type": "integer", "description": "起始ID，默认1"},
                "end_id": {"type": "integer", "description": "结束ID，默认10"}
            },
            "required": ["url", "param"]
        },
        "handler": lambda **kwargs: advanced_web_tools.idor_test(**kwargs)
    },
    {
        "name": "command_injection_test",
        "description": "命令注入测试 - 测试URL参数是否存在操作系统命令注入漏洞。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标URL，需包含查询参数"},
                "param": {"type": "string", "description": "要测试的参数名"}
            },
            "required": ["url", "param"]
        },
        "handler": lambda **kwargs: advanced_web_tools.command_injection_test(**kwargs)
    },
    {
        "name": "file_upload_test",
        "description": "文件上传漏洞测试 - 测试上传点是否允许上传危险文件类型。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "upload_url": {"type": "string", "description": "文件上传接口URL"},
                "file_field": {"type": "string", "description": "文件字段名，默认file"}
            },
            "required": ["upload_url"]
        },
        "handler": lambda **kwargs: advanced_web_tools.file_upload_test(**kwargs)
    },
    {
        "name": "xxe_test",
        "description": "XXE测试 - 测试接受XML输入的端点是否存在XML外部实体注入漏洞。仅允许测试授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "接受XML输入的目标URL"}
            },
            "required": ["url"]
        },
        "handler": lambda **kwargs: advanced_web_tools.xxe_test(**kwargs)
    },
    # ===== 浏览器自动化工具 =====
    {
        "name": "browser_navigate",
        "description": "浏览器导航 - 打开指定网页。仅允许访问授权白名单内的目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "要打开的URL"}
            },
            "required": ["url"]
        },
        "handler": lambda **kwargs: browser_tools.navigate(**kwargs)
    },
    {
        "name": "browser_screenshot",
        "description": "浏览器截图 - 对当前页面截图保存",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "保存文件名"},
                "full_page": {"type": "boolean", "description": "是否截取整页，默认true"}
            }
        },
        "handler": lambda **kwargs: browser_tools.take_screenshot(**kwargs)
    },
    {
        "name": "browser_get_content",
        "description": "获取页面HTML内容 - 返回当前页面的源代码",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda **kwargs: browser_tools.get_page_content(**kwargs)
    },
    {
        "name": "browser_extract_links",
        "description": "提取页面链接 - 获取当前页面所有超链接",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda **kwargs: browser_tools.extract_links(**kwargs)
    },
    {
        "name": "browser_extract_forms",
        "description": "提取页面表单 - 获取当前页面所有表单和输入字段",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda **kwargs: browser_tools.extract_forms(**kwargs)
    },
    {
        "name": "browser_fill_form",
        "description": "填写表单 - 在页面指定输入框中填入值",
        "inputSchema": {
            "type": "object",
            "properties": {
                "selector": {"type": "string", "description": "CSS选择器"},
                "value": {"type": "string", "description": "要填入的值"}
            },
            "required": ["selector", "value"]
        },
        "handler": lambda **kwargs: browser_tools.fill_form(**kwargs)
    },
    {
        "name": "browser_click",
        "description": "点击元素 - 点击页面上指定的元素",
        "inputSchema": {
            "type": "object",
            "properties": {
                "selector": {"type": "string", "description": "CSS选择器"}
            },
            "required": ["selector"]
        },
        "handler": lambda **kwargs: browser_tools.click_element(**kwargs)
    },
    {
        "name": "browser_eval_js",
        "description": "执行JavaScript - 在当前页面上下文中执行JS代码",
        "inputSchema": {
            "type": "object",
            "properties": {
                "script": {"type": "string", "description": "要执行的JavaScript代码"}
            },
            "required": ["script"]
        },
        "handler": lambda **kwargs: browser_tools.evaluate_script(**kwargs)
    },
    # ===== 桌面自动化工具 =====
    {
        "name": "desktop_screen_size",
        "description": "获取屏幕分辨率 - 返回当前显示器的宽高",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda **kwargs: desktop_tools.get_screen_size(**kwargs)
    },
    {
        "name": "desktop_mouse_position",
        "description": "获取鼠标位置 - 返回当前鼠标指针的坐标",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda **kwargs: desktop_tools.get_mouse_position(**kwargs)
    },
    {
        "name": "desktop_screenshot",
        "description": "屏幕截图 - 对整个桌面或指定区域截图",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "保存文件名"},
                "region": {"type": "array", "items": {"type": "integer"}, "description": "截取区域 [x, y, width, height]"}
            }
        },
        "handler": lambda **kwargs: desktop_tools.screenshot(**kwargs)
    },
    {
        "name": "desktop_move_mouse",
        "description": "移动鼠标 - 将鼠标指针移动到指定坐标",
        "inputSchema": {
            "type": "object",
            "properties": {
                "x": {"type": "integer", "description": "目标X坐标"},
                "y": {"type": "integer", "description": "目标Y坐标"},
                "duration": {"type": "number", "description": "移动时长(秒)"}
            },
            "required": ["x", "y"]
        },
        "handler": lambda **kwargs: desktop_tools.move_mouse(**kwargs)
    },
    {
        "name": "desktop_click",
        "description": "鼠标点击 - 在指定位置或当前位置点击鼠标",
        "inputSchema": {
            "type": "object",
            "properties": {
                "x": {"type": "integer", "description": "点击X坐标"},
                "y": {"type": "integer", "description": "点击Y坐标"},
                "button": {"type": "string", "description": "按键 left/right/middle，默认left"},
                "clicks": {"type": "integer", "description": "点击次数，默认1"}
            }
        },
        "handler": lambda **kwargs: desktop_tools.click(**kwargs)
    },
    {
        "name": "desktop_type_text",
        "description": "键盘输入 - 在当前焦点应用中输入文本",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "要输入的文本"},
                "interval": {"type": "number", "description": "字符间隔(秒)，默认0.05"}
            },
            "required": ["text"]
        },
        "handler": lambda **kwargs: desktop_tools.type_text(**kwargs)
    },
    {
        "name": "desktop_press_key",
        "description": "按键操作 - 按下指定键盘按键",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "按键名称，例如 enter, tab, esc, f5"},
                "presses": {"type": "integer", "description": "按下次数，默认1"},
                "interval": {"type": "number", "description": "间隔(秒)，默认0.25"}
            },
            "required": ["key"]
        },
        "handler": lambda **kwargs: desktop_tools.press_key(**kwargs)
    },
    {
        "name": "desktop_hotkey",
        "description": "组合键 - 按下组合键，例如 ctrl+c, alt+tab",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keys": {"type": "array", "items": {"type": "string"}, "description": "按键列表，例如 ['ctrl', 'c']"}
            },
            "required": ["keys"]
        },
        "handler": lambda **kwargs: desktop_tools.hotkey(*kwargs.get("keys", []))
    },
    {
        "name": "desktop_scroll",
        "description": "滚轮滚动 - 向上或向下滚动鼠标滚轮",
        "inputSchema": {
            "type": "object",
            "properties": {
                "amount": {"type": "integer", "description": "滚动量，正数向上，负数向下"},
                "x": {"type": "integer", "description": "滚动位置X"},
                "y": {"type": "integer", "description": "滚动位置Y"}
            },
            "required": ["amount"]
        },
        "handler": lambda **kwargs: desktop_tools.scroll(**kwargs)
    },
    {
        "name": "desktop_locate_image",
        "description": "图像识别定位 - 在屏幕上查找指定图片的位置",
        "inputSchema": {
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "要查找的图片文件路径"},
                "confidence": {"type": "number", "description": "匹配置信度0-1，默认0.8"}
            },
            "required": ["image_path"]
        },
        "handler": lambda **kwargs: desktop_tools.locate_on_screen(**kwargs)
    },
    # ===== 内网渗透工具（12个） =====
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
    # ===== API安全工具（5个） =====
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
    # ===== 云安全工具（5个） =====
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
    # ===== API安全工具（5个） =====
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
    # ===== 云安全工具（5个） =====
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
    # ===== 内网渗透工具（12个） =====
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
    # ===== API安全工具（5个） =====
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
    # ===== 云安全工具（5个） =====
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
    # ===== 内网渗透工具（12个） =====
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


    # ===== 高级安全工具（空前升级新增9个） =====
    {
        "name": "ssl_tls_audit",
        "description": "SSL/TLS安全审计 - 检查证书有效性、协议版本、密码套件、过期时间。仅允许测试授权白名单内的目标。",
        "inputSchema": {"type": "object", "properties": {"hostname": {"type": "string"}, "port": {"type": "integer"}, "timeout": {"type": "integer"}}, "required": ["hostname"]},
        "handler": lambda **kwargs: ssl_tls_audit(**kwargs)
    },
    {
        "name": "whois_lookup",
        "description": "WHOIS域名信息查询 - 获取域名注册商、注册时间、过期时间、DNS服务器。",
        "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]},
        "handler": lambda **kwargs: whois_lookup(**kwargs)
    },
    {
        "name": "cms_fingerprint",
        "description": "CMS指纹识别 - 识别WordPress/Drupal/Joomla等15种CMS和技术栈。仅允许测试授权白名单内的目标。",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        "handler": lambda **kwargs: cms_fingerprint(**kwargs)
    },
    {
        "name": "security_headers_audit",
        "description": "安全头审计 - 检查HSTS/CSP/X-Frame-Options等7种安全头，给出0-100安全评分。仅允许测试授权白名单内的目标。",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        "handler": lambda **kwargs: security_headers_audit(**kwargs)
    },
    {
        "name": "cors_test",
        "description": "CORS跨域测试 - 检测任意Origin反射、null Origin等CORS配置漏洞。仅允许测试授权白名单内的目标。",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        "handler": lambda **kwargs: cors_test(**kwargs)
    },
    {
        "name": "clickjacking_test",
        "description": "点击劫持测试 - 检查X-Frame-Options和CSP frame-ancestors配置。仅允许测试授权白名单内的目标。",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        "handler": lambda **kwargs: clickjacking_test(**kwargs)
    },
    {
        "name": "ssh_audit",
        "description": "SSH安全审计 - 检查SSH版本、Banner、已知漏洞（regreSSHion/Terrapin等20+CVE）。仅允许测试授权白名单内的目标。",
        "inputSchema": {"type": "object", "properties": {"hostname": {"type": "string"}, "port": {"type": "integer"}, "timeout": {"type": "integer"}}, "required": ["hostname"]},
        "handler": lambda **kwargs: ssh_audit(**kwargs)
    },
    {
        "name": "tech_stack_detect",
        "description": "技术栈检测 - 综合识别Web服务器/编程语言/框架/数据库/CDN/操作系统。仅允许测试授权白名单内的目标。",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        "handler": lambda **kwargs: tech_stack_detect(**kwargs)
    },
    {
        "name": "full_recon",
        "description": "一键全面侦察 - 组合端口扫描+DNS+HTTP头+SSL+CMS+安全头+技术栈+CORS+点击劫持，输出综合报告。仅允许测试授权白名单内的目标。",
        "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}, "timeout": {"type": "integer"}}, "required": ["target"]},
        "handler": lambda **kwargs: full_recon(**kwargs)
    },

]

# ===== 工具去重：保留每个工具名的第一个定义，移除重复注册 =====
_seen_tools = set()
_deduped_tools = []
for _t in TOOL_DEFINITIONS:
    if _t["name"] not in _seen_tools:
        _seen_tools.add(_t["name"])
        _deduped_tools.append(_t)
TOOL_DEFINITIONS = _deduped_tools
log.info(f"工具去重完成: {len(_deduped_tools)}个唯一工具")


async def handle_list_tools(params: PaginatedRequestParams) -> ListToolsResult:
    """向大模型暴露所有可用工具"""
    tools = []
    for tool_def in TOOL_DEFINITIONS:
        tools.append(Tool(
            name=tool_def["name"],
            description=tool_def["description"],
            inputSchema=tool_def["inputSchema"]
        ))
    log.info(f"已注册 {len(tools)} 个MCP工具 (v2全面升级版)")
    return ListToolsResult(tools=tools)

server.request_handlers["tools/list"] = handle_list_tools


async def handle_call_tool(params: CallToolRequestParams) -> CallToolResult:
    """处理大模型的工具调用请求"""
    name = params.name
    arguments = params.arguments or {}
    log.info(f"工具调用: {name}, 参数: {json.dumps(arguments, ensure_ascii=False)[:200]}")

    tool_def = next((t for t in TOOL_DEFINITIONS if t["name"] == name), None)
    if not tool_def:
        error_msg = f"未知工具: {name}"
        log.error(error_msg)
        return CallToolResult(content=[TextContent(type="text", text=json.dumps({"error": error_msg}, ensure_ascii=False))])

    try:
        result = await tool_def["handler"](**arguments) if inspect.iscoroutinefunction(tool_def["handler"]) else tool_def["handler"](**arguments)

        if isinstance(result, dict):
            result_text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
        else:
            result_text = str(result)

        log.info(f"工具 {name} 执行完成，结果长度: {len(result_text)}")
        return CallToolResult(content=[TextContent(type="text", text=result_text)])

    except Exception as e:
        error_msg = f"工具 {name} 执行失败: {str(e)}"
        log.error(error_msg)
        return CallToolResult(content=[TextContent(type="text", text=json.dumps({"error": error_msg}, ensure_ascii=False))])

server.request_handlers["tools/call"] = handle_call_tool


async def run_stdio():
    """以stdio模式运行MCP服务端"""
    from mcp.server.stdio import stdio_server
    log.info("MCP服务端启动 (stdio模式) v2")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


async def run_http(host: str = "127.0.0.1", port: int = 8000):
    """以HTTP模式运行MCP服务端"""
    from mcp.server.http import http_server
    log.info(f"MCP服务端启动 (HTTP模式): {host}:{port} v2")
    async with http_server(server, host=host, port=port) as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main():
    """主入口"""
    import sys
    from config.settings import settings

    mode = settings.mcp.mode
    if len(sys.argv) > 1:
        mode = sys.argv[1]

    log.info("=" * 60)
    log.info("AI Hacking Agent - MCP服务端 v2.0 (全面升级版)")
    log.info(f"运行模式: {mode}")
    log.info(f"注册工具数: {len(TOOL_DEFINITIONS)}")
    log.info("=" * 60)

    if mode == "http":
        asyncio.run(run_http(settings.mcp.host, settings.mcp.port))
    else:
        asyncio.run(run_stdio())


if __name__ == "__main__":
    main()
