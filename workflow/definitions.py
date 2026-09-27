#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
definitions工作流引擎模块，提供相关安全测试工作流的定义和执行。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
from workflow.engine import WorkflowPhase


def create_standard_pentest_workflow(target: str, config: dict = None) -> list:
    """
    创建标准渗透测试工作流（7个阶段，增强版）
    :param target: 目标IP或域名
    :param config: 配置参数
    :return: 阶段列表
    """
    config = config or {}
    scan_depth = config.get("scan_depth", "standard")  # quick/standard/deep
    include_exploit = config.get("include_exploit", False)  # 是否包含漏洞利用阶段
    require_approval = config.get("require_approval", True)  # 高危操作是否需要人工审核

    phases = []

    # ===== 阶段1: 情报收集（并行执行DNS+HTTP头，端口扫描单独） =====
    phases.append(WorkflowPhase(
        phase_id="recon",
        name="情报收集",
        description="收集目标的基本信息：DNS解析、端口扫描（nmap真实扫描）、HTTP头分析、服务识别",
        order=1,
        tools=[
            {
                "tool_name": "dns_lookup",
                "parameters": {"domain": "{target}"},
                "description": "DNS解析 - 获取目标IP地址",
                "max_retries": 2,
                "retry_delay": 3
            },
            {
                "tool_name": "http_headers",
                "parameters": {"url": "http://{target}"},
                "description": "HTTP头分析 - 识别服务器类型和技术栈",
                "max_retries": 2,
                "retry_delay": 3
            },
            {
                "tool_name": "port_scan",
                "parameters": {
                    "target": "{target}",
                    "ports": "1-1000" if scan_depth == "quick" else "1-10000" if scan_depth == "standard" else "1-65535"
                },
                "description": "端口扫描 - 发现开放端口和运行服务（nmap真实扫描）",
                "max_retries": 1,
                "retry_delay": 5
            }
        ],
        parallel=False,  # 端口扫描慢，不并行（但DNS和HTTP头可以在端口扫描前快速完成）
        ai_analysis_prompt="""你是一名资深渗透测试专家。请分析以下情报收集阶段的结果：
1. 目标有哪些开放端口？分别运行什么服务？
2. 服务器使用什么技术栈？有哪些安全头缺失？
3. 根据收集到的信息，下一步应该重点测试哪些方向？
4. 评估目标的整体安全状况。
请用中文回答，结构清晰，重点突出。""",
        required=True,
        timeout=300,
        max_retries=1
    ))

    # ===== 阶段2: 枚举与发现（条件：有Web端口才执行目录扫描） =====
    phases.append(WorkflowPhase(
        phase_id="enumeration",
        name="枚举与发现",
        description="深度枚举目标的子域名、目录、文件，发现隐藏的攻击面",
        order=2,
        tools=[
            {
                "tool_name": "subdomain_certificate_transparency",
                "parameters": {"domain": "{target}"},
                "description": "证书透明度查询 - 发现子域名",
                "max_retries": 2,
                "retry_delay": 3
            },
            {
                "tool_name": "directory_scan",
                "parameters": {"url": "http://{target}"},
                "description": "目录扫描 - 发现隐藏目录和敏感文件",
                "max_retries": 1,
                "retry_delay": 5
            }
        ],
        parallel=True,  # 子域名枚举和目录扫描并行执行
        condition="has_open_port(80) or has_open_port(443) or has_service('http') or has_service('https')",
        ai_analysis_prompt="""你是一名资深渗透测试专家。请分析以下枚举阶段的结果：
1. 发现了哪些子域名？哪些可能是高价值目标？
2. 发现了哪些敏感目录或文件？（如admin、backup、.git、config等）
3. 哪些发现值得进一步深入测试？
4. 攻击面比预期大还是小？
请用中文回答，结构清晰，重点突出。""",
        required=False,
        timeout=300,
        max_retries=1,
        on_skip_reason="目标未开放Web端口，跳过枚举阶段"
    ))

    # ===== 阶段3: 漏洞扫描（条件：有Web端口才执行Web漏洞测试） =====
    phases.append(WorkflowPhase(
        phase_id="vuln_scan",
        name="漏洞扫描",
        description="对目标进行全面漏洞扫描：SSL检测、SQL注入、XSS、SSRF、IDOR、命令注入、文件上传、XXE等OWASP Top 10漏洞",
        order=3,
        tools=[
            {
                "tool_name": "ssl_certificate_check",
                "parameters": {"host": "{target}"},
                "description": "SSL证书检测 - 检查HTTPS配置",
                "max_retries": 2,
                "retry_delay": 3
            },
            {
                "tool_name": "sql_injection_test",
                "parameters": {"url": "http://{target}/?id=1", "param": "id"},
                "description": "SQL注入测试 - 测试id参数",
                "max_retries": 2,
                "retry_delay": 3
            },
            {
                "tool_name": "xss_test",
                "parameters": {"url": "http://{target}/?q=test", "param": "q"},
                "description": "XSS测试 - 测试搜索参数",
                "max_retries": 2,
                "retry_delay": 3
            }
        ],
        parallel=True,  # 多个漏洞测试并行执行
        condition="has_open_port(80) or has_open_port(443)",
        ai_analysis_prompt="""你是一名资深渗透测试专家。请分析以下漏洞扫描阶段的结果：
1. 发现了哪些漏洞？分别是什么严重程度？
2. 哪些漏洞可以被实际利用？利用难度如何？
3. SSL/TLS配置有什么问题？
4. 根据漏洞情况，下一步应该优先验证哪些漏洞？
5. 整体风险评级是什么？
请用中文回答，结构清晰，重点突出。""",
        required=True,
        timeout=300,
        max_retries=1,
        on_skip_reason="目标未开放Web端口，跳过漏洞扫描阶段"
    ))

    # ===== 阶段4: 漏洞验证（条件：发现了漏洞才执行深度验证） =====
    phases.append(WorkflowPhase(
        phase_id="vuln_verify",
        name="漏洞验证",
        description="对扫描发现的漏洞进行手动验证，确认漏洞真实存在并评估可利用性：SSRF、IDOR、命令注入、文件上传、XXE深度验证",
        order=4,
        tools=[
            {
                "tool_name": "ssrf_test",
                "parameters": {"url": "http://{target}/fetch?url=http://127.0.0.1", "param": "url"},
                "description": "SSRF测试 - 验证服务端请求伪造",
                "max_retries": 2,
                "retry_delay": 3
            },
            {
                "tool_name": "idor_test",
                "parameters": {"url": "http://{target}/api/user?id=1", "param": "id", "start_id": 1, "end_id": 5},
                "description": "IDOR测试 - 验证越权访问",
                "max_retries": 2,
                "retry_delay": 3
            },
            {
                "tool_name": "command_injection_test",
                "parameters": {"url": "http://{target}/ping?host=127.0.0.1", "param": "host"},
                "description": "命令注入测试 - 验证操作系统命令注入",
                "max_retries": 2,
                "retry_delay": 3
            }
        ],
        parallel=True,  # 多个验证并行执行
        condition="phase_completed('vuln_scan') and (has_vulnerability('high') or has_vulnerability('critical') or has_vulnerability('medium'))",
        ai_analysis_prompt="""你是一名资深渗透测试专家。请分析以下漏洞验证阶段的结果：
1. 哪些漏洞被确认存在？哪些是误报？
2. 每个确认漏洞的利用条件是什么？需要什么权限？
3. 漏洞的实际影响范围有多大？
4. 哪些漏洞可以组合利用以获得更高权限？
5. 给出最终的漏洞清单和风险评级。
请用中文回答，结构清晰，重点突出。""",
        required=False,
        timeout=300,
        max_retries=1,
        on_skip_reason="未发现中高危漏洞，跳过深度验证阶段"
    ))

    # ===== 阶段5: 漏洞利用（可选，需要人工审核） =====
    if include_exploit:
        phases.append(WorkflowPhase(
            phase_id="exploitation",
            name="漏洞利用",
            description="利用已确认的漏洞获取访问权限：Webshell上传、XXE利用、权限提升",
            order=5,
            tools=[
                {
                    "tool_name": "file_upload_test",
                    "parameters": {"upload_url": "http://{target}/upload", "file_field": "file"},
                    "description": "文件上传漏洞利用 - 上传Webshell",
                    "max_retries": 1,
                    "retry_delay": 5
                },
                {
                    "tool_name": "xxe_test",
                    "parameters": {"url": "http://{target}/api/xml"},
                    "description": "XXE利用 - 读取服务器文件",
                    "max_retries": 1,
                    "retry_delay": 5
                }
            ],
            parallel=False,
            condition="phase_completed('vuln_verify') and (has_vulnerability('high') or has_vulnerability('critical'))",
            require_approval=require_approval,
            approval_prompt="即将执行漏洞利用阶段，该阶段可能对目标系统造成影响。请确认：\n1. 已获得目标系统的书面授权\n2. 了解漏洞利用可能的风险\n3. 同意继续执行",
            ai_analysis_prompt="""你是一名资深渗透测试专家。请分析以下漏洞利用阶段的结果：
1. 成功利用了哪些漏洞？获得了什么权限？
2. 获取到了哪些敏感数据？
3. 是否可以进一步提权？提权路径是什么？
4. 内网渗透的可能性有多大？
5. 整个攻击链的完整路径是什么？
请用中文回答，结构清晰，重点突出。""",
            required=False,
            timeout=300,
            max_retries=1,
            on_skip_reason="未发现高危漏洞或未授权漏洞利用，跳过利用阶段"
        ))

    # ===== 阶段6: 风险分析（纯AI分析，不需要工具） =====
    phases.append(WorkflowPhase(
        phase_id="risk_analysis",
        name="风险分析",
        description="综合所有阶段的结果，进行全面的风险分析和影响评估，AI自动生成风险评级和修复优先级",
        order=6 if include_exploit else 5,
        tools=[],  # 纯AI分析阶段
        ai_analysis_prompt="""你是一名资深渗透测试专家和安全顾问。请基于前面所有阶段的结果，进行全面的风险分析：
1. 目标系统的整体安全状况如何？
2. 发现的所有漏洞按严重程度排序，列出Top 10风险。
3. 每个高风险漏洞的业务影响是什么？（数据泄露、服务中断、合规风险等）
4. 攻击者利用这些漏洞的难易程度和可能性。
5. 综合风险评级（Critical/High/Medium/Low）。
6. 优先修复建议（按紧急程度排序）。
请用中文回答，结构清晰，数据准确，建议可操作。""",
        required=True,
        timeout=120,
        max_retries=1
    ))

    # ===== 阶段7: 报告生成（纯AI生成，不需要工具） =====
    phases.append(WorkflowPhase(
        phase_id="report",
        name="报告生成",
        description="生成完整的渗透测试报告：执行摘要、技术细节、漏洞清单、修复建议、附录",
        order=7 if include_exploit else 6,
        tools=[],  # 纯AI生成阶段
        ai_analysis_prompt="""你是一名专业的渗透测试报告撰写专家。请基于前面所有阶段的结果，生成一份完整的渗透测试报告，包括以下部分：

# 渗透测试报告

## 1. 执行摘要
- 测试目标、时间、范围
- 整体安全评级
- 关键发现概述
- 最重要的3个风险和建议

## 2. 测试方法论
- 使用的测试标准（PTES/OWASP）
- 测试工具清单
- 测试流程概述

## 3. 情报收集结果
- 目标基本信息
- 开放端口和服务
- 技术栈识别

## 4. 漏洞清单
按严重程度排序，每个漏洞包含：
- 漏洞名称和编号
- 严重程度（Critical/High/Medium/Low）
- 漏洞描述
- 影响范围
- 复现步骤
- 修复建议
- 参考链接

## 5. 风险分析
- 整体风险评估
- 业务影响分析
- 攻击路径分析

## 6. 修复建议
- 紧急修复（24小时内）
- 高优先级修复（1周内）
- 中优先级修复（1个月内）
- 长期安全改进建议

## 7. 附录
- 工具输出原始数据摘要
- 测试过程日志摘要

请用中文撰写，专业、准确、可操作。""",
        required=True,
        timeout=120,
        max_retries=1
    ))

    return phases


def create_quick_scan_workflow(target: str) -> list:
    """快速扫描工作流（3个阶段，增强版）"""
    phases = [
        WorkflowPhase(
            phase_id="quick_recon",
            name="快速侦察",
            description="快速端口扫描和HTTP头分析",
            order=1,
            tools=[
                {
                    "tool_name": "port_scan",
                    "parameters": {"target": "{target}", "ports": "1-1000"},
                    "description": "快速端口扫描",
                    "max_retries": 2,
                    "retry_delay": 3
                },
                {
                    "tool_name": "http_headers",
                    "parameters": {"url": "http://{target}"},
                    "description": "HTTP头分析",
                    "max_retries": 2,
                    "retry_delay": 3
                }
            ],
            parallel=True,  # 端口扫描和HTTP头并行
            ai_analysis_prompt="分析快速扫描结果，给出目标的基本安全状况评估和下一步建议。",
            required=True,
            timeout=120,
            max_retries=1
        ),
        WorkflowPhase(
            phase_id="quick_vuln",
            name="快速漏洞扫描",
            description="常见漏洞快速检测：SSL、SQL注入",
            order=2,
            tools=[
                {
                    "tool_name": "ssl_certificate_check",
                    "parameters": {"host": "{target}"},
                    "description": "SSL检测",
                    "max_retries": 2,
                    "retry_delay": 3
                },
                {
                    "tool_name": "sql_injection_test",
                    "parameters": {"url": "http://{target}/?id=1", "param": "id"},
                    "description": "SQL注入检测",
                    "max_retries": 2,
                    "retry_delay": 3
                }
            ],
            parallel=True,
            condition="has_open_port(80) or has_open_port(443)",
            ai_analysis_prompt="分析漏洞扫描结果，列出发现的漏洞和风险评级。",
            required=True,
            timeout=120,
            max_retries=1,
            on_skip_reason="目标未开放Web端口，跳过漏洞扫描"
        ),
        WorkflowPhase(
            phase_id="quick_report",
            name="快速报告",
            description="生成简要扫描报告",
            order=3,
            tools=[],
            ai_analysis_prompt="基于扫描结果生成简要报告，包括目标概况、发现的漏洞、风险评级和修复建议。",
            required=True,
            timeout=60,
            max_retries=1
        )
    ]
    return phases


def create_api_security_workflow(target: str, openapi_url: str = "") -> list:
    """API安全专项工作流（P1新增，用于API安全测试）"""
    phases = [
        WorkflowPhase(
            phase_id="api_recon",
            name="API侦察",
            description="API端点发现、认证方式识别、参数枚举",
            order=1,
            tools=[
                {
                    "tool_name": "http_headers",
                    "parameters": {"url": "{target}"},
                    "description": "API响应头分析",
                    "max_retries": 2,
                    "retry_delay": 3
                },
                {
                    "tool_name": "directory_scan",
                    "parameters": {"url": "{target}"},
                    "description": "API端点发现",
                    "max_retries": 1,
                    "retry_delay": 5
                }
            ],
            parallel=True,
            ai_analysis_prompt="分析API侦察结果，识别API类型、认证方式、潜在攻击面。",
            required=True,
            timeout=120,
            max_retries=1
        ),
        WorkflowPhase(
            phase_id="api_auth_test",
            name="API认证测试",
            description="测试API认证授权：越权访问、令牌泄露、会话固定",
            order=2,
            tools=[
                {
                    "tool_name": "idor_test",
                    "parameters": {"url": "{target}/api/user?id=1", "param": "id", "start_id": 1, "end_id": 10},
                    "description": "IDOR越权测试",
                    "max_retries": 2,
                    "retry_delay": 3
                },
                {
                    "tool_name": "ssrf_test",
                    "parameters": {"url": "{target}/api/proxy?url=http://127.0.0.1", "param": "url"},
                    "description": "SSRF测试",
                    "max_retries": 2,
                    "retry_delay": 3
                }
            ],
            parallel=True,
            ai_analysis_prompt="分析API认证测试结果，识别越权、认证绕过等漏洞。",
            required=True,
            timeout=120,
            max_retries=1
        ),
        WorkflowPhase(
            phase_id="api_injection_test",
            name="API注入测试",
            description="测试API注入漏洞：SQL注入、命令注入、XXE",
            order=3,
            tools=[
                {
                    "tool_name": "sql_injection_test",
                    "parameters": {"url": "{target}/api/search?q=test", "param": "q"},
                    "description": "SQL注入测试",
                    "max_retries": 2,
                    "retry_delay": 3
                },
                {
                    "tool_name": "command_injection_test",
                    "parameters": {"url": "{target}/api/ping?host=127.0.0.1", "param": "host"},
                    "description": "命令注入测试",
                    "max_retries": 2,
                    "retry_delay": 3
                },
                {
                    "tool_name": "xxe_test",
                    "parameters": {"url": "{target}/api/xml"},
                    "description": "XXE测试",
                    "max_retries": 2,
                    "retry_delay": 3
                }
            ],
            parallel=True,
            ai_analysis_prompt="分析API注入测试结果，识别各类注入漏洞及利用难度。",
            required=False,
            timeout=120,
            max_retries=1
        ),
        WorkflowPhase(
            phase_id="api_report",
            name="API安全报告",
            description="生成API安全测试报告",
            order=4,
            tools=[],
            ai_analysis_prompt="生成完整的API安全测试报告，包括API资产清单、漏洞清单、风险评级、修复建议。",
            required=True,
            timeout=120,
            max_retries=1
        )
    ]
    return phases


def create_internal_pentest_workflow(target: str, config: dict = None) -> list:
    """
    创建内网渗透测试工作流（6个阶段，增强版）
    覆盖：内网侦察/SMB枚举/AD域渗透/远程管理检测/数据库检测/弱口令检测/哈希传递评估
    """
    config = config or {}
    domain = config.get("domain", "")

    phases = [
        # 阶段1: 内网侦察（端口扫描+服务识别）
        WorkflowPhase(
            phase_id="internal_recon",
            name="内网侦察",
            description="内网端口扫描和服务识别：扫描40+内网常用端口（SMB/RDP/WinRM/LDAP/Kerberos/MSSQL/SSH/FTP/SNMP等）",
            order=1,
            tools=[
                {
                    "tool_name": "internal_port_scan",
                    "parameters": {"target": "{target}", "ports": "common"},
                    "description": "内网常用端口扫描（40+端口）",
                    "max_retries": 1,
                    "retry_delay": 3
                }
            ],
            ai_analysis_prompt="""你是一名资深内网渗透测试专家。请分析以下内网侦察结果：
1. 目标开放了哪些内网服务？（SMB/RDP/WinRM/LDAP/Kerberos/数据库等）
2. 目标可能是什么角色？（域控制器/文件服务器/数据库服务器/工作站）
3. 哪些服务是高价值攻击目标？
4. 下一步应该重点测试哪些方向？
请用中文回答，结构清晰，重点突出。""",
            required=True,
            timeout=180,
            max_retries=1
        ),
        # 阶段2: SMB/NetBIOS枚举（条件：SMB端口开放）
        WorkflowPhase(
            phase_id="smb_enum",
            name="SMB/NetBIOS枚举",
            description="SMB服务扫描、NetBIOS名称枚举、共享目录发现、操作系统识别",
            order=2,
            tools=[
                {
                    "tool_name": "smb_scan",
                    "parameters": {"target": "{target}"},
                    "description": "SMB服务扫描和漏洞检测",
                    "max_retries": 2,
                    "retry_delay": 3
                },
                {
                    "tool_name": "netbios_enum",
                    "parameters": {"target": "{target}"},
                    "description": "NetBIOS名称和MAC地址枚举",
                    "max_retries": 2,
                    "retry_delay": 3
                }
            ],
            parallel=True,
            condition="has_open_port(445) or has_open_port(139)",
            ai_analysis_prompt="""分析SMB/NetBIOS枚举结果：
1. SMB服务版本和配置如何？是否启用SMB1？
2. 是否存在匿名访问？有哪些共享目录？
3. NetBIOS信息揭示了什么？（计算机名/工作组/域）
4. 是否存在永恒之蓝(MS17-010)等高危漏洞风险？
请用中文回答。""",
            required=False,
            timeout=120,
            max_retries=1,
            on_skip_reason="SMB端口未开放，跳过SMB枚举"
        ),
        # 阶段3: AD域渗透（条件：LDAP或Kerberos端口开放）
        WorkflowPhase(
            phase_id="ad_enum",
            name="AD域渗透",
            description="Active Directory信息收集：LDAP查询、Kerberos枚举、域用户/组/计算机发现、AS-REP Roasting检测",
            order=3,
            tools=[
                {
                    "tool_name": "ldap_query",
                    "parameters": {"target": "{target}"},
                    "description": "LDAP/AD查询和匿名绑定检测",
                    "max_retries": 2,
                    "retry_delay": 3
                },
                {
                    "tool_name": "kerberos_enum",
                    "parameters": {"target": "{target}"},
                    "description": "Kerberos服务检测和用户枚举",
                    "max_retries": 2,
                    "retry_delay": 3
                }
            ],
            parallel=True,
            condition="has_open_port(389) or has_open_port(88) or has_open_port(636)",
            ai_analysis_prompt="""分析AD域渗透结果：
1. 目标是否为域控制器？域名是什么？
2. LDAP是否允许匿名绑定？可获取哪些信息？
3. Kerberos服务是否可访问？是否存在AS-REP Roasting风险？
4. 域内可能有哪些高价值账户？（Domain Admin/Enterprise Admin/Krbtgt）
5. 下一步域渗透的攻击路径建议。
请用中文回答。""",
            required=False,
            timeout=120,
            max_retries=1,
            on_skip_reason="LDAP/Kerberos端口未开放，跳过AD域渗透"
        ),
        # 阶段4: 远程管理服务检测（RDP/WinRM）
        WorkflowPhase(
            phase_id="remote_mgmt",
            name="远程管理检测",
            description="远程管理服务检测：RDP远程桌面、WinRM远程管理、NLA支持、加密级别",
            order=4,
            tools=[
                {
                    "tool_name": "rdp_detect",
                    "parameters": {"target": "{target}"},
                    "description": "RDP服务检测和漏洞评估",
                    "max_retries": 2,
                    "retry_delay": 3
                },
                {
                    "tool_name": "winrm_detect",
                    "parameters": {"target": "{target}"},
                    "description": "WinRM服务检测和风险评估",
                    "max_retries": 2,
                    "retry_delay": 3
                }
            ],
            parallel=True,
            condition="has_open_port(3389) or has_open_port(5985) or has_open_port(5986)",
            ai_analysis_prompt="""分析远程管理服务检测结果：
1. RDP服务配置如何？是否启用NLA？是否存在BlueKeep风险？
2. WinRM服务是否可访问？认证方式有哪些？
3. 哪些服务可用于横向移动？
4. 远程管理服务的整体风险评级。
请用中文回答。""",
            required=False,
            timeout=120,
            max_retries=1,
            on_skip_reason="远程管理端口未开放，跳过远程管理检测"
        ),
        # 阶段5: 数据库和弱口令检测（MSSQL/SSH/FTP/SNMP）
        WorkflowPhase(
            phase_id="db_weakpass",
            name="数据库与弱口令",
            description="数据库服务检测和弱口令/匿名访问检测：MSSQL、SSH、FTP匿名登录、SNMP默认社区字符串",
            order=5,
            tools=[
                {
                    "tool_name": "mssql_scan",
                    "parameters": {"target": "{target}"},
                    "description": "MSSQL服务检测和弱口令评估",
                    "max_retries": 2,
                    "retry_delay": 3
                },
                {
                    "tool_name": "ssh_scan",
                    "parameters": {"target": "{target}"},
                    "description": "SSH服务版本检测",
                    "max_retries": 2,
                    "retry_delay": 3
                },
                {
                    "tool_name": "ftp_scan",
                    "parameters": {"target": "{target}"},
                    "description": "FTP服务和匿名登录检测",
                    "max_retries": 2,
                    "retry_delay": 3
                },
                {
                    "tool_name": "snmp_enum",
                    "parameters": {"target": "{target}"},
                    "description": "SNMP默认社区字符串检测",
                    "max_retries": 2,
                    "retry_delay": 3
                }
            ],
            parallel=True,
            condition="has_open_port(1433) or has_open_port(22) or has_open_port(21) or has_open_port(161)",
            ai_analysis_prompt="""分析数据库和弱口令检测结果：
1. 哪些数据库服务暴露？是否存在弱口令风险？
2. FTP是否允许匿名登录？
3. SNMP是否使用默认社区字符串？可获取哪些信息？
4. SSH版本是否存在已知漏洞？
5. 弱口令/匿名访问的整体风险评级。
请用中文回答。""",
            required=False,
            timeout=180,
            max_retries=1,
            on_skip_reason="数据库/弱口令相关端口未开放，跳过检测"
        ),
        # 阶段6: 哈希传递评估和报告
        WorkflowPhase(
            phase_id="pth_report",
            name="哈希传递与报告",
            description="哈希传递(Pass-the-Hash)风险评估，生成完整内网渗透测试报告",
            order=6,
            tools=[
                {
                    "tool_name": "pass_the_hash_detect",
                    "parameters": {"target": "{target}"},
                    "description": "哈希传递攻击风险评估",
                    "max_retries": 1,
                    "retry_delay": 3
                }
            ],
            ai_analysis_prompt="""你是一名资深内网渗透测试专家。请基于前面所有阶段的结果，生成完整的内网渗透测试报告：
1. 目标系统角色判断（域控/文件服务器/数据库/工作站）
2. 发现的所有漏洞按严重程度排序
3. 内网横向移动路径分析
4. 域渗透攻击路径（如果适用）
5. 哈希传递风险评估
6. 整体安全评级和修复建议
请用中文回答，专业、准确、可操作。""",
            required=True,
            timeout=180,
            max_retries=1
        )
    ]
    return phases


# 工作流模板注册表
WORKFLOW_TEMPLATES = {
    "standard_pentest": {
        "name": "标准渗透测试",
        "description": "完整的PTES标准渗透测试流程，7个阶段，支持条件分支/并行执行/人工审核，适合正式渗透测试项目",
        "phases_count": 7,
        "estimated_time": "30-60分钟",
        "features": ["条件分支", "并行执行", "人工审核", "自动重试", "AI分析"],
        "creator": create_standard_pentest_workflow
    },
    "quick_scan": {
        "name": "快速扫描",
        "description": "快速端口扫描和漏洞检测，3个阶段，并行执行，适合快速评估",
        "phases_count": 3,
        "estimated_time": "5-10分钟",
        "features": ["并行执行", "条件分支", "自动重试", "AI分析"],
        "creator": create_quick_scan_workflow
    },
    "api_security": {
        "name": "API安全专项",
        "description": "API安全专项测试：认证授权、越权访问、注入漏洞，4个阶段",
        "phases_count": 4,
        "estimated_time": "15-30分钟",
        "features": ["并行执行", "条件分支", "自动重试", "AI分析"],
        "creator": create_api_security_workflow
    },
    "internal_pentest": {
        "name": "内网渗透测试",
        "description": "内网渗透专项测试：SMB枚举/AD域渗透/远程管理检测/数据库弱口令/哈希传递评估，6个阶段，12个内网工具",
        "phases_count": 6,
        "estimated_time": "20-40分钟",
        "features": ["条件分支", "并行执行", "自动重试", "AI分析", "域渗透"],
        "creator": create_internal_pentest_workflow
    }
}
