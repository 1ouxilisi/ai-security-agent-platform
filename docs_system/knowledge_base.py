# -*- coding: utf-8 -*-
"""
knowledge_base.py — 知识库与最佳实践模块。

提供安全知识库、最佳实践库、案例库、FAQ、术语表。
基于项目32大安全方向构建完整安全知识库。
"""

from __future__ import annotations

from typing import Any, Dict, List


# --------------------------------------------------------------------------- #
# 1. 安全知识库
# --------------------------------------------------------------------------- #
def get_security_knowledge_base() -> Dict[str, Any]:
    """安全知识库。"""
    return {
        "title": "安全知识库",
        "vulnerability_knowledge": _build_vuln_kb(),
        "attack_techniques": _build_attack_techniques(),
        "defense_solutions": _build_defense_solutions(),
        "cve_library": _build_cve_library(),
        "attack_mapping": _build_attack_mapping(),
        "security_terms": _build_security_terms(),
    }


def _build_vuln_kb() -> List[Dict[str, str]]:
    return [
        {
            "id": "VULN-001",
            "name": "SQL注入",
            "category": "Web漏洞",
            "description": "攻击者通过输入恶意SQL语句操纵数据库查询",
            "severity": "critical",
            "cwe": "CWE-89",
            "prevention": "参数化查询、ORM框架、输入验证",
        },
        {
            "id": "VULN-002",
            "name": "XSS跨站脚本",
            "category": "Web漏洞",
            "description": "在网页中注入恶意脚本，窃取用户会话或执行操作",
            "severity": "high",
            "cwe": "CWE-79",
            "prevention": "输入过滤、输出编码、CSP策略",
        },
        {
            "id": "VULN-003",
            "name": "CSRF跨站请求伪造",
            "category": "Web漏洞",
            "description": "诱导已认证用户执行非预期操作",
            "severity": "medium",
            "cwe": "CWE-352",
            "prevention": "CSRF Token、SameSite Cookie、Referer验证",
        },
        {
            "id": "VULN-004",
            "name": "认证绕过",
            "category": "身份安全",
            "description": "绕过认证机制获取未授权访问",
            "severity": "critical",
            "cwe": "CWE-287",
            "prevention": "强认证、会话管理、多因素认证",
        },
        {
            "id": "VULN-005",
            "name": "权限提升",
            "category": "访问控制",
            "description": "低权限用户获取高权限操作能力",
            "severity": "high",
            "cwe": "CWE-269",
            "prevention": "最小权限原则、权限审计、定期review",
        },
        {
            "id": "VULN-006",
            "name": "敏感数据泄露",
            "category": "数据安全",
            "description": "未授权访问或泄露敏感信息",
            "severity": "high",
            "cwe": "CWE-200",
            "prevention": "数据加密、访问控制、DLP策略",
        },
        {
            "id": "VULN-007",
            "name": "不安全的反序列化",
            "category": "应用安全",
            "description": "恶意序列化数据导致远程代码执行",
            "severity": "critical",
            "cwe": "CWE-502",
            "prevention": "避免反序列化不可信数据、白名单类",
        },
        {
            "id": "VULN-008",
            "name": "SSRF服务端请求伪造",
            "category": "Web漏洞",
            "description": "诱导服务器发起非预期请求",
            "severity": "high",
            "cwe": "CWE-918",
            "prevention": "URL白名单、禁用不需要的协议、网络隔离",
        },
    ]


def _build_attack_techniques() -> List[Dict[str, str]]:
    return [
        {
            "id": "T-001",
            "name": "初始访问 - 鱼叉式钓鱼",
            "tactic": "Initial Access",
            "description": "通过伪装邮件诱导目标执行恶意操作",
            "indicators": "异常邮件头、可疑附件、链接域名",
        },
        {
            "id": "T-002",
            "name": "执行 - 命令行执行",
            "tactic": "Execution",
            "description": "通过命令行执行恶意命令或脚本",
            "indicators": "异常进程创建、可疑命令行参数",
        },
        {
            "id": "T-003",
            "name": "持久化 - 注册表启动项",
            "tactic": "Persistence",
            "description": "修改注册表实现开机自启动",
            "indicators": "异常Run键值、可疑启动项",
        },
        {
            "id": "T-004",
            "name": "权限提升 - UAC绕过",
            "tactic": "Privilege Escalation",
            "description": "绕过用户账户控制获取管理员权限",
            "indicators": "异常COM对象调用、可疑进程提升",
        },
        {
            "id": "T-005",
            "name": "凭据访问 - 凭证转储",
            "tactic": "Credential Access",
            "description": "从内存或存储中提取明文凭据",
            "indicators": "LSASS内存访问、Mimikatz特征",
        },
        {
            "id": "T-006",
            "name": "发现 - 网络服务扫描",
            "tactic": "Discovery",
            "description": "扫描内部网络发现目标服务",
            "indicators": "异常连接请求、端口扫描特征",
        },
        {
            "id": "T-007",
            "name": "横向移动 - RDP远程桌面",
            "tactic": "Lateral Movement",
            "description": "通过RDP协议横向移动到其他主机",
            "indicators": "异常RDP登录、非工作时间登录",
        },
        {
            "id": "T-008",
            "name": "数据窃取 - 文件打包传输",
            "tactic": "Exfiltration",
            "description": "打包敏感数据并外传",
            "indicators": "异常大流量上传、可疑外部连接",
        },
    ]


def _build_defense_solutions() -> List[Dict[str, str]]:
    return [
        {
            "id": "DEF-001",
            "name": "Web应用防火墙(WAF)",
            "category": "边界防护",
            "description": "拦截常见Web攻击(SQLi/XSS/RFI等)",
            "deployment": "反向代理模式部署在Web服务器前",
        },
        {
            "id": "DEF-002",
            "name": "入侵检测系统(IDS/IPS)",
            "category": "检测防护",
            "description": "监控网络流量识别恶意行为",
            "deployment": "旁路监听或在线阻断",
        },
        {
            "id": "DEF-003",
            "name": "终端检测与响应(EDR)",
            "category": "终端防护",
            "description": "监控终端行为，检测和响应威胁",
            "deployment": "在所有终端安装Agent",
        },
        {
            "id": "DEF-004",
            "name": "安全信息与事件管理(SIEM)",
            "category": "集中分析",
            "description": "集中收集和分析安全日志",
            "deployment": "部署日志收集和分析平台",
        },
        {
            "id": "DEF-005",
            "name": "数据防泄漏(DLP)",
            "category": "数据安全",
            "description": "防止敏感数据未授权外传",
            "deployment": "网络DLP + 终端DLP + 存储DLP",
        },
        {
            "id": "DEF-006",
            "name": "零信任架构",
            "category": "架构安全",
            "description": "永不信任，始终验证",
            "deployment": "身份认证 + 设备验证 + 最小权限",
        },
    ]


def _build_cve_library() -> List[Dict[str, str]]:
    return [
        {"id": "CVE-2024-XXXX", "product": "Apache Log4j", "type": "远程代码执行",
         "severity": "critical", "cvss": "10.0", "desc": "JNDI注入导致RCE"},
        {"id": "CVE-2024-XXXX", "product": "OpenSSL", "type": "内存泄漏",
         "severity": "high", "cvss": "7.5", "desc": "TLS握手内存泄露"},
        {"id": "CVE-2024-XXXX", "product": "Linux Kernel", "type": "权限提升",
         "severity": "high", "cvss": "7.8", "desc": "本地权限提升漏洞"},
        {"id": "CVE-2024-XXXX", "product": "Nginx", "type": "HTTP/2拒绝服务",
         "severity": "medium", "cvss": "5.3", "desc": "HTTP/2 Rapid Reset"},
    ]


def _build_attack_mapping() -> Dict[str, Any]:
    return {
        "framework": "MITRE ATT&CK",
        "tactics_covered": [
            "Reconnaissance (侦察)",
            "Resource Development (资源开发)",
            "Initial Access (初始访问)",
            "Execution (执行)",
            "Persistence (持久化)",
            "Privilege Escalation (权限提升)",
            "Defense Evasion (防御规避)",
            "Credential Access (凭据访问)",
            "Discovery (发现)",
            "Lateral Movement (横向移动)",
            "Collection (收集)",
            "Command and Control (命令控制)",
            "Exfiltration (数据窃取)",
            "Impact (影响)",
        ],
        "mapping_status": "已覆盖全部14个战术，映射至项目32大安全方向",
    }


def _build_security_terms() -> List[Dict[str, str]]:
    return [
        {"term": "RCE", "full": "Remote Code Execution", "desc": "远程代码执行"},
        {"term": "XSS", "full": "Cross-Site Scripting", "desc": "跨站脚本攻击"},
        {"term": "CSRF", "full": "Cross-Site Request Forgery", "desc": "跨站请求伪造"},
        {"term": "SSRF", "full": "Server-Side Request Forgery", "desc": "服务端请求伪造"},
        {"term": "MITM", "full": "Man-in-the-Middle", "desc": "中间人攻击"},
        {"term": "CVE", "full": "Common Vulnerabilities and Exposures", "desc": "通用漏洞披露"},
        {"term": "CWE", "full": "Common Weakness Enumeration", "desc": "通用弱点枚举"},
        {"term": "IDS", "full": "Intrusion Detection System", "desc": "入侵检测系统"},
        {"term": "IPS", "full": "Intrusion Prevention System", "desc": "入侵防御系统"},
        {"term": "EDR", "full": "Endpoint Detection and Response", "desc": "终端检测与响应"},
        {"term": "SIEM", "full": "Security Information and Event Management",
         "desc": "安全信息与事件管理"},
        {"term": "DLP", "full": "Data Loss Prevention", "desc": "数据防泄漏"},
    ]


# --------------------------------------------------------------------------- #
# 2. 最佳实践库
# --------------------------------------------------------------------------- #
def get_best_practices() -> Dict[str, Any]:
    """最佳实践库。"""
    return {
        "title": "安全评估最佳实践库",
        "assessment_practices": [
            {
                "category": "安全评估流程",
                "items": [
                    "评估前确认授权范围和目标",
                    "制定评估计划和时间表",
                    "使用最新工具和漏洞库",
                    "保留完整的扫描日志",
                    "结果需人工复核",
                    "报告需包含修复建议",
                ],
            },
            {
                "category": "报告编写",
                "items": [
                    "报告结构: 概述/发现/风险/建议/附录",
                    "按严重程度排序漏洞",
                    "每个漏洞包含: 描述/影响/复现/修复",
                    "使用CVSS评分系统",
                    "提供修复优先级建议",
                ],
            },
            {
                "category": "工具使用",
                "items": [
                    "先在测试环境验证扫描参数",
                    "生产环境低峰期执行",
                    "控制扫描速率避免影响业务",
                    "定期更新工具规则库",
                    "多种工具交叉验证",
                ],
            },
            {
                "category": "团队协作",
                "items": [
                    "明确角色分工: 项目经理/技术专家/报告编写",
                    "定期站会同步进度",
                    "共享知识库和扫描结果",
                    "评估结束后复盘总结",
                ],
            },
        ],
    }


# --------------------------------------------------------------------------- #
# 3. 案例库
# --------------------------------------------------------------------------- #
def get_case_library() -> Dict[str, Any]:
    """案例库。"""
    return {
        "title": "安全评估案例库",
        "cases": [
            {
                "id": "CASE-001",
                "name": "电商平台Web安全评估",
                "type": "漏洞评估",
                "industry": "电商",
                "duration": "2周",
                "scope": "Web应用 + API + 后台管理",
                "findings_summary": "发现SQL注入2个、XSS 5个、CSRF 3个、认证缺陷1个",
                "highlights": [
                    "支付接口存在越权访问漏洞",
                    "用户密码使用弱哈希算法",
                    "API未做速率限制",
                ],
                "recommendation": "优先修复支付相关漏洞，升级密码哈希，添加API限流",
            },
            {
                "id": "CASE-002",
                "name": "云服务器配置审计",
                "type": "合规检查",
                "industry": "金融",
                "duration": "3天",
                "scope": "AWS云资源配置",
                "findings_summary": "S3桶公开访问、安全组配置过宽、未启用CloudTrail",
                "highlights": [
                    "生产数据库暴露在公网",
                    "未启用MFA保护root账号",
                    "日志未保留足够时长",
                ],
                "recommendation": "立即收紧安全组，启用MFA，配置S3访问日志",
            },
            {
                "id": "CASE-003",
                "name": "应急响应 - 勒索软件感染",
                "type": "应急响应",
                "industry": "制造业",
                "duration": "1周",
                "scope": "受感染内网",
                "findings_summary": "勒索软件通过RDP暴力破解进入，横向移动至文件服务器",
                "highlights": [
                    "攻击入口: RDP弱密码",
                    "横向移动: SMB协议",
                    "影响: 生产数据加密",
                ],
                "recommendation": "隔离受感染主机，恢复备份，禁用RDP公网暴露，部署EDR",
            },
            {
                "id": "CASE-004",
                "name": "护网行动红蓝对抗",
                "type": "红蓝对抗",
                "industry": "政府",
                "duration": "30天",
                "scope": "全 IT 基础设施",
                "findings_summary": "红队成功突破边界，获取域控权限；蓝队在24小时内发现并响应",
                "highlights": [
                    "攻击链: 钓鱼邮件 → 执行 → 提权 → 横向 → 域控",
                    "检测时间: 24小时",
                    "防御改进: 邮件安全网关、EDR、网络分段",
                ],
                "recommendation": "部署邮件安全网关，实现网络微分段，完善检测规则",
            },
        ],
    }


# --------------------------------------------------------------------------- #
# 4. FAQ
# --------------------------------------------------------------------------- #
def get_faq() -> Dict[str, Any]:
    """FAQ常见问题。"""
    return {
        "title": "常见问题 FAQ",
        "categories": [
            {
                "category": "安装部署",
                "questions": [
                    {"q": "支持哪些操作系统？", "a": "Windows 10+/Linux/macOS，推荐Linux生产部署"},
                    {"q": "最低硬件要求？", "a": "4GB内存、10GB磁盘、2核CPU"},
                    {"q": "支持Docker部署吗？", "a": "支持，提供Dockerfile和docker-compose模板"},
                ],
            },
            {
                "category": "功能使用",
                "questions": [
                    {"q": "一次可以扫描多少个目标？", "a": "并发数受MAX_WORKERS限制，默认4个"},
                    {"q": "扫描结果会保存多久？", "a": "内存存储，重启后丢失，建议定期导出报告"},
                    {"q": "支持自定义扫描规则吗？", "a": "支持，可通过API传递自定义参数"},
                ],
            },
            {
                "category": "安全合规",
                "questions": [
                    {"q": "使用这个工具合法吗？", "a": "仅限经过授权的安全测试使用"},
                    {"q": "扫描会不会影响业务？", "a": "控制扫描速率和并发数，低峰期执行"},
                    {"q": "数据会上传到第三方吗？", "a": "所有数据本地处理，不上传任何数据"},
                ],
            },
            {
                "category": "故障排查",
                "questions": [
                    {"q": "服务启动报错怎么办？", "a": "查看日志，检查Python版本和依赖安装"},
                    {"q": "API返回401？", "a": "检查X-API-Key请求头是否正确"},
                    {"q": "任务一直pending？", "a": "重启服务，检查worker是否正常"},
                ],
            },
        ],
        "hot_questions": [
            "如何配置API认证？",
            "扫描结果如何导出？",
            "如何添加新的安全模块？",
            "生产环境如何部署？",
        ],
    }


# --------------------------------------------------------------------------- #
# 5. 术语表
# --------------------------------------------------------------------------- #
def get_glossary() -> Dict[str, Any]:
    """安全术语表。"""
    terms = _build_security_terms() + [
        {"term": "APT", "full": "Advanced Persistent Threat", "desc": "高级持续性威胁"},
        {"term": "IOC", "full": "Indicator of Compromise", "desc": "失陷指标"},
        {"term": "TTPs", "full": "Tactics, Techniques, Procedures", "desc": "战术、技术、过程"},
        {"term": "CVSS", "full": "Common Vulnerability Scoring System",
         "desc": "通用漏洞评分系统"},
        {"term": "RBAC", "full": "Role-Based Access Control", "desc": "基于角色的访问控制"},
        {"term": "MFA", "full": "Multi-Factor Authentication", "desc": "多因素认证"},
        {"term": "VPN", "full": "Virtual Private Network", "desc": "虚拟专用网络"},
        {"term": "WAF", "full": "Web Application Firewall", "desc": "Web应用防火墙"},
        {"term": "GDPR", "full": "General Data Protection Regulation",
         "desc": "通用数据保护条例"},
        {"term": "等保", "full": "网络安全等级保护", "desc": "中国网络安全等级保护制度"},
        {"term": "护网", "full": "护网行动", "desc": "国家级网络安全攻防演练"},
        {"term": "零信任", "full": "Zero Trust Architecture", "desc": "零信任安全架构"},
    ]
    return {
        "title": "安全术语表",
        "total_terms": len(terms),
        "categories": {
            "缩写术语": ["RCE", "XSS", "CSRF", "SSRF", "MITM", "CVE", "CWE"],
            "安全产品": ["IDS", "IPS", "EDR", "SIEM", "DLP", "WAF"],
            "合规标准": ["GDPR", "等保", "CVSS"],
            "攻击概念": ["APT", "IOC", "TTPs", "零信任"],
        },
        "terms": terms,
    }
