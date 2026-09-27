#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITRE ATT&CK 映射器
将漏洞和攻击技术映射到MITRE ATT&CK框架
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class ATTCTechnique:
    """ATT&CK技术"""
    technique_id: str = ""  # T1234
    name: str = ""
    tactic: str = ""  # 战术阶段
    description: str = ""
    platforms: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    detections: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)


@dataclass
class AttackMapping:
    """攻击映射结果"""
    vulnerability_type: str = ""
    techniques: List[ATTCTechnique] = field(default_factory=list)
    kill_chain_phase: str = ""
    severity: str = ""
    description: str = ""


class AttackMapper:
    """MITRE ATT&CK映射器"""

    # 战术阶段
    TACTICS = [
        "reconnaissance",        # 侦察
        "resource_development",  # 资源开发
        "initial_access",        # 初始访问
        "execution",             # 执行
        "persistence",           # 持久化
        "privilege_escalation",  # 权限提升
        "defense_evasion",       # 防御规避
        "credential_access",     # 凭据访问
        "discovery",             # 发现
        "lateral_movement",      # 横向移动
        "collection",            # 收集
        "command_and_control",   # 命令与控制
        "exfiltration",          # 数据渗出
        "impact",                # 影响
    ]

    # 漏洞类型到ATT&CK技术的映射
    VULN_TO_TECHNIQUES = {
        "sql_injection": {
            "techniques": ["T1190", "T1110"],
            "kill_chain": "exploitation",
            "description": "通过SQL注入获取数据库访问权限",
        },
        "xss": {
            "techniques": ["T1059.007", "T1189"],
            "kill_chain": "exploitation",
            "description": "跨站脚本执行恶意JavaScript",
        },
        "rce": {
            "techniques": ["T1203", "T1059"],
            "kill_chain": "exploitation",
            "description": "远程代码执行",
        },
        "ssrf": {
            "techniques": ["T1190", "T1046"],
            "kill_chain": "reconnaissance",
            "description": "服务器端请求伪造进行内网探测",
        },
        "lfi": {
            "techniques": ["T1005", "T1213"],
            "kill_chain": "collection",
            "description": "本地文件包含读取敏感文件",
        },
        "path_traversal": {
            "techniques": ["T1005"],
            "kill_chain": "collection",
            "description": "路径遍历读取任意文件",
        },
        "command_injection": {
            "techniques": ["T1059", "T1203"],
            "kill_chain": "execution",
            "description": "命令注入执行系统命令",
        },
        "authentication_bypass": {
            "techniques": ["T1078", "T1110"],
            "kill_chain": "initial_access",
            "description": "认证绕过获取未授权访问",
        },
        "privilege_escalation": {
            "techniques": ["T1068", "T1548"],
            "kill_chain": "privilege_escalation",
            "description": "权限提升获取更高权限",
        },
        "csrf": {
            "techniques": ["T1189", "T1059.007"],
            "kill_chain": "initial_access",
            "description": "跨站请求伪造诱导用户执行操作",
        },
        "deserialization": {
            "techniques": ["T1203", "T1059"],
            "kill_chain": "execution",
            "description": "不安全反序列化执行任意代码",
        },
        "xxe": {
            "techniques": ["T1005", "T1190"],
            "kill_chain": "exploitation",
            "description": "XML外部实体注入读取文件或SSRF",
        },
        "file_upload": {
            "techniques": ["T1505.003", "T1190"],
            "kill_chain": "persistence",
            "description": "文件上传WebShell持久化访问",
        },
        "information_disclosure": {
            "techniques": ["T1592", "T1213"],
            "kill_chain": "reconnaissance",
            "description": "信息泄露收集敏感数据",
        },
        "open_redirect": {
            "techniques": ["T1189", "T1090"],
            "kill_chain": "initial_access",
            "description": "开放重定向用于钓鱼和流量转发",
        },
        "weak_password": {
            "techniques": ["T1110", "T1078"],
            "kill_chain": "credential_access",
            "description": "弱密码暴力破解",
        },
        "default_credentials": {
            "techniques": ["T1078.001", "T1110"],
            "kill_chain": "initial_access",
            "description": "默认凭据直接登录",
        },
        "misconfiguration": {
            "techniques": ["T1078", "T1211"],
            "kill_chain": "initial_access",
            "description": "安全配置错误",
        },
        "outdated_component": {
            "techniques": ["T1190", "T1203"],
            "kill_chain": "exploitation",
            "description": "使用含已知漏洞的组件",
        },
        "exposed_panel": {
            "techniques": ["T1078", "T1190"],
            "kill_chain": "initial_access",
            "description": "管理面板暴露",
        },
        "hardcoded_credentials": {
            "techniques": ["T1552.001", "T1078"],
            "kill_chain": "credential_access",
            "description": "硬编码凭据泄露",
        },
        "ssl_tls": {
            "techniques": ["T1573", "T1040"],
            "kill_chain": "defense_evasion",
            "description": "SSL/TLS配置问题",
        },
    }

    # ATT&CK技术详细信息
    TECHNIQUE_DETAILS = {
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "tactic": "initial_access",
            "description": "利用面向公众的应用程序漏洞获取初始访问",
            "platforms": ["Windows", "Linux", "macOS", "SaaS"],
            "mitigations": ["M1051", "M1048", "M1016"],
            "detections": ["监控异常的Web请求", "检测利用尝试的WAF日志"],
        },
        "T1059": {
            "name": "Command and Scripting Interpreter",
            "tactic": "execution",
            "description": "通过命令和脚本解释器执行代码",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1038", "M1026"],
            "detections": ["监控异常进程创建", "检测可疑命令行参数"],
        },
        "T1059.007": {
            "name": "JavaScript",
            "tactic": "execution",
            "description": "通过JavaScript执行代码",
            "platforms": ["Windows", "Linux", "macOS", "SaaS"],
            "mitigations": ["M1038"],
            "detections": ["监控浏览器异常行为", "检测恶意JS"],
        },
        "T1189": {
            "name": "Drive-by Compromise",
            "tactic": "initial_access",
            "description": "路过式攻击，通过访问恶意网站获取访问",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1051", "M1048"],
            "detections": ["监控可疑网络流量", "检测恶意重定向"],
        },
        "T1203": {
            "name": "Exploitation for Client Execution",
            "tactic": "execution",
            "description": "利用客户端漏洞执行代码",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1051", "M1048"],
            "detections": ["监控异常进程", "检测利用尝试"],
        },
        "T1046": {
            "name": "Network Service Scanning",
            "tactic": "discovery",
            "description": "扫描网络服务获取信息",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1037"],
            "detections": ["监控端口扫描行为", "检测异常网络连接"],
        },
        "T1005": {
            "name": "Data from Local System",
            "tactic": "collection",
            "description": "从本地系统收集数据",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1041"],
            "detections": ["监控文件访问", "检测敏感文件读取"],
        },
        "T1213": {
            "name": "Data from Information Repositories",
            "tactic": "collection",
            "description": "从信息库收集数据",
            "platforms": ["Windows", "Linux", "macOS", "SaaS"],
            "mitigations": ["M1041"],
            "detections": ["监控数据库查询", "检测异常数据访问"],
        },
        "T1078": {
            "name": "Valid Accounts",
            "tactic": "initial_access",
            "description": "使用有效账户获取访问",
            "platforms": ["Windows", "Linux", "macOS", "SaaS"],
            "mitigations": ["M1032", "M1027"],
            "detections": ["监控异常登录", "检测可疑账户使用"],
        },
        "T1078.001": {
            "name": "Default Accounts",
            "tactic": "initial_access",
            "description": "使用默认账户",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1027"],
            "detections": ["监控默认账户登录"],
        },
        "T1110": {
            "name": "Brute Force",
            "tactic": "credential_access",
            "description": "暴力破解凭据",
            "platforms": ["Windows", "Linux", "macOS", "SaaS"],
            "mitigations": ["M1032", "M1027", "M1036"],
            "detections": ["监控失败登录尝试", "检测密码喷洒"],
        },
        "T1068": {
            "name": "Exploitation for Privilege Escalation",
            "tactic": "privilege_escalation",
            "description": "利用漏洞提升权限",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1051", "M1048"],
            "detections": ["监控权限变更", "检测提权尝试"],
        },
        "T1548": {
            "name": "Abuse Elevation Control Mechanism",
            "tactic": "privilege_escalation",
            "description": "滥用权限提升控制机制",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1038", "M1026"],
            "detections": ["监控UAC/SUDO使用", "检测权限提升"],
        },
        "T1505.003": {
            "name": "Web Shell",
            "tactic": "persistence",
            "description": "通过WebShell持久化",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1051", "M1041"],
            "detections": ["监控可疑Web文件", "检测异常Web请求"],
        },
        "T1592": {
            "name": "Gather Victim Host Information",
            "tactic": "reconnaissance",
            "description": "收集受害者主机信息",
            "platforms": ["PRE"],
            "mitigations": ["M1056"],
            "detections": ["监控信息收集行为"],
        },
        "T1090": {
            "name": "Proxy",
            "tactic": "command_and_control",
            "description": "使用代理进行C2通信",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1037"],
            "detections": ["监控代理使用", "检测异常网络流量"],
        },
        "T1552.001": {
            "name": "Credentials In Files",
            "tactic": "credential_access",
            "description": "从文件中获取凭据",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1027"],
            "detections": ["监控敏感文件访问", "检测凭据搜索"],
        },
        "T1573": {
            "name": "Encrypted Channel",
            "tactic": "command_and_control",
            "description": "使用加密通道通信",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1037"],
            "detections": ["监控加密流量", "检测可疑TLS连接"],
        },
        "T1040": {
            "name": "Network Sniffing",
            "tactic": "credential_access",
            "description": "网络嗅探获取凭据",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1041", "M1032"],
            "detections": ["监控网卡混杂模式", "检测嗅探工具"],
        },
        "T1211": {
            "name": "Exploitation for Defense Evasion",
            "tactic": "defense_evasion",
            "description": "利用漏洞规避防御",
            "platforms": ["Windows", "Linux", "macOS"],
            "mitigations": ["M1051"],
            "detections": ["监控防御绕过行为"],
        },
    }

    def __init__(self):
        pass

    def map_vulnerability(self, vulnerability_type: str) -> Optional[AttackMapping]:
        """
        将漏洞类型映射到ATT&CK

        Args:
            vulnerability_type: 漏洞类型

        Returns:
            AttackMapping映射结果
        """
        vuln_info = self.VULN_TO_TECHNIQUES.get(vulnerability_type.lower())
        if not vuln_info:
            return None

        mapping = AttackMapping(
            vulnerability_type=vulnerability_type,
            kill_chain_phase=vuln_info.get("kill_chain", ""),
            description=vuln_info.get("description", ""),
        )

        for tech_id in vuln_info.get("techniques", []):
            tech = self._get_technique(tech_id)
            if tech:
                mapping.techniques.append(tech)

        return mapping

    def _get_technique(self, technique_id: str) -> Optional[ATTCTechnique]:
        """获取技术详情"""
        details = self.TECHNIQUE_DETAILS.get(technique_id)
        if not details:
            return ATTCTechnique(technique_id=technique_id, name=technique_id)

        return ATTCTechnique(
            technique_id=technique_id,
            name=details.get("name", ""),
            tactic=details.get("tactic", ""),
            description=details.get("description", ""),
            platforms=details.get("platforms", []),
            mitigations=details.get("mitigations", []),
            detections=details.get("detections", []),
            examples=details.get("examples", []),
        )

    def map_batch(self, vulnerability_types: List[str]) -> List[AttackMapping]:
        """批量映射漏洞类型"""
        results = []
        for vtype in vulnerability_types:
            mapping = self.map_vulnerability(vtype)
            if mapping:
                results.append(mapping)
        return results

    def get_attack_chain(self, vulnerability_types: List[str]) -> List[Dict]:
        """
        生成攻击链（按Kill Chain阶段排序）

        Args:
            vulnerability_types: 漏洞类型列表

        Returns:
            攻击链阶段列表
        """
        phase_order = [
            "reconnaissance", "initial_access", "execution",
            "persistence", "privilege_escalation", "defense_evasion",
            "credential_access", "discovery", "lateral_movement",
            "collection", "command_and_control", "exfiltration", "impact",
        ]

        mappings = self.map_batch(vulnerability_types)

        # 按阶段分组
        chain = {}
        for mapping in mappings:
            phase = mapping.kill_chain_phase
            if phase not in chain:
                chain[phase] = []
            chain[phase].append({
                "vulnerability_type": mapping.vulnerability_type,
                "description": mapping.description,
                "techniques": [
                    {"id": t.technique_id, "name": t.name}
                    for t in mapping.techniques
                ],
            })

        # 按顺序输出
        ordered_chain = []
        for phase in phase_order:
            if phase in chain:
                ordered_chain.append({
                    "phase": phase,
                    "attacks": chain[phase],
                })

        return ordered_chain

    def get_tactic_name(self, tactic: str) -> str:
        """获取战术中文名"""
        names = {
            "reconnaissance": "侦察",
            "resource_development": "资源开发",
            "initial_access": "初始访问",
            "execution": "执行",
            "persistence": "持久化",
            "privilege_escalation": "权限提升",
            "defense_evasion": "防御规避",
            "credential_access": "凭据访问",
            "discovery": "发现",
            "lateral_movement": "横向移动",
            "collection": "收集",
            "command_and_control": "命令与控制",
            "exfiltration": "数据渗出",
            "impact": "影响",
        }
        return names.get(tactic, tactic)

    def get_all_vuln_types(self) -> List[str]:
        """获取所有支持的漏洞类型"""
        return list(self.VULN_TO_TECHNIQUES.keys())

    def get_technique_details(self, technique_id: str) -> Optional[ATTCTechnique]:
        """获取技术详情"""
        return self._get_technique(technique_id)
