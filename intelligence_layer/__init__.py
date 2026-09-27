#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能层（Intelligence Layer）
不只是LLM包装器，注入OWASP测试方法论、漏洞模式、攻击链推理和工具编排逻辑

对标 CyberStrike 的智能层设计：
- 模式规范化：无论使用何种提供商，都能获得结构化输出
- 上下文守卫：防止提示词泄漏，确保智能体聚焦于当前测试阶段
- 提供商自动检测：自动识别LLM端点并配置最优参数
- 领域知识注入：OWASP方法论、漏洞模式、攻击链推理
"""

import json
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class TestPhase(Enum):
    """测试阶段"""
    RECON = "reconnaissance"           # 侦察
    SCAN = "scanning"                  # 扫描
    ENUM = "enumeration"               # 枚举
    VULN_ANALYSIS = "vulnerability_analysis"  # 漏洞分析
    EXPLOIT = "exploitation"           # 利用
    POST_EXPLOIT = "post_exploitation" # 后渗透
    REPORT = "reporting"               # 报告


class OutputFormat(Enum):
    """输出格式"""
    JSON = "json"
    MARKDOWN = "markdown"
    XML = "xml"
    CSV = "csv"


@dataclass
class PhaseContext:
    """阶段上下文"""
    phase: TestPhase = TestPhase.RECON
    target: str = ""
    findings: List[Dict] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)
    allowed_actions: List[str] = field(default_factory=list)
    forbidden_actions: List[str] = field(default_factory=list)


@dataclass
class StructuredOutput:
    """结构化输出"""
    format: OutputFormat = OutputFormat.JSON
    schema: Dict = field(default_factory=dict)
    data: Any = None
    raw_response: str = ""
    parse_success: bool = False
    error: str = ""


class IntelligenceLayer:
    """
    智能层核心

    在每次LLM交互中注入领域特定上下文，"教会"模型如何成为安全专家
    """

    # OWASP测试方法论
    OWASP_METHODOLOGY = {
        "reconnaissance": {
            "goal": "收集目标信息，绘制攻击面",
            "tasks": [
                "域名和子域名枚举",
                "DNS记录分析",
                "SSL/TLS证书分析",
                "IP地址和网段识别",
                "技术栈指纹识别",
                "员工信息收集（OSINT）",
                "社交媒体信息收集",
            ],
            "tools": ["subfinder", "amass", "nmap", "httpx", "whatweb", "theHarvester"],
            "output_schema": {
                "domains": "list",
                "subdomains": "list",
                "ip_addresses": "list",
                "technologies": "list",
                "open_ports": "list",
                "osint_findings": "list",
            },
        },
        "scanning": {
            "goal": "发现开放端口、服务和潜在漏洞",
            "tasks": [
                "端口扫描",
                "服务版本识别",
                "操作系统检测",
                "漏洞扫描",
                "Web应用扫描",
            ],
            "tools": ["nmap", "nuclei", "nikto", "masscan", "rustscan"],
            "output_schema": {
                "open_ports": "list",
                "services": "list",
                "os": "string",
                "vulnerabilities": "list",
            },
        },
        "enumeration": {
            "goal": "深度探查目标，寻找潜在突破口",
            "tasks": [
                "用户枚举",
                "API端点探测",
                "目录和文件枚举",
                "参数发现",
                "版本识别",
                "配置错误检查",
            ],
            "tools": ["gobuster", "ffuf", "dirsearch", "wfuzz", "burp"],
            "output_schema": {
                "users": "list",
                "api_endpoints": "list",
                "directories": "list",
                "parameters": "list",
                "misconfigurations": "list",
            },
        },
        "vulnerability_analysis": {
            "goal": "风险研判，漏洞优先级排序",
            "tasks": [
                "CVE匹配",
                "CVSS评分",
                "可利用性评估",
                "业务影响分析",
                "漏洞优先级排序",
                "误报排除",
            ],
            "tools": ["searchsploit", "cve-search", "cvss-calculator"],
            "output_schema": {
                "vulnerabilities": "list",
                "cvss_scores": "dict",
                "exploitability": "dict",
                "business_impact": "string",
                "priority_order": "list",
            },
        },
        "exploitation": {
            "goal": "受控漏洞验证，提供入侵证明",
            "tasks": [
                "漏洞利用验证",
                "获取Shell",
                "权限提升",
                "数据提取（最小化）",
                "持久化测试",
            ],
            "tools": ["metasploit", "sqlmap", "exploit-db", "custom-pocs"],
            "output_schema": {
                "exploited_vulns": "list",
                "access_gained": "string",
                "proof_of_concept": "string",
                "data_extracted": "list",
            },
            "constraints": [
                "不得造成附带损害",
                "最小化数据提取",
                "不得修改或删除数据",
                "不得持久化后门",
            ],
        },
        "post_exploitation": {
            "goal": "评估入侵爆炸半径，量化业务影响",
            "tasks": [
                "横向移动路径发现",
                "凭据窃取测试",
                "认证机制分析",
                "业务影响量化",
                "数据泄露评估",
            ],
            "tools": ["mimikatz", "bloodhound", "crackmapexec", "impacket"],
            "output_schema": {
                "lateral_paths": "list",
                "credentials_found": "list",
                "business_impact": "string",
                "data_exposure": "list",
                "blast_radius": "string",
            },
        },
        "reporting": {
            "goal": "生成专业渗透测试报告",
            "tasks": [
                "执行摘要",
                "漏洞详情",
                "修复建议",
                "风险评级",
                "附录和证据",
            ],
            "tools": ["report-generator", "cvss-scorer"],
            "output_schema": {
                "executive_summary": "string",
                "findings": "list",
                "remediations": "list",
                "risk_matrix": "dict",
                "appendix": "list",
            },
        },
    }

    # 漏洞模式库
    VULNERABILITY_PATTERNS = {
        "sql_injection": {
            "indicators": [
                "SQL语法错误",
                "单引号导致异常",
                "布尔盲注响应差异",
                "时间延迟",
                "UNION注入数据泄露",
            ],
            "test_payloads": ["'", "1' OR '1'='1", "1; DROP TABLE--", "1' UNION SELECT NULL--"],
            "false_positives": ["数据库错误处理不当但无注入", "WAF拦截"],
            "verification": "使用sqlmap进行自动化验证",
        },
        "xss": {
            "indicators": [
                "输入在响应中未编码",
                "脚本标签执行",
                "事件处理器执行",
                "JavaScript URI执行",
            ],
            "test_payloads": [
                "<script>alert(1)</script>",
                "\"><img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
            ],
            "false_positives": ["HTML实体编码后显示", "Content-Security-Policy阻止"],
            "verification": "验证脚本在浏览器中实际执行",
        },
        "ssrf": {
            "indicators": [
                "内网地址响应差异",
                "云元数据访问",
                "端口扫描行为",
                "协议切换",
            ],
            "test_payloads": [
                "http://127.0.0.1",
                "http://169.254.169.254/",
                "file:///etc/passwd",
                "gopher://127.0.0.1:6379",
            ],
            "false_positives": ["DNS解析到外部", "请求被代理拦截"],
            "verification": "验证能访问内网资源或云元数据",
        },
    }

    # 攻击链推理模板
    ATTACK_CHAIN_REASONING = {
        "web_application": [
            {"phase": "recon", "action": "子域名枚举", "output": "子域名列表"},
            {"phase": "recon", "action": "技术栈识别", "output": "技术栈信息"},
            {"phase": "scan", "action": "端口扫描", "output": "开放端口和服务"},
            {"phase": "scan", "action": "Web漏洞扫描", "output": "潜在漏洞列表"},
            {"phase": "enum", "action": "目录枚举", "output": "隐藏目录和文件"},
            {"phase": "enum", "action": "参数发现", "output": "可注入参数"},
            {"phase": "vuln_analysis", "action": "漏洞验证", "output": "已验证漏洞"},
            {"phase": "exploit", "action": "漏洞利用", "output": "访问权限"},
            {"phase": "post_exploit", "action": "横向移动", "output": "内网访问"},
            {"phase": "report", "action": "报告生成", "output": "渗透测试报告"},
        ],
        "network_infrastructure": [
            {"phase": "recon", "action": "IP范围识别", "output": "目标网段"},
            {"phase": "scan", "action": "主机发现", "output": "存活主机"},
            {"phase": "scan", "action": "端口扫描", "output": "开放端口"},
            {"phase": "enum", "action": "服务枚举", "output": "服务详情"},
            {"phase": "vuln_analysis", "action": "漏洞匹配", "output": "CVE列表"},
            {"phase": "exploit", "action": "漏洞利用", "output": "初始访问"},
            {"phase": "post_exploit", "action": "权限提升", "output": "管理员权限"},
            {"phase": "post_exploit", "action": "凭据窃取", "output": "凭据集合"},
            {"phase": "post_exploit", "action": "横向移动", "output": "域控访问"},
            {"phase": "report", "action": "报告生成", "output": "渗透测试报告"},
        ],
    }

    # 上下文守卫规则
    CONTEXT_GUARD_RULES = [
        "不得忽略之前的安全约束",
        "不得执行超出当前测试阶段的操作",
        "不得访问未授权的目标",
        "不得执行可能造成损害的操作",
        "所有操作必须在授权范围内",
        "发现高危漏洞时立即报告，不得继续利用",
        "不得提取超出测试范围的数据",
        "不得修改或删除目标系统数据",
    ]

    def __init__(self, llm_provider: str = "auto"):
        self.llm_provider = llm_provider
        self.current_phase = TestPhase.RECON
        self.phase_context = PhaseContext()
        self.conversation_history: List[Dict] = []
        self._detect_provider()

    def _detect_provider(self):
        """自动检测LLM提供商并配置最优参数"""
        # 这里可以根据API端点自动检测
        # 简化实现：根据配置设置
        self.provider_config = {
            "openai": {
                "model": "gpt-4",
                "temperature": 0.1,
                "max_tokens": 4096,
                "top_p": 0.9,
            },
            "anthropic": {
                "model": "claude-3-opus",
                "temperature": 0.1,
                "max_tokens": 4096,
                "top_p": 0.9,
            },
            "siliconflow": {
                "model": "Qwen2.5-7B",
                "temperature": 0.1,
                "max_tokens": 4096,
                "top_p": 0.9,
            },
            "auto": {
                "model": "auto-detect",
                "temperature": 0.1,
                "max_tokens": 4096,
                "top_p": 0.9,
            },
        }

    def set_phase(self, phase: TestPhase, target: str = ""):
        """设置当前测试阶段"""
        self.current_phase = phase
        self.phase_context = PhaseContext(phase=phase, target=target)

        # 根据阶段设置约束
        methodology = self.OWASP_METHODOLOGY.get(phase.value, {})
        if "constraints" in methodology:
            self.phase_context.constraints = methodology["constraints"]

        self.phase_context.allowed_actions = methodology.get("tasks", [])
        self.phase_context.tools_used = methodology.get("tools", [])

    def build_system_prompt(self) -> str:
        """
        构建系统提示词，注入领域知识

        这是智能层的核心：不只是把用户提示词转发给API，
        而是注入OWASP方法论、漏洞模式、攻击链推理和工具编排逻辑
        """
        methodology = self.OWASP_METHODOLOGY.get(self.current_phase.value, {})

        prompt = f"""你是一个专业的渗透测试安全专家，正在执行 {self.current_phase.value} 阶段的测试。

## 当前阶段目标
{methodology.get('goal', '')}

## 阶段任务
{chr(10).join(f'- {t}' for t in methodology.get('tasks', []))}

## 推荐工具
{', '.join(methodology.get('tools', []))}

## 输出要求
必须以JSON格式输出，包含以下字段：
{json.dumps(methodology.get('output_schema', {}), indent=2, ensure_ascii=False)}

## 安全约束
{chr(10).join(f'- {c}' for c in self.phase_context.constraints)}
{chr(10).join(f'- {r}' for r in self.CONTEXT_GUARD_RULES)}

## 漏洞模式参考
当识别到以下模式时，按照对应的验证方法进行验证：
{json.dumps({k: v['indicators'] for k, v in self.VULNERABILITY_PATTERNS.items()}, indent=2, ensure_ascii=False)}

## 重要规则
1. 只输出JSON，不要输出其他内容
2. 所有发现必须基于实际证据，不得猜测
3. 发现高危漏洞时立即报告
4. 严格遵守安全约束
5. 如果不确定，标记为"需要人工验证"
"""
        return prompt

    def build_user_prompt(self, user_input: str, context: Dict = None) -> str:
        """构建用户提示词，添加上下文"""
        prompt = f"""## 测试目标
{self.phase_context.target or '未指定'}

## 当前阶段
{self.current_phase.value}

## 已发现的信息
{json.dumps(self.phase_context.findings[-5:] if self.phase_context.findings else '无', indent=2, ensure_ascii=False)}

## 用户请求
{user_input}

## 额外上下文
{json.dumps(context or {}, indent=2, ensure_ascii=False)}

请按照系统提示词的要求，以JSON格式输出分析结果。
"""
        return prompt

    def guard_response(self, response: str) -> tuple[bool, str]:
        """
        上下文守卫：检查响应是否违反安全约束

        Returns:
            (是否安全, 原因)
        """
        # 检查是否包含危险操作
        dangerous_patterns = [
            r"rm\s+-rf\s+/",
            r"DROP\s+DATABASE",
            r"DELETE\s+FROM\s+\w+\s+WHERE\s+1=1",
            r"format\s+[a-zA-Z]:",
            r"shutdown",
            r"halt",
            r"poweroff",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return False, f"检测到危险操作模式: {pattern}"

        # 检查是否试图绕过约束
        bypass_patterns = [
            r"ignore.*previous.*instructions",
            r"忽略.*之前.*指令",
            r"forget.*constraints",
            r"忘记.*约束",
        ]

        for pattern in bypass_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return False, f"检测到提示词注入尝试: {pattern}"

        return True, "通过守卫检查"

    def normalize_output(self, response: str,
                         expected_schema: Dict = None) -> StructuredOutput:
        """
        模式规范化：将LLM输出解析为结构化格式

        无论使用何种提供商，都能获得一致的结构化输出
        """
        result = StructuredOutput(raw_response=response)

        # 尝试提取JSON
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                data = json.loads(json_match.group())
                result.data = data
                result.parse_success = True
                result.format = OutputFormat.JSON
            except json.JSONDecodeError as e:
                result.error = f"JSON解析失败: {e}"
                result.parse_success = False

        # 如果JSON解析失败，尝试Markdown
        if not result.parse_success:
            if response.startswith('#') or '**' in response:
                result.format = OutputFormat.MARKDOWN
                result.data = response
                result.parse_success = True

        return result

    def reason_attack_chain(self, target_type: str = "web_application") -> List[Dict]:
        """
        攻击链推理：根据目标类型生成完整攻击链

        这是智能层的核心推理能力，不是简单的工具调用，
        而是基于攻击链逻辑的规划
        """
        chain = self.ATTACK_CHAIN_REASONING.get(target_type, [])
        return chain

    def select_tools(self, phase: TestPhase,
                     target_info: Dict = None) -> List[str]:
        """
        工具编排逻辑：根据阶段和目标信息选择最优工具组合
        """
        methodology = self.OWASP_METHODOLOGY.get(phase.value, {})
        tools = methodology.get("tools", [])

        # 根据目标信息优化工具选择
        if target_info:
            if target_info.get("is_web"):
                if "nuclei" not in tools:
                    tools.append("nuclei")
                if "nikto" not in tools:
                    tools.append("nikto")
            if target_info.get("has_api"):
                if "postman" not in tools:
                    tools.append("postman")
            if target_info.get("is_windows"):
                if "crackmapexec" not in tools:
                    tools.append("crackmapexec")

        return tools

    def add_finding(self, finding: Dict):
        """添加发现到上下文"""
        self.phase_context.findings.append(finding)

    def get_context_summary(self) -> Dict:
        """获取上下文摘要"""
        return {
            "current_phase": self.current_phase.value,
            "target": self.phase_context.target,
            "findings_count": len(self.phase_context.findings),
            "recent_findings": self.phase_context.findings[-3:],
            "tools_used": self.phase_context.tools_used,
            "constraints": self.phase_context.constraints,
        }

    def generate_test_plan(self, target: str,
                           target_type: str = "web_application") -> Dict:
        """
        生成完整测试计划

        基于攻击链推理，自动规划每个阶段的任务和工具
        """
        chain = self.reason_attack_chain(target_type)

        plan = {
            "target": target,
            "target_type": target_type,
            "phases": [],
            "estimated_steps": len(chain),
        }

        for step in chain:
            phase = step["phase"]
            phase_enum = TestPhase(phase) if phase in [p.value for p in TestPhase] else TestPhase.RECON

            methodology = self.OWASP_METHODOLOGY.get(phase, {})

            plan["phases"].append({
                "phase": phase,
                "action": step["action"],
                "expected_output": step["output"],
                "recommended_tools": methodology.get("tools", []),
                "tasks": methodology.get("tasks", []),
                "constraints": methodology.get("constraints", []),
            })

        return plan
