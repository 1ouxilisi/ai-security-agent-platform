#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
workflow/templates.py — Round 7 新增：8 个预定义 DAG 工作流模板。

每个模板是一个字典，包含：
    id / name / description / scenario / steps(DAG 步骤定义) / parameters / expected_output

步骤定义字段：
    step_id / name / description / action_type / action_params / depends_on /
    condition / on_failure / retry_count / retry_delay / timeout

说明：
    - action_type 统一使用 "tool_call"（防御/评估视角，只做检测不做利用）
    - action_params 中使用 {target} 占位符，运行时由实例创建阶段替换
    - depends_on 形成 DAG 依赖，由 DAGWorkflowEngine 拓扑排序后并行执行
    - 本模块仅用于授权的安全评估与合规检查，请勿用于非法用途
"""
from typing import Any, Dict, List, Optional


# ============ 工具调用参数快捷构造 ============
def _tool(tool_name: str, **params) -> Dict[str, Any]:
    """构造 tool_call 类型的动作参数。"""
    p = {"tool": tool_name}
    p.update(params)
    return p


def _step(step_id: str, name: str, tool: str, depends_on: Optional[List[str]] = None,
          description: str = "", condition: Optional[str] = None,
          on_failure: str = "continue", retry_count: int = 1,
          extra_params: Optional[Dict[str, Any]] = None,
          action_type: str = "tool_call") -> Dict[str, Any]:
    """便捷构造一个步骤定义。"""
    params = _tool(tool, **(extra_params or {}))
    params.setdefault("target", "{target}")
    return {
        "step_id": step_id,
        "name": name,
        "description": description,
        "action_type": action_type,
        "action_params": params,
        "depends_on": depends_on or [],
        "condition": condition,
        "on_failure": on_failure,
        "retry_count": retry_count,
        "retry_delay": 2.0,
        "timeout": 600,
    }


# ============ 模板 1：完整渗透测试 ============
_TPL_PENTEST_FULL = {
    "id": "pentest_full",
    "name": "完整渗透测试",
    "description": "面向授权目标的完整渗透测试：信息收集→端口扫描→服务识别→Web/服务漏洞扫描→漏洞验证→风险评估→报告",
    "scenario": "external_pentest",
    "estimated_minutes": 60,
    "parameters": {
        "target": {"type": "string", "required": True, "description": "目标域名或IP"},
        "scan_depth": {"type": "enum", "values": ["quick", "standard", "deep"], "default": "standard"},
    },
    "expected_output": "完整渗透测试报告，含漏洞清单、风险评分、修复建议",
    "steps": [
        _step("whois", "WHOIS信息收集", "whois_lookup", [], "查询目标域名注册信息"),
        _step("dns", "DNS解析", "dns_lookup", [], "解析目标DNS记录"),
        _step("subdomain", "子域名枚举", "subdomain_enum", [], "枚举目标子域名"),
        _step("port_scan", "端口扫描", "port_scan",
              depends_on=["whois", "dns", "subdomain"],
              description="TCP端口与服务发现",
              extra_params={"ports": "1-10000"}),
        _step("service_id", "服务识别", "service_fingerprint",
              depends_on=["port_scan"],
              description="识别端口对应服务与版本"),
        _step("web_vuln", "Web漏洞扫描", "web_vuln_scan",
              depends_on=["port_scan"],
              description="OWASP Top 10 Web漏洞检测（仅检测）",
              condition="steps.port_scan.result.open_ports",
              extra_params={"url": "http://{target}"}),
        _step("service_vuln", "服务漏洞扫描", "service_vuln_scan",
              depends_on=["service_id"],
              description="基于服务版本的CVE漏洞检测",
              extra_params={"cve_db": "local"}),
        _step("vuln_verify", "漏洞验证", "vuln_verify",
              depends_on=["web_vuln", "service_vuln"],
              description="对发现的漏洞进行无害验证（不利用）"),
        _step("risk_assess", "风险评估", "risk_scoring",
              depends_on=["vuln_verify"],
              description="综合风险评分与分级"),
        _step("report", "报告生成", "report_generate",
              depends_on=["risk_assess"],
              description="生成渗透测试报告",
              action_type="script",
              extra_params={"report_type": "pentest_full"}),
    ],
}

# ============ 模板 2：Web应用安全测试 ============
_TPL_WEB_SECURITY = {
    "id": "web_security",
    "name": "Web应用安全测试",
    "description": "针对Web应用的专项安全测试：爬取→敏感路径→SQL注入/XSS/CSRF/上传/认证/安全头→验证→报告",
    "scenario": "web_app_testing",
    "estimated_minutes": 45,
    "parameters": {
        "target": {"type": "string", "required": True, "description": "目标URL，如 https://example.com"},
    },
    "expected_output": "Web应用安全测试报告，含漏洞清单与严重程度分级",
    "steps": [
        _step("crawl", "URL爬取", "web_crawler", [], "爬取站点URL结构",
              extra_params={"url": "{target}", "max_pages": 50}),
        _step("sensitive_path", "敏感路径探测", "path_bruteforce",
              depends_on=["crawl"], description="探测备份文件、配置文件、管理后台等敏感路径"),
        _step("sqli", "SQL注入扫描", "sqli_scan",
              depends_on=["crawl"], description="SQL注入检测（仅检测payload）"),
        _step("xss", "XSS扫描", "xss_scan",
              depends_on=["crawl"], description="反射型/存储型XSS检测"),
        _step("csrf", "CSRF检测", "csrf_check",
              depends_on=["crawl"], description="表单与接口CSRF Token检测"),
        _step("upload", "文件上传检测", "upload_scan",
              depends_on=["crawl"], description="上传点文件类型校验检测"),
        _step("auth_test", "认证测试", "auth_tester",
              depends_on=["crawl"], description="会话管理、弱认证、密码策略测试"),
        _step("security_headers", "安全头检查", "security_headers",
              depends_on=["crawl"], description="CSP/HSTS/X-Frame-Options等安全响应头检查"),
        _step("vuln_verify", "漏洞验证", "vuln_verify",
              depends_on=["sqli", "xss", "csrf", "upload", "auth_test", "security_headers"],
              description="对发现的漏洞进行无害复核"),
        _step("report", "报告生成", "report_generate",
              depends_on=["vuln_verify", "sensitive_path"],
              description="生成Web安全测试报告",
              action_type="script"),
    ],
}

# ============ 模板 3：移动应用安全测试 ============
_TPL_MOBILE_SECURITY = {
    "id": "mobile_security",
    "name": "移动应用安全测试",
    "description": "Android APK 静态安全测试：结构解析→权限分析→组件暴露→硬编码密钥→不安全通信→风险评分→报告",
    "scenario": "mobile_app_testing",
    "estimated_minutes": 20,
    "parameters": {
        "target": {"type": "string", "required": True, "description": "APK文件路径或应用包名"},
    },
    "expected_output": "移动应用安全评估报告",
    "steps": [
        _step("apk_parse", "APK结构解析", "apk_parser", [], "解析APK包结构、Manifest、组件清单",
              extra_params={"apk_path": "{target}"}),
        _step("permission", "权限分析", "permission_analyzer",
              depends_on=["apk_parse"], description="分析危险权限申请"),
        _step("component", "组件暴露检测", "component_detector",
              depends_on=["apk_parse"], description="检测Activity/Service/Receiver/Provider暴露"),
        _step("hardcoded", "硬编码密钥扫描", "hardcoded_scan",
              depends_on=["apk_parse"], description="扫描硬编码密钥、Token、口令"),
        _step("insecure_comm", "不安全通信检测", "tls_check",
              depends_on=["apk_parse"], description="检测明文HTTP、证书校验绕过"),
        _step("risk_score", "风险评分", "risk_scoring",
              depends_on=["permission", "component", "hardcoded", "insecure_comm"],
              description="综合移动应用风险评分"),
        _step("report", "报告生成", "report_generate",
              depends_on=["risk_score"], description="生成移动安全报告", action_type="script"),
    ],
}

# ============ 模板 4：内网安全评估 ============
_TPL_INTERNAL = {
    "id": "internal_assessment",
    "name": "内网安全评估",
    "description": "授权内网环境评估：主机发现→端口扫描→服务枚举→弱口令→未授权访问→横向移动风险→凭据审计→报告",
    "scenario": "internal_assessment",
    "estimated_minutes": 90,
    "parameters": {
        "target": {"type": "string", "required": True, "description": "内网网段，如 192.168.1.0/24"},
    },
    "expected_output": "内网安全评估报告",
    "steps": [
        _step("host_disc", "主机发现", "host_discovery", [], "ICMP/TCP主机存活探测",
              extra_params={"cidr": "{target}"}),
        _step("port_scan", "端口扫描", "port_scan",
              depends_on=["host_disc"], description="存活主机端口扫描"),
        _step("service_enum", "服务枚举", "service_enum",
              depends_on=["port_scan"], description="服务版本与banner枚举"),
        _step("weak_pwd", "弱口令检测", "weak_password_scan",
              depends_on=["service_enum"], description="常见服务弱口令检测（不爆破，仅策略评估）"),
        _step("unauth", "未授权访问检测", "unauth_access_scan",
              depends_on=["service_enum"], description="Redis/Mongo/ES等未授权访问检测"),
        _step("lateral", "横向移动风险评估", "lateral_risk",
              depends_on=["weak_pwd", "unauth"], description="横向移动路径风险分析"),
        _step("cred_audit", "凭据审计", "credential_audit",
              depends_on=["weak_pwd"], description="凭据强度与复用风险审计"),
        _step("report", "报告生成", "report_generate",
              depends_on=["lateral", "cred_audit"], description="生成内网评估报告", action_type="script"),
    ],
}

# ============ 模板 5：域安全审计 ============
_TPL_DOMAIN = {
    "id": "domain_audit",
    "name": "域安全审计",
    "description": "Active Directory 安全审计：DC发现→AD枚举→Kerberoasting/AS-REP→PtH风险→密码策略→DC审计→报告",
    "scenario": "domain_audit",
    "estimated_minutes": 60,
    "parameters": {
        "target": {"type": "string", "required": True, "description": "域名或DC地址，如 corp.local"},
    },
    "expected_output": "域安全审计报告",
    "steps": [
        _step("dc_find", "DC发现", "dc_discovery", [], "定位域控",
              extra_params={"domain": "{target}"}),
        _step("ad_enum", "AD信息枚举", "ad_enumeration",
              depends_on=["dc_find"], description="枚举用户、组、OU、GPO"),
        _step("kerberoast", "Kerberoasting检测", "kerberoast_detect",
              depends_on=["ad_enum"], description="检测可Kerberoasting的SPN账户（仅检测，不导出哈希）"),
        _step("asrep", "AS-REP Roasting检测", "asrep_detect",
              depends_on=["ad_enum"], description="检测禁用预认证账户"),
        _step("pth", "PtH风险评估", "pth_risk",
              depends_on=["kerberoast", "asrep"], description="Pass-the-Hash攻击面评估"),
        _step("pwd_policy", "密码策略审计", "password_policy_audit",
              depends_on=["ad_enum"], description="审计域密码策略与锁定策略"),
        _step("dc_audit", "DC安全审计", "dc_security_audit",
              depends_on=["pth", "pwd_policy"], description="域控配置与日志审计"),
        _step("report", "报告生成", "report_generate",
              depends_on=["dc_audit"], description="生成域安全审计报告", action_type="script"),
    ],
}

# ============ 模板 6：AI智能体安全评估 ============
_TPL_AI_AGENT = {
    "id": "ai_agent_security",
    "name": "AI智能体安全评估",
    "description": "AI Agent 安全评估：提示注入(16规则)→越狱(14规则)→Agent配置审计(8项)→LLM API安全→风险评分→报告",
    "scenario": "ai_agent_security",
    "estimated_minutes": 30,
    "parameters": {
        "target": {"type": "string", "required": True, "description": "Agent API地址或服务标识"},
    },
    "expected_output": "AI智能体安全评估报告",
    "steps": [
        _step("prompt_inject", "提示注入测试", "prompt_injection_test",
              [], "16条提示注入规则检测"),
        _step("jailbreak", "越狱测试", "jailbreak_test",
              [], "14条越狱规则检测"),
        _step("agent_config", "Agent配置审计", "agent_config_audit",
              depends_on=["prompt_inject"], description="8项Agent配置项审计"),
        _step("llm_api", "LLM API安全检测", "llm_api_security",
              depends_on=["agent_config"], description="LLM API鉴权、速率、越权检测"),
        _step("risk_score", "风险评分", "risk_scoring",
              depends_on=["prompt_inject", "jailbreak", "agent_config", "llm_api"],
              description="AI Agent 风险综合评分"),
        _step("report", "报告生成", "report_generate",
              depends_on=["risk_score"], description="生成AI安全报告", action_type="script"),
    ],
}

# ============ 模板 7：区块链安全评估 ============
_TPL_BLOCKCHAIN = {
    "id": "blockchain_security",
    "name": "区块链安全评估",
    "description": "区块链安全评估：智能合约静态分析(14类漏洞)→钱包安全→交易安全→风险评分→报告",
    "scenario": "blockchain_security",
    "estimated_minutes": 25,
    "parameters": {
        "target": {"type": "string", "required": True, "description": "合约地址或合约源码路径"},
    },
    "expected_output": "区块链安全评估报告",
    "steps": [
        _step("contract_sa", "智能合约静态分析", "contract_static_analyzer",
              [], "14类合约漏洞静态分析（重入/溢出/访问控制等）",
              extra_params={"contract": "{target}"}),
        _step("wallet", "钱包安全检测", "wallet_security_check",
              depends_on=["contract_sa"], description="钱包私钥管理与签名流程检测"),
        _step("tx", "交易安全检测", "transaction_security_check",
              depends_on=["contract_sa"], description="交易路由、前置校验、滑点检测"),
        _step("risk_score", "风险评分", "risk_scoring",
              depends_on=["wallet", "tx"], description="区块链风险综合评分"),
        _step("report", "报告生成", "report_generate",
              depends_on=["risk_score"], description="生成区块链安全报告", action_type="script"),
    ],
}

# ============ 模板 8：合规审计 ============
_TPL_COMPLIANCE = {
    "id": "compliance_audit",
    "name": "合规审计",
    "description": "合规基线审计：资产发现→安全基线(26项)→漏洞扫描→漏洞验证→等保2.0/ISO27001/PCI-DSS→合规报告",
    "scenario": "compliance_audit",
    "estimated_minutes": 75,
    "parameters": {
        "target": {"type": "string", "required": True, "description": "目标资产范围（IP段或域名）"},
        "standard": {"type": "enum", "values": ["dengbao2", "iso27001", "pci_dss", "all"], "default": "all"},
    },
    "expected_output": "合规审计报告，含不符合项清单与整改建议",
    "steps": [
        _step("asset_disc", "资产发现", "asset_discovery", [], "发现目标范围内资产"),
        _step("baseline", "安全基线检查", "baseline_check",
              depends_on=["asset_disc"], description="26项安全基线检查"),
        _step("vuln_scan", "漏洞扫描", "vuln_scan",
              depends_on=["asset_disc"], description="资产漏洞扫描"),
        _step("vuln_verify", "漏洞验证", "vuln_verify",
              depends_on=["vuln_scan"], description="对高危漏洞进行无害验证"),
        _step("dengbao", "等保2.0检查", "dengbao2_check",
              depends_on=["baseline"], description="等保2.0控制项核查"),
        _step("iso", "ISO27001检查", "iso27001_check",
              depends_on=["baseline"], description="ISO27001控制项核查"),
        _step("pci", "PCI-DSS检查", "pci_dss_check",
              depends_on=["baseline"], description="PCI-DSS控制项核查"),
        _step("report", "合规报告生成", "report_generate",
              depends_on=["vuln_verify", "dengbao", "iso", "pci"],
              description="生成合规审计报告", action_type="script"),
    ],
}


# ============ 模板 9：API 安全测试 ============
_TPL_API_SECURITY = {
    "id": "api_security_test",
    "name": "API安全测试",
    "description": "面向API的专项安全测试：OpenAPI解析→端点发现→参数提取→认证分析→参数fuzz→逻辑漏洞测试→风险评估→报告",
    "scenario": "api_security",
    "estimated_minutes": 45,
    "parameters": {
        "openapi_url": {"type": "string", "default": "", "description": "OpenAPI 规范 URL（或使用 openapi_content）"},
        "auth_token": {"type": "string", "default": "", "description": "授权测试用 Bearer Token"},
        "fuzz_intensity": {"type": "enum", "values": ["low", "medium", "high"], "default": "medium"},
    },
    "expected_output": "API安全测试报告，包含端点列表/漏洞详情/风险评分/修复建议",
    "steps": [
        _step("openapi_parse", "OpenAPI解析", "openapi_parser",
              [], "解析 OpenAPI 3.0/3.1 规范（JSON/YAML）",
              action_type="script"),
        _step("endpoint_discovery", "端点发现与分类", "endpoint_discovery",
              depends_on=["openapi_parse"],
              description="枚举全部端点，按 public/authenticated/admin/user 分类",
              action_type="script"),
        _step("param_extraction", "参数提取", "param_extraction",
              depends_on=["endpoint_discovery"],
              description="提取路径/查询/请求头/Cookie/请求体字段",
              action_type="script"),
        _step("auth_analysis", "认证方式分析", "auth_analysis",
              depends_on=["openapi_parse"],
              description="识别 API Key / Bearer / Basic / OAuth2 / Cookie 认证方式",
              action_type="script"),
        _step("param_fuzz", "参数Fuzz测试", "param_fuzzer",
              depends_on=["param_extraction", "auth_analysis"],
              description="12 类 payload（SQLi/XSS/命令注入/路径穿越/SSRF/XXE 等）参数 fuzz，仅检测不利用",
              extra_params={"intensity": "{fuzz_intensity}"},
              action_type="script"),
        _step("logic_test", "逻辑漏洞测试", "logic_tester",
              depends_on=["endpoint_discovery", "auth_analysis"],
              description="越权/认证绕过/IDOR/批量赋值/CSRF/竞争条件等逻辑测试",
              action_type="script"),
        _step("risk_assessment", "风险评估", "risk_scoring",
              depends_on=["param_fuzz", "logic_test"],
              description="合并 fuzz 与逻辑测试结果，统一风险评级与去重",
              action_type="script"),
        _step("report_gen", "报告生成", "report_generate",
              depends_on=["risk_assessment"],
              description="生成 API 安全测试报告（JSON/HTML）",
              action_type="script"),
    ],
}


# ============ 模板注册表 ============
WORKFLOW_TEMPLATES_V7: Dict[str, Dict[str, Any]] = {
    t["id"]: t for t in [
        _TPL_PENTEST_FULL,
        _TPL_WEB_SECURITY,
        _TPL_MOBILE_SECURITY,
        _TPL_INTERNAL,
        _TPL_DOMAIN,
        _TPL_AI_AGENT,
        _TPL_BLOCKCHAIN,
        _TPL_COMPLIANCE,
        _TPL_API_SECURITY,
    ]
}


def list_templates() -> List[Dict[str, Any]]:
    """列出所有模板概要（不含完整步骤，避免体积过大）。"""
    out = []
    for t in WORKFLOW_TEMPLATES_V7.values():
        out.append({
            "id": t["id"],
            "name": t["name"],
            "description": t["description"],
            "scenario": t["scenario"],
            "estimated_minutes": t.get("estimated_minutes"),
            "steps_count": len(t["steps"]),
            "parameters": t.get("parameters", {}),
            "expected_output": t.get("expected_output"),
        })
    return out


def get_template(template_id: str) -> Optional[Dict[str, Any]]:
    """获取模板完整定义（含步骤DAG）。"""
    return WORKFLOW_TEMPLATES_V7.get(template_id)


def instantiate_template(template_id: str, target: str,
                        params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    实例化模板：深拷贝步骤定义，替换 {target} 等占位符。
    返回可直接交给 DAGWorkflowEngine.create_instance 的 workflow_def。
    """
    import copy
    tpl = WORKFLOW_TEMPLATES_V7.get(template_id)
    if not tpl:
        raise KeyError(f"未知模板: {template_id}，可用: {list(WORKFLOW_TEMPLATES_V7.keys())}")

    params = params or {}
    params.setdefault("target", target)

    tpl_copy = copy.deepcopy(tpl)

    def repl(v):
        if isinstance(v, str):
            v = v.replace("{target}", target).replace("{TARGET}", target)
            for k, val in params.items():
                v = v.replace("{%s}" % k, str(val))
            return v
        if isinstance(v, dict):
            return {kk: repl(vv) for kk, vv in v.items()}
        if isinstance(v, list):
            return [repl(x) for x in v]
        return v

    for s in tpl_copy["steps"]:
        s["action_params"] = repl(s.get("action_params") or s.get("parameters") or {})
        if isinstance(s.get("name"), str):
            s["name"] = repl(s["name"])
        if isinstance(s.get("description"), str):
            s["description"] = repl(s["description"])

    return {
        "workflow_id": tpl_copy["id"],
        "name": tpl_copy["name"],
        "description": tpl_copy["description"],
        "target": target,
        "scenario": tpl_copy.get("scenario"),
        "steps": tpl_copy["steps"],
        "params": params,
    }


__all__ = [
    "WORKFLOW_TEMPLATES_V7",
    "list_templates",
    "get_template",
    "instantiate_template",
]
