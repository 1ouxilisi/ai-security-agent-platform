# -*- coding: utf-8 -*-
"""
scenario_templates.py — 核心场景模板库（第16轮升级·方向1）。

预置 8 个端到端场景模板，每个模板定义：
    - 执行步骤列表
    - 步骤间依赖关系（DAG）
    - 每步调用的模块与方法（handler 键，由 workflow_engine 分发到真实检测模块）
    - 输入输出格式说明
    - 超时设置

模板可扩展：add_template / update_template / delete_template / list_templates。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 工具：构建一个步骤定义
# --------------------------------------------------------------------------- #
def _step(sid: str, name: str, handler: str, description: str = "",
          timeout: int = 60, depends_on: Optional[List[str]] = None,
          weight: float = 1.0) -> Dict[str, Any]:
    return {
        "id": sid,
        "name": name,
        "handler": handler,      # workflow_engine 中注册的真实执行函数
        "description": description,
        "timeout": timeout,
        "depends_on": list(depends_on or []),
        "weight": weight,         # 风险评分权重
    }


# --------------------------------------------------------------------------- #
# 预置 8 个场景
# --------------------------------------------------------------------------- #
BUILTIN_TEMPLATES: Dict[str, Dict[str, Any]] = {}


def _register_web_full() -> None:
    BUILTIN_TEMPLATES["web_full_assessment"] = {
        "id": "web_full_assessment",
        "name": "Web资产全面评估",
        "description": "端口扫描→服务识别→Web漏洞扫描→SSL/TLS检测→安全头检查→风险评级→报告",
        "target_types": ["ip", "domain", "url"],
        "steps": [
            _step("target_recognize", "目标识别", "target_recognize",
                  "自动识别目标类型并解析为 host/port/scheme", 10, weight=0.5),
            _step("port_scan", "端口扫描", "port_scan",
                  "真实TCP连接探测常用端口（复用 pentest.internal_tools）", 90,
                  depends_on=["target_recognize"], weight=1.2),
            _step("service_detect", "服务识别", "service_detect",
                  "对开放端口抓取Banner识别服务与版本", 60,
                  depends_on=["port_scan"], weight=1.0),
            _step("web_vuln_scan", "Web漏洞扫描", "web_vuln_scan",
                  "调用 scanner.advanced_vuln_scanner 对Web端点真实扫描", 120,
                  depends_on=["service_detect"], weight=1.5),
            _step("ssl_tls_check", "SSL/TLS检测", "ssl_tls_check",
                  "原生ssl探测证书链与协议版本", 30,
                  depends_on=["target_recognize"], weight=1.0),
            _step("security_headers", "安全头检查", "security_headers",
                  "原生HTTP请求抓取响应头并检查安全头", 30,
                  depends_on=["target_recognize"], weight=0.8),
            _step("risk_rating", "风险评级", "risk_rating",
                  "聚合各步骤结果按权重计算0-100风险分", 10,
                  depends_on=["web_vuln_scan", "ssl_tls_check", "security_headers"],
                  weight=1.0),
            _step("report", "生成报告", "generate_report",
                  "汇总为统一评估报告", 15,
                  depends_on=["risk_rating"], weight=0.3),
        ],
    }


def _register_mobile() -> None:
    BUILTIN_TEMPLATES["mobile_assessment"] = {
        "id": "mobile_assessment",
        "name": "移动应用安全评估",
        "description": "APK解析→权限分析→组件安全→代码审计→数据泄露检测→风险评级→报告",
        "target_types": ["apk"],
        "steps": [
            _step("apk_parse", "APK解析", "apk_parse",
                  "调用 mobile_security 解析APK清单", 60, weight=1.0),
            _step("permission_analysis", "权限分析", "permission_analysis",
                  "分析危险权限申请", 30, depends_on=["apk_parse"], weight=1.2),
            _step("component_security", "组件安全", "component_security",
                  "导出组件与deeplink安全检查", 30, depends_on=["apk_parse"], weight=1.0),
            _step("code_audit", "代码审计", "mobile_code_audit",
                  "SMali/字符串敏感信息审计", 60, depends_on=["apk_parse"], weight=1.3),
            _step("data_leak", "数据泄露检测", "mobile_data_leak",
                  "硬编码密钥/日志泄露检测", 30, depends_on=["code_audit"], weight=1.2),
            _step("risk_rating", "风险评级", "risk_rating",
                  "聚合评分", 10, depends_on=["data_leak"], weight=1.0),
            _step("report", "生成报告", "generate_report",
                  "汇总报告", 15, depends_on=["risk_rating"], weight=0.3),
        ],
    }


def _register_internal_pentest() -> None:
    BUILTIN_TEMPLATES["internal_pentest"] = {
        "id": "internal_pentest",
        "name": "内网渗透评估",
        "description": "主机发现→端口扫描→服务识别→漏洞扫描→弱口令检测→横向移动评估→报告",
        "target_types": ["ip", "domain"],
        "steps": [
            _step("host_discovery", "主机发现", "host_discovery",
                  "ICMP/TCP存活探测", 30, weight=1.0),
            _step("port_scan", "端口扫描", "port_scan",
                  "TCP端口探测", 90, depends_on=["host_discovery"], weight=1.2),
            _step("service_detect", "服务识别", "service_detect",
                  "Banner识别", 60, depends_on=["port_scan"], weight=1.0),
            _step("vuln_scan", "漏洞扫描", "vuln_scan",
                  "服务级漏洞匹配", 90, depends_on=["service_detect"], weight=1.5),
            _step("weak_cred", "弱口令检测", "weak_cred_detect",
                  "复用 pentest.credential_audit 评估", 60,
                  depends_on=["service_detect"], weight=1.4),
            _step("lateral_move", "横向移动评估", "lateral_move_assess",
                  "复用 pentest.lateral_movement_detection", 60,
                  depends_on=["weak_cred"], weight=1.3),
            _step("risk_rating", "风险评级", "risk_rating",
                  "聚合评分", 10, depends_on=["lateral_move"], weight=1.0),
            _step("report", "生成报告", "generate_report",
                  "汇总报告", 15, depends_on=["risk_rating"], weight=0.3),
        ],
    }


def _register_ai_security() -> None:
    BUILTIN_TEMPLATES["ai_security_assessment"] = {
        "id": "ai_security_assessment",
        "name": "AI应用安全评估",
        "description": "端点探测→输入验证→输出过滤→模型安全→数据隐私→提示注入检测→报告",
        "target_types": ["url", "ai_endpoint"],
        "steps": [
            _step("endpoint_probe", "端点探测", "ai_endpoint_probe",
                  "探测AI应用可达性", 20, weight=0.8),
            _step("input_validation", "输入验证", "ai_input_validation",
                  "调用 ai_security 输入侧检测", 40, depends_on=["endpoint_probe"], weight=1.0),
            _step("output_filter", "输出过滤", "ai_output_filter",
                  "输出侧越权信息泄露检查", 40, depends_on=["endpoint_probe"], weight=1.0),
            _step("model_security", "模型安全", "ai_model_security",
                  "jailbreak/越权风险", 40, depends_on=["endpoint_probe"], weight=1.2),
            _step("data_privacy", "数据隐私", "ai_data_privacy",
                  "数据隐私面评估", 30, depends_on=["endpoint_probe"], weight=1.1),
            _step("prompt_injection", "提示注入检测", "ai_prompt_injection",
                  "复用 ai_security.prompt_injection_detector", 60,
                  depends_on=["endpoint_probe"], weight=1.5),
            _step("risk_rating", "风险评级", "risk_rating", "聚合评分", 10,
                  depends_on=["prompt_injection"], weight=1.0),
            _step("report", "生成报告", "generate_report", "汇总报告", 15,
                  depends_on=["risk_rating"], weight=0.3),
        ],
    }


def _register_blockchain() -> None:
    BUILTIN_TEMPLATES["blockchain_contract"] = {
        "id": "blockchain_contract",
        "name": "区块链合约评估",
        "description": "合约解析→函数分析→重入检测→溢出检测→权限检查→Gas优化→报告",
        "target_types": ["contract"],
        "steps": [
            _step("contract_parse", "合约解析", "contract_parse",
                  "调用 blockchain_security 解析合约", 40, weight=1.0),
            _step("function_analysis", "函数分析", "contract_function_analysis",
                  "暴露函数与修饰符分析", 30, depends_on=["contract_parse"], weight=1.0),
            _step("reentrancy", "重入检测", "contract_reentrancy",
                  "重入漏洞模式检测", 40, depends_on=["contract_parse"], weight=1.5),
            _step("overflow", "溢出检测", "contract_overflow",
                  "整数溢出/下溢检测", 30, depends_on=["contract_parse"], weight=1.2),
            _step("permission", "权限检查", "contract_permission",
                  "onlyOwner/越权检查", 30, depends_on=["contract_parse"], weight=1.2),
            _step("gas", "Gas优化", "contract_gas",
                  "Gas消耗模式评估", 20, depends_on=["contract_parse"], weight=0.5),
            _step("risk_rating", "风险评级", "risk_rating", "聚合评分", 10,
                  depends_on=["permission"], weight=1.0),
            _step("report", "生成报告", "generate_report", "汇总报告", 15,
                  depends_on=["risk_rating"], weight=0.3),
        ],
    }


def _register_supply_chain() -> None:
    BUILTIN_TEMPLATES["supply_chain_sbom"] = {
        "id": "supply_chain_sbom",
        "name": "供应链SBOM评估",
        "description": "依赖解析→SBOM生成→漏洞匹配→许可证检查→组件健康度→报告",
        "target_types": ["path", "repo"],
        "steps": [
            _step("dep_resolve", "依赖解析", "sca_dep_resolve",
                  "调用 code_audit.sca_engine 解析依赖", 60, weight=1.0),
            _step("sbom_gen", "SBOM生成", "sca_sbom",
                  "生成组件清单", 30, depends_on=["dep_resolve"], weight=0.8),
            _step("vuln_match", "漏洞匹配", "sca_vuln_match",
                  "组件CVE匹配", 60, depends_on=["sbom_gen"], weight=1.5),
            _step("license_check", "许可证检查", "sca_license",
                  "许可证合规检查", 30, depends_on=["sbom_gen"], weight=0.8),
            _step("health", "组件健康度", "sca_health",
                  "维护状态/版本陈旧度", 30, depends_on=["sbom_gen"], weight=0.7),
            _step("risk_rating", "风险评级", "risk_rating", "聚合评分", 10,
                  depends_on=["vuln_match"], weight=1.0),
            _step("report", "生成报告", "generate_report", "汇总报告", 15,
                  depends_on=["risk_rating"], weight=0.3),
        ],
    }


def _register_compliance() -> None:
    BUILTIN_TEMPLATES["compliance_baseline"] = {
        "id": "compliance_baseline",
        "name": "合规基线检查",
        "description": "系统配置→服务配置→密码策略→访问控制→日志审计→合规评分→报告",
        "target_types": ["host", "domain"],
        "steps": [
            _step("sys_config", "系统配置", "baseline_sys_config",
                  "系统安全配置基线", 40, weight=1.0),
            _step("svc_config", "服务配置", "baseline_svc_config",
                  "服务安全配置", 40, depends_on=["sys_config"], weight=1.0),
            _step("pwd_policy", "密码策略", "baseline_pwd_policy",
                  "密码策略评估", 30, depends_on=["sys_config"], weight=1.1),
            _step("access_ctrl", "访问控制", "baseline_access_ctrl",
                  "访问控制评估", 30, depends_on=["sys_config"], weight=1.1),
            _step("log_audit", "日志审计", "baseline_log_audit",
                  "审计日志完整性", 30, depends_on=["sys_config"], weight=0.9),
            _step("compliance_score", "合规评分", "risk_rating",
                  "合规综合评分", 10, depends_on=["log_audit"], weight=1.0),
            _step("report", "生成报告", "generate_report", "汇总报告", 15,
                  depends_on=["compliance_score"], weight=0.3),
        ],
    }


def _register_redblue() -> None:
    BUILTIN_TEMPLATES["redblue_exercise"] = {
        "id": "redblue_exercise",
        "name": "红蓝对抗演练",
        "description": "攻击面探测→漏洞利用评估→权限提升评估→横向移动评估→数据窃取评估→痕迹清理评估→防御检测→报告",
        "target_types": ["ip", "domain"],
        "steps": [
            _step("attack_surface", "攻击面探测", "rb_attack_surface",
                  "攻击面枚举", 40, weight=1.0),
            _step("exploit_assess", "漏洞利用评估", "rb_exploit_assess",
                  "可利用性评估（仅检测不利用）", 60, depends_on=["attack_surface"], weight=1.3),
            _step("priv_esc", "权限提升评估", "rb_priv_esc",
                  "提权路径评估", 40, depends_on=["exploit_assess"], weight=1.2),
            _step("lateral", "横向移动评估", "rb_lateral",
                  "横向通道评估", 40, depends_on=["priv_esc"], weight=1.2),
            _step("data_exfil", "数据窃取评估", "rb_data_exfil",
                  "数据外带面评估", 30, depends_on=["lateral"], weight=1.1),
            _step("trace_clean", "痕迹清理评估", "rb_trace_clean",
                  "日志/痕迹面评估", 30, depends_on=["data_exfil"], weight=0.8),
            _step("defense_detect", "防御检测", "rb_defense_detect",
                  "现有防御对各阶段的检测率", 40, depends_on=["trace_clean"], weight=1.2),
            _step("risk_rating", "风险评级", "risk_rating", "聚合评分", 10,
                  depends_on=["defense_detect"], weight=1.0),
            _step("report", "生成报告", "generate_report", "汇总报告", 15,
                  depends_on=["risk_rating"], weight=0.3),
        ],
    }


for _fn in (_register_web_full, _register_mobile, _register_internal_pentest,
            _register_ai_security, _register_blockchain, _register_supply_chain,
            _register_compliance, _register_redblue):
    _fn()


# --------------------------------------------------------------------------- #
# 自定义模板（内存）
# --------------------------------------------------------------------------- #
_CUSTOM_TEMPLATES: Dict[str, Dict[str, Any]] = {}


class ScenarioTemplateLibrary:
    """模板库：内置 + 自定义。"""

    def __init__(self) -> None:
        self.builtin: Dict[str, Dict[str, Any]] = {
            k: dict(v) for k, v in BUILTIN_TEMPLATES.items()
        }
        self.custom: Dict[str, Dict[str, Any]] = dict(_CUSTOM_TEMPLATES)

    def list_templates(self, include_custom: bool = True) -> List[Dict[str, Any]]:
        out = []
        for tpl in self.builtin.values():
            out.append(self._summary(tpl, builtin=True))
        if include_custom:
            for tpl in self.custom.values():
                out.append(self._summary(tpl, builtin=False))
        return out

    def get(self, scenario_id: str) -> Optional[Dict[str, Any]]:
        if scenario_id in self.builtin:
            return self.builtin[scenario_id]
        return self.custom.get(scenario_id)

    def _summary(self, tpl: Dict[str, Any], builtin: bool) -> Dict[str, Any]:
        return {
            "id": tpl["id"],
            "name": tpl["name"],
            "description": tpl["description"],
            "target_types": tpl.get("target_types", []),
            "step_count": len(tpl["steps"]),
            "steps": tpl["steps"],
            "builtin": builtin,
        }

    def add_template(self, tpl: Dict[str, Any]) -> Dict[str, Any]:
        tid = tpl.get("id") or ("custom_" + str(len(self.custom) + 1))
        tpl["id"] = tid
        tpl.setdefault("name", tid)
        tpl.setdefault("description", "自定义场景")
        tpl.setdefault("target_types", ["ip"])
        tpl.setdefault("steps", [])
        self.custom[tid] = tpl
        return self._summary(tpl, builtin=False)

    def update_template(self, scenario_id: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if scenario_id not in self.custom:
            return None
        self.custom[scenario_id].update(patch)
        if "steps" in patch:
            self.custom[scenario_id]["steps"] = patch["steps"]
        return self._summary(self.custom[scenario_id], builtin=False)

    def delete_template(self, scenario_id: str) -> bool:
        if scenario_id in self.custom:
            del self.custom[scenario_id]
            return True
        return False


LIBRARY = ScenarioTemplateLibrary()


__all__ = ["ScenarioTemplateLibrary", "LIBRARY", "BUILTIN_TEMPLATES"]
