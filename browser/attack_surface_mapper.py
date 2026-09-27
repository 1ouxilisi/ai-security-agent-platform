"""
攻击面映射器 - 汇总动态侦察结果，生成完整的Web应用攻击面图谱
对标Shannon的攻击面映射（Attack Surface Mapping）
整合：页面发现、表单、API端点、技术栈、漏洞、认证流程
"""
import json
from dataclasses import dataclass, field
from typing import Optional

from .dynamic_crawler import CrawlResult
from .vuln_validator import ValidationResult, VulnProof


@dataclass
class AttackSurface:
    """完整攻击面"""
    target_url: str
    # 基础设施
    pages: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    api_endpoints: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    tech_stack: dict = field(default_factory=dict)
    # 安全
    confirmed_vulns: list = field(default_factory=list)
    auth_flows: list = field(default_factory=list)
    # 统计
    total_attack_vectors: int = 0
    risk_score: float = 0.0
    risk_level: str = "low"  # low/medium/high/critical
    # 元数据
    crawl_time: str = ""
    validator_version: str = "1.0"


class AttackSurfaceMapper:
    """
    攻击面映射器
    整合爬虫和验证器结果，生成可操作的攻击面报告
    """

    def __init__(self):
        self._surface = AttackSurface(target_url="")

    def map(self, crawl_result: CrawlResult,
            validation_results: list[ValidationResult]) -> AttackSurface:
        """
        生成完整攻击面
        """
        self._surface = AttackSurface(target_url=crawl_result.base_url)

        # 基础设施
        self._surface.pages = [s.url for s in crawl_result.page_snapshots]
        self._surface.forms = crawl_result.forms_found
        self._surface.api_endpoints = crawl_result.api_endpoints
        self._surface.scripts = crawl_result.scripts
        self._surface.tech_stack = crawl_result.tech_stack

        # 漏洞汇总
        all_vulns = []
        for vr in validation_results:
            all_vulns.extend(vr.confirmed_vulns)
        self._surface.confirmed_vulns = all_vulns

        # 认证流程识别
        self._surface.auth_flows = self._identify_auth_flows(crawl_result)

        # 统计
        self._surface.total_attack_vectors = (
            len(self._surface.forms)
            + len(self._surface.api_endpoints)
            + len(self._surface.confirmed_vulns)
        )

        # 风险评分
        self._surface.risk_score = self._calculate_risk_score()
        self._surface.risk_level = self._risk_level(self._surface.risk_score)

        return self._surface

    def _identify_auth_flows(self, crawl_result: CrawlResult) -> list:
        """识别认证流程"""
        auth_flows = []

        for form in crawl_result.forms_found:
            form_dict = form if isinstance(form, dict) else form.__dict__
            if form_dict.get("has_auth"):
                auth_flows.append({
                    "type": "login_form",
                    "action": form_dict.get("action", ""),
                    "method": form_dict.get("method", "POST"),
                    "fields": [i.get("name", "") for i in form_dict.get("inputs", [])],
                })

        # 检查常见认证路径
        auth_paths = ["/login", "/signin", "/auth", "/oauth", "/token", "/register", "/signup"]
        for page_url in self._surface.pages:
            for ap in auth_paths:
                if ap in page_url.lower():
                    auth_flows.append({
                        "type": "auth_endpoint",
                        "url": page_url,
                        "path_pattern": ap,
                    })
                    break

        return auth_flows

    def _calculate_risk_score(self) -> float:
        """计算风险评分（0-10）"""
        score = 0.0

        # 漏洞权重
        for vuln in self._surface.confirmed_vulns:
            v = vuln if isinstance(vuln, dict) else vuln.__dict__
            severity = v.get("severity", "low")
            cvss = v.get("cvss_score", 0)
            if severity == "critical":
                score += 3.0
            elif severity == "high":
                score += 1.5
            elif severity == "medium":
                score += 0.5
            else:
                score += 0.2
            score += cvss * 0.1

        # 攻击面广度
        score += min(len(self._surface.forms) * 0.1, 1.0)
        score += min(len(self._surface.api_endpoints) * 0.05, 1.0)

        # 认证面
        score += len(self._surface.auth_flows) * 0.3

        return min(score, 10.0)

    def _risk_level(self, score: float) -> str:
        if score >= 8.0:
            return "critical"
        elif score >= 5.0:
            return "high"
        elif score >= 2.5:
            return "medium"
        else:
            return "low"

    def generate_report(self) -> dict:
        """生成攻击面报告"""
        return {
            "target": self._surface.target_url,
            "summary": {
                "pages_discovered": len(self._surface.pages),
                "forms": len(self._surface.forms),
                "api_endpoints": len(self._surface.api_endpoints),
                "confirmed_vulnerabilities": len(self._surface.confirmed_vulns),
                "auth_flows": len(self._surface.auth_flows),
                "total_attack_vectors": self._surface.total_attack_vectors,
            },
            "risk_assessment": {
                "risk_score": round(self._surface.risk_score, 2),
                "risk_level": self._surface.risk_level,
            },
            "technology_stack": self._surface.tech_stack,
            "attack_vectors": {
                "forms": [
                    f.__dict__ if hasattr(f, '__dict__') else f
                    for f in self._surface.forms
                ],
                "api_endpoints": [
                    e.__dict__ if hasattr(e, '__dict__') else e
                    for e in self._surface.api_endpoints
                ],
                "auth_flows": self._surface.auth_flows,
            },
            "confirmed_vulnerabilities": [
                v.__dict__ if hasattr(v, '__dict__') else v
                for v in self._surface.confirmed_vulns
            ],
            "pages": self._surface.pages,
            "recommendations": self._generate_recommendations(),
        }

    def _generate_recommendations(self) -> list:
        """生成修复建议"""
        recs = []

        vuln_types = set()
        for v in self._surface.confirmed_vulns:
            vd = v if isinstance(v, dict) else v.__dict__
            vuln_types.add(vd.get("vuln_type", ""))

        if "XSS" in str(vuln_types):
            recs.append("XSS: 实施输入验证和输出编码，使用CSP策略")
        if "SQL Injection" in str(vuln_types):
            recs.append("SQL注入: 使用参数化查询/预编译语句，禁止字符串拼接SQL")
        if "SSRF" in str(vuln_types):
            recs.append("SSRF: 实施URL白名单，禁止内网地址访问")
        if "Path Traversal" in str(vuln_types):
            recs.append("路径遍历: 规范化文件路径，使用chroot或沙箱")
        if "Command Injection" in str(vuln_types):
            recs.append("命令注入: 禁止直接执行系统命令，使用安全API替代")

        if self._surface.auth_flows:
            recs.append("认证: 实施MFA、速率限制、账户锁定策略")

        if not recs:
            recs.append("未发现确认可利用漏洞，建议持续监控和定期测试")

        return recs

    def to_json(self, indent: int = 2) -> str:
        """导出JSON"""
        return json.dumps(self.generate_report(), indent=indent, ensure_ascii=False, default=str)
