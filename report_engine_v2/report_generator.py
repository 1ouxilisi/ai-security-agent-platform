#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
专业渗透测试报告生成器
生成HTML/PDF/Markdown格式的专业安全测试报告
"""

import json
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

from .cvss_scorer import CVSSScorer, CVSSMetrics
from .remediation_library import RemediationLibrary, Remediation


@dataclass
class VulnerabilityFinding:
    """漏洞发现"""
    finding_id: str = ""
    title: str = ""
    vulnerability_type: str = ""
    severity: str = "info"  # critical/high/medium/low/info
    cvss_score: float = 0.0
    cvss_vector: str = ""
    description: str = ""
    affected_url: str = ""
    affected_parameter: str = ""
    proof_of_concept: str = ""
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cwe_id: str = ""
    cve_id: str = ""
    discovered_at: str = ""
    status: str = "open"  # open/fixed/accepted/risk_accepted


@dataclass
class ReportSection:
    """报告章节"""
    section_id: str = ""
    title: str = ""
    content: str = ""
    order: int = 0


@dataclass
class PentestReport:
    """渗透测试报告"""
    report_id: str = ""
    title: str = ""
    client_name: str = ""
    target: str = ""
    test_type: str = ""  # web/network/mobile/cloud/api
    test_scope: str = ""
    start_date: str = ""
    end_date: str = ""
    tester: str = ""
    executive_summary: str = ""
    overall_risk: str = "medium"
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    sections: List[ReportSection] = field(default_factory=list)
    methodology: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


class ReportGenerator:
    """专业报告生成器"""

    # 标准渗透测试方法论
    STANDARD_METHODOLOGY = [
        "1. 侦察 (Reconnaissance) - 信息收集、子域名枚举、端口扫描",
        "2. 扫描 (Scanning) - 服务识别、漏洞扫描、技术指纹",
        "3. 枚举 (Enumeration) - 目录爆破、参数发现、API端点发现",
        "4. 漏洞验证 (Vulnerability Validation) - 真实利用验证、误报排除",
        "5. 漏洞利用 (Exploitation) - 权限获取、数据访问、横向移动",
        "6. 后渗透 (Post-Exploitation) - 权限提升、持久化、数据收集",
        "7. 报告 (Reporting) - 漏洞整理、风险评估、修复建议",
    ]

    def __init__(self):
        self.cvss_scorer = CVSSScorer()
        self.remediation_library = RemediationLibrary()

    def create_report(self, title: str, client_name: str = "",
                      target: str = "", test_type: str = "web",
                      tester: str = "") -> PentestReport:
        """创建新报告"""
        report = PentestReport(
            report_id=f"PT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            title=title,
            client_name=client_name,
            target=target,
            test_type=test_type,
            tester=tester,
            start_date=datetime.now().isoformat(),
            methodology=self.STANDARD_METHODOLOGY.copy(),
        )
        return report

    def add_finding(self, report: PentestReport,
                    title: str,
                    vulnerability_type: str,
                    description: str = "",
                    affected_url: str = "",
                    affected_parameter: str = "",
                    proof_of_concept: str = "",
                    evidence: str = "",
                    impact: str = "",
                    severity: str = "",
                    cvss_metrics: CVSSMetrics = None,
                    cve_id: str = "",
                    cwe_id: str = "") -> VulnerabilityFinding:
        """添加漏洞发现"""
        # 自动评分
        if cvss_metrics:
            cvss_score = self.cvss_scorer.calculate_base_score(cvss_metrics)
            cvss_vector = self.cvss_scorer.get_vector_string(cvss_metrics)
            auto_severity = self.cvss_scorer.get_severity(cvss_score)
        else:
            cvss_score, auto_severity, cvss_vector = self.cvss_scorer.score_by_type(
                vulnerability_type
            )

        final_severity = (severity or auto_severity).lower()

        # 获取修复建议
        remediation = self.remediation_library.get_remediation(vulnerability_type)
        remediation_text = ""
        remediation_steps = []
        references = []
        remediation_cwe = ""

        if remediation:
            remediation_text = remediation.description
            remediation_steps = remediation.remediation_steps
            references = remediation.references
            remediation_cwe = remediation.cwe_id

        finding = VulnerabilityFinding(
            finding_id=f"VULN-{len(report.findings) + 1:03d}",
            title=title,
            vulnerability_type=vulnerability_type,
            severity=final_severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            description=description,
            affected_url=affected_url,
            affected_parameter=affected_parameter,
            proof_of_concept=proof_of_concept,
            evidence=evidence,
            impact=impact,
            remediation=remediation_text,
            remediation_steps=remediation_steps,
            references=references,
            cwe_id=cwe_id or remediation_cwe,
            cve_id=cve_id,
            discovered_at=datetime.now().isoformat(),
        )

        report.findings.append(finding)
        self._update_overall_risk(report)
        return finding

    def _update_overall_risk(self, report: PentestReport):
        """更新整体风险等级"""
        if not report.findings:
            report.overall_risk = "low"
            return

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_severity = max(
            (severity_order.get(f.severity, 0) for f in report.findings),
            default=0
        )

        risk_map = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
        report.overall_risk = risk_map.get(max_severity, "low")

    def generate_executive_summary(self, report: PentestReport) -> str:
        """生成执行摘要"""
        if not report.findings:
            return "本次安全测试未发现安全漏洞。"

        by_severity = {}
        for f in report.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        summary = f"""本次针对 {report.target} 的{self._get_test_type_name(report.test_type)}安全测试于 {report.start_date[:10]} 进行。

测试共发现 {len(report.findings)} 个安全问题，其中：
"""
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_severity:
                sev_name = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}[sev]
                summary += f"- {sev_name}: {by_severity[sev]} 个\n"

        summary += f"\n整体风险评级为：{report.overall_risk.upper()}\n\n"

        if by_severity.get("critical", 0) > 0 or by_severity.get("high", 0) > 0:
            summary += "建议立即修复严重和高危漏洞，并制定中低危漏洞的修复计划。"
        else:
            summary += "建议对发现的问题进行修复，并定期进行安全测试。"

        report.executive_summary = summary
        return summary

    def _get_test_type_name(self, test_type: str) -> str:
        """获取测试类型中文名"""
        names = {
            "web": "Web应用",
            "network": "网络",
            "mobile": "移动应用",
            "cloud": "云服务",
            "api": "API",
            "wireless": "无线网络",
            "physical": "物理安全",
        }
        return names.get(test_type, test_type)

    def generate_markdown(self, report: PentestReport) -> str:
        """生成Markdown格式报告"""
        self.generate_executive_summary(report)

        md = f"""# {report.title}

**报告编号**: {report.report_id}
**客户名称**: {report.client_name or 'N/A'}
**测试目标**: {report.target}
**测试类型**: {self._get_test_type_name(report.test_type)}
**测试人员**: {report.tester or 'N/A'}
**开始日期**: {report.start_date[:10]}
**结束日期**: {report.end_date[:10] if report.end_date else '进行中'}
**整体风险**: {report.overall_risk.upper()}

---

## 1. 执行摘要

{report.executive_summary}

---

## 2. 测试范围

{report.test_scope or '未指定'}

---

## 3. 测试方法

"""
        for step in report.methodology:
            md += f"- {step}\n"

        md += "\n---\n\n## 4. 使用工具\n\n"
        for tool in report.tools_used:
            md += f"- {tool}\n"

        md += "\n---\n\n## 5. 漏洞发现\n\n"

        # 按严重级别排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            report.findings,
            key=lambda f: severity_order.get(f.severity, 99)
        )

        for i, finding in enumerate(sorted_findings, 1):
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}[finding.severity]
            md += f"""### {i}. {sev_emoji} {finding.title}

**编号**: {finding.finding_id}
**类型**: {finding.vulnerability_type}
**严重级别**: {finding.severity.upper()} (CVSS {finding.cvss_score})
**CVSS向量**: `{finding.cvss_vector}`
**CWE**: {finding.cwe_id or 'N/A'}
**CVE**: {finding.cve_id or 'N/A'}

**描述**:
{finding.description or 'N/A'}

**受影响位置**:
- URL: {finding.affected_url or 'N/A'}
- 参数: {finding.affected_parameter or 'N/A'}

**漏洞验证**:
{finding.proof_of_concept or 'N/A'}

**影响**:
{finding.impact or 'N/A'}

**修复建议**:
{finding.remediation or 'N/A'}

**修复步骤**:
"""
            for step in finding.remediation_steps:
                md += f"{step}\n"

            if finding.references:
                md += "\n**参考资料**:\n"
                for ref in finding.references:
                    md += f"- {ref}\n"

            md += "\n---\n\n"

        md += "## 6. 测试限制\n\n"
        for limitation in report.limitations:
            md += f"- {limitation}\n"

        md += f"\n---\n\n*报告生成时间: {datetime.now().isoformat()}*\n"

        return md

    def generate_html(self, report: PentestReport) -> str:
        """生成HTML格式报告"""
        md_content = self.generate_markdown(report)

        # 简单的Markdown转HTML（基础实现）
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report.title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; line-height: 1.6; color: #333; }}
        h1 {{ color: #1a1a1a; border-bottom: 3px solid #0066cc; padding-bottom: 10px; }}
        h2 {{ color: #0066cc; margin-top: 30px; border-left: 4px solid #0066cc; padding-left: 10px; }}
        h3 {{ color: #333; margin-top: 20px; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .info {{ color: #17a2b8; }}
        .finding {{ border: 1px solid #ddd; border-radius: 8px; padding: 15px; margin: 15px 0; background: #f9f9f9; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 20px; color: white; font-weight: bold; font-size: 12px; }}
        .severity-critical {{ background: #dc3545; }}
        .severity-high {{ background: #fd7e14; }}
        .severity-medium {{ background: #ffc107; color: #333; }}
        .severity-low {{ background: #28a745; }}
        .severity-info {{ background: #17a2b8; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
        pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
        th {{ background: #0066cc; color: white; }}
        .summary-box {{ background: #f0f7ff; border-left: 4px solid #0066cc; padding: 15px; margin: 15px 0; }}
    </style>
</head>
<body>
<pre>{md_content}</pre>
</body>
</html>"""
        return html

    def generate_json(self, report: PentestReport) -> str:
        """生成JSON格式报告"""
        data = {
            "report_id": report.report_id,
            "title": report.title,
            "client_name": report.client_name,
            "target": report.target,
            "test_type": report.test_type,
            "start_date": report.start_date,
            "end_date": report.end_date,
            "tester": report.tester,
            "overall_risk": report.overall_risk,
            "executive_summary": report.executive_summary,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "vulnerability_type": f.vulnerability_type,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "description": f.description,
                    "affected_url": f.affected_url,
                    "affected_parameter": f.affected_parameter,
                    "proof_of_concept": f.proof_of_concept,
                    "impact": f.impact,
                    "remediation": f.remediation,
                    "remediation_steps": f.remediation_steps,
                    "references": f.references,
                    "cwe_id": f.cwe_id,
                    "cve_id": f.cve_id,
                    "status": f.status,
                }
                for f in report.findings
            ],
            "methodology": report.methodology,
            "tools_used": report.tools_used,
            "limitations": report.limitations,
            "statistics": self.get_statistics(report),
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def get_statistics(self, report: PentestReport) -> Dict:
        """获取报告统计"""
        by_severity = {}
        by_type = {}
        for f in report.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_type[f.vulnerability_type] = by_type.get(f.vulnerability_type, 0) + 1

        return {
            "total_findings": len(report.findings),
            "by_severity": by_severity,
            "by_type": by_type,
            "overall_risk": report.overall_risk,
            "average_cvss": round(
                sum(f.cvss_score for f in report.findings) / len(report.findings), 1
            ) if report.findings else 0,
        }

    def save_report(self, report: PentestReport, output_path: str,
                    format: str = "markdown") -> bool:
        """保存报告到文件"""
        try:
            if format == "markdown":
                content = self.generate_markdown(report)
            elif format == "html":
                content = self.generate_html(report)
            elif format == "json":
                content = self.generate_json(report)
            else:
                return False

            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True
        except Exception:
            return False

    def add_tool(self, report: PentestReport, tool_name: str):
        """添加使用的工具"""
        if tool_name not in report.tools_used:
            report.tools_used.append(tool_name)

    def add_limitation(self, report: PentestReport, limitation: str):
        """添加测试限制"""
        report.limitations.append(limitation)

    def finalize_report(self, report: PentestReport):
        """完成报告"""
        report.end_date = datetime.now().isoformat()
        self.generate_executive_summary(report)
