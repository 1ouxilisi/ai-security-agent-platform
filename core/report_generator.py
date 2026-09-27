#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告模板系统
Report Template System

功能：多种报告格式、自定义模板、一键导出、报告市场
"""

import os
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum
from loguru import logger


class ReportFormat(str, Enum):
    """报告格式"""
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    DOCX = "docx"
    CSV = "csv"


class ReportType(str, Enum):
    """报告类型"""
    PENETRATION_TEST = "penetration_test"      # 渗透测试报告
    VULNERABILITY_SCAN = "vulnerability_scan"  # 漏洞扫描报告
    SECURITY_AUDIT = "security_audit"           # 安全审计报告
    COMPLIANCE = "compliance"                    # 合规检查报告
    INCIDENT_RESPONSE = "incident_response"     # 应急响应报告
    CUSTOM = "custom"                            # 自定义报告


class Severity(str, Enum):
    """严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """漏洞条目"""
    vuln_id: str
    name: str
    severity: Severity
    description: str
    affected_target: str
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cve_id: Optional[str] = None
    references: List[str] = field(default_factory=list)
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'vuln_id': self.vuln_id,
            'name': self.name,
            'severity': self.severity.value,
            'description': self.description,
            'affected_target': self.affected_target,
            'evidence': self.evidence,
            'impact': self.impact,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'cve_id': self.cve_id,
            'references': self.references,
            'discovered_at': self.discovered_at,
        }


@dataclass
class ReportTemplate:
    """报告模板"""
    template_id: str
    name: str
    description: str
    report_type: ReportType
    format: ReportFormat
    content: str  # 模板内容，支持占位符
    variables: List[str] = field(default_factory=list)
    is_builtin: bool = False
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'template_id': self.template_id,
            'name': self.name,
            'description': self.description,
            'report_type': self.report_type.value,
            'format': self.format.value,
            'content': self.content,
            'variables': self.variables,
            'is_builtin': self.is_builtin,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
        }


@dataclass
class Report:
    """报告"""
    report_id: str
    title: str
    report_type: ReportType
    format: ReportFormat
    template_id: Optional[str] = None
    target: str = ""
    author: str = ""
    summary: str = ""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)
    content: str = ""
    generated_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'report_id': self.report_id,
            'title': self.title,
            'report_type': self.report_type.value,
            'format': self.format.value,
            'template_id': self.template_id,
            'target': self.target,
            'author': self.author,
            'summary': self.summary,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'findings': self.findings,
            'content': self.content,
            'generated_at': self.generated_at,
            'metadata': self.metadata,
            'severity_summary': self.get_severity_summary(),
        }

    def get_severity_summary(self) -> Dict[str, int]:
        """获取严重程度统计"""
        summary = {s.value: 0 for s in Severity}
        for vuln in self.vulnerabilities:
            summary[vuln.severity.value] += 1
        return summary

    def get_risk_score(self) -> float:
        """计算风险评分（0-100）"""
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }
        score = sum(weights.get(v.severity, 0) for v in self.vulnerabilities)
        return min(score, 100.0)


class ReportGenerator:
    """报告生成器"""

    def __init__(self, templates_dir: str = "data/report_templates", reports_dir: str = "reports"):
        self.templates_dir = templates_dir
        self.reports_dir = reports_dir
        self._templates: Dict[str, ReportTemplate] = {}

        os.makedirs(templates_dir, exist_ok=True)
        os.makedirs(reports_dir, exist_ok=True)

        self._load_builtin_templates()
        self._load_custom_templates()

        logger.info(f"报告生成器初始化完成: {len(self._templates)}个模板")

    def _load_builtin_templates(self):
        """加载内置模板"""
        builtin_templates = [
            ReportTemplate(
                template_id="builtin_pentest_md",
                name="渗透测试报告（Markdown）",
                description="标准渗透测试报告模板，包含执行摘要、漏洞详情、修复建议",
                report_type=ReportType.PENETRATION_TEST,
                format=ReportFormat.MARKDOWN,
                content=self._get_pentest_md_template(),
                variables=["{{title}}", "{{target}}", "{{author}}", "{{date}}", "{{summary}}", "{{vulnerabilities}}", "{{risk_score}}"],
                is_builtin=True,
            ),
            ReportTemplate(
                template_id="builtin_vuln_scan_md",
                name="漏洞扫描报告（Markdown）",
                description="自动化漏洞扫描报告模板，按严重程度分类",
                report_type=ReportType.VULNERABILITY_SCAN,
                format=ReportFormat.MARKDOWN,
                content=self._get_vuln_scan_md_template(),
                variables=["{{title}}", "{{target}}", "{{date}}", "{{summary}}", "{{vulnerabilities}}"],
                is_builtin=True,
            ),
            ReportTemplate(
                template_id="builtin_pentest_html",
                name="渗透测试报告（HTML）",
                description="美观的HTML格式渗透测试报告，支持打印",
                report_type=ReportType.PENETRATION_TEST,
                format=ReportFormat.HTML,
                content=self._get_pentest_html_template(),
                variables=["{{title}}", "{{target}}", "{{author}}", "{{date}}", "{{summary}}", "{{vulnerabilities}}", "{{risk_score}}"],
                is_builtin=True,
            ),
            ReportTemplate(
                template_id="builtin_audit_md",
                name="安全审计报告（Markdown）",
                description="全面安全审计报告，包含配置、代码、架构审计",
                report_type=ReportType.SECURITY_AUDIT,
                format=ReportFormat.MARKDOWN,
                content=self._get_audit_md_template(),
                variables=["{{title}}", "{{target}}", "{{author}}", "{{date}}", "{{summary}}", "{{findings}}"],
                is_builtin=True,
            ),
            ReportTemplate(
                template_id="builtin_compliance_md",
                name="合规检查报告（Markdown）",
                description="等保2.0/ISO27001合规检查报告模板",
                report_type=ReportType.COMPLIANCE,
                format=ReportFormat.MARKDOWN,
                content=self._get_compliance_md_template(),
                variables=["{{title}}", "{{target}}", "{{date}}", "{{summary}}", "{{checklist}}"],
                is_builtin=True,
            ),
            ReportTemplate(
                template_id="builtin_incident_md",
                name="应急响应报告（Markdown）",
                description="安全事件应急响应报告，包含时间线、影响、处置",
                report_type=ReportType.INCIDENT_RESPONSE,
                format=ReportFormat.MARKDOWN,
                content=self._get_incident_md_template(),
                variables=["{{title}}", "{{target}}", "{{author}}", "{{date}}", "{{summary}}", "{{timeline}}", "{{impact}}"],
                is_builtin=True,
            ),
        ]

        for template in builtin_templates:
            self._templates[template.template_id] = template

    def _get_pentest_md_template(self) -> str:
        """渗透测试Markdown模板"""
        return """# {{title}}

## 1. 执行摘要

**测试目标:** {{target}}
**测试人员:** {{author}}
**测试日期:** {{date}}
**风险评分:** {{risk_score}}/100

{{summary}}

## 2. 漏洞统计

| 严重程度 | 数量 |
|----------|------|
| 严重 | {{critical_count}} |
| 高危 | {{high_count}} |
| 中危 | {{medium_count}} |
| 低危 | {{low_count}} |
| 信息 | {{info_count}} |

## 3. 漏洞详情

{{vulnerabilities}}

## 4. 修复建议优先级

1. **立即修复:** 所有严重和高危漏洞
2. **计划修复:** 中危漏洞（30天内）
3. **建议修复:** 低危和信息级漏洞

## 5. 附录

- 测试工具: AI Hacking Agent v7.0
- 报告生成时间: {{date}}
"""

    def _get_vuln_scan_md_template(self) -> str:
        """漏洞扫描Markdown模板"""
        return """# {{title}}

## 扫描摘要

**扫描目标:** {{target}}
**扫描日期:** {{date}}

{{summary}}

## 漏洞列表

{{vulnerabilities}}

## 统计信息

- 总漏洞数: {{total_count}}
- 严重: {{critical_count}}
- 高危: {{high_count}}
- 中危: {{medium_count}}
- 低危: {{low_count}}
"""

    def _get_pentest_html_template(self) -> str:
        """渗透测试HTML模板"""
        return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>{{title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .risk-score { font-size: 24px; font-weight: bold; color: {{risk_color}}; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: #007bff; color: white; }
        .critical { background: #f8d7da; }
        .high { background: #fff3cd; }
        .medium { background: #ffeeba; }
        .low { background: #d4edda; }
        .footer { margin-top: 50px; text-align: center; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <h1>{{title}}</h1>

    <div class="summary">
        <p><strong>测试目标:</strong> {{target}}</p>
        <p><strong>测试人员:</strong> {{author}}</p>
        <p><strong>测试日期:</strong> {{date}}</p>
        <p><strong>风险评分:</strong> <span class="risk-score">{{risk_score}}/100</span></p>
    </div>

    <h2>执行摘要</h2>
    <p>{{summary}}</p>

    <h2>漏洞统计</h2>
    <table>
        <tr><th>严重程度</th><th>数量</th></tr>
        <tr class="critical"><td>严重</td><td>{{critical_count}}</td></tr>
        <tr class="high"><td>高危</td><td>{{high_count}}</td></tr>
        <tr class="medium"><td>中危</td><td>{{medium_count}}</td></tr>
        <tr class="low"><td>低危</td><td>{{low_count}}</td></tr>
    </table>

    <h2>漏洞详情</h2>
    {{vulnerabilities}}

    <div class="footer">
        <p>由 AI Hacking Agent v7.0 生成 | {{date}}</p>
    </div>
</body>
</html>"""

    def _get_audit_md_template(self) -> str:
        """安全审计Markdown模板"""
        return """# {{title}}

## 审计摘要

**审计目标:** {{target}}
**审计人员:** {{author}}
**审计日期:** {{date}}

{{summary}}

## 审计发现

{{findings}}

## 改进建议

1. 高优先级: 立即修复的问题
2. 中优先级: 计划修复的问题
3. 低优先级: 建议优化的问题
"""

    def _get_compliance_md_template(self) -> str:
        """合规检查Markdown模板"""
        return """# {{title}}

## 合规检查摘要

**检查目标:** {{target}}
**检查日期:** {{date}}
**合规标准:** 等保2.0 / ISO27001

{{summary}}

## 检查清单

{{checklist}}

## 合规评分

- 总符合率: {{compliance_rate}}%
- 符合项: {{passed_count}}
- 不符合项: {{failed_count}}
- 不适用项: {{na_count}}
"""

    def _get_incident_md_template(self) -> str:
        """应急响应Markdown模板"""
        return """# {{title}}

## 事件摘要

**事件目标:** {{target}}
**响应人员:** {{author}}
**事件日期:** {{date}}

{{summary}}

## 事件时间线

{{timeline}}

## 影响分析

{{impact}}

## 处置措施

1. 遏制措施
2. 根除措施
3. 恢复措施

## 经验教训

- 根本原因
- 改进措施
- 预防建议
"""

    def _load_custom_templates(self):
        """加载自定义模板"""
        try:
            for filename in os.listdir(self.templates_dir):
                if filename.endswith('.json'):
                    filepath = os.path.join(self.templates_dir, filename)
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    template = ReportTemplate(**{k: v for k, v in data.items() if k in ReportTemplate.__dataclass_fields__})
                    if isinstance(template.report_type, str):
                        template.report_type = ReportType(template.report_type)
                    if isinstance(template.format, str):
                        template.format = ReportFormat(template.format)
                    self._templates[template.template_id] = template
        except Exception as e:
            logger.warning(f"加载自定义模板失败: {e}")

    def list_templates(self, report_type: ReportType = None, format: ReportFormat = None) -> List[ReportTemplate]:
        """列出模板"""
        templates = list(self._templates.values())
        if report_type:
            templates = [t for t in templates if t.report_type == report_type]
        if format:
            templates = [t for t in templates if t.format == format]
        return sorted(templates, key=lambda t: t.created_at, reverse=True)

    def get_template(self, template_id: str) -> Optional[ReportTemplate]:
        """获取模板"""
        return self._templates.get(template_id)

    def create_template(self, name: str, description: str, report_type: ReportType,
                        format: ReportFormat, content: str, variables: List[str] = None) -> ReportTemplate:
        """创建自定义模板"""
        template_id = f"custom_{uuid.uuid4().hex[:12]}"
        template = ReportTemplate(
            template_id=template_id,
            name=name,
            description=description,
            report_type=report_type,
            format=format,
            content=content,
            variables=variables or [],
        )
        self._templates[template_id] = template
        self._save_template(template)
        logger.info(f"创建自定义模板: {name} ({template_id})")
        return template

    def _save_template(self, template: ReportTemplate):
        """保存模板"""
        try:
            filepath = os.path.join(self.templates_dir, f"{template.template_id}.json")
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(template.to_dict(), f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存模板失败: {e}")

    def generate_report(self, title: str, report_type: ReportType, format: ReportFormat,
                        target: str = "", author: str = "", summary: str = "",
                        vulnerabilities: List[Vulnerability] = None,
                        findings: Dict[str, Any] = None,
                        template_id: str = None) -> Report:
        """生成报告"""
        report_id = str(uuid.uuid4())
        report = Report(
            report_id=report_id,
            title=title,
            report_type=report_type,
            format=format,
            template_id=template_id,
            target=target,
            author=author,
            summary=summary,
            vulnerabilities=vulnerabilities or [],
            findings=findings or {},
        )

        # 渲染内容
        report.content = self._render_report(report)

        # 保存报告
        self._save_report(report)

        logger.info(f"生成报告: {title} ({report_id}, {format.value})")
        return report

    def _render_report(self, report: Report) -> str:
        """渲染报告内容"""
        # 获取模板
        template = None
        if report.template_id:
            template = self.get_template(report.template_id)

        if not template:
            # 使用默认模板
            default_id = f"builtin_{report.report_type.value}_{report.format.value}"
            template = self.get_template(default_id)
            if not template:
                # 回退到Markdown
                template = self.get_template(f"builtin_{report.report_type.value}_markdown")

        if not template:
            return self._generate_default_content(report)

        # 准备变量
        variables = self._prepare_variables(report)

        # 替换占位符
        content = template.content
        for key, value in variables.items():
            content = content.replace(f"{{{{{key}}}}}", str(value))

        return content

    def _prepare_variables(self, report: Report) -> Dict[str, str]:
        """准备模板变量"""
        severity_summary = report.get_severity_summary()
        risk_score = report.get_risk_score()

        # 风险颜色
        if risk_score >= 80:
            risk_color = "#dc3545"  # 红
        elif risk_score >= 50:
            risk_color = "#ffc107"  # 黄
        else:
            risk_color = "#28a745"  # 绿

        variables = {
            'title': report.title,
            'target': report.target,
            'author': report.author or "AI Hacking Agent",
            'date': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(report.generated_at)),
            'summary': report.summary or "暂无摘要",
            'risk_score': f"{risk_score:.1f}",
            'risk_color': risk_color,
            'critical_count': severity_summary.get('critical', 0),
            'high_count': severity_summary.get('high', 0),
            'medium_count': severity_summary.get('medium', 0),
            'low_count': severity_summary.get('low', 0),
            'info_count': severity_summary.get('info', 0),
            'total_count': len(report.vulnerabilities),
            'vulnerabilities': self._render_vulnerabilities(report.vulnerabilities, report.format),
            'findings': self._render_findings(report.findings),
            'timeline': self._render_timeline(report.findings.get('timeline', [])),
            'impact': report.findings.get('impact', '暂无影响分析'),
            'checklist': self._render_checklist(report.findings.get('checklist', [])),
            'compliance_rate': report.findings.get('compliance_rate', 0),
            'passed_count': report.findings.get('passed_count', 0),
            'failed_count': report.findings.get('failed_count', 0),
            'na_count': report.findings.get('na_count', 0),
        }

        return variables

    def _render_vulnerabilities(self, vulnerabilities: List[Vulnerability], format: ReportFormat) -> str:
        """渲染漏洞列表"""
        if not vulnerabilities:
            return "未发现漏洞。"

        if format == ReportFormat.HTML:
            html = ""
            for i, vuln in enumerate(vulnerabilities, 1):
                severity_class = vuln.severity.value
                html += f"""
        <div class="vuln {severity_class}" style="margin: 20px 0; padding: 15px; border-radius: 5px;">
            <h3>{i}. {vuln.name} <span style="font-size: 14px; color: #666;">[{vuln.severity.value.upper()}]</span></h3>
            <p><strong>目标:</strong> {vuln.affected_target}</p>
            <p><strong>描述:</strong> {vuln.description}</p>
            <p><strong>证据:</strong> <code>{vuln.evidence}</code></p>
            <p><strong>影响:</strong> {vuln.impact}</p>
            <p><strong>修复建议:</strong> {vuln.remediation}</p>
            {'<p><strong>CVSS:</strong> ' + str(vuln.cvss_score) + '</p>' if vuln.cvss_score else ''}
            {'<p><strong>CVE:</strong> ' + vuln.cve_id + '</p>' if vuln.cve_id else ''}
        </div>"""
            return html
        else:
            # Markdown
            md = ""
            for i, vuln in enumerate(vulnerabilities, 1):
                md += f"""### {i}. {vuln.name} [{vuln.severity.value.upper()}]

- **目标:** {vuln.affected_target}
- **描述:** {vuln.description}
- **证据:** `{vuln.evidence}`
- **影响:** {vuln.impact}
- **修复建议:** {vuln.remediation}
"""
                if vuln.cvss_score:
                    md += f"- **CVSS评分:** {vuln.cvss_score}\n"
                if vuln.cve_id:
                    md += f"- **CVE编号:** {vuln.cve_id}\n"
                if vuln.references:
                    md += f"- **参考链接:**\n"
                    for ref in vuln.references:
                        md += f"  - {ref}\n"
                md += "\n"
            return md

    def _render_findings(self, findings: Dict[str, Any]) -> str:
        """渲染审计发现"""
        if not findings:
            return "暂无审计发现。"
        return json.dumps(findings, ensure_ascii=False, indent=2)

    def _render_timeline(self, timeline: List[Dict]) -> str:
        """渲染时间线"""
        if not timeline:
            return "暂无时间线记录。"
        md = ""
        for event in timeline:
            time_str = event.get('time', '')
            description = event.get('description', '')
            md += f"- **{time_str}**: {description}\n"
        return md

    def _render_checklist(self, checklist: List[Dict]) -> str:
        """渲染检查清单"""
        if not checklist:
            return "暂无检查项。"
        md = "| 检查项 | 状态 | 说明 |\n|--------|------|------|\n"
        for item in checklist:
            name = item.get('name', '')
            status = item.get('status', '未知')
            note = item.get('note', '')
            md += f"| {name} | {status} | {note} |\n"
        return md

    def _generate_default_content(self, report: Report) -> str:
        """生成默认内容（无模板时）"""
        severity_summary = report.get_severity_summary()
        return f"""# {report.title}

## 摘要

- 目标: {report.target}
- 作者: {report.author}
- 日期: {time.strftime('%Y-%m-%d %H:%M:%S')}
- 风险评分: {report.get_risk_score():.1f}/100

{report.summary}

## 漏洞统计

- 严重: {severity_summary.get('critical', 0)}
- 高危: {severity_summary.get('high', 0)}
- 中危: {severity_summary.get('medium', 0)}
- 低危: {severity_summary.get('low', 0)}

## 漏洞详情

{self._render_vulnerabilities(report.vulnerabilities, report.format)}
"""

    def _save_report(self, report: Report):
        """保存报告"""
        try:
            # 保存元数据
            metadata_file = os.path.join(self.reports_dir, f"{report.report_id}.json")
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)

            # 保存内容文件
            ext_map = {
                ReportFormat.MARKDOWN: 'md',
                ReportFormat.HTML: 'html',
                ReportFormat.JSON: 'json',
                ReportFormat.CSV: 'csv',
                ReportFormat.PDF: 'pdf',
                ReportFormat.DOCX: 'docx',
            }
            ext = ext_map.get(report.format, 'txt')
            content_file = os.path.join(self.reports_dir, f"{report.report_id}.{ext}")
            with open(content_file, 'w', encoding='utf-8') as f:
                f.write(report.content)

        except Exception as e:
            logger.error(f"保存报告失败: {e}")

    def list_reports(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """列出报告"""
        reports = []
        try:
            for filename in sorted(os.listdir(self.reports_dir), reverse=True):
                if filename.endswith('.json'):
                    filepath = os.path.join(self.reports_dir, filename)
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    reports.append(data)
        except Exception as e:
            logger.error(f"列出报告失败: {e}")
        return reports[offset:offset + limit]

    def get_report(self, report_id: str) -> Optional[Report]:
        """获取报告"""
        try:
            filepath = os.path.join(self.reports_dir, f"{report_id}.json")
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                report = Report(**{k: v for k, v in data.items() if k in Report.__dataclass_fields__})
                if isinstance(report.report_type, str):
                    report.report_type = ReportType(report.report_type)
                if isinstance(report.format, str):
                    report.format = ReportFormat(report.format)
                # 重建漏洞对象
                report.vulnerabilities = [
                    Vulnerability(**{k: v for k, v in v.items() if k in Vulnerability.__dataclass_fields__})
                    for v in data.get('vulnerabilities', [])
                ]
                return report
        except Exception as e:
            logger.error(f"获取报告失败: {e}")
        return None

    def export_report(self, report_id: str, format: ReportFormat = None) -> Optional[str]:
        """导出报告"""
        report = self.get_report(report_id)
        if not report:
            return None

        if format and format != report.format:
            # 重新生成指定格式
            report.format = format
            report.content = self._render_report(report)
            self._save_report(report)

        ext_map = {
            ReportFormat.MARKDOWN: 'md',
            ReportFormat.HTML: 'html',
            ReportFormat.JSON: 'json',
            ReportFormat.CSV: 'csv',
        }
        ext = ext_map.get(report.format, 'txt')
        return os.path.join(self.reports_dir, f"{report.report_id}.{ext}")


# 全局报告生成器实例
_global_report_generator: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    """获取全局报告生成器实例"""
    global _global_report_generator
    if _global_report_generator is None:
        _global_report_generator = ReportGenerator()
    return _global_report_generator
