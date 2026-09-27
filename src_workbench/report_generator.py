# -*- coding: utf-8 -*-
"""
report_generator.py — SRC 报告生成模块。

符合补天/HackerOne 格式：
漏洞标题 / 漏洞类型 / URL / 描述 / 复现步骤 / 影响 / 修复建议
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_REPORTS: Dict[str, Dict[str, Any]] = {}

# 漏洞类型映射（OWASP / CWE）
VULN_TYPE_MAP = {
    "cve": "通用漏洞披露 (CVE)",
    "exposure": "敏感信息泄露 / 未授权访问",
    "vulnerability": "Web 应用漏洞",
    "tech": "技术栈指纹识别",
}

# 补天平台漏洞类型映射
BUTIAN_TYPES = {
    "sql_injection": "SQL注入",
    "xss": "跨站脚本(XSS)",
    "rce": "远程代码执行",
    "ssrf": "服务端请求伪造",
    "lfi": "本地文件包含",
    "rfi": "远程文件包含",
    "xxe": "XML外部实体注入",
    "deserialization": "反序列化漏洞",
    "upload": "任意文件上传",
    "directory_traversal": "目录遍历",
    "exposure": "敏感信息泄露",
    "misconfiguration": "安全配置错误",
    "auth_bypass": "认证绕过",
    "idor": "越权访问(IDOR)",
    "csrf": "跨站请求伪造",
    "open_redirect": "开放重定向",
}


class SRCReportGenerator:
    """SRC 提交报告生成器。"""

    # ------------------------------------------------------------------ #
    # 根据 nuclei 发现自动生成报告
    # ------------------------------------------------------------------ #
    def generate_from_finding(self, finding: Dict[str, Any],
                              platform: str = "butian",
                              project_name: str = "") -> Dict[str, Any]:
        """从单个 nuclei finding 生成标准 SRC 报告。"""
        report_id = f"RPT-{int(time.time() * 1000)}-{abs(hash(str(finding.get('url', '')))) % 10000}"

        severity = finding.get("severity", "unknown")
        name = finding.get("name", "未知漏洞")
        url = finding.get("url", "")
        category = finding.get("category", "vulnerability")
        cve_id = finding.get("cve_id")
        cwe = finding.get("cwe")
        description = finding.get("description", "")
        extracted = finding.get("extracted_results", [])

        # 漏洞标题
        title = f"[{severity.upper()}] {name}"
        if cve_id:
            title = f"[{severity.upper()}] {cve_id} {name}"

        # 漏洞类型
        vuln_type = VULN_TYPE_MAP.get(category, "Web 应用漏洞")
        # 从标签推断具体类型
        tags_str = " ".join(finding.get("tags", [])).lower()
        if "sqli" in tags_str or "sql-injection" in tags_str:
            vuln_type = "SQL注入"
        elif "xss" in tags_str:
            vuln_type = "跨站脚本(XSS)"
        elif "rce" in tags_str:
            vuln_type = "远程代码执行"
        elif "ssrf" in tags_str:
            vuln_type = "服务端请求伪造"
        elif "lfi" in tags_str:
            vuln_type = "本地文件包含"
        elif "upload" in tags_str:
            vuln_type = "任意文件上传"

        # 复现步骤
        repro_steps = self._build_repro_steps(finding)

        # 影响描述
        impact = self._build_impact(severity, name, url)

        # 修复建议
        fix = self._build_fix(name, category, cve_id)

        report = {
            "report_id": report_id,
            "project_name": project_name,
            "platform": platform,
            "created_at": datetime.now().isoformat(),
            "vulnerability": {
                "title": title,
                "type": vuln_type,
                "severity": severity,
                "url": url,
                "host": finding.get("host", ""),
                "cve_id": cve_id,
                "cwe": cwe,
                "cvss_score": finding.get("cvss_score"),
            },
            "description": description or f"目标 {url} 存在 {name} 漏洞。",
            "reproduction_steps": repro_steps,
            "impact": impact,
            "fix_suggestion": fix,
            "references": finding.get("reference", []),
            "extracted_data": extracted,
            "status": "draft",  # draft / submitted / reviewing / confirmed / fixed / ignored
            "bounty": 0,
        }

        _REPORTS[report_id] = report
        return report

    # ------------------------------------------------------------------ #
    # 批量生成报告
    # ------------------------------------------------------------------ #
    def generate_batch(self, findings: List[Dict[str, Any]],
                       platform: str = "butian",
                       project_name: str = "",
                       severity_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """从 findings 批量生成报告。"""
        if severity_filter:
            findings = [f for f in findings if f.get("severity") in severity_filter]
        reports = []
        for f in findings:
            reports.append(self.generate_from_finding(f, platform, project_name))
        return reports

    # ------------------------------------------------------------------ #
    # 复现步骤
    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_repro_steps(finding: Dict[str, Any]) -> List[str]:
        url = finding.get("url", "")
        name = finding.get("name", "")
        steps = [
            f"1. 确认目标 URL: {url}",
            f"2. 使用 nuclei 模板 [{finding.get('template_id', 'N/A')}] 对目标进行扫描",
            f"3. 扫描结果命中规则: {name}",
        ]
        extracted = finding.get("extracted_results", [])
        if extracted:
            steps.append(f"4. 提取到的敏感数据: {'; '.join(str(e) for e in extracted[:5])}")
        matcher = finding.get("matcher_name", "")
        if matcher:
            steps.append(f"5. 命中匹配器: {matcher}")
        steps.append("6. 确认漏洞可稳定复现，无 WAF 拦截。")
        return steps

    # ------------------------------------------------------------------ #
    # 影响描述
    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_impact(severity: str, name: str, url: str) -> str:
        impacts = {
            "critical": (
                f"该漏洞为严重级别，攻击者可利用 {name} "
                f"远程执行任意代码、获取服务器权限、窃取数据库敏感数据，"
                f"可能导致业务完全失控、用户数据大规模泄露。"
            ),
            "high": (
                f"该漏洞为高危级别，攻击者可利用 {name} "
                f"获取敏感系统信息、越权访问管理功能，"
                f"可能导致核心数据泄露或服务被进一步渗透。"
            ),
            "medium": (
                f"该漏洞为中危级别，攻击者可利用 {name} "
                f"获取非敏感但不应公开的系统信息，"
                f"可能为后续攻击提供情报支持。"
            ),
            "low": (
                f"该漏洞为低危级别，{name} 信息泄露风险较低，"
                f"建议作为加固项处理。"
            ),
            "info": (
                f"信息级别，{name} 仅作为技术参考，暂无直接利用风险。"
            ),
        }
        return impacts.get(severity, f"该漏洞可能对目标 {url} 造成安全影响。")

    # ------------------------------------------------------------------ #
    # 修复建议
    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_fix(name: str, category: str, cve_id: Optional[str] = None) -> str:
        suggestions = {
            "exposure": "建议：1. 关闭不必要的端口和服务；2. 配置访问控制（IP白名单/认证）；"
                        "3. 移除 Web 根目录下的敏感文件（.git、.svn、phpinfo.php 等）；"
                        "4. 配置反向代理隐藏后端服务信息。",
            "vulnerability": "建议：1. 及时升级到最新版本；2. 对用户输入进行严格校验和过滤；"
                             "3. 部署 WAF 规则拦截常见攻击 payload；4. 遵循最小权限原则配置服务。",
            "cve": f"建议：1. 关注 {cve_id or '该 CVE'} 的官方补丁通告；"
                   "2. 及时升级受影响组件到安全版本；3. 临时缓解可通过 WAF 规则或网络层访问控制；"
                   "4. 升级前在测试环境验证兼容性。",
            "tech": "建议：定期进行技术栈审计，确保所有组件均为最新安全版本。",
        }
        return suggestions.get(category, "建议及时升级相关组件，配置安全基线。")

    # ------------------------------------------------------------------ #
    # 格式化报告为 Markdown（补天/HackerOne 风格）
    # ------------------------------------------------------------------ #
    def format_markdown(self, report_id: str) -> str:
        """将报告格式化为 Markdown 提交文本。"""
        r = _REPORTS.get(report_id)
        if not r:
            return ""

        v = r["vulnerability"]
        lines = [
            f"# {v['title']}",
            "",
            f"**平台**: {r['platform']}",
            f"**项目**: {r['project_name']}",
            f"**提交时间**: {r['created_at']}",
            "",
            "---",
            "",
            "## 漏洞信息",
            "",
            f"- **漏洞类型**: {v['type']}",
            f"- **严重程度**: {v['severity'].upper()}",
            f"- **目标 URL**: {v['url']}",
            f"- **主机**: {v['host']}",
        ]
        if v.get("cve_id"):
            lines.append(f"- **CVE**: {v['cve_id']}")
        if v.get("cwe"):
            lines.append(f"- **CWE**: {v['cwe']}")
        if v.get("cvss_score"):
            lines.append(f"- **CVSS Score**: {v['cvss_score']}")

        lines.extend([
            "",
            "## 漏洞描述",
            "",
            r["description"],
            "",
            "## 复现步骤",
            "",
        ])
        for step in r["reproduction_steps"]:
            lines.append(step)

        lines.extend([
            "",
            "## 影响评估",
            "",
            r["impact"],
            "",
            "## 修复建议",
            "",
            r["fix_suggestion"],
        ])

        if r.get("references"):
            lines.extend(["", "## 参考链接", ""])
            for ref in r["references"]:
                lines.append(f"- {ref}")

        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # 报告管理
    # ------------------------------------------------------------------ #
    def get_report(self, report_id: str) -> Dict[str, Any]:
        return _REPORTS.get(report_id, {})

    def list_reports(self, project_name: Optional[str] = None,
                     status: Optional[str] = None) -> List[Dict[str, Any]]:
        reports = sorted(_REPORTS.values(), key=lambda x: x.get("created_at", ""), reverse=True)
        if project_name:
            reports = [r for r in reports if r.get("project_name") == project_name]
        if status:
            reports = [r for r in reports if r.get("status") == status]
        return reports

    def update_report_status(self, report_id: str, status: str,
                             bounty: Optional[float] = None) -> Dict[str, Any]:
        if report_id in _REPORTS:
            _REPORTS[report_id]["status"] = status
            if bounty is not None:
                _REPORTS[report_id]["bounty"] = bounty
        return _REPORTS.get(report_id, {})

    def delete_report(self, report_id: str) -> bool:
        if report_id in _REPORTS:
            del _REPORTS[report_id]
            return True
        return False
