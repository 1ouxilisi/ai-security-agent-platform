"""
专业级渗透测试报告生成模块
- 真实数据引用
- 专业报告结构
- AI辅助分析
- 多格式输出（Markdown/HTML/JSON）
"""

import json
import time
import os
from typing import Dict, List, Any, Optional
from datetime import datetime


class ReportGenerator:
    """专业级渗透测试报告生成器"""

    def __init__(self, scan_data: Dict[str, Any], target: str = ""):
        self.scan_data = scan_data
        self.target = target or scan_data.get("target", "未知目标")
        self.report_id = f"PT-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_full_report(self) -> Dict[str, Any]:
        """生成完整报告"""
        report = {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "target": self.target,
            "executive_summary": self._generate_executive_summary(),
            "scope_and_methodology": self._generate_scope_methodology(),
            "asset_discovery": self._generate_asset_discovery(),
            "vulnerability_findings": self._generate_vulnerability_findings(),
            "attack_path_analysis": self._generate_attack_path_analysis(),
            "risk_assessment": self._generate_risk_assessment(),
            "remediation_plan": self._generate_remediation_plan(),
            "appendix": self._generate_appendix()
        }
        return report

    def _generate_executive_summary(self) -> Dict[str, Any]:
        """生成执行摘要"""
        vulns = self.scan_data.get("vulnerabilities", [])
        asm_result = self.scan_data.get("asm", {})

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulns:
            sev = v.get("severity", "low").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        total_vulns = len(vulns)
        risk_score = min(
            severity_counts["critical"] * 10 +
            severity_counts["high"] * 7 +
            severity_counts["medium"] * 4 +
            severity_counts["low"] * 1,
            100
        )

        if risk_score >= 70:
            overall_risk = "严重"
            risk_description = "目标存在严重安全风险，建议立即采取修复措施"
        elif risk_score >= 40:
            overall_risk = "高危"
            risk_description = "目标存在高危安全风险，建议在7天内完成修复"
        elif risk_score >= 15:
            overall_risk = "中危"
            risk_description = "目标存在中等安全风险，建议在30天内完成修复"
        else:
            overall_risk = "低危"
            risk_description = "目标安全状况良好，建议定期维护"

        # 关键发现
        key_findings = []
        for v in vulns[:5]:
            key_findings.append({
                "name": v.get("template_name", v.get("name", "未知漏洞")),
                "severity": v.get("severity", "low"),
                "evidence": v.get("evidence", v.get("matched_matcher", ""))
            })

        return {
            "overall_risk": overall_risk,
            "risk_score": risk_score,
            "risk_description": risk_description,
            "total_vulnerabilities": total_vulns,
            "severity_distribution": severity_counts,
            "key_findings": key_findings,
            "assets_discovered": asm_result.get("total_assets", 0),
            "open_ports": asm_result.get("total_open_ports", 0),
            "recommendation": self._generate_top_recommendation(overall_risk)
        }

    def _generate_top_recommendation(self, risk_level: str) -> str:
        """生成顶层建议"""
        recommendations = {
            "严重": "立即暂停相关服务，启动应急响应流程，优先修复严重和高危漏洞，完成后进行复测",
            "高危": "在7天内完成高危漏洞修复，建立漏洞管理流程，定期进行安全评估",
            "中危": "在30天内完成中危漏洞修复，加强安全意识培训，部署Web应用防火墙",
            "低危": "将低危问题纳入日常维护，定期进行安全扫描，持续监控安全状态"
        }
        return recommendations.get(risk_level, "持续监控安全状态")

    def _generate_scope_methodology(self) -> Dict[str, Any]:
        """生成评估范围和方法"""
        return {
            "assessment_type": "自动化安全评估",
            "target": self.target,
            "assessment_date": self.generated_at,
            "methodology": [
                "1. 资产发现：端口扫描、服务识别、DNS枚举、技术栈检测",
                "2. 漏洞扫描：基于Nuclei风格模板引擎，覆盖SQL注入/XSS/命令执行/SSRF等15+漏洞类型",
                "3. 攻击面管理：暴露面评估、攻击路径分析、风险优先级排序",
                "4. 深度侦察：子域名爆破、目录扫描、API端点发现",
                "5. 报告生成：自动汇总扫描结果，生成专业级安全报告"
            ],
            "tools_used": [
                "端口扫描引擎（socket全并发）",
                "Nuclei风格漏洞模板引擎（15+内置模板）",
                "ASM攻击面管理模块（4阶段评估）",
                "深度侦察模块（子域名/目录/API端点）",
                "安全头审计/CORS测试/点击劫持测试"
            ],
            "limitations": [
                "本次评估为自动化扫描，未包含人工渗透测试",
                "扫描结果可能存在误报，建议对发现的漏洞进行人工验证",
                "扫描受限于网络环境和目标防护机制",
                "未进行拒绝服务测试和社会工程学测试"
            ]
        }

    def _generate_asset_discovery(self) -> Dict[str, Any]:
        """生成资产发现结果"""
        asm = self.scan_data.get("asm", {})
        phase1 = asm.get("phase1_asset_discovery", {})
        summary = phase1.get("summary", {})

        return {
            "total_ips": summary.get("total_ips", 0),
            "total_open_ports": summary.get("total_open_ports", 0),
            "total_services": summary.get("total_services", 0),
            "total_dns_records": summary.get("total_dns_records", 0),
            "total_certificates": summary.get("total_certificates", 0),
            "open_ports_detail": phase1.get("open_ports", []),
            "services_detail": phase1.get("services", []),
            "subdomains": self.scan_data.get("subdomains", []),
            "directories": self.scan_data.get("directories", []),
            "api_endpoints": self.scan_data.get("api_endpoints", []),
            "tech_stack": self.scan_data.get("tech_stack", {})
        }

    def _generate_vulnerability_findings(self) -> Dict[str, Any]:
        """生成漏洞发现详情"""
        vulns = self.scan_data.get("vulnerabilities", [])

        # 按严重程度分组
        grouped = {"critical": [], "high": [], "medium": [], "low": []}
        for v in vulns:
            sev = v.get("severity", "low").lower()
            if sev in grouped:
                grouped[sev].append(v)

        # 生成详细的漏洞条目
        detailed_findings = []
        for v in vulns:
            detailed_findings.append({
                "id": v.get("template_id", v.get("id", "")),
                "name": v.get("template_name", v.get("name", "")),
                "severity": v.get("severity", "low"),
                "category": v.get("category", "其他"),
                "description": v.get("description", ""),
                "affected_url": v.get("request", {}).get("url", ""),
                "affected_path": v.get("request", {}).get("path", ""),
                "method": v.get("request", {}).get("method", "GET"),
                "evidence": v.get("evidence", v.get("matched_matcher", "")),
                "remediation": self._get_remediation_for_vuln(v.get("template_id", ""))
            })

        return {
            "total": len(vulns),
            "by_severity": {k: len(v) for k, v in grouped.items()},
            "by_category": self._count_by_category(vulns),
            "findings": detailed_findings
        }

    def _get_remediation_for_vuln(self, vuln_id: str) -> str:
        """获取漏洞修复建议"""
        remediations = {
            "sqli-error-based": "使用参数化查询/预编译语句，对用户输入进行严格过滤和转义，部署WAF",
            "sqli-union-based": "使用参数化查询，限制数据库用户权限，禁用UNION查询（如非必要），部署WAF",
            "xss-reflected": "对输出进行HTML编码，使用Content-Security-Policy，设置HttpOnly Cookie",
            "xss-dom": "避免使用innerHTML/document.write，使用textContent，对URL参数进行编码",
            "path-traversal": "对文件路径进行白名单校验，使用安全的文件API，禁止路径遍历字符",
            "command-injection": "避免使用系统命令，使用安全的API，对输入进行严格白名单校验",
            "ssrf": "对URL进行白名单校验，禁止访问内网地址，使用DNS重绑定防护",
            "xxe": "禁用XML外部实体解析，使用安全的XML解析器",
            "open-redirect": "对重定向URL进行白名单校验，禁止跳转到外部域名",
            "sensitive-files": "配置Web服务器禁止访问敏感文件，删除不必要的备份文件和配置文件",
            "default-credentials": "修改默认凭证，实施强密码策略，启用多因素认证",
            "cors-misconfiguration": "严格配置Access-Control-Allow-Origin，禁止使用通配符，谨慎使用Allow-Credentials",
            "clickjacking": "设置X-Frame-Options: DENY/SAMEORIGIN，配置Content-Security-Policy: frame-ancestors",
            "missing-security-headers": "添加X-Content-Type-Options、X-XSS-Protection、Strict-Transport-Security、Referrer-Policy等安全响应头"
        }
        return remediations.get(vuln_id, "建议进行人工验证并根据具体情况采取修复措施")

    def _count_by_category(self, vulns: List[Dict]) -> Dict[str, int]:
        """按类别统计漏洞"""
        categories = {}
        for v in vulns:
            cat = v.get("category", "其他")
            categories[cat] = categories.get(cat, 0) + 1
        return categories

    def _generate_attack_path_analysis(self) -> Dict[str, Any]:
        """生成攻击路径分析"""
        asm = self.scan_data.get("asm", {})
        phase3 = asm.get("phase3_attack_path_analysis", {})

        return {
            "entry_points": phase3.get("entry_points", []),
            "attack_paths": phase3.get("attack_paths", []),
            "attack_chain": phase3.get("attack_chain", []),
            "defense_recommendations": phase3.get("defense_recommendations", [])
        }

    def _generate_risk_assessment(self) -> Dict[str, Any]:
        """生成风险评估"""
        asm = self.scan_data.get("asm", {})
        phase2 = asm.get("phase2_exposure_assessment", {})
        phase4 = asm.get("phase4_risk_prioritization", {})

        return {
            "exposure_assessment": {
                "overall_risk": phase2.get("overall_risk", {}),
                "risk_distribution": phase2.get("risk_distribution", {}),
                "high_risk_ports": phase2.get("high_risk_ports", []),
                "heatmap": phase2.get("heatmap", {})
            },
            "risk_prioritization": {
                "prioritized_risks": phase4.get("prioritized_risks", []),
                "remediation_plan": phase4.get("remediation_plan", {}),
                "risk_matrix": phase4.get("risk_matrix", {})
            }
        }

    def _generate_remediation_plan(self) -> Dict[str, Any]:
        """生成修复计划"""
        vulns = self.scan_data.get("vulnerabilities", [])

        # 按优先级分组
        p0_vulns = [v for v in vulns if v.get("severity", "").lower() == "critical"]
        p1_vulns = [v for v in vulns if v.get("severity", "").lower() == "high"]
        p2_vulns = [v for v in vulns if v.get("severity", "").lower() == "medium"]
        p3_vulns = [v for v in vulns if v.get("severity", "").lower() == "low"]

        return {
            "summary": {
                "P0_critical": len(p0_vulns),
                "P1_high": len(p1_vulns),
                "P2_medium": len(p2_vulns),
                "P3_low": len(p3_vulns),
                "total_effort_estimate": self._estimate_effort(len(p0_vulns), len(p1_vulns), len(p2_vulns), len(p3_vulns))
            },
            "P0_immediate_24h": [self._format_remediation_item(v) for v in p0_vulns],
            "P1_high_7days": [self._format_remediation_item(v) for v in p1_vulns],
            "P2_medium_30days": [self._format_remediation_item(v) for v in p2_vulns],
            "P3_low_90days": [self._format_remediation_item(v) for v in p3_vulns],
            "general_recommendations": [
                "建立漏洞管理流程，定期进行安全评估",
                "部署Web应用防火墙（WAF），提供额外保护层",
                "实施安全编码规范，从源头减少漏洞",
                "加强安全意识培训，提高团队安全水平",
                "建立应急响应机制，及时处理安全事件",
                "定期备份数据，确保业务连续性"
            ]
        }

    def _format_remediation_item(self, vuln: Dict) -> Dict[str, Any]:
        """格式化修复条目"""
        return {
            "vulnerability": vuln.get("template_name", vuln.get("name", "")),
            "severity": vuln.get("severity", "low"),
            "affected_url": vuln.get("request", {}).get("url", ""),
            "evidence": vuln.get("evidence", ""),
            "remediation": self._get_remediation_for_vuln(vuln.get("template_id", ""))
        }

    def _estimate_effort(self, p0: int, p1: int, p2: int, p3: int) -> str:
        """估算修复工作量"""
        hours = p0 * 8 + p1 * 4 + p2 * 2 + p3 * 0.5
        if hours < 8:
            return f"约{hours:.1f}小时（1人天内）"
        elif hours < 40:
            return f"约{hours:.1f}小时（约{hours/8:.1f}人天）"
        else:
            return f"约{hours:.1f}小时（约{hours/40:.1f}人周）"

    def _generate_appendix(self) -> Dict[str, Any]:
        """生成附录"""
        return {
            "tool_versions": {
                "扫描引擎": "NucleiEngine v1.0",
                "ASM模块": "AttackSurfaceManager v1.0",
                "深度侦察": "DeepRecon v1.0"
            },
            "vulnerability_templates_used": [
                "sqli-error-based", "sqli-union-based",
                "xss-reflected", "xss-dom",
                "path-traversal", "command-injection",
                "ssrf", "xxe", "open-redirect",
                "sensitive-files", "default-credentials",
                "cors-misconfiguration", "clickjacking",
                "missing-security-headers"
            ],
            "severity_definitions": {
                "critical": "可直接获取服务器权限/敏感数据，无需用户交互",
                "high": "可获取敏感数据/执行特定操作，可能需要一定条件",
                "medium": "可获取部分信息/影响特定功能，需要特定条件",
                "low": "信息泄露/配置不当，影响较小"
            },
            "disclaimer": "本报告由自动化工具生成，扫描结果可能存在误报，建议对发现的漏洞进行人工验证。本报告仅用于授权范围内的安全评估，不得用于非法用途。"
        }

    def generate_markdown_report(self) -> str:
        """生成Markdown格式报告"""
        report = self.generate_full_report()
        exec_sum = report["executive_summary"]

        md = f"""# 渗透测试安全评估报告

**报告编号**: {report['report_id']}
**生成时间**: {report['generated_at']}
**评估目标**: {report['target']}

---

## 一、执行摘要

### 整体风险评级: **{exec_sum['overall_risk']}** (风险评分: {exec_sum['risk_score']}/100)

{exec_sum['risk_description']}

### 漏洞统计

| 严重程度 | 数量 |
|---------|------|
| 严重(Critical) | {exec_sum['severity_distribution']['critical']} |
| 高危(High) | {exec_sum['severity_distribution']['high']} |
| 中危(Medium) | {exec_sum['severity_distribution']['medium']} |
| 低危(Low) | {exec_sum['severity_distribution']['low']} |
| **总计** | **{exec_sum['total_vulnerabilities']}** |

### 关键发现

"""
        for i, finding in enumerate(exec_sum["key_findings"][:5], 1):
            md += f"{i}. **[{finding['severity'].upper()}] {finding['name']}**\n"
            if finding.get("evidence"):
                md += f"   - 证据: {finding['evidence']}\n"
            md += "\n"

        md += f"""### 顶层建议

{exec_sum['recommendation']}

---

## 二、评估范围与方法

### 评估类型
{report['scope_and_methodology']['assessment_type']}

### 评估方法
"""
        for method in report["scope_and_methodology"]["methodology"]:
            md += f"- {method}\n"

        md += "\n### 使用工具\n"
        for tool in report["scope_and_methodology"]["tools_used"]:
            md += f"- {tool}\n"

        md += "\n### 评估局限性\n"
        for limit in report["scope_and_methodology"]["limitations"]:
            md += f"- {limit}\n"

        md += "\n---\n\n## 三、资产发现\n\n"
        assets = report["asset_discovery"]
        md += f"""| 指标 | 数量 |
|------|------|
| IP地址 | {assets['total_ips']} |
| 开放端口 | {assets['total_open_ports']} |
| 服务 | {assets['total_services']} |
| DNS记录 | {assets['total_dns_records']} |
| 证书 | {assets['total_certificates']} |

"""

        if assets.get("open_ports_detail"):
            md += "### 开放端口详情\n\n| 端口 | 服务 |\n|------|------|\n"
            for port in assets["open_ports_detail"][:20]:
                md += f"| {port.get('port', '')} | {port.get('service', '')} |\n"
            md += "\n"

        md += "---\n\n## 四、漏洞发现详情\n\n"
        vulns = report["vulnerability_findings"]
        md += f"共发现 **{vulns['total']}** 个漏洞\n\n"

        for finding in vulns["findings"][:20]:
            md += f"""### [{finding['severity'].upper()}] {finding['name']}

- **类别**: {finding['category']}
- **描述**: {finding['description']}
- **影响URL**: `{finding['affected_url']}`
- **请求方法**: {finding['method']}
- **证据**: {finding['evidence']}
- **修复建议**: {finding['remediation']}

"""

        md += "---\n\n## 五、修复计划\n\n"
        plan = report["remediation_plan"]
        md += f"""### 修复工作量估算
{plan['summary']['total_effort_estimate']}

### P0 - 紧急（24小时内修复）
共 {plan['summary']['P0_critical']} 个

"""
        for item in plan["P0_immediate_24h"]:
            md += f"- **{item['vulnerability']}**: {item['remediation']}\n"

        md += f"\n### P1 - 高危（7天内修复）\n共 {plan['summary']['P1_high']} 个\n\n"
        for item in plan["P1_high_7days"]:
            md += f"- **{item['vulnerability']}**: {item['remediation']}\n"

        md += f"\n### P2 - 中危（30天内修复）\n共 {plan['summary']['P2_medium']} 个\n\n"
        for item in plan["P2_medium_30days"][:10]:
            md += f"- **{item['vulnerability']}**: {item['remediation']}\n"

        md += f"\n### P3 - 低危（90天内修复）\n共 {plan['summary']['P3_low']} 个\n\n"
        for item in plan["P3_low_90days"][:5]:
            md += f"- **{item['vulnerability']}**: {item['remediation']}\n"

        md += "\n### 通用安全建议\n\n"
        for rec in plan["general_recommendations"]:
            md += f"- {rec}\n"

        md += f"""

---

## 六、附录

### 免责声明
{report['appendix']['disclaimer']}

### 严重程度定义
- **Critical**: {report['appendix']['severity_definitions']['critical']}
- **High**: {report['appendix']['severity_definitions']['high']}
- **Medium**: {report['appendix']['severity_definitions']['medium']}
- **Low**: {report['appendix']['severity_definitions']['low']}

---

*报告由 AI全栈安全渗透测试平台 自动生成*
"""
        return md

    def save_report(self, output_dir: str = "", format: str = "json") -> str:
        """保存报告到文件"""
        if not output_dir:
            output_dir = os.getcwd()

        os.makedirs(output_dir, exist_ok=True)

        if format == "json":
            report = self.generate_full_report()
            filepath = os.path.join(output_dir, f"report_{self.report_id}.json")
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
        elif format == "markdown":
            md = self.generate_markdown_report()
            filepath = os.path.join(output_dir, f"report_{self.report_id}.md")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(md)
        else:
            raise ValueError(f"不支持的格式: {format}")

        return filepath
