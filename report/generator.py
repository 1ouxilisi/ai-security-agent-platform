#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generator模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from collections import Counter

from utils.logger import log


class ReportGenerator:
    """专业渗透测试报告生成器"""

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    SEVERITY_COLORS = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#20c997",
        "info": "#0dcaf0"
    }

    def __init__(self):
        """初始化ReportGenerator实例。

        Args:
            self: 类实例。
        """
        self.report_template = ""

    def generate_report(self, workflow_instance: Any, format: str = "markdown") -> str:
        """
        生成渗透测试报告
        :param workflow_instance: 工作流实例对象
        :param format: 输出格式 markdown/html
        :return: 报告内容
        """
        log.info(f"生成报告: {workflow_instance.name}, 格式: {format}")

        # 提取数据
        data = self._extract_data(workflow_instance)

        if format == "html":
            return self._generate_html(data)
        else:
            return self._generate_markdown(data)

    def _extract_data(self, instance: Any) -> Dict[str, Any]:
        """从工作流实例中提取真实数据"""
        data = {
            "report_title": f"渗透测试报告 - {instance.target}",
            "target": instance.target,
            "workflow_name": instance.name,
            "instance_id": instance.instance_id,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": round((instance.end_time - instance.start_time), 2) if instance.start_time and instance.end_time else 0,
            "phases": [],
            "vulnerabilities": [],
            "open_ports": [],
            "services": {},
            "findings_summary": {},
            "ai_analyses": {}
        }

        all_vulns = []
        all_open_ports = set()
        all_services = {}

        for phase in instance.phases:
            phase_data = {
                "name": phase.name,
                "description": phase.description,
                "status": phase.status.value if hasattr(phase.status, 'value') else str(phase.status),
                "tools_executed": len(phase.results),
                "duration_ms": phase.to_dict().get("duration_ms"),
                "ai_analysis": phase.ai_analysis,
                "tools": []
            }

            if phase.ai_analysis:
                data["ai_analyses"][phase.name] = phase.ai_analysis

            for result in phase.results:
                tool_data = {
                    "tool_name": result.get("tool_name", "unknown"),
                    "status": result.get("status", "unknown"),
                    "parameters": result.get("parameters", {}),
                    "error": result.get("error")
                }

                if result.get("status") == "success" and result.get("result"):
                    r = result["result"]
                    if isinstance(r, dict):
                        # 提取开放端口
                        if r.get("open_ports"):
                            all_open_ports.update(r["open_ports"])
                        # 提取服务
                        if r.get("services"):
                            if isinstance(r["services"], dict):
                                all_services.update(r["services"])
                        # 提取漏洞
                        if r.get("vulnerabilities"):
                            for v in r["vulnerabilities"]:
                                if isinstance(v, dict):
                                    v["_source_tool"] = result.get("tool_name")
                                    v["_source_phase"] = phase.name
                                    all_vulns.append(v)

                        tool_data["result_summary"] = self._summarize_result(r)

                phase_data["tools"].append(tool_data)

            data["phases"].append(phase_data)

        # 漏洞按严重程度排序
        all_vulns.sort(key=lambda v: self.SEVERITY_ORDER.get(v.get("severity", "info"), 5))

        data["vulnerabilities"] = all_vulns
        data["open_ports"] = sorted(list(all_open_ports))
        data["services"] = all_services

        # 统计
        severity_counts = Counter(v.get("severity", "info").lower() for v in all_vulns)
        data["findings_summary"] = {
            "total_vulnerabilities": len(all_vulns),
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
            "open_ports_count": len(all_open_ports),
            "services_count": len(all_services),
            "phases_completed": sum(1 for p in instance.phases if p.status.value == "completed"),
            "phases_total": len(instance.phases),
            "tools_total": sum(len(p.tools) for p in instance.phases),
            "tools_successful": sum(
                sum(1 for r in p.results if r.get("status") == "success")
                for p in instance.phases
            )
        }

        # 整体风险评级
        if severity_counts.get("critical", 0) > 0:
            data["overall_risk"] = "Critical"
        elif severity_counts.get("high", 0) > 0:
            data["overall_risk"] = "High"
        elif severity_counts.get("medium", 0) > 0:
            data["overall_risk"] = "Medium"
        elif severity_counts.get("low", 0) > 0:
            data["overall_risk"] = "Low"
        else:
            data["overall_risk"] = "Info"

        return data

    def _summarize_result(self, result: Dict[str, Any]) -> str:
        """简要总结工具结果"""
        summary_parts = []
        if result.get("open_ports"):
            summary_parts.append(f"开放端口: {', '.join(map(str, result['open_ports'][:10]))}")
        if result.get("vulnerabilities"):
            summary_parts.append(f"发现漏洞: {len(result['vulnerabilities'])}个")
        if result.get("services"):
            summary_parts.append(f"服务: {len(result['services'])}个")
        if result.get("status_code"):
            summary_parts.append(f"HTTP状态: {result['status_code']}")
        if not summary_parts:
            keys = list(result.keys())[:5]
            summary_parts.append(f"返回字段: {', '.join(keys)}")
        return "; ".join(summary_parts)

    def _generate_markdown(self, data: Dict[str, Any]) -> str:
        """生成Markdown格式报告"""
        lines = []

        # 标题
        lines.append(f"# {data['report_title']}")
        lines.append("")
        lines.append(f"**生成时间**: {data['generated_at']}  ")
        lines.append(f"**测试目标**: {data['target']}  ")
        lines.append(f"**工作流**: {data['workflow_name']}  ")
        lines.append(f"**执行时长**: {data['duration_seconds']}秒  ")
        lines.append(f"**整体风险评级**: **{data['overall_risk']}**  ")
        lines.append("")

        # 执行摘要
        lines.append("## 1. 执行摘要")
        lines.append("")
        s = data["findings_summary"]
        lines.append(f"本次渗透测试针对目标 **{data['target']}** 执行，共完成 {s['phases_completed']}/{s['phases_total']} 个测试阶段，"
                     f"执行 {s['tools_successful']}/{s['tools_total']} 个工具，发现 **{s['total_vulnerabilities']}** 个安全问题。")
        lines.append("")
        lines.append("| 严重程度 | 数量 |")
        lines.append("|----------|------|")
        lines.append(f"| Critical | {s['critical']} |")
        lines.append(f"| High | {s['high']} |")
        lines.append(f"| Medium | {s['medium']} |")
        lines.append(f"| Low | {s['low']} |")
        lines.append(f"| Info | {s['info']} |")
        lines.append("")

        if data["open_ports"]:
            lines.append(f"**开放端口**: {', '.join(map(str, data['open_ports']))}")
            lines.append("")

        # 测试方法论
        lines.append("## 2. 测试方法论")
        lines.append("")
        lines.append("本次测试遵循PTES（Penetration Testing Execution Standard）标准，采用AI驱动的自动化渗透测试工作流，包含以下阶段：")
        lines.append("")
        for i, phase in enumerate(data["phases"], 1):
            status_icon = "✅" if phase["status"] == "completed" else "⏭️" if phase["status"] == "skipped" else "❌"
            lines.append(f"{i}. **{phase['name']}** {status_icon} - {phase['description']}")
        lines.append("")

        # 情报收集结果
        lines.append("## 3. 情报收集结果")
        lines.append("")
        lines.append("### 3.1 开放端口和服务")
        lines.append("")
        if data["open_ports"]:
            lines.append("| 端口 | 服务 |")
            lines.append("|------|------|")
            for port in data["open_ports"]:
                service = data["services"].get(str(port), {}).get("service", "Unknown")
                lines.append(f"| {port} | {service} |")
        else:
            lines.append("未发现开放端口。")
        lines.append("")

        # 漏洞清单
        lines.append("## 4. 漏洞清单")
        lines.append("")
        if data["vulnerabilities"]:
            for i, vuln in enumerate(data["vulnerabilities"], 1):
                severity = vuln.get("severity", "info").upper()
                lines.append(f"### 4.{i} [{severity}] {vuln.get('name', '未知漏洞')}")
                lines.append("")
                lines.append(f"- **严重程度**: {severity}")
                lines.append(f"- **发现阶段**: {vuln.get('_source_phase', '未知')}")
                lines.append(f"- **发现工具**: {vuln.get('_source_tool', '未知')}")
                if vuln.get("affected"):
                    lines.append(f"- **影响范围**: {vuln['affected']}")
                if vuln.get("description"):
                    lines.append(f"- **漏洞描述**: {vuln['description']}")
                if vuln.get("recommendation"):
                    lines.append(f"- **修复建议**: {vuln['recommendation']}")
                lines.append("")
        else:
            lines.append("未发现安全漏洞。")
            lines.append("")

        # 风险分析
        lines.append("## 5. 风险分析")
        lines.append("")
        lines.append(f"**整体风险评级**: **{data['overall_risk']}**")
        lines.append("")
        if data["overall_risk"] in ("Critical", "High"):
            lines.append("⚠️ 目标系统存在高危安全漏洞，建议立即采取修复措施。攻击者可能利用这些漏洞获取系统访问权限、窃取敏感数据或造成服务中断。")
        elif data["overall_risk"] == "Medium":
            lines.append("目标系统存在中等风险安全问题，建议在合理时间内修复。这些漏洞可能被攻击者用于信息收集或作为进一步攻击的跳板。")
        else:
            lines.append("目标系统安全状况良好，仅存在低风险或信息性发现。建议持续关注并定期进行安全测试。")
        lines.append("")

        # 修复建议
        lines.append("## 6. 修复建议")
        lines.append("")
        lines.append("### 6.1 紧急修复（24小时内）")
        lines.append("")
        critical_vulns = [v for v in data["vulnerabilities"] if v.get("severity", "").lower() == "critical"]
        if critical_vulns:
            for v in critical_vulns:
                lines.append(f"- [ ] **{v.get('name')}**: {v.get('recommendation', '立即修复')}")
        else:
            lines.append("- 无紧急修复项")
        lines.append("")

        lines.append("### 6.2 高优先级修复（1周内）")
        lines.append("")
        high_vulns = [v for v in data["vulnerabilities"] if v.get("severity", "").lower() == "high"]
        if high_vulns:
            for v in high_vulns:
                lines.append(f"- [ ] **{v.get('name')}**: {v.get('recommendation', '尽快修复')}")
        else:
            lines.append("- 无高优先级修复项")
        lines.append("")

        lines.append("### 6.3 中低优先级修复（1个月内）")
        lines.append("")
        other_vulns = [v for v in data["vulnerabilities"] if v.get("severity", "").lower() in ("medium", "low")]
        if other_vulns:
            for v in other_vulns[:10]:
                lines.append(f"- [ ] **{v.get('name')}**: {v.get('recommendation', '计划修复')}")
        else:
            lines.append("- 无中低优先级修复项")
        lines.append("")

        # AI分析摘要
        if data["ai_analyses"]:
            lines.append("## 7. AI智能分析摘要")
            lines.append("")
            for phase_name, analysis in data["ai_analyses"].items():
                lines.append(f"### 7.{list(data['ai_analyses'].keys()).index(phase_name)+1} {phase_name}")
                lines.append("")
                lines.append(analysis[:2000] if len(analysis) > 2000 else analysis)
                lines.append("")

        # 附录
        lines.append("## 8. 附录")
        lines.append("")
        lines.append("### 8.1 工具执行详情")
        lines.append("")
        for phase in data["phases"]:
            lines.append(f"#### {phase['name']}")
            lines.append("")
            lines.append("| 工具名称 | 状态 | 结果摘要 |")
            lines.append("|----------|------|----------|")
            for tool in phase["tools"]:
                status = "✅" if tool["status"] == "success" else "❌"
                summary = tool.get("result_summary", tool.get("error", "-"))[:80]
                lines.append(f"| {tool['tool_name']} | {status} | {summary} |")
            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(f"*报告由 AI Hacking Agent 自动生成 - {data['generated_at']}*")

        return "\n".join(lines)

    def _generate_html(self, data: Dict[str, Any]) -> str:
        """生成HTML格式报告"""
        # 简化版HTML，实际项目中可以用模板引擎
        md_content = self._generate_markdown(data)
        html_body = self._markdown_to_html_simple(md_content)

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{data['report_title']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; line-height: 1.6; color: #333; }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
        h2 {{ color: #16213e; border-left: 4px solid #e94560; padding-left: 10px; margin-top: 30px; }}
        h3 {{ color: #0f3460; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
        th {{ background-color: #f8f9fa; font-weight: 600; }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        .severity-critical {{ background-color: #dc3545; color: white; padding: 2px 8px; border-radius: 4px; }}
        .severity-high {{ background-color: #fd7e14; color: white; padding: 2px 8px; border-radius: 4px; }}
        .severity-medium {{ background-color: #ffc107; color: #333; padding: 2px 8px; border-radius: 4px; }}
        .severity-low {{ background-color: #20c997; color: white; padding: 2px 8px; border-radius: 4px; }}
        .risk-box {{ padding: 15px; border-radius: 8px; margin: 15px 0; }}
        .risk-critical {{ background-color: #fff5f5; border: 2px solid #dc3545; }}
        .risk-high {{ background-color: #fff8f0; border: 2px solid #fd7e14; }}
        .risk-medium {{ background-color: #fffdf0; border: 2px solid #ffc107; }}
        .risk-low {{ background-color: #f0fff9; border: 2px solid #20c997; }}
        code {{ background-color: #f1f3f5; padding: 2px 6px; border-radius: 4px; font-family: 'Consolas', monospace; }}
        pre {{ background-color: #f8f9fa; padding: 15px; border-radius: 8px; overflow-x: auto; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
{html_body}
<div class="footer">
    <p>报告由 AI Hacking Agent 自动生成 - {data['generated_at']}</p>
</div>
</body>
</html>"""

    def _markdown_to_html_simple(self, md: str) -> str:
        """简易Markdown转HTML（仅用于报告展示）"""
        import re
        lines = md.split('\n')
        html_lines = []
        in_table = False
        in_code = False

        for line in lines:
            # 标题
            if line.startswith('# '):
                html_lines.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith('## '):
                html_lines.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith('### '):
                html_lines.append(f"<h3>{line[4:]}</h3>")
            elif line.startswith('#### '):
                html_lines.append(f"<h4>{line[5:]}</h4>")
            # 表格
            elif line.startswith('|') and '|' in line[1:]:
                if not in_table:
                    html_lines.append("<table>")
                    in_table = True
                cells = [c.strip() for c in line.split('|')[1:-1]]
                if all(set(c) <= set('-: ') for c in cells):
                    continue  # 分隔行
                tag = 'th' if not any(html_lines[-1].startswith('<tr>') for _ in [1]) else 'td'
                html_lines.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
            else:
                if in_table:
                    html_lines.append("</table>")
                    in_table = False
                # 粗体
                line = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', line)
                # 列表
                if line.startswith('- '):
                    html_lines.append(f"<li>{line[2:]}</li>")
                elif line.strip() == '---':
                    html_lines.append("<hr>")
                elif line.strip():
                    html_lines.append(f"<p>{line}</p>")

        if in_table:
            html_lines.append("</table>")

        return "\n".join(html_lines)

    def generate_executive_summary(self, data: Dict[str, Any]) -> str:
        """生成执行摘要（用于快速浏览）"""
        s = data["findings_summary"]
        summary = f"""
## 执行摘要

**目标**: {data['target']}
**整体风险**: {data['overall_risk']}
**执行时长**: {data['duration_seconds']}秒

### 关键发现
- 开放端口: {', '.join(map(str, data['open_ports'][:10])) if data['open_ports'] else '无'}
- 漏洞总数: {s['total_vulnerabilities']} (Critical: {s['critical']}, High: {s['high']}, Medium: {s['medium']})
- 完成阶段: {s['phases_completed']}/{s['phases_total']}
- 成功工具: {s['tools_successful']}/{s['tools_total']}

### Top 3 高危漏洞
"""
        high_vulns = [v for v in data["vulnerabilities"] if v.get("severity", "").lower() in ("critical", "high")][:3]
        for i, v in enumerate(high_vulns, 1):
            summary += f"{i}. **[{v.get('severity', '').upper()}] {v.get('name', '未知')}** - {v.get('description', '')[:100]}\n"

        if not high_vulns:
            summary += "无高危漏洞。\n"

        return summary


# 全局实例
report_generator = ReportGenerator()
