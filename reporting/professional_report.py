#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
professional_report模块，提供相关安全测试功能。

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
import html
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class ProfessionalReportGenerator:
    """专业报告生成器"""

    # CSS样式
    CSS_STYLE = """
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .report-container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        .report-header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .report-header h1 {
            font-size: 28px;
            margin-bottom: 10px;
            font-weight: 600;
        }
        .report-header .subtitle {
            font-size: 16px;
            opacity: 0.9;
            margin-bottom: 20px;
        }
        .report-header .meta {
            font-size: 14px;
            opacity: 0.8;
        }
        .report-body {
            padding: 40px;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            font-size: 22px;
            color: #1a1a2e;
            border-bottom: 3px solid #0f3460;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .section h3 {
            font-size: 18px;
            color: #16213e;
            margin: 20px 0 10px;
        }
        .executive-summary {
            background: #f8f9fa;
            border-left: 4px solid #0f3460;
            padding: 20px;
            border-radius: 4px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }
        .stat-card .number {
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-card .label {
            font-size: 14px;
            color: #666;
        }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .info { color: #17a2b8; }
        .vulnerability-card {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .vulnerability-header {
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .vulnerability-header.critical { background: #fff5f5; border-left: 4px solid #dc3545; }
        .vulnerability-header.high { background: #fff8f0; border-left: 4px solid #fd7e14; }
        .vulnerability-header.medium { background: #fffdf0; border-left: 4px solid #ffc107; }
        .vulnerability-header.low { background: #f0fff4; border-left: 4px solid #28a745; }
        .vulnerability-title {
            font-size: 16px;
            font-weight: 600;
            color: #333;
        }
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            color: white;
        }
        .severity-badge.critical { background: #dc3545; }
        .severity-badge.high { background: #fd7e14; }
        .severity-badge.medium { background: #ffc107; color: #333; }
        .severity-badge.low { background: #28a745; }
        .vulnerability-body {
            padding: 20px;
        }
        .vulnerability-body p {
            margin-bottom: 10px;
        }
        .vulnerability-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin: 15px 0;
            font-size: 14px;
        }
        .meta-item {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
        }
        .meta-item .label {
            font-weight: 600;
            color: #666;
            display: block;
            margin-bottom: 3px;
        }
        .remediation {
            background: #e8f4fd;
            border-left: 4px solid #0f3460;
            padding: 15px;
            border-radius: 4px;
            margin-top: 15px;
        }
        .remediation h4 {
            color: #0f3460;
            margin-bottom: 10px;
        }
        .remediation ol {
            margin-left: 20px;
        }
        .remediation li {
            margin-bottom: 5px;
        }
        .references {
            margin-top: 15px;
            font-size: 14px;
        }
        .references a {
            color: #0f3460;
            text-decoration: none;
        }
        .references a:hover {
            text-decoration: underline;
        }
        .table-container {
            overflow-x: auto;
            margin: 20px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #333;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .report-footer {
            background: #1a1a2e;
            color: white;
            padding: 20px 40px;
            text-align: center;
            font-size: 14px;
            opacity: 0.9;
        }
        .code-block {
            background: #f4f4f4;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
            margin: 10px 0;
        }
        .warning-box {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
        }
    </style>
    """

    def __init__(self):
        """初始化ProfessionalReportGenerator实例。

        Args:
            self: 类实例。
        """
        self.report_data = {}

    def generate_report(
        self,
        target: str,
        vulnerabilities: List[Dict],
        scan_info: Optional[Dict] = None,
        output_path: Optional[str] = None,
    ) -> str:
        """
        生成专业HTML报告

        Args:
            target: 测试目标
            vulnerabilities: 漏洞列表
            scan_info: 扫描信息（工具、时间、范围等）
            output_path: 输出路径

        Returns:
            HTML报告内容
        """
        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulnerabilities.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 5))

        # 统计
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulnerabilities:
            sev = vuln.get("severity", "info").lower()
            if sev in stats:
                stats[sev] += 1

        # 生成HTML
        html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全测试报告 - {html.escape(target)}</title>
    {self.CSS_STYLE}
</head>
<body>
    <div class="report-container">
        <!-- 报告头部 -->
        <div class="report-header">
            <h1>安全测试报告</h1>
            <div class="subtitle">AI Hacking Agent 自动化安全测试</div>
            <div class="meta">
                测试目标: {html.escape(target)} |
                生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
                报告版本: v2.0
            </div>
        </div>

        <div class="report-body">
            <!-- 执行摘要 -->
            <div class="section">
                <h2>一、执行摘要</h2>
                <div class="executive-summary">
                    <p>本次安全测试针对目标 <strong>{html.escape(target)}</strong> 进行了全面的自动化安全检测，
                    共发现 <strong>{len(vulnerabilities)}</strong> 个安全漏洞，其中：</p>
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="number critical">{stats['critical']}</div>
                            <div class="label">严重 (Critical)</div>
                        </div>
                        <div class="stat-card">
                            <div class="number high">{stats['high']}</div>
                            <div class="label">高危 (High)</div>
                        </div>
                        <div class="stat-card">
                            <div class="number medium">{stats['medium']}</div>
                            <div class="label">中危 (Medium)</div>
                        </div>
                        <div class="stat-card">
                            <div class="number low">{stats['low']}</div>
                            <div class="label">低危 (Low)</div>
                        </div>
                    </div>
                    <p><strong>总体风险评级：</strong>
                    {self._get_overall_risk(stats)}</p>
                </div>
            </div>

            <!-- 测试范围与方法 -->
            <div class="section">
                <h2>二、测试范围与方法</h2>
                <h3>2.1 测试范围</h3>
                <p>测试目标：{html.escape(target)}</p>
                <p>测试类型：自动化安全扫描 + 漏洞验证 + 风险评估</p>

                <h3>2.2 测试方法</h3>
                <ul>
                    <li>信息收集：端口扫描、服务识别、版本检测、目录枚举</li>
                    <li>漏洞扫描：CVE漏洞匹配、Web漏洞扫描、配置错误检测</li>
                    <li>漏洞验证：POC验证、漏洞可利用性评估</li>
                    <li>风险评估：CVSS评分、影响分析、修复建议</li>
                </ul>

                <h3>2.3 使用工具</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>工具</th>
                                <th>用途</th>
                                <th>版本</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr><td>AI Hacking Agent</td><td>自动化安全测试平台</td><td>v8.0</td></tr>
                            <tr><td>Nmap</td><td>端口扫描与服务识别</td><td>-</td></tr>
                            <tr><td>Nuclei</td><td>漏洞模板扫描</td><td>-</td></tr>
                            <tr><td>ReAct AI Engine</td><td>智能推理与工具调用</td><td>v3.1</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- 漏洞详情 -->
            <div class="section">
                <h2>三、漏洞详情</h2>
                {self._generate_vulnerability_details(vulnerabilities)}
            </div>

            <!-- 修复建议汇总 -->
            <div class="section">
                <h2>四、修复建议汇总</h2>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>优先级</th>
                                <th>漏洞类型</th>
                                <th>修复建议</th>
                            </tr>
                        </thead>
                        <tbody>
                            {self._generate_remediation_table(vulnerabilities)}
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- 附录 -->
            <div class="section">
                <h2>五、附录</h2>
                <h3>5.1 漏洞评级标准</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>严重程度</th>
                                <th>CVSS评分</th>
                                <th>说明</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr><td><span class="critical">严重 (Critical)</span></td><td>9.0 - 10.0</td><td>可远程未授权利用，导致系统完全沦陷</td></tr>
                            <tr><td><span class="high">高危 (High)</span></td><td>7.0 - 8.9</td><td>可远程利用，需一定条件，导致严重影响</td></tr>
                            <tr><td><span class="medium">中危 (Medium)</span></td><td>4.0 - 6.9</td><td>需本地访问或较高权限，影响有限</td></tr>
                            <tr><td><span class="low">低危 (Low)</span></td><td>0.1 - 3.9</td><td>影响很小，需特殊条件</td></tr>
                        </tbody>
                    </table>
                </div>

                <h3>5.2 免责声明</h3>
                <div class="warning-box">
                    <p>本报告由 AI Hacking Agent 自动化生成，仅供参考。漏洞的实际可利用性和影响需由专业安全人员进一步验证。
                    本报告仅用于授权范围内的安全测试，禁止用于非法用途。使用者需自行承担相应法律责任。</p>
                </div>
            </div>
        </div>

        <!-- 报告底部 -->
        <div class="report-footer">
            <p>本报告由 AI Hacking Agent v8.0 自动生成 | 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>仅供授权安全测试使用，禁止非法传播</p>
        </div>
    </div>
</body>
</html>"""

        # 保存文件
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

        return html_content

    def _get_overall_risk(self, stats: Dict) -> str:
        """获取总体风险评级"""
        if stats["critical"] > 0:
            return '<span class="critical"><strong>严重 (Critical)</strong></span> - 存在可远程未授权利用的严重漏洞，建议立即修复'
        elif stats["high"] > 0:
            return '<span class="high"><strong>高危 (High)</strong></span> - 存在高危漏洞，建议尽快修复'
        elif stats["medium"] > 0:
            return '<span class="medium"><strong>中危 (Medium)</strong></span> - 存在中危漏洞，建议计划修复'
        elif stats["low"] > 0:
            return '<span class="low"><strong>低危 (Low)</strong></span> - 仅存在低危漏洞，风险较低'
        else:
            return '<span class="info"><strong>安全 (Safe)</strong></span> - 未发现安全漏洞'

    def _generate_vulnerability_details(self, vulnerabilities: List[Dict]) -> str:
        """生成漏洞详情HTML"""
        if not vulnerabilities:
            return '<p>未发现安全漏洞。</p>'

        html_parts = []
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get("severity", "info").lower()
            severity_text = {
                "critical": "严重",
                "high": "高危",
                "medium": "中危",
                "low": "低危",
                "info": "信息"
            }.get(severity, "信息")

            cve_id = vuln.get("cve_id", "")
            cvss = vuln.get("cvss_score", vuln.get("cvss", ""))
            affected = vuln.get("affected", vuln.get("target", ""))
            description = vuln.get("description", vuln.get("desc", "暂无描述"))
            remediation = vuln.get("fix", vuln.get("remediation", "建议升级到最新版本或应用安全补丁"))
            references = vuln.get("references", [])

            # 修复建议步骤
            remediation_steps = ""
            if isinstance(remediation, dict):
                remediation_steps = remediation.get("steps", [remediation.get("summary", "")])
                remediation_summary = remediation.get("summary", "")
            elif isinstance(remediation, list):
                remediation_steps = remediation
                remediation_summary = "建议采取以下修复措施："
            else:
                remediation_steps = [str(remediation)]
                remediation_summary = "建议采取以下修复措施："

            steps_html = "".join(f"<li>{html.escape(str(step))}</li>" for step in remediation_steps)
            refs_html = "".join(f'<li><a href="{html.escape(ref)}" target="_blank">{html.escape(ref)}</a></li>' for ref in references if ref)

            vuln_html = f"""
            <div class="vulnerability-card">
                <div class="vulnerability-header {severity}">
                    <div class="vulnerability-title">
                        {i}. {html.escape(vuln.get("name", vuln.get("title", "未知漏洞")))}
                        {f' ({html.escape(cve_id)})' if cve_id else ''}
                    </div>
                    <span class="severity-badge {severity}">{severity_text}</span>
                </div>
                <div class="vulnerability-body">
                    <p><strong>漏洞描述：</strong>{html.escape(str(description))}</p>

                    <div class="vulnerability-meta">
                        <div class="meta-item">
                            <span class="label">CVSS评分</span>
                            {html.escape(str(cvss)) if cvss else 'N/A'}
                        </div>
                        <div class="meta-item">
                            <span class="label">影响范围</span>
                            {html.escape(str(affected)) if affected else 'N/A'}
                        </div>
                        <div class="meta-item">
                            <span class="label">漏洞类型</span>
                            {html.escape(vuln.get("category", vuln.get("type", "N/A")))}
                        </div>
                    </div>

                    <div class="remediation">
                        <h4>修复建议</h4>
                        <p>{html.escape(str(remediation_summary))}</p>
                        <ol>
                            {steps_html}
                        </ol>
                    </div>

                    {f'''
                    <div class="references">
                        <strong>参考链接：</strong>
                        <ul>
                            {refs_html}
                        </ul>
                    </div>
                    ''' if refs_html else ''}
                </div>
            </div>
            """
            html_parts.append(vuln_html)

        return "\n".join(html_parts)

    def _generate_remediation_table(self, vulnerabilities: List[Dict]) -> str:
        """生成修复建议表格"""
        if not vulnerabilities:
            return '<tr><td colspan="3">无漏洞需要修复</td></tr>'

        rows = []
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            priority = {"critical": "P0 - 立即", "high": "P1 - 尽快", "medium": "P2 - 计划", "low": "P3 - 低优先级"}.get(severity, "P3")
            name = vuln.get("name", vuln.get("title", "未知"))
            fix = vuln.get("fix", vuln.get("remediation", "建议升级"))
            if isinstance(fix, dict):
                fix = fix.get("summary", str(fix))
            elif isinstance(fix, list):
                fix = "; ".join(str(f) for f in fix[:2])

            rows.append(f"""
            <tr>
                <td><span class="{severity}">{priority}</span></td>
                <td>{html.escape(str(name))}</td>
                <td>{html.escape(str(fix)[:100])}</td>
            </tr>
            """)

        return "\n".join(rows)


# 便捷函数
def generate_professional_report(
    target: str,
    vulnerabilities: List[Dict],
    output_path: Optional[str] = None,
) -> str:
    """生成专业报告的便捷函数"""
    generator = ProfessionalReportGenerator()
    return generator.generate_report(target, vulnerabilities, output_path=output_path)


if __name__ == "__main__":
    # 测试
    test_vulns = [
        {
            "name": "Log4Shell 远程代码执行",
            "severity": "critical",
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "category": "rce",
            "description": "Apache Log4j2 中存在远程代码执行漏洞，攻击者可通过构造特殊的日志消息触发JNDI注入，执行任意代码。",
            "affected": "Apache Log4j 2.0-beta9 到 2.14.1",
            "fix": {
                "summary": "升级Log4j到安全版本",
                "steps": [
                    "升级到 Log4j 2.15.0 或更高版本",
                    "设置 log4j2.formatMsgNoLookups=true",
                    "检查所有依赖Log4j的组件",
                ]
            },
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
        },
        {
            "name": "缺少安全响应头",
            "severity": "low",
            "category": "misconfiguration",
            "description": "服务器未配置必要的安全响应头，可能导致点击劫持、MIME类型嗅探等攻击。",
            "affected": "所有页面",
            "fix": "添加 X-Frame-Options、X-Content-Type-Options、Content-Security-Policy 等安全响应头"
        }
    ]

    output = generate_professional_report("http://test-target.com", test_vulns, "test_report.html")
    print(f"报告生成完成，长度: {len(output)} 字符")
    print("保存到: test_report.html")
