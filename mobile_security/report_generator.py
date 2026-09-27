#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
移动安全报告生成模块
生成移动App安全分析报告，包括静态分析、动态分析、漏洞扫描结果
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional


class MobileReportGenerator:
    """移动安全报告生成器"""

    def __init__(self):
        self.report_data: Dict[str, Any] = {}

    def generate_report(self, apk_info=None, vulnerabilities: List = None,
                       dynamic_result=None, output_format: str = "json") -> str:
        """生成完整报告"""
        self.report_data = {
            'report_title': '移动App安全分析报告',
            'generated_time': datetime.now().isoformat(),
            'version': '1.0',
            'summary': {},
            'static_analysis': {},
            'vulnerability_scan': {},
            'dynamic_analysis': {},
            'recommendations': [],
        }

        # 静态分析结果
        if apk_info:
            self.report_data['static_analysis'] = {
                'file_info': {
                    'file_name': apk_info.file_name,
                    'file_size': apk_info.file_size,
                    'md5': apk_info.md5,
                    'sha1': apk_info.sha1,
                    'sha256': apk_info.sha256,
                },
                'app_info': {
                    'package_name': apk_info.package_name,
                    'version_name': apk_info.version_name,
                    'version_code': apk_info.version_code,
                    'min_sdk': apk_info.min_sdk,
                    'target_sdk': apk_info.target_sdk,
                },
                'permissions': {
                    'total': len(apk_info.permissions),
                    'dangerous': [p for p in apk_info.permissions
                                 if p in {'android.permission.READ_CONTACTS',
                                          'android.permission.ACCESS_FINE_LOCATION',
                                          'android.permission.RECORD_AUDIO',
                                          'android.permission.CAMERA',
                                          'android.permission.READ_SMS',
                                          'android.permission.SEND_SMS'}],
                    'all': apk_info.permissions,
                },
                'components': {
                    'activities': len(apk_info.activities),
                    'services': len(apk_info.services),
                    'receivers': len(apk_info.receivers),
                    'providers': len(apk_info.providers),
                },
                'security': {
                    'is_packed': apk_info.is_packed,
                    'packer_name': apk_info.packer_name,
                    'is_debuggable': apk_info.is_debuggable,
                    'allow_backup': apk_info.allow_backup,
                    'cleartext_traffic': apk_info.cleartext_traffic,
                },
                'sdk_list': apk_info.sdk_list,
                'native_libs': apk_info.native_libs,
                'hardcoded_strings': apk_info.hardcoded_strings[:30],
            }

        # 漏洞扫描结果
        if vulnerabilities:
            vuln_list = []
            for v in vulnerabilities:
                vuln_list.append({
                    'id': v.id,
                    'name': v.name,
                    'category': v.category,
                    'severity': v.severity,
                    'description': v.description,
                    'impact': v.impact,
                    'location': v.location,
                    'evidence': v.evidence,
                    'recommendation': v.recommendation,
                    'cwe': v.cwe,
                    'owasp_mobile': v.owasp_mobile,
                })

            # 统计
            by_severity = {}
            by_category = {}
            for v in vulnerabilities:
                by_severity[v.severity] = by_severity.get(v.severity, 0) + 1
                by_category[v.category] = by_category.get(v.category, 0) + 1

            self.report_data['vulnerability_scan'] = {
                'total': len(vulnerabilities),
                'by_severity': by_severity,
                'by_category': by_category,
                'vulnerabilities': vuln_list,
            }

        # 动态分析结果
        if dynamic_result:
            self.report_data['dynamic_analysis'] = {
                'package_name': dynamic_result.package_name,
                'device_id': dynamic_result.device_id,
                'is_installed': dynamic_result.is_installed,
                'is_running': dynamic_result.is_running,
                'activities_visited': dynamic_result.activities_visited,
                'network_requests': dynamic_result.network_requests,
                'sensitive_api_calls': dynamic_result.sensitive_api_calls,
                'permissions_used': dynamic_result.permissions_used,
                'duration_seconds': dynamic_result.duration_seconds,
            }

        # 生成摘要
        self._generate_summary()

        # 生成建议
        self._generate_recommendations()

        # 输出
        if output_format == "json":
            return self._save_json_report()
        elif output_format == "html":
            return self._save_html_report()
        elif output_format == "markdown":
            return self._save_markdown_report()
        else:
            return self._save_json_report()

    def _generate_summary(self):
        """生成报告摘要"""
        total_vulns = self.report_data.get('vulnerability_scan', {}).get('total', 0)
        by_severity = self.report_data.get('vulnerability_scan', {}).get('by_severity', {})

        critical = by_severity.get('Critical', 0)
        high = by_severity.get('High', 0)
        medium = by_severity.get('Medium', 0)
        low = by_severity.get('Low', 0)

        # 风险评级
        if critical > 0 or high >= 3:
            risk_level = "高风险"
        elif high > 0 or medium >= 3:
            risk_level = "中风险"
        elif medium > 0 or low >= 3:
            risk_level = "低风险"
        else:
            risk_level = "安全"

        self.report_data['summary'] = {
            'total_vulnerabilities': total_vulns,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'risk_level': risk_level,
            'app_name': self.report_data.get('static_analysis', {}).get('app_info', {}).get('package_name', ''),
            'analysis_type': '静态分析 + 漏洞扫描' + (' + 动态分析' if self.report_data.get('dynamic_analysis') else ''),
        }

    def _generate_recommendations(self):
        """生成修复建议"""
        recommendations = []

        vulns = self.report_data.get('vulnerability_scan', {}).get('vulnerabilities', [])

        # 按严重程度排序
        sorted_vulns = sorted(vulns, key=lambda x: {
            'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4
        }.get(x.get('severity', 'Info'), 4))

        for vuln in sorted_vulns[:10]:  # 最多10条建议
            recommendations.append({
                'priority': vuln.get('severity', 'Info'),
                'vulnerability': vuln.get('name', ''),
                'recommendation': vuln.get('recommendation', ''),
            })

        # 通用建议
        recommendations.extend([
            {
                'priority': 'High',
                'vulnerability': '代码保护',
                'recommendation': '使用专业加固服务对APK进行加固，实施代码混淆、反调试、反篡改检测。',
            },
            {
                'priority': 'High',
                'vulnerability': '网络安全',
                'recommendation': '所有网络通信使用HTTPS，实施证书固定（SSL Pinning），配置network_security_config.xml。',
            },
            {
                'priority': 'Medium',
                'vulnerability': '数据存储',
                'recommendation': '敏感数据使用Android Keystore加密存储，使用EncryptedSharedPreferences，不要硬编码密钥。',
            },
            {
                'priority': 'Medium',
                'vulnerability': '权限管理',
                'recommendation': '遵循最小权限原则，只请求必要的权限，实施运行时权限请求，提供清晰的权限使用说明。',
            },
        ])

        self.report_data['recommendations'] = recommendations

    def _save_json_report(self) -> str:
        """保存JSON报告"""
        output_dir = os.path.join('data', 'mobile', 'reports')
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = os.path.join(output_dir, f'mobile_security_report_{timestamp}.json')

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.report_data, f, ensure_ascii=False, indent=2)

        return output_path

    def _save_html_report(self) -> str:
        """保存HTML报告"""
        output_dir = os.path.join('data', 'mobile', 'reports')
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = os.path.join(output_dir, f'mobile_security_report_{timestamp}.html')

        summary = self.report_data.get('summary', {})
        vulns = self.report_data.get('vulnerability_scan', {}).get('vulnerabilities', [])

        html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>移动App安全分析报告</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #444; margin-top: 30px; border-left: 4px solid #007bff; padding-left: 10px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
        .summary-card {{ flex: 1; min-width: 150px; padding: 20px; border-radius: 8px; text-align: center; color: white; }}
        .critical {{ background: #dc3545; }}
        .high {{ background: #fd7e14; }}
        .medium {{ background: #ffc107; color: #333; }}
        .low {{ background: #28a745; }}
        .risk {{ background: #6c757d; font-size: 24px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #28a745; font-weight: bold; }}
        .vuln-card {{ border: 1px solid #ddd; border-radius: 8px; padding: 15px; margin: 10px 0; }}
        .vuln-title {{ font-size: 18px; font-weight: bold; margin-bottom: 10px; }}
        .vuln-meta {{ font-size: 14px; color: #666; margin-bottom: 10px; }}
        .vuln-desc {{ margin: 10px 0; }}
        .recommendation {{ background: #e8f4fd; padding: 10px; border-radius: 4px; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>移动App安全分析报告</h1>
        <p>生成时间: {self.report_data.get('generated_time', '')}</p>

        <h2>报告摘要</h2>
        <div class="summary">
            <div class="summary-card critical">
                <div style="font-size: 32px; font-weight: bold;">{summary.get('critical', 0)}</div>
                <div>严重</div>
            </div>
            <div class="summary-card high">
                <div style="font-size: 32px; font-weight: bold;">{summary.get('high', 0)}</div>
                <div>高危</div>
            </div>
            <div class="summary-card medium">
                <div style="font-size: 32px; font-weight: bold;">{summary.get('medium', 0)}</div>
                <div>中危</div>
            </div>
            <div class="summary-card low">
                <div style="font-size: 32px; font-weight: bold;">{summary.get('low', 0)}</div>
                <div>低危</div>
            </div>
            <div class="summary-card risk">
                <div>{summary.get('risk_level', '未知')}</div>
                <div style="font-size: 14px;">风险评级</div>
            </div>
        </div>

        <h2>漏洞详情</h2>
'''

        for vuln in vulns:
            severity_class = f"severity-{vuln.get('severity', '').lower()}"
            html += f'''
        <div class="vuln-card">
            <div class="vuln-title">{vuln.get('name', '')}</div>
            <div class="vuln-meta">
                <span class="{severity_class}">[{vuln.get('severity', '')}]</span>
                | {vuln.get('category', '')}
                | {vuln.get('cwe', '')}
                | {vuln.get('owasp_mobile', '')}
            </div>
            <div class="vuln-desc"><strong>描述：</strong>{vuln.get('description', '')}</div>
            <div class="vuln-desc"><strong>影响：</strong>{vuln.get('impact', '')}</div>
            <div class="vuln-desc"><strong>位置：</strong>{vuln.get('location', '')}</div>
            <div class="vuln-desc"><strong>证据：</strong>{vuln.get('evidence', '')}</div>
            <div class="recommendation"><strong>修复建议：</strong>{vuln.get('recommendation', '')}</div>
        </div>
'''

        html += '''
        <h2>修复建议汇总</h2>
        <table>
            <tr><th>优先级</th><th>漏洞</th><th>建议</th></tr>
'''

        for rec in self.report_data.get('recommendations', []):
            html += f'''
            <tr>
                <td class="severity-{rec.get('priority', '').lower()}">{rec.get('priority', '')}</td>
                <td>{rec.get('vulnerability', '')}</td>
                <td>{rec.get('recommendation', '')}</td>
            </tr>
'''

        html += '''
        </table>
    </div>
</body>
</html>'''

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        return output_path

    def _save_markdown_report(self) -> str:
        """保存Markdown报告"""
        output_dir = os.path.join('data', 'mobile', 'reports')
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = os.path.join(output_dir, f'mobile_security_report_{timestamp}.md')

        summary = self.report_data.get('summary', {})
        vulns = self.report_data.get('vulnerability_scan', {}).get('vulnerabilities', [])

        md = f'''# 移动App安全分析报告

**生成时间**: {self.report_data.get('generated_time', '')}
**报告版本**: {self.report_data.get('version', '')}

## 报告摘要

| 指标 | 数值 |
|------|------|
| 严重漏洞 | {summary.get('critical', 0)} |
| 高危漏洞 | {summary.get('high', 0)} |
| 中危漏洞 | {summary.get('medium', 0)} |
| 低危漏洞 | {summary.get('low', 0)} |
| 总漏洞数 | {summary.get('total_vulnerabilities', 0)} |
| 风险评级 | **{summary.get('risk_level', '未知')}** |

## 漏洞详情

'''

        for vuln in vulns:
            md += f'''### {vuln.get('name', '')}

- **严重程度**: {vuln.get('severity', '')}
- **类别**: {vuln.get('category', '')}
- **CWE**: {vuln.get('cwe', '')}
- **OWASP Mobile**: {vuln.get('owasp_mobile', '')}
- **位置**: {vuln.get('location', '')}

**描述**: {vuln.get('description', '')}

**影响**: {vuln.get('impact', '')}

**证据**: {vuln.get('evidence', '')}

**修复建议**: {vuln.get('recommendation', '')}

---

'''

        md += '''## 修复建议汇总

| 优先级 | 漏洞 | 建议 |
|--------|------|------|
'''

        for rec in self.report_data.get('recommendations', []):
            md += f"| {rec.get('priority', '')} | {rec.get('vulnerability', '')} | {rec.get('recommendation', '')} |\n"

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)

        return output_path


# 全局单例
_report_generator = None

def get_mobile_report_generator() -> MobileReportGenerator:
    """获取移动安全报告生成器单例"""
    global _report_generator
    if _report_generator is None:
        _report_generator = MobileReportGenerator()
    return _report_generator
