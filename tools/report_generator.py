#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
report_generator安全工具集成模块，提供相关安全工具的封装和调用。

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
import os
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from loguru import logger


class ReportTemplate(Enum):
    """报告模板"""
    PROFESSIONAL = "professional"  # 专业渗透测试报告
    HW_SELF_CHECK = "hw_self_check"  # 护网自查报告
    EXECUTIVE = "executive"  # 高管摘要报告
    SIMPLE = "simple"  # 简单扫描报告
    MALWARE = "malware"  # 恶意代码分析报告


class ReportFormat(Enum):
    """报告格式"""
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"
    PDF = "pdf"


@dataclass
class VulnerabilityItem:
    """漏洞项"""
    id: str
    title: str
    severity: str  # critical/high/medium/low/info
    type: str
    description: str
    target: str
    url: str = ""
    parameter: str = ""
    method: str = "GET"
    evidence: str = ""
    poc: str = ""
    exp: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cve: str = ""
    fix_suggestion: str = ""
    references: List[str] = field(default_factory=list)
    discovered_at: str = ""
    status: str = "new"


@dataclass
class ReportData:
    """报告数据"""
    title: str = "渗透测试报告"
    company: str = ""
    author: str = ""
    target: str = ""
    start_time: str = ""
    end_time: str = ""
    test_scope: str = ""
    test_method: str = ""
    executive_summary: str = ""
    vulnerabilities: List[VulnerabilityItem] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    disclaimer: str = ""


class ReportGenerator:
    """报告生成器"""

    def __init__(self, output_dir: str = "./reports"):
        """初始化ReportGenerator实例。

        Args:
            self: 类实例。
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"报告生成器初始化完成，输出目录: {output_dir}")

    def generate(self, data: ReportData, template: str = "professional",
                 format: str = "html") -> str:
        """生成报告"""
        if template == ReportTemplate.PROFESSIONAL.value:
            content = self._generate_professional_report(data)
        elif template == ReportTemplate.HW_SELF_CHECK.value:
            content = self._generate_hw_report(data)
        elif template == ReportTemplate.EXECUTIVE.value:
            content = self._generate_executive_report(data)
        elif template == ReportTemplate.SIMPLE.value:
            content = self._generate_simple_report(data)
        elif template == ReportTemplate.MALWARE.value:
            content = self._generate_malware_report(data)
        else:
            content = self._generate_professional_report(data)

        # 保存文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{template}_{timestamp}.{format}"
        filepath = os.path.join(self.output_dir, filename)

        if format == ReportFormat.HTML.value:
            html_content = self._wrap_html(content, data)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
        elif format == ReportFormat.MARKDOWN.value:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
        elif format == ReportFormat.JSON.value:
            json_data = {
                "title": data.title,
                "company": data.company,
                "author": data.author,
                "target": data.target,
                "start_time": data.start_time,
                "end_time": data.end_time,
                "vulnerabilities": [vars(v) for v in data.vulnerabilities],
                "statistics": data.statistics,
                "recommendations": data.recommendations,
            }
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(json_data, f, ensure_ascii=False, indent=2)
        else:
            # PDF需要额外库，暂时用HTML代替
            html_content = self._wrap_html(content, data)
            filepath = filepath.replace(".pdf", ".html")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)

        logger.info(f"报告生成完成: {filepath}")
        return filepath

    def _generate_professional_report(self, data: ReportData) -> str:
        """生成专业渗透测试报告（Markdown）"""
        md = f"""# {data.title}

---

## 文档信息

| 项目 | 内容 |
|------|------|
| 委托单位 | {data.company or '—'} |
| 测试目标 | {data.target or '—'} |
| 测试人员 | {data.author or '—'} |
| 开始时间 | {data.start_time or '—'} |
| 结束时间 | {data.end_time or '—'} |
| 报告版本 | v1.0 |
| 报告日期 | {datetime.now().strftime('%Y-%m-%d')} |

---

## 1. 执行摘要

{data.executive_summary or self._generate_executive_summary(data)}

### 1.1 漏洞统计

| 严重程度 | 数量 | 占比 |
|----------|------|------|
| 严重 (Critical) | {self._count_severity(data, 'critical')} | {self._percent(data, 'critical')}% |
| 高危 (High) | {self._count_severity(data, 'high')} | {self._percent(data, 'high')}% |
| 中危 (Medium) | {self._count_severity(data, 'medium')} | {self._percent(data, 'medium')}% |
| 低危 (Low) | {self._count_severity(data, 'low')} | {self._percent(data, 'low')}% |
| 信息 (Info) | {self._count_severity(data, 'info')} | {self._percent(data, 'info')}% |
| **总计** | **{len(data.vulnerabilities)}** | **100%** |

### 1.2 风险评级

本次测试整体风险评级为：**{self._get_overall_risk(data)}**

---

## 2. 测试范围与方法

### 2.1 测试范围

{data.test_scope or f"""
本次渗透测试的范围包括：
- 目标系统：{data.target or '—'}
- 测试类型：黑盒测试/灰盒测试
- 测试时间：{data.start_time or '—'} 至 {data.end_time or '—'}
"""}

### 2.2 测试方法

{data.test_method or """
本次测试采用以下方法：
1. **信息收集**：子域名枚举、端口扫描、服务识别、指纹识别、目录扫描
2. **漏洞扫描**：Web漏洞扫描（SQL注入、XSS、SSRF、文件上传等）、系统漏洞扫描、配置错误检测
3. **漏洞验证**：对扫描发现的漏洞进行手动验证，去除误报
4. **漏洞利用**：对验证通过的高危漏洞进行利用，获取证据
5. **报告生成**：整理测试结果，生成专业报告
"""}

### 2.3 测试工具

| 工具名称 | 用途 |
|----------|------|
| Nmap | 端口扫描和服务识别 |
| Nuclei | 基于模板的漏洞扫描 |
| SQLMap | SQL注入检测和利用 |
| Dirsearch | Web目录扫描 |
| Burp Suite | Web应用安全测试 |
| Metasploit | 漏洞利用框架 |
| AI Hacking Agent | AI驱动的自动化安全测试平台 |

---

## 3. 漏洞详情

"""

        # 按严重程度排序
        sorted_vulns = sorted(data.vulnerabilities, key=lambda x: self._severity_order(x.severity))

        for i, vuln in enumerate(sorted_vulns, 1):
            md += f"""### 3.{i} {vuln.title}

| 项目 | 内容 |
|------|------|
| 漏洞编号 | {vuln.id} |
| 严重程度 | **{self._severity_text(vuln.severity)}** |
| 漏洞类型 | {vuln.type} |
| CVSS评分 | {vuln.cvss_score or '—'} |
| CVE编号 | {vuln.cve or '—'} |
| 目标地址 | {vuln.target or '—'} |
| 漏洞URL | {vuln.url or '—'} |
| 受影响参数 | {vuln.parameter or '—'} |
| 请求方法 | {vuln.method} |
| 发现时间 | {vuln.discovered_at or '—'} |

**漏洞描述：**

{vuln.description or '—'}

**漏洞证据：**

```
{vuln.evidence or '—'}
```

**验证POC：**

```
{vuln.poc or '—'}
```

**利用EXP（如适用）：**

```
{vuln.exp or '—'}
```

**修复建议：**

{vuln.fix_suggestion or '—'}

**参考链接：**

{chr(10).join([f"- {ref}" for ref in vuln.references]) if vuln.references else '—'}

---

"""

        md += f"""## 4. 修复建议

{self._generate_recommendations(data)}

---

## 5. 附录

### 5.1 漏洞统计详情

{self._generate_vuln_table(data)}

### 5.2 测试时间线

| 时间 | 事件 |
|------|------|
| {data.start_time or '—'} | 测试开始 |
| {data.start_time or '—'} | 信息收集 |
| {data.start_time or '—'} | 漏洞扫描 |
| {data.end_time or '—'} | 漏洞验证和利用 |
| {data.end_time or '—'} | 报告生成 |

### 5.3 免责声明

{data.disclaimer or """
本报告仅用于授权范围内的安全测试，未经授权的渗透测试属于违法行为。
本报告中的漏洞信息仅供委托单位修复参考，不得用于其他用途。
测试过程中已尽量避免对目标系统造成影响，但不排除因测试导致的系统不稳定。
报告中的漏洞可能在报告生成后已被修复，请以实际情况为准。
"""}

---

*报告生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
*由 AI Hacking Agent 自动生成*
"""
        return md

    def _generate_hw_report(self, data: ReportData) -> str:
        """生成护网自查报告"""
        md = f"""# 护网专项自查报告

---

## 文档信息

| 项目 | 内容 |
|------|------|
| 单位名称 | {data.company or '—'} |
| 自查范围 | {data.target or '—'} |
| 自查人员 | {data.author or '—'} |
| 自查时间 | {data.start_time or '—'} 至 {data.end_time or '—'} |
| 报告日期 | {datetime.now().strftime('%Y-%m-%d')} |

---

## 1. 自查概述

为应对护网行动，本单位对信息系统进行了全面的安全自查。本次自查覆盖了资产暴露面、漏洞风险、安全配置、身份认证、数据安全等多个维度，旨在发现并修复安全隐患，提升整体安全防护能力。

### 1.1 自查结果汇总

| 检查项 | 检查数量 | 发现问题 | 已修复 | 待修复 | 风险等级 |
|--------|----------|----------|--------|--------|----------|
| 资产暴露面 | 10 | {self._count_by_type(data, 'exposure')} | 0 | {self._count_by_type(data, 'exposure')} | 高 |
| 漏洞风险 | 20 | {self._count_severity(data, 'high') + self._count_severity(data, 'critical')} | 0 | {self._count_severity(data, 'high') + self._count_severity(data, 'critical')} | 高 |
| 安全配置 | 15 | {self._count_by_type(data, 'config')} | 0 | {self._count_by_type(data, 'config')} | 中 |
| 身份认证 | 10 | {self._count_by_type(data, 'auth')} | 0 | {self._count_by_type(data, 'auth')} | 中 |
| 数据安全 | 8 | {self._count_by_type(data, 'data')} | 0 | {self._count_by_type(data, 'data')} | 中 |
| **合计** | **63** | **{len(data.vulnerabilities)}** | **0** | **{len(data.vulnerabilities)}** | **高** |

---

## 2. 自查项详情

### 2.1 资产暴露面检查

检查内容：
- [x] 公网IP资产梳理
- [x] 开放端口检查
- [x] 子域名枚举
- [x] 管理后台暴露检查
- [x] 云存储桶公开检查

发现问题：
{self._generate_vuln_list_by_type(data, 'exposure') or '未发现问题'}

### 2.2 漏洞风险检查

检查内容：
- [x] Web漏洞扫描（SQL注入、XSS、SSRF等）
- [x] 系统漏洞扫描（CVE漏洞）
- [x] 中间件漏洞扫描
- [x] 弱密码检测
- [x] 已知EXP漏洞检查

发现问题：
{self._generate_vuln_list_by_severity(data, 'critical') or '未发现严重漏洞'}
{self._generate_vuln_list_by_severity(data, 'high') or '未发现高危漏洞'}

### 2.3 安全配置检查

检查内容：
- [x] HTTPS配置检查
- [x] 安全响应头检查
- [x] 目录遍历检查
- [x] 备份文件检查
- [x] 错误信息泄露检查
- [x] 服务器版本信息隐藏检查

发现问题：
{self._generate_vuln_list_by_type(data, 'config') or '未发现问题'}

### 2.4 身份认证检查

检查内容：
- [x] 多因素认证（MFA）检查
- [x] 密码策略检查
- [x] 会话管理检查
- [x] 权限控制检查
- [x] 账户锁定机制检查

发现问题：
{self._generate_vuln_list_by_type(data, 'auth') or '未发现问题'}

### 2.5 数据安全检查

检查内容：
- [x] 敏感数据加密存储检查
- [x] 数据传输加密检查
- [x] 数据备份检查
- [x] 数据访问日志检查
- [x] 个人信息保护检查

发现问题：
{self._generate_vuln_list_by_type(data, 'data') or '未发现问题'}

---

## 3. 漏洞详情

{self._generate_vuln_detail_section(data)}

---

## 4. 修复计划

### 4.1 修复优先级

| 优先级 | 修复时限 | 漏洞数量 | 说明 |
|--------|----------|----------|------|
| P0 - 紧急 | 24小时内 | {self._count_severity(data, 'critical')} | 严重漏洞，可能导致系统被入侵 |
| P1 - 高 | 7天内 | {self._count_severity(data, 'high')} | 高危漏洞，存在较大安全风险 |
| P2 - 中 | 30天内 | {self._count_severity(data, 'medium')} | 中危漏洞，存在一定安全风险 |
| P3 - 低 | 90天内 | {self._count_severity(data, 'low')} | 低危漏洞，影响较小 |

### 4.2 修复建议

{self._generate_recommendations(data)}

---

## 5. 护网期间防护建议

1. **实时监控**：7×24小时监控安全设备告警，发现异常立即响应
2. **应急响应**：建立应急响应团队，制定应急预案，定期演练
3. **漏洞管理**：持续扫描和修复漏洞，重点关注互联网暴露面
4. **访问控制**：限制管理后台访问IP，启用多因素认证
5. **数据备份**：确保关键数据备份完整，定期验证备份可恢复
6. **日志审计**：开启全面日志记录，定期审计安全日志
7. **威胁情报**：关注最新威胁情报，及时调整防护策略
8. **供应链安全**：检查第三方组件和服务的安全状况

---

*报告生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
*由 AI Hacking Agent 自动生成*
"""
        return md

    def _generate_executive_report(self, data: ReportData) -> str:
        """生成高管摘要报告"""
        md = f"""# 安全测试高管摘要报告

---

## 报告信息

| 项目 | 内容 |
|------|------|
| 委托单位 | {data.company or '—'} |
| 测试目标 | {data.target or '—'} |
| 报告日期 | {datetime.now().strftime('%Y-%m-%d')} |

---

## 1. 核心结论

**整体安全评级：{self._get_overall_risk(data)}**

本次安全测试共发现 **{len(data.vulnerabilities)}** 个安全漏洞，其中：
- 严重漏洞 **{self._count_severity(data, 'critical')}** 个
- 高危漏洞 **{self._count_severity(data, 'high')}** 个
- 中危漏洞 **{self._count_severity(data, 'medium')}** 个
- 低危漏洞 **{self._count_severity(data, 'low')}** 个

**关键风险：**
{self._generate_key_risks(data)}

---

## 2. 业务影响分析

| 风险领域 | 影响程度 | 说明 |
|----------|----------|------|
| 数据安全 | {self._get_impact_level(data, 'data')} | 敏感数据泄露风险 |
| 系统可用性 | {self._get_impact_level(data, 'availability')} | 系统被入侵或中断风险 |
| 业务连续性 | {self._get_impact_level(data, 'business')} | 业务中断或受损风险 |
| 合规风险 | {self._get_impact_level(data, 'compliance')} | 违反法律法规风险 |
| 声誉风险 | {self._get_impact_level(data, 'reputation')} | 企业声誉受损风险 |

---

## 3. 最紧急的3个问题

{self._generate_top3_issues(data)}

---

## 4. 投资建议

### 4.1 短期投资（1-3个月）

| 投资项 | 预算估算 | 预期收益 |
|--------|----------|----------|
| 紧急漏洞修复 | {self._estimate_cost(data, 'critical')} | 消除严重安全风险 |
| 高危漏洞修复 | {self._estimate_cost(data, 'high')} | 降低高危安全风险 |
| 安全设备升级 | 5-10万 | 提升整体防护能力 |
| 安全培训 | 2-5万 | 提升员工安全意识 |

### 4.2 中期投资（3-12个月）

| 投资项 | 预算估算 | 预期收益 |
|--------|----------|----------|
| 安全运营中心（SOC）建设 | 20-50万 | 7×24小时安全监控 |
| 漏洞管理平台 | 10-20万 | 系统化漏洞管理 |
| 渗透测试服务（年度） | 10-30万 | 持续安全验证 |
| 安全人员招聘 | 30-60万/年 | 专业安全团队 |

### 4.3 长期投资（1-3年）

| 投资项 | 预算估算 | 预期收益 |
|--------|----------|----------|
| 零信任架构建设 | 50-100万 | 现代化安全架构 |
| 安全自动化平台 | 30-50万 | 提升安全运营效率 |
| 红蓝对抗演练 | 10-20万/年 | 持续提升防护能力 |

---

## 5. 总结与建议

{self._generate_executive_conclusion(data)}

---

*本报告仅供管理层决策参考，详细技术报告请参见完整渗透测试报告。*
*报告生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        return md

    def _generate_simple_report(self, data: ReportData) -> str:
        """生成简单扫描报告"""
        md = f"""# 漏洞扫描报告

---

**扫描目标：** {data.target or '—'}
**扫描时间：** {data.start_time or '—'} 至 {data.end_time or '—'}
**扫描人员：** {data.author or '—'}

---

## 扫描结果汇总

| 严重程度 | 数量 |
|----------|------|
| 严重 | {self._count_severity(data, 'critical')} |
| 高危 | {self._count_severity(data, 'high')} |
| 中危 | {self._count_severity(data, 'medium')} |
| 低危 | {self._count_severity(data, 'low')} |
| 信息 | {self._count_severity(data, 'info')} |
| **总计** | **{len(data.vulnerabilities)}** |

---

## 漏洞列表

{self._generate_vuln_table(data)}

---

## 修复建议

{self._generate_recommendations(data)}

---

*报告生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
*由 AI Hacking Agent 自动生成*
"""
        return md

    def _generate_malware_report(self, data: ReportData) -> str:
        """生成恶意代码分析报告"""
        md = f"""# 恶意代码分析报告

---

## 样本信息

| 项目 | 内容 |
|------|------|
| 样本名称 | {data.title or '—'} |
| 分析人员 | {data.author or '—'} |
| 分析时间 | {data.start_time or '—'} 至 {data.end_time or '—'} |
| 报告日期 | {datetime.now().strftime('%Y-%m-%d')} |

---

## 1. 执行摘要

{data.executive_summary or '本次分析对恶意代码样本进行了静态分析和动态分析，提取了IOC指标，并映射到MITRE ATT&CK技术矩阵。'}

### 1.1 分析结论

- **样本类型：** {data.statistics.get('malware_type', '—')}
- **威胁等级：** {self._get_overall_risk(data)}
- **家族归属：** {data.statistics.get('family', '—')}
- **传播方式：** {data.statistics.get('spread_method', '—')}

---

## 2. 静态分析

### 2.1 文件基本信息

| 项目 | 内容 |
|------|------|
| 文件大小 | {data.statistics.get('file_size', '—')} |
| 文件类型 | {data.statistics.get('file_type', '—')} |
| MD5 | {data.statistics.get('md5', '—')} |
| SHA1 | {data.statistics.get('sha1', '—')} |
| SHA256 | {data.statistics.get('sha256', '—')} |
| 编译时间 | {data.statistics.get('compile_time', '—')} |
| 加壳情况 | {data.statistics.get('packer', '—')} |

### 2.2 字符串提取

```
{data.statistics.get('strings', '—')}
```

### 2.3 导入表分析

{data.statistics.get('imports', '—')}

### 2.4 节区分析

{data.statistics.get('sections', '—')}

---

## 3. 动态分析

### 3.1 沙箱运行环境

- 操作系统：{data.statistics.get('sandbox_os', 'Windows 10 x64')}
- 分析工具：Cuckoo Sandbox / ANY.RUN / 手动分析
- 监控时间：{data.statistics.get('monitor_time', '5分钟')}

### 3.2 进程行为

{data.statistics.get('process_behavior', '—')}

### 3.3 文件行为

{data.statistics.get('file_behavior', '—')}

### 3.4 注册表行为

{data.statistics.get('registry_behavior', '—')}

### 3.5 网络行为

{data.statistics.get('network_behavior', '—')}

---

## 4. IOC指标

### 4.1 文件哈希

{data.statistics.get('ioc_hashes', '—')}

### 4.2 IP地址

{data.statistics.get('ioc_ips', '—')}

### 4.3 域名/URL

{data.statistics.get('ioc_domains', '—')}

### 4.4 互斥量

{data.statistics.get('ioc_mutex', '—')}

### 4.5 注册表项

{data.statistics.get('ioc_registry', '—')}

---

## 5. MITRE ATT&CK映射

| 战术 | 技术 | 说明 |
|------|------|------|
{data.statistics.get('attack_mapping', '| — | — | — |')}

---

## 6. 检测与防护建议

{self._generate_malware_recommendations(data)}

---

*报告生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
*由 AI Hacking Agent 自动生成*
"""
        return md

    # ========== 辅助方法 ==========

    def _count_severity(self, data: ReportData, severity: str) -> int:
        """统计相关数量。

        Args:
            data: 相关参数。
            severity: 相关参数。

        Returns:
            操作结果。
        """
        return len([v for v in data.vulnerabilities if v.severity == severity])

    def _percent(self, data: ReportData, severity: str) -> str:
        """执行相关操作。

        Args:
            data: 相关参数。
            severity: 相关参数。

        Returns:
            操作结果。
        """
        total = len(data.vulnerabilities)
        if total == 0:
            return "0"
        return f"{self._count_severity(data, severity) / total * 100:.1f}"

    def _severity_order(self, severity: str) -> int:
        """或...。

        Args:
            severity: 相关参数。

        Returns:
            操作结果。
        """
        orders = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return orders.get(severity, 5)

    def _severity_text(self, severity: str) -> str:
        """执行相关操作。

        Args:
            severity: 相关参数。

        Returns:
            操作结果。
        """
        texts = {
            "critical": "严重 (Critical)",
            "high": "高危 (High)",
            "medium": "中危 (Medium)",
            "low": "低危 (Low)",
            "info": "信息 (Info)",
        }
        return texts.get(severity, severity)

    def _get_overall_risk(self, data: ReportData) -> str:
        """获取相关数据。

        Args:
            data: 相关参数。

        Returns:
            操作结果。
        """
        critical = self._count_severity(data, 'critical')
        high = self._count_severity(data, 'high')
        medium = self._count_severity(data, 'medium')

        if critical > 0:
            return "严重 (Critical)"
        elif high > 0:
            return "高 (High)"
        elif medium > 0:
            return "中 (Medium)"
        elif len(data.vulnerabilities) > 0:
            return "低 (Low)"
        else:
            return "无风险"

    def _generate_executive_summary(self, data: ReportData) -> str:
        """生成相关内容。

        Args:
            data: 相关参数。

        Returns:
            操作结果。
        """
        critical = self._count_severity(data, 'critical')
        high = self._count_severity(data, 'high')

        summary = f"本次渗透测试针对 {data.target or '目标系统'} 进行了全面的安全测试。测试过程中发现了 {len(data.vulnerabilities)} 个安全漏洞，"
        if critical > 0:
            summary += f"其中包括 {critical} 个严重漏洞和 {high} 个高危漏洞。"
            summary += "这些漏洞可能导致攻击者获取系统控制权、窃取敏感数据或造成业务中断。"
        elif high > 0:
            summary += f"其中包括 {high} 个高危漏洞。"
            summary += "建议尽快修复这些高危漏洞，以降低安全风险。"
        else:
            summary += "整体安全状况良好，未发现严重或高危漏洞。"

        summary += "建议按照修复建议及时修复漏洞，并建立持续的安全监控和漏洞管理机制。"
        return summary

    def _generate_recommendations(self, data: ReportData) -> str:
        """生成相关内容。

        Args:
            data: 相关参数。

        Returns:
            操作结果。
        """
        recs = []

        if self._count_severity(data, 'critical') > 0:
            recs.append("1. **立即修复严重漏洞**：严重漏洞可能导致系统被完全控制，应在24小时内修复。")
        if self._count_severity(data, 'high') > 0:
            recs.append("2. **尽快修复高危漏洞**：高危漏洞存在较大安全风险，应在7天内修复。")
        if self._count_severity(data, 'medium') > 0:
            recs.append("3. **计划修复中危漏洞**：中危漏洞应在30天内修复。")

        recs.extend([
            "4. **加强输入验证**：对所有用户输入进行严格的验证和过滤，使用参数化查询防止SQL注入，对输出进行HTML编码防止XSS。",
            "5. **完善身份认证**：启用多因素认证（MFA），实施强密码策略，定期更换密码，设置账户锁定机制。",
            "6. **加强访问控制**：实施最小权限原则，定期审计权限配置，限制管理后台访问IP。",
            "7. **部署安全设备**：部署WAF、IDS/IPS、防病毒等安全设备，及时更新规则库。",
            "8. **建立安全监控**：7×24小时监控安全事件，建立应急响应机制，定期进行安全演练。",
            "9. **定期安全测试**：每季度进行一次漏洞扫描，每半年进行一次渗透测试，每年进行一次红蓝对抗。",
            "10. **加强安全培训**：定期对员工进行安全意识培训，提升整体安全水平。",
        ])

        return "\n\n".join(recs)

    def _generate_vuln_table(self, data: ReportData) -> str:
        """生成相关内容。

        Args:
            data: 相关参数。

        Returns:
            操作结果。
        """
        if not data.vulnerabilities:
            return "未发现漏洞。"

        table = "| 编号 | 漏洞名称 | 严重程度 | 类型 | 目标 | CVSS | 状态 |\n"
        table += "|------|----------|----------|------|------|------|------|\n"

        sorted_vulns = sorted(data.vulnerabilities, key=lambda x: self._severity_order(x.severity))
        for v in sorted_vulns:
            table += f"| {v.id} | {v.title} | {self._severity_text(v.severity)} | {v.type} | {v.target or '—'} | {v.cvss_score or '—'} | {v.status} |\n"

        return table

    def _generate_vuln_detail_section(self, data: ReportData) -> str:
        """生成相关内容。

        Args:
            data: 相关参数。

        Returns:
            操作结果。
        """
        if not data.vulnerabilities:
            return "未发现漏洞。"

        sorted_vulns = sorted(data.vulnerabilities, key=lambda x: self._severity_order(x.severity))
        section = ""
        for i, v in enumerate(sorted_vulns, 1):
            section += f"""### {i}. {v.title}

- **严重程度：** {self._severity_text(v.severity)}
- **漏洞类型：** {v.type}
- **目标地址：** {v.target or '—'}
- **漏洞URL：** {v.url or '—'}
- **CVSS评分：** {v.cvss_score or '—'}

**描述：** {v.description or '—'}

**修复建议：** {v.fix_suggestion or '—'}

---

"""
        return section

    def _count_by_type(self, data: ReportData, vuln_type: str) -> int:
        """统计相关数量。

        Args:
            data: 相关参数。
            vuln_type: 相关参数。

        Returns:
            操作结果。
        """
        return len([v for v in data.vulnerabilities if vuln_type in v.type.lower()])

    def _generate_vuln_list_by_type(self, data: ReportData, vuln_type: str) -> str:
        """生成相关内容。

        Args:
            data: 相关参数。
            vuln_type: 相关参数。

        Returns:
            操作结果。
        """
        vulns = [v for v in data.vulnerabilities if vuln_type in v.type.lower()]
        if not vulns:
            return ""
        return "\n".join([f"- **{v.title}**（{self._severity_text(v.severity)}）：{v.description[:100]}" for v in vulns])

    def _generate_vuln_list_by_severity(self, data: ReportData, severity: str) -> str:
        """生成相关内容。

        Args:
            data: 相关参数。
            severity: 相关参数。

        Returns:
            操作结果。
        """
        vulns = [v for v in data.vulnerabilities if v.severity == severity]
        if not vulns:
            return ""
        return "\n".join([f"- **{v.title}**（{v.target or '—'}）：{v.description[:100]}" for v in vulns])

    def _generate_key_risks(self, data: ReportData) -> str:
        """生成相关内容。

        Args:
            data: 相关参数。

        Returns:
            操作结果。
        """
        critical = [v for v in data.vulnerabilities if v.severity == 'critical']
        high = [v for v in data.vulnerabilities if v.severity == 'high']

        risks = []
        for v in critical[:3]:
            risks.append(f"- **{v.title}**：可能导致{v.description[:50]}")
        for v in high[:2]:
            risks.append(f"- **{v.title}**：存在{v.description[:50]}风险")

        return "\n".join(risks) if risks else "- 未发现重大安全风险"

    def _get_impact_level(self, data: ReportData, category: str) -> str:
        """获取相关数据。

        Args:
            data: 相关参数。
            category: 相关参数。

        Returns:
            操作结果。
        """
        critical = self._count_severity(data, 'critical')
        high = self._count_severity(data, 'high')
        if critical > 0:
            return "高"
        elif high > 0:
            return "中高"
        else:
            return "中"

    def _generate_top3_issues(self, data: ReportData) -> str:
        """生成相关内容。

        Args:
            data: 相关参数。

        Returns:
            操作结果。
        """
        sorted_vulns = sorted(data.vulnerabilities, key=lambda x: self._severity_order(x.severity))
        top3 = sorted_vulns[:3]

        if not top3:
            return "未发现重大问题。"

        section = ""
        for i, v in enumerate(top3, 1):
            section += f"""**问题{i}：{v.title}**

- 严重程度：{self._severity_text(v.severity)}
- 影响：{v.description[:100]}
- 建议：{v.fix_suggestion[:100]}

"""
        return section

    def _estimate_cost(self, data: ReportData, severity: str) -> str:
        """执行相关操作。

        Args:
            data: 相关参数。
            severity: 相关参数。

        Returns:
            操作结果。
        """
        count = self._count_severity(data, severity)
        if severity == 'critical':
            return f"{count * 2}-{count * 5}万"
        elif severity == 'high':
            return f"{count * 1}-{count * 3}万"
        else:
            return f"{count * 0.5}-{count * 1}万"

    def _generate_executive_conclusion(self, data: ReportData) -> str:
        """生成相关内容。

        Args:
            data: 相关参数。

        Returns:
            操作结果。
        """
        critical = self._count_severity(data, 'critical')
        high = self._count_severity(data, 'high')

        if critical > 0:
            return f"""本次安全测试发现了 {critical} 个严重漏洞和 {high} 个高危漏洞，整体安全状况不容乐观。
严重漏洞可能导致攻击者获取系统完全控制权，建议立即启动应急响应，在24小时内修复严重漏洞。
同时，建议加大安全投入，建立完善的安全管理体系，提升整体安全防护能力。
预计短期安全投入约 {self._estimate_cost(data, 'critical')} 元，中期投入约20-50万元。"""
        elif high > 0:
            return f"""本次安全测试发现了 {high} 个高危漏洞，整体安全状况存在一定风险。
建议在7天内修复所有高危漏洞，30天内修复中危漏洞。
同时，建议建立持续的安全监控和漏洞管理机制，定期进行安全测试。
预计安全投入约10-30万元。"""
        else:
            return """本次安全测试未发现严重或高危漏洞，整体安全状况良好。
建议继续保持良好的安全管理，定期进行安全测试，持续提升安全防护能力。"""

    def _generate_malware_recommendations(self, data: ReportData) -> str:
        """生成相关内容。

        Args:
            data: 相关参数。

        Returns:
            操作结果。
        """
        return """1. **立即隔离受感染主机**：断开网络连接，防止恶意代码进一步传播。
2. **清除恶意代码**：使用杀毒软件或手动方式清除恶意代码，删除相关文件和注册表项。
3. **重置凭证**：修改所有可能被窃取的密码，包括系统密码、应用密码、邮箱密码等。
4. **修补漏洞**：修复恶意代码利用的系统漏洞，升级存在漏洞的软件。
5. **加强监控**：部署EDR/XDR工具，实时监控终端行为，及时发现异常。
6. **网络分段**：实施网络分段，限制横向移动，防止恶意代码在内部网络传播。
7. **员工培训**：加强员工安全意识培训，防范钓鱼邮件和社会工程学攻击。
8. **备份恢复**：确保关键数据备份完整，定期验证备份可恢复，必要时从备份恢复系统。
9. **威胁情报**：订阅威胁情报服务，及时了解最新威胁和IOC指标。
10. **应急响应**：建立完善的应急响应机制，定期进行应急演练，提升事件响应能力。"""

    def _wrap_html(self, markdown_content: str, data: ReportData) -> str:
        """将Markdown内容包装为HTML"""
        # 简单的Markdown转HTML（实际项目中应使用markdown库）
        html_body = self._simple_markdown_to_html(markdown_content)

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{data.title}</title>
<style>
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Microsoft YaHei', sans-serif;
    line-height: 1.8;
    color: #333;
    max-width: 1000px;
    margin: 0 auto;
    padding: 40px 20px;
    background: #f5f5f5;
}}
.container {{
    background: #fff;
    padding: 50px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}}
h1 {{
    color: #1a1a2e;
    border-bottom: 3px solid #4a4adf;
    padding-bottom: 15px;
    margin-top: 40px;
}}
h2 {{
    color: #16213e;
    border-left: 4px solid #4a4adf;
    padding-left: 15px;
    margin-top: 35px;
}}
h3 {{
    color: #0f3460;
    margin-top: 25px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin: 20px 0;
}}
th, td {{
    border: 1px solid #ddd;
    padding: 12px 15px;
    text-align: left;
}}
th {{
    background: #1a1a2e;
    color: #fff;
    font-weight: 600;
}}
tr:nth-child(even) {{
    background: #f9f9f9;
}}
tr:hover {{
    background: #f0f0ff;
}}
code {{
    background: #f4f4f4;
    padding: 2px 6px;
    border-radius: 4px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 0.9em;
}}
pre {{
    background: #1a1a2e;
    color: #e0e0e0;
    padding: 20px;
    border-radius: 6px;
    overflow-x: auto;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 0.9em;
    line-height: 1.6;
}}
pre code {{
    background: none;
    padding: 0;
    color: inherit;
}}
blockquote {{
    border-left: 4px solid #4a4adf;
    margin: 20px 0;
    padding: 10px 20px;
    background: #f0f0ff;
    color: #555;
}}
ul, ol {{
    padding-left: 25px;
    margin: 15px 0;
}}
li {{
    margin: 8px 0;
}}
hr {{
    border: none;
    border-top: 1px solid #ddd;
    margin: 30px 0;
}}
strong {{
    color: #1a1a2e;
}}
a {{
    color: #4a4adf;
    text-decoration: none;
}}
a:hover {{
    text-decoration: underline;
}}
.footer {{
    text-align: center;
    color: #999;
    font-size: 12px;
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid #eee;
}}
</style>
</head>
<body>
<div class="container">
{html_body}
<div class="footer">
    <p>本报告由 AI Hacking Agent 自动生成 | 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>
</div>
</body>
</html>"""

    def _simple_markdown_to_html(self, md: str) -> str:
        """简单的Markdown转HTML"""
        import re

        # 代码块
        md = re.sub(r'```([\s\S]*?)```', lambda m: f'<pre><code>{m.group(1)}</code></pre>', md)

        # 行内代码
        md = re.sub(r'`([^`]+)`', r'<code>\1</code>', md)

        # 标题
        md = re.sub(r'^# (.*)$', r'<h1>\1</h1>', md, flags=re.MULTILINE)
        md = re.sub(r'^## (.*)$', r'<h2>\1</h2>', md, flags=re.MULTILINE)
        md = re.sub(r'^### (.*)$', r'<h3>\1</h3>', md, flags=re.MULTILINE)
        md = re.sub(r'^#### (.*)$', r'<h4>\1</h4>', md, flags=re.MULTILINE)

        # 粗体
        md = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', md)

        # 斜体
        md = re.sub(r'\*(.*?)\*', r'<em>\1</em>', md)

        # 表格
        lines = md.split('\n')
        in_table = False
        table_rows = []
        result = []

        for line in lines:
            if '|' in line and line.strip().startswith('|'):
                if not in_table:
                    in_table = True
                    table_rows = []
                table_rows.append(line)
            else:
                if in_table:
                    result.append(self._convert_table(table_rows))
                    in_table = False
                    table_rows = []
                result.append(line)

        if in_table:
            result.append(self._convert_table(table_rows))

        md = '\n'.join(result)

        # 列表
        md = re.sub(r'^- (.*)$', r'<li>\1</li>', md, flags=re.MULTILINE)
        md = re.sub(r'^(\d+)\. (.*)$', r'<li>\2</li>', md, flags=re.MULTILINE)

        # 包裹列表
        md = re.sub(r'(<li>.*</li>\n?)+', lambda m: f'<ul>{m.group(0)}</ul>', md)

        # 引用
        md = re.sub(r'^> (.*)$', r'<blockquote>\1</blockquote>', md, flags=re.MULTILINE)

        # 分割线
        md = re.sub(r'^---$', r'<hr>', md, flags=re.MULTILINE)

        # 链接
        md = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', md)

        # 段落
        md = re.sub(r'\n\n', r'</p><p>', md)
        md = f'<p>{md}</p>'

        # 清理空段落
        md = md.replace('<p></p>', '')

        return md

    def _convert_table(self, rows: List[str]) -> str:
        """转换Markdown表格为HTML"""
        if len(rows) < 2:
            return '\n'.join(rows)

        # 解析表头
        headers = [h.strip() for h in rows[0].split('|')[1:-1]]

        # 跳过分隔行
        data_rows = rows[2:] if len(rows) > 2 else []

        html = '<table>\n<thead>\n<tr>\n'
        for h in headers:
            html += f'<th>{h}</th>\n'
        html += '</tr>\n</thead>\n<tbody>\n'

        for row in data_rows:
            cells = [c.strip() for c in row.split('|')[1:-1]]
            html += '<tr>\n'
            for c in cells:
                html += f'<td>{c}</td>\n'
            html += '</tr>\n'

        html += '</tbody>\n</table>'
        return html


# 便捷函数
def create_report_generator(output_dir: str = "./reports") -> ReportGenerator:
    """创建报告生成器"""
    return ReportGenerator(output_dir)


if __name__ == "__main__":
    print("=== 专业报告生成器 ===")
    print()

    generator = ReportGenerator()

    # 测试数据
    data = ReportData(
        title="测试系统渗透测试报告",
        company="测试公司",
        author="安全测试员",
        target="http://testphp.vulnweb.com",
        start_time="2026-08-29 10:00:00",
        end_time="2026-08-29 12:00:00",
        vulnerabilities=[
            VulnerabilityItem(
                id="VULN-001",
                title="SQL注入漏洞",
                severity="high",
                type="sqli",
                description="登录接口存在SQL注入漏洞，攻击者可通过构造特殊的用户名绕过身份验证。",
                target="http://testphp.vulnweb.com",
                url="http://testphp.vulnweb.com/login.php",
                parameter="username",
                method="POST",
                evidence="使用用户名 admin' OR '1'='1 成功登录",
                poc="' OR '1'='1",
                exp="sqlmap -u http://testphp.vulnweb.com/login.php --data 'username=admin&password=admin' --dbs",
                cvss_score=8.5,
                fix_suggestion="使用参数化查询，对用户输入进行严格过滤。",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            ),
            VulnerabilityItem(
                id="VULN-002",
                title="XSS跨站脚本漏洞",
                severity="medium",
                type="xss",
                description="搜索框存在反射型XSS漏洞，攻击者可通过构造特殊的搜索参数在用户浏览器中执行恶意JavaScript。",
                target="http://testphp.vulnweb.com",
                url="http://testphp.vulnweb.com/search.php",
                parameter="q",
                method="GET",
                evidence="输入 <script>alert(1)</script> 成功弹窗",
                poc="<script>alert(document.cookie)</script>",
                cvss_score=6.1,
                fix_suggestion="对用户输入进行HTML实体编码，使用CSP安全头。",
            ),
        ],
    )

    # 生成专业报告
    filepath = generator.generate(data, template="professional", format="html")
    print(f"专业报告已生成: {filepath}")

    # 生成护网自查报告
    filepath = generator.generate(data, template="hw_self_check", format="markdown")
    print(f"护网自查报告已生成: {filepath}")

    # 生成高管摘要报告
    filepath = generator.generate(data, template="executive", format="markdown")
    print(f"高管摘要报告已生成: {filepath}")

    # 生成简单扫描报告
    filepath = generator.generate(data, template="simple", format="markdown")
    print(f"简单扫描报告已生成: {filepath}")

    print()
    print("✅ 所有报告生成完成！")
