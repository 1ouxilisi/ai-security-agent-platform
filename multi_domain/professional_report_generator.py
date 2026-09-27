#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
专业报告生成器（Professional Report Generator）

生成专业级渗透测试报告，包含：
1. 执行摘要 - 高层级风险概览
2. 测试范围 - 目标和领域
3. 方法论 - 使用的工具和技术
4. 漏洞详情 - 按严重程度排序
5. 攻击链分析 - 12条攻击链验证结果
6. 风险评分 - CVSS和业务影响
7. 修复建议 - 具体的修复步骤
8. 附录 - 工具列表和原始数据
"""

import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field


@dataclass
class ReportSection:
    """报告章节"""
    title: str
    content: str
    order: int = 0


class ProfessionalReportGenerator:
    """
    专业报告生成器

    生成可交付的渗透测试报告。
    """

    def __init__(self):
        self.sections: List[ReportSection] = []

    def generate_report(self,
                        findings: List[Dict],
                        chain_results: List[Dict] = None,
                        execution_plan: Dict = None,
                        target: str = "",
                        domains_tested: List[str] = None,
                        tool_status: Dict = None,
                        report_type: str = "full") -> str:
        """
        生成完整报告

        Args:
            findings: 所有发现
            chain_results: 攻击链验证结果
            execution_plan: 执行计划
            target: 目标
            domains_tested: 测试的领域
            tool_status: 工具状态
            report_type: 报告类型 (full/executive/technical)

        Returns:
            Markdown格式的报告
        """
        self.sections = []
        chain_results = chain_results or []
        domains_tested = domains_tested or []
        tool_status = tool_status or {}

        # 统计
        stats = self._calculate_stats(findings, chain_results)

        # 1. 报告头
        self._add_header(target, stats)

        # 2. 执行摘要
        self._add_executive_summary(stats, chain_results)

        # 3. 测试范围
        self._add_scope(target, domains_tested)

        # 4. 方法论
        self._add_methodology(tool_status)

        # 5. 漏洞详情
        self._add_vulnerabilities(findings)

        # 6. 攻击链分析
        if chain_results:
            self._add_attack_chains(chain_results)

        # 7. 执行计划
        if execution_plan:
            self._add_execution_plan(execution_plan)

        # 8. 修复建议
        self._add_remediation(findings, chain_results)

        # 9. 风险矩阵
        self._add_risk_matrix(stats)

        # 10. 附录
        self._add_appendix(tool_status, findings)

        # 按顺序排序并合并
        self.sections.sort(key=lambda s: s.order)
        report = "\n\n---\n\n".join(s.content for s in self.sections)

        return report

    def _calculate_stats(self, findings: List[Dict],
                         chain_results: List[Dict]) -> Dict[str, Any]:
        """计算统计数据"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        real_findings = 0
        simulated_findings = 0
        domains_covered = set()

        for f in findings:
            sev = f.get('severity', 'info').lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            if f.get('source') == 'real_tool':
                real_findings += 1
            else:
                simulated_findings += 1
            if 'domain' in f:
                domains_covered.add(f['domain'])

        # 风险评分 (0-100)
        risk_score = min(100,
            severity_counts['critical'] * 25 +
            severity_counts['high'] * 15 +
            severity_counts['medium'] * 8 +
            severity_counts['low'] * 3
        )

        # 攻击链统计
        exploitable_chains = sum(1 for c in chain_results if c.get('status') == 'exploitable')
        verified_chains = sum(1 for c in chain_results if c.get('status') == 'verified')
        high_risk_chains = sum(1 for c in chain_results
                              if c.get('risk_level') in ['critical', 'high'])

        return {
            'total_findings': len(findings),
            'severity_counts': severity_counts,
            'real_findings': real_findings,
            'simulated_findings': simulated_findings,
            'domains_covered': len(domains_covered),
            'risk_score': risk_score,
            'exploitable_chains': exploitable_chains,
            'verified_chains': verified_chains,
            'high_risk_chains': high_risk_chains,
            'total_chains': len(chain_results),
        }

    def _add_header(self, target: str, stats: Dict):
        """添加报告头"""
        content = f"""# 渗透测试报告

**报告编号**: PT-{datetime.now().strftime('%Y%m%d')}-001
**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**测试目标**: {target or '未指定'}
**报告类型**: 全栈安全评估

---

## 风险概览

| 指标 | 数值 |
|------|------|
| 总发现数 | {stats['total_findings']} |
| 严重(Critical) | {stats['severity_counts']['critical']} |
| 高危(High) | {stats['severity_counts']['high']} |
| 中危(Medium) | {stats['severity_counts']['medium']} |
| 低危(Low) | {stats['severity_counts']['low']} |
| 信息(Info) | {stats['severity_counts']['info']} |
| 真实工具发现 | {stats['real_findings']} |
| 模拟发现 | {stats['simulated_findings']} |
| 综合风险评分 | **{stats['risk_score']}/100** |
| 可利用攻击链 | {stats['exploitable_chains']} |
| 已验证攻击链 | {stats['verified_chains']} |"""

        self.sections.append(ReportSection("报告头", content, 0))

    def _add_executive_summary(self, stats: Dict, chain_results: List[Dict]):
        """添加执行摘要"""
        risk_level = "严重" if stats['risk_score'] >= 70 else "高" if stats['risk_score'] >= 50 else "中" if stats['risk_score'] >= 30 else "低"

        content = f"""## 1. 执行摘要

### 1.1 总体评估

本次安全评估针对目标系统进行了全栈安全测试，覆盖{stats['domains_covered']}个安全领域，共发现{stats['total_findings']}个安全问题。

**综合风险等级: {risk_level} ({stats['risk_score']}/100)**

### 1.2 关键发现

- 发现{stats['severity_counts']['critical']}个严重漏洞，需立即修复
- 发现{stats['severity_counts']['high']}个高危漏洞，建议24小时内修复
- {stats['exploitable_chains']}条攻击链已完全验证可被利用
- {stats['verified_chains']}条攻击链大部分阶段已验证
- {stats['high_risk_chains']}条攻击链存在高风险

### 1.3 业务影响

根据发现的漏洞和攻击链，目标系统存在被未授权访问、数据泄露、服务中断等风险。建议优先修复严重和高危漏洞，并对已验证的攻击链进行针对性防护。

### 1.4 测试真实性

本次测试中，{stats['real_findings']}个发现来自真实工具执行，{stats['simulated_findings']}个发现来自智能体模拟分析。真实工具发现具有更高的可信度和可验证性。"""

        self.sections.append(ReportSection("执行摘要", content, 1))

    def _add_scope(self, target: str, domains_tested: List[str]):
        """添加测试范围"""
        domains_text = "\n".join(f"- {d}" for d in domains_tested) if domains_tested else "- 全部12个安全领域"

        content = f"""## 2. 测试范围

### 2.1 测试目标

- **目标地址**: {target or '未指定'}
- **测试类型**: 黑盒/灰盒渗透测试
- **测试时间**: {datetime.now().strftime('%Y-%m-%d')}

### 2.2 测试领域

本次测试覆盖以下安全领域:

{domains_text}

### 2.3 测试限制

- 测试仅在授权范围内进行
- 未进行拒绝服务(DoS)测试
- 未进行社会工程学实际攻击
- 所有发现均基于公开漏洞和配置问题"""

        self.sections.append(ReportSection("测试范围", content, 2))

    def _add_methodology(self, tool_status: Dict):
        """添加方法论"""
        available_tools = [k for k, v in tool_status.items() if v == 'available']
        tools_text = ", ".join(available_tools[:20]) if available_tools else "未检测到工具"

        content = f"""## 3. 测试方法论

### 3.1 测试流程

本次测试遵循标准渗透测试方法论:

1. **侦察阶段** - 信息收集、端口扫描、服务识别
2. **扫描阶段** - 漏洞扫描、配置审计、版本检测
3. **分析阶段** - 漏洞验证、攻击链构建、风险评估
4. **利用阶段** - 漏洞利用、权限提升、横向移动
5. **报告阶段** - 结果整理、修复建议、报告生成

### 3.2 使用工具

本次测试使用以下安全工具:

{tools_text}

### 3.3 AI智能体协作

测试过程中使用了多智能体协作系统，包含:
- 12个安全领域的专业智能体
- 8个MITRE ATT&CK角色映射
- 多线程并行执行
- 攻击链自动验证
- 智能决策引擎"""

        self.sections.append(ReportSection("方法论", content, 3))

    def _add_vulnerabilities(self, findings: List[Dict]):
        """添加漏洞详情"""
        # 按严重程度排序
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(findings,
                                key=lambda f: severity_order.get(f.get('severity', 'info'), 5))

        vuln_content = []
        for i, f in enumerate(sorted_findings[:30], 1):  # 最多30个
            name = f.get('name', f.get('type', 'unknown'))
            severity = f.get('severity', 'info').upper()
            ftype = f.get('type', 'unknown')
            source = f.get('source', 'simulated')
            source_text = "真实工具" if source == 'real_tool' else "智能体模拟"

            details = []
            for k, v in f.items():
                if k not in ['name', 'severity', 'type', 'source', 'agent_role', 'tool']:
                    details.append(f"  - {k}: {v}")
            details_text = "\n".join(details[:5]) if details else "  - 无额外详情"

            vuln_content.append(f"""### 3.{i} {name}

- **严重程度**: {severity}
- **类型**: {ftype}
- **来源**: {source_text}
- **详情**:
{details_text}""")

        content = f"""## 4. 漏洞详情

共发现{len(findings)}个安全问题，以下按严重程度排序展示前{min(30, len(findings))}个:

{chr(10).join(vuln_content)}"""

        self.sections.append(ReportSection("漏洞详情", content, 4))

    def _add_attack_chains(self, chain_results: List[Dict]):
        """添加攻击链分析"""
        chains_text = []
        for i, chain in enumerate(chain_results, 1):
            name = chain.get('name', 'unknown')
            status = chain.get('status', 'unknown')
            risk = chain.get('risk_level', 'info').upper()
            completion = int(chain.get('completion_rate', 0) * 100)
            score = chain.get('overall_score', 0)
            difficulty = chain.get('exploit_difficulty', 'unknown')

            stages = chain.get('stages', [])
            stages_text = "\n".join(
                f"  - [{'✓' if s.get('verified') else '✗'}] {s.get('name')}: {s.get('description')}"
                for s in stages
            )

            chains_text.append(f"""### 4.{i} {name}

- **状态**: {status}
- **风险等级**: {risk}
- **完成度**: {completion}%
- **综合评分**: {score}/100
- **利用难度**: {difficulty}
- **阶段验证**:
{stages_text}""")

        content = f"""## 5. 攻击链分析

本次测试验证了{len(chain_results)}条跨领域攻击链:

{chr(10).join(chains_text)}"""

        self.sections.append(ReportSection("攻击链分析", content, 5))

    def _add_execution_plan(self, plan: Dict):
        """添加执行计划"""
        actions = plan.get('actions', [])
        actions_text = []
        for i, a in enumerate(actions[:15], 1):
            actions_text.append(f"""| {i} | {a.get('title', '')} | {a.get('priority', '')} | {a.get('type', '')} | {a.get('estimated_time', '')} |""")

        content = f"""## 6. 后续执行计划

基于发现和攻击链分析，智能决策引擎生成了以下执行计划:

### 6.1 计划概览

- **总行动数**: {plan.get('total_actions', 0)}
- **P0紧急行动**: {plan.get('critical_actions', 0)}
- **P1高优先级**: {plan.get('high_actions', 0)}
- **预计总耗时**: {plan.get('estimated_total_time', '未知')}
- **整体风险**: {plan.get('overall_risk', 'unknown')}

### 6.2 行动清单

| 序号 | 行动 | 优先级 | 类型 | 预计耗时 |
|------|------|--------|------|----------|
{chr(10).join(actions_text)}"""

        self.sections.append(ReportSection("执行计划", content, 6))

    def _add_remediation(self, findings: List[Dict], chain_results: List[Dict]):
        """添加修复建议"""
        content = """## 7. 修复建议

### 7.1 优先级修复

#### P0 - 立即修复 (24小时内)

- 修复所有严重(Critical)漏洞
- 阻断已验证可利用的攻击链
- 轮换所有泄露的凭证和密钥
- 隔离受影响的系统

#### P1 - 高优先级 (本周内)

- 修复所有高危(High)漏洞
- 加强访问控制和认证机制
- 实施网络分段和微隔离
- 部署入侵检测和监控

#### P2 - 中优先级 (本月内)

- 修复中危(Medium)漏洞
- 完善安全配置和基线
- 加强日志审计和告警
- 进行安全意识培训

### 7.2 攻击链防护

针对已验证的攻击链，建议采取以下防护措施:

1. **Web→内网攻击链**: 部署WAF、加强Web服务器加固、实施网络分段
2. **移动→AI攻击链**: 移除APP硬编码密钥、实施API限流和认证、监控异常调用
3. **IoT→工控攻击链**: 隔离工控网络、修改默认凭证、部署工控防火墙
4. **社工→内网攻击链**: 实施多因素认证、加强邮件安全、定期安全培训

### 7.3 长期建议

- 建立持续安全监控机制
- 定期进行渗透测试和红队演练
- 实施DevSecOps流程
- 建立漏洞管理和响应流程
- 加强供应链安全管理"""

        self.sections.append(ReportSection("修复建议", content, 7))

    def _add_risk_matrix(self, stats: Dict):
        """添加风险矩阵"""
        content = f"""## 8. 风险矩阵

### 8.1 严重程度分布

```
Critical  {'█' * stats['severity_counts']['critical']} {stats['severity_counts']['critical']}
High      {'█' * stats['severity_counts']['high']} {stats['severity_counts']['high']}
Medium    {'█' * stats['severity_counts']['medium']} {stats['severity_counts']['medium']}
Low       {'█' * stats['severity_counts']['low']} {stats['severity_counts']['low']}
Info      {'█' * stats['severity_counts']['info']} {stats['severity_counts']['info']}
```

### 8.2 攻击链风险分布

- 可利用攻击链: {stats['exploitable_chains']}/{stats['total_chains']}
- 已验证攻击链: {stats['verified_chains']}/{stats['total_chains']}
- 高风险攻击链: {stats['high_risk_chains']}/{stats['total_chains']}

### 8.3 综合风险评分

**{stats['risk_score']}/100**

风险等级: {"严重" if stats['risk_score'] >= 70 else "高" if stats['risk_score'] >= 50 else "中" if stats['risk_score'] >= 30 else "低"}"""

        self.sections.append(ReportSection("风险矩阵", content, 8))

    def _add_appendix(self, tool_status: Dict, findings: List[Dict]):
        """添加附录"""
        available = [k for k, v in tool_status.items() if v == 'available']
        not_found = [k for k, v in tool_status.items() if v == 'not_found']

        content = f"""## 9. 附录

### 9.1 工具清单

**可用工具 ({len(available)}个)**:
{', '.join(available[:30]) if available else '无'}

**未检测到工具 ({len(not_found)}个)**:
{', '.join(not_found[:20]) if not_found else '无'}

### 9.2 原始发现数据

共{len(findings)}个发现，详细数据见附件JSON文件。

### 9.3 免责声明

本报告仅用于授权范围内的安全评估，所有测试均在合法授权下进行。报告中的漏洞信息仅供修复参考，不得用于非法用途。

---

**报告结束**

*本报告由AI全栈安全测试平台自动生成*
*生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"""

        self.sections.append(ReportSection("附录", content, 9))

    def save_report(self, report: str, filepath: str):
        """保存报告到文件"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report)
        return filepath


# 单例模式
_generator_instance: Optional[ProfessionalReportGenerator] = None

def get_report_generator() -> ProfessionalReportGenerator:
    """获取全局报告生成器实例"""
    global _generator_instance
    if _generator_instance is None:
        _generator_instance = ProfessionalReportGenerator()
    return _generator_instance
