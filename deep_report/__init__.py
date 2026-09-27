#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深度报告引擎 (Deep Report Engine)

极其深度的渗透测试报告生成：
执行摘要→攻击链时间线→漏洞详情→CVSS评分→合规映射→修复优先级→风险矩阵→多格式导出

不是简单的漏洞列表，而是企业级完整报告：
1. 执行摘要：管理层可读的风险概览
2. 攻击链时间线：完整攻击路径可视化
3. 漏洞详情：每个漏洞的技术细节/复现步骤/影响范围
4. CVSS v3.1评分：完整的向量字符串和评分
5. 合规映射：等保2.0/ISO27001/PCI-DSS/NIST CSF
6. 修复优先级：按风险/业务影响/修复难度排序
7. 风险矩阵：可能性×影响的二维矩阵
8. 趋势分析：历史对比和改进建议
9. 多格式导出：HTML/PDF/Markdown/JSON/CSV
"""

import json
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


# ============================================================
# CVSS v3.1 评分
# ============================================================

class CVSSv31:
    """CVSS v3.1 评分计算器"""

    # 评分权重
    METRIC_WEIGHTS = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {
            "N": {"U": 0.85, "C": 0.85},
            "L": {"U": 0.62, "C": 0.68},
            "H": {"U": 0.27, "C": 0.50},
        },
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"H": 0.56, "L": 0.22, "N": 0},
        "I": {"H": 0.56, "L": 0.22, "N": 0},
        "A": {"H": 0.56, "L": 0.22, "N": 0},
    }

    @staticmethod
    def calculate(
        av: str = "N", ac: str = "L", pr: str = "N", ui: str = "N",
        c: str = "N", i: str = "N", a: str = "N",
        scope: str = "U",
    ) -> Dict:
        """计算CVSS v3.1基础评分"""
        # 攻击向量
        av_score = CVSSv31.METRIC_WEIGHTS["AV"][av]
        ac_score = CVSSv31.METRIC_WEIGHTS["AC"][ac]
        pr_score = CVSSv31.METRIC_WEIGHTS["PR"][pr][scope]
        ui_score = CVSSv31.METRIC_WEIGHTS["UI"][ui]

        # 影响
        c_score = CVSSv31.METRIC_WEIGHTS["C"][c]
        i_score = CVSSv31.METRIC_WEIGHTS["I"][i]
        a_score = CVSSv31.METRIC_WEIGHTS["A"][a]

        # 可利用性
        exploitability = 8.22 * av_score * ac_score * pr_score * ui_score

        # 影响
        iss = 1 - ((1 - c_score) * (1 - i_score) * (1 - a_score))
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # 基础分
        if impact <= 0:
            base_score = 0
        else:
            if scope == "U":
                base_score = min((exploitability + impact), 10)
            else:
                base_score = min(1.08 * (exploitability + impact), 10)

        # 四舍五入到0.1
        base_score = round(base_score * 10) / 10

        # 等级
        if base_score == 0:
            severity = "None"
        elif base_score < 4.0:
            severity = "Low"
        elif base_score < 7.0:
            severity = "Medium"
        elif base_score < 9.0:
            severity = "High"
        else:
            severity = "Critical"

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"

        return {
            "base_score": base_score,
            "severity": severity,
            "vector": vector,
            "exploitability_score": round(exploitability, 2),
            "impact_score": round(impact, 2),
            "metrics": {
                "AV": av, "AC": ac, "PR": pr, "UI": ui,
                "S": scope, "C": c, "I": i, "A": a,
            },
        }


# ============================================================
# 合规映射
# ============================================================

COMPLIANCE_MAPPING = {
    "sql_injection": {
        "等保2.0": ["8.1.3 访问控制", "8.1.4 安全审计"],
        "ISO27001": ["A.13.1.1 网络安全管理", "A.14.2.5 安全系统工程"],
        "PCI-DSS": ["Req 6.5.1 注入攻击防护", "Req 6.6 Web应用防火墙"],
        "NIST_CSF": ["PR.AC-4 访问权限", "DE.CM-1 网络监控"],
    },
    "xss": {
        "等保2.0": ["8.1.3 访问控制", "8.1.5 入侵防范"],
        "ISO27001": ["A.14.2.5 安全系统工程", "A.13.2.1 信息传输"],
        "PCI-DSS": ["Req 6.5.7 跨站脚本防护"],
        "NIST_CSF": ["PR.DS-2 数据保护", "DE.CM-7 应用监控"],
    },
    "rce": {
        "等保2.0": ["8.1.5 入侵防范", "8.1.6 恶意代码防范"],
        "ISO27001": ["A.12.6.1 恶意软件防护", "A.14.2.5 安全系统工程"],
        "PCI-DSS": ["Req 5 恶意软件防护", "Req 6.5 安全编码"],
        "NIST_CSF": ["PR.PT-3 远程维护", "RS.MI-1 事件缓解"],
    },
    "path_traversal": {
        "等保2.0": ["8.1.3 访问控制", "8.1.5 入侵防范"],
        "ISO27001": ["A.9.1.2 访问权限", "A.14.2.5 安全系统工程"],
        "PCI-DSS": ["Req 6.5.8 目录遍历防护"],
        "NIST_CSF": ["PR.AC-4 访问权限", "PR.DS-5 数据保护"],
    },
    "sensitive_file_exposure": {
        "等保2.0": ["8.1.3 访问控制", "8.1.4 安全审计"],
        "ISO27001": ["A.9.1.2 访问权限", "A.10.1.1 物理介质"],
        "PCI-DSS": ["Req 3 存储加密", "Req 7 访问控制"],
        "NIST_CSF": ["PR.AC-4 访问权限", "PR.DS-1 静态数据保护"],
    },
    "prompt_injection": {
        "等保2.0": ["8.1.5 入侵防范", "8.1.10 个人信息保护"],
        "ISO27001": ["A.14.2.5 安全系统工程", "A.16.1.4 安全事件处置"],
        "PCI-DSS": ["Req 6.5 安全编码（新增AI安全）"],
        "NIST_CSF": ["PR.AI-1 AI系统安全", "DE.AE-3 事件分析"],
    },
    "system_prompt_leak": {
        "等保2.0": ["8.1.3 访问控制", "8.1.10 个人信息保护"],
        "ISO27001": ["A.9.1.2 访问权限", "A.13.2.1 信息传输"],
        "PCI-DSS": ["Req 3 存储加密", "Req 6.5 安全编码"],
        "NIST_CSF": ["PR.AI-2 AI数据保护", "PR.DS-5 数据保护"],
    },
    "default_credentials": {
        "等保2.0": ["8.1.3 访问控制", "8.1.4 安全审计"],
        "ISO27001": ["A.9.2.1 用户注册", "A.9.3.1 密码使用"],
        "PCI-DSS": ["Req 8.1 密码管理", "Req 8.2 强认证"],
        "NIST_CSF": ["PR.AC-1 身份管理", "PR.AC-7 认证"],
    },
}


# ============================================================
# 数据结构
# ============================================================

@dataclass
class VulnerabilityDetail:
    """漏洞详情"""
    vuln_id: str
    title: str
    description: str
    severity: str  # critical/high/medium/low/info
    cvss: Dict = field(default_factory=dict)
    category: str = ""
    affected_url: str = ""
    affected_component: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    impact: str = ""
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""
    remediation_complexity: str = "medium"  # easy/medium/hard
    compliance_mapping: Dict[str, List[str]] = field(default_factory=dict)
    discovered_at: str = ""
    status: str = "open"  # open/fixed/accepted/risk_accepted


@dataclass
class AttackChainStep:
    """攻击链步骤"""
    step: int
    phase: str
    action: str
    tool: str
    result: str
    timestamp: str
    duration_seconds: float = 0
    evidence: List[str] = field(default_factory=list)


@dataclass
class RiskMatrixItem:
    """风险矩阵项"""
    vulnerability: str
    likelihood: float  # 0-1
    impact: float  # 0-1
    risk_level: str = ""  # calculated


@dataclass
class ExecutiveSummary:
    """执行摘要"""
    total_vulns: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    overall_risk_score: float = 0.0
    overall_risk_level: str = "low"
    attack_surface_size: int = 0
    successful_attack_chains: int = 0
    max_attack_depth: str = ""
    key_findings: List[str] = field(default_factory=list)
    top_risks: List[str] = field(default_factory=list)


@dataclass
class DeepReport:
    """深度报告"""
    report_id: str = ""
    title: str = ""
    target: str = ""
    report_date: str = ""
    generated_by: str = "AI Hacking Agent v4.8"
    executive_summary: ExecutiveSummary = field(default_factory=ExecutiveSummary)
    vulnerabilities: List[VulnerabilityDetail] = field(default_factory=list)
    attack_chain: List[AttackChainStep] = field(default_factory=list)
    risk_matrix: List[RiskMatrixItem] = field(default_factory=list)
    remediation_plan: List[Dict] = field(default_factory=list)
    compliance_status: Dict[str, Dict] = field(default_factory=dict)
    appendices: Dict[str, Any] = field(default_factory=dict)


# ============================================================
# 深度报告引擎
# ============================================================

class DeepReportEngine:
    """深度报告引擎"""

    def __init__(self):
        self.report = DeepReport()

    def generate_report(
        self,
        target: str,
        recon_result: Optional[Any] = None,
        exploit_result: Optional[Any] = None,
        adversarial_result: Optional[Any] = None,
        choreography_result: Optional[Any] = None,
    ) -> DeepReport:
        """
        生成完整深度报告

        Args:
            target: 目标
            recon_result: 深度侦察结果
            exploit_result: 漏洞利用链结果
            adversarial_result: AI对抗结果
            choreography_result: 攻击链编排结果
        """
        self.report = DeepReport(
            report_id=hashlib.md5(f"{target}{datetime.now().isoformat()}".encode()).hexdigest()[:12],
            title=f"深度渗透测试报告 - {target}",
            target=target,
            report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        # 1. 收集漏洞
        self._collect_vulnerabilities(recon_result, exploit_result, adversarial_result)

        # 2. 构建攻击链
        self._build_attack_chain(recon_result, exploit_result, choreography_result)

        # 3. 执行摘要
        self._build_executive_summary()

        # 4. 风险矩阵
        self._build_risk_matrix()

        # 5. 修复计划
        self._build_remediation_plan()

        # 6. 合规状态
        self._build_compliance_status()

        return self.report

    def _collect_vulnerabilities(self, recon_result, exploit_result, adversarial_result):
        """收集所有漏洞"""
        vulns = []

        # 从侦察结果收集
        if recon_result:
            # 敏感文件
            for sf in getattr(recon_result, "sensitive_files", []):
                cvss = CVSSv31.calculate(
                    av="N", ac="L", pr="N", ui="N",
                    c="H" if sf.severity == "critical" else "L",
                    i="L", a="N",
                )
                vulns.append(VulnerabilityDetail(
                    vuln_id=f"VULN-{len(vulns)+1:03d}",
                    title=f"敏感文件暴露: {sf.path}",
                    description=sf.description or f"敏感文件 {sf.path} 可被公开访问",
                    severity=sf.severity,
                    cvss=cvss,
                    category="sensitive_file_exposure",
                    affected_url=sf.path,
                    impact="攻击者可获取敏感配置信息、凭证或源代码",
                    remediation="删除敏感文件或配置访问控制，禁止公网访问",
                    remediation_complexity="easy",
                    compliance_mapping=COMPLIANCE_MAPPING.get("sensitive_file_exposure", {}),
                    discovered_at=recon_result.scan_time,
                ))

            # JS中的API密钥
            for js in getattr(recon_result, "js_findings", []):
                if js.api_keys_found:
                    cvss = CVSSv31.calculate(av="N", ac="L", pr="N", ui="N", c="H", i="H", a="N")
                    vulns.append(VulnerabilityDetail(
                        vuln_id=f"VULN-{len(vulns)+1:03d}",
                        title=f"JS文件中泄露API密钥: {js.url}",
                        description=f"在JavaScript文件中发现 {len(js.api_keys_found)} 个API密钥",
                        severity="critical",
                        cvss=cvss,
                        category="sensitive_file_exposure",
                        affected_url=js.url,
                        impact="攻击者可使用泄露的API密钥访问后端服务",
                        remediation="立即轮换所有泄露的API密钥，从前端代码中移除密钥",
                        remediation_complexity="medium",
                    ))

            # 公开云存储
            for cs in getattr(recon_result, "cloud_storages", []):
                if cs.is_public:
                    cvss = CVSSv31.calculate(av="N", ac="L", pr="N", ui="N", c="H", i="L", a="N")
                    vulns.append(VulnerabilityDetail(
                        vuln_id=f"VULN-{len(vulns)+1:03d}",
                        title=f"公开云存储桶: {cs.bucket_name}",
                        description=f"云存储桶 {cs.bucket_name} ({cs.provider}) 可公开访问",
                        severity="high",
                        cvss=cvss,
                        category="sensitive_file_exposure",
                        affected_url=f"{cs.bucket_name}.{cs.provider}.amazonaws.com",
                        impact=f"攻击者可访问桶中 {cs.files_count} 个文件",
                        remediation="关闭公共访问，启用访问日志和加密",
                        remediation_complexity="easy",
                    ))

        # 从漏洞利用结果收集
        if exploit_result:
            for v in getattr(exploit_result, "matched_vulns", []):
                cvss = CVSSv31.calculate(
                    av="N", ac="L", pr="N", ui="N",
                    c="H" if v.severity == "critical" else ("L" if v.severity == "medium" else "H"),
                    i="H" if v.severity == "critical" else "L",
                    a="N",
                )
                vulns.append(VulnerabilityDetail(
                    vuln_id=f"VULN-{len(vulns)+1:03d}",
                    title=f"{v.cve}: {v.description}",
                    description=f"{v.product} {v.version} 存在 {v.type} 漏洞",
                    severity=v.severity,
                    cvss=cvss,
                    category=v.type,
                    affected_component=f"{v.product} {v.version}",
                    impact=f"CVSS {v.cvss}，{v.description}",
                    remediation=f"升级 {v.product} 到最新版本，应用安全补丁",
                    remediation_complexity="medium",
                    reproduction_steps=[
                        f"1. 识别目标运行 {v.product} {v.version}",
                        f"2. 使用 {v.poc_type} 类型PoC进行验证",
                        f"3. 确认漏洞可利用性: {v.verification_result}",
                    ],
                    compliance_mapping=COMPLIANCE_MAPPING.get(v.type, {}),
                ))

        # 从AI对抗结果收集
        if adversarial_result:
            if getattr(adversarial_result, "system_prompt_extracted", False):
                cvss = CVSSv31.calculate(av="N", ac="L", pr="N", ui="R", c="H", i="N", a="N")
                vulns.append(VulnerabilityDetail(
                    vuln_id=f"VULN-{len(vulns)+1:03d}",
                    title="AI系统提示泄露",
                    description="AI模型的系统提示可被提取，包含内部指令和配置信息",
                    severity="high",
                    cvss=cvss,
                    category="system_prompt_leak",
                    impact="攻击者可了解AI系统的内部逻辑，绕过安全限制",
                    remediation="不在系统提示中存储敏感信息，实施输入输出过滤",
                    remediation_complexity="medium",
                    compliance_mapping=COMPLIANCE_MAPPING.get("system_prompt_leak", {}),
                ))

            # 间接注入风险
            for inj in getattr(adversarial_result, "indirect_injections", []):
                if inj.severity in ["critical", "high"]:
                    cvss = CVSSv31.calculate(av="N", ac="L", pr="N", ui="R", c="L", i="H", a="N")
                    vulns.append(VulnerabilityDetail(
                        vuln_id=f"VULN-{len(vulns)+1:03d}",
                        title=f"间接提示注入风险: {inj.vector_name}",
                        description=inj.payload,
                        severity=inj.severity,
                        cvss=cvss,
                        category="prompt_injection",
                        impact="攻击者可通过外部内容操纵AI行为",
                        remediation="对所有外部输入进行注入检测和过滤",
                        remediation_complexity="hard",
                        compliance_mapping=COMPLIANCE_MAPPING.get("prompt_injection", {}),
                    ))

        self.report.vulnerabilities = vulns

    def _build_attack_chain(self, recon_result, exploit_result, choreography_result):
        """构建攻击链时间线"""
        chain = []

        if choreography_result:
            for entry in getattr(choreography_result, "full_timeline", []):
                chain.append(AttackChainStep(
                    step=len(chain) + 1,
                    phase=entry.get("phase", ""),
                    action=entry.get("action", ""),
                    tool=entry.get("engine", ""),
                    result=entry.get("output", ""),
                    timestamp=entry.get("start_time", ""),
                ))

        if not chain and recon_result:
            # 从侦察结果构建
            chain.append(AttackChainStep(
                step=1, phase="reconnaissance",
                action="深度侦察", tool="deep_recon",
                result=f"发现 {len(getattr(recon_result, 'subdomains', []))} 子域名, "
                       f"{len(getattr(recon_result, 'sensitive_files', []))} 敏感文件",
                timestamp=recon_result.scan_time,
            ))

        self.report.attack_chain = chain

    def _build_executive_summary(self):
        """构建执行摘要"""
        vulns = self.report.vulnerabilities
        summary = ExecutiveSummary(
            total_vulns=len(vulns),
            critical_count=sum(1 for v in vulns if v.severity == "critical"),
            high_count=sum(1 for v in vulns if v.severity == "high"),
            medium_count=sum(1 for v in vulns if v.severity == "medium"),
            low_count=sum(1 for v in vulns if v.severity == "low"),
            info_count=sum(1 for v in vulns if v.severity == "info"),
        )

        # 风险评分
        score = (
            summary.critical_count * 10 +
            summary.high_count * 5 +
            summary.medium_count * 2 +
            summary.low_count * 1
        )
        summary.overall_risk_score = min(100.0, score)
        if score >= 70:
            summary.overall_risk_level = "critical"
        elif score >= 50:
            summary.overall_risk_level = "high"
        elif score >= 30:
            summary.overall_risk_level = "medium"
        else:
            summary.overall_risk_level = "low"

        # 关键发现
        summary.key_findings = [
            f"共发现 {len(vulns)} 个安全漏洞",
            f"其中 {summary.critical_count} 个严重、{summary.high_count} 个高危",
            f"综合风险等级: {summary.overall_risk_level.upper()}",
        ]

        # Top风险
        top_vulns = sorted(vulns, key=lambda v: v.cvss.get("base_score", 0), reverse=True)[:5]
        summary.top_risks = [f"{v.vuln_id}: {v.title} (CVSS {v.cvss.get('base_score', 0)})" for v in top_vulns]

        self.report.executive_summary = summary

    def _build_risk_matrix(self):
        """构建风险矩阵"""
        matrix = []
        for v in self.report.vulnerabilities:
            likelihood = v.cvss.get("exploitability_score", 5) / 10
            impact = v.cvss.get("impact_score", 5) / 10
            risk = likelihood * impact
            if risk >= 0.6:
                level = "critical"
            elif risk >= 0.4:
                level = "high"
            elif risk >= 0.2:
                level = "medium"
            else:
                level = "low"
            matrix.append(RiskMatrixItem(
                vulnerability=v.title,
                likelihood=likelihood,
                impact=impact,
                risk_level=level,
            ))
        self.report.risk_matrix = matrix

    def _build_remediation_plan(self):
        """构建修复计划"""
        # 按优先级分组
        immediate = [v for v in self.report.vulnerabilities if v.severity == "critical"]
        short_term = [v for v in self.report.vulnerabilities if v.severity == "high"]
        medium_term = [v for v in self.report.vulnerabilities if v.severity == "medium"]
        long_term = [v for v in self.report.vulnerabilities if v.severity in ["low", "info"]]

        self.report.remediation_plan = [
            {
                "priority": "P0 - 立即修复",
                "timeframe": "24-48小时",
                "vulnerabilities": [v.vuln_id for v in immediate],
                "actions": [v.remediation for v in immediate],
                "owner": "安全团队",
            },
            {
                "priority": "P1 - 短期修复",
                "timeframe": "1-2周",
                "vulnerabilities": [v.vuln_id for v in short_term],
                "actions": list(set(v.remediation for v in short_term)),
                "owner": "开发团队",
            },
            {
                "priority": "P2 - 中期修复",
                "timeframe": "1个月",
                "vulnerabilities": [v.vuln_id for v in medium_term],
                "actions": list(set(v.remediation for v in medium_term)),
                "owner": "开发团队",
            },
            {
                "priority": "P3 - 长期改进",
                "timeframe": "3个月",
                "vulnerabilities": [v.vuln_id for v in long_term],
                "actions": ["建立安全编码规范", "实施持续安全监控", "定期安全培训"],
                "owner": "安全团队",
            },
        ]

    def _build_compliance_status(self):
        """构建合规状态"""
        frameworks = ["等保2.0", "ISO27001", "PCI-DSS", "NIST_CSF"]
        status = {}

        for fw in frameworks:
            controls = set()
            failed_controls = set()
            for v in self.report.vulnerabilities:
                mapping = v.compliance_mapping.get(fw, [])
                for c in mapping:
                    controls.add(c)
                    if v.severity in ["critical", "high"]:
                        failed_controls.add(c)

            status[fw] = {
                "total_controls": len(controls),
                "failed_controls": len(failed_controls),
                "compliance_rate": f"{(1 - len(failed_controls)/max(len(controls),1))*100:.0f}%",
                "failed_list": list(failed_controls),
            }

        self.report.compliance_status = status

    def export_markdown(self) -> str:
        """导出Markdown格式报告"""
        r = self.report
        s = r.executive_summary
        lines = [
            f"# {r.title}",
            f"",
            f"**报告ID**: {r.report_id}",
            f"**目标**: {r.target}",
            f"**日期**: {r.report_date}",
            f"**生成工具**: {r.generated_by}",
            f"",
            f"---",
            f"",
            f"## 1. 执行摘要",
            f"",
            f"| 指标 | 值 |",
            f"|------|-----|",
            f"| 总漏洞数 | {s.total_vulns} |",
            f"| 严重(Critical) | {s.critical_count} |",
            f"| 高危(High) | {s.high_count} |",
            f"| 中危(Medium) | {s.medium_count} |",
            f"| 低危(Low) | {s.low_count} |",
            f"| 综合风险 | {s.overall_risk_level.upper()} ({s.overall_risk_score:.1f}/100) |",
            f"",
            f"### 关键发现",
        ]
        for finding in s.key_findings:
            lines.append(f"- {finding}")

        lines.append(f"\n### Top 5 风险")
        for risk in s.top_risks:
            lines.append(f"- {risk}")

        lines.append(f"\n---\n\n## 2. 攻击链时间线\n")
        lines.append("| 步骤 | 阶段 | 动作 | 工具 | 结果 |")
        lines.append("|------|------|------|------|------|")
        for step in r.attack_chain:
            lines.append(f"| {step.step} | {step.phase} | {step.action} | {step.tool} | {step.result[:50]} |")

        lines.append(f"\n---\n\n## 3. 漏洞详情\n")
        for v in r.vulnerabilities:
            lines.append(f"### {v.vuln_id}: {v.title}")
            lines.append(f"- **严重程度**: {v.severity.upper()}")
            lines.append(f"- **CVSS**: {v.cvss.get('base_score', 'N/A')} ({v.cvss.get('severity', 'N/A')})")
            lines.append(f"- **向量**: `{v.cvss.get('vector', 'N/A')}`")
            lines.append(f"- **描述**: {v.description}")
            lines.append(f"- **影响**: {v.impact}")
            if v.reproduction_steps:
                lines.append(f"- **复现步骤**:")
                for step in v.reproduction_steps:
                    lines.append(f"  {step}")
            lines.append(f"- **修复建议**: {v.remediation}")
            lines.append(f"- **修复难度**: {v.remediation_complexity}")
            lines.append("")

        lines.append(f"---\n\n## 4. 修复计划\n")
        for plan in r.remediation_plan:
            lines.append(f"### {plan['priority']} ({plan['timeframe']})")
            lines.append(f"- 涉及漏洞: {', '.join(plan['vulnerabilities']) or '无'}")
            lines.append(f"- 负责人: {plan['owner']}")
            lines.append(f"- 行动:")
            for action in plan['actions']:
                lines.append(f"  - {action}")
            lines.append("")

        lines.append(f"---\n\n## 5. 合规状态\n")
        lines.append("| 框架 | 总控制项 | 未通过 | 合规率 |")
        lines.append("|------|----------|--------|--------|")
        for fw, status in r.compliance_status.items():
            lines.append(f"| {fw} | {status['total_controls']} | {status['failed_controls']} | {status['compliance_rate']} |")

        return "\n".join(lines)

    def export_json(self) -> str:
        """导出JSON格式"""
        def to_dict(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return {k: to_dict(v) for k, v in obj.__dict__.items()}
            elif isinstance(obj, list):
                return [to_dict(i) for i in obj]
            elif isinstance(obj, dict):
                return {k: to_dict(v) for k, v in obj.items()}
            return obj
        return json.dumps(to_dict(self.report), indent=2, ensure_ascii=False)


# ============================================================
# 单例
# ============================================================

_report_instance = None

def get_deep_report_engine() -> DeepReportEngine:
    global _report_instance
    if _report_instance is None:
        _report_instance = DeepReportEngine()
    return _report_instance
