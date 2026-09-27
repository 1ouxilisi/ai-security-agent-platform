# -*- coding: utf-8 -*-
"""
compliance - 合规审计深化模块

模块功能：
    - 合规框架库（等保2.0/ISO27001/PCI-DSS/SOC2/NIST/CIS/COBIT/GDPR/HIPAA）
    - 合规评估器（评估任务、自动评估、评分、差距分析）
    - 合规报告生成器（HTML/多框架对比）
    - 合规整改管理器（整改任务、验证、统计）
    - 合规映射引擎（漏洞自动映射到合规控制项）

与主项目的集成方式：
    - 使用 utils.database.db 全局 SQLite 实例（WAL 模式）
    - 每个子模块自行 CREATE TABLE IF NOT EXISTS 初始化数据表
    - 路由由 api_server/compliance_routes.py 提供（prefix=/api/v1/compliance）

注意事项：
    - 本模块仅用于授权的合规审计与安全评估
    - 请勿用于非法用途
"""

from __future__ import annotations

__version__ = "2.0.0"
__all__ = [
    "frameworks",
    "assessment",
    "report_generator",
    "remediation",
    "ComplianceMapper",
    "ComplianceControl",
    "ComplianceGap",
    "ComplianceReport",
]

# v2.0 新增：合规映射引擎
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class ComplianceFramework(Enum):
    """合规框架"""
    MLPS2 = "mlps2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"


@dataclass
class ComplianceControl:
    """合规控制项"""
    control_id: str = ""
    control_name: str = ""
    description: str = ""
    category: str = ""
    level: str = ""
    mapped_vuln_types: List[str] = field(default_factory=list)
    remediation_guidance: str = ""


@dataclass
class ComplianceGap:
    """合规差距"""
    framework: str = ""
    control_id: str = ""
    control_name: str = ""
    status: str = "fail"
    related_vulnerabilities: List[Dict] = field(default_factory=list)
    risk_level: str = "medium"
    remediation_priority: str = "medium"
    description: str = ""


@dataclass
class ComplianceReport:
    """合规报告"""
    framework: str = ""
    report_date: str = ""
    target: str = ""
    overall_score: float = 0.0
    overall_status: str = ""
    total_controls: int = 0
    passed_controls: int = 0
    failed_controls: int = 0
    partial_controls: int = 0
    gaps: List[ComplianceGap] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)


class ComplianceMapper:
    """合规映射引擎 - 将漏洞自动映射到合规控制项"""

    def __init__(self):
        self.controls = self._init_controls()

    def _init_controls(self) -> Dict[str, List[ComplianceControl]]:
        controls = {
            "mlps2": self._init_mlps2(),
            "iso27001": self._init_iso27001(),
            "pci_dss": self._init_pci_dss(),
        }
        return controls

    def _init_mlps2(self) -> List[ComplianceControl]:
        """等保2.0控制项"""
        return [
            ComplianceControl("8.1.1", "网络架构", "应保证网络设备的业务处理能力满足业务高峰期需要", "安全通信网络", "三级", ["misconfiguration", "exposed_panel"], "评估网络设备性能"),
            ComplianceControl("8.1.2", "通信传输", "应采用校验技术或密码技术保证通信过程中数据的完整性", "安全通信网络", "三级", ["ssl_tls", "information_disclosure"], "启用TLS加密"),
            ComplianceControl("8.1.3", "边界防护", "应保证跨越边界的访问和数据流通过边界设备提供的受控接口进行通信", "安全区域边界", "三级", ["misconfiguration", "exposed_panel"], "配置防火墙规则"),
            ComplianceControl("8.1.4", "访问控制", "应在网络边界或区域之间根据访问控制策略设置访问控制规则", "安全区域边界", "三级", ["authentication_bypass", "privilege_escalation"], "实施最小权限原则"),
            ComplianceControl("8.1.5", "入侵防范", "应在关键网络节点处检测、防止或限制从外部发起的网络攻击行为", "安全区域边界", "三级", ["sql_injection", "xss", "rce", "command_injection"], "部署IDS/IPS/WAF"),
            ComplianceControl("8.1.6", "身份鉴别", "应对登录的用户进行身份标识和鉴别，身份标识具有唯一性", "安全计算环境", "三级", ["weak_password", "default_credentials", "authentication_bypass"], "强密码策略+MFA"),
            ComplianceControl("8.1.7", "访问控制", "应对登录的用户分配账户和权限，实现管理用户的权限分离", "安全计算环境", "三级", ["privilege_escalation", "authentication_bypass"], "RBAC权限控制"),
            ComplianceControl("8.1.8", "安全审计", "应启用安全审计功能，审计覆盖到每个用户", "安全计算环境", "三级", ["information_disclosure"], "全面安全审计日志"),
            ComplianceControl("8.1.9", "入侵防范", "应遵循最小安装的原则，仅安装需要的组件和应用程序", "安全计算环境", "三级", ["outdated_component", "misconfiguration"], "最小化安装+补丁管理"),
            ComplianceControl("8.1.10", "数据完整性", "应采用校验技术或密码技术保证重要数据在传输过程中的完整性", "安全计算环境", "三级", ["ssl_tls", "information_disclosure"], "加密传输+数据校验"),
            ComplianceControl("8.1.11", "数据保密性", "应采用密码技术保证重要数据在传输过程中的保密性", "安全计算环境", "三级", ["hardcoded_credentials", "information_disclosure"], "敏感数据加密存储"),
            ComplianceControl("8.1.12", "系统管理", "应对系统管理员进行身份鉴别，只允许其通过特定的命令或操作界面进行系统管理操作", "安全管理中心", "三级", ["exposed_panel", "default_credentials"], "限制管理接口访问"),
        ]

    def _init_iso27001(self) -> List[ComplianceControl]:
        """ISO 27001:2022控制项"""
        return [
            ComplianceControl("A.5.15", "访问控制", "应限制信息和其他相关对象的访问", "组织控制", "A.5", ["authentication_bypass", "privilege_escalation"], "访问控制策略"),
            ComplianceControl("A.8.2", "特权访问权限", "应限制和控制特权访问权限的分配和使用", "技术控制", "A.8", ["privilege_escalation", "default_credentials"], "最小权限+定期审查"),
            ComplianceControl("A.8.3", "信息访问限制", "应限制信息、其他相关对象的访问权限", "技术控制", "A.8", ["authentication_bypass", "lfi", "path_traversal"], "RBAC访问控制"),
            ComplianceControl("A.8.5", "安全认证", "应在系统中使用安全认证技术", "技术控制", "A.8", ["weak_password", "authentication_bypass"], "强认证+MFA"),
            ComplianceControl("A.8.8", "系统漏洞管理", "应及时检测系统中的漏洞并采取适当措施", "技术控制", "A.8", ["outdated_component", "sql_injection", "xss", "rce"], "漏洞管理流程"),
            ComplianceControl("A.8.9", "配置管理", "应建立和实施配置管理流程", "技术控制", "A.8", ["misconfiguration", "exposed_panel"], "安全配置基线"),
            ComplianceControl("A.8.12", "数据泄露防护", "应实施数据泄露防护措施", "技术控制", "A.8", ["information_disclosure", "lfi", "ssrf"], "DLP解决方案"),
            ComplianceControl("A.8.16", "网络安全", "应管理网络和网络设备的安全", "技术控制", "A.8", ["exposed_panel", "misconfiguration", "ssl_tls"], "网络分段+防火墙"),
            ComplianceControl("A.8.17", "Web服务安全", "应保护Web服务的安全", "技术控制", "A.8", ["sql_injection", "xss", "csrf", "file_upload"], "WAF+安全编码"),
            ComplianceControl("A.8.19", "安全组件安装", "应安全地安装和配置安全组件", "技术控制", "A.8", ["default_credentials", "misconfiguration"], "修改默认配置"),
            ComplianceControl("A.8.23", "应用安全", "应保护应用的信息安全", "技术控制", "A.8", ["sql_injection", "xss", "rce", "deserialization", "xxe"], "安全SDLC+渗透测试"),
            ComplianceControl("A.8.24", "安全开发", "应在系统开发生命周期中实施安全", "技术控制", "A.8", ["outdated_component", "hardcoded_credentials"], "DevSecOps"),
            ComplianceControl("A.8.28", "安全架构", "应建立和维护信息安全架构", "技术控制", "A.8", ["misconfiguration"], "纵深防御架构"),
        ]

    def _init_pci_dss(self) -> List[ComplianceControl]:
        """PCI-DSS v4.0控制项"""
        return [
            ComplianceControl("Req 1", "网络安全控制", "安装并维护防火墙配置和路由器等网络安全控制", "网络安全", "Req 1", ["exposed_panel", "misconfiguration"], "防火墙配置"),
            ComplianceControl("Req 2", "安全配置", "将系统配置、密码和其他安全参数设置为安全的默认值", "安全配置", "Req 2", ["default_credentials", "misconfiguration", "hardcoded_credentials"], "安全基线"),
            ComplianceControl("Req 3", "保护存储数据", "保护存储的持卡人数据", "数据保护", "Req 3", ["information_disclosure", "hardcoded_credentials"], "加密存储"),
            ComplianceControl("Req 4", "加密传输", "使用强加密技术在开放公共网络上传输持卡人数据", "数据保护", "Req 4", ["ssl_tls", "information_disclosure"], "TLS 1.2+"),
            ComplianceControl("Req 5", "恶意软件防护", "使用和定期更新防病毒软件", "恶意软件防护", "Req 5", ["rce", "command_injection"], "EDR/AV部署"),
            ComplianceControl("Req 6", "安全开发", "开发和维护安全的系统和软件", "安全开发", "Req 6", ["sql_injection", "xss", "rce", "outdated_component", "deserialization"], "安全SDLC"),
            ComplianceControl("Req 7", "访问控制", "根据业务需要和最小权限原则限制访问", "访问控制", "Req 7", ["privilege_escalation", "authentication_bypass"], "最小权限"),
            ComplianceControl("Req 8", "身份认证", "识别和认证系统组件和用户的访问", "身份认证", "Req 8", ["weak_password", "default_credentials", "authentication_bypass"], "强密码+MFA"),
            ComplianceControl("Req 10", "日志监控", "记录和监控对系统资源和持卡人数据的所有访问", "日志监控", "Req 10", ["information_disclosure"], "集中日志+监控"),
            ComplianceControl("Req 11", "安全测试", "定期测试系统和进程的安全性", "安全测试", "Req 11", ["sql_injection", "xss", "rce", "ssrf", "outdated_component"], "定期渗透测试"),
        ]

    def map_vulnerabilities(self, vulnerabilities: List[Dict],
                            framework: str = "all") -> Dict[str, List[ComplianceGap]]:
        """将漏洞映射到合规控制项"""
        frameworks = ["mlps2", "iso27001", "pci_dss"] if framework == "all" else [framework]
        all_gaps = {}

        for fw in frameworks:
            controls = self.controls.get(fw, [])
            gaps = []
            for control in controls:
                related = [v for v in vulnerabilities
                          if v.get("type", v.get("vulnerability_type", "")).lower()
                          in [t.lower() for t in control.mapped_vuln_types]]
                if related:
                    gaps.append(ComplianceGap(
                        framework=fw, control_id=control.control_id,
                        control_name=control.control_name, status="fail",
                        related_vulnerabilities=related,
                        risk_level=max([v.get("severity", "medium") for v in related]),
                        remediation_priority=self._calc_priority(related),
                        description=f"发现 {len(related)} 个相关漏洞",
                    ))
                elif control.mapped_vuln_types:
                    gaps.append(ComplianceGap(
                        framework=fw, control_id=control.control_id,
                        control_name=control.control_name, status="pass",
                        description="未发现相关漏洞",
                    ))
            all_gaps[fw] = gaps
        return all_gaps

    def _calc_priority(self, vulns: List[Dict]) -> str:
        scores = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_s = max([scores.get(v.get("severity", "info"), 0) for v in vulns])
        return "critical" if max_s >= 4 else "high" if max_s >= 3 else "medium" if max_s >= 2 else "low"

    def generate_report(self, vulnerabilities: List[Dict],
                        target: str = "", framework: str = "all") -> Dict[str, ComplianceReport]:
        """生成合规报告"""
        gaps_by_fw = self.map_vulnerabilities(vulnerabilities, framework)
        reports = {}
        for fw, gaps in gaps_by_fw.items():
            total = len(gaps)
            failed = len([g for g in gaps if g.status == "fail"])
            passed = len([g for g in gaps if g.status == "pass"])
            score = round((passed / total * 100), 1) if total > 0 else 100
            status = "优秀" if score >= 90 else "良好" if score >= 70 else "一般" if score >= 50 else "较差"
            reports[fw] = ComplianceReport(
                framework=fw, report_date=datetime.now().isoformat(),
                target=target, overall_score=score, overall_status=status,
                total_controls=total, passed_controls=passed, failed_controls=failed,
                gaps=[g for g in gaps if g.status == "fail"],
                summary={
                    "total_vulnerabilities": len(vulnerabilities),
                    "critical": len([v for v in vulnerabilities if v.get("severity") == "critical"]),
                    "high": len([v for v in vulnerabilities if v.get("severity") == "high"]),
                    "medium": len([v for v in vulnerabilities if v.get("severity") == "medium"]),
                },
            )
        return reports

    def get_framework_name(self, framework: str) -> str:
        names = {
            "mlps2": "网络安全等级保护2.0（GB/T 22239-2019）",
            "iso27001": "ISO/IEC 27001:2022 信息安全管理体系",
            "pci_dss": "PCI-DSS v4.0 支付卡行业数据安全标准",
        }
        return names.get(framework, framework)

    def get_stats(self) -> Dict:
        return {
            "frameworks": {fw: {"name": self.get_framework_name(fw), "controls": len(c)}
                          for fw, c in self.controls.items()},
            "total_controls": sum(len(c) for c in self.controls.values()),
        }
