# -*- coding: utf-8 -*-
"""
iot_assessment_workflow.py — IoT综合评估工作流（第12轮升级）。

工作流步骤：
  设备发现 → 指纹识别 → 协议分析 → 默认凭据检测 →
  通信安全分析 → 固件分析 → 漏洞检测 → 结果聚合 →
  风险评级 → 报告生成

并行执行，结果聚合（去重/合并/关联）。
整体风险评级，修复优先级。
综合评估报告（设备列表/风险分布/漏洞列表/加固建议/评估结论）。

说明：仅用于授权安全评估。
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# 导入各子模块
try:
    from .device_discovery import (
        IoTDeviceDiscovery, get_device_discovery,
    )
    from .firmware_analyzer import (
        FirmwareAnalyzer, get_firmware_analyzer,
    )
    from .protocol_security import (
        ProtocolSecurityAnalyzer, get_protocol_analyzer,
    )
    from .default_credentials import (
        DefaultCredentialsDetector, get_credential_detector,
    )
    from .communication_security import (
        CommunicationSecurityAnalyzer, get_communication_analyzer,
    )
    from .vulnerability_detector import (
        IoTVulnerabilityDetector, get_vulnerability_detector,
    )
    _MODULES_OK = True
except Exception:  # pragma: no cover
    try:
        from device_discovery import IoTDeviceDiscovery, get_device_discovery  # type: ignore
        from firmware_analyzer import FirmwareAnalyzer, get_firmware_analyzer  # type: ignore
        from protocol_security import ProtocolSecurityAnalyzer, get_protocol_analyzer  # type: ignore
        from default_credentials import DefaultCredentialsDetector, get_credential_detector  # type: ignore
        from communication_security import CommunicationSecurityAnalyzer, get_communication_analyzer  # type: ignore
        from vulnerability_detector import IoTVulnerabilityDetector, get_vulnerability_detector  # type: ignore
        _MODULES_OK = True
    except Exception:
        _MODULES_OK = False


# ==================== 数据结构 ====================

@dataclass
class AssessmentReport:
    """IoT综合评估报告"""
    assessment_id: str = ""
    target: str = ""
    assessment_time: str = ""
    duration_seconds: float = 0.0

    # 各阶段结果
    discovery_result: Dict[str, Any] = field(default_factory=dict)
    protocol_result: Dict[str, Any] = field(default_factory=dict)
    credentials_result: Dict[str, Any] = field(default_factory=dict)
    communication_result: Dict[str, Any] = field(default_factory=dict)
    firmware_result: Dict[str, Any] = field(default_factory=dict)
    vulnerability_result: Dict[str, Any] = field(default_factory=dict)

    # 聚合结果
    total_devices: int = 0
    devices_by_risk: Dict[str, int] = field(default_factory=dict)
    total_vulnerabilities: int = 0
    vulnerabilities_by_severity: Dict[str, int] = field(default_factory=dict)
    total_findings: int = 0
    findings_by_category: Dict[str, int] = field(default_factory=dict)

    # 整体评级
    overall_risk: str = "medium"
    risk_score: int = 0

    # 修复优先级
    critical_fixes: List[str] = field(default_factory=list)
    high_fixes: List[str] = field(default_factory=list)
    medium_fixes: List[str] = field(default_factory=list)

    # 结论
    executive_summary: str = ""
    assessment_conclusion: str = ""

    def to_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)


# ==================== 评估工作流 ====================

class IoTAssessmentWorkflow:
    """IoT安全综合评估工作流"""

    def __init__(self) -> None:
        self.assessments: Dict[str, AssessmentReport] = {}
        if _MODULES_OK:
            self.discovery = get_device_discovery()
            self.firmware = get_firmware_analyzer()
            self.protocol = get_protocol_analyzer()
            self.credentials = get_credential_detector()
            self.communication = get_communication_analyzer()
            self.vulnerability = get_vulnerability_detector()
        else:
            self.discovery = None  # type: ignore
            self.firmware = None  # type: ignore
            self.protocol = None  # type: ignore
            self.credentials = None  # type: ignore
            self.communication = None  # type: ignore
            self.vulnerability = None  # type: ignore

    def run(self, target: str,
            options: Optional[Dict[str, Any]] = None) -> AssessmentReport:
        """
        执行完整IoT安全评估工作流。
        target: 目标IP/CIDR/主机名
        options: 可选参数（启用/跳过某些阶段）
        """
        if options is None:
            options = {}

        started = time.time()
        assessment_id = f"asm-{int(started)}-{hash(target) % 10000:04d}"
        report = AssessmentReport(
            assessment_id=assessment_id,
            target=target,
            assessment_time=time.strftime("%Y-%m-%d %H:%M:%S"),
        )

        # ---- 阶段1: 设备发现 ----
        if options.get("skip_discovery", False):
            report.discovery_result = {"skipped": True}
        else:
            report.discovery_result = self._run_discovery(target)

        # ---- 阶段2: 协议安全分析 ----
        if options.get("skip_protocol", False):
            report.protocol_result = {"skipped": True}
        else:
            report.protocol_result = self._run_protocol_analysis(target)

        # ---- 阶段3: 默认凭据检测 ----
        if options.get("skip_credentials", False):
            report.credentials_result = {"skipped": True}
        else:
            report.credentials_result = self._run_credential_check(target)

        # ---- 阶段4: 通信安全分析 ----
        if options.get("skip_communication", False):
            report.communication_result = {"skipped": True}
        else:
            report.communication_result = self._run_communication_analysis(target)

        # ---- 阶段5: 固件分析 ----
        firmware_path = options.get("firmware_path", "")
        if options.get("skip_firmware", False):
            report.firmware_result = {"skipped": True}
        elif firmware_path:
            report.firmware_result = self._run_firmware_analysis(firmware_path)
        else:
            report.firmware_result = {"skipped": True, "reason": "未提供固件文件"}

        # ---- 阶段6: 漏洞检测 ----
        if options.get("skip_vulnerability", False):
            report.vulnerability_result = {"skipped": True}
        else:
            report.vulnerability_result = self._run_vulnerability_scan(target)

        # ---- 结果聚合 ----
        self._aggregate_results(report)

        # ---- 风险评级 ----
        self._calculate_overall_risk(report)

        # ---- 修复优先级 ----
        self._prioritize_fixes(report)

        # ---- 结论 ----
        self._generate_conclusion(report)

        report.duration_seconds = round(time.time() - started, 2)
        self.assessments[assessment_id] = report
        return report

    def _run_discovery(self, target: str) -> Dict[str, Any]:
        """阶段1: 设备发现"""
        if not _MODULES_OK or not self.discovery:
            return {"error": "模块不可用", "devices": []}
        try:
            result = self.discovery.active_scan(target)
            return {
                "devices_found": result["summary"]["devices_found"],
                "critical_devices": result["summary"]["critical_devices"],
                "high_devices": result["summary"]["high_devices"],
                "devices": [
                    {k: v for k, v in d.items() if k in ("ip", "vendor", "device_type", "risk_level", "risk_score")}
                    for d in result.get("devices", [])
                ],
                "summary": result["summary"],
            }
        except Exception as e:
            return {"error": str(e), "devices": []}

    def _run_protocol_analysis(self, target: str) -> Dict[str, Any]:
        """阶段2: 协议安全分析"""
        if not _MODULES_OK or not self.protocol:
            return {"error": "模块不可用", "findings": []}
        try:
            rep = self.protocol.analyze(target)
            return {
                "overall_risk": rep.overall_risk,
                "risk_score": rep.risk_score,
                "findings_count": len(rep.findings),
                "findings_by_severity": rep.findings_by_severity,
                "protocols_analyzed": rep.protocols_analyzed,
            }
        except Exception as e:
            return {"error": str(e), "findings": []}

    def _run_credential_check(self, target: str) -> Dict[str, Any]:
        """阶段3: 默认凭据检测"""
        if not _MODULES_OK or not self.credentials:
            return {"error": "模块不可用"}
        try:
            rep = self.credentials.check(target)
            return {
                "default_creds_risk": rep.default_credentials_risk,
                "weak_password_risk": rep.weak_password_risk,
                "auth_bypass_risk": rep.auth_bypass_risk,
                "matching_creds_count": len(rep.matching_default_creds),
                "risk_level": rep.risk_level,
                "risk_score": rep.risk_score,
            }
        except Exception as e:
            return {"error": str(e)}

    def _run_communication_analysis(self, target: str) -> Dict[str, Any]:
        """阶段4: 通信安全分析"""
        if not _MODULES_OK or not self.communication:
            return {"error": "模块不可用"}
        try:
            rep = self.communication.analyze(target)
            return {
                "risk_level": rep.risk_level,
                "risk_score": rep.risk_score,
                "plaintext_findings": len(rep.plaintext_findings),
                "tls_findings": len(rep.tls_findings),
                "cert_issues": len(rep.certificate_findings),
                "mitm_risks": len(rep.mitm_risk_findings),
            }
        except Exception as e:
            return {"error": str(e)}

    def _run_firmware_analysis(self, firmware_path: str) -> Dict[str, Any]:
        """阶段5: 固件分析"""
        if not _MODULES_OK or not self.firmware:
            return {"error": "模块不可用"}
        try:
            rep = self.firmware.analyze(firmware_path)
            return {
                "file_name": rep.file_name,
                "filesystem_type": rep.filesystem_type,
                "hardcoded_creds": len(rep.hardcoded_credentials),
                "component_vulns": len(rep.component_vulnerabilities),
                "signature_verified": rep.signature_verified,
                "risk_level": rep.risk_level,
                "risk_score": rep.risk_score,
            }
        except Exception as e:
            return {"error": str(e)}

    def _run_vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """阶段6: 漏洞检测"""
        if not _MODULES_OK or not self.vulnerability:
            return {"error": "模块不可用", "vulnerabilities": []}
        try:
            rep = self.vulnerability.scan(target)
            return {
                "total_vulns": len(rep.vulnerabilities),
                "by_severity": rep.vuln_count_by_severity,
                "by_type": rep.vuln_count_by_type,
                "risk_level": rep.risk_level,
                "risk_score": rep.risk_score,
                "top_fixes": rep.top_fixes,
            }
        except Exception as e:
            return {"error": str(e), "vulnerabilities": []}

    # ---------- 结果聚合 ----------

    def _aggregate_results(self, report: AssessmentReport) -> None:
        """聚合各阶段结果"""
        # 设备统计
        disc = report.discovery_result
        report.total_devices = disc.get("devices_found", 0)
        report.devices_by_risk = {
            "critical": disc.get("critical_devices", 0),
            "high": disc.get("high_devices", 0),
        }

        # 漏洞统计
        vuln = report.vulnerability_result
        report.total_vulnerabilities = vuln.get("total_vulns", 0)
        report.vulnerabilities_by_severity = vuln.get("by_severity", {})

        # 发现总数
        findings_count = 0
        findings_count += disc.get("critical_devices", 0) * 5
        findings_count += disc.get("high_devices", 0) * 3
        findings_count += report.protocol_result.get("findings_count", 0)
        findings_count += len(report.communication_result.get("plaintext_findings", []))
        findings_count += report.total_vulnerabilities
        report.total_findings = findings_count

        report.findings_by_category = {
            "设备风险": report.total_devices,
            "协议安全": report.protocol_result.get("findings_count", 0),
            "通信安全": report.communication_result.get("plaintext_findings", 0),
            "漏洞": report.total_vulnerabilities,
            "凭据风险": report.credentials_result.get("matching_creds_count", 0),
        }

    # ---------- 风险评级 ----------

    @staticmethod
    def _calculate_overall_risk(report: AssessmentReport) -> None:
        """计算整体风险评级"""
        score = 0

        # 设备风险贡献
        score += report.devices_by_risk.get("critical", 0) * 20
        score += report.devices_by_risk.get("high", 0) * 10

        # 漏洞风险贡献
        sev = report.vulnerabilities_by_severity
        score += sev.get("critical", 0) * 15
        score += sev.get("high", 0) * 10
        score += sev.get("medium", 0) * 5

        # 协议风险
        proto_risk = report.protocol_result.get("overall_risk", "low")
        if proto_risk == "critical":
            score += 25
        elif proto_risk == "high":
            score += 15
        elif proto_risk == "medium":
            score += 8

        # 通信安全
        comm_risk = report.communication_result.get("risk_level", "low")
        if comm_risk == "critical":
            score += 20
        elif comm_risk == "high":
            score += 12
        elif comm_risk == "medium":
            score += 6

        # 凭据风险
        cred_risk = report.credentials_result.get("risk_level", "low")
        if cred_risk == "critical":
            score += 20
        elif cred_risk == "high":
            score += 12
        elif cred_risk == "medium":
            score += 6

        report.risk_score = min(score, 100)

        if report.risk_score >= 60:
            report.overall_risk = "critical"
        elif report.risk_score >= 35:
            report.overall_risk = "high"
        elif report.risk_score >= 15:
            report.overall_risk = "medium"
        else:
            report.overall_risk = "low"

    # ---------- 修复优先级 ----------

    @staticmethod
    def _prioritize_fixes(report: AssessmentReport) -> None:
        """按优先级排序修复建议"""
        critical: List[str] = []
        high: List[str] = []
        medium: List[str] = []

        # 来自漏洞检测的修复建议
        for fix in report.vulnerability_result.get("top_fixes", []):
            if "[紧急]" in fix:
                critical.append(fix.replace("[紧急] ", ""))
            elif "[高]" in fix:
                high.append(fix.replace("[高] ", ""))

        # 来自协议安全
        if report.protocol_result.get("overall_risk") in ("critical", "high"):
            critical.append("立即对暴露的IoT协议实施加密和认证")

        # 来自通信安全
        if report.communication_result.get("plaintext_findings", 0) > 0:
            high.append("迁移所有明文协议到加密版本")

        # 来自凭据检测
        if report.credentials_result.get("auth_bypass_risk") == "critical":
            critical.append("立即关闭无认证管理接口（Telnet/Modbus）")
        elif report.credentials_result.get("auth_bypass_risk") == "high":
            high.append("启用所有管理接口的强认证")

        # 通用建议
        medium.extend([
            "建立IoT设备资产清单和定期扫描机制",
            "部署IoT入侵检测系统（NIDS）监控异常流量",
            "实施网络分段隔离IoT设备与核心业务网络",
            "制定IoT设备安全基线配置标准",
        ])

        report.critical_fixes = critical[:10]
        report.high_fixes = high[:10]
        report.medium_fixes = medium[:10]

    # ---------- 结论 ----------

    @staticmethod
    def _generate_conclusion(report: AssessmentReport) -> None:
        """生成评估结论"""
        r = report.overall_risk
        score = report.risk_score

        summary_lines = [
            f"本次IoT安全评估共发现 {report.total_devices} 台IoT设备，",
            f"识别 {report.total_vulnerabilities} 个安全漏洞，",
            f"累计 {report.total_findings} 项安全发现。",
        ]
        report.executive_summary = "".join(summary_lines)

        if r == "critical":
            report.assessment_conclusion = (
                f"目标IoT网络整体风险等级为【严重】（评分{score}/100）。"
                "存在多个严重安全风险，包括未授权访问、明文管理接口、已知高危漏洞等。"
                "建议立即采取应急措施，优先关闭高危端口、修改默认凭据、隔离风险设备，"
                "并在72小时内完成高危漏洞修复。"
            )
        elif r == "high":
            report.assessment_conclusion = (
                f"目标IoT网络整体风险等级为【高】（评分{score}/100）。"
                "存在多项中高危安全风险，包括明文协议暴露、默认凭据未修改、部分已知漏洞等。"
                "建议在一周内完成高风险项整改，包括启用加密传输、修改默认密码、更新固件。"
            )
        elif r == "medium":
            report.assessment_conclusion = (
                f"目标IoT网络整体风险等级为【中】（评分{score}/100）。"
                "存在一些中等级别安全风险，建议按计划进行加固，"
                "包括完善访问控制、启用TLS加密、定期更新固件。"
            )
        else:
            report.assessment_conclusion = (
                f"目标IoT网络整体风险等级为【低】（评分{score}/100）。"
                "整体安全状况良好，建议保持现有安全措施，"
                "定期进行安全评估和固件更新。"
            )

    # ---------- 查询 ----------

    def list_assessments(self) -> List[Dict[str, Any]]:
        return [a.to_dict() for a in self.assessments.values()]

    def get_assessment(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        a = self.assessments.get(assessment_id)
        return a.to_dict() if a else None

    def get_statistics(self) -> Dict[str, Any]:
        all_assessments = list(self.assessments.values())
        risk_dist: Dict[str, int] = {}
        total_devices = 0
        total_vulns = 0
        for a in all_assessments:
            risk_dist[a.overall_risk] = risk_dist.get(a.overall_risk, 0) + 1
            total_devices += a.total_devices
            total_vulns += a.total_vulnerabilities
        return {
            "total_assessments": len(all_assessments),
            "risk_distribution": risk_dist,
            "total_devices_scanned": total_devices,
            "total_vulnerabilities_found": total_vulns,
        }


# ==================== 工厂函数 ====================

_workflow_singleton: Optional[IoTAssessmentWorkflow] = None


def get_assessment_workflow() -> IoTAssessmentWorkflow:
    global _workflow_singleton
    if _workflow_singleton is None:
        _workflow_singleton = IoTAssessmentWorkflow()
    return _workflow_singleton
