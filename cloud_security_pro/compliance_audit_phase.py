# -*- coding: utf-8 -*-
"""
compliance_audit_phase.py — 云安全 Pro 阶段5：合规审计。

框架:
    - 等保 2.0（云计算扩展要求）
    - ISO 27001 云相关控制项
    - CIS Benchmark（AWS / 通用）
    - 合规报告 + 不符合项整改建议
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# 合规控制项映射：每条规则 -> 对应合规条款
COMPLIANCE_MAP: Dict[str, Dict[str, List[str]]] = {
    "SG-001": {"等保2.0": ["安全通信网络-边界防护"],
               "ISO27001": ["A.13.1.1 网络控制"],
               "CIS": ["4.1 确保无安全组对 0.0.0.0/0 开放 22"]},
    "SG-002": {"等保2.0": ["安全通信网络-边界防护"],
               "ISO27001": ["A.13.1.1"],
               "CIS": ["4.2 确保无安全组对 0.0.0.0/0 开放 3389"]},
    "SG-003": {"等保2.0": ["安全区域边界-访问控制"],
               "ISO27001": ["A.9.1.2 远程访问"],
               "CIS": ["4.3 限制数据库端口公网暴露"]},
    "SG-004": {"等保2.0": ["安全区域边界-访问控制"],
               "ISO27001": ["A.13.1.1"],
               "CIS": ["4.x 中间件端口最小化"]},
    "STO-001": {"等保2.0": ["安全计算环境-数据保密性"],
                "ISO27001": ["A.8.3 介质保护"],
                "CIS": ["2.1.1 确保 S3 桶不公开"]},
    "STO-002": {"等保2.0": ["安全计算环境-数据完整性"],
                "ISO27001": ["A.8.3.1"],
                "CIS": ["2.1.1 禁止桶公开写"]},
    "STO-003": {"等保2.0": ["安全计算环境-数据保密性"],
                "ISO27001": ["A.10.1.1 加密控制"],
                "CIS": ["2.1.2 确保 S3 加密"]},
    "STO-004": {"等保2.0": ["安全计算环境-数据备份恢复"],
                "ISO27001": ["A.12.3.1 信息备份"],
                "CIS": ["2.1.3 开启桶版本控制"]},
    "STO-005": {"等保2.0": ["安全计算环境-访问控制"],
                "ISO27001": ["A.9.2 访问权限管理"],
                "CIS": ["2.1.1 拒绝 Principal=*"]},
    "IAM-001": {"等保2.0": ["安全计算环境-身份鉴别"],
                "ISO27001": ["A.9.2.3 秘密信息管理"],
                "CIS": ["1.5 确保 MFA 启用"]},
    "IAM-002": {"等保2.0": ["安全计算环境-身份鉴别"],
                "ISO27001": ["A.9.3 凭证使用"],
                "CIS": ["1.12 移除未使用密钥/轮换"]},
    "IAM-003": {"等保2.0": ["安全管理中心-系统管理"],
                "ISO27001": ["A.9.2.1 特权权限分配"],
                "CIS": ["1.4 根账号无 AccessKey"]},
    "IAM-004": {"等保2.0": ["安全计算环境-访问控制"],
                "ISO27001": ["A.9.2.1"],
                "CIS": ["1.1 移除过度权限"]},
    "KEY-001": {"等保2.0": ["安全计算环境-数据保密性"],
                "ISO27001": ["A.10.1.1"],
                "CIS": ["1.14 确保 CMK 轮换"]},
    "NET-001": {"等保2.0": ["安全通信网络-审计"],
                "ISO27001": ["A.12.4 日志与监控"],
                "CIS": ["3.1 开启 VPC Flow Logs"]},
    "DB-001": {"等保2.0": ["安全计算环境-数据保密性/备份恢复"],
               "ISO27001": ["A.8.2.3 记录信息保护"],
               "CIS": ["5.x RDS 加密/公网/备份"]},
    "LOG-001": {"等保2.0": ["安全审计-审计记录"],
                "ISO27001": ["A.12.4.1 事件日志"],
                "CIS": ["1.2 确保 CloudTrail 启用"]},
}


@dataclass
class ComplianceItem:
    framework: str = ""
    control_id: str = ""
    control_title: str = ""
    status: str = "not_assessed"      # pass / fail / not_assessed
    mapped_rule: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework": self.framework, "control_id": self.control_id,
            "control_title": self.control_title, "status": self.status,
            "mapped_rule": self.mapped_rule, "remediation": self.remediation,
        }


@dataclass
class ComplianceResult:
    frameworks: Dict[str, Any] = field(default_factory=dict)
    items: List[Dict[str, Any]] = field(default_factory=dict)
    pass_rate: float = 0.0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "frameworks": self.frameworks,
            "item_count": len(self.items),
            "pass_rate": self.pass_rate,
            "items": self.items,
            "notes": self.notes,
        }


class ComplianceAuditPhase:
    """合规审计：将配置检查发现映射到等保/ISO/CIS 条款。"""

    FRAMEWORKS = ["等保2.0", "ISO27001", "CIS"]

    def audit(self, config_findings: List[Dict[str, Any]]) -> ComplianceResult:
        res = ComplianceResult()
        failed_rules = {f.get("rule_id") for f in config_findings}

        # 构建条款条目
        items: List[ComplianceItem] = []
        covered: Dict[str, set] = {fw: set() for fw in self.FRAMEWORKS}

        for rule_id, mp in COMPLIANCE_MAP.items():
            status = "fail" if rule_id in failed_rules else "pass"
            for fw, controls in mp.items():
                for ctl in controls:
                    cid, _, title = ctl.partition(" ")
                    items.append(ComplianceItem(
                        framework=fw, control_id=cid,
                        control_title=ctl, status=status,
                        mapped_rule=rule_id,
                        remediation="; ".join(
                            f.get("remediation", "") for f in config_findings
                            if f.get("rule_id") == rule_id) or ""))
                    covered[fw].add(status)

        res.items = [i.to_dict() for i in items]

        # 各框架通过率
        total = len(items) or 1
        passed = sum(1 for i in items if i.status == "pass")
        res.pass_rate = round(passed * 100.0 / total, 1)

        for fw in self.FRAMEWORKS:
            fw_items = [i for i in items if i.framework == fw]
            fw_pass = sum(1 for i in fw_items if i.status == "pass")
            fw_total = len(fw_items) or 1
            res.frameworks[fw] = {
                "total": len(fw_items),
                "pass": fw_pass,
                "fail": len(fw_items) - fw_pass,
                "pass_rate": round(fw_pass * 100.0 / fw_total, 1),
                "status": ("compliant" if fw_pass == len(fw_items)
                           else ("partial" if fw_pass > 0 else "non_compliant")),
            }

        if not config_findings:
            res.notes.append("无配置失败项，合规映射基于空结果（未做真实资产审计时不构成合规结论）。")
        return res


_default_comp: Optional[ComplianceAuditPhase] = None


def get_compliance_audit_phase() -> ComplianceAuditPhase:
    global _default_comp
    if _default_comp is None:
        _default_comp = ComplianceAuditPhase()
    return _default_comp
