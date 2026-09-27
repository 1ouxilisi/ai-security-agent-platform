#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
compliance_audit.py — 合规与审计度量。

覆盖：
    - 合规覆盖率、控制项通过率、审计发现、整改率、逾期项
    - 合规趋势、框架对比（GDPR / 等保2.0 / ISO27001 / SOC2）
    - 审计准备度、合规报告
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


COMPLIANCE_FRAMEWORKS: Dict[str, Dict[str, Any]] = {
    "gdpr": {"name": "GDPR（欧盟通用数据保护条例）", "controls": 99,
             "scope": "欧盟个人数据处理", "key_areas": ["合法性", "数据主体权利",
             "DPIA", "数据泄露通报", "跨境传输"]},
    "djcp": {"name": "网络安全等级保护2.0（中国）", "controls": 211,
             "scope": "中国境内网络运营者", "key_areas": ["安全物理环境",
             "安全通信网络", "安全区域边界", "安全计算环境", "安全管理中心"]},
    "iso27001": {"name": "ISO/IEC 27001:2022", "controls": 93,
                 "scope": "全球通用 ISMS 认证", "key_areas": ["组织控制", "人员控制",
                 "物理控制", "技术控制"]},
    "soc2": {"name": "SOC 2 Type II（AICPA）", "controls": 64,
             "scope": "SaaS/云服务商信任服务准则", "key_areas": ["安全", "可用性",
             "处理完整性", "保密性", "隐私"]},
}


class ComplianceAuditMetrics:
    """合规与审计度量器（全内存模拟）。"""

    def __init__(self) -> None:
        self._findings: List[Dict[str, Any]] = self._seed_findings()

    # ------------------------------------------------------------------ #
    # 框架对比 / 覆盖率
    # ------------------------------------------------------------------ #
    def framework_comparison(self) -> Dict[str, Any]:
        rows = []
        for key, fw in COMPLIANCE_FRAMEWORKS.items():
            # 模拟通过率
            pass_rate = round(88 + (hash(key) % 9) - 3, 1)
            rows.append({
                "code": key, "name": fw["name"], "scope": fw["scope"],
                "total_controls": fw["controls"],
                "passed_controls": int(fw["controls"] * pass_rate / 100),
                "fail_controls": int(fw["controls"] * (100 - pass_rate) / 100),
                "pass_rate": pass_rate,
                "key_areas": fw["key_areas"],
                "certification_status": "已认证" if pass_rate >= 92 else "在维持/整改中",
            })
        return {"frameworks": rows,
                "overall_avg_pass_rate": round(
                    sum(r["pass_rate"] for r in rows) / len(rows), 1)}

    def coverage(self) -> Dict[str, Any]:
        fw = self.framework_comparison()
        return {
            "regulation_mapping_coverage_pct": 96.0,
            "control_impl_rate_pct": 91.2,
            "evidence_retention_complete_pct": 88.5,
            "internal_audit_coverage_pct": 94.0,
            "framework_avg_pass_rate": fw["overall_avg_pass_rate"],
            "target": 95.0,
        }

    # ------------------------------------------------------------------ #
    # 审计发现 / 整改
    # ------------------------------------------------------------------ #
    def _seed_findings(self) -> List[Dict[str, Any]]:
        raw = [
            ("F-101", "高危", "gdpr", "未对跨境传输做标准合同备案", 45, 20, "open"),
            ("F-102", "中", "djcp", "三级系统日志保留不足6个月", 60, 60, "closed"),
            ("F-103", "高危", "iso27001", "访问复核年度记录缺失", 30, 30, "in_progress"),
            ("F-104", "低", "soc2", "变更审批单缺二级签字", 90, 90, "closed"),
            ("F-105", "中", "gdpr", "DPIA 模板未覆盖AI处理场景", 60, 40, "in_progress"),
            ("F-106", "高危", "djcp", "边界防火墙策略存在冗余规则", 45, 10, "open"),
            ("F-107", "低", "iso27001", "办公区门禁日志导出流程缺失", 90, 90, "closed"),
            ("F-108", "中", "soc2", "SLA 监控仪表盘未做变更审批", 60, 55, "overdue"),
        ]
        out = []
        for fid, sev, fw, desc, due, elapsed, status in raw:
            out.append({
                "finding_id": fid, "severity": sev, "framework": fw,
                "description": desc, "due_days": due, "elapsed_days": elapsed,
                "overdue": elapsed > due, "status": status,
            })
        return out

    def audit_findings(self, severity: Optional[str] = None) -> Dict[str, Any]:
        items = self._findings
        if severity:
            items = [f for f in items if f["severity"] == severity]
        sev_counts: Dict[str, int] = {}
        for f in self._findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        return {
            "total": len(self._findings), "returned": len(items),
            "severity_distribution": sev_counts,
            "items": items,
        }

    def remediation(self) -> Dict[str, Any]:
        total = len(self._findings)
        closed = sum(1 for f in self._findings if f["status"] == "closed")
        overdue = sum(1 for f in self._findings if f["status"] == "overdue"
                      or (f["status"] == "open" and f["overdue"]))
        on_time = sum(1 for f in self._findings
                      if f["status"] == "closed" and not f["overdue"])
        avg_days = round(sum(f["elapsed_days"] for f in self._findings) / total, 1)
        return {
            "total_findings": total,
            "closed": closed, "in_progress": sum(1 for f in self._findings if f["status"] == "in_progress"),
            "open": sum(1 for f in self._findings if f["status"] == "open"),
            "overdue": overdue,
            "remediation_rate_pct": round(closed / total * 100, 1),
            "on_time_rate_pct": round(on_time / total * 100, 1),
            "avg_cycle_days": avg_days,
            "target_remediation_rate": 90.0,
        }

    # ------------------------------------------------------------------ #
    # 趋势 / 准备度 / 报告
    # ------------------------------------------------------------------ #
    def compliance_trend(self, periods: int = 12) -> Dict[str, Any]:
        now = time.time()
        labels, rates = [], []
        for i in range(periods):
            t = now - (periods - i) * 30 * 86400
            labels.append(time.strftime("%Y-%m", time.localtime(t)))
            rates.append(round(82 + i * 0.7 + (i % 3) * 0.6, 1))
        return {"periods": labels, "pass_rates": rates,
                "latest": rates[-1], "target": 95.0}

    def audit_readiness(self) -> Dict[str, Any]:
        cov = self.coverage()
        rem = self.remediation()
        scores = {
            "control_evidence": min(100.0, cov["evidence_retention_complete_pct"]),
            "remediation_health": rem["remediation_rate_pct"],
            "policies_doc": cov["regulation_mapping_coverage_pct"],
            "training": 90.0,
        }
        overall = round(sum(scores.values()) / len(scores), 1)
        return {
            "scores": scores,
            "overall_readiness_pct": overall,
            "level": "充分" if overall >= 85 else ("基本就绪" if overall >= 70 else "不足"),
            "gap_items": ["补齐 GDPR 跨境传输备案", "完善日志保留策略",
                           "关闭 F-108 逾期项"],
        }

    def compliance_report_markdown(self) -> str:
        fw = self.framework_comparison()
        rem = self.remediation()
        rd = self.audit_readiness()
        lines = [
            "# 合规与审计度量报告",
            "", f"生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
            "", "## 框架对比",
        ]
        for r in fw["frameworks"]:
            lines.append(f"- {r['name']}：通过率 {r['pass_rate']}%（{r['passed_controls']}/{r['total_controls']}）")
        lines += [
            "", "## 整改情况",
            f"- 整改完成率：{rem['remediation_rate_pct']}%",
            f"- 按期率：{rem['on_time_rate_pct']}%",
            f"- 逾期项：{rem['overdue']} 项",
            "", "## 审计准备度",
            f"- 综合准备度：{rd['overall_readiness_pct']}%（{rd['level']}）",
            "", "## 待办",
        ]
        for g in rd["gap_items"]:
            lines.append(f"- {g}")
        return "\n".join(lines)
