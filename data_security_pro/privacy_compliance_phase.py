# -*- coding: utf-8 -*-
"""
privacy_compliance_phase.py — 阶段5：隐私合规。

GDPR 检查项 + 个人信息保护法（PIPL）检查项，
合规评分、不符合项整改建议、合规报告生成。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
@dataclass
class ComplianceItem:
    item_id: str
    framework: str           # GDPR / PIPL
    domain: str              # 同意/主体权利/跨境/留存/隐私政策...
    title: str
    description: str
    status: str = "not_assessed"   # pass/fail/partial/not_assessed
    score: int = 0
    suggestion: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id, "framework": self.framework,
            "domain": self.domain, "title": self.title,
            "description": self.description,
            "status": self.status, "score": self.score,
            "suggestion": self.suggestion,
        }


def _seed_items() -> List[ComplianceItem]:
    items: List[ComplianceItem] = []
    # ---------------- GDPR ----------------
    gdpr = [
        ("同意管理-用户同意记录", "consent",
         "是否留存每一次用户同意的时间、版本、范围记录？",
         "建立 Consent Log，记录同意版本/时间戳/IP/UA，支持撤回"),
        ("同意管理-同意撤回", "consent",
         "是否提供一键撤回同意的入口？",
         "在隐私设置中提供 withdraw consent 按钮并联动下游删除"),
        ("主体权利-访问权", "subject_rights",
         "是否在 30 天内提供个人数据副本？",
         "上线 Subject Access Request (SAR) 自助工单与 30 天 SLA"),
        ("主体权利-更正权", "subject_rights",
         "是否允许用户更正个人数据？",
         "在账户设置开放资料编辑，变更留痕"),
        ("主体权利-删除权", "subject_rights",
         "是否支持被遗忘权/删除？",
         "上线账号注销与数据删除流水线，关联备份同步清理"),
        ("主体权利-可携带权", "subject_rights",
         "是否提供结构化导出（JSON/CSV）？",
         "提供 GDPR 标准的数据导出接口"),
        ("主体权利-限制处理权", "subject_rights",
         "是否支持暂停处理？",
         "在隐私设置中支持暂停营销/分析处理"),
        ("主体权利-反对权", "subject_rights",
         "是否允许反对直接营销？",
         "邮件页脚提供 unsubscribe 与反对营销入口"),
        ("跨境传输-数据出境评估", "cross_border",
         "是否对出境数据做影响评估？",
         "完成 Transfer Impact Assessment (TIA)"),
        ("跨境传输-标准合同条款", "cross_border",
         "是否签署 SCC 标准合同条款？",
         "与境外处理者签署 EU 委员会 SCC 模块"),
        ("跨境传输-充分性认定", "cross_border",
         "接收国是否在充分性认定名单？",
         "核对欧盟最新充分性认定国家清单"),
        ("数据留存-留存期限", "retention",
         "每类数据是否定义留存期限？",
         "建立数据留存矩阵，到期自动删除/匿名化"),
        ("数据留存-到期删除", "retention",
         "是否自动执行到期删除？",
         "调度 Job 按月扫描过期数据并归档/删除"),
        ("数据留存-匿名化", "retention",
         "分析用数据是否做匿名化？",
         "对分析数据集做 k-匿名/差分隐私处理"),
        ("隐私政策-透明度", "notice",
         "隐私政策是否清晰易读？",
         "更新隐私通知：谁/什么/为什么/多久/权利"),
        ("隐私政策-DPO 任命", "dpo",
         "是否任命 DPO 并公开联系方式？",
         "任命 DPO 并在隐私政策中公示联系邮箱"),
        ("DPIA 评估", "dpia",
         "高风险处理是否做 DPIA？",
         "对大规模/监控/敏感数据处理完成 DPIA 文档"),
    ]
    for i, (title, dom, desc, sug) in enumerate(gdpr, 1):
        items.append(ComplianceItem(
            item_id=f"GDPR-{i:03d}", framework="GDPR", domain=dom,
            title=title, description=desc, suggestion=sug))

    # ---------------- PIPL ----------------
    pipl = [
        ("告知同意", "consent",
         "处理个人信息前是否充分告知并取得同意？",
         "更新隐私弹窗与同意书，单独同意敏感信息处理"),
        ("最小必要", "minimization",
         "收集字段是否为实现目的最小必要？",
         "评审字段清单，下线非必要字段并停止采集"),
        ("目的限制", "purpose",
         "是否在告知目的范围内使用？",
         "新增用途必须重新告知/取得同意"),
        ("存储期限", "retention",
         "保存期限是否为实现目的所必要的最短时间？",
         "设定最短留存期并自动清理"),
        ("个人权利-知情/决定/查阅/复制", "subject_rights",
         "是否保障个人的知情、决定、查阅、复制权？",
         "上线个人信息中心：查阅/复制/转移/删除"),
        ("个人权利-更正/补充", "subject_rights",
         "是否支持更正补充？",
         "开放资料更正入口并留痕"),
        ("个人权利-删除", "subject_rights",
         "是否支持删除权？",
         "提供注销与删除工单，15 工作日内完成"),
        ("跨境传输", "cross_border",
         "向境外提供个人信息是否通过安全评估？",
         "完成 PIPL 第 38 条：安全评估/标准合同/认证"),
        ("安全措施", "security",
         "是否采取加密/去标识化/访问控制？",
         "敏感字段加密落地、最小权限、审计日志"),
        ("PIA 评估", "pia",
         "处理敏感个人信息是否做个人信息保护影响评估？",
         "完成 PIA 报告并留存至少 3 年"),
    ]
    for i, (title, dom, desc, sug) in enumerate(pipl, 1):
        items.append(ComplianceItem(
            item_id=f"PIPL-{i:03d}", framework="PIPL", domain=dom,
            title=title, description=desc, suggestion=sug))
    return items


class PrivacyCompliancePhase:
    """阶段5：隐私合规。"""

    def __init__(self) -> None:
        self._items: List[ComplianceItem] = _seed_items()

    # ------------------------------------------------------------------ #
    def list_items(self, framework: Optional[str] = None,
                   domain: Optional[str] = None) -> List[Dict[str, Any]]:
        items = self._items
        if framework:
            items = [i for i in items if i.framework == framework]
        if domain:
            items = [i for i in items if i.domain == domain]
        return [i.to_dict() for i in items]

    def get_item(self, item_id: str) -> Optional[Dict[str, Any]]:
        for i in self._items:
            if i.item_id == item_id:
                return i.to_dict()
        return None

    def assess(self, item_id: str, status: str, score: int,
               note: str = "") -> Dict[str, Any]:
        if status not in ("pass", "fail", "partial"):
            return {"error": "status must be pass/fail/partial"}
        for i in self._items:
            if i.item_id == item_id:
                i.status = status
                i.score = max(0, min(100, score))
                if note:
                    i.suggestion = note
                return i.to_dict()
        return {"error": "item not found"}

    # ------------------------------------------------------------------ #
    def auto_assess(self) -> Dict[str, Any]:
        """演示性自动评估：随机给一批 pass/partial/fail。"""
        import hashlib
        for i in self._items:
            h = int(hashlib.md5(i.item_id.encode()).hexdigest(), 16)
            bucket = h % 10
            if bucket < 5:
                i.status = "pass"
                i.score = 85 + h % 15
            elif bucket < 8:
                i.status = "partial"
                i.score = 50 + h % 30
            else:
                i.status = "fail"
                i.score = 10 + h % 30
        return self.summary()

    # ------------------------------------------------------------------ #
    def summary(self) -> Dict[str, Any]:
        by_fw: Dict[str, Dict[str, int]] = {}
        overall = []
        for i in self._items:
            by_fw.setdefault(i.framework, {
                "pass": 0, "fail": 0, "partial": 0,
                "not_assessed": 0, "score_sum": 0, "count": 0,
            })
            by_fw[i.framework][i.status] += 1
            by_fw[i.framework]["score_sum"] += i.score
            by_fw[i.framework]["count"] += 1
            overall.append(i.score)
        fw_score = {}
        for fw, s in by_fw.items():
            fw_score[fw] = round(s["score_sum"] / s["count"], 1) if s["count"] else 0
        total = len(self._items)
        fails = [i for i in self._items if i.status == "fail"]
        partials = [i for i in self._items if i.status == "partial"]
        return {
            "total_items": total,
            "by_framework": {k: {kk: vv for kk, vv in v.items()
                                  if kk != "score_sum"}
                             for k, v in by_fw.items()},
            "framework_scores": fw_score,
            "overall_score": round(sum(overall) / total, 1) if total else 0,
            "fail_items": [i.to_dict() for i in fails],
            "partial_items": [i.to_dict() for i in partials],
            "remediation": [
                {"item_id": i.item_id, "title": i.title,
                 "framework": i.framework,
                 "suggestion": i.suggestion}
                for i in (fails + partials)
            ],
        }

    # ------------------------------------------------------------------ #
    def generate_report(self) -> str:
        s = self.summary()
        lines = [
            "# 隐私合规评估报告",
            f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"- 总检查项: {s['total_items']}",
            f"- 整体得分: {s['overall_score']}",
            "",
            "## 各框架得分",
        ]
        for fw, sc in s["framework_scores"].items():
            lines.append(f"- {fw}: {sc}")
        lines += ["", "## 不符合项整改建议"]
        for r in s["remediation"][:20]:
            lines.append(f"- [{r['framework']}] {r['title']}: "
                         f"{r['suggestion']}")
        return "\n".join(lines)


_default_phase: Optional[PrivacyCompliancePhase] = None


def get_privacy_compliance_phase() -> PrivacyCompliancePhase:
    global _default_phase
    if _default_phase is None:
        _default_phase = PrivacyCompliancePhase()
    return _default_phase


__all__ = [
    "PrivacyCompliancePhase", "ComplianceItem",
    "get_privacy_compliance_phase",
]
