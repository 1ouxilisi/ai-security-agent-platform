#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
privacy_compliance.py — 隐私合规评估器。

覆盖：
    - GDPR 合规检查（合法性/透明性/数据主体权利/最小化/准确性/存储限制/完整性/问责制）
    - 个保法(PIPL) 合规检查（合法基础/告知同意/个人权利/跨境/数据安全/自动化决策/敏感个人信息）
    - CCPA 合规检查（知情/删除/选择退出/非歧视/透明）
    - 隐私政策分析（完整性/可读性/合规性/缺失条款）
    - 数据主体权利(DSAR) 实现评估
    - 同意管理（收集/记录/撤回/粒度/有效期）
    - 数据留存（策略/期限/到期删除/归档）
    - 跨境传输评估（安全评估/标准合同/认证/充分性认定）
    - 隐私影响评估(PIA/DPIA)
    - 合规评分与差距分析

设计定位：仅做合规差距分析与评估建议，输出检查表与整改清单。
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 合规框架库
# --------------------------------------------------------------------------- #
COMPLIANCE_FRAMEWORKS: Dict[str, Dict[str, Any]] = {
    "GDPR": {
        "name": "欧盟通用数据保护条例", "region": "欧盟/EEA",
        "articles": ["Art.5 原则", "Art.6 合法基础", "Art.7 同意", "Art.13/14 告知",
                     "Art.15-22 数据主体权利", "Art.25 数据保护设计", "Art.30 处理记录",
                     "Art.32 安全", "Art.33/34 泄露通知", "Art.35 DPIA", "Art.44-49 跨境"],
        "key_rights": ["访问", "更正", "删除(被遗忘)", "限制处理", "可携带", "反对", "自动化决策拒绝"],
    },
    "PIPL": {
        "name": "中华人民共和国个人信息保护法", "region": "中国大陆",
        "articles": ["第13条 处理基础", "第14条 同意", "第17条 告知", "第23条 共同处理/委托",
                     "第24条 自动化决策", "第28-32条 敏感个人信息", "第38-43条 跨境提供",
                     "第44-50条 个人权利", "第51-59条 安全义务", "第55-56条 个人保护影响评估"],
        "key_rights": ["知情决定", "查阅复制", "更正补充", "删除", "解释说明", "撤回同意"],
        "sensitive_pi": ["生物识别", "宗教特定身份", "医疗健康", "金融账户", "行踪轨迹",
                         "不满14周岁未成年人"],
    },
    "CCPA": {
        "name": "加州消费者隐私法/CPRA", "region": "美国加州",
        "articles": ["1798.100 收集披露", "1798.105 删除", "1798.110 知情",
                     "1798.120 选择出售退出", "1798.125 不歧视", "1798.130 响应义务"],
        "key_rights": ["知情(收集类别/目的)", "删除", "选择退出出售", "不歧视", "更正"],
    },
}


class PrivacyComplianceAssessor:
    """隐私合规评估器。"""

    def __init__(self) -> None:
        self.frameworks = COMPLIANCE_FRAMEWORKS
        self.findings: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 通用：运行某框架的检查项（逐项给 满足/部分满足/不满足）
    # ------------------------------------------------------------------ #
    @staticmethod
    def _item(fw: str, ref: str, name: str, status: str,
              gap: str = "", evidence: str = "") -> Dict[str, Any]:
        return {"framework": fw, "ref": ref, "name": name, "status": status,
                "gap": gap, "evidence": evidence,
                "weight": {"满足": 1.0, "部分满足": 0.5, "不满足": 0.0}.get(status, 0.0)}

    # ------------------------------------------------------------------ #
    # GDPR 检查
    # ------------------------------------------------------------------ #
    def check_gdpr(self, signals: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        s = signals or {}
        items = [
            self._item("GDPR", "Art.6", "处理具有合法基础",
                       s.get("legal_basis", "不满足"), "未明确告知合法基础(同意/合同/合法利益等)"),
            self._item("GDPR", "Art.7", "同意可证明且可撤回",
                       s.get("consent_record", "部分满足"), "同意记录粒度/撤回路径不完整"),
            self._item("GDPR", "Art.13/14", "透明告知(控制者身份/目的/保留期/权利)",
                       s.get("transparency", "部分满足"), "隐私政策缺少保留期与权利行使方式"),
            self._item("GDPR", "Art.5(1)c", "数据最小化",
                       s.get("data_minimization", "部分满足"), "存在超范围收集(通讯录/位置/相册)"),
            self._item("GDPR", "Art.5(1)d", "数据准确性",
                       s.get("accuracy", "满足"), "提供更正机制即视为满足"),
            self._item("GDPR", "Art.5(1)e", "存储限制(到期删除)",
                       s.get("storage_limit", "不满足"), "无明确留存期限与到期自动删除"),
            self._item("GDPR", "Art.32", "处理安全(加密/抗毁/可用性)",
                       s.get("security", "部分满足"), "传输加密有，但静态加密/访问审计待补"),
            self._item("GDPR", "Art.30", "处理活动记录(ROPA)",
                       s.get("ropa", "不满足"), "缺少处理活动记录台账"),
            self._item("GDPR", "Art.35", "高风险处理做DPIA",
                       s.get("dpia", "部分满足"), "大规模画像/生物识别场景未做DPIA"),
            self._item("GDPR", "Art.33", "72小时泄露通报机制",
                       s.get("breach_notify", "不满足"), "无数据泄露应急与通报流程"),
            self._item("GDPR", "Art.44-49", "跨境传输合法机制",
                       s.get("cross_border", "部分满足"), "未使用SCC/充分性认定/BCR"),
            self._item("GDPR", "Art.21", "反对权与画像退出",
                       s.get("object_right", "部分满足"), "个性化推荐无一键关闭/退出"),
        ]
        return items

    # ------------------------------------------------------------------ #
    # 个保法(PIPL) 检查
    # ------------------------------------------------------------------ #
    def check_pipl(self, signals: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        s = signals or {}
        items = [
            self._item("PIPL", "第13条", "处理有合法基础",
                       s.get("legal_basis", "部分满足"), "除同意外需列明法定处理情形"),
            self._item("PIPL", "第14条", "单独/充分告知同意",
                       s.get("consent", "部分满足"), "捆绑同意，未做到单独、具体、自愿"),
            self._item("PIPL", "第17条", "事前告知(目的/方式/种类/保留期/权利)",
                       s.get("notice", "部分满足"), "隐私政策未逐项列明处理目的与保留期限"),
            self._item("PIPL", "第24条", "自动化决策透明度与退出",
                       s.get("automated_decision", "不满足"), "大数据杀熟/个性化推送无说明与关闭"),
            self._item("PIPL", "第28-32条", "敏感个人信息单独同意+影响评估",
                       s.get("sensitive_consent", "不满足"), "人脸/行踪/金融账户未取得单独同意"),
            self._item("PIPL", "第38-43条", "出境合规(安全评估/标准合同/认证)",
                       s.get("cross_border", "不满足"), "数据出境未通过安评或备案标准合同"),
            self._item("PIPL", "第44-50条", "个人权利响应机制",
                       s.get("dsar", "部分满足"), "无在线访问/更正/删除/复制入口"),
            self._item("PIPL", "第51-59条", "安全措施(分级/加密/审计/权限)",
                       s.get("security", "部分满足"), "缺少权限最小化与访问审计"),
            self._item("PIPL", "第55-56条", "个人信息保护影响评估(PIPIA)",
                       s.get("pipia", "不满足"), "处理敏感PI/自动化决策前未做PIPIA"),
            self._item("PIPL", "第57条", "泄露通知(监管+个人)",
                       s.get("breach_notify", "不满足"), "无泄露告知流程"),
            self._item("PIPL", "第31条", "未成年人(不满14岁)监护人同意",
                       s.get("minor_consent", "部分满足"), "无儿童个人信息专项规则"),
            self._item("PIPL", "第19条", "保留期限最短化",
                       s.get("retention", "不满足"), "无到期删除策略"),
        ]
        return items

    # ------------------------------------------------------------------ #
    # CCPA 检查
    # ------------------------------------------------------------------ #
    def check_ccpa(self, signals: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        s = signals or {}
        items = [
            self._item("CCPA", "1798.100", "收集类别/目的透明披露",
                       s.get("transparency", "部分满足"), "未在收集时点披露类别与目的"),
            self._item("CCPA", "1798.105", "删除权(经验证请求)",
                       s.get("deletion", "不满足"), "无经验证的删除请求渠道"),
            self._item("CCPA", "1798.110", "知情(已收集的具体信息)",
                       s.get("access", "部分满足"), "无数据主体数据导出"),
            self._item("CCPA", "1798.120", "选择出售/共享退出(Do Not Sell)",
                       s.get("opt_out", "不满足"), "缺少“Do Not Sell My Personal Information”链接"),
            self._item("CCPA", "1798.125", "行使权利不受歧视",
                       s.get("non_discrimination", "满足"), "无差别定价即满足"),
            self._item("CCPA", "1798.130", "45天响应",
                       s.get("response_sla", "部分满足"), "响应SLA/验证机制未明确"),
            self._item("CCPA", "CPRA", "敏感个人信息限制使用",
                       s.get("sensitive_limit", "不满足"), "未披露并限制SPI使用"),
        ]
        return items

    # ------------------------------------------------------------------ #
    # 隐私政策分析
    # ------------------------------------------------------------------ #
    def analyze_policy(self, text: str) -> Dict[str, Any]:
        """分析隐私政策文本完整性/可读性/缺失条款。"""
        must_have = {
            "控制者/运营者身份": r"(运营者|公司名称|联系方式|我们)",
            "收集信息类型": r"(收集|采集|个人信息|数据).{0,10}(包括|类型|如下)",
            "使用目的": r"(目的|用途|用于|为了)",
            "共享/委托/对外提供": r"(共享|委托|对外提供|第三方|合作)",
            "跨境传输": r"(跨境|出境|境外|海外)",
            "用户权利": r"(权利|查阅|更正|删除|注销|撤回)",
            "保留期限": r"(保留|存储期限|保存|留存|删除)",
            "Cookie/SDK": r"(Cookie|cookie|SDK|埋点|设备信息)",
            "未成年人": r"(儿童|未成年人|14岁|监护人)",
            "更新与生效": r"(更新|修订|生效|版本)",
            "投诉渠道": r"(投诉|反馈|联系方式|邮箱|电话)",
        }
        present: List[str] = []
        missing: List[str] = []
        for label, pat in must_have.items():
            if re.search(pat, text or "", re.IGNORECASE):
                present.append(label)
            else:
                missing.append(label)
        # 可读性：粗略估算平均句长与字数
        chars = len(re.findall(r"[\u4e00-\u9fa5]", text or ""))
        sentences = len(re.split(r"[。！？!?]", text or ""))
        avg_len = round(chars / max(sentences, 1), 1)
        readability = "较差(长句多)" if avg_len > 45 else ("中等" if avg_len > 25 else "较好")
        score = round(len(present) / len(must_have) * 100, 1)
        return {
            "length_chars": chars,
            "present_clauses": present,
            "missing_clauses": missing,
            "coverage_score": score,
            "readability": readability,
            "avg_chars_per_sentence": avg_len,
            "verdict": "合规" if score >= 80 else ("基本合规" if score >= 60 else "不合规/重大缺失"),
        }

    # ------------------------------------------------------------------ #
    # DSAR 实现评估
    # ------------------------------------------------------------------ #
    def assess_dsar(self, signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        s = signals or {}
        rights = [
            ("访问权", "数据导出/查看", s.get("access", "不满足")),
            ("更正权", "在线修改资料", s.get("rectify", "部分满足")),
            ("删除权", "账号注销/数据删除", s.get("delete", "不满足")),
            ("限制处理权", "暂停营销/处理", s.get("restrict", "部分满足")),
            ("可携带权", "机器可读导出(JSON/CSV)", s.get("portability", "不满足")),
            ("反对权", "反对营销/画像", s.get("object", "部分满足")),
            ("自动化决策说明权", "对决策要求解释", s.get("explain", "不满足")),
        ]
        rows = [{"right": r, "implementation": impl, "status": st} for r, impl, st in rights]
        met = sum(1 for r in rows if r["status"] == "满足")
        return {
            "rights": rows,
            "met_count": met,
            "total": len(rows),
            "score": round(met / len(rows) * 100, 1),
            "sla": s.get("sla_days", "未定义(建议≤30日)"),
            "verdict": "健全" if met >= 5 else ("部分实现" if met >= 3 else "严重缺失"),
        }

    # ------------------------------------------------------------------ #
    # 同意管理
    # ------------------------------------------------------------------ #
    def assess_consent(self, signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        s = signals or {}
        checks = {
            "同意可主动获取(非默认勾选)": s.get("active_consent", "不满足"),
            "同意粒度(按目的/字段拆分)": s.get("granular", "部分满足"),
            "同意记录留痕(时间/版本/范围)": s.get("consent_log", "部分满足"),
            "可一键撤回同意": s.get("withdraw", "不满足"),
            "同意有效期/到期重新征求": s.get("expiry", "不满足"),
            "敏感PI单独同意": s.get("sensitive_separate", "不满足"),
            "未成年人监护人同意": s.get("minor_consent", "部分满足"),
        }
        rows = [{"item": k, "status": v} for k, v in checks.items()]
        ok = sum(1 for v in checks.values() if v == "满足")
        return {"items": rows, "met": ok, "total": len(checks),
                "score": round(ok / len(checks) * 100, 1),
                "recommendation": "采用分层弹窗+同意中心，按目的记录版本并支持撤回"}

    # ------------------------------------------------------------------ #
    # 数据留存
    # ------------------------------------------------------------------ #
    def assess_retention(self, signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        s = signals or {}
        policies = s.get("policies", [
            {"category": "账号注册信息", "retention": "注销后30天", "auto_delete": False, "legal_hold": False},
            {"category": "交易/订单", "retention": "法规要求10年", "auto_delete": False, "legal_hold": True},
            {"category": "行为日志", "retention": "180天", "auto_delete": True, "legal_hold": False},
            {"category": "客服录音", "retention": "6个月", "auto_delete": False, "legal_hold": False},
            {"category": "营销画像", "retention": "随用户撤回即删", "auto_delete": False, "legal_hold": False},
        ])
        gaps = [p for p in policies if not p.get("auto_delete") and not p.get("legal_hold")]
        return {
            "policies": policies,
            "manual_delete_gaps": len(gaps),
            "archiving_strategy": "冷数据归档后加密,到期自动销毁",
            "verdict": "需为非法定留存项配置到期自动删除/匿名化",
            "gap_items": [g["category"] for g in gaps],
        }

    # ------------------------------------------------------------------ #
    # 跨境传输评估
    # ------------------------------------------------------------------ #
    def assess_cross_border(self, signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        s = signals or {}
        pathways = [
            ("安全评估(国家网信办)", s.get("sec_assessment", "不适用"), "处理100万人PI或关键信息基础设施须申报"),
            ("标准合同备案(SCC)", s.get("scc", "不满足"), "非安评情形应签署个人信息出境标准合同并备案"),
            ("个人信息保护认证", s.get("cert", "不适用"), "可作为SCC替代路径"),
            ("充分性认定", s.get("adequacy", "不适用"), "目的地国获我国充分性认定"),
            ("单独同意+告知", s.get("separate_consent", "部分满足"), "跨境前须单独告知接收方/目的/权利并取得同意"),
            ("出境影响评估(PIPIA)", s.get("pipia", "不满足"), "出境前应做个人信息保护影响评估"),
        ]
        rows = [{"pathway": p, "status": st, "note": n} for p, st, n in pathways]
        return {
            "destination_country": s.get("country", "未知"),
            "volume": s.get("volume", "未知"),
            "pathways": rows,
            "recommended_path": "标准合同备案 + 单独同意 + 出境影响评估",
            "risk": "high" if s.get("volume") in ("large", "100万+") else "medium",
        }

    # ------------------------------------------------------------------ #
    # DPIA / PIA
    # ------------------------------------------------------------------ #
    def run_dpia(self, scope: str = "", signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        s = signals or {}
        risks = [
            {"risk": "大规模画像/自动化决策", "likelihood": s.get("likelihood", "中"),
             "impact": s.get("impact", "高"), "treatment": "human-in-the-loop + 解释权"},
            {"risk": "敏感个人信息处理", "likelihood": s.get("sensitive", "高"),
             "impact": "高", "treatment": "最小化 + 单独同意 + 加密"},
            {"risk": "数据跨境", "likelihood": "中", "impact": "中",
             "treatment": "SCC/安评 + 影响评估"},
            {"risk": "新技术(AI/人脸)应用", "likelihood": s.get("new_tech", "中"),
             "impact": "高", "treatment": "试点 + 隐私设计默认开启"},
            {"risk": "第三方/供应商处理", "likelihood": "中", "impact": "中",
             "treatment": "DPA合同 + 审计"},
        ]
        score = 0
        for r in risks:
            li = {"低": 1, "中": 2, "高": 3}[r["likelihood"]]
            im = {"低": 1, "中": 2, "高": 3}[r["impact"]]
            score += li * im
        level = "高风险" if score >= 25 else ("中风险" if score >= 15 else "低风险")
        return {
            "dpia_id": uuid.uuid4().hex[:10],
            "scope": scope or "未指定处理活动",
            "risks": risks,
            "residual_score": score,
            "risk_level": level,
            "mitigations": [
                "默认隐私设计(privacy by default)",
                "数据最小化 + 去标识化",
                "访问最小权限 + 全程审计",
                "建立DSAR响应与泄露通报流程",
                "高风险须暂停处理并咨询监管/数据保护官",
            ],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 综合评估 + 评分 + 差距分析
    # ------------------------------------------------------------------ #
    def assess(self, signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        signals = signals or {}
        gdpr = self.check_gdpr(signals)
        pipl = self.check_pipl(signals)
        ccpa = self.check_ccpa(signals)
        dsar = self.assess_dsar(signals)
        consent = self.assess_consent(signals)
        retention = self.assess_retention(signals)
        cross = self.assess_cross_border(signals)
        dpia = self.run_dpia(signals.get("scope", ""), signals)

        def score(items: List[Dict[str, Any]]) -> float:
            return round(sum(i["weight"] for i in items) / len(items) * 100, 1)

        scores = {
            "GDPR": score(gdpr),
            "PIPL": score(pipl),
            "CCPA": score(ccpa),
            "DSAR": dsar["score"],
            "同意管理": consent["score"],
            "数据留存": 60.0 if retention["manual_delete_gaps"] else 90.0,
        }
        gaps: List[Dict[str, Any]] = []
        for items in (gdpr, pipl, ccpa):
            for it in items:
                if it["status"] in ("不满足", "部分满足"):
                    gaps.append({"framework": it["framework"], "ref": it["ref"],
                                 "name": it["name"], "status": it["status"], "gap": it["gap"]})
        overall = round(sum(scores.values()) / len(scores), 1)
        grade = "A 优秀" if overall >= 85 else ("B 良好" if overall >= 70 else
                ("C 一般" if overall >= 55 else "D 较差/高风险"))
        return {
            "assessment_id": uuid.uuid4().hex[:10],
            "frameworks": {"GDPR": gdpr, "PIPL": pipl, "CCPA": ccpa},
            "dsar": dsar, "consent": consent, "retention": retention,
            "cross_border": cross, "dpia": dpia,
            "scores": scores, "overall_score": overall, "grade": grade,
            "gaps": gaps, "gap_count": len(gaps),
            "priority_gaps": [g for g in gaps if g["status"] == "不满足"][:15],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def get_report_markdown(self, result: Dict[str, Any]) -> str:
        lines = [
            "# 隐私合规评估报告", "",
            f"- 评估 ID: {result.get('assessment_id')}",
            f"- 时间: {result.get('generated_at')}",
            f"- 综合得分: {result.get('overall_score')} ({result.get('grade')})", "",
            "## 各框架得分",
        ]
        for k, v in (result.get("scores") or {}).items():
            lines.append(f"- {k}: {v}")
        lines += ["", "## 优先整改项(不满足)"]
        for g in result.get("priority_gaps", []):
            lines.append(f"- [{g['framework']} {g['ref']}] {g['name']}: {g['gap']}")
        lines += ["", f"## DPIA 残余风险: {result.get('dpia', {}).get('risk_level')}",
                  "", "## 结论",
                  "建议优先补齐合法基础、同意管理、DSAR在线渠道与跨境路径。"]
        return "\n".join(lines)

    def list_frameworks(self) -> Dict[str, Any]:
        return {"total": len(self.frameworks), "frameworks": self.frameworks}
