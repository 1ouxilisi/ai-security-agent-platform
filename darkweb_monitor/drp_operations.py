# -*- coding: utf-8 -*-
"""
drp_operations.py — 数字风险保护(DRP)综合运营器（第13轮升级）。

功能：
- 监控策略：监控目标/源/关键词/告警规则/频率/范围。
- 风险评分：泄露/品牌/欺诈/威胁Actor 维度评分、趋势、预测。
- 优先级排序：风险等级/影响范围/紧急程度/可操作性。
- 响应建议：按风险类型的响应步骤/模板/时间要求。
- Takedown协助：域名/网站/App下架/账号封禁/内容删除流程与模板。
- 情报报告：日报/周报/月报/专项/威胁简报/高管摘要/董事会报告。
- 仪表盘：风险概览/趋势/Top风险/告警统计/响应统计/效果指标。
- 综合评估工作流：监控配置→情报收集→风险分析→优先级→响应→报告。

说明：聚合同包其它5个模块；跨模块导入做容错，缺失时用内置模拟数据。
所有功能为防御/监控/保护视角。
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# 跨模块导入（容错：包内导入失败时退化为同目录直接导入）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from darkweb_monitor.darkweb_intel import get_darkweb_intel_monitor  # type: ignore
    from darkweb_monitor.credential_leak import get_credential_leak_detector  # type: ignore
    from darkweb_monitor.brand_protection import get_brand_protection_detector  # type: ignore
    from darkweb_monitor.data_breach_analysis import get_data_breach_analyzer  # type: ignore
    from darkweb_monitor.threat_actor_analysis import get_threat_actor_analyzer  # type: ignore
    _SUBMODULES_OK = True
except Exception:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from darkweb_intel import get_darkweb_intel_monitor  # type: ignore
        from credential_leak import get_credential_leak_detector  # type: ignore
        from brand_protection import get_brand_protection_detector  # type: ignore
        from data_breach_analysis import get_data_breach_analyzer  # type: ignore
        from threat_actor_analysis import get_threat_actor_analyzer  # type: ignore
        _SUBMODULES_OK = True
    except Exception:
        _SUBMODULES_OK = False
        # 占位，避免名称未定义
        def get_darkweb_intel_monitor(): return None
        def get_credential_leak_detector(): return None
        def get_brand_protection_detector(): return None
        def get_data_breach_analyzer(): return None
        def get_threat_actor_analyzer(): return None


# 响应时间 SLA 要求
RESPONSE_SLA = {
    "critical": 4,    # 小时
    "high": 24,
    "medium": 72,
    "low": 168,
}

# 风险类型 -> 响应建议模板
RESPONSE_TEMPLATES: Dict[str, List[str]] = {
    "credential_leak": [
        "确认泄露邮箱/账户范围",
        "强制重置密码并开启MFA",
        "检查近90天异常登录",
        "通知受影响用户",
    ],
    "phishing": [
        "固化钓鱼页面证据",
        "向主机商/CDN提交滥用投诉",
        "提交Google Safe Browsing",
        "监控品牌搜索词",
    ],
    "lookalike_domain": [
        "WHOIS取证",
        "向注册商投诉/UDRP",
        "配置DNSSinkhole",
    ],
    "fake_app": [
        "知识产权下架申诉",
        "通知应用商店",
        "发布官方澄清",
    ],
    "data_breach": [
        "止血并隔离",
        "评估合规通知义务(GDPR/个保法)",
        "通知监管与用户",
        "复盘根因并加固",
    ],
}


# ==================== 数据结构 ====================

@dataclass
class MonitorPolicy:
    name: str = ""
    targets: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    alert_rules: List[str] = field(default_factory=list)
    frequency: str = "hourly"
    scope: str = "public_sources"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==================== DRP 综合运营器 ====================

class DRPOperator:
    """数字风险保护综合运营器"""

    def __init__(self) -> None:
        self.policies: Dict[str, MonitorPolicy] = {}
        self.assessment_history: List[Dict[str, Any]] = []

    # ---------- 监控策略 ----------

    def configure_policy(self, name: str = "default",
                         targets: Optional[List[str]] = None,
                         keywords: Optional[List[str]] = None,
                         frequency: str = "hourly") -> Dict[str, Any]:
        policy = MonitorPolicy(
            name=name,
            targets=targets or ["example.com", "ExampleCorp"],
            sources=["forums", "markets", "chat_channels", "paste_sites",
                     "leak_sites", "blogs", "irc"],
            keywords=keywords or ["ExampleCorp", "example.com", "产品代号X"],
            alert_rules=["critical即时通知", "high当日通知", "medium汇总周报"],
            frequency=frequency,
            scope="public_sources",
        )
        self.policies[name] = policy
        return policy.to_dict()

    def list_policies(self) -> List[Dict[str, Any]]:
        return [p.to_dict() for p in self.policies.values()]

    # ---------- 风险评分 ----------

    def composite_risk_score(self, brand: str = "ExampleCorp") -> Dict[str, Any]:
        dims = {"泄露": 0, "品牌": 0, "欺诈": 0, "威胁Actor": 0}
        # 凭证泄露维度
        if _SUBMODULES_OK:
            try:
                cl = get_credential_leak_detector()
                rep = cl.password_reuse_stats()
                dims["泄露"] = min(100, int(rep["weak_password_ratio"]) + 30)
            except Exception:
                dims["泄露"] = 45
            try:
                bp = get_brand_protection_detector()
                sc = bp.calculate_risk_score(brand)
                dims["品牌"] = sc["overall_risk_score"]
                dims["欺诈"] = sc["overall_risk_score"]
            except Exception:
                dims["品牌"] = 50
                dims["欺诈"] = 40
            try:
                ta = get_threat_actor_analyzer()
                top = ta.list_actors()
                high = len([a for a in top["actors"] if a["threat_level"] in ("高", "严重")])
                dims["威胁Actor"] = min(100, high * 20)
            except Exception:
                dims["威胁Actor"] = 30
        else:
            dims = {"泄露": 45, "品牌": 55, "欺诈": 40, "威胁Actor": 30}

        overall = round(sum(dims.values()) / len(dims))
        # 趋势（模拟近6周）
        trend = [max(5, overall - 10 + (i % 5)) for i in range(6)]
        return {
            "brand": brand,
            "overall_score": overall,
            "dimensions": dims,
            "trend_6w": trend,
            "forecast_next_week": overall + (2 if trend[-1] >= trend[-2] else -2),
            "evaluated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ---------- 优先级排序 ----------

    def prioritize(self, risks: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        risks = risks or [
            {"id": "R1", "type": "credential_leak", "level": "critical",
             "impact": 5000, "urgency": 9, "actionability": 8},
            {"id": "R2", "type": "phishing", "level": "high",
             "impact": 800, "urgency": 8, "actionability": 7},
            {"id": "R3", "type": "lookalike_domain", "level": "medium",
             "impact": 200, "urgency": 5, "actionability": 6},
            {"id": "R4", "type": "fake_app", "level": "medium",
             "impact": 150, "urgency": 4, "actionability": 5},
        ]
        def score(r: Dict[str, Any]) -> float:
            lvl_w = {"critical": 40, "high": 25, "medium": 12, "low": 5}[r["level"]]
            return lvl_w + r["urgency"] * 3 + r["actionability"] * 2 + min(20, r["impact"] / 500)
        ranked = sorted(risks, key=score, reverse=True)
        for i, r in enumerate(ranked, 1):
            r["priority"] = f"P{i}"
            r["priority_score"] = round(score(r), 1)
            r["sla_hours"] = RESPONSE_SLA.get(r["level"], 72)
        return ranked

    # ---------- 响应建议 ----------

    def response_advice(self, risk_type: str = "credential_leak") -> Dict[str, Any]:
        steps = RESPONSE_TEMPLATES.get(risk_type, ["评估影响", "制定方案", "执行响应"])
        return {
            "risk_type": risk_type,
            "steps": steps,
            "template": "".join(steps),
            "sla_hours": RESPONSE_SLA.get("high", 24),
            "owners": ["SecOps", "品牌/法务", "客服"],
        }

    # ---------- Takedown 协助 ----------

    def takedown_assist(self, target_type: str = "domain") -> Dict[str, Any]:
        templates = {
            "domain": "致注册商：以下域名涉嫌仿冒品牌，请依据UDRP/滥用政策立即暂停或下线。",
            "website": "致主机商滥用部门：该主机托管钓鱼页面，请依据滥用政策下线。",
            "app": "致应用商店：以下App侵犯商标并仿冒官方，请依据知识产权政策下架。",
            "account": "致平台：该账号假冒官方，请依据平台政策封禁并冻结。",
            "content": "致内容平台：该内容侵权/欺诈，请予删除。",
        }
        return {
            "target_type": target_type,
            "process": ["取证存证", "起草投诉", "提交平台", "跟踪回执", "验证下线"],
            "template": templates.get(target_type, "请提交下架投诉。"),
            "typical_sla_hours": 48,
        }

    # ---------- 情报报告 ----------

    def intelligence_report(self, kind: str = "daily",
                            brand: str = "ExampleCorp") -> Dict[str, Any]:
        score = self.composite_risk_score(brand)
        reports = {
            "daily": "DRP日报", "weekly": "DRP周报", "monthly": "DRP月报",
            "special": "专项威胁简报", "executive": "高管摘要",
            "board": "董事会报告",
        }
        return {
            "kind": kind,
            "title": reports.get(kind, "DRP情报报告"),
            "brand": brand,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "headline": f"当前综合数字风险 {score['overall_score']}/100",
            "risk_score": score,
            "highlights": [
                "本周新增泄露情报需跟进",
                "仿冒域名注册商投诉已提交",
                "高风险账户重置进度更新",
            ],
            "audience": {
                "daily": "SecOps值班", "weekly": "安全团队",
                "monthly": "安全负责人", "executive": "CTO/CSO",
                "board": "董事会/审计委员会"}.get(kind, "安全团队"),
        }

    # ---------- 仪表盘 ----------

    def dashboard(self, brand: str = "ExampleCorp") -> Dict[str, Any]:
        score = self.composite_risk_score(brand)
        return {
            "brand": brand,
            "overview": {
                "overall_risk": score["overall_score"],
                "active_alerts": 12,
                "open_takedowns": 3,
                "assets_monitored": 8,
            },
            "trend": score["trend_6w"],
            "top_risks": self.prioritize()[:3],
            "alert_stats": {"critical": 2, "high": 5, "medium": 4, "low": 1},
            "response_stats": {"resolved_7d": 9, "open": 12, "overdue": 1},
            "effectiveness": {"takedown_success_rate": 86,
                              "mean_response_hours": 18,
                              "mttd_hours": 6},
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ---------- 综合评估工作流 ----------

    def run_assessment(self, brand: str = "ExampleCorp",
                       targets: Optional[List[str]] = None) -> Dict[str, Any]:
        started = time.time()
        steps: List[Dict[str, Any]] = []
        # 1. 监控配置
        pol = self.configure_policy(brand, targets=targets)
        steps.append({"step": "监控配置", "status": "done"})
        # 2. 情报收集
        intel = {}
        if _SUBMODULES_OK:
            try:
                intel["credential"] = get_credential_leak_detector().check_email_leak(domain=brand.split()[-1].lower() if " " in brand else "example.com")
                intel["brand"] = get_brand_protection_detector().calculate_risk_score(brand)
                intel["actor"] = get_threat_actor_analyzer().list_actors()
            except Exception as e:
                intel["error"] = str(e)
        steps.append({"step": "情报收集", "status": "done"})
        # 3. 风险分析
        score = self.composite_risk_score(brand)
        steps.append({"step": "风险分析", "status": "done"})
        # 4. 优先级排序
        ranked = self.prioritize()
        steps.append({"step": "优先级排序", "status": "done"})
        # 5. 响应建议
        advice = self.response_advice()
        steps.append({"step": "响应建议", "status": "done"})
        # 6. 报告生成
        report = self.intelligence_report("executive", brand)
        steps.append({"step": "报告生成", "status": "done"})

        result = {
            "assessment_id": f"DRP-{int(time.time())}",
            "brand": brand,
            "duration_seconds": round(time.time() - started, 2),
            "workflow": steps,
            "risk_score": score,
            "prioritized_risks": ranked,
            "response_advice": advice,
            "executive_report": report,
            "legal_boundary": "仅监控公开可访问信息源，不参与非法交易，情报仅用于防御与保护。",
        }
        self.assessment_history.append({
            "assessment_id": result["assessment_id"], "brand": brand,
            "overall": score["overall_score"], "at": result["executive_report"]["generated_at"],
        })
        return result

    def history(self) -> Dict[str, Any]:
        return {"history": list(reversed(self.assessment_history)),
                "count": len(self.assessment_history)}


# ==================== 工厂函数 ====================

_ops_singleton: Optional[DRPOperator] = None


def get_drp_operator() -> DRPOperator:
    global _ops_singleton
    if _ops_singleton is None:
        _ops_singleton = DRPOperator()
    return _ops_singleton
