# -*- coding: utf-8 -*-
"""
zero_trust_maturity.py — 零信任成熟度评估器（第13轮升级 · 零信任模块）。

功能：
- 5 阶段成熟度模型：传统边界安全 / 初步零信任 / 进阶零信任 /
  高级零信任 / 优化零信任
- 成熟度维度：身份 / 设备 / 网络 / 应用 / 数据 / 运维 / 治理 / 文化 8 个维度
- 差距分析：当前状态与目标状态差距 / 关键能力缺失 / 技术债务 / 组织障碍
- 路线图规划：分阶段实施路线 / 优先级排序 / 快速获胜 / 关键里程碑 / 资源需求
- 架构评估：零信任架构完整性 / 组件覆盖 / 集成度 / 自动化程度 / 可观测性
- 零信任评分：综合成熟度评分（0-100）/ 维度评分 / 行业对标
- 零信任成熟度评估报告

说明：内嵌成熟度模型与策略库，仅做评估与路线图建议，不部署实际策略。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional


# ==================== 5 阶段成熟度模型 ====================

MATURITY_STAGES: List[Dict[str, Any]] = [
    {"stage": 1, "name": "传统边界安全", "abbr": "Perimeter",
     "score_range": (0, 20),
     "desc": "依赖防火墙/VPN 边界，内网默认可信，东西向无控制"},
    {"stage": 2, "name": "初步零信任", "abbr": "Initial",
     "score_range": (20, 40),
     "desc": "身份 MFA 覆盖、部分 SSO，开始设备合规检查"},
    {"stage": 3, "name": "进阶零信任", "abbr": "Advanced",
     "score_range": (40, 60),
     "desc": "ZTNA 试点、mTLS 服务网格、微隔离起步、持续验证上线"},
    {"stage": 4, "name": "高级零信任", "abbr": "Optimal",
     "score_range": (60, 80),
     "desc": "全要素动态授权、JIT 特权、全栈可观测、自动响应"},
    {"stage": 5, "name": "优化零信任", "abbr": "Adaptive",
     "score_range": (80, 100),
     "desc": "AI 驱动自适应策略、持续优化、行业最佳实践"},
]

# 8 个成熟度维度
MATURITY_DIMENSIONS = [
    {"id": "identity",   "name": "身份",   "weight": 0.18, "description": "IAM/MFA/SSO/PAM"},
    {"id": "device",     "name": "设备",   "weight": 0.14, "description": "EDR/合规/信任评估"},
    {"id": "network",   "name": "网络",   "weight": 0.14, "description": "微隔离/ZTNA/SDP"},
    {"id": "application", "name": "应用",  "weight": 0.14, "description": "API网关/mTLS/服务网格"},
    {"id": "data",       "name": "数据",   "weight": 0.12, "description": "DLP/加密/分级分类"},
    {"id": "operations", "name": "运维",   "weight": 0.10, "description": "自动化/编排/SOAR"},
    {"id": "governance", "name": "治理",   "weight": 0.10, "description": "策略/合规/度量"},
    {"id": "culture",    "name": "文化",   "weight": 0.08, "description": "意识/培训/责任人"},
]

# 行业对标基准（0-100）
INDUSTRY_BENCHMARK = {
    "金融": 72, "互联网": 65, "制造业": 38, "医疗": 42,
    "政府": 55, "教育": 30, "能源": 48,
}


# ==================== 主评估器 ====================

class ZeroTrustMaturityAssessor:
    """零信任成熟度评估器。"""

    def __init__(self) -> None:
        # 模拟当前 8 维评分
        self.current_scores: Dict[str, int] = {
            "identity": 55, "device": 48, "network": 35, "application": 50,
            "data": 30, "operations": 40, "governance": 45, "culture": 25,
        }
        self.history: List[Dict[str, Any]] = []

    # ---------- 综合评分 ----------

    def overall_score(self) -> Dict[str, Any]:
        total = round(
            sum(self.current_scores[d["id"]] * d["weight"] for d in MATURITY_DIMENSIONS), 1
        )
        stage = self._stage_for(total)
        return {
            "score": total,
            "stage": stage["stage"],
            "stage_name": stage["name"],
            "abbr": stage["abbr"],
        }

    @staticmethod
    def _stage_for(score: float) -> Dict[str, Any]:
        for s in MATURITY_STAGES:
            lo, hi = s["score_range"]
            if lo <= score < hi:
                return s
        return MATURITY_STAGES[-1]

    # ---------- 维度评分 ----------

    def dimension_scores(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for d in MATURITY_DIMENSIONS:
            out.append({
                "id": d["id"], "name": d["name"],
                "current": self.current_scores[d["id"]],
                "weight": d["weight"],
                "description": d["description"],
                "gap_to_stage4": 80 - self.current_scores[d["id"]],
            })
        return out

    # ---------- 差距分析 ----------

    def gap_analysis(self, target_stage: int = 4) -> Dict[str, Any]:
        gaps: List[Dict[str, Any]] = []
        targets = {1: 15, 2: 35, 3: 55, 4: 75, 5: 90}
        target_score = targets.get(target_stage, 75)
        for d in MATURITY_DIMENSIONS:
            cur = self.current_scores[d["id"]]
            gap = target_score - cur
            if gap > 0:
                gaps.append({
                    "dimension": d["name"],
                    "current": cur, "target": target_score, "gap": gap,
                    "missing_capabilities": self._missing_caps(d["id"]),
                })
        gaps.sort(key=lambda x: x["gap"], reverse=True)
        return {
            "target_stage": target_stage,
            "target_score": target_score,
            "gaps": gaps,
            "technical_debt": [
                "VPN 全流量接入未替换",
                "东西向流量未隔离",
                "特权账户未入 PAM",
                "数据分级分类未完成",
            ],
            "organizational_barriers": [
                "业务部门担心零信任影响体验，推动阻力大",
                "安全团队人手不足，自动化程度低",
            ],
        }

    @staticmethod
    def _missing_caps(dim_id: str) -> List[str]:
        table = {
            "identity": ["JIT 即时授权", "身份风险评分", "PAM 全覆盖"],
            "device":   ["BYOD 容器化", "设备指纹", "自动隔离不合规设备"],
            "network":  ["ZTNA 全覆盖", "微隔离默认拒绝", "SDP 端口敲门"],
            "application": ["mTLS 全启用", "服务网格策略", "API 细粒度授权"],
            "data":     ["数据分级分类", "DLP 全链路", "字段级加密"],
            "operations": ["SOAR 自动响应", "持续验证流水线", "策略即代码"],
            "governance": ["零信任度量指标", "季度合规审计", "责任人 RACI"],
            "culture":  ["全员安全意识", "红队演练", "高管 Sponsor"],
        }
        return table.get(dim_id, [])

    # ---------- 路线图 ----------

    def roadmap(self, horizon_months: int = 18) -> Dict[str, Any]:
        return {
            "horizon_months": horizon_months,
            "phases": [
                {"phase": 1, "name": "快速获胜", "months": "0-3",
                 "items": [
                     "特权账户强制硬件 MFA",
                     "休眠/离职账户清理",
                     "生产 DB 直连访问收口",
                 ],
                 "expected_score_gain": 8},
                {"phase": 2, "name": "基础建设", "months": "3-9",
                 "items": [
                     "部署 ZTNA 试点替代 VPN",
                     "服务网格 mTLS 全启用",
                     "EDR/MDM 覆盖全量设备",
                 ],
                 "expected_score_gain": 18},
                {"phase": 3, "name": "全面推广", "months": "9-15",
                 "items": [
                     "微隔离默认拒绝策略",
                     "PAM/JIT 上线",
                     "数据分级与 DLP",
                 ],
                 "expected_score_gain": 20},
                {"phase": 4, "name": "优化自适应", "months": "15-18+",
                 "items": [
                     "AI 风险评分驱动自适应策略",
                     "SOAR 自动响应闭环",
                     "全员零信任文化建设",
                 ],
                 "expected_score_gain": 12},
            ],
            "quick_wins": ["特权 MFA", "清理僵尸账户", "关闭 DMZ 到办公网 any-any"],
            "milestones": [
                {"date": "M3", "name": "身份基线达成"},
                {"date": "M9", "name": "ZTNA 试点上线"},
                {"date": "M15", "name": "微隔离全覆盖"},
                {"date": "M18", "name": "进入阶段 4"},
            ],
            "resource_needs": {
                "headcount": 6,
                "budget_cny_m": 4.5,
                "platforms": ["ZTNA", "PAM", "服务网格", "SOAR"],
            },
        }

    # ---------- 架构评估 ----------

    def architecture_assessment(self) -> Dict[str, Any]:
        return {
            "principles": [
                "从不信任、始终验证",
                "最小权限",
                "假设已被攻破",
                "按身份与设备授权，而非网络位置",
            ],
            "components_coverage": {
                "身份层": "已覆盖",
                "设备层": "部分覆盖",
                "网络层": "试点",
                "应用层": "部分覆盖",
                "数据层": "缺失",
                "自动化编排层": "缺失",
            },
            "integration": {
                "iam_edr_siem_connected": True,
                "policy_orchestration": False,
                "continuous_telemetry": True,
            },
            "automation_level": 0.35,
            "observability": {
                "central_logging": True,
                "user_behavior_analytics": False,
                "threat_detection": True,
            },
            "gaps": [
                "数据层策略缺失",
                "策略编排未自动化",
                "UEBA 未上线",
            ],
        }

    # ---------- 行业对标 ----------

    def benchmark(self, industry: str = "金融") -> Dict[str, Any]:
        cur = self.overall_score()["score"]
        bench = INDUSTRY_BENCHMARK.get(industry, 50)
        return {
            "industry": industry,
            "current_score": cur,
            "benchmark_score": bench,
            "delta": round(cur - bench, 1),
            "vs_industry": "above" if cur >= bench else "below",
        }

    # ---------- 历史 ----------

    def record_snapshot(self) -> Dict[str, Any]:
        snap = {
            "time": datetime.now().isoformat(),
            "overall": self.overall_score(),
            "dimensions": self.dimension_scores(),
        }
        self.history.append(snap)
        return snap

    def list_history(self) -> List[Dict[str, Any]]:
        return self.history[-20:]

    # ---------- 综合报告 ----------

    def full_assessment(self, industry: str = "金融") -> Dict[str, Any]:
        ov = self.overall_score()
        dims = self.dimension_scores()
        gaps = self.gap_analysis()
        road = self.roadmap()
        arch = self.architecture_assessment()
        bench = self.benchmark(industry)
        self.record_snapshot()
        return {
            "report_title": "零信任成熟度评估报告",
            "generated_at": datetime.now().isoformat(),
            "overall": ov,
            "dimensions": dims,
            "gap_analysis": gaps,
            "roadmap": road,
            "architecture": arch,
            "benchmark": bench,
            "maturity_stages": MATURITY_STAGES,
            "summary": (
                f"当前综合成熟度 {ov['score']}/100，处于「{ov['stage_name']}」阶段；"
                f"对比{industry}行业基准 {bench['benchmark_score']}，"
                f"{('领先' if bench['delta'] >= 0 else '落后')} {abs(bench['delta'])} 分；"
                f"差距最大维度为 {gaps['gaps'][0]['dimension'] if gaps['gaps'] else '无'}。"
            ),
        }


# ==================== 工厂函数 ====================

_ztm_singleton: Optional[ZeroTrustMaturityAssessor] = None


def get_zero_trust_maturity_assessor() -> ZeroTrustMaturityAssessor:
    global _ztm_singleton
    if _ztm_singleton is None:
        _ztm_singleton = ZeroTrustMaturityAssessor()
    return _ztm_singleton
