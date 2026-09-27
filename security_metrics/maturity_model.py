#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
maturity_model.py — 安全成熟度模型（CMMI 式 5 级）。

覆盖：
    - 5 级成熟度：1 初始级 / 2 可重复级 / 3 已定义级 / 4 量化管理级 / 5 优化级
    - 5 大维度：治理 Governance / 技术 Technology / 运营 Operations / 人员 People / 合规 Compliance
    - 成熟度问卷（每维度若干问题，1-5 分自评）
    - 综合成熟度评级、雷达图数据、差距分析、改进路线图、行业对标、成熟度报告
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 成熟度等级定义
# --------------------------------------------------------------------------- #
MATURITY_LEVELS: Dict[int, Dict[str, Any]] = {
    1: {
        "level": 1, "name": "初始级", "name_en": "Initial",
        "color": "#ff4d4f", "score_range": (0, 1.49),
        "desc": "安全工作零散、被动响应，依赖个别英雄，过程不可重复、不可预测。",
        "characteristics": ["事件驱动、无成文流程", "工具零散、数据孤岛", "无专职安全团队"],
    },
    2: {
        "level": 2, "name": "可重复级", "name_en": "Repeatable",
        "color": "#fa8c16", "score_range": (1.5, 2.49),
        "desc": "建立了基本的项目级过程，类似活动可重复，但标准尚不统一。",
        "characteristics": ["有漏洞管理/补丁流程", "基础日志与告警", "安全责任初步明确"],
    },
    3: {
        "level": 3, "name": "已定义级", "name_en": "Defined",
        "color": "#fadb14", "score_range": (2.5, 3.49),
        "desc": "过程已文档化、标准化，全组织统一推行，有明确策略与培训体系。",
        "characteristics": ["信息安全策略成文", "安全开发生命周期 SDL", "全员安全意识培训"],
    },
    4: {
        "level": 4, "name": "量化管理级", "name_en": "Quantitatively Managed",
        "color": "#1890ff", "score_range": (3.5, 4.49),
        "desc": "用度量与统计技术量化管理安全过程，关键指标可预测、可控制。",
        "characteristics": ["MTTD/MTTR 等 SLA 量化", "风险量化建模", "持续度量与趋势分析"],
    },
    5: {
        "level": 5, "name": "优化级", "name_en": "Optimizing",
        "color": "#52c41a", "score_range": (4.5, 5.0),
        "desc": "以持续改进为核心，通过创新与技术改进不断优化过程与安全效能。",
        "characteristics": ["安全自动化与编排", "威胁情报驱动运营", "持续优化与自适应防御"],
    },
}


# --------------------------------------------------------------------------- #
# 成熟度维度定义
# --------------------------------------------------------------------------- #
MATURITY_DIMENSIONS: Dict[str, Dict[str, Any]] = {
    "governance": {
        "key": "governance", "name": "治理 Governance", "weight": 0.25,
        "questions": [
            {"id": "g1", "text": "是否有经董事会/CISO 签署的正式信息安全策略？", "hint": "策略是否成文、审批、定期评审"},
            {"id": "g2", "text": "安全组织、职责与汇报线是否明确（RACI）？", "hint": "CISO 对管理层汇报路径"},
            {"id": "g3", "text": "是否建立年度安全风险评估与治理流程？", "hint": "风险登记册、治理委员会"},
            {"id": "g4", "text": "安全预算是否与业务风险挂钩并年度审批？", "hint": "安全投入占比与 ROI 度量"},
            {"id": "g5", "text": "是否有供应商/第三方安全治理与尽职调查？", "hint": "第三方风险评估流程"},
        ],
    },
    "technology": {
        "key": "technology", "name": "技术 Technology", "weight": 0.25,
        "questions": [
            {"id": "t1", "text": "网络边界与终端防护是否统一部署并策略集中管理？", "hint": "NGFW/EDR 覆盖率"},
            {"id": "t2", "text": "是否具备集中日志/SIEM 与实时检测能力？", "hint": "日志保留与关联分析"},
            {"id": "t3", "text": "开发流程是否集成安全测试（SAST/DAST/SCA）？", "hint": "CI/CD 安全门禁"},
            {"id": "t4", "text": "身份与访问管理是否实现 MFA/最小权限？", "hint": "零信任/特权账号管理 PAM"},
            {"id": "t5", "text": "数据加密（传输/存储/密钥管理）是否体系化？", "hint": "KMS、TDE、BYOK"},
        ],
    },
    "operations": {
        "key": "operations", "name": "运营 Operations", "weight": 0.20,
        "questions": [
            {"id": "o1", "text": "是否有 7x24 安全监控值班与事件响应流程？", "hint": "IR Playbook、升级路径"},
            {"id": "o2", "text": "漏洞是否按 SLA 分级闭环（发现→修复→验证）？", "hint": "修复时限与逾期率"},
            {"id": "o3", "text": "是否定期开展渗透测试与红蓝对抗？", "hint": "测试频率与复盘"},
            {"id": "o4", "text": "备份与恢复是否定期演练？", "hint": "RTO/RPO 达成率"},
            {"id": "o5", "text": "告警是否经过降噪、自动化编排（SOAR）？", "hint": "误报率、自动化处置率"},
        ],
    },
    "people": {
        "key": "people", "name": "人员 People", "weight": 0.15,
        "questions": [
            {"id": "p1", "text": "全员是否完成年度安全意识培训并考试？", "hint": "培训覆盖率与通过率"},
            {"id": "p2", "text": "关键岗位是否有安全技能认证与梯队建设？", "hint": "CISSP/CISA 等持证比例"},
            {"id": "p3", "text": "是否建立安全考核与激励机制？", "hint": "KPI 与绩效挂钩"},
            {"id": "p4", "text": "新员工入职是否包含安全合规培训？", "hint": "入职安全合规率"},
            {"id": "p5", "text": "是否有钓鱼演练与报告渠道？", "hint": "点击率、误报/举报率"},
        ],
    },
    "compliance": {
        "key": "compliance", "name": "合规 Compliance", "weight": 0.15,
        "questions": [
            {"id": "c1", "text": "是否映射适用法规框架（等保/ISO27001/GDPR 等）？", "hint": "框架差距分析"},
            {"id": "c2", "text": "控制项是否有证据留存并定期内审？", "hint": "审计证据链完整度"},
            {"id": "c3", "text": "审计发现是否按期整改闭环？", "hint": "整改率与逾期率"},
            {"id": "c4", "text": "隐私影响评估（PIA/DPIA）是否嵌入业务流程？", "hint": "隐私-by-design"},
            {"id": "c5", "text": "是否具备外部审计/认证维护能力？", "hint": "ISO/SOC2 认证维持"},
        ],
    },
}


# 行业对标基准（成熟度均值，用于雷达图对比）
INDUSTRY_BENCHMARKS: Dict[str, Dict[str, float]] = {
    "金融": {"governance": 3.8, "technology": 3.9, "operations": 3.7, "people": 3.5, "compliance": 4.1},
    "互联网": {"governance": 3.4, "technology": 4.2, "operations": 4.0, "people": 3.3, "compliance": 3.2},
    "制造": {"governance": 2.6, "technology": 2.5, "operations": 2.4, "people": 2.3, "compliance": 2.7},
    "医疗": {"governance": 2.9, "technology": 2.7, "operations": 2.6, "people": 2.5, "compliance": 3.2},
    "政府": {"governance": 3.5, "technology": 3.1, "operations": 3.0, "people": 3.2, "compliance": 3.8},
    "零售": {"governance": 2.4, "technology": 2.3, "operations": 2.2, "people": 2.1, "compliance": 2.5},
}


class SecurityMaturityModel:
    """安全成熟度评估器。"""

    def __init__(self) -> None:
        self._sessions: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    # 问卷
    # ------------------------------------------------------------------ #
    def get_questionnaire(self) -> Dict[str, Any]:
        """返回完整成熟度问卷。"""
        dims: List[Dict[str, Any]] = []
        total = 0
        for key, dim in MATURITY_DIMENSIONS.items():
            dims.append({
                "key": key, "name": dim["name"], "weight": dim["weight"],
                "question_count": len(dim["questions"]),
                "questions": dim["questions"],
            })
            total += len(dim["questions"])
        return {
            "framework": "CMMI-Security v1.0 (5 levels x 5 dimensions)",
            "levels": MATURITY_LEVELS,
            "dimensions": dims, "total_questions": total,
            "scoring": "每题 1-5 分，维度均分=问题均分，总分=加权维度均分",
        }

    # ------------------------------------------------------------------ #
    # 评估
    # ------------------------------------------------------------------ #
    def assess(self, answers: Optional[Dict[str, int]] = None,
               industry: str = "金融") -> Dict[str, Any]:
        """
        根据问卷答案评估成熟度。

        answers: {question_id: score(1-5)}；缺省时用一组合理的模拟分。
        """
        if answers is None:
            answers = self._demo_answers()

        # 维度均分
        dim_scores: Dict[str, float] = {}
        dim_details: Dict[str, Any] = {}
        for dkey, dim in MATURITY_DIMENSIONS.items():
            vals = [answers.get(q["id"], 3) for q in dim["questions"]]
            avg = round(sum(vals) / len(vals), 2)
            dim_scores[dkey] = avg
            dim_details[dkey] = {
                "name": dim["name"], "score": avg, "weight": dim["weight"],
                "answered": sum(1 for q in dim["questions"] if q["id"] in answers),
                "total": len(dim["questions"]),
                "weighted": round(avg * dim["weight"], 3),
            }

        overall = round(sum(dim_scores[k] * MATURITY_DIMENSIONS[k]["weight"]
                            for k in dim_scores), 2)
        level = self._score_to_level(overall)

        bench = INDUSTRY_BENCHMARKS.get(industry, INDUSTRY_BENCHMARKS["金融"])
        gaps: List[Dict[str, Any]] = []
        for k in MATURITY_DIMENSIONS:
            g = round(dim_scores[k] - bench.get(k, 3.0), 2)
            gaps.append({
                "dimension": MATURITY_DIMENSIONS[k]["name"],
                "score": dim_scores[k], "benchmark": bench.get(k, 3.0),
                "gap": g, "status": "ahead" if g >= 0 else "behind",
            })

        roadmap = self._build_roadmap(level, dim_details)
        report = self._build_report(overall, level, dim_details, gaps, industry)

        sid = uuid.uuid4().hex[:12]
        result = {
            "assessment_id": sid, "assessed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "industry": industry,
            "overall_score": overall, "maturity_level": level,
            "level_name": MATURITY_LEVELS[level]["name"],
            "level_name_en": MATURITY_LEVELS[level]["name_en"],
            "dimension_scores": dim_scores,
            "dimension_details": dim_details,
            "radar": {
                "labels": [MATURITY_DIMENSIONS[k]["name"] for k in MATURITY_DIMENSIONS],
                "current": [dim_scores[k] for k in MATURITY_DIMENSIONS],
                "benchmark": [bench.get(k, 3.0) for k in MATURITY_DIMENSIONS],
            },
            "gap_analysis": gaps,
            "roadmap": roadmap,
            "report_markdown": report,
        }
        self._sessions[sid] = result
        return result

    def _demo_answers(self) -> Dict[str, int]:
        base = {"g1": 4, "g2": 4, "g3": 3, "g4": 3, "g5": 3,
                "t1": 4, "t2": 4, "t3": 3, "t4": 4, "t5": 3,
                "o1": 3, "o2": 3, "o3": 3, "o4": 2, "o5": 2,
                "p1": 3, "p2": 2, "p3": 2, "p4": 4, "p5": 3,
                "c1": 4, "c2": 3, "c3": 3, "c4": 2, "c5": 3}
        return base

    @staticmethod
    def _score_to_level(score: float) -> int:
        for lv, info in MATURITY_LEVELS.items():
            lo, hi = info["score_range"]
            if lo <= score <= hi:
                return lv
        return 5 if score > 4.49 else 1

    # ------------------------------------------------------------------ #
    # 路线图
    # ------------------------------------------------------------------ #
    def _build_roadmap(self, current_level: int,
                       details: Dict[str, Any]) -> List[Dict[str, Any]]:
        next_lv = min(current_level + 1, 5)
        # 找出得分最低的两个维度优先改进
        weak = sorted(details.items(), key=lambda kv: kv[1]["score"])[:2]
        roadmap: List[Dict[str, Any]] = []
        horizons = [("0-6 个月（短期）", "quick_win"),
                    ("6-18 个月（中期）", "foundation"),
                    ("18-36 个月（长期）", "strategic")]
        actions = {
            "quick_win": ["补齐最弱维度的缺失控制项", "建立关键 KPI 度量与周报",
                          "完成全员安全意识培训补课"],
            "foundation": ["统一安全工具链与数据中台", "落地 SDL 与 CI/CD 安全门禁",
                           "建立 7x24 监控值班与 IR 演练"],
            "strategic": ["推进量化管理与风险建模", "建设 SOAR 自动化编排",
                          "对标行业头部，冲击优化级"],
        }
        for i, (horizon, kind) in enumerate(horizons):
            roadmap.append({
                "phase": horizon, "target_level": next_lv,
                "weak_dimensions": [d[1]["name"] for d in weak],
                "actions": actions[kind],
                "kpi_expectation": f"维度均分提升至 {round(2.5 + i * 0.8, 1)}+",
            })
        return roadmap

    # ------------------------------------------------------------------ #
    # 报告
    # ------------------------------------------------------------------ #
    def _build_report(self, overall: float, level: int,
                      details: Dict[str, Any], gaps: List[Dict[str, Any]],
                      industry: str) -> str:
        lv = MATURITY_LEVELS[level]
        lines = [
            f"# 安全成熟度评估报告",
            f"",
            f"- 评估时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"- 对标行业：{industry}",
            f"- 综合成熟度得分：**{overall} / 5.0**",
            f"- 成熟度等级：**{level} 级 - {lv['name']}（{lv['name_en']}）**",
            f"- 等级说明：{lv['desc']}",
            f"",
            f"## 维度得分",
        ]
        for k, d in details.items():
            lines.append(f"- {d['name']}：{d['score']}（权重 {d['weight']}）")
        lines += ["", "## 行业对标差距"]
        for g in gaps:
            arrow = "领先" if g["gap"] >= 0 else "落后"
            lines.append(f"- {g['dimension']}：{g['score']} vs 行业 {g['benchmark']}（{arrow} {abs(g['gap'])}）")
        lines += ["", "## 改进建议",
                  "1. 优先补强得分最低维度，6 个月内完成 quick win；",
                  "2. 建立量化度量体系，为冲击下一成熟度等级打基础；",
                  "3. 每半年复评一次，跟踪路线图进展。"]
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # 行业对标
    # ------------------------------------------------------------------ #
    def list_benchmarks(self) -> Dict[str, Any]:
        return {
            "industries": list(INDUSTRY_BENCHMARKS.keys()),
            "benchmarks": INDUSTRY_BENCHMARKS,
        }

    def get_session(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        return self._sessions.get(assessment_id)
