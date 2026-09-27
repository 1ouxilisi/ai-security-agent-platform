# -*- coding: utf-8 -*-
"""
devsecops_maturity.py — DevSecOps 成熟度评估。

覆盖：
    - 5 阶段成熟度模型（初始 / 基础 / 进阶 / 高级 / 优化）
    - 差距分析
    - 工具链评估
    - 流程评估
    - 文化评估
    - 路线图规划
    - 综合报告

设计定位：自评问卷 + 加权评分，输出成熟度等级与改进路线图。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


MATURITY_LEVELS: List[Dict[str, Any]] = [
    {"id": "L1", "name": "初始级", "score_range": [0, 20],
     "desc": "安全靠人肉，上线前一次性审计，工具零散",
     "characteristics": ["无自动化", "事故驱动", "安全是后置闸门"]},
    {"id": "L2", "name": "基础级", "score_range": [21, 40],
     "desc": "SAST/SCA 接入流水线，secret 扫描开始",
     "characteristics": ["pre-commit 雏形", "门禁 advisory", "安全团队独立"]},
    {"id": "L3", "name": "进阶级", "score_range": [41, 60],
     "desc": "CI 强制门禁，镜像扫描，SBOM 起步",
     "characteristics": ["流水线强制门禁", "开发自助修复", "K8s 基线"]},
    {"id": "L4", "name": "高级级", "score_range": [61, 80],
     "desc": "全链路左移 + 运行时联动，IR 闭环",
     "characteristics": ["运行时威胁检测", "SLSA 3+", "自动豁免与度量"]},
    {"id": "L5", "name": "优化级", "score_range": [81, 100],
     "desc": "持续自适应，安全即产品特性",
     "characteristics": ["自适应策略", "零事故文化", "供应链可验证"]},
]

DIMENSIONS = [
    {"id": "toolchain", "name": "工具链", "weight": 0.30},
    {"id": "process", "name": "流程", "weight": 0.25},
    {"id": "culture", "name": "文化", "weight": 0.20},
    {"id": "metrics", "name": "度量", "weight": 0.15},
    {"id": "governance", "name": "治理", "weight": 0.10},
]

TOOLCHAIN_CAPABILITIES = [
    "SAST", "SCA", "Secret Scan", "Container Scan",
    "IaC Scan", "SBOM", "Signing", "Runtime Detection",
    "Supply Chain (SLSA)", "ASM", "WAF", "K8s PSS",
]

ROADMAP = {
    "L1": ["引入 SAST + SCA pre-commit", "建立分支保护",
           "secret 扫描接入 CI"],
    "L2": ["流水线强制门禁 L2", "镜像扫描",
           "SBOM 生成", "安全基线"],
    "L3": ["运行时检测", "制品签名", "RBAC 最小化",
           "度量指标"],
    "L4": ["SLSA 3", "自适应策略", "IR 闭环",
           "供应商风险"],
    "L5": ["持续自适应", "零信任", "供应链验证"],
}


class DevSecOpsMaturity:
    """DevSecOps 成熟度评估器。"""

    def __init__(self) -> None:
        self.history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 主评估
    # ------------------------------------------------------------------ #
    def assess(self, signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        s = signals or {}
        dim_scores = self._dimension_scores(s)
        total = round(sum(d["weighted"] for d in dim_scores), 1)
        level = self._level(total)
        gaps = self._gaps(dim_scores, level)
        roadmap = self._roadmap(level)
        result = {
            "assess_id": uuid.uuid4().hex[:12],
            "total_score": total,
            "level_id": level["id"],
            "level_name": level["name"],
            "level_desc": level["desc"],
            "dimensions": dim_scores,
            "gaps": gaps,
            "roadmap": roadmap,
            "next_level": self._next_level(level["id"]),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.history.append(result)
        return result

    def _dimension_scores(self, s: Dict[str, Any]) -> List[Dict[str, Any]]:
        out = []
        for d in DIMENSIONS:
            raw = float(s.get(d["id"], self._default(d["id"])))
            raw = max(0.0, min(100.0, raw))
            out.append({
                "id": d["id"], "name": d["name"], "weight": d["weight"],
                "raw": raw, "weighted": raw * d["weight"],
            })
        return out

    @staticmethod
    def _default(dim: str) -> float:
        return {"toolchain": 30, "process": 35, "culture": 25,
                "metrics": 20, "governance": 40}.get(dim, 30)

    @staticmethod
    def _level(score: float) -> Dict[str, Any]:
        for lv in MATURITY_LEVELS:
            lo, hi = lv["score_range"]
            if lo <= score <= hi:
                return lv
        return MATURITY_LEVELS[-1]

    def _gaps(self, dims: List[Dict[str, Any]],
               level: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = 100 if level["id"] == "L5" else \
            MATURITY_LEVELS[int(level["id"][1])]["score_range"][0]
        gaps = []
        for d in dims:
            if d["raw"] < target * 0.7:
                gaps.append({"dimension": d["name"], "current": d["raw"],
                             "target": target,
                             "advice": f"{d['name']}维度需提升到{target}"})
        return gaps

    @staticmethod
    def _roadmap(level: Dict[str, Any]) -> List[str]:
        return ROADMAP.get(level["id"], [])

    @staticmethod
    def _next_level(cur_id: str) -> Optional[Dict[str, Any]]:
        idx = int(cur_id[1])
        if idx >= len(MATURITY_LEVELS):
            return None
        return MATURITY_LEVELS[idx]

    # ------------------------------------------------------------------ #
    # 工具链评估
    # ------------------------------------------------------------------ #
    def assess_toolchain(self, present: Optional[List[str]] = None
                         ) -> Dict[str, Any]:
        present = set(present or [])
        rows = [{"capability": c, "present": c in present}
                for c in TOOLCHAIN_CAPABILITIES]
        score = int(100 * sum(1 for r in rows if r["present"]) / len(rows))
        return {
            "capabilities": rows,
            "missing": [r["capability"] for r in rows if not r["present"]],
            "score": score,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 流程评估
    # ------------------------------------------------------------------ #
    def assess_process(self, signals: Optional[Dict[str, Any]] = None
                       ) -> Dict[str, Any]:
        s = signals or {}
        checks = [
            ("security_requirements", "安全需求纳入需求阶段", s.get("security_requirements", False)),
            ("threat_model", "威胁建模", s.get("threat_model", False)),
            ("pre_commit", "pre-commit 钩子", s.get("pre_commit", False)),
            ("ci_gate", "CI 门禁", s.get("ci_gate", False)),
            ("cd_approval", "CD 审批", s.get("cd_approval", True)),
            ("incident_playbook", "应急响应手册", s.get("incident_playbook", False)),
            ("retro", "事故复盘", s.get("retro", True)),
        ]
        passed = sum(1 for c in checks if c[2])
        return {
            "checks": [{"id": c[0], "name": c[0], "passed": c[2]} for c in checks],
            "passed": passed, "total": len(checks),
            "score": int(100 * passed / len(checks)),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 文化评估
    # ------------------------------------------------------------------ #
    def assess_culture(self, signals: Optional[Dict[str, Any]] = None
                       ) -> Dict[str, Any]:
        s = signals or {}
        checks = [
            ("training", "开发安全培训", s.get("training", False)),
            ("champion", "安全布道官", s.get("champion", False)),
            ("blameless", "无责复盘", s.get("blameless", True)),
            ("time_for_remediation", "修复时间被排期", s.get("time_for_remediation", False)),
            ("shared_ownership", "安全共担", s.get("shared_ownership", False)),
        ]
        passed = sum(1 for c in checks if c[2])
        return {
            "checks": [{"id": c[0], "passed": c[2]} for c in checks],
            "passed": passed, "total": len(checks),
            "score": int(100 * passed / len(checks)),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 报告
    # ------------------------------------------------------------------ #
    def get_report_markdown(self, result: Dict[str, Any]) -> str:
        lines = [
            "# DevSecOps 成熟度评估报告", "",
            f"- 评估 ID: {result.get('assess_id')}",
            f"- 总分: {result.get('total_score')}",
            f"- 等级: {result.get('level_name')}",
            f"- 描述: {result.get('level_desc')}", "",
            "## 各维度得分",
        ]
        for d in result.get("dimensions", []):
            lines.append(f"- {d['name']}: {d['raw']} (权重 {d['weight']})")
        lines += ["", "## 差距",
                  *(f"- {g['dimension']}: {g['advice']}" for g in result.get("gaps", []))]
        lines += ["", "## 下一步路线图",
                  *(f"- {r}" for r in result.get("roadmap", []))]
        return "\n".join(lines)

    def list_history(self) -> List[Dict[str, Any]]:
        return self.history

    def list_levels(self) -> List[Dict[str, Any]]:
        return MATURITY_LEVELS


_instance: Optional[DevSecOpsMaturity] = None


def get_devsecops_maturity() -> DevSecOpsMaturity:
    global _instance
    if _instance is None:
        _instance = DevSecOpsMaturity()
    return _instance
