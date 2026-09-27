# -*- coding: utf-8 -*-
"""
kg_dashboard.py — 安全知识图谱控制台数据聚合层。

聚合 7 大模块的关键指标，供前端控制台一次性拉取：
    - 总览指标
    - 图谱质量
    - 攻击路径 Top N
    - 漏洞优先级 Top N
    - 威胁传播摘要
    - 推理引擎状态
    - 问答统计
    - 系统设置
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

try:
    from security_kg.kg_builder import kg_builder
    from security_kg.attack_path import attack_path_engine
    from security_kg.vuln_correlation import vuln_correlation
    from security_kg.threat_propagation import threat_propagation
    from security_kg.reasoning_engine import reasoning_engine
    from security_kg.kg_qa import kg_qa
except Exception:  # pragma: no cover
    kg_builder = None  # type: ignore
    attack_path_engine = None  # type: ignore
    vuln_correlation = None  # type: ignore
    threat_propagation = None  # type: ignore
    reasoning_engine = None  # type: ignore
    kg_qa = None  # type: ignore


SYSTEM_SETTINGS = {
    "graph_name": "企业安全知识图谱 v27",
    "auto_reasoning": True,
    "auto_cleanse": False,
    "max_paths": 50,
    "sir_default_beta": 0.5,
    "sir_default_gamma": 0.1,
    "alert_threshold_p0": 0.75,
    "data_retention_days": 90,
    "language": "zh-CN",
}


class KGDashboard:
    """控制台数据聚合。"""

    def overview(self) -> Dict[str, Any]:
        kg_stats = kg_builder.stats() if kg_builder else {}
        quality = kg_builder.quality_report() if kg_builder else {}
        pri = vuln_correlation.prioritize() if vuln_correlation else []
        urgent = [p for p in pri if p["priority_level"] in ("P0", "P1")]
        sir = threat_propagation.sir() if threat_propagation else {}
        return {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "graph": {
                "nodes": kg_stats.get("nodes", 0),
                "edges": kg_stats.get("edges", 0),
                "density": kg_stats.get("density", 0),
                "quality_score": quality.get("score", 0),
                "quality_grade": quality.get("grade", "N/A"),
            },
            "vulns": {
                "total": len(vuln_correlation.vulns) if vuln_correlation else 0,
                "open": sum(1 for v in (vuln_correlation.vulns.values()
                                         if vuln_correlation else [])
                            if v["status"] == "open"),
                "p0_p1": len(urgent),
            },
            "threat": {
                "sir_peak": sir.get("peak_infected", 0),
                "sir_final_ratio": sir.get("final_infected_ratio", 0),
            },
            "reasoning": {
                "rules": len(reasoning_engine.rules)
                         if reasoning_engine else 0,
                "facts": len(reasoning_engine.facts)
                         if reasoning_engine else 0,
            },
            "qa": (kg_qa.statistics() if kg_qa else {}),
        }

    def graph_section(self) -> Dict[str, Any]:
        return {
            "stats": kg_builder.stats() if kg_builder else {},
            "quality": kg_builder.quality_report() if kg_builder else {},
            "audit": list(reversed(kg_builder._audit[-20:])) if kg_builder else [],
        }

    def attack_path_section(self) -> Dict[str, Any]:
        if attack_path_engine is None or kg_builder is None:
            return {"paths": []}
        # 找一对典型节点
        nodes = list(kg_builder.nodes.values())
        if len(nodes) < 2:
            return {"paths": []}
        src = nodes[0]["id"]
        dst_candidates = [n for n in nodes if n["type"] == "asset"]
        if not dst_candidates:
            return {"paths": []}
        dst = dst_candidates[-1]["id"]
        sp = attack_path_engine.shortest_path(src, dst)
        ap = attack_path_engine.astar_path(src, dst)
        prob = attack_path_engine.probabilistic_path(src, dst)
        all_p = attack_path_engine.all_paths(src, dst)
        return {
            "shortest": sp,
            "astar": ap,
            "probabilistic": prob,
            "all_paths_count": all_p.get("count", 0),
            "visualization": attack_path_engine.visualization_data(),
        }

    def vuln_section(self) -> Dict[str, Any]:
        if vuln_correlation is None:
            return {}
        return {
            "prioritized": vuln_correlation.prioritize(),
            "trend": vuln_correlation.trend(),
            "combined": vuln_correlation.combined_priority(),
            "kb": vuln_correlation.knowledge_base(),
        }

    def propagation_section(self) -> Dict[str, Any]:
        if threat_propagation is None:
            return {}
        return {
            "sir": threat_propagation.sir(),
            "seir": threat_propagation.seir(),
            "blocking": threat_propagation.blocking_strategies("Web"),
            "monte_carlo": threat_propagation.monte_carlo(runs=30),
            "sensitivity": threat_propagation.sensitivity(),
        }

    def reasoning_section(self) -> Dict[str, Any]:
        if reasoning_engine is None:
            return {}
        fc = reasoning_engine.forward_chain()
        return {
            "rules": reasoning_engine.list_rules(),
            "forward_chain": fc,
            "uncertainty": reasoning_engine.uncertain_reasoning(),
            "validate": reasoning_engine.validate(),
            "predict": reasoning_engine.predict_attack(),
            "recommendations": reasoning_engine.recommendations(),
        }

    def qa_section(self) -> Dict[str, Any]:
        if kg_qa is None:
            return {}
        return {
            "faq": kg_qa.list_faq(),
            "statistics": kg_qa.statistics(),
            "history": kg_qa.history_list(limit=10),
        }

    def settings(self) -> Dict[str, Any]:
        return dict(SYSTEM_SETTINGS)

    def update_settings(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        SYSTEM_SETTINGS.update({k: v for k, v in updates.items()
                                if k in SYSTEM_SETTINGS})
        return self.settings()


kg_dashboard = KGDashboard()
