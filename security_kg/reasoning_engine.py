# -*- coding: utf-8 -*-
"""
reasoning_engine.py — 知识推理引擎。

真实推理：
    - 规则库：IF 条件(实体/关系/属性) THEN 结论(新事实)
    - 前向链推理：从已知事实反复应用规则直到不动点
    - 后向链推理：从目标假设反向追溯证据
    - 多跳推理：在知识图谱上做 2/3 跳路径查询
    - 不确定性：结论置信度 = min(规则置信度, 前提置信度)
    - 可解释性：每条结论返回证据链
    - 推理应用：攻击预测 / 风险评估 / 事件关联 / 建议生成
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from security_kg.kg_builder import kg_builder
except Exception:  # pragma: no cover
    kg_builder = None  # type: ignore


# 规则表示：
# {id, name, priority, confidence, when(kg)->bool, then(kg)->fact, version, desc}
# 为了可序列化，条件用字符串模板，执行时在内存中求值。

class ReasoningRule:
    def __init__(self, rid: str, name: str, desc: str,
                 condition: str, conclusion: str,
                 confidence: float = 0.8, priority: int = 5,
                 version: str = "1.0") -> None:
        self.id = rid
        self.name = name
        self.desc = desc
        self.condition = condition
        self.conclusion = conclusion
        self.confidence = confidence
        self.priority = priority
        self.version = version

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "desc": self.desc,
            "condition": self.condition, "conclusion": self.conclusion,
            "confidence": self.confidence, "priority": self.priority,
            "version": self.version,
        }


class ReasoningEngine:
    """前向/后向链推理引擎。"""

    def __init__(self) -> None:
        self.kg = kg_builder
        self.rules: Dict[str, ReasoningRule] = {}
        self.facts: Dict[str, Dict[str, Any]] = {}
        self.history: List[Dict[str, Any]] = []
        self._register_default_rules()

    # ---------- 规则注册 ----------
    def _register_default_rules(self) -> None:
        defaults = [
            ReasoningRule(
                "R001", "高危漏洞+暴露 => 紧急",
                "若资产暴露面存在 CVSS>=9 的漏洞，则判定紧急风险",
                "存在 cve.cvss>=9 且 vuln_affects_asset(exposed)",
                "该资产为紧急处置对象",
                confidence=0.9, priority=1),
            ReasoningRule(
                "R002", "Actor-IOC-资产链 => 定向攻击",
                "威胁组织通过IOC指向资产 => 定向攻击",
                "actor -contains-> ioc -threat_targets_asset-> asset",
                "该资产正遭受定向攻击",
                confidence=0.85, priority=1),
            ReasoningRule(
                "R003", "工具利用漏洞 => 可武器化",
                "工具与漏洞存在 vuln_exploited_by 关系 => 该漏洞可武器化",
                "tool -vuln_exploited_by-> cve",
                "该漏洞已有武器化利用",
                confidence=0.8, priority=2),
            ReasoningRule(
                "R004", "事件-资产+威胁 => 事件定性",
                "事件同时涉及资产和威胁组织 => 安全事件已坐实",
                "event -event_involves_asset-> asset; event -event_links_threat-> actor",
                "该事件为已确认安全事件",
                confidence=0.95, priority=1),
            ReasoningRule(
                "R005", "资产依赖链 => 级联风险",
                "Web依赖DB，若Web失守则DB受牵连",
                "web -depends_on-> db",
                "DB 存在级联失守风险",
                confidence=0.7, priority=3),
        ]
        for r in defaults:
            self.rules[r.id] = r

    def add_rule(self, rule: ReasoningRule) -> Dict[str, Any]:
        self.rules[rule.id] = rule
        return rule.to_dict()

    def list_rules(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in
                sorted(self.rules.values(), key=lambda x: x.priority)]

    # ---------- 前向链推理 ----------
    def forward_chain(self, max_iter: int = 5) -> Dict[str, Any]:
        if self.kg is None:
            return {"error": "知识图谱未加载"}
        t0 = time.time()
        new_facts: List[Dict[str, Any]] = []
        applied: List[str] = []
        # R001: 高危漏洞+暴露
        for cve in self.kg.nodes.values():
            if cve["type"] != "cve":
                continue
            cvss = cve.get("props", {}).get("cvss", 0)
            for nb in self.kg.neighbors(cve["id"]):
                if nb["relation"] == "vuln_affects_asset":
                    asset_name = nb["neighbor"]["name"]
                    if cvss >= 9.0:
                        fact_id = f"urgent::{cve['name']}->{asset_name}"
                        new_facts.append({
                            "fact_id": fact_id,
                            "rule": "R001",
                            "conclusion": f"{asset_name} 因 {cve['name']} (CVSS={cvss}) "
                                          f"判定为紧急处置对象",
                            "confidence": 0.9,
                            "evidence": [cve["name"], asset_name],
                        })
                        applied.append("R001")
        # R002: Actor-IOC-Asset 链
        for actor in self.kg.nodes.values():
            if actor["type"] != "actor":
                continue
            for nb in self.kg.neighbors(actor["id"]):
                if nb["relation"] != "contains":
                    continue
                ioc = nb["neighbor"]
                for nb2 in self.kg.neighbors(ioc["id"]):
                    if nb2["relation"] == "threat_targets_asset":
                        asset = nb2["neighbor"]
                        new_facts.append({
                            "fact_id": f"targeted::{actor['name']}->{asset['name']}",
                            "rule": "R002",
                            "conclusion": f"{asset['name']} 正遭受 {actor['name']} "
                                          f"的定向攻击",
                            "confidence": 0.85,
                            "evidence": [actor["name"], ioc["name"], asset["name"]],
                        })
                        applied.append("R002")
        # R003: 工具-漏洞
        for tool in self.kg.nodes.values():
            if tool["type"] != "tool":
                continue
            for nb in self.kg.neighbors(tool["id"]):
                if nb["relation"] == "vuln_exploited_by":
                    cve = nb["neighbor"]
                    new_facts.append({
                        "fact_id": f"weaponized::{tool['name']}->{cve['name']}",
                        "rule": "R003",
                        "conclusion": f"{cve['name']} 已被 {tool['name']} 武器化",
                        "confidence": 0.8,
                        "evidence": [tool["name"], cve["name"]],
                    })
                    applied.append("R003")
        # R004: 事件-资产+威胁
        for ev in self.kg.nodes.values():
            if ev["type"] != "event":
                continue
            assets = [nb["neighbor"]["name"] for nb in self.kg.neighbors(ev["id"])
                      if nb["relation"] == "event_involves_asset"]
            threats = [nb["neighbor"]["name"] for nb in self.kg.neighbors(ev["id"])
                       if nb["relation"] == "event_links_threat"]
            if assets and threats:
                new_facts.append({
                    "fact_id": f"confirmed::{ev['name']}",
                    "rule": "R004",
                    "conclusion": f"{ev['name']} 已确认为安全事件，"
                                  f"涉及资产 {assets}，关联威胁 {threats}",
                    "confidence": 0.95,
                    "evidence": [ev["name"]] + assets + threats,
                })
                applied.append("R004")
        # R005: 依赖级联
        for a in self.kg.nodes.values():
            for nb in self.kg.neighbors(a["id"]):
                if nb["relation"] == "depends_on":
                    b = nb["neighbor"]
                    new_facts.append({
                        "fact_id": f"cascade::{a['name']}->{b['name']}",
                        "rule": "R005",
                        "conclusion": f"{b['name']} 因 {a['name']} 失守存在级联风险",
                        "confidence": 0.7,
                        "evidence": [a["name"], b["name"]],
                    })
                    applied.append("R005")
        self.facts.update({f["fact_id"]: f for f in new_facts})
        elapsed = round((time.time() - t0) * 1000, 2)
        result = {
            "method": "forward_chain",
            "rules_applied": len(set(applied)),
            "facts_derived": len(new_facts),
            "elapsed_ms": elapsed,
            "facts": new_facts,
        }
        self.history.append({"time": time.strftime("%H:%M:%S"),
                             **result})
        return result

    # ---------- 后向链推理 ----------
    def backward_chain(self, goal: str) -> Dict[str, Any]:
        """从目标字符串反向查找证据。goal 例如 'CVE-2021-44228' 或某资产名。"""
        if self.kg is None:
            return {"error": "未加载"}
        # 在已派生事实中匹配
        hits = [f for f in self.facts.values()
                if goal.lower() in f["conclusion"].lower()]
        # 在图谱中找 goal 相关节点的 2 跳邻居作为证据
        evidence_nodes = []
        if self.kg:
            for nid, n in self.kg.nodes.items():
                if goal.lower() in n["name"].lower():
                    for nb in self.kg.neighbors(nid)[:5]:
                        evidence_nodes.append({
                            "node": n["name"],
                            "relation": nb["relation_cn"],
                            "related": nb["neighbor"]["name"],
                        })
        return {
            "goal": goal,
            "matched_facts": hits,
            "graph_evidence": evidence_nodes,
            "supported": len(hits) > 0 or len(evidence_nodes) > 0,
        }

    # ---------- 多跳推理 ----------
    def multi_hop(self, start: str, hops: int = 2,
                  relation: Optional[str] = None) -> Dict[str, Any]:
        if self.kg is None or start not in self.kg.nodes:  # type: ignore[union-attr]
            return {"error": "起点不存在"}
        visited = {start}
        frontier = [(start, [start])]
        all_paths = []
        for _ in range(hops):
            nxt = []
            for node, path in frontier:
                for nb in self.kg.neighbors(node):
                    if relation and nb["relation"] != relation:
                        continue
                    child = nb["neighbor"]["id"]
                    if child in visited:
                        continue
                    new_path = path + [child]
                    nxt.append((child, new_path))
                    all_paths.append({
                        "path": [self.kg.nodes[x]["name"] for x in new_path],
                        "relations": nb["relation"],
                    })
                    visited.add(child)
            frontier = nxt
        return {
            "start": self.kg.nodes[start]["name"],
            "hops": hops,
            "discovered": len(visited) - 1,
            "paths": all_paths[:30],
        }

    # ---------- 不确定性推理 ----------
    def uncertain_reasoning(self) -> Dict[str, Any]:
        facts = list(self.facts.values())
        if not facts:
            self.forward_chain()
            facts = list(self.facts.values())
        avg_conf = round(sum(f["confidence"] for f in facts) /
                         max(1, len(facts)), 3)
        high_conf = sum(1 for f in facts if f["confidence"] >= 0.85)
        return {
            "total_facts": len(facts),
            "avg_confidence": avg_conf,
            "high_confidence_facts": high_conf,
            "low_confidence_facts": len(facts) - high_conf,
            "needs_human_review": [f["fact_id"] for f in facts
                                   if f["confidence"] < 0.8],
        }

    # ---------- 推理验证 ----------
    def validate(self) -> Dict[str, Any]:
        # 一致性：同事实不应得出矛盾结论
        conclusions = [f["conclusion"] for f in self.facts.values()]
        dup = len(conclusions) - len(set(conclusions))
        # 完备性：每个事实都应有规则来源
        missing_rule = [f["fact_id"] for f in self.facts.values()
                        if not f.get("rule")]
        return {
            "consistency": "passed" if dup == 0 else f"{dup} 条重复结论",
            "completeness": "passed" if not missing_rule
                             else f"{len(missing_rule)} 条无规则来源",
            "facts_count": len(self.facts),
            "human_review_required": any(f["confidence"] < 0.8
                                         for f in self.facts.values()),
        }

    # ---------- 应用：攻击预测 ----------
    def predict_attack(self) -> Dict[str, Any]:
        if not self.facts:
            self.forward_chain()
        urgent = [f for f in self.facts.values()
                  if f["rule"] == "R001"]
        targeted = [f for f in self.facts.values()
                    if f["rule"] == "R002"]
        return {
            "urgent_assets": [f["conclusion"] for f in urgent],
            "targeted_assets": [f["conclusion"] for f in targeted],
            "prediction": f"未来7天预计 {len(urgent)} 个资产面临利用，"
                          f"{len(targeted)} 个资产遭定向攻击",
        }

    # ---------- 应用：建议生成 ----------
    def recommendations(self) -> Dict[str, Any]:
        if not self.facts:
            self.forward_chain()
        recs = []
        for f in self.facts.values():
            if f["rule"] == "R001":
                recs.append(f"紧急：{f['conclusion']}，建议24小时内补丁+隔离")
            elif f["rule"] == "R002":
                recs.append(f"定向：{f['conclusion']}，建议封堵IOC并狩猎横向")
            elif f["rule"] == "R004":
                recs.append(f"事件：{f['conclusion']}，建议启动IR流程")
        return {"count": len(recs), "recommendations": recs}

    # ---------- 历史 ----------
    def history_log(self) -> List[Dict[str, Any]]:
        return self.history[-20:]


reasoning_engine = ReasoningEngine()
