# -*- coding: utf-8 -*-
"""
attack_path.py — 攻击路径推理引擎。

真实算法：
    - 基于知识图谱邻接表构建有向攻击图
    - Dijkstra 最短路径
    - A* 启发式搜索（启发式 = 目标节点类型权重 + 已探索代价）
    - 枚举所有简单路径（DFS，深度受限）
    - 概率路径（边概率乘积最大）
    - 风险路径（边风险加权和最小）
    - 路径分析（长度/复杂度/概率/风险/瓶颈/关键节点）
    - 下一步攻击预测 / 杀伤链映射 / 攻击树 / 可视化数据
"""
from __future__ import annotations

import heapq
import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

try:
    from security_kg.kg_builder import kg_builder
except Exception:  # pragma: no cover
    kg_builder = None  # type: ignore


# ATT&CK 杀伤链阶段（简化映射）
KILL_CHAIN = [
    ("reconnaissance", "侦察"),
    ("weaponization", "武器化"),
    ("delivery", "投递"),
    ("exploitation", "利用"),
    ("installation", "安装"),
    ("command_and_control", "命令控制"),
    ("actions_on_objectives", "目标行动"),
]

# 节点类型启发式权重（越接近"核心资产"启发值越低，利于 A*）
_TYPE_HEURISTIC = {
    "asset": 1.0, "cve": 2.0, "ioc": 3.0, "actor": 4.0,
    "tool": 2.5, "event": 3.0, "attack_tech": 2.0,
    "attack_tactic": 1.5, "person": 5.0, "org": 5.0,
    "domain": 3.0, "ip": 2.5, "port": 2.0, "service": 1.8,
    "cwe": 2.2,
}


class AttackPathEngine:
    """攻击路径推理。"""

    def __init__(self) -> None:
        self.kg = kg_builder

    # ---------- 构建有向攻击图 ----------
    def _build_graph(self) -> Tuple[Dict[str, List[Tuple[str, float, str]]],
                                    Dict[str, Dict[str, Any]]]:
        """返回 adj[src] = [(dst, cost, relation)] 以及 nodes 元数据。"""
        adj: Dict[str, List[Tuple[str, float, str]]] = defaultdict(list)
        nodes: Dict[str, Dict[str, Any]] = {}
        if self.kg is None:
            return adj, nodes
        for nid, node in self.kg.nodes.items():
            nodes[nid] = node
        for e in self.kg.edges:
            # 所有边都视为可攻击（无向图搜索更合理）
            conf = e.get("confidence", 0.9)
            cost = 1.0 / max(0.05, conf)
            adj[e["source"]].append((e["target"], cost, e["relation"]))
            adj[e["target"]].append((e["source"], cost, e["relation"]))
        return adj, nodes

    # ---------- Dijkstra 最短路径 ----------
    def shortest_path(self, src: str, dst: str) -> Dict[str, Any]:
        adj, nodes = self._build_graph()
        if src not in nodes or dst not in nodes:
            return {"found": False, "error": "源或目标节点不存在"}
        dist = {src: 0.0}
        prev: Dict[str, Optional[str]] = {}
        pq: List[Tuple[float, str]] = [(0.0, src)]
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist.get(u, float("inf")):
                continue
            if u == dst:
                break
            for v, w, _rel in adj.get(u, []):
                nd = d + w
                if nd < dist.get(v, float("inf")):
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))
        if dst not in dist:
            return {"found": False, "path": [], "cost": None}
        # 回溯
        path = [dst]
        while path[-1] != src:
            path.append(prev[path[-1]])
        path.reverse()
        return {
            "found": True,
            "path": path,
            "cost": round(dist[dst], 3),
            "length": len(path) - 1,
            "nodes": [nodes[p] for p in path],
        }

    # ---------- A* 启发式搜索 ----------
    def astar_path(self, src: str, dst: str) -> Dict[str, Any]:
        adj, nodes = self._build_graph()
        if src not in nodes or dst not in nodes:
            return {"found": False, "error": "节点不存在"}

        def h(n: str) -> float:
            t = nodes.get(n, {}).get("type", "")
            base = _TYPE_HEURISTIC.get(t, 3.0)
            return base

        g = {src: 0.0}
        f = {src: h(src)}
        prev: Dict[str, Optional[str]] = {}
        open_heap: List[Tuple[float, str]] = [(f[src], src)]
        closed = set()
        while open_heap:
            _, u = heapq.heappop(open_heap)
            if u in closed:
                continue
            if u == dst:
                path = [dst]
                while path[-1] != src:
                    path.append(prev[path[-1]])
                path.reverse()
                return {
                    "found": True, "algorithm": "A*",
                    "path": path, "g_cost": round(g[dst], 3),
                    "length": len(path) - 1,
                    "nodes": [nodes[p] for p in path],
                    "explored": len(closed) + 1,
                }
            closed.add(u)
            for v, w, _rel in adj.get(u, []):
                if v in closed:
                    continue
                ng = g[u] + w
                if ng < g.get(v, float("inf")):
                    g[v] = ng
                    prev[v] = u
                    heapq.heappush(open_heap, (ng + h(v), v))
        return {"found": False, "algorithm": "A*",
                "explored": len(closed)}

    # ---------- 枚举所有简单路径（深度受限） ----------
    def all_paths(self, src: str, dst: str,
                  max_depth: int = 6, limit: int = 50) -> Dict[str, Any]:
        adj, nodes = self._build_graph()
        if src not in nodes or dst not in nodes:
            return {"paths": [], "error": "节点不存在"}
        results: List[List[str]] = []

        def dfs(cur: str, visited: set, path: List[str]) -> None:
            if len(results) >= limit:
                return
            if len(path) > max_depth:
                return
            if cur == dst:
                results.append(list(path))
                return
            for v, _w, _r in adj.get(cur, []):
                if v in visited:
                    continue
                visited.add(v)
                path.append(v)
                dfs(v, visited, path)
                path.pop()
                visited.remove(v)

        dfs(src, {src}, [src])
        results.sort(key=len)
        return {
            "count": len(results),
            "paths": [
                {"path": p, "length": len(p) - 1,
                 "nodes": [nodes[x]["name"] for x in p]}
                for p in results
            ],
        }

    # ---------- 概率路径（边概率乘积最大） ----------
    def probabilistic_path(self, src: str, dst: str) -> Dict[str, Any]:
        # 用对数概率把乘积变求和，最大化 log P
        adj, nodes = self._build_graph()
        if src not in nodes or dst not in nodes:
            return {"found": False}
        # 边概率 = confidence
        # 负对数概率作为 Dijkstra 权重
        def cost_of(conf: float) -> float:
            p = max(0.01, min(0.99, conf))
            return -math.log(p)

        dist = {src: 0.0}
        prev: Dict[str, Optional[str]] = {}
        pq = [(0.0, src)]
        # 重新构建带 confidence 的邻接
        adjc: Dict[str, List[Tuple[str, float, str]]] = defaultdict(list)
        for e in self.kg.edges:  # type: ignore[union-attr]
            conf = e.get("confidence", 0.9)
            adjc[e["source"]].append((e["target"], conf, e["relation"]))
            adjc[e["target"]].append((e["source"], conf, e["relation"]))
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist.get(u, float("inf")):
                continue
            if u == dst:
                break
            for v, conf, _r in adjc.get(u, []):
                nd = d + cost_of(conf)
                if nd < dist.get(v, float("inf")):
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))
        if dst not in dist:
            return {"found": False}
        path = [dst]
        while path[-1] != src:
            path.append(prev[path[-1]])
        path.reverse()
        prob = math.exp(-dist[dst])
        return {
            "found": True, "path": path,
            "probability": round(prob, 4),
            "nodes": [nodes[p]["name"] for p in path],
        }

    # ---------- 风险路径（综合风险最低） ----------
    def risk_path(self, src: str, dst: str) -> Dict[str, Any]:
        # 风险权重 = (1 - confidence) * 边类型风险系数
        adj, nodes = self._build_graph()
        if src not in nodes or dst not in nodes:
            return {"found": False}
        risk_factor = {
            "vuln_affects_asset": 0.8, "threat_targets_asset": 0.9,
            "vuln_exploited_by": 0.95, "causal": 0.7,
            "depends_on": 0.4, "asset_connects_asset": 0.5,
            "contains": 0.3,
        }
        adjr: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        for e in self.kg.edges:  # type: ignore[union-attr]
            r = risk_factor.get(e["relation"], 0.5)
            risk = r * (1.1 - e.get("confidence", 0.9))
            adjr[e["source"]].append((e["target"], risk))
            adjr[e["target"]].append((e["source"], risk))
        dist = {src: 0.0}
        prev: Dict[str, Optional[str]] = {}
        pq = [(0.0, src)]
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist.get(u, float("inf")):
                continue
            if u == dst:
                break
            for v, rk in adjr.get(u, []):
                nd = d + rk
                if nd < dist.get(v, float("inf")):
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))
        if dst not in dist:
            return {"found": False}
        path = [dst]
        while path[-1] != src:
            path.append(prev[path[-1]])
        path.reverse()
        return {
            "found": True, "path": path,
            "risk_score": round(dist[dst], 3),
            "nodes": [nodes[p]["name"] for p in path],
        }

    # ---------- 路径分析 ----------
    def analyze_path(self, path: List[str]) -> Dict[str, Any]:
        if not path or len(path) < 2:
            return {"valid": False, "reason": "路径过短"}
        adj, nodes = self._build_graph()
        # 验证可达
        length = len(path) - 1
        # 复杂度 = 2^(length-1) 近似
        complexity = min(1e6, 2 ** max(0, length - 1))
        # 概率 = 边 confidence 乘积
        prob = 1.0
        risks: List[float] = []
        for i in range(len(path) - 1):
            a, b = path[i], path[i + 1]
            found_conf = 0.5
            found_rel = None
            for e in self.kg.edges:  # type: ignore[union-attr]
                if ((e["source"] == a and e["target"] == b)
                        or (e["source"] == b and e["target"] == a)):
                    found_conf = e.get("confidence", 0.5)
                    found_rel = e["relation"]
                    break
            prob *= found_conf
            risks.append(1.0 - found_conf)
        risk_score = round(sum(risks), 3)
        # 瓶颈 = 最低 confidence 边
        bottleneck = min(risks) if risks else 0
        # 关键节点 = 度最高的中间节点
        degree_counter: Dict[str, int] = defaultdict(int)
        for e in self.kg.edges:  # type: ignore[union-attr]
            if e["source"] in path or e["target"] in path:
                degree_counter[e["source"]] += 1
                degree_counter[e["target"]] += 1
        key_nodes = sorted(degree_counter.items(),
                            key=lambda x: x[1], reverse=True)[:3]
        return {
            "valid": True,
            "length": length,
            "complexity": complexity,
            "probability": round(prob, 4),
            "risk_score": risk_score,
            "bottleneck_conf_gap": round(bottleneck, 3),
            "key_nodes": [{"id": k, "degree": v} for k, v in key_nodes],
            "feasibility": round(max(0.0, min(1.0, prob * (1 - risk_score / max(1, length)))), 3),
        }

    # ---------- 下一步攻击预测 ----------
    def predict_next(self, current_node: str,
                     top_k: int = 5) -> Dict[str, Any]:
        adj, nodes = self._build_graph()
        nbrs = self.kg.neighbors(current_node) if self.kg else []  # type: ignore[union-attr]
        ranked = []
        for nb in nbrs:
            n = nb["neighbor"]
            # 启发评分：越靠近核心资产分越高
            score = nb.get("confidence", 0.5)
            if n["type"] == "asset":
                score += 0.3
            if n["type"] in ("cve", "ioc"):
                score += 0.1
            ranked.append({
                "node_id": n["id"], "name": n["name"],
                "type": n["type"], "relation": nb["relation"],
                "score": round(score, 3),
            })
        ranked.sort(key=lambda x: x["score"], reverse=True)
        return {
            "current": current_node,
            "predictions": ranked[:top_k],
            "likely_goal": "横向移动至核心资产" if any(
                r["type"] == "asset" for r in ranked) else "信息收集",
        }

    # ---------- 杀伤链映射 ----------
    def map_kill_chain(self, path: List[str]) -> Dict[str, Any]:
        if self.kg is None:
            return {"stages": []}
        stages = []
        for nid in path:
            node = self.kg.nodes.get(nid, {})
            ntype = node.get("type", "")
            name = node.get("name", "")
            stage = "未知"
            if ntype in ("ioc", "domain", "ip"):
                stage = "投递/侦察"
            elif ntype in ("cve", "cwe", "attack_tech"):
                stage = "利用"
            elif ntype == "tool":
                stage = "命令控制"
            elif ntype == "asset":
                stage = "目标行动"
            elif ntype == "actor":
                stage = "侦察"
            stages.append({"node": name, "type": ntype, "stage": stage})
        return {"kill_chain_stages": stages,
                "chain": [s[1] for s in KILL_CHAIN]}

    # ---------- 攻击树（从根到叶） ----------
    def attack_tree(self, root: str, max_depth: int = 3) -> Dict[str, Any]:
        if root not in self.kg.nodes:  # type: ignore[union-attr]
            return {"root": root, "tree": None}

        def build(node: str, depth: int, visited: set) -> Dict[str, Any]:
            n = self.kg.nodes[node]  # type: ignore[union-attr]
            children = []
            if depth < max_depth:
                for nb in self.kg.neighbors(node):  # type: ignore[union-attr]
                    child = nb["neighbor"]["id"]
                    if child in visited:
                        continue
                    visited.add(child)
                    children.append(build(child, depth + 1, visited))
                    visited.remove(child)
            return {
                "node_id": node, "name": n["name"], "type": n["type"],
                "children": children,
            }

        tree = build(root, 0, {root})
        return {"root": root, "tree": tree}

    # ---------- 路径验证 / 回放 ----------
    def validate_path(self, path: List[str]) -> Dict[str, Any]:
        if self.kg is None:
            return {"valid": False}
        reachable = True
        for i in range(len(path) - 1):
            a, b = path[i], path[i + 1]
            edge_ok = any(
                (e["source"] == a and e["target"] == b)
                or (e["source"] == b and e["target"] == a)
                for e in self.kg.edges  # type: ignore[union-attr]
            )
            if not edge_ok:
                reachable = False
                break
        analysis = self.analyze_path(path)
        return {
            "reachable": reachable,
            "valid": reachable and analysis.get("valid", False),
            "analysis": analysis,
            "replay_steps": [
                {"step": i + 1, "from": path[i], "to": path[i + 1]}
                for i in range(len(path) - 1)
            ] if reachable else [],
        }

    # ---------- 可视化数据 ----------
    def visualization_data(self) -> Dict[str, Any]:
        if self.kg is None:
            return {"nodes": [], "edges": []}
        nodes = [
            {"id": n["id"], "label": n["name"], "type": n["type"]}
            for n in self.kg.nodes.values()
        ]
        edges = [
            {"source": e["source"], "target": e["target"],
             "relation": e["relation"], "weight": e["confidence"]}
            for e in self.kg.edges
        ]
        return {"nodes": nodes, "edges": edges,
                "kill_chain": KILL_CHAIN}


attack_path_engine = AttackPathEngine()
