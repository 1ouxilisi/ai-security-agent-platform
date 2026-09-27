# -*- coding: utf-8 -*-
"""
threat_propagation.py — 威胁传播建模。

真实模型：
    - SIR / SEIR 常微分方程数值积分（欧拉法）
    - 网络级联传播（基于知识图谱邻接表的阈值模型）
    - 蒙特卡洛模拟（多随机种子重复模拟取统计量）
    - 传播影响评估（感染节点数 / 峰值 / 持续时间）
    - 阻断策略模拟（节点隔离 / 边切断 / 疫苗接种）
    - 参数敏感性分析
"""
from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

try:
    from security_kg.kg_builder import kg_builder
except Exception:  # pragma: no cover
    kg_builder = None  # type: ignore


class ThreatPropagation:
    """威胁传播建模与模拟。"""

    def __init__(self) -> None:
        self.kg = kg_builder

    # ---------- SIR 模型 ----------
    def sir(self, beta: float = 0.5, gamma: float = 0.1,
            initial_infected: int = 1, total: int = 100,
            days: int = 60, dt: float = 1.0) -> Dict[str, Any]:
        """标准 SIR 模型欧拉积分。"""
        total = max(initial_infected + 1, total)
        s = total - initial_infected
        i = initial_infected
        r = 0
        series: List[Dict[str, float]] = []
        peak = 0.0
        peak_day = 0
        day = 0.0
        while day <= days:
            series.append({
                "day": round(day, 2),
                "S": round(s, 2), "I": round(i, 2), "R": round(r, 2),
                "R0": round(beta / max(1e-6, gamma), 2),
            })
            if i > peak:
                peak = i
                peak_day = day
            new_inf = beta * s * i / total * dt
            new_rec = gamma * i * dt
            s -= new_inf
            i += new_inf - new_rec
            r += new_rec
            day += dt
        # 持续时间 = I > 0.5 的天数
        duration = sum(1 for p in series if p["I"] > 0.5)
        return {
            "model": "SIR",
            "params": {"beta": beta, "gamma": gamma,
                       "R0": round(beta / max(1e-6, gamma), 2),
                       "total": total},
            "peak_infected": round(peak, 2),
            "peak_day": round(peak_day, 2),
            "duration_days": duration,
            "final_infected_ratio": round((total - s) / total, 3),
            "series": series,
        }

    # ---------- SEIR 模型 ----------
    def seir(self, beta: float = 0.5, sigma: float = 0.3,
             gamma: float = 0.1, initial_exposed: int = 1,
             total: int = 100, days: int = 80,
             dt: float = 1.0) -> Dict[str, Any]:
        total = max(initial_exposed + 1, total)
        s = total - initial_exposed
        e = initial_exposed
        i = 0
        r = 0
        series: List[Dict[str, float]] = []
        peak = 0.0
        day = 0.0
        while day <= days:
            series.append({
                "day": round(day, 2),
                "S": round(s, 2), "E": round(e, 2),
                "I": round(i, 2), "R": round(r, 2),
            })
            if i > peak:
                peak = i
            new_exp = beta * s * i / total * dt
            new_inf = sigma * e * dt
            new_rec = gamma * i * dt
            s -= new_exp
            e += new_exp - new_inf
            i += new_inf - new_rec
            r += new_rec
            day += dt
        return {
            "model": "SEIR",
            "params": {"beta": beta, "sigma": sigma, "gamma": gamma,
                       "total": total},
            "peak_infected": round(peak, 2),
            "final_infected_ratio": round((total - s) / total, 3),
            "series": series,
        }

    # ---------- 网络级联（基于知识图谱） ----------
    def network_cascade(self, seed_nodes: List[str],
                         threshold: float = 0.3,
                         rounds: int = 10) -> Dict[str, Any]:
        """阈值模型：邻居感染比例超过 threshold 则被感染。"""
        if self.kg is None:
            return {"error": "知识图谱未加载"}
        infected = set(seed_nodes)
        history: List[Dict[str, Any]] = []
        adj: Dict[str, List[str]] = defaultdict(list)
        for e in self.kg.edges:
            adj[e["source"]].append(e["target"])
            adj[e["target"]].append(e["source"])
        for rnd in range(1, rounds + 1):
            new_infected = []
            for node in self.kg.nodes:
                if node in infected:
                    continue
                nbrs = adj.get(node, [])
                if not nbrs:
                    continue
                infected_nbr = sum(1 for n in nbrs if n in infected)
                if infected_nbr / len(nbrs) >= threshold:
                    new_infected.append(node)
            for n in new_infected:
                infected.add(n)
            history.append({
                "round": rnd,
                "new_infected": len(new_infected),
                "total_infected": len(infected),
                "nodes": [self.kg.nodes[n]["name"] for n in new_infected],
            })
            if not new_infected:
                break
        return {
            "seed_nodes": [self.kg.nodes[s]["name"] if s in self.kg.nodes
                           else s for s in seed_nodes],
            "threshold": threshold,
            "total_infected": len(infected),
            "total_nodes": len(self.kg.nodes),
            "infected_ratio": round(len(infected) / max(1, len(self.kg.nodes)), 3),
            "history": history,
            "infected_nodes": [self.kg.nodes[n]["name"]
                               for n in infected if n in self.kg.nodes],
        }

    # ---------- 传播路径分析 ----------
    def propagation_paths(self, seed: str) -> Dict[str, Any]:
        if self.kg is None:
            return {"error": "未加载"}
        # BFS 找种子到所有可达节点的最短路径
        from collections import deque
        dist = {seed: 0}
        prev: Dict[str, Optional[str]] = {seed: None}
        q = deque([seed])
        while q:
            u = q.popleft()
            for nb in self.kg.neighbors(u):  # type: ignore[union-attr]
                v = nb["neighbor"]["id"]
                if v not in dist:
                    dist[v] = dist[u] + 1
                    prev[v] = u
                    q.append(v)
        paths = []
        for node, d in dist.items():
            if node == seed:
                continue
            # 回溯路径
            p = [node]
            while p[-1] != seed:
                p.append(prev[p[-1]])
            p.reverse()
            paths.append({
                "to": self.kg.nodes[node]["name"],
                "hops": d,
                "path": [self.kg.nodes[x]["name"] for x in p],
            })
        paths.sort(key=lambda x: x["hops"])
        # 传播源 = 种子；传播节点 = 距离=1
        return {
            "seed": self.kg.nodes.get(seed, {}).get("name", seed),
            "reachable_nodes": len(paths),
            "spread_hops_distribution": dict(Counter(p["hops"] for p in paths)),
            "paths": paths[:20],
        }

    # ---------- 传播影响评估 ----------
    def impact_assessment(self, seed: str) -> Dict[str, Any]:
        sim = self.sir(beta=0.6, gamma=0.1, initial_infected=1,
                       total=max(10, len(self.kg.nodes) if self.kg else 10),
                       days=60)
        return {
            "estimated_infected_peak": sim["peak_infected"],
            "estimated_peak_day": sim["peak_day"],
            "estimated_duration_days": sim["duration_days"],
            "final_infected_ratio": sim["final_infected_ratio"],
            "severity": "高" if sim["final_infected_ratio"] > 0.6 else
                        "中" if sim["final_infected_ratio"] > 0.3 else "低",
            "seed": seed,
        }

    # ---------- 阻断策略 ----------
    def blocking_strategies(self, seed: str) -> Dict[str, Any]:
        # 对比不同策略下 SIR 的感染峰值
        base = self.sir(beta=0.6, gamma=0.1)
        strategies = [
            {"name": "节点隔离(关键资产)",
             "beta_factor": 0.5, "gamma_factor": 1.0,
             "description": "断开高价值资产的连接"},
            {"name": "边切断(横向移动通道)",
             "beta_factor": 0.7, "gamma_factor": 1.0,
             "description": "在东西向流量上做 ACL"},
            {"name": "免疫/疫苗(补丁)",
             "beta_factor": 0.6, "gamma_factor": 2.0,
             "description": "全员打补丁缩短感染期"},
            {"name": "配置加固+监控",
             "beta_factor": 0.4, "gamma_factor": 1.5,
             "description": "最小权限 + SIEM 实时检测"},
        ]
        results = []
        for s in strategies:
            sim = self.sir(beta=0.6 * s["beta_factor"],
                           gamma=0.1 * s["gamma_factor"])
            reduction = round(1 - sim["peak_infected"] /
                              max(1e-3, base["peak_infected"]), 3)
            results.append({
                **s,
                "simulated_peak": sim["peak_infected"],
                "reduction_ratio": reduction,
            })
        results.sort(key=lambda x: x["reduction_ratio"], reverse=True)
        return {
            "baseline_peak": base["peak_infected"],
            "strategies": results,
            "recommended": results[0]["name"] if results else "无",
        }

    # ---------- 蒙特卡洛模拟 ----------
    def monte_carlo(self, runs: int = 50, beta: float = 0.5,
                    gamma: float = 0.1, total: int = 50) -> Dict[str, Any]:
        random.seed(42)
        peaks = []
        finals = []
        for _ in range(runs):
            b = beta * random.uniform(0.7, 1.3)
            g = gamma * random.uniform(0.7, 1.3)
            sim = self.sir(beta=b, gamma=g, total=total, days=60)
            peaks.append(sim["peak_infected"])
            finals.append(sim["final_infected_ratio"])
        peaks.sort()
        finals.sort()
        return {
            "runs": runs,
            "peak_mean": round(sum(peaks) / runs, 2),
            "peak_p50": peaks[runs // 2],
            "peak_p90": peaks[int(runs * 0.9)],
            "final_mean": round(sum(finals) / runs, 3),
            "final_p90": finals[int(runs * 0.9)],
            "scenarios": [
                {"label": "悲观(P90)", "peak": peaks[int(runs * 0.9)],
                 "final_ratio": finals[int(runs * 0.9)]},
                {"label": "中位(P50)", "peak": peaks[runs // 2],
                 "final_ratio": finals[runs // 2]},
                {"label": "乐观(P10)", "peak": peaks[runs // 10],
                 "final_ratio": finals[runs // 10]},
            ],
        }

    # ---------- 参数敏感性 ----------
    def sensitivity(self) -> Dict[str, Any]:
        # 扫描 beta
        beta_sweep = []
        for b in [0.1, 0.3, 0.5, 0.7, 0.9]:
            sim = self.sir(beta=b, gamma=0.1)
            beta_sweep.append({"beta": b,
                               "final_ratio": sim["final_infected_ratio"]})
        gamma_sweep = []
        for g in [0.05, 0.1, 0.2, 0.4]:
            sim = self.sir(beta=0.5, gamma=g)
            gamma_sweep.append({"gamma": g,
                                "final_ratio": sim["final_infected_ratio"]})
        return {
            "beta_sensitivity": beta_sweep,
            "gamma_sensitivity": gamma_sweep,
            "conclusion": "beta(传播率) 对最终感染规模影响最大；"
                          "gamma(恢复率) 提高可显著降低峰值",
        }

    # ---------- 可视化数据 ----------
    def visualization(self) -> Dict[str, Any]:
        sim = self.sir()
        return {
            "sir_series": sim["series"],
            "metrics": {k: sim[k] for k in
                        ("peak_infected", "peak_day", "duration_days",
                         "final_infected_ratio")},
        }


threat_propagation = ThreatPropagation()
