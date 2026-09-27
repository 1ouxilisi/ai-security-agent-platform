#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
attack_chain.py — 攻击链分析与重建模块
=======================================

功能：
    1. 攻击链检测：多阶段攻击检测/阶段识别/技术关联/工具关联/基础设施关联
    2. 攻击链重建：时间线重建/操作序列重建/攻击路径重建/影响范围重建/证据链重建
    3. 攻击链可视化：攻击链图/拓扑图/时间线/攻击树/杀伤链/热力图/3D 可视化
    4. 攻击链分析：起点/路径/手法/目标/影响/归因分析
    5. 攻击链预测：下一步攻击/目标/时间/规模预测/防御建议
    6. 攻击链知识库：已知攻击链/模板/模式/特征/案例/IOC

全部内存字典模拟。
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


_KILL_CHAIN_PHASES = [
    {"id": "recon", "name": "侦察", "order": 1, "description": "收集目标信息"},
    {"id": "weaponize", "name": "武器化", "order": 2, "description": "制作攻击载荷"},
    {"id": "deliver", "name": "投递", "order": 3, "description": "投递攻击载荷"},
    {"id": "exploit", "name": "利用", "order": 4, "description": "利用漏洞执行代码"},
    {"id": "install", "name": "安装", "order": 5, "description": "植入后门/持久化"},
    {"id": "command", "name": "命令控制", "order": 6, "description": "建立 C2 信道"},
    {"id": "actions", "name": "目标行动", "order": 7, "description": "达成攻击目的"},
]

_KNOWN_CHAINS = [
    {
        "chain_id": "KC-001", "name": "钓鱼邮件-勒索软件链",
        "phases": ["recon", "weaponize", "deliver", "exploit", "install", "command", "actions"],
        "techniques": ["T1566", "T1204", "T1059", "T1546", "T1071", "T1486"],
        "industry": "通用", "severity": "critical",
    },
    {
        "chain_id": "KC-002", "name": "供应链入侵-数据窃取链",
        "phases": ["recon", "deliver", "exploit", "install", "command", "actions"],
        "techniques": ["T1195", "T1190", "T1059", "T1003", "T1071", "T1041"],
        "industry": "科技", "severity": "high",
    },
    {
        "chain_id": "KC-003", "name": "漏洞利用-横向移动链",
        "phases": ["recon", "exploit", "install", "command", "actions"],
        "techniques": ["T1190", "T1068", "T1021", "T1550", "T1046"],
        "industry": "金融", "severity": "high",
    },
]


class AttackChainAnalyzer:
    """攻击链分析与重建引擎。"""

    def __init__(self) -> None:
        self.kill_chain = _KILL_CHAIN_PHASES
        self.known_chains = _KNOWN_CHAINS
        self.detected_chains: List[Dict[str, Any]] = []
        self.chain_knowledge: List[Dict[str, Any]] = []
        self._seed_demo_chains()

    def _seed_demo_chains(self) -> None:
        """生成演示攻击链。"""
        for i in range(3):
            chain = self._build_sample_chain(f"CHAIN-{i+1:03d}")
            self.detected_chains.append(chain)

    def _build_sample_chain(self, chain_id: str) -> Dict[str, Any]:
        base_time = datetime.now() - timedelta(hours=random.randint(2, 72))
        nodes = []
        for phase in _KILL_CHAIN_PHASES[:random.randint(4, 7)]:
            nodes.append({
                "phase": phase["id"],
                "phase_name": phase["name"],
                "order": phase["order"],
                "timestamp": (base_time + timedelta(hours=random.randint(1, 48))).isoformat(timespec="seconds"),
                "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "target_host": f"host-{random.randint(1,20):03d}",
                "technique": random.choice(["T1566", "T1059", "T1071", "T1003", "T1041", "T1486"]),
                "tool": random.choice(["Cobalt Strike", "Metasploit", "Empire", "自定义恶意软件"]),
            })
        return {
            "chain_id": chain_id,
            "name": f"检测攻击链 {chain_id}",
            "nodes": nodes,
            "phase_count": len(nodes),
            "completed_phases": len(nodes),
            "current_phase": nodes[-1]["phase_name"] if nodes else "未知",
            "severity": random.choice(["high", "high", "critical"]),
            "status": "active",
            "attribution": random.choice(["未知", "疑似APT29", "疑似勒索组织", "疑似内部威胁"]),
            "created_at": nodes[0]["timestamp"] if nodes else _now(),
        }

    # ---------- 攻击链检测 ----------

    def detect_chain(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """从事件流中检测多阶段攻击链。"""
        chain_id = f"CHAIN-{uuid.uuid4().hex[:8].upper()}"
        phases_identified = []
        for evt in events:
            technique = evt.get("technique_id", evt.get("technique", ""))
            phase = self._map_technique_to_phase(technique)
            if phase and phase not in [p["phase"] for p in phases_identified]:
                phases_identified.append({
                    "phase": phase["id"], "phase_name": phase["name"],
                    "technique": technique, "event": evt,
                })

        chain = {
            "chain_id": chain_id,
            "name": f"自动检测链 {chain_id}",
            "nodes": phases_identified,
            "phase_count": len(phases_identified),
            "severity": "critical" if len(phases_identified) >= 5 else ("high" if len(phases_identified) >= 3 else "medium"),
            "status": "detected",
            "tool_association": self._associate_tools(events),
            "infra_association": self._associate_infra(events),
        }
        self.detected_chains.append(chain)
        return chain

    def _map_technique_to_phase(self, technique_id: str) -> Optional[Dict[str, Any]]:
        mapping = {
            "T1566": _KILL_CHAIN_PHASES[2], "T1190": _KILL_CHAIN_PHASES[1],
            "T1204": _KILL_CHAIN_PHASES[3], "T1059": _KILL_CHAIN_PHASES[3],
            "T1546": _KILL_CHAIN_PHASES[4], "T1068": _KILL_CHAIN_PHASES[3],
            "T1071": _KILL_CHAIN_PHASES[5], "T1027": _KILL_CHAIN_PHASES[4],
            "T1003": _KILL_CHAIN_PHASES[6], "T1041": _KILL_CHAIN_PHASES[6],
            "T1486": _KILL_CHAIN_PHASES[6], "T1021": _KILL_CHAIN_PHASES[5],
            "T1046": _KILL_CHAIN_PHASES[0], "T1087": _KILL_CHAIN_PHASES[0],
        }
        return mapping.get(technique_id)

    def _associate_tools(self, events: List[Dict[str, Any]]) -> List[str]:
        tools = set()
        for evt in events:
            if evt.get("tool"):
                tools.add(evt["tool"])
        return list(tools) if tools else ["未知工具"]

    def _associate_infra(self, events: List[Dict[str, Any]]) -> List[str]:
        ips = set()
        for evt in events:
            if evt.get("source_ip"):
                ips.add(evt["source_ip"])
        return list(ips)

    # ---------- 攻击链重建 ----------

    def reconstruct(self, chain_id: str) -> Dict[str, Any]:
        """重建攻击链时间线和操作序列。"""
        chain = next((c for c in self.detected_chains if c["chain_id"] == chain_id), None)
        if not chain:
            return {"error": f"攻击链 {chain_id} 不存在"}

        nodes = chain.get("nodes", [])
        timeline = sorted(nodes, key=lambda n: n.get("timestamp", ""))

        return {
            "chain_id": chain_id,
            "name": chain["name"],
            "timeline": timeline,
            "operation_sequence": [f"{n.get('phase_name', n.get('phase', '?'))}: {n.get('technique', '?')}" for n in timeline],
            "attack_path": self._build_path(timeline),
            "impact_scope": self._estimate_impact(chain),
            "evidence_chain": [
                {"event_id": f"EV-{i+1:03d}", "source": n.get("target_host", ""),
                 "technique": n.get("technique", ""), "timestamp": n.get("timestamp", "")}
                for i, n in enumerate(timeline)
            ],
            "status": "reconstructed",
            "timestamp": _now(),
        }

    def _build_path(self, timeline: List[Dict[str, Any]]) -> List[str]:
        path = []
        for n in timeline:
            src = n.get("source_ip", "?")
            tgt = n.get("target_host", "?")
            path.append(f"{src} -> {tgt} ({n.get('phase_name', '?')})")
        return path

    def _estimate_impact(self, chain: Dict[str, Any]) -> Dict[str, Any]:
        affected_hosts = len(set(n.get("target_host", "") for n in chain.get("nodes", []) if n.get("target_host")))
        return {
            "affected_hosts": affected_hosts,
            "affected_users": random.randint(1, 20),
            "data_at_risk": random.choice(["低", "中", "高", "严重"]),
            "business_impact": random.choice(["无明显影响", "部分系统降级", "业务中断", "数据泄露"]),
        }

    # ---------- 攻击链分析 ----------

    def analyze_chain(self, chain_id: str) -> Dict[str, Any]:
        """攻击链深度分析。"""
        recon = self.reconstruct(chain_id)
        if "error" in recon:
            return recon

        chain = next((c for c in self.detected_chains if c["chain_id"] == chain_id), {})
        return {
            "chain_id": chain_id,
            "starting_point": recon["attack_path"][0] if recon["attack_path"] else "未知",
            "attack_path": recon["attack_path"],
            "technique_mix": list(set(n.get("technique", "?") for n in recon["timeline"])),
            "tools_used": chain.get("tool_association", []),
            "target": recon["impact_scope"],
            "attribution": chain.get("attribution", "未知"),
            "defense_gaps": [
                {"phase": p["name"], "gap": "未检测到该阶段活动" if p["name"] not in [n.get("phase_name") for n in recon["timeline"]] else "已覆盖"}
                for p in _KILL_CHAIN_PHASES
            ],
            "timestamp": _now(),
        }

    # ---------- 攻击链预测 ----------

    def predict_next(self, chain_id: str) -> Dict[str, Any]:
        """预测攻击链下一步。"""
        chain = next((c for c in self.detected_chains if c["chain_id"] == chain_id), None)
        if not chain:
            return {"error": f"攻击链 {chain_id} 不存在"}

        current_order = max((n.get("order", 0) for n in chain.get("nodes", [])), default=0)
        next_phases = [p for p in _KILL_CHAIN_PHASES if p["order"] > current_order]

        predictions = []
        for p in next_phases[:3]:
            predictions.append({
                "predicted_phase": p["name"],
                "probability": round(random.uniform(0.3, 0.85), 3),
                "likely_techniques": random.sample(["T1041", "T1486", "T1021", "T1550", "T1485"], k=2),
                "estimated_time_window_h": random.randint(1, 24),
            })

        return {
            "chain_id": chain_id,
            "current_phase": chain.get("current_phase", "未知"),
            "next_predictions": predictions,
            "overall_threat_trend": "escalating" if predictions else "stabilizing",
            "defense_recommendations": [
                "加强出站流量监控", "实施网络分段", "启用 EDR 实时防护", "重置相关账户凭证",
            ],
            "timestamp": _now(),
        }

    # ---------- 知识库 ----------

    def get_knowledge_base(self) -> Dict[str, Any]:
        """攻击链知识库。"""
        return {
            "known_chains": self.known_chains,
            "chain_templates": [
                {"template_id": "TPL-RANSOMWARE", "name": "勒索软件通用链", "phases": 7},
                {"template_id": "TPL-DATA-THEFT", "name": "数据窃取通用链", "phases": 6},
                {"template_id": "TPL-APT-LONG", "name": "APT 长期潜伏链", "phases": 12},
            ],
            "chain_patterns": [
                {"pattern_id": "PAT-001", "name": "钓鱼→执行→持久化", "frequency": "高"},
                {"pattern_id": "PAT-002", "name": "漏洞利用→横向→渗出", "frequency": "中"},
            ],
            "iocs": [
                {"type": "IP", "value": "45.xxx.xxx.xxx", "associated_chain": "KC-001"},
                {"type": "Domain", "value": "update-check[.]cc", "associated_chain": "KC-001"},
                {"type": "Hash", "value": "a1b2c3d4...", "associated_chain": "KC-002"},
            ],
            "total_known_chains": len(self.known_chains),
        }

    # ---------- 可视化数据 ----------

    def visualization_data(self, chain_id: str) -> Dict[str, Any]:
        """生成攻击链可视化所需数据。"""
        chain = next((c for c in self.detected_chains if c["chain_id"] == chain_id), None)
        if not chain:
            return {"error": f"攻击链 {chain_id} 不存在"}

        nodes = chain.get("nodes", [])
        vis_nodes = [{"id": i, "label": n.get("phase_name", "?"), "phase": n.get("phase", "?"),
                      "technique": n.get("technique", ""), "timestamp": n.get("timestamp", "")}
                     for i, n in enumerate(nodes)]
        vis_edges = [{"from": i, "to": i + 1} for i in range(len(nodes) - 1)]

        return {
            "chain_id": chain_id,
            "graph_nodes": vis_nodes,
            "graph_edges": vis_edges,
            "timeline_data": [{"time": n.get("timestamp", ""), "event": n.get("phase_name", "?")} for n in nodes],
            "kill_chain_coverage": [
                {"phase": p["name"], "covered": p["name"] in [n.get("phase_name") for n in nodes]}
                for p in _KILL_CHAIN_PHASES
            ],
            "severity_heatmap": {n.get("phase_name", "?"): random.randint(1, 10) for n in nodes},
        }

    def overview(self) -> Dict[str, Any]:
        return {
            "total_detected_chains": len(self.detected_chains),
            "active_chains": len([c for c in self.detected_chains if c.get("status") == "active"]),
            "critical_chains": len([c for c in self.detected_chains if c.get("severity") == "critical"]),
            "kill_chain_phases": len(self.kill_chain),
            "known_chains_in_kb": len(self.known_chains),
            "average_chain_length": round(sum(len(c.get("nodes", [])) for c in self.detected_chains) / max(len(self.detected_chains), 1), 1),
        }


# 单例
attack_chain_analyzer = AttackChainAnalyzer()
