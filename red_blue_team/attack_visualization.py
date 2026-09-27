# -*- coding: utf-8 -*-
"""
attack_visualization.py — 攻击路径可视化（第24轮升级方向1）。

职责：
    1. 攻击拓扑图（网络拓扑/资产分布/攻击路径/节点状态/边权重）
    2. 攻击链时间线（阶段/时间/操作/结果/影响/防御动作/告警）
    3. 攻击树可视化（目标/子目标/方法/前提/成功概率/影响）
    4. 杀伤链分析（7 阶段杀伤链 / 每阶段状态 / 检测点 / 响应点）
    5. 热力图（攻击频率/风险分布/漏洞分布/告警分布/资产重要性）
    6. 3D 攻击地图（全球攻击来源/目标/类型/实时流量/动画）

全部内存字典模拟，输出供前端 ECharts / 3D 渲染的结构化数据。
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from red_blue_team.attack_simulator import (
    ATTACK_TACTICS, ATTACK_TECHNIQUES, ATTACK_SCENARIOS,
)


# ============================================================
# 1. 攻击拓扑图
# ============================================================

class TopologyVisualizer:
    """网络拓扑 + 攻击路径可视化数据生成。"""

    def build(self, exercise_id: str = "default") -> Dict[str, Any]:
        """生成攻击拓扑图数据（节点 + 边）。"""
        nodes: List[Dict[str, Any]] = [
            {"id": "internet", "name": "互联网", "group": 0,
             "status": "external", "value": 5},
            {"id": "fw", "name": "边界防火墙", "group": 1,
             "status": "active", "value": 4},
            {"id": "dmz-web", "name": "DMZ-Web 服务器", "group": 2,
             "status": "compromised", "value": 6},
            {"id": "dmz-db", "name": "DMZ-数据库", "group": 2,
             "status": "attacked", "value": 5},
            {"id": "internal-pc", "name": "内网办公机", "group": 3,
             "status": "compromised", "value": 4},
            {"id": "dc", "name": "域控制器", "group": 3,
             "status": "targeted", "value": 8},
            {"id": "file-server", "name": "文件服务器", "group": 3,
             "status": "attacked", "value": 5},
            {"id": "backup", "name": "备份服务器", "group": 4,
             "status": "protected", "value": 3},
        ]

        edges: List[Dict[str, Any]] = [
            {"source": "internet", "target": "fw", "weight": 1, "label": "入站流量"},
            {"source": "fw", "target": "dmz-web", "weight": 5, "label": "HTTP/HTTPS"},
            {"source": "dmz-web", "target": "dmz-db", "weight": 4, "label": "SQL"},
            {"source": "dmz-web", "target": "internal-pc", "weight": 6,
             "label": "横向移动", "attacker_path": True},
            {"source": "internal-pc", "target": "dc", "weight": 7,
             "label": "凭证转储", "attacker_path": True},
            {"source": "internal-pc", "target": "file-server", "weight": 5,
             "label": "数据收集", "attacker_path": True},
            {"source": "dc", "target": "backup", "weight": 2, "label": "备份访问"},
        ]

        return {
            "topology_id": f"topo-{uuid.uuid4().hex[:8]}",
            "exercise_id": exercise_id,
            "nodes": nodes,
            "edges": edges,
            "legend": {
                "external": "外部", "active": "正常", "compromised": "已失陷",
                "attacked": "受攻击", "targeted": "目标", "protected": "受保护",
            },
            "updated_at": datetime.now().isoformat(),
        }


# ============================================================
# 2. 攻击链时间线
# ============================================================

class TimelineVisualizer:
    """攻击阶段时间线。"""

    def build(self, chain_run: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        events: List[Dict[str, Any]] = []
        base_time = datetime.now().timestamp() - 3600

        stages = (chain_run or {}).get("stage_results", []) or [
            {"technique_cn": "鱼叉钓鱼附件", "technique_id": "T1566.001",
             "success": True, "duration_sec": 5},
            {"technique_cn": "PowerShell 执行", "technique_id": "T1059.001",
             "success": True, "duration_sec": 3},
            {"technique_cn": "注册表持久化", "technique_id": "T1547.001",
             "success": True, "duration_sec": 2},
            {"technique_cn": "LSASS 凭证转储", "technique_id": "T1003.001",
             "success": False, "duration_sec": 8},
            {"technique_cn": "RDP 横向移动", "technique_id": "T1021.001",
             "success": True, "duration_sec": 12},
        ]

        for i, s in enumerate(stages):
            events.append({
                "stage": i + 1,
                "time": datetime.fromtimestamp(base_time + i * 600).isoformat(),
                "operation": s.get("technique_cn"),
                "technique_id": s.get("technique_id"),
                "result": "成功" if s.get("success") else "被阻断",
                "duration_min": round(s.get("duration_sec", 5) / 60, 1),
                "defense_action": next(
                    ("EDR 告警已触发" if s.get("success") else "防火墙拦截"),
                    "—"),
                "alert": "SIEM 告警 #A-" + str(1000 + i),
            })

        return {
            "timeline_id": f"tl-{uuid.uuid4().hex[:8]}",
            "events": events,
            "total_events": len(events),
            "span": f"{len(events) * 10} 分钟",
        }


# ============================================================
# 3. 攻击树可视化
# ============================================================

class AttackTreeVisualizer:
    """攻击目标 / 子目标 / 方法 / 成功概率 / 影响。"""

    def build(self, goal: str = "获取域管理员权限") -> Dict[str, Any]:
        tree = {
            "goal": goal,
            "success_probability": 0.62,
            "impact": 5,
            "children": [
                {
                    "subgoal": "获得初始立足点",
                    "success_prob": 0.85,
                    "children": [
                        {"method": "鱼叉钓鱼", "prereq": "收集员工邮箱", "prob": 0.7},
                        {"method": "Web 漏洞利用", "prereq": "发现公开应用", "prob": 0.5},
                    ],
                },
                {
                    "subgoal": "本地管理员权限",
                    "success_prob": 0.7,
                    "children": [
                        {"method": "LSASS 凭证转储", "prereq": "本地管理员", "prob": 0.6},
                        {"method": "UAC 绕过", "prereq": "普通用户", "prob": 0.55},
                    ],
                },
                {
                    "subgoal": "域管理员权限",
                    "success_prob": 0.55,
                    "children": [
                        {"method": "Kerberoasting", "prereq": "域用户", "prob": 0.5},
                        {"method": "黄金票据", "prereq": "KRBTGT 哈希", "prob": 0.8},
                    ],
                },
            ],
        }
        return {
            "tree_id": f"tree-{uuid.uuid4().hex[:8]}",
            "tree": tree,
            "legend": "成功概率 = 路径达成该子目标的估计概率",
        }


# ============================================================
# 4. 杀伤链分析（7 阶段）
# ============================================================

class KillChainVisualizer:
    """Lockheed Martin 7 阶段杀伤链。"""

    PHASES = ["侦察", "武器化", "投递", "利用", "安装", "命令与控制", "目标行动"]

    def build(self, chain_run: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        phase_status = []
        for i, phase in enumerate(self.PHASES):
            succeeded = random.random() > 0.25 if i < 6 else random.random() > 0.4
            phase_status.append({
                "phase": i + 1,
                "name": phase,
                "status": "completed" if succeeded else "blocked",
                "success_rate": round(random.uniform(0.5, 0.95), 2) if succeeded else 0.0,
                "detection_point": random.choice([True, False, True]),
                "response_point": random.choice([False, True, True]),
                "techniques": [t["tid"] for t in list(ATTACK_TECHNIQUES.values())
                               if t["tactic"] in ("ta0043", "ta0042", "ta0001",
                                                  "ta0002", "ta0003", "ta0011",
                                                  "ta0010", "ta0040")][:3],
            })

        return {
            "killchain_id": f"kc-{uuid.uuid4().hex[:8]}",
            "phases": phase_status,
            "breach_point": next((p["name"] for p in phase_status
                                  if p["status"] == "blocked"), "无阻断点"),
            "full_chain": all(p["status"] == "completed" for p in phase_status),
        }


# ============================================================
# 5. 热力图
# ============================================================

class HeatmapVisualizer:
    """攻击频率 / 风险分布 / 漏洞分布 / 告警分布 / 资产重要性。"""

    def build(self) -> Dict[str, Any]:
        assets = ["Web 服务器", "数据库", "域控", "办公机", "文件服务器", "备份"]
        metrics = ["攻击频率", "风险分布", "漏洞分布", "告警分布", "资产重要性"]

        matrix: List[List[int]] = []
        for ai, asset in enumerate(assets):
            row: List[int] = []
            for mi, metric in enumerate(metrics):
                # 域控/数据库风险高，备份告警少
                base = random.randint(10, 90)
                if asset in ("域控", "数据库") and metric in ("风险分布", "资产重要性"):
                    base = random.randint(75, 98)
                if asset == "备份" and metric == "告警分布":
                    base = random.randint(5, 25)
                row.append(base)
            matrix.append(row)

        return {
            "heatmap_id": f"hm-{uuid.uuid4().hex[:8]}",
            "assets": assets,
            "metrics": metrics,
            "matrix": matrix,
            "color_scale": "0(低)-100(高)",
            "hotspots": ["域控-风险分布", "数据库-资产重要性", "Web 服务器-攻击频率"],
        }


# ============================================================
# 6. 3D 攻击地图
# ============================================================

class AttackMap3D:
    """全球攻击地图：来源/目标/类型/实时流量/动画。"""

    SOURCES = [
        {"city": "莫斯科", "lat": 55.75, "lon": 37.61},
        {"city": "北京", "lat": 39.90, "lon": 116.40},
        {"city": "特拉维夫", "lat": 32.08, "lon": 34.78},
        {"city": "圣保罗", "lat": -23.55, "lon": -46.63},
        {"city": "新加坡", "lat": 1.35, "lon": 103.82},
        {"city": "柏林", "lat": 52.52, "lon": 13.40},
    ]
    TARGETS = [
        {"city": "上海", "lat": 31.23, "lon": 121.47},
        {"city": "纽约", "lat": 40.71, "lon": -74.00},
        {"city": "伦敦", "lat": 51.50, "lon": -0.12},
    ]

    def build(self) -> Dict[str, Any]:
        arcs: List[Dict[str, Any]] = []
        attack_types = ["钓鱼", "暴力破解", "SQL 注入", "勒索软件", "DDoS", "横向移动"]
        for _ in range(12):
            src = random.choice(self.SOURCES)
            tgt = random.choice(self.TARGETS)
            arcs.append({
                "source": src["city"], "source_lat": src["lat"], "source_lon": src["lon"],
                "target": tgt["city"], "target_lat": tgt["lat"], "target_lon": tgt["lon"],
                "type": random.choice(attack_types),
                "intensity": random.randint(30, 100),
            })

        return {
            "map_id": f"map3d-{uuid.uuid4().hex[:8]}",
            "arcs": arcs,
            "total_attacks": len(arcs),
            "live_traffic": random.randint(50, 500),
            "animation": "arc-flow",
            "last_updated": datetime.now().isoformat(),
        }


# ============================================================
# 7. 单例导出
# ============================================================

_topology = TopologyVisualizer()
_timeline = TimelineVisualizer()
_tree = AttackTreeVisualizer()
_killchain = KillChainVisualizer()
_heatmap = HeatmapVisualizer()
_map3d = AttackMap3D()


def get_attack_visualization() -> Dict[str, Any]:
    return {
        "topology": _topology,
        "timeline": _timeline,
        "tree": _tree,
        "killchain": _killchain,
        "heatmap": _heatmap,
        "map3d": _map3d,
    }


def stats() -> Dict[str, Any]:
    return {"visualizers": 6, "killchain_phases": 7}
