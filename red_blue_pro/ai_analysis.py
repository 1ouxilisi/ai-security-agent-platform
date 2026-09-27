# -*- coding: utf-8 -*-
"""
ai_analysis.py — 红蓝对抗 Pro AI 分析。

功能:
    - AI 自动分析攻击路径
    - 生成攻击链图（节点+边，SVG 数据）
    - 漏洞严重程度评级
    - 利用建议
    - 修复建议
    - 红蓝对抗效果评估
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ChainNode:
    id: str = ""
    label: str = ""
    side: str = "red"
    severity: str = "info"

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "label": self.label, "side": self.side,
                "severity": self.severity}


@dataclass
class ChainEdge:
    src: str = ""
    dst: str = ""
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "label": self.label}


SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2,
                  "low": 1, "info": 0}


class AIAnalysis:
    """红蓝对抗 AI 分析引擎（规则驱动 + 启发式）。"""

    RED_STAGES = [
        ("recon", "侦察", "OSINT 子域名/邮箱/泄露检测"),
        ("initial_access", "初始访问", "钓鱼/Exploit/凭据攻击"),
        ("execution", "执行", "命令/代码执行/持久化"),
        ("privesc", "提权", "CVE 指纹/配置审计"),
        ("lateral", "横向", "SMB/WMI/WinRM/PtH"),
        ("objective", "目标", "数据窃取/维持/清理"),
    ]

    def analyze(self, red_results: Dict[str, Any],
                blue_results: Dict[str, Any]) -> Dict[str, Any]:
        """综合红蓝产物，输出攻击链 + 评级 + 建议。"""
        # 红队节点
        nodes: List[ChainNode] = []
        edges: List[ChainEdge] = []
        prev = None
        for i, (key, label, desc) in enumerate(self.RED_STAGES):
            nid = f"red_{key}"
            res = red_results.get(key, {}) or {}
            sev = "success" if res else "info"
            nodes.append(ChainNode(id=nid, label=f"红·{label}",
                                   side="red", severity=sev))
            if prev:
                edges.append(ChainEdge(src=prev, dst=nid, label=desc))
            prev = nid
        # 蓝队检测节点
        for j, (key, label, _) in enumerate([
                ("detection", "蓝·检测", ""),
                ("response", "蓝·响应", ""),
                ("attribution", "蓝·溯源", "")]):
            nid = f"blue_{key}"
            res = blue_results.get(key, {}) or {}
            nodes.append(ChainNode(id=nid, label=label, side="blue",
                                   severity="medium" if res else "info"))
            if j == 0 and prev:
                edges.append(ChainEdge(src=prev, dst=nid,
                                       label="蓝队告警"))
            if j > 0:
                edges.append(ChainEdge(src=f"blue_{['detection','response','attribution'][j-1]}",
                                       dst=nid, label="IR 流程"))
        # 严重度聚合
        sev_counts = {"critical": 0, "high": 0, "medium": 0,
                      "low": 0, "info": 0}
        for f in (red_results.get("privesc", {}) or {}).get("findings", []):
            sev_counts[f.get("severity", "info")] += 1
        for a in (blue_results.get("detection", {}) or {}).get("alerts", []):
            sev_counts[a.get("severity", "info")] += 1
        overall = "info"
        if sev_counts["critical"]:
            overall = "critical"
        elif sev_counts["high"]:
            overall = "high"
        elif sev_counts["medium"]:
            overall = "medium"
        # 利用/修复建议
        exploit_advice = [
            "侦察阶段：优先子域名+邮箱+泄露凭证",
            "初始访问：钓鱼 + 凭据喷洒组合",
            "提权：按 OS 指纹选 CVE",
        ]
        fix_advice = [
            "强制 MFA，阻断凭据喷洒",
            "部署 EDR/Suricata，覆盖 SMB/WMI/WinRM",
            "最小权限 + 网络分段",
            "定期红蓝对抗演练",
        ]
        return {
            "overall_risk": overall,
            "severity_counts": sev_counts,
            "attack_chain": {
                "nodes": [n.to_dict() for n in nodes],
                "edges": [e.to_dict() for e in edges],
            },
            "attack_paths": [
                {"name": "标准红队六阶段链",
                 "description": "侦察→初始访问→执行→提权→横向→目标",
                 "difficulty": "medium"}
            ],
            "exploit_advice": exploit_advice,
            "fix_advice": fix_advice,
            "rb_effect": {
                "red_success": sum(1 for k, _, _ in self.RED_STAGES
                                   if red_results.get(k)),
                "blue_detected": sum(1 for k in ("detection", "response",
                                                  "attribution")
                                     if blue_results.get(k)),
            },
            "analyzed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


_default_ai: Optional[AIAnalysis] = None


def get_ai_analysis() -> AIAnalysis:
    global _default_ai
    if _default_ai is None:
        _default_ai = AIAnalysis()
    return _default_ai
