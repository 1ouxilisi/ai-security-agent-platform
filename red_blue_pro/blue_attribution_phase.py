# -*- coding: utf-8 -*-
"""
blue_attribution_phase.py — 蓝队阶段3：溯源。

功能:
    - 攻击路径重建（时间线 / 攻击链）
    - 攻击者画像（TTPs / 动机 / 能力）
    - 入侵时间线
    - 影响范围评估
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TimelineEvent:
    ts: str = ""
    phase: str = ""
    action: str = ""
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"ts": self.ts, "phase": self.phase,
                "action": self.action, "evidence": self.evidence}


@dataclass
class AttributionResult:
    attacker_profile: Dict[str, Any] = field(default_factory=dict)
    timeline: List[TimelineEvent] = field(default_factory=list)
    impact: Dict[str, Any] = field(default_factory=dict)
    attack_chain: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attacker_profile": self.attacker_profile,
            "timeline": [t.to_dict() for t in self.timeline],
            "timeline_count": len(self.timeline),
            "impact": self.impact,
            "attack_chain": self.attack_chain,
        }


class BlueAttributionPhase:
    """蓝队阶段3：溯源。"""

    # ------------------------------------------------------------------ #
    def rebuild_timeline(self,
                          red_logs: Optional[List[Dict[str, Any]]] = None
                          ) -> AttributionResult:
        r = AttributionResult()
        base = [
            ("09:00", "侦察", "OSINT 收集子域名/邮箱",
             "subfinder/theHarvester"),
            ("09:30", "初始访问", "钓鱼邮件投递", "phishing template"),
            ("10:00", "执行", "宏/Payload 执行", "AutoOpen"),
            ("10:05", "提权", "本地提权", "CVE-2021-4034"),
            ("10:10", "横向", "SMB/WMI 横向", "wmiexec"),
            ("10:20", "目标", "数据窃取", "secretsdump"),
            ("10:25", "痕迹", "日志清理", "wevtutil cl"),
        ]
        if red_logs:
            for i, lg in enumerate(red_logs[:20]):
                r.timeline.append(TimelineEvent(
                    ts=lg.get("ts", f"T{i}"),
                    phase=lg.get("phase", "?"),
                    action=lg.get("message", ""),
                    evidence=lg.get("level", "INFO")))
        else:
            for ts, ph, ac, ev in base:
                r.timeline.append(TimelineEvent(ts=ts, phase=ph,
                                               action=ac, evidence=ev))
        # 攻击链
        r.attack_chain = [
            {"stage": "侦察", "tool": "OSINT", "success": True},
            {"stage": "初始访问", "tool": "钓鱼", "success": True},
            {"stage": "执行", "tool": "宏", "success": True},
            {"stage": "提权", "tool": "CVE", "success": True},
            {"stage": "横向", "tool": "WMI", "success": True},
            {"stage": "目标", "tool": "dump", "success": True},
        ]
        return r

    # ------------------------------------------------------------------ #
    def attacker_profile(self, chain: Optional[List[Dict[str, Any]]] = None
                         ) -> AttributionResult:
        r = AttributionResult()
        r.attacker_profile = {
            "ttps": ["T1595 主动侦察", "T1566 钓鱼", "T1059 命令执行",
                     "T1068 提权", "T1021 横向", "T1005 数据窃取"],
            "motivation": "演练/间谍/勒索（演练场景）",
            "capability": "中级（熟悉公开工具与 CVE）",
            "sophistication": "medium",
            "tools_seen": ["subfinder", "hydra", "impacket",
                           "mimikatz"],
        }
        return r

    # ------------------------------------------------------------------ #
    def impact_assessment(self, hosts: int = 5,
                          accounts: int = 12,
                          data_records: int = 0) -> AttributionResult:
        r = AttributionResult()
        r.impact = {
            "hosts_compromised": hosts,
            "accounts_compromised": accounts,
            "data_records_exposed": data_records,
            "data_risk": "high" if data_records > 10000 else "medium",
            "service_downtime": "unknown",
            "compliance_impact": ["等保2.0", "GDPR" if data_records > 0
                                  else ""],
        }
        return r

    # ------------------------------------------------------------------ #
    def full_attribution(self,
                         red_logs: Optional[List[Dict[str, Any]]] = None
                         ) -> AttributionResult:
        tl = self.rebuild_timeline(red_logs)
        ap = self.attacker_profile(tl.attack_chain)
        im = self.impact_assessment()
        r = AttributionResult()
        r.timeline = tl.timeline
        r.attack_chain = tl.attack_chain
        r.attacker_profile = ap.attacker_profile
        r.impact = im.impact
        return r

    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        return {
            "analyzers": ["timeline", "attacker_profile", "impact"],
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


_default: Optional[BlueAttributionPhase] = None


def get_blue_attribution_phase() -> BlueAttributionPhase:
    global _default
    if _default is None:
        _default = BlueAttributionPhase()
    return _default
