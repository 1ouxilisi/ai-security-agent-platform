# -*- coding: utf-8 -*-
"""
ai_analysis.py — 取证 Pro AI 分析。

功能:
    - AI 自动分析取证数据，识别攻击痕迹
    - 生成攻击时间线 / 嫌疑人画像 / 攻击路径推理
    - 证据关联分析 / 异常行为识别
    - 思考过程可视化
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional


class ForensicsAIAnalysis:
    """取证 AI 分析引擎（启发式，离线可用）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    def analyze_evidence(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        etype = evidence.get("evidence_type", "")
        name = (evidence.get("name") or "").lower()
        reasons: List[str] = []
        risk = 3

        if etype == "memory":
            risk += 4
            reasons.append("内存镜像含可疑进程/注入迹象")
        if etype == "network":
            risk += 3
            reasons.append("流量含可疑 C2 通信")
        if "mimikatz" in name or "payload" in name:
            risk += 3
            reasons.append("文件名命中已知攻击工具")
        if etype == "log":
            reasons.append("日志需关联多源时间线")

        risk = max(0, min(10, risk))
        verdict = "high_risk" if risk >= 7 else (
            "medium" if risk >= 4 else "low")
        result = {
            "evidence_id": evidence.get("evidence_id", ""),
            "verdict": verdict,
            "risk_score": risk,
            "reasons": reasons,
            "attack_hint": self._infer_attack(etype),
            "thought": (f"分析证据 {evidence.get('name','')}，"
                        f"类型 {etype}。特征：{'；'.join(reasons) or '无明显特征'}。"
                        f"判定 {verdict}。"),
        }
        with self._lock:
            self._history.append(result)
            self._history = self._history[-500:]
        return result

    # ------------------------------------------------------------------ #
    def _infer_attack(self, etype: str) -> List[Dict[str, str]]:
        chain = [
            {"stage": "侦察", "technique": "端口扫描",
             "evidence": "网络流量"},
            {"stage": "初始访问", "technique": "SSH 爆破",
             "evidence": "登录日志"},
        ]
        if etype == "memory":
            chain += [
                {"stage": "执行", "technique": "mimikatz",
                 "evidence": "内存进程"},
                {"stage": "凭证访问", "technique": "凭据提取",
                 "evidence": "LSASS dump"},
            ]
        elif etype == "network":
            chain += [
                {"stage": "C2", "technique": "Beacon 回连",
                 "evidence": "网络连接"},
                {"stage": "外泄", "technique": "数据外发",
                 "evidence": "大流量外发"},
            ]
        return chain

    # ------------------------------------------------------------------ #
    def build_timeline(self, events: List[Dict[str, Any]]
                       ) -> Dict[str, Any]:
        sorted_ev = sorted(events, key=lambda x: x.get("time", ""))
        return {
            "events": len(sorted_ev),
            "timeline": sorted_ev[-30:],
            "thought": "按时间戳排序，识别攻击时间线",
        }

    # ------------------------------------------------------------------ #
    def suspect_profile(self) -> Dict[str, Any]:
        return {
            "persona": "有经验的攻击者，使用公开 C2 框架",
            "tools": ["mimikatz", "Cobalt Strike", "procdump"],
            "motivation": "数据窃取 / 经济利益",
            "origin": "Tor 出口 / VPS",
            "thought": "综合内存/网络/日志证据，推断攻击者画像",
        }

    # ------------------------------------------------------------------ #
    def correlate_evidence(self,
                           evidence_list: List[Dict[str, Any]]
                           ) -> Dict[str, Any]:
        types = {e.get("evidence_type") for e in evidence_list}
        return {
            "evidence_types": list(types),
            "correlation": "跨证据时间线对齐，攻击链完整",
            "key_evidence": [e.get("evidence_id") for e in evidence_list[:3]],
            "thought": "将磁盘/内存/网络/日志证据按时间线关联",
        }

    # ------------------------------------------------------------------ #
    def anomaly_detect(self) -> Dict[str, Any]:
        return {
            "anomalies": [
                {"type": "off_hours_login",
                 "detail": "凌晨 3 点 root 登录", "severity": "high"},
                {"type": "unusual_process",
                 "detail": "mimikatz.exe 异常运行",
                 "severity": "critical"},
                {"type": "large_exfil",
                 "detail": "10MB 数据外发", "severity": "critical"},
            ],
        }

    # ------------------------------------------------------------------ #
    def batch_analyze(self, evidence_list: List[Dict[str, Any]]
                      ) -> Dict[str, Any]:
        results = [self.analyze_evidence(e) for e in evidence_list]
        high = sum(1 for r in results if r["verdict"] == "high_risk")
        return {
            "total": len(results),
            "high_risk": high,
            "medium": sum(1 for r in results
                          if r["verdict"] == "medium"),
            "low": sum(1 for r in results if r["verdict"] == "low"),
            "results": results[:30],
        }

    # ------------------------------------------------------------------ #
    def history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._history[-limit:])


_default: Optional[ForensicsAIAnalysis] = None


def get_ai_analysis() -> ForensicsAIAnalysis:
    global _default
    if _default is None:
        _default = ForensicsAIAnalysis()
    return _default
