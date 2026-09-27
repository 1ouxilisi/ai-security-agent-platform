#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 告警关联分析器 (Alert Correlator)
===================================

功能：
    - 关联规则：基于时间 / IP / 端口 / 漏洞 / 攻击类型的告警关联
    - 攻击链识别：识别完整攻击链（侦察→扫描→利用→提权→横向移动→数据窃取），
      内置 MITRE ATT&CK 战术/技术映射表
    - 告警聚合：将相关告警聚合为一个安全事件，降低告警噪音
    - 告警优先级：基于攻击链阶段 / 严重程度 / 影响范围 / 置信度计算
    - 误报识别：基于历史数据 / 白名单 / 行为模式识别误报
    - 关联报告：生成告警关联分析报告

仅用于授权的安全运营与监控场景。
"""
import os
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat()


class AlertCorrelator:
    """AI 告警关联分析器"""

    # MITRE ATT&CK 战术 -> 攻击链阶段映射
    # 攻击链阶段顺序：侦察(1) → 扫描(2) → 利用(3) → 提权(4) → 横向移动(5) → 数据窃取(6)
    MITRE_PHASE_MAP: Dict[str, Dict[str, Any]] = {
        "reconnaissance": {"phase": 1, "name": "侦察", "tactics": ["TA0043"]},
        "resource_development": {"phase": 1, "name": "侦察", "tactics": ["TA0042"]},
        "initial_access": {"phase": 2, "name": "扫描/初始访问", "tactics": ["TA0001"]},
        "execution": {"phase": 3, "name": "执行/利用", "tactics": ["TA0002"]},
        "persistence": {"phase": 4, "name": "持久化/提权准备", "tactics": ["TA0003"]},
        "privilege_escalation": {"phase": 4, "name": "提权", "tactics": ["TA0004"]},
        "defense_evasion": {"phase": 4, "name": "防御规避", "tactics": ["TA0005"]},
        "credential_access": {"phase": 5, "name": "凭证访问", "tactics": ["TA0006"]},
        "lateral_movement": {"phase": 5, "name": "横向移动", "tactics": ["TA0008"]},
        "collection": {"phase": 6, "name": "数据收集", "tactics": ["TA0009"]},
        "exfiltration": {"phase": 6, "name": "数据窃取", "tactics": ["TA0010"]},
        "command_and_control": {"phase": 5, "name": "命令与控制", "tactics": ["TA0011"]},
    }

    PHASE_NAMES = {1: "侦察", 2: "扫描", 3: "利用", 4: "提权", 5: "横向移动", 6: "数据窃取"}

    def __init__(self):
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._correlated: Dict[str, List[Dict[str, Any]]] = {}
        self._attack_chains: Dict[str, List[Dict[str, Any]]] = {}
        self._aggregated: Dict[str, List[Dict[str, Any]]] = {}
        # 误报识别：白名单
        self._whitelist_ips = {"127.0.0.1", "10.0.0.5", "192.168.1.100"}
        self._fp_keywords = {"scan_test", "legitimate_scan", "monitoring_probe"}
        # 历史误报样本
        self._fp_history: List[str] = []
        self._data_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "ai_soc", "correlation"
        )
        os.makedirs(self._data_dir, exist_ok=True)

    # ---------------- 告警优先级 ----------------
    def calculate_priority(self, alert: Dict[str, Any]) -> int:
        """
        计算告警优先级（0-100）。
        综合：攻击链阶段权重 / 严重程度 / 影响范围 / 置信度。
        """
        score = 0.0
        # 攻击链阶段权重（越靠后越危险）
        phase = alert.get("attack_chain_phase", 0)
        score += phase * 8.0
        # 严重程度权重
        sev = {"critical": 40, "high": 30, "medium": 18, "low": 8, "info": 3}.get(
            str(alert.get("severity", "low")).lower(), 5)
        score += sev
        # 影响范围
        impact = alert.get("impact_scope", 0)
        score += min(15.0, float(impact))
        # 置信度
        confidence = alert.get("confidence", 50)
        score += (float(confidence) / 100.0) * 10.0
        return int(max(0, min(100, round(score))))

    # ---------------- 误报识别 ----------------
    def detect_false_positives(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """识别误报：基于历史数据 / 白名单 / 行为模式"""
        results: List[Dict[str, Any]] = []
        for a in alerts:
            reasons: List[str] = []
            src_ip = a.get("source_ip", "")
            if src_ip in self._whitelist_ips:
                reasons.append("来源IP在白名单")
            title = str(a.get("title", a.get("message", ""))).lower()
            if any(kw in title for kw in self._fp_keywords):
                reasons.append("标题命中测试/监控类关键词")
            # 历史重复误报
            sig = a.get("signature") or title
            if sig in self._fp_history:
                reasons.append("与历史误报特征重复")
            # 单条孤立且低严重度
            if str(a.get("severity", "")).lower() == "info" and a.get("frequency", 1) <= 1:
                reasons.append("孤立低危告警")
            if reasons:
                results.append({**a, "is_false_positive": True, "fp_reasons": reasons})
            else:
                results.append({**a, "is_false_positive": False})
        return results

    # ---------------- 告警聚合 ----------------
    def aggregate_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """将相关告警按 (source_ip, attack_type, time_window) 聚合为安全事件"""
        buckets: Dict[str, List[Dict[str, Any]]] = {}
        for a in alerts:
            key = f"{a.get('source_ip', 'na')}|{a.get('attack_type', 'na')}"
            buckets.setdefault(key, []).append(a)

        aggregated: List[Dict[str, Any]] = []
        for key, group in buckets.items():
            severity = "critical" if any(
                str(g.get("severity", "")).lower() == "critical" for g in group) else \
                "high" if any(str(g.get("severity", "")).lower() == "high" for g in group) else "medium"
            aggregated.append({
                "event_id": "evt-" + uuid.uuid4().hex[:10],
                "aggregate_key": key,
                "alert_count": len(group),
                "source_ip": group[0].get("source_ip"),
                "attack_type": group[0].get("attack_type"),
                "severity": severity,
                "first_seen": group[0].get("timestamp", _now()),
                "last_seen": group[-1].get("timestamp", _now()),
                "alerts": group,
            })
        # 按聚合规模排序
        aggregated.sort(key=lambda e: e["alert_count"], reverse=True)
        return aggregated

    # ---------------- 攻击链识别 ----------------
    def identify_attack_chains(self, correlated_alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        基于 MITRE ATT&CK 映射识别完整攻击链：
        侦察→扫描→利用→提权→横向移动→数据窃取。
        """
        # 按 source_ip 归集
        by_src: Dict[str, List[Dict[str, Any]]] = {}
        for a in correlated_alerts:
            src = a.get("source_ip", "na")
            by_src.setdefault(src, []).append(a)

        chains: List[Dict[str, Any]] = []
        for src, group in by_src.items():
            phase_set = set()
            ordered_alerts: Dict[int, List[Dict[str, Any]]] = {}
            for a in group:
                tactic = str(a.get("mitre_tactic", "")).lower()
                mapping = self.MITRE_PHASE_MAP.get(tactic)
                if mapping:
                    phase = mapping["phase"]
                else:
                    phase = self._infer_phase(a)
                phase_set.add(phase)
                ordered_alerts.setdefault(phase, []).append(a)

            if len(phase_set) >= 2:
                sequence = [self.PHASE_NAMES[p] for p in sorted(phase_set) if p in self.PHASE_NAMES]
                completeness = round(len(phase_set) / 6.0, 2)
                chains.append({
                    "chain_id": "chain-" + uuid.uuid4().hex[:10],
                    "source_ip": src,
                    "phases_reached": sorted(phase_set),
                    "phase_sequence": sequence,
                    "completeness": completeness,
                    "alert_count": len(group),
                    "alerts": group,
                    "assessment": "完整攻击链" if completeness >= 0.7 else "部分攻击链",
                })
        chains.sort(key=lambda c: c["completeness"], reverse=True)
        return chains

    def _infer_phase(self, alert: Dict[str, Any]) -> int:
        """无 MITRE 标签时，依据攻击类型推断阶段"""
        at = str(alert.get("attack_type", "")).lower()
        table = {
            "recon": 1, "scan": 2, "port_scan": 2, "brute_force": 3,
            "exploit": 3, "web_attack": 3, "privilege_escalation": 4,
            "lateral_movement": 5, "data_exfiltration": 6,
        }
        for k, v in table.items():
            if k in at:
                return v
        return 0

    # ---------------- 关联主入口 ----------------
    def correlate(self, alerts: List[Dict[str, Any]]) -> str:
        """
        启动告警关联分析，返回 task_id。
        流程：误报识别 → 聚合 → 优先级计算 → 攻击链识别。
        """
        task_id = "corr-" + uuid.uuid4().hex[:12]
        self._tasks[task_id] = {"status": "running", "created_at": _now(), "type": "alert_correlate"}
        try:
            clean = self.detect_false_positives(alerts or [])
            real_alerts = [a for a in clean if not a.get("is_false_positive")]
            aggregated = self.aggregate_alerts(real_alerts)
            # 为每条告警计算优先级
            for a in real_alerts:
                a["priority"] = self.calculate_priority(a)
            attack_chains = self.identify_attack_chains(real_alerts)

            self._correlated[task_id] = real_alerts
            self._aggregated[task_id] = aggregated
            self._attack_chains[task_id] = attack_chains
            self._tasks[task_id] = {
                "status": "completed",
                "created_at": self._tasks[task_id]["created_at"],
                "completed_at": _now(),
                "input_count": len(alerts or []),
                "false_positive_count": len(clean) - len(real_alerts),
                "correlated_count": len(real_alerts),
                "aggregated_events": len(aggregated),
                "attack_chains": len(attack_chains),
            }
        except Exception as e:  # pragma: no cover
            self._tasks[task_id] = {"status": "failed", "error": str(e), "created_at": _now()}
            self._correlated[task_id] = []
            self._aggregated[task_id] = []
            self._attack_chains[task_id] = []
        return task_id

    # ---------------- 结果获取 ----------------
    def get_attack_chains(self, task_id: str) -> List[Dict[str, Any]]:
        """获取攻击链识别结果"""
        return self._attack_chains.get(task_id, [])

    def get_aggregated(self, task_id: str) -> List[Dict[str, Any]]:
        """获取聚合告警"""
        return self._aggregated.get(task_id, [])

    def get_correlated(self, task_id: str) -> List[Dict[str, Any]]:
        """获取关联后的告警"""
        return self._correlated.get(task_id, [])

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        task = self._tasks.get(task_id, {})
        return {"task_id": task_id, **task} if task else {"task_id": task_id, "status": "not_found"}

    # ---------------- 报告 ----------------
    def generate_report(self, task_id: str) -> Dict[str, Any]:
        """生成告警关联分析报告：攻击链 / 相关告警 / 影响分析 / 建议"""
        chains = self._attack_chains.get(task_id, [])
        aggregated = self._aggregated.get(task_id, [])
        correlated = self._correlated.get(task_id, [])
        task = self._tasks.get(task_id, {})
        return {
            "report_type": "alert_correlation",
            "task_id": task_id,
            "generated_at": _now(),
            "task_status": task.get("status"),
            "summary": {
                "input_alerts": task.get("input_count", len(correlated)),
                "false_positives": task.get("false_positive_count", 0),
                "aggregated_events": len(aggregated),
                "attack_chain_count": len(chains),
            },
            "attack_chains": chains,
            "aggregated_events": aggregated,
            "related_alerts": correlated,
            "impact_analysis": self._impact(chains, aggregated),
            "recommendations": self._recommend(chains),
        }

    @staticmethod
    def _impact(chains: List[Dict[str, Any]], aggregated: List[Dict[str, Any]]) -> Dict[str, Any]:
        critical = [c for c in aggregated if c.get("severity") == "critical"]
        return {
            "critical_events": len(critical),
            "chains_detected": len(chains),
            "highest_completeness": max((c["completeness"] for c in chains), default=0.0),
            "overall_risk": "critical" if chains and chains[0]["completeness"] >= 0.7 else "elevated" if chains else "normal",
        }

    @staticmethod
    def _recommend(chains: List[Dict[str, Any]]) -> List[str]:
        recs = []
        if any("数据窃取" in c["phase_sequence"] for c in chains):
            recs.append("检测到数据窃取阶段，立即隔离受影响主机并开展数据泄露评估")
        if any("横向移动" in c["phase_sequence"] for c in chains):
            recs.append("存在横向移动迹象，进行网段隔离并轮换凭证")
        if not recs:
            recs.append("对聚合事件进行优先级排序，优先处置 critical/high 级别事件")
        recs.append("维护误报白名单，持续降低告警噪音")
        return recs


# ---------------- 模块级单例 ----------------
_alert_correlator_instance: Optional[AlertCorrelator] = None


def get_alert_correlator() -> AlertCorrelator:
    global _alert_correlator_instance
    if _alert_correlator_instance is None:
        _alert_correlator_instance = AlertCorrelator()
    return _alert_correlator_instance


alert_correlator: AlertCorrelator = get_alert_correlator()
