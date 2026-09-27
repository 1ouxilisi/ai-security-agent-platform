#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
advanced_threat_dashboard.py — 高级威胁检测控制台数据层
=======================================================

功能：
    1. 威胁总览：威胁等级/数量/类型/趋势/攻击链数/狩猎任务数/告警数/响应数
    2. UEBA 管理：用户列表/实体列表/行为基线/风险评分/异常行为/告警/同行分析
    3. ML 管理：模型列表/训练/推理/监控/异常检测/分类/解释
    4. APT 检测：APT告警/攻击链/基础设施/数据渗出/威胁狩猎/任务/结果
    5. 攻击链管理：列表/详情/重建/可视化/分析/预测/知识库
    6. 系统设置：检测规则/模型配置/狩猎配置/告警配置/通知配置/数据源/审计

全部内存字典模拟，聚合各子系统数据。
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .ueba_engine import ueba_engine
from .ml_anomaly import ml_anomaly
from .apt_detection import apt_detector
from .attack_chain import attack_chain_analyzer
from .threat_hunt import threat_hunt_platform


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class AdvancedThreatDashboard:
    """高级威胁检测控制台数据聚合层。"""

    def __init__(self) -> None:
        self.settings: Dict[str, Any] = {
            "detection_rules": {
                "ueba_enabled": True,
                "ml_anomaly_enabled": True,
                "apt_detection_enabled": True,
                "attack_chain_enabled": True,
                "threat_hunt_enabled": True,
                "sensitivity": "medium",
            },
            "model_config": {
                "default_algorithm": "isolation_forest",
                "auto_retrain": True,
                "retrain_threshold_drift": 0.2,
                "retrain_interval_days": 7,
                "batch_size": 1000,
            },
            "hunt_config": {
                "default_time_range_h": 24,
                "auto_hunt_enabled": True,
                "hunt_interval_h": 6,
                "max_parallel_hunts": 5,
            },
            "alert_config": {
                "min_severity": "medium",
                "escalation_threshold": "critical",
                "auto_response_enabled": True,
                "notification_channels": ["email", "webhook", "sms"],
            },
            "notification_config": {
                "email_recipients": ["soc-team@company.com"],
                "webhook_url": "https://hooks.example.com/soc",
                "enable_sms": False,
                "quiet_hours": {"start": "22:00", "end": "07:00"},
            },
            "data_source_config": {
                "windows_logs": True,
                "linux_logs": True,
                "dns_logs": True,
                "proxy_logs": True,
                "edr_telemetry": True,
                "network_flow": True,
            },
            "audit_config": {
                "audit_enabled": True,
                "retention_days": 90,
                "log_all_actions": True,
            },
        }
        self.audit_logs: List[Dict[str, Any]] = []

    # ---------- 威胁总览 ----------

    def threat_overview(self) -> Dict[str, Any]:
        """全局威胁总览。"""
        ueba_ov = ueba_engine.overview()
        ml_ov = ml_anomaly.overview()
        apt_ov = apt_detector.overview()
        chain_ov = attack_chain_analyzer.overview()
        hunt_ov = threat_hunt_platform.overview()

        total_threats = (ueba_ov.get("total_alerts", 0) + ml_ov.get("total_anomalies", 0) +
                         apt_ov.get("exfiltration_events", 0) + chain_ov.get("critical_chains", 0))

        # 威胁趋势（7天）
        trend = []
        for i in range(7, 0, -1):
            day = (datetime.now() - timedelta(days=i)).strftime("%m-%d")
            trend.append({
                "date": day,
                "threats": random.randint(10, 80),
                "alerts": random.randint(5, 40),
                "resolved": random.randint(5, 35),
            })

        return {
            "threat_level": "high" if total_threats > 50 else ("medium" if total_threats > 20 else "low"),
            "total_threats": total_threats,
            "threat_types": {
                "ueba_alerts": ueba_ov.get("total_alerts", 0),
                "ml_anomalies": ml_ov.get("total_anomalies", 0),
                "apt_events": apt_ov.get("exfiltration_events", 0),
                "attack_chains": chain_ov.get("total_detected_chains", 0),
            },
            "threat_trend_7d": trend,
            "active_chains": chain_ov.get("active_chains", 0),
            "hunt_tasks": hunt_ov.get("total_hunt_sessions", 0),
            "total_alerts": ueba_ov.get("total_alerts", 0),
            "open_alerts": ueba_ov.get("open_alerts", 0),
            "response_rate": round(random.uniform(0.75, 0.95), 3),
            "ueba": ueba_ov,
            "ml": ml_ov,
            "apt": apt_ov,
            "chain": chain_ov,
            "hunt": hunt_ov,
        }

    # ---------- UEBA 管理视图 ----------

    def ueba_view(self) -> Dict[str, Any]:
        """UEBA 管理面板数据。"""
        return {
            "users": [
                {"user_id": u["user_id"], "username": u["username"], "department": u["department"],
                 "role": u["role"], "risk_score": u["risk_score"], "risk_level": u["risk_level"],
                 "status": u["status"]}
                for u in ueba_engine.users
            ],
            "entities": [
                {"entity_id": e["entity_id"], "name": e["name"], "type": e["type"],
                 "risk_score": e["risk_score"], "status": e["status"]}
                for e in ueba_engine.entities
            ],
            "alerts": ueba_engine.list_alerts(),
            "peer_groups": ueba_engine.peer_group_analysis(),
            "overview": ueba_engine.overview(),
        }

    # ---------- ML 管理视图 ----------

    def ml_view(self) -> Dict[str, Any]:
        """ML 管理面板数据。"""
        return {
            "models": list(ml_anomaly.models.values()),
            "algorithms": ml_anomaly.algorithms,
            "anomalies": ml_anomaly.anomalies[-20:],
            "drift_reports": ml_anomaly.drift_reports[-10:],
            "explanations": ml_anomaly.explanations[-5:],
            "overview": ml_anomaly.overview(),
        }

    # ---------- APT 检测视图 ----------

    def apt_view(self) -> Dict[str, Any]:
        """APT 检测面板数据。"""
        return {
            "alerts": ueba_engine.list_alerts(severity="critical") + ueba_engine.list_alerts(severity="high"),
            "c2_infrastructure": apt_detector.c2_infrastructure,
            "exfiltration_events": apt_detector.exfiltration_events,
            "hunt_jobs": apt_detector.hunt_jobs,
            "ttp_profiles": apt_detector.ttp_profiles,
            "techniques": apt_detector.techniques,
            "overview": apt_detector.overview(),
        }

    # ---------- 攻击链管理视图 ----------

    def chain_view(self) -> Dict[str, Any]:
        """攻击链管理面板数据。"""
        return {
            "chains": attack_chain_analyzer.detected_chains,
            "kill_chain": attack_chain_analyzer.kill_chain,
            "knowledge_base": attack_chain_analyzer.get_knowledge_base(),
            "overview": attack_chain_analyzer.overview(),
        }

    # ---------- 狩猎管理视图 ----------

    def hunt_view(self) -> Dict[str, Any]:
        """狩猎管理面板数据。"""
        return {
            "templates": threat_hunt_platform.templates,
            "sessions": threat_hunt_platform.hunt_sessions[-10:],
            "reports": threat_hunt_platform.hunt_reports,
            "metrics": threat_hunt_platform.get_metrics(),
            "knowledge_base": threat_hunt_platform.knowledge_base,
            "best_practices": [
                "狩猎前明确假设，避免无目的数据探索",
                "优先覆盖 ATT&CK 高权重技术",
                "结合 IOC + TTP + 行为分析三层检测",
                "狩猎结果需闭环到规则和 SIEM",
                "定期回顾狩猎模板有效性",
            ],
        }

    # ---------- 系统设置 ----------

    def get_settings(self) -> Dict[str, Any]:
        """获取系统设置。"""
        return self.settings

    def update_settings(self, section: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """更新系统设置。"""
        if section in self.settings:
            self.settings[section].update(updates)
            self._audit("update_settings", section, updates)
            return {"success": True, "section": section, "settings": self.settings[section]}
        return {"error": f"设置节 '{section}' 不存在"}

    def _audit(self, action: str, target: str, detail: Any) -> None:
        """记录审计日志。"""
        self.audit_logs.append({
            "audit_id": f"AUD-{len(self.audit_logs)+1:05d}",
            "action": action, "target": target,
            "detail": str(detail)[:200],
            "timestamp": _now(),
            "operator": "admin",
        })

    def list_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """列出审计日志。"""
        return list(reversed(self.audit_logs[-limit:]))

    # ---------- 综合报表 ----------

    def generate_report(self) -> Dict[str, Any]:
        """生成高级威胁检测综合报表。"""
        ov = self.threat_overview()
        return {
            "report_id": f"ATRPT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "generated_at": _now(),
            "summary": {
                "overall_threat_level": ov["threat_level"],
                "total_threats": ov["total_threats"],
                "open_alerts": ov["open_alerts"],
                "active_chains": ov["active_chains"],
                "hunt_coverage": threat_hunt_platform.metrics["hunt_coverage"],
            },
            "ueba_summary": ueba_engine.overview(),
            "ml_summary": ml_anomaly.overview(),
            "apt_summary": apt_detector.overview(),
            "chain_summary": attack_chain_analyzer.overview(),
            "recommendations": [
                "对高风险用户加强多因素认证",
                "对偏离基线的服务器加强监控",
                "更新 ML 模型以应对最新漂移",
                "扩大威胁狩猎覆盖范围",
                "完善 C2 基础设施黑名单",
            ],
        }


# 单例
advanced_threat_dashboard = AdvancedThreatDashboard()
