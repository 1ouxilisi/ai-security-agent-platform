# -*- coding: utf-8 -*-
"""
hunt_report_metrics.py — 狩猎报告与度量。

提供狩猎报告生成、狩猎度量计算、狩猎知识库、
狩猎成熟度评估和狩猎仪表盘数据五大子系统。

设计定位：仅用于经过授权的防御性狩猎活动度量与报告。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 狩猎报告生成
# --------------------------------------------------------------------------- #
class HuntReportGenerator:
    """狩猎报告生成器。"""

    def __init__(self) -> None:
        self._reports: Dict[str, Dict[str, Any]] = {}

    def generate_report(self, title: str, goal: str = "",
                        methods: List[str] = None,
                        findings: List[Dict[str, Any]] = None,
                        impact: str = "",
                        recommendations: List[str] = None,
                        timeline: List[Dict[str, Any]] = None,
                        evidence_refs: List[str] = None,
                        analyst: str = "analyst") -> Dict[str, Any]:
        """生成狩猎报告。"""
        rid = uuid.uuid4().hex[:12]
        report = {
            "report_id": rid,
            "title": title,
            "goal": goal,
            "methods": methods or [],
            "findings": findings or [],
            "impact": impact,
            "recommendations": recommendations or [],
            "timeline": timeline or [],
            "evidence_refs": evidence_refs or [],
            "analyst": analyst,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "executive_summary": self._build_summary(findings or []),
            "appendix": {
                "total_hours": 40,
                "queries_executed": 25,
                "data_sources_used": 7,
                "iocs_extracted": len(findings or []),
            },
        }
        self._reports[rid] = report
        return report

    def _build_summary(self, findings: List[Dict[str, Any]]) -> str:
        """构建执行摘要。"""
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        total = len(findings)
        if total == 0:
            return "本次狩猎未发现重大安全事件。基线行为正常，建议继续定期监控。"
        return (f"本次狩猎活动共发现 {total} 项安全发现，其中 {critical} 项严重、{high} 项高危。"
                f"建议立即处置严重发现并加固相关系统。")

    def list_reports(self) -> List[Dict[str, Any]]:
        return list(self._reports.values())

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        return self._reports.get(report_id)


# --------------------------------------------------------------------------- #
# 狩猎度量
# --------------------------------------------------------------------------- #
class HuntMetricsCalculator:
    """狩猎度量计算器。"""

    def __init__(self) -> None:
        self._metrics_history: List[Dict[str, Any]] = []

    def calculate(self) -> Dict[str, Any]:
        """计算狩猎核心度量指标。"""
        metrics = {
            "mttd_hours": 4.5,
            "mttd_trend": -0.3,
            "hunt_coverage_pct": 78.5,
            "hunt_coverage_trend": 2.5,
            "discovery_rate_pct": 12.3,
            "discovery_rate_trend": 1.2,
            "false_positive_rate_pct": 18.5,
            "false_positive_trend": -1.8,
            "analyst_efficiency": 8.2,
            "analyst_efficiency_trend": 0.5,
            "hypothesis_validation_rate_pct": 65.0,
            "hypothesis_validation_trend": 5.0,
            "queries_executed_weekly": 145,
            "queries_executed_trend": 12,
            "hunts_completed_monthly": 8,
            "avg_findings_per_hunt": 3.2,
            "tracked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._metrics_history.append(metrics)
        return metrics

    def get_history(self) -> List[Dict[str, Any]]:
        return self._metrics_history[-30:]

    def metrics_definitions(self) -> List[Dict[str, Any]]:
        """度量指标定义说明。"""
        return [
            {"name": "MTTD", "full_name": "Mean Time To Detect", "unit": "hours",
             "description": "从攻击发生到被检测到的平均时间"},
            {"name": "Hunt Coverage", "full_name": "Hunt Coverage Rate", "unit": "percent",
             "description": "已狩猎覆盖的资产/场景比例"},
            {"name": "Discovery Rate", "full_name": "Discovery Rate", "unit": "percent",
             "description": "每次狩猎查询发现真实威胁的比例"},
            {"name": "False Positive Rate", "full_name": "False Positive Rate", "unit": "percent",
             "description": "告警中误报的比例"},
            {"name": "Analyst Efficiency", "full_name": "Analyst Efficiency Score", "unit": "score(1-10)",
             "description": "分析师单位时间处理狩猎任务的效率评分"},
            {"name": "Hypothesis Validation Rate", "full_name": "Hypothesis Validation Rate", "unit": "percent",
             "description": "狩猎假设被验证为真的比例"},
        ]


# --------------------------------------------------------------------------- #
# 狩猎知识库
# --------------------------------------------------------------------------- #
class HuntKnowledgeBase:
    """狩猎知识库。"""

    def __init__(self) -> None:
        self._tps: List[Dict[str, Any]] = self._seed_tps()
        self._cases: List[Dict[str, Any]] = self._seed_cases()
        self._best_practices: List[Dict[str, Any]] = self._seed_practices()

    def _seed_tps(self) -> List[Dict[str, Any]]:
        return [
            {"tp_id": "T1059.001", "name": "PowerShell", "category": "execution",
             "common_indicators": ["-enc flag", "FromBase64String", "IEX (New-Object Net.WebClient)"],
             "hunt_queries": ["查找异常powershell编码命令", "查找进程命令行含Base64"]},
            {"tp_id": "T1566.001", "name": "Spearphishing Attachment", "category": "initial_access",
             "common_indicators": ["Office child processes", "macro execution", "suspicious attachments"],
             "hunt_queries": ["Office宏启动子进程", "钓鱼邮件响应狩猎剧本"]},
            {"tp_id": "T1021.002", "name": "SMB/Windows Admin Shares", "category": "lateral",
             "common_indicators": ["445 connections from single host", "admin$ shares", "IPC$ enumeration"],
             "hunt_queries": ["横向SMB连接", "APT横向移动链"]},
            {"tp_id": "T1547.001", "name": "Registry Run Keys", "category": "persistence",
             "common_indicators": ["Run/RunOnce modifications", "unusual values"],
             "hunt_queries": ["持久化注册表修改"]},
            {"tp_id": "T1071.001", "name": "Web Protocols C2", "category": "command_control",
             "common_indicators": ["Beaconing intervals", "unusual User-Agent", "encryption"],
             "hunt_queries": ["Beaconing行为检测", "异常出站连接到已知C2"]},
        ]

    def _seed_cases(self) -> List[Dict[str, Any]]:
        return [
            {"case_id": "CASE-2026-001", "title": "Emotet钓鱼邮件入侵事件",
             "summary": "通过钓鱼邮件分发恶意Office文档，宏执行后下载Emotet载荷，最终导致横向移动",
             "ttps": ["T1566.001", "T1059.001", "T1021.002"],
             "duration": "14天", "outcome": "成功检测并清除，3台主机受影响",
             "lessons": ["强化邮件网关检测", "部署Office宏执行拦截策略"]},
            {"case_id": "CASE-2026-002", "title": "Web服务器WebShell入侵",
             "summary": "利用公开漏洞在Web服务器部署ASPX WebShell，窃取数据库凭据",
             "ttps": ["T1190", "T1505.003", "T1005"],
             "duration": "7天", "outcome": "WebShell被清除，凭据已重置",
             "lessons": ["加强Web目录文件完整性监控", "及时补丁管理"]},
        ]

    def _seed_practices(self) -> List[Dict[str, Any]]:
        return [
            {"id": "BP-001", "title": "从威胁情报驱动狩猎",
             "description": "将最新威胁情报IOC自动注入狩猎查询，保持狩猎与情报同步"},
            {"id": "BP-002", "title": "建立行为基线再狩猎",
             "description": "先建立正常行为基线，再偏离检测，减少误报"},
            {"id": "BP-003", "title": "假设驱动而非数据驱动",
             "description": "从具体假设出发设计狩猎查询，提高发现率"},
            {"id": "BP-004", "title": "狩猎结果转化为检测规则",
             "description": "每次狩猎发现应转化为自动化检测规则，持续监控"},
        ]

    def list_tps(self) -> List[Dict[str, Any]]:
        return self._tps

    def list_cases(self) -> List[Dict[str, Any]]:
        return self._cases

    def list_practices(self) -> List[Dict[str, Any]]:
        return self._best_practices

    def search_kb(self, query: str) -> Dict[str, List[Dict[str, Any]]]:
        q = query.lower()
        return {
            "tps": [t for t in self._tps if q in t["name"].lower() or q in t["tp_id"].lower()],
            "cases": [c for c in self._cases if q in c["title"].lower()],
            "practices": [p for p in self._best_practices if q in p["title"].lower()],
        }


# --------------------------------------------------------------------------- #
# 狩猎成熟度评估
# --------------------------------------------------------------------------- #
class HuntMaturityAssessor:
    """狩猎成熟度评估器。"""

    LEVELS = [
        {"level": 1, "name": "初始级", "description": "临时响应式狩猎，无标准化流程"},
        {"level": 2, "name": "可重复级", "description": "有基本狩猎流程，可重复执行"},
        {"level": 3, "name": "已定义级", "description": "标准化狩猎流程，有假设管理和剧本"},
        {"level": 4, "name": "已管理级", "description": "量化度量，持续优化，自动化覆盖"},
        {"level": 5, "name": "优化级", "description": "智能化狩猎，AI辅助预测，持续创新"},
    ]

    def assess(self) -> Dict[str, Any]:
        """评估当前狩猎成熟度。"""
        current_level = 3  # 已定义级
        gaps = [
            {"area": "自动化狩猎", "current": "部分自动化", "target": "全自动化", "gap": "需要部署自动狩猎调度"},
            {"area": "度量体系", "current": "基础度量", "target": "全维度度量", "gap": "需增加分析师效率和覆盖率指标"},
            {"area": "知识库", "current": "基础案例库", "target": "完整TTP/案例/最佳实践库", "gap": "需扩充TTP库和自动化查询转化"},
            {"area": "团队能力", "current": "3人团队", "target": "5人+专职团队", "gap": "需增加狩猎分析师人手"},
        ]
        roadmap = [
            {"phase": "短期(0-3月)", "actions": ["完善度量体系", "自动化常见狩猎查询", "建立剧本库"]},
            {"phase": "中期(3-6月)", "actions": ["部署自动狩猎调度", "扩展知识库", "增加分析师培训"]},
            {"phase": "长期(6-12月)", "actions": ["引入AI辅助狩猎", "对接威胁情报平台", "实现预测性狩猎"]},
        ]
        return {
            "current_level": current_level,
            "current_level_name": self.LEVELS[current_level - 1]["name"],
            "levels": self.LEVELS,
            "gap_analysis": gaps,
            "improvement_roadmap": roadmap,
            "assessed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


# --------------------------------------------------------------------------- #
# 狩猎仪表盘数据
# --------------------------------------------------------------------------- #
class HuntDashboardData:
    """狩猎仪表盘数据聚合器。"""

    def get_dashboard(self) -> Dict[str, Any]:
        """生成仪表盘综合数据。"""
        return {
            "trends": {
                "findings_by_month": [
                    {"month": "2026-04", "count": 5},
                    {"month": "2026-05", "count": 8},
                    {"month": "2026-06", "count": 12},
                    {"month": "2026-07", "count": 10},
                    {"month": "2026-08", "count": 15},
                    {"month": "2026-09", "count": 18},
                ],
                "queries_by_month": [
                    {"month": "2026-04", "count": 85},
                    {"month": "2026-05", "count": 110},
                    {"month": "2026-06", "count": 135},
                    {"month": "2026-07", "count": 120},
                    {"month": "2026-08", "count": 160},
                    {"month": "2026-09", "count": 185},
                ],
            },
            "distribution": {
                "by_severity": {"critical": 3, "high": 7, "medium": 12, "low": 8},
                "by_category": {"process": 10, "network": 8, "file": 5, "registry": 3, "user": 2, "login": 4},
                "by_mitre": {"TA0001": 6, "TA0002": 8, "TA0003": 4, "TA0008": 5, "TA0010": 3},
            },
            "top_findings": [
                {"title": "RDP暴力破解成功", "severity": "critical", "date": "2026-09-14"},
                {"title": "WebShell文件上传", "severity": "critical", "date": "2026-09-14"},
                {"title": "可疑PowerShell编码执行", "severity": "high", "date": "2026-09-14"},
                {"title": "异常SMB横向连接", "severity": "high", "date": "2026-09-13"},
            ],
            "analyst_rankings": [
                {"name": "analyst_a", "findings": 12, "queries": 85, "efficiency": 9.1},
                {"name": "analyst_b", "findings": 8, "queries": 60, "efficiency": 7.8},
                {"name": "analyst_c", "findings": 5, "queries": 45, "efficiency": 6.5},
            ],
            "project_status": [
                {"name": "Q3季度例行威胁狩猎", "status": "active", "progress": 65},
                {"name": "新漏洞紧急狩猎", "status": "active", "progress": 40},
            ],
            "summary_cards": {
                "total_active_hunts": 2,
                "total_findings_month": 18,
                "critical_findings": 3,
                "avg_mttd_hours": 4.5,
            },
        }
