#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 根因分析器 (Root Cause Analyzer)
===================================

功能：
    - 8 类根因：配置错误 / 漏洞利用 / 权限不当 / 软件缺陷 /
      硬件故障 / 人为失误 / 外部攻击 / 内部威胁
    - 分析方法：
        1. 基于日志：错误日志 / 审计日志 / 系统日志模式匹配
        2. 基于拓扑：依赖关系 / 影响范围分析
        3. 基于时间线：事件序列 / 因果关系推断
    - 证据收集：日志 / 配置 / 快照 / 流量摘要
    - 根因评分：每个可能根因的置信度评分（0-100）
    - 修复建议：步骤 / 配置 / 验证方法
    - 根因报告：事件概述 / 时间线 / 根因 / 证据 / 修复建议 / 预防措施

仅用于授权的安全运营与故障排查场景。
"""
import os
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat()


class RootCauseAnalyzer:
    """AI 根因分析器"""

    ROOT_CAUSE_TYPES = ["配置错误", "漏洞利用", "权限不当", "软件缺陷",
                        "硬件故障", "人为失误", "外部攻击", "内部威胁"]

    # 日志模式 -> 根因 映射
    LOG_PATTERN_MAP: Dict[str, str] = {
        "permission denied": "权限不当",
        "access denied": "权限不当",
        "authentication failed": "权限不当",
        "stack trace": "软件缺陷",
        "exception": "软件缺陷",
        "segfault": "软件缺陷",
        "oom": "硬件故障",
        "disk full": "硬件故障",
        "i/o error": "硬件故障",
        "misconfiguration": "配置错误",
        "invalid config": "配置错误",
        "default credential": "配置错误",
        "exploit": "漏洞利用",
        "cve": "漏洞利用",
        "remote code execution": "漏洞利用",
        "brute force": "外部攻击",
        "ddos": "外部攻击",
        "unauthorized": "外部攻击",
        "offboarding": "内部威胁",
        "privilege abuse": "内部威胁",
        "manual change": "人为失误",
        "human error": "人为失误",
    }

    # 各类根因的修复建议模板
    FIX_TEMPLATES: Dict[str, Dict[str, Any]] = {
        "配置错误": {
            "steps": ["复核配置文件变更记录", "对比标准基线配置", "回滚错误配置", "灰度验证"],
            "config": "启用配置版本管理与变更审计",
            "verify": "检查目标服务配置加载日志与健康检查",
        },
        "漏洞利用": {
            "steps": ["确认受影响资产", "隔离受影响主机", "应用补丁/临时缓解", "复扫验证"],
            "config": "建立补丁管理流程，及时修复已知 CVE",
            "verify": "漏洞复扫结果与 exploit 验证",
        },
        "权限不当": {
            "steps": ["审计账号权限", "回收多余权限", "最小权限原则收敛", "开启 MFA"],
            "config": "实施 RBAC 与定期权限复核",
            "verify": "权限审计报告与登录日志复核",
        },
        "软件缺陷": {
            "steps": ["定位异常堆栈", "确认版本", "升级/热修复", "回归测试"],
            "config": "完善异常监控与告警",
            "verify": "回归测试用例通过与错误率下降",
        },
        "硬件故障": {
            "steps": ["确认硬件告警", "迁移业务", "更换硬件", "恢复业务"],
            "config": "部署硬件健康监控",
            "verify": "硬件传感器指标与业务恢复验证",
        },
        "人为失误": {
            "steps": ["复盘操作记录", "恢复正确操作", "加强操作规范", "双人复核"],
            "config": "关键操作变更审批与双人复核",
            "verify": "操作日志复核与业务一致性校验",
        },
        "外部攻击": {
            "steps": ["封禁攻击源", "IOC 排查", "加固边界", "威胁狩猎"],
            "config": "部署 WAF/IPS 并更新威胁情报",
            "verify": "攻击源封禁生效与攻击流量下降",
        },
        "内部威胁": {
            "steps": ["冻结相关账号", "审计行为日志", "数据外泄评估", "制度问责"],
            "config": "部署用户行为分析(UBA)与数据防泄漏(DLP)",
            "verify": "账号冻结生效与异常行为监控",
        },
    }

    def __init__(self):
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._results: Dict[str, List[Dict[str, Any]]] = {}
        self._evidence: Dict[str, List[Dict[str, Any]]] = {}
        self._data_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "ai_soc", "root_cause"
        )
        os.makedirs(self._data_dir, exist_ok=True)

    # ---------------- 主分析入口 ----------------
    def analyze(self,
                event_id: str,
                logs: Optional[List[str]] = None,
                topology: Optional[Dict[str, Any]] = None,
                timeline: Optional[List[Dict[str, Any]]] = None) -> str:
        """启动根因分析，返回 task_id"""
        task_id = "rca-" + uuid.uuid4().hex[:12]
        self._tasks[task_id] = {"status": "running", "event_id": event_id, "created_at": _now()}
        try:
            evidence = self.collect_evidence(event_id, logs, topology, timeline)
            analysis_data = {
                "logs": logs or [],
                "topology": topology or {},
                "timeline": timeline or [],
                "evidence": evidence,
            }
            causes = self.score_root_causes(analysis_data)
            self._evidence[task_id] = evidence
            self._results[task_id] = causes
            self._tasks[task_id] = {
                "status": "completed",
                "event_id": event_id,
                "created_at": self._tasks[task_id]["created_at"],
                "completed_at": _now(),
                "candidate_count": len(causes),
                "root_cause": causes[0]["type"] if causes else "未知",
            }
        except Exception as e:  # pragma: no cover
            self._tasks[task_id] = {"status": "failed", "event_id": event_id,
                                    "error": str(e), "created_at": _now()}
            self._results[task_id] = []
            self._evidence[task_id] = []
        return task_id

    # ---------------- 证据收集 ----------------
    def collect_evidence(self, event_id: str,
                         logs: Optional[List[str]] = None,
                         topology: Optional[Dict[str, Any]] = None,
                         timeline: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """自动收集相关证据：日志 / 配置 / 快照 / 流量摘要"""
        evidence: List[Dict[str, Any]] = []
        if logs:
            evidence.append({"type": "log", "count": len(logs),
                             "samples": [str(l)[:200] for l in logs[:5]]})
        if topology:
            evidence.append({"type": "topology", "nodes": len(topology.get("nodes", [])),
                             "edges": len(topology.get("edges", []))})
        if timeline:
            evidence.append({"type": "timeline", "events": len(timeline)})
        if not evidence:
            evidence.append({"type": "note", "message": "未提供外部证据，基于事件元数据推断"})
        return evidence

    # ---------------- 根因评分 ----------------
    def score_root_causes(self, analysis_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """对每个可能根因进行置信度评分（0-100），按置信度降序"""
        votes: Dict[str, int] = {c: 0 for c in self.ROOT_CAUSE_TYPES}
        logs = analysis_data.get("logs", [])

        # 1. 基于日志的模式匹配
        for line in logs:
            low = str(line).lower()
            for pattern, cause in self.LOG_PATTERN_MAP.items():
                if pattern in low:
                    votes[cause] += 1

        # 2. 基于时间线的因果推断：最早出现的事件指向根因
        timeline = analysis_data.get("timeline", [])
        if timeline:
            earliest = str(timeline[0]).lower()
            for pattern, cause in self.LOG_PATTERN_MAP.items():
                if pattern in earliest:
                    votes[cause] += 3  # 时间线最早事件权重更高

        # 3. 基于拓扑：上游节点故障影响下游
        topology = analysis_data.get("topology", {})
        if topology.get("downstream_impact"):
            votes["配置错误"] += 1

        # 归一化为置信度评分
        max_votes = max(votes.values()) if any(votes.values()) else 0
        results: List[Dict[str, Any]] = []
        for cause, v in votes.items():
            if v > 0 or max_votes == 0:
                confidence = int(min(100, round((v / (max_votes or 1)) * 80 + (20 if v > 0 else 0))))
                results.append({
                    "type": cause,
                    "confidence": confidence,
                    "votes": v,
                })
        results.sort(key=lambda r: r["confidence"], reverse=True)
        return results

    # ---------------- 修复建议 ----------------
    def get_fix_suggestions(self, root_cause: str) -> Dict[str, Any]:
        """基于根因提供修复建议：步骤 / 配置 / 验证方法"""
        template = self.FIX_TEMPLATES.get(root_cause, {
            "steps": ["人工排查确认"], "config": "—", "verify": "人工验证",
        })
        return {"root_cause": root_cause, **template}

    # ---------------- 结果获取 ----------------
    def get_results(self, task_id: str) -> List[Dict[str, Any]]:
        """获取根因分析结果（含置信度排序）"""
        return self._results.get(task_id, [])

    def get_evidence(self, task_id: str) -> List[Dict[str, Any]]:
        """获取证据列表"""
        return self._evidence.get(task_id, [])

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        task = self._tasks.get(task_id, {})
        return {"task_id": task_id, **task} if task else {"task_id": task_id, "status": "not_found"}

    # ---------------- 报告 ----------------
    def generate_report(self, task_id: str) -> Dict[str, Any]:
        """生成根因分析报告"""
        causes = self._results.get(task_id, [])
        evidence = self._evidence.get(task_id, [])
        task = self._tasks.get(task_id, {})
        top = causes[0] if causes else {"type": "未知", "confidence": 0}
        fix = self.get_fix_suggestions(top["type"])
        return {
            "report_type": "root_cause_analysis",
            "task_id": task_id,
            "event_id": task.get("event_id"),
            "generated_at": _now(),
            "task_status": task.get("status"),
            "event_summary": task.get("event_id", "未知事件"),
            "root_cause": top,
            "candidates": causes,
            "evidence": evidence,
            "fix_suggestions": fix,
            "prevention": [
                "建立变更管理与配置基线，防止配置错误复发",
                "定期漏洞扫描与补丁管理",
                "加强最小权限与访问审计",
                "完善监控告警与可观测性",
            ],
        }


# ---------------- 模块级单例 ----------------
_root_cause_analyzer_instance: Optional[RootCauseAnalyzer] = None


def get_root_cause_analyzer() -> RootCauseAnalyzer:
    global _root_cause_analyzer_instance
    if _root_cause_analyzer_instance is None:
        _root_cause_analyzer_instance = RootCauseAnalyzer()
    return _root_cause_analyzer_instance


root_cause_analyzer: RootCauseAnalyzer = get_root_cause_analyzer()
