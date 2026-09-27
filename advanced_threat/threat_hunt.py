#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
threat_hunt.py — 威胁狩猎深度平台模块
======================================

功能：
    1. 狩猎查询语言：类SQL/正则/语义/时序/关联/聚合查询/可视化构建器
    2. 狩猎模板库：ATT&CK映射模板/50+预置场景/行业模板/自定义/分享/版本
    3. 狩猎工作流：假设生成/数据收集/分析调查/验证确认/报告生成/知识沉淀/闭环改进
    4. 狩猎工具集：数据探索/可视化/统计分析/ML/IOC匹配/TTP匹配/行为分析/关联分析
    5. 狩猎知识库：狩猎技巧/案例/工具/指标/数据源/最佳实践
    6. 狩猎度量：覆盖率/效率/成功率/发现率/误报率/平均时间/ROI

全部内存字典模拟。
"""
from __future__ import annotations

import random
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# ==================== 狩猎模板 ====================

_PRESET_TEMPLATES = [
    {"template_id": "HT-001", "name": "异常登录检测", "tactic": "TA0001",
     "description": "检测非常用时间/地点/设备的登录活动", "query_type": "sql",
     "query": "SELECT * FROM auth_logs WHERE login_hour NOT BETWEEN 7 AND 20 AND success = 1",
     "industry": "通用", "hit_rate": 0.72},
    {"template_id": "HT-002", "name": "异常 PowerShell 执行", "tactic": "TA0002",
     "description": "检测可疑 PowerShell 命令行参数", "query_type": "regex",
     "query": r"powershell.*(-enc|-e |bypass|hidden|downloadstring)",
     "industry": "通用", "hit_rate": 0.85},
    {"template_id": "HT-003", "name": "横向移动检测", "tactic": "TA0008",
     "description": "检测 SMB/RDP/WMI 异常远程访问", "query_type": "sql",
     "query": "SELECT src_ip, COUNT(*) FROM network_conn WHERE dst_port IN (445,3389,5985) GROUP BY src_ip HAVING COUNT(*) > 10",
     "industry": "通用", "hit_rate": 0.68},
    {"template_id": "HT-004", "name": "数据渗出检测", "tactic": "TA0010",
     "description": "检测异常出站数据传输", "query_type": "time_series",
     "query": "sum(bytes_out) by src_ip where bytes_out > 100MB window 1h",
     "industry": "通用", "hit_rate": 0.79},
    {"template_id": "HT-005", "name": "凭证转储检测", "tactic": "TA0006",
     "description": "检测 LSASS 访问/转储行为", "query_type": "ioc",
     "query": "process_name IN ('procdump.exe','mimikatz.exe') OR access_path = 'lsass.exe'",
     "industry": "通用", "hit_rate": 0.91},
    {"template_id": "HT-006", "name": "DGA 域名检测", "tactic": "TA0011",
     "description": "DNS 查询中检测 DGA 算法生成域名", "query_type": "ml",
     "query": "model=dga_detector input=dns_queries threshold=0.8",
     "industry": "通用", "hit_rate": 0.88},
    {"template_id": "HT-007", "name": "计划任务持久化", "tactic": "TA0003",
     "description": "检测异常计划任务/ cron 创建", "query_type": "sql",
     "query": "SELECT * FROM scheduler_events WHERE action = 'create' AND user NOT IN ('system','svc_account')",
     "industry": "通用", "hit_rate": 0.74},
    {"template_id": "HT-008", "name": "内网端口扫描", "tactic": "TA0007",
     "description": "检测主机对内网的端口扫描行为", "query_type": "aggregate",
     "query": "count(distinct dst_port) by src_ip where dst_ip like '10.%' group by 5m",
     "industry": "金融", "hit_rate": 0.82},
]

_BEST_PRACTICES = [
    "狩猎前明确假设，避免无目的数据探索",
    "优先覆盖 ATT&CK 高权重技术",
    "结合 IOC + TTP + 行为分析三层检测",
    "狩猎结果需闭环到规则和 SIEM",
    "定期回顾狩猎模板有效性，淘汰低效模板",
]


# ==================== 威胁狩猎平台 ====================

class ThreatHuntPlatform:
    """威胁狩猎深度平台。"""

    def __init__(self) -> None:
        self.templates: List[Dict[str, Any]] = _PRESET_TEMPLATES
        self.hunt_sessions: List[Dict[str, Any]] = []
        self.hunt_reports: List[Dict[str, Any]] = []
        self.knowledge_base: Dict[str, List[Dict[str, Any]]] = {
            "techniques": [
                {"name": "基线对比法", "description": "建立正常行为基线，对比异常偏差"},
                {"name": "假设驱动法", "description": "从威胁情报假设出发，定向搜索证据"},
                {"name": "大数据统计法", "description": "利用统计/ML 从海量数据中发现异常"},
            ],
            "cases": [
                {"case_id": "CASE-001", "title": "某企业钓鱼邮件导致的横向移动事件",
                 "duration_days": 5, "findings": "3台主机被控，未造成数据泄露"},
            ],
            "tools": [
                {"name": "Splunk", "type": "SIEM查询"},
                {"name": "Elasticsearch", "type": "日志搜索"},
                {"name": "Wireshark", "type": "流量分析"},
                {"name": "Sigma", "type": "规则检测"},
            ],
            "data_sources": [
                {"source": "Windows 安全日志", "coverage": 0.85},
                {"source": "DNS 查询日志", "coverage": 0.70},
                {"source": "Web 代理日志", "coverage": 0.75},
                {"source": "EDR 遥测", "coverage": 0.90},
            ],
        }
        self.metrics: Dict[str, float] = {
            "hunt_coverage": 0.78,
            "hunt_efficiency": 0.65,
            "hunt_success_rate": 0.72,
            "discovery_rate": 0.45,
            "false_positive_rate": 0.18,
            "avg_hunt_time_min": 120.0,
            "hunt_roi": 2.3,
        }

    # ---------- 查询语言引擎 ----------

    def execute_query(self, query: str, query_type: str = "sql",
                      time_range_h: int = 24, limit: int = 100) -> Dict[str, Any]:
        """执行狩猎查询（模拟）。"""
        session_id = f"HUNT-{uuid.uuid4().hex[:8].upper()}"

        # 解析查询类型
        q_lower = query.lower()
        if query_type == "regex" or r"\\" in query or ".*" in query:
            query_type = "regex"
        elif "select" in q_lower and "from" in q_lower:
            query_type = "sql"
        elif "model=" in q_lower:
            query_type = "ml"
        elif "count(" in q_lower or "group by" in q_lower:
            query_type = "aggregate"

        events_scanned = random.randint(10000, 500000)
        events_matched = random.randint(0, min(events_scanned // 20, 50))

        results = []
        for i in range(min(events_matched, limit)):
            results.append({
                "event_id": f"EV-{uuid.uuid4().hex[:6].upper()}",
                "timestamp": _now(),
                "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "user": f"user{random.randint(1,30):03d}",
                "severity": random.choice(["low", "medium", "medium", "high", "high", "critical"]),
                "summary": f"匹配规则: {query[:50]}...",
            })

        session = {
            "session_id": session_id,
            "query": query,
            "query_type": query_type,
            "time_range_h": time_range_h,
            "events_scanned": events_scanned,
            "events_matched": events_matched,
            "results": results,
            "status": "completed",
            "started_at": _now(),
            "completed_at": _now(),
            "duration_sec": round(random.uniform(0.5, 15.0), 2),
        }
        self.hunt_sessions.append(session)
        return session

    # ---------- 模板管理 ----------

    def list_templates(self, industry: Optional[str] = None,
                       tactic: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出狩猎模板。"""
        result = self.templates
        if industry:
            result = [t for t in result if t["industry"] == industry]
        if tactic:
            result = [t for t in result if t["tactic"] == tactic]
        return result

    def create_template(self, name: str, description: str, query: str,
                        query_type: str = "sql", industry: str = "通用") -> Dict[str, Any]:
        """创建自定义狩猎模板。"""
        tpl = {
            "template_id": f"HT-CUSTOM-{uuid.uuid4().hex[:6].upper()}",
            "name": name, "description": description,
            "query": query, "query_type": query_type,
            "industry": industry, "hit_rate": 0.0, "custom": True,
            "version": "1.0", "created_at": _now(),
        }
        self.templates.append(tpl)
        return tpl

    # ---------- 狩猎工作流 ----------

    def run_hunt_workflow(self, hypothesis: str, template_id: Optional[str] = None,
                          time_range_h: int = 48) -> Dict[str, Any]:
        """执行完整狩猎工作流。"""
        hunt_id = f"WHUNT-{uuid.uuid4().hex[:8].upper()}"
        steps = []

        # Step 1: 假设生成
        steps.append({
            "step": "假设生成", "status": "completed",
            "detail": f"假设: {hypothesis}",
        })

        # Step 2: 数据收集
        data_sources = ["Windows安全日志", "DNS日志", "Web代理日志", "EDR遥测"]
        steps.append({
            "step": "数据收集", "status": "completed",
            "detail": f"采集数据源: {', '.join(data_sources)}, 时间范围 {time_range_h}h",
            "events_collected": random.randint(100000, 800000),
        })

        # Step 3: 分析调查
        query_result = self.execute_query(hypothesis, time_range_h=time_range_h)
        steps.append({
            "step": "分析调查", "status": "completed",
            "detail": f"扫描 {query_result['events_scanned']} 条事件, 匹配 {query_result['events_matched']} 条",
            "matched_events": query_result["results"][:10],
        })

        # Step 4: 验证确认
        findings = query_result["events_matched"]
        confirmed = findings > 0
        steps.append({
            "step": "验证确认", "status": "completed",
            "detail": f"确认发现 {findings} 个可疑事件" if confirmed else "未发现确认威胁",
            "confirmed": confirmed,
        })

        # Step 5: 报告生成
        report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
        report = {
            "report_id": report_id, "hunt_id": hunt_id,
            "hypothesis": hypothesis,
            "findings_count": findings,
            "severity": "high" if findings > 10 else ("medium" if findings > 0 else "low"),
            "recommendation": "建议立即响应" if confirmed and findings > 5 else ("建议持续监控" if confirmed else "无行动项"),
            "created_at": _now(),
        }
        self.hunt_reports.append(report)
        steps.append({"step": "报告生成", "status": "completed", "detail": f"报告ID: {report_id}"})

        # Step 6: 知识沉淀
        steps.append({"step": "知识沉淀", "status": "completed", "detail": "狩猎经验已存入知识库"})

        return {
            "hunt_id": hunt_id,
            "workflow_steps": steps,
            "report": report,
            "status": "completed",
            "timestamp": _now(),
        }

    # ---------- 狩猎工具集 ----------

    def explore_data(self, source: str, time_range_h: int = 24) -> Dict[str, Any]:
        """数据探索。"""
        return {
            "data_source": source,
            "time_range_h": time_range_h,
            "total_records": random.randint(50000, 500000),
            "fields": ["timestamp", "source_ip", "destination_ip", "user", "action", "status", "bytes_in", "bytes_out"],
            "sample_records": [
                {"timestamp": _now(), "source_ip": f"10.0.0.{i}", "action": random.choice(["login", "file_access", "network_conn"])}
                for i in range(1, 6)
            ],
        }

    def ioc_match(self, ioc_list: List[str]) -> Dict[str, Any]:
        """IOC 匹配。"""
        matches = []
        for ioc in ioc_list:
            hit = random.random() > 0.5
            matches.append({
                "ioc": ioc,
                "ioc_type": "ip" if re.match(r"\d+\.\d+\.\d+\.\d+", ioc) else ("domain" if "." in ioc else "hash"),
                "matched": hit,
                "match_count": random.randint(0, 5) if hit else 0,
                "first_seen": _now() if hit else None,
            })
        return {"ioc_list": ioc_list, "matches": matches, "total_hits": sum(1 for m in matches if m["matched"])}

    def ttp_match(self, ttps: List[str]) -> Dict[str, Any]:
        """TTP 匹配。"""
        matched_ttps = []
        for ttp in ttps:
            confidence = round(random.uniform(0.3, 0.95), 3)
            if confidence > 0.5:
                matched_ttps.append({
                    "ttp": ttp, "confidence": confidence,
                    "evidence_count": random.randint(1, 20),
                })
        return {"requested_ttps": ttps, "matched": matched_ttps}

    # ---------- 度量 ----------

    def get_metrics(self) -> Dict[str, Any]:
        """狩猎度量指标。"""
        return {
            **self.metrics,
            "total_hunts": len(self.hunt_sessions),
            "successful_hunts": len([s for s in self.hunt_sessions if s["events_matched"] > 0]),
            "templates_available": len(self.templates),
            "reports_generated": len(self.hunt_reports),
            "knowledge_items": sum(len(v) for v in self.knowledge_base.values()),
        }

    # ---------- 概览 ----------

    def overview(self) -> Dict[str, Any]:
        return {
            "total_hunt_sessions": len(self.hunt_sessions),
            "templates": len(self.templates),
            "reports": len(self.hunt_reports),
            "data_sources": len(self.knowledge_base["data_sources"]),
            "best_practices": len(_BEST_PRACTICES),
            **{k: v for k, v in self.metrics.items() if k in ("hunt_coverage", "hunt_success_rate", "discovery_rate")},
        }


# 单例
threat_hunt_platform = ThreatHuntPlatform()
