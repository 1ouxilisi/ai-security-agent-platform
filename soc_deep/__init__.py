#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soc_deep — 第26轮升级方向3：安全运营中心(SOC)深度平台。

包含 7 大核心模块：
    - siem_logging           SIEM 日志管理深度（采集/解析/标准化/存储/检索/分析）
    - correlation_engine     关联规则引擎深度（规则管理/编写/测试/执行/告警/度量）
    - alert_triage_deep      告警分诊与聚合深度（接入/去重/聚合/分诊/丰富化/处置）
    - incident_response_deep 事件响应深度（事件管理/IR流程/调查/遏制/根除/恢复/复盘）
    - threat_intel_soc       威胁情报整合深度（接入/标准化/管理/匹配/响应/质量）
    - soc_metrics            SOC 度量与报告深度（MTTD/MTTR/MTRS/仪表盘/报告/成熟度）
    - soc_dashboard          SOC 深度控制台数据聚合层

设计定位：全部内存字典模拟，不建数据库表；日志可真实解析 Syslog/JSON/CSV，
关联规则可真实匹配条件触发告警，事件响应可真实走 NIST/SANS IR 流程。
"""

from __future__ import annotations

__version__ = "26.3.0"
__all__ = [
    "siem_logging",
    "correlation_engine",
    "alert_triage_deep",
    "incident_response_deep",
    "threat_intel_soc",
    "soc_metrics",
    "soc_dashboard",
]
