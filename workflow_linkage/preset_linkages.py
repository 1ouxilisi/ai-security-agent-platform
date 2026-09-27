# -*- coding: utf-8 -*-
"""
preset_linkages.py — 8 条预设联动规则实现。

1. 渗透→合规联动：渗透测试发现的漏洞自动同步到合规整改任务
2. 威胁情报→SOC联动：威胁情报 IOC 自动匹配 SOC 日志，产生告警
3. DevSecOps→供应链联动：代码扫描发现的组件漏洞自动同步到供应链风险
4. 红蓝对抗→取证联动：红队攻击痕迹自动同步到取证分析
5. 数据安全→合规联动：数据安全发现自动同步到合规评估
6. 工控IoT→威胁情报联动：工控设备漏洞自动匹配威胁情报
7. CTF→安全培训联动：CTF 题目自动同步到培训课程
8. SRC→漏洞库联动：SRC 提交的漏洞自动同步到漏洞知识库
"""

from __future__ import annotations

from typing import Any, Dict

from .linkage_rules import get_rule_manager


PRESET_DEFS = [
    {
        "rule_id": "preset-01",
        "name": "渗透→合规联动",
        "source_domain": "web-pentest-pro",
        "target_domain": "compliance-pro",
        "description": "渗透测试发现的漏洞自动同步到合规整改任务",
        "event_type": "vuln_found",
        "severity_threshold": "medium",
        "actions": ["create_task", "sync_data", "send_notification"],
        "priority": 1,
    },
    {
        "rule_id": "preset-02",
        "name": "威胁情报→SOC联动",
        "source_domain": "threat-intel-pro",
        "target_domain": "soc-pro",
        "description": "威胁情报 IOC 自动匹配 SOC 日志，产生告警",
        "event_type": "ioc_detected",
        "severity_threshold": "high",
        "actions": ["generate_alert", "sync_data"],
        "priority": 1,
    },
    {
        "rule_id": "preset-03",
        "name": "DevSecOps→供应链联动",
        "source_domain": "devsecops-pro",
        "target_domain": "supply-chain-pro",
        "description": "代码扫描发现的组件漏洞自动同步到供应链风险",
        "event_type": "vuln_found",
        "severity_threshold": "high",
        "actions": ["sync_data", "generate_alert"],
        "priority": 2,
    },
    {
        "rule_id": "preset-04",
        "name": "红蓝对抗→取证联动",
        "source_domain": "red-blue-pro",
        "target_domain": "forensics-pro",
        "description": "红队攻击痕迹自动同步到取证分析",
        "event_type": "attack_trace",
        "severity_threshold": "high",
        "actions": ["create_task", "sync_data"],
        "priority": 2,
    },
    {
        "rule_id": "preset-05",
        "name": "数据安全→合规联动",
        "source_domain": "data-security-pro",
        "target_domain": "compliance-pro",
        "description": "数据安全发现自动同步到合规评估",
        "event_type": "data_discovered",
        "severity_threshold": "medium",
        "actions": ["create_task", "send_notification"],
        "priority": 3,
    },
    {
        "rule_id": "preset-06",
        "name": "工控IoT→威胁情报联动",
        "source_domain": "iot-ot-pro",
        "target_domain": "threat-intel-pro",
        "description": "工控设备漏洞自动匹配威胁情报",
        "event_type": "device_vuln",
        "severity_threshold": "medium",
        "actions": ["sync_data", "generate_alert"],
        "priority": 3,
    },
    {
        "rule_id": "preset-07",
        "name": "CTF→安全培训联动",
        "source_domain": "ctf-pro",
        "target_domain": "security-training-pro",
        "description": "CTF 题目自动同步到培训课程",
        "event_type": "challenge_created",
        "severity_threshold": "low",
        "actions": ["sync_data", "send_notification"],
        "priority": 4,
    },
    {
        "rule_id": "preset-08",
        "name": "SRC→漏洞库联动",
        "source_domain": "src-platform-pro",
        "target_domain": "threat-intel-pro",
        "description": "SRC 提交的漏洞自动同步到漏洞知识库",
        "event_type": "submission_received",
        "severity_threshold": "medium",
        "actions": ["sync_data"],
        "priority": 4,
    },
]


def install_presets() -> Dict[str, Any]:
    """安装（幂等）8 条预设联动规则。"""
    rm = get_rule_manager()
    installed = []
    already = 0
    for d in PRESET_DEFS:
        existing = rm.get(d["rule_id"])
        if existing is not None:
            already += 1
            installed.append(existing)
            continue
        rule = rm.create(
            name=d["name"],
            source_domain=d["source_domain"],
            target_domain=d["target_domain"],
            description=d["description"],
            event_type=d["event_type"],
            severity_threshold=d["severity_threshold"],
            actions=d["actions"],
            priority=d["priority"],
            enabled=True,
            rule_id=d["rule_id"],
            time_window_sec=300,
        )
        installed.append(rule)
    return {"installed": len(installed) - already,
            "already": already,
            "total": len(installed)}
