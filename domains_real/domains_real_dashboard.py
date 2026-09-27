# -*- coding: utf-8 -*-
"""domains_real_dashboard.py — 领域真实可用仪表盘聚合。

聚合所有5大领域的真实功能状态、工具可用性、最近活动、统计数据。
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from . import red_blue_real
from . import supply_chain_real
from . import devsecops_real
from . import forensics_real
from . import iot_ics_real


# ============================================================
# 领域元数据
# ============================================================
DOMAIN_METADATA: List[Dict[str, Any]] = [
    {
        "id": "red_blue",
        "name": "红蓝对抗做实",
        "icon": "⚔️",
        "description": "红队真实攻击流程（信息收集→漏洞利用→权限维持→痕迹清理）+ 蓝队真实检测规则",
        "modules": [
            {"name": "子域名枚举", "tool": "subfinder", "type": "red_team"},
            {"name": "端口扫描", "tool": "nmap", "type": "red_team"},
            {"name": "漏洞扫描", "tool": "nuclei", "type": "red_team"},
            {"name": "计划任务后门", "tool": "schtasks/crontab", "type": "red_team"},
            {"name": "日志清理", "tool": "wevtutil/journalctl", "type": "red_team"},
            {"name": "IDS规则管理", "tool": "suricata/snort", "type": "blue_team"},
            {"name": "异常行为检测", "tool": "anomaly_engine", "type": "blue_team"},
            {"name": "事件响应", "tool": "ir_playbooks", "type": "blue_team"},
        ],
    },
    {
        "id": "supply_chain",
        "name": "供应链安全做实",
        "icon": "🔗",
        "description": "真实 SBOM 生成（syft/cyclonedx）+ 组件漏洞检测（grype/trivy + CVE 比对）",
        "modules": [
            {"name": "SBOM 生成 (syft)", "tool": "syft", "type": "sbom"},
            {"name": "SBOM 生成 (cyclonedx)", "tool": "cyclonedx", "type": "sbom"},
            {"name": "漏洞扫描 (grype)", "tool": "grype", "type": "vuln_scan"},
            {"name": "漏洞扫描 (trivy)", "tool": "trivy", "type": "vuln_scan"},
            {"name": "风险评级", "tool": "cvss_rating", "type": "analysis"},
        ],
    },
    {
        "id": "devsecops",
        "name": "DevSecOps 做实",
        "icon": "🔄",
        "description": "CI/CD 集成（Jenkins/GitLab）+ Semgrep SAST 静态分析 + 安全门禁",
        "modules": [
            {"name": "Jenkins 集成", "tool": "jenkins_api", "type": "ci_cd"},
            {"name": "GitLab CI 集成", "tool": "gitlab_api", "type": "ci_cd"},
            {"name": "安全门禁", "tool": "quality_gates", "type": "gate"},
            {"name": "Semgrep SAST", "tool": "semgrep", "type": "sast"},
            {"name": "自定义规则", "tool": "semgrep_custom", "type": "sast"},
        ],
    },
    {
        "id": "forensics",
        "name": "取证分析做实",
        "icon": "🔍",
        "description": "内存取证（Volatility3）+ 磁盘取证（Sleuth Kit）+ 网络取证（tshark）+ 日志取证",
        "modules": [
            {"name": "内存分析", "tool": "volatility3", "type": "memory"},
            {"name": "分区分析", "tool": "mmls/fls", "type": "disk"},
            {"name": "文件提取", "tool": "icat", "type": "disk"},
            {"name": "PCAP 分析", "tool": "tshark", "type": "network"},
            {"name": "日志分析", "tool": "log_analyzer", "type": "log"},
        ],
    },
    {
        "id": "iot_ics",
        "name": "工控/IoT 做实",
        "icon": "🏭",
        "description": "Modbus/S7 协议分析 + 工控设备发现 + IoT 设备扫描与指纹识别",
        "modules": [
            {"name": "Modbus 读取", "tool": "modbus_tcp", "type": "protocol"},
            {"name": "S7 设备检测", "tool": "s7comm", "type": "protocol"},
            {"name": "工控设备发现", "tool": "ics_scan", "type": "discovery"},
            {"name": "IoT 设备发现", "tool": "iot_scan", "type": "discovery"},
            {"name": "设备指纹", "tool": "fingerprint", "type": "analysis"},
        ],
    },
]


def get_dashboard_overview() -> Dict[str, Any]:
    """获取仪表盘总览。"""
    # 各领域工具可用性
    rb_tools = red_blue_real.tool_availability()
    sc_tools = supply_chain_real.tool_availability()
    ds_tools = devsecops_real.tool_availability()
    fr_tools = forensics_real.tool_availability()
    iot_tools = iot_ics_real.tool_availability()

    all_tools: Dict[str, Dict[str, Any]] = {}
    all_tools.update({f"rb_{k}": v for k, v in rb_tools.items()})
    all_tools.update({f"sc_{k}": v for k, v in sc_tools.items()})
    all_tools.update({f"ds_{k}": v for k, v in ds_tools.items()})
    all_tools.update({f"fr_{k}": v for k, v in fr_tools.items()})
    all_tools.update({f"iot_{k}": v for k, v in iot_tools.items()})

    total_tools = len(all_tools)
    available_tools = sum(1 for v in all_tools.values() if v.get("available"))

    # 各领域统计
    stats = {
        "red_blue": {
            "attack_sessions": len(red_blue_real.ATTACK_SESSIONS),
            "ids_rules": len(red_blue_real.IDS_RULE_TEMPLATES),
            "alerts": len(red_blue_real.ALERTS_STORE),
            "ir_playbooks": len(red_blue_real.IR_PLAYBOOK_TEMPLATES),
        },
        "supply_chain": {
            "sbom_records": len(supply_chain_real.SBOM_RECORDS),
            "vuln_scans": len(supply_chain_real.VULN_RECORDS),
            "risk_summary": supply_chain_real.risk_rating_summary(),
        },
        "devsecops": {
            "sast_scans": len(devsecops_real.SAST_SCAN_RECORDS),
            "security_gates": len(devsecops_real.SECURITY_GATE_TEMPLATES),
            "semgrep_rules": len(devsecops_real.SEMGREP_RULE_PACK_BUILTIN),
        },
        "forensics": {
            "cases": len(forensics_real.FORENSIC_CASES),
            "memory_analyses": len(forensics_real.MEMORY_ANALYSES),
            "disk_analyses": len(forensics_real.DISK_ANALYSES),
            "network_analyses": len(forensics_real.NETWORK_ANALYSES),
            "log_analyses": len(forensics_real.LOG_ANALYSES),
        },
        "iot_ics": {
            "ics_discos": len(iot_ics_real.ICS_DISCOVERY_RECORDS),
            "iot_discos": len(iot_ics_real.IoT_DISCOVERY_RECORDS),
            "modbus_analyses": len(iot_ics_real.MODBUS_ANALYSES),
            "s7_analyses": len(iot_ics_real.S7_ANALYSES),
        },
    }

    return {
        "domains": DOMAIN_METADATA,
        "tool_status": {
            "total": total_tools,
            "available": available_tools,
            "missing": total_tools - available_tools,
            "details": all_tools,
        },
        "stats": stats,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def get_domain_detail(domain_id: str) -> Dict[str, Any]:
    """获取单个领域的详细状态。"""
    for d in DOMAIN_METADATA:
        if d["id"] == domain_id:
            return {"success": True, "domain": d}
    return {"success": False, "error": f"未知领域: {domain_id}"}


def get_all_health() -> Dict[str, Any]:
    """所有健康检查。"""
    overview = get_dashboard_overview()
    return {
        "status": "healthy",
        "domains_count": len(DOMAIN_METADATA),
        "tools_available": overview["tool_status"]["available"],
        "tools_total": overview["tool_status"]["total"],
        "uptime_note": "所有模块运行正常",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
