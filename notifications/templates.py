# -*- coding: utf-8 -*-
"""
templates.py - Notification template library.

Uses simple {key} substitution (no Jinja2 dependency).
"""

import re
import threading
from typing import Dict, List, Any

_lock = threading.Lock()

PREDEFINED_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "scan_completed": {
        "template_id": "scan_completed",
        "name": "Scan Completed",
        "description": "Fired when a scan finishes",
        "content": (
            "✅ 扫描完成\n目标: {target}\n类型: {scan_type}\n"
            "漏洞总数: {vuln_count}\n高危: {high_count}\n风险分: {risk_score}\n"
            "报告: {report_link}\n时间: {time}"
        ),
        "variables": ["target", "scan_type", "vuln_count", "high_count",
                       "risk_score", "report_link", "time"],
        "channel_hint": "all",
    },
    "high_risk_found": {
        "template_id": "high_risk_found",
        "name": "High Risk Found",
        "description": "Critical/high vulnerability discovered",
        "content": (
            "🚨 高危漏洞发现\n目标: {target}\n漏洞: {vuln_title}\n"
            "等级: {severity}\nCVE: {cve}\n描述: {description}\n时间: {time}"
        ),
        "variables": ["target", "vuln_title", "severity", "cve", "description", "time"],
        "channel_hint": "wecom,dingtalk,feishu",
    },
    "workflow_completed": {
        "template_id": "workflow_completed",
        "name": "Workflow Completed",
        "description": "SOAR/workflow run finished",
        "content": (
            "⚙️ 工作流完成\n名称: {workflow_name}\n目标: {target}\n"
            "状态: {status}\n耗时: {duration}\n步骤数: {steps_count}\n时间: {time}"
        ),
        "variables": ["workflow_name", "target", "status", "duration", "steps_count", "time"],
        "channel_hint": "all",
    },
    "task_failed": {
        "template_id": "task_failed",
        "name": "Task Failed",
        "description": "A scheduled/manual task failed",
        "content": (
            "❌ 任务失败\n任务: {task_name}\n目标: {target}\n错误: {error}\n时间: {time}"
        ),
        "variables": ["task_name", "target", "error", "time"],
        "channel_hint": "all",
    },
    "system_alert": {
        "template_id": "system_alert",
        "name": "System Alert",
        "description": "Platform/system-level alert",
        "content": (
            "⚠️ 系统告警\n类型: {alert_type}\n级别: {severity}\n"
            "信息: {message}\n时间: {time}"
        ),
        "variables": ["alert_type", "message", "severity", "time"],
        "channel_hint": "all",
    },
    "periodic_report": {
        "template_id": "periodic_report",
        "name": "Periodic Report",
        "description": "Daily/weekly digest",
        "content": (
            "📊 周期报告 ({period})\n扫描总数: {total_scans}\n"
            "漏洞总数: {total_vulns}\n风险趋势: {risk_trend}\n时间: {time}"
        ),
        "variables": ["period", "total_scans", "total_vulns", "risk_trend", "time"],
        "channel_hint": "email,feishu",
    },
    "vuln_status_changed": {
        "template_id": "vuln_status_changed",
        "name": "Vuln Status Changed",
        "description": "Vulnerability triage status update",
        "content": (
            "🔄 漏洞状态变更\n漏洞: {vuln_title}\n"
            "{old_status} → {new_status}\n时间: {time}"
        ),
        "variables": ["vuln_title", "old_status", "new_status", "time"],
        "channel_hint": "all",
    },
}

# Custom templates (user-defined).
_custom_templates: Dict[str, Dict[str, Any]] = {}


def _render(content: str, variables: Dict[str, Any]) -> str:
    """Simple {key} substitution; missing keys stay as-is."""
    def repl(m):
        key = m.group(1).strip()
        return str(variables.get(key, m.group(0)))
    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", repl, content)


def render_template(template_id: str, variables: Dict[str, Any]) -> str:
    """Render a template by id. Falls back to raw variables string if not found."""
    tpl = PREDEFINED_TEMPLATES.get(template_id) or _custom_templates.get(template_id)
    if not tpl:
        return _render(str(variables), variables)
    return _render(tpl["content"], variables)


def list_templates() -> List[Dict[str, Any]]:
    with _lock:
        out = list(PREDEFINED_TEMPLATES.values()) + list(_custom_templates.values())
        # Mark custom vs builtin.
        for t in out:
            t = dict(t)
            t["custom"] = t["template_id"] in _custom_templates
        return out


def create_template(data: Dict[str, Any]) -> Dict[str, Any]:
    tpl_id = data.get("template_id") or data.get("name", "custom")
    tpl = {
        "template_id": tpl_id,
        "name": data.get("name", tpl_id),
        "description": data.get("description", ""),
        "content": data.get("content", ""),
        "variables": list(data.get("variables") or re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", data.get("content", ""))),
        "channel_hint": data.get("channel_hint", "all"),
        "custom": True,
    }
    with _lock:
        _custom_templates[tpl_id] = tpl
    return tpl


def update_template(template_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    with _lock:
        tpl = _custom_templates.get(template_id)
        if not tpl:
            raise KeyError(f"custom template not found: {template_id}")
        for k in ("name", "description", "content", "variables", "channel_hint"):
            if k in data:
                tpl[k] = data[k]
        return tpl


def delete_template(template_id: str) -> bool:
    with _lock:
        return _custom_templates.pop(template_id, None) is not None
