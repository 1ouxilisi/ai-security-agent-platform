# -*- coding: utf-8 -*-
"""
runtime_protection.py — 运行时安全防护。

能力：
    * WAF 规则引擎（SQLi / XSS / 路径遍历 / 恶意 UA / IP 黑白名单）
    * 入侵检测（异常登录 / 异常 API 调用 / 异常访问）
    * 日志审计
    * 异常行为检测（用户行为基线 / 偏离检测）
    * 应急响应
"""

from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional

from . import common


# WAF 内置规则（模式库）
WAF_RULES: List[Dict[str, Any]] = [
    {"id": "WAF-001", "name": "SQL 联合查询", "pattern": r"(?i)(union\s+select|union\s+all)", "action": "block", "severity": "high"},
    {"id": "WAF-002", "name": "SQL 注释绕过", "pattern": r"(?i)(--|#|/\*.*\*/)", "action": "log", "severity": "medium"},
    {"id": "WAF-003", "name": "SQL 时间盲注", "pattern": r"(?i)(sleep\s*\(|benchmark\s*\(|pg_sleep)", "action": "block", "severity": "high"},
    {"id": "WAF-004", "name": "XSS 脚本标签", "pattern": r"(?i)<script[^>]*>|javascript:", "action": "block", "severity": "high"},
    {"id": "WAF-005", "name": "XSS 事件处理器", "pattern": r"(?i)on(error|load|click|mouseover)\s*=", "action": "block", "severity": "high"},
    {"id": "WAF-006", "name": "路径遍历", "pattern": r"(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|c:\\windows)", "action": "block", "severity": "high"},
    {"id": "WAF-007", "name": "命令执行", "pattern": r"(?i)(;|\||`|\$\(|\bwget\b|\bcurl\b|\bnc\b)", "action": "log", "severity": "medium"},
    {"id": "WAF-008", "name": "SSTI 探针", "pattern": r"(\{\{.*\}\}|\$\{.*\})", "action": "log", "severity": "medium"},
    {"id": "WAF-009", "name": "恶意 UA-Sqlmap", "pattern": r"(?i)sqlmap|nikto|nmap|dirb|gobuster", "action": "block", "severity": "high"},
    {"id": "WAF-010", "name": "恶意 UA-Curl", "pattern": r"(?i)curl/\d|wget/\d|python-requests", "action": "log", "severity": "low"},
]


class RuntimeProtector:
    """运行时安全防护分析与模拟引擎。"""

    def __init__(self) -> None:
        self.root = common.PROJECT_ROOT
        self.blocked: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        # 模拟 IP 黑白名单
        self.ip_blacklist: List[str] = []
        self.ip_whitelist: List[str] = ["127.0.0.1", "::1"]
        # 编译 WAF 规则
        self._waf = []
        for r in WAF_RULES:
            try:
                self._waf.append({**r, "re": re.compile(r["pattern"])})
            except re.error:
                continue

    # ------------------------------------------------------------------ #
    # WAF
    # ------------------------------------------------------------------ #
    def waf_rules(self) -> Dict[str, Any]:
        return {
            "rules": [{"id": r["id"], "name": r["name"], "action": r["action"],
                       "severity": r["severity"]} for r in self._waf],
            "ip_blacklist": self.ip_blacklist,
            "ip_whitelist": self.ip_whitelist,
            "blocked_total": len(self.blocked),
            "blocked_samples": self.blocked[-10:],
            "mode": "观察模式 / 拦截模式 可切换",
        }

    def waf_inspect(self, payload: str) -> Dict[str, Any]:
        """对一段输入做 WAF 检测（合法的检测函数，不执行 payload）。"""
        hits = []
        for rule in self._waf:
            m = rule["re"].search(payload or "")
            if m:
                hits.append({"rule_id": rule["id"], "name": rule["name"],
                             "severity": rule["severity"], "action": rule["action"],
                             "matched": m.group(0)[:80]})
                if rule["action"] == "block":
                    self.blocked.append({"ts": time.strftime("%H:%M:%S"),
                                         "rule": rule["id"], "sample": payload[:80]})
        decision = "block" if any(h["action"] == "block" for h in hits) else \
                   "log" if hits else "pass"
        return {"decision": decision, "hits": hits, "payload_length": len(payload or "")}

    # ------------------------------------------------------------------ #
    # 入侵检测
    # ------------------------------------------------------------------ #
    def intrusion_detection(self) -> Dict[str, Any]:
        return {
            "signatures": [
                {"id": "IDS-001", "name": "异地登录", "rule": "登录地与历史基线距离 >800km"},
                {"id": "IDS-002", "name": "暴力破解", "rule": "1 分钟内同一账号失败 ≥5 次"},
                {"id": "IDS-003", "name": "异常 API 调用", "rule": "1 分钟内调用 ≥200 次且返回 4xx"},
                {"id": "IDS-004", "name": "敏感时段操作", "rule": "02:00-05:00 大批量导出"},
                {"id": "IDS-005", "name": "横向移动", "rule": "10 分钟内访问 ≥5 个未访问过的主机"},
            ],
            "active_alerts": len(self.alerts),
            "alert_samples": self.alerts[-5:],
            "detection_rate": "待运行时统计",
        }

    # ------------------------------------------------------------------ #
    # 日志审计
    # ------------------------------------------------------------------ #
    def log_audit(self) -> Dict[str, Any]:
        logs_dir = os.path.join(self.root, "logs")
        files: List[str] = []
        if os.path.isdir(logs_dir):
            for fn in os.listdir(logs_dir)[:50]:
                files.append(fn)
        return {
            "log_types": ["access", "auth", "api", "admin", "data_access", "error"],
            "retention_days": 180,
            "integrity": "建议对日志做哈希链 / WORM 存储",
            "logs_dir": common.relpath(logs_dir),
            "files_detected": files,
            "checklist": [
                "登录日志记录 who/when/from/result",
                "管理员操作 全量留痕",
                "敏感数据访问记录 object + purpose",
                "日志禁止业务侧修改 / 删除",
            ],
        }

    # ------------------------------------------------------------------ #
    # 异常行为检测
    # ------------------------------------------------------------------ #
    def ueba(self) -> Dict[str, Any]:
        return {
            "baseline_dimensions": ["日均调用次数", "常用端点", "活跃时段", "常用 IP", "常见操作对象"],
            "anomaly_examples": [
                {"user": "analyst_01", "deviation": "3.2σ", "reason": "凌晨 3 点导出 10 万条客户数据"},
                {"user": "dev_ci", "deviation": "2.1σ", "reason": "首次访问 finance 库"},
            ],
            "scoring": "0-100，>80 触发二次认证，>95 自动冻结会话",
            "model": "统计偏离 + 规则引擎",
        }

    # ------------------------------------------------------------------ #
    # 应急响应
    # ------------------------------------------------------------------ #
    def incident_response(self) -> Dict[str, Any]:
        return {
            "playbook": [
                {"step": 1, "name": "发现与定级", "sla": "15 分钟"},
                {"step": 2, "name": "告警通知", "sla": "30 分钟"},
                {"step": 3, "name": "隔离受影响资产", "sla": "1 小时"},
                {"step": 4, "name": "取证（内存/磁盘/日志）", "sla": "4 小时"},
                {"step": 5, "name": "恢复业务", "sla": "24 小时"},
                {"step": 6, "name": "复盘与改进", "sla": "7 天"},
            ],
            "current_open_incidents": 0,
            "mttr_hours_target": 4.0,
            "contacts": ["soc-oncall", "security-lead", "legal", "comms"],
        }

    # ------------------------------------------------------------------ #
    # 汇总
    # ------------------------------------------------------------------ #
    def protection_overview(self) -> Dict[str, Any]:
        return {
            "waf": self.waf_rules(),
            "ids": self.intrusion_detection(),
            "logs": self.log_audit(),
            "ueba": self.ueba(),
            "incident_response": self.incident_response(),
            "effectiveness": {
                "waf_blocked_today": len(self.blocked),
                "alerts_today": len(self.alerts),
                "protection_score": 72,
            },
        }


_protector: Optional[RuntimeProtector] = None


def get_protector() -> RuntimeProtector:
    global _protector
    if _protector is None:
        _protector = RuntimeProtector()
    return _protector
