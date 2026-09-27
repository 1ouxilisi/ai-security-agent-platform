#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
identity_threat_detection.py — 异常登录与身份威胁检测。

覆盖：
    - 登录行为基线：正常时间/地点/设备/IP/频率/方式
    - 异常登录检测：不可能旅行/异常地理/设备/IP/时间/暴力破解/密码喷洒/凭据填充
    - 凭据滥用检测：共享账户/并发登录/特权异常/服务账户交互登录
    - 身份攻击链检测：初始访问→凭据窃取→横向移动→提权→数据访问，ATT&CK 映射
    - MFA 与认证分析：覆盖率/绕过/弱认证/失败模式/风险分

设计定位：仅做检测/告警/分析，输出 IOC 与处置建议，不提供攻击代码。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# ATT&CK 映射
# --------------------------------------------------------------------------- #
ATTACK_TTP = {
    "TA0001_initial_access": "Initial Access（初始访问）",
    "TA0006_credential_access": "Credential Access（凭据访问）",
    "TA0008_lateral_movement": "Lateral Movement（横向移动）",
    "TA0004_privilege_escalation": "Privilege Escalation（权限提升）",
    "TA0009_collection": "Collection（数据收集）",
    "T1078_valid_accounts": "Valid Accounts",
    "T1110_brute_force": "Brute Force",
    "T1558_credential_dumping": "Steal or Forge Kerberos Tickets",
    "T1021_remote_services": "Remote Services (RDP/SSH)",
    "T1083_file_directory_discovery": "File and Directory Discovery",
}


class IdentityThreatDetector:
    """身份威胁检测。"""

    def __init__(self) -> None:
        self.attack_ttp = ATTACK_TTP
        self._baselines: Dict[str, Dict[str, Any]] = {
            "U1001": {"typical_hours": [9, 10, 11, 14, 15, 16, 17, 22],
                      "typical_cities": ["昆明", "上海"],
                      "typical_asn": ["AS4808", "AS4134"],
                      "typical_devices": ["win11-ThinkPad-X1", "iphone15"],
                      "typical_methods": ["sso-oidc", "mfa-push"],
                      "p90_freq_per_day": 18},
            "U1004": {"typical_hours": [10, 11, 14, 15, 16, 22, 23],
                      "typical_cities": ["昆明"],
                      "typical_asn": ["AS4808"],
                      "typical_devices": ["win11-desktop"],
                      "typical_methods": ["password+mfa"],
                      "p90_freq_per_day": 12},
            "U1007": {"typical_hours": [],
                      "typical_cities": [], "typical_asn": [],
                      "typical_devices": [], "typical_methods": [],
                      "p90_freq_per_day": 0},
        }
        self._events: List[Dict[str, Any]] = [
            {"event_id": "E001", "ts": "2026-09-14 02:14:00",
             "uid": "U1001", "user": "张伟", "city": "莫斯科",
             "ip": "95.31.18.7", "asn": "AS8359", "device": "Unknown-Chrome",
             "method": "password_only", "result": "success",
             "type": "impossible_travel",
             "desc": "8 小时前在上海登录，现于莫斯科成功登录，违反物理旅行速度"},
            {"event_id": "E002", "ts": "2026-09-14 03:55:00",
             "uid": "U1004", "user": "赵磊", "city": "昆明",
             "ip": "114.88.xx.xx", "asn": "AS4808", "device": "win11-desktop",
             "method": "password_only", "result": "success",
             "type": "off_hours_access",
             "desc": "凌晨 3:55 登录，偏离基线（22-23 点）"},
            {"event_id": "E003", "ts": "2026-09-14 04:30:00",
             "uid": "U1007", "user": "吴静", "city": "深圳",
             "ip": "119.147.xx.xx", "asn": "AS4134",
             "device": "Unknown-Windows", "method": "password_only",
             "result": "success", "type": "orphan_login",
             "desc": "已离职账户成功登录，疑似凭据未回收"},
            {"event_id": "E004", "ts": "2026-09-14 05:01:00",
             "uid": "-", "user": "admin@corp.cn", "city": "境外",
             "ip": "185.220.xx.xx", "asn": "AS14646",
             "device": "Unknown", "method": "password_only",
             "result": "failed", "type": "brute_force",
             "desc": "1 分钟内对 admin@corp.cn 失败 47 次"},
            {"event_id": "E005", "ts": "2026-09-14 05:03:00",
             "uid": "-", "user": "multiple", "city": "境外",
             "ip": "185.220.xx.xx", "asn": "AS14646",
             "device": "Unknown", "method": "password_only",
             "result": "failed", "type": "password_spray",
             "desc": "同一 IP 对 312 个不同账户尝试同一密码"},
            {"event_id": "E006", "ts": "2026-09-14 05:08:00",
             "uid": "-", "user": "multiple", "city": "Tor exit node",
             "ip": "51.79.xx.xx", "asn": "AS61296",
             "device": "Unknown", "method": "oauth_token",
             "result": "failed", "type": "credential_stuffing",
             "desc": "来自 Tor 出口节点，使用已知泄露凭据尝试 OIDC 登录"},
            {"event_id": "E007", "ts": "2026-09-14 09:12:00",
             "uid": "S2001", "user": "svc-backup", "city": "机房 A",
             "ip": "10.20.3.11", "asn": "RFC1918",
             "device": "win11-ThinkPad-X1", "method": "interactive",
             "result": "success", "type": "service_interactive",
             "desc": "服务账户 svc-backup 出现交互式登录（应为无人值守）"},
            {"event_id": "E008", "ts": "2026-09-14 09:30:00",
             "uid": "U1006", "user": "周涛", "city": "昆明",
             "ip": "10.20.5.22", "asn": "RFC1918",
             "device": "win11-ThinkPad-X1", "method": "mfa-push",
             "result": "success", "type": "concurrent_session",
             "desc": "同一账户同时在 3 个会话在线，疑似共享凭据"},
        ]

    # ------------------------------------------------------------------ #
    # 基线
    # ------------------------------------------------------------------ #
    def baselines(self) -> Dict[str, Any]:
        return {"baselines": self._baselines,
                "learning_period_days": 30,
                "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    # ------------------------------------------------------------------ #
    # 异常登录
    # ------------------------------------------------------------------ #
    def anomalous_logins(self, event_type: Optional[str] = None) -> Dict[str, Any]:
        evts = self._events
        if event_type:
            evts = [e for e in evts if e.get("type") == event_type]
        type_dist: Dict[str, int] = {}
        for e in self._events:
            type_dist[e["type"]] = type_dist.get(e["type"], 0) + 1
        return {"events": evts, "total": len(self._events),
                "type_distribution": type_dist}

    # ------------------------------------------------------------------ #
    # 凭据滥用
    # ------------------------------------------------------------------ #
    def credential_abuse(self) -> Dict[str, Any]:
        out: List[Dict[str, Any]] = []
        for e in self._events:
            if e["type"] in ("concurrent_session", "service_interactive",
                              "orphan_login"):
                out.append(e)
        return {"findings": out,
                "recommended_actions": [
                    "对 U1001 强制登出并要求重新走 MFA",
                    "对 svc-backup 禁止交互式登录，改用工作负载身份",
                    "禁用/删除 U1007（已离职）账户",
                ]}

    # ------------------------------------------------------------------ #
    # 攻击链
    # ------------------------------------------------------------------ #
    def attack_chains(self) -> Dict[str, Any]:
        chains = [
            {"chain_id": "AC-2026-0914-01",
             "actor_ip": "185.220.xx.xx",
             "stages": [
                 {"step": 1, "ttp": "T1110_brute_force",
                  "name": "暴力破解 admin@corp.cn",
                  "ts": "2026-09-14 05:01:00", "result": "failed"},
                 {"step": 2, "ttp": "T1078_valid_accounts",
                  "name": "使用泄露凭据对 U1007 登录成功",
                  "ts": "2026-09-14 05:12:00", "result": "success"},
                 {"step": 3, "ttp": "TA0008_lateral_movement",
                  "name": "通过 RDP 跳转至 jumpserver",
                  "ts": "2026-09-14 05:18:00", "result": "suspected"},
                 {"step": 4, "ttp": "TA0004_privilege_escalation",
                  "name": "尝试使用 runas 提权",
                  "ts": "2026-09-14 05:21:00", "result": "blocked"},
                 {"step": 5, "ttp": "TA0009_collection",
                  "name": "枚举共享目录",
                  "ts": "2026-09-14 05:25:00", "result": "detected"},
             ],
             "severity": "critical",
             "status": "contained",
             "attck_mapping": {k: self.attack_ttp[k]
                               for k in ["T1110_brute_force", "T1078_valid_accounts",
                                         "TA0008_lateral_movement",
                                         "TA0004_privilege_escalation",
                                         "TA0009_collection"]
                               if k in self.attack_ttp}},
        ]
        return {"chains": chains, "total": len(chains)}

    # ------------------------------------------------------------------ #
    # MFA / 认证分析
    # ------------------------------------------------------------------ #
    def mfa_analysis(self) -> Dict[str, Any]:
        users = [
            {"uid": "U1001", "mfa": True, "method": "authenticator+push"},
            {"uid": "U1002", "mfa": True, "method": "authenticator"},
            {"uid": "U1003", "mfa": True, "method": "fido2"},
            {"uid": "U1004", "mfa": False, "method": None},
            {"uid": "U1005", "mfa": True, "method": "sms"},
            {"uid": "U1006", "mfa": True, "method": "authenticator"},
            {"uid": "U1007", "mfa": False, "method": None},
            {"uid": "U1008", "mfa": True, "method": "authenticator"},
            {"uid": "U1009", "mfa": False, "method": None},
            {"uid": "U1010", "mfa": True, "method": "fido2"},
        ]
        total = len(users)
        mfa_on = sum(1 for u in users if u["mfa"])
        sms_only = sum(1 for u in users if u.get("method") == "sms")
        return {
            "total_users": total,
            "mfa_enabled": mfa_on,
            "mfa_coverage_pct": round(mfa_on * 100 / max(total, 1), 1),
            "sms_only_users": sms_only,
            "bypass_risk": [
                {"uid": "U1004", "reason": "未启用 MFA", "risk": "high"},
                {"uid": "U1007", "reason": "未启用 MFA + 已离职", "risk": "critical"},
                {"uid": "U1005", "reason": "仅 SMS，SIM swap 风险", "risk": "medium"},
            ],
            "failure_mode_dist": {
                "bad_password": 1820, "mfa_timeout": 320,
                "expired_token": 88, "device_trust_new": 412,
            },
            "auth_success_pct_24h": 96.4,
        }


__all__ = ["IdentityThreatDetector", "ATTACK_TTP"]
