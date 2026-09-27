#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
privileged_access.py — 特权账户管理 PAM。

覆盖：
    - 特权账户盘点：管理员/root/服务/DBA/云管理员/域管理员，分类统计
    - 特权账户风险：共享密码/长期未改/过度权限/无人管理/使用频率/风险分
    - 特权会话监控：登录/操作/命令记录/会话录像/异常告警/回放
    - 特权访问审批：临时特权申请/审批/时限/自动回收/紧急访问
    - 服务账户管理：发现/轮换/使用监控/废弃清理/硬编码凭据/依赖关系

设计定位：仅做 PAM 治理视角的盘点与分析，输出风险与加固建议。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


PRIV_TYPES = [
    "domain_admin", "local_admin", "root", "db_admin",
    "cloud_admin", "service_account", "break_glass", "network_admin",
]


class PrivilegedAccessManager:
    """特权账户管理。"""

    def __init__(self) -> None:
        self.accounts: List[Dict[str, Any]] = [
            {"acct_id": "PA001", "username": "admin-corp", "type": "domain_admin",
             "owner": "IT-Platform", "shared": True,
             "pwd_age_days": 240, "mfa": False,
             "last_use": "2026-09-13 22:00:00", "uses_30d": 4,
             "risk_score": 0, "status": "active"},
            {"acct_id": "PA002", "username": "root@jump01", "type": "root",
             "owner": "IT-Ops", "shared": False,
             "pwd_age_days": 180, "mfa": True,
             "last_use": "2026-09-14 09:10:00", "uses_30d": 32,
             "risk_score": 0, "status": "active"},
            {"acct_id": "PA003", "username": "dbadmin-prod", "type": "db_admin",
             "owner": "Data-Platform", "shared": True,
             "pwd_age_days": 90, "mfa": True,
             "last_use": "2026-09-14 06:00:00", "uses_30d": 12,
             "risk_score": 0, "status": "active"},
            {"acct_id": "PA004", "username": "cloud-admin-aws", "type": "cloud_admin",
             "owner": "FinOps", "shared": False,
             "pwd_age_days": 45, "mfa": True,
             "last_use": "2026-09-13 18:30:00", "uses_30d": 6,
             "risk_score": 0, "status": "active"},
            {"acct_id": "PA005", "username": "svc-backup", "type": "service_account",
             "owner": "IT-Ops", "shared": False,
             "pwd_age_days": 540, "mfa": False,
             "last_use": "2026-09-14 02:00:00", "uses_30d": 720,
             "risk_score": 0, "status": "active"},
            {"acct_id": "PA006", "username": "svc-etl", "type": "service_account",
             "owner": "Data-Platform", "shared": False,
             "pwd_age_days": 30, "mfa": False,
             "last_use": "2026-09-14 06:30:00", "uses_30d": 2200,
             "risk_score": 0, "status": "active"},
            {"acct_id": "PA007", "username": "break-glass-emerg", "type": "break_glass",
             "owner": "CISO-Office", "shared": True,
             "pwd_age_days": 365, "mfa": True,
             "last_use": "2025-12-01 00:00:00", "uses_30d": 0,
             "risk_score": 0, "status": "locked"},
            {"acct_id": "PA008", "username": "legacy-oracle-dba", "type": "db_admin",
             "owner": "Unknown", "shared": True,
             "pwd_age_days": 900, "mfa": False,
             "last_use": "2025-08-11 10:00:00", "uses_30d": 0,
             "risk_score": 0, "status": "orphan"},
        ]
        self._sessions: List[Dict[str, Any]] = [
            {"sid": "SES-001", "acct": "PA002", "user": "周涛",
             "host": "db-prod-01", "protocol": "ssh",
             "started": "2026-09-14 09:10:00", "ended": "2026-09-14 09:32:00",
             "recording": True, "command_count": 18,
             "abnormal": False, "commands": ["systemctl status nginx",
                                              "tail /var/log/nginx/access.log"]},
            {"sid": "SES-002", "acct": "PA005", "user": "svc-backup",
             "host": "backup01", "protocol": "ssh",
             "started": "2026-09-14 02:00:00", "ended": "2026-09-14 02:24:00",
             "recording": False, "command_count": 0,
             "abnormal": True,
             "commands": [], "note": "服务账户出现交互式登录"},
            {"sid": "SES-003", "acct": "PA001", "user": "unknown",
             "host": "dc01", "protocol": "rdp",
             "started": "2026-09-13 22:00:00", "ended": "2026-09-13 22:18:00",
             "recording": True, "command_count": 4,
             "abnormal": True,
             "commands": ["net group \"Domain Admins\" /domain",
                          "net user /domain"], "note": "可疑枚举命令"},
        ]
        self._requests: List[Dict[str, Any]] = [
            {"req_id": "PR-001", "requester": "赵磊", "uid": "U1004",
             "acct": "PA002", "justification": "生产环境故障排查",
             "duration_min": 120, "status": "approved",
             "approver": "陈军", "created_at": "2026-09-14 09:00:00",
             "expires_at": "2026-09-14 11:00:00", "auto_revoke": True},
            {"req_id": "PR-002", "requester": "周涛", "uid": "U1006",
             "acct": "PA003", "justification": "数据库补丁执行",
             "duration_min": 60, "status": "pending",
             "approver": "待审批", "created_at": "2026-09-14 09:40:00",
             "expires_at": None, "auto_revoke": True},
            {"req_id": "PR-003", "requester": "紧急流程", "uid": "-",
             "acct": "PA007", "justification": "主用 IDP 故障",
             "duration_min": 30, "status": "used_emergency",
             "approver": "事后补批", "created_at": "2025-12-01 03:00:00",
             "expires_at": "2025-12-01 03:30:00", "auto_revoke": True},
        ]
        self._svc_deps: List[Dict[str, Any]] = [
            {"svc": "svc-backup", "depends_on": ["fileserver://fs01", "vault://backup-key"],
             "hardcoded_in_repo": False, "last_rotated": "2025-03-20",
             "next_rotate_due": "2026-09-20", "healthy": True},
            {"svc": "svc-etl", "depends_on": ["db://dw01", "s3://raw-zone"],
             "hardcoded_in_repo": True,
             "hardcoded_files": ["infra/ansible/roles/etl/vars/main.yml"],
             "last_rotated": "2026-08-15", "next_rotate_due": "2026-11-15",
             "healthy": False},
            {"svc": "svc-ci-runner", "depends_on": ["gitlab://runner-token"],
             "hardcoded_in_repo": False, "last_rotated": "2026-07-01",
             "next_rotate_due": "2026-10-01", "healthy": True},
        ]

    # ------------------------------------------------------------------ #
    # 盘点
    # ------------------------------------------------------------------ #
    def inventory(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for a in self.accounts:
            by_type[a["type"]] = by_type.get(a["type"], 0) + 1
        return {"accounts": self.accounts,
                "by_type": by_type,
                "total": len(self.accounts),
                "types": PRIV_TYPES}

    # ------------------------------------------------------------------ #
    # 风险评估
    # ------------------------------------------------------------------ #
    def risk_assessment(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for a in self.accounts:
            score = 0
            reasons: List[str] = []
            if a["shared"]:
                score += 25
                reasons.append("共享密码，无法追责")
            if a["pwd_age_days"] > 180:
                score += 20
                reasons.append(f"密码 {a['pwd_age_days']} 天未轮换")
            if not a["mfa"] and a["type"] not in ("service_account",):
                score += 20
                reasons.append("特权账户未启用 MFA")
            if a["type"] in ("domain_admin", "root", "cloud_admin"):
                score += 10
            if a["owner"] in ("Unknown", ""):
                score += 20
                reasons.append("无人负责（孤儿特权）")
            if a["uses_30d"] == 0 and a["type"] != "break_glass":
                score += 10
                reasons.append("30 天未使用，疑似闲置")
            if a["status"] == "orphan":
                score += 15
                reasons.append("账户状态为 orphan")
            score = min(score, 100)
            a["risk_score"] = score
            findings.append({**a, "reasons": reasons,
                             "level": "critical" if score >= 70
                                      else "high" if score >= 40 else "low"})
        findings.sort(key=lambda x: x["risk_score"], reverse=True)
        return {"findings": findings,
                "avg_risk": round(sum(f["risk_score"] for f in findings)
                                  / max(len(findings), 1), 1)}

    # ------------------------------------------------------------------ #
    # 会话
    # ------------------------------------------------------------------ #
    def sessions(self) -> Dict[str, Any]:
        abnormal = [s for s in self._sessions if s["abnormal"]]
        return {"sessions": self._sessions,
                "total": len(self._sessions),
                "abnormal": abnormal,
                "recording_coverage_pct": round(
                    sum(1 for s in self._sessions if s["recording"]) * 100
                    / max(len(self._sessions), 1), 1)}

    def session_replay(self, sid: str) -> Optional[Dict[str, Any]]:
        s = next((x for x in self._sessions if x["sid"] == sid), None)
        if not s:
            return None
        return {"session": s,
                "timeline": [{"t": s["started"], "event": "session_start"},
                             {"t": s["ended"], "event": "session_end"}],
                "commands": s.get("commands", [])}

    # ------------------------------------------------------------------ #
    # 申请审批
    # ------------------------------------------------------------------ #
    def access_requests(self) -> Dict[str, Any]:
        return {"requests": self._requests,
                "total": len(self._requests)}

    def create_request(self, requester: str, uid: str,
                       acct: str, justification: str,
                       duration_min: int = 60) -> Dict[str, Any]:
        req = {
            "req_id": "PR-" + uuid.uuid4().hex[:6].upper(),
            "requester": requester, "uid": uid, "acct": acct,
            "justification": justification, "duration_min": duration_min,
            "status": "pending", "approver": "待审批",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "expires_at": None, "auto_revoke": True,
        }
        self._requests.insert(0, req)
        return req

    def approve_request(self, req_id: str, approver: str,
                        decision: str = "approve") -> Dict[str, Any]:
        r = next((x for x in self._requests if x["req_id"] == req_id), None)
        if not r:
            return {"ok": False, "reason": "request not found"}
        if decision == "approve":
            r["status"] = "approved"
            from datetime import datetime, timedelta
            r["approver"] = approver
            try:
                base = datetime.strptime(r["created_at"], "%Y-%m-%d %H:%M:%S")
                r["expires_at"] = (base + timedelta(minutes=r["duration_min"])
                                   ).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass
        elif decision == "deny":
            r["status"] = "denied"
            r["approver"] = approver
        return {"ok": True, "request": r}

    # ------------------------------------------------------------------ #
    # 服务账户
    # ------------------------------------------------------------------ #
    def service_accounts(self) -> Dict[str, Any]:
        hardcoded = [d for d in self._svc_deps if d["hardcoded_in_repo"]]
        return {"service_accounts": self._svc_deps,
                "hardcoded_credential_findings": hardcoded,
                "rotation_overdue": [
                    d for d in self._svc_deps
                    if d["next_rotate_due"] < "2026-09-14"]}


__all__ = ["PrivilegedAccessManager", "PRIV_TYPES"]
