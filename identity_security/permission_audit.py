#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
permission_audit.py — 权限审计与治理。

覆盖：
    - 权限盘点：用户/角色/组/资源权限、有效权限计算、权限矩阵
    - 权限风险评估：过度权限/蔓延/休眠/特权/冲突，0-100 风险分
    - 权限复核：工作流/经理审批/Owner 确认/报告/状态跟踪
    - 最小权限分析：当前 vs 所需、差距、收敛建议、使用频率
    - 权限变更监控：授予/撤销/修改、异常告警、审计日志、趋势

设计定位：仅做权限盘点与治理视角的风险分析，输出整改建议。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 角色与权限库
# --------------------------------------------------------------------------- #
ROLE_LIBRARY: Dict[str, Dict[str, Any]] = {
    "ITAdmin": {"name": "IT 管理员", "level": "high",
                "permissions": ["server.admin", "iam.write", "vault.admin",
                                "network.config"]},
    "VaultAdmin": {"name": "密钥库管理员", "level": "critical",
                   "permissions": ["vault.admin", "vault.rotate", "secrets.read"]},
    "FinanceAnalyst": {"name": "财务分析师", "level": "medium",
                       "permissions": ["finance.report.read", "finance.export"]},
    "FinanceDirector": {"name": "财务总监", "level": "high",
                        "permissions": ["finance.report.read", "finance.export",
                                        "finance.approve"]},
    "Approver": {"name": "审批人", "level": "medium",
                 "permissions": ["access.approve"]},
    "Developer": {"name": "开发工程师", "level": "medium",
                  "permissions": ["code.read", "ci.run", "repo.push"]},
    "OpsEngineer": {"name": "运维工程师", "level": "high",
                    "permissions": ["server.admin", "deploy.run", "log.read"]},
    "DBReader": {"name": "数据库只读", "level": "medium",
                 "permissions": ["db.select"]},
    "SalesRep": {"name": "销售代表", "level": "low",
                 "permissions": ["crm.read", "crm.own"]},
    "LegacyAppUser": {"name": "旧应用用户", "level": "low",
                      "permissions": ["legacy.read"]},
    "BackupService": {"name": "备份服务", "level": "high",
                      "permissions": ["fs.read", "fs.write", "backup.run"]},
    "ETLRunner": {"name": "ETL 执行", "level": "high",
                  "permissions": ["db.select", "fs.write", "s3.read"]},
    "EngineeringDirector": {"name": "技术总监", "level": "high",
                           "permissions": ["code.admin", "deploy.run",
                                           "server.read"]},
}

PERMISSION_SEVERITY: Dict[str, str] = {
    "server.admin": "critical", "iam.write": "critical", "vault.admin": "critical",
    "vault.rotate": "high", "secrets.read": "high", "network.config": "high",
    "db.select": "medium", "fs.write": "medium", "deploy.run": "high",
    "code.admin": "high", "access.approve": "medium",
}


class PermissionAuditor:
    """权限审计与治理。"""

    def __init__(self) -> None:
        self.roles = ROLE_LIBRARY
        self._changes: List[Dict[str, Any]] = [
            {"change_id": "C001", "ts": "2026-09-10 09:12:00",
             "actor": "admin.jobs", "uid": "U1001", "role": "VaultAdmin",
             "action": "grant", "reason": "onboarding", "approved_by": "cio"},
            {"change_id": "C002", "ts": "2026-09-11 14:30:00",
             "actor": "zhang.wei", "uid": "U1004", "role": "server.admin",
             "action": "grant", "reason": "incident", "approved_by": "zhang.wei"},
            {"change_id": "C003", "ts": "2026-09-12 18:05:00",
             "actor": "unknown", "uid": "U1009", "role": "LegacyAppUser",
             "action": "modify", "reason": "unknown", "approved_by": "none"},
            {"change_id": "C004", "ts": "2026-09-13 07:55:00",
             "actor": "hr.auto", "uid": "U1007", "role": "SalesRep",
             "action": "revoke", "reason": "termination", "approved_by": "system"},
        ]
        self._reviews: List[Dict[str, Any]] = [
            {"review_id": "R2026Q3-001", "scope": "IT dept", "owner": "zhang.wei",
             "period": "2026Q3", "status": "in_progress",
             "total_roles": 42, "approved": 28, "pending": 14,
             "due": "2026-09-30", "created_at": "2026-07-01 09:00:00"},
            {"review_id": "R2026Q3-002", "scope": "Finance dept", "owner": "wang.fang",
             "period": "2026Q3", "status": "done",
             "total_roles": 18, "approved": 18, "pending": 0,
             "due": "2026-09-30", "created_at": "2026-07-01 09:00:00"},
            {"review_id": "R2026Q2-001", "scope": "Engineering dept",
             "owner": "chen.jun", "period": "2026Q2", "status": "done",
             "total_roles": 64, "approved": 60, "pending": 4,
             "due": "2026-06-30", "created_at": "2026-04-01 09:00:00"},
        ]
        # 模拟"使用频率"：角色 -> 30 天内被实际调用次数
        self._usage_freq: Dict[str, int] = {
            "ITAdmin": 120, "VaultAdmin": 8, "FinanceAnalyst": 350,
            "FinanceDirector": 12, "Approver": 5, "Developer": 2200,
            "OpsEngineer": 880, "DBReader": 4100, "SalesRep": 0,
            "LegacyAppUser": 0, "BackupService": 900, "ETLRunner": 3000,
            "EngineeringDirector": 22,
        }

    # ------------------------------------------------------------------ #
    # 权限盘点 / 矩阵
    # ------------------------------------------------------------------ #
    def inventory(self,
                  users: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        if users is None:
            users = [
                {"uid": "U1001", "name": "张伟", "dept": "IT",
                 "roles": ["ITAdmin", "VaultAdmin"]},
                {"uid": "U1002", "name": "李娜", "dept": "Finance",
                 "roles": ["FinanceAnalyst"]},
                {"uid": "U1003", "name": "王芳", "dept": "Finance",
                 "roles": ["FinanceDirector", "Approver"]},
                {"uid": "U1004", "name": "赵磊", "dept": "Engineering",
                 "roles": ["Developer", "server.admin"]},
                {"uid": "U1006", "name": "周涛", "dept": "IT",
                 "roles": ["OpsEngineer", "DBReader"]},
                {"uid": "U1007", "name": "吴静", "dept": "Sales",
                 "roles": ["SalesRep"]},
                {"uid": "U1008", "name": "郑浩", "dept": "Engineering",
                 "roles": ["Developer"]},
                {"uid": "U1009", "name": "离职未回收", "dept": "Unknown",
                 "roles": ["LegacyAppUser"]},
                {"uid": "U1010", "name": "陈军", "dept": "Engineering",
                 "roles": ["EngineeringDirector", "Approver"]},
                {"uid": "S2001", "name": "备份服务账户", "dept": "IT",
                 "roles": ["BackupService"]},
                {"uid": "S2002", "name": "ETL 服务账户", "dept": "Data",
                 "roles": ["ETLRunner"]},
            ]
        matrix: List[Dict[str, Any]] = []
        for u in users:
            effective: set[str] = set()
            norm_roles: List[str] = []
            for r in u.get("roles", []):
                if r in self.roles:
                    norm_roles.append(r)
                    effective.update(self.roles[r]["permissions"])
                else:
                    # 直接授权的权限（不在角色库中）
                    effective.add(r)
                    norm_roles.append("DIRECT:" + r)
            matrix.append({
                "uid": u["uid"], "name": u["name"], "dept": u.get("dept", ""),
                "roles": norm_roles,
                "effective_permissions": sorted(effective),
                "effective_count": len(effective),
            })
        return {"matrix": matrix, "total_users": len(users),
                "roles_library": self.roles}

    # ------------------------------------------------------------------ #
    # 风险评估
    # ------------------------------------------------------------------ #
    def risk_assessment(self) -> Dict[str, Any]:
        inv = self.inventory()
        findings: List[Dict[str, Any]] = []
        for row in inv["matrix"]:
            score = 0
            reasons: List[str] = []
            perms = row["effective_permissions"]
            crit = [p for p in perms if PERMISSION_SEVERITY.get(p) == "critical"]
            high = [p for p in perms if PERMISSION_SEVERITY.get(p) == "high"]
            if crit:
                score += 40
                reasons.append(f"持有关键权限: {','.join(crit)}")
            if high:
                score += 15 * len(high)
                reasons.append(f"持有高权权限 {len(high)} 项")
            # 过度权限：开发人员却有 server.admin
            if "server.admin" in perms and row["dept"] == "Engineering":
                score += 25
                reasons.append("开发岗位持有 server.admin，疑似过度权限")
            # 休眠权限：30 天无使用
            for r in row["roles"]:
                if r.startswith("DIRECT:"):
                    continue
                freq = self._usage_freq.get(r, 0)
                if freq == 0:
                    score += 10
                    reasons.append(f"角色 {r} 近 30 天 0 调用（休眠）")
            # 孤儿 / 离职
            if row["dept"] in ("Unknown", "") or row["uid"] == "U1009":
                score += 20
                reasons.append("疑似离职/孤儿账户")
            score = min(score, 100)
            if score >= 40:
                findings.append({
                    "uid": row["uid"], "name": row["name"],
                    "dept": row["dept"], "risk_score": score,
                    "level": "critical" if score >= 70
                             else "high" if score >= 40 else "medium",
                    "reasons": reasons,
                    "permissions": perms,
                })
        findings.sort(key=lambda x: x["risk_score"], reverse=True)
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            distribution[f["level"]] = distribution.get(f["level"], 0) + 1
        return {"findings": findings, "distribution": distribution,
                "scored_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    # ------------------------------------------------------------------ #
    # 复核工作流
    # ------------------------------------------------------------------ #
    def reviews(self) -> Dict[str, Any]:
        return {"reviews": self._reviews,
                "total": len(self._reviews),
                "avg_completion": 0.78}

    def review_action(self, review_id: str, action: str,
                      comment: str = "") -> Dict[str, Any]:
        r = next((x for x in self._reviews if x["review_id"] == review_id), None)
        if not r:
            return {"ok": False, "reason": "review not found"}
        if action == "approve_all":
            r["pending"] = 0
            r["approved"] = r["total_roles"]
            r["status"] = "done"
        elif action == "request_revoke":
            r["status"] = "revoke_requested"
        elif action == "reopen":
            r["status"] = "in_progress"
        r["last_comment"] = comment
        r["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return {"ok": True, "review": r}

    # ------------------------------------------------------------------ #
    # 最小权限分析
    # ------------------------------------------------------------------ #
    def least_privilege(self) -> Dict[str, Any]:
        findings = self.risk_assessment()["findings"]
        recommendations: List[Dict[str, Any]] = []
        for f in findings:
            to_remove: List[str] = []
            for p in f["permissions"]:
                sev = PERMISSION_SEVERITY.get(p, "low")
                if sev in ("critical", "high") and "server.admin" in f["permissions"] \
                        and f["dept"] == "Engineering" and p == "server.admin":
                    to_remove.append(p)
                if p == "LegacyAppUser" or p.startswith("legacy."):
                    to_remove.append(p)
            recommendations.append({
                "uid": f["uid"], "name": f["name"],
                "current_count": len(f["permissions"]),
                "recommended_remove": to_remove,
                "target_count": len(f["permissions"]) - len(to_remove),
                "expected_risk_drop": min(f["risk_score"], 30 + 5 * len(to_remove)),
            })
        return {"recommendations": recommendations,
                "total_candidates": len(recommendations),
                "usage_freq": self._usage_freq}

    # ------------------------------------------------------------------ #
    # 变更监控
    # ------------------------------------------------------------------ #
    def changes(self, limit: int = 50) -> Dict[str, Any]:
        items = sorted(self._changes,
                       key=lambda x: x.get("ts", ""), reverse=True)[:limit]
        alerts: List[Dict[str, Any]] = []
        for c in items:
            if c.get("approved_by") in ("none", "unknown"):
                alerts.append({"change_id": c["change_id"], "level": "high",
                               "desc": f"{c['uid']} 权限 {c['action']} 无明确审批人",
                               "ts": c["ts"]})
            if c.get("reason") == "incident" and c.get("action") == "grant":
                alerts.append({"change_id": c["change_id"], "level": "medium",
                               "desc": f"事件触发临时提权 {c['uid']}，需确认是否到期回收",
                               "ts": c["ts"]})
        trend = [
            {"day": "2026-09-08", "grant": 4, "revoke": 2, "modify": 1},
            {"day": "2026-09-09", "grant": 2, "revoke": 3, "modify": 0},
            {"day": "2026-09-10", "grant": 5, "revoke": 1, "modify": 2},
            {"day": "2026-09-11", "grant": 6, "revoke": 2, "modify": 1},
            {"day": "2026-09-12", "grant": 3, "revoke": 4, "modify": 3},
            {"day": "2026-09-13", "grant": 2, "revoke": 5, "modify": 0},
        ]
        return {"changes": items, "alerts": alerts, "trend": trend,
                "total": len(self._changes)}


__all__ = ["PermissionAuditor", "ROLE_LIBRARY", "PERMISSION_SEVERITY"]
