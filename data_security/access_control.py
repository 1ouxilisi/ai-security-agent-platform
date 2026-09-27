#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
access_control.py — 数据访问控制器。

覆盖：
    - 权限矩阵：用户-角色-权限-数据对象建模与可视化
    - 最小权限评估：权限冗余/过度权限/未使用权限/权限蔓延
    - 特权账户：管理员/服务账户/共享账户/应急账户识别与风险
    - 访问审计：访问日志分析/频率/时间/位置/异常访问模式
    - 异常访问检测：非工作时间/异常位置/异常下载量/异常查询/权限提升
    - 数据脱敏评估：规则/效果/动态脱敏/静态脱敏/完整性
    - 访问控制报告与整改建议

设计定位：仅做访问权限与行为审计评估，输出风险与整改建议。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 特权风险库
# --------------------------------------------------------------------------- #
PRIVILEGE_RISK_LIBRARY: Dict[str, Dict[str, Any]] = {
    "shared_account": {"name": "共享账户", "risk": "high",
                       "desc": "多人共用同一账户，无法追责，应改为个人身份+SSO"},
    "service_account": {"name": "服务账户长期高权", "risk": "high",
                        "desc": "服务账户密码硬编码/永不过期，应改用短期令牌/工作负载身份"},
    "break_glass": {"name": "应急(break-glass)账户", "risk": "medium",
                    "desc": "应急账户应单独保管、全程告警、用完即废"},
    "excess_admin": {"name": "过度管理员", "risk": "critical",
                     "desc": "普通员工持有管理员/超级权限，违反最小权限"},
    "never_expire": {"name": "密钥永不过期", "risk": "high",
                     "desc": "访问令牌/密钥无有效期，泄露后长期可用"},
    "no_mfa": {"name": "特权账户无MFA", "risk": "critical",
               "desc": "管理员未启用多因素认证，易被撞库/钓鱼接管"},
    "orphan_account": {"name": "离职孤儿账户", "risk": "medium",
                       "desc": "员工离职后账户未回收"},
}


class DataAccessController:
    """数据访问控制器。"""

    def __init__(self) -> None:
        self.risk_lib = PRIVILEGE_RISK_LIBRARY

    # ------------------------------------------------------------------ #
    # 权限矩阵
    # ------------------------------------------------------------------ #
    def build_matrix(self,
                     users: Optional[List[Dict[str, Any]]] = None,
                     roles: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """建模 用户-角色-权限-数据对象 权限矩阵。"""
        users = users or [
            {"uid": "u001", "name": "张三", "role": "admin", "dept": "IT"},
            {"uid": "u002", "name": "李四", "role": "analyst", "dept": "市场"},
            {"uid": "u003", "name": "王五", "role": "dev", "dept": "研发"},
            {"uid": "s001", "name": "svc-etl", "role": "service", "dept": "数据平台"},
        ]
        roles = roles or [
            {"role": "admin", "permissions": ["read", "write", "delete", "export", "manage"],
             "objects": ["*"]},
            {"role": "analyst", "permissions": ["read", "export"],
             "objects": ["report.*"]},
            {"role": "dev", "permissions": ["read", "write"],
             "objects": ["dev.*", "stg.*"]},
            {"role": "service", "permissions": ["read", "write"],
             "objects": ["dw.*"], "mfa": False, "expire": "never"},
        ]
        matrix = []
        role_map = {r["role"]: r for r in roles}
        for u in users:
            r = role_map.get(u["role"], {})
            matrix.append({
                "uid": u["uid"], "name": u["name"], "dept": u["dept"],
                "role": u["role"],
                "permissions": r.get("permissions", []),
                "objects": r.get("objects", []),
                "mfa": r.get("mfa", True),
            })
        return {
            "users": users, "roles": roles, "matrix": matrix,
            "visualization": "rows=用户, cols=权限/数据对象, 单元格=授权",
            "total_users": len(users), "total_roles": len(roles),
        }

    # ------------------------------------------------------------------ #
    # 最小权限评估
    # ------------------------------------------------------------------ #
    def assess_least_privilege(self, matrix: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        matrix = matrix or self.build_matrix()
        findings: List[Dict[str, Any]] = []
        for row in matrix["matrix"]:
            perms = set(row["permissions"])
            # 过度权限
            if "manage" in perms or "delete" in perms:
                findings.append({
                    "user": row["name"], "uid": row["uid"],
                    "type": "过度权限", "risk": "high",
                    "detail": f"角色 {row['role']} 持有 manage/delete 权限，超出常规职责",
                    "recommendation": "降级为只读或按需临时提升(JIT)",
                })
            # 导出权限滥用
            if "export" in perms and row["dept"] in ("市场", "研发"):
                findings.append({
                    "user": row["name"], "uid": row["uid"],
                    "type": "导出权限", "risk": "medium",
                    "detail": f"{row['dept']} 角色具备 export 全量导出能力",
                    "recommendation": "导出走审批+脱敏+水印",
                })
            # 通配对象
            if "*" in row["objects"]:
                findings.append({
                    "user": row["name"], "uid": row["uid"],
                    "type": "通配数据对象", "risk": "high",
                    "detail": f"可访问全部数据对象 {row['objects']}",
                    "recommendation": "按业务范围缩小数据对象范围",
                })
            # 未使用权限（模拟：dev 的 export 长期未用）
            if row["role"] == "dev":
                findings.append({
                    "user": row["name"], "uid": row["uid"],
                    "type": "未使用权限", "risk": "low",
                    "detail": "近90天无 export/manage 使用记录",
                    "recommendation": "回收未使用权限",
                })
        # 权限蔓延统计
        sprawl = round(len(findings) / max(len(matrix["matrix"]), 1) * 100, 1)
        return {
            "findings": findings,
            "finding_count": len(findings),
            "permission_sprawl_pct": sprawl,
            "verdict": "权限蔓延严重" if sprawl > 50 else ("需优化" if sprawl > 25 else "较健康"),
        }

    # ------------------------------------------------------------------ #
    # 特权账户
    # ------------------------------------------------------------------ #
    def assess_privileged_accounts(self, accounts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        accounts = accounts or [
            {"name": "root/admin", "type": "管理员账户", "mfa": False, "shared": False,
             "expire": "never", "last_use": "2026-09-01"},
            {"name": "svc-etl", "type": "服务账户", "mfa": False, "shared": True,
             "expire": "never", "last_use": "2026-09-13"},
            {"name": "break-glass", "type": "应急账户", "mfa": True, "shared": True,
             "expire": "180天", "last_use": "2025-12-01"},
            {"name": "legacy-upload", "type": "共享账户", "mfa": False, "shared": True,
             "expire": "never", "last_use": "2024-03-01"},
            {"name": "alice(离职)", "type": "孤儿账户", "mfa": True, "shared": False,
             "expire": "已离职", "last_use": "2026-01-01"},
        ]
        rows = []
        risks: List[str] = []
        for a in accounts:
            flags = []
            if not a["mfa"]:
                flags.append("无MFA")
                risks.append("no_mfa")
            if a["shared"]:
                flags.append("共享")
                risks.append("shared_account")
            if a["expire"] == "never":
                flags.append("永不过期")
                risks.append("never_expire")
            if a["type"] == "服务账户":
                risks.append("service_account")
            if a["type"] == "孤儿账户":
                flags.append("已离职未回收")
                risks.append("orphan_account")
            sev = "critical" if "无MFA" in flags or "已离职未回收" in flags else \
                  ("high" if flags else "low")
            rows.append({**a, "flags": flags, "risk": sev})
        return {
            "accounts": rows, "total": len(rows),
            "high_risk_count": sum(1 for r in rows if r["risk"] in ("critical", "high")),
            "risk_categories": sorted(set(risks)),
            "recommendation": "特权账户强制MFA+JIT提升+短期令牌+及时回收离职账户",
        }

    # ------------------------------------------------------------------ #
    # 访问审计
    # ------------------------------------------------------------------ #
    def audit_access(self, logs: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        logs = logs or [
            {"user": "u002", "action": "read", "object": "report.pii", "ts": "2026-09-14T10:21:00",
             "ip": "10.0.0.5", "bytes": 12000},
            {"user": "u003", "action": "export", "object": "dw.customers", "ts": "2026-09-14T02:11:00",
             "ip": "203.0.113.9", "bytes": 480000000},
            {"user": "u001", "action": "delete", "object": "prod.users", "ts": "2026-09-13T16:40:00",
             "ip": "10.0.0.2", "bytes": 0},
            {"user": "u002", "action": "query", "object": "report.salary", "ts": "2026-09-14T09:05:00",
             "ip": "10.0.0.5", "bytes": 8000},
            {"user": "svc-etl", "action": "write", "object": "dw.orders", "ts": "2026-09-14T03:00:00",
             "ip": "10.0.0.9", "bytes": 12000000},
        ]
        by_user: Dict[str, Dict[str, Any]] = {}
        for l in logs:
            u = by_user.setdefault(l["user"], {"reads": 0, "writes": 0, "exports": 0,
                                               "deletes": 0, "bytes": 0, "times": []})
            act = l["action"]
            if act in u:
                u[act] += 1
            u["bytes"] += l.get("bytes", 0)
            u["times"].append(l["ts"])
        return {
            "total_events": len(logs),
            "by_user": by_user,
            "audit_note": "建议接入UEBA基线:正常工作时间/常用IP/单次数据量",
        }

    # ------------------------------------------------------------------ #
    # 异常访问检测
    # ------------------------------------------------------------------ #
    def detect_anomalies(self, logs: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        logs = logs or [
            {"user": "u003", "action": "export", "object": "dw.customers",
             "hour": 2, "ip": "203.0.113.9", "bytes": 480000000, "new_ip": True},
            {"user": "u002", "action": "query", "object": "report.salary",
             "hour": 10, "ip": "10.0.0.5", "bytes": 8000, "new_ip": False},
            {"user": "u001", "action": "delete", "object": "prod.users",
             "hour": 16, "ip": "10.0.0.2", "bytes": 0, "new_ip": False},
            {"user": "u002", "action": "priv_escalate", "object": "role.admin",
             "hour": 23, "ip": "198.51.100.4", "bytes": 0, "new_ip": True},
        ]
        anomalies: List[Dict[str, Any]] = []
        for l in logs:
            reasons = []
            if l.get("hour", 12) < 7 or l.get("hour", 12) > 21:
                reasons.append("非工作时间")
            if l.get("new_ip"):
                reasons.append("异常位置/新IP")
            if l.get("bytes", 0) > 100_000_000:
                reasons.append("异常大批量下载(>100MB)")
            if l["action"] in ("delete", "export") and "prod" in l["object"]:
                reasons.append("高危操作-生产数据")
            if l["action"] == "priv_escalate":
                reasons.append("疑似权限提升")
            if reasons:
                anomalies.append({
                    "user": l["user"], "action": l["action"], "object": l["object"],
                    "hour": l["hour"], "ip": l["ip"], "bytes": l["bytes"],
                    "reasons": reasons,
                    "severity": "critical" if "权限提升" in reasons or "大批量" in reasons else "high",
                    "recommendation": "触发MFA/审批/会话挂起+人工复核",
                })
        return anomalies

    # ------------------------------------------------------------------ #
    # 数据脱敏评估
    # ------------------------------------------------------------------ #
    def assess_masking(self, samples: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        samples = samples or [
            {"field": "mobile", "rule": "保留前3后4", "before": "13812345678",
             "after": "138****5678", "dynamic": True, "leakage_risk": "low"},
            {"field": "id_card", "rule": "保留前6后4", "before": "110101199001011234",
             "after": "110101********1234", "dynamic": True, "leakage_risk": "low"},
            {"field": "bank_card", "rule": "未脱敏", "before": "6222021234567890123",
             "after": "6222021234567890123", "dynamic": False, "leakage_risk": "critical"},
            {"field": "address", "rule": "保留省市", "before": "北京市朝阳区xx路1号",
             "after": "北京市朝阳区", "dynamic": True, "leakage_risk": "medium"},
            {"field": "salary", "rule": "静态脱敏库", "before": "25000",
             "after": "2xxxx", "dynamic": False, "leakage_risk": "medium"},
        ]
        incomplete = [s for s in samples if s["leakage_risk"] in ("high", "critical")]
        return {
            "fields": samples,
            "masked_count": len(samples) - len(incomplete),
            "leaky_count": len(incomplete),
            "dynamic_masking": any(s["dynamic"] for s in samples),
            "static_masking": any(not s["dynamic"] for s in samples),
            "incomplete_fields": [s["field"] for s in incomplete],
            "recommendation": "生产查询默认动态脱敏;银行卡/身份证全程mask;按角色决定是否可见",
        }

    # ------------------------------------------------------------------ #
    # 综合 + 报告
    # ------------------------------------------------------------------ #
    def assess(self, signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        signals = signals or {}
        matrix = self.build_matrix(signals.get("users"), signals.get("roles"))
        least = self.assess_least_privilege(matrix)
        priv = self.assess_privileged_accounts(signals.get("accounts"))
        audit = self.audit_access(signals.get("logs"))
        anomalies = self.detect_anomalies(signals.get("logs"))
        masking = self.assess_masking(signals.get("samples"))
        score = round(100 - least["finding_count"] * 6 - priv["high_risk_count"] * 12
                      - len(anomalies) * 8 - masking["leaky_count"] * 10, 1)
        score = max(0, min(100, score))
        return {
            "assessment_id": uuid.uuid4().hex[:10],
            "matrix": matrix,
            "least_privilege": least,
            "privileged_accounts": priv,
            "audit": audit,
            "anomalies": anomalies,
            "masking": masking,
            "overall_score": score,
            "grade": "A" if score >= 85 else ("B" if score >= 70 else ("C" if score >= 55 else "D")),
            "remediation": [
                "特权账户强制MFA+JIT临时提升",
                "回收未使用/过度权限,避免通配",
                "离职/共享账户及时清理",
                "生产查询默认动态脱敏",
                "部署UEBA检测非工作时间/异常下载/权限提升",
            ],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def get_report_markdown(self, result: Dict[str, Any]) -> str:
        lines = [
            "# 数据访问控制报告", "",
            f"- 评估ID: {result.get('assessment_id')}",
            f"- 综合得分: {result.get('overall_score')} ({result.get('grade')})",
            f"- 最小权限问题: {result.get('least_privilege', {}).get('finding_count')}",
            f"- 高风险特权账户: {result.get('privileged_accounts', {}).get('high_risk_count')}",
            f"- 异常访问: {len(result.get('anomalies', []))}",
            f"- 脱敏不完整字段: {result.get('masking', {}).get('leaky_count')}", "",
            "## 异常访问",
        ]
        for a in result.get("anomalies", []):
            lines.append(f"- [{a['severity']}] {a['user']} {a['action']} {a['object']}: "
                         + ",".join(a["reasons"]))
        lines += ["", "## 整改建议"]
        for r in result.get("remediation", []):
            lines.append(f"- {r}")
        return "\n".join(lines)

    def list_anomalies(self) -> Dict[str, Any]:
        return {"anomalies": self.detect_anomalies(),
                "risk_categories": self.risk_lib}
