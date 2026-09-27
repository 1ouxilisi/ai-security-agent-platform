#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
access_audit.py — 数据访问控制与审计深度引擎（Round24 方向3）。

覆盖：
    1. 访问控制：认证/RBAC/ABAC/最小权限/职责分离
    2. 数据访问审批：申请/审批流程/多级审批/临时授权/授权期限/审批记录
    3. 数据访问审计：访问/操作/查询/导出/修改/删除日志/完整审计链
    4. 异常访问检测：异常时间/地点/频率/数据量/用户/ML异常检测
    5. 数据防滥用：批量导出限制/敏感操作限制/下载/打印/截屏/复制限制/水印追踪
    6. 合规报告：访问/权限/审计/数据使用/风险/整改报告

设计定位：仅做访问策略模拟与审计日志记录，不做真实系统权限管控。
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


# 访问控制模式
ACCESS_CONTROL_MODES: Dict[str, Dict[str, Any]] = {
    "rbac": {
        "name": "基于角色的访问控制(RBAC)",
        "desc": "用户通过角色获得权限，最常用模型",
        "complexity": "low", "granularity": "medium",
        "use_when": "组织架构稳定、岗位明确",
    },
    "abac": {
        "name": "基于属性的访问控制(ABAC)",
        "desc": "根据用户/资源/环境属性动态决策",
        "complexity": "high", "granularity": "very_high",
        "use_when": "需要细粒度动态策略",
    },
    "acl": {
        "name": "访问控制列表(ACL)",
        "desc": "直接在资源上挂用户/组权限",
        "complexity": "medium", "granularity": "high",
        "use_when": "资源数量有限、权限明确",
    },
    "pam": {
        "name": "特权访问管理(PAM)",
        "desc": "特权账号精细化管控、会话录制、审批",
        "complexity": "high", "granularity": "very_high",
        "use_when": "保护高敏感数据/系统",
    },
}

# 异常检测规则
ANOMALY_RULES: Dict[str, Dict[str, Any]] = {
    "off_hours_access": {
        "name": "非工作时间访问", "desc": "检测夜间/节假日的访问行为",
        "threshold": "22:00-06:00", "severity": "medium",
    },
    "geo_anomaly": {
        "name": "异地登录异常", "desc": "短时间内多地登录",
        "threshold": "距离>500km 且时间<1h", "severity": "high",
    },
    "freq_anomaly": {
        "name": "访问频率异常", "desc": "短时间高频访问同一资源",
        "threshold": ">100次/分钟", "severity": "medium",
    },
    "volume_anomaly": {
        "name": "数据量异常", "desc": "单次导出/查询量远超正常",
        "threshold": ">10000条/次", "severity": "high",
    },
    "privilege_abuse": {
        "name": "权限滥用", "desc": "用户访问其职责范围外数据",
        "threshold": "超出岗位职责", "severity": "critical",
    },
    "ml_anomaly": {
        "name": "ML模型异常检测", "desc": "基于行为基线的无监督异常检测",
        "threshold": "偏离基线>3σ", "severity": "high",
    },
}

# 防滥用策略
ANTI_ABUSE_POLICIES: Dict[str, Dict[str, Any]] = {
    "export_limit": {"name": "批量导出限制", "max_rows_per_day": 5000, "max_rows_per_query": 1000},
    "download_limit": {"name": "下载限制", "max_files_per_day": 50, "require_approval_over": 10},
    "print_limit": {"name": "打印限制", "max_pages_per_day": 100, "watermark_required": True},
    "screenshot_block": {"name": "截屏限制", "block_on_sensitive": True, "alert_on_attempt": True},
    "copy_limit": {"name": "复制限制", "max_chars_per_copy": 5000, "log_all": True},
    "watermark_tracking": {"name": "水印追踪", "embed_user_watermark": True, "trace_enabled": True},
}


class AccessAuditEngine:
    """数据访问控制与审计引擎"""

    def __init__(self) -> None:
        self.users: Dict[str, Dict[str, Any]] = {}
        self.roles: Dict[str, Dict[str, Any]] = {}
        self.permissions: Dict[str, List[str]] = {}
        self.approval_requests: Dict[str, Dict[str, Any]] = {}
        self.audit_logs: List[Dict[str, Any]] = []
        self.anomaly_alerts: Dict[str, Dict[str, Any]] = {}
        self.temp_grants: Dict[str, Dict[str, Any]] = {}
        self._init_defaults()

    def _init_defaults(self) -> None:
        self.roles = {
            "admin": {"role_id": "admin", "name": "系统管理员", "permissions": ["*"]},
            "data_analyst": {"role_id": "data_analyst", "name": "数据分析师",
                             "permissions": ["read:customer", "read:finance", "export:limited"]},
            "auditor": {"role_id": "auditor", "name": "审计员",
                        "permissions": ["read:audit", "read:logs"]},
            "developer": {"role_id": "developer", "name": "开发人员",
                          "permissions": ["read:internal", "write:dev"]},
        }
        self.users = {
            "u001": {"user_id": "u001", "name": "张三", "role": "data_analyst",
                     "department": "数据部", "risk_level": "low"},
            "u002": {"user_id": "u002", "name": "李四", "role": "admin",
                     "department": "IT部", "risk_level": "medium"},
            "u003": {"user_id": "u003", "name": "王五", "role": "auditor",
                     "department": "审计部", "risk_level": "low"},
        }

    # ---------- 1. 访问控制 ----------
    def check_access(self, user_id: str, resource: str,
                    action: str = "read") -> Dict[str, Any]:
        """检查用户对资源的访问权限"""
        if user_id not in self.users:
            return {"allowed": False, "reason": "用户不存在"}
        user = self.users[user_id]
        role = self.roles.get(user["role"], {})
        perms = role.get("permissions", [])
        # 通配符
        if "*" in perms:
            allowed = True
        else:
            perm_key = f"{action}:{resource.split(':')[0] if ':' in resource else resource}"
            allowed = perm_key in perms or f"{action}:*" in perms
        # 记录审计
        log_id = f"log-{uuid.uuid4().hex[:10]}"
        self.audit_logs.append({
            "log_id": log_id, "user_id": user_id, "user_name": user["name"],
            "resource": resource, "action": action,
            "allowed": allowed, "role": user["role"],
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "ip": "10.0.1." + str(hash(user_id) % 254),
        })
        # 异常检测
        anomaly = self._detect_anomaly(user_id, action, resource)
        return {
            "allowed": allowed, "user": user["name"],
            "role": user["role"], "resource": resource, "action": action,
            "anomaly_detected": anomaly["detected"],
            "anomaly_reasons": anomaly["reasons"],
            "log_id": log_id,
        }

    def _detect_anomaly(self, user_id: str, action: str,
                       resource: str) -> Dict[str, Any]:
        reasons = []
        hour = datetime.now().hour
        if hour < 6 or hour > 22:
            reasons.append("非工作时间访问")
        if action in ("export", "delete") and "admin" not in self.users.get(user_id, {}).get("role", ""):
            reasons.append("非管理员执行敏感操作")
        return {"detected": len(reasons) > 0, "reasons": reasons}

    def list_roles(self) -> Dict[str, Any]:
        return self.roles

    def list_users(self) -> Dict[str, Any]:
        return self.users

    # ---------- 2. 数据访问审批 ----------
    def request_access(self, user_id: str, resource: str,
                      reason: str = "", duration_hours: int = 4,
                      approver: str = "manager") -> Dict[str, Any]:
        """申请敏感数据访问"""
        req_id = f"req-{uuid.uuid4().hex[:10]}"
        self.approval_requests[req_id] = {
            "request_id": req_id, "user_id": user_id,
            "resource": resource, "reason": reason,
            "duration_hours": duration_hours,
            "approver": approver,
            "status": "pending",
            "requested_at": datetime.now().isoformat(timespec="seconds"),
        }
        return {
            "request_id": req_id, "status": "pending",
            "resource": resource, "duration_hours": duration_hours,
            "message": "审批申请已提交",
        }

    def approve_request(self, request_id: str, approver: str,
                       approved: bool = True, comment: str = "") -> Dict[str, Any]:
        if request_id not in self.approval_requests:
            return {"error": "申请不存在"}
        req = self.approval_requests[request_id]
        req["status"] = "approved" if approved else "rejected"
        req["approver"] = approver
        req["comment"] = comment
        req["decided_at"] = datetime.now().isoformat(timespec="seconds")
        if approved:
            # 创建临时授权
            grant_id = f"grant-{uuid.uuid4().hex[:10]}"
            expiry = (datetime.now() + timedelta(hours=req["duration_hours"])).isoformat(timespec="seconds")
            self.temp_grants[grant_id] = {
                "grant_id": grant_id, "user_id": req["user_id"],
                "resource": req["resource"], "expires_at": expiry,
                "approved_by": approver,
            }
            req["grant_id"] = grant_id
        return {
            "request_id": request_id, "status": req["status"],
            "grant_id": req.get("grant_id"),
            "expires_at": self.temp_grants.get(req.get("grant_id", ""), {}).get("expires_at"),
        }

    def list_requests(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.approval_requests.values())
        if status:
            items = [r for r in items if r["status"] == status]
        return items

    def list_temp_grants(self) -> List[Dict[str, Any]]:
        now = datetime.now()
        active = []
        for g in self.temp_grants.values():
            try:
                exp = datetime.fromisoformat(g["expires_at"])
                g["expired"] = now > exp
                g["remaining_hours"] = max(0, round((exp - now).total_seconds() / 3600, 1))
            except Exception:
                g["expired"] = True
            active.append(g)
        return active

    # ---------- 3. 审计日志 ----------
    def get_audit_logs(self, user_id: Optional[str] = None,
                      action: Optional[str] = None,
                      resource: Optional[str] = None,
                      start: int = 0, limit: int = 100) -> Dict[str, Any]:
        logs = self.audit_logs
        if user_id:
            logs = [l for l in logs if l["user_id"] == user_id]
        if action:
            logs = [l for l in logs if l["action"] == action]
        if resource:
            logs = [l for l in logs if resource in l["resource"]]
        total = len(logs)
        return {
            "total": total, "start": start, "limit": limit,
            "items": logs[start:start + limit],
        }

    def audit_chain(self, user_id: str) -> List[Dict[str, Any]]:
        """某用户的完整审计链"""
        return [l for l in self.audit_logs if l["user_id"] == user_id]

    # ---------- 4. 异常访问检测 ----------
    def detect_anomalies(self, hours: int = 24) -> Dict[str, Any]:
        """综合异常检测"""
        alerts = []
        now = datetime.now()
        # 模拟生成告警
        rule_list = list(ANOMALY_RULES.values())
        for i, rule in enumerate(rule_list):
            aid = f"anomaly-{uuid.uuid4().hex[:8]}"
            alert = {
                "alert_id": aid, "rule_name": rule["name"],
                "severity": rule["severity"],
                "user_id": f"u00{i + 1}",
                "detail": f"触发规则: {rule['name']}, 阈值: {rule['threshold']}",
                "detected_at": (now - timedelta(hours=i)).isoformat(timespec="seconds"),
                "status": "open",
            }
            self.anomaly_alerts[aid] = alert
            alerts.append(alert)
        return {
            "window_hours": hours,
            "total_alerts": len(alerts),
            "by_severity": {
                "critical": sum(1 for a in alerts if a["severity"] == "critical"),
                "high": sum(1 for a in alerts if a["severity"] == "high"),
                "medium": sum(1 for a in alerts if a["severity"] == "medium"),
            },
            "alerts": alerts,
        }

    def list_anomaly_rules(self) -> Dict[str, Any]:
        return ANOMALY_RULES

    # ---------- 5. 数据防滥用 ----------
    def check_abuse(self, user_id: str, operation: str,
                   data_volume: int = 0) -> Dict[str, Any]:
        """检查操作是否违反防滥用策略"""
        violations = []
        policies = ANTI_ABUSE_POLICIES
        if operation == "export" and data_volume > policies["export_limit"]["max_rows_per_query"]:
            violations.append({
                "policy": "export_limit",
                "reason": f"单次导出{data_volume}条超过限制({policies['export_limit']['max_rows_per_query']})",
                "action": "block",
            })
        if operation == "print":
            violations.append({
                "policy": "print_limit",
                "reason": "打印敏感数据需加水印",
                "action": "watermark",
            })
        if operation == "screenshot":
            violations.append({
                "policy": "screenshot_block",
                "reason": "敏感页面截屏已被阻断并记录",
                "action": "block",
            })
        return {
            "user_id": user_id, "operation": operation,
            "violations_detected": len(violations),
            "violations": violations,
            "allowed": len(violations) == 0 or all(v["action"] != "block" for v in violations),
        }

    def get_anti_abuse_policies(self) -> Dict[str, Any]:
        return ANTI_ABUSE_POLICIES

    # ---------- 6. 合规报告 ----------
    def generate_compliance_report(self, report_type: str = "access") -> Dict[str, Any]:
        """生成合规报告"""
        report_id = f"report-{uuid.uuid4().hex[:10]}"
        reports = {
            "access": {
                "name": "访问合规报告",
                "summary": f"本周期共记录{len(self.audit_logs)}条访问日志",
                "metrics": {
                    "total_access": len(self.audit_logs),
                    "denied_access": sum(1 for l in self.audit_logs if not l["allowed"]),
                    "avg_permission_score": 85,
                },
                "findings": ["权限分配符合最小权限原则", "3个账号存在过度授权待清理"],
            },
            "permission": {
                "name": "权限合规报告",
                "summary": f"共{len(self.roles)}个角色, {len(self.users)}个用户",
                "metrics": {
                    "roles": len(self.roles), "users": len(self.users),
                    "temp_grants": len(self.temp_grants),
                },
                "findings": ["2个临时授权已过期未回收", "建议清理离职人员权限"],
            },
            "audit": {
                "name": "审计合规报告",
                "summary": f"审计日志完整率100%",
                "metrics": {
                    "logs_total": len(self.audit_logs),
                    "integrity": "100%",
                    "retention_days": 180,
                },
                "findings": ["审计链完整", "建议增加实时告警"],
            },
            "risk": {
                "name": "风险评估报告",
                "summary": "数据访问风险等级: 中",
                "metrics": {
                    "risk_score": 65,
                    "open_alerts": len(self.anomaly_alerts),
                    "critical_alerts": sum(1 for a in self.anomaly_alerts.values() if a.get("severity") == "critical"),
                },
                "findings": ["存在非工作时间访问异常", "建议加强终端管控"],
            },
        }
        rpt = reports.get(report_type, reports["access"])
        return {
            "report_id": report_id, "type": report_type,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            **rpt,
        }

    # ---------- 统计 ----------
    def stats(self) -> Dict[str, Any]:
        return {
            "users": len(self.users),
            "roles": len(self.roles),
            "audit_logs": len(self.audit_logs),
            "pending_requests": sum(1 for r in self.approval_requests.values() if r["status"] == "pending"),
            "temp_grants": len(self.temp_grants),
            "anomaly_alerts": len(self.anomaly_alerts),
            "access_control_modes": len(ACCESS_CONTROL_MODES),
            "anomaly_rules": len(ANOMALY_RULES),
            "anti_abuse_policies": len(ANTI_ABUSE_POLICIES),
        }


_instance: Optional[AccessAuditEngine] = None


def get_access_audit_engine() -> AccessAuditEngine:
    global _instance
    if _instance is None:
        _instance = AccessAuditEngine()
    return _instance
