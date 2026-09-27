# -*- coding: utf-8 -*-
"""
identity_access.py — 身份与访问管理器（第13轮升级 · 零信任模块）。

功能：
- 身份治理：身份生命周期（创建/变更/停用/删除）、身份合并/去重、
  孤儿账户检测、休眠账户检测
- 多因素认证(MFA)评估：MFA覆盖率 / 认证方式（短信/邮件/TOTP/硬件令牌/生物识别）
  / MFA绕过风险 / 弱MFA检测
- 单点登录(SSO)：SSO覆盖率 / 协议（SAML/OAuth2/OIDC/CAS）/ 会话管理 /
  联邦身份 / SSO配置安全
- 生命周期管理：入职/转岗/离职流程自动化、权限回收及时性、账户停用延迟
- 特权访问管理(PAM)：特权账户识别 / 特权会话管理 / 密码保险库 /
  即时授权(JIT) / 会话录制 / 特权操作审计
- 身份风险评分：基于用户行为 / 权限 / 设备 / 位置的综合风险评分（0-100）
- 身份与访问评估报告

说明：所有第三方依赖用 try-import，不可用时返回内嵌模拟数据。
仅用于授权环境下的防御性评估，不实际登录、不枚举真实目录服务。
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

# 可选第三方库：目录服务 SDK 等，不可用时走模拟数据
try:  # pragma: no cover
    import ldap3  # type: ignore
    _LDAP3_OK = True
except Exception:
    ldap3 = None  # type: ignore
    _LDAP3_OK = False

try:  # pragma: no cover
    import jwt  # type: ignore
    _JWT_OK = True
except Exception:
    jwt = None  # type: ignore
    _JWT_OK = False


# ==================== 内嵌策略库 ====================

# MFA 认证方式强度评级（0-100），用于弱 MFA 检测
MFA_METHOD_STRENGTH: Dict[str, Dict[str, Any]] = {
    "sms":       {"name": "短信验证码",     "strength": 35, "risk": "high",
                  "desc": "SIM劫持/钓鱼风险高，易被中间人拦截"},
    "email":     {"name": "邮件验证码",     "strength": 25, "risk": "critical",
                  "desc": "邮箱凭据泄露即失陷，不建议作为强MFA"},
    "totp":      {"name": "TOTP动态口令",   "strength": 70, "risk": "medium",
                  "desc": "时间同步一次性口令，备份码泄露风险"},
    "push":      {"name": "推送确认",       "strength": 65, "risk": "medium",
                  "desc": "MFA疲劳钓鱼（Bombing）需额外应对"},
    "hardware":  {"name": "硬件令牌",       "strength": 90, "risk": "low",
                  "desc": "FIDO2/U2F硬件密钥，抗钓鱼最强"},
    "biometric": {"name": "生物识别",       "strength": 80, "risk": "low",
                  "desc": "指纹/面容，需与设备绑定防重放"},
    "cert":      {"name": "客户端证书",     "strength": 85, "risk": "low",
                  "desc": "证书+私钥，需配合硬件存储"},
}

# SSO 协议安全评级
SSO_PROTOCOL_SECURITY: Dict[str, Dict[str, Any]] = {
    "saml":     {"name": "SAML 2.0",      "maturity": 75, "risk": "medium",
                 "desc": "企业主流，需校验签名与断言有效期"},
    "oauth2":   {"name": "OAuth 2.0",     "maturity": 70, "risk": "medium",
                 "desc": "授权框架本身不强制认证强度，易过度授权"},
    "oidc":     {"name": "OIDC",          "maturity": 85, "risk": "low",
                 "desc": "OAuth+身份层，ID Token标准完善"},
    "cas":      {"name": "CAS",           "maturity": 55, "risk": "high",
                 "desc": "旧版票据协议，升级为SAML/OIDC"},
    "kerberos": {"name": "Kerberos",      "maturity": 75, "risk": "medium",
                 "desc": "域环境标准，需防黄金/白银票据"},
}

# 特权账户类型
PRIVILEGED_ACCOUNT_TYPES: List[Dict[str, Any]] = [
    {"type": "domain_admin",   "name": "域管理员",       "risk": "critical", "scope": "全域"},
    {"type": "local_admin",    "name": "本地管理员",     "risk": "high",     "scope": "单机"},
    {"type": "root_sudo",      "name": "root/sudo",     "risk": "critical", "scope": "Linux主机"},
    {"type": "db_admin",        "name": "数据库管理员", "risk": "high",     "scope": "数据库"},
    {"type": "cloud_admin",     "name": "云平台管理员",  "risk": "critical", "scope": "云租户"},
    {"type": "service_account", "name": "服务账户",      "risk": "high",     "scope": "应用/服务"},
    {"type": "emergency_break", "name": "紧急中断账户",  "risk": "critical", "scope": "急救"},
]

# 休眠账户阈值（天）
DORMANT_THRESHOLDS = {"warning_days": 45, "critical_days": 90}


# ==================== 数据结构 ====================

@dataclass
class IdentityUser:
    """模拟用户身份记录"""
    user_id: str = ""
    username: str = ""
    display_name: str = ""
    email: str = ""
    department: str = ""
    status: str = "active"          # active/suspended/disabled/terminated
    created_at: str = ""
    last_login: str = ""
    mfa_enabled: bool = False
    mfa_method: str = ""
    sso_enabled: bool = False
    sso_protocol: str = ""
    is_privileged: bool = False
    privileged_type: str = ""
    role: str = ""
    groups: List[str] = field(default_factory=list)
    risk_score: int = 0


# ==================== 主评估器 ====================

class IdentityAccessManager:
    """身份与访问管理器（防御性评估视角）。"""

    def __init__(self) -> None:
        self.users: Dict[str, IdentityUser] = {}
        self._seed_users()
        self.assessment_history: List[Dict[str, Any]] = []

    # ---------- 内置模拟身份目录 ----------

    def _seed_users(self) -> None:
        """生成一批模拟用户用于演示评估（非真实目录数据）。"""
        depts = ["研发部", "运维部", "财务部", "人事部", "市场部", "安全部", "外包"]
        roles = ["employee", "developer", "ops", "finance", "manager", "admin", "contractor"]
        mfa_methods = ["sms", "email", "totp", "hardware", "biometric", ""]
        sso_protos = ["saml", "oidc", "oauth2", "cas", ""]
        now = datetime.now()
        rng = random.Random(1301)
        for i in range(1, 121):
            uid = f"u{i:04d}"
            priv = rng.random() < 0.08
            last_login_days = rng.choice([0, 0, 1, 2, 3, 7, 15, 30, 60, 120, 200, 400])
            created = (now - timedelta(days=rng.randint(30, 1800))).isoformat()
            last_login = (now - timedelta(days=last_login_days)).isoformat()
            status = "active"
            if last_login_days > 90:
                status = rng.choice(["active", "active", "suspended"])
            mfa_on = rng.random() < 0.72
            u = IdentityUser(
                user_id=uid,
                username=f"user{i:04d}",
                display_name=f"测试用户{i:04d}",
                email=f"user{i:04d}@example.com",
                department=rng.choice(depts),
                status=status,
                created_at=created,
                last_login=last_login,
                mfa_enabled=mfa_on,
                mfa_method=rng.choice(mfa_methods) if mfa_on else "",
                sso_enabled=rng.random() < 0.6,
                sso_protocol=rng.choice(sso_protos),
                is_privileged=priv,
                privileged_type=rng.choice([t["type"] for t in PRIVILEGED_ACCOUNT_TYPES]) if priv else "",
                role=rng.choice(roles),
                groups=[f"grp_{rng.randint(1, 20)}" for _ in range(rng.randint(0, 4))],
            )
            self.users[uid] = u

    # ---------- 身份生命周期与治理 ----------

    def assess_lifecycle(self) -> Dict[str, Any]:
        """身份生命周期治理评估：孤儿账户、休眠账户、状态一致性。"""
        now = datetime.now()
        dormant_warn, dormant_crit, orphan = [], [], []
        active_count = suspended = disabled = 0
        for uid, u in self.users.items():
            if u.status == "active":
                active_count += 1
            elif u.status == "suspended":
                suspended += 1
            else:
                disabled += 1
            # 休眠检测
            try:
                last = datetime.fromisoformat(u.last_login)
                days = (now - last).days
            except Exception:
                days = 9999
            if u.status == "active":
                if days >= DORMANT_THRESHOLDS["critical_days"]:
                    dormant_crit.append({"user_id": uid, "username": u.username,
                                         "days_inactive": days, "department": u.department})
                elif days >= DORMANT_THRESHOLDS["warning_days"]:
                    dormant_warn.append({"user_id": uid, "username": u.username,
                                         "days_inactive": days, "department": u.department})
            # 孤儿账户：无部门/无角色/无组但仍 active
            if u.status == "active" and (not u.department or u.department == ""
                                         or (not u.groups and u.role == "employee"
                                             and u.department == "外包")):
                orphan.append({"user_id": uid, "username": u.username,
                               "issue": "可能为孤儿账户：无归属部门或无组成员关系"})
        total = len(self.users)
        return {
            "total_users": total,
            "active": active_count,
            "suspended": suspended,
            "disabled_or_terminated": disabled,
            "dormant_warning": dormant_warn,
            "dormant_critical": dormant_crit,
            "orphan_accounts": orphan,
            "orphan_count": len(orphan),
            "dormant_warning_count": len(dormant_warn),
            "dormant_critical_count": len(dormant_crit),
            "recommendations": self._lifecycle_reco(len(orphan), len(dormant_warn), len(dormant_crit)),
        }

    @staticmethod
    def _lifecycle_reco(orphan: int, warn: int, crit: int) -> List[str]:
        reco: List[str] = []
        if orphan > 0:
            reco.append(f"发现 {orphan} 个疑似孤儿账户，应在 7 日内完成归属核查并回收或清理。")
        if crit > 0:
            reco.append(f"{crit} 个账户超过 90 天未登录仍处于 active，建议立即自动停用并触发复核流程。")
        if warn > 0:
            reco.append(f"{warn} 个账户超过 45 天未登录，应发送提醒并延长即停用。")
        if not reco:
            reco.append("身份生命周期治理状态良好，建议保持定期（季度）访问审查。")
        return reco

    # ---------- MFA 评估 ----------

    def assess_mfa(self) -> Dict[str, Any]:
        """MFA 覆盖率、认证方式分布、弱 MFA 与绕过风险。"""
        total = len(self.users)
        enabled = [u for u in self.users.values() if u.mfa_enabled]
        coverage = round(len(enabled) / total * 100, 1) if total else 0.0
        method_dist: Dict[str, int] = {}
        weak_mfa: List[Dict[str, Any]] = []
        bypass_risks: List[Dict[str, Any]] = []
        for u in enabled:
            method_dist[u.mfa_method or "unknown"] = method_dist.get(u.mfa_method or "unknown", 0) + 1
            info = MFA_METHOD_STRENGTH.get(u.mfa_method, {})
            if info.get("strength", 100) < 40:
                weak_mfa.append({
                    "user_id": u.user_id, "username": u.username,
                    "method": u.mfa_method,
                    "risk": info.get("risk", "high"),
                    "desc": info.get("desc", ""),
                })
        # 未启用 MFA 的特权账户 = 高风险绕过
        for u in self.users.values():
            if u.is_privileged and not u.mfa_enabled:
                bypass_risks.append({
                    "user_id": u.user_id, "username": u.username,
                    "privileged_type": u.privileged_type,
                    "issue": "特权账户未启用 MFA，凭据泄露即完全失陷",
                })
        weak_share = round(len(weak_mfa) / len(enabled) * 100, 1) if enabled else 0.0
        score = min(100, int(coverage * 0.6 + (100 - weak_share) * 0.25
                             + (100 if not bypass_risks else 20) * 0.15))
        return {
            "total_users": total,
            "mfa_enabled_count": len(enabled),
            "mfa_coverage_pct": coverage,
            "method_distribution": method_dist,
            "weak_mfa_users": weak_mfa,
            "weak_mfa_count": len(weak_mfa),
            "privileged_without_mfa": bypass_risks,
            "privileged_without_mfa_count": len(bypass_risks),
            "mfa_strength_dictionary": MFA_METHOD_STRENGTH,
            "mfa_score": score,
            "recommendations": [
                "特权账户强制启用硬件令牌或 FIDO2，禁止短信/邮件作为唯一 MFA。",
                "将短信/邮件 MFA 用户在 30 日内迁移至 TOTP 或硬件密钥。",
                "对所有未启用 MFA 的账户强制注册，阻断登录直至完成。",
            ],
        }

    # ---------- SSO 评估 ----------

    def assess_sso(self) -> Dict[str, Any]:
        """SSO 覆盖率、协议分布、会话与联邦配置安全。"""
        total = len(self.users)
        sso_users = [u for u in self.users.values() if u.sso_enabled]
        coverage = round(len(sso_users) / total * 100, 1) if total else 0.0
        proto_dist: Dict[str, int] = {}
        legacy_protocol_users: List[Dict[str, Any]] = []
        for u in sso_users:
            p = u.sso_protocol or "unknown"
            proto_dist[p] = proto_dist.get(p, 0) + 1
            info = SSO_PROTOCOL_SECURITY.get(p, {})
            if info.get("maturity", 100) < 65:
                legacy_protocol_users.append({
                    "user_id": u.user_id, "username": u.username, "protocol": p,
                    "desc": info.get("desc", ""),
                })
        # 模拟 SSO 配置问题
        config_findings = [
            {"check": "断言签名校验", "status": "pass", "severity": "info",
             "desc": "SAML 断言已配置 XML 签名校验"},
            {"check": "会话空闲超时", "status": "warn", "severity": "medium",
             "desc": "部分应用会话空闲超时 > 12 小时，建议 ≤ 30 分钟"},
            {"check": "Federated 身份租户限制", "status": "fail", "severity": "high",
             "desc": "外部租户联合身份未做租户白名单，存在 IdP 混淆风险"},
            {"check": "Token 有效期", "status": "warn", "severity": "medium",
             "desc": "OIDC Access Token 有效期 12 小时，建议 ≤ 1 小时 + Refresh Token 轮换"},
            {"check": "登出会话清理", "status": "fail", "severity": "high",
             "desc": "单点登出(LogOut)未全应用覆盖，登出后旧会话仍可访问"},
        ]
        score = min(100, int(coverage * 0.5 + 70 * 0.3 + 20 * 0.2))
        return {
            "total_users": total,
            "sso_enabled_count": len(sso_users),
            "sso_coverage_pct": coverage,
            "protocol_distribution": proto_dist,
            "legacy_protocol_users": legacy_protocol_users,
            "legacy_protocol_count": len(legacy_protocol_users),
            "config_findings": config_findings,
            "protocol_dictionary": SSO_PROTOCOL_SECURITY,
            "sso_score": score,
            "recommendations": [
                "逐步淘汰 CAS，迁移至 OIDC/SAML 2.0。",
                "配置租户白名单防止 IdP 混淆攻击。",
                "缩短 Token 有效期并启用 Refresh Token 轮换。",
                "覆盖所有应用的单点登出与会话清理。",
            ],
        }

    # ---------- 生命周期流程与权限回收 ----------

    def assess_lifecycle_ops(self) -> Dict[str, Any]:
        """入职/转岗/离职流程自动化与权限回收及时性。"""
        # 模拟流程指标
        onboarding = {"automated": True, "avg_hours": 4.5, "issues": 2}
        transfer = {"automated": False, "avg_hours": 72.0, "issues": 8}
        offboarding = {"automated": True, "avg_hours": 2.0, "issues": 1}
        delayed_revocation = [
            {"username": "user0087", "left_date": (datetime.now() - timedelta(days=12)).isoformat(),
             "still_active_days": 12, "risk": "critical"},
            {"username": "user0103", "left_date": (datetime.now() - timedelta(days=5)).isoformat(),
             "still_active_days": 5, "risk": "high"},
        ]
        avg_delay = round((onboarding["avg_hours"] + transfer["avg_hours"]
                           + offboarding["avg_hours"]) / 3, 1)
        return {
            "onboarding": onboarding,
            "transfer": transfer,
            "offboarding": offboarding,
            "offboarding_revocation_hours": offboarding["avg_hours"],
            "delayed_revocation_accounts": delayed_revocation,
            "delayed_revocation_count": len(delayed_revocation),
            "avg_process_hours": avg_delay,
            "recommendations": [
                "转岗流程接入 IAM 自动化，实现权限按角色模板即时变更。",
                "离职流程对接 HR 系统，离职当日自动回收全部访问权限。",
                "清理仍处于 active 的离职账户，建立每日孤儿账户巡检任务。",
            ],
        }

    # ---------- PAM ----------

    def assess_pam(self) -> Dict[str, Any]:
        """特权访问管理成熟度评估。"""
        privileged_users = [u for u in self.users.values() if u.is_privileged]
        # 模拟 PAM 能力覆盖
        capabilities = {
            "password_vault": {"implemented": True, "maturity": 80, "desc": "特权密码已入保险库，自动轮换"},
            "session_recording": {"implemented": True, "maturity": 65, "desc": "SSH/RDP 会话已录制，未覆盖数据库"},
            "jit_access": {"implemented": False, "maturity": 20, "desc": "长期特权常驻，未实现即时授权"},
            "just_enough": {"implemented": False, "maturity": 15, "desc": "权限范围过大，未做最小化拆分"},
            "approval_workflow": {"implemented": True, "maturity": 70, "desc": "特权提权需双人审批"},
            "privileged_audit": {"implemented": True, "maturity": 75, "desc": "特权操作日志接入 SIEM"},
        }
        avg = int(sum(c["maturity"] for c in capabilities.values()) / len(capabilities))
        type_dist: Dict[str, int] = {}
        for u in privileged_users:
            type_dist[u.privileged_type or "unknown"] = type_dist.get(u.privileged_type or "unknown", 0) + 1
        return {
            "privileged_user_count": len(privileged_users),
            "privileged_ratio_pct": round(len(privileged_users) / len(self.users) * 100, 1),
            "privileged_type_distribution": type_dist,
            "privileged_account_catalog": [
                {"user_id": u.user_id, "username": u.username,
                 "type": u.privileged_type, "department": u.department,
                 "mfa": u.mfa_enabled}
                for u in privileged_users[:20]
            ],
            "capabilities": capabilities,
            "pam_maturity_score": avg,
            "recommendations": [
                "推行 JIT（即时授权），特权默认不常驻，按需提权+自动到期。",
                "将数据库、云管理控制台会话纳入录制与审计。",
                "拆分过宽的本地管理员权限，采用 LAPS 或每设备随机密码。",
            ],
        }

    # ---------- 身份风险评分 ----------

    def score_identity_risk(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """基于行为/权限/设备/位置的身份风险评分（0-100，越高越危险）。"""
        def _score(u: IdentityUser) -> int:
            score = 0
            # 权限维度
            if u.is_privileged:
                score += 35
            if len(u.groups) >= 5:
                score += 10
            # MFA 维度
            if not u.mfa_enabled:
                score += 25
            elif u.mfa_method in ("sms", "email"):
                score += 10
            # 生命周期/休眠
            try:
                days = (datetime.now() - datetime.fromisoformat(u.last_login)).days
            except Exception:
                days = 0
            if u.status == "active" and days > 90:
                score += 15
            if u.status != "active":
                score += 5
            # 部门风险
            if u.department in ("外包",):
                score += 10
            if u.role == "admin" and not u.is_privileged:
                score += 5
            return max(0, min(100, score))

        if user_id:
            u = self.users.get(user_id)
            if not u:
                return {"error": "用户不存在"}
            u.risk_score = _score(u)
            return {
                "user_id": u.user_id, "username": u.username,
                "risk_score": u.risk_score,
                "level": self._risk_level(u.risk_score),
                "factors": self._risk_factors(u),
            }
        scored = []
        for u in self.users.values():
            s = _score(u)
            u.risk_score = s
            scored.append({"user_id": u.user_id, "username": u.username,
                           "risk_score": s, "level": self._risk_level(s),
                           "department": u.department, "privileged": u.is_privileged})
        scored.sort(key=lambda x: x["risk_score"], reverse=True)
        high = [s for s in scored if s["risk_score"] >= 60]
        critical = [s for s in scored if s["risk_score"] >= 80]
        return {
            "scored_users": scored[:50],
            "total_scored": len(scored),
            "high_risk_count": len(high),
            "critical_risk_count": len(critical),
            "avg_risk_score": round(sum(s["risk_score"] for s in scored) / len(scored), 1) if scored else 0,
        }

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 35:
            return "medium"
        return "low"

    @staticmethod
    def _risk_factors(u: IdentityUser) -> List[str]:
        factors: List[str] = []
        if u.is_privileged:
            factors.append(f"特权账户（{u.privileged_type}）")
        if not u.mfa_enabled:
            factors.append("未启用 MFA")
        elif u.mfa_method in ("sms", "email"):
            factors.append(f"MFA 方式较弱（{u.mfa_method}）")
        if len(u.groups) >= 5:
            factors.append(f"组成员关系过多（{len(u.groups)} 个组）")
        if u.department == "外包":
            factors.append("外包身份")
        if not factors:
            factors.append("无显著风险因子")
        return factors

    # ---------- 综合评估报告 ----------

    def full_assessment(self) -> Dict[str, Any]:
        """一次性跑全部身份与访问评估并生成报告。"""
        lifecycle = self.assess_lifecycle()
        mfa = self.assess_mfa()
        sso = self.assess_sso()
        ops = self.assess_lifecycle_ops()
        pam = self.assess_pam()
        risk = self.score_identity_risk()
        overall = int(round((mfa["mfa_score"] + sso["sso_score"] + pam["pam_maturity_score"]) / 3))
        report = {
            "report_title": "身份与访问安全评估报告",
            "generated_at": datetime.now().isoformat(),
            "overall_score": overall,
            "overall_level": self._risk_level(100 - overall),
            "lifecycle": lifecycle,
            "mfa": mfa,
            "sso": sso,
            "lifecycle_ops": ops,
            "pam": pam,
            "identity_risk": risk,
            "executive_summary": (
                f"共评估 {lifecycle['total_users']} 个身份；"
                f"MFA 覆盖率 {mfa['mfa_coverage_pct']}%；"
                f"SSO 覆盖率 {sso['sso_coverage_pct']}%；"
                f"特权账户 {pam['privileged_user_count']} 个；"
                f"高风险身份 {risk.get('critical_risk_count', 0)} 个。"
            ),
            "top_remediations": [
                "特权账户强制硬件 MFA 并迁移至 PAM 保险库",
                "清理休眠/离职未回收账户",
                "推行 JIT 即时授权，消除长期常驻特权",
                "淘汰弱 MFA（短信/邮件）与 legacy SSO 协议",
            ],
        }
        self.assessment_history.append({
            "assessment_time": report["generated_at"],
            "overall_score": overall,
            "total_users": lifecycle["total_users"],
        })
        return report

    def list_users(self, limit: int = 100) -> List[Dict[str, Any]]:
        return [
            {"user_id": u.user_id, "username": u.username, "display_name": u.display_name,
             "department": u.department, "status": u.status, "mfa_enabled": u.mfa_enabled,
             "sso_enabled": u.sso_enabled, "is_privileged": u.is_privileged,
             "risk_score": u.risk_score}
            for u in list(self.users.values())[:limit]
        ]

    def list_privileged(self) -> List[Dict[str, Any]]:
        return [
            {"user_id": u.user_id, "username": u.username, "type": u.privileged_type,
             "department": u.department, "mfa_enabled": u.mfa_enabled,
             "last_login": u.last_login}
            for u in self.users.values() if u.is_privileged
        ]


# ==================== 工厂函数 ====================

_ia_singleton: Optional[IdentityAccessManager] = None


def get_identity_access_manager() -> IdentityAccessManager:
    global _ia_singleton
    if _ia_singleton is None:
        _ia_singleton = IdentityAccessManager()
    return _ia_singleton
