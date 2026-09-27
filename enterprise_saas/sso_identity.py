# -*- coding: utf-8 -*-
"""
sso_identity.py — 企业SSO与身份管理核心模块。

覆盖：
- SSO集成（SAML 2.0/OIDC/OAuth2.0/CAS/LDAP/AD/企业微信/钉钉/飞书）
- 身份提供商（IdP/SP配置/元数据/证书/签名验证/属性映射）
- MFA多因素认证（TOTP/HOTP/短信/邮件/硬件令牌/生物/备份码）
- 身份生命周期（入职→配置→使用→变更→离职→注销）
- 访问控制（单点登录/登出/会话/超时/并发限制/异地提醒）
- 身份审计（登录日志/操作日志/权限变更/异常/风险评分/合规报告）

第三方库 try-import，缺失时回退模拟。
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 第三方库 try-import
# --------------------------------------------------------------------------- #
_SAML_AVAILABLE = False
try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore
    _SAML_AVAILABLE = True
except Exception:
    OneLogin_Saml2_Auth = None  # type: ignore

_LDAP_AVAILABLE = False
try:
    import ldap3  # type: ignore
    _LDAP_AVAILABLE = True
except Exception:
    ldap3 = None  # type: ignore

_OIDC_AVAILABLE = False
try:
    from authlib.integrations.starlette_client import OAuth  # type: ignore
    _OIDC_AVAILABLE = True
except Exception:
    OAuth = None  # type: ignore


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _uid(prefix: str = "") -> str:
    return prefix + uuid.uuid4().hex[:12]


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(c for c in obj if c >= " " or c in "\n\r\t")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    return obj


# --------------------------------------------------------------------------- #
# 内存存储
# --------------------------------------------------------------------------- #
class SSOStore:
    def __init__(self) -> None:
        self.idp_configs: Dict[str, Dict[str, Any]] = {}
        self.sp_configs: Dict[str, Dict[str, Any]] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.login_logs: List[Dict[str, Any]] = []
        self.operation_logs: List[Dict[str, Any]] = []
        self.mfa_secrets: Dict[str, Dict[str, Any]] = {}
        self.identity_lifecycle: Dict[str, Dict[str, Any]] = {}
        self.risk_scores: Dict[str, float] = {}
        self.custom_apps: Dict[str, Dict[str, Any]] = {}


_store = SSOStore()


# --------------------------------------------------------------------------- #
# 1. SSO集成配置
# --------------------------------------------------------------------------- #
def configure_saml(tenant_id: str, idp_metadata_url: str,
                   entity_id: str = "",
                   attribute_mapping: Optional[Dict] = None) -> Dict[str, Any]:
    """配置SAML 2.0 SSO。"""
    cfg_id = _uid("saml_")
    config = {
        "id": cfg_id, "tenant_id": tenant_id, "protocol": "saml2",
        "idp_metadata_url": idp_metadata_url,
        "entity_id": entity_id or f"https://app.example.com/saml/{tenant_id}",
        "attribute_mapping": attribute_mapping or {
            "email": "email", "name": "displayName",
            "groups": "groups", "uid": "uid",
        },
        "certificate": "-----BEGIN CERTIFICATE-----\nMOCK_CERT_DATA\n-----END CERTIFICATE-----",
        "signature_algorithm": "sha256",
        "status": "configured",
        "saml_available": _SAML_AVAILABLE,
        "created_at": _now(),
    }
    _store.idp_configs[cfg_id] = config
    return config


def configure_oidc(tenant_id: str, client_id: str, client_secret: str,
                   issuer: str, scopes: str = "openid email profile") -> Dict:
    """配置OIDC SSO。"""
    cfg_id = _uid("oidc_")
    config = {
        "id": cfg_id, "tenant_id": tenant_id, "protocol": "oidc",
        "client_id": client_id, "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "scopes": scopes,
        "status": "configured",
        "oidc_available": _OIDC_AVAILABLE,
        "created_at": _now(),
    }
    # secret 仅存储哈希
    config["client_secret_hash"] = hashlib.sha256(
        client_secret.encode()).hexdigest()[:16]
    _store.idp_configs[cfg_id] = config
    return config


def configure_oauth2(tenant_id: str, client_id: str,
                     authorization_url: str, token_url: str,
                     user_info_url: str) -> Dict[str, Any]:
    cfg_id = _uid("oauth_")
    config = {
        "id": cfg_id, "tenant_id": tenant_id, "protocol": "oauth2",
        "client_id": client_id,
        "authorization_url": authorization_url,
        "token_url": token_url, "user_info_url": user_info_url,
        "status": "configured", "created_at": _now(),
    }
    _store.idp_configs[cfg_id] = config
    return config


def configure_ldap(tenant_id: str, server_url: str,
                   bind_dn: str, base_dn: str,
                   user_filter: str = "(uid={username})") -> Dict[str, Any]:
    cfg_id = _uid("ldap_")
    config = {
        "id": cfg_id, "tenant_id": tenant_id, "protocol": "ldap",
        "server_url": server_url, "bind_dn": bind_dn,
        "base_dn": base_dn, "user_filter": user_filter,
        "use_ssl": True, "status": "configured",
        "ldap_available": _LDAP_AVAILABLE,
        "created_at": _now(),
    }
    _store.idp_configs[cfg_id] = config
    return config


def configure_wework(tenant_id: str, corp_id: str,
                    agent_id: str) -> Dict[str, Any]:
    """企业微信SSO。"""
    cfg_id = _uid("ww_")
    config = {
        "id": cfg_id, "tenant_id": tenant_id, "protocol": "wework",
        "corp_id": corp_id, "agent_id": agent_id,
        "status": "configured", "created_at": _now(),
    }
    _store.idp_configs[cfg_id] = config
    return config


def configure_dingtalk(tenant_id: str, app_key: str,
                       app_secret: str) -> Dict[str, Any]:
    cfg_id = _uid("dt_")
    config = {
        "id": cfg_id, "tenant_id": tenant_id, "protocol": "dingtalk",
        "app_key": app_key, "status": "configured",
        "app_secret_hash": hashlib.sha256(
            app_secret.encode()).hexdigest()[:16],
        "created_at": _now(),
    }
    _store.idp_configs[cfg_id] = config
    return config


def configure_feishu(tenant_id: str, app_id: str,
                     app_secret: str) -> Dict[str, Any]:
    cfg_id = _uid("fs_")
    config = {
        "id": cfg_id, "tenant_id": tenant_id, "protocol": "feishu",
        "app_id": app_id, "status": "configured",
        "app_secret_hash": hashlib.sha256(
            app_secret.encode()).hexdigest()[:16],
        "created_at": _now(),
    }
    _store.idp_configs[cfg_id] = config
    return config


def list_sso_configs(tenant_id: str) -> List[Dict[str, Any]]:
    return [c for c in _store.idp_configs.values()
            if c["tenant_id"] == tenant_id]


# --------------------------------------------------------------------------- #
# 2. 认证流程
# --------------------------------------------------------------------------- #
def sso_login(tenant_id: str, protocol: str,
              credentials: Dict[str, Any]) -> Dict[str, Any]:
    """模拟SSO登录流程。"""
    login_id = _uid("login_")
    # 查找匹配的IdP配置
    cfg = None
    for c in _store.idp_configs.values():
        if c["tenant_id"] == tenant_id and c["protocol"] == protocol:
            cfg = c
            break

    if not cfg:
        return {"success": False, "error": f"未找到 {protocol} SSO配置"}

    # 模拟认证
    session_id = _uid("sess_")
    user_email = credentials.get("email", "user@example.com")
    session = {
        "id": session_id, "tenant_id": tenant_id,
        "user_email": user_email, "protocol": protocol,
        "idp_config_id": cfg["id"],
        "login_time": _now(),
        "expires_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                     time.localtime(time.time() + 3600)),
        "ip": credentials.get("ip", "127.0.0.1"),
        "user_agent": credentials.get("user_agent", ""),
        "mfa_verified": False, "status": "active",
    }
    _store.sessions[session_id] = session

    # 记录登录日志
    log_entry = {
        "id": _uid("llog_"), "tenant_id": tenant_id,
        "user_email": user_email, "protocol": protocol,
        "login_time": _now(), "ip": session["ip"],
        "status": "success", "risk_score": _calc_risk(session),
    }
    _store.login_logs.append(log_entry)

    return {
        "success": True, "session_id": session_id,
        "user": {"email": user_email},
        "expires_at": session["expires_at"],
        "risk_score": log_entry["risk_score"],
        "mfa_required": _needs_mfa(tenant_id, user_email),
    }


def sso_logout(session_id: str) -> Dict[str, Any]:
    session = _store.sessions.get(session_id)
    if not session:
        return {"success": False, "error": "会话不存在"}
    session["status"] = "logged_out"
    session["logout_time"] = _now()
    return {"success": True, "message": "已登出"}


def validate_session(session_id: str) -> Dict[str, Any]:
    session = _store.sessions.get(session_id)
    if not session:
        return {"valid": False, "reason": "not_found"}
    if session["status"] != "active":
        return {"valid": False, "reason": session["status"]}
    # 检查超时
    expires = session.get("expires_at", "")
    if expires and expires < _now():
        session["status"] = "expired"
        return {"valid": False, "reason": "expired"}
    return {"valid": True, "session": session}


# --------------------------------------------------------------------------- #
# 3. MFA多因素认证
# --------------------------------------------------------------------------- #
def setup_mfa(user_id: str, method: str = "totp") -> Dict[str, Any]:
    """设置MFA。"""
    valid_methods = ["totp", "hotp", "sms", "email",
                     "hardware_token", "biometric", "backup_code"]
    if method not in valid_methods:
        return {"success": False, "error": f"不支持的MFA方式: {method}"}

    secret = _uid("mfa_")
    mfa_config = {
        "user_id": user_id, "method": method,
        "secret": secret, "status": "pending_verification",
        "created_at": _now(),
        "backup_codes": [uuid.uuid4().hex[:8].upper() for _ in range(8)],
    }
    if method == "totp":
        mfa_config["otpauth_url"] = (
            f"otpauth://totp/AIHacking:{user_id}?secret={secret}&issuer=AIHacking")
    _store.mfa_secrets[user_id] = mfa_config
    return {"success": True, "method": method,
            "secret": secret, "backup_codes": mfa_config["backup_codes"],
            "otpauth_url": mfa_config.get("otpauth_url", "")}


def verify_mfa(user_id: str, code: str) -> Dict[str, Any]:
    mfa = _store.mfa_secrets.get(user_id)
    if not mfa:
        return {"success": False, "error": "未设置MFA"}
    # 模拟验证（实际应基于TOTP算法）
    expected = hashlib.sha256(
        f"{mfa['secret']}{int(time.time()) // 30}".encode()).hexdigest()[:6]
    valid = (code == expected or code in mfa.get("backup_codes", []))
    if valid:
        mfa["status"] = "active"
        mfa["verified_at"] = _now()
        # 如果是备份码，移除该码
        if code in mfa.get("backup_codes", []):
            mfa["backup_codes"].remove(code)
    return {"success": valid, "mfa_verified": valid,
            "method": mfa["method"]}


def disable_mfa(user_id: str) -> Dict[str, Any]:
    if user_id in _store.mfa_secrets:
        del _store.mfa_secrets[user_id]
        return {"success": True, "message": "MFA已禁用"}
    return {"success": False, "error": "未设置MFA"}


# --------------------------------------------------------------------------- #
# 4. 身份生命周期
# --------------------------------------------------------------------------- #
def identity_onboard(tenant_id: str, user_email: str,
                     name: str, dept: str = "") -> Dict[str, Any]:
    """新员工入职 → 自动配置身份。"""
    iid = _uid("idn_")
    identity = {
        "id": iid, "tenant_id": tenant_id, "email": user_email,
        "name": name, "department": dept,
        "lifecycle_stage": "provisioned",
        "auto_provisioned": True,
        "permissions_granted": ["scan.view", "report.view"],
        "created_at": _now(),
    }
    _store.identity_lifecycle[iid] = identity
    return identity


def identity_change(user_id: str,
                   changes: Dict[str, Any]) -> Optional[Dict]:
    """员工变更 → 更新身份。"""
    for ident in _store.identity_lifecycle.values():
        if ident.get("email") == user_id or ident["id"] == user_id:
            ident.update(changes)
            ident["lifecycle_stage"] = "modified"
            ident["modified_at"] = _now()
            return ident
    return None


def identity_offboard(user_id: str) -> Optional[Dict]:
    """员工离职 → 自动注销身份。"""
    for ident in _store.identity_lifecycle.values():
        if ident["id"] == user_id or ident.get("email") == user_id:
            ident["lifecycle_stage"] = "offboarded"
            ident["offboarded_at"] = _now()
            ident["permissions_granted"] = []
            # 终止所有会话
            for sid, sess in _store.sessions.items():
                if sess.get("user_email") == ident["email"]:
                    sess["status"] = "terminated"
            return ident
    return None


# --------------------------------------------------------------------------- #
# 5. 访问控制
# --------------------------------------------------------------------------- #
def get_active_sessions(tenant_id: str = "") -> List[Dict[str, Any]]:
    items = list(_store.sessions.values())
    if tenant_id:
        items = [s for s in items if s["tenant_id"] == tenant_id]
    return [s for s in items if s["status"] == "active"]


def enforce_session_policy(session_id: str,
                           policy: Dict[str, Any]) -> Dict[str, Any]:
    """应用会话策略。"""
    session = _store.sessions.get(session_id)
    if not session:
        return {"success": False, "error": "会话不存在"}
    max_concurrent = policy.get("max_concurrent", 1)
    timeout_min = policy.get("timeout_min", 30)
    # 检查并发
    user_sessions = [s for s in _store.sessions.values()
                     if s.get("user_email") == session["user_email"]
                     and s["status"] == "active"]
    if len(user_sessions) > max_concurrent:
        # 终止最早的会话
        oldest = sorted(user_sessions,
                        key=lambda x: x["login_time"])[0]
        oldest["status"] = "terminated_by_policy"
        oldest["terminated_reason"] = "concurrent_limit"
    session["timeout_policy_min"] = timeout_min
    return {"success": True, "applied_policy": policy}


# --------------------------------------------------------------------------- #
# 6. 身份审计
# --------------------------------------------------------------------------- #
def _calc_risk(session: Dict[str, Any]) -> float:
    """计算登录风险评分 (0-100)。"""
    score = 10.0
    ip = session.get("ip", "")
    # 异地登录
    if ip and not ip.startswith(("10.", "192.168.", "127.")):
        score += 25
    # 新设备
    ua = session.get("user_agent", "")
    if "bot" in ua.lower() or len(ua) < 20:
        score += 20
    # 时间异常（凌晨）
    hour = int(_now()[11:13])
    if hour < 6 or hour > 23:
        score += 15
    return min(score, 100.0)


def get_login_logs(tenant_id: str = "",
                   status: str = "",
                   page: int = 1,
                   page_size: int = 50) -> Dict[str, Any]:
    items = list(_store.login_logs)
    if tenant_id:
        items = [l for l in items if l["tenant_id"] == tenant_id]
    if status:
        items = [l for l in items if l["status"] == status]
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    return {"total": total, "page": page, "page_size": page_size,
            "items": items[start:end]}


def get_operation_logs(tenant_id: str = "",
                       action: str = "") -> List[Dict[str, Any]]:
    items = list(_store.operation_logs)
    if tenant_id:
        items = [l for l in items if l["tenant_id"] == tenant_id]
    if action:
        items = [l for l in items if action in l.get("action", "")]
    return items


def log_operation(tenant_id: str, user_id: str,
                  action: str, detail: str) -> Dict[str, Any]:
    entry = {
        "id": _uid("oplog_"), "tenant_id": tenant_id,
        "user_id": user_id, "action": action,
        "detail": detail, "timestamp": _now(),
    }
    _store.operation_logs.append(entry)
    return entry


def get_risk_report(tenant_id: str) -> Dict[str, Any]:
    logs = [l for l in _store.login_logs
            if l["tenant_id"] == tenant_id]
    high_risk = [l for l in logs if l.get("risk_score", 0) > 50]
    return {
        "tenant_id": tenant_id,
        "total_logins": len(logs),
        "high_risk_logins": len(high_risk),
        "avg_risk_score": round(
            sum(l.get("risk_score", 0) for l in logs) / max(len(logs), 1), 1),
        "risk_distribution": {
            "low": len([l for l in logs if l.get("risk_score", 0) < 30]),
            "medium": len([l for l in logs if 30 <= l.get("risk_score", 0) <= 60]),
            "high": len([l for l in logs if l.get("risk_score", 0) > 60]),
        },
        "recommendations": [
            "为高风险用户启用MFA",
            "限制异地登录IP范围",
            "定期审查活跃会话",
        ],
    }


def _needs_mfa(tenant_id: str, user_email: str) -> bool:
    """判断是否需要MFA。"""
    return True  # 企业版默认要求MFA


def get_store() -> SSOStore:
    return _store
