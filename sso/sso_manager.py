# -*- coding: utf-8 -*-
"""
sso_manager.py — SSO 统一管理器。

职责：
    - 统一注册 / 管理 SAML / OAuth2 / OIDC / LDAP 提供商（CRUD）。
    - SSO 策略：强制 / 可选 / 按 IP 段 / 按租户，支持优先级与默认提供商。
    - 统一登录入口：按策略选择提供商，生成登录 URL。
    - 统一回调处理：分发到对应子管理器，完成用户映射与会话创建。
    - SSO 会话：与本地会话关联，支持超时 / 续期 / 销毁。
    - SSO 统计：登录次数 / 提供商分布 / 成功率 / 失败原因。

数据库表：sso_providers, sso_sessions, sso_policies, sso_login_logs
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sso import _db
from sso.ldap_manager import ldap_manager
from sso.oauth2_manager import oauth2_manager
from sso.saml_manager import saml_manager

# 合法提供商类型
VALID_PROVIDER_TYPES = {"saml", "oauth2", "oidc", "ldap"}
# 会话默认有效期（秒）
SESSION_TTL_SECONDS = 8 * 3600


def _now_iso() -> str:
    """当前时间 ISO 字符串。"""
    return datetime.now().isoformat(timespec="seconds")


def _expiry_iso(seconds: int = SESSION_TTL_SECONDS) -> str:
    """会话过期时间 ISO 字符串。"""
    return (datetime.now() + timedelta(seconds=seconds)).isoformat(timespec="seconds")


def _time_range_to_delta(time_range: str) -> timedelta:
    """将 1d/7d/30d 等范围转为 timedelta。"""
    mapping = {"1d": 1, "7d": 7, "30d": 30, "90d": 90}
    days = mapping.get(time_range, 30)
    return timedelta(days=days)


class SSOManager:
    """SSO 统一管理器（单例）。"""

    def __init__(self) -> None:
        """初始化并建表。"""
        _db.init_tables()

    # ------------------------------------------------------------------ #
    # 提供商管理
    # ------------------------------------------------------------------ #
    def register_provider(self, provider_type: str,
                          config: Dict[str, Any]) -> Dict[str, Any]:
        """注册一个 SSO 提供商（同时在对应子管理器创建配置）。

        :param provider_type: saml / oauth2 / ldap
        :param config: 传给子管理器 create_* 的参数字典
        :return: 注册后的提供商记录
        """
        if provider_type not in VALID_PROVIDER_TYPES:
            raise ValueError(f"不支持的提供商类型: {provider_type}")
        ref_id = ""
        if provider_type == "saml":
            ref = saml_manager.create_config(**config)
            ref_id = ref["id"]
        elif provider_type in ("oauth2", "oidc"):
            ref = oauth2_manager.create_config(**config)
            ref_id = ref["id"]
        elif provider_type == "ldap":
            ref = ldap_manager.create_config(**config)
            ref_id = ref["id"]
        else:
            raise ValueError(provider_type)

        provider_id = "prov_" + uuid.uuid4().hex[:12]
        now = _now_iso()
        _db.execute(
            """INSERT INTO sso_providers
               (id, name, provider_type, ref_config_id, enabled, priority,
                tenant_id, description, created_at, updated_at)
               VALUES (?,?,?,?,1,100,?,?,?,?)""",
            (provider_id, config.get("name", provider_type), provider_type, ref_id,
             config.get("tenant_id"), config.get("description", ""), now, now),
        )
        return self.get_provider(provider_id)

    def unregister_provider(self, provider_id: str) -> bool:
        """注销并删除提供商。"""
        prov = self.get_provider(provider_id)
        if not prov:
            return False
        ref_id = prov.get("ref_config_id")
        try:
            if prov["provider_type"] == "saml" and ref_id:
                saml_manager.delete_config(ref_id)
            elif prov["provider_type"] in ("oauth2", "oidc") and ref_id:
                oauth2_manager.delete_config(ref_id)
            elif prov["provider_type"] == "ldap" and ref_id:
                ldap_manager.delete_config(ref_id)
        except Exception:
            pass
        _db.execute("DELETE FROM sso_providers WHERE id=?", (provider_id,))
        return True

    def get_provider(self, provider_id: str) -> Optional[Dict[str, Any]]:
        """按 ID 获取提供商。"""
        return _db.query_one("SELECT * FROM sso_providers WHERE id=?", (provider_id,))

    def list_providers(self, provider_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出提供商，可按类型过滤。"""
        if provider_type:
            return _db.query_all(
                "SELECT * FROM sso_providers WHERE provider_type=? ORDER BY priority, created_at DESC",
                (provider_type,))
        return _db.query_all("SELECT * FROM sso_providers ORDER BY priority, created_at DESC")

    def update_provider(self, provider_id: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
        """更新提供商（名称/启用状态/优先级/租户/描述）。"""
        allowed = {"name", "enabled", "priority", "tenant_id", "description"}
        sets, params = [], []
        for k, v in kwargs.items():
            if k not in allowed:
                continue
            if k == "enabled":
                v = int(bool(v))
            sets.append(f"{k}=?")
            params.append(v)
        if not sets:
            return self.get_provider(provider_id)
        sets.append("updated_at=?")
        params.append(_now_iso())
        params.append(provider_id)
        _db.execute(f"UPDATE sso_providers SET {','.join(sets)} WHERE id=?", tuple(params))
        return self.get_provider(provider_id)

    # ------------------------------------------------------------------ #
    # SSO 策略
    # ------------------------------------------------------------------ #
    def set_policy(self, tenant_id: Optional[str] = None,
                   policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """设置 SSO 策略。

        :param tenant_id: 租户 ID，None 表示全局默认策略
        :param policy: {policy_type, priority, default_provider_id, ip_ranges, config}
        """
        policy = policy or {}
        tenant_id = tenant_id or "global"
        existing = _db.query_one("SELECT id FROM sso_policies WHERE tenant_id=?", (tenant_id,))
        now = _now_iso()
        policy_id = existing["id"] if existing else "pol_" + uuid.uuid4().hex[:12]
        if existing:
            _db.execute(
                """UPDATE sso_policies SET policy_type=?, priority=?,
                   default_provider_id=?, ip_ranges=?, config=?, updated_at=? WHERE id=?""",
                (policy.get("policy_type", "optional"), policy.get("priority", 100),
                 policy.get("default_provider_id"),
                 _db.dumps_json(policy.get("ip_ranges", [])),
                 _db.dumps_json(policy.get("config", {})), now, policy_id),
            )
        else:
            _db.execute(
                """INSERT INTO sso_policies
                   (id, tenant_id, policy_type, priority, default_provider_id,
                    ip_ranges, config, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (policy_id, tenant_id, policy.get("policy_type", "optional"),
                 policy.get("priority", 100), policy.get("default_provider_id"),
                 _db.dumps_json(policy.get("ip_ranges", [])),
                 _db.dumps_json(policy.get("config", {})), now, now),
            )
        return self.get_policy(tenant_id)

    def get_policy(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """获取 SSO 策略（无租户时返回全局默认）。"""
        tenant_id = tenant_id or "global"
        row = _db.query_one("SELECT * FROM sso_policies WHERE tenant_id=?", (tenant_id,))
        if not row:
            return {"tenant_id": tenant_id, "policy_type": "optional",
                    "priority": 100, "default_provider_id": None,
                    "ip_ranges": [], "config": {}}
        row["ip_ranges"] = _db.loads_json(row.get("ip_ranges"), [])
        row["config"] = _db.loads_json(row.get("config"), {})
        return row

    # ------------------------------------------------------------------ #
    # 统一登录入口
    # ------------------------------------------------------------------ #
    def get_login_url(self, provider_id: str,
                      redirect_url: Optional[str] = None) -> Dict[str, Any]:
        """获取指定提供商的登录 URL。"""
        prov = self.get_provider(provider_id)
        if not prov:
            raise ValueError(f"提供商不存在: {provider_id}")
        ref = prov["ref_config_id"]
        if prov["provider_type"] == "saml":
            result = saml_manager.initiate_sso(ref, relay_state=redirect_url)
            return {"login_url": result["redirect_url"], "provider_type": "saml",
                    "relay_state": result.get("relay_state")}
        if prov["provider_type"] in ("oauth2", "oidc"):
            result = oauth2_manager.get_auth_url(ref)
            return {"login_url": result["auth_url"], "provider_type": "oauth2",
                    "state": result["state"]}
        if prov["provider_type"] == "ldap":
            return {"login_url": "", "provider_type": "ldap",
                    "note": "LDAP 为直接账密认证，无重定向 URL，请调用认证接口"}
        raise ValueError(f"未知提供商类型: {prov['provider_type']}")

    def initiate_login(self, provider_id: Optional[str] = None,
                       **kwargs: Any) -> Dict[str, Any]:
        """统一登录入口：未指定提供商时按策略选择默认提供商。"""
        if provider_id:
            return self.get_login_url(provider_id, kwargs.get("redirect_url"))
        policy = self.get_policy(kwargs.get("tenant_id"))
        default_id = policy.get("default_provider_id")
        if default_id and self.get_provider(default_id):
            return self.get_login_url(default_id, kwargs.get("redirect_url"))
        providers = self.list_providers()
        enabled = [p for p in providers if p.get("enabled", 1)]
        if not enabled:
            return {"login_url": "", "provider_type": None,
                    "note": "尚无可用 SSO 提供商，请先注册"}
        return self.get_login_url(enabled[0]["id"], kwargs.get("redirect_url"))

    # ------------------------------------------------------------------ #
    # 统一回调
    # ------------------------------------------------------------------ #
    def process_callback(self, provider_type: str, **kwargs: Any) -> Dict[str, Any]:
        """统一回调处理：分发到对应子管理器，映射用户并创建会话。"""
        provider_id = kwargs.get("provider_id")
        prov = self.get_provider(provider_id) if provider_id else None
        ref = prov["ref_config_id"] if prov else kwargs.get("config_id")
        if not ref:
            raise ValueError("回调缺少 provider_id / config_id")

        user: Dict[str, Any] = {}
        if provider_type == "saml":
            result = saml_manager.process_acs(ref, kwargs.get("saml_response", ""))
            user = result["user"]
        elif provider_type in ("oauth2", "oidc"):
            code = kwargs.get("code", "")
            token_res = oauth2_manager.exchange_token(ref, code, kwargs.get("redirect_uri"))
            access_token = ""
            if token_res.get("success"):
                access_token = token_res["token"].get("access_token", "")
                id_token = token_res["token"].get("id_token")
                if id_token:
                    oauth2_manager.verify_id_token(id_token, ref)
            ui = oauth2_manager.get_user_info(ref, access_token) if access_token else {}
            user_info = ui.get("user_info", {}) if ui.get("success") else {}
            user = oauth2_manager.map_user(user_info, ref)
        elif provider_type == "ldap":
            auth = ldap_manager.authenticate_user(
                ref, kwargs.get("username", ""), kwargs.get("password", ""))
            if not auth.get("success"):
                self._log_login(None, None, provider_id, provider_type,
                                "failure", auth.get("error", "ldap_auth_failed"),
                                kwargs.get("ip"))
                return {"success": False, "error": auth.get("error")}
            user = auth.get("user") or {"username": kwargs.get("username", "")}
        else:
            raise ValueError(f"未知回调类型: {provider_type}")

        # 创建 SSO 会话
        session = self.create_sso_session(
            user_id=user.get("username", ""),
            provider_id=provider_id or ref,
            provider_type=provider_type,
        )
        self._log_login(user.get("username"), user.get("email"), provider_id,
                        provider_type, "success", None, kwargs.get("ip"))
        return {"success": True, "user": user, "session": session}

    # ------------------------------------------------------------------ #
    # SSO 会话
    # ------------------------------------------------------------------ #
    def create_sso_session(self, user_id: str, provider_id: str,
                          provider_type: str) -> Dict[str, Any]:
        """创建 SSO 会话并与本地用户关联。"""
        session_id = "sso_sess_" + uuid.uuid4().hex[:16]
        now = _now_iso()
        _db.execute(
            """INSERT INTO sso_sessions
               (id, session_id, user_id, username, provider_id, provider_type,
                ip, status, created_at, expires_at, last_active)
               VALUES (?,?,?,?,?,?,?,'active',?,?,?)""",
            ("sso_sess_" + uuid.uuid4().hex[:12], session_id, user_id, user_id,
             provider_id, provider_type, None, now, _expiry_iso(), now),
        )
        return {"session_id": session_id, "user_id": user_id,
                "provider_id": provider_id, "provider_type": provider_type,
                "expires_at": _expiry_iso()}

    def get_sso_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取 SSO 会话（校验是否过期）。"""
        row = _db.query_one(
            "SELECT * FROM sso_sessions WHERE session_id=? AND status='active'",
            (session_id,))
        if not row:
            return None
        # 过期检查
        try:
            exp = datetime.fromisoformat(row["expires_at"])
            if datetime.now() > exp:
                _db.execute("UPDATE sso_sessions SET status='expired' WHERE session_id=?",
                            (session_id,))
                return None
        except Exception:
            pass
        # 续期：更新 last_active
        _db.execute("UPDATE sso_sessions SET last_active=? WHERE session_id=?",
                    (_now_iso(), session_id))
        return row

    def destroy_sso_session(self, session_id: str) -> bool:
        """销毁（登出）SSO 会话。"""
        cur = _db.execute(
            "UPDATE sso_sessions SET status='logged_out' WHERE session_id=?",
            (session_id,))
        return cur is not None

    def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """获取某用户的全部活跃会话。"""
        return _db.query_all(
            "SELECT * FROM sso_sessions WHERE user_id=? AND status='active' ORDER BY created_at DESC",
            (user_id,))

    # ------------------------------------------------------------------ #
    # 登录日志
    # ------------------------------------------------------------------ #
    def _log_login(self, username: Optional[str], email: Optional[str],
                   provider_id: Optional[str], provider_type: str,
                   result: str, failure_reason: Optional[str],
                   ip: Optional[str]) -> None:
        """记录一次登录事件。"""
        try:
            _db.execute(
                """INSERT INTO sso_login_logs
                   (id, user_id, username, provider_id, provider_type, result,
                    failure_reason, ip, user_agent, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                ("log_" + uuid.uuid4().hex[:12], username, username, provider_id,
                 provider_type, result, failure_reason, ip, None, _now_iso()),
            )
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # 统计
    # ------------------------------------------------------------------ #
    def get_stats(self, time_range: str = "30d") -> Dict[str, Any]:
        """获取 SSO 统计：登录次数/成功率/提供商分布/失败原因。"""
        since = (datetime.now() - _time_range_to_delta(time_range)).isoformat(timespec="seconds")
        rows = _db.query_all(
            "SELECT * FROM sso_login_logs WHERE created_at >= ?", (since,))
        total = len(rows)
        success = sum(1 for r in rows if r["result"] == "success")
        failure = total - success
        # 提供商分布
        dist: Dict[str, int] = {}
        reason_dist: Dict[str, int] = {}
        for r in rows:
            pt = r.get("provider_type") or "unknown"
            dist[pt] = dist.get(pt, 0) + 1
            if r["result"] != "success" and r.get("failure_reason"):
                reason_dist[r["failure_reason"]] = reason_dist.get(r["failure_reason"], 0) + 1
        # 每日趋势
        trend: Dict[str, int] = {}
        for r in rows:
            day = (r.get("created_at") or "")[:10]
            trend[day] = trend.get(day, 0) + 1
        active_sessions = _db.query_one(
            "SELECT COUNT(*) AS c FROM sso_sessions WHERE status='active'")
        return {
            "time_range": time_range,
            "total_logins": total,
            "success": success,
            "failure": failure,
            "success_rate": round(success / total * 100, 2) if total else 0.0,
            "provider_distribution": dist,
            "failure_reasons": reason_dist,
            "daily_trend": dict(sorted(trend.items())),
            "active_sessions": active_sessions["c"] if active_sessions else 0,
            "total_providers": len(self.list_providers()),
        }


# --------------------------------------------------------------------------- #
# 模块级单例
# --------------------------------------------------------------------------- #
sso_manager = SSOManager()

__all__ = ["SSOManager", "sso_manager"]
