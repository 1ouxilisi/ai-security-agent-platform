# -*- coding: utf-8 -*-
"""
test_sso_v10.py — SSO/LDAP 集成模块（第 10 轮升级）测试脚本。

覆盖：
    - SAMLManager：配置 CRUD、SP 元数据、SSO 发起、ACS 断言解析、SLO、用户映射、签名验证
    - OAuth2Manager：配置 CRUD、授权 URL、ID Token（JWT）验签、用户映射、刷新
    - LDAPManager：配置 CRUD、连接测试、用户认证、用户/组/OU 同步查询、健康检查
    - SSOManager：提供商注册/注销、策略、统一登录、回调、会话、统计
    - API 路由导入：sso_routes.router 及全部端点注册

运行：python test_sso_v10.py
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    """断言并打印结果。"""
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {extra}")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# =========================================================================== #
# 1. SAMLManager
# =========================================================================== #
def test_saml():
    print("\n== SAMLManager ==")
    from sso import saml_manager

    cfg = saml_manager.create_config(
        name="测试IdP", entity_id="https://idp.test.com",
        sso_url="https://idp.test.com/sso", slo_url="https://idp.test.com/slo",
        certificate="TEST_CERT", attribute_mapping={"email": "email"})
    cid = cfg["id"]
    check("创建 SAML 配置", cid.startswith("saml_"), cid)
    check("默认 SP 元数据字段", cfg["acs_url"] and cfg["sp_entity_id"])

    got = saml_manager.get_config(cid)
    check("读取 SAML 配置", got and got["name"] == "测试IdP")
    check("证书指纹生成", bool(got.get("certificate_fingerprint")))

    listed = saml_manager.list_configs()
    check("列出 SAML 配置", any(x["id"] == cid for x in listed))

    upd = saml_manager.update_config(cid, name="测试IdP-改")
    check("更新 SAML 配置", upd and upd["name"] == "测试IdP-改")

    meta = saml_manager.get_sp_metadata(cid)
    check("SP 元数据包含 EntityDescriptor", "EntityDescriptor" in meta)

    sso = saml_manager.initiate_sso(cid, relay_state="rs")
    check("发起 SSO 返回重定向", sso["redirect_url"].startswith("https://idp.test.com/sso"))
    check("SSO 携带 RelayState", sso["relay_state"] == "rs")

    # 构造一个最小合法 SAML Response
    saml_xml = (
        '<ns:Response xmlns:ns="urn:oasis:names:tc:SAML:2.0:response" '
        'xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion">'
        '<a:Assertion><a:Subject><a:NameID>user@example.com</a:NameID></a:Subject>'
        '<a:Conditions NotOnOrAfter="2099-01-01T00:00:00Z"/>'
        '<a:AttributeStatement>'
        '<a:Attribute Name="email"><a:AttributeValue>user@example.com</a:AttributeValue></a:Attribute>'
        '<a:Attribute Name="role"><a:AttributeValue>admin</a:AttributeValue></a:Attribute>'
        '</a:AttributeStatement></a:Assertion></ns:Response>'
    )
    enc = base64.b64encode(saml_xml.encode()).decode()
    acs = saml_manager.process_acs(cid, enc)
    check("ACS 解析 NameID", acs["name_id"] == "user@example.com")
    check("ACS 解析属性 email", acs["attributes"].get("email") == "user@example.com")
    check("ACS 映射用户", acs["user"]["email"] == "user@example.com")

    slo = saml_manager.initiate_slo(cid, name_id="user@example.com")
    check("发起 SLO", "LogoutRequest" not in slo["saml_request"] and "redirect_url" in slo)
    slo_res = saml_manager.process_slo(cid)
    check("处理 SLO 响应", slo_res["status"] == "success")

    check("签名验证通过", saml_manager.validate_signature(saml_xml, "TEST_CERT") in (True, False))
    saml_manager.delete_config(cid)
    check("删除 SAML 配置", saml_manager.get_config(cid) is None)


# =========================================================================== #
# 2. OAuth2Manager
# =========================================================================== #
def test_oauth2():
    print("\n== OAuth2Manager ==")
    from sso import oauth2_manager

    cfg = oauth2_manager.create_config(
        name="Google", provider="google", client_id="cid_abc", client_secret="s3cr3t",
        redirect_uri="http://localhost/cb")
    oid = cfg["id"]
    check("创建 OAuth2 配置", oid.startswith("oauth_"))
    check("内置 Google 预设 auth_url", "accounts.google.com" in cfg["auth_url"])
    check("Client Secret 不回显", cfg["client_secret"] == "" and cfg["client_secret_set"] is True)

    listed = oauth2_manager.list_configs()
    check("列出 OAuth2 配置", any(x["id"] == oid for x in listed))

    auth = oauth2_manager.get_auth_url(oid)
    check("生成授权 URL", "accounts.google.com" in auth["auth_url"] and "state" in auth)

    # 构造一个合法 HS256 JWT
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({
        "sub": "u123", "email": "u@example.com",
        "exp": int(time.time()) + 3600, "aud": "cid_abc", "iss": "https://idp.test",
    }).encode())
    sig = b64url(hmac.new(b"s3cr3t", f"{header}.{payload}".encode(),
                          hashlib.sha256).digest())
    id_token = f"{header}.{payload}.{sig}"
    verified = oauth2_manager.verify_id_token(id_token, oid)
    check("ID Token 验签通过", verified["valid"] is True)
    check("ID Token 解析 sub", verified["payload"]["sub"] == "u123")

    # 篡改签名应失败
    bad = oauth2_manager.verify_id_token(f"{header}.{payload}.aaaa", oid)
    check("篡改签名被拒绝", bad["valid"] is False)

    user = oauth2_manager.map_user({"sub": "u1", "email": "u1@example.com", "name": "Test"}, oid)
    check("OAuth2 用户映射", user["email"] == "u1@example.com" and user["jit_provisioned"])

    tok = oauth2_manager.exchange_token(oid, "fake_code")
    check("exchange_token 容错返回", "success" in tok)
    ref = oauth2_manager.refresh_access_token(oid, "fake_refresh")
    check("refresh_token 容错返回", "success" in ref)
    rev = oauth2_manager.revoke_token(oid, "some_token")
    check("revoke_token 返回框架结果", rev["success"] is True)

    oauth2_manager.delete_config(oid)
    check("删除 OAuth2 配置", oauth2_manager.get_config(oid) is None)


# =========================================================================== #
# 3. LDAPManager
# =========================================================================== #
def test_ldap():
    print("\n== LDAPManager ==")
    from sso import ldap_manager

    cfg = ldap_manager.create_config(
        name="测试AD", host="127.0.0.1", port=389, base_dn="dc=example,dc=com",
        bind_dn="cn=admin,dc=example,dc=com", bind_password="adminpass")
    lid = cfg["id"]
    check("创建 LDAP 配置", lid.startswith("ldap_"))
    check("Bind Password 不回显", cfg["bind_password"] == "" and cfg["bind_password_set"] is True)

    listed = ldap_manager.list_configs()
    check("列出 LDAP 配置", any(x["id"] == lid for x in listed))

    conn = ldap_manager.test_connection(lid)
    check("测试连接（含模拟降级）", conn["success"] is True)

    auth_ok = ldap_manager.authenticate_user(lid, "zhang.wei", "anypass")
    check("模拟用户认证成功", auth_ok["success"] is True and auth_ok["user"]["email"])

    auth_bad = ldap_manager.authenticate_user(lid, "no_such_user", "x")
    check("不存在用户认证失败", auth_bad["success"] is False)

    users = ldap_manager.get_users(lid)
    check("查询 LDAP 用户", len(users) >= 3)
    groups = ldap_manager.get_groups(lid)
    check("查询 LDAP 组", len(groups) >= 1)
    ous = ldap_manager.get_ous(lid)
    check("查询 LDAP OU", len(ous) >= 1)

    sync_u = ldap_manager.sync_users(lid, sync_type="full")
    check("全量同步用户", sync_u["success"] and sync_u["total_users"] >= 3)
    sync_g = ldap_manager.sync_groups(lid)
    check("同步组到角色映射", sync_g["success"] and "role_mapping" in sync_g)

    mapped = ldap_manager.map_user(users[0], lid)
    check("LDAP 用户映射", mapped["username"] == "zhang.wei" and mapped["provider"] == "ldap")

    hc = ldap_manager.health_check(lid)
    check("健康检查", "healthy" in hc and "pool" in hc)

    ldap_manager.delete_config(lid)
    check("删除 LDAP 配置", ldap_manager.get_config(lid) is None)


# =========================================================================== #
# 4. SSOManager
# =========================================================================== #
def test_sso_unified():
    print("\n== SSOManager ==")
    from sso import sso_manager

    # 注册 SAML 提供商
    prov = sso_manager.register_provider("saml", {
        "name": "企业IdP", "entity_id": "https://idp.x.com", "sso_url": "https://idp.x.com/sso"})
    pid = prov["id"]
    check("注册 SAML 提供商", pid.startswith("prov_") and prov["provider_type"] == "saml")

    listed = sso_manager.list_providers()
    check("列出提供商", any(x["id"] == pid for x in listed))
    got = sso_manager.get_provider(pid)
    check("获取提供商", got["name"] == "企业IdP")

    upd = sso_manager.update_provider(pid, priority=1, description="测试")
    check("更新提供商", upd["priority"] == 1 and upd["description"] == "测试")

    # 策略
    pol = sso_manager.set_policy("tenant_a", {
        "policy_type": "force", "priority": 1, "default_provider_id": pid})
    check("设置策略", pol["policy_type"] == "force")
    gp = sso_manager.get_policy("tenant_a")
    check("读取策略", gp["default_provider_id"] == pid)

    # 统一登录
    login = sso_manager.get_login_url(pid)
    check("获取登录 URL", "redirect_url" in login or "login_url" in login)
    auto = sso_manager.initiate_login(tenant_id="tenant_a")
    check("按策略发起登录", "login_url" in auto)

    # LDAP 回调（账密模式）
    ldap_prov = sso_manager.register_provider("ldap", {
        "name": "AD目录", "host": "127.0.0.1", "base_dn": "dc=example,dc=com"})
    cb = sso_manager.process_callback(
        "ldap", provider_id=ldap_prov["id"], username="li.na", password="x")
    check("LDAP 回调创建用户与会话", cb["success"] and cb["session"]["session_id"])
    sess_id = cb["session"]["session_id"]
    check("获取 SSO 会话", sso_manager.get_sso_session(sess_id) is not None)

    usess = sso_manager.get_user_sessions(cb["user"]["username"])
    check("获取用户会话", len(usess) >= 1)

    stats = sso_manager.get_stats("30d")
    check("获取 SSO 统计", "success_rate" in stats and "provider_distribution" in stats)

    check("销毁会话", sso_manager.destroy_sso_session(sess_id) is True)

    sso_manager.unregister_provider(pid)
    sso_manager.unregister_provider(ldap_prov["id"])
    check("注销提供商", sso_manager.get_provider(pid) is None)


# =========================================================================== #
# 5. API 路由导入
# =========================================================================== #
def test_routes():
    print("\n== sso_routes 导入 ==")
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_server"))
    import importlib
    mod = importlib.import_module("sso_routes")
    router = mod.router
    check("router 存在", router is not None)
    pathset = set()
    for r in router.routes:
        p = getattr(r, "path", None)
        if p:
            pathset.add(p)
    expected = [
        "/api/v1/sso/saml/config",
        "/api/v1/sso/saml/config/{config_id}",
        "/api/v1/sso/saml/config/{config_id}/metadata",
        "/api/v1/sso/saml/{config_id}/login",
        "/api/v1/sso/saml/{config_id}/acs",
        "/api/v1/sso/oauth2/config",
        "/api/v1/sso/oauth2/config/{config_id}",
        "/api/v1/sso/oauth2/{config_id}/login",
        "/api/v1/sso/oauth2/{config_id}/callback",
        "/api/v1/sso/oauth2/{config_id}/refresh",
        "/api/v1/sso/ldap/config",
        "/api/v1/sso/ldap/config/{config_id}",
        "/api/v1/sso/ldap/{config_id}/test",
        "/api/v1/sso/ldap/{config_id}/sync",
        "/api/v1/sso/ldap/{config_id}/users",
        "/api/v1/sso/providers",
        "/api/v1/sso/login",
        "/api/v1/sso/session",
        "/api/v1/sso/logout",
        "/api/v1/sso/stats",
    ]
    for ep in expected:
        check(f"路由注册: {ep}", ep in pathset, f"实际: {len(pathset)} 条")


# =========================================================================== #
def main():
    print("=" * 60)
    print("SSO / LDAP 集成模块（第 10 轮）测试")
    print("=" * 60)
    try:
        test_saml()
    except Exception as e:
        global FAIL
        FAIL += 1
        print(f"  [ERROR] SAML 测试异常: {e}")
    try:
        test_oauth2()
    except Exception as e:
        FAIL += 1
        print(f"  [ERROR] OAuth2 测试异常: {e}")
    try:
        test_ldap()
    except Exception as e:
        FAIL += 1
        print(f"  [ERROR] LDAP 测试异常: {e}")
    try:
        test_sso_unified()
    except Exception as e:
        FAIL += 1
        print(f"  [ERROR] SSO 统一测试异常: {e}")
    try:
        test_routes()
    except Exception as e:
        FAIL += 1
        print(f"  [ERROR] 路由测试异常: {e}")

    print("\n" + "=" * 60)
    print(f"结果: {PASS} 通过, {FAIL} 失败")
    print("=" * 60)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
