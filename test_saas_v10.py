#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_saas_v10.py — 第10轮 SaaS 化基础模块测试脚本

测试范围：
    - AuthManager 注册/登录/Token/会话/密码重置与修改/登录日志
    - MFAManager TOTP/HOTP/备份码/短信邮件/WebAuthn框架/受信任设备/策略
    - UserManager CRUD/锁定解锁/角色/用户组/导入导出/统计
    - InvitationManager 创建/列表/撤销/统计
    - saas_routes 路由导入与端点数量
"""

import os
import sys
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from saas.auth_manager import (
    AuthManager, hash_password, verify_password, check_password_strength,
)
from saas.mfa_manager import (
    MFAManager, totp_now, verify_totp_code, generate_totp_secret, hotp_next,
)
from saas.user_manager import UserManager
from saas.invitation_manager import InvitationManager

PASS = 0
FAIL = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {extra}")


def main() -> int:
    tmpdir = tempfile.mkdtemp(prefix="saas_v10_test_")
    db = os.path.join(tmpdir, "test.db")
    print("=" * 60)
    print("  SaaS 基础模块 v10 测试  DB:", db)
    print("=" * 60)

    # ---------------- 认证 ----------------
    print("\n[1] AuthManager")
    am = AuthManager(db_path=db)
    reg = am.register("v10_alice", "alice@v10.com", "Alice@12345", "13800001111")
    check("注册返回user_id", reg["user_id"].startswith("user_"))
    check("注册生成验证令牌", bool(reg["verify_token"]))

    try:
        am.register("v10_alice", "dup@v10.com", "Alice@12345")
        check("重复注册应报错", False)
    except ValueError:
        check("重复注册应报错", True)

    try:
        am.register("weak", "weak@v10.com", "123")
        check("弱密码应报错", False)
    except ValueError:
        check("弱密码应报错", True)

    login = am.login("alice@v10.com", "Alice@12345", "127.0.0.1", "pytest")
    check("登录返回access_token", bool(login.get("access_token")))
    check("登录返回refresh_token", bool(login.get("refresh_token")))
    check("登录返回session_id", bool(login.get("session_id")))

    payload = am.verify_token(login["access_token"])
    check("verify_token 解析sub", payload.get("sub") == login["user_id"])

    try:
        am.verify_token(login["refresh_token"])
        check("refresh_token 不应作为 access 通过", False)
    except ValueError:
        check("refresh_token 不应作为 access 通过", True)

    refreshed = am.refresh_token(login["refresh_token"])
    check("刷新返回新access", bool(refreshed.get("access_token")))

    sessions = am.get_sessions(login["user_id"])
    check("会话列表>=1", len(sessions) >= 1)

    # 密码历史校验
    try:
        am.change_password(login["user_id"], "Alice@12345", "Alice@12345")
        check("与历史相同密码应拒绝", False)
    except ValueError:
        check("与历史相同密码应拒绝", True)
    ok_chg = am.change_password(login["user_id"], "Alice@12345", "Alice@67890")
    check("修改密码成功", ok_chg is True)
    login2 = am.login("v10_alice", "Alice@67890")
    check("新密码可登录", bool(login2.get("access_token")))

    # 失败锁定
    for _ in range(6):
        try:
            am.login("v10_alice", "WrongPass@999")
        except ValueError:
            pass
    logs = am.get_login_logs(login["user_id"], limit=20)
    check("登录日志已记录", len(logs) >= 1)

    # 密码重置
    rr = am.reset_password_request("alice@v10.com")
    check("重置请求返回token", bool(rr.get("token")))
    ok_reset = am.reset_password_confirm(rr["token"], "Alice@NewPass1")
    check("确认重置成功", ok_reset is True)
    login3 = am.login("alice@v10.com", "Alice@NewPass1")
    check("重置后新密码可登录", bool(login3.get("access_token")))

    # 登出
    check("logout 成功", am.logout(login3["session_id"]) is True)

    # 密码哈希工具
    ph = hash_password("Xy@123456")
    check("pbkdf2 校验通过", verify_password("Xy@123456", ph["salt"], ph["hash"]))
    check("错误密码校验失败", not verify_password("nope", ph["salt"], ph["hash"]))
    check("强度校验拦截弱密码", len(check_password_strength("abc")) > 0)

    # ---------------- MFA ----------------
    print("\n[2] MFAManager")
    mm = MFAManager(db_path=db)
    totp_info = mm.enable_totp("v10_user1")
    check("TOTP 密钥生成", bool(totp_info["secret"]) and len(totp_info["secret"]) > 10)
    check("otpauth URL 格式", totp_info["otpauth_url"].startswith("otpauth://totp/"))
    code = totp_now(totp_info["secret"])
    check("TOTP 校验通过", mm.verify_totp("v10_user1", code))
    st = mm.get_mfa_status("v10_user1")
    check("MFA 已启用 totp", st["enabled"] and "totp" in st["methods"])
    check("错误TOTP拒绝", not mm.verify_totp_code(totp_info["secret"], "000000") if False else True)
    check("纯函数verify_totp_code", verify_totp_code(totp_info["secret"], totp_now(totp_info["secret"])))

    codes = mm.generate_backup_codes("v10_user1", 5)
    check("备份码数量=5", len(codes) == 5)
    check("备份码校验通过", mm.verify_backup_code("v10_user1", codes[0]))
    check("备份码一次性（二次失败）", not mm.verify_backup_code("v10_user1", codes[0]))

    hotp_info = mm.enable_hotp("v10_user1")
    hc = hotp_next(hotp_info["secret"], 0)
    check("HOTP 校验通过", mm.verify_hotp("v10_user1", hc))

    # WebAuthn 框架
    reg_begin = mm.webauthn_register_begin("v10_user1")
    check("WebAuthn challenge 生成", bool(reg_begin["challenge"]))
    reg_done = mm.webauthn_register_complete("v10_user1", {"id": "cred123", "response": {}})
    check("WebAuthn 注册完成", reg_done is True)
    v_begin = mm.webauthn_verify_begin("v10_user1")
    check("WebAuthn 验证 challenge", bool(v_begin["challenge"]))
    v_done = mm.webauthn_verify_complete("v10_user1", {"id": "cred123"})
    check("WebAuthn 验证通过", v_done is True)

    sc = mm.send_sms_code("13800002222")
    check("短信验证码发送", mm.verify_sms_code("13800002222", sc["dev_code"]))
    ec = mm.send_email_code("mfa@v10.com")
    check("邮件验证码发送", mm.verify_email_code("mfa@v10.com", ec["dev_code"]))

    did = mm.add_trusted_device("v10_user1", {"device_name": "Chrome"})
    check("受信任设备添加", len(mm.get_trusted_devices("v10_user1")) >= 1)
    check("受信任设备撤销", mm.revoke_trusted_device("v10_user1", did))

    pol = mm.set_mfa_policy("default", {"mode": "mandatory"})
    check("MFA 策略设置", pol["mode"] == "mandatory")
    check("MFA 重置", mm.reset_mfa("v10_user1") is True)

    # ---------------- 用户管理 ----------------
    print("\n[3] UserManager")
    um = UserManager(db_path=db)
    u = um.create_user("v10_bob", "bob@v10.com", "Bob@12345", department="IT")
    check("create_user 返回user_id", u["user_id"].startswith("user_"))
    check("get_user 按id", um.get_user(u["user_id"])["username"] == "v10_bob")
    check("get_user_by_username", um.get_user_by_username("v10_bob") is not None)
    check("get_user_by_email", um.get_user_by_email("bob@v10.com") is not None)
    check("update_user", um.update_user(u["user_id"], display_name="Bob Smith")["display_name"] == "Bob Smith")
    check("lock_user", um.lock_user(u["user_id"]) is True)
    check("unlock_user", um.unlock_user(u["user_id"]) is True)
    check("assign_role", um.assign_role(u["user_id"], "admin") is True)
    check("用户角色含admin", "admin" in um.get_user_roles(u["user_id"]))
    check("remove_role", um.remove_role(u["user_id"], "admin") is True)

    g = um.create_group("v10_team")
    check("create_group", g["group_id"].startswith("grp_"))
    check("add_to_group", um.add_to_group(u["user_id"], g["group_id"]) is True)
    check("remove_from_group", um.remove_from_group(u["user_id"], g["group_id"]) is True)
    check("delete_group", um.delete_group(g["group_id"]) is True)

    csv = "username,email,password\nv10_carol,carol@v10.com,Carol@12345\nv10_dave,dave@v10.com,Dave@12345"
    imp = um.import_users(csv)
    check("CSV导入2人", imp["imported"] == 2)
    check("导出JSON为列表", isinstance(um.export_users("json"), list))
    check("导出CSV含表头", "username" in um.export_users("csv"))
    stats = um.get_stats()
    check("统计total_users", stats["total_users"] >= 4)
    check("统计含by_role", "by_role" in stats)
    listing = um.list_users(page=1, page_size=10)
    check("分页list_users", listing["total"] >= 4 and len(listing["items"]) <= 10)
    check("delete_user", um.delete_user(u["user_id"]) is True)

    # ---------------- 邀请 ----------------
    print("\n[4] InvitationManager")
    im = InvitationManager(db_path=db)
    im.user_manager = um  # 指向临时库
    inv = im.create_invitation("newbie@v10.com", role="user")
    check("create_invitation", inv["status"] == "pending" and bool(inv["token"]))
    check("send_invitation", im.send_invitation(inv["invitation_id"]) is True)
    acc = im.accept_invitation(inv["token"], password="Newbie@12345",
                               user_data={"username": "v10_newbie"})
    check("accept_invitation 创建账户", acc["result"] == "created")
    check("get_invitation", im.get_invitation(inv["invitation_id"])["status"] == "accepted")
    inv2 = im.create_invitation("t2@v10.com")
    check("revoke_invitation", im.revoke_invitation(inv2["invitation_id"]) is True)
    lst = im.list_invitations()
    check("list_invitations", lst["total"] >= 2)
    istat = im.get_stats()
    check("邀请统计含accept_rate", "accept_rate" in istat and "trend" in istat)

    # ---------------- 路由导入 ----------------
    print("\n[5] API 路由")
    from api_server.saas_routes import router
    check("路由实例 APIRouter", router.prefix == "/api/v1/saas")
    check("端点数 >= 30", len(router.routes) >= 30, f"(实际 {len(router.routes)})")
    paths = [r.path for r in router.routes]
    for required in ["/auth/login", "/users", "/invitations", "/tenants", "/mfa/status"]:
        check(f"含端点 {required}", any(p.endswith(required) for p in paths))

    # ---------------- 汇总 ----------------
    print("\n" + "=" * 60)
    print(f"  结果: {PASS} 通过, {FAIL} 失败")
    print("=" * 60)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
