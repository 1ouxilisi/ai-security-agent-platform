# -*- coding: utf-8 -*-
"""商业化核心模块自检脚本。

验证：
1. 所有模块可导入
2. 租户创建 + 目录隔离
3. 配额检查 + 配置读写
4. 订阅 + 订单 + 模拟支付 + 用量 + 超额
5. API Key 创建 + 验证 + 限流 + 429
6. AES 加密/解密往返 + 脱敏
7. 用户登录 + 权限检查 + 并发会话限制
"""
import os
import sys
import time
import shutil
import tempfile

# 确保项目根目录在 sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name} {detail}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def main():
    print("=" * 60)
    print("商业化核心模块自检")
    print("=" * 60)

    # 用临时目录避免污染真实数据
    tmp = tempfile.mkdtemp(prefix="comm_test_")
    tenants_dir = os.path.join(tmp, "tenants")
    base_dir = tmp
    print(f"\n[0] 使用临时数据目录: {tmp}")

    # ---------- 1. 模块导入 ----------
    print("\n[1] 模块导入检查")
    try:
        from commercial.multi_tenant import TenantManager
        from commercial.billing import BillingEngine, PLANS
        from commercial.api_gateway import APIGateway, TokenBucket
        from commercial.data_security import DataSecurity
        from utils.multi_user import UserManager, DEFAULT_ROLES
        check("commercial 全部模块导入", True)
        check("角色含 tenant_admin/read_only",
              "tenant_admin" in DEFAULT_ROLES and "read_only" in DEFAULT_ROLES)
    except Exception as e:
        check("commercial 全部模块导入", False, str(e))
        print("导入失败，终止。")
        shutil.rmtree(tmp, ignore_errors=True)
        return

    # ---------- 2. 租户创建 + 隔离 ----------
    print("\n[2] 多租户创建与隔离")
    tm = TenantManager(tenants_dir)
    t1 = tm.create_tenant("acme", "Acme 公司", "PRO")
    t2 = tm.create_tenant("beta", "Beta 团队", "FREE")
    check("创建 2 个租户", t1 and t2)
    p1 = tm.get_tenant_path("acme")
    p2 = tm.get_tenant_path("beta")
    check("租户根目录存在", os.path.isdir(p1) and os.path.isdir(p2))
    check("子目录 assessments/reports/logs/uploads 齐全",
          all(os.path.isdir(os.path.join(p1, s))
              for s in ("assessments", "reports", "logs", "uploads")))
    check("目录相互隔离", os.path.abspath(p1) != os.path.abspath(p2))
    check("列出 2 个租户", len(tm.list_tenants()) == 2)
    check("get_tenant 返回正确", tm.get_tenant("acme")["name"] == "Acme 公司")

    # 配额检查
    ok, rem, lim = tm.check_quota("acme", "scan_count")
    check("初始配额检查 allowed=True", ok)
    check("PRO scan_count=100", lim == 100, f"(limit={lim})")
    used = tm.record_usage("acme", "scan_count", 5)
    check("记录用量后 used=5", used == 5, f"(used={used})")
    ok2, rem2, lim2 = tm.check_quota("acme", "scan_count")
    check("记录后 remaining=95", rem2 == 95, f"(remaining={rem2})")

    # 配置读写
    tm.set_config("acme", "brand_name", "Acme 安全云")
    tm.set_config("acme", "notifications.email", "ops@acme.com")
    check("get_config brand_name",
          tm.get_config("acme", "brand_name") == "Acme 安全云")
    check("get_config 嵌套 notifications.email",
          tm.get_config("acme", "notifications.email") == "ops@acme.com")

    # 禁用/启用
    check("disable_tenant", tm.disable_tenant("beta") is True)
    okb, _, _ = tm.check_quota("beta", "scan_count")
    check("禁用后配额检查返回 False", okb is False)
    check("enable_tenant", tm.enable_tenant("beta") is True)

    # ---------- 3. 计费 + 订单 + 模拟支付 ----------
    print("\n[3] 计费与订阅")
    billing = BillingEngine(tenants_dir, tm)
    sub = billing.subscribe("acme", "PRO", "monthly")
    check("订阅 PRO", sub["plan"] == "PRO" and sub["status"] == "active")
    check("PRO 月价 999", PLANS["PRO"]["price_monthly"] == 999)

    order = billing.create_order("acme", "PRO", "monthly")
    check("创建订单返回 order_id", order["order_id"].startswith("ORD"))
    check("订单金额 999", order["amount"] == 999)
    check("订单含支付链接", bool(order["payment_url"]))

    pay = billing.pay_order(order["order_id"], "simulated")
    check("模拟支付成功", pay["status"] == "paid")
    check("订阅已激活", billing.get_subscription("acme")["status"] == "active")

    # 记录用量 + 超额
    billing.record_usage("acme", "scan", 200)  # 超过 PRO 100 上限
    usage = billing.get_usage("acme", period="month")
    check("用量统计扫描=200", usage["by_resource"].get("scan") == 200)
    over = billing.check_overage("acme")
    check("检测到超额项", len(over) > 0, f"(overages={over})")
    alert = billing.send_overage_alert("acme")
    check("超额告警已触发", alert["alerted"] is True)

    # 发票
    inv_path = billing.generate_invoice(order["order_id"])
    check("发票文件已生成", os.path.exists(inv_path), f"({inv_path})")

    # ---------- 4. API Key + 限流 ----------
    print("\n[4] API 网关")
    gw = APIGateway(tenants_dir, tm)
    plain, kid = gw.create_api_key("acme", "admin", "生产Key")
    check("创建 Key 返回 sk_ 前缀", plain.startswith("sk_"), f"({plain[:8]}...)")
    check("Key 有 key_id", bool(kid))

    v = gw.validate_api_key(plain)
    check("验证有效 Key 返回元组", v is not None and v[0] == "acme")
    check("验证伪造 Key 返回 None", gw.validate_api_key("sk_fake") is None)
    check("吊销后验证失败", (gw.revoke_api_key(kid), gw.validate_api_key(plain))[1] is None)

    # 重新创建一个用于限流测试
    plain2, kid2 = gw.create_api_key("acme", "alice", "限流测试")
    # 令牌桶：capacity=3, rate=1/s，前3次通过，第4次在短期内应被用户级限流
    bucket = TokenBucket(capacity=3, rate=1.0)
    results = [bucket.consume() for _ in range(5)]
    check("令牌桶前3次放行", results[:3] == [True, True, True])
    check("令牌桶第4次拒绝", results[3] is False)

    # 三级限流：连续快速调用超过用户级 30/min 容量触发
    allowed_count = 0
    for i in range(40):
        ok, reason = gw.check_rate_limit("acme", "alice", "/api/v1/scan")
        if ok:
            allowed_count += 1
    check("连续40次调用触发限流", allowed_count < 40, f"(allowed={allowed_count})")

    # 调用计量
    gw.record_call("acme", "alice", kid2, "/api/v1/scan", "POST", 200, 12.5)
    stats = gw.get_call_stats("acme")
    check("调用统计 total>=1", stats["total"] >= 1, f"(total={stats['total']})")
    check("调用日志 jsonl 存在", os.path.exists(gw.calls_file))

    # 429 信息
    okq, remq, limq = gw.check_quota("acme")
    check("配额检查返回三元组", isinstance(okq, bool) and isinstance(remq, int))

    # ---------- 5. 数据安全 ----------
    print("\n[5] 数据安全")
    sec = DataSecurity(base_dir, tm)
    ct = sec.encrypt("这是一段敏感数据 hello")
    pt = sec.decrypt(ct)
    check("AES 加密->解密往返", pt == "这是一段敏感数据 hello", f"({pt})")
    check("密文非明文", ct != "这是一段敏感数据 hello")

    h = sec.hash_password("S3cret!")
    check("密码哈希验证正确", sec.verify_password("S3cret!", h) is True)
    check("错误密码验证失败", sec.verify_password("wrong", h) is False)

    check("mask_ip", sec.mask_ip("192.168.1.100") == "192.168.1.***")
    check("mask_domain", sec.mask_domain("example.com") == "ex***.com")
    masked = sec.mask_data({"password": "abcdef123456", "ip": "10.0.0.5",
                            "name": "正常字段", "nested": {"token": "tok_xyzabc"}})
    check("递归脱敏 password", "****" in masked["password"])
    check("递归脱敏 ip", masked["ip"].endswith("***"))
    check("递归脱敏嵌套 token", "tok_xyzabc" not in masked["nested"]["token"])

    # 保留策略
    sec.set_retention_policy("acme", "assessments", 30)
    check("保留策略已设置", sec.get_retention_policy("acme").get("assessments") == 30)

    # 审计日志
    sec.log_access("acme", "admin", "data:export", "file", {"x": 1})
    logs = sec.get_audit_logs("acme")
    check("审计日志可查询", len(logs) >= 1)

    # 导出
    exp_path = sec.export_tenant_data("acme")
    check("导出文件存在", os.path.exists(exp_path))

    # ---------- 6. 用户登录 + 权限 + 并发 ----------
    print("\n[6] 用户/RBAC")
    um = UserManager(os.path.join(tmp, "umdata"))
    um.create_user("analyst1", "pass123", tenant_id="acme", role="security_analyst")
    um.create_user("viewer1", "pass123", tenant_id="acme", role="read_only")
    um.create_user("admin_acme", "pass123", tenant_id="acme", role="tenant_admin")
    check("创建租户用户", um.get_user("analyst1") is not None)
    check("list_users(tenant) 过滤",
          len(um.list_users("acme")) == 3)
    check("get_user_by_tenant", um.get_user_by_tenant("analyst1", "acme") is not None)
    check("跨租户查询返回 None",
          um.get_user_by_tenant("analyst1", "other") is None)

    tok = um.login("analyst1", "pass123", ip="1.2.3.4")
    check("登录返回 session_token", bool(tok))
    u = um.validate_session(tok)
    check("validate_session 返回用户", u is not None and u.username == "analyst1")
    check("has_permission scan:create", um.has_permission("analyst1", "scan:create", "acme"))
    check("read_only 无 scan:create",
          not um.has_permission("viewer1", "scan:create", "acme"))
    check("tenant_admin 有 tenant:users",
          um.has_permission("admin_acme", "tenant:users", "acme"))
    check("跨租户权限拒绝",
          not um.has_permission("analyst1", "scan:create", "beta"))

    # 并发会话限制：连续登录 5 次，活跃会话应 <= MAX_CONCURRENT_SESSIONS(3)
    toks = [um.login("viewer1", "pass123") for _ in range(5)]
    active = [t for t in toks if um.validate_session(t) is not None]
    check("并发会话<=3 (踢出旧会话)",
          len(active) <= um.MAX_CONCURRENT_SESSIONS,
          f"(active={len(active)}, max={um.MAX_CONCURRENT_SESSIONS})")

    # 登出
    um.logout(tok)
    check("登出后会话失效", um.validate_session(tok) is None)

    # 审计
    um.log_audit("admin_acme", "user:create", "analyst1", {"by": "test"})
    check("用户审计日志已记录", len(um.get_audit_logs()) > 0)

    # ---------- 清理 ----------
    print("\n[7] 清理临时目录")
    shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 60)
    print(f"自检完成: PASS={PASS}  FAIL={FAIL}")
    print("=" * 60)
    return FAIL == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
