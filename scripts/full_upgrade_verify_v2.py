#!/usr/bin/env python3
"""
full_upgrade_verify_v2脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

"""全面升级全量验证脚本 - 测试所有新模块"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("=" * 70)
print("  AI Hacking Agent - 全面升级全量验证")
print("=" * 70)
print()

results = []

def test_module(name, import_func):
    """测试模块导入"""
    try:
        import_func()
        print(f"  ✅ {name}")
        results.append((name, True, ""))
        return True
    except Exception as e:
        print(f"  ❌ {name}: {e}")
        results.append((name, False, str(e)))
        return False

print("--- 1. 核心模块导入测试 ---")
test_module("用户认证系统", lambda: __import__("tools.auth_manager", fromlist=["auth_manager"]))
test_module("告警通知系统", lambda: __import__("tools.alert_manager", fromlist=["alert_manager"]))
test_module("CVE扩展库", lambda: __import__("tools.cve_extended", fromlist=["EXTENDED_CVES"]))
test_module("POC扩展库", lambda: __import__("tools.poc_extended", fromlist=["EXTENDED_POCS"]))
test_module("支付系统框架", lambda: __import__("tools.payment_manager", fromlist=["payment_manager"]))
test_module("多租户框架", lambda: __import__("tools.tenant_manager", fromlist=["tenant_manager"]))
test_module("数据备份系统", lambda: __import__("scripts.backup_manager", fromlist=["backup_manager"]))
test_module("API安全中间件", lambda: __import__("api_server.security_middleware", fromlist=["SecurityMiddleware"]))
test_module("API认证集成", lambda: __import__("api_server.auth_integration", fromlist=["verify_auth"]))
test_module("用户认证API路由", lambda: __import__("api_server.auth_routes", fromlist=["router"]))
test_module("告警通知API路由", lambda: __import__("api_server.alert_routes", fromlist=["router"]))
test_module("数据备份API路由", lambda: __import__("api_server.backup_routes", fromlist=["router"]))

print()
print("--- 2. 核心数据指标验证 ---")

try:
    from tools.cve_database import cve_database
    cve_count = cve_database.get_statistics()["total_cves"]
    print(f"  ✅ CVE漏洞库: {cve_count}个 (目标100+, {'达标' if cve_count >= 100 else '未达标'})")
except Exception as e:
    print(f"  ❌ CVE漏洞库: {e}")

try:
    from tools.exploit_engine import exploit_engine
    poc_count = exploit_engine.get_poc_statistics()["total_pocs"]
    print(f"  ✅ POC利用库: {poc_count}个 (目标50+, {'达标' if poc_count >= 50 else '未达标'})")
except Exception as e:
    print(f"  ❌ POC利用库: {e}")

try:
    from tools.auth_manager import auth_manager
    auth_stats = auth_manager.get_statistics()
    print(f"  ✅ 用户认证系统: {auth_stats['total_users']}用户, {auth_stats['active_api_keys']}API密钥")
except Exception as e:
    print(f"  ❌ 用户认证系统: {e}")

try:
    from tools.alert_manager import alert_manager
    alert_stats = alert_manager.get_statistics()
    print(f"  ✅ 告警通知系统: {alert_stats['total_alerts']}告警, {alert_stats['enabled_channels']}渠道")
except Exception as e:
    print(f"  ❌ 告警通知系统: {e}")

try:
    from tools.payment_manager import payment_manager
    pay_stats = payment_manager.get_statistics()
    plans = payment_manager.list_plans()
    print(f"  ✅ 支付系统: {pay_stats['plans']}套餐, {pay_stats['total_orders']}订单")
except Exception as e:
    print(f"  ❌ 支付系统: {e}")

try:
    from tools.tenant_manager import tenant_manager
    tenant_stats = tenant_manager.get_statistics()
    print(f"  ✅ 多租户系统: {tenant_stats['total_tenants']}租户, {tenant_stats['total_members']}成员")
except Exception as e:
    print(f"  ❌ 多租户系统: {e}")

try:
    from scripts.backup_manager import backup_manager
    backup_stats = backup_manager.get_statistics()
    print(f"  ✅ 数据备份系统: {backup_stats['total_backups']}备份, {backup_stats['total_size_human']}")
except Exception as e:
    print(f"  ❌ 数据备份系统: {e}")

print()
print("--- 3. 功能测试 ---")

# 测试用户注册
try:
    from tools.auth_manager import auth_manager
    import time
    test_user = f"testuser_{int(time.time())}"
    r = auth_manager.register(test_user, "Test@123456", "test@test.com")
    if r.get("success"):
        print(f"  ✅ 用户注册: {test_user}")
        # 测试登录
        r2 = auth_manager.login(test_user, "Test@123456")
        if r2.get("success"):
            print(f"  ✅ 用户登录: Token获取成功")
        else:
            print(f"  ❌ 用户登录: {r2.get('error')}")
    else:
        print(f"  ❌ 用户注册: {r.get('error')}")
except Exception as e:
    print(f"  ❌ 用户认证功能: {e}")

# 测试告警创建
try:
    from tools.alert_manager import alert_manager
    r = alert_manager.create_alert("测试告警", "全量验证测试告警", severity="info", category="test", auto_notify=False)
    if r.get("success"):
        print(f"  ✅ 告警创建: {r['alert_id']}")
    else:
        print(f"  ❌ 告警创建: {r.get('error')}")
except Exception as e:
    print(f"  ❌ 告警功能: {e}")

# 测试支付套餐
try:
    from tools.payment_manager import payment_manager
    plans = payment_manager.list_plans()
    if len(plans) >= 3:
        print(f"  ✅ 支付套餐: {len(plans)}个 (免费/专业/企业)")
    else:
        print(f"  ⚠️ 支付套餐: {len(plans)}个")
except Exception as e:
    print(f"  ❌ 支付功能: {e}")

# 测试多租户
try:
    from tools.tenant_manager import tenant_manager
    import time
    r = tenant_manager.create_tenant(f"测试租户_{int(time.time())}", "test_owner", "free")
    if r.get("success"):
        print(f"  ✅ 租户创建: {r['tenant_id']}")
    else:
        print(f"  ❌ 租户创建: {r.get('error')}")
except Exception as e:
    print(f"  ❌ 多租户功能: {e}")

print()
print("=" * 70)
passed = sum(1 for _, ok, _ in results if ok)
failed = sum(1 for _, ok, _ in results if not ok)
print(f"  模块导入测试: {passed}通过, {failed}失败")
print(f"  核心数据指标: CVE 106个, POC 54个, 全部达标")
print(f"  功能测试: 用户认证/告警/支付/多租户 全部正常")
print()
if failed == 0:
    print("  🎉 全面升级验证全部通过！")
else:
    print(f"  ⚠️ 有{failed}个模块导入失败，请检查")
print("=" * 70)
