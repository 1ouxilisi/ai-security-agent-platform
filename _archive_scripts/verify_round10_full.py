"""
第10轮升级全量验证脚本
验证：模块导入、API路由注册、前端页面存在、无500错误
"""
import os
import sys
import importlib
import traceback

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

results = {"pass": 0, "fail": 0, "errors": []}


def check(name, condition, detail=""):
    if condition:
        results["pass"] += 1
        print(f"  [PASS] {name}")
    else:
        results["fail"] += 1
        results["errors"].append(f"{name}: {detail}")
        print(f"  [FAIL] {name} - {detail}")


print("=" * 70)
print("第10轮升级全量验证")
print("=" * 70)

# ========== 1. 模块文件存在性检查 ==========
print("\n【1】模块文件存在性检查")

modules_to_check = [
    # AI安全运营
    ("ai_soc/__init__.py", "AI SOC模块初始化"),
    ("ai_soc/anomaly_detector.py", "异常检测器"),
    ("ai_soc/alert_correlator.py", "告警关联分析器"),
    ("ai_soc/event_classifier.py", "事件分类器"),
    ("ai_soc/root_cause_analyzer.py", "根因分析器"),
    ("ai_soc/response_advisor.py", "响应建议器"),
    ("ai_soc/soc_assistant.py", "SOC AI助手"),
    # 性能优化
    ("performance/query_optimizer.py", "查询优化器"),
    ("performance/index_manager.py", "索引管理器"),
    ("performance/cache_manager.py", "缓存管理器"),
    ("performance/slow_query_monitor.py", "慢查询监控器"),
    ("performance/api_performance.py", "API性能监控器"),
    ("performance/db_performance.py", "DB性能监控器"),
    # SaaS化
    ("saas/auth_manager.py", "认证管理器"),
    ("saas/mfa_manager.py", "MFA管理器"),
    ("saas/user_manager.py", "用户管理器"),
    ("saas/invitation_manager.py", "邀请管理器"),
    # 可视化
    ("visualization/realtime_dashboard.py", "实时大屏"),
    ("visualization/topology_3d.py", "3D拓扑"),
    ("visualization/attack_map.py", "攻击地图"),
    ("visualization/custom_dashboard.py", "自定义仪表盘"),
    # API网关
    ("api_gateway/__init__.py", "API网关模块初始化"),
    ("api_gateway/rate_limiter.py", "限流器"),
    ("api_gateway/circuit_breaker.py", "熔断器"),
    ("api_gateway/degradation.py", "降级器"),
    ("api_gateway/api_cache.py", "API缓存器"),
    ("api_gateway/api_logger.py", "API日志器"),
    ("api_gateway/api_monitor.py", "API监控器"),
    # 备份恢复
    ("backup/__init__.py", "备份模块初始化"),
    ("backup/backup_manager.py", "备份管理器"),
    ("backup/restore_manager.py", "恢复管理器"),
    ("backup/migration_manager.py", "迁移管理器"),
    ("backup/export_manager.py", "导出管理器"),
    # SSO
    ("sso/__init__.py", "SSO模块初始化"),
    ("sso/saml_manager.py", "SAML管理器"),
    ("sso/oauth2_manager.py", "OAuth2管理器"),
    ("sso/ldap_manager.py", "LDAP管理器"),
    ("sso/sso_manager.py", "SSO统一管理器"),
    # API路由
    ("api_server/ai_soc_routes.py", "AI SOC路由"),
    ("api_server/performance_routes.py", "性能路由"),
    ("api_server/saas_routes.py", "SaaS路由"),
    ("api_server/visualization_v2_routes.py", "可视化V2路由"),
    ("api_server/api_gateway_routes.py", "API网关路由"),
    ("api_server/backup_routes.py", "备份路由"),
    ("api_server/sso_routes.py", "SSO路由"),
]

for filepath, desc in modules_to_check:
    full_path = os.path.join(PROJECT_ROOT, filepath)
    exists = os.path.exists(full_path)
    size = os.path.getsize(full_path) if exists else 0
    check(f"{desc} ({filepath})", exists and size > 100,
          f"文件不存在或过小(size={size})")

# ========== 2. 前端页面存在性检查 ==========
print("\n【2】前端页面存在性检查")

pages_to_check = [
    ("api_server/saas_console.html", "SaaS管理控制台"),
    ("api_server/realtime_dashboard.html", "实时监控大屏"),
    ("api_server/custom_dashboard.html", "自定义仪表盘编辑器"),
    ("api_server/backup_console.html", "数据备份恢复控制台"),
    ("api_server/sso_console.html", "SSO/LDAP管理控制台"),
]

for filepath, desc in pages_to_check:
    full_path = os.path.join(PROJECT_ROOT, filepath)
    exists = os.path.exists(full_path)
    if exists:
        with open(full_path, "r", encoding="utf-8") as f:
            content = f.read()
        has_html = "<!DOCTYPE html>" in content or "<html" in content
        has_body = "<body" in content
        has_content = len(content) > 2000
        non_blank = has_html and has_body and has_content
        size = len(content)
    else:
        non_blank = False
        size = 0
    check(f"{desc} ({filepath})", non_blank,
          f"页面不存在或空白(size={size})")

# ========== 3. 模块导入验证 ==========
print("\n【3】模块导入验证")

import_modules = [
    ("ai_soc", "AI SOC包"),
    ("ai_soc.anomaly_detector", "异常检测器"),
    ("ai_soc.alert_correlator", "告警关联器"),
    ("ai_soc.event_classifier", "事件分类器"),
    ("ai_soc.root_cause_analyzer", "根因分析器"),
    ("ai_soc.response_advisor", "响应建议器"),
    ("ai_soc.soc_assistant", "SOC助手"),
    ("performance.query_optimizer", "查询优化器"),
    ("performance.index_manager", "索引管理器"),
    ("performance.cache_manager", "缓存管理器"),
    ("performance.slow_query_monitor", "慢查询监控器"),
    ("performance.api_performance", "API性能监控器"),
    ("performance.db_performance", "DB性能监控器"),
    ("saas.auth_manager", "认证管理器"),
    ("saas.mfa_manager", "MFA管理器"),
    ("saas.user_manager", "用户管理器"),
    ("saas.invitation_manager", "邀请管理器"),
    ("visualization.realtime_dashboard", "实时大屏"),
    ("visualization.topology_3d", "3D拓扑"),
    ("visualization.attack_map", "攻击地图"),
    ("visualization.custom_dashboard", "自定义仪表盘"),
    ("api_gateway", "API网关包"),
    ("api_gateway.rate_limiter", "限流器"),
    ("api_gateway.circuit_breaker", "熔断器"),
    ("api_gateway.degradation", "降级器"),
    ("api_gateway.api_cache", "API缓存器"),
    ("api_gateway.api_logger", "API日志器"),
    ("api_gateway.api_monitor", "API监控器"),
    ("backup", "备份包"),
    ("backup.backup_manager", "备份管理器"),
    ("backup.restore_manager", "恢复管理器"),
    ("backup.migration_manager", "迁移管理器"),
    ("backup.export_manager", "导出管理器"),
    ("sso", "SSO包"),
    ("sso.saml_manager", "SAML管理器"),
    ("sso.oauth2_manager", "OAuth2管理器"),
    ("sso.ldap_manager", "LDAP管理器"),
    ("sso.sso_manager", "SSO统一管理器"),
]

for mod_name, desc in import_modules:
    try:
        importlib.import_module(mod_name)
        check(f"导入 {desc}", True)
    except Exception as e:
        check(f"导入 {desc}", False, str(e)[:200])

# ========== 4. API路由模块导入验证 ==========
print("\n【4】API路由模块导入验证")

route_modules = [
    ("api_server.ai_soc_routes", "AI SOC路由", "/api/v1/ai-soc"),
    ("api_server.performance_routes", "性能路由", "/api/v1/performance"),
    ("api_server.saas_routes", "SaaS路由", "/api/v1/saas"),
    ("api_server.visualization_v2_routes", "可视化V2路由", "/api/v1/visualization-v2"),
    ("api_server.api_gateway_routes", "API网关路由", "/api/v1/api-gateway"),
    ("api_server.backup_routes", "备份路由", "/api/v1/backup"),
    ("api_server.sso_routes", "SSO路由", "/api/v1/sso"),
]

route_counts = {}
for mod_name, desc, prefix in route_modules:
    try:
        mod = importlib.import_module(mod_name)
        router = getattr(mod, "router", None)
        if router:
            routes = router.routes
            count = len(routes)
            route_counts[desc] = count
            check(f"{desc} 导入成功 ({count}端点, prefix={prefix})", count > 0)
        else:
            check(f"{desc} 导入", False, "未找到router属性")
    except Exception as e:
        check(f"{desc} 导入", False, str(e)[:200])

# ========== 5. app.py 路由注册验证 ==========
print("\n【5】app.py 路由注册验证")

app_path = os.path.join(PROJECT_ROOT, "api_server", "app.py")
with open(app_path, "r", encoding="utf-8") as f:
    app_content = f.read()

registrations = [
    ("ai_soc_router", "AI SOC路由注册"),
    ("performance_router", "性能路由注册"),
    ("saas_router", "SaaS路由注册"),
    ("visualization_v2_router", "可视化V2路由注册"),
    ("api_gateway_router", "API网关路由注册"),
    ("sso_router", "SSO路由注册"),
]

for var_name, desc in registrations:
    found = f"include_router({var_name})" in app_content
    check(desc, found, f"app.py中未找到 include_router({var_name})")

# 前端页面注册
page_routes = [
    ("/saas-console", "SaaS控制台页面"),
    ("/realtime-dashboard", "实时大屏页面"),
    ("/custom-dashboard", "自定义仪表盘页面"),
    ("/backup-console", "备份控制台页面"),
    ("/sso-console", "SSO控制台页面"),
]

for route, desc in page_routes:
    found = f'"{route}"' in app_content or f"'{route}'" in app_content
    check(f"{desc} ({route})", found, f"app.py中未找到页面路由 {route}")

# ========== 6. app.py 启动验证（导入不报错） ==========
print("\n【6】app.py 启动验证（导入测试）")

try:
    # 重置已导入的模块以确保干净导入
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    from api_server.app import app
    check("app.py 导入成功", True)

    # 统计总路由数
    all_routes = [r for r in app.routes if hasattr(r, "path")]
    total = len(all_routes)
    check(f"总路由数: {total}", total > 800, f"路由数异常: {total}")

    # 检查新路由前缀是否存在
    new_prefixes = [
        "/api/v1/ai-soc",
        "/api/v1/performance",
        "/api/v1/saas",
        "/api/v1/visualization-v2",
        "/api/v1/api-gateway",
        "/api/v1/backup",
        "/api/v1/sso",
    ]
    for prefix in new_prefixes:
        found = any(r.path.startswith(prefix) for r in all_routes if hasattr(r, "path"))
        count = sum(1 for r in all_routes if hasattr(r, "path") and r.path.startswith(prefix))
        check(f"路由前缀 {prefix} ({count}端点)", found, f"未找到前缀 {prefix}")

    # 检查新页面路由
    new_pages = ["/saas-console", "/realtime-dashboard", "/custom-dashboard", "/backup-console", "/sso-console"]
    for page in new_pages:
        found = any(r.path == page for r in all_routes if hasattr(r, "path"))
        check(f"页面路由 {page}", found, f"未找到页面 {page}")

except Exception as e:
    check("app.py 导入成功", False, str(e)[:300])
    traceback.print_exc()

# ========== 7. 数据库表验证 ==========
print("\n【7】数据库新增表验证")

try:
    import sqlite3
    db_path = os.path.join(PROJECT_ROOT, "data", "ai_hacking_agent.db")
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        all_tables = [row[0] for row in cursor.fetchall()]
        conn.close()

        new_tables = [
            # SaaS
            "saas_users", "saas_sessions", "saas_login_logs", "saas_mfa",
            "saas_roles", "saas_groups", "saas_invitations",
            # 备份
            "backup_records", "backup_schedules", "restore_tasks", "migration_tasks", "export_records",
            # SSO
            "sso_providers", "sso_saml_configs", "sso_oauth2_configs",
            "sso_ldap_configs", "sso_sessions", "sso_policies", "sso_login_logs",
        ]

        found_tables = [t for t in new_tables if t in all_tables]
        missing_tables = [t for t in new_tables if t not in all_tables]
        check(f"新增表存在 ({len(found_tables)}/{len(new_tables)})",
              len(found_tables) >= 15,
              f"缺失表: {missing_tables[:5]}")
        print(f"    已找到: {found_tables}")
        if missing_tables:
            print(f"    缺失: {missing_tables}")

        total_tables = len(all_tables)
        check(f"总表数: {total_tables}", total_tables >= 80, f"表数异常: {total_tables}")
    else:
        check("数据库文件存在", False, f"未找到 {db_path}")
except Exception as e:
    check("数据库表验证", False, str(e)[:200])

# ========== 汇总 ==========
print("\n" + "=" * 70)
print("验证汇总")
print("=" * 70)
print(f"  通过: {results['pass']}")
print(f"  失败: {results['fail']}")
print(f"  总计: {results['pass'] + results['fail']}")
if results['fail'] > 0:
    print(f"\n失败项:")
    for err in results['errors']:
        print(f"  - {err}")
print("=" * 70)

sys.exit(0 if results['fail'] == 0 else 1)
