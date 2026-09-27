# -*- coding: utf-8 -*-
"""第4轮升级 - 集成验证脚本（第一阶段：模块导入 + app.py语法）"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

results = []

def check(name, func):
    try:
        func()
        results.append((name, "PASS", ""))
        print(f"[PASS] {name}")
    except Exception as e:
        results.append((name, "FAIL", str(e)))
        print(f"[FAIL] {name}: {e}")

# 1. 数据层模块
check("database.models 导入", lambda: __import__("database.models"))
check("database.db_manager 导入", lambda: __import__("database.db_manager"))
check("database.analytics 导入", lambda: __import__("database.analytics"))
check("api_server.analytics_routes 导入", lambda: __import__("api_server.analytics_routes"))

# 2. 报告模块
check("reporting.pdf_exporter 导入", lambda: __import__("reporting.pdf_exporter"))
check("reporting.word_exporter 导入", lambda: __import__("reporting.word_exporter"))
check("reporting.excel_exporter 导入", lambda: __import__("reporting.excel_exporter"))
check("reporting.template_manager 导入", lambda: __import__("reporting.template_manager"))
check("api_server.reporting_routes 导入", lambda: __import__("api_server.reporting_routes"))

# 3. 集成模块
check("integrations.siem_connector 导入", lambda: __import__("integrations.siem_connector"))
check("integrations.ticket_connector 导入", lambda: __import__("integrations.ticket_connector"))
check("integrations.notification_channels 导入", lambda: __import__("integrations.notification_channels"))
check("integrations.ldap_auth 导入", lambda: __import__("integrations.ldap_auth"))
check("integrations.vuln_db_sync 导入", lambda: __import__("integrations.vuln_db_sync"))
check("api_server.integrations_routes 导入", lambda: __import__("api_server.integrations_routes"))

# 4. 高级安全模块
check("security.vuln_lifecycle 导入", lambda: __import__("security.vuln_lifecycle"))
check("security.asset_discovery 导入", lambda: __import__("security.asset_discovery"))
check("security.compliance_audit 导入", lambda: __import__("security.compliance_audit"))
check("security.attack_path 导入", lambda: __import__("security.attack_path"))
check("api_server.security_routes 导入", lambda: __import__("api_server.security_routes"))

# 5. app.py 语法检查（不实际启动，只编译）
def check_app_syntax():
    import py_compile
    py_compile.compile(os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_server", "app.py"), doraise=True)
check("app.py 语法编译", check_app_syntax)

# 6. 路由对象可访问
def check_routers():
    from api_server.analytics_routes import router as r1
    from api_server.reporting_routes import router as r2
    from api_server.integrations_routes import router as r3
    from api_server.security_routes import router as r4
    assert r1.prefix == "/api/v1/analytics"
    assert r2.prefix == "/api/v1/reporting"
    assert r3.prefix == "/api/v1/integrations"
    assert r4.prefix == "/api/v1/security"
    assert len(r1.routes) > 0
    assert len(r2.routes) > 0
    assert len(r3.routes) > 0
    assert len(r4.routes) > 0
check("路由对象前缀和端点数量", check_routers)

# 汇总
passed = sum(1 for _, s, _ in results if s == "PASS")
failed = sum(1 for _, s, _ in results if s == "FAIL")
print(f"\n{'='*50}")
print(f"集成验证（第一阶段）: PASS={passed}  FAIL={failed}  TOTAL={len(results)}")
if failed > 0:
    print("\n失败项:")
    for name, s, err in results:
        if s == "FAIL":
            print(f"  - {name}: {err}")
sys.exit(0 if failed == 0 else 1)
