"""
第9轮升级全面验证脚本 —— 模块导入/语法/表结构/路由统计。
用法：python verify_round9_imports.py
"""
import sys
import os
import importlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_module_import(name, desc):
    """验证模块可导入"""
    try:
        mod = importlib.import_module(name)
        return True, mod
    except Exception as e:
        return False, str(e)

def check_route_import(name, desc):
    """验证路由文件可导入并统计端点"""
    try:
        mod = importlib.import_module(name)
        router = getattr(mod, "router", None)
        if router is None:
            return False, 0, "router对象未找到"
        count = len(router.routes)
        return True, count, "OK"
    except Exception as e:
        return False, 0, str(e)

def main():
    print("=" * 70)
    print("第9轮升级 —— 模块导入与基础验证")
    print("=" * 70)

    # ===== 1. 业务模块导入 =====
    print("\n【1/4】业务模块导入验证")
    modules = [
        ("soc", "SOC安全运营中心"),
        ("soc.incident_manager", "事件管理器"),
        ("soc.alert_manager", "告警管理器"),
        ("soc.ticket_manager", "工单管理器"),
        ("soc.incident_response", "应急响应管理器"),
        ("soc.soc_dashboard", "SOC仪表盘"),
        ("vuln_management", "漏洞管理深化"),
        ("vuln_management.lifecycle", "漏洞生命周期"),
        ("vuln_management.sla", "漏洞SLA"),
        ("vuln_management.analytics", "漏洞分析引擎"),
        ("vuln_management.remediation_tracker", "修复跟踪器"),
        ("asset_management", "资产管理深化"),
        ("asset_management.discovery", "资产发现器"),
        ("asset_management.fingerprint", "资产指纹库"),
        ("asset_management.risk_rating", "资产风险评级"),
        ("asset_management.change_detection", "资产变更检测"),
        ("asset_management.grouping", "资产分组管理"),
        ("threat_intel", "威胁情报"),
        ("threat_intel.ioc_manager", "IOC管理器"),
        ("threat_intel.threat_actor", "威胁Actor库"),
        ("threat_intel.sample_analyzer", "样本分析器"),
        ("threat_intel.threat_hunting", "威胁狩猎器"),
        ("compliance", "合规审计"),
        ("compliance.frameworks", "合规框架库"),
        ("compliance.assessment", "合规评估器"),
        ("compliance.report_generator", "报告生成器"),
        ("compliance.remediation", "整改管理器"),
        ("red_team", "红队"),
        ("red_team.simulation", "红队模拟器"),
        ("blue_team", "蓝队"),
        ("blue_team.detection", "蓝队检测器"),
        ("purple_team", "紫队"),
        ("purple_team.debrief", "紫队复盘器"),
        ("hudong", "护网行动"),
        ("hudong.preparation", "护网准备"),
        ("hudong.monitoring", "护网监控"),
        ("hudong.emergency", "护网应急"),
        ("hudong.summary", "护网总结"),
        ("audit", "审计日志"),
        ("audit.operation_log", "操作审计日志"),
        ("audit.login_log", "登录日志"),
        ("audit.api_log", "API调用日志"),
        ("audit.data_access_log", "数据访问日志"),
        ("audit.log_manager", "日志管理器"),
    ]

    mod_pass = 0
    mod_fail = 0
    for name, desc in modules:
        ok, result = check_module_import(name, desc)
        if ok:
            mod_pass += 1
            print(f"  OK  {desc} ({name})")
        else:
            mod_fail += 1
            print(f"  FAIL {desc} ({name}): {result}")

    print(f"\n  模块导入: {mod_pass} 通过, {mod_fail} 失败")

    # ===== 2. 路由文件导入与端点统计 =====
    print("\n【2/4】API路由导入与端点统计")
    routes = [
        ("api_server.soc_routes", "SOC路由"),
        ("api_server.vuln_management_routes", "漏洞管理路由"),
        ("api_server.asset_management_routes", "资产管理路由"),
        ("api_server.threat_intel_routes", "威胁情报路由"),
        ("api_server.compliance_routes", "合规审计路由"),
        ("api_server.purple_team_routes", "红蓝对抗路由"),
        ("api_server.hudong_routes", "护网行动路由"),
        ("api_server.audit_routes", "审计日志路由"),
    ]

    route_pass = 0
    route_fail = 0
    total_endpoints = 0
    for name, desc in routes:
        ok, count, msg = check_route_import(name, desc)
        if ok:
            route_pass += 1
            total_endpoints += count
            print(f"  OK  {desc}: {count} 端点")
        else:
            route_fail += 1
            print(f"  FAIL {desc}: {msg}")

    print(f"\n  路由导入: {route_pass} 通过, {route_fail} 失败")
    print(f"  第9轮新增API端点总数: {total_endpoints}")

    # ===== 3. app.py 语法检查 =====
    print("\n【3/4】app.py 语法检查")
    import py_compile
    app_path = os.path.join(os.path.dirname(__file__), "api_server", "app.py")
    try:
        py_compile.compile(app_path, doraise=True)
        print(f"  OK  app.py 语法正确 ({os.path.getsize(app_path)} bytes)")
        syntax_ok = True
    except py_compile.PyCompileError as e:
        print(f"  FAIL app.py 语法错误: {e}")
        syntax_ok = False

    # ===== 4. 数据库表统计 =====
    print("\n【4/4】数据库表统计（第9轮新增表）")
    try:
        from utils.database import db
        conn = db._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        all_tables = [row[0] for row in cursor.fetchall()]

        # 第9轮新增表前缀
        new_prefixes = ["soc_", "vm_", "am_", "ti_", "cp_", "rt_", "bt_", "pt_", "hd_", "audit_"]
        new_tables = [t for t in all_tables if any(t.startswith(p) for p in new_prefixes)]

        print(f"  数据库总表数: {len(all_tables)}")
        print(f"  第9轮新增表数: {len(new_tables)}")
        for t in new_tables:
            cursor.execute(f"SELECT COUNT(*) FROM [{t}]")
            count = cursor.fetchone()[0]
            print(f"    {t}: {count} 条记录")

        conn.close()
        db_ok = True
    except Exception as e:
        print(f"  FAIL 数据库检查失败: {e}")
        db_ok = False

    # ===== 总结 =====
    print("\n" + "=" * 70)
    print("验证总结")
    print("=" * 70)
    print(f"  业务模块导入: {mod_pass}/{len(modules)} 通过")
    print(f"  API路由导入: {route_pass}/{len(routes)} 通过, 共 {total_endpoints} 端点")
    print(f"  app.py语法: {'通过' if syntax_ok else '失败'}")
    print(f"  数据库表: {'通过' if db_ok else '失败'} (第9轮新增 {len(new_tables) if db_ok else '?'} 张表)")

    all_pass = (mod_fail == 0 and route_fail == 0 and syntax_ok and db_ok)
    if all_pass:
        print("\n  *** 全部基础验证通过 ***")
        sys.exit(0)
    else:
        print("\n  !!! 存在验证失败项，请检查 !!!")
        sys.exit(1)


if __name__ == "__main__":
    main()
