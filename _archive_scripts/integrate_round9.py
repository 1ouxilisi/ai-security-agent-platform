"""
第9轮升级集成脚本 —— 将8个新模块的路由和6个前端页面注册到 app.py。

用法：python integrate_round9.py
功能：
  1. 在 app.py 的全局异常处理器之前插入第9轮路由注册（8个router）
  2. 插入第9轮前端页面路由（6个控制台页面）
  3. 幂等：重复运行不会重复插入
"""
import os
import re

APP_PATH = os.path.join(os.path.dirname(__file__), "api_server", "app.py")

# 第9轮路由注册代码块
ROUTES_BLOCK = '''

# ============== 第9轮升级：安全运营中心(SOC)路由（37端点） ==============
try:
    from api_server.soc_routes import router as soc_router
    app.include_router(soc_router)
    log.info("第9轮SOC路由已注册：事件/告警/工单/应急响应/仪表盘，共37个端点")
except Exception as e:
    log.warning(f"第9轮SOC路由注册失败: {e}")


# ============== 第9轮升级：漏洞管理深化路由（24端点） ==============
try:
    from api_server.vuln_management_routes import router as vuln_mgmt_router
    app.include_router(vuln_mgmt_router)
    log.info("第9轮漏洞管理深化路由已注册：生命周期/SLA/分析/修复跟踪，共24个端点")
except Exception as e:
    log.warning(f"第9轮漏洞管理深化路由注册失败: {e}")


# ============== 第9轮升级：资产管理深化路由（30端点） ==============
try:
    from api_server.asset_management_routes import router as asset_mgmt_router
    app.include_router(asset_mgmt_router)
    log.info("第9轮资产管理深化路由已注册：发现/指纹/风险评级/变更检测/分组，共30个端点")
except Exception as e:
    log.warning(f"第9轮资产管理深化路由注册失败: {e}")


# ============== 第9轮升级：威胁情报集成路由（19端点） ==============
try:
    from api_server.threat_intel_routes import router as threat_intel_router
    app.include_router(threat_intel_router)
    log.info("第9轮威胁情报路由已注册：IOC/Actor/样本分析/威胁狩猎，共19个端点")
except Exception as e:
    log.warning(f"第9轮威胁情报路由注册失败: {e}")


# ============== 第9轮升级：合规审计深化路由（17端点） ==============
try:
    from api_server.compliance_routes import router as compliance_router
    app.include_router(compliance_router)
    log.info("第9轮合规审计路由已注册：框架/评估/报告/整改，共17个端点")
except Exception as e:
    log.warning(f"第9轮合规审计路由注册失败: {e}")


# ============== 第9轮升级：红蓝对抗演练路由（18端点） ==============
try:
    from api_server.purple_team_routes import router as purple_team_router
    app.include_router(purple_team_router)
    log.info("第9轮红蓝对抗路由已注册：红队模拟/蓝队检测/紫队复盘，共18个端点")
except Exception as e:
    log.warning(f"第9轮红蓝对抗路由注册失败: {e}")


# ============== 第9轮升级：护网行动支持路由（35端点） ==============
try:
    from api_server.hudong_routes import router as hudong_router
    app.include_router(hudong_router)
    log.info("第9轮护网行动路由已注册：准备/监控/应急/总结，共35个端点")
except Exception as e:
    log.warning(f"第9轮护网行动路由注册失败: {e}")


# ============== 第9轮升级：审计日志深化路由（30端点） ==============
try:
    from api_server.audit_routes import router as audit_router
    app.include_router(audit_router)
    log.info("第9轮审计日志路由已注册：操作/登录/API/数据访问/日志管理，共30个端点")
except Exception as e:
    log.warning(f"第9轮审计日志路由注册失败: {e}")


# ============== 第9轮升级：新前端页面路由（6个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR9

    _PAGES_R9 = [
        ("/soc-console", "soc_console.html", "SOC安全运营中心控制台"),
        ("/asset-console", "asset_console.html", "资产管理控制台"),
        ("/compliance-console", "compliance_console.html", "合规审计控制台"),
        ("/purple-team-console", "purple_team_console.html", "红蓝对抗控制台"),
        ("/hudong-console", "hudong_console.html", "护网行动控制台"),
        ("/audit-console", "audit_console.html", "审计日志控制台"),
    ]

    for _route, _fname, _desc in _PAGES_R9:
        def _make_page_handler_r9(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r9():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR9(content=_f.read())
                return _HTMLR9(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r9
        _make_page_handler_r9()

    log.info("第9轮新前端页面已注册：/soc-console /asset-console /compliance-console /purple-team-console /hudong-console /audit-console")
except Exception as e:
    log.warning(f"第9轮新前端页面注册失败: {e}")

'''


def main():
    if not os.path.exists(APP_PATH):
        print(f"ERROR: app.py not found at {APP_PATH}")
        return

    with open(APP_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # 幂等检查：如果已经插入过第9轮路由，不再重复插入
    if "第9轮升级：安全运营中心(SOC)路由" in content:
        print("第9轮路由已存在于app.py中，跳过插入（幂等）。")
    else:
        # 找到全局异常处理器的位置，在其之前插入
        marker = "# ============== 全局异常处理器"
        if marker not in content:
            print(f"ERROR: 未找到插入标记 '{marker}'")
            return

        content = content.replace(marker, ROUTES_BLOCK + marker, 1)
        print("第9轮路由和页面注册代码已插入app.py。")

    with open(APP_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    # 验证：检查插入后的关键字符串
    with open(APP_PATH, "r", encoding="utf-8") as f:
        final = f.read()

    checks = [
        ("soc_router", "SOC路由"),
        ("vuln_mgmt_router", "漏洞管理路由"),
        ("asset_mgmt_router", "资产管理路由"),
        ("threat_intel_router", "威胁情报路由"),
        ("compliance_router", "合规审计路由"),
        ("purple_team_router", "红蓝对抗路由"),
        ("hudong_router", "护网行动路由"),
        ("audit_router", "审计日志路由"),
        ("/soc-console", "SOC控制台页面"),
        ("/asset-console", "资产控制台页面"),
        ("/compliance-console", "合规控制台页面"),
        ("/purple-team-console", "红蓝控制台页面"),
        ("/hudong-console", "护网控制台页面"),
        ("/audit-console", "审计控制台页面"),
    ]

    print("\\n=== 集成验证 ===")
    all_ok = True
    for keyword, desc in checks:
        if keyword in final:
            print(f"  OK: {desc} ({keyword})")
        else:
            print(f"  FAIL: {desc} ({keyword}) 未找到!")
            all_ok = False

    if all_ok:
        print("\\n=== 全部集成验证通过 ===")
    else:
        print("\\n=== 部分验证失败，请检查 ===")

    print(f"app.py 最终行数: {len(final.splitlines())}")


if __name__ == "__main__":
    main()
