"""
第10轮升级：路由注册集成脚本
将所有新模块的API路由和前端页面注册到 app.py
在第9轮注册之后、全局异常处理器之前插入
"""
import os
import re

APP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_server", "app.py")

# 第10轮路由注册代码块
ROUTE_BLOCK = '''

# ============== 第10轮升级：AI安全运营(AI SOC)路由（23端点） ==============
try:
    from api_server.ai_soc_routes import router as ai_soc_router
    app.include_router(ai_soc_router)
    log.info("第10轮AI安全运营路由已注册：异常检测/告警关联/事件分类/根因分析/响应建议/AI助手，共23个端点")
except Exception as e:
    log.warning(f"第10轮AI安全运营路由注册失败: {e}")


# ============== 第10轮升级：性能监控路由（22端点） ==============
try:
    from api_server.performance_routes import router as performance_router
    app.include_router(performance_router)
    log.info("第10轮性能监控路由已注册：查询优化/索引管理/缓存/慢查询/API性能/DB性能，共22个端点")
except Exception as e:
    log.warning(f"第10轮性能监控路由注册失败: {e}")


# ============== 第10轮升级：SaaS化基础路由（25端点） ==============
try:
    from api_server.saas_routes import router as saas_router
    app.include_router(saas_router)
    log.info("第10轮SaaS化基础路由已注册：认证/MFA/用户/租户/邀请，共25个端点")
except Exception as e:
    log.warning(f"第10轮SaaS化基础路由注册失败: {e}")


# ============== 第10轮升级：数据可视化V2路由（20端点） ==============
try:
    from api_server.visualization_v2_routes import router as visualization_v2_router
    app.include_router(visualization_v2_router)
    log.info("第10轮数据可视化V2路由已注册：实时大屏/3D拓扑/攻击地图/自定义仪表盘，共20个端点")
except Exception as e:
    log.warning(f"第10轮数据可视化V2路由注册失败: {e}")


# ============== 第10轮升级：API网关深化路由（24端点） ==============
try:
    from api_server.api_gateway_routes import router as api_gateway_router
    app.include_router(api_gateway_router)
    log.info("第10轮API网关深化路由已注册：限流/熔断/降级/缓存/日志/监控，共24个端点")
except Exception as e:
    log.warning(f"第10轮API网关深化路由注册失败: {e}")


# ============== 第10轮升级：SSO/LDAP集成路由（23端点） ==============
try:
    from api_server.sso_routes import router as sso_router
    app.include_router(sso_router)
    log.info("第10轮SSO/LDAP集成路由已注册：SAML/OAuth2/LDAP/SSO统一，共23个端点")
except Exception as e:
    log.warning(f"第10轮SSO/LDAP集成路由注册失败: {e}")


# ============== 第10轮升级：新前端页面路由（5个控制台+大屏） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR10

    _PAGES_R10 = [
        ("/saas-console", "saas_console.html", "SaaS管理控制台"),
        ("/realtime-dashboard", "realtime_dashboard.html", "实时监控大屏"),
        ("/custom-dashboard", "custom_dashboard.html", "自定义仪表盘编辑器"),
        ("/backup-console", "backup_console.html", "数据备份恢复控制台"),
        ("/sso-console", "sso_console.html", "SSO/LDAP管理控制台"),
    ]

    for _route, _fname, _desc in _PAGES_R10:
        def _make_page_handler_r10(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r10():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR10(content=_f.read())
                return _HTMLR10(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r10
        _make_page_handler_r10()

    log.info("第10轮新前端页面已注册：/saas-console /realtime-dashboard /custom-dashboard /backup-console /sso-console")
except Exception as e:
    log.warning(f"第10轮新前端页面注册失败: {e}")

'''


def main():
    if not os.path.exists(APP_PATH):
        print(f"错误: app.py 不存在: {APP_PATH}")
        return False

    with open(APP_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # 检查是否已经注册过第10轮
    if "第10轮升级：AI安全运营" in content:
        print("第10轮路由已经注册过，跳过")
        return True

    # 找到插入点：在全局异常处理器之前
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        # 备选：在 def run_api_server 之前
        marker = "def run_api_server"
        if marker not in content:
            print("错误: 找不到插入点")
            return False

    # 在标记之前插入
    insert_pos = content.find(marker)
    new_content = content[:insert_pos] + ROUTE_BLOCK + "\n" + content[insert_pos:]

    with open(APP_PATH, "w", encoding="utf-8") as f:
        f.write(new_content)

    print(f"第10轮路由注册成功，已插入到 app.py (位置: 行 {content[:insert_pos].count(chr(10))+1})")
    print(f"app.py 新行数: {new_content.count(chr(10))+1}")
    return True


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
