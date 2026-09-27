# -*- coding: utf-8 -*-
"""注入第28轮方向2-4路由到app.py"""
import os

APP_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_server", "app.py")

with open(APP_PY, "r", encoding="utf-8") as f:
    content = f.read()

if "第28轮升级方向2" in content:
    print("方向2-4已存在，跳过")
else:
    marker = "# ============== 第28轮升级：新前端页面路由 =============="
    insert_code = '''
# ============== 第28轮升级方向2：真实场景验证与误报率优化路由（50+端点） ==============
try:
    from api_server.real_validation_routes import router as real_validation_router
    app.include_router(real_validation_router)
    log.info("第28轮真实场景验证与误报率优化路由已注册：靶场集成/扫描验证/误报优化/漏洞验证/验证体系/真实场景验证控制台，共50+个端点")
except Exception as e:
    log.warning(f"第28轮真实场景验证与误报率优化路由注册失败: {e}")


# ============== 第28轮升级方向3：性能优化与压力测试路由（50+端点） ==============
try:
    from api_server.performance_deep_routes import router as performance_deep_router
    app.include_router(performance_deep_router)
    log.info("第28轮性能优化与压力测试路由已注册：基准测试/高并发优化/大数据优化/分布式扫描优化/压力测试/性能监控/性能优化控制台，共50+个端点")
except Exception as e:
    log.warning(f"第28轮性能优化与压力测试路由注册失败: {e}")


# ============== 第28轮升级方向4：文档完善与用户体验优化路由（50+端点） ==============
try:
    from api_server.ux_docs_deep_routes import router as ux_docs_deep_router
    app.include_router(ux_docs_deep_router)
    log.info("第28轮文档完善与用户体验优化路由已注册：用户手册/部署文档/API文档/前端UX/新手引导/文档管理/文档与UX控制台，共50+个端点")
except Exception as e:
    log.warning(f"第28轮文档完善与用户体验优化路由注册失败: {e}")


'''
    content = content.replace(marker, insert_code + marker)

    # 更新前端页面路由
    old_pages = '''    _PAGES_R28 = [
        ("/real-tools-deep", "real_tools_deep_console.html", "真实工具集成深度增强控制台"),
    ]'''
    new_pages = '''    _PAGES_R28 = [
        ("/real-tools-deep", "real_tools_deep_console.html", "真实工具集成深度增强控制台"),
        ("/real-validation", "real_validation_console.html", "真实场景验证与误报率优化控制台"),
        ("/performance-deep", "performance_deep_console.html", "性能优化与压力测试控制台"),
        ("/ux-docs-deep", "ux_docs_deep_console.html", "文档完善与用户体验优化控制台"),
    ]'''
    content = content.replace(old_pages, new_pages)

    content = content.replace(
        'log.info("第28轮新前端页面已注册：/real-tools-deep")',
        'log.info("第28轮新前端页面已注册：/real-tools-deep /real-validation /performance-deep /ux-docs-deep")'
    )

    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("方向2-4路由注入成功")

with open(APP_PY, "r", encoding="utf-8") as f:
    c = f.read()
print("方向2存在:", "第28轮升级方向2" in c)
print("方向3存在:", "第28轮升级方向3" in c)
print("方向4存在:", "第28轮升级方向4" in c)
print("页面real-validation存在:", "/real-validation" in c)
print("页面performance-deep存在:", "/performance-deep" in c)
print("页面ux-docs-deep存在:", "/ux-docs-deep" in c)
