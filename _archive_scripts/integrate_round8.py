#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
integrate_round8.py — 第8轮升级集成脚本
在 app.py 的全局异常处理器之前插入：
  1. 7个新路由注册（71个API端点）
  2. 6个新前端页面路由
  3. 静态文件挂载（css/js/locales）
"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
APP_PATH = os.path.join(ROOT, "api_server", "app.py")

# 要插入的代码块
INSERTION_CODE = '''

# ============== 第8轮升级：静态文件挂载（css/js/locales） ==============
try:
    from fastapi.staticfiles import StaticFiles as _StaticFiles
    _api_dir = os.path.dirname(__file__)
    for _sub, _path in [("css", "css"), ("js", "js"), ("locales", "locales")]:
        _full = os.path.join(_api_dir, _path)
        if os.path.isdir(_full):
            app.mount(f"/static/{_sub}", _StaticFiles(directory=_full), name=f"static_{_sub}")
    log.info("第8轮静态文件已挂载：/static/css /static/js /static/locales")
except Exception as e:
    log.warning(f"第8轮静态文件挂载失败: {e}")


# ============== 第8轮升级：靶场集成路由（12端点） ==============
try:
    from api_server.target_lab_routes import router as target_lab_router
    app.include_router(target_lab_router)
    log.info("第8轮靶场集成路由已注册：靶场列表/部署/生命周期/场景/健康检查/Compose生成，共12个端点")
except Exception as e:
    log.warning(f"第8轮靶场集成路由注册失败: {e}")


# ============== 第8轮升级：数据导入导出路由（11端点） ==============
try:
    from api_server.data_io_routes import router as data_io_router
    app.include_router(data_io_router)
    log.info("第8轮数据导入导出路由已注册：导入上传/预览/确认/历史/导出/模板/格式/统计，共11个端点")
except Exception as e:
    log.warning(f"第8轮数据导入导出路由注册失败: {e}")


# ============== 第8轮升级：通知渠道路由（15端点） ==============
try:
    from api_server.notification_routes import router as notification_router
    app.include_router(notification_router)
    log.info("第8轮通知渠道路由已注册：7渠道管理/模板CRUD/事件订阅/手动发送/历史/统计，共15个端点")
except Exception as e:
    log.warning(f"第8轮通知渠道路由注册失败: {e}")


# ============== 第8轮升级：报告模板路由（13端点） ==============
try:
    from api_server.report_template_routes import router as report_template_router
    app.include_router(report_template_router)
    log.info("第8轮报告模板路由已注册：模板CRUD/预览/复制/导入导出/样式预设/Logo管理，共13个端点")
except Exception as e:
    log.warning(f"第8轮报告模板路由注册失败: {e}")


# ============== 第8轮升级：离线模式路由（8端点） ==============
try:
    from api_server.offline_routes import router as offline_router
    app.include_router(offline_router)
    log.info("第8轮离线模式路由已注册：状态/模式切换/规则管理/规则测试/知识库搜索/统计，共8个端点")
except Exception as e:
    log.warning(f"第8轮离线模式路由注册失败: {e}")


# ============== 第8轮升级：API安全专项路由（12端点） ==============
try:
    from api_server.api_security_routes import router as api_security_router
    app.include_router(api_security_router)
    log.info("第8轮API安全专项路由已注册：OpenAPI解析/端点/fuzz/逻辑测试/扫描/状态/结果/漏洞/报告/历史/payloads/统计，共12个端点")
except Exception as e:
    log.warning(f"第8轮API安全专项路由注册失败: {e}")


# ============== 第8轮升级：新前端页面路由（6个页面） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR8

    _PAGES_R8 = [
        ("/target-labs", "target_lab_console.html", "靶场管理控制台"),
        ("/notifications", "notification_console.html", "通知中心控制台"),
        ("/report-templates", "report_template_console.html", "报告模板编辑器"),
        ("/api-security", "api_security_console.html", "API安全测试控制台"),
        ("/mobile-test", "mobile_test.html", "移动端组件测试页"),
        ("/i18n-test", "i18n_test.html", "i18n多语言测试页"),
    ]

    for _route, _fname, _desc in _PAGES_R8:
        def _make_page_handler(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR8(content=_f.read())
                return _HTMLR8(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler
        _make_page_handler()

    log.info("第8轮新前端页面已注册：/target-labs /notifications /report-templates /api-security /mobile-test /i18n-test")
except Exception as e:
    log.warning(f"第8轮新前端页面注册失败: {e}")

'''

def main():
    with open(APP_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # 检查是否已经集成过
    if "第8轮升级：靶场集成路由" in content:
        print("[SKIP] app.py 已经包含第8轮集成代码，跳过")
        return 0

    # 找到插入点：全局异常处理器之前
    marker = "# ============== 全局异常处理器（不暴露堆栈，统一返回 JSON 500） =============="
    if marker not in content:
        print("[ERROR] 未找到插入点标记：全局异常处理器")
        return 1

    # 在标记之前插入
    new_content = content.replace(marker, INSERTION_CODE + "\n" + marker, 1)

    with open(APP_PATH, "w", encoding="utf-8") as f:
        f.write(new_content)

    print(f"[OK] 已在 app.py 中插入第8轮集成代码（{len(INSERTION_CODE)} 字符）")
    print(f"[OK] app.py 新行数: {len(new_content.splitlines())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
