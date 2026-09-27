#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
register_workflow_route脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

"""在app.py中注册工作流路由"""

filepath = 'api_server/app.py'
with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

old = '''    from api_server.vuln_routes import router as vuln_router
    app.include_router(auth_router)
    app.include_router(alert_router)
    app.include_router(backup_router)
    app.include_router(vuln_router)
    log.info("新API路由已注册：用户认证/告警通知/数据备份/漏洞数据库")'''

new = '''    from api_server.vuln_routes import router as vuln_router
    from api_server.workflow_routes import router as workflow_router
    app.include_router(auth_router)
    app.include_router(alert_router)
    app.include_router(backup_router)
    app.include_router(vuln_router)
    app.include_router(workflow_router)
    log.info("新API路由已注册：用户认证/告警通知/数据备份/漏洞数据库/渗透测试工作流")'''

if old in content:
    content = content.replace(old, new)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print('✓ 工作流路由已注册到app.py')
else:
    print('✗ 未找到匹配的代码块')
    # 查找类似的行
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'vuln_router' in line or '新API路由已注册' in line:
            print(f'  行{i+1}: {line.strip()[:80]}')
