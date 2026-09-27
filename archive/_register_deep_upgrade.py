# -*- coding: utf-8 -*-
import ast

with open('app_lite.py', 'r', encoding='utf-8') as f:
    c = f.read()

new_modules = [
    ("report_v2_routes", "report_v2_router", "from api_server.report_v2_routes import router as report_v2_router", "app.include_router(report_v2_router)"),
    ("recon_enhanced_routes", "recon_enhanced_router", "from api_server.recon_enhanced_routes import router as recon_enhanced_router", "app.include_router(recon_enhanced_router)"),
]

for mod_name, router_name, import_line, reg_line in new_modules:
    if router_name not in c:
        # 在mobile_router导入后添加
        old_import = 'from api_server.mobile_security_routes import router as mobile_router'
        if old_import in c:
            c = c.replace(old_import, old_import + '\n' + import_line)
        else:
            c = c.replace('from api_server.workflow_engine_routes import router as workflow_router',
                          'from api_server.workflow_engine_routes import router as workflow_router\n' + import_line)
        old_reg = 'app.include_router(mobile_router)'
        if old_reg in c:
            c = c.replace(old_reg, old_reg + '\n' + reg_line)
        else:
            c = c.replace('app.include_router(workflow_router)',
                          'app.include_router(workflow_router)\n' + reg_line)
        print(f"已注册: {mod_name}")
    else:
        print(f"已存在: {mod_name}")

with open('app_lite.py', 'w', encoding='utf-8') as f:
    f.write(c)

# 验证所有新模块语法
files = ['app_lite.py', 'api_server/report_v2_routes.py', 'api_server/recon_enhanced_routes.py', 'api_server/api_security_routes.py']
for fn in files:
    with open(fn, 'r', encoding='utf-8') as f:
        ast.parse(f.read())
    print(f"  语法OK: {fn}")

print("\n深度升级模块全部注册完成!")
