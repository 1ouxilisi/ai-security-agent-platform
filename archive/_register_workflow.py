# -*- coding: utf-8 -*-
import ast
with open('app_lite.py', 'r', encoding='utf-8') as f:
    c = f.read()

old_import = 'from api_server.rag_knowledge_routes import router as rag_router'
new_import = old_import + '\nfrom api_server.workflow_engine_routes import router as workflow_router'
c = c.replace(old_import, new_import)

old_reg = 'app.include_router(rag_router)'
new_reg = old_reg + '\napp.include_router(workflow_router)'
c = c.replace(old_reg, new_reg)

with open('app_lite.py', 'w', encoding='utf-8') as f:
    f.write(c)

with open('app_lite.py', 'r', encoding='utf-8') as f:
    ast.parse(f.read())
with open('api_server/workflow_engine_routes.py', 'r', encoding='utf-8') as f:
    ast.parse(f.read())
print("工作流引擎已注册, 全部语法OK")
