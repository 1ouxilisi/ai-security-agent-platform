#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检查console-v7和实战API结构"""
import sys
sys.path.insert(0, '.')

print("=== console-v7页面路由 ===")
import re
with open('api_server/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

routes = re.findall(r'@app\.(get|post)\("([^"]*console[^"]*)"', content)
for method, path in routes:
    print(f'  {method.upper()}: {path}')
print(f'总计: {len(routes)}个console路由')

print()
print("=== 实战能力API端点 ===")
from api_server.combat_routes import router
print(f'实战能力端点: {len(router.routes)}个')
for route in router.routes:
    if hasattr(route, 'methods') and route.methods:
        methods = ','.join(route.methods)
        print(f'  {methods}: {route.path}')
