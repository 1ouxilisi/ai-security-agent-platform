# -*- coding: utf-8 -*-
"""验证第28轮app.py导入和路由注册"""
import sys
sys.path.insert(0, '.')

from api_server.app import app
routes = getattr(app, 'routes', [])
print('总路由数:', len(routes))

prefixes = [
    '/api/v1/real-tools-deep',
    '/api/v1/real-validation',
    '/api/v1/performance-deep',
    '/api/v1/ux-docs-deep',
]
pages = ['/real-tools-deep', '/real-validation', '/performance-deep', '/ux-docs-deep']

for p in prefixes:
    found = any(p in getattr(r, 'path', '') for r in routes)
    print(f'  {p}: {"OK" if found else "FAIL"}')

for p in pages:
    found = any(getattr(r, 'path', '') == p for r in routes)
    print(f'  页面{p}: {"OK" if found else "FAIL"}')

# 统计第28轮各方向端点数
for prefix in prefixes:
    cnt = sum(1 for r in routes if prefix in getattr(r, 'path', ''))
    print(f'  {prefix} 端点数: {cnt}')

print('\n验证完成')
