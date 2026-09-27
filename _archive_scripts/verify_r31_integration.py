import sys
sys.path.insert(0, '.')

from api_server.app import app

routes = list(app.routes)
api_routes = [r for r in routes if hasattr(r, 'path') and '/api/' in getattr(r, 'path', '')]
page_routes = [r for r in routes if hasattr(r, 'path') and '/api/' not in getattr(r, 'path', '')]

print(f'总路由数: {len(routes)}')
print(f'API路由数: {len(api_routes)}')
print(f'页面路由数: {len(page_routes)}')

# 检查第31轮新路由
new_prefixes = [
    '/api/v1/internal-pentest-real',
    '/api/v1/mobile-real',
    '/api/v1/license',
    '/api/v1/src-workbench',
]
print('\n=== 第31轮新API路由 ===')
for prefix in new_prefixes:
    count = len([r for r in api_routes if getattr(r, 'path', '').startswith(prefix)])
    print(f'  {prefix}: {count}个端点')

# 检查新页面
new_pages = [
    '/internal-pentest-real',
    '/mobile-real',
    '/license-management',
    '/src-workbench',
]
print('\n=== 第31轮新页面 ===')
for page in new_pages:
    found = any(getattr(r, 'path', '') == page for r in routes)
    status = 'YES' if found else 'NO'
    print(f'  {page}: {status}')

# 检查Docker文件
import os
print('\n=== Docker部署文件 ===')
for f in ['Dockerfile', 'docker-compose.yml', 'deploy.sh', 'DEPLOY.md']:
    exists = os.path.exists(f)
    size = os.path.getsize(f) if exists else 0
    print(f'  {f}: {"EXISTS" if exists else "MISSING"} ({size}B)')

print('\n=== 集成验证完成 ===')
