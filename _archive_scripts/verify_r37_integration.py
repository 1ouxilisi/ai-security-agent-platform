import sys
sys.path.insert(0, '.')

from api_server.app import app

routes = list(app.routes)
api_routes = [r for r in routes if hasattr(r, 'path') and '/api/' in getattr(r, 'path', '')]
page_routes = [r for r in routes if hasattr(r, 'path') and '/api/' not in getattr(r, 'path', '')]

print(f'总路由数: {len(routes)}')
print(f'API路由数: {len(api_routes)}')
print(f'页面路由数: {len(page_routes)}')

# 检查第37轮新路由
new_prefixes = [
    '/api/v1/internal-pentest-pro',
    '/api/v1/mobile-pentest-pro',
    '/api/v1/cloud-security-pro',
]
print('\n=== 第37轮新API路由 ===')
for prefix in new_prefixes:
    count = len([r for r in api_routes if getattr(r, 'path', '').startswith(prefix)])
    print(f'  {prefix}: {count}个端点')

# 检查新页面
new_pages = [
    '/internal-pentest-pro',
    '/mobile-pentest-pro',
    '/cloud-security-pro',
]
print('\n=== 第37轮新页面 ===')
for page in new_pages:
    found = any(getattr(r, 'path', '') == page for r in routes)
    status = 'YES' if found else 'NO'
    print(f'  {page}: {status}')

print('\n=== 集成验证完成 ===')
