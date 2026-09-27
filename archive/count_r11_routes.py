# -*- coding: utf-8 -*-
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from api_server.app import app

routes = [r for r in app.routes if hasattr(r, 'path')]
keywords = ['cloud-v2', 'code-v2', 'forensics-v2', '/plugins', 'cloud-security-v2', 'code-audit-v2', 'forensics-v2', 'plugins-console']
new_r11 = [r for r in routes if any(k in r.path for k in keywords)]

print(f'总路由数: {len(routes)}')
print(f'第11轮新增路由: {len(new_r11)}')
print()
print('新增路由列表:')
for r in new_r11:
    methods = getattr(r, 'methods', {'GET'})
    print(f'  {methods} {r.path}')

# 统计各模块
cloud = [r for r in new_r11 if 'cloud-v2' in r.path or 'cloud-security' in r.path]
code = [r for r in new_r11 if 'code-v2' in r.path or 'code-audit' in r.path]
forensics = [r for r in new_r11 if 'forensics-v2' in r.path or 'forensics-v2' in r.path]
plugins = [r for r in new_r11 if '/plugins' in r.path or 'plugins-console' in r.path]
print()
print(f'  云安全: {len(cloud)} 条')
print(f'  代码审计: {len(code)} 条')
print(f'  取证分析: {len(forensics)} 条')
print(f'  插件系统: {len(plugins)} 条')
