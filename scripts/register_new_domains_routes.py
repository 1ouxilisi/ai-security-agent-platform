#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""注册新领域安全API路由"""

with open('api_server/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 检查是否已经注册
if 'new_domains_routes' in content:
    print("新领域安全路由已注册，跳过")
else:
    # 在实战能力路由后添加新领域路由
    old = '''    log.info("实战能力API路由已注册：SQL注入(3端点)/Metasploit(6端点)/AD攻击链(5端点)/Web利用(5端点)/攻击模板(5端点)，共25+新端点")
except Exception as e:
    log.warning(f"实战能力API路由注册失败: {e}")'''

    new = '''    log.info("实战能力API路由已注册：SQL注入(3端点)/Metasploit(6端点)/AD攻击链(5端点)/Web利用(5端点)/攻击模板(5端点)，共25+新端点")
except Exception as e:
    log.warning(f"实战能力API路由注册失败: {e}")

# ============== 新领域安全路由注册（移动安全/云安全/客户端安全/AI安全） ==============
try:
    from api_server.new_domains_routes import router as new_domains_router
    app.include_router(new_domains_router)
    log.info("新领域安全API路由已注册：移动安全(3端点)/云安全(3端点)/客户端安全(3端点)/AI安全(3端点)/综合状态(1端点)，共13个新端点")
except Exception as e:
    log.warning(f"新领域安全API路由注册失败: {e}")'''

    if old in content:
        content = content.replace(old, new)
        with open('api_server/app.py', 'w', encoding='utf-8') as f:
            f.write(content)
        print("新领域安全路由注册成功")
    else:
        print("未找到匹配文本，检查文件内容")

# 验证语法
import ast
try:
    with open('api_server/app.py', 'r', encoding='utf-8') as f:
        ast.parse(f.read())
    print("语法验证通过")
except SyntaxError as e:
    print(f"语法错误: {e}")
