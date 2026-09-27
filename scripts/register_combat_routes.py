#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在主应用中注册实战能力路由"""

with open('api_server/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 检查是否已经注册
if 'combat_router' in content:
    print("实战能力路由已注册，跳过")
else:
    # 在v7.0路由注册后添加实战能力路由
    old = '''    log.info("v7.0新API路由已注册：内网渗透(25端点)/漏洞利用(20端点)/工具集成(18端点)/分布式扫描(22端点)，共85+新端点")
except Exception as e:
    log.warning(f"v7.0新API路由注册失败: {e}")'''

    new = '''    log.info("v7.0新API路由已注册：内网渗透(25端点)/漏洞利用(20端点)/工具集成(18端点)/分布式扫描(22端点)，共85+新端点")
except Exception as e:
    log.warning(f"v7.0新API路由注册失败: {e}")

# ============== 实战能力路由注册（sqlmap/Metasploit/AD攻击链/Web利用/一键模板） ==============
try:
    from api_server.combat_routes import router as combat_router
    app.include_router(combat_router)
    log.info("实战能力API路由已注册：SQL注入(3端点)/Metasploit(6端点)/AD攻击链(5端点)/Web利用(5端点)/攻击模板(5端点)，共25+新端点")
except Exception as e:
    log.warning(f"实战能力API路由注册失败: {e}")'''

    if old in content:
        content = content.replace(old, new)
        with open('api_server/app.py', 'w', encoding='utf-8') as f:
            f.write(content)
        print("实战能力路由注册成功")
    else:
        print("未找到匹配文本，检查文件内容")
        # 显示相关行
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if 'v7.0新API路由' in line:
                print(f"  {i+1}: {line}")

# 验证语法
import ast
try:
    with open('api_server/app.py', 'r', encoding='utf-8') as f:
        ast.parse(f.read())
    print("语法验证通过")
except SyntaxError as e:
    print(f"语法错误: {e}")
