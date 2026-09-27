# -*- coding: utf-8 -*-
import os
filepath = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent\api_server\ai_decision_engine_routes.py"
with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# 修复DecisionReq模型 - 移除session_id字段（在URL路径中）
old = '''class DecisionReq(BaseModel):
    session_id: str
    observation: str = ""'''
new = '''class DecisionReq(BaseModel):
    observation: str = ""'''

if old in content:
    content = content.replace(old, new)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print("DecisionReq修复成功")
else:
    print("未找到DecisionReq定义")
