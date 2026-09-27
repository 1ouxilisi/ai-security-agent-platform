# -*- coding: utf-8 -*-
import os
filepath = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent\api_server\ai_decision_engine_routes.py"
with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

old = 'conn.execute("""INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",'
new = 'conn.execute("""INSERT INTO sessions (id,target,status,current_phase,phase_index,decisions,results,attack_path,risk_score,created_at,updated_at,completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",'

if old in content:
    content = content.replace(old, new)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print("修复成功")
else:
    print("未找到目标字符串，可能已修复")
