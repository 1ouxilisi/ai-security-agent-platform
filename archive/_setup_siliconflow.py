# -*- coding: utf-8 -*-
"""一键配置硅基流动LLM提供商"""
import sys, os, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 从命令行参数或环境变量获取API Key
api_key = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SILICONFLOW_KEY", "")
if not api_key:
    print("用法: python _setup_siliconflow.py <你的硅基流动API Key>")
    print("或设置环境变量: set SILICONFLOW_KEY=你的Key")
    sys.exit(1)

from api_server.llm_provider_routes import _PRESET_PROVIDERS, _encrypt, _get_db
from datetime import datetime

preset = _PRESET_PROVIDERS["siliconflow"]
conn = _get_db()
now = datetime.now().isoformat()
existing = conn.execute("SELECT id FROM providers WHERE name=?", (preset["name"],)).fetchone()
if existing:
    conn.execute("UPDATE providers SET api_key=?, base_url=?, model=?, priority=?, enabled=1, status='unknown', updated_at=? WHERE name=?",
        (_encrypt(api_key), preset["base_url"], preset["model"], 1, now, preset["name"]))
    print(f"[更新] 硅基流动提供商已更新，优先级=1（最高）")
else:
    pid = f"LLM-SILICONFLOW-{hashlib.md5(preset['name'].encode()).hexdigest()[:6].upper()}"
    conn.execute("INSERT INTO providers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid, preset["name"], preset["provider_type"], _encrypt(api_key), preset["base_url"], preset["model"],
         1, 1, "unknown", now, 0, now, now))
    print(f"[创建] 硅基流动提供商已添加，ID={pid}，优先级=1（最高）")
conn.commit()
conn.close()

print(f"API Key已加密存储（XOR+Base64），不以明文保存")
print(f"默认模型: {preset['model']}")
print(f"可用模型: {', '.join(preset['models'][:4])}...")
print(f"\n下一步:")
print(f"  1. 重启服务: python app_lite.py")
print(f"  2. 测试连通性: POST http://127.0.0.1:8001/api/v1/llm/providers/test-all")
print(f"  3. 测试对话:   POST http://127.0.0.1:8001/api/v1/llm/chat")
