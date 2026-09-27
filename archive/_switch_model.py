# -*- coding: utf-8 -*-
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from api_server.llm_provider_routes import _get_db
conn = _get_db()
conn.execute("UPDATE providers SET model='Qwen/Qwen2.5-7B-Instruct' WHERE name='硅基流动'")
conn.commit()
row = conn.execute("SELECT name, model, priority FROM providers").fetchone()
print(f"OK: {row['name']} -> {row['model']} priority={row['priority']}")
conn.close()
