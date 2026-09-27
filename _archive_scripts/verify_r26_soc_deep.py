# -*- coding: utf-8 -*-
"""SOC Deep 第26轮 验证脚本"""
from __future__ import annotations
import os, sys, re

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

print("=" * 60)
print("SOC Deep 第26轮方向3 验证")
print("=" * 60)

# 1. 独立 import 7 个核心模块
print("\n[1] 独立 import 核心模块:")
mods = [
    "soc_deep.siem_logging",
    "soc_deep.correlation_engine",
    "soc_deep.alert_triage_deep",
    "soc_deep.incident_response_deep",
    "soc_deep.threat_intel_soc",
    "soc_deep.soc_metrics",
    "soc_deep.soc_dashboard",
]
for m in mods:
    try:
        __import__(m)
        print(f"  OK  {m}")
    except Exception as e:
        print(f"  FAIL {m}: {e}")

# 2. 路由 import & 端点计数
print("\n[2] 路由 import & 端点计数:")
try:
    from api_server import soc_deep_routes
    paths = []
    for r in soc_deep_routes.router.routes:
        methods = getattr(r, "methods", set())
        paths.append((list(methods)[0] if methods else "?", r.path))
    print(f"  OK  路由加载成功, 端点数 = {len(paths)}")
    for m, p in paths:
        print(f"      {m:6s} {p}")
except Exception as e:
    import traceback; traceback.print_exc()
    print(f"  FAIL 路由加载: {e}")

# 3. HTML 大小
print("\n[3] HTML 文件大小:")
hp = os.path.join(ROOT, "api_server", "soc_deep_console.html")
sz = os.path.getsize(hp)
print(f"  {hp} = {sz} bytes ({sz/1024:.1f} KB)  {'OK' if sz > 15*1024 else 'FAIL(<15KB)'}")

# 4. 文件行数 & 大小
print("\n[4] 交付文件清单:")
files = [
    "soc_deep/__init__.py",
    "soc_deep/siem_logging.py",
    "soc_deep/correlation_engine.py",
    "soc_deep/alert_triage_deep.py",
    "soc_deep/incident_response_deep.py",
    "soc_deep/threat_intel_soc.py",
    "soc_deep/soc_metrics.py",
    "soc_deep/soc_dashboard.py",
    "api_server/soc_deep_routes.py",
    "api_server/soc_deep_console.html",
]
for f in files:
    p = os.path.join(ROOT, f)
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as fh:
            lines = sum(1 for _ in fh)
        print(f"  {os.path.getsize(p):>7d}B  {lines:>4d}行  {p}")
    else:
        print(f"  MISSING: {p}")
