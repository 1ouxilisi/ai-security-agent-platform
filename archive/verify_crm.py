# -*- coding: utf-8 -*-
import os, sys, importlib
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

files = [
    "crm_system/__init__.py",
    "crm_system/customer_manager.py",
    "crm_system/sales_pipeline.py",
    "crm_system/communication_activity.py",
    "crm_system/product_pricing.py",
    "crm_system/customer_service.py",
    "crm_system/crm_dashboard.py",
    "api_server/crm_system_routes.py",
]
print("=== 文件行数 ===")
total = 0
for f in files:
    p = os.path.join(ROOT, f)
    n = sum(1 for _ in open(p, "r", encoding="utf-8"))
    total += n
    print(f"  {os.path.abspath(p)}  ({n} 行)")
print("  合计:", total, "行")

html = os.path.join(ROOT, "api_server", "crm_system_console.html")
sz = os.path.getsize(html)
print(f"\n=== 前端 ===\n  {html}  ({sz} 字节, {sz/1024:.1f} KB)")

print("\n=== 独立 import 验证 ===")
mods = ["crm_system", "crm_system.customer_manager", "crm_system.sales_pipeline",
        "crm_system.communication_activity", "crm_system.product_pricing",
        "crm_system.customer_service", "crm_system.crm_dashboard",
        "api_server.crm_system_routes"]
ok = 0
for m in mods:
    try:
        importlib.import_module(m)
        print(f"  [OK] {m}")
        ok += 1
    except Exception as e:
        print(f"  [FAIL] {m}: {e}")
print(f"  通过 {ok}/{len(mods)}")

r = importlib.import_module("api_server.crm_system_routes")
eps = r.router.routes
print(f"\n=== API 端点 ===\n  总数: {len(eps)}")
from collections import Counter
methods = Counter()
for e in eps:
    for mt in getattr(e, "methods", []) or ["?"]:
        methods[mt] += 1
print("  方法分布:", dict(methods))
print("  前缀:", r.router.prefix)
