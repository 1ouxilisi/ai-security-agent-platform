# -*- coding: utf-8 -*-
"""零信任模块 import 验证脚本（第13轮）。"""
import os
import sys
import traceback

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

TARGETS = [
    "zero_trust",
    "zero_trust.identity_access",
    "zero_trust.continuous_verification",
    "zero_trust.microsegmentation",
    "zero_trust.device_trust",
    "zero_trust.application_api_security",
    "zero_trust.zero_trust_maturity",
]

results = []
for mod in TARGETS:
    try:
        __import__(mod)
        results.append((mod, True, ""))
    except Exception as e:
        results.append((mod, False, f"{type(e).__name__}: {e}\n{traceback.format_exc()}"))

# 路由文件（依赖 fastapi）
try:
    sys.path.insert(0, os.path.join(ROOT, "api_server"))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "zero_trust_routes", os.path.join(ROOT, "api_server", "zero_trust_routes.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # 统计路由数
    routes = [r for r in mod.router.routes]
    results.append(("api_server/zero_trust_routes", True, f"routes={len(routes)}"))
except Exception as e:
    results.append(("api_server/zero_trust_routes", False,
                    f"{type(e).__name__}: {e}\n{traceback.format_exc()}"))

print("=" * 60)
ok = 0
for name, success, info in results:
    flag = "PASS" if success else "FAIL"
    print(f"[{flag}] {name}  {info if not success else ''}")
    if success:
        ok += 1
print("=" * 60)
print(f"通过 {ok}/{len(results)}")
sys.exit(0 if ok == len(results) else 1)
