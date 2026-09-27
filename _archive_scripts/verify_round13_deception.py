# -*- coding: utf-8 -*-
"""第13轮升级 import 验证脚本"""
import sys
import os
import importlib

PROJECT = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent"
sys.path.insert(0, PROJECT)
os.chdir(PROJECT)

modules = [
    "deception",
    "deception.honeypot_manager",
    "deception.attack_detector",
    "deception.threat_intel_generator",
    "deception.decoy_breadcrumb",
    "deception.honeynet_distributed",
    "deception.deception_operations",
]

results = []
ok_count = 0
for mod in modules:
    try:
        importlib.import_module(mod)
        results.append((mod, True, ""))
        ok_count += 1
        print(f"[OK] {mod}")
    except Exception as e:
        results.append((mod, False, str(e)))
        print(f"[FAIL] {mod}: {e}")

# 路由文件需要 fastapi
try:
    sys.path.insert(0, os.path.join(PROJECT, "api_server"))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "deception_routes",
        os.path.join(PROJECT, "api_server", "deception_routes.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    results.append(("api_server/deception_routes", True, ""))
    ok_count += 1
    print("[OK] api_server/deception_routes")
except Exception as e:
    results.append(("api_server/deception_routes", False, str(e)))
    print(f"[FAIL] api_server/deception_routes: {e}")

print(f"\n=== 验证结果: {ok_count}/{len(modules)+1} 通过 ===")
for mod, ok, err in results:
    status = "PASS" if ok else "FAIL"
    print(f"  {status}: {mod}" + (f" — {err}" if err else ""))
