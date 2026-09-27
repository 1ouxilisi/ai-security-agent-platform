# -*- coding: utf-8 -*-
"""Verify all IoT security modules import correctly."""
import sys, os, importlib.util

PROJECT = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent"
sys.path.insert(0, PROJECT)
os.chdir(PROJECT)

iot_modules = [
    "iot_security",
    "iot_security.device_discovery",
    "iot_security.firmware_analyzer",
    "iot_security.protocol_security",
    "iot_security.default_credentials",
    "iot_security.communication_security",
    "iot_security.vulnerability_detector",
    "iot_security.iot_assessment_workflow",
]

results = []

for mod in iot_modules:
    try:
        __import__(mod)
        results.append((mod, "OK", ""))
    except Exception as e:
        results.append((mod, "FAIL", str(e)))

# Routes file
routes_path = os.path.join(PROJECT, "api_server", "iot_security_routes.py")
try:
    spec = importlib.util.spec_from_file_location("iot_security_routes", routes_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    results.append(("api_server.iot_security_routes", "OK", ""))
except Exception as e:
    results.append(("api_server.iot_security_routes", "FAIL", str(e)))

for name, status, err in results:
    print(f"{status}: {name}")
    if err:
        print(f"  -> {err}")

ok_count = sum(1 for _, s, _ in results if s == "OK")
fail_count = sum(1 for _, s, _ in results if s == "FAIL")
print(f"\nTotal: {len(results)}, OK: {ok_count}, FAIL: {fail_count}")
