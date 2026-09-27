# -*- coding: utf-8 -*-
"""第13轮 暗网监控/DRP 模块 import 验证脚本。"""
import importlib
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

modules = [
    "darkweb_monitor",
    "darkweb_monitor.darkweb_intel",
    "darkweb_monitor.credential_leak",
    "darkweb_monitor.brand_protection",
    "darkweb_monitor.data_breach_analysis",
    "darkweb_monitor.threat_actor_analysis",
    "darkweb_monitor.drp_operations",
    "api_server.darkweb_monitor_routes",
]

ok = True
for m in modules:
    try:
        mod = importlib.import_module(m)
        print(f"[OK]  {m}")
    except Exception as e:
        ok = False
        import traceback
        print(f"[FAIL] {m}: {e}")
        traceback.print_exc()

# 功能性冒烟：调用各单例工厂方法
try:
    from darkweb_monitor.darkweb_intel import get_darkweb_intel_monitor
    from darkweb_monitor.credential_leak import get_credential_leak_detector
    from darkweb_monitor.brand_protection import get_brand_protection_detector
    from darkweb_monitor.data_breach_analysis import get_data_breach_analyzer
    from darkweb_monitor.threat_actor_analysis import get_threat_actor_analyzer
    from darkweb_monitor.drp_operations import get_drp_operator
    r = get_drp_operator().run_assessment("ExampleCorp")
    print(f"[OK]  DRP run_assessment overall_score={r['risk_score']['overall_score']}")
except Exception as e:
    ok = False
    print(f"[FAIL] functional smoke: {e}")
    import traceback; traceback.print_exc()

# 路由计数
try:
    from api_server.darkweb_monitor_routes import router
    paths = [getattr(r, 'path', '') for r in router.routes]
    print(f"[OK]  路由总数={len(paths)}")
except Exception as e:
    ok = False
    print(f"[FAIL] route count: {e}")

print("RESULT:", "ALL_PASS" if ok else "HAS_FAILURE")
sys.exit(0 if ok else 1)
