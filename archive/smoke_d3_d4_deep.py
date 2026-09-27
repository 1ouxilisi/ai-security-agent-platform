# -*- coding: utf-8 -*-
"""方向3+4 冒烟测试：导入路由、统计端点、跑 demo。"""
from __future__ import annotations

import os, sys, json
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

def count(router):
    paths = [r.path for r in router.routes]
    v2 = [p for p in paths if "/v2/" in p]
    return paths, v2

def main():
    from api_server.mobile_deep_routes import router as m_router
    from api_server.cloud_deep_routes import router as c_router

    m_paths, m_v2 = count(m_router)
    c_paths, _ = count(c_router)
    print(f"[MOBILE] total routes on router = {len(m_paths)}; v2 endpoints = {len(m_v2)}")
    for p in m_v2:
        print("   ", p)
    print(f"[CLOUD] total routes = {len(c_paths)}")
    for p in c_paths:
        print("   ", p)

    # 业务级 demo
    from mobile_deep.mobile_deep_dashboard import MobileDeepDashboard
    rep = MobileDeepDashboard().demo_assess()
    print("\n=== MOBILE DEMO ===")
    print(json.dumps({
        "package": rep["apk"]["summary"]["package"],
        "overall": rep["overall"],
        "vuln_counts": rep["vulns"]["counts"],
        "perm_overall": rep["permissions"]["overall_level"],
    }, ensure_ascii=False, indent=2))

    from cloud_deep.cloud_deep_dashboard import CloudDeepDashboard
    d = CloudDeepDashboard().demo_scan()
    print("\n=== CLOUD DEMO ===")
    print(json.dumps({
        "risk_score": d["risk"]["risk_score"],
        "risk_level": d["risk"]["risk_level"],
        "counts": d["check"]["counts"],
        "top_fixes": [x["title"] for x in d["risk"]["top_fixes"][:5]],
    }, ensure_ascii=False, indent=2))

    assert len(m_v2) >= 25, "mobile v2 endpoints < 25"
    assert len(c_paths) >= 25, "cloud endpoints < 25"
    print("\n[SMOKE OK]")

if __name__ == "__main__":
    main()
