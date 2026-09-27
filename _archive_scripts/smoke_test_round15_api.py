# -*- coding: utf-8 -*-
"""第15轮API端点冒烟测试"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fastapi.testclient import TestClient
from api_server.app import app

client = TestClient(app)

ENDPOINTS = [
    # 供应链安全
    ("POST", "/api/v1/supply-chain/sbom/generate", {"target": "project"}),
    ("GET", "/api/v1/supply-chain/sbom/list", None),
    ("GET", "/api/v1/supply-chain/sbom/components", None),
    ("GET", "/api/v1/supply-chain/sbom/dependency-tree", None),
    ("POST", "/api/v1/supply-chain/component/analyze", {"target": "pkg"}),
    ("GET", "/api/v1/supply-chain/component/list", None),
    ("GET", "/api/v1/supply-chain/component/health-criteria", None),
    ("POST", "/api/v1/supply-chain/vulnerability/scan", {"target": "pkg"}),
    ("GET", "/api/v1/supply-chain/vulnerability/database", None),
    ("GET", "/api/v1/supply-chain/vulnerability/alerts", None),
    ("POST", "/api/v1/supply-chain/license/check", {"target": "project"}),
    ("GET", "/api/v1/supply-chain/license/library", None),
    ("GET", "/api/v1/supply-chain/license/policies", None),
    ("POST", "/api/v1/supply-chain/supplier/assess", {"supplier": "test"}),
    ("GET", "/api/v1/supply-chain/supplier/list", None),
    ("GET", "/api/v1/supply-chain/supplier/scorecard", None),
    ("POST", "/api/v1/supply-chain/workflow/run", {"target": "all"}),
    ("GET", "/api/v1/supply-chain/workflow/history", None),
    # SOAR
    ("POST", "/api/v1/soar/playbook/create", {"name": "test"}),
    ("GET", "/api/v1/soar/playbook/list", None),
    ("GET", "/api/v1/soar/playbook/templates", None),
    ("POST", "/api/v1/soar/playbook/execute", {"playbook_id": "1"}),
    ("GET", "/api/v1/soar/action/library", None),
    ("GET", "/api/v1/soar/action/categories", None),
    ("POST", "/api/v1/soar/alert/triage", {"alert_id": "1"}),
    ("GET", "/api/v1/soar/alert/list", None),
    ("GET", "/api/v1/soar/alert/enriched", None),
    ("POST", "/api/v1/soar/case/create", {"title": "test"}),
    ("GET", "/api/v1/soar/case/list", None),
    ("GET", "/api/v1/soar/case/timeline", None),
    ("POST", "/api/v1/soar/execution/run", {"action": "isolate_host"}),
    ("GET", "/api/v1/soar/execution/logs", None),
    ("GET", "/api/v1/soar/metrics/dashboard", None),
    ("GET", "/api/v1/soar/metrics/mttr", None),
    ("POST", "/api/v1/soar/workflow/run", {"alert_id": "1"}),
    ("GET", "/api/v1/soar/workflow/history", None),
    # 开放API平台
    ("GET", "/api/v1/developer-portal/docs/categories", None),
    ("GET", "/api/v1/developer-portal/docs/endpoints", None),
    ("GET", "/api/v1/developer-portal/docs/openapi", None),
    ("GET", "/api/v1/developer-portal/docs/error-codes", None),
    ("GET", "/api/v1/developer-portal/sdk/list", None),
    ("GET", "/api/v1/developer-portal/sdk/postman", None),
    ("GET", "/api/v1/developer-portal/sdk/curl-examples", None),
    ("POST", "/api/v1/developer-portal/sandbox/create", {"name": "test"}),
    ("GET", "/api/v1/developer-portal/sandbox/list", None),
    ("GET", "/api/v1/developer-portal/sandbox/health", None),
    ("POST", "/api/v1/developer-portal/app/register", {"name": "test"}),
    ("GET", "/api/v1/developer-portal/app/list", None),
    ("GET", "/api/v1/developer-portal/app/scopes", None),
    ("POST", "/api/v1/developer-portal/key/create", {"app_id": "1"}),
    ("GET", "/api/v1/developer-portal/key/list", None),
    ("GET", "/api/v1/developer-portal/usage/stats", None),
    ("GET", "/api/v1/developer-portal/usage/plans", None),
    ("GET", "/api/v1/developer-portal/usage/rate-limit", None),
    ("GET", "/api/v1/developer-portal/community/posts", None),
    ("GET", "/api/v1/developer-portal/community/tutorials", None),
    ("GET", "/api/v1/developer-portal/community/faq", None),
    ("GET", "/api/v1/developer-portal/community/status", None),
    ("POST", "/api/v1/developer-portal/workflow/onboard", {"user": "test"}),
    ("GET", "/api/v1/developer-portal/workflow/overview", None),
    # 安全度量
    ("POST", "/api/v1/security-metrics/maturity/assess", {"target": "org"}),
    ("GET", "/api/v1/security-metrics/maturity/dimensions", None),
    ("GET", "/api/v1/security-metrics/maturity/roadmap", None),
    ("GET", "/api/v1/security-metrics/maturity/history", None),
    ("GET", "/api/v1/security-metrics/kpi/list", None),
    ("GET", "/api/v1/security-metrics/kpi/categories", None),
    ("GET", "/api/v1/security-metrics/kpi/thresholds", None),
    ("POST", "/api/v1/security-metrics/risk/score", {"target": "org"}),
    ("GET", "/api/v1/security-metrics/risk/trend", None),
    ("GET", "/api/v1/security-metrics/risk/heatmap", None),
    ("GET", "/api/v1/security-metrics/risk/distribution", None),
    ("GET", "/api/v1/security-metrics/efficiency/mttd", None),
    ("GET", "/api/v1/security-metrics/efficiency/mttr", None),
    ("GET", "/api/v1/security-metrics/efficiency/alerts", None),
    ("GET", "/api/v1/security-metrics/efficiency/automation-rate", None),
    ("GET", "/api/v1/security-metrics/compliance/coverage", None),
    ("GET", "/api/v1/security-metrics/compliance/frameworks", None),
    ("GET", "/api/v1/security-metrics/compliance/findings", None),
    ("GET", "/api/v1/security-metrics/compliance/remediation", None),
    ("GET", "/api/v1/security-metrics/executive/dashboard", None),
    ("GET", "/api/v1/security-metrics/executive/summary", None),
    ("GET", "/api/v1/security-metrics/executive/roi", None),
    ("POST", "/api/v1/security-metrics/workflow/run", {"target": "all"}),
    ("GET", "/api/v1/security-metrics/workflow/history", None),
]

PAGES = [
    ("/supply-chain", "供应链安全控制台"),
    ("/soar", "SOAR控制台"),
    ("/developer-portal", "开发者中心控制台"),
    ("/security-metrics", "安全度量控制台"),
]

def main():
    print("=" * 60)
    print("第15轮 API 端点冒烟测试")
    print("=" * 60)
    passed = failed = 0
    for item in ENDPOINTS:
        method, path = item[0], item[1]
        body = item[2] if len(item) > 2 else None
        try:
            if method == "GET":
                resp = client.get(path)
            else:
                resp = client.post(path, json=body or {})
            if resp.status_code < 500:
                passed += 1
            else:
                failed += 1
                print(f"  [FAIL] {method} {path} ({resp.status_code})")
                print(f"         {resp.text[:200]}")
        except Exception as e:
            failed += 1
            print(f"  [ERROR] {method} {path} -> {e}")
    print(f"\nAPI端点: {passed} 通过, {failed} 失败 (共 {len(ENDPOINTS)} 个)")

    print("\n" + "=" * 60)
    print("前端页面测试")
    print("=" * 60)
    pp = pf = 0
    for path, desc in PAGES:
        try:
            resp = client.get(path)
            if resp.status_code == 200 and len(resp.text) > 5000:
                pp += 1
                print(f"  [OK] {path} ({desc}) - {len(resp.text)} 字节")
            else:
                pf += 1
                print(f"  [FAIL] {path} ({desc}) - status={resp.status_code}, size={len(resp.text)}")
        except Exception as e:
            pf += 1
            print(f"  [ERROR] {path} -> {e}")
    print(f"\n前端页面: {pp} 通过, {pf} 失败")

    all_pass = failed == 0 and pf == 0
    print(f"\n总体: {'ALL PASS - 无500错误' if all_pass else 'HAS FAILURES'}")
    return 0 if all_pass else 1

if __name__ == "__main__":
    sys.exit(main())
