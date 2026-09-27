# -*- coding: utf-8 -*-
"""第14轮API端点冒烟测试"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fastapi.testclient import TestClient
from api_server.app import app

client = TestClient(app)

ENDPOINTS = [
    # DevSecOps
    ("POST", "/api/v1/devsecops/pipeline/audit", {"target": "repo"}),
    ("GET", "/api/v1/devsecops/pipeline/rules", None),
    ("GET", "/api/v1/devsecops/pipeline/history", None),
    ("POST", "/api/v1/devsecops/repo/audit", {"target": "repo"}),
    ("GET", "/api/v1/devsecops/repo/rules", None),
    ("GET", "/api/v1/devsecops/repo/history", None),
    ("POST", "/api/v1/devsecops/build/scan", {"target": "image"}),
    ("GET", "/api/v1/devsecops/build/rules", None),
    ("GET", "/api/v1/devsecops/build/history", None),
    ("POST", "/api/v1/devsecops/deploy/audit", {"target": "k8s"}),
    ("GET", "/api/v1/devsecops/deploy/rules", None),
    ("GET", "/api/v1/devsecops/deploy/history", None),
    ("POST", "/api/v1/devsecops/gate/evaluate", {"target": "pipeline"}),
    ("GET", "/api/v1/devsecops/gate/policies", None),
    ("GET", "/api/v1/devsecops/gate/history", None),
    ("POST", "/api/v1/devsecops/maturity/assess", {"target": "org"}),
    ("GET", "/api/v1/devsecops/maturity/roadmap", None),
    ("GET", "/api/v1/devsecops/maturity/history", None),
    ("POST", "/api/v1/devsecops/workflow/run", {"target": "all"}),
    ("GET", "/api/v1/devsecops/workflow/history", None),
    # 安全培训
    ("POST", "/api/v1/security-training/course/create", {"title": "test"}),
    ("GET", "/api/v1/security-training/course/list", None),
    ("GET", "/api/v1/security-training/course/categories", None),
    ("GET", "/api/v1/security-training/course/recommendations", None),
    ("POST", "/api/v1/security-training/lab/start", {"lab_id": "1"}),
    ("GET", "/api/v1/security-training/lab/list", None),
    ("GET", "/api/v1/security-training/lab/targets", None),
    ("POST", "/api/v1/security-training/exam/create", {"title": "test"}),
    ("GET", "/api/v1/security-training/exam/list", None),
    ("GET", "/api/v1/security-training/exam/question-bank", None),
    ("GET", "/api/v1/security-training/exam/certificates", None),
    ("POST", "/api/v1/security-training/phishing/launch", {"campaign": "test"}),
    ("GET", "/api/v1/security-training/phishing/templates", None),
    ("GET", "/api/v1/security-training/phishing/results", None),
    ("POST", "/api/v1/security-training/awareness/assess", {"user": "test"}),
    ("GET", "/api/v1/security-training/awareness/questions", None),
    ("GET", "/api/v1/security-training/awareness/reports", None),
    ("GET", "/api/v1/security-training/operations/students", None),
    ("GET", "/api/v1/security-training/operations/instructors", None),
    ("GET", "/api/v1/security-training/operations/dashboard", None),
    ("POST", "/api/v1/security-training/workflow/run", {"target": "all"}),
    ("GET", "/api/v1/security-training/workflow/history", None),
    # 专业报告引擎
    ("POST", "/api/v1/report-engine/template/create", {"name": "test"}),
    ("GET", "/api/v1/report-engine/template/list", None),
    ("GET", "/api/v1/report-engine/template/categories", None),
    ("GET", "/api/v1/report-engine/template/industries", None),
    ("POST", "/api/v1/report-engine/generate/run", {"template_id": "1"}),
    ("GET", "/api/v1/report-engine/generate/reports", None),
    ("POST", "/api/v1/report-engine/quality/check", {"report_id": "1"}),
    ("GET", "/api/v1/report-engine/quality/history", None),
    ("GET", "/api/v1/report-engine/export/formats", None),
    ("POST", "/api/v1/report-engine/export/run", {"report_id": "1", "format": "pdf"}),
    ("POST", "/api/v1/report-engine/collab/create", {"title": "test"}),
    ("GET", "/api/v1/report-engine/collab/list", None),
    ("GET", "/api/v1/report-engine/collab/history", None),
    ("GET", "/api/v1/report-engine/analytics/dashboard", None),
    ("GET", "/api/v1/report-engine/analytics/search", None),
    ("POST", "/api/v1/report-engine/workflow/run", {"target": "all"}),
    ("GET", "/api/v1/report-engine/workflow/history", None),
    # 安全服务交付
    ("POST", "/api/v1/service-delivery/project/create", {"name": "test"}),
    ("GET", "/api/v1/service-delivery/project/list", None),
    ("GET", "/api/v1/service-delivery/project/types", None),
    ("GET", "/api/v1/service-delivery/project/gantt", None),
    ("GET", "/api/v1/service-delivery/customer/list", None),
    ("GET", "/api/v1/service-delivery/customer/contracts", None),
    ("GET", "/api/v1/service-delivery/customer/invoices", None),
    ("POST", "/api/v1/service-delivery/billing/timesheet", {"hours": 8}),
    ("GET", "/api/v1/service-delivery/billing/rates", None),
    ("GET", "/api/v1/service-delivery/billing/invoices", None),
    ("GET", "/api/v1/service-delivery/billing/profit", None),
    ("GET", "/api/v1/service-delivery/sla/templates", None),
    ("GET", "/api/v1/service-delivery/sla/monitor", None),
    ("GET", "/api/v1/service-delivery/sla/reports", None),
    ("GET", "/api/v1/service-delivery/deliverable/list", None),
    ("GET", "/api/v1/service-delivery/deliverable/templates", None),
    ("GET", "/api/v1/service-delivery/deliverable/archive", None),
    ("GET", "/api/v1/service-delivery/team/members", None),
    ("GET", "/api/v1/service-delivery/team/skills", None),
    ("GET", "/api/v1/service-delivery/team/utilization", None),
    ("GET", "/api/v1/service-delivery/team/dashboard", None),
    ("POST", "/api/v1/service-delivery/workflow/run", {"target": "all"}),
    ("GET", "/api/v1/service-delivery/workflow/history", None),
]

PAGES = [
    ("/devsecops", "DevSecOps控制台"),
    ("/security-training", "安全培训控制台"),
    ("/report-engine", "报告引擎控制台"),
    ("/service-delivery", "服务交付控制台"),
]

def main():
    print("=" * 60)
    print("第14轮 API 端点冒烟测试")
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
