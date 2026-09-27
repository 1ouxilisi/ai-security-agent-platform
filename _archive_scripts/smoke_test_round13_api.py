# -*- coding: utf-8 -*-
"""第13轮API端点冒烟测试"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fastapi.testclient import TestClient
from api_server.app import app

client = TestClient(app)

ENDPOINTS = [
    # 数据安全
    ("POST", "/api/v1/data-security/classification/scan", {"path": "/tmp/data"}),
    ("GET", "/api/v1/data-security/classification/types", None),
    ("GET", "/api/v1/data-security/classification/assets", None),
    ("POST", "/api/v1/data-security/dlp/scan", {"path": "/tmp/data"}),
    ("GET", "/api/v1/data-security/dlp/policies", None),
    ("GET", "/api/v1/data-security/dlp/events", None),
    ("POST", "/api/v1/data-security/privacy/assess", {"target": "example.com"}),
    ("GET", "/api/v1/data-security/privacy/frameworks", None),
    ("GET", "/api/v1/data-security/privacy/dpia", None),
    ("POST", "/api/v1/data-security/encryption/check", {"target": "example.com"}),
    ("GET", "/api/v1/data-security/encryption/algorithms", None),
    ("GET", "/api/v1/data-security/encryption/certificates", None),
    ("POST", "/api/v1/data-security/access/audit", {"target": "example.com"}),
    ("GET", "/api/v1/data-security/access/matrix", None),
    ("GET", "/api/v1/data-security/access/anomalies", None),
    ("POST", "/api/v1/data-security/assessment/run", {"target": "example.com"}),
    ("GET", "/api/v1/data-security/assessment/history", None),
    # 零信任
    ("POST", "/api/v1/zero-trust/identity/assess", {"target": "example.com"}),
    ("GET", "/api/v1/zero-trust/identity/users", None),
    ("GET", "/api/v1/zero-trust/identity/privileged", None),
    ("POST", "/api/v1/zero-trust/verification/evaluate", {"target": "example.com"}),
    ("GET", "/api/v1/zero-trust/verification/risk-scores", None),
    ("GET", "/api/v1/zero-trust/verification/policies", None),
    ("POST", "/api/v1/zero-trust/microsegmentation/analyze", {"target": "example.com"}),
    ("GET", "/api/v1/zero-trust/microsegmentation/topology", None),
    ("GET", "/api/v1/zero-trust/microsegmentation/policies", None),
    ("POST", "/api/v1/zero-trust/device/assess", {"target": "example.com"}),
    ("GET", "/api/v1/zero-trust/device/inventory", None),
    ("GET", "/api/v1/zero-trust/device/compliance", None),
    ("POST", "/api/v1/zero-trust/application/assess", {"target": "example.com"}),
    ("GET", "/api/v1/zero-trust/application/services", None),
    ("GET", "/api/v1/zero-trust/application/api-gateway", None),
    ("POST", "/api/v1/zero-trust/maturity/assess", {"target": "example.com"}),
    ("GET", "/api/v1/zero-trust/maturity/roadmap", None),
    ("GET", "/api/v1/zero-trust/maturity/history", None),
    # 蜜罐欺骗
    ("POST", "/api/v1/deception/honeypot/deploy", {"type": "ssh", "port": 2222}),
    ("GET", "/api/v1/deception/honeypot/list", None),
    ("GET", "/api/v1/deception/honeypot/types", None),
    ("POST", "/api/v1/deception/attack/detect", {"target": "honeypot-1"}),
    ("GET", "/api/v1/deception/attack/alerts", None),
    ("GET", "/api/v1/deception/attack/attack-chain", None),
    ("POST", "/api/v1/deception/threat/generate", {"target": "honeypot-1"}),
    ("GET", "/api/v1/deception/threat/iocs", None),
    ("GET", "/api/v1/deception/threat/actors", None),
    ("GET", "/api/v1/deception/threat/export", None),
    ("POST", "/api/v1/deception/decoy/create", {"type": "file"}),
    ("GET", "/api/v1/deception/decoy/list", None),
    ("GET", "/api/v1/deception/decoy/types", None),
    ("GET", "/api/v1/deception/decoy/detections", None),
    ("POST", "/api/v1/deception/honeynet/deploy", {"nodes": 3}),
    ("GET", "/api/v1/deception/honeynet/list", None),
    ("GET", "/api/v1/deception/honeynet/topology", None),
    ("GET", "/api/v1/deception/honeynet/health", None),
    ("POST", "/api/v1/deception/operations/assess", {"target": "all"}),
    ("GET", "/api/v1/deception/operations/metrics", None),
    ("GET", "/api/v1/deception/operations/history", None),
    # 暗网监控DRP
    ("POST", "/api/v1/darkweb-monitor/intel/monitor", {"keyword": "example.com"}),
    ("GET", "/api/v1/darkweb-monitor/intel/sources", None),
    ("GET", "/api/v1/darkweb-monitor/intel/alerts", None),
    ("GET", "/api/v1/darkweb-monitor/intel/keywords", None),
    ("POST", "/api/v1/darkweb-monitor/credential/check", {"email": "test@example.com"}),
    ("GET", "/api/v1/darkweb-monitor/credential/leaked", None),
    ("GET", "/api/v1/darkweb-monitor/credential/api-keys", None),
    ("GET", "/api/v1/darkweb-monitor/credential/reset-suggestions", None),
    ("POST", "/api/v1/darkweb-monitor/brand/monitor", {"brand": "example"}),
    ("GET", "/api/v1/darkweb-monitor/brand/typosquatting", None),
    ("GET", "/api/v1/darkweb-monitor/brand/phishing", None),
    ("GET", "/api/v1/darkweb-monitor/brand/fake-apps", None),
    ("GET", "/api/v1/darkweb-monitor/brand/risk-score", None),
    ("POST", "/api/v1/darkweb-monitor/breach/analyze", {"file": "breach.csv"}),
    ("GET", "/api/v1/darkweb-monitor/breach/timeline", None),
    ("GET", "/api/v1/darkweb-monitor/breach/impact", None),
    ("GET", "/api/v1/darkweb-monitor/breach/compliance", None),
    ("POST", "/api/v1/darkweb-monitor/actor/analyze", {"actor": "APT28"}),
    ("GET", "/api/v1/darkweb-monitor/actor/list", None),
    ("GET", "/api/v1/darkweb-monitor/actor/ttps", None),
    ("POST", "/api/v1/darkweb-monitor/operations/assess", {"target": "all"}),
    ("GET", "/api/v1/darkweb-monitor/operations/dashboard", None),
    ("GET", "/api/v1/darkweb-monitor/operations/history", None),
]

PAGES = [
    ("/data-security", "数据安全控制台"),
    ("/zero-trust", "零信任控制台"),
    ("/deception", "蜜罐欺骗控制台"),
    ("/darkweb-monitor", "暗网监控控制台"),
]

def main():
    print("=" * 60)
    print("第13轮 API 端点冒烟测试")
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
