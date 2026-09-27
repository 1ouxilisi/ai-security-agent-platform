#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第7轮API端点冒烟测试 - 验证新端点不返回500"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from api_server.app import app

client = TestClient(app)

PASS = 0
FAIL = 0

def test_endpoint(name, method, path, json_data=None, expected_status=None):
    global PASS, FAIL
    try:
        if method == "GET":
            resp = client.get(path)
        elif method == "POST":
            resp = client.post(path, json=json_data or {})
        else:
            resp = client.request(method, path, json=json_data or {})

        if resp.status_code == 500:
            print(f"  [FAIL] {name} -> 500 Internal Server Error: {resp.text[:200]}")
            FAIL += 1
            return

        if expected_status and resp.status_code != expected_status:
            # 404/400/422 are acceptable for smoke test (means endpoint exists and handles input)
            if resp.status_code in (404, 400, 422, 405, 503):
                print(f"  [PASS] {name} -> {resp.status_code} (端点正常响应，非500)")
                PASS += 1
            else:
                print(f"  [WARN] {name} -> {resp.status_code} (非预期但非500)")
                PASS += 1
        else:
            print(f"  [PASS] {name} -> {resp.status_code} OK")
            PASS += 1
    except Exception as e:
        print(f"  [FAIL] {name} -> 异常: {type(e).__name__}: {e}")
        FAIL += 1

print("=" * 60)
print("第7轮 API 端点冒烟测试")
print("=" * 60)

# ===== 工作流端点 =====
print("\n【工作流 API】")
test_endpoint("GET /workflows/templates", "GET", "/api/v1/workflows/templates")
test_endpoint("GET /workflows/dag_templates", "GET", "/api/v1/workflows/dag_templates")
test_endpoint("GET /workflows (列表)", "GET", "/api/v1/workflows")
test_endpoint("GET /workflows/history", "GET", "/api/v1/workflows/history")
test_endpoint("GET /workflows/custom", "GET", "/api/v1/workflows/custom")
test_endpoint("GET /workflows/schedule", "GET", "/api/v1/workflows/schedule")
test_endpoint("POST /workflows/execute (空body)", "POST", "/api/v1/workflows/execute", {})
test_endpoint("POST /workflows/custom (空body)", "POST", "/api/v1/workflows/custom", {})

# ===== 漏洞库端点 =====
print("\n【漏洞库 API】")
test_endpoint("GET /vuln-db/cve", "GET", "/api/v1/vuln-db/cve")
test_endpoint("GET /vuln-db/cve/search?keyword=log4j", "GET", "/api/v1/vuln-db/cve/search?keyword=log4j")
test_endpoint("GET /vuln-db/cve/CVE-2021-44228", "GET", "/api/v1/vuln-db/cve/CVE-2021-44228")
test_endpoint("POST /vuln-db/cve/match", "POST", "/api/v1/vuln-db/cve/match", {"service": "Apache", "version": "2.4.49"})
test_endpoint("GET /vuln-db/exploit", "GET", "/api/v1/vuln-db/exploit")
test_endpoint("GET /vuln-db/exploit/CVE-2021-44228", "GET", "/api/v1/vuln-db/exploit/CVE-2021-44228")
test_endpoint("GET /vuln-db/remediation", "GET", "/api/v1/vuln-db/remediation")
test_endpoint("GET /vuln-db/remediation/CVE-2021-44228", "GET", "/api/v1/vuln-db/remediation/CVE-2021-44228")
test_endpoint("GET /vuln-db/stats", "GET", "/api/v1/vuln-db/stats")

# ===== 可视化端点 =====
print("\n【可视化 API】")
test_endpoint("POST /visualization/attack-path", "POST", "/api/v1/visualization/attack-path", {
    "target": "test.com", "ip": "1.2.3.4",
    "open_ports": [{"port": 80, "service": "http", "version": "Apache 2.4.49"}],
    "vulnerabilities": [{"id": "CVE-2021-41773", "name": "路径穿越", "severity": "高", "type": "路径穿越", "port": 80}]
})
test_endpoint("POST /visualization/network-topology", "POST", "/api/v1/visualization/network-topology", {
    "targets": [{"ip": "192.168.1.1", "hostname": "gw", "os": "Linux", "open_ports": [{"port": 80, "service": "http"}], "risk_level": "中", "subnet": "192.168.1.0/24"}]
})
test_endpoint("POST /visualization/risk-heatmap", "POST", "/api/v1/visualization/risk-heatmap", {
    "targets": [{"ip": "1.1.1.1", "vulnerabilities": [{"port": 80, "severity": "高", "type": "SQL注入"}]}],
    "dimension": "host_port"
})
test_endpoint("GET /visualization/trend", "GET", "/api/v1/visualization/trend")
test_endpoint("GET /visualization/formats", "GET", "/api/v1/visualization/formats")

# ===== 前端页面 =====
print("\n【前端页面】")
test_endpoint("GET /workflow-console", "GET", "/workflow-console")

print("\n" + "=" * 60)
print(f"冒烟测试结果: {PASS} 通过, {FAIL} 失败 (500错误数: {FAIL})")
print("=" * 60)

sys.exit(0 if FAIL == 0 else 1)
