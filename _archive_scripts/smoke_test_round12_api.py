# -*- coding: utf-8 -*-
"""第12轮API端点冒烟测试"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fastapi.testclient import TestClient
from api_server.app import app

client = TestClient(app)

ENDPOINTS = [
    # IoT安全
    ("POST", "/api/v1/iot-security/discovery/scan", {"target": "192.168.1.0/24"}),
    ("GET", "/api/v1/iot-security/devices/list", None),
    ("POST", "/api/v1/iot-security/firmware/analyze", {"path": "/tmp/firmware.bin"}),
    ("POST", "/api/v1/iot-security/protocol/analyze", {"target": "192.168.1.100"}),
    ("GET", "/api/v1/iot-security/protocol/supported", None),
    ("POST", "/api/v1/iot-security/credentials/check", {"target": "192.168.1.100"}),
    ("GET", "/api/v1/iot-security/credentials/database", None),
    ("POST", "/api/v1/iot-security/communication/analyze", {"target": "192.168.1.100"}),
    ("POST", "/api/v1/iot-security/vulnerability/scan", {"target": "192.168.1.100"}),
    ("GET", "/api/v1/iot-security/vulnerability/database", None),
    ("POST", "/api/v1/iot-security/assessment/run", {"target": "192.168.1.0/24"}),
    ("GET", "/api/v1/iot-security/assessment/history", None),
    # 工控安全
    ("POST", "/api/v1/ics-security/discovery/scan", {"target": "192.168.0.0/24"}),
    ("GET", "/api/v1/ics-security/assets/list", None),
    ("POST", "/api/v1/ics-security/protocol/analyze", {"target": "192.168.0.10"}),
    ("GET", "/api/v1/ics-security/protocol/supported", None),
    ("POST", "/api/v1/ics-security/vulnerability/scan", {"target": "192.168.0.10"}),
    ("GET", "/api/v1/ics-security/vulnerability/database", None),
    ("POST", "/api/v1/ics-security/baseline/check", {"target": "192.168.0.10"}),
    ("GET", "/api/v1/ics-security/baseline/rules", None),
    ("POST", "/api/v1/ics-security/anomaly/detect", {"target": "192.168.0.10"}),
    ("GET", "/api/v1/ics-security/anomaly/alerts", None),
    ("GET", "/api/v1/ics-security/threat/iocs", None),
    ("GET", "/api/v1/ics-security/threat/campaigns", None),
    ("POST", "/api/v1/ics-security/assessment/run", {"target": "192.168.0.0/24"}),
    ("GET", "/api/v1/ics-security/assessment/history", None),
    # 无线网络安全
    ("POST", "/api/v1/wireless-security/wifi/scan", {"interface": "wlan0"}),
    ("GET", "/api/v1/wireless-security/wifi/aps", None),
    ("GET", "/api/v1/wireless-security/wifi/clients", None),
    ("POST", "/api/v1/wireless-security/wifi/security/assess", {"bssid": "00:11:22:33:44:55"}),
    ("GET", "/api/v1/wireless-security/wifi/security/dictionary", None),
    ("POST", "/api/v1/wireless-security/evil-twin/detect", {"ssid": "TestWiFi"}),
    ("POST", "/api/v1/wireless-security/bluetooth/scan", {"interface": "hci0"}),
    ("GET", "/api/v1/wireless-security/bluetooth/devices", None),
    ("POST", "/api/v1/wireless-security/zigbee/scan", {"channel": 15}),
    ("POST", "/api/v1/wireless-security/spectrum/analyze", {"band": "2.4g"}),
    ("POST", "/api/v1/wireless-security/assessment/run", {"interface": "wlan0"}),
    ("GET", "/api/v1/wireless-security/assessment/history", None),
    # API安全专业级
    ("POST", "/api/v1/api-security-pro/openapi/parse", {"url": "http://example.com/openapi.json"}),
    ("GET", "/api/v1/api-security-pro/openapi/endpoints", None),
    ("POST", "/api/v1/api-security-pro/auth/test", {"target": "http://example.com/api"}),
    ("GET", "/api/v1/api-security-pro/auth/payloads", None),
    ("POST", "/api/v1/api-security-pro/injection/test", {"target": "http://example.com/api"}),
    ("GET", "/api/v1/api-security-pro/injection/payloads", None),
    ("POST", "/api/v1/api-security-pro/business-logic/detect", {"target": "http://example.com/api"}),
    ("POST", "/api/v1/api-security-pro/security-config/check", {"target": "http://example.com/api"}),
    ("POST", "/api/v1/api-security-pro/fuzz/run", {"target": "http://example.com/api"}),
    ("GET", "/api/v1/api-security-pro/fuzz/payloads", None),
    ("POST", "/api/v1/api-security-pro/scan/run", {"target": "http://example.com/api"}),
    ("GET", "/api/v1/api-security-pro/scan/history", None),
]

PAGES = [
    ("/iot-security", "物联网安全控制台"),
    ("/ics-security", "工控安全控制台"),
    ("/wireless-security", "无线网络安全控制台"),
    ("/api-security-pro", "API安全专业级控制台"),
]

def main():
    print("=" * 60)
    print("第12轮 API 端点冒烟测试")
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
                print(f"  [OK] {method} {path} ({resp.status_code})")
            else:
                failed += 1
                print(f"  [FAIL] {method} {path} ({resp.status_code})")
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
