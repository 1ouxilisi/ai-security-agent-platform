#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第5轮升级关键端点快速验证"""
import sys
import json
sys.path.insert(0, '.')

from fastapi.testclient import TestClient
from api_server.app import app

client = TestClient(app)

results = []

def test_endpoint(name, method, path, json_data=None, params=None):
    try:
        if method == "GET":
            resp = client.get(path, params=params, timeout=10)
        else:
            resp = client.post(path, json=json_data or {}, timeout=15)
        status = resp.status_code
        is_500 = status == 500
        body_preview = resp.text[:200] if resp.text else ""
        results.append({
            "name": name,
            "method": method,
            "path": path,
            "status": status,
            "is_500": is_500,
            "ok": status < 500,
            "preview": body_preview[:150],
        })
        print(f"  {'PASS' if status < 500 else 'FAIL'} [{status}] {method} {path}")
        if status < 500 and resp.text:
            try:
                data = resp.json()
                if isinstance(data, dict):
                    keys = list(data.keys())[:5]
                    print(f"       keys: {keys}")
            except Exception:
                pass
    except Exception as e:
        results.append({
            "name": name,
            "method": method,
            "path": path,
            "status": -1,
            "is_500": False,
            "ok": False,
            "error": str(e)[:200],
        })
        print(f"  ERROR {method} {path}: {e}")

print("=" * 60)
print("第5轮升级关键端点验证")
print("=" * 60)

# 1. 增强健康检查
print("\n[1] 增强健康检查")
test_endpoint("health", "GET", "/health")

# 2. AI服务状态
print("\n[2] AI服务状态")
test_endpoint("ai_status", "GET", "/api/v1/ai/status")

# 3. 实战模块状态
print("\n[3] 实战模块状态")
test_endpoint("pentest_status", "GET", "/api/v1/pentest/status")

# 4. 内网工具状态
print("\n[4] 内网工具状态")
test_endpoint("tools_status", "GET", "/api/v1/pentest/tools/status")

# 5. AI助手对话（测试消息）
print("\n[5] AI助手对话")
test_endpoint("ai_assistant", "POST", "/api/v1/ai/assistant",
              json_data={"message": "什么是SQL注入？", "session_id": "test_e2e"})

# 6. 自然语言对话（扫描意图）
print("\n[6] 自然语言对话-扫描意图")
test_endpoint("nl_chat", "POST", "/api/v1/ai/chat",
              json_data={"message": "扫描192.168.1.1的端口", "session_id": "test_e2e"})

# 7. 漏洞验证
print("\n[7] 漏洞自动验证")
test_endpoint("vuln_verify", "POST", "/api/v1/ai/verify",
              json_data={"vuln_description": "SQL注入漏洞", "target": "http://example.com/page?id=1", "cve": ""})

# 8. 修复方案生成
print("\n[8] 修复方案生成")
test_endpoint("remediation", "POST", "/api/v1/ai/remediation",
              json_data={"vuln_description": "SQL注入漏洞", "vuln_type": "sql_injection", "target_env": {"os": "linux", "web_server": "nginx"}})

# 9. 域安全审计（用测试目标）
print("\n[9] 域安全审计")
test_endpoint("domain_audit", "POST", "/api/v1/pentest/domain/audit",
              json_data={"dc_ip": "127.0.0.1", "domain": "test.local"})

# 10. 横向移动检测
print("\n[10] 横向移动风险检测")
test_endpoint("lateral_detect", "POST", "/api/v1/pentest/lateral/detect",
              json_data={"target_network": "127.0.0.1", "options": {}})

# 11. 凭据审计
print("\n[11] 凭据安全审计")
test_endpoint("credential_audit", "POST", "/api/v1/pentest/credential/audit",
              json_data={"target": "127.0.0.1", "service": "ssh", "username": "admin"})

# 12. AI助手页面
print("\n[12] AI助手前端页面")
test_endpoint("ai_page", "GET", "/ai-assistant")

# 13. 对话历史
print("\n[13] 对话历史")
test_endpoint("chat_history", "GET", "/api/v1/ai/chat/history", params={"session_id": "test_e2e"})

# 14. BloodHound图数据
print("\n[14] BloodHound图数据")
test_endpoint("bh_graph", "GET", "/api/v1/pentest/bloodhound/graph")

# 汇总
print("\n" + "=" * 60)
total = len(results)
passed = sum(1 for r in results if r.get("ok"))
failed = total - passed
server_500 = sum(1 for r in results if r.get("is_500"))
print(f"总计: {total} | 通过: {passed} | 失败: {failed} | 500错误: {server_500}")
print(f"通过率: {passed/total*100:.1f}%")
if server_500 == 0:
    print("✅ 0个500错误")
else:
    print("❌ 存在500错误")
print("=" * 60)

# 保存报告
with open("tests/round5_quick_test_report.json", "w", encoding="utf-8") as f:
    json.dump({"total": total, "passed": passed, "failed": failed,
               "server_500": server_500, "results": results}, f,
              ensure_ascii=False, indent=2)
print("报告已保存: tests/round5_quick_test_report.json")
