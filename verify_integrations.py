#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
集成生态升级验证脚本。

逐项验收：
1. 所有模块导入无报错
2. 配置加载/保存、test_connection 可运行（不连接真实系统也返回合理结果）
3. SIEM CEF/LEEF/syslog 格式化输出正确
4. 通知渠道 payload 构建函数输出正确 JSON
5. 漏洞库本地搜索空库不报错；NVD 请求构造正确（mock）
6. API 路由可注册
"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, cond, detail=""):
    status = PASS if cond else FAIL
    results.append((status, name, detail))
    print(f"[{status}] {name}  {detail}")


print("=" * 70)
print("1. 模块导入")
print("=" * 70)
try:
    from integrations.siem_connector import SIEMConnector, siem_connector
    from integrations.ticket_connector import TicketConnector, ticket_connector
    from integrations.notification_channels import NotificationManager, notification_manager
    from integrations.ldap_auth import LDAPAuth, ldap_auth, LDAP_AVAILABLE
    from integrations.vuln_db_sync import VulnDBSync, vuln_db_sync
    check("导入五大集成模块", True)
except Exception as e:
    check("导入五大集成模块", False, repr(e))
    sys.exit(1)

print("python-ldap 可用:", LDAP_AVAILABLE)

print("=" * 70)
print("2. 配置加载/保存 与 test_connection")
print("=" * 70)
# SIEM
siem_connector.update_config({"enabled": False, "server": "127.0.0.1", "port": 514, "format": "cef"})
check("SIEM 配置读写", os.path.exists(os.path.join(ROOT, "config", "siem_config.json")))
r = siem_connector.test_connection()
check("SIEM test_connection 返回 dict", isinstance(r, dict) and "success" in r, str(r))

# Ticket
r = ticket_connector.test_connection()
check("工单 test_connection 不崩溃", isinstance(r, dict) and "success" in r, str(r))

# LDAP
r = ldap_auth.test_connection()
check("LDAP test_connection 不崩溃", isinstance(r, dict) and "success" in r, str(r))
# LDAP 模拟认证
ldap_auth.update_config({"mock_mode": True, "enabled": True})
r = ldap_auth.authenticate("alice", "secret123")
check("LDAP mock 认证", r.get("success") is True and "analyst" in r.get("roles", []) or "viewer" in r.get("roles", []), str(r))

# 通知渠道状态
r = notification_manager.get_channel_status()
check("通知渠道状态", "channels" in r and "wecom" in r["channels"], str(r))

print("=" * 70)
print("3. SIEM 消息格式化")
print("=" * 70)
ev = {"title": "发现 Webshell", "content": "upload.php", "severity": "critical",
      "target": "10.0.0.5", "id": "SIG-001"}

syslog_msg = siem_connector.format_syslog(ev)
check("syslog 以 <PRI>1 开头", syslog_msg.startswith("<") and ">1 " in syslog_msg, syslog_msg[:80])

siem_connector.config["format"] = "cef"
cef_msg = siem_connector.format_cef(ev)
check("CEF 格式正确", cef_msg.startswith("CEF:0|") and cef_msg.count("|") >= 6, cef_msg)

siem_connector.config["format"] = "leef"
leef_msg = siem_connector.format_leef(ev)
check("LEEF 格式正确", leef_msg.startswith("LEEF:2.0|"), leef_msg)

batch = siem_connector.send_batch([ev, ev])
check("send_batch 不崩溃", "total" in batch and batch["total"] == 2, str(batch))

print("=" * 70)
print("4. 通知渠道 payload 构建")
print("=" * 70)
alert = {"title": "高危漏洞", "content": "RCE", "severity": "high", "target": "10.0.0.9"}
wc = notification_manager.build_wecom_payload(alert)
check("企业微信 payload", wc.get("msgtype") == "markdown" and "content" in wc.get("markdown", {}), str(wc)[:80])
dt = notification_manager.build_dingtalk_payload(alert)
check("钉钉 payload", dt.get("msgtype") == "markdown" and "title" in dt.get("markdown", {}), str(dt)[:80])
fs = notification_manager.build_feishu_payload(alert)
check("飞书卡片 payload", fs.get("msg_type") == "interactive" and "card" in fs, str(fs)[:80])
wh = notification_manager.build_webhook_payload(alert)
check("通用 webhook payload", wh.get("event") == "security_alert", str(wh)[:80])
# 单渠道失败不影响其他：send_alert 对未配置渠道应全部返回结果而非抛错
r = notification_manager.send_alert(alert, channels=["wecom", "email", "webhook"])
check("send_alert 多渠道容错", "results" in r and len(r["results"]) == 3, str(r)[:100])

print("=" * 70)
print("5. 漏洞库：空库搜索 + NVD 请求构造(mock)")
print("=" * 70)
r = vuln_db_sync.search_local("nonexistent-xyz")
check("空库搜索不报错", isinstance(r, dict) and "results" in r and r["total"] == 0, str(r))

# mock NVD 请求，验证请求构造与解析入库
class FakeResp:
    status_code = 200
    content = b"{}"
    def json(self):
        return {"totalResults": 1, "vulnerabilities": [
            {"cve": {
                "id": "CVE-2024-99999",
                "published": "2024-01-01T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Mock RCE vuln"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 9.8}}]},
                "weaknesses": [{"description": [{"value": "CWE-78"}]}],
                "references": [{"url": "https://example.com/advisory"}],
            }}
        ]}

captured = {}
def fake_get(url, **kwargs):
    captured["url"] = url
    captured["params"] = kwargs.get("params")
    return FakeResp()

import integrations.vuln_db_sync as vd_mod
orig_get = vd_mod.requests.get
vd_mod.requests.get = fake_get
try:
    r = vuln_db_sync.sync_nvd(keyword="openssl", max_results=10, sleep_between=False)
finally:
    vd_mod.requests.get = orig_get

check("NVD 请求 URL 正确", captured.get("url", "").endswith("/rest/json/cves/2.0"), captured.get("url", ""))
check("NVD keyword 参数正确", (captured.get("params") or {}).get("keywordSearch") == "openssl", str(captured.get("params")))
check("NVD mock 入库", r.get("synced") == 1, str(r))
detail = vuln_db_sync.get_cve_detail("CVE-2024-99999")
check("NVD 入库后可查询", detail.get("found") and detail["cve"]["severity"] == "high", str(detail.get("cve", {}))[:100])
stats = vuln_db_sync.get_stats()
check("漏洞库统计", stats.get("total_cves", 0) >= 1, str(stats))

print("=" * 70)
print("6. API 路由可注册")
print("=" * 70)
try:
    from fastapi import FastAPI
    from api_server.integrations_routes import router
    app = FastAPI()
    try:
        app.include_router(router)
    except Exception as e:
        check("路由 include_router", False, repr(e))
    routes = [getattr(rt, "path", "") for rt in app.routes]
    expected = ["/api/v1/integrations/siem/config",
                "/api/v1/integrations/ticket/config",
                "/api/v1/integrations/notification/channels",
                "/api/v1/integrations/ldap/config",
                "/api/v1/integrations/vuln-db/search"]
    missing = [p for p in expected if p not in routes]
    check("路由注册 5 大组端点", not missing, f"missing={missing}, total_routes={len(routes)}")
except Exception as e:
    check("API 路由导入/注册", False, repr(e))

print("=" * 70)
print("汇总")
print("=" * 70)
n_pass = sum(1 for s, _, _ in results if s == PASS)
n_fail = sum(1 for s, _, _ in results if s == FAIL)
print(f"通过 {n_pass} / {len(results)}，失败 {n_fail}")
for s, n, d in results:
    if s == FAIL:
        print(f"  FAILED: {n} -> {d}")
sys.exit(0 if n_fail == 0 else 1)
