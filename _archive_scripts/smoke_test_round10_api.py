"""
第10轮 API 冒烟测试：验证新端点不返回500错误
"""
import os
import sys
import json

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

results = {"pass": 0, "fail": 0, "errors": []}

def check(name, condition, detail=""):
    if condition:
        results["pass"] += 1
        print(f"  [PASS] {name}")
    else:
        results["fail"] += 1
        results["errors"].append(f"{name}: {detail}")
        print(f"  [FAIL] {name} - {detail}")

print("=" * 60)
print("第10轮 API 冒烟测试（无500错误验证）")
print("=" * 60)

try:
    from fastapi.testclient import TestClient
    from api_server.app import app
    client = TestClient(app)
    check("TestClient 创建成功", True)
except Exception as e:
    check("TestClient 创建成功", False, str(e)[:200])
    sys.exit(1)

# 测试每个新模块的代表性GET端点（不会有副作用）
test_endpoints = [
    # AI SOC
    ("/api/v1/ai-soc/event/stats", "AI SOC 事件分类统计"),
    ("/api/v1/ai-soc/assistant/knowledge/search?query=漏洞", "AI SOC 知识检索"),
    # 性能
    ("/api/v1/performance/queries/stats", "性能 查询统计"),
    ("/api/v1/performance/indexes/stats", "性能 索引统计"),
    ("/api/v1/performance/cache/status", "性能 缓存状态"),
    ("/api/v1/performance/api/endpoints", "性能 API端点列表"),
    ("/api/v1/performance/db/connections", "性能 DB连接"),
    # SaaS
    ("/api/v1/saas/users/stats", "SaaS 用户统计"),
    ("/api/v1/saas/invitations/stats", "SaaS 邀请统计"),
    ("/api/v1/saas/mfa/methods", "SaaS MFA方法列表"),
    ("/api/v1/saas/tenants", "SaaS 租户列表"),
    # 可视化V2
    ("/api/v1/visualization-v2/realtime/data", "可视化 实时数据"),
    ("/api/v1/visualization-v2/realtime/metrics", "可视化 实时指标"),
    ("/api/v1/visualization-v2/dashboards/templates", "可视化 模板列表"),
    ("/api/v1/visualization-v2/dashboards/components", "可视化 组件列表"),
    # API网关
    ("/api/v1/api-gateway/rate-limit/stats", "网关 限流统计"),
    ("/api/v1/api-gateway/circuit-breaker/status", "网关 熔断状态"),
    ("/api/v1/api-gateway/degradation/stats", "网关 降级统计"),
    ("/api/v1/api-gateway/cache/status", "网关 缓存状态"),
    ("/api/v1/api-gateway/logs/stats", "网关 日志统计"),
    ("/api/v1/api-gateway/monitor/endpoints", "网关 监控端点"),
    # 备份
    ("/api/v1/backup/list", "备份 列表"),
    ("/api/v1/backup/stats", "备份 统计"),
    ("/api/v1/backup/schedule", "备份 计划列表"),
    ("/api/v1/backup/export/list", "备份 导出列表"),
    ("/api/v1/backup/export/stats", "备份 导出统计"),
    # SSO
    ("/api/v1/sso/providers", "SSO 提供商列表"),
    ("/api/v1/sso/stats", "SSO 统计"),
    ("/api/v1/sso/saml/config", "SSO SAML配置列表"),
    ("/api/v1/sso/oauth2/config", "SSO OAuth2配置列表"),
    ("/api/v1/sso/ldap/config", "SSO LDAP配置列表"),
]

print(f"\n测试 {len(test_endpoints)} 个GET端点...")
for endpoint, desc in test_endpoints:
    try:
        resp = client.get(endpoint)
        status = resp.status_code
        no_500 = status < 500
        # 检查响应体是否可解析为JSON
        try:
            body = resp.json()
            has_success = "success" in body or "data" in body or isinstance(body, list)
        except:
            has_success = True  # 非JSON响应也可以接受

        check(f"{desc} (HTTP {status})", no_500 and has_success,
              f"状态码={status}, 响应体前100字={resp.text[:100]}")
    except Exception as e:
        check(f"{desc}", False, f"异常: {str(e)[:150]}")

# 测试POST端点（创建操作，使用测试数据）
print(f"\n测试POST端点...")
post_tests = [
    ("/api/v1/ai-soc/event/classify", {"title": "测试事件", "description": "SQL注入尝试", "severity": "high"}, "AI SOC 事件分类"),
    ("/api/v1/ai-soc/response/advise", {"event_type": "intrusion", "severity": "high", "description": "测试"}, "AI SOC 响应建议"),
    ("/api/v1/performance/cache/clear", {}, "性能 清除缓存"),
    ("/api/v1/api-gateway/cache/clear", {}, "网关 清除缓存"),
    ("/api/v1/saas/auth/register", {"username": "test_user_v10", "email": "test_v10@example.com", "password": "Test@123456"}, "SaaS 用户注册"),
]

for endpoint, payload, desc in post_tests:
    try:
        resp = client.post(endpoint, json=payload)
        status = resp.status_code
        no_500 = status < 500
        check(f"{desc} (HTTP {status})", no_500,
              f"状态码={status}, 响应体前100字={resp.text[:100]}")
    except Exception as e:
        check(f"{desc}", False, f"异常: {str(e)[:150]}")

# 测试前端页面
print(f"\n测试前端页面...")
pages = [
    ("/saas-console", "SaaS控制台"),
    ("/realtime-dashboard", "实时大屏"),
    ("/custom-dashboard", "自定义仪表盘"),
    ("/backup-console", "备份控制台"),
    ("/sso-console", "SSO控制台"),
]

for page, desc in pages:
    try:
        resp = client.get(page)
        status = resp.status_code
        content_len = len(resp.text)
        no_500 = status < 500
        non_blank = content_len > 1000
        check(f"{desc} (HTTP {status}, {content_len}字节)", no_500 and non_blank,
              f"状态码={status}, 长度={content_len}")
    except Exception as e:
        check(f"{desc}", False, f"异常: {str(e)[:150]}")

# 汇总
print("\n" + "=" * 60)
print("API冒烟测试汇总")
print("=" * 60)
print(f"  通过: {results['pass']}")
print(f"  失败: {results['fail']}")
print(f"  总计: {results['pass'] + results['fail']}")
if results['fail'] > 0:
    print(f"\n失败项:")
    for err in results['errors']:
        print(f"  - {err}")
print("=" * 60)

sys.exit(0 if results['fail'] == 0 else 1)
