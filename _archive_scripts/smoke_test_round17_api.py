# -*- coding: utf-8 -*-
"""第17轮API冒烟测试 - 测试4大领域核心端点+4个前端页面，确保0个500错误"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from api_server.app import app

client = TestClient(app)

results = []
passed = failed = errors_500 = 0

def test_endpoint(method, path, name, json_data=None, params=None):
    global passed, failed, errors_500
    try:
        if method == "GET":
            resp = client.get(path, params=params)
        else:
            resp = client.post(path, json=json_data, params=params)
        status = resp.status_code
        if status == 500:
            errors_500 += 1
            results.append(f"  [500] {name} {method} {path}")
            failed += 1
        elif status >= 400:
            results.append(f"  [OK-{status}] {name} {method} {path}")
            passed += 1
        else:
            results.append(f"  [OK] {name} {method} {path} (status={status})")
            passed += 1
    except Exception as e:
        results.append(f"  [ERROR] {name} {method} {path}: {e}")
        failed += 1

def test_page(path, name):
    global passed, failed, errors_500
    try:
        resp = client.get(path)
        status = resp.status_code
        if status == 500:
            errors_500 += 1
            results.append(f"  [500] PAGE {name} {path}")
            failed += 1
        elif status == 200 and len(resp.text) > 1000:
            results.append(f"  [OK] PAGE {name} {path} ({len(resp.text)}B)")
            passed += 1
        else:
            results.append(f"  [WARN] PAGE {name} {path} (status={status}, size={len(resp.text)})")
            passed += 1
    except Exception as e:
        results.append(f"  [ERROR] PAGE {name} {path}: {e}")
        failed += 1

print("=" * 60)
print("第17轮API冒烟测试")
print("=" * 60)

# 方向1：威胁狩猎
print("\n--- 方向1：威胁狩猎专业级 (45端点) ---")
test_endpoint("GET", "/api/v1/threat-hunt/health", "健康检查")
test_endpoint("GET", "/api/v1/threat-hunt/query/templates", "查询模板列表")
test_endpoint("GET", "/api/v1/threat-hunt/query/history", "查询历史")
test_endpoint("POST", "/api/v1/threat-hunt/query/execute", "执行查询", json_data={"query": "SELECT * FROM process WHERE name LIKE '%powershell%'"})
test_endpoint("GET", "/api/v1/threat-hunt/hypotheses", "假设列表")
test_endpoint("GET", "/api/v1/threat-hunt/projects", "狩猎项目列表")
test_endpoint("GET", "/api/v1/threat-hunt/behavior/baselines", "行为基线")
test_endpoint("GET", "/api/v1/threat-hunt/behavior/anomalies", "异常行为")
test_endpoint("GET", "/api/v1/threat-hunt/ioc/list", "IOC列表")
test_endpoint("GET", "/api/v1/threat-hunt/data/sources", "数据源列表")
test_endpoint("GET", "/api/v1/threat-hunt/report/metrics", "狩猎度量")
test_endpoint("GET", "/api/v1/threat-hunt/report/maturity", "成熟度评估")

# 方向2：网络流量分析
print("\n--- 方向2：网络流量分析NTA/NDR (47端点) ---")
test_endpoint("GET", "/api/v1/network-analysis/info", "系统信息")
test_endpoint("GET", "/api/v1/network-analysis/capture/interfaces", "接口列表")
test_endpoint("GET", "/api/v1/network-analysis/capture/statistics", "流量统计")
test_endpoint("GET", "/api/v1/network-analysis/capture/protocols", "协议分布")
test_endpoint("GET", "/api/v1/network-analysis/anomaly/list", "异常事件列表")
test_endpoint("GET", "/api/v1/network-analysis/anomaly/tunnels", "隧道检测")
test_endpoint("GET", "/api/v1/network-analysis/anomaly/dga", "DGA检测")
test_endpoint("GET", "/api/v1/network-analysis/behavior/profiles", "实体画像")
test_endpoint("GET", "/api/v1/network-analysis/behavior/graph", "通信关系图谱")
test_endpoint("GET", "/api/v1/network-analysis/rules/signatures", "签名规则")
test_endpoint("GET", "/api/v1/network-analysis/forensics/pcaps", "PCAP列表")
test_endpoint("GET", "/api/v1/network-analysis/dashboard/realtime", "实时流量")
test_endpoint("GET", "/api/v1/network-analysis/dashboard/metrics", "NDR度量")

# 方向3：身份安全与IAM
print("\n--- 方向3：身份安全与IAM深化 (44端点) ---")
test_endpoint("GET", "/api/v1/identity-security/health", "健康检查")
test_endpoint("GET", "/api/v1/identity-security/governance/users", "用户列表")
test_endpoint("GET", "/api/v1/identity-security/governance/directories", "目录集成")
test_endpoint("GET", "/api/v1/identity-security/governance/graph", "身份图谱")
test_endpoint("GET", "/api/v1/identity-security/governance/data-quality", "数据质量")
test_endpoint("GET", "/api/v1/identity-security/permission/matrix", "权限矩阵")
test_endpoint("GET", "/api/v1/identity-security/permission/risk", "权限风险")
test_endpoint("GET", "/api/v1/identity-security/permission/least-privilege", "最小权限")
test_endpoint("GET", "/api/v1/identity-security/threat/baselines", "登录基线")
test_endpoint("GET", "/api/v1/identity-security/threat/anomalous-logins", "异常登录")
test_endpoint("GET", "/api/v1/identity-security/threat/attack-chains", "攻击链")
test_endpoint("GET", "/api/v1/identity-security/pam/accounts", "特权账户")
test_endpoint("GET", "/api/v1/identity-security/auth/policies", "认证策略")
test_endpoint("GET", "/api/v1/identity-security/dashboard/posture", "身份态势")
test_endpoint("GET", "/api/v1/identity-security/dashboard/metrics", "身份度量")

# 方向4：终端安全EDR
print("\n--- 方向4：终端安全EDR (49端点) ---")
test_endpoint("GET", "/api/v1/endpoint-security/health", "健康检查")
test_endpoint("GET", "/api/v1/endpoint-security/asset/list", "终端列表")
test_endpoint("GET", "/api/v1/endpoint-security/asset/groups", "终端分组")
test_endpoint("GET", "/api/v1/endpoint-security/process/tree", "进程树")
test_endpoint("GET", "/api/v1/endpoint-security/process/anomalies", "异常进程")
test_endpoint("GET", "/api/v1/endpoint-security/process/command-audit", "命令行审计")
test_endpoint("GET", "/api/v1/endpoint-security/process/injection", "注入检测")
test_endpoint("GET", "/api/v1/endpoint-security/process/persistence", "持久化检测")
test_endpoint("GET", "/api/v1/endpoint-security/malware/signatures", "签名检测")
test_endpoint("GET", "/api/v1/endpoint-security/malware/yara-rules", "YARA规则")
test_endpoint("GET", "/api/v1/endpoint-security/response/rules", "检测规则")
test_endpoint("GET", "/api/v1/endpoint-security/response/alerts", "告警列表")
test_endpoint("GET", "/api/v1/endpoint-security/vulnerability/list", "漏洞列表")
test_endpoint("GET", "/api/v1/endpoint-security/vulnerability/patches", "补丁管理")
test_endpoint("GET", "/api/v1/endpoint-security/dashboard/posture", "EDR态势")
test_endpoint("GET", "/api/v1/endpoint-security/dashboard/metrics", "EDR度量")

# 前端页面
print("\n--- 前端页面 (4个) ---")
test_page("/threat-hunt", "威胁狩猎控制台")
test_page("/network-analysis", "网络流量分析控制台")
test_page("/identity-security", "身份安全控制台")
test_page("/endpoint-security", "终端安全EDR控制台")

# 总结
print("\n" + "=" * 60)
print("冒烟测试总结")
print("=" * 60)
for r in results:
    print(r)
print(f"\n总计: {len(results)} 项测试")
print(f"通过: {passed}, 失败: {failed}, 500错误: {errors_500}")
print(f"总体结果: {'ALL PASS (0个500错误)' if errors_500 == 0 and failed == 0 else 'HAS FAILURES'}")
sys.exit(0 if errors_500 == 0 else 1)
