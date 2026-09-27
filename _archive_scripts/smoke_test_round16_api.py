# -*- coding: utf-8 -*-
"""第16轮API冒烟测试 - 测试4大领域核心端点+4个前端页面，确保0个500错误"""
import sys, os, json
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
            # 4xx是正常的（如参数验证），不算失败
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
print("第16轮API冒烟测试")
print("=" * 60)

# 方向1：端到端工作流
print("\n--- 方向1：端到端工作流 (32端点) ---")
test_endpoint("GET", "/api/v1/workflow-executor/health", "健康检查")
test_endpoint("GET", "/api/v1/workflow-executor/scenarios", "场景模板列表")
test_endpoint("GET", "/api/v1/workflow-executor/tasks", "任务列表")
test_endpoint("POST", "/api/v1/workflow-executor/evaluate", "提交评估任务", json_data={"target": "127.0.0.1", "scenario": "web_assessment"})
test_endpoint("GET", "/api/v1/workflow-executor/verify/e2e", "端到端验证状态")
test_endpoint("GET", "/api/v1/workflow-executor/batch/status", "批量调度状态")

# 方向2：前端交互深度提升
print("\n--- 方向2：前端交互深度提升 (55端点) ---")
test_endpoint("GET", "/api/v1/task-console/health", "健康检查")
test_endpoint("GET", "/api/v1/task-console/tasks", "任务列表")
test_endpoint("POST", "/api/v1/task-console/tasks/submit", "提交任务", json_data={"scenario": "web", "target": "example.com"})
test_endpoint("GET", "/api/v1/task-console/reports", "报告列表")
test_endpoint("GET", "/api/v1/task-console/vulnerabilities", "漏洞列表")
test_endpoint("GET", "/api/v1/task-console/assets", "资产列表")
test_endpoint("GET", "/api/v1/task-console/notifications", "通知列表")
test_endpoint("GET", "/api/v1/task-console/notifications/unread-count", "未读计数")
test_endpoint("GET", "/api/v1/task-console/activity", "活动流")
test_endpoint("GET", "/api/v1/task-console/performance/summary", "性能汇总")
test_endpoint("GET", "/api/v1/task-console/navigation/menu", "导航菜单")
test_endpoint("GET", "/api/v1/task-console/search/suggest", "搜索建议", params={"q": "漏洞"})

# 方向3：种子数据与初始化
print("\n--- 方向3：种子数据与初始化 (34端点) ---")
test_endpoint("GET", "/api/v1/seed-manager/health", "健康检查")
test_endpoint("GET", "/api/v1/seed-manager/status", "初始化状态")
test_endpoint("GET", "/api/v1/seed-manager/seed/status", "种子数据状态")
test_endpoint("GET", "/api/v1/seed-manager/vulnerabilities", "漏洞库列表", params={"page": 1, "page_size": 10})
test_endpoint("GET", "/api/v1/seed-manager/knowledge", "知识库列表", params={"page": 1, "page_size": 10})
test_endpoint("GET", "/api/v1/seed-manager/tools", "工具模板列表", params={"page": 1, "page_size": 10})
test_endpoint("GET", "/api/v1/seed-manager/report-templates", "报告模板列表")
test_endpoint("GET", "/api/v1/seed-manager/kpi", "KPI列表", params={"page": 1, "page_size": 10})
test_endpoint("GET", "/api/v1/seed-manager/compliance", "合规控制项列表", params={"page": 1, "page_size": 10})
test_endpoint("GET", "/api/v1/seed-manager/sample/status", "示例数据状态")

# 方向4：工具运行时与性能
print("\n--- 方向4：工具运行时与性能 (36端点) ---")
test_endpoint("GET", "/api/v1/system-health/health", "健康检查")
test_endpoint("GET", "/api/v1/system-health/tools", "工具列表")
test_endpoint("GET", "/api/v1/system-health/tools/available", "可用工具")
test_endpoint("GET", "/api/v1/system-health/fallback/mapping", "降级映射")
test_endpoint("GET", "/api/v1/system-health/install/guides", "安装引导")
test_endpoint("GET", "/api/v1/system-health/performance/summary", "性能汇总")
test_endpoint("GET", "/api/v1/system-health/performance/slow-apis", "慢API列表")
test_endpoint("GET", "/api/v1/system-health/dashboard", "系统健康仪表盘")
test_endpoint("GET", "/api/v1/system-health/startup/status", "启动状态")
test_endpoint("GET", "/api/v1/system-health/startup/preheat", "预热状态")

# 前端页面
print("\n--- 前端页面 (4个) ---")
test_page("/workflow-executor", "端到端工作流执行器")
test_page("/task-console", "统一任务控制台")
test_page("/seed-manager", "种子数据管理器")
test_page("/system-health", "系统健康控制台")

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
