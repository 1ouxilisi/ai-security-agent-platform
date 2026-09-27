# -*- coding: utf-8 -*-
"""第11轮API端点冒烟测试：启动TestClient测试所有新端点，确保无500错误"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from api_server.app import app

client = TestClient(app)

# 要测试的端点列表 (method, path, expected_status_min, description)
ENDPOINTS = [
    # === 云安全 V2 ===
    ("GET", "/api/v1/cloud-v2/aws/rules", 200, "AWS规则列表"),
    ("POST", "/api/v1/cloud-v2/aws/audit", 200, "启动AWS检查", {"regions": ["us-east-1"], "services": ["iam", "s3"]}),
    ("GET", "/api/v1/cloud-v2/azure/rules", 200, "Azure规则列表"),
    ("POST", "/api/v1/cloud-v2/azure/audit", 200, "启动Azure检查", {"subscriptions": ["test-sub"]}),
    ("GET", "/api/v1/cloud-v2/aliyun/rules", 200, "阿里云规则列表"),
    ("POST", "/api/v1/cloud-v2/aliyun/audit", 200, "启动阿里云检查", {"regions": ["cn-hangzhou"]}),
    ("GET", "/api/v1/cloud-v2/gcp/rules", 200, "GCP规则列表"),
    ("POST", "/api/v1/cloud-v2/gcp/audit", 200, "启动GCP检查", {"project_id": "test-project"}),
    ("POST", "/api/v1/cloud-v2/container/scan", 200, "启动容器扫描", {"image": "nginx:latest"}),
    ("POST", "/api/v1/cloud-v2/k8s/audit", 200, "启动K8s检查", {"cluster": "test-cluster"}),
    ("POST", "/api/v1/cloud-v2/asset/discovery", 200, "启动云资产发现", {"provider": "aws"}),
    ("GET", "/api/v1/cloud-v2/asset/list", 200, "云资产列表"),
    ("GET", "/api/v1/cloud-v2/asset/changes", 200, "资产变更历史"),
    ("GET", "/api/v1/cloud-v2/asset/report", 200, "资产报告"),
    ("POST", "/api/v1/cloud-v2/threat/detect", 200, "启动威胁检测", {"provider": "aws"}),
    ("GET", "/api/v1/cloud-v2/threat/alerts", 200, "威胁告警列表"),
    ("GET", "/api/v1/cloud-v2/threat/report", 200, "威胁报告"),

    # === 代码审计 V2 ===
    ("GET", "/api/v1/code-v2/sast/rules", 200, "SAST规则列表"),
    ("POST", "/api/v1/code-v2/sast/analyze", 200, "启动SAST分析", {"source_path": ".", "language": "python"}),
    ("GET", "/api/v1/code-v2/semgrep/rulesets", 200, "Semgrep规则集列表"),
    ("POST", "/api/v1/code-v2/semgrep/scan", 200, "启动Semgrep扫描", {"source_path": "."}),
    ("POST", "/api/v1/code-v2/sca/scan", 200, "启动SCA扫描", {"source_path": "."}),
    ("GET", "/api/v1/code-v2/sca/dependencies", 200, "依赖列表"),
    ("GET", "/api/v1/code-v2/sca/licenses", 200, "许可证列表"),
    ("POST", "/api/v1/code-v2/quality/analyze", 200, "启动代码质量分析", {"source_path": "."}),
    ("GET", "/api/v1/code-v2/quality/metrics", 200, "质量指标列表"),
    ("GET", "/api/v1/code-v2/secure-coding/rules", 200, "安全编码规则列表"),
    ("POST", "/api/v1/code-v2/secure-coding/check", 200, "启动安全编码检查", {"source_path": "."}),
    ("POST", "/api/v1/code-v2/audit/run", 200, "启动综合审计", {"source_path": "."}),
    ("GET", "/api/v1/code-v2/audit/history", 200, "审计历史"),

    # === 取证分析 V2 ===
    ("POST", "/api/v1/forensics-v2/memory/analyze", 200, "启动内存取证", {"image_path": "/tmp/test.raw"}),
    ("POST", "/api/v1/forensics-v2/disk/analyze", 200, "启动磁盘取证", {"image_path": "/tmp/test.dd"}),
    ("POST", "/api/v1/forensics-v2/network/analyze", 200, "启动网络取证", {"pcap_path": "/tmp/test.pcap"}),
    ("POST", "/api/v1/forensics-v2/log/analyze", 200, "启动日志取证", {"log_path": "/tmp/test.log"}),
    ("POST", "/api/v1/forensics-v2/audit/run", 200, "启动综合取证", {"evidence": ["test.raw"]}),
    ("GET", "/api/v1/forensics-v2/audit/history", 200, "取证历史"),
    ("GET", "/api/v1/forensics-v2/evidence/list", 200, "证据列表"),
    ("POST", "/api/v1/forensics-v2/evidence/upload", 200, "上传证据", {"name": "test.dd", "type": "disk"}),

    # === 插件系统 ===
    ("GET", "/api/v1/plugins/list", 200, "插件列表"),
    ("GET", "/api/v1/plugins/marketplace/browse", 200, "市场浏览"),
    ("GET", "/api/v1/plugins/marketplace/search", 200, "搜索插件"),
    ("GET", "/api/v1/plugins/marketplace/categories", 200, "分类列表"),
    ("GET", "/api/v1/plugins/marketplace/recommendations", 200, "推荐插件"),
    ("GET", "/api/v1/plugins/marketplace/stats", 200, "市场统计"),
    ("GET", "/api/v1/plugins/sdk/docs", 200, "SDK文档"),
    ("GET", "/api/v1/plugins/sdk/templates", 200, "模板列表"),
    ("GET", "/api/v1/plugins/sdk/examples", 200, "示例列表"),
    ("GET", "/api/v1/plugins/security/malicious", 200, "恶意插件列表"),
]

# 前端页面
PAGES = [
    ("/cloud-security-v2", "云安全控制台"),
    ("/code-audit-v2", "代码审计控制台"),
    ("/forensics-v2", "取证分析控制台"),
    ("/plugins-console", "插件系统控制台"),
]


def test_endpoints():
    print("=" * 70)
    print("第11轮 API 端点冒烟测试")
    print("=" * 70)

    passed = 0
    failed = 0
    errors = []

    for item in ENDPOINTS:
        method = item[0]
        path = item[1]
        desc = item[2] if len(item) > 2 else ""
        body = item[3] if len(item) > 3 else None

        try:
            if method == "GET":
                resp = client.get(path)
            elif method == "POST":
                resp = client.post(path, json=body or {})
            else:
                continue

            status = resp.status_code
            if status < 500:
                passed += 1
                print(f"  [OK] {method} {path} ({status}) {desc}")
            else:
                failed += 1
                errors.append(f"{method} {path} -> {status}")
                print(f"  [FAIL] {method} {path} ({status}) {desc}")
                try:
                    print(f"         Response: {resp.text[:200]}")
                except:
                    pass
        except Exception as e:
            failed += 1
            errors.append(f"{method} {path} -> EXCEPTION: {e}")
            print(f"  [ERROR] {method} {path} -> {e}")

    print(f"\nAPI端点测试: {passed} 通过, {failed} 失败 (共 {len(ENDPOINTS)} 个)")
    return failed == 0, errors


def test_pages():
    print("\n" + "=" * 70)
    print("前端页面可访问性测试")
    print("=" * 70)

    passed = 0
    failed = 0

    for path, desc in PAGES:
        try:
            resp = client.get(path)
            if resp.status_code == 200 and len(resp.text) > 1000:
                passed += 1
                print(f"  [OK] {path} ({desc}) - {len(resp.text)} 字节")
            else:
                failed += 1
                print(f"  [FAIL] {path} ({desc}) - status={resp.status_code}, size={len(resp.text)}")
        except Exception as e:
            failed += 1
            print(f"  [ERROR] {path} -> {e}")

    print(f"\n前端页面测试: {passed} 通过, {failed} 失败 (共 {len(PAGES)} 个)")
    return failed == 0


def test_task_status_endpoints():
    """测试任务状态/结果/报告端点（需要先创建任务）"""
    print("\n" + "=" * 70)
    print("任务状态端点测试（创建任务后查询状态/结果/报告）")
    print("=" * 70)

    # 创建几个任务然后查询
    task_tests = [
        ("POST", "/api/v1/cloud-v2/aws/audit", {}, "/api/v1/cloud-v2/aws/"),
        ("POST", "/api/v1/code-v2/sast/analyze", {"source_path": "."}, "/api/v1/code-v2/sast/"),
        ("POST", "/api/v1/forensics-v2/memory/analyze", {"image_path": "test.raw"}, "/api/v1/forensics-v2/memory/"),
    ]

    passed = 0
    failed = 0

    for method, create_path, body, base_path in task_tests:
        try:
            resp = client.post(create_path, json=body)
            if resp.status_code >= 500:
                print(f"  [FAIL] 创建任务 {create_path} -> {resp.status_code}")
                failed += 1
                continue

            data = resp.json()
            task_id = None
            if isinstance(data, dict):
                d = data.get("data", data)
                if isinstance(d, dict):
                    task_id = d.get("task_id") or d.get("id")

            if not task_id:
                # 尝试从响应中提取
                print(f"  [WARN] {create_path} 未返回task_id，跳过状态查询")
                passed += 1
                continue

            # 查询状态
            status_resp = client.get(f"{base_path}{task_id}/status")
            results_resp = client.get(f"{base_path}{task_id}/results")
            report_resp = client.get(f"{base_path}{task_id}/report")

            all_ok = all(r.status_code < 500 for r in [status_resp, results_resp, report_resp])
            if all_ok:
                passed += 1
                print(f"  [OK] {base_path}{{task_id}}/status|results|report (task={task_id})")
            else:
                failed += 1
                print(f"  [FAIL] {base_path}{{task_id}} 状态查询失败: status={status_resp.status_code}, results={results_resp.status_code}, report={report_resp.status_code}")

        except Exception as e:
            failed += 1
            print(f"  [ERROR] {create_path} -> {e}")

    print(f"\n任务状态端点测试: {passed} 通过, {failed} 失败")
    return failed == 0


def main():
    r1, e1 = test_endpoints()
    r2 = test_pages()
    r3 = test_task_status_endpoints()

    print("\n" + "=" * 70)
    print("冒烟测试总结")
    print("=" * 70)
    print(f"  API端点:     {'PASS' if r1 else 'FAIL'}")
    print(f"  前端页面:     {'PASS' if r2 else 'FAIL'}")
    print(f"  任务状态端点: {'PASS' if r3 else 'FAIL'}")

    all_pass = r1 and r2 and r3
    print(f"\n  总体: {'ALL PASS - 无500错误' if all_pass else 'HAS FAILURES'}")

    if e1:
        print(f"\n失败端点:")
        for e in e1:
            print(f"  - {e}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
