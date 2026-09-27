#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_round8_full.py — 第8轮升级全量验证脚本
检查：模块导入、app.py加载、API路由总数、新端点无500、新页面可访问、端到端测试
"""
import json
import os
import sys
import time
import traceback

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

PASS = "PASS"
FAIL = "FAIL"
results = []


def check(name, ok, detail=""):
    tag = PASS if ok else FAIL
    results.append((name, tag, detail))
    print(f"[{tag}] {name}  {detail}")


def main():
    print("=" * 70)
    print("第8轮升级全量验证")
    print("=" * 70)

    # ===== 1. 新模块导入 =====
    print("\n--- 1. 新模块导入 ---")
    modules_to_import = [
        ("target_labs.manager", "靶场管理器"),
        ("target_labs.docker_compose", "Docker Compose生成器"),
        ("target_labs.scenarios", "测试场景库"),
        ("data_import.parsers", "扫描结果解析器"),
        ("data_import.importer", "数据导入器"),
        ("data_export.exporter", "数据导出器"),
        ("notifications.channels", "通知渠道管理器"),
        ("notifications.templates", "通知模板库"),
        ("notifications.router", "通知路由器"),
        ("reporting.template_engine", "报告模板引擎"),
        ("reporting.style_presets", "样式预设库"),
        ("offline.rules_engine", "本地规则引擎"),
        ("offline.ai_fallback", "AI降级管理器"),
        ("offline.local_knowledge", "本地知识库"),
        ("api_security.openapi_parser", "OpenAPI解析器"),
        ("api_security.param_fuzzer", "参数fuzz测试器"),
        ("api_security.logic_tester", "逻辑漏洞测试器"),
        ("api_security.workflow", "API安全工作流"),
    ]
    for mod_name, desc in modules_to_import:
        try:
            __import__(mod_name)
            check(f"导入 {mod_name}", True, desc)
        except Exception as e:
            check(f"导入 {mod_name}", False, f"{desc}: {e}")

    # ===== 2. 新路由模块导入 =====
    print("\n--- 2. 新路由模块导入 ---")
    routers_to_import = [
        ("api_server.target_lab_routes", "router", 12, "靶场"),
        ("api_server.data_io_routes", "router", 11, "数据IO"),
        ("api_server.notification_routes", "router", 15, "通知"),
        ("api_server.report_template_routes", "router", 13, "报告模板"),
        ("api_server.offline_routes", "router", 8, "离线模式"),
        ("api_server.api_security_routes", "router", 12, "API安全"),
    ]
    total_new_endpoints = 0
    for mod_name, attr, expected_min, desc in routers_to_import:
        try:
            mod = __import__(mod_name, fromlist=[attr])
            r = getattr(mod, attr)
            n = len(r.routes)
            total_new_endpoints += n
            check(f"{desc}路由端点>={expected_min}", n >= expected_min, f"实际{n}个")
        except Exception as e:
            check(f"{desc}路由导入", False, str(e))

    check(f"新API端点总数>=71", total_new_endpoints >= 71, f"实际{total_new_endpoints}个")

    # ===== 3. app.py 加载 =====
    print("\n--- 3. app.py 加载与路由总数 ---")
    try:
        from api_server.app import app
        all_routes = [r for r in app.routes if hasattr(r, "path")]
        api_routes = [r for r in all_routes if r.path.startswith("/api/")]
        page_routes = [r for r in all_routes if not r.path.startswith("/api/") and not r.path.startswith("/static") and r.path != "/docs" and r.path != "/openapi.json" and r.path != "/redoc"]
        check("app.py 加载成功", True, f"总路由{len(all_routes)}，API路由{len(api_routes)}，页面路由{len(page_routes)}")
        check("API路由总数>=630", len(api_routes) >= 630, f"实际{len(api_routes)}个（原564+新{total_new_endpoints}）")
    except Exception as e:
        check("app.py 加载", False, str(e))
        traceback.print_exc()
        return 1

    # ===== 4. 新页面文件存在 =====
    print("\n--- 4. 新前端页面文件 ---")
    new_pages = [
        "target_lab_console.html",
        "notification_console.html",
        "report_template_console.html",
        "api_security_console.html",
        "mobile_test.html",
        "i18n_test.html",
    ]
    for page in new_pages:
        p = os.path.join(ROOT, "api_server", page)
        if os.path.exists(p):
            size = os.path.getsize(p)
            check(f"{page} 存在", size > 1000, f"{size}字节")
        else:
            check(f"{page} 存在", False, "文件不存在")

    # ===== 5. 静态文件目录 =====
    print("\n--- 5. 静态文件 ---")
    static_files = [
        ("css/responsive.css", "响应式样式"),
        ("js/mobile-nav.js", "移动端导航"),
        ("js/i18n.js", "i18n框架"),
        ("locales/zh-CN.json", "中文语言包"),
        ("locales/en-US.json", "英文语言包"),
    ]
    for sf, desc in static_files:
        p = os.path.join(ROOT, "api_server", sf)
        if os.path.exists(p):
            size = os.path.getsize(p)
            check(f"{sf} 存在", size > 100, f"{desc} {size}字节")
        else:
            check(f"{sf} 存在", False, f"{desc} 文件不存在")

    # 语言包key数量
    try:
        with open(os.path.join(ROOT, "api_server", "locales", "zh-CN.json"), "r", encoding="utf-8") as f:
            zh = json.load(f)
        with open(os.path.join(ROOT, "api_server", "locales", "en-US.json"), "r", encoding="utf-8") as f:
            en = json.load(f)
        zh_keys = set(zh.keys())
        en_keys = set(en.keys())
        check("中文语言包>=500key", len(zh_keys) >= 500, f"实际{len(zh_keys)}")
        check("英文语言包>=500key", len(en_keys) >= 500, f"实际{len(en_keys)}")
        check("中英文key集合一致", zh_keys == en_keys, f"差异{len(zh_keys ^ en_keys)}个")
    except Exception as e:
        check("语言包检查", False, str(e))

    # ===== 6. TestClient API 测试（无500） =====
    print("\n--- 6. API端点测试（无500错误） ---")
    try:
        from fastapi.testclient import TestClient
        client = TestClient(app)

        # 测试每个新路由模块的关键GET端点
        test_endpoints = [
            ("/api/v1/target-labs/list", "靶场列表"),
            ("/api/v1/target-labs/scenarios", "测试场景"),
            ("/api/v1/target-labs/health", "靶场健康"),
            ("/api/v1/data-io/formats", "支持格式"),
            ("/api/v1/data-io/export/templates", "导出模板"),
            ("/api/v1/data-io/parsers", "解析器列表"),
            ("/api/v1/data-io/stats", "数据IO统计"),
            ("/api/v1/data-io/import/history", "导入历史"),
            ("/api/v1/notifications/channels", "通知渠道"),
            ("/api/v1/notifications/templates", "通知模板"),
            ("/api/v1/notifications/subscriptions", "事件订阅"),
            ("/api/v1/notifications/history", "通知历史"),
            ("/api/v1/notifications/stats", "通知统计"),
            ("/api/v1/report-templates/list", "报告模板列表"),
            ("/api/v1/report-templates/styles", "样式预设"),
            ("/api/v1/offline/status", "离线状态"),
            ("/api/v1/offline/rules", "规则列表"),
            ("/api/v1/offline/knowledge/stats", "知识库统计"),
            ("/api/v1/offline/stats", "离线统计"),
            ("/api/v1/api-security/history", "API安全历史"),
            ("/api/v1/api-security/payloads", "Fuzz payload库"),
            ("/api/v1/api-security/stats", "API安全统计"),
        ]

        status_500_count = 0
        for url, desc in test_endpoints:
            try:
                resp = client.get(url)
                ok = resp.status_code < 500
                if not ok:
                    status_500_count += 1
                check(f"GET {url}", ok, f"{desc} -> {resp.status_code}")
            except Exception as e:
                check(f"GET {url}", False, f"{desc} -> 异常: {e}")
                status_500_count += 1

        check(f"新API端点无500错误", status_500_count == 0, f"500错误数: {status_500_count}")

        # ===== 7. 新页面访问测试 =====
        print("\n--- 7. 新页面访问测试 ---")
        page_routes_test = [
            ("/target-labs", "靶场控制台"),
            ("/notifications", "通知控制台"),
            ("/report-templates", "报告模板编辑器"),
            ("/api-security", "API安全控制台"),
            ("/mobile-test", "移动端测试页"),
            ("/i18n-test", "i18n测试页"),
        ]
        for url, desc in page_routes_test:
            try:
                resp = client.get(url)
                ok = resp.status_code == 200 and len(resp.text) > 500
                check(f"页面 {url}", ok, f"{desc} -> {resp.status_code}, {len(resp.text)}字节")
            except Exception as e:
                check(f"页面 {url}", False, f"{desc} -> 异常: {e}")

    except Exception as e:
        check("TestClient测试", False, str(e))
        traceback.print_exc()

    # ===== 8. 端到端：API安全工作流 =====
    print("\n--- 8. 端到端测试：API安全工作流 ---")
    try:
        from api_security.workflow import get_api_security_workflow
        wf = get_api_security_workflow()

        sample_spec = {
            "openapi": "3.0.0",
            "info": {"title": "E2E Test API", "version": "1.0.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/users/{id}": {
                    "get": {
                        "operationId": "getUser",
                        "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {"description": "OK"}},
                    }
                },
                "/login": {
                    "post": {
                        "operationId": "login",
                        "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"username": {"type": "string"}, "password": {"type": "string"}}}}}},
                        "responses": {"200": {"description": "OK"}},
                    }
                },
            },
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        }

        config = {
            "openapi_content": json.dumps(sample_spec),
            "content_type": "json",
            "base_url": "https://api.example.com",
            "auth_token": "",
            "fuzz_intensity": "low",
            "test_types": ["sql_injection", "xss"],
            "logic_test_types": ["auth_bypass", "csrf"],
            "rate_limit": {"request_interval": 0.0, "timeout": 5},
        }

        scan_id = wf.create_scan(config)
        check("创建扫描", scan_id.startswith("scan_"), f"scan_id={scan_id}")

        wf.run_scan(scan_id)
        deadline = time.time() + 20
        status = {}
        while time.time() < deadline:
            status = wf.get_scan_status(scan_id)
            if status.get("status") in ("completed", "failed"):
                break
            time.sleep(0.3)

        check("扫描完成", status.get("status") == "completed", f"status={status.get('status')}, progress={status.get('progress')}")
        check("进度100%", status.get("progress") == 100, f"progress={status.get('progress')}")

        result = wf.get_scan_result(scan_id)
        vulns = wf.get_vulnerabilities(scan_id)
        check("获取结果", "result" in result, f"漏洞数={len(vulns)}")

        report = wf.generate_report(scan_id, "json")
        check("生成JSON报告", report.get("format") == "json", "报告生成成功")

        history = wf.get_scan_history()
        check("扫描历史", len(history) >= 1, f"历史记录={len(history)}")

    except Exception as e:
        check("端到端测试", False, str(e))
        traceback.print_exc()

    # ===== 9. 工作流模板数量 =====
    print("\n--- 9. 工作流模板 ---")
    try:
        from workflow.templates import WORKFLOW_TEMPLATES_V7, list_templates
        n = len(WORKFLOW_TEMPLATES_V7)
        check("工作流模板>=9", n >= 9, f"实际{n}个")
        tpls = list_templates()
        ids = [t["id"] for t in tpls]
        check("包含api_security_test模板", "api_security_test" in ids, f"模板IDs={ids}")
    except Exception as e:
        check("工作流模板检查", False, str(e))

    # ===== 汇总 =====
    print("\n" + "=" * 70)
    n_pass = sum(1 for _, t, _ in results if t == PASS)
    n_fail = sum(1 for _, t, _ in results if t == FAIL)
    print(f"总计: {len(results)} 项 | PASS: {n_pass} | FAIL: {n_fail}")
    if n_fail:
        print("\n失败项:")
        for name, tag, detail in results:
            if tag == FAIL:
                print(f"  - {name}: {detail}")
    print("=" * 70)
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
