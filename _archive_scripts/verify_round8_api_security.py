#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_round8_api_security.py — Round 8 API 安全专项工作流验证脚本。

检查项：
    1. 所有 Python 文件可正常导入
    2. api_security_routes.py 的 router 至少 12 个端点
    3. openapi_parser.py 能解析示例 OpenAPI JSON
    4. param_fuzzer.py 包含 >=10 种 fuzz 类型，每种 >=10 个 payload（总 100+）
    5. logic_tester.py 包含 >=7 种测试类型
    6. workflow.py 包含 8 个工作流步骤
    7. workflow/templates.py 中 WORKFLOW_TEMPLATES_V7 现在有 9 个模板
    8. api_security_console.html 非空，包含完整 HTML 结构
    9. 端到端：创建扫描（内联 OpenAPI spec）→ 检查状态 → 获取结果
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback

# 确保项目根目录在 sys.path
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

PASS = "PASS"
FAIL = "FAIL"
results = []


def check(name: str, ok: bool, detail: str = "") -> None:
    tag = PASS if ok else FAIL
    results.append((name, tag, detail))
    print(f"[{tag}] {name}  {detail}")


# 示例 OpenAPI 3.0 spec（内联）
SAMPLE_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Demo API", "version": "1.0.0", "description": "示例 API"},
    "servers": [{"url": "https://api.example.com"}],
    "paths": {
        "/public/health": {
            "get": {"operationId": "health", "summary": "健康检查", "tags": ["public"]}
        },
        "/users/{id}": {
            "get": {
                "operationId": "getUser", "summary": "获取用户",
                "tags": ["user"],
                "parameters": [
                    {"name": "id", "in": "path", "required": True,
                     "schema": {"type": "integer"}, "description": "用户ID"}
                ],
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/admin/users": {
            "get": {
                "operationId": "listAdminUsers", "summary": "管理员用户列表",
                "tags": ["admin"],
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/login": {
            "post": {
                "operationId": "login", "summary": "登录",
                "tags": ["auth"],
                "requestBody": {
                    "content": {"application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"username": {"type": "string"},
                                          "password": {"type": "string"}},
                            "required": ["username", "password"],
                        }
                    }}
                },
                "responses": {"200": {"description": "OK"}},
            }
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"}
        }
    },
}


def main() -> int:
    print("=" * 70)
    print("Round 8 API 安全专项工作流 验证")
    print("=" * 70)

    # 1. 导入检查
    print("\n--- 1. 模块导入 ---")
    try:
        import api_security.openapi_parser  # noqa
        check("import api_security.openapi_parser", True)
    except Exception as e:
        check("import api_security.openapi_parser", False, str(e))

    try:
        import api_security.param_fuzzer  # noqa
        check("import api_security.param_fuzzer", True)
    except Exception as e:
        check("import api_security.param_fuzzer", False, str(e))

    try:
        import api_security.logic_tester  # noqa
        check("import api_security.logic_tester", True)
    except Exception as e:
        check("import api_security.logic_tester", False, str(e))

    try:
        import api_security.workflow  # noqa
        check("import api_security.workflow", True)
    except Exception as e:
        check("import api_security.workflow", False, str(e))

    try:
        from api_server.api_security_routes import router  # noqa
        check("from api_server.api_security_routes import router", True)
    except Exception as e:
        check("from api_server.api_security_routes import router", False, str(e))
        traceback.print_exc()

    # 2. router 端点数量
    print("\n--- 2. router 端点数量 ---")
    try:
        from api_server.api_security_routes import router
        paths = [r.path for r in router.routes]
        n = len(paths)
        check("router 至少 12 个端点", n >= 12, f"实际 {n} 个: {paths}")
    except Exception as e:
        check("router 端点数量", False, str(e))

    # 3. OpenAPI 解析
    print("\n--- 3. OpenAPI 解析器 ---")
    try:
        from api_security.openapi_parser import OpenAPIParser
        p = OpenAPIParser()
        result = p.parse_from_string(json.dumps(SAMPLE_SPEC), "json")
        valid = result.get("valid", False)
        eps = p.get_endpoints()
        info = p.get_api_info()
        auth = p.get_auth_methods()
        classes = p.classify_endpoints(eps)
        check("解析示例 OpenAPI 3.0 JSON", valid and len(eps) == 4,
              f"valid={valid}, endpoints={len(eps)}, title={info.get('title')}")
        check("识别认证方式", any(a.get("detected") == "bearer_token" for a in auth),
              f"auth_methods={[a.get('detected') for a in auth]}")
        check("端点分类", len(classes.get("admin", [])) == 1 and len(classes.get("user", [])) == 1,
              f"classes={ {k: len(v) for k, v in classes.items()} }")
    except Exception as e:
        check("OpenAPI 解析", False, str(e))
        traceback.print_exc()

    # 4. payload 库
    print("\n--- 4. Fuzz Payload 库 ---")
    try:
        from api_security.param_fuzzer import PAYLOAD_LIBRARY, ParamFuzzer
        types = list(PAYLOAD_LIBRARY.keys())
        n_types = len(types)
        total = sum(len(v) for v in PAYLOAD_LIBRARY.values())
        min_per_type = min(len(v) for v in PAYLOAD_LIBRARY.values()) if PAYLOAD_LIBRARY else 0
        check(">=10 种 fuzz 类型", n_types >= 10, f"实际 {n_types} 种: {types}")
        check("每种 >=10 个 payload", min_per_type >= 10, f"最少 {min_per_type} 个/类型")
        check("总 payload >=100", total >= 100, f"实际 {total} 个")
        fz = ParamFuzzer()
        check("get_fuzz_types 返回列表", len(fz.get_fuzz_types()) == n_types)
    except Exception as e:
        check("Payload 库", False, str(e))

    # 5. 逻辑测试类型
    print("\n--- 5. 逻辑漏洞测试类型 ---")
    try:
        from api_security.logic_tester import LogicTester
        t = LogicTester()
        types = t.get_test_types()
        check(">=7 种逻辑测试类型", len(types) >= 7, f"实际 {len(types)} 种: {types}")
        check("修复建议完整", all(k in t.remediation for k in types),
              f"remediation keys: {list(t.remediation.keys())}")
    except Exception as e:
        check("逻辑测试类型", False, str(e))

    # 6. workflow 步骤
    print("\n--- 6. Workflow 8 步骤 ---")
    try:
        from api_security.workflow import WORKFLOW_STEPS
        check("8 个工作流步骤", len(WORKFLOW_STEPS) == 8,
              f"实际 {len(WORKFLOW_STEPS)}: {[s['step'] for s in WORKFLOW_STEPS]}")
    except Exception as e:
        check("Workflow 步骤", False, str(e))

    # 7. 模板数量
    print("\n--- 7. workflow/templates.py 模板 ---")
    try:
        from workflow.templates import WORKFLOW_TEMPLATES_V7, get_template
        n = len(WORKFLOW_TEMPLATES_V7)
        check("WORKFLOW_TEMPLATES_V7 有 9 个模板", n == 9, f"实际 {n} 个")
        tpl = get_template("api_security_test")
        check("api_security_test 模板存在", tpl is not None and tpl.get("name") == "API安全测试",
              f"id={tpl and tpl.get('id')}")
        check("api_security_test 有 8 个步骤", tpl is not None and len(tpl.get("steps", [])) == 8,
              f"steps={len(tpl.get('steps', [])) if tpl else 0}")
    except Exception as e:
        check("模板数量", False, str(e))
        traceback.print_exc()

    # 8. HTML 控制台
    print("\n--- 8. HTML 控制台 ---")
    try:
        html_path = os.path.join(ROOT, "api_server", "api_security_console.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
        check("HTML 文件非空", len(html) > 1000, f"{len(html)} 字节")
        check("包含 <!DOCTYPE html>", "<!doctype html>" in html.lower())
        check("包含 API 安全测试控制台标题", "API安全测试控制台" in html)
        check("包含 base URL /api/v1/api-security", "/api/v1/api-security" in html)
        check("包含进度条/漏洞表/报告区",
              "progress-fill" in html and "vulnBody" in html and "reportContent" in html)
    except Exception as e:
        check("HTML 控制台", False, str(e))

    # 9. 端到端测试
    print("\n--- 9. 端到端：创建扫描 → 状态 → 结果 ---")
    try:
        from api_security.workflow import get_api_security_workflow
        wf = get_api_security_workflow()
        config = {
            "openapi_content": json.dumps(SAMPLE_SPEC),
            "content_type": "json",
            "base_url": "https://api.example.com",
            "auth_token": "",
            "fuzz_intensity": "low",
            "test_types": ["sql_injection", "xss"],
            "logic_test_types": ["auth_bypass", "csrf"],
            "rate_limit": {"request_interval": 0.0, "timeout": 5},
        }
        scan_id = wf.create_scan(config)
        check("create_scan 返回 scan_id", scan_id.startswith("scan_"), f"scan_id={scan_id}")

        # 异步执行
        wf.run_scan(scan_id)
        # 等待完成（最多 15 秒）
        deadline = time.time() + 15
        status = {}
        while time.time() < deadline:
            status = wf.get_scan_status(scan_id)
            if status.get("status") in ("completed", "failed"):
                break
            time.sleep(0.3)
        check("扫描在 15s 内完成", status.get("status") == "completed",
              f"status={status.get('status')}, progress={status.get('progress')}")
        check("进度=100", status.get("progress") == 100, f"progress={status.get('progress')}")

        result = wf.get_scan_result(scan_id)
        vulns = wf.get_vulnerabilities(scan_id)
        check("扫描结果包含 vulnerabilities", "result" in result and isinstance(vulns, list),
              f"vuln_count={len(vulns)}")

        report = wf.generate_report(scan_id, "json")
        check("JSON 报告生成", report.get("format") == "json" and "content" in report,
              f"keys={list(report.keys())}")
        report_html = wf.generate_report(scan_id, "html")
        check("HTML 报告生成", report_html.get("format") == "html" and "<html" in report_html.get("content", "").lower())

        history = wf.get_scan_history()
        check("扫描历史非空", len(history) >= 1, f"history={len(history)}")
        stats = wf.get_stats()
        check("统计包含 total_scans", stats.get("total_scans", 0) >= 1, f"stats={stats}")
    except Exception as e:
        check("端到端测试", False, str(e))
        traceback.print_exc()

    # 汇总
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
