# -*- coding: utf-8 -*-
"""
全量API自动化测试脚本。

功能：
    - 自动从 FastAPI app.routes 发现全部 API 端点（方法 + 路径）
    - 过滤文档端点（/docs /openapi.json /redoc）和静态文件路由
    - 对 GET 端点：期望状态码在 200/401/403/404 范围内（绝不能是 500）
    - 对 POST/PUT/PATCH 端点：发送最小 JSON，期望 200/400/401/403/422（绝不能是 500）
    - 对 DELETE 端点：同上
    - 统计总数/通过/失败/跳过/500 错误数，失败端点记录 URL/方法/状态码/响应体前 500 字符
    - 输出 JSON 报告到 tests/api_test_report.json，并在控制台彩色打印

用法：
    python tests/test_all_apis.py            # 直接运行全量测试
    pytest tests/test_all_apis.py            # pytest 运行

目标：
    - 0 个 500 错误
    - >= 95% 端点正常响应（2xx/4xx 客户端错误均视为正常）
"""
from __future__ import annotations

# 必须在导入 app 之前关闭鉴权，否则所有受保护端点都会返回 401（虽然 401 不算失败，但会掩盖真实错误）
import os as _os
_os.environ.setdefault("API_AUTH_ENABLED", "false")
_os.environ.setdefault("API_ENV", "test")

import sys
import json
import time
import traceback
from pathlib import Path
from collections import OrderedDict

# 把项目根目录加入 sys.path，保证直接运行时也能 import
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

REPORT_PATH = Path(__file__).resolve().parent / "api_test_report.json"

# 彩色控制台输出（Windows 终端默认支持 ANSI）
class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    END = "\033[0m"


# 需要排除的路径前缀 / 精确路径（文档、静态文件、健康检查以外的元数据端点）
EXACT_EXCLUDE = {"/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect", "/favicon.ico"}
PREFIX_EXCLUDE = ("/static/", "/js/", "/css/", "/assets/")
# HTML 页面路由（在 app.py 中直接返回 HTMLResponse 的 GET 路由）
HTML_PAGE_PATHS = {
    "/", "/test", "/dashboard", "/console", "/advanced-console", "/vuln-database",
    "/workbench", "/workflow", "/console-v7", "/combat-console", "/extended-console",
    "/enhanced-console", "/assessment", "/defense-console", "/commercial-console",
    "/platform", "/platform-v2",
}

# 路径参数占位符替换映射（按字段名 → 测试值）
PARAM_VALUE_MAP = {
    "task_id": "test-task-id",
    "id": "1",
    "user_id": "1",
    "target_id": "1",
    "report_id": "1",
    "scan_id": "1",
    "vuln_id": "1",
    "job_id": "1",
    "rule_id": "1",
    "alert_id": "1",
    "tenant_id": "1",
    "node_id": "1",
    "agent_id": "1",
    "template_id": "1",
    "plugin_id": "1",
    "target": "example.com",
    "host": "127.0.0.1",
    "ip": "127.0.0.1",
    "path": "test",
    "name": "test",
    "filename": "test.txt",
    "task": "test",
}
DEFAULT_PARAM = "1"

# 允许的"正常"状态码集合（429 限流、503 服务未配置均视为合理降级，不算 500）
GOOD_GET = {200, 201, 202, 204, 400, 401, 403, 404, 405, 409, 422, 429, 503}
GOOD_WRITE = {200, 201, 202, 204, 400, 401, 403, 404, 405, 409, 422, 429, 503}


def _fill_path_params(path: str) -> str:
    """把 /xxx/{task_id} 形式的路径参数替换为测试值。"""
    out = path
    # FastAPI 路径参数形如 {task_id:path} 或 {task_id}
    import re
    def _repl(m):
        raw = m.group(1)
        key = raw.split(":")[0]
        return PARAM_VALUE_MAP.get(key, DEFAULT_PARAM)
    out = re.sub(r"\{([^}]+)\}", _repl, out)
    return out


def _is_html_route(path: str) -> bool:
    return path in HTML_PAGE_PATHS or path.endswith("-console") or path in (
        "/platform", "/platform-v2", "/unified-console"
    )


def discover_endpoints(app):
    """从 FastAPI app.routes 中提取 (method, path, name) 三元组。"""
    endpoints = []
    seen = set()
    for route in app.routes:
        # APIRoute / APIWebSocketRoute / Mount / Host
        methods = getattr(route, "methods", None)
        path = getattr(route, "path", None)
        if not path:
            continue
        if path in EXACT_EXCLUDE or any(path.startswith(p) for p in PREFIX_EXCLUDE):
            continue
        # 跳过 Mount 挂载的静态目录
        if route.__class__.__name__ == "Mount":
            continue
        if not methods:
            continue
        for m in methods:
            if m == "HEAD":
                continue
            key = (m, path)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append((m, path, getattr(route, "name", "")))
    return endpoints


def _minimal_payload(method: str, path: str):
    """根据方法和路径构造最小请求体。"""
    if method in ("POST", "PUT", "PATCH"):
        return {}
    return None


def run_full_test() -> dict:
    """执行全量 API 测试，返回统计结果字典。"""
    print(f"{C.BOLD}{C.CYAN}=== 全量 API 测试开始 ==={C.END}")

    # 1. 导入 app
    t0 = time.time()
    app = None
    import_error = None
    try:
        from api_server.app import app as _app
        app = _app
    except Exception as e:  # noqa: BLE001
        import_error = f"{type(e).__name__}: {e}"
        print(f"{C.RED}✗ 导入 api_server.app 失败: {import_error}{C.END}")
        traceback.print_exc()

    report = {
        "target": "ai-hacking-agent FastAPI",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "import_error": import_error,
        "summary": {},
        "failures": [],
        "errors_500": [],
    }

    if app is None:
        report["summary"] = {
            "total": 0, "passed": 0, "failed": 0, "skipped": 0,
            "errors_500": 0, "pass_rate": 0.0,
        }
        REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return report

    endpoints = discover_endpoints(app)
    # 把 HTML 页面路由单独标记为跳过（由 test_all_pages.py 负责）
    api_endpoints = [(m, p, n) for (m, p, n) in endpoints if not _is_html_route(p)]
    skipped_pages = [(m, p, n) for (m, p, n) in endpoints if _is_html_route(p)]
    print(f"{C.CYAN}发现 {len(endpoints)} 条路由，其中 API 端点 {len(api_endpoints)} 个，"
          f"页面路由 {len(skipped_pages)} 个（跳过，交给页面测试）{C.END}")

    # 运行时禁用限流中间件（不修改源代码，只改运行时状态），避免批量测试触发 429
    try:
        from api_server.security_middleware import SecurityMiddleware
        async def _no_limit(self, request):  # noqa: ANN001
            return None
        SecurityMiddleware._check_rate_limit = _no_limit  # type: ignore
        SecurityMiddleware.enabled = False  # type: ignore
    except Exception:
        pass

    from fastapi.testclient import TestClient
    # raise_server_exceptions=False：服务端未捕获异常会变成 500 响应，而不是在测试侧抛异常
    client = TestClient(app, base_url="http://testserver", raise_server_exceptions=False)

    passed = 0
    failed = 0
    errors_500 = 0
    failures = []
    err500_list = []

    import threading
    import queue as _queue

    def _call_with_timeout(fn, timeout: float):
        """在 daemon 线程里跑 fn，timeout 秒内返回结果，超时返回 (None, 'timeout')。"""
        q = _queue.Queue()
        def _runner():
            try:
                q.put(("ok", fn()))
            except Exception as e:  # noqa: BLE001
                q.put(("err", e))
        t = threading.Thread(target=_runner, daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive():
            return None, "timeout"
        kind, val = q.get_nowait()
        if kind == "ok":
            return val, None
        return None, val

    for idx, (method, path, name) in enumerate(api_endpoints, 1):
        url = _fill_path_params(path)
        payload = _minimal_payload(method, path)

        def _do_request():
            if method == "GET":
                return client.get(url, timeout=5.0)
            if method == "POST":
                return client.post(url, json=payload, timeout=5.0)
            if method == "PUT":
                return client.put(url, json=payload, timeout=5.0)
            if method == "PATCH":
                return client.patch(url, json=payload, timeout=5.0)
            if method == "DELETE":
                return client.request("DELETE", url, timeout=5.0)
            return client.request(method, url, json=payload if payload is not None else None, timeout=5.0)

        resp, err = _call_with_timeout(_do_request, timeout=8.0)
        if err == "timeout":
            status = -2
            entry = {"method": method, "path": path, "url": url, "status": status,
                     "error": "<请求超时 8s>"}
            failed += 1
            failures.append(entry)
            print(f"{C.GRAY}[{idx}/{len(api_endpoints)}]{C.END} {C.RED}{method:6s}{C.END} {path} -> 超时")
            continue
        if err is not None:
            status = -1
            body_text = f"<请求异常: {type(err).__name__}: {err}>"
            entry = {"method": method, "path": path, "url": url, "status": status,
                     "error": body_text[:500]}
            failed += 1
            failures.append(entry)
            print(f"{C.GRAY}[{idx}/{len(api_endpoints)}]{C.END} {C.RED}{method:6s}{C.END} {path} -> 异常 {body_text[:80]}")
            continue
        status = resp.status_code

        body_text = ""
        try:
            body_text = resp.text[:500]
        except Exception:
            body_text = "<无法读取响应体>"

        good_set = GOOD_GET if method == "GET" else GOOD_WRITE
        is_good = status in good_set
        is_500 = status == 500  # 只把严格的 500 视为错误；503 等降级响应已在 GOOD_SET 中

        if is_500:
            errors_500 += 1
            err500_list.append({
                "method": method, "path": path, "url": url, "status": status,
                "body": body_text,
            })
            failed += 1
            print(f"{C.RED}[{idx}/{len(api_endpoints)}] {method:6s} {path} -> {status} [500错误]{C.END}")
        elif is_good:
            passed += 1
            tag = f"{C.GREEN}{status}{C.END}" if 200 <= status < 300 else f"{C.YELLOW}{status}{C.END}"
            print(f"{C.GRAY}[{idx}/{len(api_endpoints)}]{C.END} {method:6s} {path} -> {tag}")
        else:
            failed += 1
            failures.append({
                "method": method, "path": path, "url": url, "status": status,
                "body": body_text,
            })
            print(f"{C.RED}[{idx}/{len(api_endpoints)}] {method:6s} {path} -> {status} [未预期]{C.END}")

    total = len(api_endpoints)
    pass_rate = round(passed / total * 100, 2) if total else 0.0
    summary = {
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": len(skipped_pages),
        "errors_500": errors_500,
        "pass_rate": pass_rate,
        "import_seconds": round(time.time() - t0, 2),
    }
    report["summary"] = summary
    report["failures"] = failures
    report["errors_500"] = err500_list

    REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # 控制台汇总
    print()
    print(f"{C.BOLD}=== 测试汇总 ==={C.END}")
    print(f"  总端点数     : {total}")
    print(f"  通过         : {C.GREEN}{passed}{C.END}")
    print(f"  失败         : {C.RED}{failed}{C.END}")
    print(f"  跳过(页面)   : {summary['skipped']}")
    print(f"  500 错误     : {C.RED}{errors_500}{C.END}")
    print(f"  通过率       : {C.CYAN}{pass_rate}%{C.END}")
    print(f"  报告已写入   : {REPORT_PATH}")
    return report


# ============== pytest 兼容入口 ==============
def test_no_500_errors():
    """目标断言：0 个 500 错误。"""
    report = run_full_test()
    s = report.get("summary", {})
    assert s.get("errors_500", 1) == 0, f"存在 {s.get('errors_500')} 个 500 错误，详见 {REPORT_PATH}"


def test_pass_rate_above_95():
    """目标断言：>=95% 端点正常响应。"""
    report = run_full_test()
    s = report.get("summary", {})
    assert s.get("pass_rate", 0) >= 95.0, f"通过率 {s.get('pass_rate')}% 低于 95%，详见 {REPORT_PATH}"


if __name__ == "__main__":
    result = run_full_test()
    s = result["summary"]
    # 直接运行时：500 错误数为 0 才算退出码 0
    sys.exit(0 if s.get("errors_500", 1) == 0 else 1)
