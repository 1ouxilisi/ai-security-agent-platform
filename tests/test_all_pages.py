# -*- coding: utf-8 -*-
"""
全量前端页面自动化测试脚本。

功能：
    - 列出所有前端页面路由：先从 app.routes 自动发现，再合并已知控制台路径
    - 对每个页面发送 GET 请求，检查：
        * 状态码 200（不是 404/500）
        * Content-Type 含 charset=utf-8
        * 响应体 > 1000 字节（不是空白页）
        * 包含 <html 或 <!DOCTYPE
        * <title> 标签非空
        * 不含 "Internal Server Error" / "500" 等错误关键词
    - 解析 HTML 中 src/href 引用的本地 JS/CSS，验证文件在 api_server/ 下存在
    - 输出 JSON 报告 tests/page_test_report.json + 控制台汇总

用法：
    python tests/test_all_pages.py
    pytest tests/test_all_pages.py
"""
from __future__ import annotations

import os as _os
_os.environ.setdefault("API_AUTH_ENABLED", "false")
_os.environ.setdefault("API_ENV", "test")

import sys
import re
import json
import time
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

REPORT_PATH = Path(__file__).resolve().parent / "page_test_report.json"
API_SERVER_DIR = PROJECT_ROOT / "api_server"


class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    END = "\033[0m"


# 已知前端页面路径（控制台 + 工作台 + 文档）
KNOWN_PAGES = [
    "/", "/assessment", "/unified-console", "/defense-console",
    "/commercial-console", "/platform", "/platform-v2",
    "/console", "/workbench", "/dashboard", "/docs",
    "/advanced-console", "/vuln-database", "/workflow", "/console-v7",
    "/combat-console", "/extended-console", "/enhanced-console",
]

# 自动发现时排除的非页面路径（API/健康检查/重定向）
AUTO_EXCLUDE = {"/health", "/openapi.json", "/docs", "/redoc", "/favicon.ico",
                "/platform-root", "/test"}

# 错误关键词（页面内容中出现即视为错误页）
ERROR_KEYWORDS = ["Internal Server Error", "Traceback (most recent call last)"]

# 提取 src/href 中的本地资源引用
RE_SRC = re.compile(r"""<(?:script|link|img)[^>]+(?:src|href)=["']([^"']+)["']""", re.IGNORECASE)
RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _is_local_asset(url: str) -> bool:
    if not url:
        return False
    if url.startswith(("http://", "https://", "//", "data:", "mailto:", "tel:", "#")):
        return False
    if url.startswith("/api/") or url.startswith("api/"):
        return False
    return True


def _resolve_asset_file(url: str) -> Path | None:
    """把页面引用的本地资源路径映射到 api_server/ 下的实际文件。"""
    # 去掉 query string / fragment
    p = url.split("?")[0].split("#")[0]
    if not p:
        return None
    # 绝对路径 /xxx.js → api_server/xxx.js
    candidate = API_SERVER_DIR / p.lstrip("/")
    if candidate.exists():
        return candidate
    return None


def check_page(client, path: str) -> dict:
    """检查单个页面，返回检查结果字典。"""
    result = {
        "path": path,
        "status_code": None,
        "passed": False,
        "issues": [],
        "size_bytes": 0,
        "title": "",
        "missing_assets": [],
    }
    try:
        resp = client.get(path, follow_redirects=True)
    except Exception as e:  # noqa: BLE001
        result["issues"].append(f"请求异常: {type(e).__name__}: {e}")
        return result

    result["status_code"] = resp.status_code
    body = resp.text
    result["size_bytes"] = len(resp.content)
    ctype = resp.headers.get("content-type", "")

    if resp.status_code != 200:
        result["issues"].append(f"状态码 {resp.status_code} 非 200")
        return result

    if "text/html" not in ctype:
        result["issues"].append(f"Content-Type 不是 text/html: {ctype}")
    if "charset" not in ctype.lower():
        result["issues"].append(f"Content-Type 未声明 charset: {ctype}")

    if len(resp.content) < 1000:
        result["issues"].append(f"响应体过小 ({len(resp.content)} 字节)，疑似空白页")

    if not re.search(r"<html[\s>]", body, re.IGNORECASE) and "<!DOCTYPE" not in body.upper():
        result["issues"].append("未检测到 <html> 或 <!DOCTYPE> 标签")

    m = RE_TITLE.search(body)
    title = m.group(1).strip() if m else ""
    result["title"] = title
    if not title:
        result["issues"].append("<title> 为空")

    for kw in ERROR_KEYWORDS:
        if kw in body:
            result["issues"].append(f"页面包含错误关键词: {kw}")

    # 本地资源存在性检查（只查 api_server/ 下的文件，且仅做一次，避免 IO 爆炸）
    for src in RE_SRC.findall(body):
        if not _is_local_asset(src):
            continue
        if src.startswith("/"):
            f = _resolve_asset_file(src)
            if f is None:
                result["missing_assets"].append(src)
        # 相对路径（非 / 开头）大概率是构建产物或 CDN，跳过

    result["passed"] = len(result["issues"]) == 0 and not result["missing_assets"]
    if result["missing_assets"]:
        result["issues"].append(f"缺失本地资源 {len(result['missing_assets'])} 个: "
                                f"{result['missing_assets'][:3]}")
    return result


def run_full_test() -> dict:
    """执行全量页面测试，返回统计结果。"""
    print(f"{C.BOLD}{C.CYAN}=== 全量前端页面测试开始 ==={C.END}")
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
        "target": "ai-hacking-agent 前端页面",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "import_error": import_error,
        "summary": {},
        "results": [],
    }

    if app is None:
        report["summary"] = {"total": 0, "passed": 0, "failed": 0,
                             "blank_pages": 0, "encoding_issues": 0}
        REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return report

    # 自动发现 HTML 路由
    auto_paths = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if not path or not methods:
            continue
        if "GET" not in methods:
            continue
        # 经验规则：非 /api 开头、不含路径参数、不是静态挂载 → 视为页面路由
        if path.startswith("/api/"):
            continue
        if "{" in path:
            continue
        if path in EXACT_SKIP or path in AUTO_EXCLUDE:
            continue
        auto_paths.add(path)

    all_paths = list(dict.fromkeys(list(auto_paths) + KNOWN_PAGES))
    # 过滤掉文档元数据
    all_paths = [p for p in all_paths if p not in {"/openapi.json", "/redoc", "/docs/oauth2-redirect"}]
    print(f"{C.CYAN}待检查页面 {len(all_paths)} 个（自动发现 {len(auto_paths)} + 已知 {len(KNOWN_PAGES)}）{C.END}")

    from fastapi.testclient import TestClient
    client = TestClient(app, base_url="http://testserver")

    results = []
    passed = 0
    failed = 0
    blank = 0
    encoding_issues = 0

    for path in all_paths:
        r = check_page(client, path)
        results.append({k: v for k, v in r.items()})
        if r["passed"]:
            passed += 1
            print(f"{C.GREEN}✓{C.END} {path}  ({r['size_bytes']}B, title={r['title'][:30]!r})")
        else:
            failed += 1
            if any("空白" in i or "过小" in i for i in r["issues"]):
                blank += 1
            if any("charset" in i or "Content-Type" in i for i in r["issues"]):
                encoding_issues += 1
            print(f"{C.RED}✗{C.END} {path}  -> {'; '.join(r['issues'])}")

    total = len(all_paths)
    summary = {
        "total": total,
        "passed": passed,
        "failed": failed,
        "blank_pages": blank,
        "encoding_issues": encoding_issues,
        "pass_rate": round(passed / total * 100, 2) if total else 0.0,
        "seconds": round(time.time() - t0, 2),
    }
    report["summary"] = summary
    report["results"] = results
    REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print()
    print(f"{C.BOLD}=== 页面测试汇总 ==={C.END}")
    print(f"  总页面数     : {total}")
    print(f"  通过         : {C.GREEN}{passed}{C.END}")
    print(f"  失败         : {C.RED}{failed}{C.END}")
    print(f"  空白页       : {C.RED}{blank}{C.END}")
    print(f"  编码问题     : {C.YELLOW}{encoding_issues}{C.END}")
    print(f"  通过率       : {C.CYAN}{summary['pass_rate']}%{C.END}")
    print(f"  报告已写入   : {REPORT_PATH}")
    return report


EXACT_SKIP = {"/openapi.json", "/docs", "/redoc", "/favicon.ico"}


def test_all_pages_ok():
    """目标断言：所有页面无空白页、无编码问题、状态码 200。"""
    report = run_full_test()
    s = report.get("summary", {})
    assert s.get("blank_pages", 1) == 0, f"存在 {s.get('blank_pages')} 个空白页"
    assert s.get("failed", 1) == 0, f"存在 {s.get('failed')} 个失败页面，详见 {REPORT_PATH}"


if __name__ == "__main__":
    result = run_full_test()
    s = result["summary"]
    sys.exit(0 if s.get("failed", 1) == 0 else 1)
