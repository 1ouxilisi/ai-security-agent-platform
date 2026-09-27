# -*- coding: utf-8 -*-
"""方向5：SRC挖洞辅助工具 — 路由注入与验证脚本"""
import os, sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 方向5：SRC 挖洞工作台路由（34端点） ==============
try:
    from api_server.src_workbench_routes import router as src_workbench_router
    app.include_router(src_workbench_router)
    log.info("方向5 SRC挖洞工作台路由已注册：资产侦察/端口扫描/漏洞扫描/报告生成/项目管理/统计，共34个端点")
except Exception as e:
    log.warning(f"方向5 SRC挖洞工作台路由注册失败: {e}")


# ============== 方向5：SRC 挖洞工作台前端控制台 ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_SRC5
    _SRC5_PAGES = [
        ("/src-workbench", "src_workbench_console.html", "SRC挖洞工作台"),
    ]
    for _route, _fname, _desc in _SRC5_PAGES:
        def _make_page_handler_src5(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_src5():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_SRC5(content=_f.read())
                return _HTMLR_SRC5(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_src5
        _make_page_handler_src5()
    log.info("方向5 SRC挖洞工作台前端页面已注册：/src-workbench")
except Exception as e:
    log.warning(f"方向5 SRC挖洞工作台前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "方向5：SRC 挖洞工作台路由" in content:
        print("[INFO] 方向5路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 方向5 SRC挖洞工作台路由注册代码已注入app.py")
    return True


def verify_files():
    print("\n" + "=" * 60)
    print("【文件存在验证】")
    print("=" * 60)
    expected = [
        "src_workbench/__init__.py",
        "src_workbench/asset_discovery.py",
        "src_workbench/port_scan.py",
        "src_workbench/vuln_scan.py",
        "src_workbench/report_generator.py",
        "src_workbench/project_tracker.py",
        "src_workbench/src_dashboard.py",
        "api_server/src_workbench_routes.py",
        "api_server/src_workbench_console.html",
    ]
    missing = []
    for fpath in expected:
        full = os.path.join(PROJECT_ROOT, fpath)
        if os.path.exists(full):
            size = os.path.getsize(full)
            print(f"  ✅ {fpath} ({size:,} bytes)")
        else:
            print(f"  ❌ {fpath} MISSING")
            missing.append(fpath)
    return len(missing) == 0


def verify_imports():
    print("\n" + "=" * 60)
    print("【模块导入验证】")
    print("=" * 60)
    try:
        from src_workbench import (
            AssetDiscovery, PortScanner, VulnScanner,
            SRCReportGenerator, ProjectTracker, SRCDashboard,
        )
        print("  ✅ src_workbench 包导入成功")
    except Exception as e:
        print(f"  ❌ src_workbench 导入失败: {e}")
        return False

    try:
        from api_server.src_workbench_routes import router
        print(f"  ✅ 路由模块导入成功，{len(router.routes)} 个端点")
    except Exception as e:
        print(f"  ❌ 路由模块导入失败: {e}")
        return False
    return True


def verify_tools():
    print("\n" + "=" * 60)
    print("【真实工具可用性验证】")
    print("=" * 60)
    from src_workbench.asset_discovery import SUBFINDER_BIN, HTTPX_BIN
    from src_workbench.port_scan import NMAP_BIN
    from src_workbench.vuln_scan import NUCLEI_BIN

    tools = [
        ("subfinder", SUBFINDER_BIN),
        ("httpx", HTTPX_BIN),
        ("nmap", NMAP_BIN),
        ("nuclei", NUCLEI_BIN),
    ]
    for name, path in tools:
        if path:
            print(f"  ✅ {name}: {path}")
        else:
            fallback = {
                "subfinder": "（回退到 crt.sh CT 日志）",
                "httpx": "（回退到 Python requests）",
            }.get(name, "（未安装）")
            print(f"  ⚠️  {name}: not found {fallback}")


def verify_demo():
    print("\n" + "=" * 60)
    print("【工作流演示数据验证】")
    print("=" * 60)
    from src_workbench.report_generator import SRCReportGenerator
    from src_workbench.project_tracker import ProjectTracker

    rg = SRCReportGenerator()
    pt = ProjectTracker()

    # 模拟3个漏洞发现
    findings = [
        {"name": "Git目录泄露", "severity": "high", "url": "http://a.test.com/.git/config",
         "host": "a.test.com", "category": "exposure", "cwe": "CWE-540",
         "description": ".git目录暴露", "tags": ["exposure", "git"], "template_id": "git-exp"},
        {"name": "Redis未授权访问", "severity": "critical", "url": "http://b.test.com:6379",
         "host": "b.test.com", "category": "vulnerability", "cwe": "CWE-306",
         "description": "Redis未授权", "tags": ["redis", "rce"], "template_id": "redis-unauth"},
        {"name": "phpinfo信息泄露", "severity": "low", "url": "http://c.test.com/phpinfo.php",
         "host": "c.test.com", "category": "exposure", "cwe": "CWE-200",
         "description": "phpinfo可访问", "tags": ["exposure"], "template_id": "phpinfo"},
    ]

    proj = pt.create_project("演示项目", "test.com", "butian")
    reports = rg.generate_batch(findings, "butian", "演示项目")
    print(f"  生成 {len(reports)} 份SRC报告:")
    for r in reports:
        print(f"    - [{r['vulnerability']['severity'].upper()}] {r['vulnerability']['title']}")

    # 模拟状态流转
    pt.update_report_status(proj["project_id"], reports[0]["report_id"], "confirmed", 800)
    pt.update_report_status(proj["project_id"], reports[1]["report_id"], "submitted", 0)
    pt.update_report_status(proj["project_id"], reports[2]["report_id"], "ignored", 0)

    stats = pt.get_stats()
    print(f"\n  项目统计:")
    print(f"    总项目数: {stats['total_projects']}")
    print(f"    已提交: {stats['total_submitted']}")
    print(f"    已确认: {stats['total_confirmed']}")
    print(f"    赏金总额: ¥{stats['total_bounty']}")
    print(f"    确认率: {stats['confirm_rate_pct']}%")
    print("  ✅ 演示数据验证通过")


if __name__ == "__main__":
    print("=" * 60)
    print("方向5：SRC挖洞辅助工具 — 集成验证")
    print("=" * 60)

    ok1 = verify_files()
    ok2 = verify_imports()
    verify_tools()
    verify_demo()

    injected = inject_routes()

    print("\n" + "=" * 60)
    print("【最终结论】")
    print("=" * 60)
    if ok1 and ok2 and injected:
        print("✅ 方向5 SRC挖洞工作台 — 全部就绪")
    else:
        print("⚠️  部分项需要关注，请检查上方日志")
