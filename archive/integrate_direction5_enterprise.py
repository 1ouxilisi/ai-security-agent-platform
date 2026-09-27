# -*- coding: utf-8 -*-
"""方向5：企业级安全与合规 — 路由注入与验证脚本。

运行:
    python integrate_direction5_enterprise.py
不修改任何业务逻辑，仅向 app.py 注入路由与前端页面注册代码。
"""
from __future__ import annotations

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

MARK_TAG = "方向5：企业级安全与合规路由"

ROUTES_CODE = '''

# ============== 方向5：企业级安全与合规路由（27端点） ==============
try:
    from api_server.enterprise_security_routes import router as enterprise_sec_router
    app.include_router(enterprise_sec_router)
    log.info("方向5 企业级安全与合规路由已注册：RBAC/审计/加密/基线/合规/控制台，共27个端点")
except Exception as e:
    log.warning(f"方向5 企业级安全与合规路由注册失败: {e}")


# ============== 方向5：企业级安全与合规前端控制台 ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_ENT5
    _ENT5_PAGES = [
        ("/enterprise-security", "enterprise_security_console.html", "企业级安全与合规"),
    ]
    for _route, _fname, _desc in _ENT5_PAGES:
        def _make_page_ent5(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_ent5():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_ENT5(content=_f.read())
                return _HTMLR_ENT5(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_ent5
        _make_page_ent5()
    log.info("方向5 企业级安全与合规前端页面已注册：/enterprise-security")
except Exception as e:
    log.warning(f"方向5 企业级安全与合规前端页面注册失败: {e}")

'''


def inject_routes() -> bool:
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if MARK_TAG in content:
        print("[INFO] 企业安全路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 企业安全路由注册代码已注入 app.py")
    return True


def verify_files() -> bool:
    print("\n" + "=" * 60)
    print("【文件存在验证】")
    print("=" * 60)
    expected = [
        "enterprise_security/__init__.py",
        "enterprise_security/rbac.py",
        "enterprise_security/audit_log.py",
        "enterprise_security/data_encryption.py",
        "enterprise_security/security_baseline.py",
        "enterprise_security/compliance_report.py",
        "enterprise_security/enterprise_dashboard.py",
        "api_server/enterprise_security_routes.py",
        "api_server/enterprise_security_console.html",
    ]
    missing = []
    for fpath in expected:
        full = os.path.join(PROJECT_ROOT, fpath)
        if os.path.exists(full):
            print(f"  OK  {fpath} ({os.path.getsize(full):,} bytes)")
        else:
            print(f"  ??  {fpath} MISSING")
            missing.append(fpath)
    return not missing


def verify_imports() -> bool:
    print("\n" + "=" * 60)
    print("【模块导入验证】")
    print("=" * 60)
    try:
        from enterprise_security import (
            RBACManager, AuditLogger, DataEncryption,
            SecurityBaseline, ComplianceReportGenerator, EnterpriseDashboard,
        )
        print("  OK  enterprise_security 包导入成功")
    except Exception as e:
        print(f"  FAIL enterprise_security 导入失败: {e}")
        return False
    try:
        from api_server.enterprise_security_routes import router
        n = len(router.routes)
        print(f"  OK  路由模块导入成功，{n} 个端点")
        return n >= 25
    except Exception as e:
        print(f"  FAIL 路由模块导入失败: {e}")
        return False


def demo() -> None:
    print("\n" + "=" * 60)
    print("【功能演示】")
    print("=" * 60)
    from enterprise_security.rbac import RBACManager, PermissionDenied
    from enterprise_security.audit_log import AuditLogger
    from enterprise_security.data_encryption import DataEncryption
    from enterprise_security.security_baseline import SecurityBaseline
    from enterprise_security.compliance_report import ComplianceReportGenerator

    # RBAC 演示
    rbac = RBACManager()
    print("\n-- RBAC --")
    for u in rbac.list_users():
        print(f"   {u['user_id']} {u['username']:<16} 角色={u['role_name']:<4} 数据={u['data_scope']}")
    # 越权尝试：viewer 尝试发起扫描
    try:
        rbac.require("U00004", "scan.run")
        print("   viewer scan.run: 不应通过")
    except PermissionDenied as e:
        print(f"   viewer 尝试 scan.run -> 已拒绝: {e}")
    print("   analyst scan.run -> 允许:", rbac.has_permission("U00002", "scan.run"))
    print("   auditor audit.view -> 允许:", rbac.has_permission("U00003", "audit.view"))
    print("   analyst audit.view -> 允许:", rbac.has_permission("U00002", "audit.view"))

    # 审计日志演示
    audit = AuditLogger()
    audit.record("U00001", "user.create", "U00005", ip="10.0.0.5")
    audit.record("U00002", "scan.run", "192.168.1.0/24", ip="10.0.0.8")
    audit.record("U00004", "denied:scan.run", "-", ip="10.0.0.9",
                 result="denied", detail="权限不足")
    print("\n-- Audit --")
    print("   总事件:", audit.stats()["total_events"],
          "成功率:", audit.stats()["success_rate"], "%")
    flt = audit.query(action="denied:scan.run")
    print("   按操作类型筛选 denied:scan.run ->", flt["total"], "条")

    # 加密演示
    crypto = DataEncryption()
    st = crypto.self_test()
    print("\n-- Crypto --")
    print("   算法:", st["algorithm"], "roundtrip:", st["roundtrip_ok"])
    tok = crypto.store_secret("demo_key", "sk-super-secret-abcdef123456")
    print("   密文前缀:", tok["ciphertext"][:24], "...")
    print("   解密还原:", crypto.reveal_secret("demo_key"))
    print("   脱敏:", crypto.mask("sk-super-secret-abcdef123456"))

    # 基线 + 合规演示
    bl = SecurityBaseline()
    rep = bl.run()
    print("\n-- Baseline --")
    print("   得分:", rep["summary"]["score"], "等级:", rep["summary"]["grade"],
          "失败项:", rep["summary"]["failed"])

    cr = ComplianceReportGenerator()
    mlps = cr.generate("mlps2")
    iso = cr.generate("iso27001")
    print("\n-- Compliance --")
    print(f"   等保2.0: 符合率 {mlps['score']}% 结论={mlps['level']}")
    print(f"   ISO27001: 符合率 {iso['score']}% 结论={iso['level']}")
    print("   等保不符合项:", [g['id'] for g in mlps['gaps']])


if __name__ == "__main__":
    print("=" * 60)
    print("方向5：企业级安全与合规 — 集成验证")
    print("=" * 60)
    f = verify_files()
    i = verify_imports()
    demo()
    inj = inject_routes()
    print("\n" + "=" * 60)
    print("【最终结论】")
    print("=" * 60)
    if f and i and inj:
        print("✅ 方向5 企业级安全与合规 — 全部就绪，访问 /enterprise-security")
    else:
        print("⚠️  部分项需关注，请检查上方日志")
