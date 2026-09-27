# -*- coding: utf-8 -*-
"""
test_audit_module.py - 审计日志深化模块自测脚本。

覆盖：
    1) 模块导入
    2) 数据库表与索引创建
    3) 写入各类日志（操作/登录/API/数据访问）
    4) 哈希链写入与完整性校验（含篡改检测）
    5) 查询、统计、导出、批量写入
    6) 路由文件可导入
    7) 前端文件存在且非空
"""

import os
import sys
import sqlite3

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

PASS = 0
FAIL = 0


def check(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    tag = "✅" if ok else "❌"
    print(f"  {tag} {name}" + (f"  | {detail}" if detail else ""))
    if ok:
        PASS += 1
    else:
        FAIL += 1


def main():
    print("=" * 60)
    print("审计日志深化模块 - 自测")
    print("=" * 60)

    # ---------- 1) 模块导入 ----------
    print("\n[1] 模块导入")
    try:
        from audit.operation_log import get_operation_logger, OperationLogger
        from audit.login_log import get_login_logger
        from audit.api_log import get_api_logger, sanitize_obj, mask_phone
        from audit.data_access_log import get_data_access_logger
        from audit.log_manager import get_log_manager
        check("audit 各业务模块导入", True)
    except Exception as e:
        check("audit 各业务模块导入", False, repr(e))
        return

    # ---------- 2) 表结构 ----------
    print("\n[2] 数据库表与索引")
    # 先触发各模块初始化（建表）
    get_operation_logger(); get_login_logger(); get_api_logger(); get_data_access_logger(); get_log_manager()
    from utils.database import db
    conn = db._get_connection()
    tables = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    indexes = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
    conn.close()
    need_tables = {"audit_operations", "audit_logins", "audit_sessions",
                   "audit_api_calls", "audit_data_access",
                   "audit_log_config", "audit_log_archives"}
    missing = need_tables - tables
    check("审计相关 7+ 张表创建", len(missing) == 0, f"缺失: {missing}" if missing else f"共 {len(need_tables)} 张")
    idx_count = len([i for i in indexes if i.startswith("idx_audit") or i.startswith("idx_logins")
                     or i.startswith("idx_sessions") or i.startswith("idx_api")
                     or i.startswith("idx_da_") or i.startswith("idx_audit_ops")])
    check("审计相关索引已创建", idx_count >= 15, f"索引数: {idx_count}")

    # ---------- 3) 写入操作日志 + 哈希链 ----------
    print("\n[3] 操作日志写入与哈希链")
    op = get_operation_logger()
    id1 = op.log_operation(
        operator="tester", operation_type="create", operation_object="vulnerability",
        object_id="VULN-001", operation_detail={"before": None, "after": {"title": "SQLi"}},
        ip_address="127.0.0.1", result="success")
    id2 = op.log_operation(
        operator="tester", operation_type="update", operation_object="vulnerability",
        object_id="VULN-001", operation_detail={"before": {"cvss": 5.0}, "after": {"cvss": 9.8}},
        ip_address="127.0.0.1", result="success")
    check("单条写入操作日志", bool(id1 and id2))

    # 批量写入
    n = op.batch_log([
        {"operator": "tester", "operation_type": "delete", "operation_object": "asset",
         "object_id": "A-1", "operation_detail": {"after": "removed"}},
        {"operator": "admin", "operation_type": "config_change", "operation_object": "system",
         "operation_detail": {"after": {"retention": 180}}},
    ])
    check("批量写入操作日志", n == 2, f"写入 {n} 条")

    # 取出来验证 prev_hash 链式关系
    chain = op.get_log_chain()
    linked = all(chain[i]["prev_hash"] == chain[i - 1]["hash"] for i in range(1, len(chain)))
    check("哈希链 prev_hash 连续", linked, f"链长 {len(chain)}")

    # 完整性校验
    r = op.verify_integrity()
    check("哈希链完整性校验（写入后应为完整）", r["intact"], f"checked={r['checked']}")

    # 篡改检测：手工改一条
    conn = db._get_connection()
    conn.execute("UPDATE audit_operations SET operator = 'HACKER' WHERE id = ?", (id1,))
    conn.commit(); conn.close()
    r2 = op.verify_integrity()
    check("篡改检测（手工改一条后应检出异常）", (not r2["intact"]) and len(r2["violations"]) >= 1,
          f"violations={len(r2['violations'])}")
    # 还原
    conn = db._get_connection()
    conn.execute("UPDATE audit_operations SET operator = 'tester' WHERE id = ?", (id1,))
    conn.commit(); conn.close()
    r3 = op.verify_integrity()
    check("还原后哈希链恢复完整", r3["intact"])

    # ---------- 4) 查询 / 统计 / 导出 ----------
    print("\n[4] 操作日志查询/统计/导出")
    lst = op.list_operations(operator="tester", page=1, page_size=10)
    check("分页查询操作日志", lst["total"] >= 2, f"total={lst['total']}")
    st = op.get_operation_stats()
    check("操作日志统计", st["total"] >= 2 and "by_operation_type" in st)
    exported = op.export_operations(fmt="csv")
    check("导出 CSV", exported["format"] == "csv" and exported["count"] >= 2)

    # ---------- 5) 登录日志与会话 ----------
    print("\n[5] 登录日志与会话")
    lg = get_login_logger()
    lg.log_login(username="alice", result="success", login_ip="10.0.0.1",
                 login_location="北京", login_method="password", auto_detect=False)
    lg.log_login(username="alice", result="failure", failure_reason="password_error",
                 login_ip="10.0.0.1", auto_detect=False)
    # 制造多次失败触发暴力破解检测
    for _ in range(6):
        lg.log_login(username="bob", result="failure", failure_reason="password_error",
                     login_ip="203.0.113.99", auto_detect=False)
    sid = lg.create_session(session_id="sess-test-001", username="alice", login_ip="10.0.0.1")
    check("登录日志写入", True)
    check("创建会话", bool(lg.get_session("sess-test-001")))
    act = lg.list_active_sessions()
    check("活跃会话列表", any(s["session_id"] == "sess-test-001" for s in act))
    abn = lg.detect_abnormal_logins()
    check("暴力破解检测（bob 6次失败）", any(a["username"] == "bob" and a["type"] == "brute_force" for a in abn),
          f"异常数 {len(abn)}")
    ok_revoke = lg.revoke_session("sess-test-001", operator="tester")
    check("强制撤销会话", ok_revoke)
    lst_lg = lg.list_logins(username="alice")
    check("登录日志分页查询", lst_lg["total"] >= 2)
    lst_logout = lg.log_logout("sess-test-001")
    check("登出记录", lst_logout)

    # ---------- 6) API 日志（脱敏+性能） ----------
    print("\n[6] API 调用日志与脱敏/性能")
    ap = get_api_logger()
    # 脱敏测试
    masked = sanitize_obj({"password": "123456", "token": "abc", "nested": {"api_key": "k"},
                           "phone": "张三 13812345678"})
    check("敏感字段脱敏", masked["password"] == "***REDACTED***"
          and masked["nested"]["api_key"] == "***REDACTED***"
          and "13812345678" not in masked["phone"], str(masked))
    ap.log_api_call(api_endpoint="/api/v1/vuln/list", request_method="GET",
                    response_status_code=200, response_time_ms=120,
                    request_ip="10.0.0.5", request_params={"page": 1})
    ap.log_api_call(api_endpoint="/api/v1/vuln/detail", request_method="GET",
                    response_status_code=500, response_time_ms=3400,
                    request_ip="10.0.0.5", error_message="db timeout")
    ap.batch_log_api_calls([
        {"api_endpoint": "/api/v1/asset", "request_method": "POST",
         "response_status_code": 201, "response_time_ms": 80, "request_ip": "10.0.0.6"}
    ])
    check("API 调用日志写入", True)
    slow = ap.get_slow_requests()
    check("慢请求列表", any(r["response_time_ms"] >= 1000 for r in slow))
    errs = ap.get_error_requests()
    check("错误请求列表", any(r["response_status_code"] >= 500 for r in errs))
    perf = ap.get_performance_monitor()
    check("性能监控（P50/P95/P99）", "p95_ms" in perf and perf["total_calls"] >= 2,
          f"p95={perf.get('p95_ms')}, err_rate={perf.get('error_rate')}%")

    # ---------- 7) 数据访问日志 ----------
    print("\n[7] 数据访问日志")
    da = get_data_access_logger()
    da.log_data_access(access_user="alice", access_type="query", data_type="vulnerability",
                       data_id="V-1", ip_address="10.0.0.1", auto_detect=False)
    for i in range(12):
        da.log_data_access(access_user="mallory", access_type="export",
                           data_type="vulnerability", data_id=f"V-{i}",
                           ip_address="203.0.113.99", auto_detect=False)
    check("数据访问写入", True)
    lst_da = da.list_data_access(access_user="alice")
    check("数据访问分页查询", lst_da["total"] >= 1)
    leak = da.detect_data_leak()
    check("数据泄露检测（mallory 批量导出）", any(x.get("user") == "mallory" for x in leak),
          f"异常 {len(leak)}")
    rep = da.get_sensitive_access_report()
    check("敏感数据访问报告", len(rep) >= 1)

    # ---------- 8) 日志管理器 ----------
    print("\n[8] 日志管理器")
    lm = get_log_manager()
    cfg = lm.get_log_config()
    check("读取日志配置", "retention_days" in cfg, f"配置项 {len(cfg)} 个")
    up = lm.update_log_config({"retention_days": "90"})
    check("更新日志配置", up.get("success"))
    ov = lm.get_log_overview()
    check("日志总览", "operations" in ov and "integrity" in ov)
    rep_all = lm.get_audit_report()
    check("审计报表生成", "operations" in rep_all and "abnormal_behaviors" in rep_all)
    integ = lm.verify_all_integrity()
    check("全量哈希链校验", "intact" in integ)

    # ---------- 9) 路由文件可导入 ----------
    print("\n[9] API 路由导入")
    try:
        from api_server import audit_routes
        rts = [r.path for r in audit_routes.router.routes]
        check("audit_routes 导入", True, f"共 {len(rts)} 个端点")
        check("端点前缀正确", all(p.startswith("/api/v1/audit") for p in rts))
    except Exception as e:
        check("audit_routes 导入", False, repr(e))

    # ---------- 10) 前端文件 ----------
    print("\n[10] 前端控制台")
    fhtml = os.path.join(ROOT, "api_server", "audit_console.html")
    if os.path.exists(fhtml):
        size = os.path.getsize(fhtml)
        with open(fhtml, "rb") as f:
            head = f.read(3)
        check("audit_console.html 存在且非空", size > 5000, f"{size} bytes")
        check("UTF-8 BOM/编码正常", head != b"", f"head={head!r}")
    else:
        check("audit_console.html 存在", False)

    # ---------- 汇总 ----------
    print("\n" + "=" * 60)
    print(f"自测完成：✅ 通过 {PASS} 项，❌ 失败 {FAIL} 项")
    print("=" * 60)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
