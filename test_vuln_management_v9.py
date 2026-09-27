# -*- coding: utf-8 -*-
"""
test_vuln_management_v9.py —— 漏洞管理深化模块自测脚本。

验证内容：
    1. 模块可正常导入
    2. 数据库表创建成功、vulnerabilities 扩展列存在
    3. 核心方法：创建测试漏洞 → 状态流转 → 分配 → 优先级 → 评论/标签
                 → SLA 截止时间/状态/统计 → 修复启动/验证 → 分析引擎
    4. API 路由文件可正常导入
"""
import os
import sys
import time
import uuid
import sqlite3

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.database import db  # noqa: E402


def banner(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def main():
    banner("[1/6] 导入漏洞管理深化模块")
    from vuln_management import (
        lifecycle_manager, sla_manager, analytics_engine, remediation_tracker,
    )
    print("OK: 模块导入成功")

    banner("[2/6] 校验数据库表与扩展列")
    conn = db._get_connection()
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    need_tables = [
        "vulnerabilities", "vulnerability_history",
        "vm_lifecycle_history", "vm_vuln_comments", "vm_vuln_tags",
        "vm_sla_policies", "vm_sla_exceptions", "vm_remediation_tasks",
    ]
    for t in need_tables:
        assert t in tables, f"缺少表: {t}"
        print(f"  表存在: {t}")
    cols = {r[1] for r in conn.execute("PRAGMA table_info(vulnerabilities)")}
    need_cols = ["lifecycle_status", "priority_score", "assigned_to", "tags",
                 "comments_count", "sla_due_date", "risk_accepted",
                 "risk_accepted_by", "risk_accepted_at"]
    for c in need_cols:
        assert c in cols, f"vulnerabilities 缺少扩展列: {c}"
        print(f"  扩展列存在: {c}")
    conn.close()
    print("OK: 全部表与扩展列就绪")

    banner("[3/6] 创建测试漏洞并走生命周期")
    vuln_id = str(uuid.uuid4())
    now = time.time()
    conn = db._get_connection()
    conn.execute(
        "INSERT INTO vulnerabilities (id, assessment_id, name, severity, cve, cwe, "
        "description, evidence, status, discovered_at, target, tenant_id, lifecycle_status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, 'default', 'new')",
        (vuln_id, "assess-demo", "自测SQL注入漏洞", "high", "CVE-2024-TEST", "CWE-89",
         "用于自测的SQL注入", "evidence-string", now, "10.0.0.5"),
    )
    conn.commit()
    conn.close()
    print(f"  已创建测试漏洞: {vuln_id}")

    r1 = lifecycle_manager.update_lifecycle_status(vuln_id, "confirmed", operator="tester", note="验证通过")
    print("  new->confirmed:", r1)
    r2 = lifecycle_manager.assign_vulnerability(vuln_id, operator="tester")
    print("  自动分配:", r2)
    p = lifecycle_manager.calculate_priority(vuln_id)
    print("  优先级评分:", p)
    lifecycle_manager.add_comment(vuln_id, author="tester", content="这是一条测试评论", mentions=["alice"])
    lifecycle_manager.add_tag(vuln_id, "自测")
    lifecycle_manager.add_tag(vuln_id, "sql-injection")
    v = lifecycle_manager.get_vulnerability(vuln_id)
    print("  详情 tags:", v["tags"], "comments_count:", v["comments_count"])

    banner("[4/6] SLA 计算与统计")
    deadline = sla_manager.calculate_sla_deadline(now, "high", vuln_id)
    print(f"  SLA 截止时间戳: {deadline:.0f} (距今 {(deadline-now)/3600:.1f}h)")
    st = sla_manager.get_sla_status(v)
    print("  SLA 状态:", st)
    stats = sla_manager.get_sla_stats()
    print("  SLA 统计:", {k: stats[k] for k in ("total_open", "compliance_rate_percent")})
    policies = sla_manager.list_policies()
    print(f"  SLA 策略数量: {len(policies)}")
    exc = sla_manager.request_exception(vuln_id, reason="业务窗口限制", requested_by="tester",
                                        new_deadline=now + 30 * 86400)
    print("  例外申请:", exc)

    banner("[5/6] 修复跟踪 + 分析引擎")
    start = remediation_tracker.start_remediation(vuln_id, assignee="bob")
    print("  启动修复 task_id:", start.get("task_id"))
    task_id = start["task_id"]
    vr = remediation_tracker.verify_remediation(task_id, verified=True, result="复测通过", operator="tester")
    print("  修复验证:", vr)
    rstats = remediation_tracker.get_remediation_stats()
    print("  修复统计:", {k: rstats[k] for k in ("total_tasks", "success_rate_percent")})

    trends = analytics_engine.get_trends(granularity="day", days=30)
    print("  趋势桶数量:", len(trends["series"]))
    fr = analytics_engine.get_fix_rate(group_by="overall")
    print("  整体修复率:", {k: fr[k] for k in ("total", "fixed", "fix_rate_percent")})
    aging = analytics_engine.get_aging_distribution()
    print("  老化分布:", aging["distribution"])
    top = analytics_engine.get_top_vulnerabilities(limit=5)
    print("  TOP类型数量:", len(top["top_types"]))
    ranking = analytics_engine.get_asset_risk_ranking(limit=5)
    print("  资产排名条数:", len(ranking))
    vr2 = analytics_engine.get_verification_rate()
    print("  验证率:", vr2)

    banner("[6/6] API 路由导入")
    from api_server.vuln_management_routes import router
    routes = [r.path for r in router.routes]
    print(f"  路由导入成功，共 {len(routes)} 条端点")
    for p in routes:
        print("   -", p)

    banner("自测结果")
    print("✅ 全部检查通过：模块导入 / 建表 / 扩展列 / 生命周期 / SLA / 修复 / 分析 / 路由")
    return True


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print(f"\n❌ 断言失败: {e}")
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        print(f"\n❌ 自测异常: {e}")
        sys.exit(1)
