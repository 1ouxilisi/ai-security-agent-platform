"""
SOC 模块自测脚本

验证内容：
    1. 模块导入成功
    2. 数据库表创建成功（10+张表）
    3. 核心方法可调用（事件/告警/工单/应急响应/仪表盘）
    4. API路由文件可导入，router对象可访问
    5. 前端HTML文件存在且非空白

运行：
    python test_soc_module.py
"""
import os
import sys
import sqlite3

# 确保项目根目录在 sys.path
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

PASS = "✅"
FAIL = "❌"
results = []


def check(name: str, ok: bool, detail: str = ""):
    results.append((name, ok, detail))
    print(f"{PASS if ok else FAIL} {name} {('- ' + detail) if detail else ''}")


# ========== 1. 模块导入 ==========
print("\n===== 1. 模块导入 =====")
try:
    from soc import (incident_manager, alert_manager, ticket_manager,
                     incident_response, soc_dashboard)
    check("soc 包导入", True)
except Exception as e:
    check("soc 包导入", False, str(e))
    sys.exit(1)

try:
    from api_server.soc_routes import router
    check("api_server.soc_routes 导入", True, f"router.routes={len(router.routes)}")
except Exception as e:
    check("api_server.soc_routes 导入", False, str(e))

# ========== 2. 数据库表 ==========
print("\n===== 2. 数据库表 =====")
from utils.database import db
conn = db._get_connection()
try:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'soc_%'"
    ).fetchall()
    tables = sorted(r["name"] for r in rows)
    check("SOC表数量 >= 10", len(tables) >= 10, f"共{len(tables)}张: {', '.join(tables)}")
finally:
    conn.close()

# ========== 3. 事件管理器 ==========
print("\n===== 3. 事件管理器 =====")
inc = incident_manager.create_incident(
    title="测试事件: 异常登录", description="测试用例",
    severity="high", category="intrusion", source="ids",
    asset_id="asset-web-01")
check("create_incident", bool(inc and inc.get("id")), inc.get("id", ""))

got = incident_manager.get_incident(inc["id"])
check("get_incident", bool(got and got["title"] == "测试事件: 异常登录"))

lst = incident_manager.list_incidents(keyword="测试事件")
check("list_incidents", lst["total"] >= 1, f"total={lst['total']}")

upd = incident_manager.update_incident(inc["id"], status="analyzing")
check("update_incident", upd and upd["status"] == "analyzing")

asn = incident_manager.assign_incident(inc["id"], "secops_zhang")
check("assign_incident", asn and asn["assigned_to"] == "secops_zhang")

esc = incident_manager.escalate_incident(inc["id"], reason="自测升级")
check("escalate_incident", esc and esc["severity"] == "critical",
      f"-> {esc['severity'] if esc else 'N/A'}")

tl = incident_manager.get_incident_timeline(inc["id"])
check("get_incident_timeline", len(tl) >= 3, f"{len(tl)}条")

stats = incident_manager.get_incident_stats()
check("get_incident_stats", "by_status" in stats and "by_severity" in stats)

corr = incident_manager.auto_correlate(inc["id"])
check("auto_correlate", corr.get("success", False))

# ========== 4. 告警管理器 ==========
print("\n===== 4. 告警管理器 =====")
al = alert_manager.create_alert(
    title="测试告警: 暴力破解", severity="critical",
    source="ids", asset_id="asset-web-01", aggregation_key="brute-web-01")
check("create_alert", bool(al and al.get("id")))

ack = alert_manager.acknowledge_alert(al["id"])
check("acknowledge_alert", ack and ack["status"] == "acknowledged")

sup_al = alert_manager.create_alert(title="待抑制", severity="medium",
                                    asset_id="asset-web-01")
sup = alert_manager.suppress_alert(sup_al["id"])
check("suppress_alert", sup and sup["status"] == "suppressed")

rule = alert_manager.create_rule(
    name="暴力破解规则", description="5分钟失败登录>=10次",
    condition={"min_fail": 10, "window_min": 5}, threshold=10, severity="high")
check("create_rule", bool(rule and rule.get("id")))

rules = alert_manager.list_rules()
check("list_rules", len(rules) >= 1)

alst = alert_manager.get_alert_stats()
check("get_alert_stats", "by_status" in alst and "by_severity" in alst)

agg = alert_manager.aggregate_alerts("brute-web-01")
check("aggregate_alerts", agg["count"] >= 1)

auto_esc = alert_manager.auto_escalate(threshold_minutes=100000)
check("auto_escalate", "escalated_count" in auto_esc)

# ========== 5. 工单管理器 ==========
print("\n===== 5. 工单管理器 =====")
tk = ticket_manager.create_ticket(
    title="测试工单: 修复弱口令", priority="high",
    ticket_type="vuln_fix", incident_id=inc["id"])
check("create_ticket", bool(tk and tk.get("id")), f"-> {tk.get('assigned_to')}")

tg = ticket_manager.get_ticket(tk["id"])
check("get_ticket", bool(tg and tg["title"] == "测试工单: 修复弱口令"))

tlst = ticket_manager.list_tickets()
check("list_tickets", tlst["total"] >= 1)

tk_upd = ticket_manager.update_ticket(tk["id"], status="in_progress")
check("update_ticket", tk_upd and tk_upd["status"] == "in_progress")

tk_asn = ticket_manager.assign_ticket(tk["id"], strategy="round_robin")
check("assign_ticket", bool(tk_asn and tk_asn.get("assigned_to")))

cmt = ticket_manager.add_comment(tk["id"], "开始排查弱口令字典", author="secops_zhang")
check("add_comment", bool(cmt and cmt.get("id")))

tpl = ticket_manager.create_template(
    name="通用加固模板", ticket_type="hardening",
    title="服务器安全加固", description="基线检查+加固")
check("create_template", bool(tpl and tpl.get("id")))

tpls = ticket_manager.list_templates()
check("list_templates", len(tpls) >= 1)

tstats = ticket_manager.get_ticket_stats()
check("get_ticket_stats", "by_priority" in tstats and "by_type" in tstats)

sla = ticket_manager.check_sla()
check("check_sla", "overdue_count" in sla)

# ========== 6. 应急响应 ==========
print("\n===== 6. 应急响应(NIST) =====")
plan = incident_response.create_plan(
    name="Web入侵应急预案", incident_type="intrusion", severity="critical")
check("create_plan", bool(plan and plan.get("id")))

plans = incident_response.list_plans()
check("list_plans", len(plans) >= 1)

resp = incident_response.start_response(inc["id"], assignee="secops_li")
check("start_response", resp["task_count"] >= 6,
      f"生成{resp['task_count']}个任务")

tasks = incident_response.get_response_tasks(inc["id"])
check("get_response_tasks", len(tasks) >= 1)

done = incident_response.complete_task(inc["id"], tasks[0]["id"])
check("complete_task", done and done["status"] == "completed")

ev = incident_response.collect_evidence(
    inc["id"], evidence_type="log", description="/var/log/auth.log 快照",
    file_path="/tmp/auth.log.snap", hash_value="sha256:abc123")
check("collect_evidence", bool(ev and ev.get("id")))

evs = incident_response.list_evidence(inc["id"])
check("list_evidence", len(evs) >= 1)

rep = incident_response.generate_debrief_report(inc["id"])
check("generate_debrief_report",
      "timeline" in rep and "improvement_actions" in rep,
      f"任务完成率{rep['response_execution']['completion_rate']}%")

ex = incident_response.create_exercise(
    name="2026Q3桌面推演", exercise_type="tabletop",
    scenario="勒索软件爆发演练")
check("create_exercise", bool(ex and ex.get("id")))

# ========== 7. 仪表盘 ==========
print("\n===== 7. 仪表盘 =====")
ov = soc_dashboard.get_overview()
check("get_overview", "active_incidents" in ov and "avg_response_hours" in ov)

it = soc_dashboard.get_incident_trends()
check("get_incident_trends", "daily" in it and "severity_distribution" in it)

at = soc_dashboard.get_alert_trends()
check("get_alert_trends", "daily" in at and "top_rules" in at)

board = soc_dashboard.get_ticket_board()
check("get_ticket_board", "columns" in board and "by_status" in board)

sla_c = soc_dashboard.get_sla_compliance()
check("get_sla_compliance", "ticket_sla_compliance_pct" in sla_c)

mm = soc_dashboard.get_mttr_mttd()
check("get_mttr_mttd", "mttd_hours" in mm and "mttr_resolve_hours" in mm)

hm = soc_dashboard.get_risk_heatmap()
check("get_risk_heatmap", "matrix" in hm and "assets" in hm)

# ========== 8. 前端HTML ==========
print("\n===== 8. 前端控制台 =====")
html_path = os.path.join(ROOT, "api_server", "soc_console.html")
if os.path.exists(html_path):
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    check("soc_console.html 存在且非空白",
          len(content) > 1000 and "<!DOCTYPE html>" in content,
          f"{len(content)}字节")
    check("UTF-8编码声明", 'charset="UTF-8"' in content or 'charset=utf-8' in content)
    check("6个Tab齐全",
          all(k in content for k in
              ["dashboard", "incidents", "alerts", "tickets", "response", "settings"]))
else:
    check("soc_console.html 存在", False)

# ========== 汇总 ==========
print("\n===== 自测汇总 =====")
total = len(results)
passed = sum(1 for _, ok, _ in results if ok)
print(f"通过 {passed}/{total}")
if passed == total:
    print("🎉 全部通过")
else:
    print("⚠️ 存在失败项：")
    for name, ok, detail in results:
        if not ok:
            print(f"  - {name}: {detail}")
    sys.exit(1)
