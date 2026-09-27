"""
护网行动（hudong）模块自测脚本

验证内容：
    1. 模块导入成功
    2. 数据库表创建成功（13张表）
    3. 核心方法全流程调用（启动准备→启动监控→上报事件→处置→生成总结）
    4. API路由文件可导入，router对象可访问
    5. 前端HTML文件存在且非空白、UTF-8编码正常

运行：
    python test_hudong_module.py
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
    if detail and not isinstance(detail, str):
        detail = str(detail)
    print(f"{PASS if ok else FAIL} {name} {('- ' + detail) if detail else ''}")


# ========== 1. 模块导入 ==========
print("\n===== 1. 模块导入 =====")
try:
    from hudong import (preparation_manager, monitoring_manager,
                        emergency_manager, summary_manager)
    check("hudong 包导入", True)
except Exception as e:
    check("hudong 包导入", False, str(e))
    sys.exit(1)

try:
    from api_server.hudong_routes import router
    check("api_server.hudong_routes 导入", True,
          f"路由端点={len(router.routes)}")
except Exception as e:
    check("api_server.hudong_routes 导入", False, str(e))

# ========== 2. 数据库表 ==========
print("\n===== 2. 数据库表 =====")
from utils.database import db
conn = db._get_connection()
try:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'hd_%'"
    ).fetchall()
    tables = sorted(r["name"] for r in rows)
    expected = ["hd_preparations", "hd_attack_surfaces", "hd_hardening_tasks",
                "hd_monitorings", "hd_monitor_alerts", "hd_threats",
                "hd_emergencies", "hd_emergency_actions", "hd_reports",
                "hd_summaries", "hd_stats", "hd_reviews", "hd_improvement_plans"]
    check("护网表数量 == 13", len(tables) == 13,
          f"共{len(tables)}张: {', '.join(tables)}")
    missing = [t for t in expected if t not in tables]
    check("全部预期表存在", len(missing) == 0, f"缺失: {missing}" if missing else "无缺失")
finally:
    conn.close()

# ========== 3. 核心流程：准备 → 监控 → 应急 → 总结 ==========
print("\n===== 3. 核心方法全流程 =====")

# 3.1 启动准备
try:
    prep = preparation_manager.start_preparation(name="自测护网准备")
    prep_id = prep["id"]
    check("启动护网准备", True,
          f"资产{prep['asset_count']} 攻击面{prep['attack_surface_count']} 漏洞{prep['vuln_count']}")
except Exception as e:
    check("启动护网准备", False, str(e))
    prep_id = None

# 3.2 准备阶段各查询接口
if prep_id:
    try:
        inv = preparation_manager.get_asset_inventory(prep_id)
        check("资产梳理", True, f"资产{inv['total_assets']}个")
    except Exception as e:
        check("资产梳理", False, str(e))
    try:
        sf = preparation_manager.get_attack_surface(prep_id)
        check("攻击面梳理", True, f"互联网暴露{sf['internet_exposed_count']}")
    except Exception as e:
        check("攻击面梳理", False, str(e))
    try:
        vu = preparation_manager.get_vulnerabilities(prep_id)
        check("漏洞扫描", True, f"漏洞{vu['total']}个 分布{vu['by_severity']}")
    except Exception as e:
        check("漏洞扫描", False, str(e))
    try:
        rk = preparation_manager.get_risk_assessment(prep_id)
        check("风险评估", True, f"整体风险={rk['overall_risk_level']}")
    except Exception as e:
        check("风险评估", False, str(e))
    try:
        sug = preparation_manager.get_hardening_suggestions(prep_id)
        check("加固建议", True, f"{len(sug)}条建议")
        # 分配一个加固任务并验证
        task = preparation_manager.start_hardening(
            prep_id, title="修复高危漏洞", priority="high", assignee="张三")
        check("分配加固任务", True, task["title"])
        v = preparation_manager.verify_hardening(task["id"], passed=True)
        check("加固验证", True, f"状态={v['status']}")
    except Exception as e:
        check("加固建议/任务", False, str(e))
    try:
        rep = preparation_manager.generate_preparation_report(prep_id)
        check("生成准备报告", True, rep["title"])
    except Exception as e:
        check("生成准备报告", False, str(e))

# 3.3 启动监控
try:
    mon = monitoring_manager.start_monitoring(
        preparation_id=prep_id or "", name="自测护网监控")
    mon_id = mon["id"]
    check("启动持续监控", True, f"初始告警{mon['alert_count']}")
except Exception as e:
    check("启动持续监控", False, str(e))
    mon_id = None

if mon_id:
    try:
        monitoring_manager.detect_attacks(mon_id, round_no=2)
        al = monitoring_manager.list_alerts(mon_id, page=1, page_size=10)
        check("告警列表+攻击监测", True, f"告警{al['total']}条")
    except Exception as e:
        check("告警列表+攻击监测", False, str(e))
    try:
        ack = monitoring_manager.acknowledge_alert(al["items"][0]["id"])
        check("确认告警", True, ack["status"])
        res = monitoring_manager.resolve_alert(al["items"][0]["id"])
        check("处置告警", True, res["status"])
    except Exception as e:
        check("告警确认/处置", False, str(e))
    try:
        th = monitoring_manager.list_threats(mon_id)
        check("威胁列表", True, f"{len(th)}个威胁")
    except Exception as e:
        check("威胁列表", False, str(e))
    try:
        agg = monitoring_manager.aggregate_alerts(mon_id)
        check("告警聚合", True, f"聚合组{agg['group_count']}")
    except Exception as e:
        check("告警聚合", False, str(e))
    try:
        sz = monitoring_manager.get_situation(mon_id)
        check("态势感知", True, f"态势={sz['overall_posture']}")
    except Exception as e:
        check("态势感知", False, str(e))
    try:
        mrep = monitoring_manager.generate_monitoring_report(mon_id)
        check("生成监控报告", True, mrep["title"])
    except Exception as e:
        check("生成监控报告", False, str(e))

# 3.4 应急响应
try:
    emg = emergency_manager.report_emergency(
        title="自测：核心系统疑似入侵", monitoring_id=mon_id or "",
        level="major", asset_id="asset-001",
        attack_source="203.0.113.10", attack_method="漏洞利用+横向移动")
    emg_id = emg["id"]
    check("上报应急事件", True, f"分级={emg['level_cn']}")
except Exception as e:
    check("上报应急事件", False, str(e))
    emg_id = None

if emg_id:
    try:
        emergency_manager.contain(emg_id)
        emergency_manager.eradicate(emg_id)
        fin = emergency_manager.recover(emg_id)
        check("遏制→根除→恢复", True, f"状态={fin['status']}")
    except Exception as e:
        check("遏制→根除→恢复", False, str(e))
    try:
        tr = emergency_manager.get_trace(emg_id)
        check("溯源分析", True, str(list(tr.keys())))
    except Exception as e:
        check("溯源分析", False, str(e))
    try:
        acts = emergency_manager.list_actions(emg_id)
        check("处置记录", True, f"{len(acts)}条")
    except Exception as e:
        check("处置记录", False, str(e))
    try:
        rp = emergency_manager.submit_report(emg_id, report_type="regulatory")
        check("信息上报", True, rp["recipient"])
    except Exception as e:
        check("信息上报", False, str(e))
    try:
        erep = emergency_manager.generate_emergency_report(emg_id)
        check("生成应急报告", True, erep["title"])
    except Exception as e:
        check("生成应急报告", False, str(e))

# 3.5 生成总结
try:
    sm = summary_manager.generate_summary(
        preparation_id=prep_id or "", monitoring_id=mon_id or "",
        name="自测护网总结")
    sum_id = sm["id"]
    check("生成护网总结", True, sum_id)
except Exception as e:
    check("生成护网总结", False, str(e))
    sum_id = None

if sum_id:
    try:
        st = summary_manager.get_summary_stats(sum_id)
        check("数据统计", True, f"{len(st['stats'])}项指标")
    except Exception as e:
        check("数据统计", False, str(e))
    try:
        rv = summary_manager.get_attack_defense_review(sum_id)
        check("攻防复盘", True, f"平均检测率{rv['avg_detection_rate']}%")
    except Exception as e:
        check("攻防复盘", False, str(e))
    try:
        plans = summary_manager.list_improvement_plans(sum_id)
        np = summary_manager.create_improvement_plan(
            sum_id, title="自测改进项", category="technical", priority="high")
        check("改进计划列表/创建", True, f"原{len(plans)}项")
    except Exception as e:
        check("改进计划列表/创建", False, str(e))
    try:
        ach = summary_manager.get_achievements(sum_id)
        sho = summary_manager.get_shortcomings(sum_id)
        check("成果亮点/不足", True, f"亮点{len(ach)} 不足{len(sho)}")
    except Exception as e:
        check("成果亮点/不足", False, str(e))
    try:
        srep = summary_manager.generate_summary_report(sum_id)
        check("生成总结报告", True, srep["title"])
    except Exception as e:
        check("生成总结报告", False, str(e))

# ========== 4. 前端页面 ==========
print("\n===== 4. 前端控制台 =====")
html_path = os.path.join(ROOT, "api_server", "hudong_console.html")
try:
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    check("HTML文件存在且非空白", len(content) > 1000, f"{len(content)}字符")
    check("UTF-8编码声明", 'charset="UTF-8"' in content)
    check("含深色主题主色#58a6ff", "#58a6ff" in content)
    check("含5个Tab", all(k in content for k in
          ["护网总览", "准备阶段", "监控阶段", "应急阶段", "总结阶段"]))
    check("调用护网API", "/api/v1/hudong" in content or 'API="/api/v1/hudong"' in content)
except Exception as e:
    check("HTML文件检查", False, str(e))

# ========== 汇总 ==========
print("\n===== 汇总 =====")
passed = sum(1 for _, ok, _ in results if ok)
total = len(results)
print(f"通过 {passed}/{total}")
if passed == total:
    print("🎉 护网行动模块自测全部通过")
else:
    print("⚠️ 存在失败项：")
    for name, ok, detail in results:
        if not ok:
            print(f"  - {name}: {detail}")
sys.exit(0 if passed == total else 1)
