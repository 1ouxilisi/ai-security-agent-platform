# -*- coding: utf-8 -*-
"""
红蓝对抗演练模块自测脚本

验证项：
    1. 所有 Python 模块可正常导入
    2. 数据库表创建成功（10+ 张表）
    3. 攻击场景 12+ 个，检测规则 30+ 条
    4. 核心方法链路：启动模拟 -> 启动检测 -> 启动演练 -> 生成复盘报告
    5. API 路由文件可正常导入
    6. 前端页面存在且 UTF-8 编码正常

运行方式：在项目根目录执行 python verify_purple_team.py
"""
import os
import sys
import json

# 确保项目根目录在 sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.database import db

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{PASS if ok else FAIL}] {name} {('- ' + detail) if detail else ''}")


# ---------- 1. 模块导入 ----------
try:
    from red_team import red_team, RedTeamSimulator
    check("导入 red_team 模块", True)
except Exception as e:
    check("导入 red_team 模块", False, str(e))
    raise

try:
    from blue_team import blue_team, BlueTeamDetector
    check("导入 blue_team 模块", True)
except Exception as e:
    check("导入 blue_team 模块", False, str(e))
    raise

try:
    from purple_team import purple_team, PurpleTeamDebrief
    check("导入 purple_team 模块", True)
except Exception as e:
    check("导入 purple_team 模块", False, str(e))
    raise

# ---------- 2. 数据库表创建 ----------
conn = db._get_connection()
tables = [r[0] for r in conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
pt_tables = [t for t in tables if t.startswith(("rt_", "bt_", "pt_"))]
conn.close()
expected_tables = {"rt_attack_scenarios", "rt_simulations", "rt_attack_paths",
                   "bt_detection_rules", "bt_detections", "bt_detection_alerts",
                   "pt_exercises", "pt_comparisons", "pt_coverage", "pt_improvements"}
missing = expected_tables - set(pt_tables)
check("红/蓝/紫队数据表创建(10张)", len(missing) == 0,
      f"实际={len(expected_tables & set(pt_tables))}/10 缺失={missing or '无'}")
print(f"    表清单: {sorted(pt_tables)}")

# ---------- 3. 场景与规则数量 ----------
scenarios = red_team.list_scenarios()
check("攻击场景数量 >= 12", len(scenarios) >= 12, f"实际={len(scenarios)}")

rules = blue_team.list_rules()
check("检测规则数量 >= 30", len(rules) >= 30, f"实际={len(rules)}")

# ---------- 4. 核心方法链路 ----------
# 4.1 启动红队模拟
try:
    sc = scenarios[0]
    sim = red_team.start_simulation(sc["id"], name="自测红队模拟",
                                    target_scope={"assets": ["web-01", "db-01"],
                                                  "entry_asset": "互联网",
                                                  "target_asset": "核心数据库"})
    check("启动红队模拟", bool(sim and sim.get("id")),
          f"成功率={sim.get('success_probability')}")
    sim_id = sim["id"]
except Exception as e:
    check("启动红队模拟", False, str(e))
    sim_id = None

# 4.2 攻击路径 / 结果 / 报告
try:
    res = red_team.get_simulation_result(sim_id)
    paths = red_team.get_attack_paths(sim_id)
    report = red_team.generate_red_team_report(sim_id)
    check("红队结果/路径/报告", bool(res and paths["nodes"] and report),
          f"路径节点={len(paths['nodes'])}")
except Exception as e:
    check("红队结果/路径/报告", False, str(e))

# 4.3 启动蓝队检测
try:
    det = blue_team.start_detection(sim_id, name="自测蓝队检测")
    check("启动蓝队检测", bool(det and det.get("id")),
          f"检测率={det.get('detection_rate')} 阻断率={det.get('block_rate')}")
    det_id = det["id"]
except Exception as e:
    check("启动蓝队检测", False, str(e))
    det_id = None

# 4.4 蓝队结果/告警/报告/差距
try:
    blue_res = blue_team.get_detection_result(det_id)
    alerts = blue_team.get_detection_alerts(det_id)
    gaps = blue_team.analyze_defense_gaps(sim_id)
    b_report = blue_team.generate_blue_team_report(det_id)
    check("蓝队结果/告警/差距/报告", bool(blue_res and b_report),
          f"告警={len(alerts)} 差距={len(gaps)}")
except Exception as e:
    check("蓝队结果/告警/差距/报告", False, str(e))

# 4.5 启动紫队演练
try:
    ex = purple_team.start_exercise("自测演练", sc["id"],
                                    target_scope={"assets": ["web-01", "db-01"]})
    check("启动紫队演练", bool(ex and ex.get("id")), f"状态={ex.get('status')}")
    ex_id = ex["id"]
except Exception as e:
    check("启动紫队演练", False, str(e))
    ex_id = None

# 4.6 紫队 对比/覆盖率/时间线/复盘报告
try:
    cmp_ = purple_team.get_comparison(ex_id)
    cov = purple_team.get_coverage(ex_id)
    tl = purple_team.get_timeline(ex_id)
    debrief = purple_team.generate_debrief_report(ex_id)
    check("紫队对比/覆盖率/时间线/复盘",
          bool(cmp_ and cov and tl and debrief),
          f"覆盖率={cov.get('coverage_rate')} 延迟={tl.get('avg_detection_latency_seconds')}")
except Exception as e:
    check("紫队对比/覆盖率/时间线/复盘", False, str(e))

# 4.7 改进措施闭环
try:
    imp = purple_team.create_improvement(ex_id, title="新增C2检测规则",
                                         description="覆盖未检测技术",
                                         category="detection_rule", priority="high")
    finished = purple_team.complete_improvement(imp["id"], verification_result="验证通过")
    prog = purple_team.get_improvement_progress(ex_id)
    check("改进措施 创建->完成->进度", finished.get("status") == "completed",
          f"进度={prog.get('progress_rate')}")
except Exception as e:
    check("改进措施 创建->完成->进度", False, str(e))

# ---------- 5. API 路由导入 ----------
try:
    from api_server.purple_team_routes import router
    routes = [r.path for r in router.routes]
    check("API 路由文件导入", True, f"端点数={len(routes)}")
    for p in routes:
        print(f"    - {p}")
except Exception as e:
    check("API 路由文件导入", False, str(e))

# ---------- 6. 前端页面 ----------
html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "api_server", "purple_team_console.html")
try:
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    ok = ("UTF-8" in content or "charset=\"UTF-8\"" in content.lower() or "charset=utf-8" in content.lower()) \
         and len(content) > 1000 and "purple-team" in content
    check("前端页面存在且非空白/UTF-8", ok, f"大小={len(content)}字节")
except Exception as e:
    check("前端页面存在且非空白/UTF-8", False, str(e))

# ---------- 汇总 ----------
print("\n" + "=" * 50)
passed = sum(1 for _, ok, _ in results if ok)
total = len(results)
print(f"自测结果: {passed}/{total} 通过")
if passed == total:
    print("🎉 全部通过")
else:
    print("⚠️ 存在失败项")
sys.exit(0 if passed == total else 1)
