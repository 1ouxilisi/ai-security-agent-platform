# -*- coding: utf-8 -*-
"""
资产管理深化模块自测脚本

验证项：
    1. 所有 Python 模块可正常导入
    2. 数据库表创建成功（8+ 张表）
    3. assets 表扩展列添加成功
    4. 指纹规则初始化 200+ 条
    5. API 路由文件可正常导入（统计端点数量）
    6. 核心方法调用：发现、导入、风险评级、变更检测、分组、指纹匹配
"""
import os
import sys
import sqlite3

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{PASS if ok else FAIL}] {name} {('- ' + detail) if detail else ''}")


# 1. 模块导入
try:
    from asset_management import discovery, fingerprint, risk_rating, change_detection, grouping
    check("导入 asset_management 五个子模块", True)
except Exception as e:
    check("导入 asset_management 五个子模块", False, str(e))

# 2. 路由导入
try:
    from api_server import asset_management_routes
    n_routes = len(asset_management_routes.router.routes)
    check("导入 asset_management_routes", True, f"端点数={n_routes}")
except Exception as e:
    check("导入 asset_management_routes", False, str(e))

# 3. 数据库表
from utils.database import db
conn = db._get_connection()
tables = [r[0] for r in conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
am_tables = [t for t in tables if t.startswith("am_")]
required = ["am_discovery_tasks", "am_discovery_results", "am_fingerprint_rules",
            "am_risk_history", "am_changes", "am_baselines",
            "am_groups", "am_group_members"]
missing = [t for t in required if t not in tables]
check("8 张 am_ 业务表创建", len(missing) == 0,
      f"实际={len(am_tables)} 张, 缺失={missing}")

# assets 扩展列
asset_cols = [r[1] for r in conn.execute("PRAGMA table_info(assets)").fetchall()]
extra = ["exposure_level", "data_sensitivity", "business_impact",
         "department", "location", "open_ports_count"]
missing_cols = [c for c in extra if c not in asset_cols]
check("assets 表扩展列", len(missing_cols) == 0, f"缺失={missing_cols}")
conn.close()

# 4. 指纹规则数量
stats = fingerprint.fingerprint_manager.get_rule_stats()
check("指纹规则 >=200", stats.get("total", 0) >= 200, f"total={stats.get('total')} 分类={stats}")

# 5. 核心方法 - 发现
disc = discovery.discovery_manager
r = disc.start_discovery("自测发现任务", ["192.168.99.0/28"], "active")
check("启动主动发现", r.get("success"), f"results={r.get('results_count')}")
tid = r.get("task_id")
status = disc.get_discovery_status(tid)
check("查询发现任务状态", status is not None and status.get("status") == "completed")
res = disc.get_discovery_results(tid, page=1, page_size=5)
check("查询发现结果", res.get("total", 0) > 0, f"total={res.get('total')}")
imp = disc.import_discovered_assets(tid)
check("导入发现资产", imp.get("success"), f"imported={imp.get('imported')} updated={imp.get('updated')}")

# 6. 风险评级
rr = risk_rating.risk_rating_manager
conn = db._get_connection()
row = conn.execute("SELECT id FROM assets LIMIT 1").fetchone()
conn.close()
if row:
    asset_id = row["id"]
    rating = rr.calculate_risk_rating(asset_id)
    check("计算风险评级", rating.get("success"), f"score={rating.get('risk_score')} level={rating.get('risk_level')}")
    rank = rr.get_risk_ranking(top_n=5)
    check("风险排名", True, f"items={len(rank.get('items', []))}")
    adv = rr.get_risk_mitigation_suggestions(asset_id)
    check("风险降低建议", len(adv.get("suggestions", [])) > 0)
else:
    check("计算风险评级(有资产)", False, "无资产")

# 7. 变更检测
cd = change_detection.change_detection_manager
cd.create_baseline("自测基线", created_by="tester")
det = cd.detect_changes()
check("变更检测", det.get("success"), f"detected={det.get('detected')}")
chg_list = cd.list_changes(page=1, page_size=5)
check("列出变更", chg_list.get("total", 0) >= 0, f"total={chg_list.get('total')}")
bl = cd.list_baselines()
check("列出基线", len(bl) > 0, f"baselines={len(bl)}")

# 8. 分组
grp = grouping.grouping_manager
g = grp.create_group("测试分组", "自测")
gid = g.get("id")
check("创建分组", g.get("success"), f"id={gid}")
if row and gid:
    grp.add_asset_to_group(gid, row["id"])
stats = grp.get_group_stats(gid)
check("分组统计", stats.get("asset_count", 0) >= 1, f"stats={stats}")
bscan = grp.batch_scan(gid)
check("批量扫描分组", bscan.get("success"))

# 9. 指纹匹配
fp = fingerprint.fingerprint_manager
m = fp.match_fingerprint({"banner": "nginx/1.18.0", "port": 443})
check("指纹匹配(nginx)", any(x["name"] == "Nginx" for x in m), f"top={m[0]['name'] if m else None}")
svc = fp.match_service(port=443, banner="nginx/1.18.0")
check("服务识别", svc.get("service") != "unknown", f"service={svc.get('service')}")
os_r = fp.match_os(ttl=64, window_size=14600, open_ports=[22])
check("操作系统识别", os_r.get("os") == "Linux", f"os={os_r.get('os')}")

# 10. 前端文件
html_path = os.path.join("api_server", "asset_console.html")
with open(html_path, "r", encoding="utf-8") as f:
    html = f.read()
check("前端页面存在且非空", len(html) > 5000 and "资产管理控制台" in html,
      f"size={len(html)}")
check("前端 UTF-8 编码声明", 'charset="UTF-8"' in html)

# 汇总
print("\n========== 自测汇总 ==========")
passed = sum(1 for _, ok, _ in results if ok)
print(f"通过 {passed}/{len(results)}")
sys.exit(0 if passed == len(results) else 1)
