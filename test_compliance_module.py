# -*- coding: utf-8 -*-
"""
test_compliance_module.py - 合规审计深化模块自测脚本

验证：
    1. 所有 Python 模块可正常导入
    2. 数据库表创建成功（7+ 张表）
    3. 框架初始化 10 个，控制项 500+ 条
    4. API 路由文件可正常导入
    5. 核心方法可调用（框架/评估/报告/整改）
    6. 前端页面存在且非空白
"""

import os
import sys

# 切到项目根目录
ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

PASS = 0
FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name} {extra}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {extra}")


print("=" * 60)
print("合规审计深化模块自测")
print("=" * 60)

# 1. 模块导入
print("\n[1] 模块导入")
try:
    import compliance  # noqa
    check("compliance 包导入", True)
except Exception as e:
    check("compliance 包导入", False, str(e))

try:
    from compliance.frameworks import get_framework_manager, ComplianceFramework
    check("frameworks 模块导入", True)
except Exception as e:
    check("frameworks 模块导入", False, str(e))

try:
    from compliance.assessment import get_assessor, ComplianceAssessor
    check("assessment 模块导入", True)
except Exception as e:
    check("assessment 模块导入", False, str(e))

try:
    from compliance.report_generator import get_report_generator, ReportGenerator
    check("report_generator 模块导入", True)
except Exception as e:
    check("report_generator 模块导入", False, str(e))

try:
    from compliance.remediation import get_remediation_manager, RemediationManager
    check("remediation 模块导入", True)
except Exception as e:
    check("remediation 模块导入", False, str(e))

# 2. 路由文件导入
print("\n[2] API 路由导入")
try:
    from api_server.compliance_routes import router
    routes = [r.path for r in router.routes]
    check("compliance_routes 导入", True, f"端点 {len(routes)} 个")
    for p in routes:
        print(f"        - {p}")
except Exception as e:
    check("compliance_routes 导入", False, str(e))
    router = None

# 3. 数据库表创建（先实例化所有管理器以触发建表）
print("\n[3] 数据库表")
get_framework_manager()
get_assessor()
get_report_generator()
get_remediation_manager()
from utils.database import db
conn = db._get_connection()
tables = [r[0] for r in conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'cp_%'").fetchall()]
conn.close()
cp_tables = sorted(tables)
check("合规相关表数量 >= 7", len(cp_tables) >= 7, f"实际 {len(cp_tables)}: {cp_tables}")

# 4. 框架与控制项数量
print("\n[4] 框架与控制项")
fm = get_framework_manager()
fws = fm.list_frameworks()
check("框架数量 == 11", len(fws) == 11, f"实际 {len(fws)}")
total_ctrl = sum(f["control_count"] for f in fws)
check("控制项总数 >= 500", total_ctrl >= 500, f"实际 {total_ctrl}")
for f in fws:
    print(f"        {f['code']:12s} {f['name'][:24]:26s} 控制项 {f['control_count']}")

# 关键框架数量要求
mlps3 = next((f for f in fws if f["code"] == "MLPS3"), {})
iso = next((f for f in fws if f["code"] == "ISO27001"), {})
pci = next((f for f in fws if f["code"] == "PCIDSS"), {})
check("等保2.0三级 >= 100 项", mlps3.get("control_count", 0) >= 100,
      f"实际 {mlps3.get('control_count')}")
check("ISO27001 >= 93 项", iso.get("control_count", 0) >= 93,
      f"实际 {iso.get('control_count')}")
check("PCI-DSS >= 78 项", pci.get("control_count", 0) >= 78,
      f"实际 {pci.get('control_count')}")

# 5. 核心方法调用
print("\n[5] 核心方法调用")
try:
    det = fm.get_framework(mlps3["id"])
    check("get_framework", det is not None and det["code"] == "MLPS3")
except Exception as e:
    check("get_framework", False, str(e))

try:
    listing = fm.list_controls(mlps3["id"], page=1, page_size=5)
    check("list_controls 分页", listing["total"] >= 100 and len(listing["items"]) == 5)
except Exception as e:
    check("list_controls 分页", False, str(e))

try:
    found = fm.search_controls("身份鉴别", framework_id=mlps3["id"])
    check("search_controls", isinstance(found, list) and len(found) > 0,
          f"命中 {len(found)}")
except Exception as e:
    check("search_controls", False, str(e))

try:
    stats = fm.get_framework_stats(mlps3["id"])
    check("get_framework_stats", stats["total_controls"] >= 100,
          f"total={stats['total_controls']}")
except Exception as e:
    check("get_framework_stats", False, str(e))

try:
    mappings = fm.get_control_mappings(mlps3["id"])
    check("get_control_mappings", isinstance(mappings, list))
except Exception as e:
    check("get_control_mappings", False, str(e))

# 6. 评估器全流程
print("\n[6] 评估器流程")
assessor = get_assessor()
aid = None
try:
    a = assessor.start_assessment(framework_id=mlps3["id"],
                                  name="自测评估",
                                  scope={"asset": "测试资产"},
                                  assessor="selftest")
    aid = a["id"]
    check("start_assessment", a is not None and a["total_controls"] >= 100,
          f"total={a['total_controls']}")
except Exception as e:
    check("start_assessment", False, str(e))

try:
    if aid:
        st = assessor.get_assessment_status(aid)
        check("get_assessment_status", st["status"] == "in_progress")
except Exception as e:
    check("get_assessment_status", False, str(e))

try:
    if aid:
        results = assessor.get_assessment_results(aid)
        check("get_assessment_results", results["total"] >= 100,
              f"total={results['total']}")
        # 取第一个待评估控制项设置结果
        first = results["items"][0]
        assessor.set_control_result(aid, first["control_id"], "compliant",
                                    finding="符合", assessed_by="selftest")
        assessor.upload_evidence(aid, first["control_id"],
                                 {"type": "file", "path": "/ev/test.png",
                                  "description": "测试证据"})
        check("set_control_result + upload_evidence", True)
except Exception as e:
    check("评估结果操作", False, str(e))

try:
    if aid:
        auto = assessor.auto_assess(aid)
        check("auto_assess", auto["assessed"] > 0, f"评估 {auto['assessed']} 项")
except Exception as e:
    check("auto_assess", False, str(e))

try:
    if aid:
        score = assessor.calculate_score(aid)
        check("calculate_score", 0 <= score <= 100, f"score={score}")
        gap = assessor.get_gap_analysis(aid)
        check("get_gap_analysis", "gaps" in gap)
        done = assessor.complete_assessment(aid)
        check("complete_assessment", done["status"] == "completed",
              f"score={done['overall_score']}")
except Exception as e:
    check("评分/差距/完成", False, str(e))

# 7. 报告生成
print("\n[7] 报告生成")
try:
    rg = get_report_generator()
    if aid:
        rep = rg.generate_report(aid, title="自测报告", generated_by="selftest")
        check("generate_report", rep is not None, f"id={rep['id'] if rep else None}")
        html = rg.get_report_html(aid)
        check("get_report_html", "<html" in html.lower() and "合规审计报告" in html)
        down = rg.download_report(rep["id"])
        check("download_report", down["exists"])
        list_rep = rg.list_reports()
        check("list_reports", list_rep["total"] >= 1)
        tpls = rg.list_templates()
        check("list_templates", len(tpls) >= 1)
        multi = rg.generate_multi_framework_comparison([aid], "对比")
        check("multi_framework_comparison", len(multi["comparison"]) == 1)
except Exception as e:
    check("报告生成", False, str(e))

# 8. 整改管理
print("\n[8] 整改管理")
try:
    rm = get_remediation_manager()
    if aid and gap["gaps"]:
        g0 = gap["gaps"][0]
        task = rm.create_remediation_task(aid, g0["control_id"],
                                          title=g0["title"],
                                          description="整改",
                                          priority=g0["priority"])
        check("create_remediation_task", task is not None)
        started = rm.start_remediation(task["id"])
        check("start_remediation", started["status"] == "in_progress")
        verified = rm.verify_remediation(task["id"], "验证通过", passed=True)
        check("verify_remediation", verified["status"] == "verified")
    else:
        check("create_remediation_task", True, "（无差距项，跳过）")
except Exception as e:
    check("整改任务", False, str(e))

try:
    rm = get_remediation_manager()
    stats = rm.get_remediation_stats()
    check("get_remediation_stats", "total" in stats and "completion_rate" in stats)
    prog = rm.get_remediation_progress()
    check("get_remediation_progress", "total" in prog and "verified" in prog)
    plan = rm.get_remediation_plan(aid) if aid else {"plans": []}
    check("get_remediation_plan", "plans" in plan)
except Exception as e:
    check("整改统计", False, str(e))

# 9. 前端页面
print("\n[9] 前端页面")
html_path = os.path.join(ROOT, "api_server", "compliance_console.html")
check("compliance_console.html 存在", os.path.exists(html_path))
if os.path.exists(html_path):
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    check("非空白且UTF-8正常", len(content) > 1000 and "合规审计控制台" in content)
    check("6个Tab齐全", all(t in content for t in
          ["合规仪表盘", "框架管理", "合规评估", "差距分析", "整改跟踪", "报告中心"]))
    check("深色主题配色", "#0d1117" in content and "#58a6ff" in content)
    check("调用合规API", "/api/v1/compliance" in content)

# 10. 文件行数统计
print("\n[10] 文件行数")
files = [
    "compliance/__init__.py",
    "compliance/frameworks.py",
    "compliance/assessment.py",
    "compliance/report_generator.py",
    "compliance/remediation.py",
    "api_server/compliance_routes.py",
    "api_server/compliance_console.html",
]
for f in files:
    p = os.path.join(ROOT, f)
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as fh:
            n = sum(1 for _ in fh)
        print(f"        {f:42s} {n:5d} 行")

# 汇总
print("\n" + "=" * 60)
print(f"自测完成：通过 {PASS} 项，失败 {FAIL} 项")
print("=" * 60)
sys.exit(0 if FAIL == 0 else 1)
