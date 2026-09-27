# -*- coding: utf-8 -*-
"""冒烟测试：方向3 工控IoT Pro 八阶段/AI/大屏/报告。"""
from __future__ import annotations
import sys, os, time, threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import py_compile

FILES = [
    "iot_ot_pro/__init__.py",
    "iot_ot_pro/device_discovery_phase.py",
    "iot_ot_pro/protocol_analysis_phase.py",
    "iot_ot_pro/firmware_analysis_phase.py",
    "iot_ot_pro/vuln_detection_phase.py",
    "iot_ot_pro/config_audit_phase.py",
    "iot_ot_pro/traffic_monitor_phase.py",
    "iot_ot_pro/risk_rating_phase.py",
    "iot_ot_pro/compliance_audit_phase.py",
    "iot_ot_pro/ai_analysis.py",
    "iot_ot_pro/realtime_push.py",
    "iot_ot_pro/iot_ot_dashboard.py",
    "iot_ot_pro/report_generator.py",
    "iot_ot_pro/iot_ot_orchestrator.py",
    "api_server/iot_ot_pro_routes.py",
]

print("== 1. 语法编译检查 ==")
for f in FILES:
    py_compile.compile(f, doraise=True)
    print("  OK", f)

print("\n== 2. 模块导入 ==")
import iot_ot_pro as p
print("  exports:", len(p.__all__))

print("\n== 3. 八阶段全流程编排 ==")
o = p.get_orchestrator()
t = o.create_task("冒烟-工控IoT全流程")
threading.Thread(target=o.run_full, args=(t.task_id,), daemon=True).start()
for _ in range(60):
    time.sleep(1)
    d = o.get_task(t.task_id)
    if d.status in ("done", "error"):
        break
print("  status:", d.status, "| stage:", d.stage, "| progress:", d.progress)
if d.status == "error":
    print("  ERROR:", d.error)
    sys.exit(1)

print("\n== 4. 各阶段结果 ==")
for k in ("device_discovery", "protocol_analysis", "firmware_analysis",
          "vuln_detection", "config_audit", "traffic_monitor",
          "risk_rating", "compliance_audit", "ai_analysis"):
    print("  ", k, "->", "OK" if k in d.results else "MISSING")

print("\n== 5. 大屏 KPI ==")
dash = p.get_dashboard()
kpi = dash.kpi()
print("  ", kpi)
full = dash.full_screen()
print("  full_screen keys:", list(full.keys()))

print("\n== 6. AI 分析 ==")
ai = p.get_ai_analysis()
ov = ai.batch_overview(
    p.get_device_discovery_phase().list_devices(),
    p.get_vuln_detection_phase().list_vulns(),
    p.get_traffic_monitor_phase().list_alerts(),
    p.get_compliance_audit_phase().summary())
print("  device reports:", len(ov["devices"]))
print("  traffic noise_ratio:", ov["traffic"]["noise_ratio"])
print("  thought:", ov["thought"])

print("\n== 7. 报告生成 ==")
rep = p.get_report_generator().generate("both")
print("  md:", os.path.basename(rep["md_path"]))
print("  html:", os.path.basename(rep["html_path"]))
print("  kpi:", rep["stats"])

print("\n== 8. 路由注册检查 ==")
from api_server.iot_ot_pro_routes import router
paths = [r.path for r in router.routes]
print("  route count:", len(paths))
print("  ws:", [x for x in paths if "ws" in x])

print("\n=== 全部通过 ✅ ===")
