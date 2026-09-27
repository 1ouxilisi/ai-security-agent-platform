# -*- coding: utf-8 -*-
"""冒烟测试：第28轮升级方向2 真实场景验证与误报率优化"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=== 功能冒烟测试 ===")

# 1. 靶场管理
from real_validation.range_integration import get_range_manager
rm = get_range_manager()
ranges = rm.list_ranges()
print(f"1. 靶场实例数: {len(ranges)}")
r0 = ranges[0]
dep = rm.deploy(r0["range_id"], deploy_type="docker")
print(f"2. 部署 {r0['name']}: success={dep['success']}, status={dep['range']['status']}")
mon = rm.get_monitor(r0["range_id"])
print(f"3. 监控 {r0['name']}: cpu={mon['monitor']['resource_usage']['cpu_percent']}%")
ver = rm.verify_range(r0["range_id"])
print(f"4. 验证 {r0['name']}: pass_rate={ver['report']['pass_rate']}%")
snap = rm.create_snapshot(r0["range_id"], name="test_snap")
print(f"5. 创建快照: success={snap['success']}, size={snap['snapshot']['size_mb']}MB")
st = rm.stop(r0["range_id"])
print(f"6. 停止靶场: success={st['success']}, status={st['range']['status']}")

# 2. 扫描验证
from real_validation.scan_validation import get_scan_validator
sv = get_scan_validator()
scan = sv.execute_scan("127.0.0.1", 80, "nmap_port")
print(f"7. 执行扫描: ports={scan['port_count']}, vulns={scan['vuln_count']}")
ana = sv.analyze_results(scan["scan_id"])
a = ana["analysis"]
print(f"8. 分析结果: precision={a['precision']}, recall={a['recall']}, f1={a['f1_score']}")
print(f"   误报率={a['false_positive_rate']}, 漏报率={a['false_negative_rate']}")

# 3. 误报优化
from real_validation.false_positive_optimizer import get_fp_optimizer
fp = get_fp_optimizer()
rules = fp.list_rules()
print(f"9. 误报规则数: {len(rules)}")
opt_run = fp.run_optimization()
orun = opt_run["optimization_run"]
print(f"10. 优化前后: FP率 {orun['before']['false_positive_rate']} -> {orun['after']['false_positive_rate']}")
models = fp.list_models()
print(f"11. ML模型数: {len(models)}, 准确率={models[0]['accuracy']}")

# 4. 漏洞验证
from real_validation.vuln_verification import get_vuln_verifier
vv = get_vuln_verifier()
vulns = vv.list_vulns()
print(f"12. 漏洞总数: {len(vulns)}")
v0 = vulns[0]
conf = vv.confirm_vuln(v0["vuln_id"], method="poc")
print(f"13. POC验证 {v0['cve']}: verified={conf['vuln']['verified']}")
trend = vv.get_trends(7)
print(f"14. 趋势: {trend['total_vulns']}漏洞, 平均CVSS={trend['avg_cvss']}")

# 5. 验证体系
from real_validation.validation_framework import get_validation_framework
vf = get_validation_framework()
cases = vf.list_test_cases()
print(f"15. 测试用例数: {len(cases)}")
reg = vf.run_regression()
print(f"16. 回归测试: {reg['passed']}/{reg['total_cases']} 通过 ({reg['pass_rate']}%)")
metrics = vf.get_metrics()
print(f"17. 验证度量: 通过率={metrics['pass_rate']}%, 失败率={metrics['fail_rate']}%")

# 6. 仪表盘
from real_validation.real_validation_dashboard import get_dashboard
db = get_dashboard()
db.bind_modules(range_manager=rm, scan_validator=sv, fp_optimizer=fp,
                vuln_verifier=vv, validation_framework=vf)
ov = db.get_overview()
print(f"18. 总览KPI: ranges={ov['kpi']['total_ranges']}, scans={ov['kpi']['total_scans']}, vulns={ov['kpi']['total_vulns']}")
health = db.get_health()
print(f"19. 系统健康: {health['overall']}")

print()
print("=== 全部冒烟测试通过 ===")
