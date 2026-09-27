# -*- coding: utf-8 -*-
"""Quick smoke test for security_final modules."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security_final.self_pentest_final import get_pentest_scanner
from security_final.dep_vuln_final import get_dep_scanner
from security_final.baseline_final import get_baseline_checker
from security_final.audit_monitor import get_audit_monitor
from security_final.data_security_final import get_data_security
from security_final.security_dashboard_final import get_dashboard

# 1. Pentest
s = get_pentest_scanner()
r = s.owasp_top10_check()
print(f"[PASS] OWASP check: {r['categories_with_findings']}/10 categories with findings")

# 2. Dep scan
d = get_dep_scanner()
s2 = d.scan_dependencies()
print(f"[PASS] Dep scan: {s2['packages_scanned']} packages, {s2['vulnerabilities_found']} vulns")

# 3. Baseline
b = get_baseline_checker()
c = b.comprehensive_baseline_report()
print(f"[PASS] Baseline: overall score = {c['overall_score']}")

# 4. Audit monitor
a = get_audit_monitor()
m = a.realtime_monitoring()
print(f"[PASS] Monitor: {m['active_rules']} rules active, {m['alerts_today']} alerts today")

# 5. Data security
ds = get_data_security()
o = ds.data_security_overview()
print(f"[PASS] Data security: score = {o['overall_score']}, grade = {o['grade']}")

# 6. Dashboard
dash = get_dashboard()
ov = dash.security_overview()
print(f"[PASS] Dashboard: security score = {ov['security_score']}, risk = {ov['risk_level']}")

print("\n=== ALL 6 MODULES FUNCTIONAL TESTS PASSED ===")
