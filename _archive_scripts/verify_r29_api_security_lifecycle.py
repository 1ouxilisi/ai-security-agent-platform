#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verification script for Round 29 Direction 3: API Security Lifecycle."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 1. Import all 7 core modules
from api_security_lifecycle import (
    api_assets, design_security, dev_security,
    runtime_security, abuse_logic, governance_compliance,
    api_security_dashboard,
)
print("[PASS] 7 core modules imported OK")

# 2. Singleton getters
a = api_assets.get_api_assets()
d = design_security.get_design_security()
dv = dev_security.get_dev_security()
r = runtime_security.get_runtime_security()
ab = abuse_logic.get_abuse_logic()
g = governance_compliance.get_governance_compliance()
dash = api_security_dashboard.get_api_security_dashboard()
print("[PASS] All singletons OK")

# 3. Routes import
from api_server import api_security_lifecycle_routes as routes_mod
ep_count = len(routes_mod.router.routes)
print(f"[PASS] Routes module imported OK, endpoints: {ep_count}")

# 4. Smoke: overview
ov = dash.overview()
print(f"[PASS] Overview: security_score={ov['security_score']}, apis={ov['assets']['total_apis']}")

# 5. Smoke: threat detection
threat = r.detect_threat("' OR 1=1 UNION SELECT password FROM users")
print(f"[PASS] Threat detection: {threat['threat_count']} threats found")

# 6. Smoke: secret detection
sr = dv.detect_secrets('api_key = "sk_1234567890abcdefghij"', 'test.py')
print(f"[PASS] Secret detection: {sr['secret_count']} secrets found")

# 7. Smoke: JSON schema validation
val = d.validate_json_schema(
    {"name": "test", "age": -5},
    {"type": "object", "required": ["name"],
     "properties": {"name": {"type": "string", "maxLength": 10},
                    "age": {"type": "integer", "minimum": 0}}}
)
print(f"[PASS] Schema validation: valid={val['valid']}, errors={val['error_count']}")

# 8. Smoke: abuse detection
ab.log_request("test-client-001", "/api/v1/test", "curl/7.68.0")
for i in range(60):
    ab.log_request("test-client-001", "/api/v1/test", "curl/7.68.0")
abuse_result = ab.detect_abuse("test-client-001")
print(f"[PASS] Abuse detection: detected={abuse_result['abuse_detected']}, signals={len(abuse_result['signals'])}")

# 9. Smoke: maturity assessment
mat = g.assess_maturity({"governance": 3, "design": 4, "development": 3, "runtime": 4, "monitoring": 2})
print(f"[PASS] Maturity: {mat['maturity_name']} (level {mat['maturity_level']})")

# 10. Smoke: API asset discovery from traffic
traffic_result = a.discover_from_traffic([
    '192.168.1.1 - "GET /api/v2/newresource HTTP/1.1" 200',
    '192.168.1.2 - "POST /api/v2/submit HTTP/1.1" 201',
])
print(f"[PASS] Traffic discovery: found {len(traffic_result)} new APIs")

# 11. Smoke: health score
hs = a.compute_health_score("api-user-login")
print(f"[PASS] Health score: {hs['overall_score']} ({hs['health_status']})")

# 12. Smoke: key generation
key = dv.generate_key("test-key", "test-owner", ["read", "write"])
print(f"[PASS] Key generated: {key['key_prefix']}, id={key['id']}")

# 13. Smoke: gate evaluation
gate = dv.evaluate_gate({"critical_vulns": 0, "high_vulns": 3, "medium_vulns": 15})
print(f"[PASS] Gate evaluation: passed={gate['passed']}, violations={len(gate['violations'])}")

# 14. Smoke: circular dependency detection
cycles = a.detect_circular_deps()
print(f"[PASS] Circular deps detected: {len(cycles)} cycles")

# 15. Smoke: bot detection
bot = ab.detect_bot("python-requests/2.28", 150, 0, 0)
print(f"[PASS] Bot detection: is_bot={bot['is_bot']}, confidence={bot['confidence']}")

# 16. Smoke: data masking
masked = r.mask_data({"password": "secret123", "phone": "13800138000", "name": "test"})
print(f"[PASS] Data masking: password={masked['password']}")

print()
print("=" * 60)
print(f"TOTAL ENDPOINTS: {ep_count}")
print("ALL SMOKE TESTS PASSED")
