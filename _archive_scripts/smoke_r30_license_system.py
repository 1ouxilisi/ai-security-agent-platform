# -*- coding: utf-8 -*-
"""Smoke test for v30 real license system."""
from __future__ import annotations
import os, sys, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from license_system.license_generator import (
    generate_machine_code, generate_real_license, REAL_TIERS, VALID_TIER_CODES,
)
from license_system.license_verifier import verify_license
from license_system.license_manager import get_manager
from license_system.feature_gating import get_gate, TIER_COMPARISON

ok = 0
fail = 0
def check(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  [PASS] {name}")
    else:
        fail += 1
        print(f"  [FAIL] {name} :: {detail}")

print("== 1. 机器码生成 ==")
mc = generate_machine_code()
check("machine_code is 32-hex", isinstance(mc, str) and len(mc) == 32, mc)

print("== 2. 版本等级 ==")
check("tiers == free/pro/enterprise",
      list(REAL_TIERS.keys()) == ["free", "pro", "enterprise"],
      list(REAL_TIERS.keys()))
check("VALID_TIER_CODES ok", VALID_TIER_CODES == ("free","pro","enterprise"))

print("== 3. 签发 Pro License ==")
issued = generate_real_license(machine_code=mc, tier="pro", customer="TestUser", duration_days=365)
lic = issued["license_key"]
check("license has dot", "." in lic)
check("payload tier=pro", issued["payload"]["tier"] == "pro")
check("payload machine matches", issued["payload"]["machine_code"] == mc)
check("payload has 6 keys", all(k in issued["payload"] for k in
      ["lic_id","machine_code","tier","customer","issued_at","expires_at","features"]))

print("== 4. 验证正确 License ==")
v = verify_license(lic, expected_machine_code=mc)
check("valid=True", v["valid"] is True, v)
check("code=ok", v["code"] == "ok")
check("days_remaining ~365", 360 <= v["days_remaining"] <= 365, v["days_remaining"])

print("== 5. 篡改 License ==")
tampered = lic[:-4] + "AAAA"
v2 = verify_license(tampered, expected_machine_code=mc)
check("tampered invalid", v2["valid"] is False)
check("tampered code=bad_signature", v2["code"] == "bad_signature", v2["code"])

print("== 6. 机器码不匹配 ==")
v3 = verify_license(lic, expected_machine_code="0"*32)
check("machine mismatch invalid", v3["valid"] is False)
check("machine mismatch code", v3["code"] == "machine_mismatch", v3["code"])

print("== 7. 过期 License ==")
from license_system.license_generator import get_real_issuer
expired = get_real_issuer().issue(machine_code=mc, tier="pro", duration_days=1,
                                  issued_at=time.time() - 86400*30)
v4 = verify_license(expired["license_key"], expected_machine_code=mc)
check("expired invalid", v4["valid"] is False)
check("expired code", v4["code"] == "expired", v4["code"])

print("== 8. 激活 / 状态 / 卸载 ==")
mgr = get_manager()
r = mgr.activate(lic)
check("activate success", r["success"], r)
st = mgr.status()
check("status activated", st["activated"] is True)
check("status tier=pro", st["tier"] == "pro")
check("status customer=TestUser", st["customer"] == "TestUser")
check("status has upgrade_guide", "upgrade_guide" in st)
r2 = mgr.deactivate()
check("deactivate ok", r2["success"])
st2 = mgr.status()
check("deactivated -> free", st2["activated"] is False and st2["tier"] == "free")

print("== 9. 功能分级 ==")
gate = get_gate()
# Free
free_payload = {"tier":"free","features":["basic_scan","single_report"],
                "modules":["dashboard","basic_scan"]}
check("free has basic_scan", gate.has_feature(free_payload, "basic_scan"))
check("free no ai_analysis", not gate.has_feature(free_payload, "ai_analysis"))
check("free no multi_tenant", not gate.can_multi_tenant(free_payload))
# Pro
pro_payload = {"tier":"pro","features":["ai_analysis"],
               "modules":["vuln_scan","ai_analysis"]}
check("pro has ai_analysis", gate.has_feature(pro_payload, "ai_analysis"))
check("pro has vuln_scan module", gate.has_module(pro_payload, "vuln_scan"))
check("pro no multi_tenant", not gate.can_multi_tenant(pro_payload))
# Enterprise
ent_payload = {"tier":"enterprise","features":["*"],"modules":["*"]}
check("ent wildcard feature", gate.has_feature(ent_payload, "anything"))
check("ent wildcard module", gate.has_module(ent_payload, "anything"))
check("ent multi_tenant", gate.can_multi_tenant(ent_payload))

print("== 10. 配额 ==")
q = gate.check_quota(free_payload, "smoke")
check("free quota=100", q["limit"] == 100)
q2 = gate.consume_quota(free_payload, "smoke", 50)
check("used 50", q2["used"] == 50)
q3 = gate.consume_quota(free_payload, "smoke", 50)
check("exceeded after 100", q3["exceeded"] is True)

print("== 11. 版本对比表 ==")
check("3 tiers in comparison", len(TIER_COMPARISON) == 3)

print("== 12. FastAPI 路由可导入 ==")
try:
    from api_server.license_real_routes import router, root_router
    routes = [r.path for r in router.routes]
    check("router has 16 paths", len(routes) >= 15, str(len(routes)))
    required = ["/activate","/status","/verify","/features","/generate",
                "/deactivate","/history","/machine-code","/tiers",
                "/check-feature","/quota","/consume-quota",
                "/upgrade-guide","/health"]
    missing = [p for p in required if not any(rt.endswith(p) for rt in routes)]
    check("all required endpoints present", not missing, f"missing={missing}; have={routes}")
except Exception as e:
    check("routes import", False, repr(e))

print()
print(f"=== RESULT: {ok} passed, {fail} failed ===")
sys.exit(0 if fail == 0 else 1)
