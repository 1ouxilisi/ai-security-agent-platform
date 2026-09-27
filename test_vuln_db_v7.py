# -*- coding: utf-8 -*-
"""
test_vuln_db_v7.py - Round 7 vuln database deep module tests.

Verifies:
    - search functionality
    - service matching
    - stats
    - pagination
    - all 9 API routes mount and return sensible data
Run: python test_vuln_db_v7.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}  {detail}")


def main():
    from vuln_database.cve_database import (
        CVE_DATABASE, CVE_INDEX, get_cve, search_cve,
        match_cve_by_service, get_cve_stats, list_cves,
    )
    from vuln_database.exploit_db import (
        EXPLOIT_DB, get_exploit_by_cve, list_exploits, search_exploits,
    )
    from vuln_database.remediation_db import (
        REMEDIATION_DB, get_remediation_by_cve, list_remediations, search_remediations,
    )

    print("== 1. Data volume ==")
    check("CVE total >= 200", len(CVE_DATABASE) >= 200, f"got {len(CVE_DATABASE)}")
    check("Exploit total >= 100", len(EXPLOIT_DB) >= 100, f"got {len(EXPLOIT_DB)}")
    check("Remediation total >= 100", len(REMEDIATION_DB) >= 100, f"got {len(REMEDIATION_DB)}")

    print("== 2. get_cve / exact lookup ==")
    rec = get_cve("CVE-2021-44228")
    check("Log4Shell present", rec is not None and "Log4j" in rec["affected_product"])
    check("get_cve case-insensitive", get_cve("cve-2021-44228") is not None)
    check("get_cve unknown returns None", get_cve("CVE-9999-9999") is None)

    print("== 3. search_cve ==")
    r = search_cve(keyword="log4j")
    check("keyword=log4j returns >=1", len(r) >= 1, f"got {len(r)}")
    r = search_cve(product="nginx")
    check("product=nginx returns >=1", len(r) >= 1, f"got {len(r)}")
    r = search_cve(vuln_type="代码执行")
    check("vuln_type=代码执行 returns >=1", len(r) >= 1, f"got {len(r)}")
    r = search_cve(severity="critical")
    check("severity=critical returns >=1", len(r) >= 1, f"got {len(r)}")
    r = search_cve(cvss_min=9.5)
    check("cvss_min=9.5 returns high-severity set", all(x["cvss_score"] >= 9.5 for x in r),
          f"got {len(r)}")
    r = search_cve(year=2024)
    check("year=2024 returns >=1", len(r) >= 1, f"got {len(r)}")
    r = search_cve(keyword="nosuchword123")
    check("bogus keyword returns empty", r == [])

    print("== 4. match_cve_by_service ==")
    m = match_cve_by_service("nginx")
    check("nginx match returns >=1", len(m) >= 1, f"got {len(m)}")
    m = match_cve_by_service("apache")
    check("apache match returns >=1", len(m) >= 1, f"got {len(m)}")
    m = match_cve_by_service("")
    check("empty service returns []", m == [])
    m = match_cve_by_service("log4j")
    check("log4j match returns Log4Shell", any(x["cve_id"] == "CVE-2021-44228" for x in m),
          f"got {len(m)}")

    print("== 5. stats ==")
    s = get_cve_stats()
    check("stats.total matches DB", s["total"] == len(CVE_DATABASE))
    check("stats has by_type", isinstance(s["by_type"], dict) and len(s["by_type"]) > 0)
    check("stats has by_severity", isinstance(s["by_severity"], dict))
    check("stats has by_year", isinstance(s["by_year"], dict) and len(s["by_year"]) > 0)
    check("stats has top_products", isinstance(s["top_products"], list) and len(s["top_products"]) <= 10)

    print("== 6. list_cves pagination ==")
    p1 = list_cves(page=1, page_size=20)
    check("page1 has 20 items", len(p1["items"]) == 20)
    check("page1 total_pages correct", p1["total_pages"] >= 14)
    p2 = list_cves(page=2, page_size=20)
    check("page2 different from page1", p1["items"][0]["cve_id"] != p2["items"][0]["cve_id"])
    p_last = list_cves(page=9999, page_size=20)
    check("oversized page returns empty items", p_last["items"] == [])
    p_sort = list_cves(page=1, page_size=10, sort_by="cvss_score", sort_order="asc")
    scores = [x["cvss_score"] for x in p_sort["items"]]
    check("asc sort works", scores == sorted(scores), f"scores={scores[:5]}")

    print("== 7. exploit db ==")
    e = get_exploit_by_cve("CVE-2021-44228")
    check("Log4Shell exploit exists", e is not None)
    check("exploit has risk warning", e and "仅供" in e["risk_warning"])
    check("exploit has no executable code field", "exploit_code" not in e)
    el = list_exploits(page=1, page_size=10)
    check("exploit pagination works", len(el["items"]) == 10)
    es = search_exploits(keyword="log4j")
    check("exploit search by keyword works", len(es) >= 1)

    print("== 8. remediation db ==")
    rm = get_remediation_by_cve("CVE-2021-44228")
    check("Log4Shell remediation exists", rm is not None)
    check("remediation has fix_steps list", isinstance(rm["fix_steps"], list) and len(rm["fix_steps"]) >= 3)
    rl = list_remediations(page=1, page_size=10)
    check("remediation pagination works", len(rl["items"]) == 10)
    rs = search_remediations(priority="紧急")
    check("remediation filter by priority=紧急", len(rs) >= 1)

    print("== 9. API routes mount ==")
    from api_server.vuln_db_routes import router
    paths = {r.path for r in router.routes}
    expected = {
        "/api/v1/vuln-db/cve",
        "/api/v1/vuln-db/cve/search",
        "/api/v1/vuln-db/cve/{cve_id}",
        "/api/v1/vuln-db/cve/match",
        "/api/v1/vuln-db/exploit",
        "/api/v1/vuln-db/exploit/{cve_id}",
        "/api/v1/vuln-db/remediation",
        "/api/v1/vuln-db/remediation/{cve_id}",
        "/api/v1/vuln-db/stats",
    }
    check("all 9 endpoints mounted", expected.issubset(paths),
          f"missing: {expected - paths}")

    print()
    print(f"==== RESULT: {PASS} passed, {FAIL} failed ====")
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
