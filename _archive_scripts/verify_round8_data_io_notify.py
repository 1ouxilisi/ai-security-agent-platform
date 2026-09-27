# -*- coding: utf-8 -*-
"""
verify_round8_data_io_notify.py - Round 8 verification.

Checks:
  1. All new modules import cleanly.
  2. data_io router has >= 11 endpoints.
  3. notification router has >= 15 endpoints.
  4. parsers.py has 6 parser classes + BaseParser.
  5. channels.py has 7 channel classes + BaseChannel.
  6. templates.py has 7 predefined templates.
  7. exporter.py supports 5 formats.
  8. notification_console.html is non-empty with full HTML.
"""

import os
import sys
import inspect

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}  {detail}")


# 1. Imports.
try:
    import data_import.parsers as P
    import data_import.importer as I
    import data_export.exporter as E
    import notifications.channels as C
    import notifications.templates as T
    import notifications.router as R
    from api_server.data_io_routes import router as r1
    from api_server.notification_routes import router as r2
    check("all imports", True)
except Exception as e:
    check("all imports", False, repr(e))
    sys.exit(1)

# 2. Router endpoint counts.
n1 = len(r1.routes)
n2 = len(r2.routes)
check("data_io_routes endpoints >= 11", n1 >= 11, f"got {n1}")
check("notification_routes endpoints >= 15", n2 >= 15, f"got {n2}")

# 3. Parsers: 6 + BaseParser.
parser_names = [
    "BaseParser", "NessusParser", "OpenVASParser", "BurpParser",
    "NmapParser", "AcunetixParser", "AppScanParser",
]
missing = [n for n in parser_names if not hasattr(P, n)]
check("parsers: BaseParser + 6 scanners", not missing, f"missing={missing}")

# 4. Channels: 7 + BaseChannel.
ch_names = [
    "BaseChannel", "WeComChannel", "DingTalkChannel", "FeishuChannel",
    "SlackChannel", "EmailChannel", "WebhookChannel", "InAppChannel",
]
missing = [n for n in ch_names if not hasattr(C, n)]
check("channels: BaseChannel + 7 channels", not missing, f"missing={missing}")

# 5. Templates: 7 predefined.
n_tpl = len(T.PREDEFINED_TEMPLATES)
check("templates: 7 predefined", n_tpl == 7, f"got {n_tpl}")

# 6. Exporter: 5 formats.
fmts = set(E.SUPPORTED_FORMATS)
need = {"json", "csv", "xlsx", "pdf", "html"}
check("exporter: 5 formats", need.issubset(fmts), f"got {sorted(fmts)}")

# 7. HTML file non-empty with structure.
html_path = os.path.join(ROOT, "api_server", "notification_console.html")
with open(html_path, "r", encoding="utf-8") as f:
    html = f.read()
check("notification_console.html non-empty", len(html) > 1000, f"{len(html)} bytes")
check("notification_console.html has structure",
      "<html" in html and "</html>" in html and "通知中心" in html)

# 8. Functional smoke: parse + dedup + export + inapp send.
try:
    sample = [
        {"title": "A", "severity": "high", "cve": "CVE-2024-0001", "url": "http://x", "port": "80"},
        {"title": "A", "severity": "high", "cve": "CVE-2024-0001", "url": "http://x", "port": "80"},
        {"title": "B", "severity": "Critical", "cve": "", "url": "http://y", "port": "443"},
    ]
    out = P.deduplicate(sample)
    check("deduplicate works", len(out) == 2, f"got {len(out)}")
    # severity normalization
    check("severity normalize critical", P.normalize_severity("Critical") == "critical")
    # export
    res = E.export_data(out, "json", {"template": "brief_list"})
    check("export json ok", isinstance(res["content"], bytes) and res["count"] == 2)
    res_html = E.export_data(out, "html", {"fields": ["title", "severity", "cve"]})
    check("export html ok", b"<table" in res_html["content"])
    # channel inapp
    res_send = C.InAppChannel().send("hello round8")
    check("inapp send ok", res_send["success"])
    # template render
    rendered = T.render_template("scan_completed", {
        "target": "10.0.0.1", "scan_type": "nmap", "vuln_count": 5,
        "high_count": 2, "risk_score": 75, "report_link": "/r",
        "time": "2026-09-13",
    })
    check("template render ok", "10.0.0.1" in rendered and "scan_completed" not in rendered)
    # dispatcher: create sub + dispatch
    sub = R.create_subscription("high_risk_found", ["inapp"], {})
    dr = R.dispatch("high_risk_found", {
        "target": "h", "vuln_title": "X", "severity": "high",
        "cve": "C", "description": "d", "time": "now",
    })
    check("dispatch returns summary", dr["dispatched"] >= 1, str(dr))
    # history/stats
    R.get_history(5)
    R.get_stats()
    check("history/stats ok", True)
except Exception as e:  # noqa: BLE001
    check("functional smoke", False, repr(e))

# Summary.
print("\n=== SUMMARY ===")
passed = sum(1 for _, ok, _ in RESULTS if ok)
total = len(RESULTS)
print(f"Passed: {passed}/{total}")
sys.exit(0 if passed == total else 1)
