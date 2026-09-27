#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Smoke test for ux_docs_deep (Round 28, Direction 4)."""
from __future__ import annotations
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

print("=== SMOKE TEST: ux_docs_deep ===")

# 1. User Manual
from ux_docs_deep.user_manual import get_user_manual_manager
m = get_user_manual_manager()
secs = m.list_sections()
arts = m.list_articles()
new = m.create_article("quick_start", "qs_install", "冒烟测试文章", "测试内容", tags=["smoke"])
print("[Manual] sections=%d articles=%d created=%s" % (len(secs), len(arts), new["id"][:12]))
print("[Manual] stats=%s" % m.stats())

# 2. Deployment
from ux_docs_deep.deployment_docs import get_deployment_docs_manager
d = get_deployment_docs_manager()
d.create_doc("ops", "冒烟部署", "测试内容", "linux", "sre")
d.record_deploy("staging", "docker", "v28.4.0", "tester", "success")
print("[Deploy] platforms=%d docs=%d records=%d" % (
    len(d.list_platforms()), len(d.list_docs()), len(d.list_deploy_records())))

# 3. API Docs
from ux_docs_deep.api_docs import get_api_docs_manager
a = get_api_docs_manager()
a.create_endpoint("GET", "/api/v1/smoke", "冒烟端点", "test")
a.issue_token("smoke-client")
print("[API] endpoints=%d tokens=%d changes=%d" % (
    len(a.list_endpoints()), len(a.list_tokens()), len(a.list_changes())))

# 4. Frontend UX
from ux_docs_deep.frontend_ux import get_frontend_ux_manager
u = get_frontend_ux_manager()
u.create_improvement("performance", "冒烟改进", "测试")
u.record_perf("/smoke", 100, 200, 10, 0.01, 50, 100, 10, 10, 0.9)
print("[UX] improvements=%d perf=%d languages=%d" % (
    len(u.list_improvements()), len(u.list_perf()), len(u.list_i18n_languages())))

# 5. Onboarding
from ux_docs_deep.onboarding_tutorials import get_onboarding_manager
o = get_onboarding_manager()
o.create_tutorial("冒烟教程", "beginner")
o.create_video("冒烟视频", "feature", 120)
o.create_ticket("u1", "测试", "测试内容")
print("[Onboarding] tutorials=%d videos=%d tickets=%d" % (
    len(o.list_tutorials()), len(o.list_videos()), len(o.list_tickets())))

# 6. Docs Management
from ux_docs_deep.docs_management import get_docs_manager
dm = get_docs_manager()
doc = dm.create_doc("冒烟文档", "技术", "tester", "内容")
dm.publish_doc(doc["id"])
dm.like_doc(doc["id"])
dm.comment_doc(doc["id"], "alice", "很好")
print("[Docs] list=%d versions=%d total=%d" % (
    len(dm.list_docs()), len(dm.list_versions(doc["id"])),
    dm.analytics()["total_docs"]))

# 7. Dashboard
from ux_docs_deep.ux_docs_dashboard import get_ux_docs_dashboard
dash = get_ux_docs_dashboard()
ov = dash.overview()
print("[Dashboard] manual=%d api=%d trend=%d" % (
    ov["manual"]["total_articles"], ov["api"]["total_endpoints"],
    len(ov["trend_7d"])))

# HTML size check
html_path = os.path.join(ROOT, "api_server", "ux_docs_deep_console.html")
size = os.path.getsize(html_path)
print("[HTML] %s = %d bytes (%.1f KB)" % (html_path, size, size / 1024))
assert size > 15 * 1024, "HTML too small!"

# Endpoint count
sys.path.insert(0, os.path.join(ROOT, "api_server"))
import ux_docs_deep_routes as r
eps = [route for route in r.router.routes]
print("[Routes] total_endpoints=%d" % len(eps))
assert len(eps) >= 50, "Not enough endpoints!"

print("=== ALL SMOKE TESTS PASSED ===")
