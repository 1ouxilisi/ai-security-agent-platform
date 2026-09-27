# -*- coding: utf-8 -*-
"""
verify_round8_frontend.py — Verify Round 8 deliverables.
Checks:
  1. All new files exist with correct paths
  2. zh-CN.json / en-US.json each >= 500 keys and key sets identical
  3. responsive.css has @media queries and 3 breakpoints
  4. mobile-nav.js has hamburger / bottom-nav / gesture
  5. i18n.js has t/setLanguage/getLanguage/data-i18n handling
  6. 5 core HTML pages include viewport, responsive.css, mobile-nav.js, i18n.js, lang switcher, data-i18n
  7. mobile_test.html & i18n_test.html non-empty with full HTML structure
"""
import json, os, re, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SRV = os.path.join(ROOT, "api_server")

results = []
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))

def read(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()

def exists(p):
    return os.path.isfile(p) and os.path.getsize(p) > 0

print("=" * 70)
print("Round 8 Frontend Verification")
print("=" * 70)

# ---------- 1. Files exist ----------
print("\n[1] File existence")
required = [
    "api_server/css/responsive.css",
    "api_server/js/mobile-nav.js",
    "api_server/js/i18n.js",
    "api_server/locales/zh-CN.json",
    "api_server/locales/en-US.json",
    "api_server/mobile_test.html",
    "api_server/i18n_test.html",
]
for rel in required:
    p = os.path.join(ROOT, rel.replace("/", os.sep))
    check(f"exists: {rel}", exists(p), f"{os.path.getsize(p)} bytes" if exists(p) else "missing")

# ---------- 2. Locale key counts & equality ----------
print("\n[2] Locale JSON key counts")
zh_path = os.path.join(SRV, "locales", "zh-CN.json")
en_path = os.path.join(SRV, "locales", "en-US.json")
zh = en = {}
try:
    zh = json.loads(read(zh_path))
    en = json.loads(read(en_path))
    check("zh-CN.json parses", True)
    check("en-US.json parses", True)
except Exception as e:
    check("locale JSON parses", False, str(e))
    sys.exit(1)

check("zh-CN >= 500 keys", len(zh) >= 500, f"{len(zh)} keys")
check("en-US >= 500 keys", len(en) >= 500, f"{len(en)} keys")
check("key sets identical", set(zh.keys()) == set(en.keys()),
      f"zh={len(zh)} en={len(en)} diff={len(set(zh)^set(en))}")

# ---------- 3. responsive.css ----------
print("\n[3] responsive.css")
css = read(os.path.join(SRV, "css", "responsive.css"))
check("has @media query", css.count("@media") >= 3, f"{css.count('@media')} blocks")
for bp in ["767.98", "1024", "768"]:
    check(f"breakpoint {bp} present", bp in css)
check("has .table-responsive", ".table-responsive" in css)
check("has bottom-nav", ".mn-bottom-nav" in css)
check("has hamburger", ".mn-hamburger" in css)
check("has .echarts-container", "echarts" in css)
check("min-height 44px touch target", "44px" in css)
check("mobile font 16px", "font-size: 16px" in css)

# ---------- 4. mobile-nav.js ----------
print("\n[4] mobile-nav.js")
mn = read(os.path.join(SRV, "js", "mobile-nav.js"))
check("hamburger injection", "mn-hamburger" in mn and "injectHamburger" in mn)
check("bottom nav", "mn-bottom-nav" in mn and "injectBottomNav" in mn)
check("touch gesture", "touchstart" in mn and "touchend" in mn and "swipe" in mn.lower())
check("overlay close", "mn-overlay" in mn and "closeSidebar" in mn)
check("resize listener", "resize" in mn and "BREAKPOINT" in mn)
check("translateX animation", "translateX" in mn)
check("5 bottom entries", all(x in mn for x in ["home", "scan", "workflow", "report", "settings"]))

# ---------- 5. i18n.js ----------
print("\n[5] i18n.js")
i18n = read(os.path.join(SRV, "js", "i18n.js"))
for fn in ["function t(", "setLanguage", "getLanguage", "getMissingKeys"]:
    check(f"contains {fn}", fn in i18n)
check("localStorage key ai_hacking_lang", "ai_hacking_lang" in i18n)
check("navigator.language detect", "navigator.language" in i18n)
check("async fetch locale", "/static/locales/" in i18n and "fetch(" in i18n)
check("data-i18n attribute", "data-i18n" in i18n)
check("data-i18n-placeholder", "data-i18n-placeholder" in i18n)
check("data-i18n-title", "data-i18n-title" in i18n)
check("data-i18n-aria-label", "data-i18n-aria-label" in i18n)
check("plural handling (_one/_other)", "_one" in i18n and "_other" in i18n)
check("interpolation {var}", r"\{(\w+)\}" in i18n or "{name}" in i18n)
check("window.i18n exposed", "window.i18n" in i18n or "global.i18n" in i18n)

# ---------- 6. 5 core HTML pages ----------
print("\n[6] Core HTML pages")
core_pages = [
    "workflow_console.html",
    "ai_assistant.html",
    "platform_console_v2.html",
    "unified_console.html",
    "defense_console.html",
]
for pg in core_pages:
    p = os.path.join(SRV, pg)
    if not exists(p):
        check(pg, False, "missing")
        continue
    h = read(p)
    has_viewport = 'name="viewport"' in h
    has_css = "/static/css/responsive.css" in h
    has_mn = "/static/js/mobile-nav.js" in h
    has_i18n = "/static/js/i18n.js" in h
    has_switcher = "lang-switcher" in h or "lang-btn" in h
    has_datai18n = "data-i18n" in h
    check(f"{pg}: viewport", has_viewport)
    check(f"{pg}: responsive.css", has_css)
    check(f"{pg}: mobile-nav.js", has_mn)
    check(f"{pg}: i18n.js", has_i18n)
    check(f"{pg}: lang switcher", has_switcher)
    check(f"{pg}: data-i18n present", has_datai18n)

# ---------- 7. Test pages ----------
print("\n[7] Test pages")
mt = read(os.path.join(SRV, "mobile_test.html"))
check("mobile_test.html has full HTML", mt.lstrip().startswith("<!DOCTYPE html>") and "</html>" in mt)
check("mobile_test.html refs responsive.css", "/static/css/responsive.css" in mt)
check("mobile_test.html refs mobile-nav.js", "/static/js/mobile-nav.js" in mt)
check("mobile_test.html has device switcher", "setDevice" in mt and "375" in mt)

it = read(os.path.join(SRV, "i18n_test.html"))
check("i18n_test.html has full HTML", it.lstrip().startswith("<!DOCTYPE html>") and "</html>" in it)
check("i18n_test.html refs i18n.js", "/static/js/i18n.js" in it)
check("i18n_test.html shows coverage", "覆盖率" in it or "cov" in it or "coverage" in it.lower())
check("i18n_test.html shows missing keys", "missing" in it.lower() or "缺失" in it)

# ---------- Summary ----------
print("\n" + "=" * 70)
total = len(results)
passed = sum(1 for _, ok, _ in results if ok)
failed = total - passed
print(f"TOTAL: {passed}/{total} passed, {failed} failed")
print("=" * 70)
sys.exit(0 if failed == 0 else 1)
