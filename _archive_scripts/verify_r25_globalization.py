# -*- coding: utf-8 -*-
"""验证 globalization 模块导入和端点统计"""
import sys, os, re, py_compile

os.chdir(r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent")
sys.path.insert(0, os.getcwd())

results = []

# Test each module individually
modules = [
    "globalization.i18n_engine",
    "globalization.regional_compliance",
    "globalization.global_payment",
    "globalization.global_deployment",
    "globalization.localization",
    "globalization.globalization_dashboard",
]
for mod in modules:
    try:
        __import__(mod)
        results.append((mod, "OK", ""))
    except Exception as e:
        results.append((mod, "FAIL", str(e)))

# Test package
try:
    import globalization
    ok = globalization.I18N_ENGINE is not None
    results.append(("globalization package", "OK" if ok else "PARTIAL", ""))
except Exception as e:
    results.append(("globalization package", "FAIL", str(e)))

# Test routes file syntax
try:
    py_compile.compile("api_server/globalization_routes.py", doraise=True)
    results.append(("globalization_routes.py syntax", "OK", ""))
except Exception as e:
    results.append(("globalization_routes.py syntax", "FAIL", str(e)))

# Count endpoints
with open("api_server/globalization_routes.py", "r", encoding="utf-8") as f:
    content = f.read()
endpoints = re.findall(r"@router\.(get|post|put|delete)\(", content)
results.append(("API endpoints", str(len(endpoints)), ""))

# Count lines for each file
files = [
    "globalization/__init__.py",
    "globalization/i18n_engine.py",
    "globalization/regional_compliance.py",
    "globalization/global_payment.py",
    "globalization/global_deployment.py",
    "globalization/localization.py",
    "globalization/globalization_dashboard.py",
    "api_server/globalization_routes.py",
    "api_server/globalization_console.html",
]
for fp in files:
    try:
        with open(fp, "r", encoding="utf-8") as f:
            lines = len(f.readlines())
        results.append((f"LINES {fp}", str(lines), ""))
    except Exception as e:
        results.append((f"LINES {fp}", "ERR", str(e)))

# Check HTML size
html_path = "api_server/globalization_console.html"
sz = os.path.getsize(html_path)
results.append(("HTML size bytes", str(sz), ""))

for name, status, err in results:
    print(f"{name}: {status} {err}")

print(f"\n=== SUMMARY ===")
print(f"Modules OK: {sum(1 for n,s,e in results if s=='OK')}")
print(f"Modules FAIL: {sum(1 for n,s,e in results if s=='FAIL')}")
print(f"Total endpoints: {len(endpoints)}")
