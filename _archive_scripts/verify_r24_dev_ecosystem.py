# -*- coding: utf-8 -*-
"""Verify all developer_ecosystem modules compile and import."""
import sys, os, py_compile, json

os.chdir(r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent")
sys.path.insert(0, ".")

results = {}
files = [
    "developer_ecosystem/__init__.py",
    "developer_ecosystem/cli_tool.py",
    "developer_ecosystem/desktop_client.py",
    "developer_ecosystem/ide_plugin.py",
    "developer_ecosystem/python_sdk.py",
    "developer_ecosystem/developer_portal.py",
    "developer_ecosystem/open_api.py",
    "api_server/developer_ecosystem_routes.py",
]

all_ok = True
for f in files:
    try:
        py_compile.compile(f, doraise=True)
        lines = sum(1 for _ in open(f, "r", encoding="utf-8"))
        size = os.path.getsize(f)
        results[f] = {"status": "OK", "lines": lines, "bytes": size}
    except py_compile.PyCompileError as e:
        results[f] = {"status": "SYNTAX_ERROR", "error": str(e)}
        all_ok = False

# Actual import test
try:
    from developer_ecosystem import cli_tool, desktop_client, ide_plugin, python_sdk, developer_portal, open_api
    results["import_test"] = {"status": "OK", "modules_loaded": 6}
except Exception as e:
    results["import_test"] = {"status": "IMPORT_ERROR", "error": str(e)}
    all_ok = False

# Count API endpoints
try:
    import ast
    with open("api_server/developer_ecosystem_routes.py", "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    ep_count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Attribute) and isinstance(dec.value, ast.Name) and dec.value.id == "router":
                    ep_count += 1
    results["api_endpoints"] = ep_count
except Exception as e:
    results["api_endpoints"] = f"ERROR: {e}"

# HTML size
html_path = "api_server/developer_ecosystem_console.html"
results["html_console"] = {"bytes": os.path.getsize(html_path)}

print(json.dumps(results, indent=2, ensure_ascii=False))
print("ALL_OK:", all_ok)
