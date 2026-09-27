# -*- coding: utf-8 -*-
"""第14轮 DevSecOps 升级验证脚本。"""
import os, sys, importlib

ROOT = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent"
sys.path.insert(0, ROOT)

FILES = [
    r"devsecops\__init__.py",
    r"devsecops\pipeline_security.py",
    r"devsecops\repo_security.py",
    r"devsecops\build_artifact_security.py",
    r"devsecops\deployment_runtime_security.py",
    r"devsecops\security_gate.py",
    r"devsecops\devsecops_maturity.py",
    r"devsecops\devsecops_workflow.py",
    r"api_server\devsecops_routes.py",
]

print("=== 文件清单 ===")
total_lines = 0
for rel in FILES:
    p = os.path.join(ROOT, rel)
    with open(p, "r", encoding="utf-8") as f:
        n = sum(1 for _ in f)
    total_lines += n
    print(f"  {p}  ({n} lines, {os.path.getsize(p)} bytes)")

html = os.path.join(ROOT, r"api_server\devsecops_console.html")
print(f"  {html}  ({os.path.getsize(html)} bytes)")

print("\n=== 独立 import 验证 ===")
mods = [
    "devsecops",
    "devsecops.pipeline_security",
    "devsecops.repo_security",
    "devsecops.build_artifact_security",
    "devsecops.deployment_runtime_security",
    "devsecops.security_gate",
    "devsecops.devsecops_maturity",
    "devsecops.devsecops_workflow",
    "api_server.devsecops_routes",
]
for m in mods:
    try:
        mod = importlib.import_module(m)
        print(f"  OK  {m}")
    except Exception as e:
        print(f"  FAIL {m}: {e}")

print("\n=== 路由数量 ===")
from api_server.devsecops_routes import router
print(f"  router.routes = {len(router.routes)}")
paths = sorted({getattr(r, 'path', '?') for r in router.routes})
print(f"  unique paths = {len(paths)}")
for p in paths:
    print(f"    - {p}")
