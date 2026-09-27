# -*- coding: utf-8 -*-
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from api_server.app import app
routes = getattr(app, "routes", [])
print(f"Total routes: {len(routes)}")
prefixes = ["/api/v1/workflow-executor", "/api/v1/task-console", "/api/v1/seed-manager", "/api/v1/system-health"]
for p in prefixes:
    found = [r for r in routes if p in getattr(r, "path", "")]
    print(f"  {p}: {len(found)} endpoints")
pages = ["/workflow-executor", "/task-console", "/seed-manager", "/system-health"]
for pg in pages:
    found = any(getattr(r, "path", "") == pg for r in routes)
    status = "OK" if found else "MISSING"
    print(f"  Page {pg}: {status}")
print("DONE")
