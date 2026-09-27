# -*- coding: utf-8 -*-
"""onboarding 端点冒烟测试：起一个最小 FastAPI 实例，打 3 个端点。"""
import os
import sys
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
from fastapi import FastAPI
from fastapi.testclient import TestClient
from api_server.onboarding_routes import router

app = FastAPI()
app.include_router(router)
c = TestClient(app)

r1 = c.get("/api/v1/onboarding/status", params={"user_id": "smoke_user"})
print("GET /status ->", r1.status_code, r1.json())

r2 = c.post("/api/v1/onboarding/complete", json={"user_id": "smoke_user", "step": "nav"})
print("POST /complete(step) ->", r2.status_code, r2.json())

r3 = c.post("/api/v1/onboarding/complete", json={"user_id": "smoke_user"})
print("POST /complete(done) ->", r3.status_code, r3.json())

r4 = c.get("/api/v1/onboarding/status", params={"user_id": "smoke_user"})
print("GET /status(after) ->", r4.status_code, r4.json())

r5 = c.get("/api/v1/onboarding/steps")
j = r5.json()
print("GET /steps ->", r5.status_code, "success=", j.get("success"), "count=", j.get("count"))

# 清理冒烟数据
sf = os.path.join(ROOT, "data", "onboarding_status.json")
if os.path.exists(sf):
    os.remove(sf)
    print("cleaned", sf)
print("SMOKE_OK")
