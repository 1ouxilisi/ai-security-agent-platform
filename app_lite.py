#!/usr/bin/env python3
"""AI Security Agent Platform v14 - LLM + Mobile + Blockchain"""
import sys, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="AI Security Agent Platform", version="14.0", docs_url="/docs")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                    allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
async def health():
    routes = [r.path for r in app.routes if hasattr(r, 'path')]
    return {"status": "ok", "version": "14.0", "focus": "LLM+Mobile+Blockchain", "routes": {"total": len(routes)}}

@app.get("/", response_class=HTMLResponse)
async def root():
    p = os.path.join(os.path.dirname(__file__), "v13_console.html")
    with open(p, "r", encoding="utf-8") as f:
        return f.read()

# 注册核心路由
from api_server.v12_product_routes import router as v12_router
from api_server.v13_ai_mobile_chain import router as v13_router
app.include_router(v12_router)
app.include_router(v13_router)

if __name__ == "__main__":
    print("=" * 60)
    print("  AI Security Agent Platform v14")
    print("  Console:  http://127.0.0.1:8001/")
    print("  API Docs: http://127.0.0.1:8001/docs")
    print("=" * 60)
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")
