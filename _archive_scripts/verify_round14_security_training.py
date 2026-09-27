# -*- coding: utf-8 -*-
"""第14轮方向2 安全培训平台 验证脚本。"""
from __future__ import annotations
import importlib, os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

mods = [
    "security_training",
    "security_training.course_manager",
    "security_training.lab_environment",
    "security_training.exam_certification",
    "security_training.phishing_simulation",
    "security_training.awareness_assessment",
    "security_training.training_operations",
    "security_training.training_workflow",
]
print("=== IMPORT 验证 ===")
ok_all = True
for m in mods:
    try:
        mod = importlib.import_module(m)
        print(f"[OK] {m}")
    except Exception as e:
        ok_all = False
        print(f"[FAIL] {m}: {type(e).__name__}: {e}")

# 路由文件需要 fastapi
print("\n=== 路由导入 ===")
try:
    from api_server import security_training_routes as st
    paths = [r.path for r in st.router.routes]
    methods = set()
    for r in st.router.routes:
        methods.update(getattr(r, "methods", []) or [])
    print(f"[OK] api_server.security_training_routes")
    print(f"端点数: {len(paths)}")
    for p in paths:
        print("   ", p)
    print(f"router prefix: {st.router.prefix}")
    print(f"_MOD_AVAILABLE: {st._MOD_AVAILABLE}")
except Exception as e:
    ok_all = False
    import traceback; traceback.print_exc()

# 关键数据规模
print("\n=== 内置数据规模 ===")
try:
    from security_training.course_manager import COURSE_LIBRARY
    from security_training.exam_certification import EXAM_BANK
    from security_training.phishing_simulation import PHISHING_TEMPLATES
    from security_training.awareness_assessment import AWARENESS_QUESTIONNAIRE
    from security_training.lab_environment import RANGE_LIBRARY
    print(f"课程库: {len(COURSE_LIBRARY)}")
    print(f"考试题库: {len(EXAM_BANK)}")
    print(f"钓鱼模板: {len(PHISHING_TEMPLATES)}")
    print(f"意识测评题: {len(AWARENESS_QUESTIONNAIRE)}")
    print(f"靶场: {len(RANGE_LIBRARY)}")
except Exception as e:
    print("[FAIL]", e)

print("\n=== 前端文件大小 ===")
hp = os.path.join(ROOT, "api_server", "security_training_console.html")
sz = os.path.getsize(hp)
print(f"security_training_console.html: {sz} bytes ({sz/1024:.1f} KB)")

print("\nRESULT:", "ALL_OK" if ok_all else "HAS_FAIL")
