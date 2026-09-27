# -*- coding: utf-8 -*-
"""第23轮方向1 ai_intelligence 验证脚本"""
import os, sys, importlib, py_compile, re

ROOT = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent"
sys.path.insert(0, ROOT)

files = [
    "ai_intelligence/__init__.py",
    "ai_intelligence/nl_assistant.py",
    "ai_intelligence/scan_decision.py",
    "ai_intelligence/poc_generator.py",
    "ai_intelligence/smart_report.py",
    "ai_intelligence/ai_knowledge_base.py",
    "ai_intelligence/ai_dashboard.py",
    "api_server/ai_intelligence_routes.py",
]

print("=== 1. 语法编译检查 ===")
ok = True
for f in files:
    p = os.path.join(ROOT, f)
    try:
        py_compile.compile(p, doraise=True)
        lines = sum(1 for _ in open(p, "r", encoding="utf-8"))
        print(f"  [OK] {f}  ({lines} 行)")
    except Exception as e:
        ok = False
        print(f"  [FAIL] {f}: {e}")

print("\n=== 2. 独立 import 检查 ===")
mods = [
    "ai_intelligence.nl_assistant",
    "ai_intelligence.scan_decision",
    "ai_intelligence.poc_generator",
    "ai_intelligence.smart_report",
    "ai_intelligence.ai_knowledge_base",
    "ai_intelligence.ai_dashboard",
]
for m in mods:
    try:
        importlib.import_module(m)
        print(f"  [OK] import {m}")
    except Exception as e:
        ok = False
        print(f"  [FAIL] import {m}: {e}")

print("\n=== 3. 包整体 import ===")
try:
    pkg = importlib.import_module("ai_intelligence")
    print(f"  [OK] ai_intelligence v{pkg.__version__}, 导出 {len(pkg.__all__)} 个符号")
except Exception as e:
    ok = False
    print(f"  [FAIL] ai_intelligence: {e}")

print("\n=== 4. 路由端点统计 ===")
rp = os.path.join(ROOT, "api_server", "ai_intelligence_routes.py")
src = open(rp, "r", encoding="utf-8").read()
endpoints = re.findall(r'@router\.(get|post|put|delete)\("([^"]+)"', src)
print(f"  端点数: {len(endpoints)}")
methods = {}
for m, p in endpoints:
    methods.setdefault(m, 0)
    methods[m] += 1
print(f"  方法分布: {methods}")

print("\n=== 5. 功能冒烟测试 ===")
try:
    from ai_intelligence.nl_assistant import nl_assistant
    r = nl_assistant.chat("扫描 192.168.1.1 的 80 端口")
    print(f"  [OK] chat intent={r['intent']['intent']} target={r['params'].get('target')}")
    r2 = nl_assistant.recognize_intent("验证 CVE-2021-44228")
    print(f"  [OK] recognize_intent={r2['intent']} conf={r2['confidence']}")
    p = nl_assistant.extract_params("扫描 example.com 端口 443 深度 3")
    print(f"  [OK] extract_params={p}")
except Exception as e:
    ok = False
    print(f"  [FAIL] assistant smoke: {e}")

try:
    from ai_intelligence.scan_decision import scan_decision_engine
    s = scan_decision_engine.generate_strategy("10.0.0.5")
    print(f"  [OK] strategy {s['strategy_id']} est={s['estimated_total_min']}min")
    a = scan_decision_engine.analyze_results([
        {"host":"a","port":80,"plugin":"x","severity":"high"},
        {"host":"a","port":80,"plugin":"x","severity":"high"},
        {"host":"b","port":22,"plugin":"y","severity":"critical"}])
    print(f"  [OK] analyze raw={a['total_raw']} dedup={a['after_dedup']} sev={a['by_severity']}")
except Exception as e:
    ok = False
    print(f"  [FAIL] scan smoke: {e}")

try:
    from ai_intelligence.poc_generator import poc_generator
    poc = poc_generator.generate_poc("CVE-2021-44228")
    print(f"  [OK] poc {poc['poc_id']} lines={poc['code'].count(chr(10))}")
    rep = poc_generator.verify_poc(poc["poc_id"])
    print(f"  [OK] verify verdict={rep['verdict']}")
except Exception as e:
    ok = False
    print(f"  [FAIL] poc smoke: {e}")

try:
    from ai_intelligence.smart_report import smart_report
    rep = smart_report.generate(
        [{"name":"Log4Shell","severity":"critical","type":"rce","service":"http"}],
        "https://x.com", "technical", "markdown")
    print(f"  [OK] report {rep['report_id']} fmt={rep['format']} size={rep['size_bytes']}B grade={rep['quality']['grade']}")
except Exception as e:
    ok = False
    print(f"  [FAIL] report smoke: {e}")

try:
    from ai_intelligence.ai_knowledge_base import ai_knowledge_base
    ask = ai_knowledge_base.ask("log4j 怎么检测")
    print(f"  [OK] kb ask hits={len(ask['citations'])} answer_len={len(ask['answer'])}")
    rel = ai_knowledge_base.related("KB-V-CVE-2021-44228")
    print(f"  [OK] kb related nodes={len(rel['nodes'])}")
except Exception as e:
    ok = False
    print(f"  [FAIL] kb smoke: {e}")

try:
    from ai_intelligence.ai_dashboard import ai_dashboard
    ov = ai_dashboard.overview()
    print(f"  [OK] overview calls={ov['total_calls']} success_rate={ov['success_rate']} active={ov['active_model']}")
except Exception as e:
    ok = False
    print(f"  [FAIL] dashboard smoke: {e}")

print("\n=== 6. HTML 文件大小 ===")
hp = os.path.join(ROOT, "api_server", "ai_intelligence_console.html")
sz = os.path.getsize(hp)
print(f"  console.html: {sz} bytes ({sz/1024:.1f} KB)  {'OK >15KB' if sz>15360 else 'FAIL'}")

print("\n=== 最终结果 ===")
print("  " + ("全部通过 ✅" if ok else "存在失败项 ❌"))
sys.exit(0 if ok else 1)
