# -*- coding: utf-8 -*-
"""第26轮方向1 冒烟测试"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security_llm import (
    llm_manager, agent_engine, code_generator,
    qa_system, smart_report, llm_dashboard,
)

print("=== 1. 模型切换 ===")
print(" ", llm_manager.switch_model("sec-llm-13b"))
print(" ", llm_manager.switch_model("sec-llm-7b"))

print("=== 2. RAG检索 ===")
for d in llm_manager.kb_search("SQL注入", top_k=2):
    print(f"  [{d['category']}] {d['title']} (score={d['score']})")

print("=== 3. 对话推理 ===")
r = llm_manager.chat("什么是XSS？如何防御？")
print(f"  model={r['model']}, tokens={r['tokens_used']}, refs={len(r['references'])}")
print(f"  answer[:80]: {r['answer'][:80]}...")

print("=== 4. Agent任务执行 ===")
t = agent_engine.execute_task("扫描目标漏洞", "demo.example.com")
print(f"  task_id={t['id']}, steps={t['total_steps']}")
for s in t["steps"]:
    print(f"    step{s['step']}: {s['tool']} done")

print("=== 5. 代码生成 ===")
c = code_generator.generate("用户登录接口", "python")
print(f"  lines={c['lines']}, lang={c['language']}")

print("=== 6. 代码审查 ===")
bad_code = 'cursor.execute(f"SELECT * FROM t WHERE n=\'{x}\'")\neval(user_input)\npassword = "admin123"'
rv = code_generator.review(bad_code, "python")
print(f"  findings={rv['total']}, risk={rv['risk_level']}, score={rv['score']}")
for f in rv["findings"]:
    print(f"    - {f['rule']} (line {f['line']})")

print("=== 7. 问答系统 ===")
sess = qa_system.create_session()
a = qa_system.ask(sess["id"], "等保三级需要做什么？")
print(f"  confidence={a['confidence']}, refs={len(a['references'])}")

print("=== 8. 报告生成 ===")
rpt = smart_report.generate("测试报告", "demo.com")
print(f"  report_id={rpt['id']}, pages={rpt['pages']}, findings={len(rpt['findings'])}")

print("=== 9. 仪表盘聚合 ===")
ov = llm_dashboard.overview()
print(f"  models={ov['kpi']['models_loaded']}, agents={ov['kpi']['agents_registered']}")

print("\nSMOKE_TEST_OK")
