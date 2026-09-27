# -*- coding: utf-8 -*-
"""冒烟测试：第27轮方向1 安全知识图谱与智能推理。"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "api_server"))

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name} {detail}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


print("=" * 60)
print("1. 模块独立 import")
print("=" * 60)
import security_kg
check("package __init__", security_kg.__version__ == "27.1.0")

from security_kg import kg_builder, attack_path, vuln_correlation, \
    threat_propagation, reasoning_engine, kg_qa, kg_dashboard
check("kg_builder", hasattr(kg_builder, "kg_builder"))
check("attack_path", hasattr(attack_path, "attack_path_engine"))
check("vuln_correlation", hasattr(vuln_correlation, "vuln_correlation"))
check("threat_propagation", hasattr(threat_propagation, "threat_propagation"))
check("reasoning_engine", hasattr(reasoning_engine, "reasoning_engine"))
check("kg_qa", hasattr(kg_qa, "kg_qa"))
check("kg_dashboard", hasattr(kg_dashboard, "kg_dashboard"))

import security_kg_routes
check("routes import", hasattr(security_kg_routes, "router"))
n_routes = len(security_kg_routes.router.routes)
check("API 端点数 >=50", n_routes >= 50, f"(实际 {n_routes})")

print()
print("=" * 60)
print("2. 真实功能：知识图谱构建")
print("=" * 60)
kg = kg_builder.kg_builder
stats = kg.stats()
check("种子节点数 >=10", stats["nodes"] >= 10, f"(nodes={stats['nodes']})")
check("种子边数 >=10", stats["edges"] >= 10, f"(edges={stats['edges']})")

# 新增实体
n = kg.add_entity("ioc", "测试IOC-8.8.8.8", {"kind": "dns"})
check("新增实体", n["name"] == "测试IOC-8.8.8.8")
# 新增关系
web = [x for x in kg.nodes.values() if x["type"] == "asset" and "Web" in x["name"]][0]
e = kg.add_relation(n["id"], web["id"], "threat_targets_asset")
check("新增关系", e["relation"] == "threat_targets_asset")
# 实体对齐
al = kg.entity_align(n["id"], n["id"])
check("实体对齐", al["score"] == 1.0)
# 知识补全
cmp = kg.knowledge_completion()
check("知识补全", "inferred_relations_added" in cmp)
# 知识验证
val = kg.knowledge_validate()
check("知识验证", "passed" in val)
# 质量
q = kg.quality_report()
check("质量报告", "score" in q and "grade" in q)

print()
print("=" * 60)
print("3. 真实功能：攻击路径推理")
print("=" * 60)
ape = attack_path.attack_path_engine
nodes = list(kg.nodes.values())
src = nodes[0]["id"]
dst = [x for x in nodes if x["type"] == "asset"][-1]["id"]
sp = ape.shortest_path(src, dst)
check("Dijkstra 最短路径", sp.get("found", False),
      f"(len={sp.get('length')})")
ap = ape.astar_path(src, dst)
check("A* 搜索", ap.get("found", False),
      f"(explored={ap.get('explored')})")
allp = ape.all_paths(src, dst, max_depth=5)
check("枚举所有路径", "count" in allp, f"(count={allp.get('count')})")
pp = ape.probabilistic_path(src, dst)
check("概率路径", pp.get("found", False),
      f"(P={pp.get('probability')})")
rp = ape.risk_path(src, dst)
check("风险路径", rp.get("found", False),
      f"(risk={rp.get('risk_score')})")
if sp.get("path"):
    an = ape.analyze_path(sp["path"])
    check("路径分析", an.get("valid", False))
    kc = ape.map_kill_chain(sp["path"])
    check("杀伤链映射", "kill_chain_stages" in kc)
    vp = ape.validate_path(sp["path"])
    check("路径验证", vp.get("reachable", False))
pn = ape.predict_next(src, top_k=3)
check("下一步预测", "predictions" in pn)

print()
print("=" * 60)
print("4. 真实功能：漏洞关联")
print("=" * 60)
vc = vuln_correlation.vuln_correlation
pri = vc.prioritize()
check("漏洞优先级排序", len(pri) >= 3, f"(count={len(pri)})")
top = pri[0]
check("Top1 是高危", top["cvss"] >= 9.0, f"(top={top['id']} score={top['priority_score']})")
cor = vc.correlate("CVE-2021-44228")
check("漏洞关联", "combo_exploitability" in cor)
pg = vc.propagation("CVE-2021-44228")
check("漏洞传播", "spread_probability" in pg)
im = vc.impact("CVE-2021-44228")
check("漏洞影响", "cascade" in im)
tr = vc.trend()
check("漏洞趋势", "series_14d" in tr)
kb = vc.knowledge_base("CVE-2021-44228")
check("漏洞知识库", "poc" in kb)

print()
print("=" * 60)
print("5. 真实功能：威胁传播 SIR/SEIR")
print("=" * 60)
tp = threat_propagation.threat_propagation
sir = tp.sir(beta=0.6, gamma=0.1, total=50, days=60)
check("SIR 模型", sir["peak_infected"] > 0,
      f"(peak={sir['peak_infected']}, final={sir['final_infected_ratio']})")
check("SIR 序列长度>10", len(sir["series"]) > 10)
seir = tp.seir(beta=0.6, total=50, days=60)
check("SEIR 模型", "E" in seir["series"][0])
bl = tp.blocking_strategies("Web")
check("阻断策略", len(bl["strategies"]) >= 3)
mc = tp.monte_carlo(runs=20, total=30)
check("蒙特卡洛", mc["runs"] == 20, f"(peak_p50={mc['peak_p50']})")
sn = tp.sensitivity()
check("参数敏感性", "beta_sensitivity" in sn)

print()
print("=" * 60)
print("6. 真实功能：知识推理引擎")
print("=" * 60)
re_ = reasoning_engine.reasoning_engine
fc = re_.forward_chain()
check("前向链推理", fc["facts_derived"] >= 3,
      f"(facts={fc['facts_derived']}, rules={fc['rules_applied']})")
bc = re_.backward_chain("Web")
check("后向链推理", "matched_facts" in bc)
mh = re_.multi_hop(src, hops=2)
check("多跳推理", "discovered" in mh)
unc = re_.uncertain_reasoning()
check("不确定性推理", "avg_confidence" in unc)
val = re_.validate()
check("推理验证", "consistency" in val)
pr = re_.predict_attack()
check("攻击预测", "prediction" in pr)
rc = re_.recommendations()
check("建议生成", "recommendations" in rc)

print()
print("=" * 60)
print("7. 真实功能：智能问答")
print("=" * 60)
qas = kg_qa.kg_qa
a1 = qas.ask("什么是 Log4j？")
check("FAQ 问答", a1["source"] == "faq", f"(conf={a1['confidence']})")
a2 = qas.ask("CVE-2021-44228")
check("图谱问答", a2["source"] in ("graph", "reasoning"),
      f"(source={a2['source']})")
s = qas.statistics()
check("问答统计", s["questions"] >= 2)
fr = qas.feedback(a1["id"], 5, "有用")
check("问答反馈", fr["ok"])

print()
print("=" * 60)
print("8. 真实功能：仪表盘聚合")
print("=" * 60)
kd = kg_dashboard.kg_dashboard
ov = kd.overview()
check("总览聚合", "graph" in ov and "vulns" in ov and "reasoning" in ov)
gs = kd.graph_section()
check("图谱段", "stats" in gs)
aps = kd.attack_path_section()
check("攻击路径段", "shortest" in aps)
vs = kd.vuln_section()
check("漏洞段", "prioritized" in vs)
ps = kd.propagation_section()
check("传播段", "sir" in ps)
rs = kd.reasoning_section()
check("推理段", "rules" in rs)
qs = kd.qa_section()
check("问答段", "faq" in qs)
st = kd.settings()
check("系统设置", "graph_name" in st)

print()
print("=" * 60)
print("9. 文件大小检查")
print("=" * 60)
html_size = os.path.getsize(
    os.path.join(ROOT, "api_server", "security_kg_console.html"))
check("HTML > 15KB", html_size > 15 * 1024, f"({html_size} bytes)")

print()
print("=" * 60)
print(f"结果: PASS={PASS}  FAIL={FAIL}")
print("=" * 60)
sys.exit(0 if FAIL == 0 else 1)
