# -*- coding: utf-8 -*-
"""
test_visualization_v7.py —— 第7轮数据可视化增强模块测试脚本

测试覆盖：
    1. AttackPathGenerator：generate / to_json / to_mermaid / to_graphviz / compare_paths / get_path_details
    2. NetworkTopologyGenerator：generate / to_json / to_mermaid / to_graphviz / filter_by_type / filter_by_risk / get_stats
    3. RiskHeatmapGenerator：generate(4维度) / to_json / to_html / to_csv / get_cell_details / get_summary
    4. TrendAnalyzer：analyze_vulnerability_trend / analyze_risk_trend / analyze_scan_trend / to_echarts_config / get_all_trends
    5. API 路由：router 导入与路由数检查
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from visualization.attack_path import AttackPathGenerator
from visualization.network_topology import NetworkTopologyGenerator
from visualization.risk_heatmap import RiskHeatmapGenerator
from visualization.trend_analysis import TrendAnalyzer


# ==================== 测试用例 ====================

PASSED = 0
FAILED = 0


def check(name: str, condition: bool, detail: str = ""):
    """断言辅助。"""
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  [PASS] {name}")
    else:
        FAILED += 1
        print(f"  [FAIL] {name}  {detail}")


# ==================== 1. 攻击路径 ====================

print("=" * 60)
print("测试1: AttackPathGenerator 攻击路径可视化")
print("=" * 60)

apg = AttackPathGenerator()
scan_data = {
    "target": "test.com",
    "ip": "1.2.3.4",
    "open_ports": [
        {"port": 80, "service": "http", "version": "Apache 2.4.49"},
        {"port": 22, "service": "ssh", "version": "OpenSSH 8.0"},
    ],
    "vulnerabilities": [
        {"id": "CVE-2021-41773", "name": "路径穿越", "severity": "高", "type": "路径穿越", "port": 80},
        {"id": "CVE-2019-0001", "name": "弱口令", "severity": "中", "type": "认证", "port": 22},
    ],
    "services": {},
}
result = apg.generate(scan_data)

check("graph 存在 nodes", "nodes" in result.get("graph", {}))
check("graph 存在 edges", "edges" in result.get("graph", {}))
check("节点数 >= 5", len(result["graph"]["nodes"]) >= 5,
      f"实际: {len(result['graph']['nodes'])}")
check("边数 >= 5", len(result["graph"]["edges"]) >= 5)
check("路径数 >= 3", len(result["paths"]) >= 3,
      f"实际: {len(result['paths'])}")
check("summary.total_paths", result["summary"]["total_paths"] >= 3)
check("summary.entry_points", result["summary"]["entry_points"] >= 1)

# 检查节点类型
node_types = {n["node_type"] for n in result["graph"]["nodes"]}
check("包含 attacker 节点", "attacker" in node_types)
check("包含 host 节点", "host" in node_types)
check("包含 vulnerability 节点", "vulnerability" in node_types)
check("包含 sensitive_data 节点", "sensitive_data" in node_types)

# 检查路径类型
path_types = {p["type"] for p in result["paths"]}
check("包含 shortest 路径", "shortest" in path_types)
check("包含 highest_risk 路径", "highest_risk" in path_types)
check("包含 most_likely 路径", "most_likely" in path_types)

# to_json
j = apg.to_json(result)
check("to_json 返回字符串", isinstance(j, str))
check("to_json 可解析", isinstance(json.loads(j), dict))

# to_mermaid
m = apg.to_mermaid(result)
check("to_mermaid 以 graph TD 开头", m.startswith("graph TD"))
check("to_mermaid 含 classDef", "classDef" in m)
check("to_mermaid 含节点定义", "n_attacker_1" in m or "attacker" in m)

# to_graphviz
gv = apg.to_graphviz(result)
check("to_graphviz 以 digraph 开头", gv.strip().startswith("digraph"))
check("to_graphviz 含 }", gv.strip().endswith("}"))

# compare_paths
cmp = apg.compare_paths(result["paths"])
check("compare_paths 含 paths", "paths" in cmp)
check("compare_paths 含 summary", "summary" in cmp)

# get_path_details
if result["paths"]:
    pid = result["paths"][0]["path_id"]
    detail = apg.get_path_details(pid)
    check("get_path_details 返回路径", detail.get("path_id") == pid)
detail2 = apg.get_path_details("nonexistent")
check("get_path_details 不存在返回 found=False", detail2.get("found") == False)

print()

# ==================== 2. 网络拓扑 ====================

print("=" * 60)
print("测试2: NetworkTopologyGenerator 网络拓扑可视化")
print("=" * 60)

ntg = NetworkTopologyGenerator()
topo_data = {
    "targets": [
        {"ip": "192.168.1.1", "hostname": "gw", "os": "Linux",
         "open_ports": [{"port": 80, "service": "http"}],
         "risk_level": "中", "subnet": "192.168.1.0/24"},
        {"ip": "192.168.1.10", "hostname": "srv1", "os": "Windows",
         "open_ports": [{"port": 445, "service": "smb"}, {"port": 3389, "service": "rdp"}],
         "risk_level": "高", "subnet": "192.168.1.0/24"},
        {"ip": "192.168.1.20", "hostname": "pc1", "os": "Windows 10",
         "open_ports": [{"port": 135, "service": "msrpc"}],
         "risk_level": "低", "subnet": "192.168.1.0/24"},
    ],
    "subnets": ["192.168.1.0/24"],
    "gateway": "192.168.1.1",
}
topo_result = ntg.generate(topo_data)

check("拓扑节点数 >= 3", len(topo_result["graph"]["nodes"]) >= 3,
      f"实际: {len(topo_result['graph']['nodes'])}")
check("拓扑边数 >= 1", len(topo_result["graph"]["edges"]) >= 1)
check("含 subnet 分组", "192.168.1.0/24" in topo_result.get("subnets", {}))

# 节点属性
for n in topo_result["graph"]["nodes"]:
    check("节点含 id", "id" in n)
    check("节点含 ip", "ip" in n)
    check("节点含 node_type", "node_type" in n)
    check("节点含 risk_level", "risk_level" in n)
    break

# to_json
tj = ntg.to_json(topo_result)
check("拓扑 to_json 可解析", isinstance(json.loads(tj), dict))

# to_mermaid
tm = ntg.to_mermaid(topo_result)
check("拓扑 to_mermaid 以 graph LR 开头", tm.startswith("graph LR"))
check("拓扑 to_mermaid 含 subgraph", "subgraph" in tm)
check("拓扑 to_mermaid 含 risk 样式", "risk_" in tm)

# to_graphviz
tg = ntg.to_graphviz(topo_result)
check("拓扑 to_graphviz 以 digraph 开头", tg.strip().startswith("digraph"))

# filter_by_type
fst = ntg.filter_by_type("server")
check("filter_by_type 返回 dict", isinstance(fst, dict))
check("filter_by_type 含 nodes", "nodes" in fst)

# filter_by_risk
frr = ntg.filter_by_risk("高")
check("filter_by_risk 返回 dict", isinstance(frr, dict))
check("filter_by_risk 节点数 >= 0", frr.get("count", 0) >= 0)

# get_stats
stats = ntg.get_stats()
check("get_stats 含 total_nodes", "total_nodes" in stats)
check("get_stats 含 by_type", "by_type" in stats)
check("get_stats 含 by_risk", "by_risk" in stats)

print()

# ==================== 3. 风险热力图 ====================

print("=" * 60)
print("测试3: RiskHeatmapGenerator 风险热力图")
print("=" * 60)

rhg = RiskHeatmapGenerator()
heat_data = {
    "targets": [
        {"ip": "1.1.1.1", "vulnerabilities": [
            {"port": 80, "severity": "高", "type": "SQL注入"},
            {"port": 443, "severity": "中", "type": "XSS"},
        ]},
        {"ip": "2.2.2.2", "vulnerabilities": [
            {"port": 22, "severity": "低", "type": "信息泄露"},
        ]},
    ]
}

# host_port 维度
h1 = rhg.generate(heat_data, "host_port")
check("host_port 矩阵行数 = 2", len(h1["matrix"]) == 2)
check("host_port 含 rows", len(h1["rows"]) == 2)
check("host_port 含 cols", len(h1["cols"]) >= 2)

# 单元格结构
cell = h1["matrix"][0][0]
check("单元格含 value", "value" in cell)
check("单元格含 risk_level", "risk_level" in cell)
check("单元格含 color", "color" in cell)
check("单元格含 vulnerabilities", "vulnerabilities" in cell)

# to_html
html_out = rhg.to_html(h1)
check("to_html 含 <table", "<table" in html_out)
check("to_html 含内联样式", "style=" in html_out)

# to_csv
csv_out = rhg.to_csv(h1)
check("to_csv 含表头", "row" in csv_out)

# to_json
j_out = rhg.to_json(h1)
check("to_json 可解析", isinstance(json.loads(j_out), dict))

# get_cell_details
cd = rhg.get_cell_details("1.1.1.1", "80")
check("get_cell_details 找到单元格", cd.get("found", True) is not False or "value" in cd)

# get_summary
summ = rhg.get_summary()
check("get_summary 含 avg_risk", "avg_risk" in summ)
check("get_summary 含 max_cell", "max_cell" in summ)

# vuln_type 维度
h2 = rhg.generate(heat_data, "vuln_type")
check("vuln_type 矩阵非空", len(h2["matrix"]) >= 1)

# service_vuln 维度
h3 = rhg.generate(heat_data, "service_vuln")
check("service_vuln 矩阵非空", len(h3["matrix"]) >= 1)

# time_risk 维度
time_data = {"history": [
    {"date": "2024-01", "low_count": 5, "medium_count": 10, "high_count": 3, "critical_count": 1},
    {"date": "2024-02", "low_count": 3, "medium_count": 8, "high_count": 5, "critical_count": 2},
]}
h4 = rhg.generate(time_data, "time_risk")
check("time_risk 矩阵行数 = 2", len(h4["matrix"]) == 2)

print()

# ==================== 4. 趋势分析 ====================

print("=" * 60)
print("测试4: TrendAnalyzer 趋势分析")
print("=" * 60)

ta = TrendAnalyzer()
hist = [
    {"date": "2024-01", "new_vulns": 10, "fixed_vulns": 5, "unfixed_vulns": 20,
     "total_vulns": 25, "avg_risk": 55, "max_risk": 85,
     "critical_count": 2, "high_count": 8, "medium_count": 12, "low_count": 5,
     "scan_count": 3, "vulns_found": 10, "fix_rate": 50.0, "avg_duration": 120.0},
    {"date": "2024-02", "new_vulns": 8, "fixed_vulns": 12, "unfixed_vulns": 16,
     "total_vulns": 21, "avg_risk": 48, "max_risk": 78,
     "critical_count": 1, "high_count": 6, "medium_count": 10, "low_count": 8,
     "scan_count": 4, "vulns_found": 8, "fix_rate": 60.0, "avg_duration": 110.0},
]

# 漏洞趋势
vt = ta.analyze_vulnerability_trend(hist)
check("漏洞趋势含 dates", len(vt["dates"]) == 2)
check("漏洞趋势含 new_vulns", len(vt["new_vulns"]) == 2)
check("漏洞趋势含 fixed_vulns", len(vt["fixed_vulns"]) == 2)
check("漏洞趋势含 total_vulns", len(vt["total_vulns"]) == 2)

# 风险趋势
rt = ta.analyze_risk_trend(hist)
check("风险趋势含 avg_risk", len(rt["avg_risk"]) == 2)
check("风险趋势含 max_risk", len(rt["max_risk"]) == 2)

# 扫描趋势
st = ta.analyze_scan_trend(hist)
check("扫描趋势含 scan_count", len(st["scan_count"]) == 2)
check("扫描趋势含 fix_rate", len(st["fix_rate"]) == 2)

# ECharts - line
ec_line = ta.to_echarts_config(vt, "line")
check("ECharts line 含 title", "title" in ec_line)
check("ECharts line 含 tooltip", "tooltip" in ec_line)
check("ECharts line 含 legend", "legend" in ec_line)
check("ECharts line 含 xAxis", "xAxis" in ec_line)
check("ECharts line 含 yAxis", "yAxis" in ec_line)
check("ECharts line 含 series", "series" in ec_line)
check("ECharts line series >= 1", len(ec_line["series"]) >= 1)

# ECharts - bar
ec_bar = ta.to_echarts_config(vt, "bar")
check("ECharts bar series type=bar",
      ec_bar["series"][0]["type"] == "bar")

# ECharts - pie
ec_pie = ta.to_echarts_config(vt, "pie")
check("ECharts pie series type=pie",
      ec_pie["series"][0]["type"] == "pie")

# ECharts - area
ec_area = ta.to_echarts_config(vt, "area")
check("ECharts area 含 areaStyle",
      "areaStyle" in ec_area["series"][0])

# get_all_trends
all_tr = ta.get_all_trends(hist)
check("get_all_trends 含 vulnerability", "vulnerability" in all_tr)
check("get_all_trends 含 risk", "risk" in all_tr)
check("get_all_trends 含 scan", "scan" in all_tr)

print()

# ==================== 5. API 路由 ====================

print("=" * 60)
print("测试5: API 路由检查")
print("=" * 60)

from api_server.visualization_routes import router
check("路由数 >= 5", len(router.routes) >= 5,
      f"实际: {len(router.routes)}")
print(f"  路由数: {len(router.routes)}")

# 检查路由路径
routes_paths = [r.path for r in router.routes]
check("含 /attack-path", any("attack-path" in p for p in routes_paths))
check("含 /network-topology", any("network-topology" in p for p in routes_paths))
check("含 /risk-heatmap", any("risk-heatmap" in p for p in routes_paths))
check("含 /trend", any("trend" in p for p in routes_paths))
check("含 /formats", any("formats" in p for p in routes_paths))

print()

# ==================== 汇总 ====================

print("=" * 60)
print(f"测试完成: 通过 {PASSED} 项, 失败 {FAILED} 项")
print("=" * 60)

sys.exit(0 if FAILED == 0 else 1)
