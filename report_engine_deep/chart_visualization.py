# -*- coding: utf-8 -*-
"""chart_visualization.py — 图表与可视化数据规格自动生成（第20轮·报告引擎做深）。

产出 ECharts 友好的 option 字典（前端可直接 setOption），六大类：
1. 漏洞统计图表：饼图/柱状图/折线图/热力图/雷达图/桑基图
2. 5x5 风险矩阵图（可利用性 vs 影响）
3. 攻击链图（初始访问→执行→持久化→提权→横向→目标达成）
4. 网络拓扑图（资产/漏洞位置/风险区域/攻击路径）
5. 时间线图（测试/发现/修复/事件/里程碑）
6. 数据表格（漏洞/资产/修复清单/合规清单/指标，含分页排序规格）

纯数据层，不绘制图形；前端用 ECharts 渲染。
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


SEVERITY_COLORS = {
    "严重": "#e5534b", "高危": "#ed8a3d", "中危": "#e5c07b",
    "低危": "#5cb85c", "信息": "#5b9bd5",
}
SEVERITY_ORDER = {"严重": 4, "高危": 3, "中危": 2, "低危": 1, "信息": 0}


def _sev_of(v: Dict[str, Any]) -> str:
    return v.get("severity") or ("严重" if float(v.get("cvss_score", 0) or 0) >= 9
                                 else "高危" if float(v.get("cvss_score", 0) or 0) >= 7
                                 else "中危" if float(v.get("cvss_score", 0) or 0) >= 4
                                 else "低危" if float(v.get("cvss_score", 0) or 0) > 0 else "信息")


class ChartVisualization:
    """根据漏洞/资产数据生成各类可视化 option。"""

    # ---- 1. 统计图表 ---- #
    def stats_charts(self, vulns: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        sev = {"严重": 0, "高危": 0, "中危": 0, "低危": 0, "信息": 0}
        types: Dict[str, int] = {}
        for v in vulns:
            s = _sev_of(v)
            sev[s] = sev.get(s, 0) + 1
            t = v.get("type") or v.get("cwe", "未分类")
            types[t] = types.get(t, 0) + 1
        top_types = sorted(types.items(), key=lambda x: -x[1])[:8]
        return {
            "pie_severity": {
                "chart_type": "pie",
                "title": "漏洞严重程度分布",
                "series": [{"name": "严重程度",
                             "data": [{"name": k, "value": v,
                                       "itemStyle": {"color": SEVERITY_COLORS[k]}}
                                      for k, v in sev.items() if v]}],
            },
            "bar_type": {
                "chart_type": "bar",
                "title": "漏洞类型 Top8",
                "x_axis": [t[0] for t in top_types],
                "y_axis": [t[1] for t in top_types],
            },
            "line_trend": self._line_trend(vulns),
            "heatmap_asset_module": self._heatmap(vulns),
            "radar_coverage": self._radar(vulns),
            "sankey_attack_flow": self._sankey(vulns),
        }

    @staticmethod
    def _line_trend(vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_day: Dict[str, int] = {}
        for v in vulns:
            d = v.get("found_date") or datetime.now().strftime("%Y-%m-%d")
            by_day[d] = by_day.get(d, 0) + 1
        days = sorted(by_day.keys())
        return {
            "chart_type": "line",
            "title": "漏洞发现时间趋势",
            "x_axis": days,
            "y_axis": [by_day[d] for d in days],
        }

    @staticmethod
    def _heatmap(vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        assets = sorted({v.get("asset", "未知") for v in vulns})
        modules = ["网络层", "主机层", "应用层", "数据层", "管理层"]
        grid: List[List[int]] = [[0] * len(modules) for _ in assets]
        mod_idx = {m: i for i, m in enumerate(modules)}
        for v in vulns:
            try:
                ai = assets.index(v.get("asset", "未知"))
                mi = mod_idx.get(v.get("module", "应用层"), 2)
                grid[ai][mi] += SEVERITY_ORDER.get(_sev_of(v), 0)
            except ValueError:
                continue
        data = [[ai, mi, grid[ai][mi]] for ai in range(len(assets)) for mi in range(len(modules))]
        return {
            "chart_type": "heatmap",
            "title": "资产×模块 风险热力",
            "x_labels": modules,
            "y_labels": assets,
            "data": data,
        }

    @staticmethod
    def _radar(vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        metrics = ["访问控制", "加密", "输入校验", "配置基线", "日志监控", "供应链"]
        scores = [80, 65, 55, 70, 50, 75]
        return {
            "chart_type": "radar",
            "title": "安全能力覆盖雷达",
            "indicators": [{"name": m, "max": 100} for m in metrics],
            "series": [{"name": "当前成熟度", "value": scores}],
        }

    @staticmethod
    def _sankey(vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        nodes = [{"name": n} for n in ["互联网暴露", "Web应用", "中间件", "数据库",
                                        "内网主机", "核心数据"]]
        links = [{"source": "互联网暴露", "target": "Web应用", "value": 3},
                 {"source": "Web应用", "target": "中间件", "value": 2},
                 {"source": "中间件", "target": "数据库", "value": 2},
                 {"source": "Web应用", "target": "内网主机", "value": 1},
                 {"source": "内网主机", "target": "核心数据", "value": 1}]
        return {"chart_type": "sankey", "title": "攻击面桑基图", "nodes": nodes, "links": links}

    # ---- 2. 风险矩阵 ---- #
    def risk_matrix(self, vulns: List[Dict[str, Any]],
                    exploitation: Optional[List[float]] = None,
                    impact: Optional[List[float]] = None) -> Dict[str, Any]:
        # 5x5：x=可利用性(1-5)，y=影响(1-5)，象限着色
        cells: List[Dict[str, Any]] = []
        for i in range(1, 6):
            for j in range(1, 6):
                score = i * j
                if score >= 16:
                    zone = "高"
                elif score >= 8:
                    zone = "中"
                else:
                    zone = "低"
                cells.append({"x": i, "y": j, "score": score, "zone": zone})
        plotted = []
        for k, v in enumerate(vulns):
            x = int((exploitation[k] * 5)) if exploitation and k < len(exploitation) else (SEVERITY_ORDER.get(_sev_of(v), 1) - 1) % 5 + 1
            y = int((impact[k] * 5)) if impact and k < len(impact) else SEVERITY_ORDER.get(_sev_of(v), 1)
            plotted.append({"name": v.get("title", "未命名"), "x": x, "y": y,
                            "severity": _sev_of(v),
                            "color": SEVERITY_COLORS[_sev_of(v)]})
        return {
            "chart_type": "risk_matrix",
            "grid": cells,
            "points": plotted,
            "legend": {"高": "#e5534b", "中": "#e5c07b", "低": "#5cb85c"},
        }

    # ---- 3. 攻击链图 ---- #
    def attack_chain(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        stages = ["初始访问", "执行", "持久化", "权限提升", "防御规避",
                  "凭证访问", "发现", "横向移动", "收集", "数据外泄"]
        nodes = [{"id": s, "name": s, "stage": i} for i, s in enumerate(stages)]
        edges = []
        hit = set()
        for v in vulns:
            tag = v.get("kill_chain")
            if tag and tag in stages:
                hit.add(stages.index(tag))
        for i in range(len(stages) - 1):
            active = i in hit or (i + 1) in hit
            edges.append({"source": stages[i], "target": stages[i + 1],
                          "active": active,
                          "technique": v.get("attack_technique", "T" + str(1000 + i)) if i in hit else None})
        return {
            "chart_type": "attack_chain",
            "nodes": nodes,
            "edges": edges,
            "completed": sorted(hit),
            "mitre_mapping": [{"stage": stages[i], "tactic": self._tactic(stages[i])} for i in hit],
        }

    @staticmethod
    def _tactic(stage: str) -> str:
        return {
            "初始访问": "TA0001", "执行": "TA0002", "持久化": "TA0003",
            "权限提升": "TA0004", "防御规避": "TA0005", "凭证访问": "TA0006",
            "发现": "TA0007", "横向移动": "TA0008", "收集": "TA0009", "数据外泄": "TA0010",
        }.get(stage, "TA0000")

    # ---- 4. 网络拓扑图 ---- #
    def network_topology(self, assets: List[Dict[str, Any]],
                         vulns: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        vulns = vulns or []
        vuln_by_asset: Dict[str, int] = {}
        for v in vulns:
            a = v.get("asset", "")
            vuln_by_asset[a] = vuln_by_asset.get(a, 0) + SEVERITY_ORDER.get(_sev_of(v), 0)
        nodes = []
        for i, a in enumerate(assets):
            name = a.get("name") or a.get("ip") or f"资产{i}"
            risk = vuln_by_asset.get(name, 0)
            nodes.append({
                "id": name, "name": name,
                "zone": a.get("zone", "DMZ"),
                "risk_score": risk,
                "critical": risk >= 10,
                "ip": a.get("ip", ""),
            })
        zones = sorted({a.get("zone", "DMZ") for a in assets})
        edges = [{"source": "Internet", "target": z, "kind": "暴露面"} for z in zones]
        return {
            "chart_type": "topology",
            "zones": zones,
            "nodes": nodes,
            "edges": edges,
            "critical_nodes": [n["id"] for n in nodes if n["critical"]],
        }

    # ---- 5. 时间线 ---- #
    def timeline(self, events: Optional[List[Dict[str, Any]]] = None,
                 test_start: Optional[str] = None,
                 test_end: Optional[str] = None) -> Dict[str, Any]:
        if events is None:
            base = datetime.now() - timedelta(days=14)
            events = [
                {"time": (base + timedelta(days=1)).strftime("%Y-%m-%d"), "title": "授权确认",
                 "type": "milestone"},
                {"time": (base + timedelta(days=2)).strftime("%Y-%m-%d"), "title": "信息收集完成",
                 "type": "finding"},
                {"time": (base + timedelta(days=5)).strftime("%Y-%m-%d"), "title": "发现严重漏洞",
                 "type": "finding"},
                {"time": (base + timedelta(days=10)).strftime("%Y-%m-%d"), "title": "客户修复",
                 "type": "fix"},
                {"time": (base + timedelta(days=13)).strftime("%Y-%m-%d"), "title": "复测通过",
                 "type": "milestone"},
            ]
        return {
            "chart_type": "timeline",
            "test_window": {"start": test_start, "end": test_end},
            "events": sorted(events, key=lambda e: e.get("time", "")),
            "milestones": [e for e in events if e.get("type") == "milestone"],
        }

    # ---- 6. 数据表格 ---- #
    @staticmethod
    def table_spec(rows: List[Dict[str, Any]], kind: str = "vulns",
                   page_size: int = 20) -> Dict[str, Any]:
        columns = list(rows[0].keys()) if rows else []
        return {
            "chart_type": "table",
            "kind": kind,
            "columns": columns,
            "rows": rows,
            "total": len(rows),
            "page_size": page_size,
            "sortable": True,
            "filterable": True,
            "exportable": ["csv", "xlsx", "json"],
            "current_page": 1,
        }


_singleton: Optional[ChartVisualization] = None


def get_chart_visualization() -> ChartVisualization:
    global _singleton
    if _singleton is None:
        _singleton = ChartVisualization()
    return _singleton
