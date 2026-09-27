# -*- coding: utf-8 -*-
"""
攻击路径可视化模块

基于资产与漏洞数据构建攻击图，分析从外部入口到核心资产的攻击路径，
并提供风险评分、关键路径识别、Mermaid/SVG/HTML 可视化与缓解建议。

注意：本模块仅用于防御视角的攻击面分析与风险评估，不用于实际攻击。
"""
import html
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import log

# 漏洞严重程度权重
SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}

# 节点类型配色
NODE_COLORS = {
    "external": "#16a34a",
    "asset": "#2563eb",
    "critical_asset": "#dc2626",
    "vulnerability": "#ea580c",
}


class AttackPathAnalyzer:
    """攻击路径分析与可视化器"""

    def __init__(self):
        self.graphs: Dict[str, Dict[str, Any]] = {}
        log.info("攻击路径分析器初始化")

    # ------------------------------------------------------------------ #
    # 攻击图构建
    # ------------------------------------------------------------------ #
    def build_attack_graph(self,
                            assets: List[Dict[str, Any]],
                            vulnerabilities: List[Dict[str, Any]],
                            graph_id: Optional[str] = None) -> Dict[str, Any]:
        """
        构建攻击图。

        assets: 每项 {id, ip/name, importance(critical/high/medium/low)}
        vulnerabilities: 每项 {id, title, severity, asset_id, target_asset_id?}
        返回 {graph_id, nodes:[...], edges:[...]}
        """
        import uuid
        graph_id = graph_id or "graph-%s" % uuid.uuid4().hex[:10]
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        node_ids = set()

        def add_node(nid: str, ntype: str, label: str, **extra):
            if nid in node_ids:
                return
            node_ids.add(nid)
            n = {"id": nid, "type": ntype, "label": label}
            n.update(extra)
            nodes.append(n)

        # 外部入口节点
        external_id = "external"
        add_node(external_id, "external", "外部攻击者")

        # 资产节点
        asset_ids = set()
        for a in assets:
            aid = str(a.get("id") or a.get("ip") or "asset")
            asset_ids.add(aid)
            importance = (a.get("importance") or "medium").lower()
            ntype = "critical_asset" if importance == "critical" else "asset"
            label = a.get("name") or a.get("ip") or aid
            add_node(aid, ntype, label, importance=importance)
            # 外部可访问的边缘资产：external accesses -> asset
            edges.append({"source": external_id, "target": aid, "type": "accesses"})

        # 漏洞节点 + 边
        for v in vulnerabilities:
            vid = str(v.get("id") or "vuln")
            sev = (v.get("severity") or "info").lower()
            add_node(vid, "vulnerability", v.get("title") or vid, severity=sev)
            # 资产 exposes 漏洞
            owner = v.get("asset_id")
            if owner and str(owner) in node_ids:
                edges.append({"source": str(owner), "target": vid, "type": "exposes"})
            elif owner:
                # 引用了尚未登记的资产，自动补一个资产节点
                add_node(str(owner), "asset", str(owner))
                edges.append({"source": str(owner), "target": vid, "type": "exposes"})
            # 漏洞 exploits -> 下一资产（横向移动）
            target = v.get("target_asset_id")
            if target and str(target) in node_ids:
                edges.append({"source": vid, "target": str(target), "type": "exploits"})

        graph = {
            "graph_id": graph_id,
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "node_count": len(nodes),
                "edge_count": len(edges),
                "critical_assets": [n["id"] for n in nodes if n["type"] == "critical_asset"],
            },
        }
        self.graphs[graph_id] = graph
        log.info("构建攻击图 %s：%d 节点 %d 边" % (graph_id, len(nodes), len(edges)))
        return graph

    # ------------------------------------------------------------------ #
    # 路径分析
    # ------------------------------------------------------------------ #
    @staticmethod
    def _adjacency(graph: Dict[str, Any]) -> Dict[str, List[str]]:
        adj: Dict[str, List[str]] = {}
        for e in graph["edges"]:
            adj.setdefault(e["source"], []).append(e["target"])
        return adj

    def find_paths(self, graph: Dict[str, Any], start_node: str,
                   end_node: str, max_depth: int = 5) -> List[List[str]]:
        """BFS 查找从 start 到 end 的所有路径（限深 max_depth）。"""
        adj = self._adjacency(graph)
        results: List[List[str]] = []

        def dfs(cur: str, path: List[str], visited: set):
            if len(path) - 1 >= max_depth:
                return
            if cur == end_node:
                results.append(list(path))
                return
            for nxt in adj.get(cur, []):
                if nxt in visited:
                    continue
                visited.add(nxt)
                path.append(nxt)
                dfs(nxt, path, visited)
                path.pop()
                visited.remove(nxt)

        if start_node not in adj and start_node not in [n["id"] for n in graph["nodes"]]:
            return []
        dfs(start_node, [start_node], {start_node})
        return results

    def score_path(self, graph: Dict[str, Any], path: List[str]) -> float:
        """路径风险评分：漏洞严重程度加权 + 路径长度惩罚。"""
        node_map = {n["id"]: n for n in graph["nodes"]}
        raw = 0.0
        for nid in path:
            node = node_map.get(nid, {})
            if node.get("type") == "vulnerability":
                raw += SEVERITY_WEIGHT.get(node.get("severity", "info"), 0)
            elif node.get("type") == "critical_asset":
                raw += 5  # 直达核心资产加分
        # 长度惩罚：路径越长，攻击链越复杂，得分略衰减
        length_penalty = 1.0 / (1.0 + 0.1 * max(0, len(path) - 2))
        return round(raw * length_penalty, 2)

    def get_critical_paths(self, graph: Dict[str, Any],
                           top_n: int = 5) -> List[Dict[str, Any]]:
        """返回风险最高的 Top N 攻击路径。"""
        external = [n["id"] for n in graph["nodes"] if n["type"] == "external"]
        criticals = [n["id"] for n in graph["nodes"] if n["type"] == "critical_asset"]
        if not external:
            external = [n["id"] for n in graph["nodes"]][:1]
        if not criticals:
            criticals = [n["id"] for n in graph["nodes"] if n["type"] == "asset"][-1:]

        scored: List[Dict[str, Any]] = []
        for start in external:
            for end in criticals:
                for path in self.find_paths(graph, start, end):
                    scored.append({
                        "path_id": "path-%d" % len(scored),
                        "path": path,
                        "risk_score": self.score_path(graph, path),
                    })
        scored.sort(key=lambda x: x["risk_score"], reverse=True)
        return scored[:top_n]

    # ------------------------------------------------------------------ #
    # 可视化输出
    # ------------------------------------------------------------------ #
    @staticmethod
    def _node_short(nid: str) -> str:
        return nid.replace("-", "_").replace(".", "_").replace(":", "_")

    def generate_mermaid(self, graph: Dict[str, Any],
                         paths: Optional[List[List[str]]] = None) -> str:
        """生成 Mermaid flowchart 文本（节点按风险着色）。"""
        lines = ["graph TD"]
        node_map = {n["id"]: n for n in graph["nodes"]}
        for n in graph["nodes"]:
            nid = self._node_short(n["id"])
            label = html.escape(n["label"])
            lines.append('    %s["%s"]' % (nid, label))
        # 样式类
        style_map = {"external": "fill:#16a34a,color:#fff",
                     "asset": "fill:#2563eb,color:#fff",
                     "critical_asset": "fill:#dc2626,color:#fff",
                     "vulnerability": "fill:#ea580c,color:#fff"}
        for ntype, style in style_map.items():
            ids = [self._node_short(n["id"]) for n in graph["nodes"] if n["type"] == ntype]
            if ids:
                lines.append("    classDef %s %s" % (ntype, style))
                lines.append("    class %s %s" % (",".join(ids), ntype))
        # 边
        edge_labels = {"exposes": "暴露", "exploits": "利用", "accesses": "访问"}
        for e in graph["edges"]:
            s = self._node_short(e["source"])
            t = self._node_short(e["target"])
            lbl = edge_labels.get(e["type"], "")
            lines.append('    %s -->|%s| %s' % (s, lbl, t))
        return "\n".join(lines)

    def generate_svg(self, graph: Dict[str, Any],
                     paths: Optional[List[Dict[str, Any]]] = None) -> str:
        """生成纯 SVG 攻击路径图（矩形节点+箭头，颜色编码风险）。"""
        nodes = graph["nodes"]
        width, row_h = 900, 70
        height = 120 + row_h * len(nodes)
        parts = [
            '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" font-family="Arial">'
            % (width, height),
            '<style>.n{stroke:#333;rx:8} text{font-size:13px;fill:#fff}</style>',
        ]
        pos: Dict[str, Tuple[int, int]] = {}
        for i, n in enumerate(nodes):
            y = 60 + i * row_h
            pos[n["id"]] = (120, y)
            color = NODE_COLORS.get(n["type"], "#555")
            label = html.escape(n["label"])
            parts.append(
                '<rect class="n" x="80" y="%d" width="180" height="40" fill="%s"/>' % (y, color))
            parts.append('<text x="90" y="%d">%s</text>' % (y + 25, label))
        # 箭头
        parts.append('<defs><marker id="arr" markerWidth="10" markerHeight="10" refX="8" refY="3" '
                     'orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="#666"/></marker></defs>')
        for e in graph["edges"]:
            if e["source"] not in pos or e["target"] not in pos:
                continue
            x1, y1 = pos[e["source"]]
            x2, y2 = pos[e["target"]]
            parts.append(
                '<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#666" stroke-width="1.5" '
                'marker-end="url(#arr)"/>' % (x1 + 180, y1 + 20, x2, y2 + 20))
        parts.append("</svg>")
        return "\n".join(parts)

    def generate_html(self, graph: Dict[str, Any],
                      paths: Optional[List[Dict[str, Any]]] = None) -> str:
        """生成独立 HTML 文件（内联 SVG + CSS）。"""
        svg = self.generate_svg(graph, paths)
        path_list = ""
        if paths:
            for p in paths:
                chain = " -> ".join(p["path"])
                path_list += "<li>[风险 %.1f] %s</li>" % (p["risk_score"], html.escape(chain))
        body = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>攻击路径可视化</title>
<style>
body{font-family:'Microsoft YaHei',sans-serif;margin:24px;background:#f8fafc}
h2{color:#1e293b} ul{background:#fff;padding:16px 24px;border-radius:8px}
</style></head><body>
<h2>攻击路径分析图</h2>
%s
<h3>关键攻击路径（Top %d）</h3>
<ul>%s</ul>
</body></html>""" % (svg, len(paths or []), path_list)
        return body

    # ------------------------------------------------------------------ #
    # 缓解建议
    # ------------------------------------------------------------------ #
    def get_mitigations(self, graph: Dict[str, Any],
                        paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """分析在哪些节点部署防御可最大程度降低风险。"""
        node_map = {n["id"]: n for n in graph["nodes"]}
        # 统计各节点在多少条高风险路径中出现
        hit: Dict[str, float] = {}
        for p in paths:
            score = p["risk_score"]
            for nid in p["path"]:
                hit[nid] = hit.get(nid, 0) + score
        recs = []
        for nid, contrib in sorted(hit.items(), key=lambda x: x[1], reverse=True)[:10]:
            node = node_map.get(nid, {})
            ntype = node.get("type")
            if ntype == "vulnerability":
                action = "及时打补丁并下线危险服务（WAF/补丁）"
            elif ntype == "critical_asset":
                action = "网络隔离 + 最小权限 + 加强监控"
            elif ntype == "external":
                action = "边界收敛：WAF 与访问控制"
            else:
                action = "收敛暴露面 + 加强访问控制"
            recs.append({
                "path_id": "all",
                "mitigation_point": nid,
                "node_type": ntype,
                "recommendation": action,
                "risk_reduction": round(contrib, 2),
            })
        return recs

    # ------------------------------------------------------------------ #
    def get_graph(self, graph_id: str) -> Optional[Dict[str, Any]]:
        return self.graphs.get(graph_id)


# 全局单例
_analyzer: Optional[AttackPathAnalyzer] = None


def get_analyzer() -> AttackPathAnalyzer:
    """获取全局攻击路径分析器单例。"""
    global _analyzer
    if _analyzer is None:
        _analyzer = AttackPathAnalyzer()
    return _analyzer
