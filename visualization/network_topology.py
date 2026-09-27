# -*- coding: utf-8 -*-
"""
network_topology 模块 —— 网络拓扑可视化生成器

模块功能：
    - 根据端口扫描和主机发现结果生成网络拓扑图
    - 支持按子网分组（subnet 字段）
    - 按风险等级着色（低=绿/中=黄/高=橙/严重=红）
    - 支持按设备类型 / 风险等级筛选
    - 输出 JSON / Mermaid(graph LR) / Graphviz 三种格式

节点类型：
    gateway(网关) / firewall(防火墙) / switch(交换机) / server(服务器)
    workstation(工作站) / network_device(网络设备) / unknown_device(未知设备)

边类型：
    network_connection(网络连接) / open_port(开放端口) / service_communication(服务通信)

定位说明：
    本模块为授权安全评估 / 防御检测产品的网络资产可视化组件，
    用于帮助安全团队掌握内网资产分布与风险分布，请勿用于非法用途。
"""

import json
import html
from collections import Counter
from typing import Any, Optional


# 风险等级 -> 颜色
_RISK_COLOR_MAP = {
    "低": "#27ae60",      # 绿
    "中": "#f1c40f",      # 黄
    "高": "#e67e22",      # 橙
    "严重": "#e74c3c",    # 红
}

# 设备类型 -> 节点形状（Graphviz）
_GRAPHVIZ_SHAPE_MAP = {
    "gateway": "diamond",
    "firewall": "octagon",
    "switch": "box",
    "server": "box",
    "workstation": "note",
    "network_device": "cds",
    "unknown_device": "plaintext",
}


def _normalize_risk(level: str) -> str:
    """归一化风险等级为中文标准。"""
    if not level:
        return "低"
    s = str(level).strip().lower()
    if s in ("严重", "critical", "紧急"):
        return "严重"
    if s in ("高", "high", "高危"):
        return "高"
    if s in ("中", "medium", "moderate"):
        return "中"
    if s in ("低", "low", "低危"):
        return "低"
    return "低"


def _guess_device_type(ip: str, hostname: str, risk_level: str,
                       open_ports: list, subnet: str) -> str:
    """根据 IP / 主机名 / 端口猜测设备类型。"""
    try:
        # 网关：通常是 .1 结尾
        if ip.endswith(".1") or "gw" in hostname.lower() or "gateway" in hostname.lower():
            return "gateway"
        # 交换机 / 防火墙：常见管理端口
        port_set = {p.get("port") for p in open_ports}
        if {22, 23, 80, 443} & port_set and len(open_ports) <= 4:
            if any(x in hostname.lower() for x in ("fw", "firewall", "防火墙")):
                return "firewall"
            if any(x in hostname.lower() for x in ("sw", "switch", "交换机")):
                return "switch"
        # 工作站：常见桌面端口
        if 3389 in port_set or 5985 in port_set:
            return "workstation"
        # 服务器：通常开放较多服务端口
        if len(open_ports) >= 2:
            return "server"
        return "unknown_device"
    except Exception:  # noqa: BLE001
        return "unknown_device"


class NetworkTopologyGenerator:
    """网络拓扑可视化生成器。"""

    def __init__(self) -> None:
        self._graph: dict = {"nodes": [], "edges": []}
        self._subnets: dict[str, list[str]] = {}  # subnet -> [node_id]

    # ------------------------------------------------------------------
    # 核心生成逻辑
    # ------------------------------------------------------------------
    def generate(self, scan_data: dict) -> dict:
        """根据扫描结果生成网络拓扑图。

        Args:
            scan_data: {
                "targets": [{ip, hostname, os, open_ports:[{port,service,version}],
                              risk_level, geo_location, subnet}],
                "subnets": [],
                "gateway": ""
            }

        Returns:
            {"graph": {"nodes":[...], "edges":[...]}, "subnets": {...}, "stats": {...}}
        """
        try:
            targets = scan_data.get("targets", []) or []
            subnets_input = scan_data.get("subnets", []) or []
            gateway_ip = scan_data.get("gateway", "")

            nodes: list[dict] = []
            edges: list[dict] = []
            subnet_map: dict[str, list[str]] = {}

            node_id_counter = 1

            def _nid(prefix: str) -> str:
                nonlocal node_id_counter
                nid = f"n_{prefix}_{node_id_counter}"
                node_id_counter += 1
                return nid

            # 1) 网关节点
            gateway_id = None
            if gateway_ip:
                gateway_id = _nid("gw")
                nodes.append({
                    "id": gateway_id,
                    "ip": gateway_ip,
                    "hostname": "网关",
                    "os_type": "Network Device",
                    "open_ports_count": 0,
                    "risk_level": "中",
                    "geo_location": "",
                    "node_type": "gateway",
                })

            # 2) 各目标节点
            for t in targets:
                ip = t.get("ip", "0.0.0.0")
                hostname = t.get("hostname", ip)
                os_type = t.get("os", "Unknown")
                open_ports = t.get("open_ports", []) or []
                risk_level = _normalize_risk(t.get("risk_level", "低"))
                geo = t.get("geo_location", "")
                subnet = t.get("subnet", "default")

                ntype = _guess_device_type(ip, hostname, risk_level, open_ports, subnet)

                nid = _nid("host")
                nodes.append({
                    "id": nid,
                    "ip": ip,
                    "hostname": hostname,
                    "os_type": os_type,
                    "open_ports_count": len(open_ports),
                    "risk_level": risk_level,
                    "geo_location": geo,
                    "node_type": ntype,
                })
                subnet_map.setdefault(subnet, []).append(nid)

                # 网关 -> 该节点（网络连接）
                if gateway_id:
                    edges.append({
                        "source": gateway_id,
                        "target": nid,
                        "edge_type": "network_connection",
                        "bandwidth": "auto",
                    })

                # 节点 -> 各开放端口（open_port 边，可选：此处用节点属性承载）
                # 为拓扑简洁，开放端口数已记录在节点属性中

            # 3) 若未指定网关，按子网自动推断网关（.1 结尾的节点）
            if not gateway_id:
                for n in nodes:
                    if n["ip"].endswith(".1"):
                        n["node_type"] = "gateway"
                        gateway_id = n["id"]
                        break

            # 4) 同子网内节点互联（模拟交换机连接）
            # 注意：遍历 subnet_map 时不能修改它，先收集新增项再统一写入
            _new_subnet_entries: dict[str, list[str]] = {}
            for subnet, nid_list in list(subnet_map.items()):
                if len(nid_list) > 1:
                    # 子网交换机节点
                    sw_id = _nid("sw")
                    sw_name = f"交换机-{subnet}"
                    nodes.append({
                        "id": sw_id,
                        "ip": "",
                        "hostname": sw_name,
                        "os_type": "Switch",
                        "open_ports_count": len(nid_list),
                        "risk_level": "低",
                        "geo_location": "",
                        "node_type": "switch",
                    })
                    for nid in nid_list:
                        edges.append({
                            "source": sw_id,
                            "target": nid,
                            "edge_type": "network_connection",
                            "bandwidth": "1Gbps",
                        })
                    # 加入子网分组（延迟写入，避免遍历中修改字典）
                    _new_subnet_entries[subnet + "_sw"] = [sw_id]

            # 统一合并新增子网条目
            for k, v in _new_subnet_entries.items():
                subnet_map[k] = v

            self._graph = {"nodes": nodes, "edges": edges}
            self._subnets = subnet_map

            # 统计
            stats = self._compute_stats(nodes)

            return {
                "graph": {"nodes": nodes, "edges": edges},
                "subnets": subnet_map,
                "stats": stats,
            }
        except Exception as e:  # noqa: BLE001
            self._graph = {"nodes": [], "edges": []}
            return {
                "graph": {"nodes": [], "edges": []},
                "subnets": {},
                "stats": {"total_nodes": 0, "error": str(e)},
                "warning": f"生成拓扑失败: {e}",
            }

    # ------------------------------------------------------------------
    # 统计
    # ------------------------------------------------------------------
    def _compute_stats(self, nodes: list[dict]) -> dict:
        """计算拓扑统计信息。"""
        type_counter = Counter(n.get("node_type", "unknown") for n in nodes)
        risk_counter = Counter(n.get("risk_level", "低") for n in nodes)

        # 开放端口 TOP10
        port_counter: Counter = Counter()
        # 注：端口信息在节点属性中无明细，此处基于 open_ports_count 汇总
        # 真实场景应从扫描明细统计，这里给出占位
        total_open_ports = sum(n.get("open_ports_count", 0) for n in nodes)

        return {
            "total_nodes": len(nodes),
            "by_type": dict(type_counter),
            "by_risk": dict(risk_counter),
            "total_open_ports": total_open_ports,
            "top_ports": [],
        }

    def get_stats(self) -> dict:
        """拓扑统计（总节点数/各类型数/各风险等级数/开放端口TOP10）。"""
        nodes = self._graph.get("nodes", [])
        if not nodes:
            return {"total_nodes": 0, "message": "尚未生成拓扑，请先调用 generate()"}
        return self._compute_stats(nodes)

    # ------------------------------------------------------------------
    # 筛选
    # ------------------------------------------------------------------
    def filter_by_type(self, node_type: str) -> dict:
        """按设备类型筛选节点。"""
        nodes = self._graph.get("nodes", [])
        edges = self._graph.get("edges", [])
        filtered_nodes = [n for n in nodes if n.get("node_type") == node_type]
        filtered_ids = {n["id"] for n in filtered_nodes}
        filtered_edges = [e for e in edges
                          if e["source"] in filtered_ids and e["target"] in filtered_ids]
        return {
            "filter_type": node_type,
            "nodes": filtered_nodes,
            "edges": filtered_edges,
            "count": len(filtered_nodes),
        }

    def filter_by_risk(self, min_risk: str) -> dict:
        """按风险等级筛选（>= 指定等级）。"""
        risk_order = {"低": 1, "中": 2, "高": 3, "严重": 4}
        min_level = risk_order.get(_normalize_risk(min_risk), 1)
        nodes = self._graph.get("nodes", [])
        edges = self._graph.get("edges", [])
        filtered_nodes = [n for n in nodes
                          if risk_order.get(n.get("risk_level", "低"), 1) >= min_level]
        filtered_ids = {n["id"] for n in filtered_nodes}
        filtered_edges = [e for e in edges
                          if e["source"] in filtered_ids and e["target"] in filtered_ids]
        return {
            "min_risk": min_risk,
            "nodes": filtered_nodes,
            "edges": filtered_edges,
            "count": len(filtered_nodes),
        }

    # ------------------------------------------------------------------
    # 输出格式
    # ------------------------------------------------------------------
    def to_json(self, graph_data: Optional[dict] = None) -> str:
        """输出 JSON 字符串。"""
        data = graph_data if graph_data is not None else {
            "graph": self._graph, "subnets": self._subnets, "stats": self.get_stats()
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def to_mermaid(self, graph_data: Optional[dict] = None) -> str:
        """输出 Mermaid（graph LR，subgraph 分组子网）。"""
        try:
            data = graph_data or {"graph": self._graph, "subnets": self._subnets}
            nodes = data.get("graph", {}).get("nodes", [])
            edges = data.get("graph", {}).get("edges", [])
            subnets = data.get("subnets", {})

            lines: list[str] = ["graph LR", "    %% 网络拓扑图（防御视角资产盘点）"]

            # 按子网分 subgraph
            rendered_nodes: set = set()
            for subnet, nid_list in subnets.items():
                if subnet.endswith("_sw"):
                    continue
                safe_subnet = subnet.replace("/", "_").replace(".", "_")
                lines.append(f'    subgraph subnet_{safe_subnet}["子网: {html.escape(subnet)}"]')
                for nid in nid_list:
                    n = next((x for x in nodes if x["id"] == nid), None)
                    if not n:
                        continue
                    label = html.escape(f"{n.get('hostname', nid)}\n{n.get('ip', '')}")
                    risk = n.get("risk_level", "低")
                    lines.append(f'    {nid}["{label}"]:::risk_{risk}')
                    rendered_nodes.add(nid)
                lines.append("    end")

            # 未分组节点
            for n in nodes:
                if n["id"] not in rendered_nodes:
                    label = html.escape(f"{n.get('hostname', n['id'])}\n{n.get('ip', '')}")
                    risk = n.get("risk_level", "低")
                    lines.append(f'    {n["id"]}["{label}"]:::risk_{risk}')

            # 边
            for e in edges:
                s = e.get("source", "")
                t = e.get("target", "")
                etype = e.get("edge_type", "")
                if etype == "open_port":
                    lines.append(f'    {s} -. "{e.get("bandwidth","")}" .- {t}')
                else:
                    lines.append(f'    {s} --- {t}')

            # 风险颜色样式
            lines.append("")
            lines.append('    classDef risk_低 fill:#27ae60,stroke:#1e8449,color:#fff;')
            lines.append('    classDef risk_中 fill:#f1c40f,stroke:#f39c12,color:#000;')
            lines.append('    classDef risk_高 fill:#e67e22,stroke:#d35400,color:#fff;')
            lines.append('    classDef risk_严重 fill:#e74c3c,stroke:#c0392b,color:#fff;')

            return "\n".join(lines)
        except Exception as e:  # noqa: BLE001
            return f"graph LR\n    %% Mermaid 生成失败: {e}"

    def to_graphviz(self, graph_data: Optional[dict] = None) -> str:
        """输出 Graphviz DOT 格式。"""
        try:
            data = graph_data or {"graph": self._graph, "subnets": self._subnets}
            nodes = data.get("graph", {}).get("nodes", [])
            edges = data.get("graph", {}).get("edges", [])
            subnets = data.get("subnets", {})

            lines: list[str] = [
                "digraph NetworkTopology {",
                '    rankdir=LR;',
                '    label="网络拓扑图（防御视角资产盘点）";',
                '    labelloc=t;',
                '    fontname="Microsoft YaHei";',
                '    node [fontname="Microsoft YaHei", style="filled,rounded"];',
                '    edge [fontname="Microsoft YaHei"];',
                "",
            ]

            # 按子网建 cluster
            cluster_idx = 0
            rendered: set = set()
            for subnet, nid_list in subnets.items():
                if subnet.endswith("_sw"):
                    continue
                lines.append(f'    subgraph cluster_{cluster_idx} {{')
                lines.append(f'        label="子网: {subnet}";')
                lines.append('        style="dashed";')
                for nid in nid_list:
                    n = next((x for x in nodes if x["id"] == nid), None)
                    if not n:
                        continue
                    label = f"{n.get('hostname','')}\\n{n.get('ip','')}"
                    risk = n.get("risk_level", "低")
                    color = _RISK_COLOR_MAP.get(risk, "#95a5a6")
                    shape = _GRAPHVIZ_SHAPE_MAP.get(n.get("node_type", ""), "box")
                    lines.append(
                        f'        "{nid}" [label="{label}", fillcolor="{color}", '
                        f'shape="{shape}"];'
                    )
                    rendered.add(nid)
                lines.append("    }")
                cluster_idx += 1

            # 未分组节点
            for n in nodes:
                if n["id"] in rendered:
                    continue
                label = f"{n.get('hostname','')}\\n{n.get('ip','')}"
                risk = n.get("risk_level", "低")
                color = _RISK_COLOR_MAP.get(risk, "#95a5a6")
                shape = _GRAPHVIZ_SHAPE_MAP.get(n.get("node_type", ""), "box")
                lines.append(
                    f'    "{n["id"]}" [label="{label}", fillcolor="{color}", shape="{shape}"];'
                )

            # 边
            for e in edges:
                s = e.get("source", "")
                t = e.get("target", "")
                lines.append(f'    "{s}" -> "{t}";')

            lines.append("}")
            return "\n".join(lines)
        except Exception as e:  # noqa: BLE001
            return f'digraph NetworkTopology {{\n    label="生成失败: {e}";\n}}'
