# -*- coding: utf-8 -*-
"""
attack_path 模块 —— 攻击路径可视化生成器

模块功能：
    - 根据扫描结果自动构建从"攻击者"到"目标资产/敏感数据"的攻击路径图
    - 生成多条候选攻击路径并按最短 / 最高风险 / 最可能 排序
    - 支持 JSON / Mermaid / Graphviz 三种输出格式

节点类型：
    attacker(攻击者) / entry_point(入口点) / host(主机) / service(服务)
    vulnerability(漏洞) / target_asset(目标资产) / sensitive_data(敏感数据)

边类型：
    network_connection(网络连接) / vulnerability_exploit(漏洞利用)
    privilege_escalation(权限提升) / lateral_movement(横向移动) / data_access(数据访问)

定位说明：
    本模块输出的攻击路径图为【防御视角的风险评估】，
    用于帮助安全团队理解攻击面、识别薄弱环节、加强防护，请勿用于非法用途。
"""

import json
import html
from typing import Any, Optional


# 风险等级映射表（中文 -> 数值分数）
_RISK_SCORE_MAP = {
    "低": 20,
    "中": 50,
    "高": 75,
    "严重": 95,
    "critical": 95,
    "high": 75,
    "medium": 50,
    "low": 20,
}

# 漏洞严重程度 -> 成功率（百分比 0-100）
_SEVERITY_SUCCESS_RATE = {
    "严重": 85,
    "高": 70,
    "中": 45,
    "低": 25,
    "critical": 85,
    "high": 70,
    "medium": 45,
    "low": 25,
}

# Mermaid 节点样式类定义
_MERGE_CLASSDEFS = """
    classDef attacker fill:#9b59b6,stroke:#8e44ad,color:#fff,stroke-width:2px;
    classDef entry_point fill:#e67e22,stroke:#d35400,color:#fff,stroke-width:2px;
    classDef host fill:#3498db,stroke:#2980b9,color:#fff,stroke-width:2px;
    classDef service fill:#1abc9c,stroke:#16a085,color:#fff,stroke-width:2px;
    classDef vulnerability fill:#e74c3c,stroke:#c0392b,color:#fff,stroke-width:2px;
    classDef target_asset fill:#f39c12,stroke:#e67e22,color:#fff,stroke-width:2px;
    classDef sensitive_data fill:#c0392b,stroke:#922b21,color:#fff,stroke-width:2px;
"""

# Graphviz 节点颜色映射
_GRAPHVIZ_COLOR_MAP = {
    "attacker": "#9b59b6",
    "entry_point": "#e67e22",
    "host": "#3498db",
    "service": "#1abc9c",
    "vulnerability": "#e74c3c",
    "target_asset": "#f39c12",
    "sensitive_data": "#c0392b",
}


def _normalize_severity(severity: str) -> str:
    """将各种严重程度表述统一为中文标准等级。"""
    if not severity:
        return "中"
    s = str(severity).strip().lower()
    if s in ("严重", "critical", "严重", "紧急"):
        return "严重"
    if s in ("高", "high", "高危"):
        return "高"
    if s in ("中", "medium", "中危", "moderate"):
        return "中"
    if s in ("低", "low", "低危"):
        return "低"
    return "中"


def _severity_to_score(severity: str) -> int:
    """严重程度 -> 风险分数(0-100)。"""
    return _RISK_SCORE_MAP.get(_normalize_severity(severity), 50)


def _severity_to_success_rate(severity: str) -> int:
    """严重程度 -> 利用成功率(0-100)。"""
    return _SEVERITY_SUCCESS_RATE.get(_normalize_severity(severity), 45)


class AttackPathGenerator:
    """攻击路径可视化生成器。

    根据扫描结果自动推导从攻击者到敏感数据的攻击链路，
    并生成最短 / 最高风险 / 最可能 三条代表性路径。
    """

    def __init__(self) -> None:
        self._cache: dict[str, dict] = {}  # path_id -> path 详情缓存

    # ------------------------------------------------------------------
    # 核心生成逻辑
    # ------------------------------------------------------------------
    def generate(self, scan_data: dict) -> dict:
        """根据扫描结果生成攻击路径图。

        Args:
            scan_data: 扫描结果，格式如
                {
                    "target": "test.com",
                    "ip": "1.2.3.4",
                    "open_ports": [{"port":80,"service":"http","version":"..."}],
                    "vulnerabilities": [{"id":"CVE-xxx","name":"...","severity":"高","type":"...","port":80}],
                    "services": {}
                }

        Returns:
            {
                "graph": {"nodes": [...], "edges": [...]},
                "paths": [path_dict, ...],
                "summary": {...}
            }
        """
        try:
            target = scan_data.get("target", "未知目标")
            ip = scan_data.get("ip", "0.0.0.0")
            open_ports = scan_data.get("open_ports", []) or []
            vulnerabilities = scan_data.get("vulnerabilities", []) or []

            nodes: list[dict] = []
            edges: list[dict] = []
            node_id_counter = 1

            def _nid(prefix: str) -> str:
                nonlocal node_id_counter
                nid = f"n_{prefix}_{node_id_counter}"
                node_id_counter += 1
                return nid

            # 1) 攻击者节点（固定根节点）
            attacker_id = _nid("attacker")
            nodes.append({
                "id": attacker_id,
                "name": "攻击者",
                "node_type": "attacker",
                "risk_level": "低",
                "description": "外部攻击源（已隔离的模拟攻击者）",
                "related_vulnerabilities": [],
            })

            # 2) 入口点节点：每个开放端口对应一个入口点
            entry_point_ids: list[str] = []
            port_node_map: dict[int, str] = {}  # port -> entry_point node id

            for port_info in open_ports:
                port = port_info.get("port", 0)
                service = port_info.get("service", "unknown")
                version = port_info.get("version", "")
                ep_id = _nid("entry")
                ep_name = f"{ip}:{port} ({service})"
                nodes.append({
                    "id": ep_id,
                    "name": ep_name,
                    "node_type": "entry_point",
                    "risk_level": "中",
                    "description": f"开放端口 {port} 服务 {service} {version}".strip(),
                    "related_vulnerabilities": [],
                })
                # 攻击者 -> 入口点（网络连接）
                edges.append({
                    "source": attacker_id,
                    "target": ep_id,
                    "edge_type": "network_connection",
                    "exploit_method": "网络探测 / 端口扫描",
                    "success_rate": 90,
                    "required_permission": "无",
                })
                entry_point_ids.append(ep_id)
                port_node_map[port] = ep_id

            # 3) 如果没有开放端口但有漏洞，兜底生成一个入口点
            if not entry_point_ids and vulnerabilities:
                ep_id = _nid("entry")
                nodes.append({
                    "id": ep_id,
                    "name": f"{ip}:未知端口",
                    "node_type": "entry_point",
                    "risk_level": "中",
                    "description": "基于漏洞信息推断的入口点",
                    "related_vulnerabilities": [],
                })
                edges.append({
                    "source": attacker_id,
                    "target": ep_id,
                    "edge_type": "network_connection",
                    "exploit_method": "网络探测",
                    "success_rate": 85,
                    "required_permission": "无",
                })
                entry_point_ids.append(ep_id)

            # 4) 主机节点
            host_id = _nid("host")
            nodes.append({
                "id": host_id,
                "name": f"{target} ({ip})",
                "node_type": "host",
                "risk_level": "中",
                "description": f"目标主机 {target} 地址 {ip}",
                "related_vulnerabilities": [],
            })

            # 入口点 -> 主机
            for ep_id in entry_point_ids:
                edges.append({
                    "source": ep_id,
                    "target": host_id,
                    "edge_type": "network_connection",
                    "exploit_method": "建立会话连接",
                    "success_rate": 80,
                    "required_permission": "网络可达",
                })

            # 5) 服务节点 + 漏洞节点
            vuln_node_map: dict[int, list[str]] = {}  # port -> [vuln_node_id]
            service_node_map: dict[int, str] = {}

            for port_info in open_ports:
                port = port_info.get("port", 0)
                service = port_info.get("service", "unknown")
                version = port_info.get("version", "")
                svc_id = _nid("service")
                svc_name = f"{service} {version}".strip()
                nodes.append({
                    "id": svc_id,
                    "name": svc_name,
                    "node_type": "service",
                    "risk_level": "低",
                    "description": f"端口 {port} 运行的服务",
                    "related_vulnerabilities": [],
                })
                service_node_map[port] = svc_id
                # 主机 -> 服务
                edges.append({
                    "source": host_id,
                    "target": svc_id,
                    "edge_type": "service_communication",
                    "exploit_method": "服务枚举",
                    "success_rate": 95,
                    "required_permission": "已建立连接",
                })

            # 漏洞节点
            critical_count = 0
            for vuln in vulnerabilities:
                vid = vuln.get("id", "CVE-UNKNOWN")
                vname = vuln.get("name", "未知漏洞")
                severity = _normalize_severity(vuln.get("severity", "中"))
                vtype = vuln.get("type", "未知类型")
                port = vuln.get("port", 0)

                if severity == "严重":
                    critical_count += 1

                vn_id = _nid("vuln")
                nodes.append({
                    "id": vn_id,
                    "name": f"{vid}: {vname}",
                    "node_type": "vulnerability",
                    "risk_level": severity,
                    "description": f"类型:{vtype} 严重程度:{severity}",
                    "related_vulnerabilities": [vid],
                })

                # 关联到对应服务节点
                svc_id = service_node_map.get(port)
                if svc_id:
                    edges.append({
                        "source": svc_id,
                        "target": vn_id,
                        "edge_type": "vulnerability_exploit",
                        "exploit_method": f"利用 {vname} ({vtype})",
                        "success_rate": _severity_to_success_rate(severity),
                        "required_permission": "远程/未授权",
                    })
                else:
                    # 没有对应服务则直接挂到主机
                    edges.append({
                        "source": host_id,
                        "target": vn_id,
                        "edge_type": "vulnerability_exploit",
                        "exploit_method": f"利用 {vname} ({vtype})",
                        "success_rate": _severity_to_success_rate(severity),
                        "required_permission": "远程/未授权",
                    })

                vuln_node_map.setdefault(port, []).append(vn_id)

            # 6) 目标资产节点
            asset_id = _nid("asset")
            nodes.append({
                "id": asset_id,
                "name": f"目标资产: {target}",
                "node_type": "target_asset",
                "risk_level": "高" if critical_count > 0 else "中",
                "description": "被攻击的核心目标资产",
                "related_vulnerabilities": [],
            })

            # 漏洞 -> 目标资产（权限提升 / 数据访问）
            all_vuln_nodes: list[str] = []
            for port, vn_list in vuln_node_map.items():
                all_vuln_nodes.extend(vn_list)

            if all_vuln_nodes:
                for vn_id in all_vuln_nodes:
                    # 找到该漏洞的 risk_level 计算边的 success_rate
                    vn_node = next((n for n in nodes if n["id"] == vn_id), None)
                    sl = _severity_to_score(vn_node["risk_level"]) if vn_node else 50
                    edges.append({
                        "source": vn_id,
                        "target": asset_id,
                        "edge_type": "privilege_escalation",
                        "exploit_method": "权限提升 / 写入执行",
                        "success_rate": max(20, sl - 10),
                        "required_permission": "普通用户",
                    })
            else:
                # 无漏洞时主机直接连资产
                edges.append({
                    "source": host_id,
                    "target": asset_id,
                    "edge_type": "lateral_movement",
                    "exploit_method": "横向移动至核心资产",
                    "success_rate": 30,
                    "required_permission": "已获取主机访问",
                })

            # 7) 敏感数据节点
            data_id = _nid("data")
            nodes.append({
                "id": data_id,
                "name": "敏感数据 / 数据库",
                "node_type": "sensitive_data",
                "risk_level": "严重" if critical_count > 0 else "高",
                "description": "攻击者最终试图获取的敏感数据",
                "related_vulnerabilities": [],
            })
            edges.append({
                "source": asset_id,
                "target": data_id,
                "edge_type": "data_access",
                "exploit_method": "数据窃取 / 导出",
                "success_rate": 60,
                "required_permission": "管理员/数据库访问",
            })

            # ------------------------------------------------------------------
            # 生成多条攻击路径
            # ------------------------------------------------------------------
            paths = self._build_paths(
                nodes, edges, attacker_id, data_id, vuln_node_map, entry_point_ids
            )

            summary = {
                "total_paths": len(paths),
                "entry_points": len(entry_point_ids),
                "critical_vulnerabilities": critical_count,
                "total_nodes": len(nodes),
                "total_edges": len(edges),
            }

            result = {
                "graph": {"nodes": nodes, "edges": edges},
                "paths": paths,
                "summary": summary,
            }
            return result

        except Exception as e:  # noqa: BLE001
            # 兜底：返回空结构，保证不抛异常
            return {
                "graph": {"nodes": [], "edges": []},
                "paths": [],
                "summary": {"total_paths": 0, "entry_points": 0,
                            "critical_vulnerabilities": 0, "error": str(e)},
                "warning": f"生成攻击路径失败，已返回空结构: {e}",
            }

    # ------------------------------------------------------------------
    # 路径构建
    # ------------------------------------------------------------------
    def _build_paths(
        self,
        nodes: list[dict],
        edges: list[dict],
        start_id: str,
        end_id: str,
        vuln_node_map: dict[int, list[str]],
        entry_point_ids: list[str],
    ) -> list[dict]:
        """构建多条候选攻击路径并排序。"""
        # 构建邻接表
        adj: dict[str, list[str]] = {}
        for e in edges:
            adj.setdefault(e["source"], []).append(e["target"])

        # DFS 找出所有 start->end 的简单路径
        all_paths: list[list[str]] = []
        stack: list[list[str]] = [[start_id]]
        while stack:
            path = stack.pop()
            last = path[-1]
            if last == end_id:
                all_paths.append(path)
                continue
            for nxt in adj.get(last, []):
                if nxt not in path:
                    stack.append(path + [nxt])

        if not all_paths:
            return []

        # 计算每条路径的步骤数 / 风险分 / 成功率
        node_map = {n["id"]: n for n in nodes}
        edge_lookup = {(e["source"], e["target"]): e for e in edges}

        scored: list[dict] = []
        for idx, p in enumerate(all_paths):
            steps = len(p) - 1
            risk_sum = 0
            success_product = 1.0
            edge_ids: list[dict] = []
            for i in range(len(p) - 1):
                s, t = p[i], p[i + 1]
                e = edge_lookup.get((s, t))
                if e:
                    risk_sum += _severity_to_score(
                        node_map.get(t, {}).get("risk_level", "中")
                    )
                    success_product *= (e.get("success_rate", 50) / 100.0)
                    edge_ids.append({
                        "source": s, "target": t,
                        "edge_type": e.get("edge_type", ""),
                        "exploit_method": e.get("exploit_method", ""),
                        "success_rate": e.get("success_rate", 50),
                        "required_permission": e.get("required_permission", ""),
                    })

            avg_risk = risk_sum / max(1, steps)
            final_success = int(success_product * 100)

            path_id = f"path_{idx + 1}"
            path_detail = {
                "path_id": path_id,
                "type": "candidate",
                "nodes": [{"id": nid, "name": node_map.get(nid, {}).get("name", nid),
                           "node_type": node_map.get(nid, {}).get("node_type", "")}
                          for nid in p],
                "edges": edge_ids,
                "steps": steps,
                "risk_score": int(avg_risk),
                "success_rate": final_success,
            }
            self._cache[path_id] = path_detail
            scored.append(path_detail)

        # 选取三种代表性路径（深拷贝避免同一对象 type 被覆盖）
        import copy as _copy
        result_paths: list[dict] = []

        # 最短路径（步骤最少）
        shortest = _copy.deepcopy(min(scored, key=lambda x: (x["steps"], -x["success_rate"])))
        shortest["type"] = "shortest"
        result_paths.append(shortest)

        # 最高风险路径（累计风险最高）
        highest = _copy.deepcopy(max(scored, key=lambda x: x["risk_score"]))
        highest["type"] = "highest_risk"
        result_paths.append(highest)

        # 最可能路径（成功率最高）
        most_likely = _copy.deepcopy(max(scored, key=lambda x: x["success_rate"]))
        most_likely["type"] = "most_likely"
        result_paths.append(most_likely)

        return result_paths

    # ------------------------------------------------------------------
    # 输出格式转换
    # ------------------------------------------------------------------
    def to_json(self, graph_data: dict) -> str:
        """输出 JSON 字符串。"""
        return json.dumps(graph_data, ensure_ascii=False, indent=2)

    def to_mermaid(self, graph_data: dict) -> str:
        """输出 Mermaid 流程图（graph TD，节点用 :::class 着色）。"""
        try:
            lines: list[str] = ["graph TD"]
            lines.append("    %% 攻击路径图（防御视角风险评估）")

            nodes = graph_data.get("graph", {}).get("nodes", [])
            edges = graph_data.get("graph", {}).get("edges", [])

            # 节点定义：ID 无特殊字符，标签用引号包裹
            for n in nodes:
                nid = n.get("id", "n")
                label = html.escape(n.get("name", nid))
                ntype = n.get("node_type", "unknown")
                lines.append(f'    {nid}["{label}"]:::{ntype}')

            # 边定义
            for e in edges:
                s = e.get("source", "")
                t = e.get("target", "")
                etype = e.get("edge_type", "")
                method = html.escape(e.get("exploit_method", ""))
                if etype == "network_connection":
                    lines.append(f'    {s} -- "{method}" --> {t}')
                elif etype == "vulnerability_exploit":
                    lines.append(f'    {s} == "{method}" ==> {t}')
                elif etype == "privilege_escalation":
                    lines.append(f'    {s} -. "{method}" .-> {t}')
                elif etype == "data_access":
                    lines.append(f'    {s} == "数据访问" ==> {t}')
                else:
                    lines.append(f'    {s} -- "{method}" --> {t}')

            # 样式类定义
            lines.append("")
            for cls_def in _MERGE_CLASSDEFS.strip().split("\n"):
                lines.append("    " + cls_def.strip())

            return "\n".join(lines)
        except Exception as e:  # noqa: BLE001
            return f"graph TD\n    %% Mermaid 生成失败: {e}"

    def to_graphviz(self, graph_data: dict) -> str:
        """输出 Graphviz DOT 格式。"""
        try:
            lines: list[str] = [
                "digraph AttackPath {",
                '    rankdir=TB;',
                '    label="攻击路径图（防御视角风险评估）";',
                '    labelloc=t;',
                '    fontname="Microsoft YaHei";',
                '    node [fontname="Microsoft YaHei", style="filled,rounded"];',
                '    edge [fontname="Microsoft YaHei"];',
                "",
            ]
            nodes = graph_data.get("graph", {}).get("nodes", [])
            edges = graph_data.get("graph", {}).get("edges", [])

            for n in nodes:
                nid = n.get("id", "n").replace('"', '\\"')
                label = n.get("name", nid).replace('"', '\\"')
                ntype = n.get("node_type", "unknown")
                color = _GRAPHIVIZ_COLOR_MAP.get(ntype, "#95a5a6")
                lines.append(
                    f'    "{nid}" [label="{label}", fillcolor="{color}", '
                    f'tooltip="{ntype}"];'
                )

            for e in edges:
                s = e.get("source", "").replace('"', '\\"')
                t = e.get("target", "").replace('"', '\\"')
                method = e.get("exploit_method", "").replace('"', '\\"')
                sr = e.get("success_rate", 50)
                style = "bold" if sr >= 70 else "solid"
                lines.append(
                    f'    "{s}" -> "{t}" [label="{method} ({sr}%)", style="{style}"];'
                )

            lines.append("}")
            return "\n".join(lines)
        except Exception as e:  # noqa: BLE001
            return f'digraph AttackPath {{\n    label="生成失败: {e}";\n}}'

    # ------------------------------------------------------------------
    # 对比 / 查询
    # ------------------------------------------------------------------
    def compare_paths(self, paths: list) -> dict:
        """多条路径对比（步骤数 / 风险值 / 成功率 / 所需权限）。"""
        try:
            if not paths:
                return {"paths": [], "summary": "无路径可对比"}

            comparison = []
            for p in paths:
                permissions = set()
                for e in p.get("edges", []):
                    rp = e.get("required_permission", "")
                    if rp:
                        permissions.add(rp)
                comparison.append({
                    "path_id": p.get("path_id"),
                    "type": p.get("type"),
                    "steps": p.get("steps", 0),
                    "risk_score": p.get("risk_score", 0),
                    "success_rate": p.get("success_rate", 0),
                    "required_permissions": sorted(permissions),
                })

            # 汇总统计
            min_steps = min(c["steps"] for c in comparison)
            max_risk = max(c["risk_score"] for c in comparison)
            max_success = max(c["success_rate"] for c in comparison)

            return {
                "paths": comparison,
                "summary": {
                    "shortest_steps": min_steps,
                    "highest_risk": max_risk,
                    "highest_success_rate": max_success,
                    "path_count": len(comparison),
                },
            }
        except Exception as e:  # noqa: BLE001
            return {"paths": [], "summary": f"对比失败: {e}"}

    def get_path_details(self, path_id: str) -> dict:
        """获取单条路径详情。"""
        detail = self._cache.get(path_id)
        if detail:
            return detail
        return {"path_id": path_id, "found": False, "message": "未找到该路径，请先调用 generate()"}
