# -*- coding: utf-8 -*-
"""
risk_heatmap 模块 —— 风险热力图生成器

模块功能：
    - 支持四种维度：host_port / vuln_type / time_risk / service_vuln
    - 单元格值为风险分数(0-100)，基于漏洞严重程度和数量计算
    - 颜色映射：0-25绿(低)/26-50黄(中)/51-75橙(高)/76-100红(严重)
    - 输出 JSON / HTML(内联样式) / CSV 三种格式

定位说明：
    本模块为授权安全评估 / 防御检测产品的风险可视化组件，
    用于帮助安全团队识别高风险资产与薄弱环节，请勿用于非法用途。
"""

import json
import html
from collections import defaultdict
from typing import Any, Optional


# 严重程度 -> 风险分
_SEVERITY_SCORE = {
    "低": 15,
    "中": 40,
    "高": 70,
    "严重": 95,
    "critical": 95,
    "high": 70,
    "medium": 40,
    "low": 15,
}


def _normalize_severity(severity: str) -> str:
    """归一化严重程度。"""
    if not severity:
        return "中"
    s = str(severity).strip().lower()
    if s in ("严重", "critical", "紧急"):
        return "严重"
    if s in ("高", "high", "高危"):
        return "高"
    if s in ("中", "medium", "moderate"):
        return "中"
    if s in ("低", "low", "低危"):
        return "低"
    return "中"


def _score_to_risk_level(score: int) -> str:
    """分数 -> 风险等级。"""
    if score <= 25:
        return "低"
    if score <= 50:
        return "中"
    if score <= 75:
        return "高"
    return "严重"


def _score_to_color(score: int) -> str:
    """分数 -> 颜色(十六进制)。"""
    if score <= 25:
        return "#27ae60"   # 绿
    if score <= 50:
        return "#f1c40f"   # 黄
    if score <= 75:
        return "#e67e22"   # 橙
    return "#e74c3c"       # 红


class RiskHeatmapGenerator:
    """风险热力图生成器。"""

    def __init__(self) -> None:
        self._matrix: dict = {}
        self._cells: dict[tuple, dict] = {}  # (row, col) -> cell detail

    # ------------------------------------------------------------------
    # 核心生成逻辑
    # ------------------------------------------------------------------
    def generate(self, scan_data: dict, dimension: str = "host_port") -> dict:
        """生成风险热力图矩阵。

        Args:
            scan_data: 扫描结果
            dimension: host_port / vuln_type / time_risk / service_vuln

        Returns:
            {
                "dimension": str,
                "rows": [...],
                "cols": [...],
                "matrix": [[{row,col,value,risk_level,color,vulnerabilities}]],
                "summary": {...}
            }
        """
        try:
            if dimension == "host_port":
                return self._gen_host_port(scan_data)
            if dimension == "vuln_type":
                return self._gen_vuln_type(scan_data)
            if dimension == "time_risk":
                return self._gen_time_risk(scan_data)
            if dimension == "service_vuln":
                return self._gen_service_vuln(scan_data)
            # 未知维度兜底
            return {
                "dimension": dimension,
                "rows": [], "cols": [], "matrix": [],
                "summary": {"error": f"未知维度: {dimension}，支持 host_port/vuln_type/time_risk/service_vuln"},
            }
        except Exception as e:  # noqa: BLE001
            return {
                "dimension": dimension,
                "rows": [], "cols": [], "matrix": [],
                "summary": {"error": f"生成失败: {e}"},
            }

    # ------------------------------------------------------------------
    # 维度1：主机 × 端口/服务
    # ------------------------------------------------------------------
    def _gen_host_port(self, scan_data: dict) -> dict:
        """主机 × 端口 风险矩阵。"""
        targets = scan_data.get("targets", []) or []
        if not targets:
            # 兜底：尝试从顶层字段构造
            ip = scan_data.get("ip", "unknown")
            vulns = scan_data.get("vulnerabilities", []) or []
            targets = [{"ip": ip, "vulnerabilities": vulns}]

        rows: list[str] = []
        cols_set: list[str] = []
        cols_index: dict[str, int] = {}
        cell_matrix: list[list[dict]] = []
        self._cells = {}

        # 收集所有端口
        for t in targets:
            vulns = t.get("vulnerabilities", []) or []
            for v in vulns:
                port = str(v.get("port", "?"))
                label = f"{port}"
                if label not in cols_index:
                    cols_index[label] = len(cols_set)
                    cols_set.append(label)

        for t in targets:
            ip = t.get("ip", "unknown")
            rows.append(ip)
            vulns = t.get("vulnerabilities", []) or []

            # 按端口聚合漏洞分数
            port_scores: dict[str, list[int]] = defaultdict(list)
            port_vulns: dict[str, list[dict]] = defaultdict(list)
            for v in vulns:
                port = str(v.get("port", "?"))
                sev = _normalize_severity(v.get("severity", "中"))
                port_scores[port].append(_SEVERITY_SCORE.get(sev, 40))
                port_vulns[port].append({
                    "id": v.get("id", ""),
                    "name": v.get("name", ""),
                    "severity": sev,
                    "type": v.get("type", ""),
                })

            row_cells: list[dict] = []
            for col_label in cols_set:
                scores = port_scores.get(col_label, [])
                if scores:
                    # 单元格分数 = max + 数量加成（上限100）
                    value = min(100, max(scores) + (len(scores) - 1) * 5)
                    vuln_list = port_vulns.get(col_label, [])
                else:
                    value = 0
                    vuln_list = []

                risk_level = _score_to_risk_level(value)
                color = _score_to_color(value)
                cell = {
                    "row": ip,
                    "col": col_label,
                    "value": value,
                    "risk_level": risk_level,
                    "color": color,
                    "vulnerabilities": vuln_list,
                }
                row_cells.append(cell)
                self._cells[(ip, col_label)] = cell
            cell_matrix.append(row_cells)

        result = {
            "dimension": "host_port",
            "rows": rows,
            "cols": cols_set,
            "matrix": cell_matrix,
        }
        result["summary"] = self._summarize(cell_matrix)
        self._matrix = result
        return result

    # ------------------------------------------------------------------
    # 维度2：主机 × 漏洞类型
    # ------------------------------------------------------------------
    def _gen_vuln_type(self, scan_data: dict) -> dict:
        """主机 × 漏洞类型 矩阵。"""
        targets = scan_data.get("targets", []) or []
        if not targets:
            ip = scan_data.get("ip", "unknown")
            vulns = scan_data.get("vulnerabilities", []) or []
            targets = [{"ip": ip, "vulnerabilities": vulns}]

        rows: list[str] = []
        cols_set: list[str] = []
        cols_index: dict[str, int] = {}
        cell_matrix: list[list[dict]] = []
        self._cells = {}

        # 收集所有漏洞类型
        for t in targets:
            for v in (t.get("vulnerabilities", []) or []):
                vtype = v.get("type", "未知类型")
                if vtype not in cols_index:
                    cols_index[vtype] = len(cols_set)
                    cols_set.append(vtype)

        for t in targets:
            ip = t.get("ip", "unknown")
            rows.append(ip)
            vulns = t.get("vulnerabilities", []) or []

            type_scores: dict[str, list[int]] = defaultdict(list)
            type_vulns: dict[str, list[dict]] = defaultdict(list)
            for v in vulns:
                vtype = v.get("type", "未知类型")
                sev = _normalize_severity(v.get("severity", "中"))
                type_scores[vtype].append(_SEVERITY_SCORE.get(sev, 40))
                type_vulns[vtype].append({
                    "id": v.get("id", ""),
                    "name": v.get("name", ""),
                    "severity": sev,
                    "port": v.get("port", ""),
                })

            row_cells: list[dict] = []
            for col_label in cols_set:
                scores = type_scores.get(col_label, [])
                if scores:
                    value = min(100, max(scores) + (len(scores) - 1) * 5)
                    vuln_list = type_vulns.get(col_label, [])
                else:
                    value = 0
                    vuln_list = []
                cell = {
                    "row": ip, "col": col_label,
                    "value": value,
                    "risk_level": _score_to_risk_level(value),
                    "color": _score_to_color(value),
                    "vulnerabilities": vuln_list,
                }
                row_cells.append(cell)
                self._cells[(ip, col_label)] = cell
            cell_matrix.append(row_cells)

        result = {
            "dimension": "vuln_type",
            "rows": rows, "cols": cols_set, "matrix": cell_matrix,
        }
        result["summary"] = self._summarize(cell_matrix)
        self._matrix = result
        return result

    # ------------------------------------------------------------------
    # 维度3：时间 × 风险等级
    # ------------------------------------------------------------------
    def _gen_time_risk(self, scan_data: dict) -> dict:
        """时间 × 风险等级 矩阵。"""
        history = scan_data.get("history", []) or scan_data.get("targets", []) or []
        rows: list[str] = []
        cols_set = ["低", "中", "高", "严重"]
        cell_matrix: list[list[dict]] = []
        self._cells = {}

        for record in history:
            date = record.get("date", record.get("day", "unknown"))
            rows.append(str(date))
            # 各等级数量
            counts = {
                "低": record.get("low_count", record.get("低", 0)),
                "中": record.get("medium_count", record.get("中", 0)),
                "高": record.get("high_count", record.get("高", 0)),
                "严重": record.get("critical_count", record.get("严重", 0)),
            }
            row_cells: list[dict] = []
            for col in cols_set:
                cnt = int(counts.get(col, 0) or 0)
                # 数量 -> 分数：每个低危5分，上限100
                multiplier = {"低": 5, "中": 10, "高": 20, "严重": 30}[col]
                value = min(100, cnt * multiplier)
                cell = {
                    "row": str(date), "col": col,
                    "value": value,
                    "risk_level": _score_to_risk_level(value),
                    "color": _score_to_color(value),
                    "vulnerabilities": [{"count": cnt, "severity": col}],
                }
                row_cells.append(cell)
                self._cells[(str(date), col)] = cell
            cell_matrix.append(row_cells)

        result = {
            "dimension": "time_risk",
            "rows": rows, "cols": cols_set, "matrix": cell_matrix,
        }
        result["summary"] = self._summarize(cell_matrix)
        self._matrix = result
        return result

    # ------------------------------------------------------------------
    # 维度4：服务 × 漏洞类型
    # ------------------------------------------------------------------
    def _gen_service_vuln(self, scan_data: dict) -> dict:
        """服务 × 漏洞类型 矩阵。"""
        targets = scan_data.get("targets", []) or []
        if not targets:
            targets = [{"ip": scan_data.get("ip", "unknown"),
                        "vulnerabilities": scan_data.get("vulnerabilities", []) or []}]

        rows_set: list[str] = []
        rows_index: dict[str, int] = {}
        cols_set: list[str] = []
        cols_index: dict[str, int] = {}
        raw: dict[tuple, list[int]] = defaultdict(list)
        raw_vulns: dict[tuple, list[dict]] = defaultdict(list)

        for t in targets:
            vulns = t.get("vulnerabilities", []) or []
            # 从 open_ports 建立 port->service 映射
            port_service: dict[int, str] = {}
            for p in (t.get("open_ports", []) or []):
                port_service[p.get("port", 0)] = p.get("service", "unknown")

            for v in vulns:
                port = v.get("port", 0)
                service = port_service.get(port, f"port_{port}")
                vtype = v.get("type", "未知类型")
                sev = _normalize_severity(v.get("severity", "中"))

                if service not in rows_index:
                    rows_index[service] = len(rows_set)
                    rows_set.append(service)
                if vtype not in cols_index:
                    cols_index[vtype] = len(cols_set)
                    cols_set.append(vtype)

                raw[(service, vtype)].append(_SEVERITY_SCORE.get(sev, 40))
                raw_vulns[(service, vtype)].append({
                    "id": v.get("id", ""), "name": v.get("name", ""),
                    "severity": sev, "port": port,
                })

        cell_matrix: list[list[dict]] = []
        self._cells = {}
        for r in rows_set:
            row_cells: list[dict] = []
            for c in cols_set:
                scores = raw.get((r, c), [])
                if scores:
                    value = min(100, max(scores) + (len(scores) - 1) * 5)
                    vlist = raw_vulns.get((r, c), [])
                else:
                    value = 0
                    vlist = []
                cell = {
                    "row": r, "col": c, "value": value,
                    "risk_level": _score_to_risk_level(value),
                    "color": _score_to_color(value),
                    "vulnerabilities": vlist,
                }
                row_cells.append(cell)
                self._cells[(r, c)] = cell
            cell_matrix.append(row_cells)

        result = {
            "dimension": "service_vuln",
            "rows": rows_set, "cols": cols_set, "matrix": cell_matrix,
        }
        result["summary"] = self._summarize(cell_matrix)
        self._matrix = result
        return result

    # ------------------------------------------------------------------
    # 汇总
    # ------------------------------------------------------------------
    def _summarize(self, matrix: list[list[dict]]) -> dict:
        """计算热力图摘要。"""
        if not matrix:
            return {"max_cell": None, "avg_risk": 0, "distribution": {}}

        all_values: list[int] = []
        max_cell: Optional[dict] = None
        risk_dist: dict[str, int] = {"低": 0, "中": 0, "高": 0, "严重": 0}

        for row in matrix:
            for cell in row:
                v = cell.get("value", 0)
                all_values.append(v)
                rl = cell.get("risk_level", "低")
                risk_dist[rl] = risk_dist.get(rl, 0) + 1
                if max_cell is None or v > max_cell.get("value", -1):
                    max_cell = cell

        avg = int(sum(all_values) / len(all_values)) if all_values else 0
        return {
            "max_cell": {
                "row": max_cell.get("row"), "col": max_cell.get("col"),
                "value": max_cell.get("value"), "risk_level": max_cell.get("risk_level"),
            } if max_cell else None,
            "avg_risk": avg,
            "distribution": risk_dist,
            "total_cells": len(all_values),
        }

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def get_cell_details(self, row: str, col: str) -> dict:
        """获取单元格详情（漏洞列表）。"""
        cell = self._cells.get((row, col))
        if cell:
            return cell
        return {"row": row, "col": col, "found": False, "message": "未找到该单元格"}

    def get_summary(self) -> dict:
        """热力图摘要。"""
        if not self._matrix:
            return {"message": "尚未生成热力图，请先调用 generate()"}
        return self._matrix.get("summary", {})

    # ------------------------------------------------------------------
    # 输出格式
    # ------------------------------------------------------------------
    def to_json(self, heatmap_data: Optional[dict] = None) -> str:
        """数据矩阵 JSON。"""
        data = heatmap_data if heatmap_data is not None else self._matrix
        return json.dumps(data, ensure_ascii=False, indent=2)

    def to_html(self, heatmap_data: Optional[dict] = None) -> str:
        """带颜色的 HTML 表格（内联样式，可直接嵌入页面）。"""
        try:
            data = heatmap_data if heatmap_data is not None else self._matrix
            rows = data.get("rows", [])
            cols = data.get("cols", [])
            matrix = data.get("matrix", [])
            dimension = data.get("dimension", "unknown")

            parts: list[str] = []
            parts.append('<table style="border-collapse:collapse;font-family:Microsoft YaHei,SimHei,sans-serif;font-size:13px;">')
            parts.append("<thead><tr style='background:#2c3e50;color:#fff;'>")
            parts.append(f"<th style='padding:8px 12px;border:1px solid #34495e;'>维度:{html.escape(dimension)}</th>")
            for c in cols:
                parts.append(
                    f"<th style='padding:8px 12px;border:1px solid #34495e;'>{html.escape(str(c))}</th>"
                )
            parts.append("</tr></thead><tbody>")

            for i, row in enumerate(matrix):
                row_label = rows[i] if i < len(rows) else f"row_{i}"
                parts.append(
                    f"<tr><th style='padding:8px 12px;border:1px solid #ccc;background:#ecf0f1;text-align:left;'>"
                    f"{html.escape(str(row_label))}</th>"
                )
                for cell in row:
                    value = cell.get("value", 0)
                    color = cell.get("color", "#95a5a6")
                    rl = cell.get("risk_level", "")
                    parts.append(
                        f"<td style='padding:8px 12px;border:1px solid #ccc;"
                        f"background:{color};color:#fff;text-align:center;"
                        f'title="{html.escape(rl)}: {value}">{value}</td>'
                    )
                parts.append("</tr>")
            parts.append("</tbody></table>")
            return "".join(parts)
        except Exception as e:  # noqa: BLE001
            return f"<p style='color:red;'>HTML 生成失败: {html.escape(str(e))}</p>"

    def to_csv(self, heatmap_data: Optional[dict] = None) -> str:
        """CSV 格式输出。"""
        try:
            data = heatmap_data if heatmap_data is not None else self._matrix
            rows = data.get("rows", [])
            cols = data.get("cols", [])
            matrix = data.get("matrix", [])

            lines: list[str] = []
            header = "row," + ",".join(str(c) for c in cols)
            lines.append(header)
            for i, row in enumerate(matrix):
                row_label = rows[i] if i < len(rows) else f"row_{i}"
                values = [str(c.get("value", 0)) for c in row]
                lines.append(str(row_label) + "," + ",".join(values))
            return "\n".join(lines)
        except Exception as e:  # noqa: BLE001
            return f"# CSV 生成失败: {e}"
