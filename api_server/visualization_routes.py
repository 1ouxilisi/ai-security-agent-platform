# -*- coding: utf-8 -*-
"""
visualization_routes 模块 —— 可视化 REST API

模块功能：
    - 攻击路径图 / 网络拓扑图 / 风险热力图 / 趋势分析 的 REST 接口
    - 所有端点均做异常兜底，统一返回 JSONResponse，不向外抛出 500
    - 输入数据不足时生成合理的示例/模拟数据并标注"示例数据"

路由前缀：/api/v1/visualization

定位说明：
    本模块为授权安全评估 / 防御检测产品的可视化接口，
    所有攻击路径图均为【防御视角的风险评估】，
    用于帮助安全团队理解攻击面、识别薄弱环节、加强防护，请勿用于非法用途。
"""

import os
import sys
from typing import Any, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# 保证项目根目录在 sys.path 中（与其它路由模块保持一致）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from visualization.attack_path import AttackPathGenerator  # noqa: E402
from visualization.network_topology import NetworkTopologyGenerator  # noqa: E402
from visualization.risk_heatmap import RiskHeatmapGenerator  # noqa: E402
from visualization.trend_analysis import TrendAnalyzer  # noqa: E402

router = APIRouter(prefix="/api/v1/visualization", tags=["可视化"])


# ==================== 请求模型 ====================

class ScanDataRequest(BaseModel):
    """扫描数据请求体。"""
    scan_data: Optional[dict] = None
    assessment_id: Optional[str] = None
    dimension: Optional[str] = "host_port"


class TrendRequest(BaseModel):
    """趋势分析请求体。"""
    metric: Optional[str] = "vulnerability"  # vulnerability / risk / scan
    chart_type: Optional[str] = "line"
    history_data: Optional[list] = None


# ==================== 统一响应辅助 ====================

def _ok(data: Any, extra: Optional[dict] = None) -> JSONResponse:
    """成功响应。"""
    payload = {"success": True, "data": data}
    if extra:
        payload.update(extra)
    return JSONResponse(content=payload)


def _err(msg: str) -> JSONResponse:
    """失败响应（不抛 500，统一 JSON）。"""
    return JSONResponse(status_code=200, content={"success": False, "error": str(msg)})


# ==================== 示例数据兜底 ====================

def _sample_scan_data() -> dict:
    """生成示例扫描数据（用于输入不足时兜底）。"""
    return {
        "target": "demo.example.com",
        "ip": "203.0.113.10",
        "open_ports": [
            {"port": 80, "service": "http", "version": "Apache 2.4.49"},
            {"port": 443, "service": "https", "version": "OpenSSL 1.1.1"},
            {"port": 22, "service": "ssh", "version": "OpenSSH 8.0"},
        ],
        "vulnerabilities": [
            {"id": "CVE-2021-41773", "name": "路径穿越", "severity": "高",
             "type": "路径穿越", "port": 80},
            {"id": "CVE-2019-0000", "name": "弱口令", "severity": "中",
             "type": "认证缺陷", "port": 22},
        ],
        "services": {},
        "_is_sample": True,
    }


def _sample_topology_data() -> dict:
    """生成示例拓扑数据。"""
    return {
        "targets": [
            {"ip": "192.168.1.1", "hostname": "gw", "os": "Linux",
             "open_ports": [{"port": 80, "service": "http"}], "risk_level": "中",
             "subnet": "192.168.1.0/24"},
            {"ip": "192.168.1.10", "hostname": "srv1", "os": "Windows",
             "open_ports": [{"port": 445, "service": "smb"}, {"port": 3389, "service": "rdp"}],
             "risk_level": "高", "subnet": "192.168.1.0/24"},
        ],
        "subnets": ["192.168.1.0/24"],
        "gateway": "192.168.1.1",
        "_is_sample": True,
    }


def _sample_history_data() -> list:
    """生成示例历史趋势数据。"""
    return [
        {"date": "2024-01", "new_vulns": 12, "fixed_vulns": 5, "unfixed_vulns": 20,
         "total_vulns": 27, "avg_risk": 55, "max_risk": 85,
         "critical_count": 2, "high_count": 8, "medium_count": 12, "low_count": 5,
         "scan_count": 3, "vulns_found": 12, "fix_rate": 41.7, "avg_duration": 120.5},
        {"date": "2024-02", "new_vulns": 8, "fixed_vulns": 10, "unfixed_vulns": 18,
         "total_vulns": 25, "avg_risk": 48, "max_risk": 78,
         "critical_count": 1, "high_count": 6, "medium_count": 10, "low_count": 8,
         "scan_count": 4, "vulns_found": 8, "fix_rate": 55.6, "avg_duration": 110.2},
        {"date": "2024-03", "new_vulns": 5, "fixed_vulns": 12, "unfixed_vulns": 11,
         "total_vulns": 18, "avg_risk": 40, "max_risk": 70,
         "critical_count": 0, "high_count": 4, "medium_count": 8, "low_count": 9,
         "scan_count": 5, "vulns_found": 5, "fix_rate": 75.0, "avg_duration": 95.0},
    ]


# ==================== 端点定义 ====================

@router.post("/attack-path")
def generate_attack_path(body: ScanDataRequest):
    """生成攻击路径图（返回 JSON + Mermaid + Graphviz）。"""
    try:
        scan_data = body.scan_data or _sample_scan_data()
        is_sample = scan_data.pop("_is_sample", False) or body.scan_data is None

        gen = AttackPathGenerator()
        result = gen.generate(scan_data)

        response_data = {
            "graph_data": result,
            "mermaid": gen.to_mermaid(result),
            "graphviz": gen.to_graphviz(result),
            "json": gen.to_json(result),
            "path_comparison": gen.compare_paths(result.get("paths", [])),
        }
        extra = {"is_sample": is_sample, "note": "示例数据（输入不足时自动生成）" if is_sample else ""}
        return _ok(response_data, extra)
    except Exception as e:  # noqa: BLE001
        return _err(f"攻击路径生成失败: {e}")


@router.post("/network-topology")
def generate_network_topology(body: ScanDataRequest):
    """生成网络拓扑图。"""
    try:
        scan_data = body.scan_data or _sample_topology_data()
        is_sample = scan_data.pop("_is_sample", False) or body.scan_data is None

        gen = NetworkTopologyGenerator()
        result = gen.generate(scan_data)

        response_data = {
            "graph_data": result,
            "mermaid": gen.to_mermaid(result),
            "graphviz": gen.to_graphviz(result),
            "json": gen.to_json(result),
            "stats": gen.get_stats(),
        }
        extra = {"is_sample": is_sample, "note": "示例数据（输入不足时自动生成）" if is_sample else ""}
        return _ok(response_data, extra)
    except Exception as e:  # noqa: BLE001
        return _err(f"网络拓扑生成失败: {e}")


@router.post("/risk-heatmap")
def generate_risk_heatmap(body: ScanDataRequest):
    """生成风险热力图。"""
    try:
        scan_data = body.scan_data or _sample_scan_data()
        dimension = body.dimension or "host_port"
        is_sample = scan_data.pop("_is_sample", False) or body.scan_data is None

        gen = RiskHeatmapGenerator()
        result = gen.generate(scan_data, dimension)

        response_data = {
            "heatmap_data": result,
            "html": gen.to_html(result),
            "csv": gen.to_csv(result),
            "json": gen.to_json(result),
            "summary": result.get("summary", {}),
        }
        extra = {"is_sample": is_sample, "dimension": dimension,
                 "note": "示例数据（输入不足时自动生成）" if is_sample else ""}
        return _ok(response_data, extra)
    except Exception as e:  # noqa: BLE001
        return _err(f"风险热力图生成失败: {e}")


@router.get("/trend")
def get_trend(metric: str = "vulnerability", chart_type: str = "line"):
    """获取趋势分析数据（无数据时返回示例数据结构）。"""
    try:
        history = _sample_history_data()
        analyzer = TrendAnalyzer()

        if metric == "vulnerability":
            analysis = analyzer.analyze_vulnerability_trend(history)
        elif metric == "risk":
            analysis = analyzer.analyze_risk_trend(history)
        elif metric == "scan":
            analysis = analyzer.analyze_scan_trend(history)
        else:
            analysis = analyzer.analyze_vulnerability_trend(history)

        echarts = analyzer.to_echarts_config(analysis, chart_type)

        return _ok({
            "metric": metric,
            "analysis": analysis,
            "echarts_config": echarts,
        }, extra={"is_sample": True, "note": "示例数据（无历史数据时自动生成）"})
    except Exception as e:  # noqa: BLE001
        return _err(f"趋势分析失败: {e}")


@router.get("/{assessment_id}/all")
def get_all_visualization(assessment_id: str):
    """获取指定评估的所有可视化数据（攻击路径+拓扑+热力图）。"""
    try:
        # 评估ID仅用于标识，实际数据用示例兜底
        ap_gen = AttackPathGenerator()
        topo_gen = NetworkTopologyGenerator()
        heat_gen = RiskHeatmapGenerator()

        scan = _sample_scan_data()
        topo = _sample_topology_data()

        ap_result = ap_gen.generate(scan)
        topo_result = topo_gen.generate(topo)
        heat_result = heat_gen.generate(scan, "host_port")

        return _ok({
            "assessment_id": assessment_id,
            "attack_path": {
                "graph_data": ap_result,
                "mermaid": ap_gen.to_mermaid(ap_result),
                "graphviz": ap_gen.to_graphviz(ap_result),
            },
            "network_topology": {
                "graph_data": topo_result,
                "mermaid": topo_gen.to_mermaid(topo_result),
            },
            "risk_heatmap": {
                "heatmap_data": heat_result,
                "html": heat_gen.to_html(heat_result),
            },
        }, extra={"is_sample": True, "note": "示例数据（未找到该评估的真实数据）"})
    except Exception as e:  # noqa: BLE001
        return _err(f"获取可视化数据失败: {e}")


@router.get("/formats")
def list_formats():
    """支持的输出格式列表。"""
    try:
        return _ok({
            "formats": [
                {"name": "JSON", "description": "结构化 JSON 数据"},
                {"name": "Mermaid", "description": "Mermaid 流程图语法（可渲染）"},
                {"name": "Graphviz", "description": "Graphviz DOT 格式"},
                {"name": "HTML", "description": "内联样式 HTML 表格"},
                {"name": "CSV", "description": "CSV 矩阵数据"},
                {"name": "ECharts", "description": "ECharts 完整配置"},
            ],
            "dimensions": ["host_port", "vuln_type", "time_risk", "service_vuln"],
            "chart_types": ["line", "bar", "pie", "area"],
        })
    except Exception as e:  # noqa: BLE001
        return _err(f"格式列表查询失败: {e}")
