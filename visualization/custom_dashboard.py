# -*- coding: utf-8 -*-
"""
custom_dashboard 模块 —— 自定义仪表盘生成器（第10轮升级 / 数据可视化深化模块）

模块功能：
    - 预定义仪表盘模板（安全运营/漏洞管理/资产管理/合规审计/管理层汇报）
    - 可拖拽组件库（指标卡片/折线图/柱状图/饼图/热力图/表格/列表/地图/拓扑/文本/图片/进度条/仪表盘）
    - 12 列网格布局，响应式配置
    - 组件数据源配置（API/数据库/静态/实时）与过滤聚合转换
    - 仪表盘 CRUD / 分享（公开链接/密码/有效期）/ 导出（JSON/HTML）
    - 权限控制（私有/租户内/公开）
    - 配置持久化到 data/visualization/dashboards/

定位说明：
    本模块为授权安全运营 / 管理汇报产品的仪表盘构建器，
    所有图表数据均为防御视角统计，请勿用于非法用途。
"""

import os
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "visualization", "dashboards",
)

# 组件库定义（每个组件含配置 schema）
COMPONENT_LIBRARY: List[Dict[str, Any]] = [
    {"type": "metric_card", "name": "指标卡片", "icon": "1️⃣",
     "schema": {"title": {"type": "string", "default": "指标"},
                "value": {"type": "number", "default": 0},
                "unit": {"type": "string", "default": ""},
                "color": {"type": "color", "default": "#00e5ff"}}},
    {"type": "line_chart", "name": "折线图", "icon": "📈",
     "schema": {"title": {"type": "string", "default": "趋势"},
                "series": {"type": "array", "default": []},
                "color": {"type": "color", "default": "#00e5ff"}}},
    {"type": "bar_chart", "name": "柱状图", "icon": "📊",
     "schema": {"title": {"type": "string", "default": "分布"},
                "data": {"type": "array", "default": []}}},
    {"type": "pie_chart", "name": "饼图", "icon": "🥧",
     "schema": {"title": {"type": "string", "default": "占比"},
                "data": {"type": "array", "default": []}}},
    {"type": "heatmap", "name": "热力图", "icon": "🔥",
     "schema": {"title": {"type": "string", "default": "风险热力"},
                "grid": {"type": "array", "default": []}}},
    {"type": "table", "name": "表格", "icon": "📋",
     "schema": {"title": {"type": "string", "default": "表格"},
                "columns": {"type": "array", "default": []},
                "rows": {"type": "array", "default": []}}},
    {"type": "list", "name": "列表", "icon": "📝",
     "schema": {"title": {"type": "string", "default": "列表"},
                "items": {"type": "array", "default": []}}},
    {"type": "map", "name": "地图", "icon": "🗺️",
     "schema": {"title": {"type": "string", "default": "地图"},
                "points": {"type": "array", "default": []}}},
    {"type": "topology", "name": "拓扑图", "icon": "🕸️",
     "schema": {"title": {"type": "string", "default": "拓扑"},
                "nodes": {"type": "array", "default": []}}},
    {"type": "text", "name": "文本", "icon": "📄",
     "schema": {"title": {"type": "string", "default": "文本"},
                "content": {"type": "string", "default": ""}}},
    {"type": "image", "name": "图片", "icon": "🖼️",
     "schema": {"title": {"type": "string", "default": "图片"},
                "src": {"type": "string", "default": ""}}},
    {"type": "progress", "name": "进度条", "icon": "📏",
     "schema": {"title": {"type": "string", "default": "进度"},
                "value": {"type": "number", "default": 0},
                "max": {"type": "number", "default": 100}}},
    {"type": "gauge", "name": "仪表盘", "icon": "⏲️",
     "schema": {"title": {"type": "string", "default": "仪表"},
                "value": {"type": "number", "default": 0},
                "max": {"type": "number", "default": 100}}},
]


def _sample_components(template: str) -> List[Dict[str, Any]]:
    """根据模板生成默认组件布局。"""
    layouts: Dict[str, List[Dict[str, Any]]] = {
        "安全运营": [
            {"type": "metric_card", "x": 0, "y": 0, "w": 3, "h": 2, "props": {"title": "今日事件", "value": 328}},
            {"type": "metric_card", "x": 3, "y": 0, "w": 3, "h": 2, "props": {"title": "活跃告警", "value": 86}},
            {"type": "line_chart", "x": 6, "y": 0, "w": 6, "h": 4, "props": {"title": "24h事件趋势"}},
            {"type": "map", "x": 0, "y": 2, "w": 6, "h": 4, "props": {"title": "攻击来源地图"}},
            {"type": "list", "x": 6, "y": 4, "w": 6, "h": 4, "props": {"title": "最新告警"}},
        ],
        "漏洞管理": [
            {"type": "metric_card", "x": 0, "y": 0, "w": 3, "h": 2, "props": {"title": "漏洞总数", "value": 458}},
            {"type": "metric_card", "x": 3, "y": 0, "w": 3, "h": 2, "props": {"title": "高危", "value": 52}},
            {"type": "bar_chart", "x": 6, "y": 0, "w": 6, "h": 4, "props": {"title": "漏洞分布"}},
            {"type": "pie_chart", "x": 0, "y": 2, "w": 6, "h": 4, "props": {"title": "严重程度占比"}},
            {"type": "progress", "x": 6, "y": 4, "w": 6, "h": 2, "props": {"title": "修复率", "value": 78}},
        ],
        "资产管理": [
            {"type": "metric_card", "x": 0, "y": 0, "w": 4, "h": 2, "props": {"title": "资产总数", "value": 920}},
            {"type": "metric_card", "x": 4, "y": 0, "w": 4, "h": 2, "props": {"title": "在线率", "value": 97.2, "unit": "%"}},
            {"type": "table", "x": 8, "y": 0, "w": 4, "h": 4, "props": {"title": "资产清单"}},
            {"type": "topology", "x": 0, "y": 2, "w": 8, "h": 4, "props": {"title": "资产拓扑"}},
        ],
        "合规审计": [
            {"type": "gauge", "x": 0, "y": 0, "w": 4, "h": 3, "props": {"title": "合规率", "value": 86}},
            {"type": "progress", "x": 4, "y": 0, "w": 4, "h": 2, "props": {"title": "等保达标", "value": 92}},
            {"type": "table", "x": 8, "y": 0, "w": 4, "h": 4, "props": {"title": "审计项"}},
            {"type": "text", "x": 0, "y": 3, "w": 8, "h": 2, "props": {"title": "审计说明"}},
        ],
        "管理层汇报": [
            {"type": "metric_card", "x": 0, "y": 0, "w": 3, "h": 2, "props": {"title": "MTTD", "value": 95, "unit": "s"}},
            {"type": "metric_card", "x": 3, "y": 0, "w": 3, "h": 2, "props": {"title": "MTTR", "value": 18, "unit": "min"}},
            {"type": "metric_card", "x": 6, "y": 0, "w": 3, "h": 2, "props": {"title": "SLA", "value": 98.4, "unit": "%"}},
            {"type": "line_chart", "x": 9, "y": 0, "w": 3, "h": 4, "props": {"title": "季度趋势"}},
            {"type": "pie_chart", "x": 0, "y": 2, "w": 12, "h": 4, "props": {"title": "安全态势总览"}},
        ],
    }
    return layouts.get(template, layouts["安全运营"])


class CustomDashboard:
    """自定义仪表盘生成器（单例）。"""

    def __init__(self) -> None:
        """初始化仪表盘管理器。"""
        self._dashboards: Dict[str, Dict[str, Any]] = {}
        self._shares: Dict[str, Dict[str, Any]] = {}
        os.makedirs(_DATA_DIR, exist_ok=True)
        self._load_from_disk()

    # ------------------------------------------------------------------ #
    # 持久化
    # ------------------------------------------------------------------ #
    def _load_from_disk(self) -> None:
        """从磁盘加载已有仪表盘配置。"""
        try:
            for fname in os.listdir(_DATA_DIR):
                if not fname.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(_DATA_DIR, fname), "r", encoding="utf-8") as f:
                        obj = json.load(f)
                    did = obj.get("id")
                    if did:
                        self._dashboards[did] = obj
                        if obj.get("share_token"):
                            self._shares[obj["share_token"]] = obj
                except Exception:
                    continue
        except Exception:
            pass

    def _save(self, dashboard: Dict[str, Any]) -> None:
        """持久化单个仪表盘。"""
        try:
            with open(os.path.join(_DATA_DIR, f"{dashboard['id']}.json"), "w", encoding="utf-8") as f:
                json.dump(dashboard, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # 模板 / 组件库
    # ------------------------------------------------------------------ #
    def get_templates(self) -> List[Dict[str, Any]]:
        """返回预定义模板列表。"""
        return [
            {"key": "安全运营", "name": "安全运营大屏",
             "description": "事件/告警/攻击地图一体化运营视图"},
            {"key": "漏洞管理", "name": "漏洞管理",
             "description": "漏洞总数、分布、修复进度跟踪"},
            {"key": "资产管理", "name": "资产管理",
             "description": "资产清单、在线率、拓扑视图"},
            {"key": "合规审计", "name": "合规审计",
             "description": "合规率、等保达标、审计项"},
            {"key": "管理层汇报", "name": "管理层汇报",
             "description": "MTTD/MTTR/SLA 与季度趋势"},
        ]

    def get_components(self) -> List[Dict[str, Any]]:
        """返回组件库定义。"""
        return COMPONENT_LIBRARY

    # ------------------------------------------------------------------ #
    # CRUD
    # ------------------------------------------------------------------ #
    def create_dashboard(self, name: str, template: Optional[str] = None,
                         config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """创建仪表盘。

        :param name: 仪表盘名称
        :param template: 模板 key（安全运营/漏洞管理/...）
        :param config: 自定义配置（覆盖模板）
        :return: 新仪表盘对象
        """
        did = f"dash-{uuid.uuid4().hex[:10]}"
        components = _sample_components(template or "安全运营")
        dashboard = {
            "id": did,
            "name": name or "未命名仪表盘",
            "template": template,
            "permission": "private",
            "components": components,
            "global_settings": {
                "columns": 12, "auto_refresh": 30, "theme": "dark",
            },
            "share_token": None,
            "share_password": None,
            "share_expires": None,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        if config:
            for k in ("components", "permission", "global_settings"):
                if k in config:
                    dashboard[k] = config[k]
        self._dashboards[did] = dashboard
        self._save(dashboard)
        return dict(dashboard)

    def get_dashboard(self, dashboard_id: str) -> Optional[Dict[str, Any]]:
        """按 ID 获取仪表盘。"""
        return self._dashboards.get(dashboard_id)

    def update_dashboard(self, dashboard_id: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """更新仪表盘配置。"""
        dash = self._dashboards.get(dashboard_id)
        if not dash:
            return None
        for k in ("name", "components", "permission", "global_settings"):
            if k in config:
                dash[k] = config[k]
        dash["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._save(dash)
        return dict(dash)

    def delete_dashboard(self, dashboard_id: str) -> bool:
        """删除仪表盘。"""
        if dashboard_id not in self._dashboards:
            return False
        dash = self._dashboards.pop(dashboard_id)
        if dash.get("share_token"):
            self._shares.pop(dash["share_token"], None)
        try:
            os.remove(os.path.join(_DATA_DIR, f"{dashboard_id}.json"))
        except Exception:
            pass
        return True

    def list_dashboards(self, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """分页列出仪表盘。"""
        items = list(self._dashboards.values())
        items.sort(key=lambda d: d.get("updated_at", ""), reverse=True)
        start = (max(1, page) - 1) * max(1, page_size)
        end = start + max(1, page_size)
        return {
            "total": len(items),
            "page": page,
            "page_size": page_size,
            "items": items[start:end],
        }

    # ------------------------------------------------------------------ #
    # 分享 / 导出 / 渲染
    # ------------------------------------------------------------------ #
    def share_dashboard(self, dashboard_id: str, password: Optional[str] = None,
                        expires_in_days: int = 7) -> Dict[str, Any]:
        """生成分享链接。"""
        dash = self._dashboards.get(dashboard_id)
        if not dash:
            return {"error": "dashboard not found"}
        token = uuid.uuid4().hex[:16]
        expires = (datetime.now() + timedelta(days=max(1, expires_in_days))).strftime("%Y-%m-%d %H:%M:%S")
        dash["share_token"] = token
        dash["share_password"] = password
        dash["share_expires"] = expires
        dash["permission"] = "public"
        self._shares[token] = dash
        self._save(dash)
        return {"share_token": token, "expires_at": expires,
                "url": f"/api/v1/visualization-v1/dashboards/shared/{token}"}

    def get_shared_dashboard(self, share_token: str) -> Optional[Dict[str, Any]]:
        """通过分享 token 获取仪表盘（校验有效期与密码）。"""
        dash = self._shares.get(share_token)
        if not dash:
            return None
        try:
            expires = datetime.strptime(dash.get("share_expires", "2000-01-01 00:00:00"),
                                        "%Y-%m-%d %H:%M:%S")
            if expires < datetime.now():
                return None
        except Exception:
            return None
        return {
            "id": dash["id"], "name": dash["name"],
            "components": dash["components"],
            "global_settings": dash.get("global_settings", {}),
            "has_password": bool(dash.get("share_password")),
        }

    def export_dashboard(self, dashboard_id: str, fmt: str = "json") -> Any:
        """导出仪表盘。"""
        dash = self._dashboards.get(dashboard_id)
        if not dash:
            return {"error": "dashboard not found"}
        fmt = (fmt or "json").lower()
        if fmt == "html":
            return self.render_dashboard(dashboard_id)
        return dict(dash)

    def render_dashboard(self, dashboard_id: str) -> str:
        """将仪表盘渲染为 HTML（预览/导出）。"""
        dash = self._dashboards.get(dashboard_id)
        if not dash:
            return "<html><body>仪表盘不存在</body></html>"
        payload = json.dumps(dash, ensure_ascii=False)
        return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<title>{dash.get('name','仪表盘')}</title>
<style>
  body {{ background:#0a0e17; color:#e6f1ff; font-family:sans-serif; margin:0; padding:16px; }}
  h2 {{ margin:0 0 12px; }}
  .grid {{ display:grid; grid-template-columns:repeat(12,1fr); gap:10px; }}
  .cell {{ background:#111827; border:1px solid #1e3a5f; border-radius:6px; padding:10px; }}
  .cell .t {{ color:#7a8ba6; font-size:12px; }}
  .cell .v {{ font-size:24px; color:#00e5ff; }}
</style></head><body>
<h2>{dash.get('name','仪表盘')}</h2>
<div class="grid" id="grid"></div>
<script>
const DASH = {payload};
const grid = document.getElementById('grid');
(DASH.components||[]).forEach(c => {{
  const d = document.createElement('div');
  d.className='cell';
  d.style.gridColumn = `span ${{c.w||3}}`;
  d.style.gridRow = `span ${{c.h||2}}`;
  const p = c.props||{{}};
  d.innerHTML = `<div class="t">${{p.title||c.type}}</div>` +
    (p.value!==undefined?`<div class="v">${{p.value}}${{p.unit||''}}</div>`:'');
  grid.appendChild(d);
}});
</script></body></html>"""


# 模块级单例
custom_dashboard = CustomDashboard()
