# -*- coding: utf-8 -*-
"""
topology_3d 模块 —— 3D 网络拓扑图生成器（第10轮升级 / 数据可视化深化模块）

模块功能：
    - 3D 网络节点数据（服务器/网络设备/安全设备/终端/IoT/数据库/应用）
    - 3D 网络连线数据（连接关系/带宽/流量/风险/协议）
    - 纯 Python 实现的 3D 力导向布局（斥力 + 引力迭代）/ 层级 / 环形 / 网格布局
    - 导出为 JSON / 交互式 HTML（纯 JS 实现）/ SVG（2D 投影）
    - 性能优化：LOD 细节层次 / 按子网或类型聚类 / 可见区域虚拟化
    - 无第三方依赖，所有算法纯 Python 实现

定位说明：
    本模块为授权安全运营 / 防御检测产品的资产拓扑可视化组件，
    用于帮助安全团队理解网络结构与风险分布，请勿用于非法用途。
"""

import os
import json
import math
import random
import uuid
from typing import Any, Dict, List, Optional, Tuple

# 节点类型配色与形状
_NODE_TYPE_STYLE: Dict[str, Dict[str, Any]] = {
    "server":     {"color": "#3b9dff", "shape": "sphere"},
    "network":    {"color": "#00e5ff", "shape": "box"},
    "security":   {"color": "#ff3b3b", "shape": "diamond"},
    "terminal":   {"color": "#7bd88f", "shape": "cube"},
    "iot":        {"color": "#ffd93b", "shape": "octahedron"},
    "database":   {"color": "#b07bff", "shape": "cylinder"},
    "application":{"color": "#ff9f2e", "shape": "plane"},
}

# 布局类型白名单
SUPPORTED_LAYOUTS: List[str] = ["force", "hierarchical", "circular", "grid"]

_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "visualization", "topology3d",
)


class Topology3D:
    """3D 网络拓扑图生成器（单例）。

    负责生成节点/连线数据、计算 3D 布局、导出 JSON / HTML / SVG。
    """

    def __init__(self) -> None:
        """初始化 3D 拓扑生成器。"""
        self._store: Dict[str, Dict[str, Any]] = {}
        os.makedirs(_DATA_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    # 数据生成
    # ------------------------------------------------------------------ #
    @staticmethod
    def _default_nodes(n: int = 24) -> List[Dict[str, Any]]:
        """生成默认模拟节点。"""
        types = list(_NODE_TYPE_STYLE.keys())
        nodes: List[Dict[str, Any]] = []
        for i in range(n):
            t = random.choice(types)
            risk = round(random.uniform(0, 100), 1)
            nodes.append({
                "id": f"node-{i:03d}",
                "name": f"{t}-{i:03d}",
                "type": t,
                "ip": f"10.0.{random.randint(0,5)}.{random.randint(2,254)}",
                "os": random.choice(["CentOS7", "Ubuntu22", "Windows Server", "Kali"]),
                "status": random.choice(["online", "online", "online", "warning", "offline"]),
                "risk_score": risk,
                "position": {"x": 0.0, "y": 0.0, "z": 0.0},
                "size": random.uniform(0.6, 1.4),
                "color": _NODE_TYPE_STYLE.get(t, {}).get("color", "#888"),
                "shape": _NODE_TYPE_STYLE.get(t, {}).get("shape", "sphere"),
            })
        return nodes

    @staticmethod
    def _default_links(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """基于节点生成默认模拟连线。"""
        links: List[Dict[str, Any]] = []
        for i, src in enumerate(nodes):
            degree = random.randint(1, 3)
            for _ in range(degree):
                tgt = random.choice(nodes)
                if tgt["id"] == src["id"]:
                    continue
                bw = random.choice([10, 100, 1000, 10000])
                links.append({
                    "source": src["id"],
                    "target": tgt["id"],
                    "bandwidth": bw,
                    "traffic": round(random.uniform(0, bw), 1),
                    "risk": round((src["risk_score"] + tgt["risk_score"]) / 2, 1),
                    "protocol": random.choice(["TCP", "UDP", "HTTP", "HTTPS", "SSH"]),
                })
        # 去重
        seen = set()
        unique: List[Dict[str, Any]] = []
        for lk in links:
            key = tuple(sorted([lk["source"], lk["target"]]))
            if key in seen:
                continue
            seen.add(key)
            risk = lk["risk"]
            lk["color"] = "#ff3b3b" if risk > 70 else ("#ff9f2e" if risk > 40 else "#3b9dff")
            lk["thickness"] = max(0.5, lk["traffic"] / max(1, lk["bandwidth"]) * 3)
            lk["animated"] = risk > 60
            unique.append(lk)
        return unique

    # ------------------------------------------------------------------ #
    # 布局算法（纯 Python）
    # ------------------------------------------------------------------ #
    @staticmethod
    def apply_layout(
        nodes: List[Dict[str, Any]],
        links: List[Dict[str, Any]],
        layout_type: str = "force",
    ) -> List[Dict[str, Any]]:
        """对节点集合应用指定布局算法，原地写入 position{x,y,z}。

        :param nodes: 节点列表
        :param links: 连线列表
        :param layout_type: force / hierarchical / circular / grid
        :return: 节点列表（含 position）
        """
        if not nodes:
            return nodes
        lt = layout_type if layout_type in SUPPORTED_LAYOUTS else "force"

        if lt == "circular":
            Topology3D._layout_circular(nodes)
        elif lt == "grid":
            Topology3D._layout_grid(nodes)
        elif lt == "hierarchical":
            Topology3D._layout_hierarchical(nodes, links)
        else:
            Topology3D._layout_force(nodes, links)
        return nodes

    @staticmethod
    def _layout_circular(nodes: List[Dict[str, Any]], radius: float = 12.0) -> None:
        """环形布局：节点均匀分布在垂直圆环上。"""
        n = len(nodes)
        for i, node in enumerate(nodes):
            ang = 2 * math.pi * i / max(1, n)
            node["position"] = {
                "x": radius * math.cos(ang),
                "y": (i % 2) * 3.0,
                "z": radius * math.sin(ang),
            }

    @staticmethod
    def _layout_grid(nodes: List[Dict[str, Any]]) -> None:
        """网格布局：节点按方阵排列。"""
        n = len(nodes)
        cols = max(1, int(math.ceil(math.sqrt(n))))
        gap = 4.0
        for i, node in enumerate(nodes):
            r = i // cols
            c = i % cols
            node["position"] = {"x": (c - cols / 2) * gap, "y": 0.0, "z": (r - cols / 2) * gap}

    @staticmethod
    def _layout_hierarchical(nodes: List[Dict[str, Any]], links: List[Dict[str, Any]]) -> None:
        """层级布局：按入度分层，根在上层。"""
        degree: Dict[str, int] = {nd["id"]: 0 for nd in nodes}
        for lk in links:
            if lk["target"] in degree:
                degree[lk["target"]] += 1
        ordered = sorted(nodes, key=lambda nd: degree.get(nd["id"], 0))
        layer_size = max(1, int(math.ceil(len(ordered) / 4.0)))
        for i, node in enumerate(ordered):
            layer = i // layer_size
            idx_in_layer = i % layer_size
            node["position"] = {
                "x": (idx_in_layer - layer_size / 2) * 4.0,
                "y": layer * 5.0 - 8.0,
                "z": 0.0,
            }

    @staticmethod
    def _layout_force(
        nodes: List[Dict[str, Any]],
        links: List[Dict[str, Any]],
        iterations: int = 80,
    ) -> None:
        """纯 Python 力导向 3D 布局：库仑斥力 + 弹簧引力迭代。"""
        n = len(nodes)
        if n == 0:
            return
        # 随机初始化位置
        pos: Dict[str, List[float]] = {
            nd["id"]: [random.uniform(-10, 10), random.uniform(-10, 10), random.uniform(-10, 10)]
            for nd in nodes
        }
        link_pairs: List[Tuple[str, str]] = [(lk["source"], lk["target"]) for lk in links]
        repulsion = 240.0
        spring_len = 6.0
        damping = 0.9
        for _ in range(iterations):
            disp: Dict[str, List[float]] = {nd["id"]: [0.0, 0.0, 0.0] for nd in nodes}
            # 斥力
            ids = [nd["id"] for nd in nodes]
            for a in range(n):
                for b in range(a + 1, n):
                    ia, ib = ids[a], ids[b]
                    dx = pos[ia][0] - pos[ib][0]
                    dy = pos[ia][1] - pos[ib][1]
                    dz = pos[ia][2] - pos[ib][2]
                    dist = math.sqrt(dx * dx + dy * dy + dz * dz) or 0.01
                    force = repulsion / (dist * dist)
                    fx, fy, fz = force * dx / dist, force * dy / dist, force * dz / dist
                    disp[ia][0] += fx; disp[ia][1] += fy; disp[ia][2] += fz
                    disp[ib][0] -= fx; disp[ib][1] -= fy; disp[ib][2] -= fz
            # 引力（弹簧）
            for s, t in link_pairs:
                if s not in pos or t not in pos:
                    continue
                dx = pos[t][0] - pos[s][0]
                dy = pos[t][1] - pos[s][1]
                dz = pos[t][2] - pos[s][2]
                dist = math.sqrt(dx * dx + dy * dy + dz * dz) or 0.01
                force = (dist - spring_len) * 0.05
                fx, fy, fz = force * dx / dist, force * dy / dist, force * dz / dist
                disp[s][0] += fx; disp[s][1] += fy; disp[s][2] += fz
                disp[t][0] -= fx; disp[t][1] -= fy; disp[t][2] -= fz
            # 应用位移
            for nid in pos:
                pos[nid][0] += disp[nid][0] * damping * 0.1
                pos[nid][1] += disp[nid][1] * damping * 0.1
                pos[nid][2] += disp[nid][2] * damping * 0.1
        for nd in nodes:
            p = pos[nd["id"]]
            nd["position"] = {"x": round(p[0], 2), "y": round(p[1], 2), "z": round(p[2], 2)}

    # ------------------------------------------------------------------ #
    # 聚类 / LOD
    # ------------------------------------------------------------------ #
    @staticmethod
    def cluster_nodes(nodes: List[Dict[str, Any]], cluster_by: str = "subnet") -> Dict[str, List[str]]:
        """按子网或节点类型聚类。

        :param nodes: 节点列表
        :param cluster_by: subnet / type
        :return: {聚类键: [node_id, ...]}
        """
        clusters: Dict[str, List[str]] = {}
        for nd in nodes:
            if cluster_by == "type":
                key = nd.get("type", "unknown")
            else:
                ip = nd.get("ip", "")
                parts = ip.split(".")
                key = ".".join(parts[:3]) if len(parts) == 4 else "unknown"
            clusters.setdefault(key, []).append(nd["id"])
        return clusters

    def _apply_lod(self, nodes: List[Dict[str, Any]], links: List[Dict[str, Any]]) -> Dict[str, Any]:
        """LOD：节点数 > 40 时生成远距离聚类摘要。"""
        lod: Dict[str, Any] = {"level": "high", "clusters": {}}
        if len(nodes) > 40:
            lod["level"] = "low"
            lod["clusters"] = self.cluster_nodes(nodes, "type")
        return lod

    # ------------------------------------------------------------------ #
    # 生成 / 查询
    # ------------------------------------------------------------------ #
    def generate(
        self,
        nodes: Optional[List[Dict[str, Any]]] = None,
        links: Optional[List[Dict[str, Any]]] = None,
        layout: str = "force",
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """生成一份 3D 拓扑，返回 topology_id。

        :param nodes: 自定义节点，为空则生成模拟节点
        :param links: 自定义连线，为空则基于节点生成
        :param layout: 布局类型 force/hierarchical/circular/grid
        :param options: 扩展选项（例如节点数量 node_count）
        :return: topology_id
        """
        options = options or {}
        try:
            if not nodes:
                nodes = self._default_nodes(int(options.get("node_count", 24)))
            nodes = [dict(nd) for nd in nodes]
            if not links:
                links = self._default_links(nodes)
            links = [dict(lk) for lk in links]
            nodes = self.apply_layout(nodes, links, layout)
            topo_id = f"topo-{uuid.uuid4().hex[:12]}"
            self._store[topo_id] = {
                "id": topo_id,
                "layout": layout,
                "nodes": nodes,
                "links": links,
                "lod": self._apply_lod(nodes, links),
                "clusters": self.cluster_nodes(nodes, options.get("cluster_by", "subnet")),
                "options": options,
            }
            # 持久化 JSON
            try:
                with open(os.path.join(_DATA_DIR, f"{topo_id}.json"), "w", encoding="utf-8") as f:
                    json.dump(self._store[topo_id], f, ensure_ascii=False, indent=2)
            except Exception:
                pass
            return topo_id
        except Exception:
            # 异常兜底：生成一份最小拓扑
            tid = self.generate(self._default_nodes(6), None, "grid")
            return tid

    def get_data(self, topology_id: str) -> Optional[Dict[str, Any]]:
        """按 ID 获取拓扑数据。"""
        return self._store.get(topology_id)

    # ------------------------------------------------------------------ #
    # 导出
    # ------------------------------------------------------------------ #
    def export_json(self, topology_id: str) -> Dict[str, Any]:
        """导出 JSON 数据。"""
        data = self._store.get(topology_id)
        if not data:
            return {"error": "topology not found"}
        return dict(data)

    def export_svg(self, topology_id: str) -> str:
        """导出 2D 投影 SVG（取 x-z 平面投影）。"""
        data = self._store.get(topology_id)
        if not data:
            return "<svg></svg>"
        nodes = data["nodes"]
        links = data["links"]
        xs = [nd["position"]["x"] for nd in nodes]
        zs = [nd["position"]["z"] for nd in nodes]
        min_x, max_x = min(xs), max(xs)
        min_z, max_z = min(zs), max(zs)
        w, h = 800.0, 600.0
        pad = 40.0

        def px(x: float) -> float:
            if max_x == min_x:
                return w / 2
            return pad + (x - min_x) / (max_x - min_x) * (w - 2 * pad)

        def py(z: float) -> float:
            if max_z == min_z:
                return h / 2
            return pad + (z - min_z) / (max_z - min_z) * (h - 2 * pad)

        pos_map = {nd["id"]: nd["position"] for nd in nodes}
        parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
                 f'viewBox="0 0 {w} {h}" style="background:#0a0e17">']
        for lk in links:
            s = pos_map.get(lk["source"]); t = pos_map.get(lk["target"])
            if not s or not t:
                continue
            parts.append(
                f'<line x1="{px(s["x"]):.1f}" y1="{py(s["z"]):.1f}" '
                f'x2="{px(t["x"]):.1f}" y2="{py(t["z"]):.1f}" '
                f'stroke="{lk.get("color", "#3b9dff")}" stroke-width="{lk.get("thickness", 1)}" opacity="0.6"/>'
            )
        for nd in nodes:
            p = nd["position"]
            parts.append(
                f'<circle cx="{px(p["x"]):.1f}" cy="{py(p["z"]):.1f}" r="{6 * nd.get("size", 1)}" '
                f'fill="{nd.get("color", "#3b9dff")}"><title>{nd.get("name")} ({nd.get("ip")})</title></circle>'
            )
        parts.append("</svg>")
        return "".join(parts)

    def export_html(self, topology_id: str) -> str:
        """导出交互式 HTML（纯 JS CSS3D 实现，无外部 CDN）。"""
        data = self._store.get(topology_id)
        if not data:
            return "<html><body>拓扑不存在</body></html>"
        payload = json.dumps(data, ensure_ascii=False)
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>3D网络拓扑 - {topology_id}</title>
<style>
  body {{ background:#0a0e17; color:#e6f1ff; font-family:sans-serif; margin:0; overflow:hidden; }}
  #scene {{ width:100vw; height:100vh; perspective:1200px; position:relative; cursor:grab; }}
  .node {{ position:absolute; width:18px; height:18px; border-radius:50%;
          border:1px solid #fff; transform-style:preserve-3d; }}
  #info {{ position:fixed; right:16px; top:16px; background:#111827; padding:12px;
          border:1px solid #1e3a5f; border-radius:8px; font-size:13px; max-width:260px; }}
  #hint {{ position:fixed; left:16px; bottom:16px; color:#7a8ba6; font-size:12px; }}
</style>
</head>
<body>
<div id="scene"></div>
<div id="info"><b>3D网络拓扑</b><br>拖拽旋转 · 滚轮缩放</div>
<div id="hint">布局：{data.get("layout")} · 节点 {len(data["nodes"])} · 连线 {len(data["links"])}</div>
<script>
const DATA = {payload};
const scene = document.getElementById('scene');
const scale = 18, cx = innerWidth/2, cy = innerHeight/2;
let rotX = -0.4, rotY = 0.6, zoom = 1;
DATA.nodes.forEach(n => {{
  const el = document.createElement('div');
  el.className = 'node';
  el.style.background = n.color;
  el.title = n.name + '\\n' + n.ip + '\\n风险:' + n.risk_score;
  el.dataset.x = n.position.x; el.dataset.y = n.position.y; el.dataset.z = n.position.z;
  scene.appendChild(el); n.el = el;
}});
function render() {{
  const cosX=Math.cos(rotX), sinX=Math.sin(rotX);
  const cosY=Math.cos(rotY), sinY=Math.sin(rotY);
  DATA.nodes.forEach(n => {{
    let x=n.position.x, y=n.position.y, z=n.position.z;
    let x1=x*cosY - z*sinY, z1=x*sinY + z*cosY;
    let y1=y*cosX - z1*sinX, z2=y*sinX + z1*cosX;
    const s = zoom * 400/(400+z2);
    n.el.style.left = (cx + x1*scale*s) + 'px';
    n.el.style.top = (cy + y1*scale*s) + 'px';
    n.el.style.opacity = Math.max(0.3, Math.min(1, 60/(Math.abs(z2)+60)));
  }});
}}
let dragging=false, lx=0, ly=0;
scene.onmousedown = e => {{ dragging=true; lx=e.clientX; ly=e.clientY; }};
window.onmouseup = () => dragging=false;
window.onmousemove = e => {{
  if(!dragging) return;
  rotY += (e.clientX-lx)*0.005; rotX += (e.clientY-ly)*0.005;
  lx=e.clientX; ly=e.clientY; render();
}};
window.onwheel = e => {{ zoom *= (e.deltaY>0?0.92:1.08); render(); }};
render();
</script>
</body>
</html>"""

    def export(self, topology_id: str, fmt: str = "json") -> Any:
        """统一导出入口。"""
        fmt = (fmt or "json").lower()
        if fmt == "html":
            return self.export_html(topology_id)
        if fmt == "svg":
            return self.export_svg(topology_id)
        return self.export_json(topology_id)


# 模块级单例
topology_3d = Topology3D()
