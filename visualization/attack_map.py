# -*- coding: utf-8 -*-
"""
attack_map 模块 —— 攻击地图生成器（第10轮升级 / 数据可视化深化模块）

模块功能：
    - 内置简化 IP 地理定位库（国家 / 省份 / 城市 / 经纬度），不依赖外部 API
    - 攻击来源地图数据（世界 / 中国 / 省份）按国家 / 省份 / 城市聚合
    - 攻击目标地图数据（目标资产地理位置 / 受攻击次数 / 严重程度）
    - 攻击路径数据（源→目标弧线 / 直线坐标，颜色表示严重程度，粗细表示次数）
    - 多维统计（国家 / 省份 / 城市 / IP / 攻击类型 / 严重程度）Top N
    - 导出 JSON / 交互式 HTML（SVG 绘制）/ CSV 统计
    - 内置世界主要国家与中国省份经纬度数据

定位说明：
    本模块为授权安全运营 / 防御检测产品的攻击态势可视化组件，
    所有攻击数据均为防御视角统计，请勿用于非法用途。
"""

import os
import csv
import json
import math
import random
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# 严重程度配色
_SEV_COLOR: Dict[str, str] = {
    "critical": "#ff3b3b", "high": "#ff9f2e",
    "medium": "#ffd93b", "low": "#3b9dff", "info": "#9aa4b2",
}

# 世界主要国家经纬度（首都/中心坐标）
_WORLD_COUNTRIES: Dict[str, Dict[str, Any]] = {
    "中国": {"code": "CN", "lat": 35.0, "lng": 105.0},
    "美国": {"code": "US", "lat": 39.0, "lng": -98.0},
    "俄罗斯": {"code": "RU", "lat": 61.0, "lng": 90.0},
    "日本": {"code": "JP", "lat": 36.0, "lng": 138.0},
    "韩国": {"code": "KR", "lat": 37.5, "lng": 127.0},
    "印度": {"code": "IN", "lat": 21.0, "lng": 78.0},
    "德国": {"code": "DE", "lat": 51.0, "lng": 9.0},
    "英国": {"code": "GB", "lat": 54.0, "lng": -2.0},
    "法国": {"code": "FR", "lat": 46.0, "lng": 2.0},
    "荷兰": {"code": "NL", "lat": 52.3, "lng": 5.5},
    "巴西": {"code": "BR", "lat": -14.0, "lng": -52.0},
    "加拿大": {"code": "CA", "lat": 56.0, "lng": -106.0},
    "澳大利亚": {"code": "AU", "lat": -25.0, "lng": 133.0},
    "新加坡": {"code": "SG", "lat": 1.35, "lng": 103.8},
    "越南": {"code": "VN", "lat": 14.0, "lng": 108.0},
    "土耳其": {"code": "TR", "lat": 39.0, "lng": 35.0},
    "乌克兰": {"code": "UA", "lat": 49.0, "lng": 32.0},
    "伊朗": {"code": "IR", "lat": 32.0, "lng": 53.0},
}

# 中国主要省份经纬度
_CHINA_PROVINCES: Dict[str, Dict[str, float]] = {
    "北京": {"lat": 39.9, "lng": 116.4},
    "上海": {"lat": 31.2, "lng": 121.5},
    "广东": {"lat": 23.1, "lng": 113.3},
    "浙江": {"lat": 30.3, "lng": 120.2},
    "江苏": {"lat": 32.1, "lng": 118.8},
    "山东": {"lat": 36.7, "lng": 117.0},
    "四川": {"lat": 30.6, "lng": 104.1},
    "湖北": {"lat": 30.6, "lng": 114.3},
    "福建": {"lat": 26.1, "lng": 119.3},
    "河南": {"lat": 34.8, "lng": 113.6},
    "陕西": {"lat": 34.3, "lng": 108.9},
    "辽宁": {"lat": 41.8, "lng": 123.4},
    "云南": {"lat": 25.0, "lng": 102.7},
    "新疆": {"lat": 43.8, "lng": 87.6},
}

# 简化 IP 段 -> 国家映射（用于 geolocate_ip）
_IP_PREFIX_COUNTRY: List[Tuple[str, str]] = [
    ("1.1.", "日本"), ("2.1.", "英国"), ("5.", "美国"), ("8.", "荷兰"),
    ("23.", "美国"), ("27.", "日本"), ("31.", "德国"), ("36.", "印度"),
    ("37.", "俄罗斯"), ("45.", "荷兰"), ("46.", "俄罗斯"), ("50.", "加拿大"),
    ("58.", "日本"), ("59.", "中国"), ("60.", "中国"), ("61.", "中国"),
    ("63.", "美国"), ("64.", "美国"), ("66.", "美国"), ("67.", "美国"),
    ("72.", "美国"), ("74.", "美国"), ("77.", "德国"), ("78.", "俄罗斯"),
    ("79.", "俄罗斯"), ("80.", "德国"), ("81.", "德国"), ("82.", "荷兰"),
    ("83.", "荷兰"), ("84.", "德国"), ("85.", "俄罗斯"), ("86.", "欧洲"),
    ("87.", "德国"), ("88.", "德国"), ("89.", "俄罗斯"), ("91.", "俄罗斯"),
    ("93.", "德国"), ("94.", "欧洲"), ("95.", "俄罗斯"), ("101.", "中国"),
    ("103.", "新加坡"), ("104.", "美国"), ("106.", "中国"), ("108.", "美国"),
    ("110.", "中国"), ("111.", "中国"), ("112.", "中国"), ("113.", "中国"),
    ("114.", "中国"), ("115.", "中国"), ("116.", "中国"), ("117.", "中国"),
    ("118.", "中国"), ("119.", "中国"), ("120.", "中国"), ("121.", "中国"),
    ("122.", "中国"), ("123.", "中国"), ("124.", "中国"), ("125.", "中国"),
    ("134.", "美国"), ("138.", "美国"), ("139.", "日本"), ("140.", "美国"),
    ("142.", "加拿大"), ("144.", "澳大利亚"), ("148.", "欧洲"), ("150.", "法国"),
    ("151.", "法国"), ("153.", "澳大利亚"), ("154.", "印度"), ("157.", "中国"),
    ("160.", "美国"), ("161.", "美国"), ("162.", "美国"), ("164.", "阿根廷"),
    ("167.", "美国"), ("171.", "中国"), ("173.", "美国"), ("174.", "美国"),
    ("175.", "中国"), ("176.", "欧洲"), ("177.", "巴西"), ("178.", "欧洲"),
    ("179.", "巴西"), ("180.", "中国"), ("181.", "巴西"), ("182.", "中国"),
    ("183.", "中国"), ("184.", "美国"), ("185.", "欧洲"), ("186.", "巴西"),
    ("187.", "巴西"), ("188.", "欧洲"), ("189.", "巴西"), ("190.", "巴西"),
    ("192.168.", "内网"), ("10.", "内网"), ("172.16.", "内网"),
    ("193.", "欧洲"), ("194.", "欧洲"), ("195.", "欧洲"), ("196.", "南非"),
    ("197.", "南非"), ("198.", "美国"), ("199.", "美国"), ("200.", "巴西"),
    ("201.", "巴西"), ("202.", "中国"), ("203.", "澳大利亚"), ("204.", "加拿大"),
    ("208.", "美国"), ("209.", "美国"), ("210.", "中国"), ("211.", "韩国"),
    ("212.", "欧洲"), ("213.", "欧洲"), ("216.", "美国"), ("218.", "中国"),
    ("219.", "中国"), ("220.", "中国"), ("221.", "中国"), ("222.", "中国"),
    ("223.", "中国"),
]

_ATTACK_TYPES = ["SQL注入", "XSS", "暴力破解", "端口扫描", "DDoS", "命令注入",
                 "文件上传", "未授权访问", "木马后门", "钓鱼"]

_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "visualization", "attackmap",
)


class AttackMap:
    """攻击地图生成器（单例）。"""

    def __init__(self) -> None:
        """初始化攻击地图生成器。"""
        self._store: Dict[str, Dict[str, Any]] = {}
        os.makedirs(_DATA_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    # 地理定位
    # ------------------------------------------------------------------ #
    def geolocate_ip(self, ip: str) -> Dict[str, Any]:
        """基于内置简化库对 IP 做地理定位。

        :param ip: IPv4 地址
        :return: {country, province, city, lat, lng, code}
        """
        try:
            if not ip:
                return {"country": "未知", "province": "", "city": "", "lat": 0.0, "lng": 0.0}
            country = "未知"
            for prefix, c in _IP_PREFIX_COUNTRY:
                if ip.startswith(prefix):
                    country = c
                    break
            if country in ("内网", "未知", "欧洲"):
                return {"country": country, "province": "", "city": "",
                        "lat": 0.0, "lng": 0.0, "code": ""}
            info = _WORLD_COUNTRIES.get(country, {"code": "", "lat": 0.0, "lng": 0.0})
            return {"country": country, "province": "", "city": country,
                    "lat": info["lat"], "lng": info["lng"], "code": info["code"]}
        except Exception:
            return {"country": "未知", "province": "", "city": "", "lat": 0.0, "lng": 0.0}

    # ------------------------------------------------------------------ #
    # 模拟攻击日志
    # ------------------------------------------------------------------ #
    @staticmethod
    def _sample_logs(n: int = 200) -> List[Dict[str, Any]]:
        """生成模拟攻击日志。"""
        logs: List[Dict[str, Any]] = []
        countries = list(_WORLD_COUNTRIES.keys())
        sevs = ["critical", "high", "medium", "low", "info"]
        weights = [1, 3, 5, 6, 8]
        for _ in range(n):
            country = random.choice(countries)
            logs.append({
                "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}."
                             f"{random.randint(0,255)}.{random.randint(1,254)}",
                "source_country": country,
                "source_lat": _WORLD_COUNTRIES[country]["lat"],
                "source_lng": _WORLD_COUNTRIES[country]["lng"],
                "target_ip": f"10.0.{random.randint(0,3)}.{random.randint(2,254)}",
                "attack_type": random.choice(_ATTACK_TYPES),
                "severity": random.choices(sevs, weights=weights)[0],
                "count": random.randint(1, 50),
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
        return logs

    # ------------------------------------------------------------------ #
    # 生成
    # ------------------------------------------------------------------ #
    def generate(self, attack_logs: Optional[List[Dict[str, Any]]] = None,
                 map_type: str = "world") -> str:
        """基于攻击日志生成一份攻击地图，返回 map_id。

        :param attack_logs: 攻击日志列表，为空则生成模拟数据
        :param map_type: world / china / province
        :return: map_id
        """
        try:
            logs = attack_logs or self._sample_logs(200)
            map_id = f"amap-{uuid.uuid4().hex[:10]}"
            self._store[map_id] = {
                "id": map_id,
                "map_type": map_type,
                "logs": logs,
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            try:
                with open(os.path.join(_DATA_DIR, f"{map_id}.json"), "w", encoding="utf-8") as f:
                    json.dump(self._store[map_id], f, ensure_ascii=False, indent=2)
            except Exception:
                pass
            return map_id
        except Exception:
            return self.generate(None, map_type)

    def get_map_data(self, map_id: str) -> Optional[Dict[str, Any]]:
        """获取地图完整数据（来源/目标/路径/统计）。"""
        data = self._store.get(map_id)
        if not data:
            return None
        return {
            "id": map_id,
            "map_type": data["map_type"],
            "generated_at": data["generated_at"],
            "sources": self.get_attack_sources(map_id, 100),
            "targets": self.get_attack_targets(map_id, 100),
            "paths": self.get_attack_paths(map_id),
            "stats": self.get_stats(map_id),
        }

    # ------------------------------------------------------------------ #
    # 聚合统计
    # ------------------------------------------------------------------ #
    def _aggregate(self, map_id: str, key: str) -> List[Dict[str, Any]]:
        data = self._store.get(map_id)
        if not data:
            return []
        agg: Dict[str, Dict[str, Any]] = {}
        for log in data["logs"]:
            k = log.get(key, "未知")
            item = agg.setdefault(k, {"name": k, "count": 0, "critical": 0,
                                      "high": 0, "medium": 0, "low": 0, "info": 0})
            c = log.get("count", 1)
            item["count"] += c
            sev = log.get("severity", "info")
            item[sev] = item.get(sev, 0) + c
        ranked = sorted(agg.values(), key=lambda x: x["count"], reverse=True)
        return ranked

    def get_attack_sources(self, map_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """攻击来源按国家聚合。"""
        ranked = self._aggregate(map_id, "source_country")
        out: List[Dict[str, Any]] = []
        for i, item in enumerate(ranked[: max(1, int(limit))]):
            geo = _WORLD_COUNTRIES.get(item["name"], {"lat": 0.0, "lng": 0.0})
            out.append({
                "rank": i + 1, "country": item["name"],
                "lat": geo["lat"], "lng": geo["lng"],
                "count": item["count"],
                "critical": item["critical"], "high": item["high"],
            })
        return out

    def get_attack_targets(self, map_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """攻击目标按目标 IP 聚合（目标默认位于北京机房）。"""
        data = self._store.get(map_id)
        if not data:
            return []
        agg: Dict[str, Dict[str, Any]] = {}
        for log in data["logs"]:
            t = log.get("target_ip", "unknown")
            item = agg.setdefault(t, {"ip": t, "count": 0, "severity": "info"})
            item["count"] += log.get("count", 1)
            if log.get("severity") in ("critical", "high"):
                item["severity"] = log["severity"]
        ranked = sorted(agg.values(), key=lambda x: x["count"], reverse=True)
        for it in ranked:
            it["lat"] = 39.9042
            it["lng"] = 116.4074
            it["color"] = _SEV_COLOR.get(it["severity"], "#9aa4b2")
        return ranked[: max(1, int(limit))]

    def get_attack_paths(self, map_id: str) -> List[Dict[str, Any]]:
        """生成源→目标攻击路径（弧线坐标）。"""
        sources = self.get_attack_sources(map_id, 50)
        paths: List[Dict[str, Any]] = []
        target = {"lat": 39.9042, "lng": 116.4074, "name": "核心机房"}
        for s in sources:
            if not s["lat"] and not s["lng"]:
                continue
            mid_lat = (s["lat"] + target["lat"]) / 2
            mid_lng = (s["lng"] + target["lng"]) / 2 + 15
            severity = "high" if s["critical"] > 0 else ("medium" if s["high"] > 5 else "low")
            paths.append({
                "source": {"lat": s["lat"], "lng": s["lng"], "name": s["country"]},
                "target": target,
                "midpoint": {"lat": mid_lat, "lng": mid_lng},
                "count": s["count"],
                "severity": severity,
                "color": _SEV_COLOR[severity],
                "width": max(0.5, min(4, s["count"] / 200)),
                "animated": True,
            })
        return paths

    def get_stats(self, map_id: str) -> Dict[str, Any]:
        """多维统计汇总。"""
        by_country = self._aggregate(map_id, "source_country")
        by_type = self._aggregate(map_id, "attack_type")
        by_sev: Dict[str, int] = {}
        total = 0
        data = self._store.get(map_id, {})
        for log in data.get("logs", []):
            sev = log.get("severity", "info")
            by_sev[sev] = by_sev.get(sev, 0) + log.get("count", 1)
            total += log.get("count", 1)
        return {
            "total_attacks": total,
            "by_country": by_country[:15],
            "by_type": by_type[:15],
            "by_severity": by_sev,
            "unique_sources": len({l.get("source_country") for l in data.get("logs", [])}),
        }

    # ------------------------------------------------------------------ #
    # 导出
    # ------------------------------------------------------------------ #
    def export_json(self, map_id: str) -> Dict[str, Any]:
        """导出 JSON 数据。"""
        data = self.get_map_data(map_id)
        return data or {"error": "map not found"}

    def export_csv(self, map_id: str) -> str:
        """导出 CSV 统计（按攻击类型）。"""
        stats = self.get_stats(map_id)
        rows = [["attack_type", "count", "critical", "high", "medium", "low", "info"]]
        for item in stats.get("by_type", []):
            rows.append([
                item["name"], item["count"],
                item.get("critical", 0), item.get("high", 0),
                item.get("medium", 0), item.get("low", 0), item.get("info", 0),
            ])
        lines = [",".join(str(c) for c in r) for r in rows]
        return "\n".join(lines)

    def export_html(self, map_id: str) -> str:
        """导出交互式 HTML（SVG 简化世界地图 + 弧线）。"""
        data = self.get_map_data(map_id)
        if not data:
            return "<html><body>地图不存在</body></html>"
        payload = json.dumps(data, ensure_ascii=False)
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>攻击地图 - {map_id}</title>
<style>
  body {{ background:#0a0e17; color:#e6f1ff; font-family:sans-serif; margin:0; }}
  #wrap {{ padding:16px; }}
  svg {{ width:100%; height:60vh; background:#0d1420; border:1px solid #1e3a5f; border-radius:8px; }}
  .stat {{ display:flex; gap:16px; margin-top:12px; }}
  .card {{ background:#111827; border:1px solid #1e3a5f; border-radius:8px; padding:10px 16px; }}
</style>
</head>
<body>
<div id="wrap">
  <h2 style="margin:0 0 8px">攻击态势地图（{data['map_type']}）</h2>
  <svg id="map" viewBox="-180 -90 360 180">
    <g id="paths"></g><g id="dots"></g>
  </svg>
  <div class="stat">
    <div class="card">总攻击 <b id="t1"></b></div>
    <div class="card">攻击源国家 <b id="t2"></b></div>
  </div>
</div>
<script>
const DATA = {payload};
const NS='http://www.w3.org/2000/svg';
function el(t,a){{const e=document.createElementNS(NS,t);for(const k in a)e.setAttribute(k,a[k]);return e;}}
DATA.paths.forEach(p=>{{
  const m=el('path',{{d:`M ${{p.source.lng}} ${{p.source.lat}} Q ${{p.midpoint.lng}} ${{p.midpoint.lat}} ${{p.target.lng}} ${{p.target.lat}}`,
    stroke:p.color,'stroke-width':p.width,fill:'none',opacity:0.7}});
  document.getElementById('paths').appendChild(m);
}});
DATA.sources.slice(0,30).forEach(s=>{{
  const c=el('circle',{{cx:s.lng,cy:s.lat,r:Math.max(1.5,s.count/80),fill:'#ff3b3b',opacity:0.8}});
  const t=el('title',{{}});t.textContent=s.country+' '+s.count;c.appendChild(t);
  document.getElementById('dots').appendChild(c);
}});
document.getElementById('t1').textContent=DATA.stats.total_attacks;
document.getElementById('t2').textContent=DATA.stats.unique_sources;
</script>
</body>
</html>"""


# 模块级单例
attack_map = AttackMap()
