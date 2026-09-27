# -*- coding: utf-8 -*-
"""
asset_management.risk_rating - 资产风险评级器

7 维度加权评分：
    1. 漏洞数量       (默认权重 0.25)
    2. 漏洞严重程度   (默认权重 0.25)
    3. 暴露程度       (默认权重 0.15)
    4. 资产重要性     (默认权重 0.15)
    5. 数据敏感性     (默认权重 0.10)
    6. 业务影响       (默认权重 0.05)
    7. 开放端口数量   (默认权重 0.05)

评级等级：critical(>90) / high(70-90) / medium(40-70) / low(<40)

数据库表：am_risk_history
并对 assets 表扩展列：exposure_level / data_sensitivity / business_impact /
                      department / location / open_ports_count
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.database import db
from utils.logger import log

# 默认权重（可配置）
DEFAULT_WEIGHTS = {
    "vuln_count": 0.25,
    "vuln_severity": 0.25,
    "exposure": 0.15,
    "importance": 0.15,
    "data_sensitivity": 0.10,
    "business_impact": 0.05,
    "open_ports": 0.05,
}

# 暴露程度分值
_EXPOSURE_SCORE = {"internet": 1.0, "dmz": 0.7, "internal": 0.4, "isolated": 0.1}
# 资产重要性分值
_IMPORTANCE_SCORE = {"core": 1.0, "critical": 1.0, "high": 0.7,
                     "important": 0.7, "medium": 0.4, "low": 0.1}
# 数据敏感性分值
_SENSITIVITY_SCORE = {"top_secret": 1.0, "confidential": 0.8, "secret": 0.8,
                      "internal": 0.4, "public": 0.1}
# 业务影响分值
_BUSINESS_SCORE = {"high": 1.0, "medium": 0.5, "low": 0.2}
# 严重程度分值
_SEVERITY_SCORE = {"critical": 1.0, "high": 0.75, "medium": 0.45, "low": 0.15, "info": 0.05}


def _now() -> str:
    return datetime.now().isoformat()


class RiskRatingManager:
    """资产风险评级器"""

    def __init__(self, weights: Optional[Dict[str, float]] = None) -> None:
        """初始化评级器，建表并扩展 assets 列。"""
        self.weights = dict(DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)
        self._ensure_tables()
        self._extend_assets_columns()

    # ------------------------------------------------------------------ #
    # 表与列初始化
    # ------------------------------------------------------------------ #
    def _ensure_tables(self) -> None:
        """创建风险历史表。"""
        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS am_risk_history (
                    id TEXT PRIMARY KEY,
                    asset_id TEXT,
                    risk_score REAL,
                    risk_level TEXT,
                    factors TEXT,
                    calculated_at TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rh_asset ON am_risk_history(asset_id)")
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"创建风险历史表失败: {e}")
        finally:
            conn.close()

    def _extend_assets_columns(self) -> None:
        """用 try-except ALTER TABLE 为 assets 表扩展评级相关列。"""
        extra = {
            "exposure_level": "TEXT DEFAULT 'internal'",
            "data_sensitivity": "TEXT DEFAULT 'internal'",
            "business_impact": "TEXT DEFAULT 'low'",
            "department": "TEXT",
            "location": "TEXT",
            "open_ports_count": "INTEGER DEFAULT 0",
        }
        conn = db._get_connection()
        try:
            existing = {r[1] for r in conn.execute("PRAGMA table_info(assets)").fetchall()}
            for col, decl in extra.items():
                if col not in existing:
                    try:
                        conn.execute(f"ALTER TABLE assets ADD COLUMN {col} {decl}")
                    except Exception:
                        # 列可能已存在，忽略
                        pass
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.warning(f"扩展 assets 列失败: {e}")
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 工具
    # ------------------------------------------------------------------ #
    @staticmethod
    def _asset_row(asset_id: str) -> Optional[Dict[str, Any]]:
        conn = db._get_connection()
        try:
            row = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def _vuln_stats_for_asset(self, asset: Dict[str, Any]) -> Dict[str, float]:
        """根据资产 IP/域名字段关联 vulnerabilities 表，统计漏洞数量与严重程度。"""
        conn = db._get_connection()
        count = 0
        sev_score = 0.0
        try:
            # 确保 vulnerabilities 表存在
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY, title TEXT, description TEXT, type TEXT,
                    severity TEXT DEFAULT 'medium', status TEXT DEFAULT 'new',
                    target TEXT, cvss_score REAL DEFAULT 0.0
                )
            """)
            conn.commit()
            targets = [t for t in (asset.get("ip"), asset.get("domain"), asset.get("name")) if t]
            if targets:
                placeholders = ",".join("?" for _ in targets)
                rows = conn.execute(
                    f"SELECT severity, COUNT(*) AS cnt FROM vulnerabilities "
                    f"WHERE target IN ({placeholders}) GROUP BY severity",
                    targets).fetchall()
                for r in rows:
                    count += r["cnt"]
                    sev_score += _SEVERITY_SCORE.get((r["severity"] or "").lower(), 0.3) * r["cnt"]
        except Exception as e:  # pragma: no cover
            log.warning(f"统计漏洞失败: {e}")
        finally:
            conn.close()
        return {"count": count, "severity_score": sev_score}

    # ------------------------------------------------------------------ #
    # 核心评级
    # ------------------------------------------------------------------ #
    def calculate_risk_rating(self, asset_id: str,
                              persist: bool = True) -> Dict[str, Any]:
        """计算资产 7 维度加权评分。"""
        asset = self._asset_row(asset_id)
        if not asset:
            return {"success": False, "error": f"资产 {asset_id} 不存在"}

        vuln = self._vuln_stats_for_asset(asset)
        # 各维度归一化到 0~1
        # 1. 漏洞数量：>=20 条封顶
        vuln_count_score = min(vuln["count"] / 20.0, 1.0)
        # 2. 漏洞严重程度：加权平均 / 1
        sev_avg = (vuln["severity_score"] / vuln["count"]) if vuln["count"] else 0.0
        # 3. 暴露程度
        exposure_score = _EXPOSURE_SCORE.get((asset.get("exposure_level") or "internal").lower(), 0.4)
        # 4. 资产重要性
        importance_score = _IMPORTANCE_SCORE.get((asset.get("importance") or "medium").lower(), 0.4)
        # 5. 数据敏感性
        sens_score = _SENSITIVITY_SCORE.get((asset.get("data_sensitivity") or "internal").lower(), 0.4)
        # 6. 业务影响
        biz_score = _BUSINESS_SCORE.get((asset.get("business_impact") or "low").lower(), 0.2)
        # 7. 开放端口数量：>=50 封顶
        ports = asset.get("open_ports_count") or 0
        ports_score = min(ports / 50.0, 1.0)

        factors = {
            "vuln_count": {"value": vuln["count"], "score": round(vuln_count_score, 3),
                           "weight": self.weights["vuln_count"]},
            "vuln_severity": {"value": round(sev_avg, 3), "score": round(sev_avg, 3),
                              "weight": self.weights["vuln_severity"]},
            "exposure": {"value": asset.get("exposure_level", "internal"),
                         "score": exposure_score, "weight": self.weights["exposure"]},
            "importance": {"value": asset.get("importance", "medium"),
                           "score": importance_score, "weight": self.weights["importance"]},
            "data_sensitivity": {"value": asset.get("data_sensitivity", "internal"),
                                 "score": sens_score, "weight": self.weights["data_sensitivity"]},
            "business_impact": {"value": asset.get("business_impact", "low"),
                                "score": biz_score, "weight": self.weights["business_impact"]},
            "open_ports": {"value": ports, "score": round(ports_score, 3),
                           "weight": self.weights["open_ports"]},
        }
        # 加权总分 -> 0~100
        total = sum(f["score"] * f["weight"] for f in factors.values())
        risk_score = round(total * 100, 2)
        risk_level = self._level_of(risk_score)

        result = {
            "success": True,
            "asset_id": asset_id,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "factors": factors,
            "weights": self.weights,
            "calculated_at": _now(),
        }
        if persist:
            self._save_history(asset_id, risk_score, risk_level, factors)
            # 回写 assets.risk_score
            conn = db._get_connection()
            try:
                conn.execute("UPDATE assets SET risk_score=?, updated_at=? WHERE id=?",
                             (risk_score, _now(), asset_id))
                conn.commit()
            finally:
                conn.close()
        return result

    @staticmethod
    def _level_of(score: float) -> str:
        if score > 90:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"

    def _save_history(self, asset_id: str, score: float, level: str,
                      factors: Dict[str, Any]) -> None:
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO am_risk_history (id, asset_id, risk_score, risk_level,
                                             factors, calculated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (f"am-rh-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
                  asset_id, score, level,
                  __import__("json").dumps(factors, ensure_ascii=False), _now()))
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"保存风险历史失败: {e}")
        finally:
            conn.close()

    def get_risk_rating(self, asset_id: str) -> Dict[str, Any]:
        """获取资产最新风险评级（无历史则现算）。"""
        conn = db._get_connection()
        try:
            row = conn.execute("""
                SELECT * FROM am_risk_history WHERE asset_id=?
                ORDER BY calculated_at DESC LIMIT 1
            """, (asset_id,)).fetchone()
            if not row:
                return self.calculate_risk_rating(asset_id)
            d = dict(row)
            if d.get("factors"):
                try:
                    import json
                    d["factors"] = json.loads(d["factors"])
                except Exception:
                    pass
            return {"success": True, **d}
        finally:
            conn.close()

    def recalculate_all(self) -> Dict[str, Any]:
        """重新计算所有资产风险评级。"""
        conn = db._get_connection()
        try:
            rows = conn.execute("SELECT id FROM assets").fetchall()
        finally:
            conn.close()
        total = 0
        for r in rows:
            self.calculate_risk_rating(r["id"])
            total += 1
        return {"success": True, "recalculated": total}

    def get_risk_trends(self, asset_id: str, limit: int = 30) -> Dict[str, Any]:
        """资产风险评级随时间变化趋势。"""
        conn = db._get_connection()
        try:
            rows = conn.execute("""
                SELECT risk_score, risk_level, calculated_at
                FROM am_risk_history WHERE asset_id=?
                ORDER BY calculated_at ASC LIMIT ?
            """, (asset_id, limit)).fetchall()
            points = [{"score": r["risk_score"], "level": r["risk_level"],
                       "time": r["calculated_at"]} for r in rows]
            return {"asset_id": asset_id, "points": points}
        finally:
            conn.close()

    def get_risk_ranking(self, top_n: int = 20,
                         level: Optional[str] = None) -> Dict[str, Any]:
        """资产风险排名 TOP N（按最新评分）。"""
        conn = db._get_connection()
        try:
            where = ""
            params: List[Any] = []
            if level:
                where = " WHERE risk_level=?"
                params.append(level)
            rows = conn.execute(f"""
                SELECT asset_id, risk_score, risk_level, MAX(calculated_at) AS latest
                FROM am_risk_history {where}
                GROUP BY asset_id
                ORDER BY risk_score DESC LIMIT ?
            """, params + [top_n]).fetchall()
            items = [dict(r) for r in rows]
            # 关联资产基本信息
            for it in items:
                a = self._asset_row(it["asset_id"])
                if a:
                    it["ip"] = a.get("ip")
                    it["name"] = a.get("name") or a.get("hostname")
                    it["asset_type"] = a.get("asset_type")
            return {"items": items, "total": len(items)}
        finally:
            conn.close()

    def get_risk_factors(self, asset_id: str) -> Dict[str, Any]:
        """影响资产风险评级的关键因子分析。"""
        rating = self.get_risk_rating(asset_id)
        factors = rating.get("factors", {}) if isinstance(rating, dict) else {}
        # 按贡献度 = score*weight 排序
        contrib = []
        for name, f in factors.items():
            if isinstance(f, dict):
                contrib.append({
                    "factor": name,
                    "value": f.get("value"),
                    "score": f.get("score"),
                    "weight": f.get("weight"),
                    "contribution": round((f.get("score") or 0) * (f.get("weight") or 0) * 100, 2),
                })
        contrib.sort(key=lambda x: x["contribution"], reverse=True)
        return {"asset_id": asset_id, "risk_score": rating.get("risk_score"),
                "risk_level": rating.get("risk_level"), "factors": contrib}

    def get_risk_mitigation_suggestions(self, asset_id: str) -> Dict[str, Any]:
        """针对高风险资产给出风险降低建议。"""
        analysis = self.get_risk_factors(asset_id)
        suggestions: List[str] = []
        for f in analysis.get("factors", []):
            name = f["factor"]
            if name == "vuln_count" and (f.get("score") or 0) > 0.5:
                suggestions.append(f"资产存在较多漏洞（{f.get('value')}个），应优先安排漏洞扫描与修复闭环。")
            if name == "vuln_severity" and (f.get("score") or 0) > 0.6:
                suggestions.append("存在高危/严重漏洞，建议立即进行补丁升级或临时缓解（WAF/隔离）。")
            if name == "exposure" and f.get("value") == "internet":
                suggestions.append("资产直接暴露于互联网，建议收敛攻击面、启用防火墙白名单与最小化端口开放。")
            if name == "importance" and f.get("value") in ("core", "critical", "high"):
                suggestions.append("该资产为核心/重要资产，建议加强访问控制、启用双因素认证并纳入重点监控。")
            if name == "data_sensitivity" and f.get("value") in ("confidential", "top_secret", "secret"):
                suggestions.append("承载敏感/绝密数据，建议加密存储与传输，并开展数据分类分级审计。")
            if name == "open_ports" and (f.get("score") or 0) > 0.5:
                suggestions.append("开放端口较多，建议关闭不必要端口与服务，最小化暴露面。")
            if name == "business_impact" and f.get("value") == "high":
                suggestions.append("业务影响高，建议制定高可用与应急回滚方案。")
        if not suggestions:
            suggestions.append("当前风险水平可控，建议保持常规巡检与定期复评。")
        return {"asset_id": asset_id, "risk_level": analysis.get("risk_level"),
                "suggestions": suggestions}

    def update_asset_importance(self, asset_id: str,
                                importance: Optional[str] = None,
                                data_sensitivity: Optional[str] = None,
                                exposure_level: Optional[str] = None,
                                business_impact: Optional[str] = None,
                                department: Optional[str] = None,
                                location: Optional[str] = None) -> Dict[str, Any]:
        """更新资产重要性/数据敏感性/暴露程度等属性。"""
        fields = {
            "importance": importance, "data_sensitivity": data_sensitivity,
            "exposure_level": exposure_level, "business_impact": business_impact,
            "department": department, "location": location,
        }
        sets, params = [], []
        for k, v in fields.items():
            if v is not None:
                sets.append(f"{k}=?")
                params.append(v)
        if not sets:
            return {"success": False, "error": "无更新字段"}
        sets.append("updated_at=?")
        params.append(_now())
        params.append(asset_id)
        conn = db._get_connection()
        try:
            cur = conn.execute(
                f"UPDATE assets SET {', '.join(sets)} WHERE id=?", params)
            conn.commit()
            if cur.rowcount == 0:
                return {"success": False, "error": "资产不存在"}
            # 更新后重新评级
            self.calculate_risk_rating(asset_id)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()


# 全局单例
risk_rating_manager = RiskRatingManager()
