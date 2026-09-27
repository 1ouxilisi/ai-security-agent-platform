# -*- coding: utf-8 -*-
"""
analytics.py —— 漏洞分析引擎。

职责：
    - 从 vulnerabilities 与 vulnerability_history 表聚合计算
    - 提供趋势 / 修复率 / 老化分布 / TOP 漏洞 / 资产风险排名 / 扫描对比 / 验证率等指标
    - 全部返回结构化数据，前端可直接用于图表渲染

时间字段说明：discovered_at / remediated_at 为 Unix 时间戳（秒）。
"""
import time
from typing import Optional, List, Dict, Any

from utils.database import db
from utils.logger import log


# 已闭环状态集合
CLOSED_STATES = ("resolved", "closed")


def _now() -> float:
    return time.time()


class VulnerabilityAnalytics:
    """漏洞分析引擎（只读聚合）。"""

    def _fetch_all(self, where: str = "", params: Optional[List[Any]] = None) -> List[Dict[str, Any]]:
        """读取全部漏洞记录（聚合数据量可控时使用）。"""
        conn = db._get_connection()
        try:
            sql = f"SELECT * FROM vulnerabilities WHERE {where}" if where else "SELECT * FROM vulnerabilities"
            rows = conn.execute(sql, params or []).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-analytics] 查询失败: {e}")
            return []
        finally:
            conn.close()

    # ==================== 趋势 ====================

    def _bucket_key(self, ts: float, granularity: str) -> str:
        """将时间戳按粒度分桶。"""
        if not ts:
            return "unknown"
        if granularity == "day":
            return time.strftime("%Y-%m-%d", time.localtime(ts))
        if granularity == "month":
            return time.strftime("%Y-%m", time.localtime(ts))
        # week：按 ISO 年-周
        gmtime = time.gmtime(ts)
        y, w, _ = time.isocalendar(gmtime)
        return f"{y}-W{w:02d}"

    def get_trends(self, granularity: str = "day", days: int = 90) -> Dict[str, Any]:
        """按日/周/月统计新增 / 已修复 / 未修复漏洞数量。

        Args:
            granularity: day / week / month
            days: 统计窗口（近 N 天）
        """
        cutoff = _now() - days * 86400
        vulns = self._fetch_all()
        buckets: Dict[str, Dict[str, int]] = {}

        for v in vulns:
            disc = v.get("discovered_at") or 0
            if disc < cutoff:
                continue
            key = self._bucket_key(disc, granularity)
            b = buckets.setdefault(key, {"new": 0, "fixed": 0, "open": 0})
            b["new"] += 1
            remediated = v.get("remediated_at")
            status = v.get("lifecycle_status") or v.get("status") or "new"
            if remediated and remediated >= cutoff and status in CLOSED_STATES:
                b["fixed"] += 1
            else:
                b["open"] += 1

        series = [
            {"bucket": k, "new": v["new"], "fixed": v["fixed"], "open": v["open"]}
            for k, v in sorted(buckets.items())
        ]
        return {"granularity": granularity, "days": days, "series": series}

    # ==================== 修复率 ====================

    def get_fix_rate(self, group_by: str = "overall") -> Dict[str, Any]:
        """计算修复率。

        Args:
            group_by: overall / severity / target / time
                - time 时按近 7/30/90 天分组
        """
        vulns = self._fetch_all()

        def _rate(items: List[Dict[str, Any]]) -> Dict[str, float]:
            total = len(items)
            fixed = sum(1 for v in items
                        if (v.get("lifecycle_status") or v.get("status")) in CLOSED_STATES)
            rate = round(fixed / total * 100, 2) if total else 100.0
            return {"total": total, "fixed": fixed, "open": total - fixed, "fix_rate_percent": rate}

        if group_by == "severity":
            groups: Dict[str, List[Dict[str, Any]]] = {}
            for v in vulns:
                groups.setdefault(v.get("severity") or "unknown", []).append(v)
            return {"group_by": "severity",
                    "groups": {k: _rate(items) for k, items in groups.items()}}
        if group_by == "target":
            groups = {}
            for v in vulns:
                groups.setdefault(v.get("target") or "unknown", []).append(v)
            return {"group_by": "target",
                    "groups": {k: _rate(items) for k, items in sorted(groups.items())}}
        if group_by == "time":
            now = _now()
            windows = {"7d": 7, "30d": 30, "90d": 90}
            result = {}
            for label, d in windows.items():
                cutoff = now - d * 86400
                items = [v for v in vulns if (v.get("discovered_at") or 0) >= cutoff]
                result[label] = _rate(items)
            return {"group_by": "time", "groups": result}
        # overall
        return {"group_by": "overall", **_rate(vulns)}

    # ==================== 老化分布 ====================

    def get_aging_distribution(self) -> Dict[str, Any]:
        """漏洞存在时间分布：<7天 / 7-30天 / 30-90天 / >90天（仅未闭环）。"""
        now = _now()
        buckets = {"<7d": 0, "7-30d": 0, "30-90d": 0, ">90d": 0}
        vulns = self._fetch_all()
        for v in vulns:
            status = v.get("lifecycle_status") or v.get("status") or "new"
            if status in CLOSED_STATES:
                continue
            age_days = (now - (v.get("discovered_at") or now)) / 86400
            if age_days < 7:
                buckets["<7d"] += 1
            elif age_days < 30:
                buckets["7-30d"] += 1
            elif age_days < 90:
                buckets["30-90d"] += 1
            else:
                buckets[">90d"] += 1
        return {"distribution": buckets, "total_open": sum(buckets.values())}

    # ==================== TOP 漏洞 ====================

    def get_top_vulnerabilities(self, limit: int = 10) -> Dict[str, Any]:
        """最常见漏洞类型 TOP / 最严重漏洞 / 重复出现漏洞。"""
        vulns = self._fetch_all()

        # 最常见类型（按 name）
        name_count: Dict[str, int] = {}
        for v in vulns:
            name = v.get("name") or "unknown"
            name_count[name] = name_count.get(name, 0) + 1
        top_types = [
            {"name": k, "count": cnt}
            for k, cnt in sorted(name_count.items(), key=lambda x: x[1], reverse=True)[:limit]
        ]

        # 最严重漏洞（按 severity 权重 + priority_score）
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        ranked = sorted(
            vulns,
            key=lambda v: (sev_rank.get((v.get("severity") or "low").lower(), 0),
                           v.get("priority_score") or 0),
            reverse=True,
        )[:limit]
        top_severe = [
            {"id": v.get("id"), "name": v.get("name"), "severity": v.get("severity"),
             "target": v.get("target"), "cve": v.get("cve"),
             "priority_score": v.get("priority_score")}
            for v in ranked
        ]

        # 重复出现漏洞（同名出现多次）
        duplicates = [
            {"name": k, "count": cnt}
            for k, cnt in sorted(name_count.items(), key=lambda x: x[1], reverse=True)
            if cnt > 1
        ][:limit]

        return {"top_types": top_types, "top_severe": top_severe, "duplicates": duplicates}

    # ==================== 资产风险排名 ====================

    def get_asset_risk_ranking(self, limit: int = 10) -> List[Dict[str, Any]]:
        """按漏洞数量 / 严重程度 / 风险评分排名的资产 TOP10。"""
        vulns = self._fetch_all()
        sev_score = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}
        assets: Dict[str, Dict[str, Any]] = {}

        for v in vulns:
            target = v.get("target") or "unknown"
            a = assets.setdefault(target, {
                "target": target, "total": 0, "critical": 0, "high": 0,
                "open": 0, "risk_score": 0.0,
            })
            sev = (v.get("severity") or "low").lower()
            a["total"] += 1
            a["risk_score"] += sev_score.get(sev, 2)
            if sev == "critical":
                a["critical"] += 1
            elif sev == "high":
                a["high"] += 1
            status = v.get("lifecycle_status") or v.get("status") or "new"
            if status not in CLOSED_STATES:
                a["open"] += 1

        ranked = sorted(assets.values(), key=lambda x: x["risk_score"], reverse=True)[:limit]
        return ranked

    # ==================== 扫描对比 ====================

    def compare_scans(self, range1_start: float, range1_end: float,
                      range2_start: float, range2_end: float) -> Dict[str, Any]:
        """对比两个扫描周期：新增 / 修复 / 持续存在。

        Args:
            range1_start/end: 上一周期时间戳
            range2_start/end: 当前周期时间戳
        """
        conn = db._get_connection()
        try:
            # 周期1内发现的漏洞
            prev = conn.execute(
                "SELECT id, name, status, lifecycle_status FROM vulnerabilities "
                "WHERE discovered_at BETWEEN ? AND ?",
                (range1_start, range1_end),
            ).fetchall()
            # 周期2内发现的漏洞
            cur = conn.execute(
                "SELECT id, name, status, lifecycle_status FROM vulnerabilities "
                "WHERE discovered_at BETWEEN ? AND ?",
                (range2_start, range2_end),
            ).fetchall()

            prev_map = {r["id"]: dict(r) for r in prev}
            cur_ids = {r["id"] for r in cur}

            new_in_cur = [dict(r) for r in cur if r["id"] not in prev_map]
            resolved_in_cur = [
                prev_map[i] for i in prev_map
                if i not in cur_ids and (prev_map[i].get("lifecycle_status")
                                         or prev_map[i].get("status")) in CLOSED_STATES
            ]
            persistent = [
                prev_map[i] for i in prev_map
                if i not in cur_ids and (prev_map[i].get("lifecycle_status")
                                         or prev_map[i].get("status")) not in CLOSED_STATES
            ]

            return {
                "range1": {"start": range1_start, "end": range1_end},
                "range2": {"start": range2_start, "end": range2_end},
                "previous_count": len(prev),
                "current_count": len(cur),
                "new": {"count": len(new_in_cur), "items": new_in_cur},
                "fixed": {"count": len(resolved_in_cur), "items": resolved_in_cur},
                "persistent": {"count": len(persistent), "items": persistent},
            }
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-analytics] 扫描对比失败: {e}")
            return {"error": str(e)}
        finally:
            conn.close()

    # ==================== 验证率 / 误报率 ====================

    def get_verification_rate(self) -> Dict[str, Any]:
        """漏洞修复验证通过率 / 误报率。"""
        conn = db._get_connection()
        try:
            total = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            verified = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE lifecycle_status='fix_verified'"
            ).fetchone()[0]
            closed = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE lifecycle_status IN ('resolved','closed')"
            ).fetchone()[0]
            fp = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE lifecycle_status='false_positive'"
            ).fetchone()[0]

            # 修复验证通过率：fix_verified / (fix_verified + 验证失败重试近似为 closed 前总量)
            attempted = verified + closed
            pass_rate = round(verified / attempted * 100, 2) if attempted else 100.0
            fp_rate = round(fp / total * 100, 2) if total else 0.0

            return {
                "total": total,
                "fix_verified": verified,
                "resolved_or_closed": closed,
                "verification_pass_rate_percent": pass_rate,
                "false_positive": fp,
                "false_positive_rate_percent": fp_rate,
            }
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-analytics] 验证率统计失败: {e}")
            return {"total": 0, "fix_verified": 0, "resolved_or_closed": 0,
                    "verification_pass_rate_percent": 0.0,
                    "false_positive": 0, "false_positive_rate_percent": 0.0}
        finally:
            conn.close()


# 全局单例
analytics_engine = VulnerabilityAnalytics()
