"""
analytics模块 —— 平台数据分析引擎。

模块功能：
    - 漏洞数量趋势（按日/周/月）
    - 风险分趋势
    - 按严重级别 / 漏洞类型 / 目标 的分布统计
    - Top N 漏洞类型 / Top N 高风险目标
    - 两次评估对比（新增 / 已修复 / 持续存在）
    - 综合统计摘要
    - 结果导出（JSON / CSV）

注意事项：
    - 所有方法均做空数据兜底，空库返回空列表 / 零值，绝不抛错
    - 本模块为授权安全评估 / 防御检测产品的数据层
"""
import csv
import io
import json
import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import func

from database.db_manager import db_manager as _global_db
from database.models import Assessment, Vulnerability

logger = logging.getLogger("platform.analytics")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] analytics: %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# 标准严重级别顺序
_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _norm_severity(sev: Optional[str]) -> str:
    """统一严重级别命名，未知值归入 medium。"""
    if not sev:
        return "medium"
    s = str(sev).strip().lower()
    if s in ("critical", "crit", "严重"):
        return "critical"
    if s in ("high", "high-risk", "高"):
        return "high"
    if s in ("medium", "moderate", "medium-risk", "中"):
        return "medium"
    if s in ("low", "低", "info", "informational", "inform"):
        return "low"
    return "medium"


def _bucket(ts: Optional[float], group_by: str) -> str:
    """把时间戳归入时间分桶标签。"""
    if not ts:
        return "unknown"
    try:
        dt = datetime.fromtimestamp(float(ts))
    except Exception:  # noqa: BLE001
        return "unknown"
    gb = (group_by or "day").lower()
    if gb == "week":
        return dt.strftime("%G-%V")
    if gb == "month":
        return dt.strftime("%Y-%m")
    return dt.strftime("%Y-%m-%d")


class AnalyticsEngine:
    """数据分析引擎，依赖 db_manager 提供的会话。"""

    def __init__(self, db=None):
        """初始化引擎。

        Args:
            db: DBManager 实例，缺省使用全局单例
        """
        self.db = db or _global_db

    # -------------------- 内部查询辅助 --------------------

    def _query_vulns(self, tenant_id: Optional[str] = None):
        """返回 (discovered_at, severity, name, target, assessment_id) 元组列表。"""
        rows: List[tuple] = []
        try:
            with self.db.get_session() as session:
                if session is None:
                    return []
                q = session.query(
                    Vulnerability.discovered_at,
                    Vulnerability.severity,
                    Vulnerability.name,
                    Vulnerability.target,
                    Vulnerability.assessment_id,
                )
                if tenant_id:
                    q = q.filter(Vulnerability.tenant_id == tenant_id)
                rows = q.all()
        except Exception as e:  # noqa: BLE001
            logger.error(f"查询漏洞失败: {e}")
        return rows or []

    def _query_assessments(self, tenant_id: Optional[str] = None):
        """返回 Assessment 实体元组 (id, target, risk_score, created_at, started_at)。"""
        rows: List[tuple] = []
        try:
            with self.db.get_session() as session:
                if session is None:
                    return []
                q = session.query(
                    Assessment.id,
                    Assessment.target,
                    Assessment.risk_score,
                    Assessment.created_at,
                    Assessment.started_at,
                )
                if tenant_id:
                    q = q.filter(Assessment.tenant_id == tenant_id)
                rows = q.all()
        except Exception as e:  # noqa: BLE001
            logger.error(f"查询评估失败: {e}")
        return rows or []

    # -------------------- 趋势分析 --------------------

    def trend_vulnerabilities(self, days: int = 30, group_by: str = "day") -> List[Dict[str, Any]]:
        """按时间桶统计漏洞数量及各级别分布。

        Returns:
            [{date, count, critical, high, medium, low}, ...]
        """
        try:
            days = max(1, int(days or 30))
            since = time.time() - days * 86400
            rows = self._query_vulns()
            bucket: Dict[str, Dict[str, int]] = {}
            for discovered_at, severity, _name, _target, _aid in rows:
                ts = float(discovered_at or 0)
                if ts and ts < since:
                    continue
                key = _bucket(ts, group_by)
                if key not in bucket:
                    bucket[key] = {"count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
                sev = _norm_severity(severity)
                bucket[key]["count"] += 1
                bucket[key][sev] += 1
            result = [{"date": k, **v} for k, v in sorted(bucket.items())]
            return result
        except Exception as e:  # noqa: BLE001
            logger.error(f"trend_vulnerabilities 失败: {e}")
            return []

    def trend_risk(self, days: int = 30) -> List[Dict[str, Any]]:
        """按日统计风险分趋势。

        Returns:
            [{date, avg_risk, max_risk, assessment_count}, ...]
        """
        try:
            days = max(1, int(days or 30))
            since = time.time() - days * 86400
            rows = self._query_assessments()
            bucket: Dict[str, List[float]] = defaultdict(list)
            for _id, _target, risk, created_at, started_at in rows:
                ts = float(created_at or started_at or 0)
                if ts and ts < since:
                    continue
                key = _bucket(ts, "day")
                bucket[key].append(float(risk or 0))
            result = []
            for k in sorted(bucket.keys()):
                vals = bucket[k]
                result.append({
                    "date": k,
                    "avg_risk": round(sum(vals) / len(vals), 2) if vals else 0.0,
                    "max_risk": round(max(vals), 2) if vals else 0.0,
                    "assessment_count": len(vals),
                })
            return result
        except Exception as e:  # noqa: BLE001
            logger.error(f"trend_risk 失败: {e}")
            return []

    # -------------------- 分布统计 --------------------

    def distribution_by_severity(self, tenant_id: Optional[str] = None) -> Dict[str, int]:
        """按严重级别统计漏洞数量。"""
        dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        try:
            rows = self._query_vulns(tenant_id)
            for _at, severity, _n, _t, _a in rows:
                sev = _norm_severity(severity)
                dist[sev] = dist.get(sev, 0) + 1
        except Exception as e:  # noqa: BLE001
            logger.error(f"distribution_by_severity 失败: {e}")
        return dist

    def distribution_by_type(self, tenant_id: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        """按漏洞名称/类型聚合 Top N。"""
        try:
            limit = max(1, int(limit or 20))
            rows = self._query_vulns(tenant_id)
            agg: Dict[str, Dict[str, Any]] = {}
            for _at, severity, name, _t, _a in rows:
                nm = (name or "未命名漏洞").strip() or "未命名漏洞"
                if nm not in agg:
                    agg[nm] = {"name": nm, "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
                agg[nm]["count"] += 1
                agg[nm][_norm_severity(severity)] += 1
            result = sorted(agg.values(), key=lambda x: x["count"], reverse=True)[:limit]
            return result
        except Exception as e:  # noqa: BLE001
            logger.error(f"distribution_by_type 失败: {e}")
            return []

    def distribution_by_target(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """按目标统计漏洞数，并关联评估风险分。"""
        try:
            rows = self._query_vulns(tenant_id)
            vuln_count: Dict[str, int] = defaultdict(int)
            for _at, _s, _n, target, _a in rows:
                t = (target or "未知目标").strip() or "未知目标"
                vuln_count[t] += 1
            # 关联评估风险分
            assess_rows = self._query_assessments(tenant_id)
            risk_by_target: Dict[str, List[float]] = defaultdict(list)
            for _id, target, risk, _c, _s in assess_rows:
                t = (target or "").strip()
                if t:
                    risk_by_target[t].append(float(risk or 0))
            result = []
            for t, cnt in vuln_count.items():
                risks = risk_by_target.get(t, [])
                result.append({
                    "target": t,
                    "vuln_count": cnt,
                    "avg_risk": round(sum(risks) / len(risks), 2) if risks else 0.0,
                })
            result.sort(key=lambda x: (x["avg_risk"], x["vuln_count"]), reverse=True)
            return result
        except Exception as e:  # noqa: BLE001
            logger.error(f"distribution_by_target 失败: {e}")
            return []

    # -------------------- Top 分析 --------------------

    def top_vulnerabilities(self, n: int = 10, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Top N 漏洞类型（按出现次数）。"""
        try:
            n = max(1, int(n or 10))
            return self.distribution_by_type(tenant_id=tenant_id, limit=n)
        except Exception as e:  # noqa: BLE001
            logger.error(f"top_vulnerabilities 失败: {e}")
            return []

    def top_targets(self, n: int = 10, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """风险最高的 Top N 目标。"""
        try:
            n = max(1, int(n or 10))
            assess_rows = self._query_assessments(tenant_id)
            vuln_rows = self._query_vulns(tenant_id)
            vuln_count: Dict[str, int] = defaultdict(int)
            for _at, _s, _n2, target, _a in vuln_rows:
                t = (target or "").strip()
                if t:
                    vuln_count[t] += 1
            risk_by_target: Dict[str, List[float]] = defaultdict(list)
            for _id, target, risk, _c, _s in assess_rows:
                t = (target or "").strip()
                if t:
                    risk_by_target[t].append(float(risk or 0))
            result = []
            for t, risks in risk_by_target.items():
                result.append({
                    "target": t,
                    "avg_risk": round(sum(risks) / len(risks), 2) if risks else 0.0,
                    "max_risk": round(max(risks), 2) if risks else 0.0,
                    "assessment_count": len(risks),
                    "vuln_count": vuln_count.get(t, 0),
                })
            result.sort(key=lambda x: (x["avg_risk"], x["vuln_count"]), reverse=True)
            return result[:n]
        except Exception as e:  # noqa: BLE001
            logger.error(f"top_targets 失败: {e}")
            return []

    # -------------------- 评估对比 --------------------

    @staticmethod
    def _vuln_key(v: Any) -> str:
        """漏洞对比键：名称+CVE+目标 归一化。"""
        return "|".join([
            str(getattr(v, "name", "") or "").strip().lower(),
            str(getattr(v, "cve", "") or "").strip().upper(),
            str(getattr(v, "target", "") or "").strip().lower(),
        ])

    def _vulns_of_assessment(self, assessment_id: str) -> List[Any]:
        """取某评估的全部漏洞实体。"""
        try:
            with self.db.get_session() as session:
                if session is None:
                    return []
                rows = (
                    session.query(Vulnerability)
                    .filter(Vulnerability.assessment_id == assessment_id)
                    .all()
                )
                for r in rows:
                    session.expunge(r)
                return rows
        except Exception as e:  # noqa: BLE001
            logger.error(f"查询评估漏洞失败 ({assessment_id}): {e}")
            return []

    @staticmethod
    def _vuln_to_dict(v: Any) -> Dict[str, Any]:
        """漏洞实体转字典。"""
        return {
            "id": getattr(v, "id", ""),
            "name": getattr(v, "name", ""),
            "severity": getattr(v, "severity", ""),
            "cve": getattr(v, "cve", ""),
            "target": getattr(v, "target", ""),
            "status": getattr(v, "status", ""),
        }

    def compare_assessments(self, assessment_id1: str, assessment_id2: str) -> Dict[str, Any]:
        """对比两次评估的漏洞差异。

        Returns:
            {new:[...], fixed:[...], persisted:[...], summary:{...}}
        """
        empty = {"new": [], "fixed": [], "persisted": [], "summary": {
            "count1": 0, "count2": 0, "new_count": 0, "fixed_count": 0, "persisted_count": 0
        }}
        try:
            v1 = self._vulns_of_assessment(assessment_id1)
            v2 = self._vulns_of_assessment(assessment_id2)
            keys1 = {self._vuln_key(v): v for v in v1}
            keys2 = {self._vuln_key(v): v for v in v2}
            new_keys = set(keys2) - set(keys1)
            fixed_keys = set(keys1) - set(keys2)
            persisted_keys = set(keys1) & set(keys2)
            return {
                "new": [self._vuln_to_dict(keys2[k]) for k in sorted(new_keys)],
                "fixed": [self._vuln_to_dict(keys1[k]) for k in sorted(fixed_keys)],
                "persisted": [self._vuln_to_dict(keys2[k]) for k in sorted(persisted_keys)],
                "summary": {
                    "count1": len(v1),
                    "count2": len(v2),
                    "new_count": len(new_keys),
                    "fixed_count": len(fixed_keys),
                    "persisted_count": len(persisted_keys),
                },
            }
        except Exception as e:  # noqa: BLE001
            logger.error(f"compare_assessments 失败: {e}")
            return empty

    # -------------------- 综合摘要 --------------------

    def get_summary(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """综合统计摘要。"""
        try:
            assess_rows = self._query_assessments(tenant_id)
            vuln_rows = self._query_vulns(tenant_id)
            risks = [float(r[2] or 0) for r in assess_rows]
            return {
                "total_assessments": len(assess_rows),
                "total_vulnerabilities": len(vuln_rows),
                "by_severity": self.distribution_by_severity(tenant_id),
                "avg_risk": round(sum(risks) / len(risks), 2) if risks else 0.0,
                "recent_trend": self.trend_vulnerabilities(days=7, group_by="day"),
                "top_assets": self.top_targets(n=5, tenant_id=tenant_id),
            }
        except Exception as e:  # noqa: BLE001
            logger.error(f"get_summary 失败: {e}")
            return {
                "total_assessments": 0,
                "total_vulnerabilities": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "avg_risk": 0.0,
                "recent_trend": [],
                "top_assets": [],
            }

    # -------------------- 导出 --------------------

    def export_results(self, data: Any, format: str = "json") -> str:
        """导出结果为字符串。

        Args:
            data: 待导出数据（list[dict] 或 dict）
            format: 'json' 或 'csv'

        Returns:
            字符串内容
        """
        try:
            fmt = (format or "json").lower()
            if fmt == "csv":
                return self._to_csv(data)
            return json.dumps(data, ensure_ascii=False, indent=2, default=str)
        except Exception as e:  # noqa: BLE001
            logger.error(f"export_results 失败: {e}")
            return "[]" if format == "csv" else "{}"

    @staticmethod
    def _to_csv(data: Any) -> str:
        """把 list[dict] 扁平化为 CSV 字符串。"""
        try:
            if not data:
                return ""
            if isinstance(data, dict):
                # 单层 dict 转成 key,value 两列
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(["key", "value"])
                for k, v in data.items():
                    w.writerow([k, "" if v is None else v if isinstance(v, (str, int, float)) else json.dumps(v, ensure_ascii=False, default=str)])
                return buf.getvalue()
            if not isinstance(data, list):
                data = [data]
            # 收集全部字段
            fieldnames: List[str] = []
            seen = set()
            for item in data:
                if isinstance(item, dict):
                    for k in item.keys():
                        if k not in seen:
                            seen.add(k)
                            fieldnames.append(k)
            buf = io.StringIO()
            w = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
            w.writeheader()
            for item in data:
                if isinstance(item, dict):
                    row = {}
                    for k, v in item.items():
                        if v is None:
                            row[k] = ""
                        elif isinstance(v, (str, int, float, bool)):
                            row[k] = v
                        else:
                            row[k] = json.dumps(v, ensure_ascii=False, default=str)
                    w.writerow(row)
            return buf.getvalue()
        except Exception as e:  # noqa: BLE001
            logger.error(f"_to_csv 失败: {e}")
            return ""


# ==================== 全局单例 ====================
analytics_engine = AnalyticsEngine()
