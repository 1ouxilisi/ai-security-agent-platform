# -*- coding: utf-8 -*-
"""
performance/slow_query_monitor.py — 慢查询实时监控器（单例）

功能：
    - 实时监控：超过阈值立即记录（与 query_optimizer 集成）；
    - 告警通知：慢查询数量超过阈值时自动记录告警事件；
    - 慢查询日志：持久化到 JSON 文件（语句/参数/耗时/调用栈/时间）；
    - 模式分析：频繁慢查询 / 特定表 / 特定时间段 / Top N；
    - 慢查询报告：列表 / 统计 / 分析 / 优化建议。

仅依赖标准库，日志持久化到 data/performance/slow_query_log.json。
"""
import json
import os
import threading
import time
from collections import Counter
from typing import Any, Dict, List, Optional


class SlowQueryMonitor:
    """慢查询实时监控器：记录、告警、日志、分析、报告。单例。"""

    _instance: Optional["SlowQueryMonitor"] = None
    _lock = threading.Lock()

    def __new__(cls, threshold_ms: float = 100.0) -> "SlowQueryMonitor":
        """线程安全单例构造。"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    obj = super().__new__(cls)
                    obj._init(threshold_ms)
                    cls._instance = obj
        return cls._instance

    def _init(self, threshold_ms: float) -> None:
        """初始化阈值、监控开关、日志与告警存储。"""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.data_dir = os.path.join(root, "data", "performance")
        os.makedirs(self.data_dir, exist_ok=True)
        self._log_path = os.path.join(self.data_dir, "slow_query_log.json")
        self.threshold_ms = threshold_ms
        self.alert_threshold = 20          # 单位时间窗内告警阈值
        self._window_seconds = 60          # 统计窗口
        self._monitoring = False
        self._log: List[Dict[str, Any]] = []
        self._alerts: List[Dict[str, Any]] = []
        self._load_log()

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------
    def _load_log(self) -> None:
        """从 JSON 文件恢复历史慢查询日志（容错）。"""
        try:
            if os.path.exists(self._log_path):
                with open(self._log_path, "r", encoding="utf-8") as f:
                    self._log = json.load(f)
        except Exception:
            self._log = []

    def _save_log(self) -> None:
        """将日志写入 JSON 文件（仅保留最近 2000 条）。"""
        try:
            self._log = self._log[-2000:]
            with open(self._log_path, "w", encoding="utf-8") as f:
                json.dump(self._log, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 监控开关
    # ------------------------------------------------------------------
    def start_monitoring(self, threshold_ms: float = 100.0) -> Dict[str, Any]:
        """启动慢查询监控。

        Args:
            threshold_ms: 慢查询阈值（毫秒）。

        Returns:
            Dict: 启动状态。
        """
        self.threshold_ms = threshold_ms
        self._monitoring = True
        return {"monitoring": True, "threshold_ms": threshold_ms}

    def stop_monitoring(self) -> Dict[str, Any]:
        """停止慢查询监控。"""
        self._monitoring = False
        return {"monitoring": False}

    @property
    def is_monitoring(self) -> bool:
        """当前是否处于监控状态。"""
        return self._monitoring

    # ------------------------------------------------------------------
    # 记录慢查询
    # ------------------------------------------------------------------
    def record_slow_query(self,
                          sql: str,
                          execution_time: float,
                          params: Optional[Any] = None) -> Optional[str]:
        """记录一条慢查询（若超过阈值）。

        Args:
            sql: SQL 语句。
            execution_time: 执行时间（毫秒）。
            params: 查询参数。

        Returns:
            Optional[str]: 记录 id；未超阈值返回 None。
        """
        try:
            if execution_time < self.threshold_ms:
                return None
            rid = f"sq_{int(time.time() * 1000)}_{len(self._log)}"
            entry = {
                "id": rid,
                "sql": sql,
                "execution_time_ms": round(float(execution_time), 3),
                "params": self._safe_params(params),
                "timestamp": time.time(),
            }
            self._log.append(entry)
            self._save_log()
            # 集成 query_optimizer 记录
            try:
                from performance.query_optimizer import query_optimizer
                query_optimizer.record_query(sql, execution_time, params=params)
            except Exception:
                pass
            # 告警检测
            self._check_alert()
            return rid
        except Exception:
            return None

    @staticmethod
    def _safe_params(params: Any) -> Any:
        """参数可序列化处理。"""
        try:
            json.dumps(params)
            return params
        except Exception:
            return str(params)

    def _check_alert(self) -> None:
        """统计时间窗内慢查询数量，超过阈值则记录告警事件。"""
        try:
            now = time.time()
            recent = [e for e in self._log
                      if now - e.get("timestamp", 0) <= self._window_seconds]
            if len(recent) >= self.alert_threshold:
                self._alerts.append({
                    "level": "warning",
                    "message": f"{self._window_seconds}s 内慢查询 {len(recent)} 次，"
                               f"超过阈值 {self.alert_threshold}",
                    "count": len(recent),
                    "timestamp": now,
                })
                # 仅保留最近 200 条告警
                self._alerts = self._alerts[-200:]
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 查询接口
    # ------------------------------------------------------------------
    def get_alerts(self) -> List[Dict[str, Any]]:
        """获取告警事件列表（倒序）。"""
        try:
            return list(reversed(self._alerts))
        except Exception:
            return []

    def get_slow_query_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取慢查询日志（最新在前）。"""
        try:
            return list(reversed(self._log))[:max(1, limit)]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # 模式分析
    # ------------------------------------------------------------------
    def analyze_patterns(self) -> Dict[str, Any]:
        """分析慢查询模式：频繁 SQL / 高峰时段 / Top N 耗时。"""
        patterns: Dict[str, Any] = {
            "total": len(self._log),
            "frequent_queries": [],
            "peak_hours": [],
            "top_slow": [],
        }
        try:
            if not self._log:
                return patterns
            sql_counter: Counter = Counter(e.get("sql", "") for e in self._log)
            patterns["frequent_queries"] = [
                {"sql": sql, "count": cnt}
                for sql, cnt in sql_counter.most_common(5)
            ]
            hour_counter: Counter = Counter(
                int(time.localtime(e.get("timestamp", 0)).tm_hour) for e in self._log
            )
            patterns["peak_hours"] = [
                {"hour": h, "count": cnt} for h, cnt in hour_counter.most_common(5)
            ]
            top = sorted(self._log,
                         key=lambda e: e.get("execution_time_ms", 0), reverse=True)[:10]
            patterns["top_slow"] = [
                {"sql": e.get("sql", "")[:120],
                 "execution_time_ms": e.get("execution_time_ms", 0)}
                for e in top
            ]
        except Exception as e:
            patterns["error"] = str(e)
        return patterns

    # ------------------------------------------------------------------
    # 报告
    # ------------------------------------------------------------------
    def generate_report(self,
                        time_range: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
        """生成慢查询报告。

        Args:
            time_range: {"start": ts, "end": ts}；为空则取全部日志。

        Returns:
            Dict: 报告（列表/统计/分析/建议）。
        """
        report: Dict[str, Any] = {
            "generated_at": time.time(),
            "threshold_ms": self.threshold_ms,
            "monitoring": self._monitoring,
        }
        try:
            entries = self._log
            if time_range:
                start = time_range.get("start", 0)
                end = time_range.get("end", time.time())
                entries = [e for e in entries if start <= e.get("timestamp", 0) <= end]
            report["count"] = len(entries)
            if entries:
                times = sorted(e.get("execution_time_ms", 0) for e in entries)
                report["stats"] = {
                    "avg_ms": round(sum(times) / len(times), 3),
                    "max_ms": round(max(times), 3),
                    "min_ms": round(min(times), 3),
                }
            else:
                report["stats"] = {}
            report["patterns"] = self.analyze_patterns()
            report["alerts"] = self.get_alerts()
            # 优化建议
            suggestions: List[str] = []
            try:
                from performance.query_optimizer import query_optimizer
                for sql in report["patterns"].get("frequent_queries", [])[:3]:
                    for sug in query_optimizer.get_optimization_suggestions(sql["sql"]):
                        suggestions.append(sug.get("message", ""))
            except Exception:
                pass
            report["suggestions"] = suggestions[:10]
            report["recent"] = [
                {"sql": e.get("sql", "")[:120],
                 "execution_time_ms": e.get("execution_time_ms", 0),
                 "timestamp": e.get("timestamp", 0)}
                for e in list(reversed(entries))[:20]
            ]
        except Exception as e:
            report["error"] = str(e)
        return report


# 模块级单例
slow_query_monitor = SlowQueryMonitor()
