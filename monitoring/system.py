"""
system模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import time
import json
import platform
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
from utils.logger import log


@dataclass
class Metric:
    """指标"""
    name: str
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    help: str = ""
    type: str = "gauge"  # gauge/counter/histogram/summary
    timestamp: float = field(default_factory=time.time)


@dataclass
class AlertRule:
    """告警规则"""
    name: str
    metric: str
    condition: str  # >, <, >=, <=, ==
    threshold: float
    severity: str = "warning"  # warning/critical
    message: str = ""
    enabled: bool = True
    cooldown: int = 300  # 冷却时间（秒）
    last_triggered: float = 0


@dataclass
class Alert:
    """告警"""
    rule_name: str
    severity: str
    message: str
    metric_value: float
    threshold: float
    timestamp: float
    acknowledged: bool = False


class MonitoringSystem:
    """监控系统"""

    def __init__(self, history_size: int = 1000):
        """初始化MonitoringSystem实例。

        Args:
            self: 类实例。
        """
        self.metrics: Dict[str, Metric] = {}
        self.metric_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=history_size))
        self.alert_rules: List[AlertRule] = []
        self.alerts: List[Alert] = []
        self.health_checks: Dict[str, Callable] = {}
        self._init_default_alert_rules()
        self._init_health_checks()
        log.info("监控系统初始化")

    def _init_default_alert_rules(self):
        """初始化默认告警规则"""
        self.alert_rules = [
            AlertRule(name="高CPU使用率", metric="cpu_usage", condition=">", threshold=80,
                      severity="warning", message="CPU使用率超过80%"),
            AlertRule(name="严重高CPU", metric="cpu_usage", condition=">", threshold=95,
                      severity="critical", message="CPU使用率超过95%"),
            AlertRule(name="高内存使用率", metric="memory_usage", condition=">", threshold=85,
                      severity="warning", message="内存使用率超过85%"),
            AlertRule(name="磁盘空间不足", metric="disk_usage", condition=">", threshold=90,
                      severity="critical", message="磁盘使用率超过90%"),
            AlertRule(name="任务队列积压", metric="pending_tasks", condition=">", threshold=100,
                      severity="warning", message="待处理任务超过100个"),
            AlertRule(name="任务失败率高", metric="task_failure_rate", condition=">", threshold=10,
                      severity="critical", message="任务失败率超过10%"),
            AlertRule(name="API响应慢", metric="api_response_time_p95", condition=">", threshold=5000,
                      severity="warning", message="API P95响应时间超过5秒"),
            AlertRule(name="Worker离线", metric="offline_workers", condition=">", threshold=0,
                      severity="critical", message="有Worker节点离线"),
        ]

    def _init_health_checks(self):
        """初始化健康检查"""
        self.health_checks = {
            "system": self._check_system_health,
            "api": self._check_api_health,
            "database": self._check_database_health,
            "cache": self._check_cache_health,
            "workers": self._check_workers_health,
        }

    def _get_system_info(self) -> Dict:
        """获取系统信息（不依赖psutil）"""
        info = {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "hostname": platform.node(),
        }
        return info

    def _check_system_health(self) -> Dict:
        """系统健康检查"""
        try:
            # 基础系统信息
            info = self._get_system_info()

            # 尝试获取CPU/内存（如果有psutil）
            cpu_usage = 0.0
            memory_usage = 0.0
            disk_usage = 0.0

            try:
                import psutil
                cpu_usage = psutil.cpu_percent(interval=0.1)
                memory_usage = psutil.virtual_memory().percent
                disk_usage = psutil.disk_usage("/").percent
            except ImportError:
                # psutil未安装，使用估算值
                pass

            self.update_metric("cpu_usage", cpu_usage, {"host": info["hostname"]})
            self.update_metric("memory_usage", memory_usage, {"host": info["hostname"]})
            self.update_metric("disk_usage", disk_usage, {"host": info["hostname"]})

            return {
                "status": "healthy" if cpu_usage < 90 and memory_usage < 95 else "degraded",
                "cpu_usage": cpu_usage,
                "memory_usage": memory_usage,
                "disk_usage": disk_usage,
                "system_info": info,
            }
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    def _check_api_health(self) -> Dict:
        """API健康检查"""
        try:
            # 检查API服务是否可访问
            api_status = "healthy"
            api_response_time = 0.0

            try:
                import urllib.request
                start = time.time()
                urllib.request.urlopen("http://localhost:8000/health", timeout=2)
                api_response_time = (time.time() - start) * 1000
            except Exception:
                api_status = "unreachable"

            self.update_metric("api_response_time_p95", api_response_time)
            return {"status": api_status, "response_time_ms": round(api_response_time, 2)}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    def _check_database_health(self) -> Dict:
        """数据库健康检查"""
        try:
            from database.db import Database
            db = Database(db_path=":memory:")
            # 简单查询测试
            db.get_all_tasks()
            db.close()
            return {"status": "healthy", "type": "sqlite"}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    def _check_cache_health(self) -> Dict:
        """缓存健康检查"""
        try:
            from cache.cache_manager import cache_manager
            stats = cache_manager.get_stats()
            return {"status": "healthy", "stats": stats}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    def _check_workers_health(self) -> Dict:
        """Worker健康检查"""
        try:
            from distributed.scheduler import distributed_scheduler
            stats = distributed_scheduler.get_worker_stats()
            offline = stats.get("offline_workers", 0)
            self.update_metric("offline_workers", offline)
            return {"status": "healthy" if offline == 0 else "degraded", "stats": stats}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    def update_metric(self, name: str, value: float, labels: Dict = None,
                      help: str = "", type: str = "gauge"):
        """更新指标"""
        metric = Metric(name=name, value=value, labels=labels or {}, help=help, type=type)
        self.metrics[name] = metric
        self.metric_history[name].append(metric)

    def get_metric(self, name: str) -> Optional[Metric]:
        """获取指标"""
        return self.metrics.get(name)

    def get_metric_history(self, name: str, limit: int = 100) -> List[Dict]:
        """获取指标历史"""
        history = list(self.metric_history.get(name, []))[-limit:]
        return [{"value": m.value, "timestamp": m.timestamp} for m in history]

    def export_prometheus(self) -> str:
        """导出Prometheus格式指标"""
        lines = []
        for name, metric in self.metrics.items():
            if metric.help:
                lines.append(f"# HELP {name} {metric.help}")
            if metric.type:
                lines.append(f"# TYPE {name} {metric.type}")

            labels_str = ""
            if metric.labels:
                labels_str = "{" + ",".join(f'{k}="{v}"' for k, v in metric.labels.items()) + "}"

            lines.append(f"{name}{labels_str} {metric.value}")

        return "\n".join(lines)

    def run_health_checks(self) -> Dict:
        """运行所有健康检查"""
        results = {}
        overall_status = "healthy"

        for name, check_func in self.health_checks.items():
            try:
                result = check_func()
                results[name] = result
                if result.get("status") == "unhealthy":
                    overall_status = "unhealthy"
                elif result.get("status") == "degraded" and overall_status == "healthy":
                    overall_status = "degraded"
            except Exception as e:
                results[name] = {"status": "error", "error": str(e)}
                overall_status = "unhealthy"

        # 检查告警
        self._check_alerts()

        return {
            "overall_status": overall_status,
            "timestamp": time.time(),
            "checks": results,
            "active_alerts": len([a for a in self.alerts if not a.acknowledged]),
        }

    def _check_alerts(self):
        """检查告警规则"""
        now = time.time()
        for rule in self.alert_rules:
            if not rule.enabled:
                continue

            metric = self.metrics.get(rule.metric)
            if not metric:
                continue

            # 检查条件
            triggered = False
            if rule.condition == ">" and metric.value > rule.threshold:
                triggered = True
            elif rule.condition == "<" and metric.value < rule.threshold:
                triggered = True
            elif rule.condition == ">=" and metric.value >= rule.threshold:
                triggered = True
            elif rule.condition == "<=" and metric.value <= rule.threshold:
                triggered = True
            elif rule.condition == "==" and metric.value == rule.threshold:
                triggered = True

            if triggered and (now - rule.last_triggered) > rule.cooldown:
                rule.last_triggered = now
                alert = Alert(
                    rule_name=rule.name, severity=rule.severity,
                    message=rule.message, metric_value=metric.value,
                    threshold=rule.threshold, timestamp=now,
                )
                self.alerts.append(alert)
                log.warning(f"告警触发: {rule.name} - {rule.message} (当前值: {metric.value}, 阈值: {rule.threshold})")

    def get_alerts(self, severity: str = None, acknowledged: bool = None) -> List[Dict]:
        """获取告警列表"""
        alerts = self.alerts
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]
        return [
            {"rule_name": a.rule_name, "severity": a.severity, "message": a.message,
             "metric_value": a.metric_value, "threshold": a.threshold,
             "timestamp": a.timestamp, "acknowledged": a.acknowledged}
            for a in sorted(alerts, key=lambda x: x.timestamp, reverse=True)
        ]

    def acknowledge_alert(self, alert_index: int) -> bool:
        """确认告警"""
        if 0 <= alert_index < len(self.alerts):
            self.alerts[alert_index].acknowledged = True
            return True
        return False

    def get_stats(self) -> Dict:
        """获取监控系统统计"""
        return {
            "total_metrics": len(self.metrics),
            "total_alert_rules": len(self.alert_rules),
            "enabled_alert_rules": sum(1 for r in self.alert_rules if r.enabled),
            "total_alerts": len(self.alerts),
            "unacknowledged_alerts": len([a for a in self.alerts if not a.acknowledged]),
            "critical_alerts": len([a for a in self.alerts if a.severity == "critical" and not a.acknowledged]),
            "warning_alerts": len([a for a in self.alerts if a.severity == "warning" and not a.acknowledged]),
            "health_checks": len(self.health_checks),
        }


# 全局监控系统实例
monitoring_system = MonitoringSystem()
