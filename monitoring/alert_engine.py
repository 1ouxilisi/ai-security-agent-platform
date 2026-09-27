"""告警引擎模块。

提供：
- Alert: 告警对象
- AlertRule: 告警规则
- AlertEngine: 规则评估、告警触发、去重、通知（站内/邮件/Webhook）、
  确认/关闭/静默等生命周期管理，全部持久化到 JSON。
"""
import os
import json
import time
import uuid
import threading
from typing import Dict, List, Optional, Any

from utils.logger import log

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
MONITORING_DIR = os.path.join(DATA_DIR, "monitoring")
COLLAB_DIR = os.path.join(DATA_DIR, "collaboration")
os.makedirs(MONITORING_DIR, exist_ok=True)
os.makedirs(COLLAB_DIR, exist_ok=True)

ALERTS_FILE = os.path.join(MONITORING_DIR, "alerts.json")
RULES_FILE = os.path.join(MONITORING_DIR, "alert_rules.json")
NOTIFICATIONS_FILE = os.path.join(COLLAB_DIR, "notifications.json")
DEDUPE_WINDOW = 24 * 3600  # 24 小时去重窗口


def _load_env() -> Dict[str, str]:
    """从 .env 读取配置（简单解析，不依赖 python-dotenv）。"""
    env: Dict[str, str] = {}
    path = os.path.join(_PROJECT_ROOT, ".env")
    if not os.path.exists(path):
        return env
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    except Exception as e:
        log.warning(f"读取 .env 失败: {e}")
    return env


# --------------------------------------------------------------------------
# 数据类
# --------------------------------------------------------------------------
class Alert:
    """告警对象。"""

    def __init__(self, alert_id: str, rule_id: str, rule_name: str,
                 severity: str, title: str, description: str,
                 target: str = "", metadata: Optional[Dict[str, Any]] = None,
                 channel: str = "inapp"):
        self.alert_id = alert_id
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity          # critical/high/medium/low/info
        self.title = title
        self.description = description
        self.target = target
        self.metadata = metadata or {}
        self.status = "open"              # open/acknowledged/closed
        self.created_at = time.time()
        self.acknowledged_at: float = 0
        self.closed_at: float = 0
        self.acknowledged_by: str = ""
        self.channel = channel
        self._silence_until: float = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "target": self.target,
            "metadata": self.metadata,
            "status": self.status,
            "created_at": self.created_at,
            "acknowledged_at": self.acknowledged_at,
            "closed_at": self.closed_at,
            "acknowledged_by": self.acknowledged_by,
            "channel": self.channel,
            "silence_until": self._silence_until,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        a = cls(
            alert_id=data["alert_id"],
            rule_id=data.get("rule_id", ""),
            rule_name=data.get("rule_name", ""),
            severity=data.get("severity", "info"),
            title=data.get("title", ""),
            description=data.get("description", ""),
            target=data.get("target", ""),
            metadata=data.get("metadata", {}),
            channel=data.get("channel", "inapp"),
        )
        a.status = data.get("status", "open")
        a.created_at = data.get("created_at", time.time())
        a.acknowledged_at = data.get("acknowledged_at", 0)
        a.closed_at = data.get("closed_at", 0)
        a.acknowledged_by = data.get("acknowledged_by", "")
        a._silence_until = data.get("silence_until", 0)
        return a


class AlertRule:
    """告警规则。"""

    def __init__(self, rule_id: str, name: str, description: str,
                 condition_type: str, condition_params: Optional[Dict[str, Any]] = None,
                 severity: str = "medium", enabled: bool = True,
                 channels: Optional[List[str]] = None):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        # new_vuln / risk_change / tool_error / task_failed / quota_exceeded
        self.condition_type = condition_type
        self.condition_params = condition_params or {}
        self.severity = severity
        self.enabled = enabled
        self.channels = channels or ["inapp"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "condition_type": self.condition_type,
            "condition_params": self.condition_params,
            "severity": self.severity,
            "enabled": self.enabled,
            "channels": self.channels,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AlertRule":
        return cls(
            rule_id=data["rule_id"],
            name=data.get("name", ""),
            description=data.get("description", ""),
            condition_type=data.get("condition_type", "new_vuln"),
            condition_params=data.get("condition_params", {}),
            severity=data.get("severity", "medium"),
            enabled=data.get("enabled", True),
            channels=data.get("channels", ["inapp"]),
        )


# --------------------------------------------------------------------------
# 告警引擎
# --------------------------------------------------------------------------
class AlertEngine:
    """告警引擎。"""

    def __init__(self):
        self._rules: Dict[str, AlertRule] = {}
        self._alerts: Dict[str, Alert] = {}
        self._lock = threading.Lock()
        self._env = _load_env()
        self._load()
        if not self._rules:
            self._install_default_rules()
            self._save_rules()

    # ---------------- 持久化 ----------------
    def _load(self):
        try:
            if os.path.exists(ALERTS_FILE):
                with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                    for item in json.load(f):
                        a = Alert.from_dict(item)
                        self._alerts[a.alert_id] = a
            if os.path.exists(RULES_FILE):
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    for item in json.load(f):
                        r = AlertRule.from_dict(item)
                        self._rules[r.rule_id] = r
        except Exception as e:
            log.warning(f"加载告警数据失败: {e}")

    def _save_alerts(self):
        try:
            with open(ALERTS_FILE, "w", encoding="utf-8") as f:
                json.dump([a.to_dict() for a in self._alerts.values()],
                          f, ensure_ascii=False, indent=2)
        except Exception as e:
            log.warning(f"保存告警失败: {e}")

    def _save_rules(self):
        try:
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump([r.to_dict() for r in self._rules.values()],
                          f, ensure_ascii=False, indent=2)
        except Exception as e:
            log.warning(f"保存规则失败: {e}")

    # ---------------- 默认规则 ----------------
    def _install_default_rules(self):
        defaults = [
            ("r-new-vuln", "新高危漏洞", "当扫描发现新的高危/严重漏洞时触发",
             "new_vuln", {"min_severity": "high"}, "critical", ["inapp"]),
            ("r-task-failed", "任务失败", "当扫描任务连续失败时触发",
             "task_failed", {"max_retries": 3}, "high", ["inapp", "webhook"]),
            ("r-tool-error", "工具异常", "当外部扫描工具报错/不可用时触发",
             "tool_error", {}, "medium", ["inapp"]),
            ("r-quota", "配额超限", "当 API/扫描配额超过阈值时触发",
             "quota_exceeded", {"threshold_percent": 90}, "medium", ["inapp", "email"]),
            ("r-risk-change", "风险等级变化", "当目标整体风险等级上升时触发",
             "risk_change", {"direction": "up"}, "high", ["inapp", "webhook"]),
        ]
        for rid, name, desc, ctype, params, sev, chans in defaults:
            self._rules[rid] = AlertRule(
                rule_id=rid, name=name, description=desc,
                condition_type=ctype, condition_params=params,
                severity=sev, channels=chans)
        log.info(f"已安装 {len(defaults)} 条默认告警规则")

    # ---------------- 规则管理 ----------------
    def add_rule(self, rule: AlertRule) -> AlertRule:
        with self._lock:
            self._rules[rule.rule_id] = rule
            self._save_rules()
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                self._save_rules()
                return True
            return False

    def list_rules(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in self._rules.values()]

    # ---------------- 评估与触发 ----------------
    def evaluate(self, rule: AlertRule, context: Dict[str, Any]) -> bool:
        """根据规则条件类型评估 context 是否触发。"""
        ct = rule.condition_type
        params = rule.condition_params or {}
        try:
            if ct == "new_vuln":
                sev = str(context.get("severity", "")).lower()
                order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                min_s = order.get(str(params.get("min_severity", "high")), 3)
                return order.get(sev, -1) >= min_s
            if ct == "task_failed":
                return bool(context.get("failed"))
            if ct == "tool_error":
                return bool(context.get("error")) or bool(context.get("tool_down"))
            if ct == "quota_exceeded":
                pct = float(context.get("usage_percent", 0))
                return pct >= float(params.get("threshold_percent", 90))
            if ct == "risk_change":
                old = context.get("old_risk", "low")
                new = context.get("new_risk", "low")
                order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                if params.get("direction", "up") == "up":
                    return order.get(new, 0) > order.get(old, 0)
                return order.get(new, 0) < order.get(old, 0)
        except Exception as e:
            log.warning(f"规则 {rule.rule_id} 评估异常: {e}")
        return False

    def _is_duplicate(self, rule_id: str, target: str) -> Optional[Alert]:
        """24 小时内相同 rule+target 的 open 告警视为重复。"""
        now = time.time()
        for a in self._alerts.values():
            if (a.rule_id == rule_id and a.target == target
                    and a.status in ("open", "acknowledged")
                    and now - a.created_at < DEDUPE_WINDOW):
                return a
        return None

    def trigger_alert(self, rule: AlertRule, context: Dict[str, Any]) -> Optional[Alert]:
        """触发告警：评估 -> 去重 -> 创建 -> 通知。"""
        if not rule.enabled:
            return None
        if not self.evaluate(rule, context):
            return None
        target = context.get("target", "")
        with self._lock:
            dup = self._is_duplicate(rule.rule_id, target)
            if dup is not None:
                log.info(f"告警去重: 合并到已有告警 {dup.alert_id}")
                return dup
            alert = Alert(
                alert_id=str(uuid.uuid4())[:8],
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=context.get("severity", rule.severity),
                title=context.get("title", rule.name),
                description=context.get("description", rule.description),
                target=target,
                metadata=context.get("metadata", context),
                channel=",".join(rule.channels),
            )
            self._alerts[alert.alert_id] = alert
            self._save_alerts()
        # 发送通知（在锁外，避免阻塞）
        for ch in rule.channels:
            try:
                self.send_notification(alert, ch)
            except Exception as e:
                log.warning(f"告警通知发送失败(channel={ch}): {e}")
        log.warning(f"触发告警: [{alert.severity}] {alert.title} -> {target}")
        return alert

    # ---------------- 告警查询与生命周期 ----------------
    def list_alerts(self, status: Optional[str] = None,
                    severity: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._alerts.values())
        if status:
            items = [a for a in items if a.status == status]
        if severity:
            items = [a for a in items if a.severity == severity]
        items.sort(key=lambda a: a.created_at, reverse=True)
        return [a.to_dict() for a in items[:limit]]

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            a = self._alerts.get(alert_id)
            return a.to_dict() if a else None

    def acknowledge_alert(self, alert_id: str, user: str = "") -> bool:
        with self._lock:
            a = self._alerts.get(alert_id)
            if not a:
                return False
            a.status = "acknowledged"
            a.acknowledged_at = time.time()
            a.acknowledged_by = user
            self._save_alerts()
            return True

    def close_alert(self, alert_id: str, user: str = "") -> bool:
        with self._lock:
            a = self._alerts.get(alert_id)
            if not a:
                return False
            a.status = "closed"
            a.closed_at = time.time()
            a.acknowledged_by = user or a.acknowledged_by
            self._save_alerts()
            return True

    def silence_alert(self, alert_id: str, duration_seconds: int) -> bool:
        with self._lock:
            a = self._alerts.get(alert_id)
            if not a:
                return False
            a._silence_until = time.time() + int(duration_seconds)
            self._save_alerts()
            return True

    # ---------------- 通知渠道 ----------------
    def send_notification(self, alert: Alert, channel: str) -> bool:
        """发送通知：inapp / email / webhook。"""
        try:
            if channel == "inapp":
                return self._notify_inapp(alert)
            if channel == "email":
                return self._notify_email(alert)
            if channel == "webhook":
                return self._notify_webhook(alert)
            log.debug(f"未知通知渠道: {channel}")
            return False
        except Exception as e:
            log.warning(f"通知({channel})失败: {e}")
            return False

    def _notify_inapp(self, alert: Alert) -> bool:
        """站内通知：写入 data/collaboration/notifications.json。"""
        os.makedirs(COLLAB_DIR, exist_ok=True)
        notes: List[Dict[str, Any]] = []
        if os.path.exists(NOTIFICATIONS_FILE):
            try:
                with open(NOTIFICATIONS_FILE, "r", encoding="utf-8") as f:
                    notes = json.load(f)
            except Exception:
                notes = []
        notes.append({
            "id": str(uuid.uuid4())[:8],
            "type": "alert",
            "severity": alert.severity,
            "title": alert.title,
            "body": alert.description,
            "target": alert.target,
            "alert_id": alert.alert_id,
            "created_at": time.time(),
            "read": False,
        })
        with open(NOTIFICATIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(notes[-200:], f, ensure_ascii=False, indent=2)
        return True

    def _notify_email(self, alert: Alert) -> bool:
        """邮件通知：SMTP 配置从 .env 读取。"""
        host = self._env.get("SMTP_HOST")
        if not host:
            log.info("未配置 SMTP_HOST，跳过邮件告警")
            return False
        import smtplib
        from email.mime.text import MIMEText
        port = int(self._env.get("SMTP_PORT", "465"))
        user = self._env.get("SMTP_USER", "")
        password = self._env.get("SMTP_PASS", "")
        sender = self._env.get("SMTP_FROM", user)
        receiver = self._env.get("SMTP_TO", user)
        msg = MIMEText(f"[{alert.severity}] {alert.title}\n\n{alert.description}\n目标: {alert.target}",
                       "plain", "utf-8")
        msg["Subject"] = f"[告警] {alert.title}"
        msg["From"] = sender
        msg["To"] = receiver
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls()
        if user:
            server.login(user, password)
        server.sendmail(sender, [receiver], msg.as_string())
        server.quit()
        log.info(f"邮件告警已发送至 {receiver}")
        return True

    def _notify_webhook(self, alert: Alert) -> bool:
        """Webhook 通知：POST JSON 到配置 URL。"""
        url = self._env.get("ALERT_WEBHOOK_URL")
        if not url:
            log.info("未配置 ALERT_WEBHOOK_URL，跳过 webhook 告警")
            return False
        import requests
        payload = alert.to_dict()
        resp = requests.post(url, json=payload, timeout=5)
        return resp.status_code < 400


# 模块级单例
_alert_engine_instance: Optional[AlertEngine] = None


def get_alert_engine() -> AlertEngine:
    global _alert_engine_instance
    if _alert_engine_instance is None:
        _alert_engine_instance = AlertEngine()
    return _alert_engine_instance
