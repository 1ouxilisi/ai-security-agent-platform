"""
alert_manager安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import time
import smtplib
import sqlite3
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, field
from utils.logger import log


@dataclass
class Alert:
    """告警"""
    alert_id: str
    title: str
    message: str
    severity: str = "info"  # critical/high/warning/info
    category: str = "general"  # vulnerability/system/security/compliance
    target: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    status: str = "new"  # new/acknowledged/resolved
    notified_channels: List[str] = field(default_factory=list)


@dataclass
class NotificationChannel:
    """通知渠道"""
    channel_id: str
    name: str
    type: str  # email/dingtalk/feishu/wecom/slack/webhook
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""


class AlertManager:
    """告警管理器"""

    def __init__(self, db_path: str = None):
        """初始化AlertManager实例。

        Args:
            self: 类实例。
        """
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data", "alerts.db"
            )
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """初始化数据库"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 告警表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                message TEXT,
                severity TEXT DEFAULT 'info',
                category TEXT DEFAULT 'general',
                target TEXT,
                details TEXT,
                created_at TEXT,
                status TEXT DEFAULT 'new',
                notified_channels TEXT
            )
        """)

        # 通知渠道表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS channels (
                channel_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                config TEXT,
                created_at TEXT
            )
        """)

        # 通知记录表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                notification_id TEXT PRIMARY KEY,
                alert_id TEXT,
                channel_id TEXT,
                channel_type TEXT,
                status TEXT,
                response TEXT,
                created_at TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at)")

        conn.commit()
        conn.close()

    # ==================== 告警创建 ====================

    def create_alert(self, title: str, message: str, severity: str = "info",
                     category: str = "general", target: str = "",
                     details: Dict[str, Any] = None,
                     auto_notify: bool = True) -> Dict[str, Any]:
        """创建告警"""
        import secrets
        alert_id = "alert_" + secrets.token_hex(12)
        now = datetime.now().isoformat()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (alert_id, title, message, severity, category, target, details, created_at, status, notified_channels)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (alert_id, title, message, severity, category, target,
              json.dumps(details or {}), now, "new", json.dumps([])))
        conn.commit()
        conn.close()

        log.info(f"告警创建: [{severity.upper()}] {title}")

        alert = Alert(
            alert_id=alert_id, title=title, message=message,
            severity=severity, category=category, target=target,
            details=details or {}, created_at=now, status="new"
        )

        if auto_notify:
            self.notify_alert(alert)

        return {
            "success": True,
            "alert_id": alert_id,
            "severity": severity,
            "title": title,
            "message": "告警已创建" + ("并已通知" if auto_notify else ""),
        }

    # ==================== 通知渠道管理 ====================

    def add_channel(self, name: str, channel_type: str,
                    config: Dict[str, Any]) -> Dict[str, Any]:
        """添加通知渠道"""
        import secrets
        channel_id = "ch_" + secrets.token_hex(8)
        now = datetime.now().isoformat()

        valid_types = ["email", "dingtalk", "feishu", "wecom", "slack", "webhook"]
        if channel_type not in valid_types:
            return {"success": False, "error": f"不支持的渠道类型: {channel_type}，支持: {valid_types}"}

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO channels (channel_id, name, type, enabled, config, created_at)
            VALUES (?, ?, ?, 1, ?, ?)
        """, (channel_id, name, channel_type, json.dumps(config), now))
        conn.commit()
        conn.close()

        return {
            "success": True,
            "channel_id": channel_id,
            "name": name,
            "type": channel_type,
            "message": "通知渠道已添加",
        }

    def list_channels(self) -> List[Dict[str, Any]]:
        """列出通知渠道"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT channel_id, name, type, enabled, created_at FROM channels ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "channel_id": r[0], "name": r[1], "type": r[2],
                "enabled": bool(r[3]), "created_at": r[4],
            }
            for r in rows
        ]

    # ==================== 通知发送 ====================

    def notify_alert(self, alert: Alert) -> Dict[str, Any]:
        """发送告警通知到所有启用的渠道"""
        channels = self.list_channels()
        enabled_channels = [c for c in channels if c["enabled"]]

        results = []
        for channel in enabled_channels:
            try:
                result = self._send_to_channel(channel, alert)
                results.append(result)
                self._record_notification(alert.alert_id, channel["channel_id"],
                                           channel["type"], result)
            except Exception as e:
                log.error(f"通知发送失败 [{channel['name']}]: {e}")
                results.append({
                    "channel": channel["name"],
                    "type": channel["type"],
                    "success": False,
                    "error": str(e),
                })

        return {
            "alert_id": alert.alert_id,
            "channels_notified": len(results),
            "success_count": sum(1 for r in results if r.get("success")),
            "failed_count": sum(1 for r in results if not r.get("success")),
            "results": results,
        }

    def _send_to_channel(self, channel: Dict[str, Any], alert: Alert) -> Dict[str, Any]:
        """发送到指定渠道"""
        channel_type = channel["type"]

        # 获取渠道配置
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT config FROM channels WHERE channel_id = ?", (channel["channel_id"],))
        row = cursor.fetchone()
        conn.close()

        config = json.loads(row[0]) if row and row[0] else {}

        if channel_type == "email":
            return self._send_email(config, alert)
        elif channel_type == "dingtalk":
            return self._send_dingtalk(config, alert)
        elif channel_type == "feishu":
            return self._send_feishu(config, alert)
        elif channel_type == "wecom":
            return self._send_wecom(config, alert)
        elif channel_type == "slack":
            return self._send_slack(config, alert)
        elif channel_type == "webhook":
            return self._send_webhook(config, alert)
        else:
            return {"success": False, "error": f"不支持的渠道类型: {channel_type}"}

    def _send_email(self, config: Dict[str, Any], alert: Alert) -> Dict[str, Any]:
        """发送邮件通知"""
        try:
            smtp_server = config.get("smtp_server", "smtp.qq.com")
            smtp_port = config.get("smtp_port", 587)
            username = config.get("username", "")
            password = config.get("password", "")
            from_addr = config.get("from_addr", username)
            to_addrs = config.get("to_addrs", [])

            if not username or not password or not to_addrs:
                return {"success": False, "error": "邮件配置不完整"}

            severity_emoji = {"critical": "🔴", "high": "🟠", "warning": "🟡", "info": "🔵"}.get(alert.severity, "⚪")

            msg = MIMEMultipart()
            msg["From"] = from_addr
            msg["To"] = ", ".join(to_addrs)
            msg["Subject"] = f"{severity_emoji} [{alert.severity.upper()}] {alert.title}"

            body = f"""
安全告警通知
{'='*50}

告警级别: {alert.severity.upper()}
告警类型: {alert.category}
告警时间: {alert.created_at}
目标: {alert.target or 'N/A'}

告警标题: {alert.title}

告警详情:
{alert.message}

详细信息:
{json.dumps(alert.details, indent=2, ensure_ascii=False)}

{'='*50}
此邮件由AI Hacking Agent自动发送，请勿直接回复。
"""
            msg.attach(MIMEText(body, "plain", "utf-8"))

            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(username, password)
            server.sendmail(from_addr, to_addrs, msg.as_string())
            server.quit()

            return {"success": True, "channel": "email", "message": "邮件发送成功"}
        except Exception as e:
            return {"success": False, "channel": "email", "error": str(e)}

    def _send_dingtalk(self, config: Dict[str, Any], alert: Alert) -> Dict[str, Any]:
        """发送钉钉通知"""
        try:
            import requests
            webhook_url = config.get("webhook_url", "")
            secret = config.get("secret", "")

            if not webhook_url:
                return {"success": False, "error": "钉钉webhook_url未配置"}

            severity_emoji = {"critical": "🔴", "high": "🟠", "warning": "🟡", "info": "🔵"}.get(alert.severity, "⚪")

            content = f"{severity_emoji} **[{alert.severity.upper()}] {alert.title}**\n\n"
            content += f"**告警类型**: {alert.category}\n"
            content += f"**告警时间**: {alert.created_at}\n"
            if alert.target:
                content += f"**目标**: {alert.target}\n"
            content += f"\n**详情**: {alert.message}\n"

            payload = {
                "msgtype": "markdown",
                "markdown": {
                    "title": f"[{alert.severity.upper()}] {alert.title}",
                    "text": content,
                },
            }

            # 如果配置了secret，进行签名
            if secret:
                import hmac
                import hashlib
                import base64
                import urllib.parse
                timestamp = str(round(time.time() * 1000))
                string_to_sign = f"{timestamp}\n{secret}"
                hmac_code = hmac.new(secret.encode(), string_to_sign.encode(),
                                     digestmod=hashlib.sha256).digest()
                sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
                webhook_url = f"{webhook_url}&timestamp={timestamp}&sign={sign}"

            response = requests.post(webhook_url, json=payload, timeout=10)
            result = response.json()

            return {
                "success": result.get("errcode") == 0,
                "channel": "dingtalk",
                "response": result,
            }
        except Exception as e:
            return {"success": False, "channel": "dingtalk", "error": str(e)}

    def _send_feishu(self, config: Dict[str, Any], alert: Alert) -> Dict[str, Any]:
        """发送飞书通知"""
        try:
            import requests
            webhook_url = config.get("webhook_url", "")

            if not webhook_url:
                return {"success": False, "error": "飞书webhook_url未配置"}

            severity_color = {"critical": "red", "high": "orange", "warning": "yellow", "info": "blue"}.get(alert.severity, "grey")

            content = f"**[{alert.severity.upper()}] {alert.title}**\n"
            content += f"告警类型: {alert.category}\n"
            content += f"告警时间: {alert.created_at}\n"
            if alert.target:
                content += f"目标: {alert.target}\n"
            content += f"\n详情: {alert.message}"

            payload = {
                "msg_type": "interactive",
                "card": {
                    "header": {
                        "title": {"tag": "plain_text", "content": f"安全告警 - {alert.severity.upper()}"},
                        "template": severity_color,
                    },
                    "elements": [
                        {"tag": "markdown", "content": content},
                    ],
                },
            }

            response = requests.post(webhook_url, json=payload, timeout=10)
            result = response.json()

            return {
                "success": result.get("code") == 0 or result.get("StatusCode") == 0,
                "channel": "feishu",
                "response": result,
            }
        except Exception as e:
            return {"success": False, "channel": "feishu", "error": str(e)}

    def _send_wecom(self, config: Dict[str, Any], alert: Alert) -> Dict[str, Any]:
        """发送企业微信通知"""
        try:
            import requests
            webhook_url = config.get("webhook_url", "")

            if not webhook_url:
                return {"success": False, "error": "企业微信webhook_url未配置"}

            content = f"[{alert.severity.upper()}] {alert.title}\n"
            content += f"告警类型: {alert.category}\n"
            content += f"告警时间: {alert.created_at}\n"
            if alert.target:
                content += f"目标: {alert.target}\n"
            content += f"\n详情: {alert.message}"

            payload = {
                "msgtype": "text",
                "text": {"content": content},
            }

            response = requests.post(webhook_url, json=payload, timeout=10)
            result = response.json()

            return {
                "success": result.get("errcode") == 0,
                "channel": "wecom",
                "response": result,
            }
        except Exception as e:
            return {"success": False, "channel": "wecom", "error": str(e)}

    def _send_slack(self, config: Dict[str, Any], alert: Alert) -> Dict[str, Any]:
        """发送Slack通知"""
        try:
            import requests
            webhook_url = config.get("webhook_url", "")

            if not webhook_url:
                return {"success": False, "error": "Slack webhook_url未配置"}

            severity_color = {"critical": "#FF0000", "high": "#FFA500", "warning": "#FFFF00", "info": "#0000FF"}.get(alert.severity, "#808080")

            payload = {
                "attachments": [
                    {
                        "color": severity_color,
                        "title": f"[{alert.severity.upper()}] {alert.title}",
                        "text": alert.message,
                        "fields": [
                            {"title": "类型", "value": alert.category, "short": True},
                            {"title": "时间", "value": alert.created_at, "short": True},
                        ],
                    }
                ]
            }

            if alert.target:
                payload["attachments"][0]["fields"].append(
                    {"title": "目标", "value": alert.target, "short": True}
                )

            response = requests.post(webhook_url, json=payload, timeout=10)

            return {
                "success": response.status_code == 200,
                "channel": "slack",
                "status_code": response.status_code,
            }
        except Exception as e:
            return {"success": False, "channel": "slack", "error": str(e)}

    def _send_webhook(self, config: Dict[str, Any], alert: Alert) -> Dict[str, Any]:
        """发送通用Webhook通知"""
        try:
            import requests
            webhook_url = config.get("webhook_url", "")
            headers = config.get("headers", {"Content-Type": "application/json"})

            if not webhook_url:
                return {"success": False, "error": "webhook_url未配置"}

            payload = {
                "alert_id": alert.alert_id,
                "title": alert.title,
                "message": alert.message,
                "severity": alert.severity,
                "category": alert.category,
                "target": alert.target,
                "details": alert.details,
                "created_at": alert.created_at,
                "source": "AI Hacking Agent",
            }

            response = requests.post(webhook_url, json=payload, headers=headers, timeout=10)

            return {
                "success": response.status_code in [200, 201, 204],
                "channel": "webhook",
                "status_code": response.status_code,
            }
        except Exception as e:
            return {"success": False, "channel": "webhook", "error": str(e)}

    def _record_notification(self, alert_id: str, channel_id: str,
                              channel_type: str, result: Dict[str, Any]):
        """记录通知发送结果"""
        try:
            import secrets
            notification_id = "notif_" + secrets.token_hex(12)
            now = datetime.now().isoformat()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO notifications (notification_id, alert_id, channel_id, channel_type, status, response, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (notification_id, alert_id, channel_id, channel_type,
                  "success" if result.get("success") else "failed",
                  json.dumps(result, ensure_ascii=False), now))
            conn.commit()
            conn.close()
        except Exception as e:
            log.debug(f"记录通知失败: {e}")

    # ==================== 告警查询 ====================

    def list_alerts(self, severity: str = "", status: str = "",
                     category: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        """查询告警列表"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT alert_id, title, message, severity, category, target, created_at, status FROM alerts WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if category:
            query += " AND category = ?"
            params.append(category)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "alert_id": r[0], "title": r[1], "message": r[2],
                "severity": r[3], "category": r[4], "target": r[5],
                "created_at": r[6], "status": r[7],
            }
            for r in rows
        ]

    def get_statistics(self) -> Dict[str, Any]:
        """获取告警统计"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cursor.fetchone()[0]

        cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
        by_severity = dict(cursor.fetchall())

        cursor.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status")
        by_status = dict(cursor.fetchall())

        cursor.execute("SELECT COUNT(*) FROM channels WHERE enabled = 1")
        enabled_channels = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM notifications WHERE status = 'success'")
        successful_notifications = cursor.fetchone()[0]

        conn.close()

        return {
            "total_alerts": total_alerts,
            "by_severity": by_severity,
            "by_status": by_status,
            "enabled_channels": enabled_channels,
            "successful_notifications": successful_notifications,
        }


# 全局告警管理器实例
alert_manager = AlertManager()


# ==================== 便捷告警函数 ====================

def alert_vulnerability(title: str, target: str, severity: str = "high",
                         details: Dict[str, Any] = None):
    """漏洞告警便捷函数"""
    return alert_manager.create_alert(
        title=title,
        message=f"在目标 {target} 发现安全漏洞",
        severity=severity,
        category="vulnerability",
        target=target,
        details=details or {},
    )

def alert_system(title: str, severity: str = "warning",
                  details: Dict[str, Any] = None):
    """系统告警便捷函数"""
    return alert_manager.create_alert(
        title=title,
        message=f"系统事件: {title}",
        severity=severity,
        category="system",
        details=details or {},
    )

def alert_compliance(title: str, severity: str = "medium",
                      details: Dict[str, Any] = None):
    """合规告警便捷函数"""
    return alert_manager.create_alert(
        title=title,
        message=f"合规问题: {title}",
        severity=severity,
        category="compliance",
        details=details or {},
    )
