#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
notification_manager模块，提供相关安全测试功能。

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
import os
import smtplib
import time
import hashlib
import hmac
import base64
import urllib.parse
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    import requests
except ImportError:
    requests = None

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


class NotificationChannel(Enum):
    """通知渠道"""
    EMAIL = "email"
    DINGTALK = "dingtalk"
    WECOM = "wecom"
    WEBHOOK = "webhook"


class NotificationType(Enum):
    """通知类型"""
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    VULN_FOUND = "vuln_found"
    HIGH_VULN_FOUND = "high_vuln_found"
    CRITICAL_VULN_FOUND = "critical_vuln_found"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    SYSTEM_ERROR = "system_error"
    USER_LOGIN = "user_login"
    API_KEY_CREATED = "api_key_created"
    CUSTOM = "custom"


@dataclass
class NotificationConfig:
    """通知配置"""
    email_enabled: bool = False
    email_smtp_server: str = ""
    email_smtp_port: int = 587
    email_use_tls: bool = True
    email_username: str = ""
    email_password: str = ""
    email_from: str = ""
    email_to: List[str] = field(default_factory=list)

    dingtalk_enabled: bool = False
    dingtalk_webhook: str = ""
    dingtalk_secret: str = ""
    dingtalk_at_mobiles: List[str] = field(default_factory=list)

    wecom_enabled: bool = False
    wecom_webhook: str = ""
    wecom_corp_id: str = ""
    wecom_agent_id: str = ""

    webhook_enabled: bool = False
    webhook_url: str = ""
    webhook_method: str = "POST"
    webhook_headers: Dict = field(default_factory=dict)


@dataclass
class AlertRule:
    """告警规则"""
    rule_id: str
    name: str
    notification_type: str
    condition: Dict = field(default_factory=dict)
    channels: List[str] = field(default_factory=list)
    enabled: bool = True
    created_at: str = ""


@dataclass
class NotificationMessage:
    """通知消息"""
    title: str
    content: str
    notification_type: str = "custom"
    severity: str = "info"  # info, warning, critical
    data: Dict = field(default_factory=dict)
    channels: List[str] = field(default_factory=list)


class NotificationManager:
    """通知管理器"""

    def __init__(self, config_path: str = "./data/notification_config.json"):
        """初始化NotificationManager实例。

        Args:
            self: 类实例。
        """
        self.config_path = config_path
        self.config = NotificationConfig()
        self.alert_rules: List[AlertRule] = []
        self.notification_history: List[Dict] = []
        self._load_config()
        self._load_alert_rules()
        logger.info("通知系统初始化完成")

    def _load_config(self):
        """加载配置"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for key, value in data.items():
                        if hasattr(self.config, key):
                            setattr(self.config, key, value)
            except Exception as e:
                logger.error(f"加载通知配置失败: {e}")

    def _save_config(self):
        """保存配置"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        data = {
            "email_enabled": self.config.email_enabled,
            "email_smtp_server": self.config.email_smtp_server,
            "email_smtp_port": self.config.email_smtp_port,
            "email_use_tls": self.config.email_use_tls,
            "email_username": self.config.email_username,
            "email_password": self.config.email_password,
            "email_from": self.config.email_from,
            "email_to": self.config.email_to,
            "dingtalk_enabled": self.config.dingtalk_enabled,
            "dingtalk_webhook": self.config.dingtalk_webhook,
            "dingtalk_secret": self.config.dingtalk_secret,
            "dingtalk_at_mobiles": self.config.dingtalk_at_mobiles,
            "wecom_enabled": self.config.wecom_enabled,
            "wecom_webhook": self.config.wecom_webhook,
            "webhook_enabled": self.config.webhook_enabled,
            "webhook_url": self.config.webhook_url,
            "webhook_method": self.config.webhook_method,
            "webhook_headers": self.config.webhook_headers,
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _load_alert_rules(self):
        """加载告警规则"""
        rules_path = self.config_path.replace("notification_config", "alert_rules")
        if os.path.exists(rules_path):
            try:
                with open(rules_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.alert_rules = [AlertRule(**rule) for rule in data]
            except Exception as e:
                logger.error(f"加载告警规则失败: {e}")

        # 如果没有规则，创建默认规则
        if not self.alert_rules:
            self.alert_rules = [
                AlertRule(
                    rule_id="rule_001",
                    name="严重漏洞告警",
                    notification_type="critical_vuln_found",
                    condition={"severity": "critical"},
                    channels=["email", "webhook"],
                    enabled=True,
                    created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
                AlertRule(
                    rule_id="rule_002",
                    name="扫描完成通知",
                    notification_type="scan_completed",
                    condition={},
                    channels=["email"],
                    enabled=True,
                    created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
                AlertRule(
                    rule_id="rule_003",
                    name="系统异常告警",
                    notification_type="system_error",
                    condition={},
                    channels=["webhook"],
                    enabled=False,
                    created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            ]

    def configure_email(self, smtp_server: str, smtp_port: int, username: str,
                        password: str, from_addr: str, to_addrs: List[str],
                        use_tls: bool = True):
        """配置邮件通知"""
        self.config.email_enabled = True
        self.config.email_smtp_server = smtp_server
        self.config.email_smtp_port = smtp_port
        self.config.email_username = username
        self.config.email_password = password
        self.config.email_from = from_addr
        self.config.email_to = to_addrs
        self.config.email_use_tls = use_tls
        self._save_config()
        logger.info(f"邮件通知已配置: {smtp_server}:{smtp_port}")

    def configure_dingtalk(self, webhook: str, secret: str = "", at_mobiles: List[str] = None):
        """配置钉钉通知"""
        self.config.dingtalk_enabled = True
        self.config.dingtalk_webhook = webhook
        self.config.dingtalk_secret = secret
        self.config.dingtalk_at_mobiles = at_mobiles or []
        self._save_config()
        logger.info("钉钉通知已配置")

    def configure_wecom(self, webhook: str):
        """配置企业微信通知"""
        self.config.wecom_enabled = True
        self.config.wecom_webhook = webhook
        self._save_config()
        logger.info("企业微信通知已配置")

    def configure_webhook(self, url: str, method: str = "POST", headers: Dict = None):
        """配置通用Webhook"""
        self.config.webhook_enabled = True
        self.config.webhook_url = url
        self.config.webhook_method = method
        self.config.webhook_headers = headers or {}
        self._save_config()
        logger.info(f"Webhook通知已配置: {url}")

    def send(self, message: NotificationMessage) -> Dict:
        """发送通知"""
        results = {"success": [], "failed": [], "skipped": []}

        # 确定发送渠道
        channels = message.channels
        if not channels:
            # 根据告警规则确定渠道
            channels = self._get_channels_for_type(message.notification_type, message.severity)

        for channel in channels:
            try:
                if channel == NotificationChannel.EMAIL.value:
                    if self.config.email_enabled:
                        self._send_email(message)
                        results["success"].append("email")
                    else:
                        results["skipped"].append("email (未启用)")
                elif channel == NotificationChannel.DINGTALK.value:
                    if self.config.dingtalk_enabled:
                        self._send_dingtalk(message)
                        results["success"].append("dingtalk")
                    else:
                        results["skipped"].append("dingtalk (未启用)")
                elif channel == NotificationChannel.WECOM.value:
                    if self.config.wecom_enabled:
                        self._send_wecom(message)
                        results["success"].append("wecom")
                    else:
                        results["skipped"].append("wecom (未启用)")
                elif channel == NotificationChannel.WEBHOOK.value:
                    if self.config.webhook_enabled:
                        self._send_webhook(message)
                        results["success"].append("webhook")
                    else:
                        results["skipped"].append("webhook (未启用)")
            except Exception as e:
                logger.error(f"发送{channel}通知失败: {e}")
                results["failed"].append(f"{channel}: {str(e)}")

        # 记录历史
        self.notification_history.append({
            "title": message.title,
            "type": message.notification_type,
            "severity": message.severity,
            "channels": channels,
            "results": results,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

        logger.info(f"通知发送完成: {message.title} | 成功: {len(results['success'])} | 失败: {len(results['failed'])}")
        return results

    def _get_channels_for_type(self, notification_type: str, severity: str) -> List[str]:
        """根据通知类型获取渠道"""
        channels = []
        for rule in self.alert_rules:
            if not rule.enabled:
                continue
            if rule.notification_type == notification_type:
                channels.extend(rule.channels)
            elif severity == "critical" and rule.notification_type == "critical_vuln_found":
                channels.extend(rule.channels)

        # 去重
        return list(set(channels)) if channels else ["email", "webhook"]

    def _send_email(self, message: NotificationMessage):
        """发送邮件"""
        if not self.config.email_smtp_server:
            raise ValueError("邮件服务器未配置")

        msg = MIMEMultipart()
        msg["From"] = self.config.email_from or self.config.email_username
        msg["To"] = ", ".join(self.config.email_to)
        msg["Subject"] = f"[AI Hacking Agent] {message.title}"

        # HTML内容
        severity_colors = {"info": "#3b82f6", "warning": "#f59e0b", "critical": "#ef4444"}
        color = severity_colors.get(message.severity, "#3b82f6")

        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid {color};">
                <h2 style="color: {color}; margin-top: 0;">{message.title}</h2>
                <p style="color: #333; line-height: 1.6;">{message.content}</p>
                <hr style="border: none; border-top: 1px solid #ddd; margin: 15px 0;">
                <p style="color: #666; font-size: 12px;">
                    通知类型: {message.notification_type}<br>
                    发送时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                    系统: AI Hacking Agent
                </p>
            </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(html_content, "html", "utf-8"))

        # 附加数据
        if message.data:
            data_json = json.dumps(message.data, ensure_ascii=False, indent=2)
            msg.attach(MIMEText(f"\n\n详细数据:\n{data_json}", "plain", "utf-8"))

        # 发送
        with smtplib.SMTP(self.config.email_smtp_server, self.config.email_smtp_port) as server:
            if self.config.email_use_tls:
                server.starttls()
            if self.config.email_username:
                server.login(self.config.email_username, self.config.email_password)
            server.send_message(msg)

    def _send_dingtalk(self, message: NotificationMessage):
        """发送钉钉通知"""
        if not requests:
            raise ImportError("requests未安装")
        if not self.config.dingtalk_webhook:
            raise ValueError("钉钉Webhook未配置")

        webhook = self.config.dingtalk_webhook

        # 加签
        if self.config.dingtalk_secret:
            timestamp = str(round(time.time() * 1000))
            secret_enc = self.config.dingtalk_secret.encode("utf-8")
            string_to_sign = f"{timestamp}\n{self.config.dingtalk_secret}"
            hmac_code = hmac.new(secret_enc, string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
            sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
            webhook = f"{webhook}&timestamp={timestamp}&sign={sign}"

        # 消息内容
        severity_emoji = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}
        emoji = severity_emoji.get(message.severity, "ℹ️")

        content = f"{emoji} **{message.title}**\n\n{message.content}\n\n"
        content += f"通知类型: {message.notification_type}\n"
        content += f"发送时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        # @指定人
        at = {}
        if self.config.dingtalk_at_mobiles:
            at["atMobiles"] = self.config.dingtalk_at_mobiles
            at["isAtAll"] = False

        data = {
            "msgtype": "markdown",
            "markdown": {"title": message.title, "text": content},
            "at": at,
        }

        resp = requests.post(webhook, json=data, timeout=10)
        if resp.status_code != 200:
            raise Exception(f"钉钉发送失败: {resp.status_code} - {resp.text}")

    def _send_wecom(self, message: NotificationMessage):
        """发送企业微信通知"""
        if not requests:
            raise ImportError("requests未安装")
        if not self.config.wecom_webhook:
            raise ValueError("企业微信Webhook未配置")

        severity_emoji = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}
        emoji = severity_emoji.get(message.severity, "ℹ️")

        content = f"{emoji} **{message.title}**\n\n{message.content}\n\n"
        content += f"> 通知类型: {message.notification_type}\n"
        content += f"> 发送时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        data = {
            "msgtype": "markdown",
            "markdown": {"content": content},
        }

        resp = requests.post(self.config.wecom_webhook, json=data, timeout=10)
        if resp.status_code != 200:
            raise Exception(f"企业微信发送失败: {resp.status_code} - {resp.text}")

    def _send_webhook(self, message: NotificationMessage):
        """发送通用Webhook"""
        if not requests:
            raise ImportError("requests未安装")
        if not self.config.webhook_url:
            raise ValueError("Webhook URL未配置")

        data = {
            "title": message.title,
            "content": message.content,
            "type": message.notification_type,
            "severity": message.severity,
            "data": message.data,
            "timestamp": datetime.now().isoformat(),
            "source": "AI Hacking Agent",
        }

        headers = {"Content-Type": "application/json"}
        headers.update(self.config.webhook_headers)

        resp = requests.request(
            method=self.config.webhook_method,
            url=self.config.webhook_url,
            json=data,
            headers=headers,
            timeout=10,
        )
        if resp.status_code not in [200, 201, 204]:
            raise Exception(f"Webhook发送失败: {resp.status_code} - {resp.text}")

    def notify_scan_completed(self, scan_id: str, target: str, vuln_count: int, duration: str):
        """扫描完成通知"""
        message = NotificationMessage(
            title=f"扫描任务完成: {target}",
            content=f"扫描任务 {scan_id} 已完成。\n\n目标: {target}\n发现漏洞: {vuln_count}个\n耗时: {duration}",
            notification_type="scan_completed",
            severity="info" if vuln_count < 5 else ("warning" if vuln_count < 20 else "critical"),
            data={"scan_id": scan_id, "target": target, "vuln_count": vuln_count, "duration": duration},
        )
        return self.send(message)

    def notify_vulnerability_found(self, vuln_name: str, severity: str, target: str, evidence: str = ""):
        """漏洞发现通知"""
        notif_type = f"{severity}_vuln_found" if severity in ["high", "critical"] else "vuln_found"
        message = NotificationMessage(
            title=f"发现{severity.upper()}漏洞: {vuln_name}",
            content=f"在目标 {target} 发现{severity}级别漏洞。\n\n漏洞名称: {vuln_name}\n严重程度: {severity.upper()}\n证据: {evidence or '详见扫描报告'}",
            notification_type=notif_type,
            severity=severity,
            data={"vuln_name": vuln_name, "severity": severity, "target": target, "evidence": evidence},
        )
        return self.send(message)

    def notify_task_failed(self, task_id: str, task_name: str, error: str):
        """任务失败通知"""
        message = NotificationMessage(
            title=f"任务执行失败: {task_name}",
            content=f"任务 {task_id} ({task_name}) 执行失败。\n\n错误信息: {error}",
            notification_type="task_failed",
            severity="critical",
            data={"task_id": task_id, "task_name": task_name, "error": error},
        )
        return self.send(message)

    def notify_system_error(self, error: str, component: str = ""):
        """系统错误通知"""
        message = NotificationMessage(
            title=f"系统错误: {component or '未知组件'}",
            content=f"系统发生错误，请及时处理。\n\n错误信息: {error}\n组件: {component or '未知'}",
            notification_type="system_error",
            severity="critical",
            data={"error": error, "component": component},
        )
        return self.send(message)

    def test_channel(self, channel: str) -> bool:
        """测试通知渠道"""
        message = NotificationMessage(
            title="通知测试",
            content=f"这是一条测试消息，来自 AI Hacking Agent 通知系统。\n\n发送时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            notification_type="custom",
            severity="info",
            channels=[channel],
        )
        results = self.send(message)
        return channel in results["success"]

    def get_history(self, limit: int = 50) -> List[Dict]:
        """获取通知历史"""
        return self.notification_history[-limit:][::-1]

    def get_status(self) -> Dict:
        """获取通知系统状态"""
        return {
            "email_enabled": self.config.email_enabled,
            "email_configured": bool(self.config.email_smtp_server),
            "dingtalk_enabled": self.config.dingtalk_enabled,
            "dingtalk_configured": bool(self.config.dingtalk_webhook),
            "wecom_enabled": self.config.wecom_enabled,
            "wecom_configured": bool(self.config.wecom_webhook),
            "webhook_enabled": self.config.webhook_enabled,
            "webhook_configured": bool(self.config.webhook_url),
            "alert_rules_count": len(self.alert_rules),
            "enabled_rules_count": len([r for r in self.alert_rules if r.enabled]),
            "total_notifications_sent": len(self.notification_history),
        }


def main():
    """演示用法"""
    print("=" * 60)
    print("  通知系统")
    print("=" * 60)
    print()

    manager = NotificationManager()

    # 查看状态
    print("[1/3] 通知系统状态:")
    status = manager.get_status()
    for key, value in status.items():
        print(f"  {key}: {value}")
    print()

    # 配置Webhook（示例）
    print("[2/3] 配置Webhook通知...")
    manager.configure_webhook(
        url="https://hooks.example.com/security-alerts",
        method="POST",
        headers={"Authorization": "Bearer test-token"},
    )
    print("  Webhook已配置")
    print()

    # 发送测试通知
    print("[3/3] 发送测试通知...")
    message = NotificationMessage(
        title="测试通知",
        content="这是一条来自 AI Hacking Agent 通知系统的测试消息。",
        notification_type="custom",
        severity="info",
    )
    results = manager.send(message)
    print(f"  成功: {results['success']}")
    print(f"  失败: {results['failed']}")
    print(f"  跳过: {results['skipped']}")
    print()

    # 快捷通知示例
    print("快捷通知示例:")
    print("  - manager.notify_scan_completed('scan_001', 'http://example.com', 5, '2分30秒')")
    print("  - manager.notify_vulnerability_found('SQL注入', 'high', 'http://example.com', 'id参数存在注入')")
    print("  - manager.notify_task_failed('task_001', '端口扫描', '连接超时')")
    print("  - manager.notify_system_error('数据库连接失败', 'database')")
    print()

    print("=" * 60)
    print("  支持的通知渠道:")
    print("  - 📧 邮件 (SMTP/TLS)")
    print("  - 🔔 钉钉 (Webhook + 加签)")
    print("  - 💼 企业微信 (Webhook)")
    print("  - 🔗 通用Webhook (自定义)")
    print()
    print("  支持的通知类型:")
    print("  - 扫描完成/失败")
    print("  - 漏洞发现 (严重/高危/中危)")
    print("  - 任务完成/失败")
    print("  - 系统错误")
    print("  - 用户登录")
    print("  - API密钥创建")
    print("  - 自定义通知")
    print("=" * 60)


if __name__ == "__main__":
    main()
