#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
notification_channels 模块，提供多渠道通知能力。

模块功能：
    - 企业微信 / 钉钉 / 飞书机器人（Webhook）
    - 邮件（SMTP，支持 HTML）
    - 通用 Webhook
    - 消息模板占位符替换 {title}/{content}/{severity}/{time}/{target}
    - 单渠道失败不影响其他渠道

注意事项：
    - 本模块仅用于授权的安全运营场景
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import json
import os
import smtplib
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.header import Header
from typing import Any, Dict, List, Optional

import requests

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")
CONFIG_PATH = os.path.join(CONFIG_DIR, "notification_config.json")

# 支持的渠道类型
CHANNEL_TYPES = ["wecom", "dingtalk", "feishu", "email", "webhook"]

DEFAULT_CONFIG: Dict[str, Any] = {
    "wecom": {
        "enabled": False,
        "webhook_url": "",
        "recipients": [],
        "message_template": "【安全告警-{severity}】{title}\n{content}\n目标: {target}\n时间: {time}",
    },
    "dingtalk": {
        "enabled": False,
        "webhook_url": "",
        "recipients": [],
        "message_template": "### 安全告警 [{severity}]\n> {title}\n\n{content}\n\n目标: {target}\n\n时间: {time}",
    },
    "feishu": {
        "enabled": False,
        "webhook_url": "",
        "recipients": [],
        "message_template": "【安全告警-{severity}】{title}\n{content}\n目标: {target}\n时间: {time}",
    },
    "email": {
        "enabled": False,
        "smtp": {
            "host": "smtp.example.com",
            "port": 465,
            "user": "alert@example.com",
            "password": "",
            "use_tls": True,
        },
        "recipients": [],
        "subject_template": "[{severity}] 安全告警: {title}",
        "message_template": "<h3>{title}</h3><p>{content}</p><p>目标: {target}</p><p>时间: {time}</p>",
    },
    "webhook": {
        "enabled": False,
        "webhook_url": "",
        "recipients": [],
        "message_template": "{title}",
    },
}

# 严重级别 -> emoji / 颜色（仅用于文案）
SEVERITY_TAG = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}


class NotificationManager:
    """多渠道通知管理器。"""

    def __init__(self, config_path: str = CONFIG_PATH):
        """初始化并加载配置。"""
        self.config_path = config_path
        self.config: Dict[str, Any] = json.loads(json.dumps(DEFAULT_CONFIG))
        self.load_config()

    # ==================== 配置读写 ====================

    def load_config(self) -> Dict[str, Any]:
        """加载通知渠道配置。"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            if os.path.exists(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                for k, v in saved.items():
                    if isinstance(v, dict) and isinstance(self.config.get(k), dict):
                        self.config[k].update(v)
                    else:
                        self.config[k] = v
            else:
                self.save_config()
        except Exception as e:
            logger.warning("通知配置加载失败，使用默认配置: %s", e)
            self.config = json.loads(json.dumps(DEFAULT_CONFIG))
        return self.config

    def save_config(self) -> bool:
        """保存通知渠道配置。"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error("通知配置保存失败: %s", e)
            return False

    def update_channel_config(self, channel: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """更新单个渠道配置。"""
        if channel not in CHANNEL_TYPES:
            raise ValueError(f"不支持的渠道类型: {channel}")
        self.config.setdefault(channel, {})
        self.config[channel].update(config or {})
        self.save_config()
        return self.config[channel]

    # ==================== 模板渲染 ====================

    def _render(self, template: str, alert: Dict[str, Any]) -> str:
        """用 alert 数据替换模板中的占位符。"""
        ctx = {
            "title": alert.get("title", "安全告警"),
            "content": alert.get("content") or alert.get("message", ""),
            "severity": alert.get("severity", "info"),
            "time": alert.get("time") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "target": alert.get("target") or "未知",
        }
        try:
            return template.format(**ctx)
        except Exception:
            return template

    # ==================== Payload 构建（不发送，便于单测） ====================

    def build_wecom_payload(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """企业微信 markdown 消息体。"""
        tpl = self.config.get("wecom", {}).get(
            "message_template", DEFAULT_CONFIG["wecom"]["message_template"])
        content = self._render(tpl, alert)
        return {"msgtype": "markdown", "markdown": {"content": content}}

    def build_dingtalk_payload(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """钉钉 markdown 消息体。"""
        tpl = self.config.get("dingtalk", {}).get(
            "message_template", DEFAULT_CONFIG["dingtalk"]["message_template"])
        text = self._render(tpl, alert)
        title = f"安全告警 [{alert.get('severity', 'info')}]"
        return {"msgtype": "markdown", "markdown": {"title": title, "text": text}}

    def build_feishu_payload(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """飞书交互式卡片消息体。"""
        tpl = self.config.get("feishu", {}).get(
            "message_template", DEFAULT_CONFIG["feishu"]["message_template"])
        content = self._render(tpl, alert)
        severity = alert.get("severity", "info")
        header_color = {
            "critical": "red", "high": "red",
            "medium": "orange", "low": "blue", "info": "grey",
        }.get(severity, "blue")
        return {
            "msg_type": "interactive",
            "card": {
                "header": {
                    "title": {"tag": "plain_text",
                              "content": f"安全告警 [{SEVERITY_TAG.get(severity, severity)}]"},
                    "template": header_color,
                },
                "elements": [
                    {"tag": "div", "text": {"tag": "lark_md", "content": content}},
                    {"tag": "note",
                     "elements": [{"tag": "plain_text",
                                   "content": f"目标: {alert.get('target', '未知')}"}]},
                ],
            },
        }

    def build_webhook_payload(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """通用 Webhook 消息体。"""
        return {
            "event": "security_alert",
            "title": alert.get("title", "安全告警"),
            "content": alert.get("content") or alert.get("message", ""),
            "severity": alert.get("severity", "info"),
            "target": alert.get("target"),
            "time": alert.get("time") or datetime.now(timezone.utc).isoformat(),
        }

    # ==================== 实际发送 ====================

    def _post_json(self, url: str, payload: Dict[str, Any], timeout: int = 5) -> Dict[str, Any]:
        try:
            resp = requests.post(url, json=payload, timeout=timeout)
            return {"success": resp.ok, "status_code": resp.status_code}
        except Exception as e:
            logger.warning("Webhook 推送失败: %s", e)
            return {"success": False, "message": str(e)}

    def _send_wecom(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.config.get("wecom", {})
        url = cfg.get("webhook_url", "")
        if not url:
            return {"success": False, "message": "企业微信 webhook_url 未配置"}
        return self._post_json(url, self.build_wecom_payload(alert))

    def _send_dingtalk(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.config.get("dingtalk", {})
        url = cfg.get("webhook_url", "")
        if not url:
            return {"success": False, "message": "钉钉 webhook_url 未配置"}
        return self._post_json(url, self.build_dingtalk_payload(alert))

    def _send_feishu(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.config.get("feishu", {})
        url = cfg.get("webhook_url", "")
        if not url:
            return {"success": False, "message": "飞书 webhook_url 未配置"}
        return self._post_json(url, self.build_feishu_payload(alert))

    def _send_webhook(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.config.get("webhook", {})
        url = cfg.get("webhook_url", "")
        if not url:
            return {"success": False, "message": "通用 webhook_url 未配置"}
        return self._post_json(url, self.build_webhook_payload(alert))

    def _send_email(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """通过 SMTP 发送 HTML 邮件。"""
        cfg = self.config.get("email", {})
        smtp = cfg.get("smtp", {})
        recipients = cfg.get("recipients", [])
        if not smtp.get("host") or not recipients:
            return {"success": False, "message": "SMTP host 或收件人未配置"}
        subject = self._render(
            cfg.get("subject_template", DEFAULT_CONFIG["email"]["subject_template"]), alert)
        body = self._render(
            cfg.get("message_template", DEFAULT_CONFIG["email"]["message_template"]), alert)
        try:
            msg = MIMEText(body, "html", "utf-8")
            msg["Subject"] = Header(subject, "utf-8")
            msg["From"] = smtp.get("user", "")
            msg["To"] = ", ".join(recipients)
            host, port = smtp["host"], int(smtp.get("port", 465))
            if smtp.get("use_tls", True):
                server = smtplib.SMTP_SSL(host, port, timeout=10)
            else:
                server = smtplib.SMTP(host, port, timeout=10)
            if smtp.get("user") and smtp.get("password"):
                server.login(smtp["user"], smtp["password"])
            server.sendmail(smtp.get("user", ""), recipients, msg.as_string())
            server.quit()
            return {"success": True, "message": f"邮件已发送至 {len(recipients)} 人"}
        except Exception as e:
            logger.warning("邮件发送失败: %s", e)
            return {"success": False, "message": f"邮件发送失败: {e}"}

    # ==================== 业务接口 ====================

    def send_alert(self, alert_data: Dict[str, Any],
                   channels: Optional[List[str]] = None) -> Dict[str, Any]:
        """把告警推送到所有启用渠道（或指定渠道）。

        单个渠道失败不影响其他渠道。
        """
        alert = {
            "title": alert_data.get("title", "安全告警"),
            "content": alert_data.get("content") or alert_data.get("message", ""),
            "severity": (alert_data.get("severity") or "info").lower(),
            "target": alert_data.get("target", "未知"),
            "time": alert_data.get("time") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
        senders = {
            "wecom": self._send_wecom,
            "dingtalk": self._send_dingtalk,
            "feishu": self._send_feishu,
            "email": self._send_email,
            "webhook": self._send_webhook,
        }
        targets = channels or list(senders.keys())
        results = {}
        for ch in targets:
            cfg = self.config.get(ch, {})
            # 未启用的渠道（且非显式指定）跳过
            if channels is None and not cfg.get("enabled", False):
                results[ch] = {"success": False, "skipped": True, "message": "渠道未启用"}
                continue
            try:
                results[ch] = senders[ch](alert)
            except Exception as e:
                results[ch] = {"success": False, "message": str(e)}
        ok_count = sum(1 for r in results.values() if r.get("success"))
        return {"success": ok_count > 0, "total": len(results),
                "success_count": ok_count, "results": results}

    def send_test(self, channel_type: str) -> Dict[str, Any]:
        """向指定渠道发送测试消息。"""
        if channel_type not in CHANNEL_TYPES:
            return {"success": False, "message": f"不支持的渠道: {channel_type}"}
        test_alert = {
            "title": "通知渠道连通性测试",
            "content": "这是一条来自 AI Hacking Agent 的测试消息，无需处理。",
            "severity": "info",
            "target": "test",
        }
        return self.send_alert(test_alert, channels=[channel_type])

    def get_channel_status(self) -> Dict[str, Any]:
        """返回各渠道配置状态（脱敏）。"""
        status = {}
        for ch in CHANNEL_TYPES:
            cfg = self.config.get(ch, {})
            status[ch] = {
                "enabled": bool(cfg.get("enabled", False)),
                "configured": bool(
                    cfg.get("webhook_url") or cfg.get("smtp", {}).get("host")
                    or (ch == "email" and cfg.get("recipients"))
                ),
                "recipients_count": len(cfg.get("recipients", [])),
            }
        return {"channels": status, "supported": CHANNEL_TYPES}


# 模块级单例
notification_manager = NotificationManager()
