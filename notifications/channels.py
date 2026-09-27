# -*- coding: utf-8 -*-
"""
channels.py - Notification channel implementations.

7 channels: WeCom, DingTalk, Feishu, Slack, Email, Webhook, InApp.
Uses urllib.request (stdlib) for HTTP; smtplib for email.
"""

import json
import ssl
import time
import base64
import hmac
import hashlib
import urllib.parse
import urllib.request
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from typing import Dict, List, Any, Optional

HTTP_TIMEOUT = 10
RETRIES = 1

# Global per-channel config.
_channel_configs: Dict[str, Dict[str, Any]] = {}
# In-app notification storage.
_inapp_store: List[Dict[str, Any]] = []
_inapp_seq = 0


def _http_post(url: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None,
               method: str = "POST", content_type: str = "application/json") -> Dict[str, Any]:
    """Perform HTTP request via urllib. Never raises."""
    data = json.dumps(payload).encode("utf-8") if content_type == "application/json" else \
        urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", content_type)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    last_err = None
    for attempt in range(RETRIES + 1):
        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")[:500]
                return {"success": True, "status": resp.status, "response": body}
        except Exception as e:  # noqa: BLE001
            last_err = str(e)
            if attempt < RETRIES:
                time.sleep(0.5)
    return {"success": False, "error": last_err or "request failed"}


class BaseChannel:
    """Base class for notification channels."""

    name: str = "base"
    label: str = "Base Channel"

    def send(self, message: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        raise NotImplementedError

    def validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Return {valid: bool, missing: [...]}."""
        return {"valid": True, "missing": []}

    def test(self, config: Dict[str, Any]) -> Dict[str, Any]:
        return self.send("test message from notification center", config)


class WeComChannel(BaseChannel):
    """企业微信 Webhook 机器人."""

    name = "wecom"
    label = "WeCom (企业微信)"

    def validate_config(self, config):
        missing = [k for k in ("webhook_url",) if not config.get(k)]
        return {"valid": not missing, "missing": missing}

    def send(self, message, config=None):
        config = config or get_config("wecom")
        url = config.get("webhook_url")
        if not url:
            return {"success": False, "error": "webhook_url not configured"}
        payload = {"msgtype": "markdown", "markdown": {"content": message}}
        return _http_post(url, payload)


class DingTalkChannel(BaseChannel):
    """钉钉 Webhook 机器人 (加签可选)."""

    name = "dingtalk"
    label = "DingTalk (钉钉)"

    def validate_config(self, config):
        missing = [k for k in ("webhook_url",) if not config.get(k)]
        return {"valid": not missing, "missing": missing}

    def _signed_url(self, url: str, secret: str) -> str:
        ts = str(round(time.time() * 1000))
        sign = hmac.new(secret.encode("utf-8"), f"{ts}\n{secret}".encode("utf-8"),
                        digestmod=hashlib.sha256).digest()
        sign_b64 = urllib.parse.quote_plus(base64.b64encode(sign))
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}timestamp={ts}&sign={sign_b64}"

    def send(self, message, config=None):
        config = config or get_config("dingtalk")
        url = config.get("webhook_url")
        if not url:
            return {"success": False, "error": "webhook_url not configured"}
        secret = config.get("secret")
        if secret:
            url = self._signed_url(url, secret)
        msg_type = config.get("msg_type", "markdown")
        if msg_type == "text":
            payload = {"msgtype": "text", "text": {"content": message}}
        else:
            payload = {"msgtype": "markdown", "markdown": {"title": "Alert", "text": message}}
        return _http_post(url, payload)


class FeishuChannel(BaseChannel):
    """飞书 Webhook 机器人."""

    name = "feishu"
    label = "Feishu (飞书)"

    def validate_config(self, config):
        missing = [k for k in ("webhook_url",) if not config.get(k)]
        return {"valid": not missing, "missing": missing}

    def send(self, message, config=None):
        config = config or get_config("feishu")
        url = config.get("webhook_url")
        if not url:
            return {"success": False, "error": "webhook_url not configured"}
        msg_type = config.get("msg_type", "text")
        if msg_type == "post":
            payload = {"msg_type": "post",
                       "content": {"post": {"zh_cn": {"title": "Alert", "content": [[{"tag": "text", "text": message}]]}}}}
        else:
            payload = {"msg_type": "text", "content": {"text": message}}
        return _http_post(url, payload)


class SlackChannel(BaseChannel):
    """Slack Incoming Webhook."""

    name = "slack"
    label = "Slack"

    def validate_config(self, config):
        missing = [k for k in ("webhook_url",) if not config.get(k)]
        return {"valid": not missing, "missing": missing}

    def send(self, message, config=None):
        config = config or get_config("slack")
        url = config.get("webhook_url")
        if not url:
            return {"success": False, "error": "webhook_url not configured"}
        use_blocks = config.get("use_blocks", True)
        if use_blocks:
            payload = {"blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": message}}]}
        else:
            payload = {"text": message}
        return _http_post(url, payload)


class EmailChannel(BaseChannel):
    """SMTP email channel."""

    name = "email"
    label = "Email (SMTP)"

    def validate_config(self, config):
        missing = [k for k in ("smtp_host", "smtp_port", "username", "password", "from_addr", "to_addrs")
                   if not config.get(k)]
        return {"valid": not missing, "missing": missing}

    def send(self, message, config=None):
        config = config or get_config("email")
        required = ("smtp_host", "smtp_port", "username", "password", "from_addr", "to_addrs")
        if any(not config.get(k) for k in required):
            return {"success": False, "error": "incomplete SMTP config"}
        try:
            use_tls = config.get("use_tls", True)
            host = config["smtp_host"]
            port = int(config["smtp_port"])
            to_addrs = config["to_addrs"]
            if isinstance(to_addrs, str):
                to_addrs = [a.strip() for a in to_addrs.split(",") if a.strip()]
            mime_type = config.get("mime_type", "plain")
            msg = MIMEText(message, _subtype=mime_type, _charset="utf-8")
            msg["Subject"] = config.get("subject", "Security Alert")
            msg["From"] = config["from_addr"]
            msg["To"] = ",".join(to_addrs)
            if use_tls:
                server = smtplib.SMTP(host, port, timeout=HTTP_TIMEOUT)
                server.starttls()
            else:
                server = smtplib.SMTP(host, port, timeout=HTTP_TIMEOUT)
            server.login(config["username"], config["password"])
            server.sendmail(config["from_addr"], to_addrs, msg.as_string())
            server.quit()
            return {"success": True, "response": "email sent"}
        except Exception as e:  # noqa: BLE001
            return {"success": False, "error": str(e)}


class WebhookChannel(BaseChannel):
    """Generic custom HTTP webhook."""

    name = "webhook"
    label = "Custom Webhook"

    def validate_config(self, config):
        missing = [k for k in ("url",) if not config.get(k)]
        return {"valid": not missing, "missing": missing}

    def send(self, message, config=None):
        config = config or get_config("webhook")
        url = config.get("url")
        if not url:
            return {"success": False, "error": "url not configured"}
        method = config.get("method", "POST")
        content_type = config.get("content_type", "application/json")
        body_key = config.get("body_key", "message")
        payload = {body_key: message, "timestamp": datetime.now().isoformat()}
        headers = config.get("headers") or {}
        return _http_post(url, payload, headers=headers, method=method, content_type=content_type)


class InAppChannel(BaseChannel):
    """In-app notification stored in memory."""

    name = "inapp"
    label = "In-App (站内通知)"

    def validate_config(self, config):
        return {"valid": True, "missing": []}

    def send(self, message, config=None):
        global _inapp_seq
        _inapp_seq += 1
        record = {
            "id": _inapp_seq,
            "channel": "inapp",
            "content": message,
            "read": False,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        _inapp_store.append(record)
        return {"success": True, "record": record}


CHANNEL_REGISTRY: Dict[str, type] = {
    WeComChannel.name: WeComChannel,
    DingTalkChannel.name: DingTalkChannel,
    FeishuChannel.name: FeishuChannel,
    SlackChannel.name: SlackChannel,
    EmailChannel.name: EmailChannel,
    WebhookChannel.name: WebhookChannel,
    InAppChannel.name: InAppChannel,
}


def get_channel(name: str) -> Optional[BaseChannel]:
    cls = CHANNEL_REGISTRY.get(name)
    return cls() if cls else None


def list_channels() -> List[Dict[str, Any]]:
    out = []
    for key, cls in CHANNEL_REGISTRY.items():
        out.append({
            "name": key,
            "label": cls.label,
            "configured": key in _channel_configs,
            "config_keys": list((_channel_configs.get(key) or {}).keys()),
        })
    return out


def set_config(name: str, config: Dict[str, Any]):
    _channel_configs[name] = config or {}


def get_config(name: str) -> Dict[str, Any]:
    return _channel_configs.get(name, {})


def list_inapp(limit: int = 50, unread_only: bool = False) -> List[Dict[str, Any]]:
    items = list(reversed(_inapp_store))
    if unread_only:
        items = [i for i in items if not i.get("read")]
    return items[:limit]


def mark_inapp_read(record_id: int) -> bool:
    for item in _inapp_store:
        if item["id"] == record_id:
            item["read"] = True
            return True
    return False
