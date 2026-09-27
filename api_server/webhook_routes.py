# -*- coding: utf-8 -*-
"""Webhook/通知告警 - 发现高危漏洞时推送"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
import json, os, urllib.request

router = APIRouter(prefix="/api/v1/webhook", tags=["Webhook告警"])
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "system_config.json")

def _load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except: pass
    return {}

def _send_webhook(url, payload):
    """发送Webhook通知"""
    try:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"success": True, "status": resp.status}
    except Exception as e:
        return {"success": False, "error": str(e)}

class WebhookTestReq(BaseModel):
    url: str

class AlertReq(BaseModel):
    title: str
    severity: str = "high"
    target: Optional[str] = ""
    description: Optional[str] = ""
    vuln_count: Optional[int] = 0

@router.get("/config")
def get_webhook_config():
    config = _load_config()
    notif = config.get("notification", {})
    return {"success": True, "data": {
        "enabled": notif.get("webhook_enabled", False),
        "url": notif.get("webhook_url", ""),
        "alert_on_critical": notif.get("alert_on_critical", True),
        "alert_on_high": notif.get("alert_on_high", True),
    }}

@router.put("/config")
def update_webhook_config(data: dict):
    config = _load_config()
    if "notification" not in config:
        config["notification"] = {}
    config["notification"].update(data)
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
    return {"success": True, "data": {"updated": True}}

@router.post("/test")
def test_webhook(req: WebhookTestReq):
    """测试Webhook连通性"""
    payload = {
        "msgtype": "text",
        "text": {"content": "AI Hacking Agent Webhook测试 - 通知通道正常"},
        "timestamp": datetime.now().isoformat()
    }
    result = _send_webhook(req.url, payload)
    return {"success": result["success"], "data": result}

@router.post("/alert")
def send_alert(req: AlertReq):
    """发送告警通知"""
    config = _load_config()
    notif = config.get("notification", {})
    if not notif.get("webhook_enabled"):
        return {"success": False, "error": "Webhook未启用"}
    if req.severity == "critical" and not notif.get("alert_on_critical", True):
        return {"success": False, "error": "critical告警被禁用"}
    if req.severity == "high" and not notif.get("alert_on_high", True):
        return {"success": False, "error": "high告警被禁用"}
    url = notif.get("webhook_url", "")
    if not url:
        return {"success": False, "error": "Webhook URL未配置"}
    severity_emoji = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢","info":"🔵"}.get(req.severity,"⚪")
    content = f"{severity_emoji} [{req.severity.upper()}] {req.title}\n目标: {req.target}\n漏洞数: {req.vuln_count}\n描述: {req.description}\n时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    payload = {"msgtype": "text", "text": {"content": content}, "timestamp": datetime.now().isoformat()}
    result = _send_webhook(url, payload)
    return {"success": result["success"], "data": result}

@router.post("/scan-complete")
def scan_complete_alert(data: dict):
    """扫描完成后自动判断是否需要告警"""
    config = _load_config()
    notif = config.get("notification", {})
    if not notif.get("webhook_enabled"):
        return {"success": False, "error": "Webhook未启用"}
    vulns = data.get("vulnerabilities", [])
    critical = [v for v in vulns if v.get("severity") == "critical"]
    high = [v for v in vulns if v.get("severity") == "high"]
    should_alert = (critical and notif.get("alert_on_critical", True)) or (high and notif.get("alert_on_high", True))
    if not should_alert:
        return {"success": True, "data": {"alert_sent": False, "reason": "无critical/high漏洞或对应告警被禁用"}}
    url = notif.get("webhook_url", "")
    content = f"🔴 扫描完成告警\n目标: {data.get('target','')}\n发现: {len(critical)}个critical, {len(high)}个high漏洞\n总漏洞: {len(vulns)}\n时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    payload = {"msgtype": "text", "text": {"content": content}}
    result = _send_webhook(url, payload)
    return {"success": result["success"], "data": {"alert_sent": True, "result": result}}
