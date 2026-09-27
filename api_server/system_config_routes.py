# -*- coding: utf-8 -*-
"""系统配置面板 - 工具路径/超时/默认设置管理"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json, os

router = APIRouter(prefix="/api/v1/system-config", tags=["系统配置"])
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "system_config.json")

DEFAULT_CONFIG = {
    "tools": {
        "nmap_path": r"C:\Program Files (x86)\Nmap\nmap.exe",
        "nuclei_path": r"C:\Users\ASUS\tools\nuclei.exe",
        "nuclei_template_dir": r"C:\Users\ASUS\nuclei-templates",
        "sqlmap_path": r"C:\Users\ASUS\tools\sqlmap.bat",
        "nikto_path": r"C:\Users\ASUS\tools\nikto.bat",
        "subfinder_path": r"C:\Users\ASUS\bin\subfinder.exe",
    },
    "scan": {
        "nmap_timeout": 30,
        "nuclei_timeout": 20,
        "sqlmap_timeout": 120,
        "default_depth": "standard",
        "nmap_scan_type": "sT",
    },
    "ai": {
        "enabled": False,
        "provider": "deepseek",
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "api_key_set": False,
    },
    "report": {
        "default_format": "html",
        "include_attack_paths": True,
        "include_remediation": True,
        "company_name": "",
    },
    "notification": {
        "webhook_enabled": False,
        "webhook_url": "",
        "alert_on_critical": True,
        "alert_on_high": True,
    }
}

def _load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except: pass
    return DEFAULT_CONFIG

def _save_config(config):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

@router.get("/config")
def get_config():
    return {"success": True, "data": _load_config()}

@router.put("/config")
def update_config(config: Dict[str, Any]):
    current = _load_config()
    def deep_merge(base, override):
        for k, v in override.items():
            if isinstance(v, dict) and k in base and isinstance(base[k], dict):
                deep_merge(base[k], v)
            else:
                base[k] = v
    deep_merge(current, config)
    _save_config(current)
    return {"success": True, "data": {"updated": True, "config": current}}

@router.post("/config/reset")
def reset_config():
    _save_config(DEFAULT_CONFIG)
    return {"success": True, "data": {"reset": True}}

@router.get("/tools/status")
def tools_status():
    """检查所有工具可用性"""
    from asm.real_tools import RealToolExecutor
    tools = RealToolExecutor.check_tools()
    return {"success": True, "data": tools}

@router.get("/system/info")
def system_info():
    """系统信息"""
    import sys, platform
    config = _load_config()
    return {"success": True, "data": {
        "version": "9.0-lite",
        "python_version": sys.version,
        "platform": platform.platform(),
        "config_path": CONFIG_PATH,
        "ai_enabled": config.get("ai", {}).get("enabled", False),
        "webhook_enabled": config.get("notification", {}).get("webhook_enabled", False),
    }}
