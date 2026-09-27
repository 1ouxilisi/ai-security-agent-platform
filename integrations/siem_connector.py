#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
siem_connector 模块，提供 SIEM 系统连接器。

模块功能：
    - 通过 syslog（UDP/TCP, RFC 5424）向 SIEM 服务器推送日志
    - 支持 syslog / CEF / LEEF 三种日志格式
    - 推送告警 / 漏洞 / 扫描结果
    - 支持批量推送与连接测试

注意事项：
    - 本模块仅用于授权的安全运营场景
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import json
import os
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


# 项目根目录（本文件位于 <root>/integrations/）
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")
CONFIG_PATH = os.path.join(CONFIG_DIR, "siem_config.json")

# 严重级别 -> syslog severity (0-7)
SEVERITY_MAP = {
    "critical": 2,   # Emergency/Alert 级别，归为 CRIT(2)
    "high": 4,       # Warning
    "medium": 5,     # Notice
    "low": 6,        # Informational
    "info": 6,
    "informational": 6,
}

# 默认配置
DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": False,
    "server": "127.0.0.1",
    "port": 514,
    "protocol": "udp",          # udp / tcp
    "format": "syslog",         # syslog / cef / leef
    "facility": 16,             # local0
    "app_name": "AIHackingAgent",
    "vendor": "AISec",
    "product": "AI-Hacking-Agent",
    "version": "1.0.0",
    "timeout": 5,
}


class SIEMConnector:
    """SIEM 连接器，负责把安全事件推送到 SIEM 平台。"""

    def __init__(self, config_path: str = CONFIG_PATH):
        """初始化连接器，加载配置。

        Args:
            config_path: 配置文件路径，默认 config/siem_config.json
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = dict(DEFAULT_CONFIG)
        self.load_config()

    # ==================== 配置读写 ====================

    def load_config(self) -> Dict[str, Any]:
        """从磁盘加载配置，文件不存在则写入默认配置。"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            if os.path.exists(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                self.config.update(saved)
            else:
                self.save_config()
        except Exception as e:  # 配置损坏不崩溃
            logger.warning("SIEM 配置加载失败，使用默认配置: %s", e)
            self.config = dict(DEFAULT_CONFIG)
        return self.config

    def save_config(self) -> bool:
        """保存当前配置到磁盘。"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error("SIEM 配置保存失败: %s", e)
            return False

    def update_config(self, new_config: Dict[str, Any]) -> Dict[str, Any]:
        """合并更新配置。"""
        self.config.update(new_config or {})
        self.save_config()
        return self.config

    # ==================== 日志格式化 ====================

    @staticmethod
    def _ts() -> str:
        """生成 RFC 5424 UTC 时间戳。"""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def _pri(self, severity: str) -> int:
        """计算 PRI 字段值 = facility*8 + severity。"""
        sev = SEVERITY_MAP.get((severity or "info").lower(), 6)
        fac = int(self.config.get("facility", 16))
        return fac * 8 + sev

    def format_syslog(self, event: Dict[str, Any]) -> str:
        """把事件格式化为 RFC 5424 syslog 消息。

        Args:
            event: 事件字典，支持 title/content/severity/source/target/time 等键。
        """
        pri = self._pri(event.get("severity", "info"))
        ts = event.get("time") or self._ts()
        host = event.get("source") or socket.gethostname()
        app = self.config.get("app_name", "AIHackingAgent")
        title = event.get("title", "event")
        content = event.get("content", "")
        msgid = event.get("msgid", "EVT")
        payload = f"{title}: {content}".strip(": ")
        # RFC 5424: <PRI>1 TS HOST APP PROCID MSGID [SD] MSG
        return f"<{pri}>1 {ts} {host} {app} - {msgid} - {payload}"

    def format_cef(self, event: Dict[str, Any]) -> str:
        """把事件格式化为 CEF 消息。

        格式: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|extension
        """
        vendor = self.config.get("vendor", "AISec")
        product = self.config.get("product", "AI-Hacking-Agent")
        version = self.config.get("version", "1.0.0")
        sig_id = str(event.get("signature_id", event.get("id", "0")))
        name = event.get("title", "security event")
        sev = str(event.get("severity", "info"))
        # extension 字段
        ext_parts = []
        for key in ("src", "dst", "target", "source", "user", "msg", "content"):
            if key in event and event[key] is not None:
                ext_parts.append(f"{key}={event[key]}")
        if "time" in event:
            ext_parts.append(f"rt={event['time']}")
        extension = " ".join(ext_parts)
        # CEF 头管道符需转义
        name_safe = str(name).replace("|", "\\|")
        return f"CEF:0|{vendor}|{product}|{version}|{sig_id}|{name_safe}|{sev}|{extension}"

    def format_leef(self, event: Dict[str, Any]) -> str:
        """把事件格式化为 LEEF 2.0 消息。

        格式: LEEF:2.0|Vendor|Product|Version|EventID|Attributes
        """
        vendor = self.config.get("vendor", "AISec")
        product = self.config.get("product", "AI-Hacking-Agent")
        version = self.config.get("version", "1.0.0")
        event_id = str(event.get("event_id", event.get("id", "0")))
        attrs = []
        attrs.append(f"devTime={event.get('time') or self._ts()}")
        attrs.append(f"title={event.get('title', 'security event')}")
        attrs.append(f"severity={event.get('severity', 'info')}")
        if event.get("content"):
            attrs.append(f"msg={event['content']}")
        if event.get("target"):
            attrs.append(f"target={event['target']}")
        attributes = "\t".join(attrs)
        return f"LEEF:2.0|{vendor}|{product}|{version}|{event_id}|{attributes}"

    def format_message(self, event: Dict[str, Any]) -> str:
        """根据配置的 format 字段选择格式化方式。"""
        fmt = (self.config.get("format") or "syslog").lower()
        if fmt == "cef":
            return self.format_cef(event)
        if fmt == "leef":
            return self.format_leef(event)
        return self.format_syslog(event)

    # ==================== 网络发送 ====================

    def _send(self, message: str) -> bool:
        """通过 UDP/TCP socket 发送一条已格式化的日志消息。"""
        server = self.config.get("server", "127.0.0.1")
        port = int(self.config.get("port", 514))
        protocol = (self.config.get("protocol") or "udp").lower()
        timeout = float(self.config.get("timeout", 5))
        data = (message + "\n").encode("utf-8")
        try:
            if protocol == "tcp":
                with socket.create_connection((server, port), timeout=timeout) as s:
                    s.sendall(data)
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    s.sendto(data, (server, port))
            return True
        except Exception as e:
            logger.warning("SIEM 推送失败 (%s:%s/%s): %s", server, port, protocol, e)
            return False

    def _push(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """把事件格式化并推送，返回推送结果。"""
        if not self.config.get("enabled", False):
            return {"success": False, "pushed": False, "message": "SIEM 推送未启用"}
        msg = self.format_message(event)
        ok = self._send(msg)
        return {"success": ok, "pushed": ok, "message": msg,
                "format": self.config.get("format"), "size": len(msg)}

    # ==================== 业务接口 ====================

    def send_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """推送告警事件。"""
        event = {
            "id": alert_data.get("alert_id", "alert"),
            "title": alert_data.get("title", "安全告警"),
            "content": alert_data.get("message") or alert_data.get("content", ""),
            "severity": alert_data.get("severity", "high"),
            "target": alert_data.get("target"),
            "source": "alert_engine",
            "time": self._ts(),
        }
        return self._push(event)

    def send_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """推送漏洞事件。"""
        event = {
            "id": vuln_data.get("cve_id") or vuln_data.get("vuln_id", "vuln"),
            "title": vuln_data.get("title") or vuln_data.get("name", "漏洞发现"),
            "content": vuln_data.get("description") or vuln_data.get("detail", ""),
            "severity": vuln_data.get("severity", "medium"),
            "target": vuln_data.get("target") or vuln_data.get("asset"),
            "source": "vuln_scanner",
            "time": self._ts(),
        }
        return self._push(event)

    def send_scan_result(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """推送扫描结果事件。"""
        event = {
            "id": scan_data.get("scan_id", "scan"),
            "title": scan_data.get("title", "扫描完成"),
            "content": scan_data.get("summary") or scan_data.get("message", ""),
            "severity": scan_data.get("severity", "info"),
            "target": scan_data.get("target"),
            "source": "scan_engine",
            "time": self._ts(),
        }
        return self._push(event)

    def send_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """批量推送多条事件。

        Returns:
            {"total": n, "success": k, "failed": m, "results": [...]}
        """
        results = []
        ok_count = 0
        for ev in events or []:
            r = self._push(ev)
            results.append(r)
            if r.get("success"):
                ok_count += 1
        return {
            "total": len(events or []),
            "success": ok_count,
            "failed": len(events or []) - ok_count,
            "results": results,
        }

    def test_connection(self) -> Dict[str, Any]:
        """测试到 SIEM 服务器的连接可用性。

        Returns:
            {"success": bool, "message": str}
        """
        server = self.config.get("server", "127.0.0.1")
        port = int(self.config.get("port", 514))
        protocol = (self.config.get("protocol") or "udp").lower()
        timeout = float(self.config.get("timeout", 5))
        try:
            if protocol == "tcp":
                with socket.create_connection((server, port), timeout=timeout) as s:
                    s.settimeout(timeout)
                return {"success": True, "message": f"TCP 连接 {server}:{port} 成功"}
            # UDP 是无连接的，发送一条测试包即视为可达
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto("<134>1 udp-test AIHackingAgent - - - SIEM connectivity test\n".encode("utf-8"),
                         (server, port))
            return {"success": True, "message": f"UDP 测试包已发送至 {server}:{port}"}
        except Exception as e:
            return {"success": False, "message": f"连接失败: {e}"}


# 模块级单例，便于路由直接调用
siem_connector = SIEMConnector()
