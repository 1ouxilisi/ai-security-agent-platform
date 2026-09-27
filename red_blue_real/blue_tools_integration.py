# -*- coding: utf-8 -*-
"""
blue_tools_integration.py — 方向4：真实蓝队安全工具集成。

统一接口（连接/认证/查询/结果解析/错误处理）:
    - Suricata   IDS/IPS（规则/告警/PCAP）
    - Snort      IDS/IPS
    - Elasticsearch  日志存储/搜索
    - Wazuh      SIEM/EDR（规则/告警/漏洞）
    - TheHive    事件响应平台（案例/任务/告警/IOC）

真实原则：端口/服务真实探测，可达则真实 HTTP/CLI 调用，
未安装/未配置给安装配置步骤，绝不 mock。
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .red_attack_chain import run_command, probe, port_open, http_json as _http_json


class SuricataTool:
    name = "Suricata"

    def __init__(self, eve_json: str = "/var/log/suricata/eve.json") -> None:
        self.eve_json = eve_json

    def status(self) -> Dict[str, Any]:
        b = probe("suricata")
        return {"tool": self.name, "available": bool(b["available"]),
                "binary": b["path"], "eve_json": self.eve_json,
                "eve_exists": __import__("os").path.exists(self.eve_json),
                "install_hint": "apt install suricata && suricata-update"}

    def alerts(self, limit: int = 50) -> Dict[str, Any]:
        import os
        if not os.path.exists(self.eve_json):
            return {"tool": self.name, "alerts": [], "available": False,
                    "error": f"eve.json 不存在: {self.eve_json}",
                    "install_hint": "启动 suricata -i eth0 后生成 eve.json"}
        out = []
        with open(self.eve_json, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if obj.get("event_type") == "alert":
                        out.append({"severity": obj.get("alert", {}).get("severity"),
                                    "signature": obj.get("alert", {}).get("signature"),
                                    "src_ip": obj.get("src_ip"),
                                    "dest_ip": obj.get("dest_ip")})
                except Exception:  # noqa: BLE001
                    continue
        return {"tool": self.name, "alerts": out[-limit:],
                "alert_count": len(out)}


class SnortTool:
    name = "Snort"

    def status(self) -> Dict[str, Any]:
        b = probe("snort")
        return {"tool": self.name, "available": bool(b["available"]),
                "binary": b["path"],
                "install_hint": "apt install snort；规则 /etc/snort/snort.rules"}

    def version(self) -> Dict[str, Any]:
        b = probe("snort")
        if not b["available"]:
            return {"tool": self.name, "available": False,
                    "install_hint": "apt install snort"}
        r = run_command([b["path"], "-V"], timeout=20)
        return {"tool": self.name, "available": True,
                "version": (r["stdout"] or "")[:300], "error": r["error"]}


class ElasticsearchTool:
    name = "Elasticsearch"

    def __init__(self, host: str = "127.0.0.1", port: int = 9200) -> None:
        self.host = host
        self.port = port

    def status(self) -> Dict[str, Any]:
        reachable = port_open(self.host, self.port)
        return {"tool": self.name, "host": self.host, "port": self.port,
                "reachable": reachable,
                "install_hint": ("docker run -d -p 9200:9200 "
                                 "-e discovery.type=single-node "
                                 "-e xpack.security.enabled=false "
                                 "docker.elastic.co/elasticsearch/elasticsearch:8.13.0")}

    def query(self, index: str = "*", q: str = "*", size: int = 20
              ) -> Dict[str, Any]:
        if not self.status()["reachable"]:
            return {"tool": self.name, "hits": [], "error": "ES 不可达",
                    "install_hint": "确认 9200 端口服务"}
        body = {"query": {"query_string": {"query": q}}, "size": size}
        r = _http_json(f"http://{self.host}:{self.port}/{index}/_search", body)
        hits = r["json"].get("hits", {}).get("hits", []) if r["ok"] else []
        return {"tool": self.name, "ok": r["ok"],
                "hits": [h.get("_source", {}) for h in hits],
                "total": r["json"].get("hits", {}).get("total", {}),
                "error": r["error"]}


class WazuhTool:
    name = "Wazuh"

    def __init__(self, host: str = "127.0.0.1", port: int = 55000,
                 user: str = "wazuh", password: str = "") -> None:
        self.host = host
        self.port = port
        self.user = user
        self.password = password

    def status(self) -> Dict[str, Any]:
        reachable = port_open(self.host, self.port)
        return {"tool": self.name, "host": self.host, "port": self.port,
                "reachable": reachable,
                "install_hint": ("docker compose up -d wazuh.wazuh-dashboard "
                                 "wazuh.elasticsearch wazuh.manager")}

    def alerts(self, limit: int = 20) -> Dict[str, Any]:
        if not self.status()["reachable"]:
            return {"tool": self.name, "alerts": [], "error": "Wazuh API 不可达",
                    "install_hint": "Wazuh API 默认 55000，需 api.login"}
        r = _http_json(f"https://{self.host}:{self.port}/alerts?limit={limit}",
                      headers={}, method="GET")
        return {"tool": self.name, "ok": r["ok"], "alerts": r["json"],
                "error": r["error"]}


class TheHiveTool:
    name = "TheHive"

    def __init__(self, uri: str = "http://127.0.0.1:9000",
                 api_key: str = "") -> None:
        self.uri = uri.rstrip("/")
        self.api_key = api_key

    def status(self) -> Dict[str, Any]:
        host = self.uri.replace("http://", "").replace("https://", "").split("/")[0]
        hp = host.split(":")
        reachable = port_open(hp[0], int(hp[1]) if len(hp) > 1 else 80)
        return {"tool": self.name, "uri": self.uri, "reachable": reachable,
                "install_hint": "docker run -p 9000:9000 "
                                "be4sd/thehive:latest；API key 在组织设置生成"}

    def cases(self) -> Dict[str, Any]:
        if not self.status()["reachable"]:
            return {"tool": self.name, "cases": [], "error": "TheHive 不可达",
                    "install_hint": "确认 9000 端口并配置 API key"}
        h = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        r = _http_json(f"{self.uri}/api/v1/case/_search",
                       {"query": {"filter": {}}, "size": 20},
                       headers=h)
        return {"tool": self.name, "ok": r["ok"],
                "cases": r["json"] if r["ok"] else [],
                "error": r["error"]}


class BlueToolsIntegration:
    """蓝队工具集成门面。"""

    def __init__(self) -> None:
        self.suricata = SuricataTool()
        self.snort = SnortTool()
        self.elasticsearch = ElasticsearchTool()
        self.wazuh = WazuhTool()
        self.thehive = TheHiveTool()

    def matrix(self) -> Dict[str, Any]:
        return {
            "suricata": self.suricata.status(),
            "snort": self.snort.status(),
            "elasticsearch": self.elasticsearch.status(),
            "wazuh": self.wazuh.status(),
            "thehive": self.thehive.status(),
        }

    def health(self) -> Dict[str, Any]:
        m = self.matrix()
        reachable = sum(1 for v in m.values()
                        if v.get("reachable") or v.get("available"))
        return {"tools": list(m.keys()), "ready_count": reachable,
                "total": len(m), "detail": m}


_default: Optional[BlueToolsIntegration] = None


def get_blue_tools() -> BlueToolsIntegration:
    global _default
    if _default is None:
        _default = BlueToolsIntegration()
    return _default
