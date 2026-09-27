# -*- coding: utf-8 -*-
"""range_manager.py — 真实靶场集成（方向3）。

靶场列表管理 / 状态检测 / 验证结果。
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

KNOWN_RANGES: List[Dict[str, Any]] = [
    {"id": "dvwa", "name": "DVWA", "type": "web_vuln",
     "repo": "vulnerables/web-dvwa",
     "default_url": "http://localhost:8081/login.php",
     "has_auth": True, "default_creds": "admin/password"},
    {"id": "juice_shop", "name": "OWASP Juice Shop", "type": "web_vuln",
     "repo": "bkimminich/juice-shop",
     "default_url": "http://localhost:3000",
     "has_auth": False},
    {"id": "webgoat", "name": "OWASP WebGoat", "type": "web_vuln",
     "repo": "webgoat/webgoat",
     "default_url": "http://localhost:8080/WebGoat",
     "has_auth": True},
    {"id": "bwapp", "name": "bWAPP", "type": "web_vuln",
     "repo": "raesene/bwapp",
     "default_url": "http://localhost:8082/login.php",
     "has_auth": True, "default_creds": "bee/bug"},
    {"id": "mutillidae", "name": "Mutillidae II", "type": "web_vuln",
     "repo": "cldeen/mutillidae",
     "default_url": "http://localhost:8083",
     "has_auth": False},
    {"id": "pikachu", "name": "Pikachu", "type": "web_vuln",
     "repo": "area345/pikachu",
     "default_url": "http://localhost:8084",
     "has_auth": False},
    {"id": "vulhub", "name": "Vulhub", "type": "multi_cve",
     "repo": "vulhub/vulhub",
     "default_url": "http://localhost:8085",
     "has_auth": False},
    {"id": "metasploitable2", "name": "Metasploitable2", "type": "vm",
     "repo": "", "default_url": "http://localhost:8086",
     "has_auth": False},
    {"id": "testphp", "name": "testphp.vulnweb.com", "type": "external",
     "repo": "", "default_url": "http://testphp.vulnweb.com",
     "has_auth": False},
    {"id": "google", "name": "Google (对照)", "type": "negative",
     "repo": "", "default_url": "https://www.google.com",
     "has_auth": False, "is_negative": True},
]


class RangeManager:
    """靶场管理。"""

    def __init__(self) -> None:
        self.ranges: Dict[str, Dict[str, Any]] = {r["id"]: dict(r)
                                                  for r in KNOWN_RANGES}
        self.verification_results: Dict[str, Dict[str, Any]] = {}

    def list(self) -> List[Dict[str, Any]]:
        return list(self.ranges.values())

    def get(self, range_id: str) -> Optional[Dict[str, Any]]:
        return self.ranges.get(range_id)

    def add(self, range_id: str, name: str, url: str,
            **kw: Any) -> Dict[str, Any]:
        self.ranges[range_id] = {
            "id": range_id, "name": name, "default_url": url, **kw,
        }
        return {"success": True, "range": self.ranges[range_id]}

    def status(self, range_id: str) -> Dict[str, Any]:
        """真实检测靶场是否在线（curl）。"""
        rng = self.ranges.get(range_id)
        if not rng:
            return {"success": False, "error": "unknown range"}
        url = rng["default_url"]
        if not shutil.which("curl"):
            return {"success": False, "error": "curl 未安装",
                    "online": False}
        try:
            proc = subprocess.run(
                ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "10", url],
                capture_output=True, text=True, timeout=15,
            )
            code = proc.stdout.strip()
            online = bool(code and code[0] in "23")
            result = {
                "range_id": range_id, "url": url,
                "http_code": code, "online": online,
                "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.verification_results[range_id] = result
            return {"success": True, **result}
        except Exception as e:
            return {"success": False, "error": str(e), "online": False}

    def verify(self, range_id: str) -> Dict[str, Any]:
        """跑一次状态检测。"""
        return self.status(range_id)

    def verify_all(self) -> Dict[str, Any]:
        results = {}
        for rid in self.ranges:
            results[rid] = self.status(rid)
        online = sum(1 for r in results.values() if r.get("online"))
        return {
            "total": len(self.ranges),
            "online": online,
            "offline": len(self.ranges) - online,
            "results": results,
        }
