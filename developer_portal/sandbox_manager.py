# -*- coding: utf-8 -*-
"""sandbox_manager.py — 开发者沙箱。

能力：
- 沙箱环境申请 / 重置 / 健康检查
- 沙箱专用测试 API Key
- 模拟数据集、速率限制、调试日志、请求回放
"""

from __future__ import annotations

import secrets
import time
import uuid
from typing import Any, Dict, List, Optional


MOCK_DATASETS: Dict[str, Dict[str, Any]] = {
    "vuln_reports": {
        "name": "漏洞报告样例",
        "size": "2.4 MB",
        "records": 128,
        "sample": [
            {"cve": "CVE-2024-1234", "severity": "high", "package": "log4j"},
            {"cve": "CVE-2024-5678", "severity": "medium", "package": "openssl"},
        ],
    },
    "assets": {
        "name": "资产样例",
        "size": "512 KB",
        "records": 42,
        "sample": [
            {"id": "ast_001", "name": "web-prod-01", "type": "server"},
            {"id": "ast_002", "name": "db-prod-01", "type": "database"},
        ],
    },
    "ioc": {
        "name": "威胁情报样例",
        "size": "1.1 MB",
        "records": 1024,
        "sample": [
            {"indicator": "1.2.3.4", "verdict": "malicious"},
            {"indicator": "bad-domain.com", "verdict": "suspicious"},
        ],
    },
}


class SandboxManager:
    """沙箱环境管理。"""

    def __init__(self) -> None:
        self.sandboxes: Dict[str, Dict[str, Any]] = {}
        self.request_logs: Dict[str, List[Dict[str, Any]]] = {}
        self.playbacks: Dict[str, List[Dict[str, Any]]] = {}

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def create(self, owner: str, name: str = "") -> Dict[str, Any]:
        sb_id = "sb_" + uuid.uuid4().hex[:10]
        key = "sbx_" + secrets.token_hex(16)
        sb = {
            "sandbox_id": sb_id,
            "name": name or f"sandbox-{sb_id[:8]}",
            "owner": owner,
            "test_key": key,
            "status": "running",
            "rate_limit_per_min": 60,
            "calls_used": 0,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "expires_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(time.time() + 86400 * 7)),
            "dataset": "vuln_reports",
        }
        self.sandboxes[sb_id] = sb
        self.request_logs[sb_id] = []
        return sb

    def get(self, sb_id: str) -> Optional[Dict[str, Any]]:
        return self.sandboxes.get(sb_id)

    def list(self, owner: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.sandboxes.values())
        if owner:
            items = [s for s in items if s.get("owner") == owner]
        return items

    def reset(self, sb_id: str) -> Dict[str, Any]:
        sb = self.sandboxes.get(sb_id)
        if not sb:
            return {}
        sb["calls_used"] = 0
        sb["test_key"] = "sbx_" + secrets.token_hex(16)
        sb["reset_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.request_logs[sb_id] = []
        return sb

    def destroy(self, sb_id: str) -> bool:
        if sb_id in self.sandboxes:
            self.sandboxes.pop(sb_id, None)
            self.request_logs.pop(sb_id, None)
            return True
        return False

    def health(self, sb_id: str) -> Dict[str, Any]:
        sb = self.sandboxes.get(sb_id)
        if not sb:
            return {"healthy": False, "reason": "not_found"}
        return {
            "sandbox_id": sb_id,
            "healthy": sb["status"] == "running",
            "latency_ms": 12 + (sum(ord(c) for c in sb_id) % 30),
            "disk_free_mb": 512,
            "mem_free_mb": 256,
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 模拟请求 / 日志 / 回放
    # ------------------------------------------------------------------ #
    def mock_request(self, sb_id: str, endpoint: str, method: str = "GET",
                     payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        sb = self.sandboxes.get(sb_id)
        if not sb:
            return {"success": False, "error": "sandbox not found"}
        if sb["calls_used"] >= sb["rate_limit_per_min"]:
            return {"success": False, "error": "rate_limit_exceeded"}
        sb["calls_used"] += 1
        rec = {
            "req_id": "req_" + uuid.uuid4().hex[:8],
            "method": method,
            "endpoint": endpoint,
            "payload": payload or {},
            "status": 200,
            "latency_ms": 8 + (sum(ord(c) for c in endpoint) % 40),
            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "response": {"mock": True, "echo": payload or {}, "dataset": sb["dataset"]},
        }
        self.request_logs.setdefault(sb_id, []).append(rec)
        self.playbacks.setdefault(sb_id, []).append(rec)
        return {"success": True, "request": rec}

    def debug_logs(self, sb_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        logs = self.request_logs.get(sb_id, [])
        return logs[-limit:]

    def replay(self, sb_id: str, req_id: str) -> Dict[str, Any]:
        recs = self.playbacks.get(sb_id, [])
        target = next((r for r in recs if r.get("req_id") == req_id), None)
        if not target:
            return {"success": False, "error": "req not found"}
        rerun = dict(target)
        rerun["req_id"] = "req_" + uuid.uuid4().hex[:8]
        rerun["replayed_from"] = req_id
        rerun["at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.request_logs.setdefault(sb_id, []).append(rerun)
        return {"success": True, "replay": rerun}

    def list_datasets(self) -> Dict[str, Dict[str, Any]]:
        return MOCK_DATASETS

    def set_dataset(self, sb_id: str, dataset: str) -> Dict[str, Any]:
        sb = self.sandboxes.get(sb_id)
        if not sb:
            return {}
        if dataset not in MOCK_DATASETS:
            return {"success": False, "error": "unknown dataset"}
        sb["dataset"] = dataset
        return {"success": True, "sandbox": sb}


_sandbox: Optional[SandboxManager] = None


def get_sandbox_manager() -> SandboxManager:
    global _sandbox
    if _sandbox is None:
        _sandbox = SandboxManager()
    return _sandbox
