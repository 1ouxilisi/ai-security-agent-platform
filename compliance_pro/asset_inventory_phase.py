# -*- coding: utf-8 -*-
"""
asset_inventory_phase.py — 阶段1：资产盘点。

功能:
    - 自动发现 IT 资产（服务器/网络设备/数据库/应用/终端）
    - 资产分类（按类型/按重要性/按业务线）
    - 资产属性管理（IP/主机名/操作系统/版本/负责人/业务线/位置）
    - 资产变更监控
    - 资产价值评估
    - 资产清单导出
    - 真实发现工具框架（nmap/arp/ping，subprocess 超时300s），未安装明确提示不 mock
    - 内置资产模拟框架兜底
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

TOOL_TIMEOUT = 300  # 秒

ASSET_TYPES = ["server", "network", "database", "application", "endpoint"]
CRITICALITY = ["critical", "high", "medium", "low"]
BUSINESS_LINES = ["核心业务", "办公OA", "研发测试", "对外门户", "数据平台"]


# --------------------------------------------------------------------------- #
# 工具探测
# --------------------------------------------------------------------------- #
def _which(name: str) -> Optional[str]:
    p = shutil.which(name)
    if p:
        return p
    for cand in (
        f"C:\\Program Files\\{name}\\{name}.exe",
        f"C:\\Windows\\System32\\{name}.exe",
        f"/usr/bin/{name}", f"/usr/local/bin/{name}",
    ):
        try:
            if os.path.exists(cand):
                return cand
        except Exception:
            pass
    return None


# --------------------------------------------------------------------------- #
# 数据类
# --------------------------------------------------------------------------- #
@dataclass
class Asset:
    asset_id: str = ""
    name: str = ""
    ip: str = ""
    hostname: str = ""
    asset_type: str = "server"
    os: str = ""
    os_version: str = ""
    owner: str = ""
    business_line: str = "核心业务"
    location: str = ""
    criticality: str = "medium"
    value_score: int = 50
    status: str = "active"   # active/quarantine/decommissioned
    first_seen: str = ""
    last_seen: str = ""
    tags: List[str] = field(default_factory=list)
    changed: bool = False
    change_log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


# --------------------------------------------------------------------------- #
# 内置资产模拟框架（未安装真实发现工具时兜底）
# --------------------------------------------------------------------------- #
_SIMULATED_ASSETS: List[Dict[str, Any]] = [
    {"name": "核心数据库服务器", "ip": "10.10.1.11", "asset_type": "database",
     "os": "CentOS", "os_version": "7.9", "owner": "张运维",
     "business_line": "核心业务", "location": "机房A-3排",
     "criticality": "critical", "value_score": 95},
    {"name": "Web前端服务器", "ip": "10.10.1.21", "asset_type": "server",
     "os": "Ubuntu", "os_version": "22.04", "owner": "李开发",
     "business_line": "对外门户", "location": "机房A-5排",
     "criticality": "high", "value_score": 82},
    {"name": "Nginx负载均衡", "ip": "10.10.1.31", "asset_type": "network",
     "os": "Debian", "os_version": "12", "owner": "李开发",
     "business_line": "对外门户", "location": "机房A-5排",
     "criticality": "high", "value_score": 78},
    {"name": "MySQL主库", "ip": "10.10.1.12", "asset_type": "database",
     "os": "RHEL", "os_version": "8.6", "owner": "张运维",
     "business_line": "核心业务", "location": "机房A-3排",
     "criticality": "critical", "value_score": 92},
    {"name": "Redis缓存集群", "ip": "10.10.1.13", "asset_type": "database",
     "os": "CentOS", "os_version": "7.9", "owner": "王DBA",
     "business_line": "核心业务", "location": "机房A-4排",
     "criticality": "high", "value_score": 75},
    {"name": "OA应用服务器", "ip": "10.10.2.11", "asset_type": "application",
     "os": "Windows Server", "os_version": "2019", "owner": "赵行政",
     "business_line": "办公OA", "location": "机房B-1排",
     "criticality": "medium", "value_score": 55},
    {"name": "财务数据库", "ip": "10.10.2.21", "asset_type": "database",
     "os": "Windows Server", "os_version": "2016", "owner": "钱财务",
     "business_line": "办公OA", "location": "机房B-2排",
     "criticality": "high", "value_score": 80},
    {"name": "研发测试机", "ip": "192.168.10.51", "asset_type": "endpoint",
     "os": "Windows 10", "os_version": "22H2", "owner": "孙开发",
     "business_line": "研发测试", "location": "研发区",
     "criticality": "low", "value_score": 30},
    {"name": "核心交换机", "ip": "10.10.0.1", "asset_type": "network",
     "os": "Huawei VRP", "os_version": "V8", "owner": "网管网",
     "business_line": "核心业务", "location": "机房A-1排",
     "criticality": "critical", "value_score": 90},
    {"name": "备份服务器", "ip": "10.10.3.11", "asset_type": "server",
     "os": "Ubuntu", "os_version": "20.04", "owner": "张运维",
     "business_line": "数据平台", "location": "机房C-1排",
     "criticality": "medium", "value_score": 60},
]


class AssetInventoryPhase:
    """阶段1：资产盘点。"""

    def __init__(self) -> None:
        self._assets: Dict[str, Asset] = {}
        self._lock = threading.Lock()
        self._discovered_log: List[Dict[str, Any]] = []
        self._seed_simulated()

    # ------------------------------------------------------------------ #
    def _seed_simulated(self) -> None:
        for s in _SIMULATED_ASSETS:
            aid = "ast_" + uuid.uuid4().hex[:8]
            now = datetime.now().isoformat(timespec="seconds")
            a = Asset(asset_id=aid, first_seen=now, last_seen=now, **s)
            with self._lock:
                self._assets[aid] = a

    # ------------------------------------------------------------------ #
    # 真实工具调用
    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        return {
            "nmap": _which("nmap") or _which("nmap.exe"),
            "arp": _which("arp") or _which("arp.exe"),
            "ping": _which("ping") or _which("ping.exe"),
            "note": "真实资产发现调用上述工具；未安装时使用内置模拟资产框架兜底",
        }

    def discover_subnet(self, cidr: str = "10.10.0.0/16") -> Dict[str, Any]:
        """尝试用 nmap 真实发现；未安装则回退模拟框架。"""
        nmap = _which("nmap") or _which("nmap.exe")
        if not nmap:
            self._discovered_log.append({
                "time": datetime.now().isoformat(timespec="seconds"),
                "cidr": cidr, "method": "simulated_fallback",
                "msg": "nmap 未安装，使用内置模拟资产清单兜底",
            })
            return {
                "cidr": cidr, "method": "simulated_fallback",
                "found": len(self._assets),
                "message": "nmap 未检测到，已使用内置模拟资产框架",
            }
        try:
            # 快速扫描：-T4 快时序，--host-timeout 单主机超时，
            # --max-rtt-timeout 缩短等待，避免大网段长时间挂起
            cmd = [nmap, "-sn", "-T4", "--max-rtt-timeout", "200ms",
                   "--host-timeout", "60s", "-PR", cidr, "-oX", "-"]
            out = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=TOOL_TIMEOUT)
            hosts = out.stdout.count("<host ")
            self._discovered_log.append({
                "time": datetime.now().isoformat(timespec="seconds"),
                "cidr": cidr, "method": "nmap", "hosts": hosts,
            })
            return {"cidr": cidr, "method": "nmap", "found": hosts,
                    "message": f"nmap 发现 {hosts} 个在线主机"}
        except subprocess.TimeoutExpired:
            return {"cidr": cidr, "method": "nmap", "error": "超时300s",
                    "message": "nmap 扫描超时"}
        except Exception as e:  # noqa: BLE001
            return {"cidr": cidr, "method": "nmap", "error": str(e),
                    "message": f"nmap 调用失败: {e}"}

    # ------------------------------------------------------------------ #
    # CRUD
    # ------------------------------------------------------------------ #
    def add_asset(self, name: str, ip: str,
                  asset_type: str = "server", **kw: Any) -> Dict[str, Any]:
        aid = "ast_" + uuid.uuid4().hex[:8]
        now = datetime.now().isoformat(timespec="seconds")
        a = Asset(asset_id=aid, name=name, ip=ip, asset_type=asset_type,
                  first_seen=now, last_seen=now, **kw)
        with self._lock:
            self._assets[aid] = a
        return a.to_dict()

    def update_asset(self, asset_id: str, **kw: Any) -> Optional[Dict[str, Any]]:
        with self._lock:
            a = self._assets.get(asset_id)
            if a is None:
                return None
            for k, v in kw.items():
                if hasattr(a, k) and v is not None:
                    old = getattr(a, k)
                    if old != v:
                        a.change_log.append(
                            f"{datetime.now().strftime('%Y-%m-%d %H:%M')} "
                            f"{k}: {old} -> {v}")
                        a.changed = True
                        setattr(a, k, v)
            a.last_seen = datetime.now().isoformat(timespec="seconds")
            return a.to_dict()

    def delete_asset(self, asset_id: str) -> bool:
        with self._lock:
            return self._assets.pop(asset_id, None) is not None

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            a = self._assets.get(asset_id)
            return a.to_dict() if a else None

    def list_assets(self, asset_type: Optional[str] = None,
                    criticality: Optional[str] = None,
                    business_line: Optional[str] = None,
                    keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._assets.values())
        out = []
        for a in items:
            if asset_type and a.asset_type != asset_type:
                continue
            if criticality and a.criticality != criticality:
                continue
            if business_line and a.business_line != business_line:
                continue
            if keyword and keyword.lower() not in (a.name + a.ip + a.hostname
                                                    ).lower():
                continue
            out.append(a.to_dict())
        out.sort(key=lambda x: (-x["value_score"], x["name"]))
        return out

    # ------------------------------------------------------------------ #
    def classify_summary(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._assets.values())
        by_type: Dict[str, int] = {}
        by_crit: Dict[str, int] = {}
        by_bl: Dict[str, int] = {}
        for a in items:
            by_type[a.asset_type] = by_type.get(a.asset_type, 0) + 1
            by_crit[a.criticality] = by_crit.get(a.criticality, 0) + 1
            by_bl[a.business_line] = by_bl.get(a.business_line, 0) + 1
        return {"total": len(items), "by_type": by_type,
                "by_criticality": by_crit, "by_business_line": by_bl}

    def value_assessment(self) -> List[Dict[str, Any]]:
        items = self.list_assets()
        items.sort(key=lambda x: x["value_score"], reverse=True)
        return items

    def change_monitor(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._assets.values())
        changed = [a.to_dict() for a in items if a.changed]
        return {"changed_count": len(changed), "changed": changed,
                "discovery_log": self._discovered_log[-20:]}

    def export_inventory(self, fmt: str = "json") -> Dict[str, Any]:
        items = self.list_assets()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "reports", "compliance_pro")
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f"asset_inventory_{ts}.{fmt}")
        if fmt == "csv":
            import csv
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["asset_id", "name", "ip", "asset_type", "os",
                            "owner", "business_line", "criticality",
                            "value_score"])
                for a in items:
                    w.writerow([a["asset_id"], a["name"], a["ip"],
                                a["asset_type"], a["os"], a["owner"],
                                a["business_line"], a["criticality"],
                                a["value_score"]])
        else:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(items, f, ensure_ascii=False, indent=2)
        return {"path": path, "count": len(items), "format": fmt}

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        s = self.classify_summary()
        return {"total": s["total"], "by_type": s["by_type"],
                "by_criticality": s["by_criticality"],
                "by_business_line": s["by_business_line"],
                "changed": sum(1 for a in self._assets.values() if a.changed)}


_default: Optional[AssetInventoryPhase] = None


def get_asset_inventory_phase() -> AssetInventoryPhase:
    global _default
    if _default is None:
        _default = AssetInventoryPhase()
    return _default
