#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
endpoint_asset.py — 终端资产管理模块。

覆盖：
    - 终端发现：自动发现网络中的终端/操作系统/硬件配置/安装软件/开放服务/发现方式
    - 终端清单：主机名/IP/MAC/OS版本/补丁级别/CPU/内存/磁盘/域/位置/所有者/Agent版本/最后通信时间
    - 终端分组：按部门/操作系统/位置/风险等级/功能角色分组，分组规则/组成员/分组统计
    - 终端状态监控：在线/离线/CPU/内存/磁盘/网络/进程数/服务状态/Agent状态/资源使用率
    - 终端生命周期管理：注册/激活/退役/重新分配/丢失/被盗处理/生命周期事件/状态流转

设计定位：仅做终端资产盘点、监控与管理视角的分析，输出清单与状态报告。
"""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 依赖 try-import
# --------------------------------------------------------------------------- #
try:
    import psutil  # type: ignore
    _PSUTIL_AVAILABLE = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore
    _PSUTIL_AVAILABLE = False


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
OS_LIST = [
    {"name": "Windows 11 Pro", "build": "22631.4169", "arch": "x64", "vendor": "Microsoft"},
    {"name": "Windows 10 Enterprise", "build": "19045.4842", "arch": "x64", "vendor": "Microsoft"},
    {"name": "Windows Server 2022", "build": "20348.2402", "arch": "x64", "vendor": "Microsoft"},
    {"name": "Ubuntu 22.04 LTS", "build": "22.04.4", "arch": "x64", "vendor": "Canonical"},
    {"name": "CentOS 7.9", "build": "7.9.2009", "arch": "x64", "vendor": "Red Hat"},
    {"name": "Rocky Linux 9.3", "build": "9.3", "arch": "x64", "vendor": "Rocky"},
    {"name": "macOS Sonoma 14.5", "build": "23F79", "arch": "arm64", "vendor": "Apple"},
]

DEPARTMENTS = ["研发部", "财务部", "人力资源部", "市场部", "运维部", "安全部", "销售部", "法务部"]
LOCATIONS = ["北京总部", "上海分部", "深圳分部", "成都分部", "武汉分部", "远程办公"]
RISK_LEVELS = ["low", "medium", "high", "critical"]
RISK_NAMES = {"low": "低风险", "medium": "中风险", "high": "高风险", "critical": "严重风险"}
FUNCTIONAL_ROLES = ["开发工作站", "办公终端", "服务器", "数据库服务器", "应用服务器",
                    "测试终端", "财务终端", "安全运维终端", "CRM工作站", "文件服务器"]
DISCOVERY_METHODS = ["Agent上报", "网络扫描", "DHCP日志", "AD域同步", "SNMP查询", "手动录入"]
AGENT_VERSIONS = ["4.8.2", "4.8.1", "4.7.9", "4.7.5", "4.6.12"]
LIFECYCLE_STATES = ["registered", "active", "deactivated", "retired", "lost", "stolen"]
LIFECYCLE_FLOW = {
    "registered": ["active"],
    "active": ["deactivated", "lost", "stolen", "retired"],
    "deactivated": ["active", "retired"],
    "lost": ["active", "stolen", "retired"],
    "stolen": ["retired"],
    "retired": [],
}


def _hash_mac(idx: int) -> str:
    raw = f"EDR-ASSET-{idx}-{uuid.uuid4().hex[:4]}"
    h = hashlib.md5(raw.encode()).hexdigest()[:12].upper()
    return ":".join(h[i:i+2] for i in range(0, 12, 2))


def _gen_hostname(idx: int) -> str:
    prefixes = ["WIN", "SRV", "DEV", "OPS", "SEC", "FIN", "WEB", "DB"]
    p = random.choice(prefixes)
    return f"{p}-WS-{idx:04d}"


def _gen_ip(idx: int) -> str:
    return f"10.{random.randint(10,30)}.{random.randint(0,255)}.{random.randint(2,254)}"


def _gen_software(os_name: str) -> List[Dict[str, Any]]:
    common = [
        {"name": "Google Chrome", "version": "127.0.6533.100", "publisher": "Google"},
        {"name": "Microsoft Office 365", "version": "16.0.17726.20078", "publisher": "Microsoft"},
        {"name": "7-Zip", "version": "23.01", "publisher": "Igor Pavlov"},
        {"name": "Slack", "version": "4.36.140", "publisher": "Slack Technologies"},
        {"name": "Zoom", "version": "5.16.5", "publisher": "Zoom Video"},
        {"name": "VS Code", "version": "1.92.1", "publisher": "Microsoft"},
    ]
    if "Windows" in os_name:
        common.append({"name": "Microsoft Edge", "version": "127.0.2651.105", "publisher": "Microsoft"})
        common.append({"name": "Adobe Acrobat Reader", "version": "2024.002.20893", "publisher": "Adobe"})
    elif "Linux" in os_name or "Ubuntu" in os_name or "CentOS" in os_name or "Rocky" in os_name:
        common.append({"name": "OpenSSH", "version": "8.9p1", "publisher": "OpenBSD"})
        common.append({"name": "Docker", "version": "26.1.4", "publisher": "Docker Inc."})
    return random.sample(common, k=random.randint(3, len(common)))


def _gen_services() -> List[Dict[str, Any]]:
    svcs = [
        {"name": "EDR Agent Service", "status": "running", "startup": "auto"},
        {"name": "Windows Defender", "status": "running", "startup": "auto"},
        {"name": "Remote Registry", "status": "stopped", "startup": "manual"},
        {"name": "Print Spooler", "status": "running", "startup": "auto"},
        {"name": "Windows Update", "status": "running", "startup": "auto"},
        {"name": "Sysmon", "status": "running", "startup": "auto"},
    ]
    return random.sample(svcs, k=random.randint(3, 5))


def _gen_open_ports() -> List[int]:
    base = [135, 139, 445, 3389]
    extra = random.sample([22, 80, 443, 8080, 8443, 5985, 5986, 9090], k=random.randint(0, 3))
    return sorted(set(base + extra))


# --------------------------------------------------------------------------- #
# 主类
# --------------------------------------------------------------------------- #
class EndpointAssetManager:
    """终端资产管理：发现、清单、分组、监控、生命周期。"""

    def __init__(self) -> None:
        self._assets: Dict[str, Dict[str, Any]] = {}
        self._groups: Dict[str, Dict[str, Any]] = {}
        self._lifecycle_events: List[Dict[str, Any]] = []
        self._discovery_history: List[Dict[str, Any]] = []
        self._boot_demo()

    # ------------------------------------------------------------------ #
    # 数据初始化
    # ------------------------------------------------------------------ #
    def _boot_demo(self) -> None:
        rng = random.Random(42)
        random.seed(42)
        for i in range(1, 41):
            asset_id = f"EP-{i:04d}"
            os_info = random.choice(OS_LIST)
            dept = random.choice(DEPARTMENTS)
            loc = random.choice(LOCATIONS)
            risk = random.choices(RISK_LEVELS, weights=[40, 30, 20, 10])[0]
            role = random.choice(FUNCTIONAL_ROLES)
            online = random.random() > 0.12
            now = time.time()
            last_seen = now - random.randint(30, 7200) if online else now - random.randint(86400, 86400*7)
            cpu_pct = round(random.uniform(5, 85), 1) if online else 0.0
            mem_pct = round(random.uniform(15, 90), 1) if online else 0.0
            disk_pct = round(random.uniform(20, 95), 1)
            self._assets[asset_id] = {
                "asset_id": asset_id,
                "hostname": _gen_hostname(i),
                "ip_address": _gen_ip(i),
                "mac_address": _hash_mac(i),
                "os_name": os_info["name"],
                "os_build": os_info["build"],
                "os_arch": os_info["arch"],
                "patch_level": f"KB{random.randint(5000000, 5500000)}",
                "cpu_model": random.choice(["Intel i5-12400", "Intel i7-13700", "AMD Ryzen 7 7700", "Intel Xeon Silver 4314"]),
                "cpu_cores": random.choice([4, 8, 12, 16]),
                "memory_gb": random.choice([8, 16, 32, 64]),
                "disk_gb": random.choice([256, 512, 1024, 2048]),
                "domain": random.choice(["corp.example.com", "lab.internal", "workgroup"]),
                "location": loc,
                "department": dept,
                "owner": random.choice(["zhangsan", "lisi", "wangwu", "zhaoliu", "sunqi", "zhouba"]),
                "functional_role": role,
                "risk_level": risk,
                "risk_level_name": RISK_NAMES[risk],
                "agent_version": random.choice(AGENT_VERSIONS),
                "agent_status": "active" if online else "offline",
                "online": online,
                "last_communication": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_seen)),
                "discovery_method": random.choice(DISCOVERY_METHODS),
                "cpu_usage_pct": cpu_pct,
                "memory_usage_pct": mem_pct,
                "disk_usage_pct": disk_pct,
                "network_in_mbps": round(random.uniform(0.1, 80.0), 2) if online else 0.0,
                "network_out_mbps": round(random.uniform(0.1, 60.0), 2) if online else 0.0,
                "process_count": random.randint(80, 350) if online else 0,
                "installed_software": _gen_software(os_info["name"]),
                "open_ports": _gen_open_ports(),
                "services": _gen_services(),
                "lifecycle_state": "active",
                "registered_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - random.randint(86400*30, 86400*365))),
            }
        # 预置分组
        self._groups = {
            "grp-dept-rd": {"group_id": "grp-dept-rd", "name": "研发部终端", "type": "department",
                            "rule": "department=研发部", "members": [a for a in self._assets if self._assets[a]["department"] == "研发部"],
                            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")},
            "grp-os-win11": {"group_id": "grp-os-win11", "name": "Windows 11终端", "type": "os",
                             "rule": "os_name=Windows 11 Pro", "members": [a for a in self._assets if "Windows 11" in self._assets[a]["os_name"]],
                             "created_at": time.strftime("%Y-%m-%d %H:%M:%S")},
            "grp-risk-crit": {"group_id": "grp-risk-crit", "name": "严重风险终端", "type": "risk",
                              "rule": "risk_level=critical", "members": [a for a in self._assets if self._assets[a]["risk_level"] == "critical"],
                              "created_at": time.strftime("%Y-%m-%d %H:%M:%S")},
            "grp-role-srv": {"group_id": "grp-role-srv", "name": "服务器", "type": "role",
                             "rule": "functional_role in [服务器,数据库服务器,应用服务器,文件服务器]",
                             "members": [a for a in self._assets if "服务器" in self._assets[a]["functional_role"]],
                             "created_at": time.strftime("%Y-%m-%d %H:%M:%S")},
            "grp-loc-bj": {"group_id": "grp-loc-bj", "name": "北京总部终端", "type": "location",
                           "rule": "location=北京总部", "members": [a for a in self._assets if self._assets[a]["location"] == "北京总部"],
                           "created_at": time.strftime("%Y-%m-%d %H:%M:%S")},
        }

    # ------------------------------------------------------------------ #
    # 1. 终端发现
    # ------------------------------------------------------------------ #
    def discover_endpoints(self, network_range: str = "10.10.0.0/16",
                           method: str = "Agent上报") -> Dict[str, Any]:
        discovered = []
        new_count = random.randint(2, 8)
        base_idx = len(self._assets)
        for i in range(base_idx + 1, base_idx + 1 + new_count):
            asset_id = f"EP-{i:04d}"
            os_info = random.choice(OS_LIST)
            discovered.append({
                "asset_id": asset_id,
                "hostname": _gen_hostname(i),
                "ip_address": _gen_ip(i),
                "mac_address": _hash_mac(i),
                "os_detected": os_info["name"],
                "os_confidence": round(random.uniform(0.75, 0.99), 2),
                "discovery_method": method,
                "discovered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "open_ports": _gen_open_ports(),
                "installed_software_count": random.randint(15, 80),
                "needs_agent_deploy": True,
            })
        record = {
            "scan_id": uuid.uuid4().hex[:12],
            "network_range": network_range,
            "method": method,
            "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "hosts_scanned": random.randint(100, 500),
            "hosts_up": random.randint(30, 120),
            "new_endpoints": discovered,
            "new_count": new_count,
        }
        self._discovery_history.append(record)
        return record

    def list_discovery_history(self) -> List[Dict[str, Any]]:
        return list(reversed(self._discovery_history[-20:]))

    # ------------------------------------------------------------------ #
    # 2. 终端清单
    # ------------------------------------------------------------------ #
    def list_assets(self, department: Optional[str] = None, os_name: Optional[str] = None,
                    risk_level: Optional[str] = None, location: Optional[str] = None,
                    online: Optional[bool] = None, search: Optional[str] = None) -> Dict[str, Any]:
        items = list(self._assets.values())
        if department:
            items = [a for a in items if a["department"] == department]
        if os_name:
            items = [a for a in items if os_name.lower() in a["os_name"].lower()]
        if risk_level:
            items = [a for a in items if a["risk_level"] == risk_level]
        if location:
            items = [a for a in items if a["location"] == location]
        if online is not None:
            items = [a for a in items if a["online"] == online]
        if search:
            s = search.lower()
            items = [a for a in items if s in a["hostname"].lower() or s in a["ip_address"]]
        summary = {
            "total": len(items),
            "online": sum(1 for a in items if a["online"]),
            "offline": sum(1 for a in items if not a["online"]),
            "by_risk": {r: sum(1 for a in items if a["risk_level"] == r) for r in RISK_LEVELS},
            "by_os": {},
        }
        for a in items:
            summary["by_os"][a["os_name"]] = summary["by_os"].get(a["os_name"], 0) + 1
        return {"assets": items, "summary": summary}

    def get_asset_detail(self, asset_id: str) -> Optional[Dict[str, Any]]:
        a = self._assets.get(asset_id)
        if not a:
            return None
        detail = dict(a)
        detail["hardware"] = {
            "cpu_model": a["cpu_model"], "cpu_cores": a["cpu_cores"],
            "memory_gb": a["memory_gb"], "disk_gb": a["disk_gb"],
            "memory_usage_pct": a["memory_usage_pct"], "disk_usage_pct": a["disk_usage_pct"],
        }
        detail["software"] = a["installed_software"]
        detail["services"] = a["services"]
        detail["ports"] = a["open_ports"]
        return detail

    # ------------------------------------------------------------------ #
    # 3. 终端分组
    # ------------------------------------------------------------------ #
    def list_groups(self) -> Dict[str, Any]:
        groups = []
        for g in self._groups.values():
            groups.append({
                "group_id": g["group_id"], "name": g["name"], "type": g["type"],
                "rule": g["rule"], "member_count": len(g["members"]),
                "members": g["members"][:10],
                "created_at": g["created_at"],
            })
        return {"groups": groups, "total": len(groups)}

    def create_group(self, name: str, gtype: str, rule: str) -> Dict[str, Any]:
        gid = f"grp-{uuid.uuid4().hex[:8]}"
        members = []
        if gtype == "department":
            dept = rule.split("=")[-1] if "=" in rule else rule
            members = [a for a in self._assets if self._assets[a]["department"] == dept]
        elif gtype == "os":
            members = [a for a in self._assets if rule.lower() in self._assets[a]["os_name"].lower()]
        elif gtype == "risk":
            rl = rule.split("=")[-1] if "=" in rule else rule
            members = [a for a in self._assets if self._assets[a]["risk_level"] == rl]
        elif gtype == "location":
            loc = rule.split("=")[-1] if "=" in rule else rule
            members = [a for a in self._assets if self._assets[a]["location"] == loc]
        self._groups[gid] = {
            "group_id": gid, "name": name, "type": gtype, "rule": rule,
            "members": members, "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return {"group_id": gid, "name": name, "type": gtype, "member_count": len(members)}

    def get_group_stats(self, group_id: str) -> Optional[Dict[str, Any]]:
        g = self._groups.get(group_id)
        if not g:
            return None
        members = [self._assets[m] for m in g["members"] if m in self._assets]
        return {
            "group_id": group_id, "name": g["name"], "type": g["type"],
            "total_members": len(members),
            "online": sum(1 for m in members if m["online"]),
            "offline": sum(1 for m in members if not m["online"]),
            "avg_cpu": round(sum(m["cpu_usage_pct"] for m in members) / max(len(members), 1), 1),
            "avg_memory": round(sum(m["memory_usage_pct"] for m in members) / max(len(members), 1), 1),
            "risk_distribution": {r: sum(1 for m in members if m["risk_level"] == r) for r in RISK_LEVELS},
            "os_distribution": {},
        }

    # ------------------------------------------------------------------ #
    # 4. 终端状态监控
    # ------------------------------------------------------------------ #
    def monitor_status(self) -> Dict[str, Any]:
        items = list(self._assets.values())
        online = [a for a in items if a["online"]]
        offline = [a for a in items if not a["online"]]
        high_cpu = [a for a in online if a["cpu_usage_pct"] > 80]
        high_mem = [a for a in online if a["memory_usage_pct"] > 85]
        high_disk = [a for a in items if a["disk_usage_pct"] > 90]
        agent_down = [a for a in items if a["agent_status"] != "active"]
        return {
            "total_endpoints": len(items),
            "online": len(online),
            "offline": len(offline),
            "agent_active": len([a for a in items if a["agent_status"] == "active"]),
            "agent_down": len(agent_down),
            "avg_cpu": round(sum(a["cpu_usage_pct"] for a in online) / max(len(online), 1), 1),
            "avg_memory": round(sum(a["memory_usage_pct"] for a in online) / max(len(online), 1), 1),
            "avg_disk": round(sum(a["disk_usage_pct"] for a in items) / max(len(items), 1), 1),
            "high_cpu_count": len(high_cpu),
            "high_memory_count": len(high_mem),
            "high_disk_count": len(high_disk),
            "top_cpu": sorted(online, key=lambda x: x["cpu_usage_pct"], reverse=True)[:5],
            "top_memory": sorted(online, key=lambda x: x["memory_usage_pct"], reverse=True)[:5],
            "offline_list": [{"asset_id": a["asset_id"], "hostname": a["hostname"],
                              "last_communication": a["last_communication"]} for a in offline],
            "agent_down_list": [{"asset_id": a["asset_id"], "hostname": a["hostname"],
                                 "agent_status": a["agent_status"]} for a in agent_down],
            "monitored_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 5. 终端生命周期
    # ------------------------------------------------------------------ #
    def lifecycle_register(self, hostname: str, ip: str, department: str,
                           owner: str) -> Dict[str, Any]:
        asset_id = f"EP-{len(self._assets)+1:04d}"
        os_info = random.choice(OS_LIST)
        self._assets[asset_id] = {
            "asset_id": asset_id, "hostname": hostname, "ip_address": ip,
            "mac_address": _hash_mac(len(self._assets)+1),
            "os_name": os_info["name"], "os_build": os_info["build"],
            "os_arch": os_info["arch"], "patch_level": "KB0000000",
            "cpu_model": "Unknown", "cpu_cores": 0, "memory_gb": 0, "disk_gb": 0,
            "domain": "workgroup", "location": "未分配", "department": department,
            "owner": owner, "functional_role": "办公终端",
            "risk_level": "low", "risk_level_name": RISK_NAMES["low"],
            "agent_version": "4.8.2", "agent_status": "pending",
            "online": False, "last_communication": "—",
            "discovery_method": "手动录入",
            "cpu_usage_pct": 0, "memory_usage_pct": 0, "disk_usage_pct": 0,
            "network_in_mbps": 0, "network_out_mbps": 0, "process_count": 0,
            "installed_software": [], "open_ports": [], "services": [],
            "lifecycle_state": "registered",
            "registered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._lifecycle_events.append({
            "event_id": uuid.uuid4().hex[:10], "asset_id": asset_id,
            "event": "register", "detail": f"终端 {hostname} 注册",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        return {"asset_id": asset_id, "state": "registered", "message": "注册成功"}

    def lifecycle_transition(self, asset_id: str, action: str,
                             operator: str = "admin") -> Dict[str, Any]:
        a = self._assets.get(asset_id)
        if not a:
            return {"error": "终端不存在"}
        current = a["lifecycle_state"]
        if action not in LIFECYCLE_FLOW.get(current, []):
            return {"error": f"非法状态流转: {current} -> {action}"}
        a["lifecycle_state"] = action
        if action == "active":
            a["agent_status"] = "active"
            a["online"] = True
        elif action in ("retired",):
            a["online"] = False
            a["agent_status"] = "retired"
        elif action in ("lost", "stolen"):
            a["online"] = False
        self._lifecycle_events.append({
            "event_id": uuid.uuid4().hex[:10], "asset_id": asset_id,
            "event": action, "operator": operator,
            "detail": f"状态 {current} -> {action}",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        return {"asset_id": asset_id, "previous_state": current,
                "new_state": action, "message": "状态流转成功"}

    def lifecycle_events(self, asset_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if asset_id:
            return [e for e in self._lifecycle_events if e["asset_id"] == asset_id]
        return list(reversed(self._lifecycle_events[-50:]))

    def lifecycle_summary(self) -> Dict[str, Any]:
        items = list(self._assets.values())
        return {
            "by_state": {s: sum(1 for a in items if a["lifecycle_state"] == s) for s in LIFECYCLE_STATES},
            "total": len(items),
            "events_recent": list(reversed(self._lifecycle_events[-20:])),
        }


# --------------------------------------------------------------------------- #
# 模块级单例
# --------------------------------------------------------------------------- #
_default_manager: Optional[EndpointAssetManager] = None


def get_asset_manager() -> EndpointAssetManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = EndpointAssetManager()
    return _default_manager
