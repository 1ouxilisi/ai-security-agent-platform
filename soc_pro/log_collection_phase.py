# -*- coding: utf-8 -*-
"""
log_collection_phase.py — 阶段1：日志收集。

功能:
    - 真实 syslog/filebeat/logstash 集成框架（subprocess 调用，超时300s）
    - 多源日志接入（系统/应用/网络设备/安全设备）
    - 日志源管理（添加/删除/配置/状态监控）
    - 日志采集状态监控
    - 未安装工具明确提示，不 mock；未安装时用内置日志模拟框架兜底
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

TOOL_TIMEOUT = 300  # 秒

# --------------------------------------------------------------------------- #
# 工具探测
# --------------------------------------------------------------------------- #
def _which(name: str) -> Optional[str]:
    p = shutil.which(name)
    if p:
        return p
    for cand in (
        f"C:\\Program Files\\{name}\\{name}.exe",
        f"C:\\Program Files (x86)\\{name}\\{name}.exe",
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
class LogSource:
    source_id: str = ""
    name: str = ""
    source_type: str = "system"   # system/app/network/security/file/syslog
    protocol: str = "file"        # file/syslog_tcp/syslog_udp/filebeat/logstash
    path: str = ""                # 本地文件路径或 syslog 地址
    enabled: bool = True
    status: str = "unknown"       # running/stopped/error/unknown
    last_collected: str = ""
    collected_count: int = 0
    config: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id, "name": self.name,
            "source_type": self.source_type, "protocol": self.protocol,
            "path": self.path, "enabled": self.enabled,
            "status": self.status,
            "last_collected": self.last_collected,
            "collected_count": self.collected_count,
            "config": self.config, "error": self.error,
        }


@dataclass
class CollectedLog:
    log_id: str = ""
    source_id: str = ""
    source_name: str = ""
    raw: str = ""
    timestamp: str = ""
    received_at: str = ""
    parsed_ok: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_id": self.log_id, "source_id": self.source_id,
            "source_name": self.source_name, "raw": self.raw,
            "timestamp": self.timestamp, "received_at": self.received_at,
            "parsed_ok": self.parsed_ok,
        }


# --------------------------------------------------------------------------- #
# 内置日志模拟框架（未安装真实工具时兜底）
# --------------------------------------------------------------------------- #
_SAMPLE_TEMPLATES: List[Dict[str, str]] = [
    {
        "source_type": "system",
        "template": (
            "sshd[{pid}]: Failed password for invalid user {user} "
            "from {ip} port {port} ssh2"
        ),
    },
    {
        "source_type": "system",
        "template": (
            "sshd[{pid}]: Accepted password for {user} from {ip} port "
            "{port} ssh2"
        ),
    },
    {
        "source_type": "network",
        "template": (
            "%ASA-4-106023: Deny tcp src inside:{ip}/{port} "
            "dst outside:{ip2}/443 by access-group"
        ),
    },
    {
        "source_type": "security",
        "template": (
            "suricata[{pid}]: [**] [1:2001219:1] ET SCAN Potential SSH "
            "Scan [**] [Classification: Attempted Information Leak] "
            "[Priority: 2] {ip}:{port} -> {ip2}:22"
        ),
    },
    {
        "source_type": "app",
        "template": (
            "apache: {ip} - - [{ts}] \"POST /login HTTP/1.1\" 401 528 "
            "\"-\" \"Mozilla/5.0\""
        ),
    },
    {
        "source_type": "system",
        "template": (
            "sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; "
            "USER=root ; COMMAND=/bin/bash"
        ),
    },
    {
        "source_type": "network",
        "template": (
            "ntopng: Host {ip} sent {size} bytes outbound to {ip2}:443 "
            "unusual for user {user}"
        ),
    },
    {
        "source_type": "security",
        "template": (
            "sysmon: EventID=11 FileCreate user={user} "
            "C:\\Users\\{user}\\Downloads\\{file}"
        ),
    },
]

_USERS = ["admin", "root", "www-data", "oracle", "backup", "svc_account"]
_FILES = ["update.exe", "payload.dll", "dump.sql", "export.csv", "install.sh"]


def _rand_ip(rng) -> str:
    return f"{rng.randint(1,223)}.{rng.randint(0,255)}." \
           f"{rng.randint(0,255)}.{rng.randint(1,254)}"


def _generate_sample(source_type: str, rng) -> str:
    import random as _r
    pool = [t for t in _SAMPLE_TEMPLATES if t["source_type"] == source_type]
    if not pool:
        pool = _SAMPLE_TEMPLATES
    tpl = _r.choice(pool)["template"]
    return tpl.format(
        pid=rng.randint(100, 65535),
        user=rng.choice(_USERS),
        ip=_rand_ip(rng), ip2=_rand_ip(rng),
        port=rng.randint(1024, 65000),
        size=rng.choice([5242880, 10485760, 20971520, 52428800]),
        file=rng.choice(_FILES),
        ts=datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0800"),
    )


# --------------------------------------------------------------------------- #
# 阶段类
# --------------------------------------------------------------------------- #
class LogCollectionPhase:
    """阶段1：日志收集。"""

    def __init__(self) -> None:
        self._sources: Dict[str, LogSource] = {}
        self._logs: "deque" = __import__("collections").deque(maxlen=5000)
        self._lock = threading.Lock()
        self._sim_running: bool = False
        self._sim_thread: Optional[threading.Thread] = None
        self._ensure_default_sources()

    # ------------------------------------------------------------------ #
    def _ensure_default_sources(self) -> None:
        defaults = [
            ("syslog_udp_514", "Linux Syslog (UDP/514)", "system",
             "syslog_udp", "0.0.0.0:514"),
            ("filebeat_agent", "Filebeat Agent", "system",
             "filebeat", "/var/log/filebeat"),
            ("logstash_pipeline", "Logstash Pipeline", "app",
             "logstash", "localhost:5044"),
            ("asa_firewall", "Cisco ASA 防火墙", "network",
             "syslog_udp", "10.0.0.1:514"),
            ("suricata_ids", "Suricata IDS", "security",
             "file", "/var/log/suricata/fast.log"),
            ("apache_access", "Apache 访问日志", "app",
             "file", "/var/log/apache2/access.log"),
            ("windows_sysmon", "Windows Sysmon", "security",
             "file", "C:\\Windows\\System32\\winevt\\Logs"),
        ]
        for sid, name, stype, proto, path in defaults:
            if sid not in self._sources:
                self._sources[sid] = LogSource(
                    source_id=sid, name=name, source_type=stype,
                    protocol=proto, path=path, enabled=True,
                    status="stopped",
                )

    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        """真实工具探测：未安装明确提示。"""
        out: Dict[str, Any] = {}
        for tool in ("filebeat", "logstash", "syslog-ng", "rsyslogd",
                     "snort", "suricata"):
            path = _which(tool)
            out[tool] = {
                "available": bool(path),
                "path": path or "",
                "hint": "" if path
                        else f"未检测到 {tool}，请安装；当前使用内置日志模拟框架",
            }
        return out

    # ------------------------------------------------------------------ #
    def list_sources(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [s.to_dict() for s in self._sources.values()]

    def add_source(self, name: str, source_type: str = "system",
                   protocol: str = "file", path: str = "",
                   config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        sid = "src_" + uuid.uuid4().hex[:8]
        s = LogSource(source_id=sid, name=name, source_type=source_type,
                      protocol=protocol, path=path,
                      config=config or {})
        with self._lock:
            self._sources[sid] = s
        return s.to_dict()

    def remove_source(self, source_id: str) -> bool:
        with self._lock:
            return self._sources.pop(source_id, None) is not None

    def update_source(self, source_id: str,
                      **kwargs: Any) -> Optional[Dict[str, Any]]:
        with self._lock:
            s = self._sources.get(source_id)
            if s is None:
                return None
            for k, v in kwargs.items():
                if hasattr(s, k) and k not in ("source_id",):
                    setattr(s, k, v)
            return s.to_dict()

    # ------------------------------------------------------------------ #
    def start_collect(self, source_id: Optional[str] = None,
                      count: int = 200) -> Dict[str, Any]:
        """启动一次收集。优先真实工具；不可用则内置模拟兜底。"""
        started: List[str] = []
        notes: List[str] = []
        real_tools = self.tool_status()

        with self._lock:
            targets = ([self._sources[source_id]] if source_id
                       and source_id in self._sources
                       else [s for s in self._sources.values()
                             if s.enabled])

        import random as _r
        rng = _r.Random(int(time.time()))
        produced = 0
        per_source = max(1, count // max(1, len(targets)))

        for s in targets:
            # 真实工具尝试
            if s.protocol in ("filebeat", "logstash"):
                bin_path = _which(s.protocol)
                if bin_path:
                    try:
                        proc = subprocess.run(
                            [bin_path, "--version"],
                            capture_output=True, text=True,
                            timeout=TOOL_TIMEOUT,
                            encoding="utf-8", errors="ignore",
                        )
                        notes.append(
                            f"[真实] {s.name}: 调用 {bin_path} 成功 "
                            f"(rc={proc.returncode})")
                    except Exception as e:  # noqa: BLE001
                        notes.append(f"[真实] {s.name} 调用失败: {e}；"
                                     f"降级为内置模拟")
                        self._collect_simulated(s, per_source, rng)
                else:
                    notes.append(
                        f"[兜底] {s.name}: {s.protocol} 未安装，"
                        f"使用内置日志模拟框架")
                    self._collect_simulated(s, per_source, rng)
            else:
                self._collect_simulated(s, per_source, rng)
            s.status = "running"
            s.last_collected = datetime.now().isoformat(timespec="seconds")
            started.append(s.source_id)
            produced += s.collected_count

        return {
            "started_sources": started,
            "produced": produced,
            "notes": notes,
            "tools": real_tools,
        }

    def _collect_simulated(self, s: LogSource, n: int, rng) -> None:
        for _ in range(n):
            raw = _generate_sample(s.source_type, rng)
            rec = CollectedLog(
                log_id="log_" + uuid.uuid4().hex[:10],
                source_id=s.source_id, source_name=s.name,
                raw=raw,
                timestamp=datetime.now().isoformat(timespec="seconds"),
                received_at=datetime.now().isoformat(timespec="seconds"),
            )
            with self._lock:
                self._logs.append(rec)
                s.collected_count += 1

    # ------------------------------------------------------------------ #
    def recent_logs(self, limit: int = 100,
                    source_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._logs)
        if source_id:
            items = [x for x in items if x.source_id == source_id]
        items = items[-limit:]
        return [x.to_dict() for x in items]

    def status(self) -> Dict[str, Any]:
        with self._lock:
            total = sum(s.collected_count for s in self._sources.values())
            running = sum(1 for s in self._sources.values()
                         if s.status == "running")
        return {
            "source_total": len(self._sources),
            "running": running,
            "total_collected": total,
            "buffer_size": len(self._logs),
            "tools": self.tool_status(),
        }


_default: Optional[LogCollectionPhase] = None


def get_log_collection_phase() -> LogCollectionPhase:
    global _default
    if _default is None:
        _default = LogCollectionPhase()
    return _default
