# -*- coding: utf-8 -*-
"""
asset_management.discovery - 资产发现器

功能：
    - 主动发现模拟（IP 段扫描 / 端口扫描 / 服务识别 / 操作系统识别）
    - 被动发现模拟（流量分析 / 日志分析 / ARP 表 / DHCP 日志 / DNS 日志）
    - 发现任务管理、结果分页筛选、导入 assets 表、自动合并去重

数据库表：
    - am_discovery_tasks   资产发现任务表
    - am_discovery_results  发现结果表

注意：本模块仅生成模拟发现数据，不执行真实网络扫描。
"""

from __future__ import annotations

import ipaddress
import json
import random
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.database import db
from utils.logger import log

# 支持的资产类型
ASSET_TYPES = [
    "server", "workstation", "network_device", "security_device",
    "mobile_device", "iot_device", "cloud_asset", "container", "unknown",
]

# 常用端口 -> (服务名, 默认banner指纹)
_COMMON_PORTS: Dict[int, Dict[str, str]] = {
    21: {"service": "ftp", "banner": "vsftpd 3.0.3"},
    22: {"service": "ssh", "banner": "OpenSSH_8.2p1"},
    23: {"service": "telnet", "banner": "Linux telnetd"},
    25: {"service": "smtp", "banner": "Postfix smtpd"},
    53: {"service": "dns", "banner": "BIND 9.11"},
    80: {"service": "http", "banner": "nginx/1.18.0"},
    110: {"service": "pop3", "banner": "Dovecot pop3d"},
    111: {"service": "rpcbind", "banner": "rpcbind"},
    135: {"service": "msrpc", "banner": "Microsoft Windows RPC"},
    139: {"service": "netbios", "banner": "Samba smbd"},
    143: {"service": "imap", "banner": "Dovecot imapd"},
    443: {"service": "https", "banner": "nginx/1.18.0"},
    445: {"service": "smb", "banner": "Samba smbd 4.9"},
    465: {"service": "smtps", "banner": "Postfix smtpd"},
    587: {"service": "submission", "banner": "Postfix smtpd"},
    993: {"service": "imaps", "banner": "Dovecot imapd"},
    995: {"service": "pop3s", "banner": "Dovecot pop3d"},
    1433: {"service": "mssql", "banner": "Microsoft SQL Server"},
    1521: {"service": "oracle", "banner": "Oracle TNS listener"},
    2049: {"service": "nfs", "banner": "NFS v3"},
    2375: {"service": "docker", "banner": "Docker API"},
    2376: {"service": "docker-tls", "banner": "Docker API TLS"},
    3306: {"service": "mysql", "banner": "MySQL 8.0.28"},
    3389: {"service": "rdp", "banner": "Microsoft Terminal Service"},
    5432: {"service": "postgresql", "banner": "PostgreSQL 13.5"},
    5900: {"service": "vnc", "banner": "VNC server"},
    6379: {"service": "redis", "banner": "Redis 6.2.6"},
    8080: {"service": "http-proxy", "banner": "Apache Tomcat 9.0"},
    8443: {"service": "https-alt", "banner": "nginx/1.18.0"},
    9000: {"service": "php-fpm", "banner": "PHP-FPM"},
    9200: {"service": "elasticsearch", "banner": "Elasticsearch 7.10"},
    11211: {"service": "memcached", "banner": "memcached 1.6"},
    27017: {"service": "mongodb", "banner": "MongoDB 4.4"},
}

_OS_POOL = [
    ("Linux", "Linux 5.4 (Ubuntu 20.04)"), ("Linux", "Linux 4.19 (CentOS 7)"),
    ("Linux", "Linux 5.15 (Debian 11)"), ("Windows", "Windows Server 2019"),
    ("Windows", "Windows 10 21H2"), ("Windows", "Windows Server 2022"),
    ("Network", "Cisco IOS 15.7"), ("Network", "Huawei VRP V8"),
    ("Network", "Juniper Junos 21.4"), ("Embedded", "VxWorks 7"),
]

_HOSTNAME_PREFIX = ["srv", "app", "db", "web", "cache", "gw", "fw", "nas", "node", "edge"]


def _now() -> str:
    """返回当前 ISO 时间字符串"""
    return datetime.now().isoformat()


def _ensure_assets_table() -> None:
    """确保 assets 表存在并具备资产管理所需的列（幂等）。"""
    conn = db._get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                ip TEXT,
                domain TEXT,
                asset_type TEXT DEFAULT 'unknown',
                fingerprint TEXT,
                first_seen TEXT,
                last_scanned TEXT,
                tenant_id TEXT,
                risk_score REAL DEFAULT 0,
                owner TEXT,
                importance TEXT DEFAULT 'medium',
                exposure_level TEXT DEFAULT 'internal',
                data_sensitivity TEXT DEFAULT 'internal',
                business_impact TEXT DEFAULT 'low',
                department TEXT,
                location TEXT,
                open_ports_count INTEGER DEFAULT 0,
                name TEXT,
                status TEXT DEFAULT 'active',
                tags TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        conn.commit()
    except Exception as e:  # pragma: no cover
        log.warning(f"创建 assets 表失败（可能已存在）: {e}")
    finally:
        conn.close()


class DiscoveryManager:
    """资产发现管理器"""

    def __init__(self) -> None:
        """初始化发现器并建表。"""
        self._ensure_tables()
        _ensure_assets_table()

    # ------------------------------------------------------------------ #
    # 表结构初始化
    # ------------------------------------------------------------------ #
    def _ensure_tables(self) -> None:
        """创建资产发现相关数据表。"""
        conn = db._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS am_discovery_tasks (
                    id TEXT PRIMARY KEY,
                    task_name TEXT NOT NULL,
                    target_ranges TEXT,
                    discovery_type TEXT DEFAULT 'active',
                    status TEXT DEFAULT 'pending',
                    started_at TEXT,
                    completed_at TEXT,
                    results_count INTEGER DEFAULT 0,
                    error TEXT,
                    created_at TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS am_discovery_results (
                    id TEXT PRIMARY KEY,
                    task_id TEXT,
                    ip TEXT,
                    mac TEXT,
                    hostname TEXT,
                    os TEXT,
                    open_ports TEXT,
                    services TEXT,
                    asset_type TEXT DEFAULT 'unknown',
                    confidence REAL DEFAULT 0.8,
                    fingerprint TEXT,
                    discovered_at TEXT
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_am_dr_task ON am_discovery_results(task_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_am_dr_ip ON am_discovery_results(ip)")
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"创建资产发现表失败: {e}")
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 目标解析
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse_targets(target_ranges: List[str]) -> List[str]:
        """将 IP 段/CIDR/范围/域名列表解析为待探测目标 IP 列表（模拟）。"""
        ips: List[str] = []
        for item in target_ranges or []:
            item = str(item).strip()
            if not item:
                continue
            # CIDR
            if "/" in item:
                try:
                    net = ipaddress.ip_network(item, strict=False)
                    hosts = [str(h) for h in net.hosts()]
                    # 模拟大网段只抽样，避免结果爆炸
                    sample = hosts if len(hosts) <= 32 else random.sample(hosts, 32)
                    ips.extend(sample)
                    continue
                except Exception:
                    pass
            # 范围 192.168.1.1-192.168.1.10
            if "-" in item and item.count(".") >= 3:
                try:
                    start_s, end_s = item.split("-", 1)
                    start = ipaddress.IPv4Address(start_s.strip())
                    prefix = ".".join(start_s.strip().split(".")[:3])
                    end_last = int(end_s.strip().split(".")[-1])
                    for last in range(int(str(start).split(".")[-1]), end_last + 1):
                        ips.append(f"{prefix}.{last}")
                    continue
                except Exception:
                    pass
            # 单 IP 或域名
            ips.append(item)
        # 去重并限制数量
        seen, uniq = set(), []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                uniq.append(ip)
        return uniq[:64]

    # ------------------------------------------------------------------ #
    # 任务管理
    # ------------------------------------------------------------------ #
    def start_discovery(self, task_name: str, target_ranges: List[str],
                        discovery_type: str = "active",
                        tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """创建并启动一次资产发现任务（模拟执行，立即生成结果）。"""
        task_id = f"am-disc-{uuid.uuid4().hex[:12]}"
        now = _now()
        if discovery_type not in ("active", "passive"):
            discovery_type = "active"
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO am_discovery_tasks
                    (id, task_name, target_ranges, discovery_type, status,
                     started_at, completed_at, results_count, error, created_at)
                VALUES (?, ?, ?, ?, 'running', ?, NULL, 0, NULL, ?)
            """, (task_id, task_name, json.dumps(target_ranges, ensure_ascii=False),
                  discovery_type, now, now))
            conn.commit()
        except Exception as e:
            log.error(f"创建发现任务失败: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

        # 执行模拟发现
        try:
            if discovery_type == "passive":
                results = self.passive_discovery_simulate(target_ranges, task_id)
            else:
                results = self.active_scan_simulate(target_ranges, task_id)
            self._save_results(task_id, results)
            self._update_task_status(task_id, "completed", results_count=len(results))
            return {"success": True, "task_id": task_id,
                    "discovery_type": discovery_type, "results_count": len(results)}
        except Exception as e:
            log.exception("执行资产发现失败")
            self._update_task_status(task_id, "failed", error=str(e))
            return {"success": False, "task_id": task_id, "error": str(e)}

    def _update_task_status(self, task_id: str, status: str,
                            results_count: int = 0, error: Optional[str] = None) -> None:
        """更新发现任务状态。"""
        conn = db._get_connection()
        try:
            if status in ("completed", "failed"):
                conn.execute("""
                    UPDATE am_discovery_tasks
                    SET status=?, completed_at=?, results_count=?, error=?
                    WHERE id=?
                """, (status, _now(), results_count, error, task_id))
            else:
                conn.execute("UPDATE am_discovery_tasks SET status=? WHERE id=?",
                             (status, task_id))
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"更新发现任务状态失败: {e}")
        finally:
            conn.close()

    def get_discovery_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """获取发现任务状态。"""
        conn = db._get_connection()
        try:
            row = conn.execute("SELECT * FROM am_discovery_tasks WHERE id=?",
                               (task_id,)).fetchone()
            if not row:
                return None
            task = dict(row)
            if task.get("target_ranges"):
                task["target_ranges"] = json.loads(task["target_ranges"])
            return task
        finally:
            conn.close()

    def list_tasks(self, page: int = 1, page_size: int = 20,
                   status: Optional[str] = None) -> Dict[str, Any]:
        """列出发现任务（分页）。"""
        conn = db._get_connection()
        try:
            where, params = " WHERE 1=1 ", []
            if status:
                where += " AND status=?"
                params.append(status)
            total = conn.execute(
                f"SELECT COUNT(*) FROM am_discovery_tasks {where}", params).fetchone()[0]
            start = (max(1, page) - 1) * max(1, page_size)
            rows = conn.execute(
                f"SELECT * FROM am_discovery_tasks {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                params + [page_size, start]).fetchall()
            items = []
            for r in rows:
                d = dict(r)
                if d.get("target_ranges"):
                    d["target_ranges"] = json.loads(d["target_ranges"])
                items.append(d)
            return {"total": total, "page": page, "page_size": page_size, "items": items}
        finally:
            conn.close()

    def get_discovery_results(self, task_id: str, page: int = 1,
                              page_size: int = 20,
                              asset_type: Optional[str] = None,
                              keyword: Optional[str] = None) -> Dict[str, Any]:
        """获取发现结果（分页 + 筛选）。"""
        conn = db._get_connection()
        try:
            where, params = " WHERE task_id=? ", [task_id]
            if asset_type:
                where += " AND asset_type=?"
                params.append(asset_type)
            if keyword:
                where += " AND (ip LIKE ? OR hostname LIKE ? OR os LIKE ?)"
                like = f"%{keyword}%"
                params.extend([like, like, like])
            total = conn.execute(
                f"SELECT COUNT(*) FROM am_discovery_results {where}", params).fetchone()[0]
            start = (max(1, page) - 1) * max(1, page_size)
            rows = conn.execute(
                f"SELECT * FROM am_discovery_results {where} ORDER BY confidence DESC LIMIT ? OFFSET ?",
                params + [page_size, start]).fetchall()
            items = []
            for r in rows:
                d = dict(r)
                for jf in ("open_ports", "services", "fingerprint"):
                    if d.get(jf):
                        try:
                            d[jf] = json.loads(d[jf])
                        except Exception:
                            pass
                items.append(d)
            return {"total": total, "page": page, "page_size": page_size, "items": items}
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 模拟发现
    # ------------------------------------------------------------------ #
    def _synthesize_host(self, ip: str, source: str) -> Dict[str, Any]:
        """根据 IP 合成一个模拟主机结果。"""
        # 随机决定开放端口数量
        n_ports = random.randint(1, 8)
        ports = random.sample(list(_COMMON_PORTS.keys()), min(n_ports, len(_COMMON_PORTS)))
        open_ports = []
        services = []
        for p in sorted(ports):
            info = _COMMON_PORTS[p]
            open_ports.append(p)
            services.append({"port": p, "service": info["service"],
                             "banner": info["banner"]})
        os_name, os_detail = random.choice(_OS_POOL)
        # 根据端口组合推断资产类型
        asset_type = self._infer_asset_type(open_ports, services, os_name)
        hostname = f"{random.choice(_HOSTNAME_PREFIX)}-{random.randint(1, 40)}.local"
        mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(
            random.randint(0, 255) for _ in range(5))
        return {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "os": os_detail,
            "open_ports": open_ports,
            "services": services,
            "asset_type": asset_type,
            "confidence": round(random.uniform(0.7, 0.99), 2),
            "fingerprint": {
                "os_family": os_name,
                "source": source,
                "services": [s["service"] for s in services],
            },
        }

    @staticmethod
    def _infer_asset_type(open_ports: List[int], services: List[Dict[str, str]],
                          os_family: str) -> str:
        """根据端口/服务/操作系统推断资产类型。"""
        svc_names = {s["service"] for s in services}
        if 2375 in open_ports or 2376 in open_ports:
            return "container"
        if any(p in open_ports for p in (1433, 3306, 5432, 6379, 9200, 27017)):
            return "server"
        if "network_device" in ("network_device",) and any(
                p in open_ports for p in (53, 161, 179)):
            return "network_device"
        if os_family == "Embedded":
            return "iot_device"
        if os_family == "Network":
            return "network_device"
        if os_family == "Windows" and 3389 in open_ports:
            return "workstation"
        if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
            return "server"
        return "unknown"

    def active_scan_simulate(self, target_ranges: List[str],
                             task_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """主动发现模拟：IP 段扫描/端口扫描/服务识别/操作系统识别。"""
        targets = self._parse_targets(target_ranges)
        results = []
        for ip in targets:
            # 主动探测有一定存活率
            if not self._is_ip(ip) and not ip.endswith(".local"):
                # 域名类目标也生成一条
                results.append(self._synthesize_host(ip, "active"))
                continue
            if random.random() < 0.75:  # 75% 主机存活
                results.append(self._synthesize_host(ip, "active"))
        return results

    def passive_discovery_simulate(self, target_ranges: List[str],
                                   task_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """被动发现模拟：流量/日志/ARP/DHCP/DNS 日志分析。"""
        targets = self._parse_targets(target_ranges)
        sources = ["traffic_analysis", "arp_table", "dhcp_log", "dns_log", "flow_log"]
        results = []
        for ip in targets:
            if random.random() < 0.6:  # 被动发现命中率略低
                host = self._synthesize_host(ip, random.choice(sources))
                host["confidence"] = round(min(host["confidence"], 0.85), 2)
                results.append(host)
        return results

    @staticmethod
    def _is_ip(s: str) -> bool:
        try:
            ipaddress.IPv4Address(s)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    # 结果落库与导入
    # ------------------------------------------------------------------ #
    def _save_results(self, task_id: str, results: List[Dict[str, Any]]) -> None:
        """将发现结果批量写入 am_discovery_results。"""
        conn = db._get_connection()
        try:
            for r in results:
                conn.execute("""
                    INSERT INTO am_discovery_results
                        (id, task_id, ip, mac, hostname, os, open_ports, services,
                         asset_type, confidence, fingerprint, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f"am-dr-{uuid.uuid4().hex[:12]}", task_id, r.get("ip"), r.get("mac"),
                    r.get("hostname"), r.get("os"),
                    json.dumps(r.get("open_ports", []), ensure_ascii=False),
                    json.dumps(r.get("services", []), ensure_ascii=False),
                    r.get("asset_type", "unknown"), r.get("confidence", 0.8),
                    json.dumps(r.get("fingerprint", {}), ensure_ascii=False), _now(),
                ))
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"保存发现结果失败: {e}")
        finally:
            conn.close()

    def merge_assets(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """同一资产的多个发现结果自动合并（基于 IP/MAC/主机名）。"""
        merged: Dict[str, Dict[str, Any]] = {}
        for r in results:
            key = r.get("ip") or r.get("mac") or r.get("hostname")
            if not key:
                continue
            if key not in merged:
                merged[key] = dict(r)
            else:
                existing = merged[key]
                # 合并端口与服务
                exist_ports = set(existing.get("open_ports", []))
                new_ports = set(r.get("open_ports", []))
                existing["open_ports"] = sorted(exist_ports | new_ports)
                # 服务合并（按端口去重）
                svc_map = {s["port"]: s for s in existing.get("services", [])}
                for s in r.get("services", []):
                    svc_map[s["port"]] = s
                existing["services"] = list(svc_map.values())
                existing["confidence"] = round(
                    max(existing.get("confidence", 0), r.get("confidence", 0)), 2)
                if not existing.get("mac") and r.get("mac"):
                    existing["mac"] = r["mac"]
                if not existing.get("os") and r.get("os"):
                    existing["os"] = r["os"]
        return list(merged.values())

    def deduplicate_assets(self) -> int:
        """对 assets 表按 IP/MAC/主机名去重，返回删除的重复条数。"""
        conn = db._get_connection()
        removed = 0
        try:
            # 按 IP 分组，保留最早出现的一条
            rows = conn.execute("""
                SELECT ip, MIN(rowid) AS keep_row
                FROM assets
                WHERE ip IS NOT NULL AND ip != ''
                GROUP BY ip
            """).fetchall()
            for r in rows:
                keep = r["keep_row"]
                cur = conn.execute("""
                    DELETE FROM assets WHERE rowid != ? AND ip = ?
                """, (keep, r["ip"]))
                removed += cur.rowcount
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"资产去重失败: {e}")
        finally:
            conn.close()
        return removed

    def import_discovered_assets(self, task_id: str,
                                tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """将发现结果导入 assets 表，自动合并去重。"""
        results = self.get_discovery_results(task_id, page=1, page_size=100000)
        items = results.get("items", [])
        merged = self.merge_assets(items)
        conn = db._get_connection()
        imported, updated = 0, 0
        now = _now()
        try:
            for r in merged:
                ip = r.get("ip")
                if not ip:
                    continue
                # 查找是否已存在同 IP 资产
                existing = conn.execute(
                    "SELECT id, open_ports_count FROM assets WHERE ip=?", (ip,)).fetchone()
                ports = r.get("open_ports", [])
                if existing:
                    conn.execute("""
                        UPDATE assets SET asset_type=?, last_scanned=?, risk_score=?,
                                          fingerprint=?, open_ports_count=?, updated_at=?
                        WHERE id=?
                    """, (r.get("asset_type", "unknown"), now, 0,
                          json.dumps(r.get("fingerprint", {}), ensure_ascii=False),
                          len(ports), now, existing["id"]))
                    updated += 1
                else:
                    conn.execute("""
                        INSERT INTO assets
                            (id, ip, domain, asset_type, fingerprint, first_seen,
                             last_scanned, tenant_id, risk_score, owner, importance,
                             open_ports_count, name, status, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        f"am-asset-{uuid.uuid4().hex[:12]}", ip, r.get("hostname"),
                        r.get("asset_type", "unknown"),
                        json.dumps(r.get("fingerprint", {}), ensure_ascii=False),
                        now, now, tenant_id, 0, None, "medium", len(ports),
                        r.get("hostname"), "active", now, now,
                    ))
                    imported += 1
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"导入发现资产失败: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()
        return {"success": True, "imported": imported, "updated": updated,
                "merged": len(merged), "task_id": task_id}


# 全局单例
discovery_manager = DiscoveryManager()
