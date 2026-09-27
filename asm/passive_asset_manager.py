"""
被动资产积累模块
- 历史数据存储（每次扫描结果持久化）
- 趋势分析（资产/漏洞/端口变化趋势）
- 变更追踪（新发现/消失/变化的资产和服务）
- 资产画像（基于历史数据构建）
- 变更告警
"""

import json
import os
import time
import sqlite3
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class AssetRecord:
    """资产记录"""
    asset_id: str
    target: str
    ip: str
    scan_time: float
    open_ports: List[int] = field(default_factory=list)
    services: Dict[str, str] = field(default_factory=dict)
    vulnerabilities: List[Dict] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    raw_data: Optional[Dict] = None


@dataclass
class ChangeEvent:
    """变更事件"""
    change_id: str
    asset_id: str
    target: str
    change_type: str  # new_asset, disappeared_asset, new_port, closed_port, service_changed, new_vuln, fixed_vuln, tech_changed
    severity: str  # info, low, medium, high, critical
    description: str
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    detected_at: float = field(default_factory=time.time)


class PassiveAssetManager:
    """被动资产管理器"""

    def __init__(self, db_path: str = ""):
        if not db_path:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(project_root, "data", "passive_assets.db")

        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_database()

    def _init_database(self):
        """初始化数据库"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 扫描记录表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE,
                target TEXT,
                scan_type TEXT,
                scan_time REAL,
                duration REAL,
                status TEXT,
                result_json TEXT
            )
        """)

        # 资产表（当前状态）
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT UNIQUE,
                target TEXT,
                ip TEXT,
                first_seen REAL,
                last_seen REAL,
                scan_count INTEGER DEFAULT 0,
                open_ports TEXT,
                services TEXT,
                tech_stack TEXT,
                current_vulns TEXT,
                status TEXT DEFAULT 'active'
            )
        """)

        # 资产历史表（每次扫描的快照）
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS asset_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT,
                scan_id TEXT,
                scan_time REAL,
                open_ports TEXT,
                services TEXT,
                tech_stack TEXT,
                vulnerabilities TEXT,
                FOREIGN KEY (asset_id) REFERENCES assets (asset_id)
            )
        """)

        # 变更事件表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                change_id TEXT UNIQUE,
                asset_id TEXT,
                target TEXT,
                change_type TEXT,
                severity TEXT,
                description TEXT,
                old_value TEXT,
                new_value TEXT,
                detected_at REAL
            )
        """)

        # 漏洞历史表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_key TEXT,
                asset_id TEXT,
                target TEXT,
                vuln_name TEXT,
                severity TEXT,
                category TEXT,
                first_seen REAL,
                last_seen REAL,
                status TEXT DEFAULT 'open',
                occurrence_count INTEGER DEFAULT 1
            )
        """)

        # 创建索引
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(scan_time)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_history_asset ON asset_history(asset_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_history_time ON asset_history(scan_time)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_changes_asset ON changes(asset_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_changes_time ON changes(detected_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_asset ON vulnerability_history(asset_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerability_history(status)")

        conn.commit()
        conn.close()

    def record_scan(self, target: str, scan_type: str, result: Dict, duration: float = 0) -> str:
        """记录一次扫描结果"""
        scan_id = f"scan_{int(time.time())}_{abs(hash(target + scan_type)) % 10000}"
        scan_time = time.time()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT OR REPLACE INTO scans (scan_id, target, scan_type, scan_time, duration, status, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, target, scan_type, scan_time, duration,
                "completed" if result.get("success", True) else "failed",
                json.dumps(result, ensure_ascii=False, default=str)
            ))

            # 更新资产信息
            self._update_asset(conn, target, result, scan_id, scan_time)

            # 检测变更
            changes = self._detect_changes(conn, target, result)
            for change in changes:
                cursor.execute("""
                    INSERT OR IGNORE INTO changes (change_id, asset_id, target, change_type, severity, description, old_value, new_value, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    change["change_id"], change["asset_id"], target,
                    change["change_type"], change["severity"], change["description"],
                    json.dumps(change.get("old_value"), ensure_ascii=False, default=str),
                    json.dumps(change.get("new_value"), ensure_ascii=False, default=str),
                    change["detected_at"]
                ))

            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

        return scan_id

    def _update_asset(self, conn: sqlite3.Connection, target: str, result: Dict, scan_id: str, scan_time: float):
        """更新资产信息"""
        cursor = conn.cursor()
        asset_id = f"asset_{abs(hash(target)) % 1000000}"

        # 提取资产信息
        open_ports = result.get("open_ports", result.get("ports", []))
        if isinstance(open_ports, list) and open_ports and isinstance(open_ports[0], dict):
            open_ports = [p.get("port", p.get("port_number", 0)) for p in open_ports]

        services = result.get("services", {})
        tech_stack = result.get("tech_stack", result.get("technologies", []))
        vulnerabilities = result.get("vulnerabilities", result.get("vulns", []))

        # 检查资产是否存在
        cursor.execute("SELECT asset_id, scan_count FROM assets WHERE asset_id = ?", (asset_id,))
        existing = cursor.fetchone()

        if existing:
            # 更新现有资产
            cursor.execute("""
                UPDATE assets SET
                    last_seen = ?,
                    scan_count = scan_count + 1,
                    open_ports = ?,
                    services = ?,
                    tech_stack = ?,
                    current_vulns = ?,
                    status = 'active'
                WHERE asset_id = ?
            """, (
                scan_time,
                json.dumps(open_ports),
                json.dumps(services, ensure_ascii=False),
                json.dumps(tech_stack, ensure_ascii=False),
                json.dumps(vulnerabilities, ensure_ascii=False, default=str),
                asset_id
            ))
        else:
            # 创建新资产
            cursor.execute("""
                INSERT INTO assets (asset_id, target, ip, first_seen, last_seen, scan_count, open_ports, services, tech_stack, current_vulns, status)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 'active')
            """, (
                asset_id, target, result.get("ip", target),
                scan_time, scan_time,
                json.dumps(open_ports),
                json.dumps(services, ensure_ascii=False),
                json.dumps(tech_stack, ensure_ascii=False),
                json.dumps(vulnerabilities, ensure_ascii=False, default=str),
            ))

        # 记录历史快照
        cursor.execute("""
            INSERT INTO asset_history (asset_id, scan_id, scan_time, open_ports, services, tech_stack, vulnerabilities)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            asset_id, scan_id, scan_time,
            json.dumps(open_ports),
            json.dumps(services, ensure_ascii=False),
            json.dumps(tech_stack, ensure_ascii=False),
            json.dumps(vulnerabilities, ensure_ascii=False, default=str),
        ))

        # 更新漏洞历史
        self._update_vulnerability_history(conn, asset_id, target, vulnerabilities, scan_time)

    def _update_vulnerability_history(self, conn: sqlite3.Connection, asset_id: str, target: str, vulnerabilities: List[Dict], scan_time: float):
        """更新漏洞历史"""
        cursor = conn.cursor()

        current_vuln_keys = set()
        for vuln in vulnerabilities:
            vuln_name = vuln.get("name", vuln.get("template_name", "未知"))
            vuln_key = f"{asset_id}_{vuln_name}"
            current_vuln_keys.add(vuln_key)

            cursor.execute("SELECT id, occurrence_count FROM vulnerability_history WHERE vuln_key = ?", (vuln_key,))
            existing = cursor.fetchone()

            if existing:
                cursor.execute("""
                    UPDATE vulnerability_history SET
                        last_seen = ?,
                        status = 'open',
                        occurrence_count = occurrence_count + 1
                    WHERE vuln_key = ?
                """, (scan_time, vuln_key))
            else:
                cursor.execute("""
                    INSERT INTO vulnerability_history (vuln_key, asset_id, target, vuln_name, severity, category, first_seen, last_seen, status, occurrence_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', 1)
                """, (
                    vuln_key, asset_id, target, vuln_name,
                    vuln.get("severity", "medium"),
                    vuln.get("category", "其他"),
                    scan_time, scan_time,
                ))

        # 标记未出现的漏洞为已修复
        if current_vuln_keys:
            placeholders = ",".join(["?"] * len(current_vuln_keys))
            cursor.execute(f"""
                UPDATE vulnerability_history SET status = 'fixed'
                WHERE asset_id = ? AND status = 'open' AND vuln_key NOT IN ({placeholders})
            """, [asset_id] + list(current_vuln_keys))

    def _detect_changes(self, conn: sqlite3.Connection, target: str, result: Dict) -> List[Dict]:
        """检测变更"""
        changes = []
        asset_id = f"asset_{abs(hash(target)) % 1000000}"
        now = time.time()

        cursor = conn.cursor()

        # 获取上一次扫描的资产状态
        cursor.execute("""
            SELECT open_ports, services, tech_stack, vulnerabilities FROM asset_history
            WHERE asset_id = ? ORDER BY scan_time DESC LIMIT 1 OFFSET 1
        """, (asset_id,))
        previous = cursor.fetchone()

        if not previous:
            # 第一次扫描，记录新资产
            changes.append({
                "change_id": f"change_{int(now)}_new_asset",
                "asset_id": asset_id,
                "change_type": "new_asset",
                "severity": "info",
                "description": f"发现新资产: {target}",
                "old_value": None,
                "new_value": target,
                "detected_at": now,
            })
            return changes

        prev_ports = set(json.loads(previous[0]) or [])
        prev_services = json.loads(previous[1]) or {}
        prev_tech = set(json.loads(previous[2]) or [])
        prev_vulns = json.loads(previous[3]) or []

        # 当前状态
        curr_ports = set(result.get("open_ports", result.get("ports", [])))
        if curr_ports and isinstance(list(curr_ports)[0], dict):
            curr_ports = set(p.get("port", 0) for p in curr_ports)

        curr_services = result.get("services", {})
        curr_tech = set(result.get("tech_stack", result.get("technologies", [])))
        curr_vulns = result.get("vulnerabilities", result.get("vulns", []))

        # 新开放端口
        new_ports = curr_ports - prev_ports
        for port in new_ports:
            changes.append({
                "change_id": f"change_{int(now)}_new_port_{port}",
                "asset_id": asset_id,
                "change_type": "new_port",
                "severity": "medium",
                "description": f"新开放端口: {port}",
                "old_value": None,
                "new_value": port,
                "detected_at": now,
            })

        # 关闭端口
        closed_ports = prev_ports - curr_ports
        for port in closed_ports:
            changes.append({
                "change_id": f"change_{int(now)}_closed_port_{port}",
                "asset_id": asset_id,
                "change_type": "closed_port",
                "severity": "info",
                "description": f"端口关闭: {port}",
                "old_value": port,
                "new_value": None,
                "detected_at": now,
            })

        # 服务变化
        for port, service in curr_services.items():
            if port in prev_services and prev_services[port] != service:
                changes.append({
                    "change_id": f"change_{int(now)}_service_{port}",
                    "asset_id": asset_id,
                    "change_type": "service_changed",
                    "severity": "low",
                    "description": f"端口{port}服务变化: {prev_services[port]} -> {service}",
                    "old_value": prev_services[port],
                    "new_value": service,
                    "detected_at": now,
                })

        # 新技术栈
        new_tech = curr_tech - prev_tech
        if new_tech:
            changes.append({
                "change_id": f"change_{int(now)}_new_tech",
                "asset_id": asset_id,
                "change_type": "tech_changed",
                "severity": "info",
                "description": f"新技术栈: {', '.join(new_tech)}",
                "old_value": list(prev_tech),
                "new_value": list(curr_tech),
                "detected_at": now,
            })

        # 新漏洞
        prev_vuln_names = set(v.get("name", v.get("template_name", "")) for v in prev_vulns)
        curr_vuln_names = set(v.get("name", v.get("template_name", "")) for v in curr_vulns)
        new_vulns = curr_vuln_names - prev_vuln_names

        for vuln_name in new_vulns:
            vuln_info = next((v for v in curr_vulns if v.get("name", v.get("template_name")) == vuln_name), {})
            severity = vuln_info.get("severity", "medium")
            changes.append({
                "change_id": f"change_{int(now)}_new_vuln_{abs(hash(vuln_name)) % 10000}",
                "asset_id": asset_id,
                "change_type": "new_vuln",
                "severity": severity,
                "description": f"新发现漏洞: {vuln_name} ({severity})",
                "old_value": None,
                "new_value": vuln_name,
                "detected_at": now,
            })

        # 已修复漏洞
        fixed_vulns = prev_vuln_names - curr_vuln_names
        for vuln_name in fixed_vulns:
            changes.append({
                "change_id": f"change_{int(now)}_fixed_vuln_{abs(hash(vuln_name)) % 10000}",
                "asset_id": asset_id,
                "change_type": "fixed_vuln",
                "severity": "info",
                "description": f"漏洞已修复: {vuln_name}",
                "old_value": vuln_name,
                "new_value": None,
                "detected_at": now,
            })

        return changes

    def get_asset_profile(self, target: str) -> Dict[str, Any]:
        """获取资产画像（基于历史数据）"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        asset_id = f"asset_{abs(hash(target)) % 1000000}"

        # 基本信息
        cursor.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,))
        asset = cursor.fetchone()

        if not asset:
            conn.close()
            return {"error": f"资产 {target} 不存在"}

        # 扫描历史
        cursor.execute("""
            SELECT scan_time, open_ports, vulnerabilities FROM asset_history
            WHERE asset_id = ? ORDER BY scan_time DESC LIMIT 30
        """, (asset_id,))
        history = cursor.fetchall()

        # 变更历史
        cursor.execute("""
            SELECT change_type, severity, description, detected_at FROM changes
            WHERE asset_id = ? ORDER BY detected_at DESC LIMIT 20
        """, (asset_id,))
        changes = cursor.fetchall()

        # 漏洞统计
        cursor.execute("""
            SELECT severity, COUNT(*) as count FROM vulnerability_history
            WHERE asset_id = ? AND status = 'open' GROUP BY severity
        """, (asset_id,))
        vuln_stats = cursor.fetchall()

        # 端口趋势（最近10次扫描）
        cursor.execute("""
            SELECT scan_time, open_ports FROM asset_history
            WHERE asset_id = ? ORDER BY scan_time DESC LIMIT 10
        """, (asset_id,))
        port_trend = cursor.fetchall()

        conn.close()

        # 构建资产画像
        profile = {
            "target": target,
            "ip": asset["ip"],
            "first_seen": datetime.fromtimestamp(asset["first_seen"]).strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": datetime.fromtimestamp(asset["last_seen"]).strftime("%Y-%m-%d %H:%M:%S"),
            "scan_count": asset["scan_count"],
            "status": asset["status"],
            "current_open_ports": json.loads(asset["open_ports"] or "[]"),
            "current_services": json.loads(asset["services"] or "{}"),
            "current_tech_stack": json.loads(asset["tech_stack"] or "[]"),
            "current_vulnerabilities": json.loads(asset["current_vulns"] or "[]"),
            "vulnerability_statistics": {row["severity"]: row["count"] for row in vuln_stats},
            "recent_changes": [
                {
                    "type": row["change_type"],
                    "severity": row["severity"],
                    "description": row["description"],
                    "time": datetime.fromtimestamp(row["detected_at"]).strftime("%Y-%m-%d %H:%M:%S"),
                }
                for row in changes
            ],
            "port_trend": [
                {
                    "scan_time": datetime.fromtimestamp(row["scan_time"]).strftime("%m-%d %H:%M"),
                    "port_count": len(json.loads(row["open_ports"] or "[]")),
                    "ports": json.loads(row["open_ports"] or "[]"),
                }
                for row in reversed(list(port_trend))
            ],
            "scan_history_count": len(history),
        }

        return profile

    def get_trend_analysis(self, target: str, days: int = 30) -> Dict[str, Any]:
        """趋势分析"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        asset_id = f"asset_{abs(hash(target)) % 1000000}"
        since = time.time() - days * 86400

        # 扫描趋势
        cursor.execute("""
            SELECT DATE(scan_time, 'unixepoch', 'localtime') as date, COUNT(*) as count
            FROM scans WHERE target = ? AND scan_time > ?
            GROUP BY date ORDER BY date
        """, (target, since))
        scan_trend = cursor.fetchall()

        # 端口数量趋势
        cursor.execute("""
            SELECT scan_time, open_ports FROM asset_history
            WHERE asset_id = ? AND scan_time > ? ORDER BY scan_time
        """, (asset_id, since))
        port_history = cursor.fetchall()

        # 漏洞数量趋势
        cursor.execute("""
            SELECT scan_time, vulnerabilities FROM asset_history
            WHERE asset_id = ? AND scan_time > ? ORDER BY scan_time
        """, (asset_id, since))
        vuln_history = cursor.fetchall()

        # 变更统计
        cursor.execute("""
            SELECT change_type, COUNT(*) as count FROM changes
            WHERE asset_id = ? AND detected_at > ? GROUP BY change_type
        """, (asset_id, since))
        change_stats = cursor.fetchall()

        conn.close()

        return {
            "target": target,
            "period_days": days,
            "scan_trend": [{"date": row["date"], "count": row["count"]} for row in scan_trend],
            "port_count_trend": [
                {
                    "time": datetime.fromtimestamp(row["scan_time"]).strftime("%m-%d %H:%M"),
                    "port_count": len(json.loads(row["open_ports"] or "[]")),
                }
                for row in port_history
            ],
            "vulnerability_count_trend": [
                {
                    "time": datetime.fromtimestamp(row["scan_time"]).strftime("%m-%d %H:%M"),
                    "vuln_count": len(json.loads(row["vulnerabilities"] or "[]")),
                }
                for row in vuln_history
            ],
            "change_statistics": {row["change_type"]: row["count"] for row in change_stats},
        }

    def get_all_assets(self) -> List[Dict]:
        """获取所有资产列表"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT asset_id, target, ip, first_seen, last_seen, scan_count, status,
                   open_ports, current_vulns
            FROM assets ORDER BY last_seen DESC
        """)
        assets = cursor.fetchall()
        conn.close()

        return [
            {
                "asset_id": row["asset_id"],
                "target": row["target"],
                "ip": row["ip"],
                "first_seen": datetime.fromtimestamp(row["first_seen"]).strftime("%Y-%m-%d %H:%M"),
                "last_seen": datetime.fromtimestamp(row["last_seen"]).strftime("%Y-%m-%d %H:%M"),
                "scan_count": row["scan_count"],
                "status": row["status"],
                "open_port_count": len(json.loads(row["open_ports"] or "[]")),
                "vulnerability_count": len(json.loads(row["current_vulns"] or "[]")),
            }
            for row in assets
        ]

    def get_recent_changes(self, limit: int = 50) -> List[Dict]:
        """获取最近的变更事件"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT change_id, target, change_type, severity, description, detected_at
            FROM changes ORDER BY detected_at DESC LIMIT ?
        """, (limit,))
        changes = cursor.fetchall()
        conn.close()

        return [
            {
                "change_id": row["change_id"],
                "target": row["target"],
                "change_type": row["change_type"],
                "severity": row["severity"],
                "description": row["description"],
                "time": datetime.fromtimestamp(row["detected_at"]).strftime("%Y-%m-%d %H:%M:%S"),
            }
            for row in changes
        ]

    def get_statistics(self) -> Dict[str, Any]:
        """获取全局统计"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM assets")
        total_assets = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM assets WHERE status = 'active'")
        active_assets = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM changes")
        total_changes = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM vulnerability_history WHERE status = 'open'")
        open_vulns = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM vulnerability_history WHERE status = 'fixed'")
        fixed_vulns = cursor.fetchone()[0]

        cursor.execute("SELECT severity, COUNT(*) FROM vulnerability_history WHERE status = 'open' GROUP BY severity")
        vuln_by_severity = cursor.fetchall()

        conn.close()

        return {
            "total_assets": total_assets,
            "active_assets": active_assets,
            "total_scans": total_scans,
            "total_changes": total_changes,
            "open_vulnerabilities": open_vulns,
            "fixed_vulnerabilities": fixed_vulns,
            "vulnerabilities_by_severity": {row[0]: row[1] for row in vuln_by_severity},
            "database_path": self.db_path,
        }
