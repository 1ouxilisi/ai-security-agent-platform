# -*- coding: utf-8 -*-
"""持续监控 - 定时扫描/变更检测/告警"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
import sqlite3, json, os, threading, time

router = APIRouter(prefix="/api/v1/monitor", tags=["持续监控"])

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "monitor.db")
_monitor_thread = None
_monitor_running = False

def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL UNIQUE,
        interval_minutes INTEGER DEFAULT 60,
        enabled INTEGER DEFAULT 1,
        last_scan_at TEXT,
        last_risk_score INTEGER DEFAULT 0,
        last_vulns_count INTEGER DEFAULT 0,
        created_at TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS changes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER,
        change_type TEXT,
        description TEXT,
        detected_at TEXT
    )""")
    conn.commit()
    return conn

class MonitorTargetReq(BaseModel):
    target: str
    interval_minutes: int = 60

@router.post("/targets/add")
def add_target(req: MonitorTargetReq):
    """添加监控目标"""
    conn = _get_db()
    try:
        conn.execute("INSERT INTO targets (target,interval_minutes,enabled,created_at) VALUES (?,?,1,?)",
            (req.target, req.interval_minutes, datetime.now().isoformat()))
        conn.commit()
        tid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        return {"success": True, "data": {"id": tid, "target": req.target, "interval": req.interval_minutes}}
    except sqlite3.IntegrityError:
        conn.close()
        return {"success": False, "error": "目标已存在"}

@router.get("/targets/list")
def list_targets():
    """监控目标列表"""
    conn = _get_db()
    rows = conn.execute("SELECT * FROM targets ORDER BY id DESC").fetchall()
    conn.close()
    return {"success": True, "data": {"targets": [dict(r) for r in rows], "count": len(rows)}}

@router.delete("/targets/{target_id}")
def remove_target(target_id: int):
    """移除监控目标"""
    conn = _get_db()
    conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
    conn.execute("DELETE FROM changes WHERE target_id=?", (target_id,))
    conn.commit()
    conn.close()
    return {"success": True, "data": {"removed": target_id}}

@router.post("/targets/{target_id}/toggle")
def toggle_target(target_id: int):
    """启用/禁用监控"""
    conn = _get_db()
    row = conn.execute("SELECT enabled FROM targets WHERE id=?", (target_id,)).fetchone()
    if not row:
        conn.close()
        return {"success": False, "error": "目标不存在"}
    new_val = 0 if row["enabled"] else 1
    conn.execute("UPDATE targets SET enabled=? WHERE id=?", (new_val, target_id))
    conn.commit()
    conn.close()
    return {"success": True, "data": {"id": target_id, "enabled": bool(new_val)}}

@router.post("/scan/{target_id}")
def manual_scan(target_id: int):
    """手动触发一次扫描并检测变更"""
    conn = _get_db()
    row = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    if not row:
        conn.close()
        return {"success": False, "error": "目标不存在"}
    target = row["target"]
    prev_risk = row["last_risk_score"]
    prev_vulns = row["last_vulns_count"]
    # 执行扫描
    from asm.real_tools import NmapRunner
    nmap = NmapRunner(target, timeout=30).quick_scan()
    ports = nmap.get("open_ports", [])
    vulns_count = 0
    risk_score = min(100, len(ports) * 5 + vulns_count * 10)
    # 检测变更
    changes = []
    if prev_risk and risk_score != prev_risk:
        changes.append({"type": "risk_change", "desc": f"风险评分从{prev_risk}变为{risk_score}"})
    if prev_vulns is not None and vulns_count != prev_vulns:
        direction = "新增" if vulns_count > prev_vulns else "减少"
        changes.append({"type": "vuln_change", "desc": f"漏洞数量{direction}: {prev_vulns} -> {vulns_count}"})
    # 记录变更
    for ch in changes:
        conn.execute("INSERT INTO changes (target_id,change_type,description,detected_at) VALUES (?,?,?,?)",
            (target_id, ch["type"], ch["desc"], datetime.now().isoformat()))
    # 更新目标状态
    conn.execute("UPDATE targets SET last_scan_at=?,last_risk_score=?,last_vulns_count=? WHERE id=?",
        (datetime.now().isoformat(), risk_score, vulns_count, target_id))
    conn.commit()
    conn.close()
    return {"success": True, "data": {"target": target, "ports": len(ports), "vulns": vulns_count, "risk": risk_score, "changes": changes}}

@router.get("/changes/{target_id}")
def get_changes(target_id: int, limit: int = 50):
    """获取变更历史"""
    conn = _get_db()
    rows = conn.execute("SELECT * FROM changes WHERE target_id=? ORDER BY id DESC LIMIT ?", (target_id, limit)).fetchall()
    conn.close()
    return {"success": True, "data": {"changes": [dict(r) for r in rows], "count": len(rows)}}

@router.get("/status")
def monitor_status():
    """监控系统状态"""
    conn = _get_db()
    total = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
    enabled = conn.execute("SELECT COUNT(*) FROM targets WHERE enabled=1").fetchone()[0]
    changes = conn.execute("SELECT COUNT(*) FROM changes").fetchone()[0]
    conn.close()
    return {"success": True, "data": {"total_targets": total, "enabled_targets": enabled, "total_changes": changes, "auto_monitor": _monitor_running}}
