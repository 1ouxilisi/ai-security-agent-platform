# -*- coding: utf-8 -*-
"""扫描历史存储 - SQLite持久化"""
from fastapi import APIRouter, Query
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
import sqlite3, json, os

router = APIRouter(prefix="/api/v1/scan-history", tags=["扫描历史"])

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "scan_history.db")

def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        scan_type TEXT DEFAULT 'recon',
        status TEXT DEFAULT 'completed',
        ports_count INTEGER DEFAULT 0,
        vulns_count INTEGER DEFAULT 0,
        risk_score INTEGER DEFAULT 0,
        risk_level TEXT DEFAULT 'unknown',
        duration_seconds REAL DEFAULT 0,
        result_json TEXT,
        created_at TEXT
    )""")
    conn.commit()
    return conn

def save_scan(target, scan_type, ports_count, vulns_count, risk_score, risk_level, duration, result):
    conn = _get_db()
    conn.execute("INSERT INTO scans (target,scan_type,ports_count,vulns_count,risk_score,risk_level,duration_seconds,result_json,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (target, scan_type, ports_count, vulns_count, risk_score, risk_level, duration, json.dumps(result, ensure_ascii=False)[:50000], datetime.now().isoformat()))
    conn.commit()
    scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return scan_id

@router.get("/list")
def list_scans(page: int = 1, page_size: int = 20, target: Optional[str] = None):
    """扫描历史列表"""
    conn = _get_db()
    q = "SELECT id,target,scan_type,status,ports_count,vulns_count,risk_score,risk_level,duration_seconds,created_at FROM scans"
    params = []
    if target:
        q += " WHERE target LIKE ?"
        params.append(f"%{target}%")
    q += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([page_size, (page-1)*page_size])
    rows = conn.execute(q, params).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM scans" + (" WHERE target LIKE ?" if target else ""), [f"%{target}%"] if target else []).fetchone()[0]
    conn.close()
    return {"success": True, "data": {"scans": [dict(r) for r in rows], "total": total, "page": page, "page_size": page_size}}

@router.get("/{scan_id}")
def get_scan(scan_id: int):
    """获取单次扫描详情"""
    conn = _get_db()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    if not row:
        return {"success": False, "error": "扫描记录不存在"}
    d = dict(row)
    try: d["result"] = json.loads(d.pop("result_json", "{}"))
    except: d["result"] = {}
    return {"success": True, "data": d}

@router.delete("/{scan_id}")
def delete_scan(scan_id: int):
    """删除扫描记录"""
    conn = _get_db()
    conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()
    return {"success": True, "data": {"deleted": scan_id}}

@router.get("/stats/summary")
def scan_stats():
    """扫描统计概览"""
    conn = _get_db()
    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    targets = conn.execute("SELECT COUNT(DISTINCT target) FROM scans").fetchone()[0]
    avg_risk = conn.execute("SELECT AVG(risk_score) FROM scans WHERE risk_score>0").fetchone()[0] or 0
    total_vulns = conn.execute("SELECT COALESCE(SUM(vulns_count),0) FROM scans").fetchone()[0]
    recent = conn.execute("SELECT target, vulns_count, risk_level, created_at FROM scans ORDER BY id DESC LIMIT 5").fetchall()
    conn.close()
    return {"success": True, "data": {"total_scans": total, "unique_targets": targets, "avg_risk_score": round(avg_risk,1), "total_vulns_found": total_vulns, "recent_scans": [dict(r) for r in recent]}}
