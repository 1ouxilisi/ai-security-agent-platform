# -*- coding: utf-8 -*-
"""漏洞管理工作流 - 状态跟踪/优先级/备注/时间线"""
from fastapi import APIRouter, Query
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
import sqlite3, json, os

router = APIRouter(prefix="/api/v1/vuln-management", tags=["漏洞管理"])

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "vuln_management.db")
VALID_STATUSES = ["new", "confirmed", "in_progress", "fixed", "verified", "reopened", "false_positive"]
STATUS_LABELS = {"new":"新建","confirmed":"已确认","in_progress":"修复中","fixed":"已修复","verified":"已验证","reopened":"重新打开","false_positive":"误报"}

def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, target TEXT,
        severity TEXT DEFAULT 'medium', status TEXT DEFAULT 'new', cve TEXT,
        description TEXT, evidence TEXT, remediation TEXT, assignee TEXT, tags TEXT,
        priority INTEGER DEFAULT 3, created_at TEXT, updated_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS vuln_timeline (
        id INTEGER PRIMARY KEY AUTOINCREMENT, vuln_id INTEGER, action TEXT, detail TEXT, created_at TEXT)""")
    conn.commit()
    return conn

def _add_timeline(conn, vid, action, detail=""):
    conn.execute("INSERT INTO vuln_timeline (vuln_id,action,detail,created_at) VALUES (?,?,?,?)",
        (vid, action, detail, datetime.now().isoformat()))

class VulnCreateReq(BaseModel):
    title: str; target: Optional[str] = ""; severity: str = "medium"
    cve: Optional[str] = ""; description: Optional[str] = ""; evidence: Optional[str] = ""
    remediation: Optional[str] = ""; assignee: Optional[str] = ""; tags: Optional[str] = ""; priority: int = 3

class VulnUpdateReq(BaseModel):
    title: Optional[str] = None; severity: Optional[str] = None; status: Optional[str] = None
    description: Optional[str] = None; evidence: Optional[str] = None; remediation: Optional[str] = None
    assignee: Optional[str] = None; tags: Optional[str] = None; priority: Optional[int] = None

class StatusChangeReq(BaseModel):
    status: str; note: Optional[str] = ""

@router.post("/vulnerabilities")
def create_vuln(req: VulnCreateReq):
    conn = _get_db(); now = datetime.now().isoformat()
    conn.execute("""INSERT INTO vulnerabilities (title,target,severity,status,cve,description,evidence,remediation,assignee,tags,priority,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (req.title,req.target,req.severity,"new",req.cve,req.description,req.evidence,req.remediation,req.assignee,req.tags,req.priority,now,now))
    conn.commit(); vid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    _add_timeline(conn, vid, "created", "漏洞创建"); conn.commit(); conn.close()
    return {"success": True, "data": {"id": vid, "title": req.title, "status": "new"}}

@router.get("/vulnerabilities")
def list_vulns(status: Optional[str] = None, severity: Optional[str] = None, target: Optional[str] = None, page: int = 1, page_size: int = 20):
    conn = _get_db(); q = "SELECT * FROM vulnerabilities WHERE 1=1"; params = []
    if status: q += " AND status=?"; params.append(status)
    if severity: q += " AND severity=?"; params.append(severity)
    if target: q += " AND target LIKE ?"; params.append("%"+target+"%")
    q += " ORDER BY priority DESC, id DESC LIMIT ? OFFSET ?"; params.extend([page_size, (page-1)*page_size])
    rows = conn.execute(q, params).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    conn.close()
    vulns = []
    for r in rows:
        d = dict(r); d["status_label"] = STATUS_LABELS.get(d["status"], d["status"]); vulns.append(d)
    return {"success": True, "data": {"vulnerabilities": vulns, "total": total, "page": page, "page_size": page_size}}

@router.get("/vulnerabilities/{vuln_id}")
def get_vuln(vuln_id: int):
    conn = _get_db()
    row = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vuln_id,)).fetchone()
    if not row: conn.close(); return {"success": False, "error": "漏洞不存在"}
    timeline = conn.execute("SELECT * FROM vuln_timeline WHERE vuln_id=? ORDER BY id DESC", (vuln_id,)).fetchall()
    conn.close(); d = dict(row); d["status_label"] = STATUS_LABELS.get(d["status"], d["status"]); d["timeline"] = [dict(t) for t in timeline]
    return {"success": True, "data": d}

@router.put("/vulnerabilities/{vuln_id}")
def update_vuln(vuln_id: int, req: VulnUpdateReq):
    conn = _get_db()
    if not conn.execute("SELECT id FROM vulnerabilities WHERE id=?", (vuln_id,)).fetchone():
        conn.close(); return {"success": False, "error": "漏洞不存在"}
    updates = []; params = []
    for f in ["title","severity","description","evidence","remediation","assignee","tags","priority"]:
        v = getattr(req, f)
        if v is not None: updates.append(f+"=?"); params.append(v)
    if updates:
        updates.append("updated_at=?"); params.append(datetime.now().isoformat()); params.append(vuln_id)
        conn.execute("UPDATE vulnerabilities SET "+",".join(updates)+" WHERE id=?", params)
        _add_timeline(conn, vuln_id, "updated", "更新信息"); conn.commit()
    conn.close(); return {"success": True, "data": {"id": vuln_id, "updated": True}}

@router.post("/vulnerabilities/{vuln_id}/status")
def change_status(vuln_id: int, req: StatusChangeReq):
    if req.status not in VALID_STATUSES: return {"success": False, "error": "无效状态"}
    conn = _get_db()
    row = conn.execute("SELECT status FROM vulnerabilities WHERE id=?", (vuln_id,)).fetchone()
    if not row: conn.close(); return {"success": False, "error": "漏洞不存在"}
    old = row["status"]
    conn.execute("UPDATE vulnerabilities SET status=?, updated_at=? WHERE id=?", (req.status, datetime.now().isoformat(), vuln_id))
    _add_timeline(conn, vuln_id, "status_change", STATUS_LABELS.get(old,old)+" -> "+STATUS_LABELS.get(req.status,req.status)+" "+req.note)
    conn.commit(); conn.close()
    return {"success": True, "data": {"id": vuln_id, "old_status": old, "new_status": req.status}}

@router.delete("/vulnerabilities/{vuln_id}")
def delete_vuln(vuln_id: int):
    conn = _get_db()
    conn.execute("DELETE FROM vulnerabilities WHERE id=?", (vuln_id,))
    conn.execute("DELETE FROM vuln_timeline WHERE vuln_id=?", (vuln_id,))
    conn.commit(); conn.close()
    return {"success": True, "data": {"deleted": vuln_id}}

@router.get("/dashboard/stats")
def vuln_dashboard():
    conn = _get_db()
    total = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    by_status = {}
    for r in conn.execute("SELECT status, COUNT(*) as cnt FROM vulnerabilities GROUP BY status"):
        by_status[STATUS_LABELS.get(r["status"], r["status"])] = r["cnt"]
    by_severity = {}
    for r in conn.execute("SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity"):
        by_severity[r["severity"]] = r["cnt"]
    open_v = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status IN ('new','confirmed','in_progress','reopened')").fetchone()[0]
    crit_high = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity IN ('critical','high') AND status IN ('new','confirmed','in_progress')").fetchone()[0]
    recent = conn.execute("SELECT id,title,severity,status,target,created_at FROM vulnerabilities ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()
    return {"success": True, "data": {"total": total, "open_vulns": open_v, "critical_high_open": crit_high, "by_status": by_status, "by_severity": by_severity, "recent": [dict(r) for r in recent]}}
