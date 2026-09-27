# -*- coding: utf-8 -*-
"""审计日志/操作追踪 - 所有API操作可追溯可导出（对标CyberStrikeAI可审计工作空间）"""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import sqlite3, json, os, time

router = APIRouter(prefix="/api/v1/audit", tags=["审计日志"])
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "audit_log.db")

def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        action TEXT,
        target TEXT,
        user TEXT,
        ip TEXT,
        method TEXT,
        path TEXT,
        status_code INTEGER,
        duration_ms REAL,
        detail TEXT,
        risk_level TEXT DEFAULT 'low'
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_logs(target)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp)")
    conn.commit()
    return conn

def log_action(action, target="", user="system", ip="", method="", path="", status_code=200, duration_ms=0, detail="", risk_level="low"):
    """记录审计日志（供其他模块调用）"""
    try:
        conn = _get_db()
        conn.execute("""INSERT INTO audit_logs (timestamp,action,target,user,ip,method,path,status_code,duration_ms,detail,risk_level)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (datetime.now().isoformat(), action, target, user, ip, method, path, status_code, duration_ms, detail, risk_level))
        conn.commit(); conn.close()
    except: pass

@router.get("/logs")
def list_logs(action: Optional[str] = None, target: Optional[str] = None,
              risk_level: Optional[str] = None, start_date: Optional[str] = None,
              end_date: Optional[str] = None, page: int = 1, page_size: int = 50):
    """审计日志查询（支持多维度筛选）"""
    conn = _get_db()
    q = "SELECT * FROM audit_logs WHERE 1=1"; params = []
    if action: q += " AND action LIKE ?"; params.append("%"+action+"%")
    if target: q += " AND target LIKE ?"; params.append("%"+target+"%")
    if risk_level: q += " AND risk_level=?"; params.append(risk_level)
    if start_date: q += " AND timestamp >= ?"; params.append(start_date)
    if end_date: q += " AND timestamp <= ?"; params.append(end_date)
    q += " ORDER BY id DESC LIMIT ? OFFSET ?"; params.extend([page_size, (page-1)*page_size])
    rows = conn.execute(q, params).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    conn.close()
    return {"success": True, "data": {"logs": [dict(r) for r in rows], "total": total, "page": page, "page_size": page_size}}

@router.get("/stats")
def audit_stats():
    """审计统计仪表盘"""
    conn = _get_db()
    total = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    by_action = {}
    for r in conn.execute("SELECT action, COUNT(*) as cnt FROM audit_logs GROUP BY action ORDER BY cnt DESC LIMIT 15"):
        by_action[r["action"]] = r["cnt"]
    by_risk = {}
    for r in conn.execute("SELECT risk_level, COUNT(*) as cnt FROM audit_logs GROUP BY risk_level"):
        by_risk[r["risk_level"]] = r["cnt"]
    high_risk = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE risk_level IN ('high','critical')").fetchone()[0]
    recent = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    return {"success": True, "data": {"total": total, "by_action": by_action, "by_risk": by_risk, "high_risk_count": high_risk, "recent": [dict(r) for r in recent]}}

@router.get("/export/csv")
def export_audit_csv(action: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None):
    """导出审计日志为CSV"""
    import csv, io
    conn = _get_db()
    q = "SELECT * FROM audit_logs WHERE 1=1"; params = []
    if action: q += " AND action LIKE ?"; params.append("%"+action+"%")
    if start_date: q += " AND timestamp >= ?"; params.append(start_date)
    if end_date: q += " AND timestamp <= ?"; params.append(end_date)
    q += " ORDER BY id DESC LIMIT 10000"
    rows = conn.execute(q, params).fetchall(); conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","时间","操作","目标","用户","IP","方法","路径","状态码","耗时ms","详情","风险等级"])
    for r in rows:
        writer.writerow([r["id"],r["timestamp"],r["action"],r["target"],r["user"],r["ip"],r["method"],r["path"],r["status_code"],r["duration_ms"],r["detail"],r["risk_level"]])
    from fastapi.responses import Response
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=audit_logs.csv"})

@router.delete("/logs/clear")
def clear_logs(days: int = 90):
    """清理N天前的审计日志"""
    conn = _get_db()
    cutoff = datetime.fromtimestamp(time.time() - days*86400).isoformat()
    deleted = conn.execute("DELETE FROM audit_logs WHERE timestamp < ?", (cutoff,)).rowcount
    conn.commit(); conn.close()
    return {"success": True, "data": {"deleted": deleted, "cutoff": cutoff}}
