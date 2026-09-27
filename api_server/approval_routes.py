# -*- coding: utf-8 -*-
"""人工监督/审批节点 - Human-in-the-loop（对标CyberStrikeAI人工监督）"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
import sqlite3, json, os, uuid

router = APIRouter(prefix="/api/v1/approvals", tags=["人工审批"])
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "approvals.db")

def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        workflow_type TEXT,
        action TEXT,
        target TEXT,
        description TEXT,
        payload TEXT,
        status TEXT DEFAULT 'pending',
        requested_by TEXT,
        approved_by TEXT,
        comment TEXT,
        created_at TEXT,
        resolved_at TEXT
    )""")
    conn.commit()
    return conn

class ApprovalCreateReq(BaseModel):
    workflow_type: str = "scan"
    action: str
    target: str = ""
    description: str = ""
    payload: Optional[Dict[str, Any]] = None
    requested_by: str = "system"

class ApprovalResolveReq(BaseModel):
    approved: bool
    approved_by: str = "admin"
    comment: Optional[str] = ""

@router.post("/request")
def create_approval(req: ApprovalCreateReq):
    """创建审批请求（工作流中需要人工确认的节点）"""
    conn = _get_db()
    aid = str(uuid.uuid4())[:8]
    now = datetime.now().isoformat()
    conn.execute("""INSERT INTO approvals (id,workflow_type,action,target,description,payload,status,requested_by,created_at)
        VALUES (?,?,?,?,?,?,?,?,?)""",
        (aid, req.workflow_type, req.action, req.target, req.description,
         json.dumps(req.payload or {}, ensure_ascii=False), "pending", req.requested_by, now))
    conn.commit(); conn.close()
    return {"success": True, "data": {"id": aid, "status": "pending", "message": "审批请求已创建，等待人工审批"}}

@router.get("/pending")
def list_pending(workflow_type: Optional[str] = None):
    """待审批列表"""
    conn = _get_db()
    q = "SELECT * FROM approvals WHERE status='pending'"
    params = []
    if workflow_type: q += " AND workflow_type=?"; params.append(workflow_type)
    q += " ORDER BY created_at DESC"
    rows = conn.execute(q, params).fetchall()
    pending_count = conn.execute("SELECT COUNT(*) FROM approvals WHERE status='pending'").fetchone()[0]
    conn.close()
    return {"success": True, "data": {"approvals": [dict(r) for r in rows], "pending_count": pending_count}}

@router.get("/{approval_id}")
def get_approval(approval_id: str):
    """审批详情"""
    conn = _get_db()
    row = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
    conn.close()
    if not row: return {"success": False, "error": "审批不存在"}
    d = dict(row)
    if d.get("payload"):
        try: d["payload"] = json.loads(d["payload"])
        except: pass
    return {"success": True, "data": d}

@router.post("/{approval_id}/resolve")
def resolve_approval(approval_id: str, req: ApprovalResolveReq):
    """审批通过/拒绝"""
    conn = _get_db()
    row = conn.execute("SELECT status FROM approvals WHERE id=?", (approval_id,)).fetchone()
    if not row: conn.close(); return {"success": False, "error": "审批不存在"}
    if row["status"] != "pending": conn.close(); return {"success": False, "error": "该审批已处理"}
    status = "approved" if req.approved else "rejected"
    conn.execute("UPDATE approvals SET status=?, approved_by=?, comment=?, resolved_at=? WHERE id=?",
        (status, req.approved_by, req.comment, datetime.now().isoformat(), approval_id))
    conn.commit(); conn.close()
    return {"success": True, "data": {"id": approval_id, "status": status, "message": "已通过" if req.approved else "已拒绝"}}

@router.get("/stats/summary")
def approval_stats():
    """审批统计"""
    conn = _get_db()
    total = conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0]
    pending = conn.execute("SELECT COUNT(*) FROM approvals WHERE status='pending'").fetchone()[0]
    approved = conn.execute("SELECT COUNT(*) FROM approvals WHERE status='approved'").fetchone()[0]
    rejected = conn.execute("SELECT COUNT(*) FROM approvals WHERE status='rejected'").fetchone()[0]
    by_type = {}
    for r in conn.execute("SELECT workflow_type, COUNT(*) as cnt FROM approvals GROUP BY workflow_type"):
        by_type[r["workflow_type"]] = r["cnt"]
    conn.close()
    return {"success": True, "data": {"total": total, "pending": pending, "approved": approved, "rejected": rejected, "by_type": by_type}}
