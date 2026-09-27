# -*- coding: utf-8 -*-
"""资产/目标管理 - 分组/标签/优先级/CRUD"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import sqlite3, os

router = APIRouter(prefix="/api/v1/assets", tags=["资产管理"])
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "assets.db")

def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, target TEXT NOT NULL,
        asset_type TEXT DEFAULT 'ip', group_name TEXT DEFAULT 'default', tags TEXT,
        priority INTEGER DEFAULT 3, description TEXT, status TEXT DEFAULT 'active',
        last_scan_at TEXT, risk_score INTEGER DEFAULT 0, created_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS asset_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, description TEXT, created_at TEXT)""")
    conn.commit()
    return conn

class AssetCreateReq(BaseModel):
    name: str; target: str; asset_type: str = "ip"; group_name: str = "default"
    tags: Optional[str] = ""; priority: int = 3; description: Optional[str] = ""

class AssetUpdateReq(BaseModel):
    name: Optional[str] = None; target: Optional[str] = None; asset_type: Optional[str] = None
    group_name: Optional[str] = None; tags: Optional[str] = None; priority: Optional[int] = None
    description: Optional[str] = None; status: Optional[str] = None

class GroupCreateReq(BaseModel):
    name: str; description: Optional[str] = ""

@router.post("/assets")
def create_asset(req: AssetCreateReq):
    conn = _get_db(); now = datetime.now().isoformat()
    conn.execute("INSERT INTO assets (name,target,asset_type,group_name,tags,priority,description,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (req.name, req.target, req.asset_type, req.group_name, req.tags, req.priority, req.description, "active", now))
    conn.commit(); aid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]; conn.close()
    return {"success": True, "data": {"id": aid, "name": req.name, "target": req.target}}

@router.get("/assets")
def list_assets(group: Optional[str] = None, asset_type: Optional[str] = None, page: int = 1, page_size: int = 50):
    conn = _get_db(); q = "SELECT * FROM assets WHERE 1=1"; params = []
    if group: q += " AND group_name=?"; params.append(group)
    if asset_type: q += " AND asset_type=?"; params.append(asset_type)
    q += " ORDER BY priority DESC, id DESC LIMIT ? OFFSET ?"; params.extend([page_size, (page-1)*page_size])
    rows = conn.execute(q, params).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    conn.close()
    return {"success": True, "data": {"assets": [dict(r) for r in rows], "total": total, "page": page, "page_size": page_size}}

@router.get("/assets/{asset_id}")
def get_asset(asset_id: int):
    conn = _get_db()
    row = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
    conn.close()
    if not row: return {"success": False, "error": "资产不存在"}
    return {"success": True, "data": dict(row)}

@router.put("/assets/{asset_id}")
def update_asset(asset_id: int, req: AssetUpdateReq):
    conn = _get_db()
    if not conn.execute("SELECT id FROM assets WHERE id=?", (asset_id,)).fetchone():
        conn.close(); return {"success": False, "error": "资产不存在"}
    updates = []; params = []
    for f in ["name","target","asset_type","group_name","tags","priority","description","status"]:
        v = getattr(req, f)
        if v is not None: updates.append(f+"=?"); params.append(v)
    if updates:
        params.append(asset_id)
        conn.execute("UPDATE assets SET "+",".join(updates)+" WHERE id=?", params); conn.commit()
    conn.close(); return {"success": True, "data": {"id": asset_id, "updated": True}}

@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: int):
    conn = _get_db(); conn.execute("DELETE FROM assets WHERE id=?", (asset_id,)); conn.commit(); conn.close()
    return {"success": True, "data": {"deleted": asset_id}}

@router.post("/groups")
def create_group(req: GroupCreateReq):
    conn = _get_db()
    try:
        conn.execute("INSERT INTO asset_groups (name,description,created_at) VALUES (?,?,?)",
            (req.name, req.description, datetime.now().isoformat())); conn.commit()
        gid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]; conn.close()
        return {"success": True, "data": {"id": gid, "name": req.name}}
    except sqlite3.IntegrityError:
        conn.close(); return {"success": False, "error": "分组已存在"}

@router.get("/groups")
def list_groups():
    conn = _get_db(); rows = conn.execute("SELECT * FROM asset_groups ORDER BY id").fetchall(); conn.close()
    return {"success": True, "data": {"groups": [dict(r) for r in rows]}}

@router.get("/dashboard/stats")
def asset_dashboard():
    conn = _get_db()
    total = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    by_type = {}
    for r in conn.execute("SELECT asset_type, COUNT(*) as cnt FROM assets GROUP BY asset_type"):
        by_type[r["asset_type"]] = r["cnt"]
    by_group = {}
    for r in conn.execute("SELECT group_name, COUNT(*) as cnt FROM assets GROUP BY group_name"):
        by_group[r["group_name"]] = r["cnt"]
    high_risk = conn.execute("SELECT COUNT(*) FROM assets WHERE risk_score >= 70").fetchone()[0]
    conn.close()
    return {"success": True, "data": {"total_assets": total, "by_type": by_type, "by_group": by_group, "high_risk": high_risk}}
