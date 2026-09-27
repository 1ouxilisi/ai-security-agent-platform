# -*- coding: utf-8 -*-
"""导出功能 - CSV/JSON导出扫描结果和报告"""
from fastapi import APIRouter
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from typing import Optional
import json, csv, io, os

router = APIRouter(prefix="/api/v1/export", tags=["导出功能"])

@router.post("/scan/csv")
def export_scan_csv(data: dict):
    """导出扫描结果为CSV"""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["类型", "值", "严重程度", "描述", "目标", "时间"])
    ports = data.get("ports", [])
    for p in ports:
        writer.writerow(["端口", str(p.get("port",""))+"/"+p.get("protocol","tcp"), "info",
            p.get("service","")+" "+p.get("product","")+" "+p.get("version",""), data.get("target",""), ""])
    vulns = data.get("vulnerabilities", [])
    for v in vulns:
        writer.writerow(["漏洞", v.get("template_id",v.get("id","")), v.get("severity","info"),
            v.get("template_name",v.get("name","")), v.get("matched_at",v.get("url","")), ""])
    return Response(content=output.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=scan_result.csv"})

@router.post("/scan/json")
def export_scan_json(data: dict):
    """导出扫描结果为JSON"""
    return JSONResponse(content=data,
        headers={"Content-Disposition": "attachment; filename=scan_result.json"})

@router.post("/report/csv")
def export_report_csv(data: dict):
    """导出报告漏洞详情为CSV"""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["编号", "漏洞ID", "名称", "严重程度", "目标URL", "CVE", "风险描述", "修复建议"])
    vulns = data.get("vulnerabilities", [])
    for i, v in enumerate(vulns, 1):
        writer.writerow([i, v.get("id",""), v.get("name",""), v.get("severity",""),
            v.get("url",""), v.get("cve",""), v.get("risk",""), v.get("fix","")])
    return Response(content=output.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=report_vulns.csv"})

@router.get("/vuln-management/csv")
def export_vuln_mgmt_csv():
    """导出漏洞管理库为CSV"""
    import sqlite3
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "vuln_management.db")
    if not os.path.exists(db_path):
        return Response(content="", media_type="text/csv")
    conn = sqlite3.connect(db_path); conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM vulnerabilities ORDER BY id").fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","标题","目标","严重程度","状态","CVE","描述","修复建议","负责人","标签","优先级","创建时间","更新时间"])
    for r in rows:
        writer.writerow([r["id"],r["title"],r["target"],r["severity"],r["status"],r["cve"],
            r["description"],r["remediation"],r["assignee"],r["tags"],r["priority"],r["created_at"],r["updated_at"]])
    return Response(content=output.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vuln_management.csv"})

@router.get("/assets/csv")
def export_assets_csv():
    """导出资产库为CSV"""
    import sqlite3
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "assets.db")
    if not os.path.exists(db_path):
        return Response(content="", media_type="text/csv")
    conn = sqlite3.connect(db_path); conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM assets ORDER BY id").fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","名称","目标","类型","分组","标签","优先级","描述","状态","风险评分","最后扫描","创建时间"])
    for r in rows:
        writer.writerow([r["id"],r["name"],r["target"],r["asset_type"],r["group_name"],r["tags"],
            r["priority"],r["description"],r["status"],r["risk_score"],r["last_scan_at"],r["created_at"]])
    return Response(content=output.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=assets.csv"})
