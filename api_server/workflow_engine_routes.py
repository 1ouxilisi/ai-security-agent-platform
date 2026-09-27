# -*- coding: utf-8 -*-
"""统一作战工作流引擎 - 一键全流程整合（侦察→扫描→攻击链→报告→入库→审计）"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
import sqlite3, json, os, uuid, threading, time

router = APIRouter(prefix="/api/v1/workflow", tags=["统一工作流"])

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
TASK_DB = os.path.join(DATA_DIR, "workflow_tasks.db")

# 任务状态
TASK_STATUS = {"pending": "等待中", "running": "运行中", "completed": "完成", "failed": "失败", "cancelled": "已取消"}

def _get_task_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(TASK_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        target TEXT,
        workflow_type TEXT,
        status TEXT DEFAULT 'pending',
        current_step TEXT,
        progress INTEGER DEFAULT 0,
        result TEXT,
        error TEXT,
        created_at TEXT,
        started_at TEXT,
        completed_at TEXT,
        duration_ms REAL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS task_steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT,
        step_name TEXT,
        status TEXT,
        detail TEXT,
        started_at TEXT,
        completed_at TEXT,
        duration_ms REAL
    )""")
    conn.commit()
    return conn

def _update_task(task_id, **kwargs):
    conn = _get_task_db()
    sets = []; params = []
    for k, v in kwargs.items():
        sets.append(f"{k}=?"); params.append(v)
    params.append(task_id)
    conn.execute(f"UPDATE tasks SET {','.join(sets)} WHERE id=?", params)
    conn.commit(); conn.close()

def _add_step(task_id, step_name, status, detail=""):
    conn = _get_task_db()
    conn.execute("INSERT INTO task_steps (task_id,step_name,status,detail,started_at) VALUES (?,?,?,?,?)",
        (task_id, step_name, status, detail, datetime.now().isoformat()))
    conn.commit(); conn.close()

def _complete_step(task_id, step_name, detail=""):
    conn = _get_task_db()
    conn.execute("UPDATE task_steps SET status='completed', detail=?, completed_at=? WHERE task_id=? AND step_name=? AND status='running'",
        (detail, datetime.now().isoformat(), task_id, step_name))
    conn.commit(); conn.close()

class WorkflowRunReq(BaseModel):
    target: str
    workflow_type: str = "full"  # full/recon/scan/report
    depth: str = "standard"  # quick/standard/deep
    auto_create_vuln: bool = True  # 自动创建漏洞管理条目
    auto_create_asset: bool = True  # 自动创建资产条目
    auto_audit: bool = True  # 自动记录审计日志
    webhook_alert: bool = False  # 完成后Webhook告警

def _run_workflow_async(task_id, req: WorkflowRunReq):
    """异步执行工作流"""
    try:
        _update_task(task_id, status="running", started_at=datetime.now().isoformat())
        result = {"target": req.target, "workflow_type": req.workflow_type, "steps": {}}
        steps_total = 6 if req.workflow_type == "full" else 3
        current_step = 0

        # Step 1: 侦察（Nmap端口扫描）
        if req.workflow_type in ("full", "recon", "scan"):
            current_step += 1
            _update_task(task_id, current_step="端口扫描", progress=int(current_step/steps_total*100))
            _add_step(task_id, "端口扫描", "running")
            from asm.real_tools import NmapRunner
            nmap_timeout = 15 if req.depth == "quick" else 30 if req.depth == "standard" else 60
            nmap = NmapRunner(req.target, timeout=nmap_timeout).quick_scan()
            ports = nmap.get("open_ports", [])
            result["steps"]["recon"] = {"ports": ports, "port_count": len(ports)}
            _complete_step(task_id, "端口扫描", f"发现{len(ports)}个开放端口")

        # Step 2: 漏洞扫描（Nuclei）
        if req.workflow_type in ("full", "scan"):
            current_step += 1
            _update_task(task_id, current_step="漏洞扫描", progress=int(current_step/steps_total*100))
            _add_step(task_id, "漏洞扫描", "running")
            from asm.real_tools import NucleiRunner
            vulns = []
            http_ports = [p for p in ports if p.get("service","") in ("http","https","http-alt") or p["port"] in (80,443,8000,8080,8443,3000)]
            is_local = req.target in ("127.0.0.1","localhost") or req.target.startswith("192.168.") or req.target.startswith("10.")
            if http_ports and not is_local:
                hp = http_ports[0]["port"]
                scheme = "https" if hp in (443,8443) else "http"
                http_target = f"{scheme}://{req.target}:{hp}" if hp not in (80,443) else f"{scheme}://{req.target}"
                nuclei = NucleiRunner(http_target, timeout=15).scan("critical,high,medium")
                vulns = nuclei.get("vulnerabilities", [])
            result["steps"]["vuln_scan"] = {"vulnerabilities": vulns, "vuln_count": len(vulns)}
            _complete_step(task_id, "漏洞扫描", f"发现{len(vulns)}个漏洞")

        # Step 3: 攻击链分析
        if req.workflow_type == "full":
            current_step += 1
            _update_task(task_id, current_step="攻击链分析", progress=int(current_step/steps_total*100))
            _add_step(task_id, "攻击链分析", "running")
            from api_server.kill_chain_routes import analyze_kill_chain, KillChainAnalyzeReq
            kc = analyze_kill_chain(KillChainAnalyzeReq(target=req.target, ports=ports, vulnerabilities=vulns))
            result["steps"]["kill_chain"] = kc.get("data", {})
            _complete_step(task_id, "攻击链分析", f"最大风险:{kc.get('data',{}).get('risk_assessment',{}).get('max_severity','info')}")

        # Step 4: 风险评分
        if req.workflow_type in ("full", "report"):
            current_step += 1
            _update_task(task_id, current_step="风险评分", progress=int(current_step/steps_total*100))
            _add_step(task_id, "风险评分", "running")
            from api_server.recon_workflow_routes import _risk_score
            risk = _risk_score(ports, vulns, [])
            result["steps"]["risk_score"] = risk
            _complete_step(task_id, "风险评分", f"风险评分:{risk.get('score',0)}/100")

        # Step 5: 报告生成
        if req.workflow_type in ("full", "report"):
            current_step += 1
            _update_task(task_id, current_step="报告生成", progress=int(current_step/steps_total*100))
            _add_step(task_id, "报告生成", "running")
            report = {
                "target": req.target,
                "generated_at": datetime.now().isoformat(),
                "ports": ports,
                "vulnerabilities": vulns,
                "risk_score": risk if req.workflow_type != "report" else result["steps"].get("risk_score", {}),
                "summary": f"目标{req.target}发现{len(ports)}个开放端口,{len(vulns)}个漏洞,风险评分{risk.get('score',0) if req.workflow_type != 'report' else result['steps'].get('risk_score',{}).get('score',0)}/100"
            }
            result["steps"]["report"] = report
            _complete_step(task_id, "报告生成", "报告已生成")

        # Step 6: 自动入库（漏洞管理+资产管理+审计日志）
        if req.workflow_type == "full":
            current_step += 1
            _update_task(task_id, current_step="数据入库", progress=int(current_step/steps_total*100))
            _add_step(task_id, "数据入库", "running")
            db_results = {"vuln_created": 0, "asset_created": False, "audit_logged": False}

            # 自动创建漏洞管理条目
            if req.auto_create_vuln and vulns:
                try:
                    vdb = sqlite3.connect(os.path.join(DATA_DIR, "vuln_management.db"))
                    for v in vulns[:20]:
                        vdb.execute("""INSERT INTO vulnerabilities (title,target,severity,status,cve,description,created_at,updated_at)
                            VALUES (?,?,?,?,?,?,?,?)""",
                            (v.get("template_name", v.get("name","Unknown")), req.target, v.get("severity","info"),
                             "new", v.get("cve",""), v.get("description", v.get("info","")),
                             datetime.now().isoformat(), datetime.now().isoformat()))
                    vdb.commit(); vdb.close()
                    db_results["vuln_created"] = min(len(vulns), 20)
                except: pass

            # 自动创建资产条目
            if req.auto_create_asset:
                try:
                    adb = sqlite3.connect(os.path.join(DATA_DIR, "assets.db"))
                    existing = adb.execute("SELECT id FROM assets WHERE target=?", (req.target,)).fetchone()
                    if not existing:
                        adb.execute("""INSERT INTO assets (name,target,asset_type,group_name,priority,status,created_at)
                            VALUES (?,?,?,?,?,?,?)""",
                            (f"目标-{req.target}", req.target, "ip" if req.target.replace(".","").isdigit() else "domain",
                             "自动发现", 3, "active", datetime.now().isoformat()))
                        adb.commit()
                        db_results["asset_created"] = True
                    adb.close()
                except: pass

            # 自动记录审计日志
            if req.auto_audit:
                try:
                    from api_server.audit_log_routes import log_action
                    log_action("workflow_run", req.target, "system", "", "POST", "/api/v1/workflow/run",
                        200, 0, f"工作流执行完成: {req.workflow_type}, 发现{len(vulns)}个漏洞", "high" if vulns else "low")
                    db_results["audit_logged"] = True
                except: pass

            result["steps"]["auto_inventory"] = db_results
            _complete_step(task_id, "数据入库", f"漏洞{db_results['vuln_created']}条, 资产{'已创建' if db_results['asset_created'] else '已存在'}, 审计{'已记录' if db_results['audit_logged'] else '未记录'}")

        # 完成
        duration = (datetime.now() - datetime.fromisoformat(result.get("_start", datetime.now().isoformat()))).total_seconds() * 1000 if "_start" in result else 0
        _update_task(task_id, status="completed", current_step="完成", progress=100,
            result=json.dumps(result, ensure_ascii=False, default=str),
            completed_at=datetime.now().isoformat(), duration_ms=duration)

    except Exception as e:
        _update_task(task_id, status="failed", error=str(e), completed_at=datetime.now().isoformat())

@router.post("/run")
def run_workflow(req: WorkflowRunReq):
    """启动统一工作流（异步执行，返回任务ID用于查询进度）"""
    task_id = str(uuid.uuid4())[:8]
    conn = _get_task_db()
    conn.execute("""INSERT INTO tasks (id,target,workflow_type,status,current_step,progress,created_at)
        VALUES (?,?,?,?,?,?,?)""",
        (task_id, req.target, req.workflow_type, "pending", "初始化", 0, datetime.now().isoformat()))
    conn.commit(); conn.close()

    # 异步执行
    t = threading.Thread(target=_run_workflow_async, args=(task_id, req), daemon=True)
    t.start()

    return {"success": True, "data": {"task_id": task_id, "status": "pending", "target": req.target,
        "workflow_type": req.workflow_type, "message": "工作流已启动，使用GET /api/v1/workflow/tasks/{id}查询进度"}}

@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    """查询任务状态和结果"""
    conn = _get_task_db()
    task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    steps = conn.execute("SELECT * FROM task_steps WHERE task_id=? ORDER BY id", (task_id,)).fetchall()
    conn.close()
    if not task:
        return {"success": False, "error": "任务不存在"}
    d = dict(task)
    d["status_label"] = TASK_STATUS.get(d["status"], d["status"])
    d["steps"] = [dict(s) for s in steps]
    if d.get("result"):
        try: d["result"] = json.loads(d["result"])
        except: pass
    return {"success": True, "data": d}

@router.get("/tasks")
def list_tasks(status: Optional[str] = None, limit: int = 20):
    """任务列表"""
    conn = _get_task_db()
    q = "SELECT id,target,workflow_type,status,current_step,progress,created_at,completed_at,duration_ms FROM tasks"
    params = []
    if status: q += " WHERE status=?"; params.append(status)
    q += " ORDER BY created_at DESC LIMIT ?"; params.append(limit)
    rows = conn.execute(q, params).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    running = conn.execute("SELECT COUNT(*) FROM tasks WHERE status='running'").fetchone()[0]
    conn.close()
    return {"success": True, "data": {"tasks": [dict(r) for r in rows], "total": total, "running": running}}

@router.get("/dashboard/overview")
def overview_dashboard():
    """总览仪表盘 - 聚合所有模块数据"""
    data = {"generated_at": datetime.now().isoformat(), "modules": {}}

    # 1. 任务统计
    try:
        conn = _get_task_db()
        total_tasks = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        completed_tasks = conn.execute("SELECT COUNT(*) FROM tasks WHERE status='completed'").fetchone()[0]
        running_tasks = conn.execute("SELECT COUNT(*) FROM tasks WHERE status='running'").fetchone()[0]
        conn.close()
        data["modules"]["workflow"] = {"total": total_tasks, "completed": completed_tasks, "running": running_tasks}
    except: data["modules"]["workflow"] = {"error": "不可用"}

    # 2. 漏洞管理统计
    try:
        vdb = sqlite3.connect(os.path.join(DATA_DIR, "vuln_management.db"))
        total_vulns = vdb.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        open_vulns = vdb.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status IN ('new','confirmed','in_progress')").fetchone()[0]
        crit_high = vdb.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity IN ('critical','high') AND status IN ('new','confirmed','in_progress')").fetchone()[0]
        vdb.close()
        data["modules"]["vuln_management"] = {"total": total_vulns, "open": open_vulns, "critical_high": crit_high}
    except: data["modules"]["vuln_management"] = {"error": "不可用"}

    # 3. 资产管理统计
    try:
        adb = sqlite3.connect(os.path.join(DATA_DIR, "assets.db"))
        total_assets = adb.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        high_risk = adb.execute("SELECT COUNT(*) FROM assets WHERE risk_score >= 70").fetchone()[0]
        adb.close()
        data["modules"]["assets"] = {"total": total_assets, "high_risk": high_risk}
    except: data["modules"]["assets"] = {"error": "不可用"}

    # 4. 扫描历史统计
    try:
        sdb = sqlite3.connect(os.path.join(DATA_DIR, "scan_history.db"))
        total_scans = sdb.execute("SELECT COUNT(*) FROM scans").fetchone()[0] if sdb.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'").fetchone() else 0
        sdb.close()
        data["modules"]["scan_history"] = {"total": total_scans}
    except: data["modules"]["scan_history"] = {"error": "不可用"}

    # 5. 审计日志统计
    try:
        adb2 = sqlite3.connect(os.path.join(DATA_DIR, "audit_log.db"))
        total_audit = adb2.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0] if adb2.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'").fetchone() else 0
        high_risk_audit = adb2.execute("SELECT COUNT(*) FROM audit_logs WHERE risk_level IN ('high','critical')").fetchone()[0] if adb2.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'").fetchone() else 0
        adb2.close()
        data["modules"]["audit"] = {"total": total_audit, "high_risk": high_risk_audit}
    except: data["modules"]["audit"] = {"error": "不可用"}

    # 6. 持续监控统计
    try:
        mdb = sqlite3.connect(os.path.join(DATA_DIR, "monitor.db"))
        total_monitors = mdb.execute("SELECT COUNT(*) FROM monitor_targets").fetchone()[0] if mdb.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='monitor_targets'").fetchone() else 0
        mdb.close()
        data["modules"]["monitor"] = {"total_targets": total_monitors}
    except: data["modules"]["monitor"] = {"error": "不可用"}

    # 7. 审批统计
    try:
        pdb = sqlite3.connect(os.path.join(DATA_DIR, "approvals.db"))
        pending_approvals = pdb.execute("SELECT COUNT(*) FROM approvals WHERE status='pending'").fetchone()[0] if pdb.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='approvals'").fetchone() else 0
        pdb.close()
        data["modules"]["approvals"] = {"pending": pending_approvals}
    except: data["modules"]["approvals"] = {"error": "不可用"}

    # 综合评分
    total_score = 0
    modules_ok = 0
    for mod, d in data["modules"].items():
        if "error" not in d:
            modules_ok += 1
            total_score += 100
    data["overall"] = {
        "modules_online": f"{modules_ok}/{len(data['modules'])}",
        "health_score": int(total_score / len(data["modules"])) if data["modules"] else 0,
        "status": "healthy" if modules_ok == len(data["modules"]) else "degraded"
    }
    return {"success": True, "data": data}

@router.post("/quick-scan")
def quick_scan(target: str):
    """快速扫描（同步执行，适合简单目标）"""
    from asm.real_tools import NmapRunner
    nmap = NmapRunner(target, timeout=15).quick_scan()
    ports = nmap.get("open_ports", [])
    from api_server.recon_workflow_routes import _risk_score
    risk = _risk_score(ports, [], [])
    return {"success": True, "data": {"target": target, "ports": ports, "port_count": len(ports), "risk_score": risk}}
