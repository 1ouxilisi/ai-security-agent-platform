# -*- coding: utf-8 -*-
"""
ai_decision_engine_routes.py - AI智能决策引擎

核心能力：AI驱动的闭环渗透测试
1. 初步侦察（Nmap端口扫描）
2. AI分析结果，智能决策下一步动作
3. 执行决策（Web扫描/漏洞扫描/目录爆破/服务枚举等）
4. 循环迭代，自动规划攻击路径
5. 生成完整测试报告

路由前缀：/api/v1/ai-decision
"""
from __future__ import annotations
import os, sys, json, sqlite3, time, hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import log

# 内置认证
async def verify_auth() -> dict:
    return {"user_id": "admin", "username": "admin", "role": "admin"}

router = APIRouter(prefix="/api/v1/ai-decision", tags=["AI智能决策引擎"])

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "ai_decision.db")

def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"code": 0, "data": data})

def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"code": status, "error": message}, status_code=status)

def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _init_db():
    conn = _get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        target TEXT,
        status TEXT DEFAULT 'pending',
        current_phase TEXT DEFAULT 'init',
        phase_index INTEGER DEFAULT 0,
        decisions TEXT DEFAULT '[]',
        results TEXT DEFAULT '{}',
        attack_path TEXT DEFAULT '[]',
        risk_score INTEGER DEFAULT 0,
        created_at TEXT,
        updated_at TEXT,
        completed_at TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS decisions (
        id TEXT PRIMARY KEY,
        session_id TEXT,
        phase TEXT,
        observation TEXT,
        ai_analysis TEXT,
        decision TEXT,
        action TEXT,
        params TEXT,
        result_summary TEXT,
        created_at TEXT
    )""")
    conn.commit()
    conn.close()

_init_db()

# ==================== 请求模型 ====================

class TargetReq(BaseModel):
    target: str
    max_iterations: int = 5
    depth: str = "standard"  # quick / standard / deep
    allowed_actions: List[str] = []  # 空=全部允许

class DecisionReq(BaseModel):
    observation: str = ""

# ==================== AI调用 ====================

def _call_ai(prompt: str, system: str = "你是一个资深渗透测试专家，擅长根据扫描结果智能决策下一步测试动作。回答用JSON格式。", max_tokens: int = 1500) -> str:
    """调用LLM（通过多LLM提供商的自动降级）"""
    try:
        import urllib.request, urllib.error, json as _json
        # 直接从多LLM数据库读取配置
        llm_db = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "llm_providers.db")
        if not os.path.exists(llm_db):
            return ""
        conn = sqlite3.connect(llm_db)
        conn.row_factory = sqlite3.Row
        providers = conn.execute("SELECT * FROM providers WHERE enabled=1 ORDER BY priority ASC").fetchall()
        conn.close()
        if not providers:
            return ""
        for p in providers:
            try:
                api_key = _decrypt_key(p["api_key"])
                if not api_key:
                    continue
                url = f"{p['base_url'].rstrip('/')}/chat/completions"
                body = _json.dumps({
                    "model": p["model"],
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                    "max_tokens": max_tokens, "temperature": 0.3
                }).encode()
                headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
                req = urllib.request.Request(url, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = _json.loads(resp.read().decode())
                    return data.get("choices", [{}])[0].get("message", {}).get("content", "")
            except Exception:
                continue
    except Exception:
        pass
    return ""

def _decrypt_key(enc_text: str) -> str:
    if not enc_text:
        return ""
    try:
        import base64
        _SECRET = os.environ.get("LLM_SECRET_KEY", "ai-hacking-agent-llm-secret-2024")
        encrypted = base64.b64decode(enc_text.encode('ascii'))
        key_bytes = _SECRET.encode()
        decrypted = bytes([encrypted[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(encrypted))])
        return decrypted.decode('utf-8')
    except Exception:
        return ""

# ==================== 工具执行 ====================

def _run_nmap(target: str) -> dict:
    """执行Nmap端口扫描"""
    try:
        import subprocess
        nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        if not os.path.exists(nmap_path):
            nmap_path = "nmap"
        result = subprocess.run(
            [nmap_path, "-sT", "-T4", "--top-ports", "1000", target],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout + result.stderr
        # 解析开放端口
        open_ports = []
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    open_ports.append({"port": int(port), "service": service})
        return {"success": True, "open_ports": open_ports, "raw_output": output[:2000], "tool": "nmap"}
    except Exception as e:
        return {"success": False, "error": str(e), "tool": "nmap"}

def _run_nuclei(url: str) -> dict:
    """执行Nuclei漏洞扫描"""
    try:
        import subprocess
        nuclei_path = r"C:\Users\ASUS\tools\nuclei.exe"
        template_dir = r"C:\Users\ASUS\nuclei-templates"
        if not os.path.exists(nuclei_path):
            nuclei_path = "nuclei"
        cmd = [nuclei_path, "-u", url, "-t", template_dir, "-jsonl", "-nc", "-duc", "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        findings = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except Exception:
                    pass
        return {"success": True, "findings": findings, "count": len(findings), "tool": "nuclei"}
    except Exception as e:
        return {"success": False, "error": str(e), "tool": "nuclei"}

def _run_whatweb(target: str) -> dict:
    """指纹识别（简化版，基于HTTP响应头）"""
    try:
        import urllib.request
        url = f"http://{target}" if not target.startswith("http") else target
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = dict(resp.headers)
            server = headers.get("Server", "unknown")
            x_powered = headers.get("X-Powered-By", "")
            technologies = []
            if "nginx" in server.lower(): technologies.append("Nginx")
            if "apache" in server.lower(): technologies.append("Apache")
            if "iis" in server.lower(): technologies.append("IIS")
            if "php" in x_powered.lower(): technologies.append("PHP")
            if "asp.net" in x_powered.lower(): technologies.append("ASP.NET")
            if "node" in x_powered.lower(): technologies.append("Node.js")
            return {"success": True, "server": server, "x_powered_by": x_powered, "technologies": technologies, "status_code": resp.status, "tool": "whatweb-simplified"}
    except Exception as e:
        return {"success": False, "error": str(e), "tool": "whatweb-simplified"}

# ==================== AI决策逻辑 ====================

# 阶段定义
PHASES = [
    {"id": "recon", "name": "侦察阶段", "description": "端口扫描、服务识别、指纹检测"},
    {"id": "vuln_scan", "name": "漏洞扫描", "description": "Web漏洞扫描、服务漏洞检测"},
    {"id": "deep_test", "name": "深度测试", "description": "目录爆破、参数测试、认证测试"},
    {"id": "analysis", "name": "分析汇总", "description": "攻击路径分析、风险评估、报告生成"},
]

def _ai_make_decision(session: dict, observation: str) -> dict:
    """AI根据观察结果决策下一步动作"""
    phase = session.get("current_phase", "recon")
    results = session.get("results", {})
    if isinstance(results, str):
        try: results = json.loads(results)
        except: results = {}

    # 构建AI提示词
    prompt = f"""你是一个资深渗透测试专家。当前测试目标：{session['target']}
当前阶段：{phase}
已收集的信息：
{json.dumps(results, ensure_ascii=False, indent=2)[:3000]}

最新观察：{observation[:1000]}

请决策下一步最有价值的测试动作。严格按以下JSON格式回答（不要其他文字）：
{{
  "analysis": "对当前情况的简短分析",
  "decision": "下一步动作类型",
  "action": "具体执行的动作",
  "params": {{"key": "value"}},
  "expected_outcome": "预期发现什么",
  "confidence": 0.0-1.0
}}

可选动作类型：nmap_scan, nuclei_scan, whatweb_fingerprint, directory_bruteforce, service_enum, vuln_verify, skip_to_next_phase, finish_test
"""

    ai_response = _call_ai(prompt, max_tokens=800)
    if not ai_response:
        # AI不可用时的降级决策（基于规则）
        return _rule_based_decision(session, observation)

    # 解析AI的JSON响应
    try:
        # 提取JSON部分
        start = ai_response.find('{')
        end = ai_response.rfind('}') + 1
        if start >= 0 and end > start:
            decision = json.loads(ai_response[start:end])
            return decision
    except Exception:
        pass
    return _rule_based_decision(session, observation)

def _rule_based_decision(session: dict, observation: str) -> dict:
    """基于规则的降级决策"""
    phase = session.get("current_phase", "recon")
    results = session.get("results", {})
    if isinstance(results, str):
        try: results = json.loads(results)
        except: results = {}

    if phase == "recon":
        if "nmap" not in results:
            return {"analysis": "需要先进行端口扫描", "decision": "nmap_scan", "action": "执行Nmap端口扫描", "params": {"target": session["target"]}, "expected_outcome": "发现开放端口和服务", "confidence": 0.9}
        nmap_result = results.get("nmap", {})
        open_ports = nmap_result.get("open_ports", [])
        http_ports = [p for p in open_ports if p["port"] in [80, 443, 8080, 8443, 8000, 8888]]
        if http_ports and "whatweb" not in results:
            return {"analysis": f"发现HTTP端口，进行指纹识别", "decision": "whatweb_fingerprint", "action": "Web指纹识别", "params": {"target": session["target"]}, "expected_outcome": "识别Web服务器和技术栈", "confidence": 0.8}
        return {"analysis": "侦察完成，进入漏洞扫描阶段", "decision": "skip_to_next_phase", "action": "进入漏洞扫描阶段", "params": {}, "expected_outcome": "开始漏洞扫描", "confidence": 0.7}

    if phase == "vuln_scan":
        nmap_result = results.get("nmap", {})
        open_ports = nmap_result.get("open_ports", [])
        http_ports = [p for p in open_ports if p["port"] in [80, 443, 8080, 8443, 8000, 8888]]
        if http_ports and "nuclei" not in results:
            port = http_ports[0]["port"]
            scheme = "https" if port in [443, 8443] else "http"
            url = f"{scheme}://{session['target']}:{port}" if port not in [80, 443] else f"{scheme}://{session['target']}"
            return {"analysis": f"对HTTP服务进行漏洞扫描", "decision": "nuclei_scan", "action": "Nuclei漏洞扫描", "params": {"url": url}, "expected_outcome": "发现Web漏洞", "confidence": 0.85}
        return {"analysis": "漏洞扫描完成，进入深度测试阶段", "decision": "skip_to_next_phase", "action": "进入深度测试阶段", "params": {}, "expected_outcome": "开始深度测试", "confidence": 0.6}

    if phase == "deep_test":
        return {"analysis": "深度测试完成，进入分析汇总阶段", "decision": "skip_to_next_phase", "action": "进入分析汇总阶段", "params": {}, "expected_outcome": "生成报告", "confidence": 0.6}

    return {"analysis": "测试完成", "decision": "finish_test", "action": "完成测试", "params": {}, "expected_outcome": "生成最终报告", "confidence": 1.0}

def _execute_action(action: str, params: dict, target: str) -> dict:
    """执行决策的动作"""
    if action == "nmap_scan":
        return _run_nmap(params.get("target", target))
    elif action == "nuclei_scan":
        return _run_nuclei(params.get("url", f"http://{target}"))
    elif action == "whatweb_fingerprint":
        return _run_whatweb(params.get("target", target))
    elif action == "skip_to_next_phase":
        return {"success": True, "message": "进入下一阶段", "tool": "phase_transition"}
    elif action == "finish_test":
        return {"success": True, "message": "测试完成", "tool": "finish"}
    else:
        return {"success": False, "error": f"不支持的动作: {action}", "tool": "unknown"}

# ==================== API端点 ====================

@router.post("/sessions")
def create_session(req: TargetReq, user: dict = Depends(verify_auth)):
    """创建AI决策测试会话"""
    try:
        session_id = f"AID-{hashlib.md5(f'{req.target}{time.time()}'.encode()).hexdigest()[:10].upper()}"
        now = datetime.now().isoformat()
        conn = _get_db()
        conn.execute("""INSERT INTO sessions (id,target,status,current_phase,phase_index,decisions,results,attack_path,risk_score,created_at,updated_at,completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (session_id, req.target, "running", "recon", 0, "[]", "{}", "[]", 0, now, now, ""))
        conn.commit()
        conn.close()
        return _ok({"session_id": session_id, "target": req.target, "status": "running", "max_iterations": req.max_iterations, "phases": PHASES})
    except Exception as e:
        log.exception("create_session 错误")
        return _err(500, f"创建会话失败: {e}")

@router.post("/sessions/{session_id}/step")
def execute_step(session_id: str, req: DecisionReq = None, user: dict = Depends(verify_auth)):
    """执行一步AI决策（侦察→AI决策→执行→记录）"""
    try:
        conn = _get_db()
        session = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if not session:
            conn.close()
            return _err(404, "会话不存在")
        session = dict(session)
        if session["status"] != "running":
            conn.close()
            return _err(400, f"会话状态为{session['status']}，无法执行")

        results = json.loads(session["results"]) if session["results"] else {}
        decisions = json.loads(session["decisions"]) if session["decisions"] else []
        attack_path = json.loads(session["attack_path"]) if session["attack_path"] else []

        # 1. AI决策
        observation = req.observation if req else ""
        if not observation:
            observation = f"当前阶段{session['current_phase']}，已执行{len(decisions)}步决策"
        decision = _ai_make_decision(session, observation)

        # 2. 执行动作
        action_result = _execute_action(decision.get("action", ""), decision.get("params", {}), session["target"])

        # 3. 记录决策
        decision_id = f"DEC-{hashlib.md5(f'{session_id}{time.time()}'.encode()).hexdigest()[:8].upper()}"
        now = datetime.now().isoformat()
        conn.execute("""INSERT INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (decision_id, session_id, session["current_phase"], observation[:2000],
             decision.get("analysis", "")[:2000], decision.get("decision", "")[:500],
             decision.get("action", "")[:200], json.dumps(decision.get("params", {}), ensure_ascii=False)[:1000],
             json.dumps(action_result, ensure_ascii=False)[:2000], now))

        decisions.append({"id": decision_id, "phase": session["current_phase"], "decision": decision.get("decision", ""), "action": decision.get("action", ""), "confidence": decision.get("confidence", 0)})

        # 4. 更新结果
        tool = action_result.get("tool", "unknown")
        if action_result.get("success"):
            results[tool] = action_result
            # 更新攻击路径
            if decision.get("action") not in ["skip_to_next_phase", "finish_test"]:
                attack_path.append({"phase": session["current_phase"], "action": decision.get("action", ""), "tool": tool, "findings": len(action_result.get("findings", action_result.get("open_ports", [])))})

        # 5. 阶段转换
        new_phase = session["current_phase"]
        phase_index = session["phase_index"]
        if decision.get("action") == "skip_to_next_phase":
            phase_index += 1
            if phase_index < len(PHASES):
                new_phase = PHASES[phase_index]["id"]
        elif decision.get("action") == "finish_test":
            new_phase = "completed"

        # 6. 风险评分
        risk_score = _calculate_risk(results)

        # 7. 检查是否完成
        status = "running"
        completed_at = ""
        if new_phase == "completed" or len(decisions) >= 20:
            status = "completed"
            completed_at = now

        conn.execute("""UPDATE sessions SET status=?, current_phase=?, phase_index=?, decisions=?, results=?, attack_path=?, risk_score=?, updated_at=?, completed_at=? WHERE id=?""",
            (status, new_phase, phase_index, json.dumps(decisions, ensure_ascii=False),
             json.dumps(results, ensure_ascii=False), json.dumps(attack_path, ensure_ascii=False),
             risk_score, now, completed_at, session_id))
        conn.commit()
        conn.close()

        return _ok({
            "session_id": session_id,
            "step": len(decisions),
            "phase": new_phase,
            "ai_decision": decision,
            "action_result": {k: v for k, v in action_result.items() if k not in ["raw_output"]},
            "risk_score": risk_score,
            "status": status
        })
    except Exception as e:
        log.exception("execute_step 错误")
        return _err(500, f"执行步骤失败: {e}")

@router.post("/sessions/{session_id}/auto")
def auto_run(session_id: str, user: dict = Depends(verify_auth)):
    """自动执行完整测试（多步迭代直到完成）"""
    try:
        conn = _get_db()
        session = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if not session:
            conn.close()
            return _err(404, "会话不存在")
        session = dict(session)
        conn.close()

        all_steps = []
        max_steps = 15
        for i in range(max_steps):
            # 执行一步
            step_result = execute_step(session_id, DecisionReq(observation=f"自动迭代第{i+1}步"))
            if hasattr(step_result, 'body'):
                import json as _json
                step_data = _json.loads(step_result.body)
            else:
                step_data = step_result
            all_steps.append(step_data.get("data", {}))
            if step_data.get("data", {}).get("status") == "completed":
                break
            time.sleep(0.5)

        return _ok({"session_id": session_id, "steps_executed": len(all_steps), "steps": all_steps, "final_status": all_steps[-1].get("status") if all_steps else "unknown"})
    except Exception as e:
        log.exception("auto_run 错误")
        return _err(500, f"自动运行失败: {e}")

@router.get("/sessions")
def list_sessions(user: dict = Depends(verify_auth)):
    """获取所有测试会话"""
    try:
        conn = _get_db()
        rows = conn.execute("SELECT id,target,status,current_phase,phase_index,risk_score,created_at,updated_at,completed_at FROM sessions ORDER BY created_at DESC LIMIT 50").fetchall()
        conn.close()
        return _ok({"sessions": [dict(r) for r in rows], "total": len(rows)})
    except Exception as e:
        return _err(500, f"获取会话列表失败: {e}")

@router.get("/sessions/{session_id}")
def get_session(session_id: str, user: dict = Depends(verify_auth)):
    """获取会话详情"""
    try:
        conn = _get_db()
        session = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if not session:
            conn.close()
            return _err(404, "会话不存在")
        session = dict(session)
        session["results"] = json.loads(session["results"]) if session["results"] else {}
        session["decisions"] = json.loads(session["decisions"]) if session["decisions"] else []
        session["attack_path"] = json.loads(session["attack_path"]) if session["attack_path"] else []
        decisions = conn.execute("SELECT * FROM decisions WHERE session_id=? ORDER BY created_at ASC", (session_id,)).fetchall()
        conn.close()
        session["decision_details"] = [dict(d) for d in decisions]
        return _ok(session)
    except Exception as e:
        return _err(500, f"获取会话详情失败: {e}")

@router.get("/sessions/{session_id}/report")
def generate_report(session_id: str, user: dict = Depends(verify_auth)):
    """生成AI决策测试报告"""
    try:
        conn = _get_db()
        session = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if not session:
            conn.close()
            return _err(404, "会话不存在")
        session = dict(session)
        results = json.loads(session["results"]) if session["results"] else {}
        decisions = json.loads(session["decisions"]) if session["decisions"] else []
        attack_path = json.loads(session["attack_path"]) if session["attack_path"] else []
        conn.close()

        # 统计发现
        total_ports = 0
        total_vulns = 0
        technologies = []
        if "nmap" in results:
            total_ports = len(results["nmap"].get("open_ports", []))
        if "nuclei" in results:
            total_vulns = results["nuclei"].get("count", 0)
        if "whatweb-simplified" in results:
            technologies = results["whatweb-simplified"].get("technologies", [])

        report = {
            "session_id": session_id,
            "target": session["target"],
            "executive_summary": {
                "risk_score": session["risk_score"],
                "risk_level": _risk_level(session["risk_score"]),
                "open_ports": total_ports,
                "vulnerabilities_found": total_vulns,
                "technologies": technologies,
                "ai_decisions_made": len(decisions),
                "attack_path_length": len(attack_path),
            },
            "attack_path": attack_path,
            "ai_decisions": decisions,
            "detailed_results": {k: {kk: vv for kk, vv in v.items() if kk != "raw_output"} if isinstance(v, dict) else v for k, v in results.items()},
            "recommendations": _generate_recommendations(results, session["risk_score"]),
            "generated_at": datetime.now().isoformat(),
        }
        return _ok(report)
    except Exception as e:
        log.exception("generate_report 错误")
        return _err(500, f"生成报告失败: {e}")

def _calculate_risk(results: dict) -> int:
    """计算风险评分0-100"""
    score = 0
    if "nmap" in results:
        ports = results["nmap"].get("open_ports", [])
        score += min(len(ports) * 3, 30)
        high_risk_ports = [p for p in ports if p["port"] in [21, 23, 25, 139, 445, 1433, 3306, 3389, 5432, 6379, 27017]]
        score += len(high_risk_ports) * 5
    if "nuclei" in results:
        vulns = results["nuclei"].get("count", 0)
        score += min(vulns * 5, 40)
    return min(score, 100)

def _risk_level(score: int) -> str:
    if score >= 80: return "严重"
    if score >= 60: return "高危"
    if score >= 40: return "中危"
    if score >= 20: return "低危"
    return "信息"

def _generate_recommendations(results: dict, risk_score: int) -> List[str]:
    """生成修复建议"""
    recs = []
    if "nmap" in results:
        ports = results["nmap"].get("open_ports", [])
        high_risk = [p for p in ports if p["port"] in [21, 23, 139, 445, 3389]]
        if high_risk:
            recs.append(f"关闭不必要的高风险端口: {', '.join([str(p['port']) for p in high_risk])}")
        if any(p["port"] == 22 for p in ports):
            recs.append("SSH服务：禁用密码登录，启用密钥认证，限制登录IP")
        if any(p["port"] in [3306, 5432, 1433] for p in ports):
            recs.append("数据库端口不应暴露在公网，应限制为内网访问")
    if "nuclei" in results and results["nuclei"].get("count", 0) > 0:
        recs.append(f"发现{results['nuclei']['count']}个漏洞，建议立即修复并重新扫描验证")
    if risk_score >= 60:
        recs.append("整体风险较高，建议进行全面的安全加固和渗透测试")
    if not recs:
        recs.append("未发现明显风险，建议持续监控和定期扫描")
    return recs

@router.delete("/sessions/{session_id}")
def delete_session(session_id: str, user: dict = Depends(verify_auth)):
    """删除测试会话"""
    try:
        conn = _get_db()
        conn.execute("DELETE FROM decisions WHERE session_id=?", (session_id,))
        conn.execute("DELETE FROM sessions WHERE id=?", (session_id,))
        conn.commit()
        conn.close()
        return _ok({"session_id": session_id, "status": "deleted"})
    except Exception as e:
        return _err(500, f"删除会话失败: {e}")

@router.get("/dashboard")
def dashboard(user: dict = Depends(verify_auth)):
    """AI决策引擎仪表盘"""
    try:
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        completed = conn.execute("SELECT COUNT(*) FROM sessions WHERE status='completed'").fetchone()[0]
        running = conn.execute("SELECT COUNT(*) FROM sessions WHERE status='running'").fetchone()[0]
        avg_risk = conn.execute("SELECT COALESCE(AVG(risk_score),0) FROM sessions WHERE status='completed'").fetchone()[0]
        total_decisions = conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
        recent = conn.execute("SELECT id,target,status,risk_score,created_at FROM sessions ORDER BY created_at DESC LIMIT 10").fetchall()
        conn.close()
        return _ok({
            "total_sessions": total,
            "completed": completed,
            "running": running,
            "avg_risk_score": round(avg_risk, 1),
            "total_ai_decisions": total_decisions,
            "recent_sessions": [dict(r) for r in recent],
        })
    except Exception as e:
        return _err(500, f"获取仪表盘失败: {e}")
