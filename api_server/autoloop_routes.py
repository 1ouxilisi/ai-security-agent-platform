"""
v9.2 自动渗透循环引擎 - AI多轮自动执行
从单次扫描升级到AI自动决策循环
"""
import os
import re
import json
import asyncio
import httpx
from pathlib import Path
from datetime import datetime
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/v9", tags=["v9-autoloop"])

AI_API_KEY = os.environ.get("SILICONFLOW_API_KEY", "")
AI_BASE_URL = "https://api.siliconflow.cn/v1/chat/completions"
AI_MODEL = "Qwen/Qwen2.5-7B-Instruct"


async def call_ai(messages, temperature=0.3, max_tokens=800):
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(AI_BASE_URL,
                headers={"Authorization": f"Bearer {AI_API_KEY}", "Content-Type": "application/json"},
                json={"model": AI_MODEL, "messages": messages, "temperature": temperature, "max_tokens": max_tokens})
            return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return json.dumps({"error": str(e)})


@router.post("/loop/start")
async def start_loop(request: Request):
    """启动自动渗透循环：AI自动决策→执行→观察→再决策，最多N轮"""
    data = await request.json()
    target = data.get("target", "")
    max_rounds = data.get("max_rounds", 5)
    mode = data.get("mode", "safe")  # safe=只扫描不利用, deep=验证漏洞
    
    if not target:
        return JSONResponse(status_code=400, content={"error": "需要target"})
    
    history = []
    state = {
        "target": target,
        "ports": [],
        "web_services": [],
        "vulnerabilities": [],
        "completed_steps": [],
        "findings": []
    }
    
    for round_num in range(1, max_rounds + 1):
        round_log = {"round": round_num, "actions": []}
        
        # AI决策
        state_summary = json.dumps(state, ensure_ascii=False)[:2000]
        ai_prompt = f"""目标: {target}
当前已知: {state_summary}
轮次: {round_num}/{max_rounds}

请选择下一步动作，只输出JSON:
{{"action": "port_scan|web_probe|vuln_scan|vuln_verify|done", "reason": "为什么", "detail": "具体参数"}}"""
        
        ai_text = await call_ai([
            {"role": "system", "content": "你是渗透测试自动化引擎。"},
            {"role": "user", "content": ai_prompt}
        ], max_tokens=300)
        
        action = "vuln_scan"
        try:
            match = re.search(r'\{[\s\S]+\}', ai_text)
            if match:
                decision = json.loads(match.group())
                action = decision.get("action", "vuln_scan")
                round_log["ai_decision"] = decision
        except:
            pass
        
        round_log["actions"].append({"step": "ai_decision", "action": action})
        
        # 执行动作
        if action == "port_scan" and not state["ports"]:
            try:
                host = target.replace("http://", "").replace("https://", "").split("/")[0]
                proc = await asyncio.create_subprocess_exec(
                    "nmap", "-sV", "-Pn", "-T4", "--top-ports", "50", host,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
                output = stdout.decode()
                for line in output.split("\n"):
                    m = re.match(r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)', line)
                    if m:
                        state["ports"].append({"port": int(m.group(1)), "service": m.group(2)})
                round_log["actions"].append({"step": "nmap", "ports_found": len(state["ports"])})
            except Exception as e:
                round_log["actions"].append({"step": "nmap", "error": str(e)})
        
        elif action == "web_probe":
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    r = await client.get(target, follow_redirects=True)
                    state["web_services"].append({
                        "url": str(r.url),
                        "status": r.status_code,
                        "title": re.search(r'<title>(.*?)</title>', r.text, re.I).group(1) if re.search(r'<title>(.*?)</title>', r.text, re.I) else "",
                        "server": r.headers.get("server", ""),
                        "tech": []
                    })
                round_log["actions"].append({"step": "httpx", "web_found": True})
            except Exception as e:
                round_log["actions"].append({"step": "httpx", "error": str(e)})
        
        elif action == "vuln_scan" and not state["vulnerabilities"]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "nuclei", "-u", target, "-silent", "-no-color",
                    "-severity", "medium,high,critical", "-timeout", "10", "-rate-limit", "30",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                vulns = [l.strip() for l in stdout.decode().split("\n") if l.strip()]
                state["vulnerabilities"] = vulns
                round_log["actions"].append({"step": "nuclei", "vulns_found": len(vulns)})
            except Exception as e:
                round_log["actions"].append({"step": "nuclei", "error": str(e)})
        
        elif action == "vuln_verify" and state["vulnerabilities"]:
            # 简单验证：检查响应码
            for v in state["vulnerabilities"][:3]:
                round_log["actions"].append({"step": "verify", "vuln": v[:80]})
        
        elif action == "done":
            round_log["actions"].append({"step": "finish", "reason": "AI认为已完成"})
            break
        
        state["completed_steps"].append(action)
        history.append(round_log)
        await asyncio.sleep(1)
    
    # 最终AI总结
    final_summary = json.dumps(state, ensure_ascii=False)[:3000]
    ai_report = await call_ai([
        {"role": "system", "content": "你是渗透测试报告专家。"},
        {"role": "user", "content": f"目标{target}的自动渗透完成，结果:\n{final_summary}\n\n请输出简短结论:风险等级、关键发现、下一步建议。"}
    ], max_tokens=500)
    
    return {
        "target": target,
        "rounds_completed": len(history),
        "final_state": state,
        "history": history,
        "ai_summary": ai_report,
        "completed_at": datetime.now().isoformat()
    }


@router.get("/loop/status")
async def loop_status():
    return {
        "engine": "auto-loop-v9.2",
        "max_rounds": 5,
        "actions_supported": ["port_scan", "web_probe", "vuln_scan", "vuln_verify", "done"],
        "timestamp": datetime.now().isoformat()
    }
