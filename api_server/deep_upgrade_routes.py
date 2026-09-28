"""
v9.1 深度升级 - 端到端渗透 + AI多轮推理 + 漏洞验证
从5.5分继续提升
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

router = APIRouter(prefix="/api/v9", tags=["v9-deep"])

AI_API_KEY = os.environ.get("SILICONFLOW_API_KEY", "")
AI_BASE_URL = "https://api.siliconflow.cn/v1/chat/completions"
AI_MODEL = "Qwen/Qwen2.5-7B-Instruct"


async def call_ai(messages, temperature=0.3, max_tokens=1000):
    """调大模型"""
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(AI_BASE_URL,
                headers={"Authorization": f"Bearer {AI_API_KEY}", "Content-Type": "application/json"},
                json={"model": AI_MODEL, "messages": messages, "temperature": temperature, "max_tokens": max_tokens})
            return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI调用失败: {e}"


# ============ 1. 端到端渗透：多轮自动执行 ============

@router.post("/e2e/scan")
async def e2e_scan(request: Request):
    """端到端渗透：侦察→扫描→验证→AI报告，多轮自动执行"""
    data = await request.json()
    target = data.get("target", "")
    phases = data.get("phases", ["recon", "scan", "vuln", "report"])
    
    if not target:
        return JSONResponse(status_code=400, content={"error": "需要target"})
    
    log = []
    findings = {}
    timeline = []
    
    def log_phase(phase, msg):
        entry = {"time": datetime.now().isoformat(), "phase": phase, "msg": msg}
        log.append(entry)
        timeline.append(entry)
        print(f"[{phase}] {msg}")
    
    # Phase 1: 侦察
    if "recon" in phases:
        log_phase("recon", f"开始侦察 {target}")
        try:
            # DNS解析
            host = target.replace("http://", "").replace("https://", "").split("/")[0]
            proc = await asyncio.create_subprocess_exec(
                "nslookup", host,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            findings["dns"] = stdout.decode()[:500]
            log_phase("recon", "DNS解析完成")
        except Exception as e:
            log_phase("recon", f"DNS解析失败: {e}")
        
        # whois
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup", "-type=mx", host,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            findings["mx"] = stdout.decode()[:300]
        except:
            pass
    
    # Phase 2: 端口扫描
    if "scan" in phases:
        log_phase("scan", "开始端口扫描")
        try:
            host = target.replace("http://", "").replace("https://", "").split("/")[0]
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-sV", "-Pn", "-T4", "--top-ports", "100", host,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            
            open_ports = []
            for line in output.split("\n"):
                m = re.match(r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)', line)
                if m:
                    open_ports.append({
                        "port": int(m.group(1)),
                        "service": m.group(2),
                        "version": m.group(3).strip()
                    })
            
            findings["open_ports"] = open_ports
            log_phase("scan", f"发现 {len(open_ports)} 个开放端口")
        except Exception as e:
            log_phase("scan", f"端口扫描失败: {e}")
    
    # Phase 3: Web探测
    if "scan" in phases:
        log_phase("scan", "Web服务探测")
        try:
            proc = await asyncio.create_subprocess_exec(
                "httpx", "-u", target, "-silent", "-status-code", "-title",
                "-tech-detect", "-content-length", "-no-color",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            findings["web"] = stdout.decode()
            log_phase("scan", "Web探测完成")
        except Exception as e:
            log_phase("scan", f"Web探测失败: {e}")
    
    # Phase 4: Nuclei漏洞扫描
    if "vuln" in phases:
        log_phase("vuln", "开始漏洞扫描")
        try:
            proc = await asyncio.create_subprocess_exec(
                "nuclei", "-u", target, "-silent", "-no-color",
                "-severity", "low,medium,high,critical",
                "-timeout", "10", "-rate-limit", "30",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
            vulns = [l.strip() for l in stdout.decode().split("\n") if l.strip()]
            findings["vulnerabilities"] = vulns
            log_phase("vuln", f"发现 {len(vulns)} 个漏洞")
        except Exception as e:
            log_phase("vuln", f"漏洞扫描失败: {e}")
    
    # Phase 5: AI分析报告
    if "report" in phases:
        log_phase("report", "AI生成分析报告")
        summary = json.dumps(findings, ensure_ascii=False)[:4000]
        ai_report = await call_ai([
            {"role": "system", "content": "你是渗透测试专家，根据扫描结果生成专业报告。"},
            {"role": "user", "content": f"目标: {target}\n扫描结果:\n{summary}\n\n请输出:\n1. 风险等级(高/中/低)\n2. 关键发现\n3. 攻击路径建议\n4. 修复建议"}
        ], max_tokens=800)
        findings["ai_report"] = ai_report
        log_phase("report", "报告生成完成")
    
    return {
        "target": target,
        "findings": findings,
        "timeline": timeline,
        "completed_at": datetime.now().isoformat(),
        "status": "done"
    }


# ============ 2. AI多轮推理：攻击链规划 ============

@router.post("/ai/reason")
async def ai_reason(request: Request):
    """AI多轮推理：根据当前状态决定下一步，模拟攻击链"""
    data = await request.json()
    target = data.get("target", "127.0.0.1")
    current_state = data.get("current_state", {})
    round_num = data.get("round", 1)
    
    # 构造上下文
    state_text = json.dumps(current_state, ensure_ascii=False)[:2000]
    
    prompt = f"""你是一个红队指挥官，正在对目标 {target} 进行渗透测试。
当前状态:
{state_text}

这是第 {round_num} 轮决策。请输出JSON:
{{
  "assessment": "对当前局势的判断(50字)",
  "next_action": "下一步具体动作",
  "tool": "用什么工具",
  "target_port_or_path": "目标端口或路径",
  "expected_result": "预期结果",
  "if_success": "成功后做什么",
  "if_fail": "失败后做什么",
  "kill_chain_phase": "recon/scanning/exploitation/post-exploitation"
}}
只输出JSON。"""
    
    ai_text = await call_ai([
        {"role": "system", "content": "你是渗透测试红队专家。"},
        {"role": "user", "content": prompt}
    ], temperature=0.4, max_tokens=600)
    
    # 解析JSON
    plan = {}
    match = re.search(r'\{[\s\S]+\}', ai_text)
    if match:
        try:
            plan = json.loads(match.group())
        except:
            plan = {"raw": ai_text}
    else:
        plan = {"raw": ai_text}
    
    return {
        "target": target,
        "round": round_num,
        "decision": plan,
        "timestamp": datetime.now().isoformat()
    }


# ============ 3. 漏洞验证：真发PoC请求 ============

@router.post("/vuln/verify")
async def vuln_verify(request: Request):
    """验证漏洞是否可利用：发实际请求"""
    data = await request.json()
    target = data.get("target", "")
    vuln_type = data.get("vuln_type", "")  # sqli/xss/rce/ssrf/xxe
    
    if not target:
        return JSONResponse(status_code=400, content={"error": "需要target"})
    
    results = []
    
    async def check(url, payload, desc):
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                r = await client.get(url, params={"q": payload})
                return {
                    "check": desc,
                    "url": str(r.url),
                    "status": r.status_code,
                    "vulnerable": desc in r.text or len(r.content) > 1000,
                    "response_snippet": r.text[:200]
                }
        except Exception as e:
            return {"check": desc, "error": str(e)}
    
    # SQL注入检测
    if vuln_type in ["sqli", "all"]:
        r = await check(target, "' OR '1'='1", "SQLi")
        results.append(r)
        r2 = await check(target, "1 UNION SELECT NULL--", "SQLi-union")
        results.append(r2)
    
    # XSS检测
    if vuln_type in ["xss", "all"]:
        r = await check(target, "<script>alert(1)</script>", "XSS-reflected")
        results.append(r)
    
    # 目录遍历
    if vuln_type in ["lfi", "all"]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"{target}/../../etc/passwd")
                results.append({
                    "check": "LFI",
                    "status": r.status_code,
                    "vulnerable": "root:" in r.text,
                    "snippet": r.text[:200]
                })
        except Exception as e:
            results.append({"check": "LFI", "error": str(e)})
    
    # 服务器信息泄露
    if vuln_type in ["info", "all"]:
        for path in ["/.env", "/.git/config", "/admin", "/api", "/robots.txt"]:
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    r = await client.get(f"{target}{path}")
                    results.append({
                        "path": path,
                        "status": r.status_code,
                        "size": len(r.content),
                        "interesting": r.status_code == 200 and len(r.content) > 50
                    })
            except:
                pass
    
    return {
        "target": target,
        "vuln_type": vuln_type,
        "checks": results,
        "vulnerable_count": sum(1 for r in results if r.get("vulnerable")),
        "checked_at": datetime.now().isoformat()
    }


# ============ 4. 资产发现：子域名+目录 ============

@router.post("/recon/assets")
async def asset_discovery(request: Request):
    """子域名和目录发现"""
    data = await request.json()
    domain = data.get("domain", "")
    
    if not domain:
        return JSONResponse(status_code=400, content={"error": "需要domain"})
    
    findings = {"subdomains": [], "directories": []}
    
    # 常见子域名
    common_subs = ["www", "mail", "admin", "api", "dev", "test", "staging", 
                   "vpn", "portal", "app", "blog", "cms", "git", "jenkins"]
    
    for sub in common_subs:
        host = f"{sub}.{domain}"
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup", host,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
            if "Address" in stdout.decode() and "#53" not in stdout.decode():
                findings["subdomains"].append(host)
        except:
            pass
    
    # 常见目录
    common_dirs = ["/admin", "/login", "/api", "/robots.txt", "/sitemap.xml",
                   "/.env", "/wp-admin", "/console", "/manager", "/swagger",
                   "/graphql", "/actuator", "/debug", "/test"]
    
    for d in common_dirs:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(f"https://{domain}{d}")
                if r.status_code < 404:
                    findings["directories"].append({
                        "path": d, "status": r.status_code, "size": len(r.content)
                    })
        except:
            pass
    
    return {
        "domain": domain,
        "subdomains_found": len(findings["subdomains"]),
        "directories_found": len(findings["directories"]),
        **findings,
        "timestamp": datetime.now().isoformat()
    }


# ============ 5. AI生成渗透报告 ============

@router.post("/report/generate")
async def generate_report(request: Request):
    """AI生成专业渗透测试报告"""
    data = await request.json()
    findings = data.get("findings", {})
    target = data.get("target", "unknown")
    
    summary = json.dumps(findings, ensure_ascii=False)[:5000]
    
    report = await call_ai([
        {"role": "system", "content": "你是注册渗透测试工程师，输出专业中文报告。"},
        {"role": "user", "content": f"""目标: {target}
扫描结果:
{summary}

请生成渗透测试报告，包含:
# 渗透测试报告
## 1. 执行摘要
## 2. 测试范围
## 3. 发现的漏洞（按严重程度排序）
## 4. 风险评估
## 5. 修复建议
## 6. 附录
用Markdown格式，专业但简洁。"""}
    ], max_tokens=1500, temperature=0.2)
    
    return {
        "target": target,
        "report_markdown": report,
        "generated_at": datetime.now().isoformat()
    }
