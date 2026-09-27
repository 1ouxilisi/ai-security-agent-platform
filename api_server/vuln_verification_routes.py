# -*- coding: utf-8 -*-
"""
vuln_verification_routes.py - 漏洞验证去重引擎

核心能力：
1. 漏洞去重 - 基于指纹的精确去重
2. 漏洞验证 - 重新请求确认漏洞真实存在
3. 误报过滤 - 基于规则的误报识别
4. 漏洞聚合 - 按主机/服务/类型聚合
5. 质量评分 - 可信度评分0-100
6. 漏洞知识库 - 常见漏洞的验证方法库

路由前缀：/api/v1/vuln-verify
"""
from __future__ import annotations
import os, sys, json, sqlite3, time, hashlib, re
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import log

async def verify_auth() -> dict:
    return {"user_id": "admin", "username": "admin", "role": "admin"}

router = APIRouter(prefix="/api/v1/vuln-verify", tags=["漏洞验证去重引擎"])

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "vuln_verify.db")

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
    c.execute("""CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        fingerprint TEXT UNIQUE,
        target TEXT,
        url TEXT,
        vuln_type TEXT,
        severity TEXT,
        title TEXT,
        description TEXT,
        evidence TEXT,
        cvss REAL DEFAULT 0,
        confidence INTEGER DEFAULT 50,
        verified INTEGER DEFAULT 0,
        false_positive INTEGER DEFAULT 0,
        params TEXT,
        request_data TEXT,
        response_snippet TEXT,
        created_at TEXT,
        verified_at TEXT,
        tags TEXT
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_vuln_target ON vulnerabilities(target)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_vuln_type ON vulnerabilities(vuln_type)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_vuln_fingerprint ON vulnerabilities(fingerprint)")
    conn.commit()
    conn.close()

_init_db()

# ==================== 漏洞验证方法库 ====================

VERIFICATION_METHODS = {
    "sql_injection": {
        "name": "SQL注入验证",
        "method": "在参数后添加单引号，观察响应是否变化或出现SQL错误",
        "payloads": ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "1 AND 1=1", "1 AND 1=2"],
        "indicators": ["sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite", "unclosed quotation", "sqlstate"],
        "false_positive_indicators": ["404", "not found", "invalid parameter", "parameter is required"],
    },
    "xss": {
        "name": "XSS验证",
        "method": "注入XSS payload，检查响应中是否包含未转义的payload",
        "payloads": ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "javascript:alert(1)", "<img src=x onerror=alert(1)>"],
        "indicators": ["<script>alert(1)</script>", "onerror=alert", "javascript:alert"],
        "false_positive_indicators": ["&lt;script&gt;", "content-security-policy", "x-xss-protection"],
    },
    "path_traversal": {
        "name": "路径遍历验证",
        "method": "注入../序列，检查是否能读取系统文件",
        "payloads": ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"],
        "indicators": ["root:x:", "[fonts]", "bin/bash", "daemon:"],
        "false_positive_indicators": ["403", "forbidden", "access denied"],
    },
    "command_injection": {
        "name": "命令注入验证",
        "method": "注入命令分隔符，观察响应时间或输出变化",
        "payloads": ["; id", "&& whoami", "| cat /etc/passwd", "`id`", "$(id)"],
        "indicators": ["uid=", "gid=", "root:", "bin/bash"],
        "false_positive_indicators": ["command not found", "syntax error"],
    },
    "open_redirect": {
        "name": "开放重定向验证",
        "method": "检查重定向参数是否可控制跳转到外部URL",
        "payloads": ["https://evil.com", "//evil.com", "/\\evil.com"],
        "indicators": ["location: https://evil.com", "302", "redirect"],
        "false_positive_indicators": [],
    },
    "sensitive_file": {
        "name": "敏感文件泄露验证",
        "method": "直接请求敏感文件，检查是否可访问",
        "files": ["/.env", "/config.json", "/wp-config.php", "/.git/config", "/backup.sql", "/phpinfo.php", "/server-status"],
        "indicators": ["db_password", "api_key", "database", "<?php", "phpinfo"],
        "false_positive_indicators": ["404", "not found", "403"],
    },
    "weak_auth": {
        "name": "弱认证验证",
        "method": "尝试常见弱密码，检查是否可登录",
        "credentials": ["admin:admin", "admin:password", "root:root", "test:test", "admin:123456"],
        "indicators": ["welcome", "dashboard", "logout", "登录成功"],
        "false_positive_indicators": ["invalid credentials", "login failed", "too many attempts"],
    },
}

# ==================== 误报过滤规则 ====================

FALSE_POSITIVE_RULES = [
    {"name": "404误报", "pattern": r"404|not found|页面不存在", "type": "response", "action": "mark_fp"},
    {"name": "403误报", "pattern": r"403|forbidden|访问被拒绝", "type": "response", "action": "mark_fp"},
    {"name": "WAF拦截", "pattern": r"waf|blocked|request rejected|安全狗|云锁", "type": "response", "action": "mark_unreliable"},
    {"name": "通用错误页", "pattern": r"error page|an error occurred|出错了", "type": "response", "action": "mark_unreliable"},
    {"name": "登录跳转", "pattern": r"login|signin|登录|redirect.*login", "type": "response", "action": "mark_unreliable"},
]

# ==================== 请求模型 ====================

class VulnIngestReq(BaseModel):
    target: str
    url: str = ""
    vuln_type: str
    severity: str = "中"
    title: str = ""
    description: str = ""
    evidence: str = ""
    params: dict = {}
    request_data: dict = {}
    response_snippet: str = ""
    tags: List[str] = []

class VerifyReq(BaseModel):
    vuln_id: str
    method: str = "auto"

class BatchIngestReq(BaseModel):
    target: str
    vulnerabilities: List[dict] = []

# ==================== 核心函数 ====================

def _generate_fingerprint(target: str, url: str, vuln_type: str, params: dict) -> str:
    """生成漏洞指纹用于去重"""
    # 标准化URL（去掉查询参数中的值，保留参数名）
    normalized_url = re.sub(r'=([^&]+)', '=', url) if url else url
    raw = f"{target}|{normalized_url}|{vuln_type}|{json.dumps(params, sort_keys=True)}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]

def _calculate_confidence(vuln: dict, verification_result: dict = None) -> int:
    """计算漏洞可信度评分0-100"""
    score = 50  # 基础分
    # 有明确证据 +20
    if vuln.get("evidence") or vuln.get("response_snippet"):
        score += 20
    # 有请求数据 +10
    if vuln.get("request_data"):
        score += 10
    # 验证通过 +20
    if verification_result and verification_result.get("verified"):
        score += 20
    # 误报标记 -50
    if verification_result and verification_result.get("false_positive"):
        score -= 50
    return max(0, min(100, score))

def _check_false_positive(response_text: str) -> dict:
    """检查是否为误报"""
    for rule in FALSE_POSITIVE_RULES:
        if re.search(rule["pattern"], response_text, re.IGNORECASE):
            return {"is_fp": True, "rule": rule["name"], "action": rule["action"]}
    return {"is_fp": False}

def _verify_vulnerability_http(vuln: dict) -> dict:
    """通过HTTP请求验证漏洞"""
    try:
        import urllib.request
        url = vuln.get("url", "")
        if not url:
            return {"verified": False, "reason": "无URL"}
        # 简单验证：重新请求，检查响应是否包含漏洞特征
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; VulnVerify/1.0)"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode('utf-8', errors='ignore')[:5000]
            status = resp.status
        # 检查误报
        fp_check = _check_false_positive(body)
        if fp_check["is_fp"]:
            return {"verified": False, "false_positive": True, "reason": fp_check["rule"], "status_code": status}
        # 检查漏洞特征是否存在
        vuln_type = vuln.get("vuln_type", "")
        method = VERIFICATION_METHODS.get(vuln_type, {})
        indicators = method.get("indicators", [])
        found_indicators = [ind for ind in indicators if ind.lower() in body.lower()]
        if found_indicators:
            return {"verified": True, "confidence_bonus": 20, "indicators_found": found_indicators, "status_code": status}
        return {"verified": False, "reason": "未检测到漏洞特征", "status_code": status}
    except Exception as e:
        return {"verified": False, "reason": f"验证请求失败: {str(e)}"}

# ==================== API端点 ====================

@router.post("/ingest")
def ingest_vulnerability(req: VulnIngestReq, user: dict = Depends(verify_auth)):
    """录入单个漏洞（自动去重）"""
    try:
        fingerprint = _generate_fingerprint(req.target, req.url, req.vuln_type, req.params)
        conn = _get_db()
        # 检查是否已存在
        existing = conn.execute("SELECT id, confidence FROM vulnerabilities WHERE fingerprint=?", (fingerprint,)).fetchone()
        if existing:
            conn.close()
            return _ok({"status": "duplicate", "vuln_id": existing["id"], "message": "漏洞已存在（指纹去重）", "confidence": existing["confidence"]})
        
        vuln_id = f"VULN-{hashlib.md5(f'{req.target}{time.time()}'.encode()).hexdigest()[:10].upper()}"
        now = datetime.now().isoformat()
        confidence = _calculate_confidence(req.dict())
        
        conn.execute("""INSERT INTO vulnerabilities (id,fingerprint,target,url,vuln_type,severity,title,description,evidence,cvss,confidence,verified,false_positive,params,request_data,response_snippet,created_at,verified_at,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (vuln_id, fingerprint, req.target, req.url, req.vuln_type, req.severity,
             req.title or f"{req.vuln_type} - {req.url}", req.description, req.evidence,
             0, confidence, 0, 0, json.dumps(req.params, ensure_ascii=False),
             json.dumps(req.request_data, ensure_ascii=False), req.response_snippet,
             now, "", json.dumps(req.tags, ensure_ascii=False)))
        conn.commit()
        conn.close()
        return _ok({"status": "new", "vuln_id": vuln_id, "fingerprint": fingerprint, "confidence": confidence, "message": "漏洞录入成功"})
    except Exception as e:
        log.exception("ingest_vulnerability 错误")
        return _err(500, f"录入失败: {e}")

@router.post("/batch-ingest")
def batch_ingest(req: BatchIngestReq, user: dict = Depends(verify_auth)):
    """批量录入漏洞（自动去重）"""
    try:
        results = {"new": [], "duplicate": [], "failed": []}
        for vuln in req.vulnerabilities:
            try:
                vreq = VulnIngestReq(
                    target=req.target,
                    url=vuln.get("url", ""),
                    vuln_type=vuln.get("type", vuln.get("vuln_type", "unknown")),
                    severity=vuln.get("severity", "中"),
                    title=vuln.get("title", ""),
                    description=vuln.get("description", ""),
                    evidence=vuln.get("evidence", ""),
                    params=vuln.get("params", {}),
                    response_snippet=vuln.get("response_snippet", ""),
                    tags=vuln.get("tags", []),
                )
                result = ingest_vulnerability(vreq, user)
                if hasattr(result, 'body'):
                    import json as _json
                    data = _json.loads(result.body)["data"]
                else:
                    data = result["data"]
                if data["status"] == "new":
                    results["new"].append(data["vuln_id"])
                elif data["status"] == "duplicate":
                    results["duplicate"].append(data["vuln_id"])
            except Exception as e:
                results["failed"].append({"vuln": vuln.get("title", "unknown"), "error": str(e)})
        return _ok({**results, "total": len(req.vulnerabilities), "new_count": len(results["new"]), "duplicate_count": len(results["duplicate"])})
    except Exception as e:
        return _err(500, f"批量录入失败: {e}")

@router.post("/verify/{vuln_id}")
def verify_vulnerability(vuln_id: str, req: VerifyReq = None, user: dict = Depends(verify_auth)):
    """验证单个漏洞"""
    try:
        conn = _get_db()
        vuln = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vuln_id,)).fetchone()
        if not vuln:
            conn.close()
            return _err(404, "漏洞不存在")
        vuln = dict(vuln)
        conn.close()
        
        # 执行验证
        verification_result = _verify_vulnerability_http(vuln)
        now = datetime.now().isoformat()
        
        # 更新漏洞状态
        new_confidence = _calculate_confidence(vuln, verification_result)
        conn = _get_db()
        conn.execute("UPDATE vulnerabilities SET verified=?, false_positive=?, confidence=?, verified_at=? WHERE id=?",
            (1 if verification_result.get("verified") else 0,
             1 if verification_result.get("false_positive") else 0,
             new_confidence, now, vuln_id))
        conn.commit()
        conn.close()
        
        return _ok({"vuln_id": vuln_id, "verification": verification_result, "new_confidence": new_confidence, "verified_at": now})
    except Exception as e:
        log.exception("verify_vulnerability 错误")
        return _err(500, f"验证失败: {e}")

@router.post("/verify-all")
def verify_all(target: str = "", user: dict = Depends(verify_auth)):
    """批量验证所有未验证漏洞"""
    try:
        conn = _get_db()
        if target:
            vulns = conn.execute("SELECT id FROM vulnerabilities WHERE verified=0 AND target=?", (target,)).fetchall()
        else:
            vulns = conn.execute("SELECT id FROM vulnerabilities WHERE verified=0").fetchall()
        conn.close()
        
        results = {"verified": [], "false_positives": [], "failed": [], "total": len(vulns)}
        for v in vulns[:20]:  # 限制最多20个，避免超时
            try:
                result = verify_vulnerability(v["id"], VerifyReq(), user)
                if hasattr(result, 'body'):
                    import json as _json
                    data = _json.loads(result.body)["data"]
                else:
                    data = result["data"]
                if data["verification"].get("verified"):
                    results["verified"].append(v["id"])
                elif data["verification"].get("false_positive"):
                    results["false_positives"].append(v["id"])
            except Exception:
                results["failed"].append(v["id"])
        return _ok(results)
    except Exception as e:
        return _err(500, f"批量验证失败: {e}")

@router.get("/vulnerabilities")
def list_vulnerabilities(target: str = "", severity: str = "", vuln_type: str = "", verified: str = "", min_confidence: int = 0, limit: int = 100, user: dict = Depends(verify_auth)):
    """获取漏洞列表（支持多维度筛选）"""
    try:
        conn = _get_db()
        query = "SELECT * FROM vulnerabilities WHERE 1=1"
        params = []
        if target:
            query += " AND target=?"
            params.append(target)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if vuln_type:
            query += " AND vuln_type=?"
            params.append(vuln_type)
        if verified == "true":
            query += " AND verified=1"
        elif verified == "false":
            query += " AND verified=0"
        if min_confidence > 0:
            query += " AND confidence>=?"
            params.append(min_confidence)
        query += " ORDER BY confidence DESC, created_at DESC LIMIT ?"
        params.append(limit)
        
        vulns = conn.execute(query, params).fetchall()
        # 统计
        stats = conn.execute("""SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN verified=1 THEN 1 ELSE 0 END) as verified,
            SUM(CASE WHEN false_positive=1 THEN 1 ELSE 0 END) as false_positives,
            AVG(confidence) as avg_confidence
            FROM vulnerabilities""").fetchone()
        conn.close()
        
        return _ok({
            "vulnerabilities": [dict(v) for v in vulns],
            "total": len(vulns),
            "stats": {"total": stats["total"], "verified": stats["verified"] or 0, "false_positives": stats["false_positives"] or 0, "avg_confidence": round(stats["avg_confidence"] or 0, 1)}
        })
    except Exception as e:
        return _err(500, f"获取漏洞列表失败: {e}")

@router.get("/vulnerabilities/{vuln_id}")
def get_vulnerability(vuln_id: str, user: dict = Depends(verify_auth)):
    """获取漏洞详情"""
    try:
        conn = _get_db()
        vuln = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vuln_id,)).fetchone()
        conn.close()
        if not vuln:
            return _err(404, "漏洞不存在")
        vuln = dict(vuln)
        vuln["params"] = json.loads(vuln["params"]) if vuln["params"] else {}
        vuln["request_data"] = json.loads(vuln["request_data"]) if vuln["request_data"] else {}
        vuln["tags"] = json.loads(vuln["tags"]) if vuln["tags"] else []
        # 获取验证方法
        method = VERIFICATION_METHODS.get(vuln["vuln_type"], {})
        vuln["verification_method"] = method
        return _ok(vuln)
    except Exception as e:
        return _err(500, f"获取漏洞详情失败: {e}")

@router.delete("/vulnerabilities/{vuln_id}")
def delete_vulnerability(vuln_id: str, user: dict = Depends(verify_auth)):
    """删除漏洞"""
    try:
        conn = _get_db()
        conn.execute("DELETE FROM vulnerabilities WHERE id=?", (vuln_id,))
        conn.commit()
        conn.close()
        return _ok({"vuln_id": vuln_id, "status": "deleted"})
    except Exception as e:
        return _err(500, f"删除失败: {e}")

@router.post("/deduplicate")
def deduplicate(target: str = "", user: dict = Depends(verify_auth)):
    """对已有漏洞进行去重清理"""
    try:
        conn = _get_db()
        if target:
            vulns = conn.execute("SELECT id, fingerprint FROM vulnerabilities WHERE target=? ORDER BY created_at ASC", (target,)).fetchall()
        else:
            vulns = conn.execute("SELECT id, fingerprint FROM vulnerabilities ORDER BY created_at ASC").fetchall()
        
        seen = set()
        duplicates = []
        for v in vulns:
            if v["fingerprint"] in seen:
                duplicates.append(v["id"])
                conn.execute("DELETE FROM vulnerabilities WHERE id=?", (v["id"],))
            else:
                seen.add(v["fingerprint"])
        conn.commit()
        conn.close()
        return _ok({"removed_duplicates": len(duplicates), "duplicate_ids": duplicates[:50]})
    except Exception as e:
        return _err(500, f"去重失败: {e}")

@router.get("/dashboard")
def dashboard(user: dict = Depends(verify_auth)):
    """漏洞验证仪表盘"""
    try:
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        verified = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE verified=1").fetchone()[0]
        fp = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE false_positive=1").fetchone()[0]
        avg_conf = conn.execute("SELECT AVG(confidence) FROM vulnerabilities").fetchone()[0] or 0
        by_severity = conn.execute("SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity").fetchall()
        by_type = conn.execute("SELECT vuln_type, COUNT(*) as cnt FROM vulnerabilities GROUP BY vuln_type ORDER BY cnt DESC LIMIT 10").fetchall()
        by_target = conn.execute("SELECT target, COUNT(*) as cnt FROM vulnerabilities GROUP BY target ORDER BY cnt DESC LIMIT 10").fetchall()
        high_conf = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE confidence>=80").fetchone()[0]
        low_conf = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE confidence<40").fetchone()[0]
        conn.close()
        
        return _ok({
            "total": total,
            "verified": verified,
            "false_positives": fp,
            "avg_confidence": round(avg_conf, 1),
            "high_confidence_count": high_conf,
            "low_confidence_count": low_conf,
            "by_severity": [dict(r) for r in by_severity],
            "by_type": [dict(r) for r in by_type],
            "by_target": [dict(r) for r in by_target],
            "verification_rate": round(verified/total*100, 1) if total > 0 else 0,
            "fp_rate": round(fp/total*100, 1) if total > 0 else 0,
        })
    except Exception as e:
        return _err(500, f"获取仪表盘失败: {e}")

@router.get("/verification-methods")
def list_verification_methods(user: dict = Depends(verify_auth)):
    """获取支持的漏洞验证方法列表"""
    return _ok({"methods": {k: {"name": v.get("name", k), "method": v.get("method", ""), "payload_count": len(v.get("payloads", v.get("files", []))), "indicator_count": len(v.get("indicators", []))} for k, v in VERIFICATION_METHODS.items()}, "total": len(VERIFICATION_METHODS)})
