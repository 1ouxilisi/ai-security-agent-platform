# -*- coding: utf-8 -*-
"""
lab_environment.py — 在线实验与靶场集成（第14轮·方向2）。

集成 DVWA / OWASP Juice Shop / WebGoat / OWASP Benchmark 等知名靶场；
提供实验管理、指导书、自动评分、报告生成、沙箱与进度跟踪。
全部内存模拟，不真实拉起容器。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

RANGE_LIBRARY: Dict[str, Dict[str, Any]] = {
    "dvwa": {"name": "DVWA", "stack": "PHP/MySQL", "level": "基础",
             "desc": "Damn Vulnerable Web Application，经典Web漏洞演练靶场",
             "vuln_types": ["SQLi", "XSS", "CSRF", "文件上传", "命令执行"]},
    "juice-shop": {"name": "OWASP Juice Shop", "stack": "Node.js/Angular",
                   "level": "进阶", "desc": "现代单页应用安全挑战，覆盖OWASP Top10",
                   "vuln_types": ["注入", "失效访问控制", "敏感数据泄露", "XSS", "安全错误配置"]},
    "webgoat": {"name": "OWASP WebGoat", "stack": "Java/Spring", "level": "基础",
                "desc": "教学型靶场，按课程章节讲解漏洞原理",
                "vuln_types": ["HTTP基础", "注入", "身份认证缺陷", "会话", "不安全的直接对象引用"]},
    "benchmark": {"name": "OWASP Benchmark", "stack": "Java", "level": "专家",
                  "desc": "漏洞检测工具的基准测试集，含1万+可判定用例",
                  "vuln_types": ["SQLi", "命令注入", "LDAP注入", "XPath注入", "路径遍历"]},
    "mutillidae": {"name": "Mutillidae II", "stack": "PHP", "level": "基础",
                   "desc": "开源PHP漏洞集合，教学友好",
                   "vuln_types": ["SQLi", "XSS", "CSRF", "文件包含"]},
    "vulhub": {"name": "Vulhub", "stack": "Docker-Compose", "level": "进阶",
               "desc": "基于Docker的漏洞环境集合，一键复现CVE",
               "vuln_types": ["RCE", "反序列化", "框架漏洞", "组件漏洞"]},
}


def _build_labs() -> List[Dict[str, Any]]:
    labs = []
    templates = [
        ("SQL注入入门", "dvwa", "low", 30, ["low"]),
        ("反射型XSS实战", "dvwa", "low", 25, ["low", "medium"]),
        ("Juice Shop 注册逻辑缺陷", "juice-shop", "easy", 45, ["easy"]),
        ("Juice Shop 越权访问", "juice-shop", "medium", 60, ["medium"]),
        ("WebGoat 认证绕过", "webgoat", "basic", 40, ["basic"]),
        ("Benchmark SQLi 用例分析", "benchmark", "expert", 90, ["expert"]),
        ("文件上传绕过", "dvwa", "medium", 35, ["medium", "high"]),
        ("命令注入靶场", "mutillidae", "medium", 40, ["medium"]),
        ("Vulhub 复现 Log4Shell", "vulhub", "hard", 120, ["hard"]),
        ("Vulhub 复现 Spring4Shell", "vulhub", "hard", 120, ["hard"]),
        ("CSRF 漏洞挖掘", "dvwa", "medium", 30, ["medium"]),
        ("不安全直接对象引用", "webgoat", "medium", 35, ["medium"]),
    ]
    lid = 1
    for title, range_key, level, minutes, flags in templates:
        steps = [
            f"步骤{1}：阅读背景并访问靶场入口 {range_key}://lab-{lid}.internal",
            f"步骤{2}：按指导书观察请求/响应，定位可疑参数",
            f"步骤{3}：提交验证 payload（教学环境内）并截图证据",
            f"步骤{4}：总结根因与修复建议",
        ]
        labs.append({
            "lab_id": f"LAB{lid:03d}", "title": title, "range": range_key,
            "range_name": RANGE_LIBRARY[range_key]["name"],
            "level": level, "estimated_min": minutes,
            "instruction": steps, "checkpoints": flags,
            "skills": RANGE_LIBRARY[range_key]["vuln_types"][:3],
        })
        lid += 1
    return labs


LAB_LIBRARY: Dict[str, Dict[str, Any]] = {l["lab_id"]: l for l in _build_labs()}


class LabEnvironmentManager:
    """在线实验管理器。"""

    def __init__(self) -> None:
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.reports: Dict[str, Dict[str, Any]] = {}

    def list_labs(self, range_key: Optional[str] = None) -> Dict[str, Any]:
        items = list(LAB_LIBRARY.values())
        if range_key:
            items = [l for l in items if l["range"] == range_key]
        return {"labs": items, "total": len(items), "ranges": RANGE_LIBRARY}

    def start_lab(self, student: str, lab_id: str) -> Dict[str, Any]:
        lab = LAB_LIBRARY.get(lab_id)
        if not lab:
            return {"ok": False, "error": "实验不存在"}
        sid = f"S{int(time.time())%1000000:06d}"
        self.sessions[sid] = {
            "session_id": sid, "student": student, "lab_id": lab_id,
            "lab_title": lab["title"], "status": "running",
            "sandbox": {"image": lab["range"], "cpu": "1core", "mem": "1GB",
                        "network": "isolated-lab"},
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "checkpoints_done": [],
        }
        return {"ok": True, "session": self.sessions[sid]}

    def submit_checkpoint(self, session_id: str,
                         checkpoint: str, evidence: str) -> Dict[str, Any]:
        s = self.sessions.get(session_id)
        if not s:
            return {"ok": False, "error": "会话不存在"}
        s["checkpoints_done"].append({"checkpoint": checkpoint,
                                     "evidence_hash": str(hash(evidence)) % 99999,
                                     "at": time.strftime("%Y-%m-%d %H:%M:%S")})
        lab = LAB_LIBRARY[s["lab_id"]]
        total = len(lab["checkpoints"])
        done = len(s["checkpoints_done"])
        if done >= total:
            s["status"] = "finished"
        return {"ok": True, "checkpoints_done": done, "checkpoints_total": total,
                "status": s["status"]}

    def auto_grade(self, session_id: str) -> Dict[str, Any]:
        s = self.sessions.get(session_id)
        if not s:
            return {"score": 0, "error": "会话不存在"}
        lab = LAB_LIBRARY[s["lab_id"]]
        total = len(lab["checkpoints"])
        done = len(s["checkpoints_done"])
        # 自动评分：完成检查点比例 * 80 + 基础分20
        score = round(20 + (done / max(1, total)) * 80, 1)
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D"
        report_id = f"RPT{int(time.time())%1000000:06d}"
        self.reports[report_id] = {
            "report_id": report_id, "session_id": session_id,
            "student": s["student"], "lab_title": s["lab_title"],
            "score": score, "grade": grade,
            "checkpoints_total": total, "checkpoints_done": done,
            "summary": f"完成 {done}/{total} 个检查点，自动评级 {grade}",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return {"score": score, "grade": grade, "report_id": report_id,
                "report": self.reports[report_id]}

    def list_reports(self, student: Optional[str] = None) -> Dict[str, Any]:
        rows = list(self.reports.values())
        if student:
            rows = [r for r in rows if r["student"] == student]
        avg = round(sum(r["score"] for r in rows) / max(1, len(rows)), 1)
        return {"reports": rows, "total": len(rows), "avg_score": avg}

    def sandbox_health(self) -> Dict[str, Any]:
        running = [s for s in self.sessions.values() if s["status"] == "running"]
        return {"sandbox_pool": "isolated-lab", "running": len(running),
                "capacity": 50, "available": 50 - len(running),
                "status": "healthy" if len(running) < 50 else "full"}
