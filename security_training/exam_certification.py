# -*- coding: utf-8 -*-
"""
exam_certification.py — 考试与认证（第14轮·方向2）。

题库（500+题，单选/多选/判断/实操）、组卷策略（随机/固定/难度自适应）、
在线考试、自动评分、证书生成（PDF模板文本）、证书验证（序列号/校验码）、
考试监控、成绩分析。全部内存模拟。
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional

_TOPICS = [
    ("网络协议", "端口与服务", "TCP三次握手", "UDP无连接"),
    ("访问控制", "RBAC模型", "最小权限原则", "默认拒绝"),
    ("加密算法", "AES对称", "RSA非对称", "哈希不可逆"),
    ("Web安全", "SQL注入", "XSS反射型", "CSRF跨站"),
    ("数据安全", "数据脱敏", "传输加密", "存储加密"),
    ("云安全", "责任共担", "IAM权限", "安全组规则"),
    ("社会工程", "钓鱼识别", "信息核实", "不轻信紧急"),
    ("合规", "等保三级", "个保法", "事件通报时限"),
    ("运维安全", "补丁管理", "日志审计", "备份恢复"),
    ("开发安全", "输入校验", "输出编码", "依赖扫描"),
]


def _gen_bank() -> List[Dict[str, Any]]:
    bank = []
    qid = 1
    for block in range(5):  # 5 组 × 10 主题 × 约11题 ≈ 550 题
        for ti, topic in enumerate(_TOPICS):
            t0 = topic[0]
            # 6 单选
            for k in range(6):
                bank.append({
                    "qid": f"Q{qid:04d}", "type": "single", "topic": t0,
                    "stem": f"[{t0}-单选{block}-{k+1}] 关于「{topic[(k % 3) + 1]}」下列说法正确的是？",
                    "options": ["A. 正确描述项", "B. 常见误区", "C. 反向干扰", "D. 无关选项"],
                    "answer": "A", "score": 2, "difficulty": ["入门", "基础", "进阶", "进阶", "专家"][k % 5],
                })
                qid += 1
            # 3 多选
            for k in range(3):
                bank.append({
                    "qid": f"Q{qid:04d}", "type": "multi", "topic": t0,
                    "stem": f"[{t0}-多选{block}-{k+1}] 下列属于「{topic[(k % 3) + 1]}」常见措施的有（多选）？",
                    "options": ["A. 措施甲", "B. 措施乙", "C. 措施丙", "D. 已被淘汰项"],
                    "answer": "A,B,C", "score": 4, "difficulty": ["基础", "进阶", "专家"][k % 3],
                })
                qid += 1
            # 1 判断
            bank.append({
                "qid": f"Q{qid:04d}", "type": "judge", "topic": t0,
                "stem": f"[{t0}-判断{block}] 判断：「{topic[1]}」是企业安全的基础要求。",
                "options": ["正确", "错误"], "answer": "正确", "score": 1, "difficulty": "入门",
            })
            qid += 1
            # 1 实操（描述题，人工/规则评分）
            bank.append({
                "qid": f"Q{qid:04d}", "type": "practical", "topic": t0,
                "stem": f"[{t0}-实操{block}] 请描述一次针对「{topic[2]}」的排查步骤与输出证据要点。",
                "options": [], "answer": "评分要点：范围/步骤/证据/修复建议", "score": 10,
                "difficulty": "专家",
            })
            qid += 1
    return bank


EXAM_BANK: Dict[str, Dict[str, Any]] = {q["qid"]: q for q in _gen_bank()}

EXAM_PAPERS: Dict[str, Dict[str, Any]] = {
    "PAPER-BASIC": {"name": "新员工安全意识认证（CSTA）", "total_score": 100,
                    "pass_score": 70, "duration_min": 60, "strategy": "random"},
    "PAPER-PRO": {"name": "企业安全工程师认证（CSE）", "total_score": 100,
                  "pass_score": 75, "duration_min": 120, "strategy": "adaptive"},
    "PAPER-COMPLIANCE": {"name": "合规与等保专员认证（CCP）", "total_score": 100,
                         "pass_score": 75, "duration_min": 90, "strategy": "fixed"},
}


class ExamCertManager:
    """考试与认证管理器。"""

    def __init__(self) -> None:
        self.papers: Dict[str, Dict[str, Any]] = {}
        self.grades: Dict[str, Dict[str, Any]] = {}
        self.certs: Dict[str, Dict[str, Any]] = {}
        self.monitor: Dict[str, Dict[str, Any]] = {}

    # ---- 题库 ----
    def bank_stats(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        by_topic: Dict[str, int] = {}
        for q in EXAM_BANK.values():
            by_type[q["type"]] = by_type.get(q["type"], 0) + 1
            by_topic[q["topic"]] = by_topic.get(q["topic"], 0) + 1
        return {"total": len(EXAM_BANK), "by_type": by_type,
                "by_topic": by_topic, "papers": EXAM_PAPERS}

    # ---- 组卷 ----
    def build_paper(self, paper_code: str,
                    strategy: Optional[str] = None) -> Dict[str, Any]:
        spec = EXAM_PAPERS.get(paper_code)
        if not spec:
            return {"ok": False, "error": "试卷模板不存在"}
        strategy = strategy or spec["strategy"]
        pool = list(EXAM_BANK.values())
        # 简易确定性抽样（按 qid 哈希分桶）
        ordered = sorted(pool, key=lambda q: int(q["qid"][1:]))
        per = max(20, len(ordered) // 25)
        picked = []
        used = set()
        if strategy == "fixed":
            picked = ordered[:per]
        elif strategy == "adaptive":
            picked = [q for q in ordered if q["difficulty"] in ("进阶", "专家")][:per]
        else:  # random / 默认：均匀抽
            step = max(1, len(ordered) // per)
            picked = ordered[::step][:per]
        items = [{"qid": q["qid"], "type": q["type"], "topic": q["topic"],
                  "stem": q["stem"], "options": q["options"],
                  "score": q["score"], "difficulty": q["difficulty"]} for q in picked]
        pid = f"P{int(time.time())%1000000:06d}"
        self.papers[pid] = {"paper_id": pid, "spec": paper_code, "strategy": strategy,
                            "questions": items, "question_count": len(items)}
        return {"ok": True, "paper_id": pid, "strategy": strategy,
                "question_count": len(items), "questions": items,
                "pass_score": spec["pass_score"], "duration_min": spec["duration_min"]}

    # ---- 在线考试与自动评分 ----
    def grade_exam(self, student: str, paper_id: str,
                   answers: Dict[str, str]) -> Dict[str, Any]:
        paper = self.papers.get(paper_id)
        if not paper:
            return {"passed": False, "error": "试卷不存在"}
        spec = EXAM_PAPERS[paper["spec"]]
        got = 0.0
        detail = []
        for q in paper["questions"]:
            full = EXAM_BANK[q["qid"]]
            user_ans = answers.get(q["qid"], "")
            if q["type"] == "practical":
                # 实操题：按提交长度给半分（模拟人工+规则）
                pts = min(q["score"], len(user_ans) / 20)
                hit = None
            elif q["type"] == "judge":
                hit = user_ans.strip() == full["answer"]
                pts = q["score"] if hit else 0
            elif q["type"] == "multi":
                want = set(full["answer"].split(","))
                have = {x.strip() for x in user_ans.replace("，", ",").split(",") if x.strip()}
                hit = have == want
                pts = q["score"] if hit else 0
            else:
                hit = user_ans.strip().upper() == full["answer"].strip().upper()
                pts = q["score"] if hit else 0
            got += pts
            detail.append({"qid": q["qid"], "type": q["type"],
                           "your": user_ans, "correct": full["answer"],
                           "points": round(pts, 1), "full": q["score"]})
        total = sum(q["score"] for q in paper["questions"])
        score = round(got / max(1, total) * 100, 1)
        passed = score >= spec["pass_score"]
        gid = f"G{int(time.time())%1000000:06d}"
        self.grades[gid] = {
            "grade_id": gid, "student": student, "paper_id": paper_id,
            "paper_name": spec["name"], "score": score, "total_score": total,
            "pass_score": spec["pass_score"], "passed": passed,
            "duration_min": spec["duration_min"],
            "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"), "detail": detail,
        }
        result = dict(self.grades[gid])
        if passed:
            cert = self._issue_cert(student, spec["name"], score, gid)
            result["certificate"] = cert
        return result

    # ---- 证书 ----
    def _issue_cert(self, student: str, exam_name: str, score: float,
                    grade_id: str) -> Dict[str, Any]:
        serial = "CERT-" + hashlib.md5(
            f"{student}{exam_name}{time.time()}".encode()).hexdigest().upper()[:12]
        checksum = hashlib.sha1(serial.encode()).hexdigest()[:8].upper()
        cert_id = f"C{int(time.time())%1000000:06d}"
        cert = {
            "cert_id": cert_id, "serial": serial, "checksum": checksum,
            "student": student, "exam_name": exam_name, "score": score,
            "grade_id": grade_id, "issued_at": time.strftime("%Y-%m-%d"),
            "valid_until": time.strftime("%Y-%m-%d",
                                         time.localtime(time.time() + 365 * 86400)),
            "qr_payload": f"https://verify.local/c/{serial}",
            "pdf_template": self._pdf_template(serial, student, exam_name, score),
        }
        self.certs[cert_id] = cert
        return {k: cert[k] for k in ("cert_id", "serial", "checksum", "issued_at",
                                     "valid_until", "qr_payload")}

    def _pdf_template(self, serial: str, student: str, exam: str,
                      score: float) -> str:
        return (
            "%PDF-1.4 (text certificate mock)\n"
            "==============================================\n"
            "        企业网络安全培训认证中心\n"
            f"  证书编号: {serial}\n"
            f"  持证人: {student}\n"
            f"  认证项目: {exam}\n"
            f"  成绩: {score}\n"
            "  验证方式: 扫描二维码 / 输入编号\n"
            "=============================================="
        )

    def verify_cert(self, serial: str, checksum: Optional[str] = None) -> Dict[str, Any]:
        for c in self.certs.values():
            if c["serial"] == serial:
                ok = (checksum is None) or (c["checksum"] == checksum)
                return {"valid": ok, "serial": serial,
                        "student": c["student"], "exam_name": c["exam_name"],
                        "issued_at": c["issued_at"], "valid_until": c["valid_until"]}
        return {"valid": False, "error": "证书不存在或已吊销"}

    # ---- 监控 ----
    def start_monitor(self, student: str, paper_id: str) -> Dict[str, Any]:
        mid = f"M{int(time.time())%1000000:06d}"
        self.monitor[mid] = {"monitor_id": mid, "student": student,
                             "paper_id": paper_id, "events": [],
                             "started_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        return {"monitor_id": mid, "policy": "切屏>3次告警/复制粘贴记录/IP归属校验"}

    def log_event(self, monitor_id: str, event: str) -> Dict[str, Any]:
        m = self.monitor.get(monitor_id)
        if not m:
            return {"ok": False}
        m["events"].append({"event": event,
                            "at": time.strftime("%Y-%m-%d %H:%M:%S")})
        risk = "high" if event in ("tab_switch", "copy_detected") else "low"
        return {"ok": True, "event_count": len(m["events"]), "risk_level": risk}

    # ---- 成绩分析 ----
    def score_analytics(self) -> Dict[str, Any]:
        rows = list(self.grades.values())
        if not rows:
            return {"exams": 0, "avg": 0, "pass_rate": 0, "distribution": {}}
        scores = [r["score"] for r in rows]
        dist = {"优秀(>=90)": 0, "良好(75-89)": 0, "合格(60-74)": 0, "不合格(<60)": 0}
        for s in scores:
            if s >= 90:
                dist["优秀(>=90)"] += 1
            elif s >= 75:
                dist["良好(75-89)"] += 1
            elif s >= 60:
                dist["合格(60-74)"] += 1
            else:
                dist["不合格(<60)"] += 1
        passed = sum(1 for r in rows if r["passed"])
        return {"exams": len(rows),
                "avg": round(sum(scores) / len(scores), 1),
                "max": max(scores), "min": min(scores),
                "pass_rate": round(passed / len(rows) * 100, 1),
                "distribution": dist}
