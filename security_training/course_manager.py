# -*- coding: utf-8 -*-
"""
course_manager.py — 课程管理（第14轮·方向2）。

功能：课程库（50+内置课程模板）、六大分类、章节管理、资源、测验题库、
学习路径、推荐算法、进度跟踪。全部内存字典模拟，无第三方硬依赖。
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional

try:
    import random  # noqa: F401  (保留以便扩展)
except Exception:  # pragma: no cover
    random = None  # type: ignore


COURSE_CATEGORIES: Dict[str, Dict[str, str]] = {
    "network_security": {"name": "网络安全", "icon": "🌐", "order": 1},
    "data_security": {"name": "数据安全", "icon": "🗄️", "order": 2},
    "cloud_security": {"name": "云安全", "icon": "☁️", "order": 3},
    "social_engineering": {"name": "社会工程", "icon": "🎭", "order": 4},
    "compliance": {"name": "合规", "icon": "⚖️", "order": 5},
    "dev_security": {"name": "开发安全", "icon": "💻", "order": 6},
}

_DIFFICULTIES = ["入门", "基础", "进阶", "专家"]


def _build_courses() -> List[Dict[str, Any]]:
    """生成 54 门内置课程模板。"""
    seeds: List[Dict[str, Any]] = []
    pool = {
        "network_security": [
            ("网络基础与OSI模型", 90, "入门"), ("防火墙与访问控制", 120, "基础"),
            ("入侵检测与IDS/IPS", 150, "进阶"), ("VPN与远程接入安全", 110, "基础"),
            ("WiFi与无线网络安全", 100, "基础"), ("内网渗透基础", 180, "进阶"),
            ("DDoS防护与CDN", 90, "入门"), ("零信任网络架构", 160, "进阶"),
            ("流量分析与Wireshark", 140, "进阶"), ("DNS安全与劫持防御", 100, "基础"),
            ("边界防护体系设计", 200, "专家"), ("网络分段与微隔离", 170, "专家"),
            ("ARP欺骗与中间人攻击", 120, "进阶"), ("安全组与ACL最佳实践", 80, "入门"),
        ],
        "data_security": [
            ("数据分类分级实战", 120, "基础"), ("数据加密基础", 130, "进阶"),
            ("数据库审计与脱敏", 140, "进阶"), ("DLP数据防泄露", 150, "进阶"),
            ("个人信息保护合规", 110, "基础"), ("数据生命周期管理", 100, "基础"),
            ("数据备份与恢复", 90, "入门"), ("隐私计算导论", 160, "专家"),
            ("跨境数据流动", 120, "进阶"), ("数据销毁与介质清理", 70, "入门"),
            ("密钥管理实践", 140, "进阶"), ("数据安全风险评估", 130, "进阶"),
        ],
        "cloud_security": [
            ("云安全责任共担模型", 90, "入门"), ("AWS安全最佳实践", 160, "进阶"),
            ("Azure安全配置", 150, "进阶"), ("阿里云安全实战", 150, "进阶"),
            ("容器与K8s安全", 180, "专家"), ("Serverless安全", 130, "进阶"),
            ("云存储桶错误配置", 80, "入门"), ("云IAM与权限治理", 140, "进阶"),
            ("云日志与审计", 110, "基础"), ("云工作负载CWPP", 170, "专家"),
            ("云安全态势CSPM", 160, "专家"), ("混合云安全边界", 150, "进阶"),
        ],
        "social_engineering": [
            ("钓鱼邮件识别", 60, "入门"), ("社会工程学心理学", 90, "基础"),
            ("尾随与物理渗透", 70, "入门"), ("电话诈骗与话术分析", 80, "基础"),
            ("假身份与 pretexting", 90, "基础"), ("BEC商业邮件诈骗", 100, "进阶"),
            ("USB投放与摆渡攻击", 80, "基础"), ("社交媒体情报收集", 110, "进阶"),
            ("语音克隆与AI诈骗", 120, "进阶"), ("办公室反侦察意识", 50, "入门"),
            ("钓鱼演练后处置", 90, "进阶"), ("勒索软件预防意识", 100, "基础"),
        ],
        "compliance": [
            ("等保2.0基础", 110, "基础"), ("ISO27001体系", 150, "进阶"),
            ("GDPR合规要点", 120, "进阶"), ("网络安全法解读", 90, "入门"),
            ("数据安全法与个保法", 110, "基础"), ("PCI-DSS支付合规", 130, "进阶"),
            ("合规审计准备", 120, "进阶"), ("供应链安全SBOM", 140, "进阶"),
            ("监管报送与事件通报", 80, "基础"), ("内部制度建设", 90, "基础"),
            ("审计取证合规边界", 130, "专家"), ("合规管理体系ISO27701", 160, "专家"),
        ],
        "dev_security": [
            ("安全编码导论", 100, "基础"), ("SQL注入与防护", 120, "进阶"),
            ("XSS跨站脚本防御", 110, "进阶"), ("CSRF与会话安全", 90, "基础"),
            ("安全SDLC落地", 140, "进阶"), ("依赖与供应链安全", 130, "进阶"),
            ("代码安全审计", 160, "专家"), ("密钥与Secrets管理", 100, "基础"),
            ("API安全设计", 140, "进阶"), ("安全测试左移", 120, "进阶"),
            ("反序列化漏洞", 150, "专家"), ("DevSecOps流水线", 170, "专家"),
        ],
    }
    cid = 1
    for cat, items in pool.items():
        for title, minutes, diff in items:
            ch_count = max(3, minutes // 25)
            chapters = [
                {"chapter_id": f"C{cid:03d}-{i+1}", "title": f"第{i+1}章 · {title}·节",
                 "duration_min": round(minutes / ch_count), "resources": [
                     {"type": "video", "name": f"视频{i+1}.mp4"},
                     {"type": "doc", "name": f"讲义{i+1}.pdf"},
                 ]}
                for i in range(ch_count)
            ]
            quiz = [
                {"qid": f"Q{cid:03d}-{j}", "type": "single",
                 "stem": f"《{title}》考点{j}：下列哪项最符合该知识点？",
                 "options": ["选项A", "选项B", "选项C", "选项D"], "answer": "A",
                 "score": 5}
                for j in range(1, 5)
            ]
            seeds.append({
                "course_id": f"CRS{cid:03d}", "title": title, "category": cat,
                "difficulty": diff, "duration_min": minutes, "chapters": chapters,
                "quiz": quiz, "tags": [cat, diff],
                "pass_score": 60, "cert_eligible": diff in ("进阶", "专家"),
                "created_at": f"2026-01-{(cid % 27) + 1:02d}",
            })
            cid += 1
    return seeds


COURSE_LIBRARY: Dict[str, Dict[str, Any]] = {c["course_id"]: c for c in _build_courses()}

LEARNING_PATHS: List[Dict[str, Any]] = [
    {"path_id": "LP-BEGINNER", "name": "新员工安全意识入门", "level": "入门",
     "course_ids": ["CRS001", "CRS037", "CRS049", "CRS025", "CRS013"]},
    {"path_id": "LP-BACKEND", "name": "后端开发安全工程师", "level": "进阶",
     "course_ids": ["CRS049", "CRS050", "CRS051", "CRS052", "CRS055", "CRS060"]},
    {"path_id": "LP-CLOUD", "name": "云安全架构师", "level": "专家",
     "course_ids": ["CRS025", "CRS029", "CRS030", "CRS035", "CRS036"]},
    {"path_id": "LP-COMPLIANCE", "name": "合规与等保专员", "level": "进阶",
     "course_ids": ["CRS037", "CRS038", "CRS041", "CRS045", "CRS046"]},
]


class CourseManager:
    """课程管理器。"""

    def __init__(self) -> None:
        self.progress: Dict[str, Dict[str, Any]] = {}

    # ---- 查询 ----
    def list_courses(self, category: Optional[str] = None,
                     difficulty: Optional[str] = None) -> Dict[str, Any]:
        items = list(COURSE_LIBRARY.values())
        if category:
            items = [c for c in items if c["category"] == category]
        if difficulty:
            items = [c for c in items if c["difficulty"] == difficulty]
        flat = [{k: c[k] for k in
                 ("course_id", "title", "category", "difficulty",
                  "duration_min", "pass_score", "cert_eligible")}
                for c in items]
        return {"courses": flat, "total": len(flat),
                "categories": COURSE_CATEGORIES}

    def get_course(self, course_id: str) -> Dict[str, Any]:
        c = COURSE_LIBRARY.get(course_id)
        if not c:
            return {"found": False}
        return {"found": True, "course": c, "chapter_count": len(c["chapters"]),
                "quiz_count": len(c["quiz"])}

    def list_paths(self) -> Dict[str, Any]:
        paths = []
        for p in LEARNING_PATHS:
            ids = p["course_ids"]
            names = [COURSE_LIBRARY[i]["title"] for i in ids if i in COURSE_LIBRARY]
            paths.append({**p, "course_count": len(ids), "course_titles": names})
        return {"paths": paths, "total": len(paths)}

    # ---- 推荐算法（基于岗位/部门/历史行为的加权打分）----
    def recommend(self, role: str = "general", dept: str = "tech",
                  history: Optional[List[str]] = None,
                  limit: int = 8) -> Dict[str, Any]:
        history = history or []
        role_map = {
            "dev": ("dev_security", 6), "devops": ("dev_security", 5),
            "cloud": ("cloud_security", 6), "finance": ("social_engineering", 5),
            "hr": ("compliance", 4), "manager": ("compliance", 4),
        }
        preferred, weight = role_map.get(role, (dept, 3))
        scored = []
        for c in COURSE_LIBRARY.values():
            score = 1.0
            if c["category"] == preferred:
                score += weight
            if c["course_id"] in history:
                score -= 0.5
            score += (0.5 if c["difficulty"] == "基础" else 0.2)
            scored.append((score, c))
        scored.sort(key=lambda x: x[0], reverse=True)
        picks = [{"course_id": c["course_id"], "title": c["title"],
                  "category": c["category"], "difficulty": c["difficulty"],
                  "fit_score": round(s, 2)}
                 for s, c in scored[:limit]]
        return {"role": role, "dept": dept, "recommended": picks,
                "preferred_category": preferred}

    # ---- 进度跟踪 ----
    def update_progress(self, student: str, course_id: str,
                        chapter_done: int) -> Dict[str, Any]:
        c = COURSE_LIBRARY.get(course_id)
        if not c:
            return {"ok": False, "error": "课程不存在"}
        total = len(c["chapters"])
        pct = round(min(100, chapter_done / max(1, total) * 100), 1)
        key = f"{student}:{course_id}"
        self.progress[key] = {
            "student": student, "course_id": course_id,
            "course_title": c["title"], "chapter_done": chapter_done,
            "chapter_total": total, "percent": pct,
            "status": "completed" if pct >= 100 else "learning",
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return {"ok": True, "progress": self.progress[key]}

    def student_progress(self, student: str) -> Dict[str, Any]:
        rows = [v for k, v in self.progress.items() if k.startswith(student + ":")]
        done = sum(1 for r in rows if r["status"] == "completed")
        avg = round(sum(r["percent"] for r in rows) / max(1, len(rows)), 1)
        return {"student": student, "enrolled": len(rows), "completed": done,
                "avg_percent": avg, "detail": rows}

    # ---- 测验 ----
    def grade_quiz(self, course_id: str,
                   answers: Dict[str, str]) -> Dict[str, Any]:
        c = COURSE_LIBRARY.get(course_id)
        if not c:
            return {"passed": False, "error": "课程不存在"}
        total = len(c["quiz"])
        correct = 0
        detail = []
        for q in c["quiz"]:
            ok_ans = q["answer"]
            got = answers.get(q["qid"], "")
            hit = got.strip().upper() == ok_ans.strip().upper()
            correct += int(hit)
            detail.append({"qid": q["qid"], "your": got, "correct": ok_ans, "right": hit})
        score = round(correct / max(1, total) * 100, 1)
        return {"course_id": course_id, "total": total, "correct": correct,
                "score": score, "passed": score >= c["pass_score"],
                "pass_score": c["pass_score"], "detail": detail,
                "hash": hashlib.md5(f"{course_id}{score}".encode()).hexdigest()[:10]}
