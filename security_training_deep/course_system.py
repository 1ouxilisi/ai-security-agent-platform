#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_training_deep/course_system.py — 课程体系深度。

覆盖六大子域：
    1. 课程管理：创建/编辑/发布/归档/分类/标签/检索
    2. 课程内容：章节/小节/富文本/视频/附件/测验/作业
    3. 课程路径：学习路径/先修关系/进阶路线/角色路径
    4. 课程模板：标准模板/行业模板/自定义模板/模板实例化
    5. 课程质量：评分/完课率/反馈/质检/改进建议
    6. 课程推荐：基于角色/岗位/能力差距/学习历史的智能推荐
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量定义
# --------------------------------------------------------------------------- #
COURSE_LEVELS: Dict[str, str] = {
    "beginner": "入门级", "intermediate": "进阶级", "advanced": "高级", "expert": "专家级",
}

COURSE_STATUS: Dict[str, str] = {
    "draft": "草稿", "reviewing": "审核中", "published": "已发布", "archived": "已归档",
}

COURSE_CATEGORIES: Dict[str, str] = {
    "web_security": "Web安全",
    "network_security": "网络安全",
    "system_security": "系统安全",
    "mobile_security": "移动安全",
    "cloud_security": "云安全",
    "appsec": "应用安全",
    "incident_response": "应急响应",
    "compliance": "合规治理",
    "social_engineering": "社会工程",
    "cryptography": "密码学",
}

COURSE_TYPES: Dict[str, str] = {
    "video": "视频课程", "text": "图文课程", "interactive": "交互课程",
    "lab": "实验课程", "mixed": "混合课程", "webinar": "直播课程",
}

ROLE_PATHS: Dict[str, List[str]] = {
    "pentester": ["Web安全基础", "渗透测试实战", "高级渗透技巧", "红队演练"],
    "soc_analyst": ["安全运营入门", "日志分析", "威胁检测", "事件响应"],
    "developer": ["安全编码入门", "代码审计", "SDL实践", "DevSecOps"],
    "manager": ["安全管理基础", "风险管理", "合规框架", "安全治理"],
}


# --------------------------------------------------------------------------- #
# 课程管理
# --------------------------------------------------------------------------- #
class CourseManager:
    """课程管理：CRUD + 分类 + 标签 + 检索。"""

    def __init__(self) -> None:
        self.courses: Dict[str, Dict[str, Any]] = {}
        self._seed_default_courses()

    def _seed_default_courses(self) -> None:
        defaults = [
            ("Web安全基础入门", "web_security", "beginner", "video", "面向零基础学员的Web安全入门，覆盖OWASP Top 10核心概念。"),
            ("渗透测试实战指南", "web_security", "intermediate", "lab", "结合靶场环境的渗透测试实操课程。"),
            ("网络安全协议详解", "network_security", "intermediate", "text", "TCP/IP、DNS、TLS等安全协议深度解析。"),
            ("云安全架构设计", "cloud_security", "advanced", "mixed", "AWS/Azure/阿里云安全架构最佳实践。"),
            ("应急响应实战", "incident_response", "advanced", "lab", "事件响应流程、取证分析、遏制清除全流程。"),
            ("安全编码规范", "appsec", "beginner", "text", "OWASP安全编码规范与常见漏洞防范。"),
        ]
        for title, cat, level, ctype, desc in defaults:
            cid = f"crs_{uuid.uuid4().hex[:8]}"
            self.courses[cid] = {
                "id": cid, "title": title, "category": cat, "level": level,
                "type": ctype, "status": "published", "description": desc,
                "tags": [cat, level], "chapters": [], "duration_minutes": 60,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "instructor": "安全研究院", "enrollment_count": 0,
                "rating_avg": 4.5, "rating_count": 0, "completion_rate": 0.0,
            }

    def create_course(self, data: Dict[str, Any]) -> Dict[str, Any]:
        cid = f"crs_{uuid.uuid4().hex[:8]}"
        course = {
            "id": cid,
            "title": data.get("title", "未命名课程"),
            "category": data.get("category", "web_security"),
            "level": data.get("level", "beginner"),
            "type": data.get("type", "video"),
            "status": "draft",
            "description": data.get("description", ""),
            "tags": data.get("tags", []),
            "chapters": [],
            "duration_minutes": int(data.get("duration_minutes", 30)),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "instructor": data.get("instructor", ""),
            "enrollment_count": 0,
            "rating_avg": 0.0,
            "rating_count": 0,
            "completion_rate": 0.0,
        }
        self.courses[cid] = course
        return course

    def get_course(self, course_id: str) -> Optional[Dict[str, Any]]:
        return self.courses.get(course_id)

    def update_course(self, course_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        c = self.courses.get(course_id)
        if not c:
            return None
        for k in ("title", "description", "category", "level", "type", "tags", "instructor", "duration_minutes"):
            if k in data:
                c[k] = data[k]
        c["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return c

    def delete_course(self, course_id: str) -> bool:
        if course_id in self.courses:
            del self.courses[course_id]
            return True
        return False

    def list_courses(self, category: str = "", level: str = "", status: str = "",
                     keyword: str = "") -> List[Dict[str, Any]]:
        results = list(self.courses.values())
        if category:
            results = [c for c in results if c["category"] == category]
        if level:
            results = [c for c in results if c["level"] == level]
        if status:
            results = [c for c in results if c["status"] == status]
        if keyword:
            kw = keyword.lower()
            results = [c for c in results if kw in c["title"].lower() or kw in c["description"].lower()]
        return results

    def change_status(self, course_id: str, status: str) -> Optional[Dict[str, Any]]:
        c = self.courses.get(course_id)
        if not c or status not in COURSE_STATUS:
            return None
        c["status"] = status
        c["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return c


# --------------------------------------------------------------------------- #
# 课程内容（章节/小节管理）
# --------------------------------------------------------------------------- #
class CourseContentManager:
    """课程内容管理：章节/小节/测验/作业。"""

    def __init__(self, course_mgr: CourseManager) -> None:
        self.course_mgr = course_mgr
        self.sections: Dict[str, Dict[str, Any]] = {}
        self.quizzes: Dict[str, List[Dict[str, Any]]] = {}

    def add_chapter(self, course_id: str, title: str, description: str = "") -> Optional[Dict[str, Any]]:
        c = self.course_mgr.get_course(course_id)
        if not c:
            return None
        ch_id = f"ch_{uuid.uuid4().hex[:8]}"
        chapter = {
            "id": ch_id, "title": title, "description": description,
            "order": len(c["chapters"]) + 1, "sections": [],
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        c["chapters"].append(chapter)
        return chapter

    def add_section(self, course_id: str, chapter_id: str, title: str,
                    content_type: str = "text", content: str = "") -> Optional[Dict[str, Any]]:
        c = self.course_mgr.get_course(course_id)
        if not c:
            return None
        for ch in c["chapters"]:
            if ch["id"] == chapter_id:
                sec_id = f"sec_{uuid.uuid4().hex[:8]}"
                section = {
                    "id": sec_id, "title": title, "type": content_type,
                    "content": content, "order": len(ch["sections"]) + 1,
                    "duration_minutes": 10,
                }
                ch["sections"].append(section)
                self.sections[sec_id] = section
                return section
        return None

    def get_course_outline(self, course_id: str) -> Optional[Dict[str, Any]]:
        c = self.course_mgr.get_course(course_id)
        if not c:
            return None
        total_secs = 0
        for ch in c["chapters"]:
            total_secs += len(ch["sections"])
        return {
            "course_id": course_id,
            "title": c["title"],
            "chapter_count": len(c["chapters"]),
            "section_count": total_secs,
            "chapters": c["chapters"],
        }

    def add_quiz_question(self, course_id: str, question: str, options: List[str],
                          answer_index: int, explanation: str = "") -> Dict[str, Any]:
        qid = f"q_{uuid.uuid4().hex[:8]}"
        q = {
            "id": qid, "course_id": course_id, "question": question,
            "options": options, "answer_index": answer_index,
            "explanation": explanation, "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if course_id not in self.quizzes:
            self.quizzes[course_id] = []
        self.quizzes[course_id].append(q)
        return q

    def get_quiz(self, course_id: str) -> List[Dict[str, Any]]:
        return self.quizzes.get(course_id, [])


# --------------------------------------------------------------------------- #
# 课程路径（学习路径/角色路径）
# --------------------------------------------------------------------------- #
class CoursePathManager:
    """学习路径管理：角色路径/先修关系/进阶路线。"""

    def __init__(self, course_mgr: CourseManager) -> None:
        self.course_mgr = course_mgr
        self.paths: Dict[str, Dict[str, Any]] = {}
        self._seed_default_paths()

    def _seed_default_paths(self) -> None:
        for role, courses in ROLE_PATHS.items():
            pid = f"path_{uuid.uuid4().hex[:8]}"
            self.paths[pid] = {
                "id": pid, "name": f"{role}安全工程师成长路径",
                "role": role, "steps": [
                    {"order": i + 1, "course_name": cn, "course_id": None}
                    for i, cn in enumerate(courses)
                ],
                "description": f"面向{role}角色的系统化学习路线",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

    def create_path(self, name: str, role: str, steps: List[Dict[str, Any]],
                    description: str = "") -> Dict[str, Any]:
        pid = f"path_{uuid.uuid4().hex[:8]}"
        path = {
            "id": pid, "name": name, "role": role, "steps": steps,
            "description": description,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.paths[pid] = path
        return path

    def list_paths(self, role: str = "") -> List[Dict[str, Any]]:
        results = list(self.paths.values())
        if role:
            results = [p for p in results if p["role"] == role]
        return results

    def get_path(self, path_id: str) -> Optional[Dict[str, Any]]:
        return self.paths.get(path_id)


# --------------------------------------------------------------------------- #
# 课程模板
# --------------------------------------------------------------------------- #
class CourseTemplateManager:
    """课程模板：标准模板/行业模板/自定义模板。"""

    def __init__(self) -> None:
        self.templates: Dict[str, Dict[str, Any]] = {}
        self._seed_default_templates()

    def _seed_default_templates(self) -> None:
        defaults = [
            ("标准安全培训模板", "standard", "适用于企业常规安全培训，含课程介绍/理论/实验/测验四模块。"),
            ("行业合规培训模板", "compliance", "面向金融/医疗/政务行业的合规培训模板。"),
            ("新员工入职安全模板", "onboarding", "新员工入职必修安全意识与规范培训。"),
            ("红队技术实战模板", "red_team", "红队技术进阶实战课程模板。"),
        ]
        for name, ttype, desc in defaults:
            tid = f"tpl_{uuid.uuid4().hex[:8]}"
            self.templates[tid] = {
                "id": tid, "name": name, "type": ttype, "description": desc,
                "structure": ["课程介绍", "理论讲解", "实操实验", "考核测验"],
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

    def list_templates(self) -> List[Dict[str, Any]]:
        return list(self.templates.values())

    def instantiate(self, template_id: str, course_mgr: CourseManager,
                    title: str) -> Optional[Dict[str, Any]]:
        tpl = self.templates.get(template_id)
        if not tpl:
            return None
        course = course_mgr.create_course({
            "title": title, "description": tpl["description"],
        })
        for step in tpl["structure"]:
            ch = course_mgr.get_course(course["id"])
            # add chapter via content manager would need it; here just store
            if ch:
                ch.setdefault("chapters", []).append({
                    "id": f"ch_{uuid.uuid4().hex[:8]}", "title": step,
                    "description": "", "sections": [], "order": len(ch.get("chapters", [])),
                })
        return course


# --------------------------------------------------------------------------- #
# 课程质量
# --------------------------------------------------------------------------- #
class CourseQualityManager:
    """课程质量：评分/反馈/完课率/质检。"""

    def __init__(self, course_mgr: CourseManager) -> None:
        self.course_mgr = course_mgr
        self.reviews: Dict[str, List[Dict[str, Any]]] = {}

    def add_review(self, course_id: str, user: str, rating: int,
                   comment: str = "") -> Optional[Dict[str, Any]]:
        c = self.course_mgr.get_course(course_id)
        if not c or rating < 1 or rating > 5:
            return None
        rid = f"rev_{uuid.uuid4().hex[:8]}"
        review = {
            "id": rid, "user": user, "rating": rating, "comment": comment,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.reviews.setdefault(course_id, []).append(review)
        # update course rating avg
        revs = self.reviews[course_id]
        c["rating_count"] = len(revs)
        c["rating_avg"] = round(sum(r["rating"] for r in revs) / len(revs), 2)
        return review

    def get_reviews(self, course_id: str) -> List[Dict[str, Any]]:
        return self.reviews.get(course_id, [])

    def quality_report(self) -> Dict[str, Any]:
        courses = list(self.course_mgr.courses.values())
        total = len(courses)
        avg_rating = round(
            sum(c["rating_avg"] for c in courses if c["rating_count"] > 0) /
            max(1, sum(1 for c in courses if c["rating_count"] > 0)), 2
        )
        high_rated = [c for c in courses if c["rating_avg"] >= 4.5 and c["rating_count"] > 0]
        low_rated = [c for c in courses if c["rating_avg"] < 3.5 and c["rating_count"] > 0]
        return {
            "total_courses": total,
            "avg_rating": avg_rating,
            "high_rated_count": len(high_rated),
            "low_rated_count": len(low_rated),
            "top_courses": sorted(courses, key=lambda x: x["rating_avg"], reverse=True)[:5],
            "needs_improvement": [c for c in low_rated],
        }


# --------------------------------------------------------------------------- #
# 课程推荐
# --------------------------------------------------------------------------- #
class CourseRecommender:
    """课程推荐：基于角色/能力差距/学习历史。"""

    def __init__(self, course_mgr: CourseManager) -> None:
        self.course_mgr = course_mgr
        self.user_history: Dict[str, List[str]] = {}

    def record_progress(self, user: str, course_id: str) -> None:
        self.user_history.setdefault(user, []).append(course_id)

    def recommend_for_role(self, role: str, limit: int = 5) -> List[Dict[str, Any]]:
        courses = list(self.course_mgr.courses.values())
        level_order = {"beginner": 0, "intermediate": 1, "advanced": 2, "expert": 3}
        # filter by role keywords in category
        role_map = {
            "pentester": ["web_security", "appsec"],
            "soc_analyst": ["incident_response", "network_security"],
            "developer": ["appsec", "cloud_security"],
            "manager": ["compliance", "network_security"],
        }
        cats = role_map.get(role, [])
        filtered = [c for c in courses if c["category"] in cats]
        filtered.sort(key=lambda x: level_order.get(x["level"], 1))
        return filtered[:limit]

    def recommend_for_gap(self, weak_skills: List[str], limit: int = 5) -> List[Dict[str, Any]]:
        courses = list(self.course_mgr.courses.values())
        scored = []
        for c in courses:
            score = 0
            for skill in weak_skills:
                if skill.lower() in c["title"].lower() or skill.lower() in c["description"].lower():
                    score += 2
                if skill.lower() in c["category"].lower():
                    score += 1
            if score > 0:
                scored.append((score, c))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in scored[:limit]]


# --------------------------------------------------------------------------- #
# 单例获取
# --------------------------------------------------------------------------- #
_course_manager: Optional[CourseManager] = None
_content_manager: Optional[CourseContentManager] = None
_path_manager: Optional[CoursePathManager] = None
_template_manager: Optional[CourseTemplateManager] = None
_quality_manager: Optional[CourseQualityManager] = None
_recommender: Optional[CourseRecommender] = None


def get_course_manager() -> CourseManager:
    global _course_manager
    if _course_manager is None:
        _course_manager = CourseManager()
    return _course_manager


def get_content_manager() -> CourseContentManager:
    global _content_manager
    if _content_manager is None:
        _content_manager = CourseContentManager(get_course_manager())
    return _content_manager


def get_path_manager() -> CoursePathManager:
    global _path_manager
    if _path_manager is None:
        _path_manager = CoursePathManager(get_course_manager())
    return _path_manager


def get_template_manager() -> CourseTemplateManager:
    global _template_manager
    if _template_manager is None:
        _template_manager = CourseTemplateManager()
    return _template_manager


def get_quality_manager() -> CourseQualityManager:
    global _quality_manager
    if _quality_manager is None:
        _quality_manager = CourseQualityManager(get_course_manager())
    return _quality_manager


def get_recommender() -> CourseRecommender:
    global _recommender
    if _recommender is None:
        _recommender = CourseRecommender(get_course_manager())
    return _recommender
