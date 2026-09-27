# -*- coding: utf-8 -*-
"""
course_management_phase.py — 阶段1：课程管理。

功能:
    - 课程创建（名称/描述/分类/难度/时长/学分/价格）
    - 10 大课程分类（Web/内网/移动/云/密码学/逆向/社工/安全开发/安全管理/其他）
    - 章节管理（创建/排序/内容/时长/课件）
    - 课件上传（PPT/PDF/文档/图片）
    - 视频管理（上传/转码/字幕/播放统计）
    - 课程属性（讲师/难度/评分/评论/收藏）
    - 课程状态机（草稿/已发布/已下线/已归档）
    - 课程版本管理 / 课程模板
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# 课程分类（10 大类，每类若干知识点）
COURSE_CATEGORIES: Dict[str, List[str]] = {
    "Web安全": ["SQL注入", "XSS", "文件上传", "命令注入", "SSRF",
               "反序列化", "逻辑漏洞"],
    "内网渗透": ["信息收集", "漏洞利用", "横向移动", "权限提升", "域渗透"],
    "移动安全": ["APK逆向", "Frida", "动态调试", "组件安全", "数据安全"],
    "云安全": ["AWS", "阿里云", "配置错误", "权限提升", "数据泄露"],
    "密码学": ["对称加密", "非对称加密", "哈希", "数字签名",
              "椭圆曲线", "格密码"],
    "逆向工程": ["静态分析", "动态调试", "脱壳", "算法分析", "反调试"],
    "社会工程学": ["钓鱼攻击", "伪装攻击", "信息收集", "心理操纵"],
    "安全开发": ["安全编码", "代码审计", "DevSecOps", "安全测试"],
    "安全管理": ["风险管理", "合规审计", "应急响应", "安全运营"],
    "其他": ["物联网安全", "工控安全", "区块链安全", "AI安全"],
}

DIFFICULTIES = ["入门", "简单", "中等", "困难", "地狱"]
COURSE_STATUS = ["草稿", "已发布", "已下线", "已归档"]


@dataclass
class Chapter:
    chapter_id: str = ""
    title: str = ""
    order: int = 0
    content: str = ""
    duration_min: int = 0
    materials: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chapter_id": self.chapter_id, "title": self.title,
            "order": self.order, "content": self.content,
            "duration_min": self.duration_min,
            "materials": self.materials,
        }


@dataclass
class Course:
    course_id: str = ""
    name: str = ""
    description: str = ""
    category: str = "Web安全"
    difficulty: str = "入门"
    duration_min: int = 60
    credit: float = 1.0
    price: float = 0.0
    instructor: str = ""
    status: str = "草稿"
    rating: float = 0.0
    rating_count: int = 0
    students: int = 0
    favorites: int = 0
    version: int = 1
    chapters: List[Chapter] = field(default_factory=list)
    videos: List[Dict[str, Any]] = field(default_factory=list)
    comments: List[Dict[str, Any]] = field(default_factory=list)
    versions: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "course_id": self.course_id, "name": self.name,
            "description": self.description, "category": self.category,
            "difficulty": self.difficulty,
            "duration_min": self.duration_min, "credit": self.credit,
            "price": self.price, "instructor": self.instructor,
            "status": self.status, "rating": round(self.rating, 2),
            "rating_count": self.rating_count, "students": self.students,
            "favorites": self.favorites, "version": self.version,
            "chapters": [c.to_dict() for c in self.chapters],
            "videos": self.videos, "comments": self.comments,
            "versions": self.versions,
            "created_at": self.created_at, "updated_at": self.updated_at,
        }


class CourseManagementPhase:
    """阶段1：课程管理。"""

    def __init__(self) -> None:
        self._courses: Dict[str, Course] = {}
        self._templates: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._seed()

    # ------------------------------------------------------------------ #
    def _seed(self) -> None:
        for cid, name, cat, diff, mins in [
            ("c_web_sqli", "SQL 注入从入门到实战", "Web安全", "中等", 360),
            ("c_xss", "跨站脚本 XSS 全解析", "Web安全", "简单", 240),
            ("c_ad", "域渗透攻防实战", "内网渗透", "困难", 600),
            ("c_frida", "Frida 动态 Hook 入门", "移动安全", "中等", 300),
            ("c_aws", "AWS 云安全配置与提权", "云安全", "困难", 420),
            ("c_crypto", "密码学基础到应用", "密码学", "入门", 480),
            ("c_re", "逆向工程静态分析", "逆向工程", "中等", 540),
        ]:
            if cid not in self._courses:
                self._courses[cid] = Course(
                    course_id=cid, name=name,
                    description=f"{name} · 系统化实战课程",
                    category=cat, difficulty=diff, duration_min=mins,
                    credit=round(mins / 45.0, 1), price=99.0,
                    instructor="AI 讲师", status="已发布",
                    rating=4.5, rating_count=120, students=320,
                    favorites=88,
                    created_at=datetime.now().isoformat(timespec="seconds"),
                    updated_at=datetime.now().isoformat(timespec="seconds"),
                )
        self._templates["tpl_web_basic"] = {
            "template_id": "tpl_web_basic", "name": "Web 安全标准模板",
            "category": "Web安全",
            "outline": ["信息收集", "漏洞原理", "漏洞利用", "防御修复"],
        }
        self._templates["tpl_occ"] = {
            "template_id": "tpl_occ", "name": "安全意识模板",
            "category": "安全管理",
            "outline": ["威胁认知", "案例", "实操", "考核"],
        }

    # ------------------------------------------------------------------ #
    def categories(self) -> Dict[str, List[str]]:
        return dict(COURSE_CATEGORIES)

    def list_courses(self, category: Optional[str] = None,
                     status: Optional[str] = None,
                     difficulty: Optional[str] = None,
                     keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._courses.values())
        out = []
        for c in items:
            if category and c.category != category:
                continue
            if status and c.status != status:
                continue
            if difficulty and c.difficulty != difficulty:
                continue
            if keyword and keyword not in c.name and \
                    keyword not in c.description:
                continue
            out.append(c.to_dict())
        return out

    def get_course(self, course_id: str) -> Optional[Dict[str, Any]]:
        c = self._courses.get(course_id)
        return c.to_dict() if c else None

    def create_course(self, name: str, description: str = "",
                      category: str = "Web安全", difficulty: str = "入门",
                      duration_min: int = 60, credit: float = 1.0,
                      price: float = 0.0, instructor: str = "") -> Dict[str, Any]:
        if category not in COURSE_CATEGORIES:
            raise ValueError(f"未知分类: {category}")
        if difficulty not in DIFFICULTIES:
            raise ValueError(f"未知难度: {difficulty}")
        c = Course(
            course_id="c_" + uuid.uuid4().hex[:8], name=name,
            description=description, category=category,
            difficulty=difficulty, duration_min=duration_min,
            credit=credit, price=price, instructor=instructor,
            status="草稿",
            created_at=datetime.now().isoformat(timespec="seconds"),
            updated_at=datetime.now().isoformat(timespec="seconds"),
        )
        with self._lock:
            self._courses[c.course_id] = c
        return c.to_dict()

    def update_course(self, course_id: str,
                      **kwargs: Any) -> Optional[Dict[str, Any]]:
        c = self._courses.get(course_id)
        if c is None:
            return None
        with self._lock:
            for k, v in kwargs.items():
                if hasattr(c, k) and k not in (
                        "course_id", "chapters", "comments", "versions"):
                    setattr(c, k, v)
            c.updated_at = datetime.now().isoformat(timespec="seconds")
        return c.to_dict()

    def change_status(self, course_id: str,
                      status: str) -> Optional[Dict[str, Any]]:
        if status not in COURSE_STATUS:
            raise ValueError(f"非法状态: {status}")
        c = self._courses.get(course_id)
        if c is None:
            return None
        with self._lock:
            # 版本快照
            c.versions.append({"version": c.version, "status": c.status,
                               "at": datetime.now().isoformat(timespec="seconds")})
            c.version += 1
            c.status = status
            c.updated_at = datetime.now().isoformat(timespec="seconds")
        return c.to_dict()

    # ------------------------------------------------------------------ #
    def add_chapter(self, course_id: str, title: str,
                    content: str = "",
                    duration_min: int = 0) -> Optional[Dict[str, Any]]:
        c = self._courses.get(course_id)
        if c is None:
            return None
        with self._lock:
            ch = Chapter(chapter_id="ch_" + uuid.uuid4().hex[:8],
                         title=title, content=content,
                         order=len(c.chapters) + 1,
                         duration_min=duration_min)
            c.chapters.append(ch)
        return ch.to_dict()

    def reorder_chapters(self, course_id: str,
                         order: List[str]) -> Optional[Dict[str, Any]]:
        c = self._courses.get(course_id)
        if c is None:
            return None
        with self._lock:
            by_id = {ch.chapter_id: ch for ch in c.chapters}
            new_list = []
            for i, cid in enumerate(order):
                ch = by_id.get(cid)
                if ch:
                    ch.order = i + 1
                    new_list.append(ch)
            c.chapters = new_list
        return c.to_dict()

    def delete_chapter(self, course_id: str, chapter_id: str) -> bool:
        c = self._courses.get(course_id)
        if c is None:
            return False
        with self._lock:
            before = len(c.chapters)
            c.chapters = [ch for ch in c.chapters
                          if ch.chapter_id != chapter_id]
            return len(c.chapters) < before

    # ------------------------------------------------------------------ #
    def upload_material(self, course_id: str, chapter_id: str,
                        filename: str, mtype: str = "pdf") -> Optional[Dict[str, Any]]:
        c = self._courses.get(course_id)
        if c is None:
            return None
        mat = {"mat_id": "m_" + uuid.uuid4().hex[:8],
               "filename": filename, "type": mtype,
               "uploaded_at": datetime.now().isoformat(timespec="seconds")}
        with self._lock:
            for ch in c.chapters:
                if ch.chapter_id == chapter_id:
                    ch.materials.append(mat)
                    return mat
        return None

    def add_video(self, course_id: str, title: str,
                  filename: str, duration_min: int = 0,
                  subtitle: bool = False) -> Optional[Dict[str, Any]]:
        c = self._courses.get(course_id)
        if c is None:
            return None
        v = {"video_id": "v_" + uuid.uuid4().hex[:8], "title": title,
             "filename": filename, "duration_min": duration_min,
             "subtitle": subtitle, "transcoded": True,
             "views": 0,
             "uploaded_at": datetime.now().isoformat(timespec="seconds")}
        with self._lock:
            c.videos.append(v)
        return v

    # ------------------------------------------------------------------ #
    def add_comment(self, course_id: str, user: str, rating: int,
                    comment: str = "") -> Optional[Dict[str, Any]]:
        c = self._courses.get(course_id)
        if c is None:
            return None
        with self._lock:
            entry = {"user": user, "rating": rating, "comment": comment,
                     "at": datetime.now().isoformat(timespec="seconds")}
            c.comments.append(entry)
            total = sum(x["rating"] for x in c.comments)
            c.rating_count = len(c.comments)
            c.rating = total / c.rating_count
        return entry

    def toggle_favorite(self, course_id: str) -> Optional[Dict[str, Any]]:
        c = self._courses.get(course_id)
        if c is None:
            return None
        with self._lock:
            c.favorites += 1
        return {"course_id": course_id, "favorites": c.favorites}

    # ------------------------------------------------------------------ #
    def templates(self) -> List[Dict[str, Any]]:
        return list(self._templates.values())

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._courses)
            by_status: Dict[str, int] = {}
            by_category: Dict[str, int] = {}
            pub = 0
            students = 0
            for c in self._courses.values():
                by_status[c.status] = by_status.get(c.status, 0) + 1
                by_category[c.category] = by_category.get(c.category, 0) + 1
                students += c.students
                if c.status == "已发布":
                    pub += 1
        return {
            "total": total, "published": pub,
            "by_status": by_status, "by_category": by_category,
            "total_students": students,
            "templates": len(self._templates),
            "categories": list(COURSE_CATEGORIES.keys()),
        }


_default: Optional[CourseManagementPhase] = None


def get_course_management_phase() -> CourseManagementPhase:
    global _default
    if _default is None:
        _default = CourseManagementPhase()
    return _default
