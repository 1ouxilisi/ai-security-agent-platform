# -*- coding: utf-8 -*-
"""community_support.py — 开发者社区与支持。

能力：
- 论坛帖子 / 问答 / 教程 / 最佳实践 / 常见问题
- 更新公告、状态页、反馈收集、开发者等级、贡献者计划
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


TIERS: List[Dict[str, Any]] = [
    {"tier": "newbie", "name": "新手", "min_points": 0, "perks": ["社区访问"]},
    {"tier": "active", "name": "活跃开发者", "min_points": 100,
     "perks": ["社区徽章", "专属支持频道"]},
    {"tier": "expert", "name": "专家", "min_points": 500,
     "perks": ["提前体验", "1v1 支持"]},
    {"tier": "contributor", "name": "贡献者", "min_points": 1000,
     "perks": ["免费 Pro 套餐", "代码署名"]},
]


FAQS: List[Dict[str, str]] = [
    {"q": "如何获取 API Key？", "a": "注册开发者账号后，在「应用密钥」页创建应用并生成 Key。"},
    {"q": "沙箱和生产环境有什么区别？", "a": "沙箱使用模拟数据，不产生真实计费；生产环境会按量计费。"},
    {"q": "触发 429 限流怎么办？", "a": "查看套餐限流配额，或升级套餐；同时实现指数退避重试。"},
    {"q": "Key 泄露了怎么处理？", "a": "立即在控制台「轮换密钥」并撤销旧 Key。"},
    {"q": "是否提供 SLA？", "a": "企业版提供 99.9% SLA，免费版不提供。"},
]


TUTORIALS: List[Dict[str, Any]] = [
    {"id": "tut_01", "title": "5 分钟接入第一个 API", "minutes": 5,
     "tags": ["入门", "Python"]},
    {"id": "tut_02", "title": "使用 SDK 实现自动化扫描", "minutes": 15,
     "tags": ["SDK", "自动化"]},
    {"id": "tut_03", "title": "Webhook 回调最佳实践", "minutes": 10,
     "tags": ["Webhook", "最佳实践"]},
]


class CommunitySupport:
    """开发者社区与支持。"""

    def __init__(self) -> None:
        self.posts: Dict[str, Dict[str, Any]] = {}
        self.questions: Dict[str, Dict[str, Any]] = {}
        self.announcements: List[Dict[str, Any]] = [
            {"id": "ann_01", "title": "v1.4.0 发布",
             "body": "新增 IOC 情报接口，详见变更日志。",
             "at": "2026-09-10 10:00:00"},
        ]
        self.feedback: Dict[str, Dict[str, Any]] = {}
        self.members: Dict[str, Dict[str, Any]] = {}
        self.status_page: Dict[str, Any] = {
            "overall": "operational",
            "services": [
                {"name": "API 网关", "status": "operational", "uptime_30d": 99.98},
                {"name": "扫描引擎", "status": "operational", "uptime_30d": 99.95},
                {"name": "报告服务", "status": "degraded", "uptime_30d": 99.20},
                {"name": "开发者沙箱", "status": "operational", "uptime_30d": 100.0},
            ],
            "incidents": [],
        }

    # ------------------------------------------------------------------ #
    # 论坛
    # ------------------------------------------------------------------ #
    def create_post(self, author: str, title: str, body: str,
                    tags: Optional[List[str]] = None) -> Dict[str, Any]:
        pid = "post_" + uuid.uuid4().hex[:8]
        post = {
            "id": pid, "author": author, "title": title, "body": body,
            "tags": tags or [], "likes": 0, "replies": [],
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.posts[pid] = post
        return post

    def list_posts(self, tag: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.posts.values())
        if tag:
            items = [p for p in items if tag in p.get("tags", [])]
        return items

    def reply_post(self, post_id: str, author: str, body: str) -> Dict[str, Any]:
        post = self.posts.get(post_id)
        if not post:
            return {}
        reply = {"author": author, "body": body,
                 "at": time.strftime("%Y-%m-%d %H:%M:%S")}
        post["replies"].append(reply)
        return reply

    # ------------------------------------------------------------------ #
    # 问答
    # ------------------------------------------------------------------ #
    def ask(self, author: str, title: str, body: str,
            tags: Optional[List[str]] = None) -> Dict[str, Any]:
        qid = "q_" + uuid.uuid4().hex[:8]
        q = {
            "id": qid, "author": author, "title": title, "body": body,
            "tags": tags or [], "answers": [], "accepted_answer": None,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.questions[qid] = q
        return q

    def answer(self, qid: str, author: str, body: str,
               accepted: bool = False) -> Dict[str, Any]:
        q = self.questions.get(qid)
        if not q:
            return {}
        ans = {"author": author, "body": body,
               "at": time.strftime("%Y-%m-%d %H:%M:%S")}
        q["answers"].append(ans)
        if accepted:
            q["accepted_answer"] = ans
        return ans

    def list_questions(self) -> List[Dict[str, Any]]:
        return list(self.questions.values())

    # ------------------------------------------------------------------ #
    # 教程 / FAQ / 公告
    # ------------------------------------------------------------------ #
    def list_tutorials(self) -> List[Dict[str, Any]]:
        return TUTORIALS

    def list_faq(self) -> List[Dict[str, str]]:
        return FAQS

    def list_announcements(self) -> List[Dict[str, Any]]:
        return self.announcements

    # ------------------------------------------------------------------ #
    # 状态页 / 反馈 / 等级
    # ------------------------------------------------------------------ #
    def get_status_page(self) -> Dict[str, Any]:
        return self.status_page

    def submit_feedback(self, author: str, kind: str, body: str) -> Dict[str, Any]:
        fid = "fb_" + uuid.uuid4().hex[:8]
        fb = {
            "id": fid, "author": author, "kind": kind, "body": body,
            "status": "open", "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.feedback[fid] = fb
        return fb

    def list_feedback(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.feedback.values())
        if status:
            items = [f for f in items if f.get("status") == status]
        return items

    def register_member(self, developer: str) -> Dict[str, Any]:
        if developer in self.members:
            return self.members[developer]
        m = {
            "developer": developer,
            "points": 0,
            "tier": "newbie",
            "contributions": 0,
            "joined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.members[developer] = m
        return m

    def add_points(self, developer: str, points: int) -> Dict[str, Any]:
        m = self.members.setdefault(developer, {
            "developer": developer, "points": 0, "tier": "newbie",
            "contributions": 0, "joined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        m["points"] += points
        m["contributions"] += points
        # 升级
        for t in sorted(TIERS, key=lambda x: x["min_points"], reverse=True):
            if m["points"] >= t["min_points"]:
                m["tier"] = t["tier"]
                break
        return m

    def list_tiers(self) -> List[Dict[str, Any]]:
        return TIERS

    def contributors(self) -> List[Dict[str, Any]]:
        return sorted(self.members.values(),
                      key=lambda x: x.get("points", 0), reverse=True)


_community: Optional[CommunitySupport] = None


def get_community() -> CommunitySupport:
    global _community
    if _community is None:
        _community = CommunitySupport()
    return _community
