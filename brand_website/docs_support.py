# -*- coding: utf-8 -*-
"""
brand_website/docs_support.py — 文档与支持中心模块。

覆盖：文档中心、知识库、社区论坛、工单系统、在线客服、视频教程。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _pid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


DOCS: Dict[str, Dict[str, Any]] = {}
KB: Dict[str, Dict[str, Any]] = {}
FORUMS: Dict[str, Dict[str, Any]] = {}
THREADS: Dict[str, Dict[str, Any]] = {}
TICKETS: Dict[str, Dict[str, Any]] = {}
CHATS: Dict[str, Dict[str, Any]] = {}
VIDEOS: Dict[str, Dict[str, Any]] = {}


def _seed() -> None:
    if not DOCS:
        for slug, title, cat in [
            ("quickstart", "快速开始", "getting_started"),
            ("install", "安装部署", "getting_started"),
            ("user_manual", "用户手册", "manual"),
            ("api_ref", "API 文档", "developer"),
            ("dev_guide", "开发者指南", "developer"),
            ("best_practice", "最佳实践", "manual"),
            ("faq", "常见问题", "manual"),
            ("changelog", "版本更新", "manual"),
        ]:
            DOCS[slug] = {
                "slug": slug, "title": title, "category": cat,
                "body": f"# {title}\n\n文档正文占位。", "views": 0,
                "updated_at": _now(),
            }
    if not KB:
        KB["kb_1"] = {"id": "kb_1", "title": "如何排查登录失败",
                      "category": "故障排查", "body": "检查密码与验证码",
                      "rating": 4.8, "views": 1200}
    if not FORUMS:
        FORUMS["f_general"] = {"id": "f_general", "name": "综合讨论",
                               "threads": 0, "posts": 0}
        FORUMS["f_help"] = {"id": "f_help", "name": "求助区",
                            "threads": 0, "posts": 0}
    if not VIDEOS:
        VIDEOS["v_welcome"] = {"id": "v_welcome", "title": "产品入门视频",
                               "category": "入门", "duration": "05:32",
                               "url": "/static/videos/welcome.mp4",
                               "views": 3400, "subtitle": "zh-CN"}


_seed()


class DocsSupport:
    # ---- 文档中心 ----
    def list_docs(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(DOCS.values())
        if category:
            items = [d for d in items if d["category"] == category]
        return items

    def get_doc(self, slug: str) -> Optional[Dict[str, Any]]:
        d = DOCS.get(slug)
        if d:
            d["views"] = d.get("views", 0) + 1
        return d

    def create_doc(self, title: str, category: str, body: str = "") -> Dict[str, Any]:
        slug = title.lower().replace(" ", "_") or _pid("doc")
        DOCS[slug] = {"slug": slug, "title": title, "category": category,
                      "body": body or f"# {title}\n", "views": 0,
                      "updated_at": _now()}
        return DOCS[slug]

    # ---- 知识库 ----
    def list_kb(self, keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(KB.values())
        if keyword:
            kw = keyword.lower()
            items = [k for k in items
                     if kw in k["title"].lower() or kw in k["body"].lower()]
        return sorted(items, key=lambda x: x["views"], reverse=True)

    def rate_kb(self, kid: str, stars: float) -> Optional[Dict[str, Any]]:
        k = KB.get(kid)
        if not k:
            return None
        n = k.get("rating_count", 1)
        k["rating"] = round((k["rating"] * n + stars) / (n + 1), 2)
        k["rating_count"] = n + 1
        return k

    # ---- 社区论坛 ----
    def list_forums(self) -> List[Dict[str, Any]]:
        return list(FORUMS.values())

    def create_thread(self, forum_id: str, title: str,
                      author: str, body: str) -> Dict[str, Any]:
        tid = _pid("thr")
        THREADS[tid] = {
            "id": tid, "forum_id": forum_id, "title": title,
            "author": author, "body": body, "replies": [],
            "pinned": False, "essence": False, "views": 0,
            "created_at": _now(),
        }
        return THREADS[tid]

    def list_threads(self, forum_id: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(THREADS.values())
        if forum_id:
            items = [t for t in items if t["forum_id"] == forum_id]
        return sorted(items, key=lambda x: x["created_at"], reverse=True)

    def reply_thread(self, tid: str, author: str,
                     body: str) -> Optional[Dict[str, Any]]:
        t = THREADS.get(tid)
        if not t:
            return None
        t["replies"].append({"author": author, "body": body,
                             "at": _now()})
        return t

    # ---- 工单系统 ----
    def create_ticket(self, title: str, category: str,
                      priority: str = "normal", requester: str = "") -> Dict[str, Any]:
        tid = _pid("tkt")
        TICKETS[tid] = {
            "id": tid, "title": title, "category": category,
            "priority": priority, "requester": requester,
            "status": "待受理", "assignee": "", "replies": [],
            "sla_due": "24h", "created_at": _now(),
        }
        return TICKETS[tid]

    def list_tickets(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(TICKETS.values())
        if status:
            items = [t for t in items if t["status"] == status]
        return sorted(items, key=lambda x: x["created_at"], reverse=True)

    def assign_ticket(self, tid: str, assignee: str) -> Optional[Dict[str, Any]]:
        t = TICKETS.get(tid)
        if not t:
            return None
        t["assignee"] = assignee
        t["status"] = "处理中"
        return t

    def reply_ticket(self, tid: str, author: str,
                     body: str) -> Optional[Dict[str, Any]]:
        t = TICKETS.get(tid)
        if not t:
            return None
        t["replies"].append({"author": author, "body": body, "at": _now()})
        return t

    # ---- 在线客服 ----
    def start_chat(self, user: str, message: str) -> Dict[str, Any]:
        cid = _pid("chat")
        CHATS[cid] = {
            "id": cid, "user": user, "status": "进行中",
            "messages": [{"role": "user", "text": message, "at": _now()}],
            "agent": "", "offline": False,
        }
        return CHATS[cid]

    def list_chats(self) -> List[Dict[str, Any]]:
        return list(CHATS.values())

    def quick_reply(self, cid: str, agent: str, text: str) -> Optional[Dict[str, Any]]:
        c = CHATS.get(cid)
        if not c:
            return None
        c["agent"] = agent
        c["messages"].append({"role": "agent", "text": text, "at": _now()})
        return c

    # ---- 视频教程 ----
    def list_videos(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(VIDEOS.values())
        if category:
            items = [v for v in items if v["category"] == category]
        return items

    def upload_video(self, title: str, category: str,
                     url: str, duration: str = "00:00") -> Dict[str, Any]:
        vid = _pid("vid")
        VIDEOS[vid] = {"id": vid, "title": title, "category": category,
                       "url": url, "duration": duration, "views": 0,
                       "subtitle": "zh-CN", "notes": []}
        return VIDEOS[vid]

    def add_note(self, vid: str, note: str) -> Optional[Dict[str, Any]]:
        v = VIDEOS.get(vid)
        if not v:
            return None
        v.setdefault("notes", []).append({"note": note, "at": _now()})
        return v
