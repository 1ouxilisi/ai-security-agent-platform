# -*- coding: utf-8 -*-
"""
brand_website/blog_marketing.py — 博客与内容营销模块。

覆盖：博客管理、内容日历、SEO 分析、社交媒体、邮件营销、数据分析。
"""

from __future__ import annotations

import random
import time
import uuid
from typing import Any, Dict, List, Optional


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _pid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


POSTS: Dict[str, Dict[str, Any]] = {}
CONTENT_CALENDAR: Dict[str, Dict[str, Any]] = {}
SEO_REPORT: Dict[str, Any] = {}
SOCIAL_ACCOUNTS: Dict[str, Dict[str, Any]] = {}
EMAIL_CAMPAIGNS: Dict[str, Dict[str, Any]] = {}
ANALYTICS: Dict[str, Any] = {}


def _seed() -> None:
    if not POSTS:
        POSTS["p_welcome"] = {
            "id": "p_welcome", "title": "AI 攻防平台正式发布",
            "category": "产品动态", "tags": ["发布", "AI"],
            "author": "editor", "cover": "/static/covers/welcome.png",
            "summary": "一站式 AI 安全攻防平台上线。",
            "body": "# AI 攻防平台正式发布\n\n...",
            "status": "已发布", "views": 5200,
            "created_at": _now(), "published_at": _now(),
        }
        POSTS["p_tip"] = {
            "id": "p_tip", "title": "渗透测试 10 个实战技巧",
            "category": "技术", "tags": ["渗透", "技巧"],
            "author": "pentester", "cover": "/static/covers/tips.png",
            "summary": "10 个真实环境中好用的技巧。",
            "body": "# 渗透测试 10 个技巧\n\n...",
            "status": "草稿", "views": 0,
            "created_at": _now(), "published_at": "",
        }
    if not SOCIAL_ACCOUNTS:
        for plat in ["weibo", "wechat", "zhihu", "csdn", "juejin", "oschina"]:
            SOCIAL_ACCOUNTS[plat] = {
                "platform": plat, "connected": True,
                "followers": random.randint(1000, 50000),
                "last_sync": _now(),
            }
    if not SEO_REPORT:
        SEO_REPORT.update({
            "keywords": [
                {"word": "AI 渗透测试", "rank": 5, "volume": 1200},
                {"word": "红蓝对抗平台", "rank": 12, "volume": 800},
            ],
            "indexed_pages": 128, "backlinks": 342,
            "domain_authority": 42,
            "competitors": ["competitor_a", "competitor_b"],
            "suggestions": ["增加长尾词", "提升页面速度", "建设外链"],
        })
    if not EMAIL_CAMPAIGNS:
        EMAIL_CAMPAIGNS["e_welcome"] = {
            "id": "e_welcome", "name": "欢迎邮件",
            "list_size": 12000, "sent": 12000,
            "open_rate": 0.32, "ctr": 0.08,
            "conversion": 0.012, "unsubscribe": 0.002,
        }
    if not ANALYTICS:
        days = [time.strftime("%Y-%m-%d",
                              time.localtime(time.time() - i * 86400))
                for i in range(30, 0, -1)]
        ANALYTICS["daily"] = [
            {"date": d, "pv": random.randint(8000, 20000),
             "uv": random.randint(3000, 9000),
             "bounce_rate": round(random.uniform(0.3, 0.6), 2)}
            for d in days
        ]
        ANALYTICS["funnel"] = [
            {"stage": "访问", "count": 50000},
            {"stage": "注册", "count": 4000},
            {"stage": "试用", "count": 800},
            {"stage": "付费", "count": 120},
        ]
        ANALYTICS["sources"] = [
            {"name": "直接访问", "uv": 18000},
            {"name": "搜索引擎", "uv": 22000},
            {"name": "社交媒体", "uv": 8000},
            {"name": "外部引荐", "uv": 4000},
        ]


_seed()


class BlogMarketing:
    # ---- 博客管理 ----
    def list_posts(self, status: Optional[str] = None,
                   category: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(POSTS.values())
        if status:
            items = [p for p in items if p["status"] == status]
        if category:
            items = [p for p in items if p["category"] == category]
        return sorted(items, key=lambda x: x["created_at"], reverse=True)

    def create_post(self, title: str, category: str, author: str,
                    summary: str = "", body: str = "",
                    tags: Optional[List[str]] = None) -> Dict[str, Any]:
        pid = _pid("post")
        POSTS[pid] = {
            "id": pid, "title": title, "category": category,
            "tags": tags or [], "author": author,
            "cover": "/static/covers/default.png",
            "summary": summary, "body": body or f"# {title}\n",
            "status": "草稿", "views": 0,
            "created_at": _now(), "published_at": "",
        }
        return POSTS[pid]

    def publish_post(self, pid: str) -> Optional[Dict[str, Any]]:
        p = POSTS.get(pid)
        if not p:
            return None
        p["status"] = "已发布"
        p["published_at"] = _now()
        return p

    def offline_post(self, pid: str) -> Optional[Dict[str, Any]]:
        p = POSTS.get(pid)
        if not p:
            return None
        p["status"] = "已下线"
        return p

    # ---- 内容日历 ----
    def plan_content(self, title: str, ctype: str, owner: str,
                     due: str) -> Dict[str, Any]:
        cid = _pid("plan")
        CONTENT_CALENDAR[cid] = {
            "id": cid, "title": title, "type": ctype,
            "owner": owner, "due": due, "status": "计划中",
            "created_at": _now(),
        }
        return CONTENT_CALENDAR[cid]

    def list_calendar(self) -> List[Dict[str, Any]]:
        return sorted(CONTENT_CALENDAR.values(),
                      key=lambda x: x.get("due", ""))

    def update_plan(self, cid: str, status: str) -> Optional[Dict[str, Any]]:
        c = CONTENT_CALENDAR.get(cid)
        if not c:
            return None
        c["status"] = status
        return c

    # ---- SEO 分析 ----
    def seo_report(self) -> Dict[str, Any]:
        return dict(SEO_REPORT)

    # ---- 社交媒体 ----
    def list_social(self) -> List[Dict[str, Any]]:
        return list(SOCIAL_ACCOUNTS.values())

    def sync_social(self, platform: str) -> Dict[str, Any]:
        s = SOCIAL_ACCOUNTS.get(platform)
        if not s:
            return {"error": "平台未绑定"}
        s["last_sync"] = _now()
        return {"platform": platform, "synced": True,
                "followers": s["followers"]}

    # ---- 邮件营销 ----
    def list_campaigns(self) -> List[Dict[str, Any]]:
        return list(EMAIL_CAMPAIGNS.values())

    def create_campaign(self, name: str, list_size: int) -> Dict[str, Any]:
        eid = _pid("eml")
        EMAIL_CAMPAIGNS[eid] = {
            "id": eid, "name": name, "list_size": list_size,
            "sent": 0, "open_rate": 0, "ctr": 0,
            "conversion": 0, "unsubscribe": 0,
        }
        return EMAIL_CAMPAIGNS[eid]

    def send_campaign(self, eid: str) -> Optional[Dict[str, Any]]:
        e = EMAIL_CAMPAIGNS.get(eid)
        if not e:
            return None
        e["sent"] = e["list_size"]
        e["open_rate"] = round(random.uniform(0.2, 0.4), 3)
        e["ctr"] = round(random.uniform(0.04, 0.12), 3)
        e["conversion"] = round(random.uniform(0.005, 0.03), 3)
        e["unsubscribe"] = round(random.uniform(0.001, 0.005), 3)
        return e

    # ---- 数据分析 ----
    def analytics(self) -> Dict[str, Any]:
        daily = ANALYTICS.get("daily", [])
        total_pv = sum(d["pv"] for d in daily)
        total_uv = sum(d["uv"] for d in daily)
        return {
            "daily": daily,
            "funnel": ANALYTICS.get("funnel", []),
            "sources": ANALYTICS.get("sources", []),
            "summary": {
                "total_pv_30d": total_pv,
                "total_uv_30d": total_uv,
                "avg_bounce_rate": round(
                    sum(d["bounce_rate"] for d in daily) / max(1, len(daily)), 3),
            },
        }
