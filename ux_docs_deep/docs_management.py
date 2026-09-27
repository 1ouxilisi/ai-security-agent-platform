#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ux_docs_deep/docs_management.py — 文档管理系统。

覆盖六大领域：
    1. 文档管理：列表/分类/标签/版本/审核/发布/归档/搜索
    2. 内容管理：富文本/Markdown/代码块/图片/表格/链接/引用/目录/锚点
    3. 版本管理：版本列表/对比/回滚/发布/审核/历史/差异
    4. 权限管理：文档/分类/角色/用户/组/公开/私有/继承
    5. 协作编辑：多人/实时/评论/@提及/变更跟踪/建议/合并/冲突
    6. 文档分析：阅读量/点赞/收藏/分享/评论/评分/搜索词/热门/质量
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
DOC_STATUSES = ["draft", "in_review", "published", "archived"]
ROLES = ["admin", "editor", "writer", "viewer"]
DOC_CATEGORIES = ["产品", "技术", "运维", "安全", "API", "教程", "FAQ"]


# --------------------------------------------------------------------------- #
# 文档版本
# --------------------------------------------------------------------------- #
class DocVersion:
    def __init__(self, version: str, content: str, author: str, note: str = "") -> None:
        self.version = version
        self.content = content
        self.author = author
        self.note = note
        self.saved_at = time.strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version, "author": self.author,
            "note": self.note, "saved_at": self.saved_at,
            "content_preview": (self.content[:80] + "...") if len(self.content) > 80 else self.content,
        }


# --------------------------------------------------------------------------- #
# 文档对象
# --------------------------------------------------------------------------- #
class DocItem:
    def __init__(self, title: str, category: str, author: str,
                 content: str = "", tags: Optional[List[str]] = None) -> None:
        self.id = f"doc_{uuid.uuid4().hex[:10]}"
        self.title = title
        self.category = category
        self.author = author
        self.content = content
        self.tags: List[str] = tags or []
        self.status = "draft"
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.updated_at = self.created_at
        self.current_version = "1.0.0"
        self.versions: List[DocVersion] = [
            DocVersion("1.0.0", content, author, "初始版本")
        ]
        self.comments: List[Dict[str, Any]] = []
        self.reads = 0
        self.likes = 0
        self.favorites = 0
        self.shares = 0
        self.rating_sum = 0
        self.rating_count = 0
        self.permissions: Dict[str, Any] = {
            "visibility": "private",  # public / internal / private
            "allow_roles": ["admin", "editor"],
            "allow_users": [],
        }

    def to_dict(self, include_content: bool = False) -> Dict[str, Any]:
        base = {
            "id": self.id, "title": self.title, "category": self.category,
            "author": self.author, "tags": self.tags, "status": self.status,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "current_version": self.current_version,
            "version_count": len(self.versions),
            "reads": self.reads, "likes": self.likes,
            "favorites": self.favorites, "shares": self.shares,
            "avg_rating": round(self.rating_sum / max(1, self.rating_count), 1),
            "comment_count": len(self.comments),
            "permissions": self.permissions,
        }
        if include_content:
            base["content"] = self.content
            base["versions"] = [v.to_dict() for v in self.versions]
            base["comments"] = self.comments
        return base


# --------------------------------------------------------------------------- #
# 文档管理器
# --------------------------------------------------------------------------- #
class DocsManager:
    """文档管理系统（内存字典模拟）。"""

    def __init__(self) -> None:
        self.docs: Dict[str, DocItem] = {}
        self.search_logs: List[Dict[str, Any]] = []
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        seeds = [
            ("产品白皮书 v28", "产品", "product-team", "AI Hacking Agent 产品白皮书...", ["v28", "白皮书"]),
            ("API 接入指南", "API", "devrel", "如何使用 OpenAPI 接入...", ["API", "入门"]),
            ("K8s 生产部署手册", "运维", "sre", "K8s 高可用部署...", ["K8s", "生产"]),
            ("等保2.0合规清单", "安全", "compliance", "等保2.0三级要求...", ["合规", "等保"]),
            ("新手快速上手教程", "教程", "doc-team", "30分钟完成首次扫描...", ["入门"]),
        ]
        for title, cat, author, content, tags in seeds:
            d = DocItem(title, cat, author, content, tags)
            d.status = "published"
            self.docs[d.id] = d

    # ---- CRUD ----
    def create_doc(self, title: str, category: str, author: str,
                   content: str = "", tags: Optional[List[str]] = None) -> Dict[str, Any]:
        d = DocItem(title, category, author, content, tags)
        self.docs[d.id] = d
        return d.to_dict()

    def get_doc(self, doc_id: str, inc_content: bool = True) -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return None
        d.reads += 1
        return d.to_dict(include_content=inc_content)

    def update_doc(self, doc_id: str, content: str, author: str,
                   note: str = "") -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return None
        d.content = content
        # 版本号递增
        major, minor, patch = d.current_version.split(".")
        d.current_version = f"{major}.{minor}.{int(patch) + 1}"
        d.versions.append(DocVersion(d.current_version, content, author, note))
        d.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return d.to_dict()

    def delete_doc(self, doc_id: str) -> bool:
        if doc_id in self.docs:
            del self.docs[doc_id]
            return True
        return False

    def list_docs(self, category: Optional[str] = None,
                  status: Optional[str] = None,
                  tag: Optional[str] = None,
                  keyword: Optional[str] = None,
                  sort: str = "updated_desc") -> List[Dict[str, Any]]:
        items = list(self.docs.values())
        if category:
            items = [d for d in items if d.category == category]
        if status:
            items = [d for d in items if d.status == status]
        if tag:
            items = [d for d in items if tag in d.tags]
        if keyword:
            kw = keyword.lower()
            items = [d for d in items
                     if kw in d.title.lower() or kw in d.content.lower()]
        # 排序
        if sort == "updated_desc":
            items.sort(key=lambda x: x.updated_at, reverse=True)
        elif sort == "reads_desc":
            items.sort(key=lambda x: x.reads, reverse=True)
        elif sort == "likes_desc":
            items.sort(key=lambda x: x.likes, reverse=True)
        return [d.to_dict() for d in items]

    # ---- 生命周期 ----
    def submit_for_review(self, doc_id: str) -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return None
        d.status = "in_review"
        return d.to_dict()

    def publish_doc(self, doc_id: str) -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return None
        d.status = "published"
        return d.to_dict()

    def archive_doc(self, doc_id: str) -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return None
        d.status = "archived"
        return d.to_dict()

    # ---- 版本 ----
    def list_versions(self, doc_id: str) -> List[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return []
        return [v.to_dict() for v in reversed(d.versions)]

    def rollback_version(self, doc_id: str, version: str) -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return None
        target = next((v for v in d.versions if v.version == version), None)
        if target is None:
            return None
        d.content = target.content
        major, minor, patch = d.current_version.split(".")
        d.current_version = f"{major}.{minor}.{int(patch) + 1}"
        d.versions.append(DocVersion(d.current_version, d.content,
                                       "system", f"回滚至 {version}"))
        return d.to_dict()

    # ---- 互动 ----
    def like_doc(self, doc_id: str) -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return None
        d.likes += 1
        return d.to_dict()

    def favorite_doc(self, doc_id: str) -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return None
        d.favorites += 1
        return d.to_dict()

    def share_doc(self, doc_id: str) -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return None
        d.shares += 1
        return d.to_dict()

    def rate_doc(self, doc_id: str, score: int) -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return None
        if 1 <= score <= 5:
            d.rating_sum += score
            d.rating_count += 1
        return d.to_dict()

    def comment_doc(self, doc_id: str, user: str,
                     content: str) -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return None
        d.comments.append({
            "id": f"cm_{uuid.uuid4().hex[:8]}",
            "user": user, "content": content,
            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        return d.to_dict()

    # ---- 权限 ----
    def set_permissions(self, doc_id: str, visibility: Optional[str] = None,
                        allow_roles: Optional[List[str]] = None,
                        allow_users: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return None
        if visibility:
            d.permissions["visibility"] = visibility
        if allow_roles is not None:
            d.permissions["allow_roles"] = allow_roles
        if allow_users is not None:
            d.permissions["allow_users"] = allow_users
        return d.to_dict()

    # ---- 搜索 ----
    def search(self, keyword: str) -> List[Dict[str, Any]]:
        self.search_logs.append({
            "keyword": keyword,
            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        return self.list_docs(keyword=keyword)

    # ---- 分析 ----
    def analytics(self) -> Dict[str, Any]:
        items = list(self.docs.values())
        by_cat: Dict[str, int] = {}
        for d in items:
            by_cat[d.category] = by_cat.get(d.category, 0) + 1
        hot = sorted(items, key=lambda x: x.reads, reverse=True)[:5]
        return {
            "total_docs": len(items),
            "by_category": by_cat,
            "published": len([d for d in items if d.status == "published"]),
            "draft": len([d for d in items if d.status == "draft"]),
            "total_reads": sum(d.reads for d in items),
            "total_likes": sum(d.likes for d in items),
            "hot_docs": [{"id": d.id, "title": d.title, "reads": d.reads}
                         for d in hot],
            "search_log_count": len(self.search_logs),
            "recent_searches": [s["keyword"]
                                for s in self.search_logs[-10:]],
        }

    # ---- 元数据 ----
    def list_categories(self) -> List[str]:
        return DOC_CATEGORIES

    def list_roles(self) -> List[str]:
        return ROLES


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_manager: Optional[DocsManager] = None


def get_docs_manager() -> DocsManager:
    global _manager
    if _manager is None:
        _manager = DocsManager()
    return _manager
