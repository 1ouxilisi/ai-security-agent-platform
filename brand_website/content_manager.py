# -*- coding: utf-8 -*-
"""
brand_website/content_manager.py — 官网内容管理模块。

覆盖：页面管理、内容编辑器、媒体库、导航菜单、多语言支持、SEO 优化。
全部内存字典模拟，不依赖数据库；可真实生成落地页 HTML。
"""

from __future__ import annotations

import html
import time
import uuid
from typing import Any, Dict, List, Optional


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _pid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- #
# 内存数据
# --------------------------------------------------------------------------- #
PAGES: Dict[str, Dict[str, Any]] = {}
MEDIA: Dict[str, Dict[str, Any]] = {}
NAV_MENUS: Dict[str, Dict[str, Any]] = {}
TRANSLATIONS: Dict[str, Dict[str, Dict[str, str]]] = {
    "zh-CN": {}, "en-US": {}, "ja-JP": {},
}
SEO_GLOBAL: Dict[str, Any] = {
    "site_name": "AI Hacking Agent",
    "default_title": "AI Hacking Agent — 智能安全攻防平台",
    "default_description": "一站式 AI 驱动的网络安全攻防、渗透测试与合规治理平台。",
    "default_keywords": ["AI安全", "渗透测试", "攻防演练", "合规治理"],
    "og_image": "/static/og-default.png",
    "twitter_handle": "@aihackingagent",
    "google_site_verification": "",
    "baidu_site_verification": "",
}

# 预置页面种子
_SEED_PAGES = [
    ("home", "首页", "home", "已发布"),
    ("products", "产品页", "products", "已发布"),
    ("features", "功能页", "features", "已发布"),
    ("pricing", "定价页", "pricing", "已发布"),
    ("cases", "客户案例", "cases", "已发布"),
    ("docs", "文档页", "docs", "草稿"),
    ("blog", "博客页", "blog", "已发布"),
    ("about", "关于我们", "about", "草稿"),
    ("contact", "联系我们", "contact", "已发布"),
]


def _seed() -> None:
    for slug, title, ptype, status in _SEED_PAGES:
        if slug in PAGES:
            continue
        PAGES[slug] = {
            "slug": slug, "title": title, "type": ptype, "status": status,
            "content_md": f"# {title}\n\n这是{title}的初始内容，使用 Markdown 编写。",
            "seo_title": title, "seo_description": f"{title} - AI Hacking Agent",
            "seo_keywords": ["安全", "AI", title],
            "version": 1, "versions": [], "author": "admin",
            "created_at": _now(), "updated_at": _now(), "language": "zh-CN",
        }
    if not NAV_MENUS:
        NAV_MENUS["main"] = {
            "name": "主导航", "items": [
                {"label": "首页", "url": "/", "order": 1},
                {"label": "产品", "url": "/products", "order": 2},
                {"label": "功能", "url": "/features", "order": 3},
                {"label": "定价", "url": "/pricing", "order": 4},
                {"label": "案例", "url": "/cases", "order": 5},
                {"label": "文档", "url": "/docs", "order": 6},
            ],
        }
        NAV_MENUS["footer"] = {
            "name": "页脚导航", "items": [
                {"label": "关于我们", "url": "/about", "order": 1},
                {"label": "联系我们", "url": "/contact", "order": 2},
                {"label": "隐私政策", "url": "/privacy", "order": 3},
            ],
        }


_seed()


# --------------------------------------------------------------------------- #
# 页面管理
# --------------------------------------------------------------------------- #
class PageManager:
    def list_pages(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(PAGES.values())
        if status:
            items = [p for p in items if p["status"] == status]
        return sorted(items, key=lambda x: x["slug"])

    def get_page(self, slug: str) -> Optional[Dict[str, Any]]:
        return PAGES.get(slug)

    def create_page(self, title: str, ptype: str = "page",
                    content_md: str = "", author: str = "admin") -> Dict[str, Any]:
        slug = title.lower().replace(" ", "-") or _pid("page")
        if slug in PAGES:
            slug = f"{slug}-{uuid.uuid4().hex[:4]}"
        page = {
            "slug": slug, "title": title, "type": ptype, "status": "草稿",
            "content_md": content_md or f"# {title}\n",
            "seo_title": title, "seo_description": "", "seo_keywords": [],
            "version": 1, "versions": [], "author": author,
            "created_at": _now(), "updated_at": _now(), "language": "zh-CN",
        }
        PAGES[slug] = page
        return page

    def edit_page(self, slug: str, **fields: Any) -> Optional[Dict[str, Any]]:
        p = PAGES.get(slug)
        if not p:
            return None
        for k, v in fields.items():
            if k in ("title", "content_md", "seo_title", "seo_description",
                     "seo_keywords", "language", "type"):
                p[k] = v
        p["updated_at"] = _now()
        return p

    def publish(self, slug: str) -> Optional[Dict[str, Any]]:
        p = PAGES.get(slug)
        if not p:
            return None
        p["status"] = "已发布"
        p["updated_at"] = _now()
        return p

    def unpublish(self, slug: str) -> Optional[Dict[str, Any]]:
        p = PAGES.get(slug)
        if not p:
            return None
        p["status"] = "已下线"
        p["updated_at"] = _now()
        return p

    def save_version(self, slug: str) -> Optional[Dict[str, Any]]:
        p = PAGES.get(slug)
        if not p:
            return None
        snap = {
            "version": p["version"], "title": p["title"],
            "content_md": p["content_md"], "saved_at": _now(),
        }
        p["versions"].append(snap)
        p["version"] += 1
        p["updated_at"] = _now()
        return snap

    def preview(self, slug: str, language: str = "zh-CN") -> Dict[str, Any]:
        p = PAGES.get(slug)
        if not p:
            return {}
        return {
            "slug": slug, "title": p["title"], "language": language,
            "html": self._render_html(p, language),
            "preview_at": _now(),
        }

    def _render_html(self, page: Dict[str, Any], language: str) -> str:
        body = html.escape(page.get("content_md", "")).replace("\n", "<br/>")
        title = page.get("seo_title") or page.get("title", "")
        desc = page.get("seo_description", "")
        return (
            f"<!DOCTYPE html><html lang='{html.escape(language)}'><head>"
            f"<meta charset='utf-8'><title>{html.escape(title)}</title>"
            f"<meta name='description' content='{html.escape(desc)}'>"
            f"</head><body><h1>{html.escape(page['title'])}</h1>"
            f"<div class='page-body'>{body}</div></body></html>"
        )


# --------------------------------------------------------------------------- #
# 内容编辑器（组件块）
# --------------------------------------------------------------------------- #
class ContentEditor:
    COMPONENT_TYPES = ["richtext", "markdown", "codeblock", "image",
                       "video", "table", "embed", "separator"]

    def insert_component(self, slug: str, comp_type: str,
                         payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        p = PAGES.get(slug)
        if not p:
            return None
        block = {
            "id": _pid("blk"), "type": comp_type, "payload": payload,
            "created_at": _now(),
        }
        blocks = p.setdefault("blocks", [])
        blocks.append(block)
        p["updated_at"] = _now()
        return block

    def list_components(self, slug: str) -> List[Dict[str, Any]]:
        p = PAGES.get(slug)
        return p.get("blocks", []) if p else []

    def configure_seo(self, slug: str, title: str, description: str,
                      keywords: List[str], og_image: str = "",
                      twitter_card: str = "summary_large_image") -> Optional[Dict[str, Any]]:
        p = PAGES.get(slug)
        if not p:
            return None
        p["seo_title"] = title
        p["seo_description"] = description
        p["seo_keywords"] = keywords
        p["og_image"] = og_image
        p["twitter_card"] = twitter_card
        p["updated_at"] = _now()
        return p


# --------------------------------------------------------------------------- #
# 媒体库
# --------------------------------------------------------------------------- #
class MediaLibrary:
    def upload(self, name: str, mtype: str = "image", size: int = 0,
               category: str = "general", tags: Optional[List[str]] = None) -> Dict[str, Any]:
        mid = _pid("media")
        item = {
            "id": mid, "name": name, "type": mtype, "size": size,
            "category": category, "tags": tags or [],
            "url": f"/static/media/{name}", "cdn_url": f"https://cdn.aihacking.io/{name}",
            "uploaded_at": _now(),
        }
        MEDIA[mid] = item
        return item

    def list_media(self, mtype: Optional[str] = None,
                  keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(MEDIA.values())
        if mtype:
            items = [m for m in items if m["type"] == mtype]
        if keyword:
            kw = keyword.lower()
            items = [m for m in items
                     if kw in m["name"].lower() or kw in " ".join(m["tags"]).lower()]
        return items

    def delete(self, mid: str) -> bool:
        return MEDIA.pop(mid, None) is not None


# --------------------------------------------------------------------------- #
# 导航菜单
# --------------------------------------------------------------------------- #
class NavigationMenu:
    def list_menus(self) -> List[Dict[str, Any]]:
        return list(NAV_MENUS.values())

    def get_menu(self, key: str) -> Optional[Dict[str, Any]]:
        return NAV_MENUS.get(key)

    def add_item(self, key: str, label: str, url: str, order: int = 0) -> Optional[Dict[str, Any]]:
        m = NAV_MENUS.get(key)
        if not m:
            return None
        item = {"label": label, "url": url, "order": order,
                "permission": "public"}
        m["items"].append(item)
        m["items"].sort(key=lambda x: x["order"])
        return item

    def reorder(self, key: str, orders: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        m = NAV_MENUS.get(key)
        if not m:
            return None
        for it in m["items"]:
            for o in orders:
                if o.get("label") == it["label"]:
                    it["order"] = o.get("order", it["order"])
        m["items"].sort(key=lambda x: x["order"])
        return m

    def set_permission(self, key: str, label: str,
                        permission: str) -> Optional[Dict[str, Any]]:
        m = NAV_MENUS.get(key)
        if not m:
            return None
        for it in m["items"]:
            if it["label"] == label:
                it["permission"] = permission
        return m


# --------------------------------------------------------------------------- #
# 多语言
# --------------------------------------------------------------------------- #
class I18nManager:
    LANGUAGES = ["zh-CN", "en-US", "ja-JP"]

    def list_languages(self) -> List[Dict[str, Any]]:
        return [{"code": c, "name": {"zh-CN": "中文", "en-US": "English",
                                     "ja-JP": "日本語"}[c],
                 "keys": len(TRANSLATIONS.get(c, {}))}
                for c in self.LANGUAGES]

    def set_translation(self, lang: str, key: str, value: str) -> Dict[str, Any]:
        TRANSLATIONS.setdefault(lang, {})[key] = value
        return {"lang": lang, "key": key, "value": value}

    def get_translations(self, lang: str) -> Dict[str, str]:
        return TRANSLATIONS.get(lang, {})

    def translate_page(self, slug: str, lang: str) -> Optional[Dict[str, Any]]:
        p = PAGES.get(slug)
        if not p:
            return None
        return {
            "slug": slug, "source_lang": p.get("language", "zh-CN"),
            "target_lang": lang,
            "translated_title": f"[{lang}] {p['title']}",
            "translated_at": _now(),
        }


# --------------------------------------------------------------------------- #
# SEO 优化
# --------------------------------------------------------------------------- #
class SEOWizard:
    def global_settings(self) -> Dict[str, Any]:
        return dict(SEO_GLOBAL)

    def update_global(self, **fields: Any) -> Dict[str, Any]:
        for k, v in fields.items():
            if k in SEO_GLOBAL:
                SEO_GLOBAL[k] = v
        return dict(SEO_GLOBAL)

    def page_seo(self, slug: str) -> Optional[Dict[str, Any]]:
        p = PAGES.get(slug)
        if not p:
            return None
        return {
            "slug": slug,
            "title": p.get("seo_title"),
            "description": p.get("seo_description"),
            "keywords": p.get("seo_keywords", []),
            "og_image": p.get("og_image", SEO_GLOBAL["og_image"]),
            "twitter_card": p.get("twitter_card", "summary"),
        }

    def generate_sitemap(self) -> str:
        urls = [{"loc": f"/{p['slug']}", "lastmod": p["updated_at"]}
                for p in PAGES.values() if p["status"] == "已发布"]
        lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
        for u in urls:
            lines.append(f"  <url><loc>{u['loc']}</loc>"
                         f"<lastmod>{u['lastmod']}</lastmod></url>")
        lines.append("</urlset>")
        return "\n".join(lines)

    def robots_txt(self) -> str:
        return ("User-agent: *\nDisallow: /admin/\nAllow: /\n\n"
                "Sitemap: /sitemap.xml\n")

    def structured_data(self, slug: str) -> Dict[str, Any]:
        p = PAGES.get(slug)
        if not p:
            return {}
        return {
            "@context": "https://schema.org",
            "@type": "WebPage",
            "name": p["title"], "description": p.get("seo_description", ""),
            "inLanguage": p.get("language", "zh-CN"),
        }


# --------------------------------------------------------------------------- #
# 落地页渲染（真实生成 HTML）
# --------------------------------------------------------------------------- #
def render_landing_page(slug: str = "home",
                        language: str = "zh-CN") -> Dict[str, Any]:
    pg = PageManager()
    p = PAGES.get(slug)
    if not p:
        return {"html": "", "error": f"页面 {slug} 不存在"}
    nav = NAV_MENUS.get("main", {})
    nav_html = "".join(
        f"<a class='nav-link' href='{html.escape(i['url'])}'>{html.escape(i['label'])}</a>"
        for i in nav.get("items", [])
    )
    body = html.escape(p.get("content_md", "")).replace("\n", "<br/>")
    title = p.get("seo_title") or p["title"]
    html_doc = (
        "<!DOCTYPE html><html lang='" + html.escape(language) + "'><head>"
        "<meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        f"<meta name='description' content='{html.escape(p.get('seo_description', ''))}'>"
        "<style>body{font-family:system-ui;margin:0;background:#0b1220;color:#e5e7eb}"
        ".nav{display:flex;gap:16px;padding:16px 32px;background:#111827}"
        ".nav-link{color:#93c5fd;text-decoration:none}"
        ".hero{padding:64px 32px;max-width:960px;margin:0 auto}"
        "</style></head><body>"
        f"<nav class='nav'>{nav_html}</nav>"
        f"<main class='hero'><h1>{html.escape(p['title'])}</h1>"
        f"<div>{body}</div></main></body></html>"
    )
    return {
        "slug": slug, "language": language, "title": title,
        "html": html_doc, "bytes": len(html_doc.encode("utf-8")),
        "rendered_at": _now(),
    }
