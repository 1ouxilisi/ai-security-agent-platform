# -*- coding: utf-8 -*-
"""
localization.py — 本地化与文化适配（第25轮升级方向4 / 模块5）。

包含：
  - 本地化管理：区域设置/时区/日历/节假日/工作时间/度量衡/纸张大小/地址格式/电话号码格式
  - 文化适配：颜色偏好/图标偏好/布局偏好/内容偏好/营销偏好/沟通偏好/禁忌/敏感话题
  - 区域内容管理：区域新闻/公告/活动/案例/客户/合作伙伴/文档/支持
  - 区域营销：SEO/SEM/社交媒体/广告/活动/合作伙伴/KOL/分析
  - 区域支持：客服/技术支持/培训/文档/社区/论坛/工单/SLA
  - 区域法律：隐私政策/服务条款/Cookie政策/可接受使用政策/免责声明/法律声明

全部内存字典模拟，不建数据库表。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ==================== 区域设置 ====================

REGIONAL_SETTINGS: Dict[str, Dict[str, Any]] = {
    "CN": {
        "locale": "zh-CN", "timezone": "Asia/Shanghai", "calendar": "gregorian",
        "weekend_days": ["saturday", "sunday"], "work_hours": "09:00-18:00",
        "measurement": "metric", "paper_size": "A4",
        "address_format": "{province}{city}{district}{street}{number}",
        "phone_format": "+86 1XX-XXXX-XXXX", "date_format": "YYYY-MM-DD",
        "first_day_of_week": "monday",
    },
    "US": {
        "locale": "en-US", "timezone": "America/New_York", "calendar": "gregorian",
        "weekend_days": ["saturday", "sunday"], "work_hours": "09:00-17:00",
        "measurement": "imperial", "paper_size": "Letter",
        "address_format": "{street}, {city}, {state} {zip}",
        "phone_format": "+1 (XXX) XXX-XXXX", "date_format": "MM/DD/YYYY",
        "first_day_of_week": "sunday",
    },
    "JP": {
        "locale": "ja-JP", "timezone": "Asia/Tokyo", "calendar": "gregorian",
        "weekend_days": ["saturday", "sunday"], "work_hours": "09:00-18:00",
        "measurement": "metric", "paper_size": "A4",
        "address_format": "{prefecture}{city}{ward}{address}",
        "phone_format": "+81 XX-XXXX-XXXX", "date_format": "YYYY/MM/DD",
        "first_day_of_week": "sunday",
    },
    "DE": {
        "locale": "de-DE", "timezone": "Europe/Berlin", "calendar": "gregorian",
        "weekend_days": ["saturday", "sunday"], "work_hours": "09:00-17:30",
        "measurement": "metric", "paper_size": "A4",
        "address_format": "{street} {number}, {postal} {city}",
        "phone_format": "+49 XXX XXXXXXX", "date_format": "DD.MM.YYYY",
        "first_day_of_week": "monday",
    },
    "SA": {
        "locale": "ar-SA", "timezone": "Asia/Riyadh", "calendar": "islamic",
        "weekend_days": ["friday", "saturday"], "work_hours": "08:00-17:00",
        "measurement": "metric", "paper_size": "A4",
        "address_format": "{city}, {district}, {street}",
        "phone_format": "+966 5X-XXX-XXXX", "date_format": "DD/MM/YYYY",
        "first_day_of_week": "saturday",
    },
    "BR": {
        "locale": "pt-BR", "timezone": "America/Sao_Paulo", "calendar": "gregorian",
        "weekend_days": ["saturday", "sunday"], "work_hours": "09:00-18:00",
        "measurement": "metric", "paper_size": "A4",
        "address_format": "{street}, {number} - {district}, {city}-{state}",
        "phone_format": "+55 (XX) XXXXX-XXXX", "date_format": "DD/MM/YYYY",
        "first_day_of_week": "sunday",
    },
}


# ==================== 节假日 ====================

HOLIDAYS: Dict[str, List[Dict[str, str]]] = {
    "CN": [
        {"name": "春节", "date": "2026-02-17", "type": "national"},
        {"name": "国庆节", "date": "2026-10-01", "type": "national"},
        {"name": "中秋节", "date": "2026-09-25", "type": "cultural"},
        {"name": "劳动节", "date": "2026-05-01", "type": "national"},
        {"name": "元旦", "date": "2026-01-01", "type": "national"},
    ],
    "US": [
        {"name": "元旦", "date": "2026-01-01", "type": "federal"},
        {"name": "独立日", "date": "2026-07-04", "type": "federal"},
        {"name": "感恩节", "date": "2026-11-26", "type": "federal"},
        {"name": "圣诞节", "date": "2026-12-25", "type": "federal"},
    ],
    "JP": [
        {"name": "新年", "date": "2026-01-01", "type": "national"},
        {"name": "黄金周", "date": "2026-04-29", "type": "national"},
        {"name": "盂兰盆节", "date": "2026-08-13", "type": "cultural"},
        {"name": "圣诞节", "date": "2026-12-25", "type": "cultural"},
    ],
    "DE": [
        {"name": "元旦", "date": "2026-01-01", "type": "national"},
        {"name": "劳动节", "date": "2026-05-01", "type": "national"},
        {"name": "德国统一日", "date": "2026-10-03", "type": "national"},
        {"name": "圣诞节", "date": "2026-12-25", "type": "national"},
    ],
    "SA": [
        {"name": "开斋节", "date": "2026-03-20", "type": "religious"},
        {"name": "宰牲节", "date": "2026-05-27", "type": "religious"},
        {"name": "国庆日", "date": "2026-09-23", "type": "national"},
    ],
}


# ==================== 文化适配 ====================

CULTURAL_PREFERENCES: Dict[str, Dict[str, Any]] = {
    "CN": {
        "colors": {"primary": "#E60012", "secondary": "#FFD700", "background": "#FFF8F0", "preferred": "red/gold", "meaning": "red=lucky, gold=wealth"},
        "icons": {"preferred_style": "flat_colored", "avoid": "owl(bad_luck)", "animals": {"dragon": "auspicious", "panda": "popular"}},
        "layout": {"rtl": False, "reading_direction": "vertical_optional", "content_density": "high", "photo_people": "group_photos"},
        "marketing": {"style": "collectivist", "tone": "respectful_formal", "influencers": "celebrity_first", "social_platforms": ["wechat", "weibo", "douyin"], "taboo_colors": ["white(funeral)"], "taboo_topics": ["tibet", "taiwan_status", "cultural_revolution"]},
        "communication": {"formality": "high", "greeting": "bow_slight", "email_style": "formal_long", "directness": "indirect"},
    },
    "US": {
        "colors": {"primary": "#0066CC", "secondary": "#FF6600", "background": "#FFFFFF", "preferred": "blue/orange", "meaning": "blue=trust, red=urgency"},
        "icons": {"preferred_style": "minimalist_line", "avoid": "cross_religious", "animals": {"eagle": "national", "bald_eagle": "patriotic"}},
        "layout": {"rtl": False, "reading_direction": "horizontal_ltr", "content_density": "medium", "photo_people": "diverse_individuals"},
        "marketing": {"style": "individualist", "tone": "casual_direct", "influencers": "micro_influencers", "social_platforms": ["facebook", "instagram", "twitter", "tiktok"], "taboo_colors": [], "taboo_topics": ["politics", "religion", "gun_control", "abortion"]},
        "communication": {"formality": "low", "greeting": "handshake_firm", "email_style": "brief_scannable", "directness": "direct"},
    },
    "JP": {
        "colors": {"primary": "#BC002D", "secondary": "#FFFFFF", "background": "#FAFAFA", "preferred": "subtle_minimal", "meaning": "red=life, white=purity"},
        "icons": {"preferred_style": "cute_kawaii", "avoid": "loud_bright", "animals": {"cat": "lucky", "crane": "longevity"}},
        "layout": {"rtl": False, "reading_direction": "vertical_horizontal", "content_density": "high", "photo_people": "polite_professional"},
        "marketing": {"style": "polite_quality", "tone": "honorific_keigo", "influencers": "talent_idol", "social_platforms": ["line", "twitter", "instagram"], "taboo_colors": ["black_with_white_funeral"], "taboo_topics": ["wwii", "emperor_criticism", "ethnic_minorities"]},
        "communication": {"formality": "very_high", "greeting": "bow_deep", "email_style": "very_formal", "directness": "very_indirect"},
    },
    "DE": {
        "colors": {"primary": "#000000", "secondary": "#DD0000", "background": "#FFFFFF", "preferred": "serious_black_red", "meaning": "black=quality, red=trust"},
        "icons": {"preferred_style": "technical_precise", "avoid": "cartoony", "animals": ["eagle"]},
        "layout": {"rtl": False, "reading_direction": "horizontal_ltr", "content_density": "medium", "photo_people": "professional_serious"},
        "marketing": {"style": "technical_rational", "tone": "direct_factual", "influencers": "expert_engineers", "social_platforms": ["xing", "linkedin", "twitter"], "taboo_colors": [], "taboo_topics": ["nazi_history", "second_world_war"]},
        "communication": {"formality": "high", "greeting": "handshake_formal", "email_style": "formal_detailed", "directness": "direct_but_polite"},
    },
    "SA": {
        "colors": {"primary": "#006C35", "secondary": "#FFFFFF", "background": "#F5F5F0", "preferred": "green_gold", "meaning": "green=islamic, gold=luxury"},
        "icons": {"preferred_style": "geometric_islamic", "avoid": "human_faces", "animals": ["pigs(forbidden)"]},
        "layout": {"rtl": True, "reading_direction": "rtl", "content_density": "medium", "photo_people": "modest_separate"},
        "marketing": {"style": "family_religious", "tone": "respectful_conservative", "influencers": "religious_scholars", "social_platforms": ["twitter", "snapchat", "tiktok"], "taboo_colors": [], "taboo_topics": ["islam_criticism", "alcohol", " pork", "lgbt", " israel"]},
        "communication": {"formality": "high", "greeting": "handshake_right_only", "email_style": "formal", "directness": "indirect_respectful"},
    },
}


# ==================== 区域内容管理 ====================

class RegionalContent:
    """区域内容管理"""

    def __init__(self):
        self.news: Dict[str, List[Dict[str, Any]]] = {}
        self.announcements: Dict[str, List[Dict[str, Any]]] = {}
        self.cases: List[Dict[str, Any]] = []
        self.partners: List[Dict[str, Any]] = []
        self._seed()

    def _seed(self):
        self.news = {
            "CN": [
                {"id": "N-CN-001", "title": "中国区数据安全中心上线", "date": "2026-09-01", "summary": "通过等保三级认证"},
                {"id": "N-CN-002", "title": "PIPL合规更新", "date": "2026-08-15", "summary": "响应最新个保法要求"},
            ],
            "US": [
                {"id": "N-US-001", "title": "US East Region Expansion", "date": "2026-09-05", "summary": "New datacenter in Virginia"},
                {"id": "N-US-002", "title": "CCPA Compliance Update", "date": "2026-08-20", "summary": "New data subject rights portal"},
            ],
            "JP": [
                {"id": "N-JP-001", "title": "東京リージョン増強", "date": "2026-09-10", "summary": "大阪に追加ノード"},
            ],
        }
        self.announcements = {
            "CN": [{"id": "A-CN-001", "title": "系统维护通知", "date": "2026-09-20", "message": "9月20日凌晨2-4点系统维护"}],
            "US": [{"id": "A-US-001", "title": "Scheduled Maintenance", "date": "2026-09-20", "message": "Sept 20 2AM-4AM ET downtime"}],
        }
        self.cases = [
            {"id": "CASE-001", "region": "CN", "industry": "金融", "customer": "某大型银行", "result": "漏洞修复率99%", "year": 2026},
            {"id": "CASE-002", "region": "US", "industry": "Tech", "customer": "Fortune 500 Tech", "result": "70% reduction in breach risk", "year": 2026},
            {"id": "CASE-003", "region": "JP", "industry": "製造業", "customer": "大手自動車メーカー", "result": "セキュリティ監査合格", "year": 2026},
        ]
        self.partners = [
            {"id": "P-001", "name": "阿里云", "region": "CN", "type": "cloud_provider", "status": "active"},
            {"id": "P-002", "name": "AWS", "region": "Global", "type": "cloud_provider", "status": "active"},
            {"id": "P-003", "name": "NTT Data", "region": "JP", "type": "system_integrator", "status": "active"},
            {"id": "P-004", "name": "T-Systems", "region": "DE", "type": "system_integrator", "status": "trial"},
        ]

    def list_news(self, region: str = "") -> Dict[str, Any]:
        if region:
            return {"region": region, "news": self.news.get(region, [])}
        return {"all_news": self.news, "total_items": sum(len(v) for v in self.news.values())}


# ==================== 区域营销 ====================

class RegionalMarketing:
    """区域营销管理"""

    def __init__(self):
        self.campaigns: List[Dict[str, Any]] = []
        self.kol_list: List[Dict[str, Any]] = []
        self._seed()

    def _seed(self):
        self.campaigns = [
            {"id": "CAMP-001", "region": "CN", "channel": "wechat", "budget": 50000, "spent": 32000, "leads": 450, "status": "active", "start_date": "2026-09-01", "end_date": "2026-10-31"},
            {"id": "CAMP-002", "region": "US", "channel": "google_ads", "budget": 30000, "spent": 28000, "leads": 320, "status": "active", "start_date": "2026-09-01", "end_date": "2026-11-30"},
            {"id": "CAMP-003", "region": "JP", "channel": "line_ad", "budget": 20000, "spent": 8000, "leads": 180, "status": "active", "start_date": "2026-09-10", "end_date": "2026-12-31"},
            {"id": "CAMP-004", "region": "DE", "channel": "linkedin", "budget": 15000, "spent": 12000, "leads": 95, "status": "active", "start_date": "2026-08-15", "end_date": "2026-10-15"},
        ]
        self.kol_list = [
            {"id": "KOL-001", "name": "安全研究员张三", "region": "CN", "platform": "weibo", "followers": 500000, "engagement_rate": 4.5, "cost_post": 8000},
            {"id": "KOL-002", "name": "CyberSecurityGuru", "region": "US", "platform": "twitter", "followers": 1200000, "engagement_rate": 3.2, "cost_post": 5000},
            {"id": "KOL-003", "name": "セキュリティ太郎", "region": "JP", "platform": "youtube", "followers": 350000, "engagement_rate": 5.1, "cost_post": 6000},
        ]

    def campaigns_summary(self) -> Dict[str, Any]:
        total_budget = sum(c["budget"] for c in self.campaigns)
        total_spent = sum(c["spent"] for c in self.campaigns)
        total_leads = sum(c["leads"] for c in self.campaigns)
        return {"total_campaigns": len(self.campaigns), "total_budget": total_budget,
                "total_spent": total_spent, "total_leads": total_leads,
                "cpl": round(total_spent / total_leads, 2) if total_leads else 0,
                "campaigns": self.campaigns, "kol_partners": len(self.kol_list)}


# ==================== 区域支持 ====================

SUPPORT_TIERS: Dict[str, Dict[str, Any]] = {
    "basic": {"name": "基础支持", "response_sla_hours": 24, "channels": ["email"], "hours": "9x5", "escalation": "next_business_day"},
    "professional": {"name": "专业支持", "response_sla_hours": 4, "channels": ["email", "chat", "ticket"], "hours": "24x5", "escalation": "2小时"},
    "enterprise": {"name": "企业支持", "response_sla_hours": 1, "channels": ["email", "chat", "phone", "dedicated_slack"], "hours": "24x7", "escalation": "30分钟"},
}


class RegionalSupport:
    """区域支持管理"""

    def __init__(self):
        self.tickets: Dict[str, Dict[str, Any]] = {}
        self.csat: List[Dict[str, Any]] = []
        self._seed()

    def _seed(self):
        regions = ["CN", "US", "JP", "DE", "SG", "BR"]
        statuses = ["open", "in_progress", "resolved", "closed"]
        for i in range(20):
            tid = f"TKT-{uuid.uuid4().hex[:8]}"
            self.tickets[tid] = {
                "ticket_id": tid, "subject": f"Support request #{i}",
                "region": regions[i % len(regions)], "status": statuses[i % len(statuses)],
                "priority": ["low", "medium", "high", "critical"][i % 4],
                "created_at": datetime.now().isoformat(timespec="seconds"),
                "sla_due": (datetime.now()).isoformat(timespec="seconds"),
                "csat": 3 + (i % 3),
            }

    def create_ticket(self, subject: str, region: str, priority: str = "medium") -> Dict[str, Any]:
        tid = f"TKT-{uuid.uuid4().hex[:8]}"
        self.tickets[tid] = {
            "ticket_id": tid, "subject": subject, "region": region,
            "status": "open", "priority": priority,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        return {"ticket_id": tid, "status": "open", "region": region}

    def stats(self) -> Dict[str, Any]:
        total = len(self.tickets)
        open_tickets = sum(1 for t in self.tickets.values() if t["status"] in ("open", "in_progress"))
        resolved = sum(1 for t in self.tickets.values() if t["status"] in ("resolved", "closed"))
        csat_scores = [t["csat"] for t in self.tickets.values() if "csat" in t]
        avg_csat = round(sum(csat_scores) / len(csat_scores), 2) if csat_scores else 0
        return {"total_tickets": total, "open": open_tickets, "resolved": resolved,
                "resolution_rate": round(resolved / total * 100, 1) if total else 0,
                "avg_csat": avg_csat, "support_tiers": SUPPORT_TIERS}


# ==================== 区域法律 ====================

LEGAL_DOCUMENTS: Dict[str, Dict[str, Dict[str, str]]] = {
    "privacy_policy": {
        "CN": {"version": "v3.2", "last_updated": "2026-08-01", "jurisdiction": "中华人民共和国法律", "link": "/legal/cn/privacy"},
        "US": {"version": "v2.8", "last_updated": "2026-07-15", "jurisdiction": "California/Delaware law", "link": "/legal/us/privacy"},
        "EU": {"version": "v4.1", "last_updated": "2026-06-20", "jurisdiction": "EU GDPR", "link": "/legal/eu/privacy"},
        "JP": {"version": "v2.5", "last_updated": "2026-05-10", "jurisdiction": "日本APPI", "link": "/legal/jp/privacy"},
    },
    "terms_of_service": {
        "CN": {"version": "v3.0", "last_updated": "2026-08-01", "governing_law": "中国法律", "link": "/legal/cn/tos"},
        "US": {"version": "v2.5", "last_updated": "2026-07-01", "governing_law": "Delaware", "link": "/legal/us/tos"},
        "EU": {"version": "v3.1", "last_updated": "2026-06-15", "governing_law": "Ireland", "link": "/legal/eu/tos"},
    },
    "cookie_policy": {
        "CN": {"version": "v1.8", "last_updated": "2026-07-20", "requires_consent": True, "link": "/legal/cn/cookies"},
        "US": {"version": "v1.5", "last_updated": "2026-06-30", "requires_consent": False, "link": "/legal/us/cookies"},
        "EU": {"version": "v2.0", "last_updated": "2026-08-01", "requires_consent": True, "link": "/legal/eu/cookies"},
    },
}


class RegionalLegal:
    """区域法律文档管理"""

    def __init__(self):
        self.documents = LEGAL_DOCUMENTS

    def list_documents(self) -> Dict[str, Any]:
        return {"categories": list(self.documents.keys()), "documents": self.documents}

    def get_version(self, category: str, region: str) -> Dict[str, Any]:
        docs = self.documents.get(category, {})
        return {"category": category, "region": region, **docs.get(region, {"error": "未找到"})}


# ==================== 主管理器 ====================

class LocalizationManager:
    """本地化与文化适配主类"""

    def __init__(self):
        self.content = RegionalContent()
        self.marketing = RegionalMarketing()
        self.support = RegionalSupport()
        self.legal = RegionalLegal()

    def overview(self) -> Dict[str, Any]:
        return {
            "total_regions_configured": len(REGIONAL_SETTINGS),
            "regional_settings": REGIONAL_SETTINGS,
            "holidays": HOLIDAYS,
            "cultural_preferences": CULTURAL_PREFERENCES,
            "regional_content_news": self.content.news,
            "regional_cases": len(self.content.cases),
            "regional_partners": len(self.content.partners),
            "marketing_campaigns": self.marketing.campaigns_summary(),
            "support_stats": self.support.stats(),
            "legal_documents": list(self.documents_categories()),
        }

    def documents_categories(self):
        return self.legal.documents.keys()


# 全局单例
localization = LocalizationManager()
