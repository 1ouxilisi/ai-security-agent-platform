#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_training_deep/security_awareness.py — 安全意识培训深度。

覆盖六大子域：
    1. 意识课程：安全意识微课/视频/图文/短视频
    2. 意识测试：钓鱼模拟/钓鱼点击统计/安全测试题
    3. 意识活动：安全月/钓鱼演练/竞赛/宣传周
    4. 意识材料：海报/邮件模板/宣传册/视频素材
    5. 意识度量：意识水平评估/趋势/部门对比
    6. 意识文化：文化建设/管理层参与/持续改进
"""

from __future__ import annotations

import random
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
AWARENESS_TOPICS: Dict[str, str] = {
    "phishing": "钓鱼邮件防范",
    "password": "密码安全",
    "social_engineering": "社会工程学",
    "data_protection": "数据保护",
    "mobile_security": "移动设备安全",
    "wifi_security": "公共WiFi安全",
    "physical_security": "物理安全",
    "incident_reporting": "事件报告",
}

ACTIVITY_TYPES: Dict[str, str] = {
    "awareness_month": "安全月活动",
    "phishing_drill": "钓鱼演练",
    "competition": "安全竞赛",
    "webinar": "线上讲座",
    "workshop": "线下工作坊",
}


# --------------------------------------------------------------------------- #
# 意识课程
# --------------------------------------------------------------------------- #
class AwarenessCourse:
    """安全意识微课管理。"""

    def __init__(self) -> None:
        self.courses: Dict[str, Dict[str, Any]] = {}
        self._seed_default_courses()

    def _seed_default_courses(self) -> None:
        defaults = [
            ("如何识别钓鱼邮件", "phishing", "video", 5, "5分钟短视频，教你识别钓鱼邮件的典型特征。"),
            ("强密码创建指南", "password", "interactive", 8, "互动式密码强度评估与最佳实践。"),
            ("社会工程学攻击防范", "social_engineering", "text", 10, "常见社会工程学手法及防范策略图文课程。"),
            ("公司数据保护规范", "data_protection", "text", 15, "公司数据分类分级与保护要求。"),
            ("手机安全使用指南", "mobile_security", "video", 6, "移动设备安全使用最佳实践。"),
        ]
        for title, topic, ctype, mins, desc in defaults:
            cid = f"awc_{uuid.uuid4().hex[:8]}"
            self.courses[cid] = {
                "id": cid, "title": title, "topic": topic,
                "type": ctype, "duration_minutes": mins,
                "description": desc,
                "enrollment_count": 0,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

    def list_courses(self, topic: str = "") -> List[Dict[str, Any]]:
        results = list(self.courses.values())
        if topic:
            results = [c for c in results if c["topic"] == topic]
        return results

    def enroll(self, course_id: str, user: str) -> Optional[Dict[str, Any]]:
        c = self.courses.get(course_id)
        if not c:
            return None
        c["enrollment_count"] += 1
        return {"course_id": course_id, "user": user, "enrolled_at": time.strftime("%Y-%m-%d %H:%M:%S")}


# --------------------------------------------------------------------------- #
# 钓鱼模拟测试
# --------------------------------------------------------------------------- #
class PhishingSimulation:
    """钓鱼模拟测试：发送/统计/分析。"""

    def __init__(self) -> None:
        self.campaigns: Dict[str, Dict[str, Any]] = {}
        self.click_logs: List[Dict[str, Any]] = []

    def create_campaign(self, name: str, target_users: List[str],
                        phish_template: str = "urgent_login") -> Dict[str, Any]:
        cid = f"phish_{uuid.uuid4().hex[:8]}"
        campaign = {
            "id": cid, "name": name,
            "template": phish_template,
            "target_count": len(target_users),
            "clicked_count": 0,
            "reported_count": 0,
            "status": "running",
            "target_users": target_users,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.campaigns[cid] = campaign
        return campaign

    def simulate_click(self, campaign_id: str, user: str) -> Optional[Dict[str, Any]]:
        c = self.campaigns.get(campaign_id)
        if not c:
            return None
        c["clicked_count"] += 1
        log = {
            "campaign_id": campaign_id, "user": user,
            "action": "clicked", "clicked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.click_logs.append(log)
        return log

    def simulate_report(self, campaign_id: str, user: str) -> Optional[Dict[str, Any]]:
        c = self.campaigns.get(campaign_id)
        if not c:
            return None
        c["reported_count"] += 1
        log = {
            "campaign_id": campaign_id, "user": user,
            "action": "reported", "reported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.click_logs.append(log)
        return log

    def campaign_results(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        c = self.campaigns.get(campaign_id)
        if not c:
            return None
        click_rate = round(c["clicked_count"] / max(1, c["target_count"]) * 100, 1)
        report_rate = round(c["reported_count"] / max(1, c["target_count"]) * 100, 1)
        return {
            "campaign_id": campaign_id,
            "name": c["name"],
            "target_count": c["target_count"],
            "clicked_count": c["clicked_count"],
            "reported_count": c["reported_count"],
            "click_rate_pct": click_rate,
            "report_rate_pct": report_rate,
            "risk_level": "high" if click_rate > 20 else "medium" if click_rate > 10 else "low",
        }

    def list_campaigns(self) -> List[Dict[str, Any]]:
        return list(self.campaigns.values())


# --------------------------------------------------------------------------- #
# 意识活动
# --------------------------------------------------------------------------- #
class AwarenessActivity:
    """安全意识活动：安全月/竞赛/讲座。"""

    def __init__(self) -> None:
        self.activities: Dict[str, Dict[str, Any]] = {}
        self._seed_default_activities()

    def _seed_default_activities(self) -> None:
        defaults = [
            ("2026年网络安全宣传周", "awareness_month", "全公司范围安全宣传教育活动。", "2026-09-15"),
            ("钓鱼邮件识别竞赛", "competition", "识别钓鱼邮件准确率竞赛，赢取奖品。", "2026-09-20"),
            ("安全意识线上讲座", "webinar", "季度安全意识主题线上讲座。", "2026-10-01"),
        ]
        for name, atype, desc, date in defaults:
            aid = f"act_{uuid.uuid4().hex[:8]}"
            self.activities[aid] = {
                "id": aid, "name": name, "type": atype,
                "description": desc, "scheduled_date": date,
                "participant_count": 0, "status": "planned",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

    def create_activity(self, name: str, atype: str, description: str,
                        scheduled_date: str) -> Dict[str, Any]:
        aid = f"act_{uuid.uuid4().hex[:8]}"
        activity = {
            "id": aid, "name": name, "type": atype,
            "description": description, "scheduled_date": scheduled_date,
            "participant_count": 0, "status": "planned",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.activities[aid] = activity
        return activity

    def join_activity(self, activity_id: str, user: str) -> Optional[Dict[str, Any]]:
        a = self.activities.get(activity_id)
        if not a:
            return None
        a["participant_count"] += 1
        return {"activity_id": activity_id, "user": user, "joined_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    def list_activities(self, atype: str = "") -> List[Dict[str, Any]]:
        results = list(self.activities.values())
        if atype:
            results = [a for a in results if a["type"] == atype]
        return results


# --------------------------------------------------------------------------- #
# 意识材料
# --------------------------------------------------------------------------- #
class AwarenessMaterial:
    """意识宣传材料管理。"""

    def __init__(self) -> None:
        self.materials: Dict[str, Dict[str, Any]] = {}
        self._seed_default_materials()

    def _seed_default_materials(self) -> None:
        defaults = [
            ("钓鱼邮件警示海报", "poster", "phishing", "A2尺寸高清海报"),
            ("密码安全提示卡片", "card", "password", "桌面提示卡片"),
            ("社会工程防范宣传册", "brochure", "social_engineering", "三折页宣传册"),
            ("数据保护培训PPT", "ppt", "data_protection", "20页培训幻灯片"),
            ("安全意识宣传视频", "video", "phishing", "3分钟动画视频"),
        ]
        for name, mtype, topic, desc in defaults:
            mid = f"awm_{uuid.uuid4().hex[:8]}"
            self.materials[mid] = {
                "id": mid, "name": name, "type": mtype,
                "topic": topic, "description": desc,
                "download_count": 0,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

    def list_materials(self, topic: str = "", mtype: str = "") -> List[Dict[str, Any]]:
        results = list(self.materials.values())
        if topic:
            results = [m for m in results if m["topic"] == topic]
        if mtype:
            results = [m for m in results if m["type"] == mtype]
        return results

    def download_material(self, material_id: str) -> Optional[Dict[str, Any]]:
        m = self.materials.get(material_id)
        if not m:
            return None
        m["download_count"] += 1
        return m


# --------------------------------------------------------------------------- #
# 意识度量
# --------------------------------------------------------------------------- #
class AwarenessMetrics:
    """意识水平度量与趋势。"""

    def __init__(self, phishing: PhishingSimulation) -> None:
        self.phishing = phishing

    def awareness_score(self, department: str = "") -> Dict[str, Any]:
        campaigns = self.phishing.list_campaigns()
        if not campaigns:
            return {"score": 0, "level": "unknown", "message": "暂无数据"}
        # compute average click rate across campaigns
        total_target = sum(c["target_count"] for c in campaigns)
        total_clicked = sum(c["clicked_count"] for c in campaigns)
        avg_click_rate = round(total_clicked / max(1, total_target) * 100, 1)
        score = max(0, round(100 - avg_click_rate * 2, 1))
        level = "优秀" if score >= 90 else "良好" if score >= 75 else "一般" if score >= 60 else "待提升"
        return {
            "score": score,
            "level": level,
            "avg_click_rate_pct": avg_click_rate,
            "campaigns_count": len(campaigns),
            "department": department or "全公司",
        }

    def trend_analysis(self) -> Dict[str, Any]:
        campaigns = self.phishing.list_campaigns()
        if len(campaigns) < 2:
            return {"trend": "insufficient_data", "message": "需要至少2次活动数据"}
        rates = []
        for c in campaigns:
            rate = c["clicked_count"] / max(1, c["target_count"]) * 100
            rates.append({"name": c["name"], "click_rate": round(rate, 1)})
        first_rate = rates[0]["click_rate"]
        last_rate = rates[-1]["click_rate"]
        direction = "improving" if last_rate < first_rate else "worsening" if last_rate > first_rate else "stable"
        return {
            "trend": direction,
            "direction_text": "钓鱼点击率下降，意识提升中" if direction == "improving" else "钓鱼点击率上升，需加强培训",
            "data_points": rates,
        }


# --------------------------------------------------------------------------- #
# 意识文化
# --------------------------------------------------------------------------- #
class AwarenessCulture:
    """安全意识文化建设。"""

    def __init__(self) -> None:
        self.initiatives: List[Dict[str, Any]] = []
        self._seed_default_initiatives()

    def _seed_default_initiatives(self) -> None:
        self.initiatives = [
            {
                "id": "init_001", "name": "管理层安全承诺",
                "type": "leadership", "description": "管理层签署安全承诺，带头参与培训。",
                "status": "active",
            },
            {
                "id": "init_002", "name": "安全之星评选",
                "type": "recognition", "description": "每月评选安全意识标兵并公开表彰。",
                "status": "active",
            },
            {
                "id": "init_003", "name": "安全建议奖励机制",
                "type": "feedback", "description": "员工上报安全隐患获得奖励。",
                "status": "active",
            },
        ]

    def list_initiatives(self) -> List[Dict[str, Any]]:
        return self.initiatives

    def add_initiative(self, name: str, itype: str, description: str) -> Dict[str, Any]:
        init = {
            "id": f"init_{uuid.uuid4().hex[:8]}",
            "name": name, "type": itype, "description": description,
            "status": "active", "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.initiatives.append(init)
        return init


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_aw_course: Optional[AwarenessCourse] = None
_phishing: Optional[PhishingSimulation] = None
_activity: Optional[AwarenessActivity] = None
_material: Optional[AwarenessMaterial] = None
_metrics: Optional[AwarenessMetrics] = None
_culture: Optional[AwarenessCulture] = None


def get_awareness_course() -> AwarenessCourse:
    global _aw_course
    if _aw_course is None:
        _aw_course = AwarenessCourse()
    return _aw_course


def get_phishing_simulation() -> PhishingSimulation:
    global _phishing
    if _phishing is None:
        _phishing = PhishingSimulation()
    return _phishing


def get_awareness_activity() -> AwarenessActivity:
    global _activity
    if _activity is None:
        _activity = AwarenessActivity()
    return _activity


def get_awareness_material() -> AwarenessMaterial:
    global _material
    if _material is None:
        _material = AwarenessMaterial()
    return _material


def get_awareness_metrics() -> AwarenessMetrics:
    global _metrics
    if _metrics is None:
        _metrics = AwarenessMetrics(get_phishing_simulation())
    return _metrics


def get_awareness_culture() -> AwarenessCulture:
    global _culture
    if _culture is None:
        _culture = AwarenessCulture()
    return _culture
