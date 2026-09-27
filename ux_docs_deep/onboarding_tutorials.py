#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ux_docs_deep/onboarding_tutorials.py — 新手引导与教程中心。

覆盖六大领域：
    1. 引导流程：首次启动/功能介绍/操作演示/任务引导/进度/完成/跳过
    2. 交互式教程：步骤引导/实时提示/操作验证/错误纠正/进度跟踪/完成奖励
    3. 视频教程：列表/分类/播放/进度/字幕/下载/推荐/搜索
    4. 实验环境：在线实验/沙箱/靶场/练习/指导/验证/报告/证书
    5. 学习路径：入门/进阶/高级/角色/场景/目标/推荐/进度
    6. 帮助中心：文档/FAQ/视频/社区/工单/客服/反馈/搜索
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 引导步骤
# --------------------------------------------------------------------------- #
GUIDE_FLOWS: Dict[str, Dict[str, Any]] = {
    "first_launch": {
        "name": "首次启动引导",
        "steps": [
            {"id": "fl_welcome", "title": "欢迎", "action": "展示欢迎页"},
            {"id": "fl_account", "title": "创建账号", "action": "引导注册"},
            {"id": "fl_org", "title": "组织初始化", "action": "创建/加入组织"},
            {"id": "fl_target", "title": "添加首个目标", "action": "录入资产"},
            {"id": "fl_scan", "title": "执行首次扫描", "action": "一键扫描演示"},
            {"id": "fl_report", "title": "查看报告", "action": "打开示例报告"},
        ],
    },
    "feature_tour": {
        "name": "功能介绍引导",
        "steps": [
            {"id": "ft_nav", "title": "导航菜单", "action": "高亮左侧菜单"},
            {"id": "ft_search", "title": "全局搜索", "action": "演示搜索"},
            {"id": "ft_task", "title": "任务中心", "action": "介绍任务流"},
            {"id": "ft_report", "title": "报告中心", "action": "介绍导出"},
        ],
    },
}

VIDEO_CATEGORIES: Dict[str, str] = {
    "beginner": "入门视频",
    "install": "安装部署",
    "feature": "功能演示",
    "scenario": "场景实战",
    "troubleshoot": "故障排查",
    "dev": "开发者",
}

LAB_ENVIRONMENTS: Dict[str, Dict[str, Any]] = {
    "web_basic":  {"name": "Web 安全入门靶场", "difficulty": "入门",
                   "duration_min": 30, "vulns": ["SQLi", "XSS", "CSRF"]},
    "web_adv":    {"name": "Web 高级漏洞靶场", "difficulty": "进阶",
                   "duration_min": 60, "vulns": ["SSRF", "RCE", "反序列化"]},
    "network":    {"name": "内网渗透靶场", "difficulty": "高级",
                   "duration_min": 120, "vulns": ["横向移动", "域渗透"]},
    "reverse":    {"name": "逆向工程练习场", "difficulty": "高级",
                   "duration_min": 90, "vulns": ["脱壳", "算法分析"]},
    "malware":     {"name": "恶意软件分析沙箱", "difficulty": "专家",
                    "duration_min": 60, "vulns": ["行为分析", "IOC提取"]},
}

LEARNING_PATHS: Dict[str, Dict[str, Any]] = {
    "starter": {"name": "新人3天上手", "target": "安全运营新人",
                "modules": ["安装", "界面", "首次扫描", "报告"], "hours": 8},
    "pentester": {"name": "渗透测试工程师", "target": "渗透测试",
                  "modules": ["信息收集", "漏洞利用", "后渗透", "报告"], "hours": 40},
    "soc_analyst": {"name": "SOC分析师", "target": "安全运营",
                    "modules": ["告警分诊", "事件响应", "威胁狩猎", "报表"], "hours": 32},
    "devsecops": {"name": "DevSecOps工程师", "target": "安全左移",
                  "modules": ["CI/CD集成", "代码扫描", "镜像扫描", "门禁"], "hours": 24},
}


# --------------------------------------------------------------------------- #
# 教程对象
# --------------------------------------------------------------------------- #
class Tutorial:
    """交互式教程。"""

    def __init__(self, title: str, category: str, description: str = "",
                 steps: Optional[List[Dict[str, Any]]] = None,
                 difficulty: str = "入门", estimated_min: int = 10) -> None:
        self.id = f"tu_{uuid.uuid4().hex[:10]}"
        self.title = title
        self.category = category
        self.description = description
        self.steps: List[Dict[str, Any]] = steps or []
        self.difficulty = difficulty
        self.estimated_min = estimated_min
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.plays = 0
        self.completions = 0
        self.rating = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "category": self.category,
            "description": self.description, "steps": self.steps,
            "difficulty": self.difficulty, "estimated_min": self.estimated_min,
            "created_at": self.created_at, "plays": self.plays,
            "completions": self.completions, "rating": self.rating,
            "completion_rate": round(self.completions / max(1, self.plays) * 100, 1),
        }


# --------------------------------------------------------------------------- #
# 视频对象
# --------------------------------------------------------------------------- #
class Video:
    """视频教程。"""

    def __init__(self, title: str, category: str, duration_sec: int,
                 description: str = "", author: str = "doc-team") -> None:
        self.id = f"vi_{uuid.uuid4().hex[:10]}"
        self.title = title
        self.category = category
        self.duration_sec = duration_sec
        self.description = description
        self.author = author
        self.views = 0
        self.likes = 0
        self.has_subtitle = True
        self.downloadable = True
        self.uploaded_at = time.strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> Dict[str, Any]:
        mins, secs = divmod(self.duration_sec, 60)
        return {
            "id": self.id, "title": self.title, "category": self.category,
            "duration": f"{mins:02d}:{secs:02d}",
            "description": self.description, "author": self.author,
            "views": self.views, "likes": self.likes,
            "has_subtitle": self.has_subtitle, "downloadable": self.downloadable,
            "uploaded_at": self.uploaded_at,
        }


# --------------------------------------------------------------------------- #
# 用户进度
# --------------------------------------------------------------------------- #
class UserProgress:
    """用户学习进度。"""

    def __init__(self, user_id: str) -> None:
        self.user_id = user_id
        self.guide_completed: List[str] = []
        self.tutorial_progress: Dict[str, int] = {}  # tutorial_id -> step_idx
        self.video_progress: Dict[str, float] = {}   # video_id -> 0..1
        self.labs_completed: List[str] = []
        self.path_progress: Dict[str, int] = {}      # path_id -> percent
        self.last_active = time.strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "guides_completed": self.guide_completed,
            "tutorial_progress": self.tutorial_progress,
            "video_progress": self.video_progress,
            "labs_completed": self.labs_completed,
            "path_progress": self.path_progress,
            "last_active": self.last_active,
        }


# --------------------------------------------------------------------------- #
# 引导管理器
# --------------------------------------------------------------------------- #
class OnboardingManager:
    """新手引导与教程中心管理器。"""

    def __init__(self) -> None:
        self.tutorials: Dict[str, Tutorial] = {}
        self.videos: Dict[str, Video] = {}
        self.users: Dict[str, UserProgress] = {}
        self.tickets: List[Dict[str, Any]] = []
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        # 教程
        t = Tutorial("首次扫描五分钟", "beginner", "从资产录入到出报告",
                     steps=[{"title": "录入目标", "hint": "输入 example.com"},
                            {"title": "选择模板", "hint": "选快速扫描"},
                            {"title": "启动", "hint": "点击开始"},
                            {"title": "查看报告", "hint": "等待完成"}],
                     difficulty="入门", estimated_min=5)
        self.tutorials[t.id] = t

        t2 = Tutorial("编写第一个检测规则", "dev", "自定义YARA/检测规则",
                     steps=[{"title": "打开规则编辑器"},
                            {"title": "复制模板"},
                            {"title": "修改条件"},
                            {"title": "测试"}],
                     difficulty="进阶", estimated_min=15)
        self.tutorials[t2.id] = t2

        # 视频
        v = Video("平台3分钟导览", "feature", 180, "全景功能演示")
        self.videos[v.id] = v
        v2 = Video("Docker 部署实战", "install", 600, "从零部署到访问")
        self.videos[v2.id] = v2

    # ---- 教程 CRUD ----
    def create_tutorial(self, title: str, category: str, description: str = "",
                        steps: Optional[List[Dict[str, Any]]] = None,
                        difficulty: str = "入门",
                        estimated_min: int = 10) -> Dict[str, Any]:
        t = Tutorial(title, category, description, steps, difficulty, estimated_min)
        self.tutorials[t.id] = t
        return t.to_dict()

    def play_tutorial(self, tutorial_id: str) -> Optional[Dict[str, Any]]:
        t = self.tutorials.get(tutorial_id)
        if t is None:
            return None
        t.plays += 1
        return t.to_dict()

    def complete_tutorial(self, tutorial_id: str) -> Optional[Dict[str, Any]]:
        t = self.tutorials.get(tutorial_id)
        if t is None:
            return None
        t.completions += 1
        t.rating = round(t.completions / max(1, t.plays) * 5, 1)
        return t.to_dict()

    def list_tutorials(self, category: Optional[str] = None,
                       difficulty: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.tutorials.values())
        if category:
            items = [t for t in items if t.category == category]
        if difficulty:
            items = [t for t in items if t.difficulty == difficulty]
        return [t.to_dict() for t in items]

    # ---- 视频 ----
    def create_video(self, title: str, category: str, duration_sec: int,
                     description: str = "") -> Dict[str, Any]:
        v = Video(title, category, duration_sec, description)
        self.videos[v.id] = v
        return v.to_dict()

    def play_video(self, video_id: str) -> Optional[Dict[str, Any]]:
        v = self.videos.get(video_id)
        if v is None:
            return None
        v.views += 1
        return v.to_dict()

    def list_videos(self, category: Optional[str] = None,
                    keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.videos.values())
        if category:
            items = [v for v in items if v.category == category]
        if keyword:
            kw = keyword.lower()
            items = [v for v in items if kw in v.title.lower()]
        return [v.to_dict() for v in items]

    # ---- 用户进度 ----
    def get_or_create_user(self, user_id: str) -> UserProgress:
        if user_id not in self.users:
            self.users[user_id] = UserProgress(user_id)
        return self.users[user_id]

    def mark_guide_completed(self, user_id: str, flow_id: str) -> Dict[str, Any]:
        u = self.get_or_create_user(user_id)
        if flow_id not in u.guide_completed:
            u.guide_completed.append(flow_id)
        u.last_active = time.strftime("%Y-%m-%d %H:%M:%S")
        return u.to_dict()

    def update_tutorial_progress(self, user_id: str, tutorial_id: str,
                                  step_idx: int) -> Dict[str, Any]:
        u = self.get_or_create_user(user_id)
        u.tutorial_progress[tutorial_id] = step_idx
        return u.to_dict()

    def get_user_progress(self, user_id: str) -> Dict[str, Any]:
        return self.get_or_create_user(user_id).to_dict()

    # ---- 工单 ----
    def create_ticket(self, user_id: str, subject: str, message: str,
                      priority: str = "P3") -> Dict[str, Any]:
        ticket = {
            "id": f"tk_{uuid.uuid4().hex[:10]}",
            "user_id": user_id, "subject": subject, "message": message,
            "priority": priority, "status": "open",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.tickets.append(ticket)
        return ticket

    def list_tickets(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = self.tickets
        if status:
            items = [t for t in items if t["status"] == status]
        return list(reversed(items))

    # ---- 元数据 ----
    def list_guide_flows(self) -> Dict[str, Dict[str, Any]]:
        return GUIDE_FLOWS

    def list_video_categories(self) -> Dict[str, str]:
        return VIDEO_CATEGORIES

    def list_labs(self) -> Dict[str, Dict[str, Any]]:
        return LAB_ENVIRONMENTS

    def list_learning_paths(self) -> Dict[str, Dict[str, Any]]:
        return LEARNING_PATHS

    # ---- 统计 ----
    def stats(self) -> Dict[str, Any]:
        return {
            "tutorials": len(self.tutorials),
            "videos": len(self.videos),
            "users_tracked": len(self.users),
            "open_tickets": len([t for t in self.tickets if t["status"] == "open"]),
            "labs": len(LAB_ENVIRONMENTS),
            "paths": len(LEARNING_PATHS),
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_manager: Optional[OnboardingManager] = None


def get_onboarding_manager() -> OnboardingManager:
    global _manager
    if _manager is None:
        _manager = OnboardingManager()
    return _manager
