# -*- coding: utf-8 -*-
"""ctf_platform — CTF 训练平台核心模块包。

仅用于经过授权的网络安全训练、教育与竞赛管理。
所有数据均为内存模拟，不执行任何对真实目标的攻击行为。
"""

from __future__ import annotations

from .challenge_manager import (
    ChallengeManager, get_challenge_manager,
    CATEGORIES, DIFFICULTIES, STATUSES,
)
from .competition_manager import (
    CompetitionManager, get_competition_manager,
    FORMATS, STATUSES as COMPETITION_STATUSES,
)
from .challenge_solver import (
    ChallengeSolver, get_challenge_solver, FLAG_PATTERN,
)
from .learning_path import (
    LearningPathManager, get_learning_manager, LEVELS,
)
from .team_manager import TeamManager, get_team_manager, ROLES
from .ctf_dashboard import CTFDashboard, get_dashboard

__all__ = [
    "ChallengeManager", "get_challenge_manager",
    "CompetitionManager", "get_competition_manager",
    "ChallengeSolver", "get_challenge_solver",
    "LearningPathManager", "get_learning_manager",
    "TeamManager", "get_team_manager",
    "CTFDashboard", "get_dashboard",
    "CATEGORIES", "DIFFICULTIES", "STATUSES",
    "FORMATS", "FLAG_PATTERN", "LEVELS", "ROLES",
]

__version__ = "1.0.0"
