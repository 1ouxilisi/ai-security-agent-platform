# -*- coding: utf-8 -*-
"""
ctf_pro 包 — 方向1：CTF 夺旗赛做深（5.5→9.0）。

八阶段流程:
    1. competition_management 赛事管理（创建/配置/报名/排名配置/状态/公告/规则/模板）
    2. challenge_management   题目管理（Web/Reverse/Pwn/Crypto/Misc/Forensics/Mobile/Blockchain）
    3. challenge_deployment   题目部署（Docker 一键部署 / 动态 flag / 资源限制 / 生命周期）
    4. game_play              比赛进行（提交/判题/动态分值/一血二血三血/提示/讨论）
    5. realtime_ranking       实时排名（积分榜/解题进度/一血榜/趋势）
    6. postmortem             比赛复盘（Writeup/题解/难度分析/知识点覆盖/导出）
    7. training_mode          训练模式（单人/专项/学习路径/能力评估）
    8. team_management        战队管理（创建/成员/训练计划/比赛记录/排名）

另含:
    - CtfAIAnalysis    AI 分析（难度/思路/出题/复盘/学习路径）
    - RealtimePush     WebSocket 实时推送
    - CtfDashboard     CTF 大屏仪表盘
    - ReportGenerator  报告生成（MD/HTML）
    - CtfOrchestrator  八阶段编排器
"""

from __future__ import annotations

from .competition_management_phase import (
    CompetitionManagementPhase, Competition, Registration,
    get_competition_phase, COMPETITION_STATUSES, COMPETITION_TYPES,
)
from .challenge_management_phase import (
    ChallengeManagementPhase, Challenge, Attachment,
    get_challenge_phase, CHALLENGE_CATEGORIES, DIFFICULTIES,
    CHALLENGE_STATUSES,
)
from .challenge_deployment_phase import (
    ChallengeDeploymentPhase, Deployment, get_deployment_phase,
    detect_docker, TOOL_TIMEOUT,
)
from .game_play_phase import (
    GamePlayPhase, Submission, get_gameplay_phase,
)
from .realtime_ranking_phase import (
    RealtimeRankingPhase, TeamScore, get_ranking_phase,
)
from .postmortem_phase import (
    PostmortemPhase, Writeup, get_postmortem_phase,
)
from .training_mode_phase import (
    TrainingModePhase, TrainingRecord, get_training_phase,
    LEARNING_PATHS,
)
from .team_management_phase import (
    TeamManagementPhase, Team, Member, get_team_phase,
)
from .ai_analysis import CtfAIAnalysis, get_ai_analysis
from .realtime_push import RealtimePush, get_realtime_push, LOG_LEVEL_COLORS
from .ctf_dashboard import CtfDashboard, get_dashboard
from .report_generator import ReportGenerator, get_report_generator, REPORTS_DIR
from .ctf_orchestrator import (
    CtfOrchestrator, CtfTask, get_orchestrator, STAGES,
)

__all__ = [
    "CompetitionManagementPhase", "Competition", "Registration",
    "get_competition_phase", "COMPETITION_STATUSES", "COMPETITION_TYPES",
    "ChallengeManagementPhase", "Challenge", "Attachment",
    "get_challenge_phase", "CHALLENGE_CATEGORIES", "DIFFICULTIES",
    "CHALLENGE_STATUSES",
    "ChallengeDeploymentPhase", "Deployment", "get_deployment_phase",
    "detect_docker", "TOOL_TIMEOUT",
    "GamePlayPhase", "Submission", "get_gameplay_phase",
    "RealtimeRankingPhase", "TeamScore", "get_ranking_phase",
    "PostmortemPhase", "Writeup", "get_postmortem_phase",
    "TrainingModePhase", "TrainingRecord", "get_training_phase",
    "LEARNING_PATHS",
    "TeamManagementPhase", "Team", "Member", "get_team_phase",
    "CtfAIAnalysis", "get_ai_analysis",
    "RealtimePush", "get_realtime_push", "LOG_LEVEL_COLORS",
    "CtfDashboard", "get_dashboard",
    "ReportGenerator", "get_report_generator", "REPORTS_DIR",
    "CtfOrchestrator", "CtfTask", "get_orchestrator", "STAGES",
]
