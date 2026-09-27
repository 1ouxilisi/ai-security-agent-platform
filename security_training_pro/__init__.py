# -*- coding: utf-8 -*-
"""
security_training_pro 包 — 方向3：安全培训做深（5.5→9.0）。

八阶段流程:
    1. course_management   课程管理（10 大分类 / 章节 / 课件 / 视频 / 状态机 / 版本）
    2. learning_path       学习路径（入门→专家 / 知识图谱 / 推荐 / 计划 / 优化）
    3. lab_environment     实验环境（真实 Docker 调用 + 内置模拟兜底）
    4. exam_system         考试系统（题库 / 组卷 / 在线考试 / 判题 / 证书）
    5. phishing            钓鱼演练（模板 / 发送 / 跟踪 / 风险 / 报告）
    6. student             学员管理（注册 / 档案 / 能力 / 行为 / 分组）
    7. instructor          讲师管理（注册 / 等级 / 排名 / 收益 / 审核）
    8. analysis            数据分析（学习 / 考试 / 能力 / ROI / 行为 / 可视化）

另含:
    - AIAnalysis             AI 分析（内容生成/出题/批改/推荐/评估）
    - RealtimePush           WebSocket 实时推送
    - TrainingDashboard      培训大屏仪表盘
    - ReportGenerator        报告生成（MD/HTML）
    - TrainingOrchestrator   八阶段编排器
"""

from __future__ import annotations

from .course_management_phase import (
    CourseManagementPhase, COURSE_CATEGORIES, DIFFICULTIES,
    get_course_management_phase,
)
from .learning_path_phase import (
    LearningPathPhase, PATH_LEVELS, PATH_TEMPLATES,
    get_learning_path_phase,
)
from .lab_environment_phase import (
    LabEnvironmentPhase, LAB_CATEGORIES, LAB_DIFFICULTIES,
    get_lab_environment_phase,
)
from .exam_system_phase import (
    ExamSystemPhase, QUESTION_TYPES, get_exam_system_phase,
)
from .phishing_simulation_phase import (
    PhishingSimulationPhase, get_phishing_simulation_phase,
)
from .student_management_phase import (
    StudentManagementPhase, DOMAINS, get_student_management_phase,
)
from .instructor_management_phase import (
    InstructorManagementPhase, INSTRUCTOR_LEVELS,
    get_instructor_management_phase,
)
from .data_analysis_phase import (
    DataAnalysisPhase, get_data_analysis_phase,
)
from .ai_analysis import AIAnalysis, get_ai_analysis
from .realtime_push import (
    RealtimePush, get_realtime_push, LOG_LEVEL_COLORS,
)
from .training_dashboard import TrainingDashboard, get_dashboard
from .report_generator import (
    ReportGenerator, get_report_generator, REPORTS_DIR,
)
from .training_orchestrator import (
    TrainingOrchestrator, TrainingTask, get_orchestrator, STAGES,
)

__all__ = [
    "CourseManagementPhase", "COURSE_CATEGORIES", "DIFFICULTIES",
    "get_course_management_phase",
    "LearningPathPhase", "PATH_LEVELS", "PATH_TEMPLATES",
    "get_learning_path_phase",
    "LabEnvironmentPhase", "LAB_CATEGORIES", "LAB_DIFFICULTIES",
    "get_lab_environment_phase",
    "ExamSystemPhase", "QUESTION_TYPES", "get_exam_system_phase",
    "PhishingSimulationPhase", "get_phishing_simulation_phase",
    "StudentManagementPhase", "DOMAINS", "get_student_management_phase",
    "InstructorManagementPhase", "INSTRUCTOR_LEVELS",
    "get_instructor_management_phase",
    "DataAnalysisPhase", "get_data_analysis_phase",
    "AIAnalysis", "get_ai_analysis",
    "RealtimePush", "get_realtime_push", "LOG_LEVEL_COLORS",
    "TrainingDashboard", "get_dashboard",
    "ReportGenerator", "get_report_generator", "REPORTS_DIR",
    "TrainingOrchestrator", "TrainingTask", "get_orchestrator",
    "STAGES",
]
