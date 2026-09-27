# -*- coding: utf-8 -*-
"""
devsecops_pro — 方向3：DevSecOps 做深（5.5 → 9.0）。

八阶段流程:
    1. cicd_integration  CI/CD 集成（GitHub Actions / GitLab CI / Jenkins）
    2. sast             SAST 静态代码分析（semgrep）
    3. sca              SCA 依赖漏洞扫描
    4. secrets          Secrets 扫描（gitleaks）
    5. iac_security     IaC 安全（checkov / terrascan）
    6. container        容器安全（trivy）
    7. security_gate    安全门禁
    8. risk_rating      风险评级

另含:
    - AIAnalysis       AI 分析（修复建议 / 优先级 / 攻击路径 / 路线图）
    - RealtimePush     WebSocket 实时推送（进度 / 日志流 / 思考过程）
    - ReportGenerator  报告生成（MD / HTML）
    - DevSecOpsOrchestrator  八阶段编排器
    - DevSecOpsDashboard     仪表盘聚合
"""

from __future__ import annotations

from .cicd_integration_phase import (
    CICDIntegrationPhase, CICDResult, PipelineConfig, get_cicd_phase,
)
from .sast_phase import (
    SASTPhase, SASTFinding, get_sast_phase,
)
from .sca_phase import (
    SCAPhase, SCAFinding, DependencyInfo, get_sca_phase,
)
from .secrets_phase import (
    SecretsPhase, SecretFinding, get_secrets_phase,
)
from .iac_security_phase import (
    IaCSecurityPhase, IaCFinding, get_iac_phase,
)
from .container_security_phase import (
    ContainerSecurityPhase, ContainerFinding, get_container_phase,
)
from .security_gate_phase import (
    SecurityGatePhase, GateResult, GateRule, get_gate_phase,
)
from .risk_rating_phase import (
    RiskRatingPhase, RiskRating, get_risk_phase,
)
from .ai_analysis import (
    DevSecOpsAIAnalysis, AIDevSecOpsResult, get_ai_analysis,
)
from .realtime_push import (
    RealtimePush, get_realtime_push,
)
from .report_generator import (
    ReportGenerator, DevSecOpsReportData, get_report_generator,
)
from .devsecops_orchestrator import (
    DevSecOpsOrchestrator, DevSecOpsTask, get_orchestrator,
    STAGES, REPORTS_DIR,
)
from .devsecops_dashboard import (
    DevSecOpsDashboard, get_dashboard,
)

__all__ = [
    "CICDIntegrationPhase", "CICDResult", "PipelineConfig", "get_cicd_phase",
    "SASTPhase", "SASTFinding", "get_sast_phase",
    "SCAPhase", "SCAFinding", "DependencyInfo", "get_sca_phase",
    "SecretsPhase", "SecretFinding", "get_secrets_phase",
    "IaCSecurityPhase", "IaCFinding", "get_iac_phase",
    "ContainerSecurityPhase", "ContainerFinding", "get_container_phase",
    "SecurityGatePhase", "GateResult", "GateRule", "get_gate_phase",
    "RiskRatingPhase", "RiskRating", "get_risk_phase",
    "DevSecOpsAIAnalysis", "AIDevSecOpsResult", "get_ai_analysis",
    "RealtimePush", "get_realtime_push",
    "ReportGenerator", "DevSecOpsReportData", "get_report_generator",
    "DevSecOpsOrchestrator", "DevSecOpsTask", "get_orchestrator",
    "STAGES", "REPORTS_DIR",
    "DevSecOpsDashboard", "get_dashboard",
]
