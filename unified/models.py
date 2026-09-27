#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一数据模型 - 四大领域共享的标准数据结构

所有领域模块必须返回 Finding / DomainAssessment 对象，
由 UnifiedAssessmentEngine 聚合成 UnifiedAssessmentResult。
"""
import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class DomainType(str, enum.Enum):
    """安全评估领域类型"""
    PENTEST = "pentest"           # 渗透测试
    MOBILE = "mobile"             # 移动安全
    BLOCKCHAIN = "blockchain"     # 区块链安全
    AI_AGENT = "ai_agent"         # AI智能体安全
    COMPREHENSIVE = "comprehensive"  # 综合评估

    @classmethod
    def all_domains(cls) -> List["DomainType"]:
        return [cls.PENTEST, cls.MOBILE, cls.BLOCKCHAIN, cls.AI_AGENT]

    def label(self) -> str:
        labels = {
            "pentest": "渗透测试",
            "mobile": "移动安全",
            "blockchain": "区块链安全",
            "ai_agent": "AI智能体安全",
            "comprehensive": "综合评估",
        }
        return labels.get(self.value, self.value)


class Severity(str, enum.Enum):
    """严重程度等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        mapping = {
            "critical": cls.CRITICAL, "crit": cls.CRITICAL, "严重": cls.CRITICAL,
            "high": cls.HIGH, "高危": cls.HIGH,
            "medium": cls.MEDIUM, "med": cls.MEDIUM, "中危": cls.MEDIUM,
            "low": cls.LOW, "低危": cls.LOW,
            "info": cls.INFO, "informational": cls.INFO, "信息": cls.INFO,
        }
        return mapping.get(s.lower().strip(), cls.INFO)

    def score(self) -> int:
        return {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}[self.value]

    def label(self) -> str:
        return {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}[self.value]

    def color(self) -> str:
        return {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280"}[self.value]


@dataclass
class Finding:
    """统一漏洞/发现项 - 所有领域的检测结果都用这个结构"""
    id: str = field(default_factory=lambda: f"finding_{uuid.uuid4().hex[:12]}")
    title: str = ""
    severity: Severity = Severity.INFO
    domain: DomainType = DomainType.PENTEST
    category: str = ""              # 子分类，如 "注入攻击"、"权限提升"、"重入攻击"
    description: str = ""
    target: str = ""                # 目标标识（IP/域名/APK路径/合约地址/AI端点）
    location: str = ""              # 具体位置（端口/文件/函数/API端点）
    evidence: str = ""              # 证据（payload/代码片段/请求响应）
    cwe: str = ""                   # CWE编号，如 "CWE-79"
    owasp: str = ""                 # OWASP编号，如 "A01:2021"
    cvss: float = 0.0               # CVSS评分
    recommendation: str = ""        # 修复建议
    reference_urls: List[str] = field(default_factory=list)
    false_positive_hint: str = ""   # 误判提示
    detected_at: float = field(default_factory=time.time)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "severity_label": self.severity.label(),
            "domain": self.domain.value,
            "domain_label": self.domain.label(),
            "category": self.category,
            "description": self.description,
            "target": self.target,
            "location": self.location,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "cvss": self.cvss,
            "recommendation": self.recommendation,
            "reference_urls": self.reference_urls,
            "false_positive_hint": self.false_positive_hint,
            "detected_at": self.detected_at,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        d = dict(d)
        if "severity" in d and isinstance(d["severity"], str):
            d["severity"] = Severity.from_str(d["severity"])
        if "domain" in d and isinstance(d["domain"], str):
            try:
                d["domain"] = DomainType(d["domain"])
            except ValueError:
                d["domain"] = DomainType.PENTEST
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class DomainAssessment:
    """单领域评估结果"""
    domain: DomainType
    target: str = ""
    status: str = "pending"         # pending/running/completed/failed/skipped
    started_at: float = 0.0
    completed_at: float = 0.0
    duration: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    risk_score: int = 0             # 0-100
    risk_level: str = "未评估"
    summary: str = ""
    tools_used: List[str] = field(default_factory=list)
    checks_run: List[str] = field(default_factory=list)
    checks_total: int = 0
    errors: List[str] = field(default_factory=list)
    raw_output: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain.value,
            "domain_label": self.domain.label(),
            "target": self.target,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration": round(self.duration, 2),
            "findings": [f.to_dict() for f in self.findings],
            "findings_count": len(self.findings),
            "findings_by_severity": self._severity_counts(),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "summary": self.summary,
            "tools_used": self.tools_used,
            "checks_run": self.checks_run,
            "checks_total": self.checks_total,
            "errors": self.errors,
            "raw_output": self.raw_output,
        }

    def _severity_counts(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts


@dataclass
class UnifiedAssessmentResult:
    """全域综合评估结果 - 聚合所有领域"""
    assessment_id: str = field(default_factory=lambda: f"ua_{uuid.uuid4().hex[:16]}")
    assessment_type: str = "comprehensive"  # pentest/mobile/blockchain/ai_agent/comprehensive
    target: str = ""
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    duration: float = 0.0
    status: str = "pending"
    domain_results: Dict[str, DomainAssessment] = field(default_factory=dict)
    all_findings: List[Finding] = field(default_factory=list)
    overall_risk_score: int = 0
    overall_risk_level: str = "未评估"
    executive_summary: str = ""
    key_findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    report_path: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "assessment_type": self.assessment_type,
            "target": self.target,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration": round(self.duration, 2),
            "status": self.status,
            "domain_results": {k: v.to_dict() for k, v in self.domain_results.items()},
            "all_findings": [f.to_dict() for f in self.all_findings],
            "findings_count": len(self.all_findings),
            "findings_by_severity": self._severity_counts(),
            "findings_by_domain": self._domain_counts(),
            "overall_risk_score": self.overall_risk_score,
            "overall_risk_level": self.overall_risk_level,
            "executive_summary": self.executive_summary,
            "key_findings": self.key_findings,
            "recommendations": self.recommendations,
            "report_path": self.report_path,
            "metadata": self.metadata,
        }

    def _severity_counts(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.all_findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def _domain_counts(self) -> Dict[str, int]:
        counts = {}
        for f in self.all_findings:
            counts[f.domain.value] = counts.get(f.domain.value, 0) + 1
        return counts

    def save_json(self, path: str) -> None:
        import json
        import os
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)


@dataclass
class ReportConfig:
    """报告生成配置"""
    title: str = "全域安全评估报告"
    author: str = "AI Hacking Agent - Unified Framework"
    include_cover: bool = True
    include_executive_summary: bool = True
    include_detail: bool = True
    include_appendix: bool = True
    format: str = "html"          # html/markdown/json
    language: str = "zh-CN"
    template: str = "default"
    output_dir: str = "reports"
