"""
models模块 —— 平台数据层 ORM 模型定义（SQLAlchemy 2.0 风格）。

模块功能：
    - 定义评估结果 / 漏洞 / 端口 / 任务 / 通知 / 告警 / 资产 / 扫描计划 / 漏洞变更历史等核心表
    - 使用 DeclarativeBase + Mapped 注解风格
    - 为常用查询字段（assessment_id、severity、status、tenant_id、created_at 等）建立索引
    - 所有时间字段统一使用 Unix 时间戳（float，秒），避免时区依赖

注意事项：
    - 本模块为授权安全评估 / 防御检测产品的数据层，仅用于防御视角
    - 请勿用于非法用途
"""
import uuid
from typing import Optional

from sqlalchemy import String, Float, Integer, Text, Boolean, ForeignKey, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


# ==================== 声明式基类 ====================

class Base(DeclarativeBase):
    """所有 ORM 模型的声明式基类。"""


def _uuid_str() -> str:
    """生成 UUID 字符串主键。"""
    return str(uuid.uuid4())


# ==================== 评估表 ====================

class Assessment(Base):
    """安全评估主表：一次授权安全评估的结果记录。"""

    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    target: Mapped[str] = mapped_column(String(512), default="", comment="评估目标（IP/域名/URL）")
    assessment_type: Mapped[str] = mapped_column(String(64), default="general", comment="评估类型")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, comment="风险分 0-100")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True, comment="状态")
    started_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True, comment="开始时间戳")
    completed_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True, comment="完成时间戳")
    tenant_id: Mapped[str] = mapped_column(String(128), default="default", index=True, comment="租户ID")
    user_id: Mapped[str] = mapped_column(String(128), default="", index=True, comment="用户ID")
    summary: Mapped[str] = mapped_column(Text, default="", comment="评估摘要")
    created_at: Mapped[float] = mapped_column(Float, default=0.0, index=True, comment="创建时间戳")

    __table_args__ = (
        Index("ix_assessment_target", "target"),
        Index("ix_assessment_risk", "risk_score"),
    )


# ==================== 漏洞表 ====================

class Vulnerability(Base):
    """漏洞明细表：某次评估发现的具体漏洞。"""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    assessment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assessments.id"), default="", index=True, comment="所属评估ID"
    )
    name: Mapped[str] = mapped_column(String(512), default="", index=True, comment="漏洞名称/类型")
    severity: Mapped[str] = mapped_column(String(32), default="medium", index=True, comment="严重级别")
    cve: Mapped[str] = mapped_column(String(64), default="", index=True, comment="CVE编号")
    cwe: Mapped[str] = mapped_column(String(64), default="", comment="CWE编号")
    description: Mapped[str] = mapped_column(Text, default="", comment="漏洞描述")
    evidence: Mapped[str] = mapped_column(Text, default="", comment="证据")
    status: Mapped[str] = mapped_column(String(32), default="open", index=True, comment="处置状态")
    discovered_at: Mapped[float] = mapped_column(Float, default=0.0, index=True, comment="发现时间戳")
    remediated_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True, comment="修复时间戳")
    target: Mapped[str] = mapped_column(String(512), default="", index=True, comment="目标")
    tenant_id: Mapped[str] = mapped_column(String(128), default="default", index=True, comment="租户ID")

    __table_args__ = (
        Index("ix_vuln_assessment_severity", "assessment_id", "severity"),
        Index("ix_vuln_tenant_status", "tenant_id", "status"),
    )


# ==================== 端口表 ====================

class Port(Base):
    """端口扫描结果表。"""

    __tablename__ = "ports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    assessment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assessments.id"), default="", index=True, comment="所属评估ID"
    )
    port: Mapped[int] = mapped_column(Integer, default=0, index=True, comment="端口号")
    protocol: Mapped[str] = mapped_column(String(16), default="tcp", comment="协议")
    service: Mapped[str] = mapped_column(String(128), default="", comment="服务名")
    version: Mapped[str] = mapped_column(String(256), default="", comment="版本")
    state: Mapped[str] = mapped_column(String(32), default="open", index=True, comment="端口状态")
    tenant_id: Mapped[str] = mapped_column(String(128), default="default", index=True, comment="租户ID")


# ==================== 任务表 ====================

class Task(Base):
    """安全任务表（修复任务 / 协同任务）。"""

    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    title: Mapped[str] = mapped_column(String(512), default="", comment="任务标题")
    description: Mapped[str] = mapped_column(Text, default="", comment="任务描述")
    assignee: Mapped[str] = mapped_column(String(128), default="", index=True, comment="负责人")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True, comment="任务状态")
    priority: Mapped[str] = mapped_column(String(32), default="medium", index=True, comment="优先级")
    due_date: Mapped[Optional[float]] = mapped_column(Float, nullable=True, comment="截止时间戳")
    tenant_id: Mapped[str] = mapped_column(String(128), default="default", index=True, comment="租户ID")
    created_at: Mapped[float] = mapped_column(Float, default=0.0, index=True, comment="创建时间戳")
    updated_at: Mapped[float] = mapped_column(Float, default=0.0, comment="更新时间戳")


# ==================== 通知表 ====================

class Notification(Base):
    """站内通知表。"""

    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    user_id: Mapped[str] = mapped_column(String(128), default="", index=True, comment="接收用户ID")
    type: Mapped[str] = mapped_column(String(64), default="general", index=True, comment="通知类型")
    title: Mapped[str] = mapped_column(String(512), default="", comment="通知标题")
    content: Mapped[str] = mapped_column(Text, default="", comment="通知内容")
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, index=True, comment="是否已读")
    created_at: Mapped[float] = mapped_column(Float, default=0.0, index=True, comment="创建时间戳")


# ==================== 告警表 ====================

class Alert(Base):
    """安全告警表。"""

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    rule_id: Mapped[str] = mapped_column(String(128), default="", index=True, comment="触发规则ID")
    level: Mapped[str] = mapped_column(String(32), default="medium", index=True, comment="告警级别")
    title: Mapped[str] = mapped_column(String(512), default="", comment="告警标题")
    content: Mapped[str] = mapped_column(Text, default="", comment="告警内容")
    status: Mapped[str] = mapped_column(String(32), default="open", index=True, comment="告警状态")
    acknowledged_by: Mapped[str] = mapped_column(String(128), default="", comment="确认人")
    acknowledged_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True, comment="确认时间戳")
    tenant_id: Mapped[str] = mapped_column(String(128), default="default", index=True, comment="租户ID")
    created_at: Mapped[float] = mapped_column(Float, default=0.0, index=True, comment="创建时间戳")


# ==================== 资产表 ====================

class Asset(Base):
    """资产管理表：被评估的主机 / 域名 / 应用资产。"""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    ip: Mapped[str] = mapped_column(String(128), default="", index=True, comment="IP地址")
    domain: Mapped[str] = mapped_column(String(512), default="", index=True, comment="域名")
    asset_type: Mapped[str] = mapped_column(String(64), default="host", index=True, comment="资产类型")
    fingerprint: Mapped[str] = mapped_column(Text, default="", comment="指纹信息")
    first_seen: Mapped[float] = mapped_column(Float, default=0.0, comment="首次发现时间戳")
    last_scanned: Mapped[float] = mapped_column(Float, default=0.0, comment="最近扫描时间戳")
    tenant_id: Mapped[str] = mapped_column(String(128), default="default", index=True, comment="租户ID")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True, comment="资产风险分")
    owner: Mapped[str] = mapped_column(String(128), default="", index=True, comment="资产负责人")
    importance: Mapped[str] = mapped_column(String(32), default="medium", comment="重要程度")


# ==================== 扫描计划表 ====================

class ScanSchedule(Base):
    """定时扫描计划表。"""

    __tablename__ = "scan_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    target: Mapped[str] = mapped_column(String(512), default="", index=True, comment="扫描目标")
    scan_type: Mapped[str] = mapped_column(String(64), default="port", comment="扫描类型")
    cron: Mapped[str] = mapped_column(String(128), default="", comment="cron 表达式")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True, comment="是否启用")
    last_run: Mapped[Optional[float]] = mapped_column(Float, nullable=True, comment="上次运行时间戳")
    next_run: Mapped[Optional[float]] = mapped_column(Float, nullable=True, comment="下次运行时间戳")
    tenant_id: Mapped[str] = mapped_column(String(128), default="default", index=True, comment="租户ID")
    created_at: Mapped[float] = mapped_column(Float, default=0.0, index=True, comment="创建时间戳")


# ==================== 漏洞变更历史表 ====================

class VulnerabilityHistory(Base):
    """漏洞状态变更历史表。"""

    __tablename__ = "vulnerability_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    vulnerability_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vulnerabilities.id"), default="", index=True, comment="漏洞ID"
    )
    from_status: Mapped[str] = mapped_column(String(32), default="", comment="原状态")
    to_status: Mapped[str] = mapped_column(String(32), default="", index=True, comment="新状态")
    changed_by: Mapped[str] = mapped_column(String(128), default="", comment="变更人")
    note: Mapped[str] = mapped_column(Text, default="", comment="变更说明")
    changed_at: Mapped[float] = mapped_column(Float, default=0.0, index=True, comment="变更时间戳")
