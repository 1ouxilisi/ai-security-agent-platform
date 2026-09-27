#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
compliance模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from utils.logger import log


class ComplianceStandard(str, Enum):
    """合规标准"""
    MLPS2 = "mlps2"  # 等保2.0
    ISO27001 = "iso27001"  # ISO27001
    PCI_DSS = "pci_dss"  # PCI DSS
    GDPR = "gdpr"  # GDPR


class CheckStatus(str, Enum):
    """检查状态"""
    PASS = "pass"  # 符合
    FAIL = "fail"  # 不符合
    PARTIAL = "partial"  # 部分符合
    NOT_APPLICABLE = "na"  # 不适用
    NOT_CHECKED = "not_checked"  # 未检查


class RiskLevel(str, Enum):
    """风险等级"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ComplianceCheckItem:
    """合规检查项"""
    item_id: str
    standard: ComplianceStandard
    category: str  # 类别（如：物理安全、网络安全、主机安全等）
    control_id: str  # 控制项编号
    title: str
    description: str
    requirement: str  # 合规要求
    risk_level: RiskLevel = RiskLevel.MEDIUM
    verification_method: str = ""  # 验证方法
    remediation_suggestion: str = ""  # 整改建议
    applicable_levels: List[str] = field(default_factory=list)  # 适用等级（等保：一级/二级/三级/四级）

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "item_id": self.item_id,
            "standard": self.standard.value,
            "category": self.category,
            "control_id": self.control_id,
            "title": self.title,
            "description": self.description,
            "requirement": self.requirement,
            "risk_level": self.risk_level.value,
            "verification_method": self.verification_method,
            "remediation_suggestion": self.remediation_suggestion,
            "applicable_levels": self.applicable_levels
        }


@dataclass
class CheckResult:
    """检查结果"""
    result_id: str
    item_id: str
    status: CheckStatus = CheckStatus.NOT_CHECKED
    evidence: str = ""  # 检查证据
    findings: str = ""  # 发现的问题
    checked_at: float = field(default_factory=time.time)
    checked_by: str = ""
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "result_id": self.result_id,
            "item_id": self.item_id,
            "status": self.status.value,
            "evidence": self.evidence,
            "findings": self.findings,
            "checked_at": self.checked_at,
            "checked_by": self.checked_by,
            "notes": self.notes
        }


@dataclass
class ComplianceAssessment:
    """合规评估"""
    assessment_id: str
    standard: ComplianceStandard
    target_name: str = ""
    target_description: str = ""
    level: str = ""  # 等保等级
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    status: str = "in_progress"  # in_progress/completed
    check_results: Dict[str, CheckResult] = field(default_factory=dict)
    overall_score: float = 0.0
    pass_count: int = 0
    fail_count: int = 0
    partial_count: int = 0
    na_count: int = 0
    not_checked_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "assessment_id": self.assessment_id,
            "standard": self.standard.value,
            "target_name": self.target_name,
            "target_description": self.target_description,
            "level": self.level,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "overall_score": round(self.overall_score, 2),
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "partial_count": self.partial_count,
            "na_count": self.na_count,
            "not_checked_count": self.not_checked_count,
            "total_checks": len(self.check_results)
        }


class ComplianceReportGenerator:
    """合规报告生成系统"""

    def __init__(self, data_dir: str = "data/compliance"):
        """初始化ComplianceReportGenerator实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.check_items: Dict[str, ComplianceCheckItem] = {}
        self.assessments: Dict[str, ComplianceAssessment] = {}

        os.makedirs(data_dir, exist_ok=True)
        self._init_mlps2_check_items()
        self._init_iso27001_check_items()
        self._load_data()

    def _init_mlps2_check_items(self):
        """初始化等保2.0检查项（核心项）"""
        mlps2_items = [
            # 网络和通信安全
            ComplianceCheckItem("mlps2-net-001", ComplianceStandard.MLPS2, "网络和通信安全", "8.1.2.1",
                "网络架构", "应保证网络设备的业务处理能力满足业务高峰期需要",
                "检查网络设备性能是否满足业务需求", RiskLevel.MEDIUM,
                "查看网络设备CPU/内存利用率，检查是否有性能瓶颈",
                "升级网络设备或优化网络架构", ["二级", "三级", "四级"]),
            ComplianceCheckItem("mlps2-net-002", ComplianceStandard.MLPS2, "网络和通信安全", "8.1.2.2",
                "网络区域划分", "应划分不同的网络区域，并按照方便管理和控制的原则为各网络区域分配地址",
                "检查是否划分了DMZ、内网、管理网等区域", RiskLevel.HIGH,
                "查看网络拓扑图，检查VLAN划分和网段分配",
                "按功能划分网络区域，使用VLAN隔离", ["二级", "三级", "四级"]),
            ComplianceCheckItem("mlps2-net-003", ComplianceStandard.MLPS2, "网络和通信安全", "8.1.3.1",
                "边界防护", "应保证跨越边界的访问和数据流通过边界设备提供的受控接口进行通信",
                "检查网络边界是否有防火墙等访问控制设备", RiskLevel.HIGH,
                "检查边界防火墙策略，确认所有跨区域流量经过受控接口",
                "部署防火墙，严格控制边界访问", ["二级", "三级", "四级"]),
            ComplianceCheckItem("mlps2-net-004", ComplianceStandard.MLPS2, "网络和通信安全", "8.1.3.2",
                "访问控制", "应在网络边界或区域之间根据访问控制策略设置访问控制规则，默认情况下除允许通信外受控接口拒绝所有通信",
                "检查防火墙策略是否遵循默认拒绝原则", RiskLevel.HIGH,
                "查看防火墙规则，确认最后一条规则为拒绝所有",
                "配置防火墙默认拒绝策略，仅开放必要端口", ["二级", "三级", "四级"]),
            # 设备和计算安全
            ComplianceCheckItem("mlps2-host-001", ComplianceStandard.MLPS2, "设备和计算安全", "8.1.4.1",
                "身份鉴别", "应对登录的用户进行身份标识和鉴别，身份标识具有唯一性，身份鉴别信息具有复杂度要求并定期更换",
                "检查系统是否启用强密码策略", RiskLevel.HIGH,
                "检查密码长度、复杂度、过期时间策略，查看是否存在弱口令",
                "启用强密码策略（长度>=8，包含大小写字母+数字+特殊字符，90天更换）", ["二级", "三级", "四级"]),
            ComplianceCheckItem("mlps2-host-002", ComplianceStandard.MLPS2, "设备和计算安全", "8.1.4.2",
                "访问控制", "应授予管理用户所需的最小权限，实现管理用户的权限分离",
                "检查是否遵循最小权限原则", RiskLevel.HIGH,
                "检查用户权限分配，确认管理员、审计员、操作员权限分离",
                "实施角色分离，按最小权限原则分配用户权限", ["二级", "三级", "四级"]),
            ComplianceCheckItem("mlps2-host-003", ComplianceStandard.MLPS2, "设备和计算安全", "8.1.4.3",
                "安全审计", "应启用安全审计功能，审计覆盖到每个用户，对重要的用户行为和重要安全事件进行审计",
                "检查是否启用系统审计日志", RiskLevel.MEDIUM,
                "检查系统日志配置，确认审计覆盖登录、权限变更、重要操作等",
                "启用系统审计，配置日志集中收集和分析", ["三级", "四级"]),
            ComplianceCheckItem("mlps2-host-004", ComplianceStandard.MLPS2, "设备和计算安全", "8.1.4.4",
                "入侵防范", "应遵循最小安装的原则，仅安装需要的组件和应用程序",
                "检查系统是否关闭不必要的服务和端口", RiskLevel.MEDIUM,
                "检查运行的服务和开放端口，确认没有不必要的服务",
                "关闭不必要的服务和端口，卸载不需要的软件", ["二级", "三级", "四级"]),
            # 应用和数据安全
            ComplianceCheckItem("mlps2-app-001", ComplianceStandard.MLPS2, "应用和数据安全", "8.1.5.1",
                "身份鉴别", "应提供专用的登录控制模块对登录用户进行身份标识和鉴别",
                "检查应用是否有独立的身份认证模块", RiskLevel.HIGH,
                "检查应用登录功能，确认使用专用认证模块而非硬编码",
                "实现独立的身份认证模块，支持多因素认证", ["二级", "三级", "四级"]),
            ComplianceCheckItem("mlps2-app-002", ComplianceStandard.MLPS2, "应用和数据安全", "8.1.5.2",
                "访问控制", "应提供访问控制功能，依据安全策略控制用户对文件、数据库表等客体的访问",
                "检查应用是否实现细粒度访问控制", RiskLevel.HIGH,
                "检查应用权限控制，确认用户只能访问授权的资源",
                "实现基于角色的访问控制(RBAC)，严格控制数据访问", ["二级", "三级", "四级"]),
            ComplianceCheckItem("mlps2-app-003", ComplianceStandard.MLPS2, "应用和数据安全", "8.1.5.3",
                "安全审计", "应提供覆盖到每个用户的安全审计功能，对应用系统重要安全事件进行审计",
                "检查应用是否记录用户操作日志", RiskLevel.MEDIUM,
                "检查应用日志，确认记录登录、数据操作、权限变更等事件",
                "实现应用审计日志，记录所有重要用户操作", ["三级", "四级"]),
            ComplianceCheckItem("mlps2-app-004", ComplianceStandard.MLPS2, "应用和数据安全", "8.1.5.4",
                "数据完整性", "应采用校验技术或密码技术保证重要数据在传输过程中的完整性",
                "检查重要数据传输是否使用加密", RiskLevel.HIGH,
                "检查是否使用HTTPS/TLS加密传输敏感数据",
                "全站启用HTTPS，使用TLS 1.2+加密传输", ["二级", "三级", "四级"]),
            ComplianceCheckItem("mlps2-app-005", ComplianceStandard.MLPS2, "应用和数据安全", "8.1.5.5",
                "数据保密性", "应采用密码技术保证重要数据在存储过程中的保密性，包括但不限于鉴别数据、重要业务数据和重要个人信息等",
                "检查敏感数据是否加密存储", RiskLevel.HIGH,
                "检查数据库中密码、身份证号等敏感数据是否加密存储",
                "使用AES-256加密存储敏感数据，密码使用bcrypt/argon2哈希", ["二级", "三级", "四级"]),
            # 安全管理
            ComplianceCheckItem("mlps2-mgmt-001", ComplianceStandard.MLPS2, "安全管理", "8.1.10.1",
                "安全管理制度", "应制定网络安全工作的总体方针和安全策略，阐明机构安全工作的总体目标、范围、原则和安全框架等",
                "检查是否有信息安全管理制度", RiskLevel.MEDIUM,
                "查看是否有信息安全管理办法、安全策略文档",
                "制定信息安全管理制度和安全策略文档", ["二级", "三级", "四级"]),
            ComplianceCheckItem("mlps2-mgmt-002", ComplianceStandard.MLPS2, "安全管理", "8.1.10.2",
                "安全管理机构", "应成立指导和管理网络安全工作的委员会或领导小组，其最高领导由单位主管领导担任或授权",
                "检查是否有信息安全领导机构", RiskLevel.MEDIUM,
                "查看是否有信息安全委员会/领导小组的任命文件",
                "成立信息安全领导小组，由单位主管领导担任组长", ["二级", "三级", "四级"]),
            ComplianceCheckItem("mlps2-mgmt-003", ComplianceStandard.MLPS2, "安全管理", "8.1.10.3",
                "人员安全管理", "应指定或授权专门的部门或人员负责人员离岗离职安全管理",
                "检查是否有人员离岗离职安全管理流程", RiskLevel.MEDIUM,
                "查看是否有员工离职时的权限回收、账号注销流程",
                "制定人员离岗离职安全管理流程，及时回收权限和账号", ["二级", "三级", "四级"]),
        ]
        for item in mlps2_items:
            self.check_items[item.item_id] = item

    def _init_iso27001_check_items(self):
        """初始化ISO27001检查项（核心控制项）"""
        iso_items = [
            ComplianceCheckItem("iso-001", ComplianceStandard.ISO27001, "信息安全方针", "5.1",
                "信息安全方针", "管理层应制定信息安全方针，包括信息安全目标",
                "检查是否有经管理层批准的信息安全方针", RiskLevel.HIGH,
                "查看信息安全方针文档，确认有管理层签字和定期评审",
                "制定信息安全方针，明确安全目标和承诺", []),
            ComplianceCheckItem("iso-002", ComplianceStandard.ISO27001, "信息安全组织", "5.2",
                "信息安全角色和职责", "应定义信息安全角色和职责，并分配给相关人员",
                "检查是否有明确的信息安全职责分配", RiskLevel.MEDIUM,
                "查看岗位职责说明，确认信息安全职责已分配",
                "定义并分配信息安全角色和职责", []),
            ComplianceCheckItem("iso-003", ComplianceStandard.ISO27001, "人力资源安全", "6.1",
                "人员筛选", "应对所有候选人进行背景验证，特别是敏感岗位",
                "检查是否对员工进行背景调查", RiskLevel.MEDIUM,
                "查看新员工入职流程，确认有背景验证环节",
                "对敏感岗位人员进行背景调查", []),
            ComplianceCheckItem("iso-004", ComplianceStandard.ISO27001, "资产管理", "7.1",
                "资产清单", "应识别和维护所有信息资产的清单",
                "检查是否有完整的信息资产清单", RiskLevel.MEDIUM,
                "查看资产清单，确认包含硬件、软件、数据、人员等资产",
                "建立并维护信息资产清单，定期更新", []),
            ComplianceCheckItem("iso-005", ComplianceStandard.ISO27001, "访问控制", "8.1",
                "访问控制策略", "应制定并实施访问控制策略，限制信息系统访问",
                "检查是否有访问控制策略", RiskLevel.HIGH,
                "查看访问控制策略文档，确认有用户权限管理流程",
                "制定访问控制策略，实施最小权限原则", []),
            ComplianceCheckItem("iso-006", ComplianceStandard.ISO27001, "访问控制", "8.2",
                "用户访问管理", "应通过正式的用户注册和注销流程控制访问权限",
                "检查是否有用户账号生命周期管理", RiskLevel.HIGH,
                "查看用户账号申请、审批、注销流程",
                "建立用户账号全生命周期管理流程", []),
            ComplianceCheckItem("iso-007", ComplianceStandard.ISO27001, "密码学", "8.3",
                "密码学控制", "应使用密码技术保护信息的保密性、完整性和真实性",
                "检查是否使用加密保护敏感数据", RiskLevel.HIGH,
                "检查数据传输和存储是否使用加密，密钥管理是否规范",
                "使用加密保护敏感数据，建立密钥管理流程", []),
            ComplianceCheckItem("iso-008", ComplianceStandard.ISO27001, "物理和环境安全", "8.4",
                "物理安全边界", "应定义和保护安全区域，防止未授权访问",
                "检查机房等安全区域是否有物理访问控制", RiskLevel.MEDIUM,
                "检查机房门禁、监控、访客登记等物理安全措施",
                "部署物理访问控制，监控安全区域", []),
            ComplianceCheckItem("iso-009", ComplianceStandard.ISO27001, "运行安全", "8.5",
                "变更管理", "应控制信息系统、软件和服务的变更",
                "检查是否有变更管理流程", RiskLevel.MEDIUM,
                "查看变更申请、审批、测试、回滚流程",
                "建立变更管理流程，所有变更需审批和测试", []),
            ComplianceCheckItem("iso-010", ComplianceStandard.ISO27001, "运行安全", "8.6",
                "技术漏洞管理", "应及时发现和修复信息系统中的技术漏洞",
                "检查是否有漏洞管理流程", RiskLevel.HIGH,
                "查看漏洞扫描、补丁管理、漏洞修复流程",
                "建立漏洞管理流程，定期扫描并及时修复漏洞", []),
            ComplianceCheckItem("iso-011", ComplianceStandard.ISO27001, "通信安全", "8.7",
                "网络安全管理", "应管理和控制网络中的信息传输，保护支持业务的信息系统",
                "检查网络是否有安全控制措施", RiskLevel.HIGH,
                "检查防火墙、入侵检测、网络分段等安全措施",
                "部署网络安全控制，实施网络分段和边界防护", []),
            ComplianceCheckItem("iso-012", ComplianceStandard.ISO27001, "系统获取开发维护", "8.8",
                "系统开发安全", "应在信息系统开发和维护过程中考虑安全",
                "检查是否有安全开发流程", RiskLevel.MEDIUM,
                "查看安全需求分析、代码审计、安全测试流程",
                "建立安全开发生命周期(SDL)，在开发各阶段考虑安全", []),
            ComplianceCheckItem("iso-013", ComplianceStandard.ISO27001, "供应商关系", "8.9",
                "供应商安全", "应管理供应商关系，确保供应商遵守安全要求",
                "检查是否有供应商安全管理", RiskLevel.MEDIUM,
                "查看供应商安全评估、合同安全条款、持续监控",
                "建立供应商安全管理流程，合同中包含安全要求", []),
            ComplianceCheckItem("iso-014", ComplianceStandard.ISO27001, "信息安全事件管理", "8.10",
                "事件管理", "应建立信息安全事件管理流程，确保及时响应和处置",
                "检查是否有信息安全事件响应流程", RiskLevel.HIGH,
                "查看事件报告、响应、处置、复盘流程和应急预案",
                "建立信息安全事件管理流程，制定应急预案并定期演练", []),
            ComplianceCheckItem("iso-015", ComplianceStandard.ISO27001, "业务连续性", "8.11",
                "业务连续性管理", "应确保业务在中断时能够持续运行",
                "检查是否有业务连续性计划", RiskLevel.HIGH,
                "查看业务影响分析、恢复策略、备份恢复、灾难恢复计划",
                "制定业务连续性计划，定期备份并测试恢复", []),
            ComplianceCheckItem("iso-016", ComplianceStandard.ISO27001, "符合性", "8.12",
                "合规性", "应确保符合法律法规、合同和安全要求",
                "检查是否进行合规性评估", RiskLevel.MEDIUM,
                "查看法律法规识别、合规评估、审计记录",
                "建立合规管理流程，定期进行合规性评估", []),
        ]
        for item in iso_items:
            self.check_items[item.item_id] = item

    def _load_data(self):
        """从文件加载数据"""
        assessments_file = os.path.join(self.data_dir, "assessments.json")
        if os.path.exists(assessments_file):
            try:
                with open(assessments_file, 'r', encoding='utf-8') as f:
                    assessments_data = json.load(f)
                for assessment_id, data in assessments_data.items():
                    assessment = ComplianceAssessment(
                        assessment_id=data["assessment_id"],
                        standard=ComplianceStandard(data["standard"]),
                        target_name=data.get("target_name", ""),
                        level=data.get("level", ""),
                        started_at=data.get("started_at", time.time()),
                        status=data.get("status", "in_progress"),
                        overall_score=data.get("overall_score", 0),
                        pass_count=data.get("pass_count", 0),
                        fail_count=data.get("fail_count", 0),
                        partial_count=data.get("partial_count", 0),
                        na_count=data.get("na_count", 0),
                        not_checked_count=data.get("not_checked_count", 0)
                    )
                    for result_id, result_data in data.get("check_results", {}).items():
                        assessment.check_results[result_id] = CheckResult(
                            result_id=result_data["result_id"],
                            item_id=result_data["item_id"],
                            status=CheckStatus(result_data.get("status", "not_checked")),
                            evidence=result_data.get("evidence", ""),
                            findings=result_data.get("findings", "")
                        )
                    self.assessments[assessment_id] = assessment
            except Exception as e:
                log.error(f"加载合规评估失败: {e}")

    def _save_data(self):
        """保存数据到文件"""
        assessments_file = os.path.join(self.data_dir, "assessments.json")
        try:
            assessments_data = {}
            for aid, assessment in self.assessments.items():
                data = assessment.to_dict()
                data["check_results"] = {rid: r.to_dict() for rid, r in assessment.check_results.items()}
                assessments_data[aid] = data
            with open(assessments_file, 'w', encoding='utf-8') as f:
                json.dump(assessments_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存合规评估失败: {e}")

    # ===== 评估管理 =====
    def start_assessment(self, standard: str, target_name: str = "",
                          level: str = "", target_description: str = "") -> str:
        """启动合规评估"""
        assessment_id = f"comp-{uuid.uuid4().hex[:8]}"
        std = ComplianceStandard(standard)
        assessment = ComplianceAssessment(
            assessment_id=assessment_id,
            standard=std,
            target_name=target_name,
            target_description=target_description,
            level=level
        )

        # 初始化所有检查项为未检查
        for item in self.check_items.values():
            if item.standard == std:
                result = CheckResult(
                    result_id=f"res-{uuid.uuid4().hex[:6]}",
                    item_id=item.item_id,
                    status=CheckStatus.NOT_CHECKED
                )
                assessment.check_results[result.result_id] = result

        assessment.not_checked_count = len(assessment.check_results)
        self.assessments[assessment_id] = assessment
        self._save_data()
        log.info(f"启动合规评估: {assessment_id}, 标准={standard}, 检查项={len(assessment.check_results)}")
        return assessment_id

    def record_check_result(self, assessment_id: str, item_id: str,
                             status: str, evidence: str = "",
                             findings: str = "", notes: str = "") -> bool:
        """记录检查结果"""
        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return False

        # 找到对应的检查结果
        target_result = None
        for result in assessment.check_results.values():
            if result.item_id == item_id:
                target_result = result
                break

        if not target_result:
            return False

        # 更新状态统计
        old_status = target_result.status
        new_status = CheckStatus(status)

        if old_status == CheckStatus.PASS:
            assessment.pass_count -= 1
        elif old_status == CheckStatus.FAIL:
            assessment.fail_count -= 1
        elif old_status == CheckStatus.PARTIAL:
            assessment.partial_count -= 1
        elif old_status == CheckStatus.NOT_APPLICABLE:
            assessment.na_count -= 1
        elif old_status == CheckStatus.NOT_CHECKED:
            assessment.not_checked_count -= 1

        target_result.status = new_status
        target_result.evidence = evidence
        target_result.findings = findings
        target_result.notes = notes
        target_result.checked_at = time.time()

        if new_status == CheckStatus.PASS:
            assessment.pass_count += 1
        elif new_status == CheckStatus.FAIL:
            assessment.fail_count += 1
        elif new_status == CheckStatus.PARTIAL:
            assessment.partial_count += 1
        elif new_status == CheckStatus.NOT_APPLICABLE:
            assessment.na_count += 1
        elif new_status == CheckStatus.NOT_CHECKED:
            assessment.not_checked_count += 1

        # 计算得分
        total_applicable = assessment.pass_count + assessment.fail_count + assessment.partial_count
        if total_applicable > 0:
            assessment.overall_score = (assessment.pass_count + assessment.partial_count * 0.5) / total_applicable * 100

        self._save_data()
        return True

    def complete_assessment(self, assessment_id: str) -> bool:
        """完成评估"""
        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return False
        assessment.status = "completed"
        assessment.completed_at = time.time()
        self._save_data()
        return True

    # ===== 报告生成 =====
    def generate_report(self, assessment_id: str, format: str = "markdown") -> str:
        """生成合规报告"""
        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return "评估不存在"

        item_map = {item.item_id: item for item in self.check_items.values()}

        if format == "markdown":
            return self._generate_markdown_report(assessment, item_map)
        elif format == "html":
            return self._generate_html_report(assessment, item_map)
        else:
            return self._generate_markdown_report(assessment, item_map)

    def _generate_markdown_report(self, assessment: ComplianceAssessment,
                                    item_map: Dict[str, ComplianceCheckItem]) -> str:
        """生成Markdown格式报告"""
        lines = []
        standard_name = "网络安全等级保护2.0" if assessment.standard == ComplianceStandard.MLPS2 else "ISO27001信息安全管理体系"

        lines.append(f"# {standard_name}合规评估报告")
        lines.append("")
        lines.append(f"**评估对象**: {assessment.target_name}")
        lines.append(f"**评估标准**: {standard_name}")
        if assessment.level:
            lines.append(f"**保护等级**: {assessment.level}")
        lines.append(f"**评估时间**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(assessment.started_at))}")
        lines.append("")

        # 评估概览
        lines.append("## 一、评估概览")
        lines.append("")
        lines.append("| 指标 | 数值 |")
        lines.append("|------|------|")
        lines.append(f"| 总检查项 | {len(assessment.check_results)} |")
        lines.append(f"| 符合 | {assessment.pass_count} |")
        lines.append(f"| 不符合 | {assessment.fail_count} |")
        lines.append(f"| 部分符合 | {assessment.partial_count} |")
        lines.append(f"| 不适用 | {assessment.na_count} |")
        lines.append(f"| 未检查 | {assessment.not_checked_count} |")
        lines.append(f"| **合规得分** | **{assessment.overall_score:.2f}%** |")
        lines.append("")

        # 不符合项详情
        fail_items = []
        for result in assessment.check_results.values():
            if result.status in [CheckStatus.FAIL, CheckStatus.PARTIAL]:
                item = item_map.get(result.item_id)
                if item:
                    fail_items.append((item, result))

        if fail_items:
            lines.append("## 二、不符合项详情")
            lines.append("")
            for i, (item, result) in enumerate(fail_items, 1):
                status_text = "不符合" if result.status == CheckStatus.FAIL else "部分符合"
                lines.append(f"### {i}. {item.title} [{status_text}]")
                lines.append("")
                lines.append(f"- **控制项编号**: {item.control_id}")
                lines.append(f"- **类别**: {item.category}")
                lines.append(f"- **风险等级**: {item.risk_level.value}")
                lines.append(f"- **合规要求**: {item.requirement}")
                if result.findings:
                    lines.append(f"- **发现问题**: {result.findings}")
                if result.evidence:
                    lines.append(f"- **检查证据**: {result.evidence}")
                if item.remediation_suggestion:
                    lines.append(f"- **整改建议**: {item.remediation_suggestion}")
                lines.append("")

        # 整改建议汇总
        lines.append("## 三、整改建议汇总")
        lines.append("")
        high_risk = [item for item, result in fail_items if item.risk_level == RiskLevel.HIGH]
        medium_risk = [item for item, result in fail_items if item.risk_level == RiskLevel.MEDIUM]
        low_risk = [item for item, result in fail_items if item.risk_level == RiskLevel.LOW]

        if high_risk:
            lines.append("### 高风险项（优先整改）")
            lines.append("")
            for item in high_risk:
                lines.append(f"- **{item.title}**: {item.remediation_suggestion}")
            lines.append("")

        if medium_risk:
            lines.append("### 中风险项（计划整改）")
            lines.append("")
            for item in medium_risk:
                lines.append(f"- **{item.title}**: {item.remediation_suggestion}")
            lines.append("")

        # 结论
        lines.append("## 四、评估结论")
        lines.append("")
        if assessment.overall_score >= 90:
            lines.append(f"本次评估合规得分为 **{assessment.overall_score:.2f}%**，整体合规状况良好。")
        elif assessment.overall_score >= 70:
            lines.append(f"本次评估合规得分为 **{assessment.overall_score:.2f}%**，基本符合要求，需对不符合项进行整改。")
        else:
            lines.append(f"本次评估合规得分为 **{assessment.overall_score:.2f}%**，存在较多不符合项，需立即进行整改。")
        lines.append("")
        lines.append(f"共发现 **{len(fail_items)}** 项不符合或部分符合，其中高风险 **{len(high_risk)}** 项，中风险 **{len(medium_risk)}** 项。")
        lines.append("")
        lines.append("建议按照风险等级优先进行整改，整改完成后进行复评。")
        lines.append("")

        return "\n".join(lines)

    def _generate_html_report(self, assessment: ComplianceAssessment,
                               item_map: Dict[str, ComplianceCheckItem]) -> str:
        """生成HTML格式报告（简化版）"""
        markdown = self._generate_markdown_report(assessment, item_map)
        # 简单转换：标题转h1/h2，表格保留
        html = markdown.replace("# ", "<h1>").replace("\n", "<br>")
        return f"<html><body>{html}</body></html>"

    # ===== 差距分析 =====
    def get_gap_analysis(self, assessment_id: str) -> Dict[str, Any]:
        """获取差距分析"""
        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return {"error": "评估不存在"}

        item_map = {item.item_id: item for item in self.check_items.values()}
        gaps = []
        for result in assessment.check_results.values():
            if result.status in [CheckStatus.FAIL, CheckStatus.PARTIAL]:
                item = item_map.get(result.item_id)
                if item:
                    gaps.append({
                        "item_id": item.item_id,
                        "title": item.title,
                        "category": item.category,
                        "control_id": item.control_id,
                        "status": result.status.value,
                        "risk_level": item.risk_level.value,
                        "requirement": item.requirement,
                        "findings": result.findings,
                        "remediation": item.remediation_suggestion
                    })

        return {
            "assessment_id": assessment_id,
            "total_gaps": len(gaps),
            "high_risk_gaps": sum(1 for g in gaps if g["risk_level"] == "high"),
            "medium_risk_gaps": sum(1 for g in gaps if g["risk_level"] == "medium"),
            "low_risk_gaps": sum(1 for g in gaps if g["risk_level"] == "low"),
            "gaps": gaps
        }

    # ===== 统计 =====
    def get_statistics(self) -> Dict[str, Any]:
        """获取系统统计"""
        return {
            "total_check_items": len(self.check_items),
            "mlps2_items": sum(1 for i in self.check_items.values() if i.standard == ComplianceStandard.MLPS2),
            "iso27001_items": sum(1 for i in self.check_items.values() if i.standard == ComplianceStandard.ISO27001),
            "total_assessments": len(self.assessments),
            "completed_assessments": sum(1 for a in self.assessments.values() if a.status == "completed"),
            "in_progress_assessments": sum(1 for a in self.assessments.values() if a.status == "in_progress"),
            "categories": list(set(i.category for i in self.check_items.values()))
        }


# 全局实例
compliance_generator = ComplianceReportGenerator()
