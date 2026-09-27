"""
compliance_manager安全工具集成模块，提供相关安全工具的封装和调用。

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
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from utils.logger import log


@dataclass
class ComplianceControl:
    """合规控制项"""
    control_id: str
    standard: str  # mlps2.0 / iso27001
    category: str
    name: str
    description: str
    level: str = ""  # 一级/二级/三级/四级 (等保)
    implementation: str = "not_assessed"  # implemented/partially/not_implemented/not_assessed
    evidence: str = ""
    risk_level: str = "medium"  # critical/high/medium/low
    recommendation: str = ""


@dataclass
class ComplianceFinding:
    """合规发现"""
    finding_id: str
    control_id: str
    standard: str
    severity: str  # critical/high/medium/low/info
    title: str
    description: str
    evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    remediation_effort: str = "medium"  # low/medium/high
    status: str = "open"  # open/in_progress/resolved/accepted


class ComplianceManager:
    """合规管理器"""

    def __init__(self):
        """初始化ComplianceManager实例。

        Args:
            self: 类实例。
        """
        self.mlps_controls = self._load_mlps_controls()
        self.iso_controls = self._load_iso_controls()

    def _load_mlps_controls(self) -> List[ComplianceControl]:
        """加载等保2.0控制项（精选关键控制项）"""
        controls = [
            # 安全物理环境
            ComplianceControl("MLPS-PE-01", "mlps2.0", "安全物理环境", "机房选址",
                            "机房场地应选择在具有防震、防风和防雨等能力的建筑内", "三级"),
            ComplianceControl("MLPS-PE-02", "mlps2.0", "安全物理环境", "物理访问控制",
                            "机房出入口应配置电子门禁系统，控制、鉴别和记录进入的人员", "三级"),
            ComplianceControl("MLPS-PE-03", "mlps2.0", "安全物理环境", "防盗窃和防破坏",
                            "应将设备或主要部件进行固定，并设置明显的不易除去的标识", "三级"),
            ComplianceControl("MLPS-PE-04", "mlps2.0", "安全物理环境", "防雷击",
                            "应将各类机柜、设施和设备等通过接地系统安全接地", "三级"),
            ComplianceControl("MLPS-PE-05", "mlps2.0", "安全物理环境", "防火",
                            "机房应设置火灾自动消防系统，能够自动检测火情、自动报警，并自动灭火", "三级"),
            ComplianceControl("MLPS-PE-06", "mlps2.0", "安全物理环境", "防水和防潮",
                            "应采取措施防止雨水通过机房窗户、屋顶和墙壁渗透", "三级"),
            ComplianceControl("MLPS-PE-07", "mlps2.0", "安全物理环境", "防静电",
                            "应采用防静电地板或地面并采取必要的接地等防静电措施", "三级"),
            ComplianceControl("MLPS-PE-08", "mlps2.0", "安全物理环境", "温湿度控制",
                            "应设置温湿度自动调节设施，使机房温湿度的变化在设备运行所允许的范围之内", "三级"),
            ComplianceControl("MLPS-PE-09", "mlps2.0", "安全物理环境", "电力供应",
                            "应在机房供电线路上配置稳压器和过电压防护设备", "三级"),
            ComplianceControl("MLPS-PE-10", "mlps2.0", "安全物理环境", "电磁防护",
                            "应采用接地方式防止外界电磁干扰和设备寄生耦合干扰", "三级"),

            # 安全通信网络
            ComplianceControl("MLPS-CN-01", "mlps2.0", "安全通信网络", "网络架构",
                            "应保证网络设备的业务处理能力满足业务高峰期需要", "三级"),
            ComplianceControl("MLPS-CN-02", "mlps2.0", "安全通信网络", "通信传输",
                            "应采用校验技术或密码技术保证通信过程中数据的完整性", "三级"),
            ComplianceControl("MLPS-CN-03", "mlps2.0", "安全通信网络", "可信验证",
                            "可基于可信根对通信设备的系统引导程序、系统程序等进行可信验证", "三级"),

            # 安全区域边界
            ComplianceControl("MLPS-AB-01", "mlps2.0", "安全区域边界", "边界防护",
                            "应保证跨越边界的访问和数据流通过边界设备提供的受控接口进行通信", "三级"),
            ComplianceControl("MLPS-AB-02", "mlps2.0", "安全区域边界", "访问控制",
                            "应在网络边界或区域之间根据访问控制策略设置访问控制规则", "三级"),
            ComplianceControl("MLPS-AB-03", "mlps2.0", "安全区域边界", "入侵防范",
                            "应在关键网络节点处检测、防止或限制从外部发起的网络攻击行为", "三级"),
            ComplianceControl("MLPS-AB-04", "mlps2.0", "安全区域边界", "恶意代码防范",
                            "应在关键网络节点处对恶意代码进行检测和清除", "三级"),
            ComplianceControl("MLPS-AB-05", "mlps2.0", "安全区域边界", "安全审计",
                            "应在网络边界、重要网络节点进行安全审计，审计覆盖到每个用户", "三级"),
            ComplianceControl("MLPS-AB-06", "mlps2.0", "安全区域边界", "可信验证",
                            "可基于可信根对边界设备的系统引导程序、系统程序等进行可信验证", "三级"),

            # 安全计算环境
            ComplianceControl("MLPS-CE-01", "mlps2.0", "安全计算环境", "身份鉴别",
                            "应对登录的用户进行身份标识和鉴别，身份标识具有唯一性", "三级"),
            ComplianceControl("MLPS-CE-02", "mlps2.0", "安全计算环境", "访问控制",
                            "应对登录的用户分配账户和权限", "三级"),
            ComplianceControl("MLPS-CE-03", "mlps2.0", "安全计算环境", "安全审计",
                            "应启用安全审计功能，审计覆盖到每个用户，对重要的用户行为和重要安全事件进行审计", "三级"),
            ComplianceControl("MLPS-CE-04", "mlps2.0", "安全计算环境", "入侵防范",
                            "应遵循最小安装的原则，仅安装需要的组件和应用程序", "三级"),
            ComplianceControl("MLPS-CE-05", "mlps2.0", "安全计算环境", "恶意代码防范",
                            "应采用免受恶意代码攻击的技术措施或主动免疫可信验证机制及时识别入侵和病毒行为", "三级"),
            ComplianceControl("MLPS-CE-06", "mlps2.0", "安全计算环境", "可信验证",
                            "可基于可信根对计算设备的系统引导程序、系统程序、重要配置参数和应用程序等进行可信验证", "三级"),
            ComplianceControl("MLPS-CE-07", "mlps2.0", "安全计算环境", "数据完整性",
                            "应采用校验技术或密码技术保证重要数据在传输过程中的完整性", "三级"),
            ComplianceControl("MLPS-CE-08", "mlps2.0", "安全计算环境", "数据保密性",
                            "应采用密码技术保证重要数据在传输过程中的保密性", "三级"),
            ComplianceControl("MLPS-CE-09", "mlps2.0", "安全计算环境", "数据备份恢复",
                            "应提供重要数据的本地数据备份与恢复功能", "三级"),
            ComplianceControl("MLPS-CE-10", "mlps2.0", "安全计算环境", "剩余信息保护",
                            "应保证鉴别信息所在的存储空间被释放或重新分配前得到完全清除", "三级"),
            ComplianceControl("MLPS-CE-11", "mlps2.0", "安全计算环境", "个人信息保护",
                            "应仅采集和保存业务必需的用户个人信息", "三级"),

            # 安全管理中心
            ComplianceControl("MLPS-MC-01", "mlps2.0", "安全管理中心", "系统管理",
                            "应对系统管理员进行身份鉴别，只允许其通过特定的命令或操作界面进行系统管理操作", "三级"),
            ComplianceControl("MLPS-MC-02", "mlps2.0", "安全管理中心", "审计管理",
                            "应对审计管理员进行身份鉴别，只允许其通过特定的命令或操作界面进行安全审计操作", "三级"),
            ComplianceControl("MLPS-MC-03", "mlps2.0", "安全管理中心", "安全管理",
                            "应对安全管理员进行身份鉴别，只允许其通过特定的命令或操作界面进行安全管理操作", "三级"),
            ComplianceControl("MLPS-MC-04", "mlps2.0", "安全管理中心", "集中管控",
                            "应划分出特定的管理区域，对分布在网络中的安全设备或安全组件进行管控", "三级"),
        ]
        return controls

    def _load_iso_controls(self) -> List[ComplianceControl]:
        """加载ISO 27001:2022控制项（精选关键控制项）"""
        controls = [
            # A.5 组织控制
            ComplianceControl("ISO-A5.1", "iso27001", "信息安全策略", "信息安全策略集",
                            "应建立信息安全策略集，由管理层批准、发布并传达给所有员工和相关外部方"),
            ComplianceControl("ISO-A5.2", "iso27001", "信息安全策略", "信息安全策略的评审",
                            "应按计划的时间间隔或在重大变更发生时评审信息安全策略"),
            ComplianceControl("ISO-A5.3", "iso27001", "组织角色", "信息安全的角色和职责",
                            "应定义和分配信息安全的角色和职责"),
            ComplianceControl("ISO-A5.4", "iso27001", "组织角色", "职责分离",
                            "应分离冲突的职责和责任范围，以降低未授权或无意识修改或滥用组织资产的风险"),
            ComplianceControl("ISO-A5.5", "iso27001", "组织角色", "与主管当局的联系",
                            "应建立并保持与相关主管当局的适当联系"),
            ComplianceControl("ISO-A5.6", "iso27001", "组织角色", "与特殊利益团体的联系",
                            "应建立并保持与特殊利益团体、其他安全专业人员和行业协会的联系"),
            ComplianceControl("ISO-A5.7", "iso27001", "组织角色", "威胁情报",
                            "应收集和分析有关威胁情报的信息，以产生对威胁的认识"),
            ComplianceControl("ISO-A5.8", "iso27001", "组织角色", "项目管理中的信息安全",
                            "信息安全应纳入项目管理"),
            ComplianceControl("ISO-A5.9", "iso27001", "组织角色", "移动设备和远程工作的信息安全",
                            "应制定并实施关于移动设备和远程工作的策略和程序"),
            ComplianceControl("ISO-A5.10", "iso27001", "组织角色", "供应商关系中的信息安全",
                            "应建立并维护关于供应商关系中信息安全的要求"),

            # A.6 人员控制
            ComplianceControl("ISO-A6.1", "iso27001", "人员安全", "人员筛选",
                            "应根据相关法律法规、道德规范和业务要求，对所有候选人进行筛选"),
            ComplianceControl("ISO-A6.2", "iso27001", "人员安全", "雇佣条款和条件",
                            "雇佣合同应声明员工和组织的信息安全责任"),
            ComplianceControl("ISO-A6.3", "iso27001", "人员安全", "信息安全意识、教育和培训",
                            "组织的所有员工和相关外部方应接受与其工作职能相适应的信息安全意识教育和培训"),
            ComplianceControl("ISO-A6.4", "iso27001", "人员安全", "纪律处理过程",
                            "应建立并传达一个正式的、有记录的纪律处理过程"),
            ComplianceControl("ISO-A6.5", "iso27001", "人员安全", "雇佣终止或变更后的责任",
                            "应定义和分配雇佣终止或变更后的信息安全责任和义务"),

            # A.7 物理控制
            ComplianceControl("ISO-A7.1", "iso27001", "物理安全", "物理安全边界",
                            "应使用安全边界（如墙壁、刷卡入口或受监控的接待区）来保护包含信息和其他相关资产的区域"),
            ComplianceControl("ISO-A7.2", "iso27001", "物理安全", "物理入口",
                            "安全区域应受到适当的入口控制，以确保只有授权人员才能进入"),
            ComplianceControl("ISO-A7.3", "iso27001", "物理安全", "办公室、房间和设施的安全",
                            "应为办公室、房间和设施设计并应用物理安全指南"),
            ComplianceControl("ISO-A7.4", "iso27001", "物理安全", "安全的电源和通信",
                            "应保护电源和通信设施，防止中断和其他异常情况"),
            ComplianceControl("ISO-A7.5", "iso27001", "物理安全", "场地布线的安全",
                            "应保护网络布线免受窃听或损坏"),
            ComplianceControl("ISO-A7.6", "iso27001", "物理安全", "设备维护",
                            "应正确维护设备，以确保其持续的可用性和完整性"),
            ComplianceControl("ISO-A7.7", "iso27001", "物理安全", "资产的安全移除",
                            "未经授权，不得将设备、信息或软件带出组织场地"),
            ComplianceControl("ISO-A7.8", "iso27001", "物理安全", "无人值守的用户设备",
                            "无人值守的用户设备应受到适当的保护"),
            ComplianceControl("ISO-A7.9", "iso27001", "物理安全", "桌面和屏幕清理策略",
                            "应实施桌面和屏幕清理策略，以减少在工作时间和工作时间之外对信息、文档和可移动存储介质的未授权访问风险"),

            # A.8 技术控制
            ComplianceControl("ISO-A8.1", "iso27001", "技术安全", "用户终端设备",
                            "应制定并实施关于用户终端设备的获取、连接和使用的规则"),
            ComplianceControl("ISO-A8.2", "iso27001", "技术安全", "特权访问权",
                            "应限制和控制特权的分配和使用"),
            ComplianceControl("ISO-A8.3", "iso27001", "技术安全", "信息访问限制",
                            "应根据业务和安全要求，限制对信息和其他相关资产的访问"),
            ComplianceControl("ISO-A8.4", "iso27001", "技术安全", "访问信息的安全",
                            "应防止对信息系统的未授权访问"),
            ComplianceControl("ISO-A8.5", "iso27001", "技术安全", "安全的身份验证",
                            "应管理身份验证信息的保密性和完整性"),
            ComplianceControl("ISO-A8.6", "iso27001", "技术安全", "能力、设备和人员的容量管理",
                            "应监控、调整和记录资源的使用，以确保满足要求的系统性能"),
            ComplianceControl("ISO-A8.7", "iso27001", "技术安全", "恶意软件的防护",
                            "应实施适当的检测、预防和恢复机制来防护恶意软件"),
            ComplianceControl("ISO-A8.8", "iso27001", "技术安全", "技术漏洞的管理",
                            "应及时识别技术漏洞并采取适当的措施"),
            ComplianceControl("ISO-A8.9", "iso27001", "技术安全", "配置管理",
                            "应建立、记录和维护配置基线"),
            ComplianceControl("ISO-A8.10", "iso27001", "技术安全", "信息删除",
                            "应在不再需要时，安全地删除或销毁存储介质上的信息"),
            ComplianceControl("ISO-A8.11", "iso27001", "技术安全", "数据脱敏",
                            "应使用数据脱敏来降低敏感数据暴露的风险"),
            ComplianceControl("ISO-A8.12", "iso27001", "技术安全", "数据防泄漏",
                            "应实施数据防泄漏措施，以检测和防止敏感数据的未授权传输"),
            ComplianceControl("ISO-A8.13", "iso27001", "技术安全", "信息备份",
                            "应按照既定的备份策略，对信息进行备份，并定期测试备份的恢复能力"),
            ComplianceControl("ISO-A8.14", "iso27001", "技术安全", "冗余能力",
                            "应实施冗余能力，以满足可用性要求"),
            ComplianceControl("ISO-A8.15", "iso27001", "技术安全", "日志记录",
                            "应记录用户活动、异常情况和信息安全事件"),
            ComplianceControl("ISO-A8.16", "iso27001", "技术安全", "监控活动",
                            "应监控网络、系统和应用程序，以检测异常活动和潜在的安全事件"),
            ComplianceControl("ISO-A8.17", "iso27001", "技术安全", "时钟同步",
                            "应同步信息系统的时钟，以支持日志记录和事件调查"),
            ComplianceControl("ISO-A8.18", "iso27001", "技术安全", "使用公用网络的安全",
                            "应保护通过公用网络传输的应用服务信息"),
            ComplianceControl("ISO-A8.19", "iso27001", "技术安全", "网络分段",
                            "应根据组织的信息安全要求，将网络划分为多个安全域"),
            ComplianceControl("ISO-A8.20", "iso27001", "技术安全", "Web服务的安全",
                            "应保护Web服务，以防止未授权访问和攻击"),
            ComplianceControl("ISO-A8.21", "iso27001", "技术安全", "安全的系统架构和工程原则",
                            "应建立并应用安全的系统架构和工程原则"),
            ComplianceControl("ISO-A8.22", "iso27001", "技术安全", "安全的开发环境",
                            "应保护开发环境，并对其访问进行控制"),
            ComplianceControl("ISO-A8.23", "iso27001", "技术安全", "外包开发",
            "应监督和监测外包开发活动"),
            ComplianceControl("ISO-A8.24", "iso27001", "技术安全", "系统安全测试",
                            "应在开发和实施过程中对系统进行安全测试"),
            ComplianceControl("ISO-A8.25", "iso27001", "技术安全", "安全的软件开发",
                            "应在整个开发生命周期中应用安全的软件开发原则"),
            ComplianceControl("ISO-A8.26", "iso27001", "技术安全", "应用安全的密钥管理",
                            "应制定、实施和维护密钥管理，以支持使用密码技术"),
            ComplianceControl("ISO-A8.27", "iso27001", "技术安全", "安全的审计和日志记录",
                            "应保护审计日志和记录，防止篡改和未授权访问"),
            ComplianceControl("ISO-A8.28", "iso27001", "技术安全", "保护信息和相关资产的隐私",
                            "应制定并实施隐私保护策略，以保护个人身份信息和其他敏感数据"),
            ComplianceControl("ISO-A8.29", "iso27001", "技术安全", "非活动账户的删除或禁用",
                            "应定期审查和删除或禁用非活动账户"),
            ComplianceControl("ISO-A8.30", "iso27001", "技术安全", "会话超时",
                            "应在一段不活动时间后终止会话"),
            ComplianceControl("ISO-A8.31", "iso27001", "技术安全", "使用加密技术",
                            "应使用加密技术来保护信息的保密性、完整性和真实性"),
        ]
        return controls

    def assess_control(self, standard: str, control_id: str,
                       implementation: str, evidence: str = "",
                       risk_level: str = "medium",
                       recommendation: str = "") -> Dict[str, Any]:
        """评估单个控制项"""
        controls = self.mlps_controls if standard == "mlps2.0" else self.iso_controls

        for control in controls:
            if control.control_id == control_id:
                control.implementation = implementation
                control.evidence = evidence
                control.risk_level = risk_level
                control.recommendation = recommendation
                return {
                    "success": True,
                    "control_id": control_id,
                    "standard": standard,
                    "implementation": implementation,
                    "risk_level": risk_level,
                    "message": "控制项评估已更新",
                }

        return {"success": False, "error": f"控制项 {control_id} 不存在"}

    def generate_gap_analysis(self, standard: str = "both",
                                scan_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """生成合规差距分析报告"""
        findings = []
        controls = []

        if standard in ["mlps2.0", "both"]:
            controls.extend(self.mlps_controls)
        if standard in ["iso27001", "both"]:
            controls.extend(self.iso_controls)

        # 根据扫描结果自动评估
        if scan_results:
            findings.extend(self._auto_assess_from_scan(scan_results, controls))

        # 统计
        implemented = sum(1 for c in controls if c.implementation == "implemented")
        partially = sum(1 for c in controls if c.implementation == "partially")
        not_implemented = sum(1 for c in controls if c.implementation == "not_implemented")
        not_assessed = sum(1 for c in controls if c.implementation == "not_assessed")

        total = len(controls)
        compliance_rate = ((implemented + partially * 0.5) / total * 100) if total > 0 else 0

        # 高风险项
        high_risk = [c for c in controls
                     if c.implementation in ["not_implemented", "partially"]
                     and c.risk_level in ["critical", "high"]]

        return {
            "standard": standard,
            "assessment_date": datetime.now().isoformat(),
            "summary": {
                "total_controls": total,
                "implemented": implemented,
                "partially_implemented": partially,
                "not_implemented": not_implemented,
                "not_assessed": not_assessed,
                "compliance_rate": round(compliance_rate, 1),
                "high_risk_items": len(high_risk),
            },
            "high_risk_findings": [
                {
                    "control_id": c.control_id,
                    "standard": c.standard,
                    "category": c.category,
                    "name": c.name,
                    "risk_level": c.risk_level,
                    "implementation": c.implementation,
                    "recommendation": c.recommendation,
                }
                for c in high_risk[:20]
            ],
            "findings": findings,
            "recommendations": self._generate_recommendations(controls),
        }

    def _auto_assess_from_scan(self, scan_results: Dict[str, Any],
                                 controls: List[ComplianceControl]) -> List[ComplianceFinding]:
        """根据扫描结果自动评估合规性"""
        findings = []

        # 检查开放端口
        open_ports = scan_results.get("open_ports", [])
        if any(p in [21, 23, 110, 143] for p in open_ports):
            findings.append(ComplianceFinding(
                finding_id="AUTO-001",
                control_id="MLPS-CN-02",
                standard="mlps2.0",
                severity="high",
                title="不安全协议使用",
                description="检测到FTP/Telnet/POP3/IMAP等不安全协议在使用，未使用加密传输",
                evidence=f"开放端口: {open_ports}",
                impact="数据在传输过程中可能被窃听或篡改",
                recommendation="禁用不安全协议，改用SFTP/SSH/HTTPS等加密协议",
            ))

        # 检查弱密码
        weak_passwords = scan_results.get("weak_passwords", [])
        if weak_passwords:
            findings.append(ComplianceFinding(
                finding_id="AUTO-002",
                control_id="MLPS-CE-01",
                standard="mlps2.0",
                severity="critical",
                title="弱密码/默认凭证",
                description=f"检测到 {len(weak_passwords)} 个弱密码或默认凭证",
                evidence=str(weak_passwords),
                impact="攻击者可轻易登录系统，获取未授权访问",
                recommendation="强制使用强密码策略，修改所有默认凭证，启用多因素认证",
            ))

        # 检查高危漏洞
        high_vulns = scan_results.get("high_vulnerabilities", [])
        if high_vulns:
            findings.append(ComplianceFinding(
                finding_id="AUTO-003",
                control_id="ISO-A8.8",
                standard="iso27001",
                severity="critical",
                title="未修复的高危漏洞",
                description=f"检测到 {len(high_vulns)} 个高危或严重漏洞未修复",
                evidence=str([v.get("cve_id", "") for v in high_vulns]),
                impact="系统可能被攻击者利用，导致数据泄露或系统被控制",
                recommendation="立即修复所有高危漏洞，建立漏洞管理流程，定期进行漏洞扫描",
            ))

        # 检查审计日志
        if not scan_results.get("audit_logging_enabled", False):
            findings.append(ComplianceFinding(
                finding_id="AUTO-004",
                control_id="MLPS-CE-03",
                standard="mlps2.0",
                severity="high",
                title="安全审计未启用",
                description="系统未启用安全审计功能，无法记录用户行为和安全事件",
                impact="安全事件发生后无法追溯，无法满足合规要求",
                recommendation="启用全面的安全审计，记录登录、权限变更、数据访问等关键操作",
            ))

        # 检查数据加密
        if not scan_results.get("data_encryption_enabled", False):
            findings.append(ComplianceFinding(
                finding_id="AUTO-005",
                control_id="MLPS-CE-08",
                standard="mlps2.0",
                severity="high",
                title="数据加密未实施",
                description="重要数据在传输和存储过程中未进行加密保护",
                impact="敏感数据可能被未授权访问或泄露",
                recommendation="实施传输加密（TLS/SSL）和存储加密，建立密钥管理流程",
            ))

        # 检查备份
        if not scan_results.get("backup_enabled", False):
            findings.append(ComplianceFinding(
                finding_id="AUTO-006",
                control_id="MLPS-CE-09",
                standard="mlps2.0",
                severity="medium",
                title="数据备份未配置",
                description="系统未配置定期数据备份和恢复机制",
                impact="数据丢失后无法恢复，业务连续性无法保障",
                recommendation="建立定期备份策略，定期测试备份恢复能力，实施异地备份",
            ))

        return findings

    def _generate_recommendations(self, controls: List[ComplianceControl]) -> List[Dict[str, Any]]:
        """生成整改建议"""
        recommendations = []

        # 按优先级排序
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        high_risk = [c for c in controls
                     if c.implementation in ["not_implemented", "partially"]
                     and c.risk_level in ["critical", "high"]]
        high_risk.sort(key=lambda x: priority_order.get(x.risk_level, 99))

        for i, control in enumerate(high_risk[:10], 1):
            recommendations.append({
                "priority": i,
                "control_id": control.control_id,
                "standard": control.standard,
                "category": control.category,
                "name": control.name,
                "risk_level": control.risk_level,
                "current_status": control.implementation,
                "recommendation": control.recommendation or f"实施 {control.name} 控制措施",
                "estimated_effort": "高" if control.risk_level == "critical" else "中",
            })

        return recommendations

    def generate_compliance_report(self, standard: str = "both",
                                     organization: str = "",
                                     system_name: str = "",
                                     scan_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """生成完整合规报告"""
        gap_analysis = self.generate_gap_analysis(standard, scan_results)

        report = {
            "report_title": f"{standard} 合规评估报告",
            "organization": organization,
            "system_name": system_name,
            "assessment_date": datetime.now().isoformat(),
            "assessor": "AI Hacking Agent - 自动化合规评估",
            "scope": {
                "standard": standard,
                "controls_assessed": gap_analysis["summary"]["total_controls"],
            },
            "executive_summary": {
                "compliance_rate": gap_analysis["summary"]["compliance_rate"],
                "overall_risk": "高" if gap_analysis["summary"]["high_risk_items"] > 5 else
                              "中" if gap_analysis["summary"]["high_risk_items"] > 0 else "低",
                "key_findings": [
                    f"已实施控制项: {gap_analysis['summary']['implemented']}",
                    f"部分实施: {gap_analysis['summary']['partially_implemented']}",
                    f"未实施: {gap_analysis['summary']['not_implemented']}",
                    f"未评估: {gap_analysis['summary']['not_assessed']}",
                    f"高风险项: {gap_analysis['summary']['high_risk_items']}",
                ],
            },
            "gap_analysis": gap_analysis,
            "remediation_plan": gap_analysis["recommendations"],
            "appendix": {
                "mlps2.0_controls_count": len(self.mlps_controls),
                "iso27001_controls_count": len(self.iso_controls),
                "assessment_methodology": "基于自动化扫描结果 + 控制项映射 + 风险评级",
            },
        }

        return report

    def get_control_list(self, standard: str = "mlps2.0") -> List[Dict[str, Any]]:
        """获取控制项列表"""
        controls = self.mlps_controls if standard == "mlps2.0" else self.iso_controls
        return [
            {
                "control_id": c.control_id,
                "category": c.category,
                "name": c.name,
                "description": c.description,
                "level": c.level,
                "implementation": c.implementation,
            }
            for c in controls
        ]


# 全局合规管理器实例
compliance_manager = ComplianceManager()
