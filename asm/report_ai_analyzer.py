"""
报告AI分析增强模块
- 漏洞关联分析（发现漏洞之间的关系）
- 攻击链推理（根据漏洞组合推断攻击路径）
- 业务影响评估（评估对业务的影响）
- 风险优先级动态调整
- MITRE ATT&CK映射
"""

import json
import os
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class AttackPhase(Enum):
    """攻击阶段（杀伤链7阶段）"""
    RECONNAISSANCE = "侦察"
    WEAPONIZATION = "武器化"
    DELIVERY = "投递"
    EXPLOITATION = "利用"
    INSTALLATION = "安装"
    COMMAND_CONTROL = "命令与控制"
    ACTIONS_OBJECTIVES = "目标达成"


class BusinessImpact(Enum):
    """业务影响等级"""
    CRITICAL = "严重"
    HIGH = "高"
    MEDIUM = "中"
    LOW = "低"
    INFO = "信息"


@dataclass
class VulnerabilityNode:
    """漏洞节点（用于关联分析）"""
    vuln_id: str
    name: str
    severity: str
    category: str
    cvss: float = 0.0
    cve_id: Optional[str] = None
    affected_component: Optional[str] = None
    affected_url: Optional[str] = None
    evidence: Optional[str] = None
    description: str = ""
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityRelation:
    """漏洞关系"""
    source_id: str
    target_id: str
    relation_type: str  # same_component, chainable, prerequisite, alternative, escalation
    confidence: float  # 0-1
    description: str = ""


@dataclass
class AttackPath:
    """攻击路径"""
    path_id: str
    name: str
    phases: List[Dict[str, Any]]  # 每个阶段的漏洞和动作
    overall_severity: str
    likelihood: float  # 0-1 可能性
    impact: str  # 业务影响
    description: str = ""
    mitre_chain: List[str] = field(default_factory=list)


@dataclass
class BusinessImpactAssessment:
    """业务影响评估"""
    vuln_id: str
    impact_level: str
    impact_areas: List[str]  # 数据泄露/服务中断/合规风险/财务损失/声誉损害
    affected_assets: List[str]
    potential_damage: str
    compliance_issues: List[str] = field(default_factory=list)
    recovery_time: str = ""
    description: str = ""


class ReportAIAnalyzer:
    """报告AI分析器"""

    def __init__(self, llm_config: Optional[Dict] = None):
        self.llm_config = llm_config or {
            "api_key": os.getenv("LLM_API_KEY", ""),
            "base_url": os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1"),
            "model": os.getenv("LLM_MODEL", "deepseek-chat"),
        }
        self.vulnerabilities: List[VulnerabilityNode] = []
        self.relations: List[VulnerabilityRelation] = []
        self.attack_paths: List[AttackPath] = []
        self.business_impacts: List[BusinessImpactAssessment] = []

    def load_vulnerabilities(self, vuln_data: List[Dict]):
        """加载漏洞数据"""
        self.vulnerabilities = []
        for i, v in enumerate(vuln_data):
            node = VulnerabilityNode(
                vuln_id=v.get("id", f"VULN-{i+1}"),
                name=v.get("name", v.get("template_name", "未知漏洞")),
                severity=v.get("severity", "medium"),
                category=v.get("category", "其他"),
                cvss=v.get("cvss", v.get("risk_score", 0)),
                cve_id=v.get("cve_id"),
                affected_component=v.get("component", v.get("affected_component")),
                affected_url=v.get("url", v.get("affected_url")),
                evidence=v.get("evidence"),
                description=v.get("description", ""),
                tags=v.get("tags", []),
                mitre_techniques=v.get("mitre_techniques", []),
            )
            self.vulnerabilities.append(node)

    def analyze_all(self) -> Dict[str, Any]:
        """执行全部AI分析"""
        # 1. 漏洞关联分析
        self.relations = self._analyze_relations()

        # 2. 攻击链推理
        self.attack_paths = self._infer_attack_paths()

        # 3. 业务影响评估
        self.business_impacts = self._assess_business_impact()

        # 4. 风险优先级动态调整
        risk_prioritization = self._dynamic_risk_prioritization()

        # 5. MITRE ATT&CK映射
        mitre_mapping = self._map_mitre_attack()

        return {
            "vulnerability_count": len(self.vulnerabilities),
            "relations": self._serialize_relations(),
            "attack_paths": self._serialize_attack_paths(),
            "business_impacts": self._serialize_business_impacts(),
            "risk_prioritization": risk_prioritization,
            "mitre_mapping": mitre_mapping,
            "executive_summary": self._generate_executive_summary(),
        }

    def _analyze_relations(self) -> List[VulnerabilityRelation]:
        """漏洞关联分析"""
        relations = []

        for i, v1 in enumerate(self.vulnerabilities):
            for j, v2 in enumerate(self.vulnerabilities):
                if i >= j:
                    continue

                # 1. 同一组件的多个漏洞
                if v1.affected_component and v1.affected_component == v2.affected_component:
                    relations.append(VulnerabilityRelation(
                        source_id=v1.vuln_id,
                        target_id=v2.vuln_id,
                        relation_type="same_component",
                        confidence=0.9,
                        description=f"同一组件 {v1.affected_component} 存在多个漏洞，可能被组合利用",
                    ))

                # 2. 可链式利用（低严重度漏洞是高严重度漏洞的前提）
                severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                if severity_order.get(v1.severity, 0) < severity_order.get(v2.severity, 0):
                    # 信息泄露 + 远程代码执行 = 可链式
                    if v1.category in ["信息泄露", "认证"] and v2.category in ["命令执行", "代码执行", "SQL注入"]:
                        relations.append(VulnerabilityRelation(
                            source_id=v1.vuln_id,
                            target_id=v2.vuln_id,
                            relation_type="chainable",
                            confidence=0.7,
                            description=f"{v1.name} 可用于获取信息，辅助 {v2.name} 的利用",
                        ))

                # 3. 同一URL的多个漏洞
                if v1.affected_url and v1.affected_url == v2.affected_url:
                    relations.append(VulnerabilityRelation(
                        source_id=v1.vuln_id,
                        target_id=v2.vuln_id,
                        relation_type="same_url",
                        confidence=0.85,
                        description=f"同一URL {v1.affected_url} 存在多个漏洞",
                    ))

                # 4. 同类漏洞（可能是同一根因）
                if v1.category == v2.category and v1.vuln_id != v2.vuln_id:
                    relations.append(VulnerabilityRelation(
                        source_id=v1.vuln_id,
                        target_id=v2.vuln_id,
                        relation_type="same_category",
                        confidence=0.6,
                        description=f"同类漏洞 {v1.category}，可能存在相同根因，修复时需统一处理",
                    ))

        return relations

    def _infer_attack_paths(self) -> List[AttackPath]:
        """攻击链推理"""
        paths = []
        path_id = 1

        # 按攻击阶段分类漏洞
        phase_vulns = {
            AttackPhase.RECONNAISSANCE: [],
            AttackPhase.EXPLOITATION: [],
            AttackPhase.COMMAND_CONTROL: [],
            AttackPhase.ACTIONS_OBJECTIVES: [],
        }

        for v in self.vulnerabilities:
            # 侦察阶段：信息泄露、目录遍历、安全头缺失
            if v.category in ["信息泄露", "路径遍历", "安全头", "配置错误"]:
                phase_vulns[AttackPhase.RECONNAISSANCE].append(v)
            # 利用阶段：SQL注入、XSS、命令执行、代码执行、SSRF、XXE、文件上传、反序列化、模板注入
            elif v.category in ["SQL注入", "XSS", "命令执行", "代码执行", "SSRF", "XXE", "文件上传", "反序列化", "模板注入", "原型污染", "文件包含"]:
                phase_vulns[AttackPhase.EXPLOITATION].append(v)
            # 命令与控制：认证绕过、业务逻辑漏洞
            elif v.category in ["认证", "业务逻辑", "CORS"]:
                phase_vulns[AttackPhase.COMMAND_CONTROL].append(v)
            # 目标达成：严重漏洞
            elif v.severity in ["critical", "high"]:
                phase_vulns[AttackPhase.ACTIONS_OBJECTIVES].append(v)

        # 构建攻击路径1：经典Web攻击链
        if phase_vulns[AttackPhase.RECONNAISSANCE] and phase_vulns[AttackPhase.EXPLOITATION]:
            recon_vuln = phase_vulns[AttackPhase.RECONNAISSANCE][0]
            exploit_vulns = phase_vulns[AttackPhase.EXPLOITATION][:3]

            phases = [
                {
                    "phase": AttackPhase.RECONNAISSANCE.value,
                    "vulnerability": recon_vuln.name,
                    "action": f"利用 {recon_vuln.name} 收集目标信息",
                    "severity": recon_vuln.severity,
                },
            ]

            for ev in exploit_vulns:
                phases.append({
                    "phase": AttackPhase.EXPLOITATION.value,
                    "vulnerability": ev.name,
                    "action": f"利用 {ev.name} 执行攻击",
                    "severity": ev.severity,
                })

            if phase_vulns[AttackPhase.ACTIONS_OBJECTIVES]:
                obj_vuln = phase_vulns[AttackPhase.ACTIONS_OBJECTIVES][0]
                phases.append({
                    "phase": AttackPhase.ACTIONS_OBJECTIVES.value,
                    "vulnerability": obj_vuln.name,
                    "action": "达成攻击目标（数据窃取/系统控制）",
                    "severity": obj_vuln.severity,
                })

            overall_severity = "critical" if any(p["severity"] == "critical" for p in phases) else "high"
            likelihood = min(0.3 + len(phases) * 0.15, 0.95)

            paths.append(AttackPath(
                path_id=f"PATH-{path_id}",
                name="经典Web攻击链",
                phases=phases,
                overall_severity=overall_severity,
                likelihood=round(likelihood, 2),
                impact="数据泄露/系统被控",
                description="从信息收集到漏洞利用再到达成目标的完整攻击路径",
                mitre_chain=["T1592", "T1190", "T1059", "T1041"],
            ))
            path_id += 1

        # 构建攻击路径2：认证绕过攻击链
        auth_vulns = [v for v in self.vulnerabilities if v.category == "认证"]
        if auth_vulns:
            phases = [
                {
                    "phase": AttackPhase.RECONNAISSANCE.value,
                    "vulnerability": "登录接口探测",
                    "action": "发现认证机制弱点",
                    "severity": "medium",
                },
            ]
            for av in auth_vulns[:2]:
                phases.append({
                    "phase": AttackPhase.EXPLOITATION.value,
                    "vulnerability": av.name,
                    "action": f"利用 {av.name} 绕过认证",
                    "severity": av.severity,
                })
            phases.append({
                "phase": AttackPhase.ACTIONS_OBJECTIVES.value,
                "vulnerability": "未授权访问",
                "action": "以高权限身份访问敏感功能和数据",
                "severity": "high",
            })

            paths.append(AttackPath(
                path_id=f"PATH-{path_id}",
                name="认证绕过攻击链",
                phases=phases,
                overall_severity="high",
                likelihood=0.6,
                impact="未授权访问/权限提升",
                description="利用认证漏洞绕过身份验证，获取高权限访问",
                mitre_chain=["T1110", "T1078", "T1068"],
            ))
            path_id += 1

        # 构建攻击路径3：文件上传GetShell攻击链
        upload_vulns = [v for v in self.vulnerabilities if v.category == "文件上传"]
        if upload_vulns:
            phases = [
                {
                    "phase": AttackPhase.RECONNAISSANCE.value,
                    "vulnerability": "上传点探测",
                    "action": "发现文件上传功能",
                    "severity": "low",
                },
                {
                    "phase": AttackPhase.EXPLOITATION.value,
                    "vulnerability": upload_vulns[0].name,
                    "action": "上传恶意Webshell",
                    "severity": upload_vulns[0].severity,
                },
                {
                    "phase": AttackPhase.COMMAND_CONTROL.value,
                    "vulnerability": "Webshell控制",
                    "action": "通过Webshell执行系统命令",
                    "severity": "critical",
                },
                {
                    "phase": AttackPhase.ACTIONS_OBJECTIVES.value,
                    "vulnerability": "服务器被控",
                    "action": "完全控制服务器，窃取数据/横向移动",
                    "severity": "critical",
                },
            ]

            paths.append(AttackPath(
                path_id=f"PATH-{path_id}",
                name="文件上传GetShell攻击链",
                phases=phases,
                overall_severity="critical",
                likelihood=0.5,
                impact="服务器完全被控",
                description="通过文件上传漏洞上传Webshell，最终完全控制服务器",
                mitre_chain=["T1190", "T1505", "T1059", "T1048"],
            ))

        return paths

    def _assess_business_impact(self) -> List[BusinessImpactAssessment]:
        """业务影响评估"""
        impacts = []

        for v in self.vulnerabilities:
            impact_areas = []
            potential_damage = ""
            compliance_issues = []
            recovery_time = ""

            # 根据漏洞类型评估影响
            if v.category in ["命令执行", "代码执行", "反序列化", "文件上传"]:
                impact_areas = ["数据泄露", "服务中断", "财务损失", "声誉损害"]
                potential_damage = "攻击者可完全控制服务器，窃取所有数据，植入后门，造成长期安全威胁"
                compliance_issues = ["等保2.0三级", "GDPR", "个人信息保护法"]
                recovery_time = "7-30天"
                impact_level = "critical"

            elif v.category in ["SQL注入", "SSRF", "XXE", "模板注入"]:
                impact_areas = ["数据泄露", "合规风险"]
                potential_damage = "攻击者可读取/篡改数据库数据，获取敏感信息（用户信息/密码/交易记录）"
                compliance_issues = ["等保2.0", "GDPR", "数据安全法"]
                recovery_time = "3-14天"
                impact_level = "high"

            elif v.category in ["XSS", "认证", "业务逻辑", "CORS"]:
                impact_areas = ["账号被盗", "数据泄露", "声誉损害"]
                potential_damage = "攻击者可窃取用户Cookie/会话，冒充用户进行操作，或绕过认证访问敏感功能"
                compliance_issues = ["等保2.0"]
                recovery_time = "1-7天"
                impact_level = "medium"

            elif v.category in ["信息泄露", "路径遍历", "文件包含"]:
                impact_areas = ["信息泄露", "合规风险"]
                potential_damage = "攻击者可获取系统配置/源代码/敏感文件，为进一步攻击提供信息"
                compliance_issues = ["等保2.0"]
                recovery_time = "1-3天"
                impact_level = "medium"

            elif v.category in ["安全头", "点击劫持", "重定向", "配置错误"]:
                impact_areas = ["用户体验", "安全加固"]
                potential_damage = "降低攻击门槛，可能被用于辅助其他攻击"
                compliance_issues = []
                recovery_time = "1天内"
                impact_level = "low"

            else:
                impact_areas = ["安全加固"]
                potential_damage = "潜在安全风险"
                recovery_time = "1天内"
                impact_level = "info"

            # 严重程度调整
            severity_multiplier = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4, "info": 0.2}
            if v.severity == "critical" and impact_level != "critical":
                impact_level = "high"

            impacts.append(BusinessImpactAssessment(
                vuln_id=v.vuln_id,
                impact_level=impact_level,
                impact_areas=impact_areas,
                affected_assets=[v.affected_url or v.affected_component or "未知资产"],
                potential_damage=potential_damage,
                compliance_issues=compliance_issues,
                recovery_time=recovery_time,
                description=f"{v.name} 的业务影响评估",
            ))

        return impacts

    def _dynamic_risk_prioritization(self) -> Dict[str, Any]:
        """风险优先级动态调整（基于关联分析和攻击链）"""
        # 基础风险分
        base_scores = {}
        for v in self.vulnerabilities:
            severity_scores = {"critical": 90, "high": 70, "medium": 50, "low": 30, "info": 10}
            base_scores[v.vuln_id] = severity_scores.get(v.severity, 30)

        # 调整因子
        adjustments = {v.vuln_id: 0 for v in self.vulnerabilities}

        # 1. 出现在攻击链中的漏洞加分
        for path in self.attack_paths:
            for phase in path.phases:
                vuln_name = phase.get("vulnerability", "")
                for v in self.vulnerabilities:
                    if v.name == vuln_name:
                        adjustments[v.vuln_id] += 10 * path.likelihood

        # 2. 与其他漏洞有关联的加分
        for rel in self.relations:
            if rel.relation_type in ["chainable", "same_component"]:
                adjustments[rel.source_id] += 5 * rel.confidence
                adjustments[rel.target_id] += 5 * rel.confidence

        # 3. 业务影响严重的加分
        for bi in self.business_impacts:
            if bi.impact_level == "critical":
                adjustments[bi.vuln_id] += 15
            elif bi.impact_level == "high":
                adjustments[bi.vuln_id] += 10

        # 计算最终风险分
        final_scores = {}
        for v in self.vulnerabilities:
            score = min(base_scores[v.vuln_id] + adjustments[v.vuln_id], 100)
            final_scores[v.vuln_id] = {
                "name": v.name,
                "base_score": base_scores[v.vuln_id],
                "adjustment": round(adjustments[v.vuln_id], 1),
                "final_score": round(score, 1),
                "severity": v.severity,
                "category": v.category,
            }

        # 排序和分级
        sorted_vulns = sorted(final_scores.items(), key=lambda x: -x[1]["final_score"])

        priorities = {"P0": [], "P1": [], "P2": [], "P3": []}
        for vuln_id, info in sorted_vulns:
            if info["final_score"] >= 80:
                priorities["P0"].append({"id": vuln_id, **info})
            elif info["final_score"] >= 60:
                priorities["P1"].append({"id": vuln_id, **info})
            elif info["final_score"] >= 40:
                priorities["P2"].append({"id": vuln_id, **info})
            else:
                priorities["P3"].append({"id": vuln_id, **info})

        return {
            "method": "动态风险优先级（基础分+攻击链加权+关联加权+业务影响加权）",
            "total_vulnerabilities": len(self.vulnerabilities),
            "priorities": {k: len(v) for k, v in priorities.items()},
            "top_10": [{"id": vid, **info} for vid, info in sorted_vulns[:10]],
            "all_priorities": priorities,
        }

    def _map_mitre_attack(self) -> Dict[str, Any]:
        """MITRE ATT&CK映射"""
        # 漏洞类别到MITRE技术的映射
        category_to_mitre = {
            "SQL注入": ["T1190", "T1505"],
            "XSS": ["T1059", "T1189"],
            "命令执行": ["T1059", "T1190"],
            "代码执行": ["T1059", "T1203"],
            "路径遍历": ["T1083", "T1552"],
            "文件包含": ["T1210", "T1505"],
            "SSRF": ["T1190", "T1090"],
            "XXE": ["T1190", "T1552"],
            "文件上传": ["T1190", "T1505"],
            "认证": ["T1110", "T1078", "T1550"],
            "业务逻辑": ["T1078", "T1110"],
            "信息泄露": ["T1592", "T1552", "T1083"],
            "反序列化": ["T1190", "T1203"],
            "模板注入": ["T1190", "T1059"],
            "原型污染": ["T1059", "T1203"],
            "CORS": ["T1110", "T1550"],
            "点击劫持": ["T1059", "T1189"],
            "安全头": ["T1027"],
            "重定向": ["T1204", "T1189"],
            "配置错误": ["T1592", "T1552"],
        }

        mitre_techniques = {}
        for v in self.vulnerabilities:
            techniques = category_to_mitre.get(v.category, ["T1190"])
            for tech in techniques:
                if tech not in mitre_techniques:
                    mitre_techniques[tech] = []
                mitre_techniques[tech].append(v.name)

        # MITRE战术映射
        tactic_mapping = {
            "侦察 (Reconnaissance)": ["T1592", "T1595"],
            "初始访问 (Initial Access)": ["T1190", "T1189", "T1204"],
            "执行 (Execution)": ["T1059", "T1203"],
            "持久化 (Persistence)": ["T1505", "T1136"],
            "权限提升 (Privilege Escalation)": ["T1068", "T1078"],
            "防御绕过 (Defense Evasion)": ["T1027", "T1550"],
            "凭据访问 (Credential Access)": ["T1110", "T1552"],
            "发现 (Discovery)": ["T1083", "T1046"],
            "横向移动 (Lateral Movement)": ["T1210", "T1090"],
            "数据窃取 (Exfiltration)": ["T1041", "T1048"],
            "影响 (Impact)": ["T1485", "T1486"],
        }

        detected_tactics = {}
        for tactic, techniques in tactic_mapping.items():
            detected = [t for t in techniques if t in mitre_techniques]
            if detected:
                detected_tactics[tactic] = {
                    "techniques": detected,
                    "vulnerabilities": list(set(
                        v for t in detected for v in mitre_techniques.get(t, [])
                    )),
                }

        return {
            "detected_techniques": mitre_techniques,
            "detected_tactics": detected_tactics,
            "total_techniques": len(mitre_techniques),
            "total_tactics": len(detected_tactics),
            "attack_coverage": f"覆盖 {len(detected_tactics)}/11 个MITRE战术",
        }

    def _generate_executive_summary(self) -> Dict[str, Any]:
        """生成执行摘要"""
        critical_count = sum(1 for v in self.vulnerabilities if v.severity == "critical")
        high_count = sum(1 for v in self.vulnerabilities if v.severity == "high")
        medium_count = sum(1 for v in self.vulnerabilities if v.severity == "medium")
        low_count = sum(1 for v in self.vulnerabilities if v.severity in ["low", "info"])

        overall_risk = "严重" if critical_count > 0 else "高" if high_count > 2 else "中" if medium_count > 0 else "低"

        # 最危险的攻击路径
        most_dangerous_path = None
        if self.attack_paths:
            most_dangerous_path = max(self.attack_paths, key=lambda p: p.likelihood)

        return {
            "overall_risk": overall_risk,
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_distribution": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
            },
            "attack_paths_found": len(self.attack_paths),
            "most_dangerous_attack_path": most_dangerous_path.name if most_dangerous_path else "无",
            "business_impact": "存在数据泄露和系统被控风险" if critical_count + high_count > 0 else "风险可控",
            "key_recommendations": [
                "立即修复所有Critical和High级别漏洞",
                "优先修复攻击链中的关键节点漏洞",
                "加强认证和访问控制",
                "建立持续监控和漏洞管理流程",
            ],
        }

    def _serialize_relations(self) -> List[Dict]:
        return [
            {
                "source": r.source_id,
                "target": r.target_id,
                "type": r.relation_type,
                "confidence": r.confidence,
                "description": r.description,
            }
            for r in self.relations
        ]

    def _serialize_attack_paths(self) -> List[Dict]:
        return [
            {
                "path_id": p.path_id,
                "name": p.name,
                "phases": p.phases,
                "overall_severity": p.overall_severity,
                "likelihood": p.likelihood,
                "impact": p.impact,
                "description": p.description,
                "mitre_chain": p.mitre_chain,
            }
            for p in self.attack_paths
        ]

    def _serialize_business_impacts(self) -> List[Dict]:
        return [
            {
                "vuln_id": bi.vuln_id,
                "impact_level": bi.impact_level,
                "impact_areas": bi.impact_areas,
                "affected_assets": bi.affected_assets,
                "potential_damage": bi.potential_damage,
                "compliance_issues": bi.compliance_issues,
                "recovery_time": bi.recovery_time,
            }
            for bi in self.business_impacts
        ]
