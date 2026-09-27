# -*- coding: utf-8 -*-
"""
regional_compliance.py — 区域合规管理（第25轮升级方向4 / 模块2）。

包含：
  - 合规框架库：GDPR/CCPA/个保法/数安法/网安法/APPI日本/LGPD巴西/PIPEDA加拿大/澳大利亚隐私法/新加坡PDPA（10+）
  - 合规要求映射：区域→框架→控制项→要求→证据→责任人/多区域矩阵/差距分析
  - 跨境数据管理：跨境传输评估/数据本地化/存储位置/处理位置/传输机制/SCC/BCR
  - 区域隐私权利：数据主体权利/请求处理/响应时间/验证/记录/报告
  - 区域合规报告：合规状态/覆盖率/违规项/整改建议/跟踪/评分/趋势
  - 区域合规监控：法规变更监控/要求更新/差距预警/事件监控/审计/证据管理

全部内存字典模拟，不建数据库表。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ==================== 合规框架库 ====================

COMPLIANCE_FRAMEWORKS: Dict[str, Dict[str, Any]] = {
    "GDPR": {
        "name": "通用数据保护条例", "region": "欧盟/欧洲经济区", "enforcement_date": "2018-05-25",
        "authority": "欧洲数据保护委员会(EDPB)", "max_fine": "全球年营业额4%或2000万欧元",
        "key_articles": ["Art.5 数据处理原则", "Art.6 合法性基础", "Art.7 同意条件", "Art.13 透明告知", "Art.15 访问权", "Art.17 被遗忘权", "Art.28 处理者义务", "Art.35 DPIA", "Art.44-49 数据跨境", "Art.77 投诉权"],
        "rights": ["访问权", "更正权", "删除权(被遗忘权)", "限制处理权", "数据可携权", "反对权", "不受自动化决策权"],
    },
    "CCPA": {
        "name": "加州消费者隐私法", "region": "美国加州", "enforcement_date": "2020-01-01",
        "authority": "加州总检察长办公室", "max_fine": "每违规$2,500 / 故意$7,500",
        "key_articles": ["Sec.1798.100 收集通知", "Sec.1798.105 删除权", "Sec.1798.110 更正权", "Sec.1798.115 数据可携权", "Sec.1798.120 选择退出", "Sec.1798.130 响应义务", "Sec.1798.140 非歧视"],
        "rights": ["知情权", "删除权", "更正权", "数据可携权", "选择出售退出权", "非歧视权"],
    },
    "PIPL": {
        "name": "个人信息保护法", "region": "中国", "enforcement_date": "2021-11-01",
        "authority": "国家网信办", "max_fine": "5000万元或年营业额5%",
        "key_articles": ["第13条 处理基础", "第14条 同意", "第17条 告知义务", "第44条 个人权利", "第55条 个人信息保护影响评估", "第38-43条 跨境提供", "第66条 法律责任"],
        "rights": ["知情权", "决定权", "查阅复制权", "可携带权", "更正补充权", "删除权", "解释说明权"],
    },
    "CSL": {
        "name": "网络安全法", "region": "中国", "enforcement_date": "2017-06-01",
        "authority": "国家网信办/公安部", "max_fine": "100万元",
        "key_articles": ["第21条 网络安全等级保护", "第22条 产品服务安全", "第37条 数据本地化", "第41-43条 个人信息保护", "第59-64条 法律责任"],
        "rights": ["个人信息知情权", "删除权", "更正权"],
    },
    "DSL": {
        "name": "数据安全法", "region": "中国", "enforcement_date": "2021-09-01",
        "authority": "国家网信办", "max_fine": "1000万元",
        "key_articles": ["第21条 数据分类分级", "第27条 全流程安全管理", "第30条 风险评估", "第31条 重要数据出境", "第45-52条 法律责任"],
        "rights": ["数据安全知情权", "投诉举报权"],
    },
    "APPI": {
        "name": "个人信息保护法(日本)", "region": "日本", "enforcement_date": "2003-05-01",
        "authority": "个人信息保护委员会(PPC)", "max_fine": "1亿日元",
        "key_articles": ["第15条 利用目的特定", "第16条 取得限制", "第18条 利用目的通知", "第24条 开示请求", "第25条 订正请求", "第27条 利用停止", "第28条 第三方提供限制"],
        "rights": ["开示请求权", "订正请求权", "利用停止请求权", "第三方提供停止请求权"],
    },
    "LGPD": {
        "name": "通用数据保护法(巴西)", "region": "巴西", "enforcement_date": "2020-09-18",
        "authority": "国家数据保护局(ANPD)", "max_fine": "营业额2%上限5000万雷亚尔",
        "key_articles": ["Art.7 处理基础", "Art.9 知情权", "Art.18 数据主体权利", "Art.33 国际传输", "Art.48 事故通知", "Art.52 制裁"],
        "rights": ["确认存在权", "访问权", "更正权", "匿名化/删除权", "数据可携权", "撤销同意权"],
    },
    "PIPEDA": {
        "name": "个人信息保护与电子文档法(加拿大)", "region": "加拿大", "enforcement_date": "2001-04-13",
        "authority": "加拿大隐私专员办公室(OPC)", "max_fine": "1000万加元",
        "key_articles": ["Sch.1原则1 问责制", "原则2 同意", "原则3 限制收集", "原则4 限制使用", "原则5 准确性", "原则6 保障措施", "原则8 公开透明", "原则9 个人访问权", "原则10 挑战合规权"],
        "rights": ["访问权", "更正权", "投诉权"],
    },
    "AU_PRIVACY": {
        "name": "1988年隐私法(澳大利亚)", "region": "澳大利亚", "enforcement_date": "1988-01-01",
        "authority": "澳大利亚信息专员办公室(OAIC)", "max_fine": "222万澳元",
        "key_articles": ["APP1 开放管理", "APP3 收集", "APP5 通知", "APP6 使用披露", "APP8 跨境披露", "APP11 安全", "APP12 访问", "APP13 更正"],
        "rights": ["访问权", "更正权", "隐私投诉权"],
    },
    "PDPA": {
        "name": "个人数据保护法(新加坡)", "region": "新加坡", "enforcement_date": "2012-10-15",
        "authority": "新加坡个人数据保护委员会(PDPC)", "max_fine": "100万新元",
        "key_articles": ["第13条 同意", "第16条 告知", "第18条 目的限制", "第22条 准确性", "第24条 保护", "第26条 保留限制", "第26D条 跨境转移", "第32条 访问与更正"],
        "rights": ["访问权", "更正权", "撤回同意权"],
    },
    "POPIA": {
        "name": "个人信息保护法(南非)", "region": "南非", "enforcement_date": "2020-07-01",
        "authority": "信息监管机构(Information Regulator)", "max_fine": "1000万兰特",
        "key_articles": ["s10 责任方", "s11 合法性条件", "s14 目的具体化", "s18 同意", "s23 告知", "s26 跨境转移", "s35 访问", "s36 更正"],
        "rights": ["知情权", "访问权", "更正权", "反对处理权"],
    },
}


# ==================== 区域→合规框架映射 ====================

REGION_FRAMEWORK_MAP: Dict[str, Dict[str, Any]] = {
    "CN": {"region_name": "中国", "frameworks": ["PIPL", "CSL", "DSL"], "data_localization": True, "cross_border_mechanism": "安全评估/标准合同/认证", "language": "zh-CN", "timezone": "Asia/Shanghai"},
    "US-CA": {"region_name": "美国加州", "frameworks": ["CCPA"], "data_localization": False, "cross_border_mechanism": "SCC/BCR/充分性认定", "language": "en", "timezone": "America/Los_Angeles"},
    "US-NY": {"region_name": "美国纽约", "frameworks": ["SHIELD_ACT"], "data_localization": False, "cross_border_mechanism": "SCC/BCR", "language": "en", "timezone": "America/New_York"},
    "EU": {"region_name": "欧盟", "frameworks": ["GDPR"], "data_localization": False, "cross_border_mechanism": "SCC/BCR/充分性决定", "language": "en", "timezone": "Europe/Brussels"},
    "JP": {"region_name": "日本", "frameworks": ["APPI"], "data_localization": False, "cross_border_mechanism": "事前同意/充分性/标准合同", "language": "ja", "timezone": "Asia/Tokyo"},
    "KR": {"region_name": "韩国", "frameworks": ["PIPA"], "data_localization": False, "cross_border_mechanism": "同意/标准合同/认证", "language": "ko", "timezone": "Asia/Seoul"},
    "BR": {"region_name": "巴西", "frameworks": ["LGPD"], "data_localization": False, "cross_border_mechanism": "标准合同/BCR/充分性", "language": "pt", "timezone": "America/Sao_Paulo"},
    "CA": {"region_name": "加拿大", "frameworks": ["PIPEDA"], "data_localization": False, "cross_border_mechanism": "同意/合同约束", "language": "en", "timezone": "America/Toronto"},
    "AU": {"region_name": "澳大利亚", "frameworks": ["AU_PRIVACY"], "data_localization": False, "cross_border_mechanism": "有约束力合同/同意", "language": "en", "timezone": "Australia/Sydney"},
    "SG": {"region_name": "新加坡", "frameworks": ["PDPA"], "data_localization": False, "cross_border_mechanism": "同意/可执行合同/保障措施", "language": "en", "timezone": "Asia/Singapore"},
    "ZA": {"region_name": "南非", "frameworks": ["POPIA"], "data_localization": False, "cross_border_mechanism": "同意/合同/充分性", "language": "en", "timezone": "Africa/Johannesburg"},
    "AE": {"region_name": "阿联酋", "frameworks": ["UAE_DATA_PROTECTION"], "data_localization": False, "cross_border_mechanism": "同意/监管批准", "language": "ar", "timezone": "Asia/Dubai"},
}


# ==================== 控制项与要求 ====================

@dataclass
class ControlItem:
    control_id: str
    framework: str
    requirement: str
    description: str
    status: str = "not_started"  # not_started / in_progress / implemented / gap
    evidence: List[str] = field(default_factory=list)
    owner: str = ""
    last_audited: str = ""


class ComplianceMatrix:
    """多区域合规矩阵"""

    def __init__(self):
        self.controls: Dict[str, ControlItem] = {}
        self._seed()

    def _seed(self):
        seed_defs = [
            ("CTRL-001", "GDPR", "Art.5(1)(a) 合法公平透明", "处理个人数据须有合法基础且对数据主体公平透明", "implemented", "DPO@example.com"),
            ("CTRL-002", "GDPR", "Art.7 同意条件", "取得数据主体有效同意并可证明", "implemented", "DPO@example.com"),
            ("CTRL-003", "GDPR", "Art.13 透明告知", "收集时向数据主体提供完整隐私通知", "in_progress", "DPO@example.com"),
            ("CTRL-004", "GDPR", "Art.35 DPIA", "高风险处理前完成数据保护影响评估", "gap", "DPO@example.com"),
            ("CTRL-005", "GDPR", "Art.44 数据跨境", "仅在适当保障措施下跨境传输", "gap", "DPO@example.com"),
            ("CTRL-006", "CCPA", "Sec.1798.100 收集通知", "告知消费者收集的个人信息类别和目的", "implemented", "Privacy@ca.com"),
            ("CTRL-007", "CCPA", "Sec.1798.120 选择退出", "提供Do Not Sell链接和退出机制", "in_progress", "Privacy@ca.com"),
            ("CTRL-008", "PIPL", "第13条 处理基础", "处理个人信息须有合法基础并取得同意", "implemented", "DPO@cn.com"),
            ("CTRL-009", "PIPL", "第38条 跨境提供", "向境外提供个人信息须满足法定条件", "in_progress", "DPO@cn.com"),
            ("CTRL-010", "PIPL", "第55条 影响评估", "定期开展个人信息保护影响评估", "gap", "DPO@cn.com"),
            ("CTRL-011", "CSL", "第21条 等保", "落实网络安全等级保护制度", "implemented", "Sec@cn.com"),
            ("CTRL-012", "CSL", "第37条 数据本地化", "关键信息基础设施运营者数据境内存储", "implemented", "Sec@cn.com"),
            ("CTRL-013", "APPI", "第24条 开示请求", "响应数据主体开示请求", "in_progress", "DPO@jp.com"),
            ("CTRL-014", "LGPD", "Art.18 数据主体权利", "保障数据主体全部法定权利", "gap", "DPO@br.com"),
            ("CTRL-015", "PIPEDA", "Sch.1原则1 问责制", "指定个人信息保护负责人", "implemented", "Privacy@ca.com"),
            ("CTRL-016", "AU_PRIVACY", "APP11 安全", "保护个人信息安全防止丢失泄露", "implemented", "Privacy@au.com"),
            ("CTRL-017", "PDPA", "第13条 同意", "取得数据主体同意方可收集使用", "in_progress", "Privacy@sg.com"),
        ]
        for cid, fw, req, desc, status, owner in seed_defs:
            self.controls[cid] = ControlItem(
                control_id=cid, framework=fw, requirement=req, description=desc,
                status=status, owner=owner,
                evidence=[f"证据文档_{cid}.pdf"] if status == "implemented" else [],
                last_audited=datetime.now().strftime("%Y-%m-%d") if status == "implemented" else "",
            )

    def gap_analysis(self) -> Dict[str, Any]:
        gaps = [c for c in self.controls.values() if c.status == "gap"]
        implemented = sum(1 for c in self.controls.values() if c.status == "implemented")
        in_progress = sum(1 for c in self.controls.values() if c.status == "in_progress")
        total = len(self.controls)
        by_framework: Dict[str, Dict[str, int]] = {}
        for c in self.controls.values():
            if c.framework not in by_framework:
                by_framework[c.framework] = {"total": 0, "implemented": 0, "gap": 0, "in_progress": 0}
            by_framework[c.framework]["total"] += 1
            by_framework[c.framework][c.status] += 1
        return {
            "total_controls": total,
            "implemented": implemented, "in_progress": in_progress, "gaps": len(gaps),
            "coverage_rate": round(implemented / total * 100, 1) if total else 0,
            "gap_details": [{"control_id": c.control_id, "framework": c.framework, "requirement": c.requirement, "owner": c.owner} for c in gaps],
            "by_framework": by_framework,
        }

    def update_control(self, control_id: str, status: str = "", evidence: str = "", owner: str = "") -> Dict[str, Any]:
        c = self.controls.get(control_id)
        if not c:
            return {"error": "控制项不存在"}
        if status:
            c.status = status
        if evidence:
            c.evidence.append(evidence)
        if owner:
            c.owner = owner
        c.last_audited = datetime.now().strftime("%Y-%m-%d")
        return {"control_id": control_id, "status": c.status, "evidence_count": len(c.evidence)}


# ==================== 跨境数据管理 ====================

class CrossBorderData:
    """跨境数据传输管理"""

    def __init__(self):
        self.transfers: Dict[str, Dict[str, Any]] = {}
        self.localization: Dict[str, bool] = {r: m["data_localization"] for r, m in REGION_FRAMEWORK_MAP.items()}
        self._seed()

    def _seed(self):
        seeds = [
            ("TF-001", "CN", "EU", "个人用户数据", "标准合同条款(SCC)", "已批准", "2026-01-15"),
            ("TF-002", "EU", "US", "分析数据", "BCR约束性公司规则", "审批中", "2026-03-20"),
            ("TF-003", "CN", "SG", "运维日志", "安全评估", "已批准", "2026-02-10"),
            ("TF-004", "JP", "US", "客户数据", "事前同意", "已批准", "2026-01-05"),
            ("TF-005", "BR", "EU", "支付数据", "标准合同", "待审批", "2026-04-01"),
        ]
        for tid, src, dst, dtype, mechanism, status, date in seeds:
            self.transfers[tid] = {"transfer_id": tid, "source_region": src, "dest_region": dst, "data_type": dtype, "mechanism": mechanism, "status": status, "approval_date": date, "encrypted": True, "has_dpia": True}

    def assess(self, source_region: str, dest_region: str, data_type: str, volume_gb: float) -> Dict[str, Any]:
        """跨境传输评估"""
        src_info = REGION_FRAMEWORK_MAP.get(source_region, {})
        dst_info = REGION_FRAMEWORK_MAP.get(dest_region, {})
        risks = []
        if src_info.get("data_localization") and not dst_info.get("data_localization"):
            risks.append({"level": "high", "issue": "源区域要求数据本地化但目标区域无此要求"})
        if "sensitive" in data_type.lower():
            risks.append({"level": "high", "issue": "敏感数据跨境需额外评估"})
        if volume_gb > 100:
            risks.append({"level": "medium", "issue": "数据量大，建议加密传输"})
        # 推荐机制
        mechanism = src_info.get("cross_border_mechanism", "标准合同")
        risk_level = "high" if any(r["level"] == "high" for r in risks) else "medium" if risks else "low"
        return {
            "assessment_id": f"TA-{uuid.uuid4().hex[:8]}",
            "source": source_region, "destination": dest_region, "data_type": data_type,
            "volume_gb": volume_gb, "recommended_mechanism": mechanism,
            "risk_level": risk_level, "risks": risks,
            "requires_dpia": risk_level in ("high", "medium"),
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        }

    def list_transfers(self) -> List[Dict[str, Any]]:
        return list(self.transfers.values())


# ==================== 区域隐私权利 ====================

class RegionalRights:
    """区域数据主体权利管理"""

    def __init__(self):
        self.requests: Dict[str, Dict[str, Any]] = {}
        self._seed()

    def _seed(self):
        rights_types = ["access", "rectification", "erasure", "portability", "restriction", "objection"]
        statuses = ["received", "verified", "processing", "completed", "rejected"]
        for i in range(15):
            rid = f"RQ-{uuid.uuid4().hex[:8]}"
            self.requests[rid] = {
                "request_id": rid, "data_subject": f"user_{i:03d}@example.com",
                "right_type": rights_types[i % len(rights_types)],
                "region": list(REGION_FRAMEWORK_MAP.keys())[i % len(REGION_FRAMEWORK_MAP)],
                "status": statuses[i % len(statuses)],
                "received_at": datetime.now().isoformat(timespec="seconds"),
                "deadline_days": 30, "verification_status": "verified" if i % 3 != 0 else "pending",
            }

    def submit(self, data_subject: str, right_type: str, region: str, details: str = "") -> Dict[str, Any]:
        rid = f"RQ-{uuid.uuid4().hex[:8]}"
        self.requests[rid] = {
            "request_id": rid, "data_subject": data_subject, "right_type": right_type,
            "region": region, "status": "received", "details": details,
            "received_at": datetime.now().isoformat(timespec="seconds"), "deadline_days": 30,
            "verification_status": "pending",
        }
        return {"request_id": rid, "status": "received", "deadline_days": 30}

    def process(self, request_id: str, action: str, handler: str = "") -> Dict[str, Any]:
        req = self.requests.get(request_id)
        if not req:
            return {"error": "请求不存在"}
        if action == "verify":
            req["verification_status"] = "verified"
            req["status"] = "processing"
        elif action == "complete":
            req["status"] = "completed"
            req["completed_at"] = datetime.now().isoformat(timespec="seconds")
        elif action == "reject":
            req["status"] = "rejected"
        req["handler"] = handler
        return {"request_id": request_id, "status": req["status"]}

    def stats(self) -> Dict[str, Any]:
        total = len(self.requests)
        completed = sum(1 for r in self.requests.values() if r["status"] == "completed")
        processing = sum(1 for r in self.requests.values() if r["status"] in ("processing", "received", "verified"))
        avg_response = round(sum(30 for _ in self.requests) / max(total, 1), 1)
        by_right: Dict[str, int] = {}
        for r in self.requests.values():
            by_right[r["right_type"]] = by_right.get(r["right_type"], 0) + 1
        return {"total": total, "completed": completed, "processing": processing,
                "completion_rate": round(completed / total * 100, 1) if total else 0,
                "avg_response_days": avg_response, "by_right_type": by_right}


# ==================== 合规报告与监控 ====================

class ComplianceReport:
    """区域合规报告与监控"""

    def __init__(self):
        self.audit_logs: List[Dict[str, Any]] = []
        self.regulation_changes: List[Dict[str, Any]] = []
        self._seed()

    def _seed(self):
        self.regulation_changes = [
            {"id": "REG-001", "framework": "GDPR", "change": "EDPB更新数据跨境传输指南", "date": "2026-03-15", "impact": "high", "action_required": "review"},
            {"id": "REG-002", "framework": "PIPL", "change": "个人信息出境标准合同备案指南更新", "date": "2026-02-20", "impact": "high", "action_required": "update_scc"},
            {"id": "REG-003", "framework": "CCPA", "change": "CPRA修正案生效", "date": "2026-01-01", "impact": "medium", "action_required": "update_notice"},
            {"id": "REG-004", "framework": "PDPA", "change": "新加坡PDPC发布数据泄露指南修订", "date": "2026-04-10", "impact": "medium", "action_required": "update_breach_procedure"},
        ]
        self.audit_logs = [
            {"id": "AUD-001", "framework": "GDPR", "date": "2026-03-01", "auditor": "外部审计机构A", "result": "pass", "findings": 2, "open_issues": 0},
            {"id": "AUD-002", "framework": "PIPL", "date": "2026-02-15", "auditor": "内部审计", "result": "conditional_pass", "findings": 5, "open_issues": 2},
            {"id": "AUD-003", "framework": "CCPA", "date": "2026-01-20", "auditor": "外部审计机构B", "result": "pass", "findings": 1, "open_issues": 0},
        ]

    def status_report(self, matrix: ComplianceMatrix) -> Dict[str, Any]:
        ga = matrix.gap_analysis()
        return {
            "report_date": datetime.now().isoformat(timespec="seconds"),
            "overall_score": round(ga["coverage_rate"], 1),
            "total_frameworks": len(COMPLIANCE_FRAMEWORKS),
            "total_regions": len(REGION_FRAMEWORK_MAP),
            "controls_summary": ga,
            "open_regulation_changes": len([c for c in self.regulation_changes if c["action_required"] != "reviewed"]),
            "recent_audits": self.audit_logs,
            "trend": [{"month": "2026-01", "score": 65}, {"month": "2026-02", "score": 70}, {"month": "2026-03", "score": 78}, {"month": "2026-04", "score": ga["coverage_rate"]}],
        }

    def alert_gap(self, control_id: str, severity: str = "high") -> Dict[str, Any]:
        return {"alert_id": f"AL-{uuid.uuid4().hex[:8]}", "control_id": control_id, "severity": severity,
                "message": f"控制项 {control_id} 存在合规差距", "timestamp": datetime.now().isoformat(timespec="seconds")}


# ==================== 主管理器 ====================

class RegionalComplianceManager:
    """区域合规管理主类"""

    def __init__(self):
        self.matrix = ComplianceMatrix()
        self.cross_border = CrossBorderData()
        self.rights = RegionalRights()
        self.report = ComplianceReport()

    def overview(self) -> Dict[str, Any]:
        return {
            "total_frameworks": len(COMPLIANCE_FRAMEWORKS),
            "total_regions": len(REGION_FRAMEWORK_MAP),
            "framework_list": [{"code": k, "name": v["name"], "region": v["region"], "enforcement_date": v["enforcement_date"]} for k, v in COMPLIANCE_FRAMEWORKS.items()],
            "region_list": [{"code": k, **v} for k, v in REGION_FRAMEWORK_MAP.items()],
            "total_controls": len(self.matrix.controls),
            "cross_border_transfers": len(self.cross_border.transfers),
            "privacy_requests": len(self.rights.requests),
            "regulation_changes": len(self.report.regulation_changes),
            "gap_analysis": self.matrix.gap_analysis(),
        }


# 全局单例
regional_compliance = RegionalComplianceManager()
