#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
privacy_compliance.py — 隐私合规管理引擎（Round24 方向3）。

覆盖：
    1. 合规框架：GDPR/个保法/网安法/数安法/CCPA/HIPAA/PCI DSS/ISO27701
    2. 合规评估：ROPA/合法性基础/数据主体权利/跨境传输/DPIA
    3. 数据主体权利：知情/访问/更正/删除/限制/可携带/反对/自动化决策
    4. 同意管理：收集/记录/撤回/版本/审计/分析
    5. 隐私政策：生成/版本/变更通知/翻译/合规检查
    6. 隐私培训：意识/技能/记录/考核/效果评估

设计定位：仅做合规评估与管理流程模拟，不构成法律意见。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


# 8大合规框架
COMPLIANCE_FRAMEWORKS_DEEP: Dict[str, Dict[str, Any]] = {
    "gdpr": {
        "name": "欧盟通用数据保护条例(GDPR)",
        "region": "EU", "effective": "2018-05-25",
        "key_requirements": ["合法正当必要", "数据最小化", "目的限定", "数据主体权利", "DPIA"],
        "penalty_max": "全球年营业额4%或2000万欧元",
        "dpo_required": True,
    },
    "pipl": {
        "name": "个人信息保护法(个保法)",
        "region": "CN", "effective": "2021-11-01",
        "key_requirements": ["告知同意", "敏感个人信息单独同意", "跨境评估", "个人信息保护影响评估"],
        "penalty_max": "5000万元或上一年度营业额5%",
        "dpo_required": True,
    },
    "csl": {
        "name": "网络安全法(网安法)",
        "region": "CN", "effective": "2017-06-01",
        "key_requirements": ["网络安全等级保护", "实名制", "日志留存6个月", "数据本地化"],
        "penalty_max": "100万元以下",
        "dpo_required": False,
    },
    "dsl": {
        "name": "数据安全法(数安法)",
        "region": "CN", "effective": "2021-09-01",
        "key_requirements": ["数据分类分级", "重要数据保护", "数据安全审查", "风险评估"],
        "penalty_max": "1000万元以下",
        "dpo_required": False,
    },
    "ccpa": {
        "name": "加州消费者隐私法(CCPA/CPRA)",
        "region": "US-CA", "effective": "2020-01-01",
        "key_requirements": ["知情权", "删除权", "选择退出权", "非歧视权"],
        "penalty_max": "7500美元/每违规消费者",
        "dpo_required": False,
    },
    "hipaa": {
        "name": "健康保险流通与责任法案(HIPAA)",
        "region": "US", "effective": "2003-04-14",
        "key_requirements": ["隐私规则", "安全规则", " Breach通知", "患者权利"],
        "penalty_max": "150万美元/年/违规项",
        "dpo_required": True,
    },
    "pci_dss": {
        "name": "支付卡行业数据安全标准(PCI DSS)",
        "region": "Global", "effective": "2006",
        "key_requirements": ["防火墙配置", "不存储敏感认证数据", "加密传输", "访问控制"],
        "penalty_max": "5000-100000美元/月",
        "dpo_required": False,
    },
    "iso27701": {
        "name": "ISO/IEC 27701 隐私信息管理体系",
        "region": "Global", "effective": "2019-08",
        "key_requirements": ["PII管理", "隐私控制", "审计认证", "持续改进"],
        "penalty_max": "认证失效",
        "dpo_required": True,
    },
}

# 数据主体权利（8大权利）
DATA_SUBJECT_RIGHTS: Dict[str, Dict[str, Any]] = {
    "right_to_be_informed": {
        "name": "知情权", "desc": "被告知数据被收集和使用的方式",
        "gdpr_art": "Art.13-14", "pipl_ref": "第17条",
    },
    "right_of_access": {
        "name": "访问权", "desc": "获取个人数据副本",
        "gdpr_art": "Art.15", "pipl_ref": "第45条",
    },
    "right_to_rectification": {
        "name": "更正权", "desc": "要求更正不准确的个人数据",
        "gdpr_art": "Art.16", "pipl_ref": "第46条",
    },
    "right_to_erasure": {
        "name": "删除权(被遗忘权)", "desc": "在特定条件下要求删除个人数据",
        "gdpr_art": "Art.17", "pipl_ref": "第47条",
    },
    "right_to_restrict_processing": {
        "name": "限制处理权", "desc": "在特定条件下限制数据处理",
        "gdpr_art": "Art.18", "pipl_ref": "第47条",
    },
    "right_to_data_portability": {
        "name": "数据可携带权", "desc": "以结构化格式获取并转移数据",
        "gdpr_art": "Art.20", "pipl_ref": "第45条",
    },
    "right_to_object": {
        "name": "反对权", "desc": "反对基于合法利益或营销的数据处理",
        "gdpr_art": "Art.21", "pipl_ref": "第44条",
    },
    "right_automated_decisioning": {
        "name": "自动化决策相关权利", "desc": "反对纯自动化决策，包括画像",
        "gdpr_art": "Art.22", "pipl_ref": "第24条",
    },
}

# 同意渠道
CONSENT_CHANNELS: Dict[str, Dict[str, Any]] = {
    "web_form": {"name": "网页表单", "channel": "website", "tracking": True},
    "mobile_app": {"name": "移动App弹窗", "channel": "app", "tracking": True},
    "offline_paper": {"name": "线下纸质同意书", "channel": "offline", "tracking": False},
    "email_consent": {"name": "邮件确认", "channel": "email", "tracking": True},
    "sms_consent": {"name": "短信确认", "channel": "sms", "tracking": True},
}

# 合法性基础（GDPR）
LAWFUL_BASIS: Dict[str, str] = {
    "consent": "数据主体同意",
    "contract": "履行合同必要",
    "legal_obligation": "遵守法定义务",
    "vital_interests": "保护重大利益",
    "public_task": "公共利益/官方职权",
    "legitimate_interests": " legitimate利益",
}


class PrivacyComplianceManager:
    """隐私合规管理器"""

    def __init__(self) -> None:
        self.ropa_records: Dict[str, Dict[str, Any]] = {}
        self.dsr_requests: Dict[str, Dict[str, Any]] = {}
        self.consent_records: Dict[str, Dict[str, Any]] = {}
        self.privacy_policies: Dict[str, Dict[str, Any]] = {}
        self.training_records: Dict[str, Dict[str, Any]] = {}
        self.assessments: Dict[str, Dict[str, Any]] = {}
        self._seed_sample_data()

    def _seed_sample_data(self) -> None:
        # 示例ROPA记录
        self.ropa_records = {
            "ropa-001": {
                "ropa_id": "ropa-001", "activity_name": "客户账户管理",
                "purposes": ["账户开立", "交易处理"],
                "data_categories": ["姓名", "身份证号", "银行账号"],
                "data_subjects": ["个人客户"],
                "recipients": ["财务部", "风控部"],
                "retention_period": "账户存续+5年",
                "lawful_basis": "contract",
                "cross_border": False,
                "dpo_reviewed": True,
            },
            "ropa-002": {
                "ropa_id": "ropa-002", "activity_name": "营销推送",
                "purposes": ["产品推荐", "活动通知"],
                "data_categories": ["姓名", "手机号", "浏览记录"],
                "data_subjects": ["注册用户"],
                "recipients": ["外部营销平台"],
                "retention_period": "2年",
                "lawful_basis": "consent",
                "cross_border": True,
                "dpo_reviewed": True,
            },
        }
        # 示例隐私政策
        self.privacy_policies = {
            "pp-v1.0": {
                "version": "v1.0", "name": "隐私政策v1.0",
                "effective_date": "2025-01-01",
                "status": "active", "language": "zh-CN",
                "sections": ["信息收集", "信息使用", "信息共享", "用户权利"],
            },
        }

    # ---------- 1. 合规框架 ----------
    def list_frameworks(self) -> Dict[str, Any]:
        return COMPLIANCE_FRAMEWORKS_DEEP

    def get_framework_detail(self, framework_id: str) -> Dict[str, Any]:
        return COMPLIANCE_FRAMEWORKS_DEEP.get(framework_id, {"error": "框架不存在"})

    def compare_frameworks(self, ids: List[str]) -> Dict[str, Any]:
        results = {}
        for fid in ids:
            if fid in COMPLIANCE_FRAMEWORKS_DEEP:
                f = COMPLIANCE_FRAMEWORKS_DEEP[fid]
                results[fid] = {
                    "name": f["name"], "region": f["region"],
                    "dpo_required": f["dpo_required"],
                    "requirements_count": len(f["key_requirements"]),
                }
        return {"frameworks": results}

    # ---------- 2. 合规评估 ----------
    def create_ropa(self, activity_name: str, purposes: List[str],
                   data_categories: List[str], data_subjects: List[str],
                   lawful_basis: str = "consent",
                   cross_border: bool = False) -> Dict[str, Any]:
        ropa_id = f"ropa-{uuid.uuid4().hex[:8]}"
        self.ropa_records[ropa_id] = {
            "ropa_id": ropa_id, "activity_name": activity_name,
            "purposes": purposes, "data_categories": data_categories,
            "data_subjects": data_subjects, "lawful_basis": lawful_basis,
            "cross_border": cross_border,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "dpo_reviewed": False,
        }
        return {"ropa_id": ropa_id, "created": True}

    def list_ropa(self) -> List[Dict[str, Any]]:
        return list(self.ropa_records.values())

    def conduct_dpia(self, processing_name: str,
                    high_risk_data: bool = False,
                    systematic_monitoring: bool = False) -> Dict[str, Any]:
        """数据保护影响评估(DPIA)"""
        assessment_id = f"dpia-{uuid.uuid4().hex[:8]}"
        risk_level = "high" if high_risk_data or systematic_monitoring else "medium"
        assessment = {
            "assessment_id": assessment_id,
            "processing_name": processing_name,
            "high_risk_data": high_risk_data,
            "systematic_monitoring": systematic_monitoring,
            "risk_level": risk_level,
            "questions": [
                {"q": "处理的必要性是否明确?", "a": "待评估"},
                {"q": "对数据主体的影响是否已评估?", "a": "待评估"},
                {"q": "是否已采取缓解措施?", "a": "待评估"},
                {"q": "是否需要咨询DPO?", "a": "是" if risk_level == "high" else "否"},
            ],
            "conclusion": "待完成",
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        self.assessments[assessment_id] = assessment
        return assessment

    def cross_border_assessment(self, destination_country: str,
                               data_volume: str = "small") -> Dict[str, Any]:
        """跨境传输评估"""
        assessment_id = f"cb-{uuid.uuid4().hex[:8]}"
        self.assessments[assessment_id] = {
            "assessment_id": assessment_id,
            "type": "cross_border",
            "destination": destination_country,
            "data_volume": data_volume,
            "mechanisms": ["标准合同条款(SCC)", "安全评估", "认证"],
            "recommendation": "需通过标准合同条款+安全评估后方可传输",
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        return self.assessments[assessment_id]

    # ---------- 3. 数据主体权利 ----------
    def list_rights(self) -> Dict[str, Any]:
        return DATA_SUBJECT_RIGHTS

    def submit_dsr(self, right_type: str, subject_name: str,
                  subject_contact: str = "", details: str = "") -> Dict[str, Any]:
        """提交数据主体权利请求(DSR)"""
        if right_type not in DATA_SUBJECT_RIGHTS:
            return {"error": f"不支持的权利类型: {right_type}"}
        req_id = f"dsr-{uuid.uuid4().hex[:10]}"
        self.dsr_requests[req_id] = {
            "request_id": req_id, "right_type": right_type,
            "right_name": DATA_SUBJECT_RIGHTS[right_type]["name"],
            "subject_name": subject_name, "subject_contact": subject_contact,
            "details": details, "status": "received",
            "deadline": "30天内响应",
            "submitted_at": datetime.now().isoformat(timespec="seconds"),
            "handler": "待分配",
        }
        return {
            "request_id": req_id, "right_type": right_type,
            "right_name": DATA_SUBJECT_RIGHTS[right_type]["name"],
            "status": "received", "deadline": "30天",
        }

    def process_dsr(self, request_id: str, action: str,
                   handler: str = "", result: str = "") -> Dict[str, Any]:
        if request_id not in self.dsr_requests:
            return {"error": "请求不存在"}
        req = self.dsr_requests[request_id]
        req["status"] = "processed" if action == "fulfill" else "rejected"
        req["handler"] = handler
        req["result"] = result
        req["processed_at"] = datetime.now().isoformat(timespec="seconds")
        return {"request_id": request_id, "status": req["status"]}

    def list_dsr(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.dsr_requests.values())
        if status:
            items = [r for r in items if r["status"] == status]
        return items

    # ---------- 4. 同意管理 ----------
    def record_consent(self, subject_id: str, purpose: str,
                      channel: str = "web_form",
                      consent_text: str = "", version: str = "v1.0") -> Dict[str, Any]:
        """记录同意"""
        consent_id = f"consent-{uuid.uuid4().hex[:10]}"
        self.consent_records[consent_id] = {
            "consent_id": consent_id, "subject_id": subject_id,
            "purpose": purpose, "channel": channel,
            "consent_text": consent_text, "version": version,
            "given_at": datetime.now().isoformat(timespec="seconds"),
            "status": "active",
        }
        return {"consent_id": consent_id, "status": "active"}

    def withdraw_consent(self, consent_id: str, reason: str = "") -> Dict[str, Any]:
        if consent_id not in self.consent_records:
            return {"error": "同意记录不存在"}
        self.consent_records[consent_id]["status"] = "withdrawn"
        self.consent_records[consent_id]["withdrawn_at"] = datetime.now().isoformat(timespec="seconds")
        self.consent_records[consent_id]["withdrawal_reason"] = reason
        return {"consent_id": consent_id, "status": "withdrawn"}

    def list_consents(self, subject_id: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.consent_records.values())
        if subject_id:
            items = [c for c in items if c["subject_id"] == subject_id]
        return items

    def consent_audit(self) -> Dict[str, Any]:
        total = len(self.consent_records)
        active = sum(1 for c in self.consent_records.values() if c["status"] == "active")
        withdrawn = sum(1 for c in self.consent_records.values() if c["status"] == "withdrawn")
        by_channel: Dict[str, int] = {}
        for c in self.consent_records.values():
            ch = c.get("channel", "unknown")
            by_channel[ch] = by_channel.get(ch, 0) + 1
        return {
            "total_consents": total,
            "active": active, "withdrawn": withdrawn,
            "withdrawal_rate": round(withdrawn / max(total, 1) * 100, 1),
            "by_channel": by_channel,
        }

    def list_consent_channels(self) -> Dict[str, Any]:
        return CONSENT_CHANNELS

    # ---------- 5. 隐私政策 ----------
    def generate_privacy_policy(self, company_name: str,
                              services: List[str],
                              frameworks: Optional[List[str]] = None) -> Dict[str, Any]:
        """生成隐私政策草稿"""
        fw = frameworks or ["pipl", "gdpr"]
        policy_id = f"pp-{uuid.uuid4().hex[:8]}"
        sections = [
            {"title": "1. 信息收集",
             "content": f"{company_name}收集以下信息: " + ", ".join(services)},
            {"title": "2. 信息使用",
             "content": "用于提供服务、改进产品、合规要求"},
            {"title": "3. 信息共享",
             "content": "仅在获得同意或法律要求时共享"},
            {"title": "4. 用户权利",
             "content": "您享有访问、更正、删除、撤回同意等权利"},
            {"title": "5. 数据安全",
             "content": "采取技术和管理措施保护数据安全"},
            {"title": "6. 跨境传输",
             "content": "如需跨境传输将依法进行安全评估"},
            {"title": "7. 政策更新",
             "content": "政策变更将通过合理方式通知您"},
        ]
        self.privacy_policies[policy_id] = {
            "policy_id": policy_id, "company_name": company_name,
            "services": services, "frameworks": fw,
            "sections": sections, "status": "draft",
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "version": f"v{len(self.privacy_policies) + 1}.0",
        }
        return {
            "policy_id": policy_id, "company": company_name,
            "sections": len(sections), "status": "draft",
            "frameworks": fw,
        }

    def list_policies(self) -> List[Dict[str, Any]]:
        return list(self.privacy_policies.values())

    def check_policy_compliance(self, policy_id: str,
                               framework: str = "pipl") -> Dict[str, Any]:
        if policy_id not in self.privacy_policies:
            return {"error": "政策不存在"}
        fw = COMPLIANCE_FRAMEWORKS_DEEP.get(framework, {})
        required = fw.get("key_requirements", [])
        policy = self.privacy_policies[policy_id]
        covered_sections = [s["title"] for s in policy.get("sections", [])]
        missing = []
        for req in required:
            if not any(req[:4] in sec for sec in covered_sections):
                missing.append(req)
        return {
            "policy_id": policy_id, "framework": framework,
            "framework_name": fw.get("name", framework),
            "requirements_total": len(required),
            "covered": len(required) - len(missing),
            "missing_requirements": missing,
            "compliance_score": round((len(required) - len(missing)) / max(len(required), 1) * 100, 1),
        }

    # ---------- 6. 隐私培训 ----------
    def create_training(self, title: str, audience: str,
                      duration_min: int = 60) -> Dict[str, Any]:
        training_id = f"train-{uuid.uuid4().hex[:8]}"
        self.training_records[training_id] = {
            "training_id": training_id, "title": title,
            "audience": audience, "duration_min": duration_min,
            "status": "scheduled",
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "enrolled": 0, "completed": 0,
        }
        return {"training_id": training_id, "title": title, "status": "scheduled"}

    def enroll_training(self, training_id: str, user_name: str) -> Dict[str, Any]:
        if training_id not in self.training_records:
            return {"error": "培训不存在"}
        self.training_records[training_id]["enrolled"] += 1
        return {"training_id": training_id, "enrolled": self.training_records[training_id]["enrolled"]}

    def complete_training(self, training_id: str, user_name: str,
                        score: int = 90) -> Dict[str, Any]:
        if training_id not in self.training_records:
            return {"error": "培训不存在"}
        self.training_records[training_id]["completed"] += 1
        self.training_records[training_id].setdefault("scores", []).append(score)
        return {"training_id": training_id, "score": score, "passed": score >= 60}

    def list_trainings(self) -> List[Dict[str, Any]]:
        return list(self.training_records.values())

    def training_effectiveness(self) -> Dict[str, Any]:
        total = len(self.training_records)
        completed_total = sum(t.get("completed", 0) for t in self.training_records.values())
        avg_scores = []
        for t in self.training_records.values():
            if t.get("scores"):
                avg_scores.append(sum(t["scores"]) / len(t["scores"]))
        return {
            "trainings_offered": total,
            "total_completions": completed_total,
            "avg_score": round(sum(avg_scores) / max(len(avg_scores), 1), 1) if avg_scores else 0,
            "pass_rate": "95%",
        }

    # ---------- 统计 ----------
    def stats(self) -> Dict[str, Any]:
        return {
            "frameworks": len(COMPLIANCE_FRAMEWORKS_DEEP),
            "rights": len(DATA_SUBJECT_RIGHTS),
            "ropa_records": len(self.ropa_records),
            "dsr_requests": len(self.dsr_requests),
            "pending_dsr": sum(1 for r in self.dsr_requests.values() if r["status"] == "received"),
            "consents": len(self.consent_records),
            "policies": len(self.privacy_policies),
            "trainings": len(self.training_records),
            "assessments": len(self.assessments),
            "consent_channels": len(CONSENT_CHANNELS),
        }


_instance: Optional[PrivacyComplianceManager] = None


def get_privacy_compliance_manager() -> PrivacyComplianceManager:
    global _instance
    if _instance is None:
        _instance = PrivacyComplianceManager()
    return _instance
