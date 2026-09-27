# -*- coding: utf-8 -*-
"""
audit_compliance.py — 审计与合规核心模块。

覆盖：
- 审计日志（登录/操作/数据访问/管理员/API调用/系统事件）
- 日志完整性（哈希链/签名/时间戳/防篡改/备份/归档/验证）
- 合规框架（等保2.0/ISO27001/SOC2/PCI DSS/HIPAA/GDPR/个保法/网安法）
- 合规评估（控制项检查/合规评分/差距分析/整改建议/整改跟踪/报告）
- 数据治理（分类/分级/血缘/质量/生命周期/销毁）
- 隐私保护（隐私政策/用户同意/数据最小化/匿名化/脱敏/数据主体权利/跨境）

全部内存字典模拟。
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Optional


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _uid(prefix: str = "") -> str:
    return prefix + uuid.uuid4().hex[:12]


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(c for c in obj if c >= " " or c in "\n\r\t")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    return obj


# --------------------------------------------------------------------------- #
# 内存存储
# --------------------------------------------------------------------------- #
class AuditStore:
    def __init__(self) -> None:
        self.audit_logs: List[Dict[str, Any]] = []
        self.hash_chain: List[str] = []
        self.compliance_frameworks: Dict[str, Dict[str, Any]] = {}
        self.compliance_assessments: Dict[str, Dict[str, Any]] = {}
        self.data_catalog: Dict[str, Dict[str, Any]] = {}
        self.privacy_consents: Dict[str, Dict[str, Any]] = {}
        self.data_subject_requests: Dict[str, Dict[str, Any]] = {}
        self._seed_frameworks()

    def _seed_frameworks(self) -> None:
        frameworks = {
            "mlps2": {
                "id": "mlps2", "name": "网络安全等级保护2.0",
                "level": "三级", "category": "中国国家标准",
                "control_groups": [
                    {"name": "安全物理环境", "controls": ["机房位置", "防火", "防水"]},
                    {"name": "安全通信网络", "controls": ["网络架构", "通信传输", "可信验证"]},
                    {"name": "安全区域边界", "controls": ["边界防护", "访问控制", "入侵防范"]},
                    {"name": "安全计算环境", "controls": ["身份鉴别", "访问控制", "安全审计"]},
                    {"name": "安全管理中心", "controls": ["系统管理", "审计管理", "安全管理"]},
                ],
            },
            "iso27001": {
                "id": "iso27001", "name": "ISO 27001",
                "level": "国际标准", "category": "信息安全管理体系",
                "control_groups": [
                    {"name": "A.5 组织", "controls": ["信息安全策略", "职责分工", "供应商关系"]},
                    {"name": "A.6 人员", "controls": ["雇佣前", "雇佣中", "纪律处分"]},
                    {"name": "A.8 物理", "controls": ["安全区域", "设备安全"]},
                    {"name": "A.9 访问控制", "controls": ["访问策略", "用户注册", "权限管理"]},
                    {"name": "A.12 操作", "controls": ["操作程序", "恶意代码", "日志"]},
                ],
            },
            "soc2": {
                "id": "soc2", "name": "SOC 2 Type II",
                "level": "美国标准", "category": "信托服务标准",
                "control_groups": [
                    {"name": "安全Security", "controls": ["防火墙", "入侵检测", "访问控制"]},
                    {"name": "可用性Availability", "controls": ["冗余", "故障恢复", "监控"]},
                    {"name": "处理完整性", "controls": ["数据验证", "错误处理", "审计"]},
                    {"name": "保密性Confidentiality", "controls": ["加密", "访问控制", "清理"]},
                    {"name": "隐私Privacy", "controls": ["数据收集", "同意", "处置"]},
                ],
            },
            "pci_dss": {
                "id": "pci_dss", "name": "PCI DSS",
                "level": "支付卡行业", "category": "支付安全标准",
                "control_groups": [
                    {"name": "构建网络", "controls": ["防火墙", "修改默认密码"]},
                    {"name": "保护数据", "controls": ["加密传输", "不要存储敏感数据"]},
                    {"name": "维护漏洞", "controls": ["恶意代码防护", "安全系统"]},
                    {"name": "实施访问控制", "controls": ["唯一ID", "限制物理访问"]},
                    {"name": "定期监控", "controls": ["访问日志", "定期测试"]},
                ],
            },
            "gdpr": {
                "id": "gdpr", "name": "GDPR",
                "level": "欧盟标准", "category": "通用数据保护条例",
                "control_groups": [
                    {"name": "合法性", "controls": ["同意", "合同必要", "合法利益"]},
                    {"name": "数据主体权利", "controls": ["访问权", "更正权", "删除权", "可携权"]},
                    {"name": "数据保护", "controls": ["加密", "假名化", "访问控制"]},
                    {"name": "违规通知", "controls": ["72小时通知", "记录保持"]},
                    {"name": "DPO", "controls": ["数据保护官", "DPIA"]},
                ],
            },
            "pipl": {
                "id": "pipl", "name": "个人信息保护法",
                "level": "中国法律", "category": "个人信息保护",
                "control_groups": [
                    {"name": "处理规则", "controls": ["告知同意", "最小必要", "目的限制"]},
                    {"name": "个人权利", "controls": ["知情权", "决定权", "查询复制", "更正删除"]},
                    {"name": "安全措施", "controls": ["加密存储", "访问控制", "安全审计"]},
                    {"name": "跨境提供", "controls": ["安全评估", "标准合同", "认证"]},
                ],
            },
            "csl": {
                "id": "csl", "name": "网络安全法",
                "level": "中国法律", "category": "网络安全",
                "control_groups": [
                    {"name": "等级保护", "controls": ["定级备案", "建设整改", "测评"]},
                    {"name": "安全义务", "controls": ["实名", "监测", "应急处置"]},
                    {"name": "信息内容", "controls": ["违法信息处置", "用户日志保存"]},
                ],
            },
        }
        self.compliance_frameworks = frameworks


_store = AuditStore()


# --------------------------------------------------------------------------- #
# 1. 审计日志
# --------------------------------------------------------------------------- #
def log_event(tenant_id: str, event_type: str,
              user_id: str = "", action: str = "",
              resource: str = "", detail: str = "",
              ip: str = "") -> Dict[str, Any]:
    """记录审计事件（含哈希链）。"""
    entry = {
        "id": _uid("aud_"), "tenant_id": tenant_id,
        "event_type": event_type, "user_id": user_id,
        "action": action, "resource": resource,
        "detail": detail, "ip": ip,
        "timestamp": _now(),
    }
    # 哈希链：前一条的哈希作为本条的前哈希
    prev_hash = _store.hash_chain[-1] if _store.hash_chain else "GENESIS"
    entry["prev_hash"] = prev_hash
    entry_hash = hashlib.sha256(
        json.dumps({**entry, "hash": None}, sort_keys=True).encode()
    ).hexdigest()
    entry["hash"] = entry_hash
    _store.audit_logs.append(entry)
    _store.hash_chain.append(entry_hash)
    # 限制内存
    if len(_store.audit_logs) > 50000:
        _store.audit_logs = _store.audit_logs[-50000:]
    return entry


def query_audit_logs(tenant_id: str = "", event_type: str = "",
                     user_id: str = "", start_date: str = "",
                     end_date: str = "",
                     page: int = 1, page_size: int = 50) -> Dict[str, Any]:
    items = list(_store.audit_logs)
    if tenant_id:
        items = [l for l in items if l["tenant_id"] == tenant_id]
    if event_type:
        items = [l for l in items if l["event_type"] == event_type]
    if user_id:
        items = [l for l in items if l["user_id"] == user_id]
    if start_date:
        items = [l for l in items if l["timestamp"] >= start_date]
    if end_date:
        items = [l for l in items if l["timestamp"] <= end_date]
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    return {"total": total, "page": page, "page_size": page_size,
            "items": items[start:end]}


# --------------------------------------------------------------------------- #
# 2. 日志完整性验证
# --------------------------------------------------------------------------- #
def verify_log_integrity() -> Dict[str, Any]:
    """验证审计日志哈希链完整性。"""
    logs = _store.audit_logs
    if not logs:
        return {"verified": True, "total": 0, "message": "无日志"}
    verified = 0
    broken_chain = []
    for i, entry in enumerate(logs):
        # 验证当前条目前哈希
        expected_prev = logs[i - 1]["hash"] if i > 0 else "GENESIS"
        if entry["prev_hash"] != expected_prev:
            broken_chain.append({"index": i, "id": entry["id"],
                                  "reason": "prev_hash_mismatch"})
            continue
        # 重新计算哈希验证
        entry_copy = {k: v for k, v in entry.items() if k != "hash"}
        recalc = hashlib.sha256(
            json.dumps(entry_copy, sort_keys=True).encode()).hexdigest()
        if recalc == entry["hash"]:
            verified += 1
        else:
            broken_chain.append({"index": i, "id": entry["id"],
                                  "reason": "hash_tampered"})
    return {
        "verified": len(broken_chain) == 0,
        "total_logs": len(logs),
        "verified_count": verified,
        "broken_chain_count": len(broken_chain),
        "broken_entries": broken_chain[:10],
        "integrity_pct": round(verified / max(len(logs), 1) * 100, 2),
    }


def archive_logs(tenant_id: str,
                 before_date: str) -> Dict[str, Any]:
    """归档旧日志。"""
    archived = [l for l in _store.audit_logs
                if l["tenant_id"] == tenant_id and l["timestamp"] < before_date]
    return {
        "archived_count": len(archived),
        "before_date": before_date,
        "archived_at": _now(),
        "note": "归档日志已写入冷存储（模拟）",
    }


# --------------------------------------------------------------------------- #
# 3. 合规框架
# --------------------------------------------------------------------------- #
def list_frameworks() -> List[Dict[str, Any]]:
    return list(_store.compliance_frameworks.values())


def get_framework(framework_id: str) -> Optional[Dict[str, Any]]:
    return _store.compliance_frameworks.get(framework_id)


# --------------------------------------------------------------------------- #
# 4. 合规评估
# --------------------------------------------------------------------------- #
def run_compliance_assessment(tenant_id: str,
                               framework_id: str) -> Dict[str, Any]:
    """执行合规评估。"""
    framework = _store.compliance_frameworks.get(framework_id)
    if not framework:
        return {"success": False, "error": "框架不存在"}

    assessment_id = _uid("assess_")
    # 模拟控制项检查结果
    control_results = []
    for group in framework["control_groups"]:
        for ctrl in group["controls"]:
            # 随机合规率 70%-95%
            import random
            random.seed(f"{tenant_id}{framework_id}{ctrl}")
            compliant = random.random() > 0.2
            control_results.append({
                "group": group["name"], "control": ctrl,
                "status": "compliant" if compliant else "non_compliant",
                "evidence": "自动检查通过" if compliant else "缺少配置证据",
            })

    compliant_count = len([c for c in control_results if c["status"] == "compliant"])
    total_controls = len(control_results)
    score = round(compliant_count / max(total_controls, 1) * 100, 1)

    assessment = {
        "id": assessment_id, "tenant_id": tenant_id,
        "framework_id": framework_id,
        "framework_name": framework["name"],
        "score": score,
        "total_controls": total_controls,
        "compliant_controls": compliant_count,
        "non_compliant_controls": total_controls - compliant_count,
        "control_results": control_results,
        "status": "completed",
        "assessed_at": _now(),
    }
    _store.compliance_assessments[assessment_id] = assessment
    return assessment


def get_compliance_report(tenant_id: str) -> Dict[str, Any]:
    """生成综合合规报告。"""
    assessments = [a for a in _store.compliance_assessments.values()
                   if a["tenant_id"] == tenant_id]
    if not assessments:
        return {"tenant_id": tenant_id, "assessments": [],
                "overall_score": 0}
    avg_score = round(sum(a["score"] for a in assessments) / len(assessments), 1)
    return {
        "tenant_id": tenant_id,
        "overall_score": avg_score,
        "framework_count": len(assessments),
        "assessments": [{"id": a["id"], "framework": a["framework_name"],
                         "score": a["score"], "status": a["status"]}
                        for a in assessments],
        "last_assessed": assessments[-1]["assessed_at"] if assessments else None,
    }


def get_remediation_plan(assessment_id: str) -> Dict[str, Any]:
    """生成整改建议。"""
    assessment = _store.compliance_assessments.get(assessment_id)
    if not assessment:
        return {}
    non_compliant = [c for c in assessment["control_results"]
                     if c["status"] == "non_compliant"]
    return {
        "assessment_id": assessment_id,
        "total_gaps": len(non_compliant),
        "remediation_items": [
            {"control": c["control"], "group": c["group"],
             "suggestion": f"配置 {c['control']} 相关安全策略并补充证据",
             "priority": "high" if i < 3 else "medium"}
            for i, c in enumerate(non_compliant)
        ],
    }


# --------------------------------------------------------------------------- #
# 5. 数据治理
# --------------------------------------------------------------------------- #
def classify_data(tenant_id: str, data_name: str,
                  data_type: str, sensitivity: str = "internal",
                  owner: str = "") -> Dict[str, Any]:
    """数据分类分级。"""
    did = _uid("dc_")
    classification = {
        "id": did, "tenant_id": tenant_id, "name": data_name,
        "type": data_type, "sensitivity": sensitivity,
        "owner": owner, "classification_level": sensitivity,
        "created_at": _now(),
    }
    _store.data_catalog[did] = classification
    return classification


def list_data_catalog(tenant_id: str) -> List[Dict[str, Any]]:
    return [d for d in _store.data_catalog.values()
            if d["tenant_id"] == tenant_id]


def get_data_quality_report(tenant_id: str) -> Dict[str, Any]:
    items = [d for d in _store.data_catalog.values()
             if d["tenant_id"] == tenant_id]
    return {
        "tenant_id": tenant_id,
        "total_datasets": len(items),
        "by_sensitivity": {
            s: len([d for d in items if d["sensitivity"] == s])
            for s in ["public", "internal", "confidential", "restricted"]
        },
        "quality_metrics": {"completeness": 95.2, "accuracy": 98.1,
                            "consistency": 92.5, "timeliness": 96.0},
    }


# --------------------------------------------------------------------------- #
# 6. 隐私保护
# --------------------------------------------------------------------------- #
def record_consent(user_id: str, consent_type: str,
                   granted: bool, scope: str = "") -> Dict[str, Any]:
    """记录用户同意。"""
    cid = _uid("consent_")
    consent = {
        "id": cid, "user_id": user_id, "type": consent_type,
        "granted": granted, "scope": scope,
        "timestamp": _now(),
    }
    _store.privacy_consents[cid] = consent
    return consent


def get_consent_history(user_id: str) -> List[Dict[str, Any]]:
    return [c for c in _store.privacy_consents.values()
            if c["user_id"] == user_id]


def submit_data_subject_request(user_id: str, request_type: str,
                                 details: str = "") -> Dict[str, Any]:
    """数据主体权利请求（访问/更正/删除/可携）。"""
    valid_types = ["access", "rectification", "erasure",
                    "portability", "restriction"]
    if request_type not in valid_types:
        return {"success": False, "error": "无效请求类型"}
    rid = _uid("dsr_")
    request = {
        "id": rid, "user_id": user_id, "type": request_type,
        "details": details, "status": "received",
        "deadline": time.strftime("%Y-%m-%d",
            time.localtime(time.time() + 30 * 86400)),
        "created_at": _now(),
    }
    _store.data_subject_requests[rid] = request
    return request


def anonymize_data(tenant_id: str,
                   data_set: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """模拟数据匿名化。"""
    result = []
    for record in data_set:
        anon = record.copy()
        for field in ["email", "phone", "name", "address"]:
            if field in anon:
                val = str(anon[field])
                anon[field] = val[:2] + "***" + val[-2:] if len(val) > 4 else "***"
        result.append(anon)
    return result


def get_privacy_summary(tenant_id: str) -> Dict[str, Any]:
    consents = list(_store.privacy_consents.values())
    return {
        "tenant_id": tenant_id,
        "total_consents": len(consents),
        "consent_types": list(set(c["type"] for c in consents)),
        "active_requests": len([r for r in _store.data_subject_requests.values()
                                if r["status"] == "received"]),
        "cross_border_transfer": {"enabled": False,
                                   "approved": False,
                                   "regions": ["CN"]},
    }


def get_store() -> AuditStore:
    return _store
