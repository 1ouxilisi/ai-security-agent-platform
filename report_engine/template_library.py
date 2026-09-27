# -*- coding: utf-8 -*-
"""template_library.py — 报告模板库。

覆盖：
- 8 大行业模板（金融/政务/医疗/教育/互联网/制造业/能源/电信）
- 8 种报告类型模板（渗透测试/漏洞评估/合规审计/应急响应/红蓝对抗/护网总结/风险评估/安全现状）
- 模板 CRUD / 版本管理 / 预览 / 导入导出

全部内存字典模拟，不写数据库。
"""

from __future__ import annotations

import copy
import json
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 行业模板骨架
# --------------------------------------------------------------------------- #
INDUSTRY_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "finance": {
        "industry": "金融",
        "compliance_refs": ["PCI-DSS", "等保三级", "银保监会指引", "SOC2"],
        "key_sections": ["客户资产清单", "交易系统风险", "数据泄露评估", "合规差距分析"],
        "risk_weight": {"high": 1.5, "medium": 1.0, "low": 0.5},
    },
    "government": {
        "industry": "政务",
        "compliance_refs": ["等保2.0", "GB/T 22239", "政务外网安全规范"],
        "key_sections": ["政务系统边界", "等保差距", "三级等保整改建议"],
        "risk_weight": {"high": 1.8, "medium": 1.2, "low": 0.6},
    },
    "medical": {
        "industry": "医疗",
        "compliance_refs": ["HIPAA", "等保三级", "医疗健康数据安全规范"],
        "key_sections": ["患者隐私保护", "HIS/LIS/PACS 风险", "处方系统评估"],
        "risk_weight": {"high": 1.6, "medium": 1.1, "low": 0.5},
    },
    "education": {
        "industry": "教育",
        "compliance_refs": ["教育系统等保", "个人信息保护法"],
        "key_sections": ["教务系统", "学生数据", "在线课堂平台"],
        "risk_weight": {"high": 1.2, "medium": 0.9, "low": 0.4},
    },
    "internet": {
        "industry": "互联网",
        "compliance_refs": ["网络安全法", "数据安全法", "GDPR(出海)"],
        "key_sections": ["Web 应用", "API 安全", "用户数据合规", "CDN/云资产"],
        "risk_weight": {"high": 1.3, "medium": 1.0, "low": 0.5},
    },
    "manufacturing": {
        "industry": "制造业",
        "compliance_refs": ["等保二级", "工业控制系统安全"],
        "key_sections": ["OT/IT 边界", "SCADA 风险", "供应链安全"],
        "risk_weight": {"high": 1.4, "medium": 1.0, "low": 0.5},
    },
    "energy": {
        "industry": "能源",
        "compliance_refs": ["电力监控系统安全防护规定", "等保三级"],
        "key_sections": ["电网调度", "调度数据网", "工控网络隔离"],
        "risk_weight": {"high": 1.9, "medium": 1.3, "low": 0.6},
    },
    "telecom": {
        "industry": "电信",
        "compliance_refs": ["电信网和互联网安全防护要求", "等保三级"],
        "key_sections": ["核心网", "BOSS 系统", "用户信令", "漫游边界"],
        "risk_weight": {"high": 1.7, "medium": 1.2, "low": 0.6},
    },
}


# --------------------------------------------------------------------------- #
# 报告类型模板骨架
# --------------------------------------------------------------------------- #
REPORT_TYPE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "penetration_test": {
        "type_name": "渗透测试报告",
        "required_sections": ["执行摘要", "测试范围", "漏洞详情", "利用过程", "修复建议", "附录"],
        "severity_order": ["critical", "high", "medium", "low", "info"],
    },
    "vulnerability_assessment": {
        "type_name": "漏洞评估报告",
        "required_sections": ["资产概览", "漏洞统计", "漏洞详情", "修复优先级"],
        "severity_order": ["critical", "high", "medium", "low", "info"],
    },
    "compliance_audit": {
        "type_name": "合规审计报告",
        "required_sections": ["合规框架", "控制项映射", "符合/不符合项", "整改计划"],
        "severity_order": ["critical", "high", "medium", "low", "info"],
    },
    "incident_response": {
        "type_name": "应急响应报告",
        "required_sections": ["事件时间线", "影响范围", "根因分析", "处置过程", "复盘建议"],
        "severity_order": ["critical", "high", "medium", "low"],
    },
    "red_blue_exercise": {
        "type_name": "红蓝对抗报告",
        "required_sections": ["演练概述", "攻击路径", "检测能力", "响应时延", "改进建议"],
        "severity_order": ["critical", "high", "medium", "low", "info"],
    },
    "hw_summary": {
        "type_name": "护网总结报告",
        "required_sections": ["护网背景", "攻击拦截统计", "情报共享", "常态化建议"],
        "severity_order": ["critical", "high", "medium", "low", "info"],
    },
    "risk_assessment": {
        "type_name": "风险评估报告",
        "required_sections": ["资产识别", "威胁识别", "脆弱性识别", "风险矩阵", "处置计划"],
        "severity_order": ["critical", "high", "medium", "low"],
    },
    "security_posture": {
        "type_name": "安全现状报告",
        "required_sections": ["安全成熟度", "控制覆盖", "差距分析", "路线图"],
        "severity_order": ["high", "medium", "low", "info"],
    },
}


# --------------------------------------------------------------------------- #
# 模板库（内存）
# --------------------------------------------------------------------------- #
class TemplateLibrary:
    """模板库：CRUD + 版本管理 + 预览 + 导入导出。"""

    def __init__(self) -> None:
        self.templates: Dict[str, Dict[str, Any]] = {}
        self.versions: Dict[str, List[Dict[str, Any]]] = {}
        self._seed_defaults()

    # ---------------- 初始化 ---------------- #
    def _seed_defaults(self) -> None:
        for ind_key, ind in INDUSTRY_TEMPLATES.items():
            for rtype_key, rtype in REPORT_TYPE_TEMPLATES.items():
                tid = f"TPL-{ind_key.upper()}-{rtype_key.upper()}"
                tpl = {
                    "template_id": tid,
                    "name": f"{ind['industry']}行业·{rtype['type_name']}",
                    "industry": ind_key,
                    "report_type": rtype_key,
                    "version": "1.0.0",
                    "required_sections": list(rtype["required_sections"]),
                    "compliance_refs": list(ind["compliance_refs"]),
                    "risk_weight": dict(ind["risk_weight"]),
                    "severity_order": list(rtype["severity_order"]),
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "is_builtin": True,
                    "tags": [ind_key, rtype_key],
                }
                self.templates[tid] = tpl
                self.versions[tid] = [self._snapshot(tpl)]

    @staticmethod
    def _snapshot(tpl: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "version": tpl["version"],
            "snapshot": copy.deepcopy(tpl),
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ---------------- CRUD ---------------- #
    def list_templates(
        self, industry: Optional[str] = None, report_type: Optional[str] = None,
        keyword: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        out = list(self.templates.values())
        if industry:
            out = [t for t in out if t["industry"] == industry]
        if report_type:
            out = [t for t in out if t["report_type"] == report_type]
        if keyword:
            kw = keyword.lower()
            out = [t for t in out if kw in t["name"].lower() or kw in str(t.get("tags", [])).lower()]
        return out

    def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        return self.templates.get(template_id)

    def create_template(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        tid = payload.get("template_id") or f"TPL-CUSTOM-{uuid.uuid4().hex[:6].upper()}"
        tpl = {
            "template_id": tid,
            "name": payload.get("name", "自定义模板"),
            "industry": payload.get("industry", "internet"),
            "report_type": payload.get("report_type", "penetration_test"),
            "version": payload.get("version", "1.0.0"),
            "required_sections": list(payload.get("required_sections", ["执行摘要", "漏洞详情"])),
            "compliance_refs": list(payload.get("compliance_refs", [])),
            "risk_weight": dict(payload.get("risk_weight", {"high": 1.0, "medium": 1.0, "low": 0.5})),
            "severity_order": list(payload.get("severity_order", ["critical", "high", "medium", "low"])),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "is_builtin": False,
            "tags": list(payload.get("tags", [])),
            "description": payload.get("description", ""),
        }
        self.templates[tid] = tpl
        self.versions[tid] = [self._snapshot(tpl)]
        return tpl

    def update_template(self, template_id: str, patch: Dict[str, Any],
                        bump: str = "minor") -> Optional[Dict[str, Any]]:
        tpl = self.templates.get(template_id)
        if not tpl:
            return None
        tpl.update({k: v for k, v in patch.items() if k in {
            "name", "industry", "report_type", "required_sections",
            "compliance_refs", "risk_weight", "severity_order", "tags", "description",
        }})
        # 版本号自增
        major, minor, patch_v = (int(x) for x in tpl["version"].split("."))
        if bump == "major":
            major, minor, patch_v = major + 1, 0, 0
        elif bump == "patch":
            major, minor, patch_v = major, minor, patch_v + 1
        else:
            major, minor, patch_v = major, minor + 1, 0
        tpl["version"] = f"{major}.{minor}.{patch_v}"
        tpl["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.versions.setdefault(template_id, []).append(self._snapshot(tpl))
        return tpl

    def delete_template(self, template_id: str) -> bool:
        if template_id in self.templates and not self.templates[template_id].get("is_builtin"):
            self.templates.pop(template_id, None)
            self.versions.pop(template_id, None)
            return True
        return False

    # ---------------- 版本 / 预览 / 导入导出 ---------------- #
    def list_versions(self, template_id: str) -> List[Dict[str, Any]]:
        return self.versions.get(template_id, [])

    def rollback(self, template_id: str, version: str) -> Optional[Dict[str, Any]]:
        hist = self.versions.get(template_id, [])
        for snap in hist:
            if snap["version"] == version:
                restored = copy.deepcopy(snap["snapshot"])
                restored["version"] = f"{restored['version']}-r{uuid.uuid4().hex[:4]}"
                restored["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                self.templates[template_id] = restored
                self.versions[template_id].append(self._snapshot(restored))
                return restored
        return None

    def preview(self, template_id: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        tpl = self.templates.get(template_id)
        if not tpl:
            return {}
        ctx = context or {}
        sections = []
        for sec in tpl["required_sections"]:
            sections.append({
                "section": sec,
                "content": f"【{sec}】示例占位内容 — {ctx.get('client', '某客户')} · "
                           f"依据：{', '.join(tpl['compliance_refs']) or '内部规范'}",
            })
        return {
            "template_id": template_id,
            "name": tpl["name"],
            "version": tpl["version"],
            "preview_sections": sections,
            "meta": {
                "industry": tpl["industry"],
                "report_type": tpl["report_type"],
                "compliance_refs": tpl["compliance_refs"],
            },
        }

    def export_template(self, template_id: str) -> Optional[str]:
        tpl = self.templates.get(template_id)
        if not tpl:
            return None
        return json.dumps({
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "template": tpl,
            "history": self.versions.get(template_id, []),
        }, ensure_ascii=False, indent=2)

    def import_template(self, raw: str) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(raw)
        except Exception:
            return None
        tpl = data.get("template") if isinstance(data, dict) else None
        if not isinstance(tpl, dict) or "template_id" not in tpl:
            return None
        tpl["is_builtin"] = False
        tpl["template_id"] = f"TPL-IMPORT-{uuid.uuid4().hex[:6].upper()}"
        self.templates[tpl["template_id"]] = tpl
        self.versions[tpl["template_id"]] = [self._snapshot(tpl)]
        return tpl


# 单例
_LIBRARY: Optional[TemplateLibrary] = None


def get_template_library() -> TemplateLibrary:
    global _LIBRARY
    if _LIBRARY is None:
        _LIBRARY = TemplateLibrary()
    return _LIBRARY


def list_industries() -> List[Dict[str, Any]]:
    return [{"key": k, **v} for k, v in INDUSTRY_TEMPLATES.items()]


def list_report_types() -> List[Dict[str, Any]]:
    return [{"key": k, **v} for k, v in REPORT_TYPE_TEMPLATES.items()]
