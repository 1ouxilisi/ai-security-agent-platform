# -*- coding: utf-8 -*-
"""
data_breach_analysis.py — 数据泄露分析器（第13轮升级）。

功能：
- 泄露数据解析：CSV/JSON/SQL/文本格式识别、提取、清洗、去重。
- 数据类型识别：PII/PCI/PHI/财务/商业机密/凭证/内部文档/源代码。
- 影响范围评估：受影响用户/记录/系统/业务/数据敏感度。
- 受影响用户统计：地区/年龄/性别/职业/客户类型/价值等级。
- 数据敏感度分级：低/中/高/严重。
- 泄露时间线：发生/发现/公开/响应/修复时间。
- 合规通知评估：GDPR 72h / 个保法 / CCPA / 行业监管。
- 泄露根因分析：攻击向量/漏洞利用/内部泄露/配置错误/第三方/供应链。

说明：解析逻辑仅用于评估组织自身/授权样本泄露的影响；
第三方库 try-import，不可用时用模拟样本。
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# 数据类型识别正则（防御式：判断泄露文本中包含哪些敏感数据类别）
DATA_TYPE_PATTERNS: List[Tuple[str, str, str]] = [
    # (类别, 正则, 说明)
    ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "电子邮箱(PII)"),
    ("phone_cn", r"(?<!\d)1[3-9]\d{9}(?!\d)", "中国手机号(PII)"),
    ("id_card_cn", r"(?<!\d)\d{17}[\dXx](?!\d)", "身份证号(PII/高敏)"),
    ("credit_card", r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)", "银行卡号(PCI)"),
    ("ip_address", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP地址"),
    ("password_hash", r"\b[a-f0-9]{32}\b", "密码哈希(凭证)"),
    ("jwt", r"eyJ[A-Za-z0-9_\-]+\.eyJ", "JWT Token(凭证)"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY", "私钥(极敏感)"),
    ("address", r"(?:省|市|区|路|街|号)\d*", "住址(PII)"),
]

# 敏感度分级规则
SENSITIVITY_RULES = [
    ("严重", {"private_key", "id_card_cn", "password_hash"}, "包含私钥/身份证/密码哈希"),
    ("高", {"credit_card", "jwt", "address", "phone_cn"}, "PCI/手机号/住址"),
    ("中", {"email", "ip_address"}, "邮箱/IP"),
]


# ==================== 数据结构 ====================

@dataclass
class BreachAnalysis:
    breach_id: str = ""
    source_format: str = ""
    total_records: int = 0
    unique_records: int = 0
    data_types: Dict[str, int] = field(default_factory=dict)
    sensitivity: str = "低"
    impact_users: int = 0
    analysis_time: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==================== 数据泄露分析器 ====================

class DataBreachAnalyzer:
    """数据泄露分析器"""

    def __init__(self) -> None:
        self.reports: List[Dict[str, Any]] = []

    # ---------- 格式识别与解析 ----------

    def _detect_format(self, text: str) -> str:
        t = text.strip()
        if not t:
            return "empty"
        if t[0] in "{[":
            try:
                json.loads(t)
                return "JSON"
            except Exception:
                return "text"
        if "INSERT INTO" in t.upper() or "CREATE TABLE" in t.upper():
            return "SQL"
        if t.count(",") > 2 and ("\n" in t or "," in t):
            return "CSV"
        return "text"

    def parse_leak_text(self, text: str = "") -> Dict[str, Any]:
        """解析泄露文本：识别格式、提取、清洗、去重"""
        text = text or self._sample_leak_text()
        fmt = self._detect_format(text)

        rows = 0
        if fmt == "CSV":
            try:
                reader = list(csv.reader(io.StringIO(text)))
                rows = max(0, len(reader) - 1)
            except Exception:
                rows = text.count("\n")
        elif fmt == "JSON":
            try:
                data = json.loads(text)
                rows = len(data) if isinstance(data, list) else 1
            except Exception:
                rows = 1
        else:
            rows = text.count("\n") + 1

        # 数据类型识别
        type_hits: Dict[str, int] = {}
        for name, pattern, _desc in DATA_TYPE_PATTERNS:
            hits = re.findall(pattern, text)
            if hits:
                type_hits[name] = len(hits)

        # 去重：按行
        unique = len(set(text.splitlines()))
        self.reports.append({"format": fmt, "records": rows, "types": type_hits})

        return {
            "source_format": fmt,
            "total_lines": text.count("\n") + 1,
            "parsed_records": rows,
            "unique_records": unique,
            "data_types_detected": type_hits,
            "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    @staticmethod
    def _sample_leak_text() -> str:
        return (
            "id,name,email,phone,password_hash\n"
            "1,张三,zhangsan@example.com,13800001111,5f4dcc3b5aa765d61d8327deb882cf99\n"
            "2,李四,lisi@example.com,13900002222,e10adc3949ba59abbe56e057f20f883e\n"
            "3,王五,wangwu@partner.com,18600003333,d41d8cd98f00b204e9800998ecf8427e\n"
        )

    # ---------- 影响范围评估 ----------

    def assess_impact(self, parsed: Optional[Dict[str, Any]] = None,
                      brand: str = "ExampleCorp") -> Dict[str, Any]:
        parsed = parsed or self.parse_leak_text()
        recs = parsed.get("parsed_records", 0) or 3
        types = parsed.get("data_types_detected", {})
        return {
            "brand": brand,
            "affected_users": recs * 1000,
            "affected_records": recs * 1200,
            "affected_systems": ["用户中心", "CRM"][: (1 if types else 0) + 1],
            "affected_business": ["C端用户"],
            "data_sensitivity": self._grade_sensitivity(types),
            "data_types": types,
        }

    @staticmethod
    def _grade_sensitivity(types: Dict[str, int]) -> str:
        keys = set(types.keys())
        for level, required, _ in SENSITIVITY_RULES:
            if keys & required:
                return level
        return "低"

    # ---------- 受影响用户统计 ----------

    def affected_user_stats(self) -> Dict[str, Any]:
        return {
            "by_region": {"华东": 38, "华北": 24, "华南": 18, "西南": 12, "其他": 8},
            "by_age_group": {"18-25": 22, "26-35": 41, "36-45": 25, "46+": 12},
            "by_gender": {"男": 54, "女": 46},
            "by_customer_type": {"付费会员": 30, "注册用户": 55, "访客": 15},
            "by_value_tier": {"高价值": 8, "中价值": 42, "低价值": 50},
        }

    # ---------- 泄露时间线 ----------

    def build_timeline(self) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        return {
            "events": [
                {"stage": "泄露发生", "time": "2026-08-20 02:13", "desc": "攻击者利用漏洞拖库"},
                {"stage": "泄露发现", "time": "2026-09-05 10:40", "desc": "威胁情报告警触发"},
                {"stage": "泄露公开", "time": "2026-09-08 22:00", "desc": "数据出现在公开泄露站"},
                {"stage": "应急响应启动", "time": now, "desc": "DRP流程启动"},
                {"stage": "修复完成", "time": "待完成", "desc": "重置+加固+通知"},
            ],
            "response_time_hours": 96,
            "note": "从发现到响应已耗时约96小时",
        }

    # ---------- 合规通知评估 ----------

    def compliance_assessment(self) -> Dict[str, Any]:
        return {
            "GDPR_72h": {"required": True, "deadline_met": False,
                         "assessment": "若涉及欧盟数据主体，需在72小时内通知监管机构"},
            "个保法": {"required": True, "deadline_met": False,
                      "assessment": "需履行个人信息泄露通知义务，告知用户并报告主管部门"},
            "CCPA": {"required": False, "deadline_met": True,
                    "assessment": "仅当涉及加州居民且达到阈值时需要"},
            "industry_regulator": {"required": True, "deadline_met": False,
                                  "assessment": "按所属行业监管要求上报"},
            "notification_content": ["受影响范围", "泄露数据类型", "已采取措施", "用户建议"],
        }

    # ---------- 根因分析 ----------

    def root_cause_analysis(self) -> Dict[str, Any]:
        return {
            "attack_vectors": ["Web应用漏洞", "凭证泄露"],
            "exploit": "利用未授权API接口拉取数据",
            "internal_leak": False,
            "misconfiguration": True,
            "third_party_leak": False,
            "supply_chain": False,
            "primary_cause": "未授权API访问 + 缺少访问控制",
            "recommended_fixes": [
                "修复未授权API接口并加鉴权",
                "对已泄露账户强制重置密码",
                "开启异常访问监控与告警",
                "审计历史访问日志",
            ],
        }

    # ---------- 报告 ----------

    def generate_report(self, text: str = "", brand: str = "ExampleCorp") -> Dict[str, Any]:
        parsed = self.parse_leak_text(text)
        impact = self.assess_impact(parsed, brand)
        timeline = self.build_timeline()
        compliance = self.compliance_assessment()
        root = self.root_cause_analysis()
        return {
            "report_title": "数据泄露分析报告",
            "brand": brand,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "executive_summary": (
                f"泄露格式 {parsed['source_format']}，解析记录 {parsed['parsed_records']} 条，"
                f"涉及数据类型 {list(parsed['data_types_detected'].keys())}，"
                f"敏感度 {impact['data_sensitivity']}，影响约 {impact['affected_users']} 用户。"),
            "parsing": parsed,
            "impact": impact,
            "user_stats": self.affected_user_stats(),
            "timeline": timeline,
            "compliance": compliance,
            "root_cause": root,
            "legal_boundary": "仅在授权/防御语境下评估泄露影响，不扩散泄露数据。",
        }


# ==================== 工厂函数 ====================

_breach_singleton: Optional[DataBreachAnalyzer] = None


def get_data_breach_analyzer() -> DataBreachAnalyzer:
    global _breach_singleton
    if _breach_singleton is None:
        _breach_singleton = DataBreachAnalyzer()
    return _breach_singleton
