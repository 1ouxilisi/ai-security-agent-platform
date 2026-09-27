#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
data_classification.py — 数据分类分级深度引擎（Round24 方向3）。

覆盖：
    1. 数据资产发现：自动扫描数据库/文件存储/对象存储/API/日志/消息队列
    2. 数据分类：按业务域/数据类型/敏感度分类，自定义规则、分类模板、分类建议
    3. 数据分级：公开/内部/机密/绝密四级，分级规则、自动分级、人工审核、分级变更
    4. 敏感数据识别：个人信息/敏感个人信息/重要数据/核心数据，正则+ML+字典匹配
    5. 数据地图：资产地图/流向图/血缘图/关系图/分布热力图
    6. 数据资产目录：资产列表/详情/标签/评分/所有者/生命周期/搜索

设计定位：仅做数据识别、分类分级与资产盘点，输出清单与报告，不泄露任何真实数据。
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 分级标准（公开 / 内部 / 机密 / 绝密）
# --------------------------------------------------------------------------- #
CLASSIFICATION_LEVELS_DEEP: Dict[str, Dict[str, Any]] = {
    "public": {
        "level": 1, "name": "公开", "code": "L1", "color": "#52c41a",
        "desc": "可对外公开的数据，泄露后不造成损害",
        "examples": ["官网宣传稿", "公开财报摘要", "新闻稿"],
    },
    "internal": {
        "level": 2, "name": "内部", "code": "L2", "color": "#1890ff",
        "desc": "仅限内部使用，泄露后造成轻微损害",
        "examples": ["内部流程文档", "组织架构", "一般培训资料"],
    },
    "confidential": {
        "level": 3, "name": "机密", "code": "L3", "color": "#fa8c16",
        "desc": "受限访问敏感数据，泄露后造成严重损害",
        "examples": ["个人信息", "客户资料", "合同", "财务报表"],
    },
    "top_secret": {
        "level": 4, "name": "绝密", "code": "L4", "color": "#ff4d4f",
        "desc": "极高敏感度核心数据，泄露后造成特别严重损害",
        "examples": ["核心算法", "密钥材料", "大规模PII库", "重要数据/核心数据"],
    },
}

# 业务域
BUSINESS_DOMAINS: Dict[str, Dict[str, Any]] = {
    "customer": {"name": "客户域", "desc": "客户/用户相关数据"},
    "finance": {"name": "财务域", "desc": "财务/资金/税务相关数据"},
    "hr": {"name": "人力域", "desc": "员工/人事/薪酬相关数据"},
    "product": {"name": "产品域", "desc": "产品/研发/技术相关数据"},
    "operation": {"name": "运营域", "desc": "运营/营销/活动相关数据"},
    "legal": {"name": "法务域", "desc": "法律/合规/合同相关数据"},
    "logistics": {"name": "供应链域", "desc": "供应链/物流/采购相关数据"},
    "management": {"name": "管理域", "desc": "战略/决策/管理相关数据"},
}

# 敏感数据识别正则库
SENSITIVE_PATTERNS: Dict[str, Dict[str, Any]] = {
    "id_card": {
        "name": "身份证号", "category": "personal_info", "risk": "high",
        "pattern": r"\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
        "desc": "中国居民身份证号（18位）",
    },
    "mobile_phone": {
        "name": "手机号", "category": "personal_info", "risk": "medium",
        "pattern": r"\b1[3-9]\d{9}\b",
        "desc": "中国大陆手机号",
    },
    "bank_card": {
        "name": "银行卡号", "category": "financial", "risk": "high",
        "pattern": r"\b[1-9]\d{14,18}\b",
        "desc": "银行卡号（15-19位数字）",
    },
    "credit_card": {
        "name": "信用卡号", "category": "payment", "risk": "critical",
        "pattern": r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|6(?:011|5\d{2})\d{12})\b",
        "desc": "Visa/MasterCard/Discover 信用卡号",
    },
    "email": {
        "name": "电子邮箱", "category": "personal_info", "risk": "low",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "desc": "电子邮件地址",
    },
    "passport": {
        "name": "护照号", "category": "personal_info", "risk": "high",
        "pattern": r"\b[A-Z]\d{8}\b",
        "desc": "中国护照号（字母+8位数字）",
    },
    "license_plate": {
        "name": "车牌号", "category": "personal_info", "risk": "low",
        "pattern": r"\b[\u4e00-\u9fa5][A-Z][A-Z0-9]{5,6}\b",
        "desc": "中国机动车号牌",
    },
    "ip_address": {
        "name": "IP地址", "category": "network", "risk": "low",
        "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "desc": "IPv4 地址",
    },
    "mac_address": {
        "name": "MAC地址", "category": "network", "risk": "low",
        "pattern": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b",
        "desc": "MAC 物理地址",
    },
    "password": {
        "name": "密码/密钥", "category": "credential", "risk": "critical",
        "pattern": r"(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token)\s*[:=]\s*\S+",
        "desc": "密码/密钥/Token 赋值模式",
    },
    "ssn": {
        "name": "SSN社保号", "category": "personal_info", "risk": "high",
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "desc": "美国 Social Security Number",
    },
    "medical_record": {
        "name": "病历号", "category": "health", "risk": "high",
        "pattern": r"(?i)(medical|patient|record)[_\-]?no\.?\s*[:=]?\s*\d{6,12}",
        "desc": "医疗病历号",
    },
    "tax_id": {
        "name": "税号", "category": "financial", "risk": "medium",
        "pattern": r"(?i)(tax[_\-]?id|tax[_\-]?no|tin|ein)\s*[:=]\s*[A-Z0-9]{8,15}",
        "desc": "纳税人识别号",
    },
    "address": {
        "name": "详细地址", "category": "personal_info", "risk": "medium",
        "pattern": r"[\u4e00-\u9fa5]{2,}(省|市|区|县|路|街|号|栋|单元|室)",
        "desc": "中国详细居住/通讯地址",
    },
    "date_of_birth": {
        "name": "出生日期", "category": "personal_info", "risk": "medium",
        "pattern": r"\b(19|20)\d{2}[-/年](0?[1-9]|1[0-2])[-/月](0?[1-9]|[12]\d|3[01])日?\b",
        "desc": "出生日期（YYYY-MM-DD 等格式）",
    },
}

# 字典匹配词库（用于模糊识别）
SENSITIVE_DICTIONARIES: Dict[str, List[str]] = {
    "medical_terms": ["诊断", "处方", "病历", "体检", "HIV", "乙肝", "抑郁", "癌症", "手术", "住院"],
    "financial_terms": ["工资", "薪资", "奖金", "分红", "贷款", "征信", "资产", "负债", "税务", "审计"],
    "hr_terms": ["劳动合同", "离职", "绩效", "考核", "晋升", "调岗", "辞退", "竞业限制"],
    "customer_terms": ["客户名单", "客户资料", "联系方式", "购买记录", "消费习惯", "偏好画像"],
    "secret_terms": ["核心算法", "源代码", "配方", "工艺", "战略", "并购", "投融资", "未公开"],
}

# 分类模板
CLASSIFICATION_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "financial_sector": {
        "name": "金融行业分类模板",
        "levels": ["public", "internal", "confidential", "top_secret"],
        "rules": ["客户身份证/银行卡=绝密", "交易流水=机密", "营销材料=内部", "公开公告=公开"],
    },
    "healthcare_sector": {
        "name": "医疗行业分类模板",
        "levels": ["public", "internal", "confidential", "top_secret"],
        "rules": ["病历/诊断=绝密", "患者信息=机密", "科室管理=内部", "医院介绍=公开"],
    },
    "ecommerce_sector": {
        "name": "电商行业分类模板",
        "levels": ["public", "internal", "confidential", "top_secret"],
        "rules": ["用户隐私数据=机密", "订单数据=机密", "运营数据=内部", "商品信息=公开"],
    },
}


class DataClassificationEngine:
    """数据分类分级深度引擎"""

    def __init__(self) -> None:
        self.assets: Dict[str, Dict[str, Any]] = {}
        self.classification_rules: List[Dict[str, Any]] = []
        self.grading_rules: List[Dict[str, Any]] = []
        self.tags: Dict[str, Dict[str, Any]] = {}
        self.scanning_tasks: Dict[str, Dict[str, Any]] = {}
        self._init_default_rules()
        self._seed_sample_assets()

    # ---------- 默认规则 ----------
    def _init_default_rules(self) -> None:
        self.classification_rules = [
            {"id": "cr001", "name": "身份证识别规则", "type": "regex",
             "pattern_key": "id_card", "target_category": "personal_info", "enabled": True},
            {"id": "cr002", "name": "手机号识别规则", "type": "regex",
             "pattern_key": "mobile_phone", "target_category": "personal_info", "enabled": True},
            {"id": "cr003", "name": "信用卡识别规则", "type": "regex",
             "pattern_key": "credit_card", "target_category": "payment", "enabled": True},
            {"id": "cr004", "name": "密码密钥识别规则", "type": "regex",
             "pattern_key": "password", "target_category": "credential", "enabled": True},
            {"id": "cr005", "name": "医疗术语字典", "type": "dictionary",
             "dictionary_key": "medical_terms", "target_category": "health", "enabled": True},
        ]
        self.grading_rules = [
            {"id": "gr001", "name": "含身份证→机密", "condition": "contains_type:id_card",
             "grade": "confidential", "priority": 10},
            {"id": "gr002", "name": "含信用卡→绝密", "condition": "contains_type:credit_card",
             "grade": "top_secret", "priority": 20},
            {"id": "gr003", "name": "含密码密钥→绝密", "condition": "contains_type:password",
             "grade": "top_secret", "priority": 20},
            {"id": "gr004", "name": "含病历→绝密", "condition": "contains_type:medical_record",
             "grade": "top_secret", "priority": 15},
            {"id": "gr005", "name": "含手机号→机密", "condition": "contains_type:mobile_phone",
             "grade": "confidential", "priority": 8},
        ]

    def _seed_sample_assets(self) -> None:
        samples = [
            {"name": "用户主库-客户表", "source_type": "database", "domain": "customer",
             "path": "mysql://prod-db/Users/customers", "size_mb": 2048},
            {"name": "交易流水文件", "source_type": "file_storage", "domain": "finance",
             "path": "/data/transactions/2026.csv", "size_mb": 512},
            {"name": "对象存储-合同扫描件", "source_type": "object_storage", "domain": "legal",
             "path": "s3://contracts/2026/", "size_mb": 10240},
            {"name": "API-用户查询接口", "source_type": "api", "domain": "customer",
             "path": "GET /api/v1/users/{id}", "size_mb": 0},
            {"name": "应用日志-访问日志", "source_type": "log", "domain": "operation",
             "path": "/var/log/app/access.log", "size_mb": 8192},
            {"name": "消息队列-订单队列", "source_type": "message_queue", "domain": "operation",
             "path": "kafka://cluster/orders", "size_mb": 0},
        ]
        for s in samples:
            aid = f"asset-{uuid.uuid4().hex[:8]}"
            self.assets[aid] = {
                "asset_id": aid, **s,
                "discovered_at": datetime.now().isoformat(timespec="seconds"),
                "classification": "pending", "grade": "pending",
                "owner": "未分配", "tags": [], "score": 0,
                "lifecycle": "active", "sensitivity_hits": [],
            }

    # ---------- 1. 数据资产发现 ----------
    def discover_assets(self, source_types: Optional[List[str]] = None,
                        scan_depth: str = "full") -> Dict[str, Any]:
        """自动扫描数据源发现数据资产"""
        try:
            sources = source_types or ["database", "file_storage", "object_storage",
                                       "api", "log", "message_queue"]
            task_id = f"discover-{uuid.uuid4().hex[:10]}"
            self.scanning_tasks[task_id] = {
                "task_id": task_id, "status": "running",
                "source_types": sources, "scan_depth": scan_depth,
                "found_count": 0, "created_at": datetime.now().isoformat(timespec="seconds"),
            }
            # 模拟扫描结果
            new_count = 0
            source_templates = {
                "database": ["订单库", "用户库", "日志库", "配置库"],
                "file_storage": ["财务报表.xlsx", "客户资料.pdf", "员工花名册.xlsx"],
                "object_storage": ["s3://bucket1/backups/", "oss://bucket2/photos/"],
                "api": ["POST /api/orders", "GET /api/reports", "PUT /api/users"],
                "log": ["/var/log/nginx/access.log", "/var/log/app/error.log"],
                "message_queue": ["kafka://topic/payments", "rabbitmq://queue/notifications"],
            }
            for src in sources:
                for tmpl in source_templates.get(src, []):
                    aid = f"asset-{uuid.uuid4().hex[:8]}"
                    self.assets[aid] = {
                        "asset_id": aid, "name": tmpl, "source_type": src,
                        "domain": self._guess_domain(tmpl),
                        "path": tmpl, "size_mb": 128,
                        "discovered_at": datetime.now().isoformat(timespec="seconds"),
                        "classification": "pending", "grade": "pending",
                        "owner": "未分配", "tags": [], "score": 0,
                        "lifecycle": "active", "sensitivity_hits": [],
                    }
                    new_count += 1
            self.scanning_tasks[task_id]["status"] = "completed"
            self.scanning_tasks[task_id]["found_count"] = new_count
            return {
                "task_id": task_id, "new_assets_found": new_count,
                "total_assets": len(self.assets),
                "source_types": sources, "status": "completed",
            }
        except Exception as e:
            return {"error": str(e)}

    def _guess_domain(self, name: str) -> str:
        n = name.lower()
        if any(k in n for k in ["user", "customer", "客户", "用户"]):
            return "customer"
        if any(k in n for k in ["finance", "pay", "order", "财务", "订单", "支付"]):
            return "finance"
        if any(k in n for k in ["hr", "employee", "员工", "人事"]):
            return "hr"
        if any(k in n for k in ["log", "access", "日志"]):
            return "operation"
        return "operation"

    # ---------- 2. 数据分类 ----------
    def classify_asset(self, asset_id: str, text_sample: str = "") -> Dict[str, Any]:
        """对单个资产进行分类"""
        if asset_id not in self.assets:
            return {"error": "资产不存在"}
        asset = self.assets[asset_id]
        hits = self._detect_sensitive(text_sample or asset.get("name", ""))
        asset["sensitivity_hits"] = hits
        # 按业务域分类
        asset["domain"] = self._guess_domain(asset.get("name", ""))
        # 按数据类型分类
        types = list({h["type"] for h in hits})
        asset["data_types"] = types
        # 按敏感度分类
        if hits:
            max_risk = max(h.get("risk", "low") for h in hits)
            risk_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            asset["sensitivity"] = max_risk if risk_order.get(max_risk, 0) >= 3 else "medium"
        else:
            asset["sensitivity"] = "low"
        asset["classification"] = "classified"
        return {
            "asset_id": asset_id, "domain": asset["domain"],
            "data_types": types, "sensitivity": asset["sensitivity"],
            "hits": len(hits),
        }

    def classify_batch(self, text_samples: Dict[str, str]) -> Dict[str, Any]:
        """批量分类：{asset_id: text_sample}"""
        results = {}
        for aid, txt in text_samples.items():
            results[aid] = self.classify_asset(aid, txt)
        return {"classified": len(results), "results": results}

    def get_classification_suggestions(self, asset_name: str) -> List[Dict[str, Any]]:
        """基于资产名称给出分类建议"""
        suggestions = []
        for key, pat in SENSITIVE_PATTERNS.items():
            if re.search(pat["pattern"], asset_name, re.IGNORECASE):
                suggestions.append({
                    "type": pat["name"], "category": pat["category"],
                    "risk": pat["risk"], "confidence": 0.85,
                })
        return suggestions

    # ---------- 3. 数据分级 ----------
    def auto_grade(self, asset_id: str) -> Dict[str, Any]:
        """根据分级规则自动定级"""
        if asset_id not in self.assets:
            return {"error": "资产不存在"}
        asset = self.assets[asset_id]
        hits = asset.get("sensitivity_hits", [])
        # 按规则优先级匹配
        best_grade = "internal"
        best_priority = 0
        for rule in self.grading_rules:
            if not rule.get("enabled", True):
                continue
            cond = rule["condition"]
            if cond.startswith("contains_type:"):
                tkey = cond.split(":", 1)[1]
                if any(h.get("type") == tkey for h in hits):
                    if rule["priority"] > best_priority:
                        best_priority = rule["priority"]
                        best_grade = rule["grade"]
        asset["grade"] = best_grade
        asset["graded_at"] = datetime.now().isoformat(timespec="seconds")
        return {
            "asset_id": asset_id, "grade": best_grade,
            "grade_name": CLASSIFICATION_LEVELS_DEEP[best_grade]["name"],
            "auto_graded": True,
        }

    def manual_grade(self, asset_id: str, grade: str, reviewer: str = "") -> Dict[str, Any]:
        """人工调整分级"""
        if asset_id not in self.assets:
            return {"error": "资产不存在"}
        if grade not in CLASSIFICATION_LEVELS_DEEP:
            return {"error": f"无效分级: {grade}"}
        asset = self.assets[asset_id]
        old = asset.get("grade")
        asset["grade"] = grade
        asset["reviewer"] = reviewer
        asset["manual_graded_at"] = datetime.now().isoformat(timespec="seconds")
        return {"asset_id": asset_id, "old_grade": old, "new_grade": grade, "reviewer": reviewer}

    def list_grading_rules(self) -> List[Dict[str, Any]]:
        return self.grading_rules

    def get_grading_standards(self) -> Dict[str, Any]:
        return CLASSIFICATION_LEVELS_DEEP

    # ---------- 4. 敏感数据识别 ----------
    def _detect_sensitive(self, text: str) -> List[Dict[str, Any]]:
        """正则+字典混合识别敏感数据"""
        hits = []
        for key, pat in SENSITIVE_PATTERNS.items():
            try:
                for m in re.finditer(pat["pattern"], text):
                    matched = m.group(0)
                    hits.append({
                        "type": key, "type_name": pat["name"],
                        "category": pat["category"], "risk": pat["risk"],
                        "match_length": len(matched),
                        "match_preview": matched[:3] + "***" + matched[-2:] if len(matched) > 5 else "***",
                        "position": m.start(),
                        "method": "regex",
                    })
            except re.error:
                continue
        # 字典匹配
        for dict_key, words in SENSITIVE_DICTIONARIES.items():
            for w in words:
                if w in text:
                    hits.append({
                        "type": f"dict_{dict_key}", "type_name": f"字典:{dict_key}",
                        "category": "semantic", "risk": "medium",
                        "match_word": w, "method": "dictionary",
                    })
        return hits

    def scan_text(self, text: str) -> Dict[str, Any]:
        """扫描文本，返回所有敏感数据命中"""
        hits = self._detect_sensitive(text)
        risk_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_risk = max((risk_order.get(h["risk"], 0) for h in hits), default=0)
        risk_name = {0: "无敏感", 1: "低", 2: "中", 3: "高", 4: "严重"}.get(max_risk, "未知")
        return {
            "text_length": len(text), "total_hits": len(hits),
            "max_risk_level": risk_name,
            "by_category": self._group_by(hits, "category"),
            "by_risk": self._group_by(hits, "risk"),
            "hits": hits[:50],  # 限制返回数量
        }

    def _group_by(self, items: List[Dict[str, Any]], key: str) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for it in items:
            k = it.get(key, "unknown")
            out[k] = out.get(k, 0) + 1
        return out

    # ---------- 5. 数据地图 ----------
    def get_data_map(self) -> Dict[str, Any]:
        """生成数据资产地图/分布"""
        by_domain: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        by_grade: Dict[str, int] = {}
        by_sensitivity: Dict[str, int] = {}
        for a in self.assets.values():
            d = a.get("domain", "unknown")
            by_domain[d] = by_domain.get(d, 0) + 1
            s = a.get("source_type", "unknown")
            by_source[s] = by_source.get(s, 0) + 1
            g = a.get("grade", "pending")
            by_grade[g] = by_grade.get(g, 0) + 1
            sen = a.get("sensitivity", "unknown")
            by_sensitivity[sen] = by_sensitivity.get(sen, 0) + 1
        return {
            "total_assets": len(self.assets),
            "by_domain": by_domain, "by_source_type": by_source,
            "by_grade": by_grade, "by_sensitivity": by_sensitivity,
            "heatmap": [
                {"domain": k, "count": v, "level": min(v, 10)}
                for k, v in by_domain.items()
            ],
        }

    def get_data_lineage(self) -> Dict[str, Any]:
        """数据血缘图（模拟）"""
        nodes = []
        edges = []
        for aid, a in list(self.assets.items())[:15]:
            nodes.append({
                "id": aid, "label": a.get("name", aid),
                "group": a.get("source_type", "unknown"),
                "grade": a.get("grade", "pending"),
            })
        # 模拟血缘边
        for i in range(min(20, len(nodes) - 1)):
            edges.append({
                "source": nodes[i]["id"], "target": nodes[i + 1]["id"],
                "type": "flow",
            })
        return {"nodes": nodes, "edges": edges, "total_nodes": len(nodes)}

    def get_data_flow(self) -> Dict[str, Any]:
        """数据流向图"""
        flows = [
            {"from": "用户端", "to": "API网关", "volume_gb": 120, "direction": "inbound"},
            {"from": "API网关", "to": "应用服务", "volume_gb": 110, "direction": "internal"},
            {"from": "应用服务", "to": "数据库", "volume_gb": 80, "direction": "internal"},
            {"from": "数据库", "to": "数据仓库", "volume_gb": 60, "direction": "outbound"},
            {"from": "数据仓库", "to": "BI报表", "volume_gb": 20, "direction": "outbound"},
            {"from": "应用服务", "to": "云存储", "volume_gb": 15, "direction": "outbound"},
        ]
        return {"flows": flows, "total_volume_gb": sum(f["volume_gb"] for f in flows)}

    # ---------- 6. 数据资产目录 ----------
    def list_assets(self, keyword: Optional[str] = None,
                   domain: Optional[str] = None,
                   grade: Optional[str] = None,
                   source_type: Optional[str] = None,
                   page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        items = list(self.assets.values())
        if keyword:
            kw = keyword.lower()
            items = [a for a in items if kw in a.get("name", "").lower()
                     or kw in a.get("path", "").lower()]
        if domain:
            items = [a for a in items if a.get("domain") == domain]
        if grade:
            items = [a for a in items if a.get("grade") == grade]
        if source_type:
            items = [a for a in items if a.get("source_type") == source_type]
        total = len(items)
        start = (page - 1) * page_size
        end = start + page_size
        return {
            "total": total, "page": page, "page_size": page_size,
            "items": items[start:end],
        }

    def get_asset_detail(self, asset_id: str) -> Dict[str, Any]:
        if asset_id not in self.assets:
            return {"error": "资产不存在"}
        return self.assets[asset_id]

    def update_asset(self, asset_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        if asset_id not in self.assets:
            return {"error": "资产不存在"}
        self.assets[asset_id].update(updates)
        return {"asset_id": asset_id, "updated": True}

    def add_tag(self, asset_id: str, tag: str) -> Dict[str, Any]:
        if asset_id not in self.assets:
            return {"error": "资产不存在"}
        if tag not in self.assets[asset_id]["tags"]:
            self.assets[asset_id]["tags"].append(tag)
        return {"asset_id": asset_id, "tags": self.assets[asset_id]["tags"]}

    def get_asset_score(self, asset_id: str) -> Dict[str, Any]:
        """资产评分：综合敏感度×分级×暴露面"""
        if asset_id not in self.assets:
            return {"error": "资产不存在"}
        a = self.assets[asset_id]
        risk_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        grade_order = {"public": 1, "internal": 2, "confidential": 3,
                       "top_secret": 4, "pending": 1}
        score = (
            risk_order.get(a.get("sensitivity", "low"), 1) * 10 +
            grade_order.get(a.get("grade", "pending"), 1) * 15 +
            len(a.get("sensitivity_hits", [])) * 5
        )
        return {"asset_id": asset_id, "score": score,
                "level": "高" if score > 80 else "中" if score > 40 else "低"}

    # ---------- 模板与统计 ----------
    def get_templates(self) -> Dict[str, Any]:
        return CLASSIFICATION_TEMPLATES

    def get_classification_rules(self) -> List[Dict[str, Any]]:
        return self.classification_rules

    def stats(self) -> Dict[str, Any]:
        graded = sum(1 for a in self.assets.values() if a.get("grade") not in ("pending", None))
        return {
            "total_assets": len(self.assets),
            "graded_assets": graded,
            "classification_coverage": round(graded / max(len(self.assets), 1) * 100, 1),
            "rules_count": len(self.classification_rules),
            "grading_rules_count": len(self.grading_rules),
            "templates": len(CLASSIFICATION_TEMPLATES),
            "patterns": len(SENSITIVE_PATTERNS),
            "dictionaries": len(SENSITIVE_DICTIONARIES),
        }


# 单例
_engine_instance: Optional[DataClassificationEngine] = None


def get_classification_engine() -> DataClassificationEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = DataClassificationEngine()
    return _engine_instance
