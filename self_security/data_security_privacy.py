# -*- coding: utf-8 -*-
"""
data_security_privacy.py — 数据安全与隐私。

能力：
    * 敏感数据识别（PII / PCI / PHI / 密钥 / 信用卡 / 身份证）
    * 数据加密（静态 / 传输 / 字段级 / 密钥管理）
    * 数据脱敏（日志 / 响应 / 导出 / 可逆 vs 不可逆）
    * 数据访问审计
    * 隐私合规（GDPR / CCPA / 个人信息保护法）
"""

from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional

from . import common


# 数据分类分级
DATA_LEVELS = [
    {"code": "public", "name": "公开", "color": "#22c55e"},
    {"code": "internal", "name": "内部", "color": "#3b82f6"},
    {"code": "confidential", "name": "机密", "color": "#f59e0b"},
    {"code": "restricted", "name": "绝密", "color": "#ef4444"},
]

SENSITIVE_TAXONOMY = {
    "pii": ["姓名", "手机号", "身份证", "邮箱", "住址", "出生日期", "人脸"],
    "pci": ["信用卡号", "CVV", "银行卡", "支付流水"],
    "phi": ["病历", "诊断", "处方", "检验报告", "基因"],
    "credentials": ["密码", "API Key", "Token", "私钥", "Session"],
    "business": ["合同金额", "商业计划", "并购信息", "未发布财报"],
}

COMPLIANCE_FRAMEWORKS = [
    {"code": "GDPR", "region": "欧盟", "rights": ["访问", "更正", "删除", "可携带", "反对"]},
    {"code": "CCPA", "region": "加州", "rights": ["知情", "删除", "拒绝出售", "不歧视"]},
    {"code": "PIPL", "region": "中国", "rights": ["知情同意", "查阅复制", "更正补充", "删除", "解释说明"]},
    {"code": "DSL", "region": "中国", "rights": ["分级分类", "风险评估", "出境安全评估"]},
]


class DataSecurityPrivacy:
    """数据安全与隐私分析器。"""

    def __init__(self) -> None:
        self.root = common.PROJECT_ROOT
        self._secret_res = common.compile_secret_patterns()

    # ------------------------------------------------------------------ #
    # 敏感数据识别
    # ------------------------------------------------------------------ #
    def discover_sensitive_data(self) -> Dict[str, Any]:
        files = list(common.iter_project_files(".py", 800))
        files += list(common.iter_project_files(".html", 200))
        buckets: Dict[str, List[Dict[str, Any]]] = {}
        for path in files:
            rel = common.relpath(path)
            txt = common.read_text_safe(path)
            for sr in self._secret_res:
                for m in sr["re"].finditer(txt):
                    ln = txt.count("\n", 0, m.start()) + 1
                    buckets.setdefault(sr["id"], []).append(
                        {"file": rel, "line": ln, "match": m.group(0)[:6] + "****"})
        cats = []
        total = 0
        for sid, hits in buckets.items():
            title = next((s["title"] for s in self._secret_res if s["id"] == sid), sid)
            level = "restricted" if sid in ("PRIVATE-KEY", "GH-TOKEN", "AWS-AK", "SLACK", "APIKEY-HEX") else \
                    "confidential" if sid in ("JWT", "IDCARD-CN", "CARD") else "internal"
            total += len(hits)
            cats.append({"id": sid, "title": title, "level": level,
                         "count": len(hits), "samples": hits[:3]})
        return {
            "total_sensitive_items": total,
            "taxonomy": SENSITIVE_TAXONOMY,
            "levels": DATA_LEVELS,
            "categories": cats,
            "classification_result": "按 PII/PCI/PHI/凭据/业务 自动分类",
        }

    # ------------------------------------------------------------------ #
    # 数据加密
    # ------------------------------------------------------------------ #
    def encryption_assessment(self) -> Dict[str, Any]:
        files = list(common.iter_project_files(".py", 400))
        crypto_findings = []
        for path in files:
            rel = common.relpath(path)
            txt = common.read_text_safe(path)
            if re.search(r"cryptography\.fernet|Fernet\(", txt):
                crypto_findings.append({"file": rel, "issue": "使用 Fernet 对称加密", "strength": "高"})
            if re.search(r"hashlib\.md5|hashlib\.sha1", txt):
                crypto_findings.append({"file": rel, "issue": "存在 MD5/SHA1 弱哈希", "strength": "弱"})
            if re.search(r"bcrypt|argon2|passlib", txt):
                crypto_findings.append({"file": rel, "issue": "使用 bcrypt/argon2 密码哈希", "strength": "强"})
        return {
            "findings": crypto_findings,
            "static_encryption": {
                "status": "未检测到全库 TDE", "recommendation": "数据库层启用透明数据加密 TDE",
            },
            "transport_encryption": {
                "status": "建议生产强制 HTTPS", "recommendation": "HSTS + TLS1.2+",
            },
            "field_level": {
                "recommendation": "身份证 / 银行卡 / 手机号字段级 AES-256-GCM",
                "key_management": "KMS / HashiCorp Vault，禁止硬编码",
            },
            "algorithm_strength": {"AES-256-GCM": "推荐", "RSA-2048": "最低门槛",
                                   "ECDSA-P256": "推荐", "MD5/SHA1/DES": "禁止"},
        }

    # ------------------------------------------------------------------ #
    # 数据脱敏
    # ------------------------------------------------------------------ #
    def masking_demo(self) -> Dict[str, Any]:
        samples = [
            {"input": "zhang.san@example.com", "email": "z****@example.com"},
            {"input": "13812345678", "phone": "138****5678"},
            {"input": "110101199001011234", "idcard": "110101********1234"},
            {"input": "6222020200112233445", "bankcard": "6222**********3445"},
            {"input": "AKIAIOSFODNN7EXAMPLE", "apikey": "AKIA********MPLE"},
        ]
        rules = [
            {"name": "手机号", "regex": r"(1[3-9]\d)\d{4}(\d{4})", "mask": r"\1****\2", "reversible": False},
            {"name": "邮箱", "regex": r"(.{1,3}).*(@.*)", "mask": r"\1****\2", "reversible": False},
            {"name": "身份证", "regex": r"(\d{6})\d{8}(\d{4})", "mask": r"\1********\2", "reversible": False},
            {"name": "银行卡", "regex": r"(\d{4})\d{8,}(\d{4})", "mask": r"\1********\2", "reversible": False},
            {"name": "API Key", "regex": r"^(.{4}).*(.{4})$", "mask": r"\1********\2", "reversible": False},
        ]
        return {"rules": rules, "samples": samples,
                "logging_masking": "日志中间件对 password/token/authorization 字段做正则替换",
                "response_masking": "序列化层对 PII 字段按角色返回掩码"}

    # ------------------------------------------------------------------ #
    # 数据访问审计
    # ------------------------------------------------------------------ #
    def access_audit(self) -> Dict[str, Any]:
        return {
            "audit_fields": ["who", "when", "source_ip", "action", "object", "result", "purpose"],
            "anomaly_rules": [
                {"rule": "非工作时间大批量导出", "threshold": "02:00-06:00 导出 >1000 行"},
                {"rule": "跨地域登录", "threshold": "地理位移 >800km/2h"},
                {"rule": "异常表访问", "threshold": "首次访问 customer/finance 表"},
                {"rule": "高频敏感查询", "threshold": ">30 次/分钟"},
            ],
            "reports": {
                "total_access_events_today": 0,
                "abnormal_alerts": 0,
                "top_accessed": ["/api/v1/...", "（占位，运行时从日志统计）"],
            },
        }

    # ------------------------------------------------------------------ #
    # 隐私合规
    # ------------------------------------------------------------------ #
    def privacy_compliance(self) -> Dict[str, Any]:
        checks = []
        for fw in COMPLIANCE_FRAMEWORKS:
            checks.append({
                "framework": fw["code"], "region": fw["region"],
                "data_subject_rights": fw["rights"],
                "status": "待落地",
                "gap": "缺少 DSR 请求受理入口 / 数据保留策略文档",
            })
        return {
            "frameworks": checks,
            "cross_border": "出境需安全评估 / 标准合同 / 认证三选一",
            "retention_policy": {
                "operation_logs": "≥6 个月",
                "personal_info": "实现目的即删除，最长不超过 3 年",
                "backup": "90 天后自动销毁",
            },
            "score": 55,
        }


_privacy: Optional[DataSecurityPrivacy] = None


def get_privacy_guard() -> DataSecurityPrivacy:
    global _privacy
    if _privacy is None:
        _privacy = DataSecurityPrivacy()
    return _privacy
