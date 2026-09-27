# -*- coding: utf-8 -*-
"""bec_detector.py — BEC（商业邮件欺诈）检测器，内置 50+ 可配置规则库。

覆盖：攻击者画像 / 攻击链检测 / 异常检测 / 付款欺诈 / 供应商入侵 / 规则库管理。
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List, Optional

from .phishing_detector import _domain_of, _extract_urls


# --------------------------------------------------------------------------- #
# 50+ BEC 规则库
# --------------------------------------------------------------------------- #
def _build_bec_rules() -> List[Dict[str, Any]]:
    R: List[Dict[str, Any]] = []
    # —— A. 冒充角色类（10 条） —— #
    roles = [
        ("BEC-A01", "冒充CEO/董事长", "impersonation", "高管"),
        ("BEC-A02", "冒充CFO/财务总监", "impersonation", "高管"),
        ("BEC-A03", "冒充供应商/合作方", "impersonation", "供应商"),
        ("BEC-A04", "冒充客户/采购方", "impersonation", "客户"),
        ("BEC-A05", "冒充外部律师/律所", "impersonation", "律师"),
        ("BEC-A06", "冒充HR/人事部门", "impersonation", "HR"),
        ("BEC-A07", "冒充银行工作人员", "impersonation", "金融"),
        ("BEC-A08", "冒充税务/海关人员", "impersonation", "政府"),
        ("BEC-A09", "冒充IT/系统管理员", "impersonation", "IT"),
        ("BEC-A10", "冒充董事会/审计委员会", "impersonation", "高管"),
    ]
    for rid, name, cat, role in roles:
        R.append({"id": rid, "name": name, "category": cat, "role": role,
                  "severity": "high", "weight": 18, "enabled": True,
                  "industry": "通用"})

    # —— B. 付款欺诈类（14 条） —— #
    pay = [
        ("BEC-B01", "要求更改银行收款账户", "payment", 25),
        ("BEC-B02", "要求紧急付款/限时转账", "payment", 22),
        ("BEC-B03", "要求保密/不得电话确认", "payment", 20),
        ("BEC-B04", "要求绕过正常审批流程", "payment", 24),
        ("BEC-B05", "提供新收款账户信息", "payment", 23),
        ("BEC-B06", "付款到个人账户而非公司账户", "payment", 26),
        ("BEC-B07", "要求使用加密货币支付", "payment", 28),
        ("BEC-B08", "要求国际电汇/Wire", "payment", 15),
        ("BEC-B09", "要求拆分多笔小额付款", "payment", 16),
        ("BEC-B10", "要求立即执行并稍后补单", "payment", 18),
        ("BEC-B11", "金额异常偏离历史均值", "payment", 14),
        ("BEC-B12", "付款时间异常（深夜/节假日）", "payment", 12),
        ("BEC-B13", "要求删除邮件/保持沉默", "payment", 19),
        ("BEC-B14", "提供转账确认截图伪造", "payment", 21),
    ]
    for rid, name, cat, w in pay:
        R.append({"id": rid, "name": name, "category": cat, "role": "财务",
                  "severity": "critical" if w >= 22 else "high",
                  "weight": w, "enabled": True, "industry": "通用"})

    # —— C. 供应商入侵类（8 条） —— #
    sup = [
        ("BEC-C01", "供应商首次使用新邮箱联系", "supplier", 18),
        ("BEC-C02", "供应商收款账户变更通知", "supplier", 25),
        ("BEC-C03", "供应商突然要求加急付款", "supplier", 20),
        ("BEC-C04", "供应商沟通方式突变（电话→邮件）", "supplier", 14),
        ("BEC-C05", "供应商邮件签名/抬头变化", "supplier", 12),
        ("BEC-C06", "供应商域名拼写轻微差异", "supplier", 24),
        ("BEC-C07", "供应商历史合作记录突然中断", "supplier", 10),
        ("BEC-C08", "供应商请求修改合同条款", "supplier", 11),
    ]
    for rid, name, cat, w in sup:
        R.append({"id": rid, "name": name, "category": cat, "role": "供应商",
                  "severity": "high" if w >= 20 else "medium",
                  "weight": w, "enabled": True, "industry": "制造业/贸易"})

    # —— D. 异常行为类（10 条） —— #
    ano = [
        ("BEC-D01", "异常发件人（首次联系财务）", "anomaly", 15),
        ("BEC-D02", "异常收件人（高管→基层财务直邮）", "anomaly", 13),
        ("BEC-D03", "异常发送时间（非工作时间）", "anomaly", 8),
        ("BEC-D04", "异常语言风格（高管突然口语化）", "anomaly", 10),
        ("BEC-D05", "附件为异常格式 PDF/Excel", "anomaly", 9),
        ("BEC-D06", "邮件正文中含银行账户格式串", "anomaly", 17),
        ("BEC-D07", "域名年龄<30天", "anomaly", 16),
        ("BEC-D08", "SPF/DKIM/DMARC 未对齐", "anomaly", 14),
        ("BEC-D09", "Reply-To 与 From 不一致", "anomaly", 12),
        ("BEC-D10", "嵌入图片伪造公司 Logo", "anomaly", 11),
    ]
    for rid, name, cat, w in ano:
        R.append({"id": rid, "name": name, "category": cat, "role": "通用",
                  "severity": "medium" if w < 12 else "high",
                  "weight": w, "enabled": True, "industry": "通用"})

    # —— E. 攻击链/社工类（10 条） —— #
    chain = [
        ("BEC-E01", "先建立信任（寒暄/会议安排）", "chain", 6),
        ("BEC-E02", "随后提出财务请求", "chain", 20),
        ("BEC-E03", "引用虚假紧急事由（并购/审计）", "chain", 16),
        ("BEC-E04", "要求线下/加密通讯", "chain", 13),
        ("BEC-E05", "诱导点击恶意链接下载付款软件", "chain", 18),
        ("BEC-E06", "伪造合同/发票附件", "chain", 17),
        ("BEC-E07", "冒充律所处理虚假诉讼", "chain", 15),
        ("BEC-E08", "礼品卡/代金券支付要求", "chain", 19),
        ("BEC-E09", "目标为HR payroll 修改工资账户", "chain", 21),
        ("BEC-E10", "数据窃取（W-2/工资单）请求", "chain", 22),
    ]
    for rid, name, cat, w in chain:
        R.append({"id": rid, "name": name, "category": cat, "role": "社工",
                  "severity": "high", "weight": w, "enabled": True,
                  "industry": "通用"})
    return R


BEC_RULES_LIBRARY = _build_bec_rules()


# 话术关键词映射到规则
_PATTERN_MAP: Dict[str, List[str]] = {
    "BEC-A01": ["ceo", "董事长", "王总", "李总", "我现在在开会", "call me now"],
    "BEC-A02": ["cfo", "财务总监", "首席财务"],
    "BEC-A03": ["supplier", "供应商", "vendor", "合作方"],
    "BEC-A04": ["customer", "客户", "采购方"],
    "BEC-A05": ["lawyer", "律所", "律师", "legal", "attorney"],
    "BEC-A06": ["hr", "人事部", "薪酬", "payroll"],
    "BEC-A07": ["bank", "银行", "客户经理"],
    "BEC-A08": ["tax", "税务", "海关", "customs"],
    "BEC-A09": ["it", "系统管理员", "helpdesk", "技术支持"],
    "BEC-B01": ["change bank", "新账户", "更新收款", "修改收款", "new bank details",
                "bank account has been changed"],
    "BEC-B02": ["urgent", "紧急", "asap", "立即付款", "紧急付款", "today"],
    "BEC-B03": ["confidential", "保密", "do not call", "不要电话", "保密处理", "between us"],
    "BEC-B04": ["bypass", "绕过", "skip approval", "先执行后补流程"],
    "BEC-B05": ["beneficiary", "收款方", "swift", "iban", "6222", "6217"],
    "BEC-B06": ["personal account", "个人账户", "私人账户"],
    "BEC-B07": ["bitcoin", "btc", "usdt", "加密货币", "crypto"],
    "BEC-B08": ["wire transfer", "电汇", "telegraphic"],
    "BEC-B09": ["split", "分笔", "拆分", "multiple small"],
    "BEC-B10": ["do it now", "稍后补单", "after approval", "later"],
    "BEC-B13": ["delete this email", "删除此邮件", "keep quiet", "stay silent"],
    "BEC-E03": ["merger", "并购", "audit", "审计", "acquisition", "acq"],
    "BEC-E04": ["whatsapp", "signal", "telegram", "wechat", "私聊"],
    "BEC-E07": ["lawsuit", "诉讼", "court", "settlement"],
    "BEC-E08": ["gift card", "礼品卡", "google play", "itunes card"],
    "BEC-E09": ["payroll", "工资单", "salary", "banking info update"],
    "BEC-E10": ["w-2", "w2", "payroll record", "employee list"],
}

BANK_ACCOUNT_RE = re.compile(
    r"\b(?:\d{16,19}|[A-Z]{2}\d{2}[A-Z0-9]{10,30})\b")
SWIFT_RE = re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b")


class BECDetector:
    """BEC 商业邮件欺诈检测器。"""

    def __init__(self) -> None:
        self.rules: List[Dict[str, Any]] = [dict(r) for r in BEC_RULES_LIBRARY]

    # ------------------------------------------------------------------ #
    # 规则管理
    # ------------------------------------------------------------------ #
    def list_rules(self, category: Optional[str] = None,
                   enabled_only: bool = False) -> List[Dict[str, Any]]:
        out = self.rules
        if category:
            out = [r for r in out if r["category"] == category]
        if enabled_only:
            out = [r for r in out if r["enabled"]]
        return out

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> bool:
        for r in self.rules:
            if r["id"] == rule_id:
                r["enabled"] = enabled
                return True
        return False

    def rule_categories(self) -> Dict[str, int]:
        d: Dict[str, int] = {}
        for r in self.rules:
            d[r["category"]] = d.get(r["category"], 0) + 1
        return d

    # ------------------------------------------------------------------ #
    # 攻击者画像
    # ------------------------------------------------------------------ #
    def _profile_attacker(self, text_low: str) -> Dict[str, Any]:
        roles: List[str] = []
        for rid in ("BEC-A01", "BEC-A02", "BEC-A03", "BEC-A04", "BEC-A05",
                    "BEC-A06", "BEC-A07", "BEC-A08", "BEC-A09", "BEC-A10"):
            kws = _PATTERN_MAP.get(rid, [])
            if any(k in text_low for k in kws):
                roles.append(next(r["role"] for r in self.rules if r["id"] == rid))
        tone = "urgent" if ("urgent" in text_low or "紧急" in text_low) else \
               ("formal" if any(x in text_low for x in
                                 ("dear", "尊敬", "sincerely", "此致敬礼")) else "casual")
        return {"impersonated_roles": roles or ["未知"], "tone": tone,
                "tone_imitation_risk": bool(roles)}

    # ------------------------------------------------------------------ #
    # 异常检测
    # ------------------------------------------------------------------ #
    def _detect_anomalies(self, text: str, meta: Dict[str, Any]) -> List[Dict[str, Any]]:
        text_low = text.lower()
        found: List[Dict[str, Any]] = []
        if BANK_ACCOUNT_RE.search(text) or SWIFT_RE.search(text):
            found.append({"rule_id": "BEC-D06", "detail": "正文中检测到银行账户/SWIFT 串"})
        if meta.get("domain_age_days", 999) < 30:
            found.append({"rule_id": "BEC-D07", "detail": f"发件域名年龄 {meta.get('domain_age_days')} 天"})
        if meta.get("spf_aligned") is False or meta.get("dmarc_aligned") is False:
            found.append({"rule_id": "BEC-D08", "detail": "邮件认证未对齐"})
        if meta.get("from_domain") and meta.get("reply_to_domain") and \
                meta["from_domain"] != meta["reply_to_domain"]:
            found.append({"rule_id": "BEC-D09", "detail": "From 与 Reply-To 不一致"})
        if meta.get("attachments"):
            found.append({"rule_id": "BEC-D05",
                          "detail": f"附带 {len(meta['attachments'])} 个附件"})
        hour = meta.get("hour", 12)
        if hour < 7 or hour > 21:
            found.append({"rule_id": "BEC-D03", "detail": f"发送时间 {hour}:00（非工作时间）"})
        if meta.get("amount") and meta.get("usual_amount") and \
                meta["amount"] > meta["usual_amount"] * 3:
            found.append({"rule_id": "BEC-B11",
                          "detail": f"金额 {meta['amount']} 超出历史均值 3 倍"})
        return found

    # ------------------------------------------------------------------ #
    # 攻击链
    # ------------------------------------------------------------------ #
    def _build_chain(self, text_low: str) -> List[Dict[str, Any]]:
        steps: List[Dict[str, Any]] = []
        if any(k in text_low for k in ("meeting", "会议", "hello", "你好")):
            steps.append({"stage": "初次接触", "rule_id": "BEC-E01",
                          "detail": "寒暄/会议安排建立联系"})
        if any(k in text_low for k in _PATTERN_MAP["BEC-B01"] + _PATTERN_MAP["BEC-B05"]):
            steps.append({"stage": "建立信任/提出请求", "rule_id": "BEC-B05",
                          "detail": "提出收款账户变更"})
        if any(k in text_low for k in _PATTERN_MAP["BEC-B02"]):
            steps.append({"stage": "施压执行", "rule_id": "BEC-B02",
                          "detail": "催促紧急付款"})
        if any(k in text_low for k in _PATTERN_MAP["BEC-B03"] + _PATTERN_MAP["BEC-B13"]):
            steps.append({"stage": "消除阻力", "rule_id": "BEC-B03",
                          "detail": "要求保密、绕过电话确认"})
        return steps

    # ------------------------------------------------------------------ #
    # 主检测
    # ------------------------------------------------------------------ #
    def detect(self, email_text: str,
               meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        meta = meta or {}
        low = email_text.lower()
        triggered: List[Dict[str, Any]] = []
        score = 0

        for rid, kws in _PATTERN_MAP.items():
            if any(k in low for k in kws):
                rule = next((r for r in self.rules if r["id"] == rid), None)
                if rule and rule["enabled"]:
                    triggered.append({"rule_id": rid, "name": rule["name"],
                                      "weight": rule["weight"],
                                      "severity": rule["severity"]})
                    score += rule["weight"]

        anomalies = self._detect_anomalies(email_text, meta)
        for a in anomalies:
            rule = next((r for r in self.rules if r["id"] == a["rule_id"]), None)
            if rule and rule["enabled"]:
                triggered.append({"rule_id": a["rule_id"], "name": rule["name"],
                                  "weight": rule["weight"], "severity": rule["severity"]})
                score += rule["weight"]

        chain = self._build_chain(low)
        profile = self._profile_attacker(low)

        score = min(100, score)
        if score >= 70:
            level = "critical"; level_name = "极高风险（疑似BEC攻击）"
        elif score >= 45:
            level = "high"; level_name = "高风险（疑似付款欺诈）"
        elif score >= 25:
            level = "medium"; level_name = "中风险（可疑沟通）"
        else:
            level = "low"; level_name = "低风险"

        # 供应商监控
        supplier_alert = any(t["rule_id"].startswith("BEC-C") for t in triggered)

        advice: List[str] = []
        if level in ("critical", "high"):
            advice.append("立即冻结该笔付款，通过已知电话/双通道回呼发件人核实")
            advice.append("财务执行 'Verify Payee' 流程，核对供应商主数据")
            advice.append("将该邮件及往来链转安全团队做入侵溯源")
        if supplier_alert:
            advice.append("标记供应商邮箱可能被入侵，通知供应商 IT 检查邮箱凭据")

        return {
            "scan_id": hashlib.md5((email_text + str(time.time())).encode()).hexdigest()[:12],
            "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "bec_score": score,
            "risk_level": level,
            "risk_level_name": level_name,
            "attacker_profile": profile,
            "attack_chain": chain,
            "anomalies": anomalies,
            "triggered_rules": triggered,
            "rules_hit": len(triggered),
            "total_rules": len(self.rules),
            "supplier_monitor_alert": supplier_alert,
            "disposition_advice": advice,
        }

    # ------------------------------------------------------------------ #
    # 供应商监控列表
    # ------------------------------------------------------------------ #
    def supplier_watchlist(self) -> List[Dict[str, Any]]:
        return [
            {"supplier_id": "SUP-1001", "name": "深圳华创电子", "status": "normal",
             "last_contact": "2026-09-10", "bank_account_changed": False,
             "anomaly_score": 5},
            {"supplier_id": "SUP-1042", "name": "苏州精密模具厂", "status": "watch",
             "last_contact": "2026-09-13", "bank_account_changed": True,
             "anomaly_score": 68},
            {"supplier_id": "SUP-1087", "name": "广州物流公司", "status": "alert",
             "last_contact": "2026-09-14", "bank_account_changed": True,
             "anomaly_score": 86},
        ]
