# -*- coding: utf-8 -*-
"""phishing_detector.py — 钓鱼邮件检测器。

覆盖：邮件头分析 / 内容分析 / URL 分析 / 附件分析 / 发件人信誉 / 综合评分。
全部规则引擎本地计算，不发起网络请求；第三方库 try-import 失败时自动回退。
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

# --------------------------------------------------------------------------- #
# 规则库
# --------------------------------------------------------------------------- #
URGENCY_PATTERNS = [
    "立即", "紧急", "马上", "final notice", "urgent", "act now", "限时",
    "账户将被冻结", "account suspended", "verify now", "立即验证", "within 24 hours",
    "last warning", "your account has been compromised", "密码即将过期",
]

BRAND_IMPERSONATION = [
    "paypal", "apple", "icloud", "microsoft", "office365", "dhl", "fedex",
    "ups", "amazon", "alibaba", "icbc", "cmbchina", "chinamobile", "chinatax",
    "微信", "支付宝", "银行", "税务", "社保", "海关", "快递", "客服中心",
]

CREDENTIAL_HARVEST_PATTERNS = [
    "verify your account", "confirm your password", "update your billing",
    "登录验证", "重新登录", "输入密码", "账户异常，请点击", "unusual login",
    "click here to login", "sign in required",
]

SUSPICIOUS_LINK_KEYWORDS = [
    "login", "verify", "update", "account", "secure", "confirm", "webscr",
    "signin", "redirect", "confirm-account", "validate",
]

SHORT_LINK_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "t.ly", "reurl.cc", "dwz.cn", "url.cn",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".msp", ".cpl",
    ".hta", ".gadget", ".lnk", ".jar", ".app",
}

MACRO_DOC_EXTENSIONS = {".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".ppsm"}
DOC_EXTENSIONS = {".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx", ".pdf"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".ace", ".iso", ".cab"}

KNOWN_BAD_URLS = {
    "http://secure-paypa1.com/login",
    "https://appleid-verify.xyz/signin",
    "http://office365-login-update.xyz/auth",
    "http://update-billing-alipay.cn/login",
    "http://dhl-tracking-update.top/parcel",
}

KNOWN_BAD_SENDERS = {
    "service@paypa1-support.xyz",
    "noreply@appleid-secure.xyz",
    "it-support@office365-auth.top",
}

# 常见银行/品牌官方域名（用于仿冒相似度比对）
TRUSTED_BRANDS = [
    "paypal.com", "apple.com", "microsoft.com", "office.com", "amazon.com",
    "alibaba.com", "icbc.com.cn", "cmbchina.com", "alipay.com", "weixin.qq.com",
]


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #
def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _extract_urls(text: str) -> List[str]:
    if not text:
        return []
    pat = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
    return pat.findall(text)


def _domain_of(url_or_email: str) -> str:
    s = (url_or_email or "").strip().lower()
    if "@" in s:
        s = s.split("@", 1)[1]
    if "://" in s:
        try:
            s = urlparse(s).netloc
        except Exception:
            pass
    if s.startswith("www."):
        s = s[4:]
    return s.split(":")[0]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                          prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _looks_typosquat(domain: str, trusted: List[str] = TRUSTED_BRANDS) -> Optional[str]:
    """若域名与某个可信品牌高度相似（字母替换/插入），返回可疑品牌。"""
    d = domain.split(":")[0]
    d = d.split(".")[0]  # 主名部分
    for brand in trusted:
        b = brand.split(".")[0]
        if d == b:
            continue
        if abs(len(d) - len(b)) <= 2 and _levenshtein(d, b) <= 2:
            return brand
        # 数字替换字母：paypa1
        digits_replaced = bool(re.search(r"\d", d)) and any(
            _levenshtein(re.sub(r"\d", "", d), b) <= 2 for _ in (0,)
        )
        if digits_replaced:
            return brand
    return None


def _is_double_extension(filename: str) -> bool:
    fn = filename.lower()
    parts = fn.split(".")
    if len(parts) < 3:
        return False
    tail = "." + parts[-1]
    second = "." + parts[-2]
    return tail in EXECUTABLE_EXTENSIONS and second in DOC_EXTENSIONS | {".pdf", ".jpg", ".png"}


def _sim_domain_age(domain: str) -> int:
    """模拟域名注册年龄（确定性伪随机，年）。真实环境应接 WHOIS/RDAP。"""
    h = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
    fresh = h % 100
    if fresh < 8:
        return fresh % 3          # 新域名 (<3年)
    return 3 + (h % 20)


# --------------------------------------------------------------------------- #
# 主检测器
# --------------------------------------------------------------------------- #
class PhishingDetector:
    """钓鱼邮件检测器。输入原始邮件文本（头+正文），输出结构化检测结果。"""

    def __init__(self) -> None:
        self.rules = self._build_rules()

    # ------------------------------------------------------------------ #
    # 规则库
    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_rules() -> List[Dict[str, Any]]:
        return [
            {"id": "PH-001", "name": "紧急/恐吓话术", "weight": 12,
             "category": "content", "enabled": True},
            {"id": "PH-002", "name": "凭证收割话术", "weight": 14,
             "category": "content", "enabled": True},
            {"id": "PH-003", "name": "品牌仿冒", "weight": 15,
             "category": "content", "enabled": True},
            {"id": "PH-004", "name": "可疑链接（短链/关键词）", "weight": 12,
             "category": "url", "enabled": True},
            {"id": "PH-005", "name": "URL 域名仿冒", "weight": 16,
             "category": "url", "enabled": True},
            {"id": "PH-006", "name": "新注册域名", "weight": 10,
             "category": "url", "enabled": True},
            {"id": "PH-007", "name": "已知钓鱼 URL 命中", "weight": 30,
             "category": "url", "enabled": True},
            {"id": "PH-008", "name": "可执行附件", "weight": 20,
             "category": "attachment", "enabled": True},
            {"id": "PH-009", "name": "双扩展名伪装", "weight": 18,
             "category": "attachment", "enabled": True},
            {"id": "PH-010", "name": "带宏文档附件", "weight": 12,
             "category": "attachment", "enabled": True},
            {"id": "PH-011", "name": "发件人与回复地址不一致", "weight": 14,
             "category": "header", "enabled": True},
            {"id": "PH-012", "name": "SPF/DKIM/DMARC 全部未通过", "weight": 18,
             "category": "header", "enabled": True},
            {"id": "PH-013", "name": "已知恶意发件人", "weight": 28,
             "category": "sender", "enabled": True},
            {"id": "PH-014", "name": "显示名仿冒但域名不符", "weight": 16,
             "category": "header", "enabled": True},
            {"id": "PH-015", "name": "语法/拼写异常密度高", "weight": 6,
             "category": "content", "enabled": True},
        ]

    # ------------------------------------------------------------------ #
    # 邮件头分析
    # ------------------------------------------------------------------ #
    def analyze_headers(self, raw: str) -> Dict[str, Any]:
        headers_block = raw.split("\n\n", 1)[0] if raw else ""
        lines = [ln.strip() for ln in headers_block.splitlines() if ln.strip()]
        headers: Dict[str, str] = {}
        received: List[str] = []
        for ln in lines:
            if ":" not in ln:
                continue
            k, v = ln.split(":", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "received":
                received.append(v)
            else:
                headers[k] = v

        from_addr = headers.get("from", "")
        reply_to = headers.get("reply-to", "")
        return_path = headers.get("return-path", "")
        subject = headers.get("subject", "")
        auth_res = headers.get("authentication-results", "")

        findings: List[Dict[str, Any]] = []
        from_domain = _domain_of(from_addr)
        reply_domain = _domain_of(reply_to)

        # PH-011 回复地址不一致
        if reply_to and from_domain and reply_domain and from_domain != reply_domain:
            findings.append({
                "rule_id": "PH-011", "severity": "high",
                "detail": f"From 域名 {from_domain} 与 Reply-To 域名 {reply_domain} 不一致",
            })

        # PH-014 显示名仿冒
        m = re.match(r'^"?([^"<]+?)"?\s*<([^>]+)>', from_addr)
        if m:
            display, addr = m.group(1).strip(), m.group(2).strip().lower()
            ddom = _domain_of(addr)
            for brand in TRUSTED_BRANDS:
                bname = brand.split(".")[0]
                if bname in display.lower() and ddom != brand:
                    findings.append({
                        "rule_id": "PH-014", "severity": "high",
                        "detail": f"显示名「{display}」仿冒 {brand}，实际域名 {ddom}",
                    })
                    break

        # 认证头解析
        spf_pass = "spf=pass" in auth_res.lower()
        dkim_pass = "dkim=pass" in auth_res.lower()
        dmarc_pass = "dmarc=pass" in auth_res.lower()
        auth_all_fail = bool(auth_res) and not (spf_pass or dkim_pass or dmarc_pass)
        if auth_all_fail:
            findings.append({
                "rule_id": "PH-012", "severity": "high",
                "detail": "SPF/DKIM/DMARC 在 Authentication-Results 中均未通过",
            })

        # Received 路由追踪
        hops = []
        for r in received[:6]:
            hops.append(r[:160])
        spoofed_route = False
        if len(received) >= 2:
            # 简单启发：首跳 HELO 主机名与 From 域名不一致不直接判定，仅记录
            spoofed_route = from_domain and from_domain not in received[-1]

        return {
            "from": from_addr, "reply_to": reply_to, "return_path": return_path,
            "subject": subject, "from_domain": from_domain,
            "received_hops": hops, "hop_count": len(received),
            "spoofed_route_suspect": spoofed_route,
            "spf_pass": spf_pass, "dkim_pass": dkim_pass, "dmarc_pass": dmarc_pass,
            "findings": findings,
        }

    # ------------------------------------------------------------------ #
    # 内容分析
    # ------------------------------------------------------------------ #
    def analyze_content(self, raw: str) -> Dict[str, Any]:
        body = raw.split("\n\n", 1)[1] if "\n\n" in raw else raw
        low = body.lower()
        hits: List[Dict[str, Any]] = []

        for kw in URGENCY_PATTERNS:
            if kw in low:
                hits.append({"type": "urgency", "keyword": kw})
        for kw in CREDENTIAL_HARVEST_PATTERNS:
            if kw in low:
                hits.append({"type": "credential", "keyword": kw})
        for brand in BRAND_IMPERSONATION:
            if brand in low:
                hits.append({"type": "brand_mention", "brand": brand})

        # 语法异常：全大写比例 / 感叹号密度
        upper_ratio = 0.0
        exclaim = 0
        letters = [c for c in body if c.isalpha()]
        if letters:
            upper_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
        exclaim = body.count("!")
        grammar_score = 0
        if upper_ratio > 0.35:
            grammar_score += 1
        if exclaim >= 3:
            grammar_score += 1

        return {
            "length": len(body),
            "urgency_hits": [h for h in hits if h["type"] == "urgency"],
            "credential_hits": [h for h in hits if h["type"] == "credential"],
            "brand_hits": [h for h in hits if h["type"] == "brand_mention"],
            "upper_ratio": round(upper_ratio, 3),
            "exclaim_count": exclaim,
            "grammar_abnormal": grammar_score,
            "total_hits": len(hits),
        }

    # ------------------------------------------------------------------ #
    # URL 分析
    # ------------------------------------------------------------------ #
    def analyze_urls(self, raw: str) -> Dict[str, Any]:
        urls = _extract_urls(raw)
        analyzed: List[Dict[str, Any]] = []
        suspicious: List[Dict[str, Any]] = []

        for u in urls[:40]:
            u_clean = u.rstrip('",.;)]>')
            host = _domain_of(u_clean)
            record: Dict[str, Any] = {
                "url": u_clean, "host": host,
                "is_short_link": host in SHORT_LINK_HOSTS,
                "expanded": None, "domain_age_years": _sim_domain_age(host),
                "typosquat_brand": None, "known_bad": False, "suspicious_kw": False,
            }
            if record["is_short_link"]:
                # 模拟展开：基于 hash 决定落地域（确定性）
                tail = hashlib.md5(u_clean.encode()).hexdigest()[:6]
                record["expanded"] = f"http://landing-{tail}.example-dynamic.net/path"
                host = _domain_of(record["expanded"])
            tq = _looks_typosquat(host)
            if tq:
                record["typosquat_brand"] = tq
            if u_clean in KNOWN_BAD_URLS or host in {_domain_of(x) for x in KNOWN_BAD_URLS}:
                record["known_bad"] = True
            if any(kw in u_clean.lower() for kw in SUSPICIOUS_LINK_KEYWORDS):
                record["suspicious_kw"] = True
            analyzed.append(record)

            if record["known_bad"] or record["typosquat_brand"] or \
               (record["is_short_link"] and record["domain_age_years"] < 1) or \
               record["suspicious_kw"] and record["domain_age_years"] < 2:
                suspicious.append(record)

        # URL 信誉评分：0-100，越高越危险
        danger = 0
        for r in analyzed:
            if r["known_bad"]:
                danger += 60
            if r["typosquat_brand"]:
                danger += 25
            if r["domain_age_years"] < 1:
                danger += 15
            if r["is_short_link"]:
                danger += 10
        reputation_score = min(100, danger)

        return {
            "urls": analyzed, "total": len(analyzed),
            "suspicious_urls": suspicious,
            "reputation_score": reputation_score,
        }

    # ------------------------------------------------------------------ #
    # 附件分析
    # ------------------------------------------------------------------ #
    def analyze_attachments(self, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        results: List[Dict[str, Any]] = []
        risky: List[Dict[str, Any]] = []
        for att in attachments:
            name = (att.get("filename") or att.get("name") or "").lower()
            ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
            r: Dict[str, Any] = {
                "filename": name or att.get("filename", "unnamed"),
                "extension": ext,
                "is_executable": ext in EXECUTABLE_EXTENSIONS,
                "is_macro_doc": ext in MACRO_DOC_EXTENSIONS,
                "is_archive": ext in ARCHIVE_EXTENSIONS,
                "is_double_ext": _is_double_extension(name),
                "size_bytes": att.get("size_bytes", 0),
            }
            r["risk"] = (r["is_executable"] or r["is_double_ext"]
                         or r["is_macro_doc"])
            results.append(r)
            if r["risk"]:
                risky.append(r)
        return {"attachments": results, "total": len(results),
                "risky": risky, "risky_count": len(risky)}

    # ------------------------------------------------------------------ #
    # 发件人信誉
    # ------------------------------------------------------------------ #
    def analyze_sender(self, from_addr: str) -> Dict[str, Any]:
        domain = _domain_of(from_addr)
        in_bad = from_addr.lower().strip() in KNOWN_BAD_SENDERS
        age = _sim_domain_age(domain)
        # 模拟历史发送量
        hist = int(hashlib.md5((domain + "hist").encode()).hexdigest()[:8], 16) % 5000
        reputation = 100
        if in_bad:
            reputation = 5
        elif age < 1:
            reputation = 35
        elif age < 3:
            reputation = 65
        return {
            "domain": domain,
            "in_known_bad_list": in_bad,
            "domain_age_years": age,
            "historical_volume": hist,
            "reputation_score": reputation,
            "asn": f"AS{13000 + (int(hashlib.md5(domain.encode()).hexdigest()[:4],16) % 800)}",
            "country": "CN" if ord(domain[-1:]) % 2 == 0 else "US",
        }

    # ------------------------------------------------------------------ #
    # 综合评分
    # ------------------------------------------------------------------ #
    def _level(self, score: int) -> Tuple[str, str]:
        if score >= 75:
            return "critical", "极高风险（高度疑似钓鱼）"
        if score >= 55:
            return "high", "高风险（疑似钓鱼）"
        if score >= 35:
            return "medium", "中风险（可疑）"
        return "low", "低风险"

    def detect(self, raw_email: str,
               attachments: Optional[List[Dict[str, Any]]] = None,
               from_addr: str = "") -> Dict[str, Any]:
        headers = self.analyze_headers(raw_email)
        content = self.analyze_content(raw_email)
        urls = self.analyze_urls(raw_email)
        atts = self.analyze_attachments(attachments or [])
        sender = self.analyze_sender(from_addr or headers["from"])

        # 加权评分
        score = 0
        triggered: List[Dict[str, Any]] = []

        if content["urgency_hits"]:
            score += 12; triggered.append({"rule_id": "PH-001", "points": 12})
        if content["credential_hits"]:
            score += 14; triggered.append({"rule_id": "PH-002", "points": 14})
        if content["brand_hits"]:
            score += 15; triggered.append({"rule_id": "PH-003", "points": 15})
        if urls["reputation_score"] >= 60:
            score += 30; triggered.append({"rule_id": "PH-007", "points": 30})
        elif urls["suspicious_urls"]:
            score += 12; triggered.append({"rule_id": "PH-004", "points": 12})
        if any(u["typosquat_brand"] for u in urls["urls"]):
            score += 16; triggered.append({"rule_id": "PH-005", "points": 16})
        if any(u["domain_age_years"] < 1 for u in urls["urls"]):
            score += 10; triggered.append({"rule_id": "PH-006", "points": 10})
        if any(a["is_executable"] for a in atts["attachments"]):
            score += 20; triggered.append({"rule_id": "PH-008", "points": 20})
        if any(a["is_double_ext"] for a in atts["attachments"]):
            score += 18; triggered.append({"rule_id": "PH-009", "points": 18})
        if any(a["is_macro_doc"] for a in atts["attachments"]):
            score += 12; triggered.append({"rule_id": "PH-010", "points": 12})
        for f in headers["findings"]:
            if f["rule_id"] == "PH-011":
                score += 14; triggered.append({"rule_id": "PH-011", "points": 14})
            if f["rule_id"] == "PH-012":
                score += 18; triggered.append({"rule_id": "PH-012", "points": 18})
            if f["rule_id"] == "PH-014":
                score += 16; triggered.append({"rule_id": "PH-014", "points": 16})
        if sender["in_known_bad_list"]:
            score += 28; triggered.append({"rule_id": "PH-013", "points": 28})
        if content["grammar_abnormal"]:
            score += 6; triggered.append({"rule_id": "PH-015", "points": 6})

        score = min(100, score)
        level, level_name = self._level(score)

        # 置信度：命中规则越多、关键规则权重越高，置信度越高
        conf = min(0.99, 0.4 + 0.05 * len(triggered) +
                   (0.15 if score >= 75 else 0.0))

        # 处置建议
        advice: List[str] = []
        if level in ("critical", "high"):
            advice.append("立即隔离邮件并阻止发件人，通知收件人不要点击任何链接或附件")
            advice.append("将邮件样本提交沙箱进一步分析，并上报威胁情报平台")
        elif level == "medium":
            advice.append("加入隔离区人工复核，提醒收件人核实发件人身份")
        if urls["suspicious_urls"]:
            advice.append("拦截全部可疑 URL 并加入本地信誉黑名单观察")
        if atts["risky"]:
            advice.append("禁止外发/落地可执行或双扩展名附件，通知终端 EDR 扫描")

        return {
            "scan_id": hashlib.md5((raw_email + str(time.time())).encode()).hexdigest()[:12],
            "scanned_at": _now(),
            "risk_score": score,
            "risk_level": level,
            "risk_level_name": level_name,
            "confidence": round(conf, 2),
            "dimensions": {
                "header": {"score": 100 - sum(1 for f in headers["findings"]) * 20,
                           "findings": headers["findings"]},
                "content": {"score": max(0, 100 - content["total_hits"] * 12),
                            "stats": {k: content[k] for k in
                                      ("urgency_hits", "credential_hits",
                                       "brand_hits", "grammar_abnormal")}},
                "url": {"score": 100 - urls["reputation_score"],
                        "reputation_score": urls["reputation_score"],
                        "suspicious_urls": urls["suspicious_urls"]},
                "attachment": {"score": 100 - atts["risky_count"] * 25,
                               "risky": atts["risky"]},
                "sender": {"score": sender["reputation_score"], "detail": sender},
            },
            "triggered_rules": triggered,
            "header_detail": headers,
            "content_detail": content,
            "url_detail": urls,
            "attachment_detail": atts,
            "sender_detail": sender,
            "disposition_advice": advice,
            "rules_used": len(self.rules),
        }

    def list_rules(self) -> List[Dict[str, Any]]:
        return self.rules
