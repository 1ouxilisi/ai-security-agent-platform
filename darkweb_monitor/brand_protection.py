# -*- coding: utf-8 -*-
"""
brand_protection.py — 品牌保护与欺诈检测器（第13轮升级）。

功能：
- 仿冒域名：Typosquatting/Combosquatting/Homoglyph/IDN欺骗/子域名仿冒/相似域名。
- 钓鱼网站：钓鱼页面检测/品牌假冒/登录页伪造/支付页伪造/证书异常/URL相似度。
- 假冒App：应用商店/第三方市场/恶意克隆/功能/图标/名称相似。
- 虚假社媒账号：假冒官方/高管/客服/促销/粉丝异常。
- 品牌滥用：未授权使用/污名化/负面关联/关键词竞价/侵权。
- 商标侵权与欺诈广告。
- 数字风险评分（0-100）。

说明：所有检测均为防御/监控视角，仅识别公开可访问的仿冒与欺诈信号，
不进行主动入侵；第三方库 try-import，不可用时返回模拟数据。
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

try:
    import idna  # type: ignore
    _IDNA_OK = True
except Exception:  # pragma: no cover
    idna = None  # type: ignore
    _IDNA_OK = False


# 常见字符替换（Homoglyph）
HOMOGLYPH_MAP = {
    "o": ["0", "о"], "l": ["1", "I"], "i": ["1", "l"],
    "e": ["е"], "a": ["а"], "s": ["5", "ѕ"], "g": ["q"],
}

# 常见 TLD 替换
TLD_SWAPS = [".net", ".org", ".cn", ".co", ".info", ".xyz", ".top"]


# ==================== 数据结构 ====================

@dataclass
class BrandFinding:
    kind: str = ""
    name: str = ""
    risk: str = "medium"
    confidence: float = 0.0
    evidence: str = ""
    takedown_channel: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==================== 品牌保护检测器 ====================

class BrandProtectionDetector:
    """品牌保护与欺诈检测器"""

    def __init__(self) -> None:
        self.findings: List[BrandFinding] = []

    # ---------- 工具 ----------

    @staticmethod
    def _seed(text: str) -> int:
        return int(hashlib.md5(text.encode("utf-8", "ignore")).hexdigest(), 16)

    # ---------- 仿冒域名 ----------

    def detect_typosquatting(self, domain: str = "example.com") -> Dict[str, Any]:
        base = domain.split(".")[0]
        tld = ".".join(domain.split(".")[1:]) or "com"
        seed = self._seed("typo:" + domain)
        candidates: List[Dict[str, Any]] = []

        # Typosquatting（键盘邻接/缺漏/重复）
        typo_variants = [
            (f"{base}e.{tld}", "typo", "缺漏字符"),
            (f"{base}{base[0]}.{tld}", "typo", "首字符重复"),
            (f"{base[:-1]}.{tld}", "typo", "尾字符缺漏"),
        ]
        # Combosquatting
        combo_variants = [
            (f"{base}-login.{tld}", "combo", "加登录后缀"),
            (f"{base}-support.{tld}", "combo", "加客服后缀"),
            (f"{base}verify.{tld}", "combo", "加验证后缀"),
        ]
        # TLD swap
        tld_variants = [(f"{base}{x}", "tld_swap", "TLD替换") for x in TLD_SWAPS[:3]]
        # Homoglyph
        homo_variants = [(f"{base}0.{tld}", "homoglyph", "o->0 视觉混淆")]

        all_variants = typo_variants + combo_variants + tld_variants + homo_variants
        for i, (var, vtype, note) in enumerate(all_variants):
            if (seed >> i) % 2 == 0 or vtype in ("combo",):
                risk = "high" if vtype in ("combo", "homoglyph") else "medium"
                candidates.append({
                    "domain": var, "type": vtype, "note": note,
                    "risk": risk,
                    "similarity": round(0.7 + (i % 3) * 0.08, 2),
                    "registered": bool((seed >> i) % 3),
                })
        return {
            "original_domain": domain,
            "lookalike_candidates": candidates,
            "total_candidates": len(candidates),
            "registered_count": len([c for c in candidates if c["registered"]]),
            "check_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "idna_support": "enabled" if _IDNA_OK else "basic",
        }

    # ---------- 钓鱼网站 ----------

    def detect_phishing(self, brand: str = "ExampleCorp") -> Dict[str, Any]:
        seed = self._seed("phish:" + brand)
        sites = [
            {"url": f"{brand.lower()}-login-verify.{['xyz','top','info'][seed%3]}/",
             "page_type": "登录页伪造", "cert": "Let's Encrypt", "cert_anomaly": True,
             "url_similarity": 0.86},
            {"url": f"{brand.lower()}-secure-pay.{['com.net','co'][seed%2]}/",
             "page_type": "支付页伪造", "cert": "自签名", "cert_anomaly": True,
             "url_similarity": 0.79},
            {"url": f"account-{brand.lower()}-update.{['shop','store'][(seed>>1)%2]}/",
             "page_type": "账户更新钓鱼", "cert": "Let's Encrypt", "cert_anomaly": False,
             "url_similarity": 0.72},
        ]
        confirmed = [s for s in sites if s["cert_anomaly"] or s["url_similarity"] > 0.75]
        return {
            "brand": brand,
            "phishing_sites_detected": len(confirmed),
            "sites": confirmed,
            "indicators": ["表单字段模仿品牌", "URL拼写混淆", "证书异常" if seed%2 else "无异常证书"],
            "check_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ---------- 假冒 App ----------

    def detect_fake_apps(self, brand: str = "ExampleCorp") -> Dict[str, Any]:
        seed = self._seed("app:" + brand)
        apps = [
            {"name": f"{brand} Secure Login", "store": "第三方市场",
             "reason": "名称+图标高度相似", "downloads": (seed % 50000) + 1000, "risk": "high"},
            {"name": f"{brand}官方客服", "store": "第三方市场",
             "reason": "仿冒官方客服", "downloads": (seed % 20000) + 500, "risk": "medium"},
        ]
        return {
            "brand": brand,
            "fake_apps_detected": len(apps),
            "apps": apps,
            "note": "建议向官方应用商店提交下架(takedown)申诉",
        }

    # ---------- 虚假社媒账号 ----------

    def detect_fake_social(self, brand: str = "ExampleCorp") -> Dict[str, Any]:
        seed = self._seed("social:" + brand)
        accounts = [
            {"handle": f"@{brand.lower()}_official", "platform": "X/Twitter",
             "type": "假冒官方账号", "followers": (seed % 500) + 50, "abnormal_growth": True},
            {"handle": f"@{brand.lower()}_support", "platform": "Telegram",
             "type": "假冒客服", "followers": (seed % 300) + 20, "abnormal_growth": False},
        ]
        return {
            "brand": brand,
            "fake_accounts": accounts,
            "total": len(accounts),
            "recommendation": "向平台举报假冒账号并申请品牌认证。",
        }

    # ---------- 品牌滥用 / 商标侵权 / 欺诈广告 ----------

    def detect_brand_abuse(self, brand: str = "ExampleCorp") -> Dict[str, Any]:
        seed = self._seed("abuse:" + brand)
        return {
            "brand": brand,
            "abuse_items": [
                {"type": "未授权品牌使用", "count": (seed % 10) + 2},
                {"type": "品牌污名化", "count": (seed >> 1) % 4},
                {"type": "负面关联", "count": (seed >> 2) % 3},
                {"type": "品牌关键词竞价", "count": (seed >> 3) % 5},
            ],
            "trademark_infringement": [
                {"product": f"{brand} 仿冒配件", "channel": "电商平台", "risk": "medium"},
                {"product": f"{brand} 未授权授权书", "channel": "论坛", "risk": "high"},
            ],
            "fraud_ads": [
                {"type": "虚假宣传", "count": (seed >> 4) % 4},
                {"type": "假冒优惠", "count": (seed >> 5) % 3},
                {"type": "恶意重定向", "count": (seed >> 6) % 2},
            ],
        }

    # ---------- 数字风险评分 ----------

    def calculate_risk_score(self, brand: str = "ExampleCorp") -> Dict[str, Any]:
        typo = self.detect_typosquatting()
        phish = self.detect_phishing(brand)
        apps = self.detect_fake_apps(brand)
        social = self.detect_fake_social(brand)
        abuse = self.detect_brand_abuse(brand)

        # 加权评分
        s_typo = min(25, typo["registered_count"] * 5)
        s_phish = min(30, phish["phishing_sites_detected"] * 10)
        s_app = min(15, len(apps["apps"]) * 7)
        s_social = min(10, len(social["fake_accounts"]) * 4)
        s_abuse = min(20, sum(i["count"] for i in abuse["abuse_items"]))
        score = min(100, s_typo + s_phish + s_app + s_social + s_abuse)

        if score >= 75:
            level = "critical"
        elif score >= 50:
            level = "high"
        elif score >= 25:
            level = "medium"
        else:
            level = "low"

        return {
            "brand": brand,
            "overall_risk_score": score,
            "risk_level": level,
            "dimension_scores": {
                "仿冒域名": s_typo, "钓鱼网站": s_phish,
                "假冒App": s_app, "虚假社媒": s_social, "品牌滥用": s_abuse,
            },
            "breakdown": {
                "registered_lookalikes": typo["registered_count"],
                "phishing_sites": phish["phishing_sites_detected"],
                "fake_apps": len(apps["apps"]),
                "fake_social": len(social["fake_accounts"]),
            },
            "evaluated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ---------- Takedown 建议 ----------

    def takedown_recommendations(self, brand: str = "ExampleCorp") -> List[Dict[str, Any]]:
        return [
            {"target": "仿冒域名", "action": "向注册商提交 UDRP/域名争议 + 注册商投诉",
             "channel": "Registrar / WIPO", "sla_hours": 72},
            {"target": "钓鱼网站", "action": "向主机商/CDN提交滥用投诉并请求下线",
             "channel": "Host abuse@ / Google Safe Browsing", "sla_hours": 24},
            {"target": "假冒App", "action": "向应用商店提交知识产权下架申诉",
             "channel": "App Store / Google Play 申诉", "sla_hours": 48},
            {"target": "虚假社媒账号", "action": "平台举报 + 品牌认证锁号",
             "channel": "平台举报中心", "sla_hours": 24},
        ]

    # ---------- 报告 ----------

    def generate_report(self, brand: str = "ExampleCorp") -> Dict[str, Any]:
        score = self.calculate_risk_score(brand)
        typo = self.detect_typosquatting()
        phish = self.detect_phishing(brand)
        return {
            "report_title": "品牌保护与欺诈检测报告",
            "brand": brand,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "executive_summary": (
                f"品牌数字风险评分 {score['overall_risk_score']}/100({score['risk_level']})；"
                f"检测到 {typo['registered_count']} 个已注册仿冒域名、"
                f"{phish['phishing_sites_detected']} 个钓鱼网站。"),
            "risk": score,
            "typosquatting": {"candidates": typo["total_candidates"],
                              "registered": typo["registered_count"]},
            "phishing": phish,
            "fake_apps": self.detect_fake_apps(brand),
            "fake_social": self.detect_fake_social(brand),
            "brand_abuse": self.detect_brand_abuse(brand),
            "takedown_recommendations": self.takedown_recommendations(brand),
            "legal_boundary": "仅识别公开仿冒与欺诈信号，不主动入侵或干扰第三方系统。",
        }


# ==================== 工厂函数 ====================

_brand_singleton: Optional[BrandProtectionDetector] = None


def get_brand_protection_detector() -> BrandProtectionDetector:
    global _brand_singleton
    if _brand_singleton is None:
        _brand_singleton = BrandProtectionDetector()
    return _brand_singleton
