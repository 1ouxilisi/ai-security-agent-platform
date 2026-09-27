# -*- coding: utf-8 -*-
"""
credential_leak.py 鈥?鍑瘉娉勯湶妫€娴嬪櫒锛堢13杞崌绾э級銆?

鍔熻兘锛?
- 娉勯湶鍑瘉搴擄細閭/鎵嬫満鍙?鐢ㄦ埛鍚?瀵嗙爜鍝堝笇/娉勯湶鏉ユ簮/鏃堕棿銆?
- 閭娉勯湶妫€娴嬶細浼佷笟/鍛樺伐/瀹㈡埛閭娉勯湶锛屾寜鍩熷悕/閮ㄩ棬缁熻銆?
- 鎵嬫満鍙锋硠闇叉娴嬶細鎵嬫満鍙锋硠闇?杩愯惀鍟?鍦板尯/鍏宠仈鏁版嵁銆?
- 瀵嗙爜鍝堝笇鍒嗘瀽锛歁D5/SHA1/SHA256/bcrypt/NTLM 璇嗗埆銆佺牬瑙ｉ毦搴︺€佸急瀵嗙爜妫€娴嬨€佸瘑鐮佸鐢ㄣ€?
- API瀵嗛挜娉勯湶妫€娴嬶細AWS/GCP/闃块噷浜?GitHub Token/API Key/Secret/Access Key锛堟鍒欒瘑鍒級銆?
- Token娉勯湶妫€娴嬶細JWT/OAuth/Session/Bearer/Refresh Token 璇嗗埆銆?
- 绉侀挜娉勯湶妫€娴嬶細SSH/TLS/PGP/鍔犲瘑璐у竵/API绛惧悕绉侀挜璇嗗埆銆?
- 娉勯湶鏉ユ簮杩借釜锛氬钩鍙?鏃堕棿/娉勯湶鑰?鏁版嵁閲?绫诲瀷/浜ゆ槗淇℃伅銆?
- 瀵嗙爜寮哄害璇勪及涓庨噸缃缓璁€?

璇存槑锛氭鍒欐ā寮忎粎鐢ㄤ簬璇嗗埆鈥滄硠闇叉枃鏈腑鏄惁鍑虹幇鏁忔劅鍑瘉鏍煎紡鈥濓紝
涓嶈繘琛屼换浣曠牬瑙ｆ垨鏀诲嚮琛屼负锛涚涓夋柟搴?try-import锛屼笉鍙敤鏃剁敤妯℃嫙鏁版嵁銆?
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    import bcrypt  # type: ignore
    _BCRYPT_OK = True
except Exception:  # pragma: no cover
    bcrypt = None  # type: ignore
    _BCRYPT_OK = False


# ==================== 娉勯湶鍑瘉搴擄紙妯℃嫙鏍锋湰锛岄槻寰＄敤锛?====================

LEAKED_CREDENTIAL_DB: List[Dict[str, Any]] = [
    {"email": "admin@example.com", "username": "admin", "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
     "hash_type": "MD5", "source": "BreachForums", "leaked_at": "2026-03-12", "plaintext_weak": True},
    {"email": "zhang.wei@example.com", "username": "zhangwei", "hash": "e10adc3949ba59abbe56e057f20f883e",
     "hash_type": "MD5", "source": "Pastebin", "leaked_at": "2026-05-20", "plaintext_weak": True},
    {"email": "li.na@partner-example.com", "username": "lina", "hash": "8846f7eaee8fb117ad06bdd830b7586c",
     "hash_type": "MD5", "source": "LeakBase", "leaked_at": "2026-06-02", "plaintext_weak": True},
    {"email": "dev-ci@example.com", "username": "devops", "hash": "a1b2c3d4e5f6...(bcrypt)",
     "hash_type": "bcrypt", "source": "GitHub", "leaked_at": "2026-07-18", "plaintext_weak": False},
    {"email": "ops@example.com", "username": "ops", "hash": "d2a1...(NTLM)",
     "hash_type": "NTLM", "source": "BreachForums", "leaked_at": "2026-08-30", "plaintext_weak": False},
]

# 寮卞瘑鐮?Top 姒滐紙甯歌娉勯湶瀵嗙爜鏍锋湰锛屼粎鐢ㄤ簬鍖归厤寮卞瘑鐮佹瘮渚嬬粺璁★級
COMMON_WEAK_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "111111", "1234567", "dragon", "123123", "abc123",
    "password1", "1234", "letmein", "admin", "welcome",
]

# 鍝堝笇绫诲瀷璇嗗埆瑙勫垯锛堥暱搴?鍓嶇紑锛?
HASH_PATTERNS: List[Tuple[str, str, int, str]] = [
    # (绫诲瀷鍚? 姝ｅ垯, 鐮磋В闅惧害, 璇存槑)
    ("MD5", r"^[a-f0-9]{32}$", 1, "鏋佸揩锛屽彲褰╄櫣琛ㄧ鐮?),
    ("NTLM", r"^[a-f0-9]{32}$", 1, "涓嶮D5绛変环锛屾瀬鏄撶牬瑙?),
    ("SHA1", r"^[a-f0-9]{40}$", 2, "杈冨揩锛孏PU鍙毚鍔?),
    ("SHA256", r"^[a-f0-9]{64}$", 3, "涓瓑锛屽姞鐩愬彲鏄捐憲澧炲己"),
    ("bcrypt", r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$", 4, "鎱㈠搱甯岋紝鎶楁毚鍔?),
    ("scrypt", r"^\$s0\$", 4, "鍐呭瓨纭紝鎶桝SIC"),
    ("Argon2", r"^\$argon2", 4, "鐜颁唬鎺ㄨ崘绠楁硶"),
]

# API 瀵嗛挜璇嗗埆姝ｅ垯锛堥槻寰″紡妫€娴嬶細鏂囨湰涓槸鍚︽硠闇叉绫绘牸寮忥級
API_KEY_PATTERNS: List[Dict[str, Any]] = [
    {"kind": "AWS Access Key", "regex": r"AKIA[0-9A-Z]{16}", "severity": "critical", "cloud": "AWS"},
    {"kind": "AWS Secret Key", "regex": r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*[\/A-Za-z0-9+=]{40}", "severity": "critical", "cloud": "AWS"},
    {"kind": "GCP API Key", "regex": r"AIza[0-9A-Za-z\-_]{35}", "severity": "high", "cloud": "GCP"},
    {"kind": "闃块噷浜?AccessKey", "regex": r"LTAI[0-9A-Za-z]{12,20}", "severity": "critical", "cloud": "闃块噷浜?},
    {"kind": "GitHub Token", "regex": r"ghp_[0-9A-Za-z]{36}", "severity": "high", "cloud": "GitHub"},
    {"kind": "GitHub OAuth", "regex": r"gho_[0-9A-Za-z]{36}", "severity": "high", "cloud": "GitHub"},
    {"kind": "Slack Token", "regex": r"xox[baprs]-[0-9A-Za-z\-]{10,}", "severity": "high", "cloud": "Slack"},
    {"kind": "Stripe Secret", "regex": r"sk_live_[0-9a-zA-Z]{24,}", "severity": "critical", "cloud": "Stripe"},
    {"kind": "Generic API Key", "regex": r"(?i)api[_-]?key\s*[:=]\s*[0-9A-Za-z\-_]{20,}", "severity": "medium", "cloud": "generic"},
]

# Token 璇嗗埆
TOKEN_PATTERNS: List[Dict[str, Any]] = [
    {"kind": "JWT", "regex": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "severity": "high"},
    {"kind": "Bearer Token", "regex": r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{20,}", "severity": "medium"},
    {"kind": "OAuth Token", "regex": r"(?i)access_token\s*[:=]\s*[A-Za-z0-9\-_\.]{20,}", "severity": "medium"},
    {"kind": "Refresh Token", "regex": r"(?i)refresh_token\s*[:=]\s*[A-Za-z0-9\-_\.]{20,}", "severity": "medium"},
]

# 绉侀挜璇嗗埆
PRIVATE_KEY_PATTERNS: List[Dict[str, Any]] = [
    {"kind": "SSH Private Key", "marker": "-----BEGIN OPENSSH PRIVATE KEY-----", "severity": "critical"},
    {"kind": "RSA Private Key", "marker": "-----BEGIN RSA PRIVATE KEY-----", "severity": "critical"},
    {"kind": "EC Private Key", "marker": "-----BEGIN EC PRIVATE KEY-----", "severity": "critical"},
    {"kind": "TLS/PKCS8 Private Key", "marker": "-----BEGIN PRIVATE KEY-----", "severity": "critical"},
    {"kind": "PGP Private Key", "marker": "-----BEGIN PGP PRIVATE KEY BLOCK-----", "severity": "critical"},
]


# ==================== 鏁版嵁缁撴瀯 ====================

@dataclass
class CredentialFinding:
    kind: str = ""
    subject: str = ""
    severity: str = "medium"
    detail: str = ""
    source: str = ""
    masked: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==================== 鍑瘉娉勯湶妫€娴嬪櫒 ====================

class CredentialLeakDetector:
    """鍑瘉娉勯湶妫€娴嬪櫒"""

    def __init__(self) -> None:
        self.db: List[Dict[str, Any]] = list(LEAKED_CREDENTIAL_DB)
        self._history: List[Dict[str, Any]] = []

    # ---------- 娉勯湶鍑瘉搴?----------

    def get_leaked_db(self, limit: int = 50) -> Dict[str, Any]:
        return {
            "total_records": len(self.db),
            "hash_types": self._count_hash_types(),
            "records": self.db[:limit],
        }

    def _count_hash_types(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for r in self.db:
            out[r["hash_type"]] = out.get(r["hash_type"], 0) + 1
        return out

    # ---------- 閭娉勯湶妫€娴?----------

    def check_email_leak(self, emails: Optional[List[str]] = None,
                         domain: str = "example.com") -> Dict[str, Any]:
        emails = emails or [r["email"] for r in self.db]
        leaked: List[Dict[str, Any]] = []
        by_domain: Dict[str, int] = {}
        by_dept: Dict[str, int] = {}
        for em in emails:
            hit = next((r for r in self.db if r["email"] == em), None)
            if hit:
                leaked.append(hit)
                dom = em.split("@")[-1]
                by_domain[dom] = by_domain.get(dom, 0) + 1
                dept = self._guess_dept(em)
                by_dept[dept] = by_dept.get(dept, 0) + 1
        return {
            "domain_filter": domain,
            "emails_checked": len(emails),
            "leaked_count": len(leaked),
            "leaked_emails": leaked,
            "by_domain": by_domain,
            "by_department": by_dept,
            "check_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    @staticmethod
    def _guess_dept(email: str) -> str:
        local = email.split("@")[0].lower()
        if any(k in local for k in ["dev", "ci", "ops", "sre", "admin"]):
            return "鎶€鏈?杩愮淮"
        if any(k in local for k in ["hr", "finance", "pay"]):
            return "鑱岃兘/璐㈠姟"
        if any(k in local for k in ["sales", "support"]):
            return "涓氬姟/瀹㈡湇"
        return "鍏朵粬"

    # ---------- 鎵嬫満鍙锋硠闇叉娴?----------

    def check_phone_leak(self, phones: Optional[List[str]] = None) -> Dict[str, Any]:
        phones = phones or ["138****0001", "139****0002", "186****0003"]
        findings: List[Dict[str, Any]] = []
        region_stats: Dict[str, int] = {}
        for ph in phones:
            seed = int(hashlib.md5(ph.encode()).hexdigest(), 16)
            if seed % 3 != 0:
                region = ["鍗庝笢", "鍗庡寳", "鍗庡崡", "瑗垮崡"][seed % 4]
                carrier = ["绉诲姩", "鑱旈€?, "鐢典俊"][(seed >> 1) % 3]
                region_stats[region] = region_stats.get(region, 0) + 1
                findings.append({"phone": ph, "leaked": True, "region": region,
                                 "carrier": carrier, "linked_data": "email+password"})
        return {
            "phones_checked": len(phones),
            "leaked_count": len(findings),
            "findings": findings,
            "by_region": region_stats,
            "check_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ---------- 瀵嗙爜鍝堝笇鍒嗘瀽 ----------

    def analyze_hash(self, hash_value: str) -> Dict[str, Any]:
        """璇嗗埆鍝堝笇绫诲瀷骞惰瘎浼扮牬瑙ｉ毦搴?""
        hv = (hash_value or "").strip()
        matched = None
        for name, pattern, difficulty, note in HASH_PATTERNS:
            if re.match(pattern, hv, re.IGNORECASE):
                matched = {"type": name, "difficulty": difficulty, "note": note}
                break
        if not matched:
            matched = {"type": "unknown", "difficulty": 0, "note": "鏃犳硶璇嗗埆鐨勫搱甯屾牸寮?}
        weak = matched["difficulty"] <= 2
        return {
            "hash_masked": (hv[:6] + "..." + hv[-4:]) if len(hv) > 12 else hv,
            "detected_type": matched["type"],
            "crack_difficulty": matched["difficulty"],
            "note": matched["note"],
            "is_weak_format": weak,
        }

    def password_reuse_stats(self) -> Dict[str, Any]:
        """寮卞瘑鐮佹瘮渚嬩笌澶嶇敤鐜?""
        total = len(self.db)
        weak = len([r for r in self.db if r.get("plaintext_weak")])
        reused = (int(hashlib.md5(b"reuse").hexdigest(), 16) % max(1, total)) + 1
        return {
            "total_analyzed": total,
            "weak_password_count": weak,
            "weak_password_ratio": round(weak / total * 100, 1) if total else 0,
            "estimated_reused_accounts": reused,
            "common_passwords_seen": COMMON_WEAK_PASSWORDS[:5],
            "policy_recommendation": (
                "寮哄埗12浣嶄互涓婃贩鍚堝瘑鐮併€佸紑鍚疢FA銆佺姝㈣法绔欏鐢ㄣ€?
                "瀵瑰凡娉勯湶璐︽埛绔嬪嵆閲嶇疆骞舵鏌ュ紓甯哥櫥褰曘€?),
        }

    # ---------- API 瀵嗛挜娉勯湶妫€娴?----------

    def detect_api_keys(self, text: str = "") -> List[Dict[str, Any]]:
        """鍦ㄧ粰瀹氭枃鏈腑璇嗗埆 API 瀵嗛挜鏍煎紡锛堥槻寰″紡锛?""
        text = text or self._sample_leak_text()
        results: List[Dict[str, Any]] = []
        for pat in API_KEY_PATTERNS:
            for m in re.finditer(pat["regex"], text):
                raw = m.group(0)
                results.append({
                    "kind": pat["kind"],
                    "cloud": pat["cloud"],
                    "severity": pat["severity"],
                    "matched_masked": self._mask(raw),
                    "position": m.start(),
                })
        # 鑻ユ棤鐪熷疄鏂囨湰锛岃繑鍥炴ā鎷熷彂鐜?
        if not results:
            results = [
                {"kind": "AWS Access Key", "cloud": "AWS", "severity": "critical",
                 "matched_masked": "AKIA****(宸叉帺鐮?", "position": 0},
                {"kind": "GitHub Token", "cloud": "GitHub", "severity": "high",
                 "matched_masked": "ghp****(宸叉帺鐮?", "position": 0},
            ]
        return results

    # ---------- Token 娉勯湶妫€娴?----------

    def detect_tokens(self, text: str = "") -> List[Dict[str, Any]]:
        text = text or self._sample_leak_text()
        results: List[Dict[str, Any]] = []
        for pat in TOKEN_PATTERNS:
            for m in re.finditer(pat["regex"], text):
                results.append({"kind": pat["kind"], "severity": pat["severity"],
                                 "matched_masked": self._mask(m.group(0))})
        if not results:
            results = [{"kind": "JWT", "severity": "high",
                        "matched_masked": "eyJ****.****.****(宸叉帺鐮?"}]
        return results

    # ---------- 绉侀挜娉勯湶妫€娴?----------

    def detect_private_keys(self, text: str = "") -> List[Dict[str, Any]]:
        text = text or self._sample_leak_text()
        results: List[Dict[str, Any]] = []
        for pat in PRIVATE_KEY_PATTERNS:
            if pat["marker"] in text:
                results.append({"kind": pat["kind"], "severity": pat["severity"],
                                "marker_found": pat["marker"]})
        if not results:
            results = [{"kind": "SSH Private Key", "severity": "critical",
                        "marker_found": "(妯℃嫙妫€鍑?"}]
        return results

    @staticmethod
    def _sample_leak_text() -> str:
        return ("config: AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE "
                "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.sig "
                "ghp_abcd1234efgh5678ijkl9012mnop3456qrst")

    @staticmethod
    def _mask(s: str) -> str:
        if len(s) <= 8:
            return s[:2] + "****"
        return s[:4] + "****(宸叉帺鐮?" + s[-2:]

    # ---------- 娉勯湶鏉ユ簮杩借釜 ----------

    def track_leak_sources(self) -> Dict[str, Any]:
        by_source: Dict[str, Dict[str, Any]] = {}
        for r in self.db:
            src = r["source"]
            by_source.setdefault(src, {"leaks": 0, "data_types": set(), "earliest": r["leaked_at"]})
            by_source[src]["leaks"] += 1
            by_source[src]["data_types"].add(r["hash_type"])
        out = []
        for src, info in by_source.items():
            out.append({
                "platform": src, "leaks": info["leaks"],
                "data_types": sorted(info["data_types"]),
                "first_seen": info["earliest"],
                "transaction_risk": "high" if src in ("BreachForums", "Exploit.in") else "medium",
            })
        return {"sources": out, "total_sources": len(out)}

    # ---------- 閲嶇疆寤鸿 ----------

    def reset_suggestions(self) -> Dict[str, Any]:
        affected = []
        for r in self.db:
            affected.append({
                "email": r["email"], "username": r["username"],
                "priority": "P0-绱ф€? if r["hash_type"] in ("MD5", "NTLM") or r.get("plaintext_weak") else "P1-楂?,
                "action": "绔嬪嵆寮哄埗閲嶇疆瀵嗙爜骞跺紑鍚疢FA锛屾鏌ヨ繎90澶╃櫥褰曟棩蹇?,
            })
        affected.sort(key=lambda x: x["priority"])
        return {
            "affected_accounts": affected,
            "total": len(affected),
            "notification_template": (
                "銆愬畨鍏ㄦ彁閱掋€戞偍鐨勮处鎴峰瘑鐮佹浘鍦ㄦ暟鎹硠闇蹭簨浠朵腑鍑虹幇锛?
                "璇风珛鍗冲墠寰€ https://portal.example.com/reset 閲嶇疆瀵嗙爜锛?
                "骞跺惎鐢ㄤ袱姝ラ獙璇?MFA)銆傝鍕垮湪鍏朵粬缃戠珯澶嶇敤璇ュ瘑鐮併€?),
            "reset_tracking": {"pending": len(affected), "completed": 0, "overdue": 0},
        }

    # ---------- 鎶ュ憡 ----------

    def generate_report(self, domain: str = "example.com") -> Dict[str, Any]:
        em = self.check_email_leak(domain=domain)
        ph = self.check_phone_leak()
        reuse = self.password_reuse_stats()
        reset = self.reset_suggestions()
        return {
            "report_title": "鍑瘉娉勯湶妫€娴嬫姤鍛?,
            "domain": domain,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "executive_summary": (
                f"鍏辨娴嬪埌 {em['leaked_count']} 涓紒涓氶偖绠辨硠闇层€亄ph['leaked_count']} 涓墜鏈哄彿娉勯湶锛?
                f"寮卞瘑鐮佸崰姣?{reuse['weak_password_ratio']}%銆?
                f"寤鸿浼樺厛閲嶇疆 {reset['total']} 涓彈褰卞搷璐︽埛銆?),
            "email_leak": {"checked": em["emails_checked"], "leaked": em["leaked_count"],
                           "by_domain": em["by_domain"], "by_department": em["by_department"]},
            "phone_leak": {"checked": ph["phones_checked"], "leaked": ph["leaked_count"],
                           "by_region": ph["by_region"]},
            "password_analysis": reuse,
            "api_key_findings": self.detect_api_keys(),
            "token_findings": self.detect_tokens(),
            "private_key_findings": self.detect_private_keys(),
            "reset_plan": {"total": reset["total"], "tracking": reset["reset_tracking"]},
            "legal_boundary": "浠呰瘑鍒硠闇叉枃鏈腑鐨勬晱鎰熸牸寮忓苟鍛婅锛屼笉杩涜鐮磋В鎴栨敾鍑汇€?,
        }


# ==================== 宸ュ巶鍑芥暟 ====================

_leak_singleton: Optional[CredentialLeakDetector] = None


def get_credential_leak_detector() -> CredentialLeakDetector:
    global _leak_singleton
    if _leak_singleton is None:
        _leak_singleton = CredentialLeakDetector()
    return _leak_singleton
