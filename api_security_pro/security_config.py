#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_config.py 鈥?API 瀹夊叏閰嶇疆涓庨槻鎶ゆ鏌ュ櫒锛堜笓涓氱骇娣卞寲锛夈€?

瑕嗙洊锛?
    - 閫熺巼闄愬埗锛氱己澶?杩囧/鍙粫杩?鍒嗗竷寮?IP/鐢ㄦ埛闄愭祦
    - CORS锛氶€氶厤绗?鍑瘉鍏辩敤/鍙嶅皠 Origin/棰勮姹傜紦瀛?
    - 瀹夊叏澶达細HSTS/X-Content-Type-Options/X-Frame-Options/CSP/X-XSS-Protection/Referrer-Policy/Permissions-Policy
    - 杈撳叆楠岃瘉锛氱被鍨?闀垮害/鏍煎紡/鑼冨洿/鐧藉悕鍗?姝ｅ垯
    - 杈撳嚭缂栫爜锛欳ontent-Type/JSON/HTML/XML/鑴辨晱
    - 閿欒淇℃伅锛氬爢鏍?璇︾粏閿欒/鍐呴儴璺緞/鐗堟湰/璋冭瘯妯″紡
    - 鏁忔劅鏁版嵁锛氬瘑閽?瀵嗙爜/Token/韬唤璇?閾惰鍗?鎵嬫満鍙锋槑鏂?
    - HTTPS锛歍LS 鐗堟湰/cipher/璇佷功/HSTS/閲嶅畾鍚?

璁捐瀹氫綅锛氫粎鍋氶厤缃悎瑙勬鏌ヤ笌椋庨櫓璇勪及锛岃緭鍑哄姞鍥哄缓璁€?
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional


# 鏁忔劅鏁版嵁姝ｅ垯
_SENSITIVE_PATTERNS = {
    "韬唤璇?: re.compile(r"\b\d{17}[\dXx]\b"),
    "閾惰鍗?: re.compile(r"\b\d{16,19}\b"),
    "鎵嬫満鍙?: re.compile(r"\b1[3-9]\d{9}\b"),
    "閭": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "API Key 鏍蜂緥": re.compile(r"\b(sk|pk|ak|sk_live|sk_test)_[A-Za-z0-9]{16,}\b"),
    "JWT 鏍蜂緥": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "绉侀挜": re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
}

# 鎺ㄨ崘瀹夊叏澶?
_RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


class SecurityConfigChecker:
    """API 瀹夊叏閰嶇疆妫€鏌ュ櫒銆?""

    def __init__(self) -> None:
        self.findings: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 鍏ュ彛
    # ------------------------------------------------------------------ #
    def check(self, response_headers: Optional[Dict[str, str]] = None,
              options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """妫€鏌ュ畨鍏ㄩ厤缃€俽esponse_headers 涓虹洰鏍?API 瀹為檯鍝嶅簲澶淬€?""
        options = options or {}
        self.findings = []
        headers = {k.lower(): v for k, v in (response_headers or {}).items()}

        self._check_rate_limit(options)
        self._check_cors(headers, options)
        self._check_security_headers(headers)
        self._check_input_validation(options)
        self._check_output_encoding(headers, options)
        self._check_error_info(options)
        self._check_sensitive_data(options)
        self._check_https(headers, options)

        score = self._compute_score()
        return {
            "total_findings": len(self.findings),
            "by_severity": self._severity_breakdown(),
            "by_category": self._category_breakdown(),
            "findings": self.findings,
            "score": score,
            "grade": self._grade(score),
            "hardening": self._build_hardening(),
        }

    def _add(self, category: str, name: str, severity: str, description: str,
             evidence: str = "", recommendation: str = "") -> None:
        self.findings.append({
            "category": category, "name": name, "severity": severity,
            "description": description, "evidence": evidence,
            "recommendation": recommendation,
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })

    # ------------------------------------------------------------------ #
    # 閫熺巼闄愬埗
    # ------------------------------------------------------------------ #
    def _check_rate_limit(self, options: Dict[str, Any]) -> None:
        self._add("閫熺巼闄愬埗", "闄愭祦缂哄け", "high",
                  "API 鏈厤缃€熺巼闄愬埗锛屽彲琚毚鍔涙灇涓?鎾炲簱/鍒锋帴鍙?,
                  "妫€鏌ラ」",
                  "鎺ュ叆闄愭祦涓棿浠讹紙Redis + 浠ょ墝妗?婕忔《锛夛紝鎸?IP+鐢ㄦ埛+绔偣澶氱淮闄愭祦")
        self._add("閫熺巼闄愬埗", "闄愭祦杩囧", "medium",
                  "闄愭祦闃堝€艰繃楂橈紙濡?10000/鍒嗛挓锛夋垨浠呮寜 IP锛岀粫杩囨垚鏈綆",
                  "妫€鏌ラ」",
                  "鐧诲綍/鐭俊/楠岃瘉鐮佺瓑鏁忔劅鎺ュ彛鏇翠弗鏍硷紙1-10 娆?鍒嗛挓锛?)
        self._add("閫熺巼闄愬埗", "闄愭祦鍙粫杩?, "medium",
                  "浠呮寜 X-Forwarded-For / X-Real-IP 闄愭祦锛屽鎴风鍙吉閫犲ご",
                  "妫€鏌ラ」",
                  "浠庡彲淇′唬鐞嗚幏鍙栫湡瀹?IP锛涙寜鐢ㄦ埛 ID 闄愭祦鍏滃簳")
        self._add("閫熺巼闄愬埗", "鍒嗗竷寮忛檺娴佺己澶?, "medium",
                  "鍗曟満闄愭祦鍦ㄥ瀹炰緥閮ㄧ讲涓嬪彲琚粫杩?,
                  "妫€鏌ラ」",
                  "浣跨敤 Redis/闆嗕腑寮忛檺娴佽鏁板櫒锛涙粦鍔ㄧ獥鍙?)
        enabled = options.get("rate_limit_enabled")
        if enabled is False:
            self._add("閫熺巼闄愬埗", "闄愭祦鏄惧紡鍏抽棴", "critical",
                      "options 鏄剧ず rate_limit_enabled=false",
                      "rate_limit_enabled=false",
                      "鐢熶骇鐜蹇呴』鍚敤闄愭祦")

    # ------------------------------------------------------------------ #
    # CORS
    # ------------------------------------------------------------------ #
    def _check_cors(self, headers: Dict[str, str], options: Dict[str, Any]) -> None:
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if acao == "*":
            sev = "high" if acac.lower() == "true" else "medium"
            self._add("CORS", "ACAO 閫氶厤绗?, sev,
                      "Access-Control-Allow-Origin: * 鍏佽浠绘剰绔欑偣璺ㄥ煙璇诲彇",
                      f"ACAO=*; ACAC={acac}",
                      "鐧藉悕鍗曠簿纭?Origin锛涗笉涓?credentials:true 鍏辩敤閫氶厤绗?)
        elif acao and acao not in ("*",):
            # 鍙嶅皠 Origin
            req_origin = (options.get("request_origin") or "").lower()
            if req_origin and acao.lower() == req_origin:
                self._add("CORS", "Origin 鍙嶅皠", "high",
                          "鏈嶅姟绔弽灏勪换鎰忚姹?Origin锛岀瓑鍚屼簬閫氶厤绗?,
                          f"ACAO={acao} == 娴嬭瘯 Origin",
                          "鐧藉悕鍗曠簿纭尮閰嶏紱绂佹鍙嶅皠浠绘剰 Origin")
        if acac.lower() == "true" and acao == "*":
            self._add("CORS", "鍑瘉涓庨€氶厤绗﹀叡鐢?, "critical",
                      "credentials:true 涓?ACAO:* 缁勫悎锛屾祻瑙堝櫒鍦ㄩ儴鍒嗗満鏅粛浼氬甫鍑嵁",
                      "ACAO=* + ACAC=true",
                      "credentials:true 鏃?ACAO 蹇呴』绮剧‘鎸囧畾 Origin")
        self._add("CORS", "棰勮姹傜紦瀛?, "low",
                  "Access-Control-Max-Age 杩囩煭浼氬鑷撮绻?OPTIONS",
                  "妫€鏌ラ」",
                  "鍚堢悊璁剧疆 Access-Control-Max-Age锛堝 600锛?)

    # ------------------------------------------------------------------ #
    # 瀹夊叏澶?
    # ------------------------------------------------------------------ #
    def _check_security_headers(self, headers: Dict[str, str]) -> None:
        for h, recommended in _RECOMMENDED_HEADERS.items():
            if h.lower() not in headers:
                sev = "high" if h in ("Strict-Transport-Security", "Content-Security-Policy") else "medium"
                self._add("瀹夊叏澶?, f"缂哄皯 {h}", sev,
                          f"鍝嶅簲鏈缃?{h}锛堟帹鑽愬€? {recommended}锛?,
                          f"Missing header: {h}",
                          f"娣诲姞 {h}: {recommended}")
            else:
                # 鍩烘湰鍊兼鏌?
                val = headers[h.lower()]
                if h == "X-Content-Type-Options" and val.lower() != "nosniff":
                    self._add("瀹夊叏澶?, "X-Content-Type-Options 鍊间笉褰?, "low",
                              f"褰撳墠鍊? {val}锛屽簲涓?nosniff",
                              val,
                              "璁剧疆涓?nosniff")
                if h == "X-Frame-Options" and val.upper() not in ("DENY", "SAMEORIGIN"):
                    self._add("瀹夊叏澶?, "X-Frame-Options 鍊间笉褰?, "low",
                              f"褰撳墠鍊? {val}",
                              val,
                              "璁剧疆涓?DENY 鎴?SAMEORIGIN")

    # ------------------------------------------------------------------ #
    # 杈撳叆楠岃瘉
    # ------------------------------------------------------------------ #
    def _check_input_validation(self, options: Dict[str, Any]) -> None:
        self._add("杈撳叆楠岃瘉", "缂哄皯鍙傛暟绫诲瀷楠岃瘉", "high",
                  "API 鏈寜 JSON Schema / Pydantic 鏍￠獙鍙傛暟绫诲瀷",
                  "妫€鏌ラ」",
                  "浣跨敤 OpenAPI 鏍￠獙涓棿浠讹紱Pydantic 妯″瀷锛涙嫆缁濆浣欏瓧娈?)
        self._add("杈撳叆楠岃瘉", "缂哄皯闀垮害闄愬埗", "medium",
                  "瀛楃涓插弬鏁版湭闄愬埗鏈€澶ч暱搴︼紝鍙鑷?DoS/瀛樺偍婧㈠嚭",
                  "妫€鏌ラ」",
                  "璁剧疆 maxLength锛堝 256/1024锛?)
        self._add("杈撳叆楠岃瘉", "缂哄皯鏍煎紡楠岃瘉", "medium",
                  "閭/鎵嬫満鍙?URL/UUID 鏈仛鏍煎紡鏍￠獙",
                  "妫€鏌ラ」",
                  "浣跨敤鏍煎紡鏍￠獙锛坒ormat: email/uri/ipv4/uuid锛?)
        self._add("杈撳叆楠岃瘉", "缂哄皯鑼冨洿楠岃瘉", "medium",
                  "鏁板瓧鍙傛暟鏈檺鍒?min/max锛屽彲浼犲叆璐熸暟/瓒呭ぇ鏁?,
                  "妫€鏌ラ」",
                  "璁剧疆 minimum/maximum锛涗笟鍔′笂绂佹璐熸暟")
        self._add("杈撳叆楠岃瘉", "鐧藉悕鍗曢獙璇佺己澶?, "high",
                  "鏋氫妇/瑙掕壊/绫诲瀷瀛楁鏈檺瀹氱櫧鍚嶅崟",
                  "妫€鏌ラ」",
                  "浣跨敤 enum 鐧藉悕鍗曪紱鎷掔粷鏈煡鍊?)
        self._add("杈撳叆楠岃瘉", "姝ｅ垯瀹夊叏锛圧eDoS锛?, "medium",
                  "鐢ㄦ埛杈撳叆杩涘叆澶嶆潅姝ｅ垯锛屽彲鑳?ReDoS",
                  "妫€鏌ラ」",
                  "閬垮厤宓屽閲忚瘝姝ｅ垯锛涜缃尮閰嶈秴鏃讹紱浣跨敤 RE2")

    # ------------------------------------------------------------------ #
    # 杈撳嚭缂栫爜
    # ------------------------------------------------------------------ #
    def _check_output_encoding(self, headers: Dict[str, str], options: Dict[str, Any]) -> None:
        ct = headers.get("content-type", "")
        if ct and "charset" not in ct.lower():
            self._add("杈撳嚭缂栫爜", "Content-Type 鏈寚瀹?charset", "low",
                      f"Content-Type: {ct}锛堟棤 charset锛?,
                      ct,
                      "JSON 鍝嶅簲浣跨敤 application/json; charset=utf-8")
        if ct and "application/json" in ct and "application/json" not in ct.split(";")[0]:
            self._add("杈撳嚭缂栫爜", "JSON 鍝嶅簲 Content-Type 涓嶈鑼?, "low",
                      f"瀹為檯: {ct}",
                      ct,
                      "浣跨敤 application/json")
        self._add("杈撳嚭缂栫爜", "鏁忔劅鏁版嵁鑴辨晱", "high",
                  "鍝嶅簲涓彲鑳借繑鍥炲瘑鐮佸搱甯?韬唤璇?閾惰鍗″叏閲?,
                  "妫€鏌ラ」",
                  "鍝嶅簲 DTO 鍓旈櫎鏁忔劅瀛楁锛涜韩浠借瘉/閾惰鍗?鎵嬫満鍙蜂腑闂存墦鐮?)
        self._add("杈撳嚭缂栫爜", "HTML/XML 杈撳嚭缂栫爜", "medium",
                  "鑻ヨ繑鍥?HTML/XML 鐗囨锛屾湭瀵圭敤鎴疯緭鍏ュ仛杈撳嚭缂栫爜鍙鑷?XSS",
                  "妫€鏌ラ」",
                  "HTML 瀹炰綋缂栫爜锛沊ML 杞箟锛涗娇鐢ㄦ鏋惰嚜鍔ㄨ浆涔?)

    # ------------------------------------------------------------------ #
    # 閿欒淇℃伅
    # ------------------------------------------------------------------ #
    def _check_error_info(self, options: Dict[str, Any]) -> None:
        self._add("閿欒淇℃伅", "鍫嗘爤璺熻釜娉勯湶", "high",
                  "500 鍝嶅簲鍙兘鍖呭惈 Python/Java 鍫嗘爤锛屾硠闇插唴閮ㄨ矾寰勪笌渚濊禆鐗堟湰",
                  "妫€鏌ラ」",
                  "鐢熶骇鐜杩斿洖缁熶竴閿欒 ID锛涘爢鏍堜粎璁版棩蹇?)
        self._add("閿欒淇℃伅", "璇︾粏閿欒淇℃伅娉勯湶", "medium",
                  "閿欒鍝嶅簲鏆撮湶 SQL/ORM 閿欒/鍐呴儴绫诲悕",
                  "妫€鏌ラ」",
                  "缁熶竴閿欒鏍煎紡 {code, message, traceId}")
        self._add("閿欒淇℃伅", "鍐呴儴璺緞娉勯湶", "medium",
                  "閿欒淇℃伅鍖呭惈 /home/app/... 鎴?C:\\... 璺緞",
                  "妫€鏌ラ」",
                  "鑴辨晱鍐呴儴璺緞")
        self._add("閿欒淇℃伅", "鐗堟湰淇℃伅娉勯湶", "low",
                  "Server/X-Powered-By 澶存垨閿欒椤垫毚闇叉鏋剁増鏈?,
                  "妫€鏌ラ」",
                  "闅愯棌 Server/X-Powered-By锛涢敊璇〉閫氱敤鍖?)
        if options.get("debug_mode"):
            self._add("閿欒淇℃伅", "璋冭瘯妯″紡寮€鍚?, "critical",
                      "options 鏄剧ず debug_mode=true锛岀敓浜х幆澧冨嵄闄?,
                      "debug_mode=true",
                      "鐢熶骇鐜鍏抽棴 debug锛涗弗绂佹毚闇茶皟璇曠鐐?)

    # ------------------------------------------------------------------ #
    # 鏁忔劅鏁版嵁
    # ------------------------------------------------------------------ #
    def _check_sensitive_data(self, options: Dict[str, Any]) -> None:
        sample_response = options.get("sample_response", "")
        if isinstance(sample_response, dict):
            sample_response = str(sample_response)
        for name, pat in _SENSITIVE_PATTERNS.items():
            m = pat.search(sample_response or "")
            if m:
                masked = m.group(0)
                if len(masked) > 8:
                    masked = masked[:4] + "***" + masked[-4:]
                self._add("鏁忔劅鏁版嵁", f"鍝嶅簲涓枒浼?{name}", "high",
                          f"鏍蜂緥鍝嶅簲涓尮閰嶅埌 {name}锛屽簲鑴辨晱",
                          f"match: {masked}",
                          "鍝嶅簲涓墧闄?鎵撶爜鏁忔劅瀛楁")
        self._add("鏁忔劅鏁版嵁", "瀵嗙爜瀛楁鏄庢枃/鍝堝笇杩斿洖", "high",
                  "鐢ㄦ埛鎺ュ彛鍙兘杩斿洖 password/password_hash",
                  "妫€鏌ラ」",
                  "鍝嶅簲妯″瀷鎺掗櫎 password 鐩稿叧瀛楁")
        self._add("鏁忔劅鏁版嵁", "Token/API Key 闀挎湡鏄庢枃瀛樺偍", "high",
                  "鏁版嵁搴撲腑 API Key/Token 鍙兘鏄庢枃瀛樺偍",
                  "妫€鏌ラ」",
                  "Token 鍙瓨鍝堝笇锛涙樉绀烘椂鎵撶爜锛涙敮鎸佸悐閿€")

    # ------------------------------------------------------------------ #
    # HTTPS
    # ------------------------------------------------------------------ #
    def _check_https(self, headers: Dict[str, str], options: Dict[str, Any]) -> None:
        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            self._add("HTTPS", "缂哄皯 HSTS", "high",
                      "鏈缃?Strict-Transport-Security锛岄娆?HTTP 鍙闄嶇骇",
                      "Missing HSTS",
                      "娣诲姞 HSTS: max-age=63072000; includeSubDomains; preload")
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < 3153600:
                self._add("HTTPS", "HSTS max-age 杩囩煭", "low",
                          f"max-age={m.group(1)}锛屽缓璁?>= 3153600",
                          hsts,
                          "寤堕暱 HSTS max-age 鍒拌嚦灏?1 骞?)
        self._add("HTTPS", "TLS 鐗堟湰", "high",
                  "搴旂‘璁ょ鐢?TLS 1.0/1.1锛屼粎 TLS 1.2+",
                  "妫€鏌ラ」",
                  "绂佺敤 TLS 1.0/1.1锛涗紭鍏?TLS 1.3")
        self._add("HTTPS", "寮?Cipher Suite", "medium",
                  "搴旂‘璁ょ鐢?3DES/CBC/RC4 绛夊急濂椾欢",
                  "妫€鏌ラ」",
                  "浠呬娇鐢?ECDHE+AEAD 濂椾欢锛汳ozilla Intermediate 閰嶇疆")
        self._add("HTTPS", "璇佷功鏈夋晥鎬?, "high",
                  "搴旀鏌ヨ瘉涔﹂摼/鏈夋晥鏈?鍩熷悕鍖归厤/鍚婇攢鐘舵€?,
                  "妫€鏌ラ」",
                  "璇佷功鐩戞帶锛涜嚜鍔ㄧ画鏈燂紙ACME锛夛紱OCSP Stapling")
        self._add("HTTPS", "HTTP 鍒?HTTPS 閲嶅畾鍚?, "medium",
                  "HTTP 绔彛搴?301 鍒?HTTPS锛屼笉淇濈暀 HTTP 涓氬姟",
                  "妫€鏌ラ」",
                  "80 绔彛浠呴噸瀹氬悜锛汬STS preload")

    # ------------------------------------------------------------------ #
    # 璇勫垎
    # ------------------------------------------------------------------ #
    def _compute_score(self) -> int:
        weight = {"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 0}
        ded = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            s = f.get("severity", "info")
            ded[s] = ded.get(s, 0) + 1
        # 婊″垎 100锛屾寜闂鎵ｅ垎
        penalty = sum(weight.get(s, 0) * c for s, c in ded.items())
        return max(0, 100 - penalty)

    @staticmethod
    def _grade(score: int) -> str:
        if score >= 90:
            return "A (浼樼)"
        if score >= 75:
            return "B (鑹ソ)"
        if score >= 60:
            return "C (涓€鑸?"
        if score >= 40:
            return "D (杈冨樊)"
        return "F (鍗遍櫓)"

    def _severity_breakdown(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            s = f.get("severity", "info")
            out[s] = out.get(s, 0) + 1
        return out

    def _category_breakdown(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            c = f.get("category", "unknown")
            out[c] = out.get(c, 0) + 1
        return out

    def _build_hardening(self) -> List[Dict[str, str]]:
        seen: Dict[str, str] = {}
        for f in self.findings:
            r = f.get("recommendation", "")
            if r and r not in seen:
                seen[r] = f["category"]
        return [{"category": v, "action": k, "priority": "P1" if f["severity"] in ("critical", "high") else "P2"}
                for k, v in seen.items() for f in [self.findings[0]]]  # simplified
