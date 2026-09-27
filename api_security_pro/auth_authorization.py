#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auth_authorization.py 鈥?璁よ瘉涓庢巿鏉冩繁搴︽祴璇曞櫒锛堜笓涓氱骇娣卞寲锛夈€?

瑕嗙洊锛?
    - JWT 娴嬭瘯锛氱畻娉曟贩娣?寮卞瘑閽?鏈獙璇佺鍚?杩囨湡/iss/aud/jku/kid 娉ㄥ叆/鏉冮檺鎻愬崌
    - API 瀵嗛挜娴嬭瘯锛歎RL 娉勯湶/鏃ュ織娉勯湶/鍙娴?鏈繃鏈?鏉冮檺杩囧ぇ
    - OAuth2 娴嬭瘯锛歳edirect_uri 寮€鏀鹃噸瀹氬悜/state 缂哄け/CSRF/闅愬紡娴佺▼/scope 鎻愬崌
    - Basic Auth 娴嬭瘯锛氬急鍙ｄ护/榛樿鍑嵁/鏄庢枃浼犺緭
    - Session 娴嬭瘯锛氬浐瀹?鍔寔/瓒呮椂/Cookie 瀹夊叏鏍囧織/CSRF
    - 璁よ瘉缁曡繃锛氭棤璁よ瘉璁块棶/榛樿璐︽埛/纭紪鐮佸嚟鎹?鍚庨棬
    - 鏉冮檺鎻愬崌锛欱OLA/BFLA/姘村钩/鍨傜洿瓒婃潈/IDOR

璁捐瀹氫綅锛氫粎杈撳嚭妫€娴嬮」銆侀闄╄瘎绾т笌淇寤鸿锛涗笉涓诲姩瀵圭湡瀹炵洰鏍囧彂璧风垎鐮磋姹傘€?
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Dict, List, Optional


# JWT 甯哥敤寮卞瘑閽ュ瓧鍏革紙鐢ㄤ簬椋庨櫓璇勪及娓呭崟锛屼笉鍋氬湪绾跨垎鐮达級
WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "qwerty", "your-256-bit-secret",
    "jwt_secret", "key", "admin", "test", "changeme", "private",
    "supersecret", "token", "auth", "default", "root",
]

# 甯歌榛樿鍑嵁
DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("root", "root"), ("root", "toor"), ("test", "test"),
    ("guest", "guest"), ("user", "user"), ("admin", "admin123"),
]

# 椋庨櫓璇勭骇鏄犲皠
_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class AuthAuthorizationTester:
    """璁よ瘉涓庢巿鏉冩祴璇曞櫒锛堟娴嬮」鐢熸垚 + 妯℃嫙璇勪及锛夈€?""

    def __init__(self) -> None:
        self.findings: List[Dict[str, Any]] = []
        self._endpoints: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 鍏ュ彛
    # ------------------------------------------------------------------ #
    def run_tests(
        self,
        endpoints: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """杩愯鍏ㄩ儴璁よ瘉鎺堟潈娴嬭瘯锛岃繑鍥炵粨鏋滃瓧鍏搞€?""
        options = options or {}
        self._endpoints = endpoints or self._default_endpoints()
        self.findings = []

        self._test_jwt(options)
        self._test_api_key(options)
        self._test_oauth2(options)
        self._test_basic_auth(options)
        self._test_session(options)
        self._test_auth_bypass()
        self._test_privilege_escalation()

        return {
            "total_findings": len(self.findings),
            "by_severity": self._severity_breakdown(),
            "findings": self.findings,
            "recommendations": self._build_recommendations(),
            "summary": self._summary(),
        }

    @staticmethod
    def _default_endpoints() -> List[Dict[str, Any]]:
        return [
            {"path": "/api/v1/users/{id}", "method": "GET", "auth_required": True},
            {"path": "/api/v1/users/{id}", "method": "PUT", "auth_required": True},
            {"path": "/api/v1/admin/users", "method": "GET", "auth_required": True},
            {"path": "/api/v1/orders/{id}", "method": "GET", "auth_required": True},
            {"path": "/api/v1/profile", "method": "GET", "auth_required": True},
        ]

    # ------------------------------------------------------------------ #
    # 閫氱敤璁板綍
    # ------------------------------------------------------------------ #
    def _add(
        self,
        category: str,
        name: str,
        severity: str,
        description: str,
        evidence: str = "",
        recommendation: str = "",
        endpoint: str = "",
    ) -> None:
        self.findings.append({
            "category": category,
            "name": name,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "endpoint": endpoint,
            "cwe": self._cwe_for(category, name),
            "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })

    @staticmethod
    def _cwe_for(category: str, name: str) -> str:
        mapping = {
            "JWT": "CWE-347", "API瀵嗛挜": "CWE-522", "OAuth2": "CWE-601",
            "Basic Auth": "CWE-522", "Session": "CWE-384",
            "璁よ瘉缁曡繃": "CWE-287", "鏉冮檺鎻愬崌": "CWE-639",
        }
        return mapping.get(category, "CWE-284")

    # ------------------------------------------------------------------ #
    # JWT 娴嬭瘯
    # ------------------------------------------------------------------ #
    def _test_jwt(self, options: Dict[str, Any]) -> None:
        token = options.get("jwt_token", "")
        if token:
            decoded = self._decode_jwt(token)
            if decoded:
                header, payload = decoded
                alg = (header.get("alg") or "").lower()
                if alg in ("none", ""):
                    self._add("JWT", "绠楁硶娣锋穯 (alg=none)", "critical",
                              "JWT 浣跨敤 none 绠楁硶锛屾敾鍑昏€呭彲浼€犱换鎰忚韩浠?,
                              f"header.alg={alg}",
                              "鏈嶅姟绔繀椤诲己鍒舵牎楠岀畻娉曠櫧鍚嶅崟锛屾嫆缁?none 绠楁硶")
                if alg.startswith("hs"):
                    self._add("JWT", "瀵圭О绠楁硶寮卞瘑閽ラ闄?, "high",
                              "HS256/HS512 瀵圭О绛惧悕渚濊禆瀵嗛挜寮哄害锛屽急瀵嗛挜鍙鐖嗙牬",
                              f"header.alg={alg}",
                              "浣跨敤瓒冲闀匡紙>=32瀛楄妭锛夌殑闅忔満瀵嗛挜锛屾垨鏀圭敤闈炲绉?RS256/ES256")
                # 杩囨湡妫€鏌?
                exp = payload.get("exp")
                if not exp:
                    self._add("JWT", "缂哄皯 exp 杩囨湡鏃堕棿", "high",
                              "JWT 鏈缃繃鏈熸椂闂达紝浠ょ墝涓€鏃︽硠闇叉案涔呮湁鏁?,
                              "payload 涓棤 exp 瀛楁",
                              "璁剧疆鍚堢悊鐨?exp锛堝 15-60 鍒嗛挓锛夛紝閰嶅悎鍒锋柊浠ょ墝")
                else:
                    try:
                        if int(exp) < time.time():
                            self._add("JWT", "浠ょ墝宸茶繃鏈熶粛琚帴鍙?, "medium",
                                      "杩囨湡浠ょ墝浠嶅彲鐢ㄤ簬璁块棶鍙椾繚鎶よ祫婧?,
                                      f"exp={exp}",
                                      "鏈嶅姟绔繀椤讳弗鏍兼牎楠?exp锛岃繃鏈熶护鐗岀珛鍗虫嫆缁?)
                    except Exception:
                        pass
                # iss/aud 妫€鏌?
                if not payload.get("iss"):
                    self._add("JWT", "缂哄皯 issuer 鏍￠獙", "medium",
                              "鏈牎楠?iss 澹版槑锛屽彲鑳芥帴鍙楀叾浠栧彂琛屾柟绛惧彂鐨勪护鐗?,
                              "payload 涓棤 iss",
                              "鏍￠獙 iss 鐧藉悕鍗曪紝鎷掔粷鏈巿鏉冨彂琛屾柟")
                if not payload.get("aud"):
                    self._add("JWT", "缂哄皯 audience 鏍￠獙", "low",
                              "鏈牎楠?aud 澹版槑锛岃法鏈嶅姟浠ょ墝鍙兘琚互鐢?,
                              "payload 涓棤 aud",
                              "鏍￠獙 aud 涓庡綋鍓?API 鍙椾紬涓€鑷?)
                # jku / kid 娉ㄥ叆
                if "jku" in header:
                    self._add("JWT", "jku 澶存敞鍏ラ闄?, "high",
                              "jku 鎸囧悜澶栭儴 JWKS URL锛屾敾鍑昏€呭彲鎵樼鎭舵剰 JWKS",
                              f"jku={header.get('jku')}",
                              "鍥哄畾 JWKS 鍦板潃锛岀姝㈠鎴风鎺у埗 jku")
                if "kid" in header:
                    kid = str(header.get("kid", ""))
                    if ".." in kid or "/" in kid or "'" in kid or "%" in kid:
                        self._add("JWT", "kid 澶存敞鍏ラ闄?, "high",
                                  "kid 鍖呭惈璺緞閬嶅巻/SQL 娉ㄥ叆瀛楃",
                                  f"kid={kid}",
                                  "kid 浣跨敤鐧藉悕鍗曠储寮曪紝绂佹鎷兼帴鏂囦欢璺緞鎴?SQL")
        else:
            # 鏈彁渚?token 鏃讹紝杈撳嚭妫€鏌ユ竻鍗?
            self._add("JWT", "绠楁硶娣锋穯 (alg=none) 妫€鏌ラ」", "high",
                      "搴旀祴璇曞皢 alg 鏀逛负 none 鍚庢湇鍔＄鏄惁浠嶆帴鍙椾护鐗?,
                      "妫€鏌ラ」",
                      "鎷掔粷 alg=none锛涘己鍒剁畻娉曠櫧鍚嶅崟")
            self._add("JWT", "寮卞瘑閽ョ垎鐮存鏌ラ」", "medium",
                      "搴旇瘎浼?HS 绯诲垪绠楁硶瀵嗛挜鏄惁鍙瀛楀吀鐖嗙牬",
                      "妫€鏌ラ」锛涘急瀵嗛挜瀛楀吀鍚?%d 鏉? % len(WEAK_JWT_SECRETS),
                      "浣跨敤寮洪殢鏈哄瘑閽ワ紝瀹氭湡杞崲")
            self._add("JWT", "鏈獙璇佺鍚嶆鏌ラ」", "critical",
                      "搴旀祴璇曟湇鍔＄鏄惁浠呰В鐮佽€屼笉楠岃瘉绛惧悕",
                      "妫€鏌ラ」",
                      "濮嬬粓楠岃瘉绛惧悕锛涙嫆缁?kid/jku/x5u 绛夊鎴风鎺у埗澶?)

    @staticmethod
    def _decode_jwt(token: str) -> Optional[tuple]:
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return None

            def _b64d(s: str) -> bytes:
                s += "=" * (-len(s) % 4)
                return base64.urlsafe_b64decode(s)

            header = json.loads(_b64d(parts[0]).decode("utf-8", errors="replace"))
            payload = json.loads(_b64d(parts[1]).decode("utf-8", errors="replace"))
            return header, payload
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # API 瀵嗛挜娴嬭瘯
    # ------------------------------------------------------------------ #
    def _test_api_key(self, options: Dict[str, Any]) -> None:
        key = options.get("api_key", "")
        self._add("API瀵嗛挜", "瀵嗛挜鍦?URL 涓紶杈撻闄?, "medium",
                  "API Key 鍑虹幇鍦?URL query 涓細琚棩蹇?鍘嗗彶/Referer 娉勯湶",
                  "妫€鏌ラ」",
                  "API Key 搴旀斁鍦?Header锛圶-API-Key/Authorization锛夛紝绂佹 URL 浼犻€?)
        self._add("API瀵嗛挜", "瀵嗛挜鍦ㄦ棩蹇椾腑娉勯湶椋庨櫓", "medium",
                  "璇锋眰鏃ュ織鑻ヨ褰曞畬鏁?URL/Header锛屼細瀵艰嚧 API Key 娉勯湶",
                  "妫€鏌ラ」",
                  "鏃ュ織鑴辨晱锛屽 Authorization/X-API-Key 瀛楁鎵撶爜")
        self._add("API瀵嗛挜", "瀵嗛挜鍙娴嬫€ф鏌?, "high",
                  "鑷/鍩轰簬鐢ㄦ埛ID/鏃堕棿鎴崇殑 API Key 鍙棰勬祴鏋氫妇",
                  "妫€鏌ラ」",
                  "浣跨敤 CSPRNG 鐢熸垚 >=32 瀛楄妭闅忔満瀵嗛挜锛屼笉鍙娴?)
        self._add("API瀵嗛挜", "瀵嗛挜姘镐笉杩囨湡", "high",
                  "API Key 鏃犺繃鏈?杞崲鏈哄埗锛屾硠闇插悗闀挎湡鏈夋晥",
                  "妫€鏌ラ」",
                  "璁剧疆瀵嗛挜鏈夋晥鏈燂紝鏀寔涓诲姩鍚婇攢涓庤疆鎹?)
        self._add("API瀵嗛挜", "瀵嗛挜鏉冮檺杩囧ぇ", "high",
                  "API Key 閫氬父鎼哄甫杩囧鏉冮檺锛岀己涔忔渶灏忔潈闄愬師鍒?,
                  "妫€鏌ラ」",
                  "鎸?scope/鏈嶅姟鑼冨洿闄愬埗瀵嗛挜鏉冮檺锛屾敮鎸佺粏绮掑害鎺堟潈")
        if key:
            if len(key) < 16:
                self._add("API瀵嗛挜", "瀵嗛挜闀垮害杩囩煭", "medium",
                          f"API Key 闀垮害浠?{len(key)} 瀛楄妭锛岀喌涓嶈冻",
                          f"len={len(key)}",
                          "瀵嗛挜闀垮害 >= 32 瀛楄妭锛?56 浣嶇喌锛?)
            if key.lower().startswith(("sk_test", "sk_live", "pk_")):
                self._add("API瀵嗛挜", "瀵嗛挜鍓嶇紑鏆撮湶绫诲瀷", "info",
                          f"瀵嗛挜鍓嶇紑 {key[:7]}... 鏆撮湶鐜/绫诲瀷锛屽缓璁贩娣嗗墠缂€",
                          f"prefix={key[:7]}",
                          "鍙帴鍙楋紝浣嗛厤鍚堟潈闄愰殧绂讳笌蹇€熷悐閿€")

    # ------------------------------------------------------------------ #
    # OAuth2 娴嬭瘯
    # ------------------------------------------------------------------ #
    def _test_oauth2(self, options: Dict[str, Any]) -> None:
        self._add("OAuth2", "redirect_uri 寮€鏀鹃噸瀹氬悜", "high",
                  "redirect_uri 鏍￠獙涓嶄弗鏍硷紙瀛愪覆/鍓嶇紑/鍚庣紑鍖归厤锛夊彲瀵艰嚧鎺堟潈鐮佹硠闇茬粰鏀诲嚮鑰?,
                  "妫€鏌ラ」",
                  "redirect_uri 涓ユ牸鐧藉悕鍗曠簿纭尮閰嶏紝绂佹閫氶厤绗?)
        self._add("OAuth2", "state 鍙傛暟缂哄け", "medium",
                  "缂哄皯 state 鍙傛暟鏄撳彈 CSRF 鏀诲嚮锛屾敾鍑昏€呭彲灏嗚嚜宸辩殑璐﹀彿缁戝畾鍙楀鑰?,
                  "妫€鏌ラ」",
                  "寮哄埗 state锛圕SRF token锛夛紝鏈嶅姟绔牎楠屼竴鑷存€?)
        self._add("OAuth2", "闅愬紡娴佺▼瀹夊叏椋庨櫓", "medium",
                  "implicit 娴佺▼灏?access_token 鏀惧湪 URL fragment锛屾槗娉勯湶",
                  "妫€鏌ラ」",
                  "鏀圭敤 authorization_code + PKCE锛岀鐢?implicit")
        self._add("OAuth2", "token 娉勯湶椋庨櫓", "high",
                  "浠ょ墝閫氳繃 URL / 娴忚鍣ㄥ巻鍙?/ Referer 娉勯湶",
                  "妫€鏌ラ」",
                  "浣跨敤鐭湡璁块棶浠ょ墝 + 鍒锋柊浠ょ墝锛汸KCE")
        self._add("OAuth2", "scope 鎻愬崌", "high",
                  "瀹㈡埛绔彲璇锋眰瓒呭嚭鍏舵潈闄愮殑 scope锛屾垨鏈嶅姟绔笉鏍￠獙璇锋眰 scope",
                  "妫€鏌ラ」",
                  "鏈嶅姟绔牎楠?client_id 鍏佽鐨?scope锛屾嫆缁濊秺鏉?scope")
        self._add("OAuth2", "authorization_code 娉ㄥ叆", "high",
                  "鎺堟潈鐮佹湭涓€娆℃€т娇鐢?鏈粦瀹?client_id/鏈牎楠?PKCE code_verifier",
                  "妫€鏌ラ」",
                  "鎺堟潈鐮佸崟娆′娇鐢ㄣ€佺煭鏃舵晥锛?=60s锛夈€佺粦瀹?client_id 涓?code_challenge")

    # ------------------------------------------------------------------ #
    # Basic Auth 娴嬭瘯
    # ------------------------------------------------------------------ #
    def _test_basic_auth(self, options: Dict[str, Any]) -> None:
        self._add("Basic Auth", "寮卞瘑鐮?/ 榛樿鍑嵁", "high",
                  f"搴旇瘎浼版槸鍚﹀瓨鍦ㄩ粯璁?寮卞彛浠ゅ嚟鎹紙鍐呯疆 {len(DEFAULT_CREDENTIALS)} 缁勫父瑙侀粯璁ゅ嚟鎹級",
                  "妫€鏌ラ」",
                  "寮哄埗寮哄瘑鐮佺瓥鐣ワ紝绂佺敤榛樿璐︽埛锛岀櫥褰曞け璐ラ攣瀹?)
        self._add("Basic Auth", "鏄庢枃浼犺緭", "critical",
                  "Basic Auth 鍑嵁 Base64 缂栫爜鍗冲彲瑙ｇ爜锛屽繀椤?over HTTPS",
                  "妫€鏌ラ」",
                  "鍏ㄧ珯 HTTPS + HSTS锛涚姝?HTTP 涓嬩娇鐢?Basic Auth")
        self._add("Basic Auth", "鍑嵁娉ㄥ叆", "medium",
                  "Authorization 澶存湭杩囨护 CRLF锛屽彲鑳藉鑷?HTTP 澶存敞鍏?,
                  "妫€鏌ラ」",
                  "鏈嶅姟绔牎楠岀敤鎴峰悕/瀵嗙爜瀛楃闆嗭紝鎷掔粷 CRLF")
        self._add("Basic Auth", "鏆村姏鐮磋В椋庨櫓", "medium",
                  "鏃犵櫥褰曞け璐ラ攣瀹?闄愭祦锛屽彲鍦ㄧ嚎鐖嗙牬",
                  "妫€鏌ラ」",
                  "澶辫触娆℃暟閿佸畾 + 楠岃瘉鐮?+ 閫熺巼闄愬埗 + 寮傚父鍛婅")

    # ------------------------------------------------------------------ #
    # Session 娴嬭瘯
    # ------------------------------------------------------------------ #
    def _test_session(self, options: Dict[str, Any]) -> None:
        self._add("Session", "浼氳瘽鍥哄畾", "high",
                  "鐧诲綍鍓嶅悗鏈噸缃?Session ID锛屾敾鍑昏€呭彲棰勮浼氳瘽 ID",
                  "妫€鏌ラ」",
                  "鐧诲綍鎴愬姛鍚庨噸鏂扮敓鎴?Session ID锛岄攢姣佹棫浼氳瘽")
        self._add("Session", "浼氳瘽鍔寔", "high",
                  "Session Cookie 缂哄皯 Secure/HttpOnly/SameSite 鏍囧織",
                  "妫€鏌ラ」",
                  "Cookie 璁剧疆 HttpOnly; Secure; SameSite=Lax/Strict")
        self._add("Session", "浼氳瘽瓒呮椂缂哄け", "medium",
                  "鏃犵粷瀵硅秴鏃?绌洪棽瓒呮椂锛屼細璇濋暱鏈熸湁鏁?,
                  "妫€鏌ラ」",
                  "绌洪棽瓒呮椂 15-30 鍒嗛挓锛岀粷瀵硅秴鏃?12-24 灏忔椂")
        self._add("Session", "CSRF 闃叉姢缂哄け", "high",
                  "鐘舵€佸彉鏇存帴鍙ｇ己灏?CSRF Token / SameSite Cookie",
                  "妫€鏌ラ」",
                  "鍏抽敭鎿嶄綔鏍￠獙 CSRF Token锛汣ookie 璁剧疆 SameSite")
        flags = options.get("cookie_flags", {})
        if flags:
            if not flags.get("httponly"):
                self._add("Session", "Cookie 缂哄皯 HttpOnly", "high",
                          "JavaScript 鍙鍙?Session Cookie锛孹SS 鍚庡彲琚獌鍙?,
                          "Set-Cookie 鏈缃?HttpOnly",
                          "娣诲姞 HttpOnly 鏍囧織")
            if not flags.get("secure"):
                self._add("Session", "Cookie 缂哄皯 Secure", "medium",
                          "Cookie 鍙€氳繃 HTTP 鏄庢枃浼犺緭",
                          "Set-Cookie 鏈缃?Secure",
                          "HTTPS 绔欑偣娣诲姞 Secure 鏍囧織")
            if not flags.get("samesite"):
                self._add("Session", "Cookie 缂哄皯 SameSite", "medium",
                          "璺ㄧ珯璇锋眰鍙惡甯?Cookie锛屾槗鍙?CSRF",
                          "Set-Cookie 鏈缃?SameSite",
                          "璁剧疆 SameSite=Lax 鎴?Strict")

    # ------------------------------------------------------------------ #
    # 璁よ瘉缁曡繃
    # ------------------------------------------------------------------ #
    def _test_auth_bypass(self) -> None:
        self._add("璁よ瘉缁曡繃", "鏃犺璇佽闂彈淇濇姢绔偣", "critical",
                  "搴旀祴璇曠Щ闄?Authorization 澶村悗鏄惁浠嶈兘璁块棶鍙椾繚鎶よ祫婧?,
                  "妫€鏌ラ」",
                  "鍦ㄧ綉鍏?涓棿浠跺眰寮哄埗璁よ瘉锛屼笉淇′换鍓嶇闅愯棌")
        self._add("璁よ瘉缁曡繃", "璺宠繃璁よ瘉涓棿浠?, "high",
                  "鏌愪簺璺緞锛?health /metrics /internal锛夊彲鑳界粫杩囪璇佷腑闂翠欢",
                  "妫€鏌ラ」",
                  "瀹¤鎵€鏈夎矾鐢辩殑璁よ瘉涓棿浠惰鐩栵紱鍐呴儴绔偣浠呴檺鍐呯綉")
        self._add("璁よ瘉缁曡繃", "榛樿璐︽埛", "high",
                  "绯荤粺鍙兘瀛樺湪 admin/admin銆乺oot/root 绛夐粯璁よ处鎴锋湭鍒犻櫎",
                  "妫€鏌ラ」",
                  "瀹夎鍚庡己鍒朵慨鏀归粯璁ゅ彛浠わ紝绂佺敤绀轰緥璐︽埛")
        self._add("璁よ瘉缁曡繃", "纭紪鐮佸嚟鎹?, "critical",
                  "浠ｇ爜/閰嶇疆涓‖缂栫爜鍑嵁锛屾硠闇插悗闅句互杞崲",
                  "妫€鏌ラ」",
                  "鍑嵁鏀惧叆瀵嗛挜绠＄悊绯荤粺锛圞MS/Vault锛夛紝浠ｇ爜鎵弿绂佹纭紪鐮?)
        self._add("璁よ瘉缁曡繃", "鍚庨棬绔偣", "high",
                  "璋冭瘯/鍚庨棬绔偣锛?debug /admin/backdoor /actuator锛夊彲鑳芥毚闇?,
                  "妫€鏌ラ」",
                  "鐢熶骇鐜鍏抽棴璋冭瘯绔偣锛涚綉鍏冲眰鎷︽埅 /debug/* /actuator/*")

    # ------------------------------------------------------------------ #
    # 鏉冮檺鎻愬崌锛圔OLA/BFLA/IDOR锛?
    # ------------------------------------------------------------------ #
    def _test_privilege_escalation(self) -> None:
        # BOLA / IDOR
        for ep in self._endpoints:
            if "{" in ep["path"]:
                self._add(
                    "鏉冮檺鎻愬崌", "BOLA / IDOR 瓒婃潈璁块棶",
                    "critical",
                    f"绔偣 {ep['method']} {ep['path']} 鍚矾寰?ID锛屽簲娴嬭瘯鐢ㄦ埛 A 璁块棶鐢ㄦ埛 B 璧勬簮",
                    f"鍙傛暟: {re.findall(r'{(\\w+)}', ep['path'])}",
                    "鏈嶅姟绔牎楠岃祫婧愬綊灞烇細褰撳墠鐢ㄦ埛蹇呴』鏄祫婧愭墍鏈夎€呮垨鍏峰绠＄悊鏉冮檺",
                    endpoint=f"{ep['method']} {ep['path']}",
                )
        # BFLA
        self._add("鏉冮檺鎻愬崌", "BFLA 瓒婃潈鎵ц鍔熻兘", "critical",
                  "搴旀祴璇曟櫘閫氱敤鎴疯皟鐢ㄧ鐞嗗憳鍔熻兘锛圖ELETE /admin/* /POST /admin/users锛?,
                  "妫€鏌ラ」",
                  "姣忎釜鍔熻兘鐐瑰崟鐙仛 RBAC 鏍￠獙锛屼笉浠呬緷璧?URL 闅愯棌")
        self._add("鏉冮檺鎻愬崌", "姘村钩瓒婃潈", "high",
                  "鍚岃鑹茬敤鎴蜂箣闂村彲浜掔浉鏌ョ湅/淇敼鏁版嵁锛堣鍗?鍙戠エ/涓汉璧勬枡锛?,
                  "妫€鏌ラ」",
                  "鍦ㄦ暟鎹闂眰寮哄埗 tenant_id / owner_id 杩囨护")
        self._add("鏉冮檺鎻愬崌", "鍨傜洿瓒婃潈", "critical",
                  "鏅€氱敤鎴峰彲鎵ц绠＄悊鍛樻搷浣滐紙鎻愬崌鏉冮檺/鍒犻櫎鐢ㄦ埛/鏌ョ湅瀹¤鏃ュ織锛?,
                  "妫€鏌ラ」",
                  "鍩轰簬瑙掕壊鐨勮闂帶鍒讹紙RBAC锛? ABAC锛涢粯璁ゆ嫆缁?)
        self._add("鏉冮檺鎻愬崌", "鏉冮檺鎻愬崌 via 瑙掕壊绡℃敼", "high",
                  "瀹㈡埛绔彲鎻愪氦 role=admin / is_admin=true / scope 鎻愭潈瀛楁",
                  "妫€鏌ラ」",
                  "鏈嶅姟绔拷鐣ュ鎴风浼犲叆鐨勮鑹?鏉冮檺瀛楁锛涗粎浠庝护鐗?浼氳瘽璇诲彇")

    # ------------------------------------------------------------------ #
    # 鎶ュ憡杈呭姪
    # ------------------------------------------------------------------ #
    def _severity_breakdown(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            s = f.get("severity", "info")
            out[s] = out.get(s, 0) + 1
        return out

    def _summary(self) -> Dict[str, Any]:
        breakdown = self._severity_breakdown()
        score = sum(_SEVERITY_WEIGHT.get(s, 0) * c for s, c in breakdown.items())
        if score >= 20:
            risk = "涓ラ噸"
        elif score >= 10:
            risk = "楂?
        elif score >= 4:
            risk = "涓?
        else:
            risk = "浣?
        return {
            "risk_level": risk,
            "risk_score": score,
            "total_categories": len({f["category"] for f in self.findings}),
        }

    def _build_recommendations(self) -> List[Dict[str, str]]:
        recs: Dict[str, str] = {}
        for f in self.findings:
            r = f.get("recommendation", "")
            if r and r not in recs:
                recs[r] = f["category"]
        return [{"category": v, "action": k} for k, v in recs.items()]

    # ------------------------------------------------------------------ #
    # 瀵煎嚭
    # ------------------------------------------------------------------ #
    def get_payloads_reference(self) -> Dict[str, Any]:
        """杩斿洖娴嬭瘯 Payload/瀛楀吀鍙傝€冿紙渚?/auth/payloads 绔偣锛夈€?""
        return {
            "weak_jwt_secrets": WEAK_JWT_SECRETS,
            "default_credentials": [{"username": u, "password": p} for u, p in DEFAULT_CREDENTIALS],
            "jwt_algs_to_test": ["none", "HS256", "RS256", "HS512"],
            "cookie_flags_to_check": ["HttpOnly", "Secure", "SameSite", "Path", "Domain"],
            "oauth2_flows": ["authorization_code", "implicit", "password", "client_credentials"],
        }
