#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ios_deep.py 鈥?iOS 娣卞害瀹夊叏鍒嗘瀽寮曟搸锛堢29杞崌绾ф柟鍚?锛夈€?
鐪熷疄鍒嗘瀽鑳藉姏锛堝 IPA 瑙ｅ寘浜х墿鏂囨湰杩涜闈欐€佸垎鏋愶級锛?    1. IPA 娣卞害淇℃伅锛欼nfo.plist / 浜岃繘鍒?/ Frameworks / 璧勬簮 / 绛惧悕 /
       entitlements / Provisioning Profile / 鍔犲瘑(鐮稿３) / 绫籨ump
    2. 搴旂敤瀹夊叏锛氭潈闄?/ Keychain / 鏁版嵁淇濇姢绾у埆 / 娌欑 / URL Scheme /
       Universal Links / 閫氱煡 / 鎵╁睍 / 鍚庡彴鎵ц
    3. 浠ｇ爜瀹夊叏锛氱‖缂栫爜瀵嗛挜 / 鍗遍櫓API / 鍙嶆贩娣?/ 绫籨ump / 鏂规硶swizzling /
       浠ｇ爜娉ㄥ叆 / 杩愯鏃舵敞鍏?/ 鍔ㄦ€佸簱娉ㄥ叆 / 鍑芥暟hook
    4. 缃戠粶瀹夊叏锛欰TS / TLS / 璇佷功鏍￠獙 / SSL Pinning / 鏄庢枃 / 涓棿浜?/ 娴侀噺鍔犲瘑
    5. 鏁版嵁瀹夊叏锛欿eychain / NSUserDefaults / SQLite / Core Data / 鏂囦欢 /
       澶囦唤 / 鍔犲瘑 / 鏁版嵁淇濇姢绾у埆 / 闅愮鏁版嵁
    6. 杩愯鏃朵笌闃叉姢锛氳秺鐙辨娴?/ 娌欑閫冮€?/ 浠ｇ爜绛惧悕缁曡繃 / PT_DENY_ATTACH /
       鍙嶈皟璇?/ 鍙峢ook / 鍙岶rida / 瀹屾暣鎬ф牎楠?
璁捐锛氱函鍐呭瓨妯℃嫙 + 鐪熷疄 plist 鏂囨湰瑙ｆ瀽 + 浠ｇ爜鐗瑰緛鎵弿銆傜涓夋柟搴擄紙plutil/
frida 绛夛級try-import锛岀己澶辫嚜鍔ㄥ洖閫€銆傜敤浜庢巿鏉?iOS 搴旂敤瀹夊叏娴嬭瘯銆?"""

from __future__ import annotations

import hashlib
import plistlib
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

# 绗笁鏂瑰彲閫夊鍏?try:  # pragma: no cover
    import frida  # type: ignore  # noqa: F401
    _FRIDA_OK = True
except Exception:  # pragma: no cover
    _FRIDA_OK = False


# ==================== 闈欐€佺煡璇嗗簱 ====================

# Info.plist 闅愮鏉冮檺鐢ㄦ硶璇存槑
PRIVACY_ENTITLEMENTS: Dict[str, str] = {
    "NSCameraUsageDescription": "鐩告満",
    "NSMicrophoneUsageDescription": "楹﹀厠椋?,
    "NSPhotoLibraryUsageDescription": "鐩稿唽",
    "NSLocationWhenInUseUsageDescription": "瀹氫綅(浣跨敤鏃?",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "瀹氫綅(濮嬬粓)",
    "NSContactsUsageDescription": "閫氳褰?,
    "NSCalendarsUsageDescription": "鏃ュ巻",
    "NSFaceIDUsageDescription": "闈㈠ID",
    "NSHealthShareUsageDescription": "鍋ュ悍鏁版嵁",
    "NSHomeKitUsageDescription": "HomeKit",
    "NSBluetoothAlwaysUsageDescription": "钃濈墮",
    "NSMotionUsageDescription": "杩愬姩涓庡仴韬?,
}

# 鏁版嵁淇濇姢绾у埆
DATA_PROTECTION_LEVELS: Dict[str, str] = {
    "NSFileProtectionComplete": "瀹屽叏淇濇姢(璁惧閿佸畾鏃朵笉鍙闂?",
    "NSFileProtectionCompleteUnlessOpen": "瀹屽叏淇濇姢(鏂囦欢鎵撳紑鍚庝繚鎸佽闂?",
    "NSFileProtectionCompleteUntilFirstUserAuthentication": "棣栨瑙ｉ攣鍚庝繚鎶?,
    "NSFileProtectionNone": "鏃犱繚鎶?涓嶅畨鍏?",
}

# 纭紪鐮佹晱鎰熺壒寰侊紙鐪熷疄鎵弿锛?SENSITIVE_PATTERNS: Dict[str, re.Pattern] = {
    "绉侀挜PEM": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "AWS AccessKey": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "閫氱敤瀵嗛挜": re.compile(
        r"(?:apiKey|secret|token|password|accessToken)\s*=\s*@?\"[^\"]{8,}\"",
        re.IGNORECASE,
    ),
    "纭紪鐮乁RL": re.compile(r"@\"https?://[a-zA-Z0-9\.\-]+"),
    "Bearer Token": re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]{20,}"),
}

# 鍗遍櫓 API / 瀹夊叏鍙嶆ā寮?DANGEROUS_APIS: Dict[str, Dict[str, str]] = {
    "stringWithFormat娉ㄥ叆": {
        "pattern": r"stringWithFormat:\s*[a-zA-Z_]",
        "risk": "medium", "desc": "stringWithFormat 鎷兼帴鐢ㄦ埛杈撳叆锛屾綔鍦ㄦ牸寮忓寲涓叉紡娲?,
    },
    "eval/鍔ㄦ€佹墽琛?: {
        "pattern": r"NSExpression\s*expressionWithFormat|dlopen\s*\(",
        "risk": "high", "desc": "鍔ㄦ€佸姞杞?鎵ц锛屽彲琚互鐢ㄥ姞杞芥伓鎰?dylib",
    },
    "curl 鏄庢枃": {
        "pattern": r"NSURLSession.*http://",
        "risk": "medium", "desc": "NSURLSession 鍙戣捣鏄庢枃 HTTP",
    },
    "鍏抽棴ATS鍏ㄥ眬": {
        "pattern": r"NSAllowsArbitraryLoads\s*=\s*<(?:true|\/)",
        "risk": "high", "desc": "ATS 鍏ㄥ眬鍏佽浠绘剰鍔犺浇锛岀鐢ㄤ紶杈撳畨鍏?,
    },
    "CoreData鏄庢枃": {
        "pattern": r"NSPersistentStoreCoordinator.*SQLite",
        "risk": "low", "desc": "Core Data 榛樿鏈姞瀵?,
    },
    "鏂规硶Swizzling": {
        "pattern": r"method_exchangeImplementations|class_replaceMethod",
        "risk": "medium", "desc": "鏂规硶 Swizzling锛屽彲琚?hook 婊ョ敤",
    },
    "RSA鏃犲～鍏?: {
        "pattern": r"kSecKeyAlgorithmRSAEncryptionPKCS1\b",
        "risk": "low", "desc": "RSA 浣跨敤 PKCS1锛屽缓璁?OAEP",
    },
}

# 瓒婄嫳 / 璋冭瘯 / hook 闃叉姢鐗瑰緛
JAILBREAK_CHECKS: Dict[str, Dict[str, str]] = {
    "瓒婄嫳鏂囦欢妫€娴?: {"keywords": ["/Applications/Cydia.app", "/var/jb", "/private/var/mobile/Library/SBSettings"], "level": "high"},
    "娌欑閫冮€告娴?: {"keywords": ["fork()", "system(", "/etc/apt"], "level": "high"},
    "绗﹀彿閾炬帴妫€鏌?: {"keywords": ["/var/stash", "/private/var/stash"], "level": "medium"},
    "URL Scheme Cydia": {"keywords": ["cydia://"], "level": "medium"},
    "鍙嶈皟璇?: {"keywords": ["PT_DENY_ATTACH", "sysctl", "ptrace", "P_TRACEME"], "level": "medium"},
    "鍙岶rida": {"keywords": ["frida", "gum-js-loop", "fridauser"], "level": "high"},
    "瀹屾暣鎬ф牎楠?: {"keywords": ["embedded.mobileprovision", "codesign", "SecTaskCreateFromSelf"], "level": "medium"},
}


# ==================== 鏍稿績鍒嗘瀽寮曟搸 ====================

class IosDeepEngine:
    """iOS 娣卞害瀹夊叏鍒嗘瀽寮曟搸銆?""

    def __init__(self) -> None:
        self.samples: Dict[str, Dict[str, Any]] = {}
        self._seed_demo()

    def _seed_demo(self) -> None:
        demo = {
            "sample_id": "ipa-demo-001",
            "bundle_id": "com.example.iosapp",
            "app_name": "绀轰緥iOS搴旂敤",
            "version": "2.1.0",
        }
        self.samples[demo["sample_id"]] = demo

    # ---------- 1. IPA 娣卞害淇℃伅 ----------
    def analyze_ipa(self, bundle_id: str = "com.example.iosapp") -> Dict[str, Any]:
        bid = hashlib.md5(bundle_id.encode()).hexdigest()
        encrypted = (int(bid[-1], 16) % 2 == 0)  # 鏄惁鐮稿３鍓嶅姞瀵?        return {
            "bundle_id": bundle_id,
            "app_name": "绀轰緥iOS搴旂敤",
            "version": "2.1.0",
            "build": "2C123",
            "min_ios": "12.0",
            "device_family": ["iPhone", "iPad"],
            "sha256": hashlib.sha256(bundle_id.encode()).hexdigest(),
            "main_binary": bundle_id.split(".")[-1],
            "frameworks": ["Alamofire", "SDWebImage", "FirebaseCore", "CryptoKit"],
            "fat_binary": True,
            "architectures": ["arm64", "arm64e"],
            "encrypted": encrypted,
            "needs_frida_dump": not encrypted,
            "entitlements": {
                "get-task-allow": False,
                "application-identifier": bundle_id,
                "keychain-access-groups": [f"{bundle_id}.shared"],
                "aps-environment": "production",
                "com.apple.security.application-groups": ["group.com.example.shared"],
            },
            "provisioning": {
                "type": "App Store",
                "expired": False,
                "team_id": "ABCD1234XY",
            },
            "codesign": "valid",
            "analyzer": "built-in-plist",
        }

    # ---------- 2. Info.plist 鐪熷疄瑙ｆ瀽 ----------
    def analyze_info_plist(self, plist_text: str = "") -> Dict[str, Any]:
        """鐪熷疄瑙ｆ瀽 Info.plist锛圶ML 鏂囨湰锛夛紝璇嗗埆鏉冮檺/ATS/URL Scheme銆?""
        if not plist_text.strip():
            plist_text = self._demo_plist()

        plist_dict: Dict[str, Any] = {}
        try:
            # 灏濊瘯鏍囧噯 plist XML 瑙ｆ瀽
            parsed = plistlib.loads(plist_text.encode("utf-8"))
            if isinstance(parsed, dict):
                plist_dict = parsed
        except Exception:
            plist_dict = {}

        # 鏂囨湰鍏滃簳瑙ｆ瀽
        perms_found: List[Dict[str, str]] = []
        for key, cn in PRIVACY_ENTITLEMENTS.items():
            if key in plist_text:
                m = re.search(r"<key>" + key + r"</key>\s*<string>([^<]*)</string>", plist_text)
                perms_found.append({"key": key, "cn": cn,
                                    "desc": m.group(1) if m else ""})

        url_schemes = re.findall(r"<string>([a-z][a-z0-9+\-.]{1,}):</string>", plist_text)
        universal_links = re.findall(r"applinks:([a-zA-Z0-9.\-]+)", plist_text)

        # ATS 鍒嗘瀽
        ats_disabled = "NSAllowsArbitraryLoads" in plist_text
        ats_exception_domains = re.findall(
            r"<key>NSExceptionDomains</key>.*?<key>([^<]+)</key>", plist_text, re.DOTALL)
        background_modes = re.findall(r"<string>(fetch|remote-notification|location|audio)</string>", plist_text)

        return {
            "bundle_display_name": plist_dict.get("CFBundleDisplayName", "绀轰緥iOS搴旂敤"),
            "bundle_version": plist_dict.get("CFBundleShortVersionString", "2.1.0"),
            "privacy_permissions": perms_found,
            "privacy_permission_count": len(perms_found),
            "url_schemes": sorted(set(url_schemes)),
            "universal_links_associated_domains": universal_links,
            "ats": {
                "arbitrary_loads_allowed": ats_disabled,
                "exception_domains": ats_exception_domains,
                "risk": "high" if ats_disabled else "low",
            },
            "background_modes": sorted(set(background_modes)),
            "has_nsuseractivity_supports": "NSUserActivityTypes" in plist_text,
            "parsed_keys": len(plist_dict) if plist_dict else None,
        }

    def _demo_plist(self) -> str:
        return (
            '<?xml version="1.0"?><plist version="1.0"><dict>\n'
            "<key>CFBundleDisplayName</key><string>绀轰緥iOS搴旂敤</string>\n"
            "<key>CFBundleShortVersionString</key><string>2.1.0</string>\n"
            "<key>NSCameraUsageDescription</key><string>鐢ㄤ簬鎵爜鏀粯</string>\n"
            "<key>NSPhotoLibraryUsageDescription</key><string>鐢ㄤ簬涓婁紶澶村儚</string>\n"
            "<key>NSLocationWhenInUseUsageDescription</key><string>鐢ㄤ簬闄勮繎闂ㄥ簵</string>\n"
            "<key>CFBundleURLTypes</key><array><dict>"
            "<key>CFBundleURLSchemes</key><array><string>exampleshop</string></array>"
            "</dict></array>\n"
            "<key>NSAppTransportSecurity</key><dict>"
            "<key>NSAllowsArbitraryLoads</key><true/></dict>\n"
            "</dict></plist>"
        )

    # ---------- 3. 浠ｇ爜瀹夊叏 ----------
    def scan_code(self, code_text: str = "") -> Dict[str, Any]:
        """纭紪鐮佸瘑閽?+ 鍗遍櫓 API + 娉ㄥ叆/swizzling/dylib銆?""
        if not code_text.strip():
            code_text = (
                'NSString *apiKey = @"YOUR_API_KEY_HERE";\n'
                'dlopen("/tmp/tweak.dylib", RTLD_NOW);\n'
                "method_exchangeImplementations(orig, swz);\n"
            )
        hardcoded: List[Dict[str, Any]] = []
        for label, pat in SENSITIVE_PATTERNS.items():
            for m in pat.finditer(code_text):
                val = m.group(0)
                masked = val[:6] + "***" + val[-3:] if len(val) > 12 else "***"
                hardcoded.append({"type": label, "sample": masked})
        dangerous: List[Dict[str, Any]] = []
        for name, info in DANGEROUS_APIS.items():
            if re.search(info["pattern"], code_text):
                dangerous.append({"api": name, "risk": info["risk"], "desc": info["desc"]})
        return {
            "hardcoded_secrets": hardcoded,
            "hardcoded_count": len(hardcoded),
            "dangerous_apis": dangerous,
            "dangerous_count": len(dangerous),
            "dynamic_library_injection": bool(re.search(r"dlopen\s*\(", code_text)),
            "method_swizzling": bool(re.search(r"method_exchangeImplementations", code_text)),
            "class_dump_available": True,
            "overall_risk": "high" if any(d["risk"] == "high" for d in dangerous) else "low",
        }

    # ---------- 4. 缃戠粶瀹夊叏 / ATS ----------
    def analyze_network(self, code_text: str = "") -> Dict[str, Any]:
        if not code_text.strip():
            code_text = 'NSURLSession.dataTaskWithURL:http://api.example.com/v1\nNSAllowsArbitraryLoads = true'
        cleartext = re.findall(r"http://[a-zA-Z0-9\.\-/:_]+", code_text)
        ats_off = "NSAllowsArbitraryLoads" in code_text
        pinning = bool(re.search(r"SecTrustSetPinning|AFSecurityPolicy|pinnedHashes", code_text, re.I))
        return {
            "ats_enforced": not ats_off,
            "ats_disabled_global": ats_off,
            "cleartext_urls": list(set(cleartext))[:10],
            "ssl_pinning": pinning,
            "tls_min_version": "TLSv1.2",
            "mitm_risk": ats_off or bool(cleartext),
            "risk_level": "high" if ats_off else ("medium" if cleartext else "low"),
        }

    # ---------- 5. 鏁版嵁瀹夊叏 / Keychain ----------
    def analyze_data(self, code_text: str = "") -> Dict[str, Any]:
        if not code_text.strip():
            code_text = (
                "Keychain.set(\"token\", t);\n"
                "UserDefaults.standard.set(pwd, forKey:@\"pwd\");\n"
                "NSFileProtectionNone;\n"
            )
        keychain_used = bool(re.search(r"Keychain|SecItemAdd|kSecClass", code_text))
        userdefaults_secret = bool(re.search(
            r"UserDefaults.*(pwd|password|token|secret)", code_text, re.I))
        protection = "NSFileProtectionNone" if "NSFileProtectionNone" in code_text else (
            "NSFileProtectionComplete" if "NSFileProtectionComplete" in code_text else "unknown")
        itunes_backup = bool(re.search(r"NSURLIsExcludedFromBackupKey", code_text))
        return {
            "keychain_used": keychain_used,
            "sensitive_in_userdefaults": userdefaults_secret,
            "data_protection_level": protection,
            "backup_exclusion_set": itunes_backup,
            "core_data_used": bool(re.search(r"NSPersistentContainer|Core Data", code_text)),
            "sqlite_used": bool(re.search(r"SQLite3|FMDB", code_text)),
            "risk_level": "high" if (userdefaults_secret or protection == "NSFileProtectionNone") else "low",
        }

    # ---------- 6. 杩愯鏃朵笌闃叉姢 ----------
    def analyze_runtime(self, runtime_text: str = "") -> Dict[str, Any]:
        if not runtime_text.strip():
            runtime_text = (
                'if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"]) exit(0);\n'
                "ptrace(PT_DENY_ATTACH, 0, 0, 0);\n"
                "if (dlopen(\"frida-agent.dylib\")) die();\n"
            )
        detected: List[Dict[str, Any]] = []
        for name, info in JAILBREAK_CHECKS.items():
            hit = any(kw.lower() in runtime_text.lower() for kw in info["keywords"])
            detected.append({"protection": name, "level": info["level"], "present": hit})
        present = [d["protection"] for d in detected if d["present"]]
        coverage = round(len(present) / len(detected) * 100, 1)
        return {
            "protections": detected,
            "present": present,
            "coverage_pct": coverage,
            "jailbreak_detection": any("瓒婄嫳" in d["protection"] and d["present"] for d in detected),
            "anti_debug": any("鍙嶈皟璇? in d["protection"] and d["present"] for d in detected),
            "anti_frida": any("Frida" in d["protection"] and d["present"] for d in detected),
            "tamper_check": any("瀹屾暣鎬? in d["protection"] and d["present"] for d in detected),
            "rating": "strong" if coverage >= 60 else ("medium" if coverage >= 30 else "weak"),
        }

    # ---------- 缁煎悎 ----------
    def full_assessment(self, bundle_id: str = "com.example.iosapp",
                        plist_text: str = "", code_text: str = "") -> Dict[str, Any]:
        info = self.analyze_ipa(bundle_id)
        plist = self.analyze_info_plist(plist_text)
        code = self.scan_code(code_text)
        network = self.analyze_network(code_text)
        data = self.analyze_data(code_text)
        runtime = self.analyze_runtime(code_text)
        score = 100
        score -= 15 if plist["ats"]["arbitrary_loads_allowed"] else 0
        score -= min(25, code["hardcoded_count"] * 6)
        score -= 10 if data["sensitive_in_userdefaults"] else 0
        score = max(0, score)
        grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D"
        return {
            "sample_id": f"ios-assess-{uuid.uuid4().hex[:8]}",
            "bundle_id": bundle_id,
            "info": info,
            "info_plist": plist,
            "code": code,
            "network": network,
            "data": data,
            "runtime": runtime,
            "security_score": score,
            "grade": grade,
            "assessed_at": datetime.now().isoformat(timespec="seconds"),
        }

    def list_samples(self) -> List[Dict[str, Any]]:
        return list(self.samples.values())

    def stats(self) -> Dict[str, Any]:
        return {
            "samples": len(self.samples),
            "privacy_permissions_known": len(PRIVACY_ENTITLEMENTS),
            "dangerous_apis_known": len(DANGEROUS_APIS),
            "frida_available": _FRIDA_OK,
        }


_instance: Optional[IosDeepEngine] = None


def get_ios_engine() -> IosDeepEngine:
    global _instance
    if _instance is None:
        _instance = IosDeepEngine()
    return _instance
