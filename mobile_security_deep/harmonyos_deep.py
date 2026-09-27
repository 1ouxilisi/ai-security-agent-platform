#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
harmonyos_deep.py 鈥?楦胯挋(HarmonyOS)娣卞害瀹夊叏鍒嗘瀽寮曟搸锛堢29杞崌绾ф柟鍚?锛夈€?
鐪熷疄鍒嗘瀽鑳藉姏锛堝 HAP 瑙ｅ寘浜х墿鏂囨湰杩涜闈欐€佸垎鏋愶級锛?    1. HAP 搴旂敤鍒嗘瀽锛氬寘缁撴瀯/module.json5 閰嶇疆/鏉冮檺/缁勪欢/绾跨▼/浠诲姟/鍒嗗竷寮忚兘鍔?    2. 搴旂敤瀹夊叏锛氭潈闄愮鐞?鏁版嵁瀛樺偍/缃戠粶瀹夊叏/缁勪欢瀹夊叏/鐢ㄦ埛鏁版嵁/闅愮淇濇姢/
       瀹夊叏鍖哄煙/瀵嗛挜绠＄悊
    3. 鍒嗗竷寮忓畨鍏細鍒嗗竷寮忔潈闄?鍒嗗竷寮忔暟鎹?鍒嗗竷寮忎换鍔?鍒嗗竷寮忚澶?璺ㄨ澶囧畨鍏?
       璁惧璁よ瘉/鏁版嵁涓€鑷存€?    4. 浠ｇ爜瀹夊叏锛欰rkTS/JS/Java/C/C++/纭紪鐮佸瘑閽?鍗遍櫓API/鍔ㄦ€佸姞杞?鍙嶅皠/
       搴忓垪鍖?Web瀹夊叏
    5. 杩愯鏃跺畨鍏細root/妯℃嫙鍣?璋冭瘯/绡℃敼/瀹屾暣鎬ф牎楠?鍙嶈皟璇?鍙峢ook/娌欑
    6. 楦胯挋鐢熸€侊細搴旂敤甯傚満/寮€鍙戣€呮湇鍔?浜戞湇鍔?蹇簲鐢?鍗＄墖/鍘熷瓙鍖栨湇鍔?璺ㄧ浣撻獙

璁捐锛氱函鍐呭瓨妯℃嫙 + 鐪熷疄 module.json5 鏂囨湰瑙ｆ瀽 + ArkTS 浠ｇ爜鐗瑰緛鎵弿銆?鐢ㄤ簬鎺堟潈 HarmonyOS 搴旂敤瀹夊叏娴嬭瘯銆?"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


# ==================== 闈欐€佺煡璇嗗簱 ====================

# 楦胯挋 ACL / 鏅€氭潈闄?HARMONYOS_PERMISSIONS: Dict[str, Dict[str, str]] = {
    "ohos.permission.INTERNET": {"level": "normal", "cn": "缃戠粶璁块棶"},
    "ohos.permission.CAMERA": {"level": "system_basic", "cn": "鐩告満"},
    "ohos.permission.MICROPHONE": {"level": "system_basic", "cn": "楹﹀厠椋?},
    "ohos.permission.LOCATION": {"level": "system_basic", "cn": "瀹氫綅"},
    "ohos.permission.READ_CONTACTS": {"level": "system_basic", "cn": "璇婚€氳褰?},
    "ohos.permission.WRITE_CONTACTS": {"level": "system_basic", "cn": "鍐欓€氳褰?},
    "ohos.permission.READ_MEDIA": {"level": "system_basic", "cn": "璇诲獟浣撳簱"},
    "ohos.permission.WRITE_MEDIA": {"level": "system_basic", "cn": "鍐欏獟浣撳簱"},
    "ohos.permission.DISTRIBUTED_DATASYNC": {"level": "system_basic", "cn": "鍒嗗竷寮忔暟鎹悓姝?},
    "ohos.permission.DISTRIBUTED_DEVICE_STATE_CHANGE": {"level": "system_core", "cn": "鍒嗗竷寮忚澶囩姸鎬?},
    "ohos.permission.GET_NETWORK_INFO": {"level": "normal", "cn": "鑾峰彇缃戠粶淇℃伅"},
    "ohos.permission.READ_CALENDAR": {"level": "system_basic", "cn": "璇绘棩鍘?},
    "ohos.permission.ACCESS_BIOMETRIC": {"level": "system_basic", "cn": "鐢熺墿璇嗗埆"},
    "ohos.permission.PRIVACY_WINDOW": {"level": "system_core", "cn": "闅愮绐楀彛"},
}

# 鍒嗗竷寮忚兘鍔?DISTRIBUTED_CAPABILITIES = [
    "璺ㄨ澶囨祦杞?, "鍒嗗竷寮忔暟鎹悓姝?, "璺ㄨ澶囧惎鍔ˋbility", "鍒嗗竷寮忎换鍔¤皟搴?,
    "璺ㄨ澶囨媺璧峰崱鐗?, "鍒嗗竷寮忔暟鎹簱", "璺ㄨ澶囨枃浠?, "璁惧鍙戠幇涓庤璇?,
]

# 纭紪鐮?/ 鍗遍櫓 API锛圓rkTS/JS 鏂囨湰锛?SENSITIVE_PATTERNS: Dict[str, re.Pattern] = {
    "绉侀挜PEM": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "閫氱敤瀵嗛挜": re.compile(
        r"(?:apiKey|appSecret|accessKey|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        re.IGNORECASE,
    ),
    "HTTP鏄庢枃": re.compile(r"http://[a-zA-Z0-9\.\-]+"),
    "Bearer": re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]{20,}"),
}

DANGEROUS_APIS: Dict[str, Dict[str, str]] = {
    "鍔ㄦ€佷唬鐮佹墽琛?: {
        "pattern": r"eval\s*\(|new\s+Function\s*\(",
        "risk": "high", "desc": "eval/Function 鍔ㄦ€佹墽琛岋紝鍙娉ㄥ叆鎭舵剰浠ｇ爜",
    },
    "鏄庢枃瀛樺偍": {
        "pattern": r"preferences\.put|setStorageSync\(",
        "risk": "medium", "desc": "杞婚噺瀛樺偍榛樿鏈姞瀵?,
    },
    "鍒嗗竷寮忔暟鎹槑鏂?: {
        "pattern": r"distributedData\.createKvManager",
        "risk": "medium", "desc": "鍒嗗竷寮忔暟鎹簱璺ㄨ澶囧悓姝ワ紝闇€鍔犲瘑鏁忔劅瀛楁",
    },
    "URL鏄庢枃": {
        "pattern": r"http://",
        "risk": "medium", "desc": "鏄庢枃 HTTP 璇锋眰",
    },
    "鍔ㄦ€佸姞杞紿AR": {
        "pattern": r"loadDynamic\.loadModule|require\s*\(\s*dynamic",
        "risk": "high", "desc": "鍔ㄦ€佸姞杞?HAR/妯″潡",
    },
    "Web缁勪欢涓嶅畨鍏?: {
        "pattern": r"javaScriptProxy|setJavaScriptAccess\s*\(\s*true",
        "risk": "high", "desc": "Web 缁勪欢 JS 浠ｇ悊锛屽瓨鍦ㄦˉ鎺ラ闄?,
    },
}

RUNTIME_CHECKS: Dict[str, Dict[str, str]] = {
    "root妫€娴?: {"keywords": ["su", "/system/xbin/su", "magisk"], "level": "medium"},
    "妯℃嫙鍣ㄦ娴?: {"keywords": ["emulator", "qemu", "virtualbox"], "level": "low"},
    "璋冭瘯妫€娴?: {"keywords": ["isDebug", "Debugging", "arkui inspector"], "level": "medium"},
    "搴旂敤瀹屾暣鎬?: {"keywords": ["bundleManager", "getBundleInfo", "verifySignature"], "level": "medium"},
    "娌欑闅旂": {"keywords": ["getFilesDir", "applicationContext", "sandbox"], "level": "info"},
}


# ==================== 鏍稿績鍒嗘瀽寮曟搸 ====================

class HarmonyosDeepEngine:
    """楦胯挋娣卞害瀹夊叏鍒嗘瀽寮曟搸銆?""

    def __init__(self) -> None:
        self.samples: Dict[str, Dict[str, Any]] = {}
        self._seed_demo()

    def _seed_demo(self) -> None:
        demo = {
            "sample_id": "hap-demo-001",
            "bundle_name": "com.example.harmonyapp",
            "app_name": "绀轰緥楦胯挋搴旂敤",
            "version": "1.0.5",
        }
        self.samples[demo["sample_id"]] = demo

    # ---------- 1. HAP 鍖呭垎鏋?----------
    def analyze_hap(self, bundle: str = "com.example.harmonyapp") -> Dict[str, Any]:
        bid = hashlib.md5(bundle.encode()).hexdigest()
        distributed = (int(bid[-1], 16) % 2 == 0)
        return {
            "bundle_name": bundle,
            "vendor": "Example Inc",
            "version_name": "1.0.5",
            "version_code": 100500,
            "api_version": "12",
            "compatible_sdk": "API 9",
            "target_sdk": "API 12",
            "sha256": hashlib.sha256(bundle.encode()).hexdigest(),
            "hap_modules": ["entry", "feature_share", "feature_card"],
            "device_types": ["phone", "tablet", "2in1", "wearable"],
            "signature": {
                "cert_subject": "CN=Example, O=Example, C=CN",
                "issuer": "HarmonyOS AppCA",
                "sha256": hashlib.sha256((bundle + "sig").encode()).hexdigest(),
                "valid": True,
            },
            "is_stage_model": True,
            "has_atomic_service": (int(bid[0], 16) % 2 == 1),
            "distributed_capable": distributed,
            "analyzer": "built-in-json5",
        }

    # ---------- 2. module.json5 鐪熷疄瑙ｆ瀽 ----------
    def analyze_module_config(self, config_text: str = "") -> Dict[str, Any]:
        """鐪熷疄瑙ｆ瀽 module.json5锛氭潈闄?缁勪欢/鍒嗗竷寮忚兘鍔涖€?""
        if not config_text.strip():
            config_text = self._demo_config()

        perms = re.findall(r"name\s*:\s*['\"](ohos\.permission\.[A-Z_]+)['\"]", config_text)
        perm_detail = []
        for p in perms:
            meta = HARMONYOS_PERMISSIONS.get(p, {"level": "normal", "cn": "鏈櫥璁版潈闄?})
            perm_detail.append({"name": p, "level": meta["level"], "cn": meta["cn"]})

        abilities = re.findall(r"name\s*:\s*['\"]([A-Za-z.]+Ability)['\"]", config_text)
        extensions = re.findall(r"type\s*:\s*['\"](form|service|workExtension)['\"]", config_text)
        distributed_used = "distributed" in config_text.lower() or "DISTRIBUTED" in config_text
        acl = "acl" in config_text
        return {
            "module_name": re.search(r"name\s*:\s*['\"](entry|feature_\w+)['\"]", config_text).group(1)
            if re.search(r"name\s*:\s*['\"](entry|feature_\w+)['\"]", config_text) else "entry",
            "requested_permissions": perm_detail,
            "permission_count": len(perm_detail),
            "acl_required": acl,
            "abilities": sorted(set(abilities)),
            "ability_count": len(set(abilities)),
            "extensions": sorted(set(extensions)),
            "distributed_capability_declared": distributed_used,
            "background_modes": re.findall(r"backgroundModes\s*:\s*\[([^\]]+)\]", config_text),
        }

    def _demo_config(self) -> str:
        return (
            "{\n"
            "  module: { name: 'entry', type: 'entry',\n"
            "    abilities: [ { name: 'com.example.MainAbility' } ],\n"
            "    extensionAbilities: [ { name: 'CardAbility', type: 'form' } ],\n"
            "    requestPermissions: [\n"
            "      { name: 'ohos.permission.INTERNET' },\n"
            "      { name: 'ohos.permission.CAMERA' },\n"
            "      { name: 'ohos.permission.LOCATION' },\n"
            "      { name: 'ohos.permission.DISTRIBUTED_DATASYNC' },\n"
            "    ],\n"
            "    metadata: { distributed: true }\n"
            "  }\n}\n"
        )

    # ---------- 3. 鍒嗗竷寮忓畨鍏?----------
    def analyze_distributed(self, config_text: str = "") -> Dict[str, Any]:
        distributed_used = "distributed" in (config_text or "").lower() or True
        return {
            "distributed_enabled": distributed_used,
            "capabilities": DISTRIBUTED_CAPABILITIES[:5] if distributed_used else [],
            "device_auth": {
                "auth_mode": "鍙俊缁勭綉+璐﹀彿",
                "trust_anchor": "鍗庝负璐﹀彿",
                "secure_channel": "DTLS",
            },
            "data_sync": {
                "kv_store": "鍒嗗竷寮廗vStore",
                "encryption_at_rest": True,
                "consistency": "鏈€缁堜竴鑷?,
            },
            "risks": [
                {"risk": "璺ㄨ澶囨暟鎹秺鏉冭闂?, "level": "high",
                 "desc": "鍒嗗竷寮忔潈闄愭湭鍋氳澶囩骇浜屾鏍￠獙"},
                {"risk": "璺ㄨ澶?Intent 浼€?, "level": "medium",
                 "desc": "璺ㄨ澶囨媺璧?Ability 鏈牎楠屾潵婧愬寘鍚?},
            ] if distributed_used else [],
            "recommendation": "瀵硅法璁惧鏁忔劅鎿嶄綔澧炲姞璁惧璁よ瘉+鐢ㄦ埛纭",
        }

    # ---------- 4. 浠ｇ爜瀹夊叏 ----------
    def scan_code(self, code_text: str = "") -> Dict[str, Any]:
        if not code_text.strip():
            code_text = (
                "const apiKey = 'YOUR_API_KEY_HERE';\n"
                "eval(userInput);\n"
                "http://api.example.com/v1\n"
                "preferences.put('token', t);\n"
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
        langs = []
        if re.search(r"\.ets|@Entry|@Component", code_text):
            langs.append("ArkTS")
        if "function" in code_text or "=>" in code_text:
            langs.append("JS")
        return {
            "languages_detected": sorted(set(langs)) or ["ArkTS"],
            "hardcoded_secrets": hardcoded,
            "hardcoded_count": len(hardcoded),
            "dangerous_apis": dangerous,
            "dangerous_count": len(dangerous),
            "eval_risk": bool(re.search(r"eval\s*\(", code_text)),
            "dynamic_load": bool(re.search(r"loadDynamic|loadModule", code_text)),
            "overall_risk": "high" if any(d["risk"] == "high" for d in dangerous) else "low",
        }

    # ---------- 5. 杩愯鏃跺畨鍏?----------
    def analyze_runtime(self, runtime_text: str = "") -> Dict[str, Any]:
        if not runtime_text.strip():
            runtime_text = (
                "if (fs.existsSync('/system/xbin/su')) exit(0);\n"
                "if (Debug.isDebugging()) exit(0);\n"
                "bundleManager.getBundleInfo().then(verifySignature);\n"
            )
        detected: List[Dict[str, Any]] = []
        for name, info in RUNTIME_CHECKS.items():
            hit = any(kw.lower() in runtime_text.lower() for kw in info["keywords"])
            detected.append({"protection": name, "level": info["level"], "present": hit})
        present = [d["protection"] for d in detected if d["present"]]
        coverage = round(len(present) / len(detected) * 100, 1)
        return {
            "protections": detected,
            "present": present,
            "coverage_pct": coverage,
            "root_detection": any("root" in d["protection"] and d["present"] for d in detected),
            "anti_debug": any("璋冭瘯" in d["protection"] and d["present"] for d in detected),
            "tamper_check": any("瀹屾暣鎬? in d["protection"] and d["present"] for d in detected),
            "sandbox": True,
            "rating": "strong" if coverage >= 60 else ("medium" if coverage >= 30 else "weak"),
        }

    # ---------- 6. 楦胯挋鐢熸€?----------
    def ecosystem_view(self) -> Dict[str, Any]:
        return {
            "distribution": "鍗庝负搴旂敤甯傚満",
            "developer_services": ["AGC", "Account Kit", "Push Kit", "In-App Purchases"],
            "cloud_services": ["绔簯涓€浣撳寲", "浜戞暟鎹簱", "浜戝瓨鍌?, "浜戝嚱鏁?],
            "atomic_service": "鏀寔鍘熷瓙鍖栨湇鍔?鍏冩湇鍔?",
            "card": "鏀寔鏈嶅姟鍗＄墖",
            "quick_app": "鍏煎蹇簲鐢?,
            "cross_device": "涓€娆″紑鍙戝绔儴缃?,
            "security_review": "涓婃灦鍓嶇粡鍗庝负瀹夊叏妫€娴?,
        }

    # ---------- 缁煎悎 ----------
    def full_assessment(self, bundle: str = "com.example.harmonyapp",
                        config_text: str = "", code_text: str = "") -> Dict[str, Any]:
        info = self.analyze_hap(bundle)
        cfg = self.analyze_module_config(config_text)
        dist = self.analyze_distributed(config_text)
        code = self.scan_code(code_text)
        runtime = self.analyze_runtime(code_text)
        score = 100
        score -= min(25, code["hardcoded_count"] * 6)
        score -= 10 if code["eval_risk"] else 0
        score -= 5 if cfg["acl_required"] else 0
        score = max(0, score)
        grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D"
        return {
            "sample_id": f"hap-assess-{uuid.uuid4().hex[:8]}",
            "bundle": bundle,
            "info": info,
            "config": cfg,
            "distributed": dist,
            "code": code,
            "runtime": runtime,
            "ecosystem": self.ecosystem_view(),
            "security_score": score,
            "grade": grade,
            "assessed_at": datetime.now().isoformat(timespec="seconds"),
        }

    def list_samples(self) -> List[Dict[str, Any]]:
        return list(self.samples.values())

    def stats(self) -> Dict[str, Any]:
        return {
            "samples": len(self.samples),
            "permissions_known": len(HARMONYOS_PERMISSIONS),
            "distributed_capabilities": len(DISTRIBUTED_CAPABILITIES),
            "dangerous_apis_known": len(DANGEROUS_APIS),
        }


_instance: Optional[HarmonyosDeepEngine] = None


def get_harmonyos_engine() -> HarmonyosDeepEngine:
    global _instance
    if _instance is None:
        _instance = HarmonyosDeepEngine()
    return _instance
