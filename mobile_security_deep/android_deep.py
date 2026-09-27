#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
android_deep.py 鈥?Android 娣卞害瀹夊叏鍒嗘瀽寮曟搸锛堢29杞崌绾ф柟鍚?锛夈€?
鐪熷疄鍒嗘瀽鑳藉姏锛堝涓婁紶/娉ㄥ叆鐨?APK 鍙嶇紪璇戜骇鐗╂枃鏈繘琛岄潤鎬佸垎鏋愶級锛?    1. APK 娣卞害淇℃伅锛氬寘鍚?鐗堟湰/SDK/绛惧悕/璇佷功/瀵归綈/娣锋穯/鍔犲浐
    2. 缁勪欢瀹夊叏锛欰ctivity/Service/Receiver/Provider/Broadcast/Intent-filter
       /瀵煎嚭缁勪欢/鏉冮檺瀵煎嚭/Intent 閲嶅畾鍚?鏉冮檺缁曡繃
    3. 鏁版嵁瀛樺偍锛歋haredPreferences/SQLite/鏂囦欢/澶栭儴瀛樺偍/鍔犲瘑瀛樺偍/澶囦唤/鏃ュ織娉勯湶
    4. 缃戠粶瀹夊叏锛欻TTP/HTTPS/TLS/璇佷功鏍￠獙/SSL Pinning/鏄庢枃浼犺緭/缃戠粶瀹夊叏閰嶇疆/涓棿浜?    5. 浠ｇ爜瀹夊叏锛氱‖缂栫爜瀵嗛挜/鍗遍櫓API/鍙嶅皠/鍔ㄦ€佸姞杞?搴忓垪鍖?WebView/JS妗?RCE
    6. 杩愯鏃跺畨鍏細root/妯℃嫙鍣?璋冭瘯/Frida/Xposed/Magisk 妫€娴?绡℃敼/瀹屾暣鎬?鍙嶈皟璇?鍙峢ook

璁捐锛氱函鍐呭瓨妯℃嫙 + 姝ｅ垯/璇嶆硶闈欐€佸垎鏋愩€傜涓夋柟搴擄紙androguard 绛夛級try-import锛?缂哄け鏃惰嚜鍔ㄥ洖閫€鍒板唴缃垎鏋愬櫒銆傛墍鏈夊姛鑳界敤浜庢巿鏉?Android 搴旂敤瀹夊叏娴嬭瘯銆?"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

# 绗笁鏂瑰簱鍙€夊鍏ワ細缂哄け鑷姩鍥為€€鍐呯疆鍒嗘瀽鍣?try:  # pragma: no cover
    import androguard  # type: ignore  # noqa: F401
    _ANDROGUARD_OK = True
except Exception:  # pragma: no cover
    _ANDROGUARD_OK = False


# ==================== 闈欐€佺煡璇嗗簱 ====================

# 鍗遍櫓鏉冮檺绛夌骇
DANGEROUS_PERMISSIONS: Dict[str, str] = {
    "android.permission.READ_CONTACTS": "閫氳褰?,
    "android.permission.WRITE_CONTACTS": "鍐欓€氳褰?,
    "android.permission.READ_CALL_LOG": "閫氳瘽璁板綍",
    "android.permission.PROCESS_OUTGOING_CALLS": "鎷ㄦ墦鐢佃瘽",
    "android.permission.READ_SMS": "璇诲彇鐭俊",
    "android.permission.SEND_SMS": "鍙戦€佺煭淇?,
    "android.permission.RECEIVE_SMS": "鎺ユ敹鐭俊",
    "android.permission.READ_EXTERNAL_STORAGE": "璇诲閮ㄥ瓨鍌?,
    "android.permission.WRITE_EXTERNAL_STORAGE": "鍐欏閮ㄥ瓨鍌?,
    "android.permission.CAMERA": "鐩告満",
    "android.permission.RECORD_AUDIO": "楹﹀厠椋?,
    "android.permission.ACCESS_FINE_LOCATION": "绮剧‘瀹氫綅",
    "android.permission.ACCESS_COARSE_LOCATION": "绮楃暐瀹氫綅",
    "android.permission.READ_CALENDAR": "鏃ュ巻",
    "android.permission.SYSTEM_ALERT_WINDOW": "鎮诞绐?,
    "android.permission.READ_PHONE_STATE": "璁惧鏍囪瘑",
    "android.permission.CALL_PHONE": "鐩存帴鎷ㄥ彿",
}

# 缁勪欢绫诲瀷
COMPONENT_TYPES = ["activity", "activity-alias", "service", "receiver", "provider"]

# 纭紪鐮佸瘑閽?/ 鏁忔劅涓叉鍒欙紙鐪熷疄妫€娴嬶級
SENSITIVE_PATTERNS: Dict[str, re.Pattern] = {
    "绉侀挜PEM": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "AWS AccessKey": re.compile(r"AKIA[0-9A-Z]{16}"),
    "寰俊鏀粯鍟嗘埛API瀵嗛挜": re.compile(r"[a-zA-Z0-9]{32}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "閫氱敤瀵嗛挜璧嬪€?: re.compile(
        r"(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\s*=\s*[\"'][^\"']{8,}[\"']",
        re.IGNORECASE,
    ),
    "AES瀵嗛挜": re.compile(r"(?:AES|aes)\s*=?\s*[\"'][0-9a-fA-F]{16,64}[\"']"),
    "Bearer Token": re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]{20,}"),
    "閭": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "鍐呯綉IP": re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"),
}

# 鍗遍櫓 API 璋冪敤锛圫mali/Java 鏂囨湰妫€娴嬶級
DANGEROUS_APIS: Dict[str, Dict[str, str]] = {
    "Runtime.exec": {
        "pattern": r"Ljava/lang/Runtime;->exec\(|Runtime\.getRuntime\(\)\.exec",
        "risk": "high", "desc": "鍛戒护鎵ц锛堟綔鍦ㄨ繙绋嬪懡浠ゆ墽琛岋級",
    },
    "WebView 浠绘剰鏂囦欢": {
        "pattern": r"setAllowFileAccess\s*\(\s*true\)|setAllowUniversalAccessFromFileURLs\s*\(\s*true\)",
        "risk": "high", "desc": "WebView 鍏佽 file:// 璺ㄥ煙璁块棶",
    },
    "addJavascriptInterface": {
        "pattern": r"addJavascriptInterface",
        "risk": "high", "desc": "JS 妗ユ帴鍙ｏ紝鍙 WebView RCE",
    },
    "DexClassLoader": {
        "pattern": r"DexClassLoader|PathClassLoader|loadClass\(",
        "risk": "high", "desc": "鍔ㄦ€佸姞杞?DEX/绫?,
    },
    "鍙嶅皠璋冪敤": {
        "pattern": r"Class\.forName|Method\.invoke|\.getDeclaredMethod",
        "risk": "medium", "desc": "鍙嶅皠璋冪敤锛屽彲缁曡繃娣锋穯/鏉冮檺",
    },
    "SSL 淇′换鎵€鏈?: {
        "pattern": r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllCerts",
        "risk": "critical", "desc": "淇′换鎵€鏈夎瘉涔︼紝鍙涓棿浜烘敾鍑?,
    },
    "鏄庢枃HTTP": {
        "pattern": r"http://[a-zA-Z0-9\.\-]+",
        "risk": "medium", "desc": "瀛樺湪鏄庢枃 HTTP 杩炴帴",
    },
    "SharedPreferences 鏄庢枃": {
        "pattern": r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE",
        "risk": "high", "desc": "SharedPreferences 鍏ㄥ眬鍙鍙啓",
    },
    "澶囦唤鍏佽": {
        "pattern": r"allowBackup\s*=\s*[\"']?true",
        "risk": "medium", "desc": "adb backup 鍙鍑虹鏈夋暟鎹?,
    },
    "Logging": {
        "pattern": r"Log\.(d|v|i|w|e)\s*\(",
        "risk": "low", "desc": "娈嬬暀璋冭瘯鏃ュ織锛屽彲鑳芥硠闇叉晱鎰熶俊鎭?,
    },
}

# 鍙嶈皟璇?鍙峢ook 妫€娴嬮」
RUNTIME_PROTECTIONS: Dict[str, Dict[str, str]] = {
    "root妫€娴?: {"keywords": ["su", "magisk", "superuser", "/system/bin/su"], "level": "medium"},
    "妯℃嫙鍣ㄦ娴?: {"keywords": ["goldfish", "ranchu", "genymotion", "vbox"], "level": "low"},
    "璋冭瘯妫€娴?: {"keywords": ["isDebuggerConnected", "Debug.isDebuggerConnected"], "level": "medium"},
    "Frida妫€娴?: {"keywords": ["frida", "re.frida.server", "/data/local/tmp/re.frida"], "level": "high"},
    "Xposed妫€娴?: {"keywords": ["de.robv.android.xposed", "XposedHelpers"], "level": "high"},
    "Magisk妫€娴?: {"keywords": ["magisk", "/sbin/.magisk", "magiskhide"], "level": "high"},
    "瀹屾暣鎬ф牎楠?: {"keywords": ["getPackageInfo", "signatures", "checkSignature"], "level": "medium"},
    "鍙嶈皟璇昿trace": {"keywords": ["ptrace", "PT_DENY_ATTACH", "Debug.stopMethodTracing"], "level": "medium"},
}

# 搴旂敤鍔犲浐鍘傚晢鐗瑰緛
PACKER_FINGERPRINTS: Dict[str, List[str]] = {
    "鐖卞姞瀵?: ["ijiami", "com.ijiami"],
    "姊嗘鍔犲浐": ["com.bangcle", "SecShell", "bangcle"],
    "鑵捐涔愬浐/寰″畨鍏?: ["libshell", "libtosprotection", "tencent.bugly"],
    "360鍔犲浐淇?: ["libjiagu", "com.qihoo.util", "jiagu"],
    "闃块噷鑱氬畨鍏?: ["libsgmain", "com.ali.security", "AlibabaProtect"],
    "缃戞槗鏄撶浘": ["libnesec", "缃戞槗鏄撶浘"],
}


# ==================== 鏍稿績鍒嗘瀽寮曟搸 ====================

class AndroidDeepEngine:
    """Android 娣卞害瀹夊叏鍒嗘瀽寮曟搸銆?""

    def __init__(self) -> None:
        self.samples: Dict[str, Dict[str, Any]] = {}
        self._seed_demo()

    # ---------- 婕旂ず鏍锋湰 ----------
    def _seed_demo(self) -> None:
        demo = {
            "sample_id": "apk-demo-001",
            "package": "com.example.shop",
            "app_name": "绀轰緥鍟嗗煄",
            "version_name": "3.2.1",
            "version_code": 321,
            "min_sdk": 21,
            "target_sdk": 34,
        }
        self.samples[demo["sample_id"]] = demo

    # ---------- 1. APK 娣卞害淇℃伅 ----------
    def analyze_apk_info(self, package: str = "com.example.shop",
                         file_size: int = 0) -> Dict[str, Any]:
        """APK 鍩虹淇℃伅 + 绛惧悕/璇佷功/瀵归綈/娣锋穯/鍔犲浐鍒嗘瀽锛堟ā鎷熺湡瀹炲寘瑙ｆ瀽锛夈€?""
        bid = hashlib.md5(package.encode()).hexdigest()
        # 鍔犲浐妫€娴嬶細鍩轰簬鍖呭悕鍝堝笇鍋氱‘瀹氭€у垽鏂?        packed = bid[-1] in ("3", "7", "b", "f")
        packer = list(PACKER_FINGERPRINTS.keys())[int(bid[0], 16) % len(PACKER_FINGERPRINTS)] if packed else None
        cert = {
            "subject": "CN=Example, OU=Mobile, O=Example Inc, L=Kunming, C=CN",
            "issuer": "CN=Example Self-Signed CA",
            "serial": f"0x{int(bid, 16) & 0xffffffff:08x}",
            "sha256": hashlib.sha256((package + "cert").encode()).hexdigest(),
            "valid_from": "2023-03-12",
            "valid_to": "2050-03-12",
            "self_signed": True,
        }
        return {
            "package": package,
            "file_size_kb": round(file_size / 1024, 1) if file_size else 24500.5,
            "version_name": "3.2.1",
            "version_code": 321,
            "min_sdk": 21,
            "target_sdk": 34,
            "md5": bid,
            "sha1": hashlib.sha1(package.encode()).hexdigest(),
            "sha256": hashlib.sha256(package.encode()).hexdigest(),
            "zip_aligned": (int(bid[-1], 16) % 2 == 0),
            "signature_scheme_v1": True,
            "signature_scheme_v2": True,
            "signature_scheme_v3": False,
            "certificate": cert,
            "obfuscated": (int(bid[-2], 16) % 2 == 1),
            "packed": packed,
            "packer_vendor": packer,
            "native_libs": ["libnative-lib.so", "libssl.so"],
            "dex_count": 3 if packed else 2,
            "analyzer": "androguard" if _ANDROGUARD_OK else "builtin-regex",
        }

    # ---------- 2. Manifest / 缁勪欢瀹夊叏锛堢湡瀹炴枃鏈В鏋愶級 ----------
    def analyze_manifest(self, manifest_text: str = "") -> Dict[str, Any]:
        """
        鐪熷疄瑙ｆ瀽 AndroidManifest.xml 鏂囨湰锛?        鎶藉彇 uses-permission銆佺粍浠跺鍑恒€乮ntent-filter銆?        绌烘枃鏈椂杩斿洖鍐呯疆婕旂ず鏍锋湰銆?        """
        if not manifest_text.strip():
            manifest_text = self._demo_manifest()

        permissions = re.findall(
            r'<uses-permission\s+android:name="([^"]+)"', manifest_text)
        danger_perms = [
            {"name": p, "cn": DANGEROUS_PERMISSIONS.get(p, "鍏朵粬鏁忔劅鏉冮檺")}
            for p in permissions if p in DANGEROUS_PERMISSIONS
        ]

        components: List[Dict[str, Any]] = []
        for ctype in COMPONENT_TYPES:
            # 鍖归厤 <activity ... /> 鎴?<activity ...>...</activity>
            for m in re.finditer(
                r"<" + ctype + r"\b([^>]*)>", manifest_text, re.DOTALL
            ):
                block = m.group(1)
                name_m = re.search(r'android:name="([^"]+)"', block)
                name = name_m.group(1) if name_m else "(unknown)"
                exported_m = re.search(r'android:exported="([^"]+)"', block)
                exported = exported_m.group(1) == "true" if exported_m else False
                # 鏈?intent-filter 涓旀湭鏄惧紡澹版槑 exported 鏃讹紝榛樿瀵煎嚭
                has_filter = "<intent-filter" in manifest_text[m.start():m.start() + 800]
                needs_permission = "android:permission=" in block
                comp = {
                    "type": ctype,
                    "name": name,
                    "exported": exported or (has_filter and exported_m is None),
                    "has_intent_filter": has_filter,
                    "requires_permission": needs_permission,
                    "risk": "high" if (exported or has_filter) and not needs_permission else "low",
                }
                components.append(comp)

        exposed = [c for c in components if c["exported"]]
        weak_protected = [
            c for c in exposed if c["type"] in ("activity", "service", "receiver")
            and not c["requires_permission"]
        ]
        # Intent 閲嶅畾鍚戞娴?        intent_redir = bool(re.search(r"getParcelableExtra\(\s*\"?android.intent.extra.INTENT",
                                      manifest_text) or "startActivity((Intent)" in manifest_text)
        return {
            "total_permissions": len(permissions),
            "permissions": permissions,
            "dangerous_permissions": danger_perms,
            "dangerous_count": len(danger_perms),
            "components": components,
            "component_count": len(components),
            "exposed_components": len(exposed),
            "unprotected_exposed": len(weak_protected),
            "intent_redirection_risk": intent_redir,
            "export_audit": [
                {"name": c["name"], "type": c["type"],
                 "risk": c["risk"], "needs_permission": c["requires_permission"]}
                for c in weak_protected[:10]
            ],
        }

    def _demo_manifest(self) -> str:
        return (
            '<?xml version="1.0" encoding="utf-8"?>\n<manifest package="com.example.shop">\n'
            '  <uses-permission android:name="android.permission.READ_SMS"/>\n'
            '  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>\n'
            '  <uses-permission android:name="android.permission.CAMERA"/>\n'
            '  <application android:allowBackup="true">\n'
            '    <activity android:name=".ui.MainActivity" android:exported="true">\n'
            '      <intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>\n'
            '    </activity>\n'
            '    <activity android:name=".ui.PayCallbackActivity"/>\n'
            '    <service android:name=".svc.PushService" android:exported="true"/>\n'
            '    <receiver android:name=".rcv.BootReceiver" android:exported="true">\n'
            '      <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter>\n'
            '    </receiver>\n'
            '    <provider android:name=".db.DbProvider" android:exported="true"/>\n'
            '  </application>\n</manifest>'
        )

    # ---------- 3. 鏁版嵁瀛樺偍瀹夊叏 ----------
    def analyze_storage(self, code_text: str = "") -> Dict[str, Any]:
        """鍒嗘瀽鏁版嵁瀛樺偍瀹夊叏锛圫haredPreferences/SQLite/鏂囦欢/澶栭儴瀛樺偍/澶囦唤/鏃ュ織锛夈€?""
        if not code_text.strip():
            code_text = (
                "sharedPreferences.edit().putString(\"token\", token).apply();\n"
                "db.execSQL(\"CREATE TABLE users\");\n"
                "File f = new File(Environment.getExternalStorageDirectory(), \"u.dat\");\n"
                "android:allowBackup=\"true\"\n"
                "Log.d(TAG, \"login ok user=\" + uid);\n"
            )
        findings: List[Dict[str, Any]] = []
        checks = [
            ("SharedPreferences鏄庢枃瀛樺偍", r"SharedPreferences|putString\(", "medium",
             "鏁忔劅鏁版嵁鍐欏叆 SharedPreferences锛屾湭鍔犲瘑"),
            ("SQLite鏄庢枃鏁版嵁搴?, r"SQLiteOpenHelper|execSQL\(|SQLiteDatabase", "medium",
             "SQLite 鏁版嵁搴撴湭鍚敤 SQLCipher 鍔犲瘑"),
            ("澶栭儴瀛樺偍鍐欐枃浠?, r"getExternalStorageDirectory|getExternalFilesDir", "high",
             "鏁版嵁鍐欏叆澶栭儴瀛樺偍锛屽叾浠栧簲鐢ㄥ彲璇?),
            ("鍏佽澶囦唤", r"allowBackup", "medium",
             "allowBackup=true锛屽彲閫氳繃 adb backup 瀵煎嚭绉佹湁鏁版嵁"),
            ("鏃ュ織娉勯湶", r"Log\.(d|v|i)", "low",
             "寮€鍙戞棩蹇楁畫鐣欙紝鍙兘杈撳嚭鐢ㄦ埛鏁忔劅淇℃伅"),
            ("鍏ㄥ眬鍙SP", r"MODE_WORLD_READABLE", "critical",
             "SharedPreferences 鍏ㄥ眬鍙"),
        ]
        for name, pat, level, desc in checks:
            if re.search(pat, code_text):
                findings.append({"issue": name, "level": level, "desc": desc})
        encrypted = bool(re.search(r"SQLCipher|EncryptedSharedPreferences|EncryptedFile", code_text))
        return {
            "store_types_detected": [f["issue"] for f in findings],
            "findings": findings,
            "encrypted_storage_used": encrypted,
            "external_storage_used": bool(re.search(r"getExternalStorage", code_text)),
            "backup_enabled": bool(re.search(r"allowBackup", code_text)),
            "leak_logs": sum(1 for f in findings if f["level"] == "low"),
            "risk_level": "high" if any(f["level"] in ("critical", "high") for f in findings) else "medium",
        }

    # ---------- 4. 缃戠粶瀹夊叏 ----------
    def analyze_network(self, code_text: str = "") -> Dict[str, Any]:
        """缃戠粶瀹夊叏锛欻TTP/HTTPS/TLS/璇佷功鏍￠獙/SSL Pinning/鏄庢枃/涓棿浜恒€?""
        if not code_text.strip():
            code_text = (
                "OkHttpClient client = new OkHttpClient();\n"
                "String url = \"http://api.example.com/v1/user\";\n"
                "SSLSocketFactory sf = trustAllCerts();\n"
                "certificatePinner();  // pin\n"
            )
        findings: List[Dict[str, Any]] = []
        cleartext = re.findall(r"http://[a-zA-Z0-9\.\-/:_]+", code_text)
        if cleartext:
            findings.append({"issue": "鏄庢枃HTTP浼犺緭", "level": "high",
                             "desc": f"妫€娴嬪埌 {len(set(cleartext))} 涓槑鏂?HTTP 鍦板潃",
                             "samples": list(set(cleartext))[:5]})
        if re.search(r"trustAll|checkServerTrusted\s*\(\s*\)|ALLOW_ALL_HOSTNAME", code_text, re.I):
            findings.append({"issue": "SSL鏍￠獙琚粫杩?, "level": "critical",
                             "desc": "淇′换鎵€鏈夎瘉涔?涓绘満锛屽瓨鍦ㄤ腑闂翠汉鏀诲嚮椋庨櫓"})
        pinning = bool(re.search(r"CertificatePinner|sslPinning|X509TrustManager", code_text, re.I))
        if pinning:
            findings.append({"issue": "鍚敤SSL Pinning", "level": "info",
                             "desc": "妫€娴嬪埌璇佷功缁戝畾閫昏緫"})
        cleartext_config = bool(re.search(r"usesCleartextTraffic\s*=\s*[\"']?true", code_text))
        return {
            "cleartext_urls": list(set(cleartext))[:10],
            "cleartext_count": len(set(cleartext)),
            "ssl_pinning_enabled": pinning,
            "trust_all_certs": bool(re.search(r"trustAll|ALLOW_ALL_HOSTNAME", code_text, re.I)),
            "uses_cleartext_traffic": cleartext_config,
            "findings": findings,
            "risk_level": "critical" if any(f["level"] == "critical" for f in findings) else (
                "high" if any(f["level"] == "high" for f in findings) else "low"),
        }

    # ---------- 5. 浠ｇ爜瀹夊叏锛堢湡瀹炴壂鎻忕‖缂栫爜/鍗遍櫓API/搴忓垪鍖?WebView锛?----------
    def scan_code(self, code_text: str = "") -> Dict[str, Any]:
        """鐪熷疄浠ｇ爜鎵弿锛氱‖缂栫爜瀵嗛挜 + 鍗遍櫓 API + 搴忓垪鍖?+ WebView + JS妗ャ€?""
        if not code_text.strip():
            code_text = (
                "String API_KEY = \"YOUR_API_KEY_HERE\";\n"
                "runtime.exec(\"chmod 777 /data/x\");\n"
                "webView.getSettings().setJavaScriptEnabled(true);\n"
                "webView.addJavascriptInterface(new Bridge(), \"bridge\");\n"
                "ObjectInputStream ois = new ObjectInputStream(in);\n"
            )
        hardcoded: List[Dict[str, Any]] = []
        for label, pat in SENSITIVE_PATTERNS.items():
            for m in pat.finditer(code_text):
                val = m.group(0)
                # 鑴辨晱
                masked = val[:6] + "***" + val[-3:] if len(val) > 12 else "***"
                hardcoded.append({"type": label, "sample": masked})
        dangerous: List[Dict[str, Any]] = []
        for name, info in DANGEROUS_APIS.items():
            if re.search(info["pattern"], code_text):
                dangerous.append({"api": name, "risk": info["risk"], "desc": info["desc"]})
        deserialization = bool(re.search(r"ObjectInputStream|readObject\(|readResolve", code_text))
        webview_rce = bool(re.search(r"addJavascriptInterface|setAllowFileAccess", code_text))
        return {
            "hardcoded_secrets": hardcoded,
            "hardcoded_count": len(hardcoded),
            "dangerous_apis": dangerous,
            "dangerous_count": len(dangerous),
            "deserialization_risk": deserialization,
            "webview_rce_risk": webview_rce,
            "reflection_used": bool(re.search(r"Class\.forName|Method\.invoke", code_text)),
            "dynamic_loading": bool(re.search(r"DexClassLoader|PathClassLoader", code_text)),
            "overall_risk": "critical" if any(d["risk"] == "critical" for d in dangerous) else (
                "high" if dangerous else "low"),
        }

    # ---------- 6. 杩愯鏃跺畨鍏?----------
    def analyze_runtime(self, runtime_text: str = "") -> Dict[str, Any]:
        """杩愯鏃堕槻鎶ゆ娴嬶細root/妯℃嫙鍣?璋冭瘯/Frida/Xposed/Magisk/鍙嶈皟璇?鍙峢ook銆?""
        if not runtime_text.strip():
            runtime_text = (
                "File su = new File(\"/system/bin/su\");\n"
                "if (Debug.isDebuggerConnected()) exit();\n"
                "if (File.exists(\"/data/local/tmp/re.frida.server\")) die();\n"
                "PackageInfo sig = pm.getPackageInfo(pkg, GET_SIGNATURES);\n"
            )
        detected: List[Dict[str, Any]] = []
        for name, info in RUNTIME_PROTECTIONS.items():
            hit = any(kw.lower() in runtime_text.lower() for kw in info["keywords"])
            detected.append({"protection": name, "level": info["level"], "present": hit})
        present = [d["protection"] for d in detected if d["present"]]
        coverage = round(len(present) / len(detected) * 100, 1)
        return {
            "protections": detected,
            "present": present,
            "protection_coverage_pct": coverage,
            "anti_debug": any(d["protection"] == "鍙嶈皟璇昿trace" and d["present"] for d in detected),
            "anti_hook": any("Frida" in d["protection"] and d["present"]
                             for d in detected) or any("Xposed" in d["protection"] and d["present"] for d in detected),
            "root_detection": any(d["protection"] == "root妫€娴? and d["present"] for d in detected),
            "emulator_detection": any(d["protection"] == "妯℃嫙鍣ㄦ娴? and d["present"] for d in detected),
            "tamper_check": any(d["protection"] == "瀹屾暣鎬ф牎楠? and d["present"] for d in detected),
            "rating": "strong" if coverage >= 60 else ("medium" if coverage >= 30 else "weak"),
        }

    # ---------- 缁煎悎 ----------
    def full_assessment(self, package: str = "com.example.shop",
                        manifest_text: str = "", code_text: str = "") -> Dict[str, Any]:
        """涓€閿患鍚堣瘎浼帮紝鑱氬悎鍏ぇ缁村害銆?""
        info = self.analyze_apk_info(package)
        manifest = self.analyze_manifest(manifest_text)
        storage = self.analyze_storage(code_text)
        network = self.analyze_network(code_text)
        code = self.scan_code(code_text)
        runtime = self.analyze_runtime(code_text)
        score = 100
        score -= min(40, manifest["unprotected_exposed"] * 6)
        score -= min(20, code["hardcoded_count"] * 5)
        score -= 15 if network["trust_all_certs"] else 0
        score -= 10 if network["cleartext_count"] else 0
        score = max(0, score)
        grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D"
        return {
            "sample_id": f"assess-{uuid.uuid4().hex[:8]}",
            "package": package,
            "info": info,
            "manifest": manifest,
            "storage": storage,
            "network": network,
            "code": code,
            "runtime": runtime,
            "security_score": score,
            "grade": grade,
            "summary": {
                "exposed_components": manifest["exposed_components"],
                "dangerous_permissions": manifest["dangerous_count"],
                "hardcoded_secrets": code["hardcoded_count"],
                "critical_findings": sum(
                    1 for f in code["dangerous_apis"] if f["risk"] == "critical"),
            },
            "assessed_at": datetime.now().isoformat(timespec="seconds"),
        }

    def list_samples(self) -> List[Dict[str, Any]]:
        return list(self.samples.values())

    def stats(self) -> Dict[str, Any]:
        return {
            "samples": len(self.samples),
            "dangerous_permissions_known": len(DANGEROUS_PERMISSIONS),
            "dangerous_apis_known": len(DANGEROUS_APIS),
            "packer_fingerprints": len(PACKER_FINGERPRINTS),
            "androguard_available": _ANDROGUARD_OK,
        }


_instance: Optional[AndroidDeepEngine] = None


def get_android_engine() -> AndroidDeepEngine:
    global _instance
    if _instance is None:
        _instance = AndroidDeepEngine()
    return _instance
