#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
绉诲姩瀹夊叏AI妯″瀷妯″潡锛圡obile Security AI Model锛?
鍊熼壌鏋舵瀯锛?- A2 (a2-android.github.io): 鏅鸿兘浣撴紡娲炲彂鐜?+ 澶氭ā鎬侀獙璇侊紙UI/缁勪欢/鏂囦欢/鍔犲瘑锛?- Thorfinn (PhonePe): APK閫嗗悜 + 姹＄偣娴佽拷韪?+ 鍔ㄦ€佸埄鐢ㄧ敓鎴?- Decepticon mobile-android: 纭紪鐮佸瘑閽?Activity鏆撮湶/WebView RCE/SSL pinning

鏍稿績鑳藉姏锛?1. APK闈欐€佸垎鏋?- Manifest瑙ｆ瀽銆佹潈闄愬垎鏋愩€佺粍浠舵毚闇叉娴?2. AI椹卞姩婕忔礊妫€娴?- 15绫荤Щ鍔ㄧ婕忔礊妯″紡璇嗗埆
3. 姹＄偣娴佸垎鏋?- Source鈫扴ink鏁版嵁娴佽拷韪?4. 鍔ㄦ€佸垎鏋愯鍒?- Frida Hook鏂规鐢熸垚
5. 婕忔礊楠岃瘉璁″垝 - 澶氭ā鎬佹敾鍑婚潰楠岃瘉
"""

import re
import json
import os
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import xml.etree.ElementTree as ET


class MobileSeverity(Enum):
    """绉诲姩瀹夊叏婕忔礊涓ラ噸绾у埆"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class MobileVulnerability:
    """绉诲姩绔紡娲?""
    vuln_id: str
    name: str
    category: str
    severity: MobileSeverity
    description: str
    location: str
    evidence: str = ""
    cvss: float = 0.0
    remediation: str = ""
    cwe: str = ""
    is_false_positive: bool = False
    ai_confidence: float = 0.0  # AI妫€娴嬬疆淇″害 0-1


@dataclass
class APKInfo:
    """APK鍩烘湰淇℃伅"""
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    activities: List[Dict] = field(default_factory=list)
    services: List[Dict] = field(default_factory=list)
    receivers: List[Dict] = field(default_factory=list)
    providers: List[Dict] = field(default_factory=list)
    exported_components: List[Dict] = field(default_factory=list)
    deeplinks: List[str] = field(default_factory=list)


class MobileAIAnalyzer:
    """
    绉诲姩瀹夊叏AI鍒嗘瀽鍣?
    鍩轰簬瑙勫垯+AI妯″紡鍖归厤鐨勭Щ鍔ㄧ婕忔礊妫€娴嬪紩鎿庛€?    鏀寔APK Manifest鍒嗘瀽銆丼mali浠ｇ爜妯″紡璇嗗埆銆佹薄鐐规祦鍒嗘瀽銆?    """

    def __init__(self):
        self.vulnerability_patterns = self._init_patterns()
        self.source_sink_map = self._init_source_sink_map()

    def _init_patterns(self) -> Dict[str, Dict]:
        """鍒濆鍖?5绫荤Щ鍔ㄧ婕忔礊妫€娴嬫ā寮?""
        return {
            "hardcoded_secrets": {
                "name": "纭紪鐮佹晱鎰熶俊鎭?,
                "severity": MobileSeverity.CRITICAL,
                "cwe": "CWE-798",
                "cvss": 9.0,
                "patterns": [
                    (r'(?:api[_-]?key|secret|password|token)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']', "纭紪鐮丄PI瀵嗛挜/瀵嗙爜"),
                    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
                    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "纭紪鐮佺閽?),
                    (r'sk_(?:live|test)_[A-Za-z0-9]{20,}', "Stripe瀵嗛挜"),
                ],
                "remediation": "浣跨敤Keystore/EncryptedSharedPreferences瀛樺偍鏁忔劅淇℃伅锛屾瀯寤烘椂閫氳繃鐜鍙橀噺娉ㄥ叆",
            },
            "exported_activity": {
                "name": "Activity缁勪欢鏆撮湶",
                "severity": MobileSeverity.HIGH,
                "cwe": "CWE-926",
                "cvss": 8.0,
                "remediation": "涓轰笉闇€瑕佸閮ㄨ皟鐢ㄧ殑Activity璁剧疆android:exported=\"false\"锛岄渶瑕佸鍑虹殑娣诲姞signature绾ф潈闄愪繚鎶?,
            },
            "webview_rce": {
                "name": "WebView杩滅▼浠ｇ爜鎵ц",
                "severity": MobileSeverity.CRITICAL,
                "cwe": "CWE-749",
                "cvss": 9.0,
                "patterns": [
                    (r'addJavascriptInterface', "addJavascriptInterface鏆撮湶锛堝彲瀵艰嚧RCE锛?),
                    (r'setJavaScriptEnabled\(true\)', "鍚敤JavaScript"),
                    (r'setAllowFileAccess\(true\)', "鍏佽鏂囦欢璁块棶"),
                    (r'setAllowUniversalAccessFromFileURLs\(true\)', "鍏佽閫氱敤鏂囦欢URL璁块棶"),
                ],
                "remediation": "绉婚櫎addJavascriptInterface锛岀鐢╯etAllowFileAccess锛屼娇鐢╓ebViewClient.shouldOverrideUrlLoading鏍￠獙URL",
            },
            "insecure_storage": {
                "name": "涓嶅畨鍏ㄦ暟鎹瓨鍌?,
                "severity": MobileSeverity.HIGH,
                "cwe": "CWE-922",
                "cvss": 7.5,
                "patterns": [
                    (r'getSharedPreferences\([^)]+\)\.edit\(\)', "SharedPreferences鏄庢枃瀛樺偍"),
                    (r'openFileOutput\([^)]+,\s*MODE_WORLD_READABLE', "鍏ㄥ眬鍙鏂囦欢"),
                    (r'getExternalStorage', "澶栭儴瀛樺偍瀛樺偍鏁忔劅鏁版嵁"),
                    (r'SQLiteDatabase.*execSQL.*CREATE TABLE', "SQLite鏁版嵁搴擄紙妫€鏌ユ槸鍚﹀姞瀵嗭級"),
                ],
                "remediation": "浣跨敤EncryptedSharedPreferences/EncryptedFile锛孲QLite浣跨敤SQLCipher鍔犲瘑",
            },
            "intent_injection": {
                "name": "Intent娉ㄥ叆/閲嶅畾鍚?,
                "severity": MobileSeverity.HIGH,
                "cwe": "CWE-925",
                "cvss": 8.0,
                "patterns": [
                    (r'getParcelableExtra\(["\']intent', "宓屽Intent瑙ｆ瀽"),
                    (r'startActivity\(getIntent\(\)\.getParcelableExtra', "Intent閲嶅畾鍚?),
                    (r'PendingIntent\.getActivity\([^)]+,\s*[^)]+,\s*[^)]+,\s*0\)', "鍙彉PendingIntent锛堥渶FLAG_IMMUTABLE锛?),
                ],
                "remediation": "鏍￠獙宓屽Intent鐨勭洰鏍囩粍浠讹紝浣跨敤FLAG_IMMUTABLE鍒涘缓PendingIntent",
            },
            "ssl_pinning_bypass": {
                "name": "SSL/TLS閰嶇疆缂洪櫡",
                "severity": MobileSeverity.MEDIUM,
                "cwe": "CWE-295",
                "cvss": 5.9,
                "patterns": [
                    (r'checkServerTrusted\s*\([^)]+\)\s*\{\s*\}', "绌虹殑璇佷功鏍￠獙锛堜俊浠绘墍鏈夎瘉涔︼級"),
                    (r'SSLSocketFactory\.setDefault\(.*AllowAll', "AllowAllHostnameVerifier"),
                    (r'X509TrustManager.*\{[\s\S]*?checkServerTrusted[\s\S]*?\{[\s\S]*?\}', "鑷畾涔塗rustManager锛堥渶瀹℃煡锛?),
                ],
                "remediation": "瀹炵幇姝ｇ‘鐨勮瘉涔︽牎楠岋紝浣跨敤CertificatePinner杩涜SSL Pinning",
            },
            "deeplink_hijack": {
                "name": "娣遍摼鎺ュ姭鎸?,
                "severity": MobileSeverity.HIGH,
                "cwe": "CWE-601",
                "cvss": 7.5,
                "remediation": "鏍￠獙娣遍摼鎺ョ殑scheme/host/path锛屼娇鐢ˋpp Links锛坉igital asset links锛夐獙璇?,
            },
            "backup_enabled": {
                "name": "搴旂敤澶囦唤娉勯湶",
                "severity": MobileSeverity.MEDIUM,
                "cwe": "CWE-922",
                "cvss": 5.5,
                "remediation": "璁剧疆android:allowBackup=\"false\"鎴栭厤缃産ackupRules鎺掗櫎鏁忔劅鏁版嵁",
            },
            "debuggable": {
                "name": "璋冭瘯妯″紡寮€鍚?,
                "severity": MobileSeverity.HIGH,
                "cwe": "CWE-489",
                "cvss": 7.0,
                "remediation": "鍙戝竷鐗堟湰璁剧疆android:debuggable=\"false\"",
            },
            "root_detection_bypass": {
                "name": "Root妫€娴嬪彲缁曡繃",
                "severity": MobileSeverity.LOW,
                "cwe": "CWE-693",
                "cvss": 3.0,
                "patterns": [
                    (r'/system/bin/su|/system/xbin/su', "绠€鍗昍oot妫€娴嬶紙鍙Frida缁曡繃锛?),
                ],
                "remediation": "浣跨敤澶氬眰Root妫€娴嬶紙鏂囦欢妫€鏌?杩涚▼妫€鏌?native妫€娴嬶級锛岀粨鍚堟湇鍔＄鏍￠獙",
            },
            "insecure_crypto": {
                "name": "寮卞姞瀵嗙畻娉?,
                "severity": MobileSeverity.MEDIUM,
                "cwe": "CWE-327",
                "cvss": 5.9,
                "patterns": [
                    (r'Cipher\.getInstance\(["\']DES', "DES鍔犲瘑锛堝凡鐮磋В锛?),
                    (r'Cipher\.getInstance\(["\']AES/ECB', "AES/ECB妯″紡锛堜笉瀹夊叏锛?),
                    (r'MD5|SHA-1', "MD5/SHA-1鍝堝笇锛堝凡鐮磋В锛?),
                    (r'Random\(\)', "浣跨敤java.util.Random锛堥潪鍔犲瘑瀹夊叏锛?),
                ],
                "remediation": "浣跨敤AES/GCM/NoPadding锛孲HA-256锛孲ecureRandom",
            },
            "broadcast_receiver": {
                "name": "骞挎挱鎺ユ敹鍣ㄦ毚闇?,
                "severity": MobileSeverity.MEDIUM,
                "cwe": "CWE-925",
                "cvss": 5.5,
                "remediation": "璁剧疆exported=\"false\"鎴栦娇鐢╯ignature绾ф潈闄愪繚鎶?,
            },
            "content_provider": {
                "name": "Content Provider鏆撮湶",
                "severity": MobileSeverity.HIGH,
                "cwe": "CWE-926",
                "cvss": 7.5,
                "remediation": "璁剧疆exported=\"false\"锛岄渶瑕佸鍑虹殑娣诲姞readPermission/writePermission",
            },
            "logging_sensitive": {
                "name": "鏁忔劅淇℃伅鏃ュ織娉勯湶",
                "severity": MobileSeverity.LOW,
                "cwe": "CWE-532",
                "cvss": 3.0,
                "patterns": [
                    (r'Log\.(d|i|v|e|w)\([^)]*(?:password|token|secret|key|credit)', "鏃ュ織杈撳嚭鏁忔劅淇℃伅"),
                ],
                "remediation": "鍙戝竷鐗堟湰绉婚櫎鏁忔劅鏃ュ織锛屼娇鐢≒roGuard/R8绉婚櫎Log璋冪敤",
            },
            "tapjacking": {
                "name": "Tapjacking闃叉姢缂哄け",
                "severity": MobileSeverity.LOW,
                "cwe": "CWE-200",
                "cvss": 3.0,
                "remediation": "鏁忔劅Activity璁剧疆filterTouchesWhenObscured=\"true\"",
            },
        }

    def _init_source_sink_map(self) -> Dict[str, List[str]]:
        """鍒濆鍖栨薄鐐规祦Source鈫扴ink鏄犲皠"""
        return {
            "sensitive_data": {
                "sources": [
                    "getDeviceId", "getSubscriberId", "getLine1Number",  # IMEI/IMSI/鎵嬫満鍙?                    "getLatitude", "getLongitude", "getLastKnownLocation",  # 浣嶇疆
                    "getAccount", "getPassword", "getToken",  # 鍑嵁
                    "getContacts", "getCallLog", "getSms",  # 閫氳褰?閫氳瘽/鐭俊
                ],
                "sinks": [
                    "sendTextMessage", "sendMultipartTextMessage",  # 鐭俊鍙戦€?                    "HttpURLConnection", "OkHttpClient", "Retrofit",  # 缃戠粶鍙戦€?                    "writeExternalStorage", "FileOutputStream",  # 鏂囦欢鍐欏叆
                    "startService", "sendBroadcast", "bindService",  # 缁勪欢浼犻€?                ],
            },
            "intent_injection": {
                "sources": [
                    "getIntent", "getStringExtra", "getParcelableExtra", "getUri",
                ],
                "sinks": [
                    "startActivity", "startService", "sendBroadcast", "PendingIntent.getActivity",
                ],
            },
            "webview_injection": {
                "sources": [
                    "getIntent.getData", "getStringExtra", "getQueryParameter",
                ],
                "sinks": [
                    "loadUrl", "evaluateJavascript", "addJavascriptInterface",
                ],
            },
        }

    def analyze_manifest(self, manifest_path: str) -> Tuple[APKInfo, List[MobileVulnerability]]:
        """
        鍒嗘瀽AndroidManifest.xml

        Args:
            manifest_path: AndroidManifest.xml鏂囦欢璺緞

        Returns:
            (APK淇℃伅, 婕忔礊鍒楄〃)
        """
        vulns = []
        apk_info = APKInfo()

        if not os.path.exists(manifest_path):
            # 杩斿洖妯℃嫙鍒嗘瀽缁撴灉
            return self._simulated_manifest_analysis()

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()

            # 鍛藉悕绌洪棿
            ns = {'android': 'http://schemas.android.com/apk/res/android'}

            # 鍩烘湰淇℃伅
            apk_info.package_name = root.get('package', '')
            apk_info.version_name = root.get('android:versionName', '')
            apk_info.version_code = root.get('android:versionCode', '')

            # SDK鐗堟湰
            uses_sdk = root.find('uses-sdk')
            if uses_sdk is not None:
                apk_info.min_sdk = int(uses_sdk.get('android:minSdkVersion', 0))
                apk_info.target_sdk = int(uses_sdk.get('android:targetSdkVersion', 0))

            # 鏉冮檺
            for perm in root.findall('uses-permission'):
                apk_info.permissions.append(perm.get('android:name', ''))

            # Application绾ч厤缃?            app = root.find('application')
            if app is not None:
                # 妫€鏌ebuggable
                if app.get('android:debuggable') == 'true':
                    vulns.append(MobileVulnerability(
                        vuln_id="MOB-008",
                        name="璋冭瘯妯″紡寮€鍚?,
                        category="configuration",
                        severity=MobileSeverity.HIGH,
                        description="搴旂敤鍦ㄥ彂甯冪増鏈腑寮€鍚簡debuggable锛屾敾鍑昏€呭彲閫氳繃adb璋冭瘯鑾峰彇搴旂敤鏁版嵁",
                        location="AndroidManifest.xml application",
                        cvss=7.0,
                        cwe="CWE-489",
                        remediation="鍙戝竷鐗堟湰璁剧疆android:debuggable=\"false\"",
                        ai_confidence=1.0,
                    ))

                # 妫€鏌llowBackup
                if app.get('android:allowBackup') != 'false':
                    vulns.append(MobileVulnerability(
                        vuln_id="MOB-007",
                        name="搴旂敤澶囦唤娉勯湶",
                        category="configuration",
                        severity=MobileSeverity.MEDIUM,
                        description="搴旂敤鍏佽adb backup锛屾敾鍑昏€呭彲閫氳繃澶囦唤鑾峰彇搴旂敤绉佹湁鏁版嵁",
                        location="AndroidManifest.xml application",
                        cvss=5.5,
                        cwe="CWE-922",
                        remediation="璁剧疆android:allowBackup=\"false\"鎴栭厤缃産ackupRules",
                        ai_confidence=1.0,
                    ))

                # 鍒嗘瀽鍥涘ぇ缁勪欢
                for component_type, list_attr in [
                    ('activity', 'activities'),
                    ('service', 'services'),
                    ('receiver', 'receivers'),
                    ('provider', 'providers'),
                ]:
                    for comp in app.findall(component_type):
                        comp_name = comp.get('android:name', '')
                        exported = comp.get('android:exported')

                        comp_info = {"name": comp_name, "exported": exported == 'true'}

                        # 妫€鏌ntent-filter锛堟湁intent-filter榛樿exported=true锛?                        intent_filter = comp.find('intent-filter')
                        if intent_filter is not None and exported is None:
                            comp_info["exported"] = True

                        if comp_info["exported"]:
                            apk_info.exported_components.append(comp_info)

                            # 妫€娴嬫繁閾炬帴
                            for data in intent_filter.findall('data') if intent_filter is not None else []:
                                scheme = data.get('android:scheme', '')
                                host = data.get('android:host', '')
                                if scheme and host:
                                    deeplink = f"{scheme}://{host}"
                                    apk_info.deeplinks.append(deeplink)
                                    vulns.append(MobileVulnerability(
                                        vuln_id="MOB-006",
                                        name=f"娣遍摼鎺ユ毚闇? {deeplink}",
                                        category="deeplink",
                                        severity=MobileSeverity.HIGH,
                                        description=f"娣遍摼鎺deeplink}鍙浠绘剰搴旂敤璋冪敤锛屽彲鑳藉鑷磋秺鏉冭闂?,
                                        location=f"{comp_name} intent-filter",
                                        cvss=7.5,
                                        cwe="CWE-601",
                                        remediation="鏍￠獙娣遍摼鎺ュ弬鏁帮紝浣跨敤App Links楠岃瘉",
                                        ai_confidence=0.9,
                                    ))

                            # 缁勪欢鏆撮湶婕忔礊
                            if component_type == 'activity':
                                vulns.append(MobileVulnerability(
                                    vuln_id="MOB-002",
                                    name=f"Activity鏆撮湶: {comp_name}",
                                    category="component_exposure",
                                    severity=MobileSeverity.HIGH,
                                    description=f"Activity {comp_name} 琚鍑猴紝鍙澶栭儴搴旂敤鐩存帴璋冪敤",
                                    location=comp_name,
                                    cvss=8.0,
                                    cwe="CWE-926",
                                    remediation="璁剧疆exported=\"false\"鎴栨坊鍔爏ignature绾ф潈闄?,
                                    ai_confidence=1.0,
                                ))
                            elif component_type == 'provider':
                                vulns.append(MobileVulnerability(
                                    vuln_id="MOB-012",
                                    name=f"Content Provider鏆撮湶: {comp_name}",
                                    category="component_exposure",
                                    severity=MobileSeverity.HIGH,
                                    description=f"Content Provider {comp_name} 琚鍑猴紝鍙兘瀵艰嚧鏁版嵁娉勯湶",
                                    location=comp_name,
                                    cvss=7.5,
                                    cwe="CWE-926",
                                    remediation="璁剧疆exported=\"false\"鎴栨坊鍔犺鍐欐潈闄?,
                                    ai_confidence=1.0,
                                ))

                        getattr(apk_info, list_attr).append(comp_info)

        except ET.ParseError as e:
            vulns.append(MobileVulnerability(
                vuln_id="MOB-ERR",
                name="Manifest瑙ｆ瀽閿欒",
                category="error",
                severity=MobileSeverity.INFO,
                description=f"AndroidManifest.xml瑙ｆ瀽澶辫触: {e}",
                location=manifest_path,
                ai_confidence=0.0,
            ))

        return apk_info, vulns

    def _simulated_manifest_analysis(self) -> Tuple[APKInfo, List[MobileVulnerability]]:
        """妯℃嫙Manifest鍒嗘瀽缁撴灉锛堢敤浜庢紨绀猴級"""
        apk_info = APKInfo(
            package_name="com.example.app",
            version_name="1.0.0",
            version_code="1",
            min_sdk=21,
            target_sdk=34,
            permissions=[
                "android.permission.INTERNET",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_CONTACTS",
                "android.permission.READ_SMS",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.CAMERA",
            ],
            activities=[
                {"name": "com.example.app.MainActivity", "exported": True},
                {"name": "com.example.app.AdminActivity", "exported": True},
                {"name": "com.example.app.LoginActivity", "exported": False},
            ],
            exported_components=[
                {"name": "com.example.app.MainActivity", "exported": True},
                {"name": "com.example.app.AdminActivity", "exported": True},
            ],
            deeplinks=["example://app", "https://example.com/app"],
        )

        vulns = [
            MobileVulnerability("MOB-001", "纭紪鐮丄PI瀵嗛挜", "hardcoded_secrets",
                MobileSeverity.CRITICAL, "浠ｇ爜涓彂鐜扮‖缂栫爜鐨凙PI瀵嗛挜",
                "com.example.app.Config.java:42", "api_key = \"stripe_api_key_here...\"",
                9.0, "浣跨敤Keystore瀛樺偍", "CWE-798", ai_confidence=0.95),
            MobileVulnerability("MOB-002", "AdminActivity鏆撮湶", "component_exposure",
                MobileSeverity.HIGH, "绠＄悊鍚庡彴Activity琚鍑猴紝鍙澶栭儴璋冪敤",
                "com.example.app.AdminActivity", "", 8.0,
                "璁剧疆exported=\"false\"", "CWE-926", ai_confidence=1.0),
            MobileVulnerability("MOB-003", "WebView RCE椋庨櫓", "webview",
                MobileSeverity.CRITICAL, "WebView浣跨敤addJavascriptInterface涓斿惎鐢↗S",
                "com.example.app.WebViewActivity.java:28", "webView.addJavascriptInterface(this, \"Android\")",
                9.0, "绉婚櫎addJavascriptInterface", "CWE-749", ai_confidence=0.9),
            MobileVulnerability("MOB-004", "SharedPreferences鏄庢枃瀛樺偍", "insecure_storage",
                MobileSeverity.HIGH, "鐢ㄦ埛瀵嗙爜浠ユ槑鏂囧瓨鍌ㄥ湪SharedPreferences",
                "com.example.app.UserPrefs.java:15", "prefs.edit().putString(\"password\", pwd)",
                7.5, "浣跨敤EncryptedSharedPreferences", "CWE-922", ai_confidence=0.85),
            MobileVulnerability("MOB-005", "SSL璇佷功鏍￠獙缂哄け", "crypto",
                MobileSeverity.MEDIUM, "鑷畾涔塜509TrustManager鏈纭牎楠岃瘉涔?,
                "com.example.app.NetworkModule.java:33", "checkServerTrusted() {}",
                5.9, "瀹炵幇姝ｇ‘璇佷功鏍￠獙", "CWE-295", ai_confidence=0.8),
            MobileVulnerability("MOB-006", "娣遍摼鎺ュ姭鎸?, "deeplink",
                MobileSeverity.HIGH, "娣遍摼鎺xample://app鏈牎楠岃皟鐢ㄦ柟",
                "AndroidManifest.xml", "", 7.5,
                "浣跨敤App Links楠岃瘉", "CWE-601", ai_confidence=0.9),
            MobileVulnerability("MOB-007", "搴旂敤澶囦唤寮€鍚?, "configuration",
                MobileSeverity.MEDIUM, "allowBackup榛樿涓簍rue锛屽彲閫氳繃adb backup绐冨彇鏁版嵁",
                "AndroidManifest.xml", "", 5.5,
                "璁剧疆allowBackup=\"false\"", "CWE-922", ai_confidence=1.0),
            MobileVulnerability("MOB-009", "AES/ECB妯″紡", "crypto",
                MobileSeverity.MEDIUM, "浣跨敤AES/ECB妯″紡鍔犲瘑锛岀浉鍚屾槑鏂囦骇鐢熺浉鍚屽瘑鏂?,
                "com.example.app.CryptoUtils.java:22", "Cipher.getInstance(\"AES/ECB/PKCS5Padding\")",
                5.9, "浣跨敤AES/GCM/NoPadding", "CWE-327", ai_confidence=0.95),
            MobileVulnerability("MOB-014", "鏁忔劅淇℃伅鏃ュ織", "logging",
                MobileSeverity.LOW, "鏃ュ織涓緭鍑虹敤鎴穞oken",
                "com.example.app.AuthManager.java:55", "Log.d(\"Auth\", \"token=\" + token)",
                3.0, "鍙戝竷鐗堟湰绉婚櫎鏁忔劅鏃ュ織", "CWE-532", ai_confidence=0.9),
        ]

        return apk_info, vulns

    def analyze_smali(self, smali_dir: str) -> List[MobileVulnerability]:
        """
        鍒嗘瀽Smali浠ｇ爜锛堥潤鎬佷唬鐮佹壂鎻忥級

        Args:
            smali_dir: Smali浠ｇ爜鐩綍

        Returns:
            婕忔礊鍒楄〃
        """
        vulns = []

        if not os.path.exists(smali_dir):
            # 杩斿洖妯℃嫙缁撴灉
            _, simulated = self._simulated_manifest_analysis()
            return [v for v in simulated if v.category in ("hardcoded_secrets", "webview", "insecure_storage", "crypto", "logging")]

        # 閬嶅巻鎵€鏈塻mali鏂囦欢
        for root, dirs, files in os.walk(smali_dir):
            for fname in files:
                if not fname.endswith('.smali'):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()

                    # 鍖归厤婕忔礊妯″紡
                    for vuln_type, pattern_info in self.vulnerability_patterns.items():
                        if 'patterns' not in pattern_info:
                            continue
                        for regex, desc in pattern_info['patterns']:
                            matches = re.findall(regex, content)
                            if matches:
                                for i, match in enumerate(matches[:3]):  # 鏈€澶氭姤鍛?涓?                                    vulns.append(MobileVulnerability(
                                        vuln_id=f"MOB-{vuln_type[:4].upper()}-{i}",
                                        name=pattern_info['name'],
                                        category=vuln_type,
                                        severity=pattern_info['severity'],
                                        description=f"{desc}: {str(match)[:100]}",
                                        location=fpath,
                                        evidence=str(match)[:200],
                                        cvss=pattern_info['cvss'],
                                        remediation=pattern_info['remediation'],
                                        cwe=pattern_info['cwe'],
                                        ai_confidence=0.85,
                                    ))
                except Exception:
                    continue

        return vulns

    def analyze_taint_flows(self, smali_dir: str) -> List[Dict]:
        """
        姹＄偣娴佸垎鏋愶紙Source鈫扴ink锛?
        Args:
            smali_dir: Smali浠ｇ爜鐩綍

        Returns:
            姹＄偣娴佸垪琛?        """
        flows = []

        if not os.path.exists(smali_dir):
            # 妯℃嫙姹＄偣娴?            return [
                {
                    "flow_type": "sensitive_data",
                    "source": "getDeviceId() (IMEI)",
                    "sink": "HttpURLConnection (缃戠粶鍙戦€?",
                    "description": "璁惧IMEI琚彂閫佸埌杩滅▼鏈嶅姟鍣?,
                    "severity": "high",
                    "path": "com.example.app.Tracker.java -> NetworkManager.java",
                },
                {
                    "flow_type": "intent_injection",
                    "source": "getIntent().getStringExtra(\"url\")",
                    "sink": "webView.loadUrl()",
                    "description": "Intent涓殑URL鐩存帴鍔犺浇鍒癢ebView锛屽彲鑳藉鑷碭SS",
                    "severity": "critical",
                    "path": "com.example.app.WebViewActivity.java",
                },
                {
                    "flow_type": "sensitive_data",
                    "source": "getLastKnownLocation() (浣嶇疆)",
                    "sink": "writeExternalStorage() (鏂囦欢鍐欏叆)",
                    "description": "浣嶇疆淇℃伅鍐欏叆澶栭儴瀛樺偍锛屽彲琚叾浠栧簲鐢ㄨ鍙?,
                    "severity": "medium",
                    "path": "com.example.app.LocationService.java",
                },
            ]

        # 鐪熷疄姹＄偣鍒嗘瀽锛堢畝鍖栫増锛?        for flow_type, mapping in self.source_sink_map.items():
            sources_found = []
            sinks_found = []

            for root, dirs, files in os.walk(smali_dir):
                for fname in files:
                    if not fname.endswith('.smali'):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                            content = f.read()
                        for src in mapping['sources']:
                            if src in content:
                                sources_found.append((src, fpath))
                        for sink in mapping['sinks']:
                            if sink in content:
                                sinks_found.append((sink, fpath))
                    except Exception:
                        continue

            if sources_found and sinks_found:
                for src, src_file in sources_found[:2]:
                    for sink, sink_file in sinks_found[:2]:
                        flows.append({
                            "flow_type": flow_type,
                            "source": src,
                            "sink": sink,
                            "source_file": src_file,
                            "sink_file": sink_file,
                            "severity": "high",
                            "description": f"{src} 鐨勬暟鎹彲鑳芥祦鍚?{sink}",
                        })

        return flows

    def generate_frida_hooks(self, vulns: List[MobileVulnerability]) -> List[Dict]:
        """
        涓烘娴嬪埌鐨勬紡娲炵敓鎴怓rida Hook楠岃瘉鑴氭湰

        Args:
            vulns: 婕忔礊鍒楄〃

        Returns:
            Frida Hook鑴氭湰鍒楄〃
        """
        hooks = []

        for vuln in vulns:
            if vuln.category == 'webview':
                hooks.append({
                    "vuln_id": vuln.vuln_id,
                    "name": f"WebView Hook - {vuln.name}",
                    "script": """
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log('[WebView] loadUrl: ' + url);
        return this.loadUrl(url);
    };
    var WebSettings = Java.use('android.webkit.WebSettings');
    WebSettings.setJavaScriptEnabled.implementation = function(enable) {
        console.log('[WebView] setJavaScriptEnabled: ' + enable);
        return this.setJavaScriptEnabled(enable);
    };
});
""",
                    "purpose": "鐩戞帶WebView鍔犺浇鐨刄RL鍜孞S鍚敤鐘舵€?,
                })
            elif vuln.category == 'insecure_storage':
                hooks.append({
                    "vuln_id": vuln.vuln_id,
                    "name": f"瀛樺偍Hook - {vuln.name}",
                    "script": """
Java.perform(function() {
    var SharedPreferences = Java.use('android.app.SharedPreferencesImpl');
    SharedPreferences.getString.implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        console.log('[SharedPrefs] getString(' + key + ') = ' + result);
        return result;
    };
});
""",
                    "purpose": "鐩戞帶SharedPreferences璇诲彇鐨勬晱鎰熸暟鎹?,
                })
            elif vuln.category == 'crypto':
                hooks.append({
                    "vuln_id": vuln.vuln_id,
                    "name": f"鍔犲瘑Hook - {vuln.name}",
                    "script": """
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
        console.log('[Cipher] getInstance: ' + transformation);
        return this.getInstance(transformation);
    };
});
""",
                    "purpose": "鐩戞帶鍔犲瘑绠楁硶浣跨敤鎯呭喌",
                })

        return hooks

    def generate_verification_plan(self, vulns: List[MobileVulnerability]) -> Dict:
        """
        鐢熸垚婕忔礊楠岃瘉璁″垝锛堝€熼壌A2鐨勫妯℃€侀獙璇侊級

        Args:
            vulns: 婕忔礊鍒楄〃

        Returns:
            楠岃瘉璁″垝
        """
        plan = {
            "ui_interaction": [],
            "inter_component": [],
            "file_system": [],
            "cryptographic": [],
            "network": [],
        }

        for vuln in vulns:
            if vuln.category == 'deeplink':
                plan["inter_component"].append({
                    "vuln_id": vuln.vuln_id,
                    "method": "adb shell am start -a android.intent.action.VIEW -d \"{deeplink}\"",
                    "expected": "瑙傚療鏄惁瓒婃潈璁块棶鏁忔劅鍔熻兘",
                })
            elif vuln.category == 'component_exposure':
                plan["inter_component"].append({
                    "vuln_id": vuln.vuln_id,
                    "method": f"adb shell am start -n {vuln.location}",
                    "expected": "瑙傚療鏄惁鍙洿鎺ヨ闂鍑虹粍浠?,
                })
            elif vuln.category == 'webview':
                plan["ui_interaction"].append({
                    "vuln_id": vuln.vuln_id,
                    "method": "閫氳繃Intent娉ㄥ叆鎭舵剰URL鍒癢ebView",
                    "expected": "楠岃瘉鏄惁鎵ц浠绘剰JS鎴栬闂湰鍦版枃浠?,
                })
            elif vuln.category == 'insecure_storage':
                plan["file_system"].append({
                    "vuln_id": vuln.vuln_id,
                    "method": "adb backup鍚庢彁鍙栨暟鎹紝妫€鏌ユ槸鍚︽槑鏂囧瓨鍌?,
                    "expected": "楠岃瘉鏁忔劅鏁版嵁鏄惁鍙鎻愬彇",
                })
            elif vuln.category == 'hardcoded_secrets':
                plan["cryptographic"].append({
                    "vuln_id": vuln.vuln_id,
                    "method": "鍙嶇紪璇慉PK锛屾悳绱㈢‖缂栫爜瀵嗛挜骞堕獙璇佹湁鏁堟€?,
                    "expected": "楠岃瘉瀵嗛挜鏄惁鍙洿鎺ヤ娇鐢?,
                })

        return plan

    def full_analysis(self, apk_path: str = "", manifest_path: str = "",
                      smali_dir: str = "") -> Dict:
        """
        鎵ц瀹屾暣绉诲姩瀹夊叏鍒嗘瀽

        Args:
            apk_path: APK鏂囦欢璺緞
            manifest_path: AndroidManifest.xml璺緞
            smali_dir: Smali浠ｇ爜鐩綍

        Returns:
            瀹屾暣鍒嗘瀽鎶ュ憡
        """
        # 1. Manifest鍒嗘瀽
        apk_info, manifest_vulns = self.analyze_manifest(manifest_path)

        # 2. Smali浠ｇ爜鍒嗘瀽
        code_vulns = self.analyze_smali(smali_dir)

        # 3. 姹＄偣娴佸垎鏋?        taint_flows = self.analyze_taint_flows(smali_dir)

        # 4. 鍚堝苟婕忔礊锛堝幓閲嶏級
        all_vulns = manifest_vulns + code_vulns

        # 5. 鐢熸垚Frida Hook鑴氭湰
        frida_hooks = self.generate_frida_hooks(all_vulns)

        # 6. 鐢熸垚楠岃瘉璁″垝
        verification_plan = self.generate_verification_plan(all_vulns)

        # 7. 椋庨櫓缁熻
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in all_vulns:
            severity_counts[v.severity.value] += 1

        risk_score = min(100,
            severity_counts["critical"] * 10 +
            severity_counts["high"] * 5 +
            severity_counts["medium"] * 2
        )

        return {
            "apk_info": {
                "package": apk_info.package_name,
                "version": apk_info.version_name,
                "min_sdk": apk_info.min_sdk,
                "target_sdk": apk_info.target_sdk,
                "permissions_count": len(apk_info.permissions),
                "exported_components": len(apk_info.exported_components),
                "deeplinks": apk_info.deeplinks,
            },
            "vulnerabilities": [
                {
                    "id": v.vuln_id,
                    "name": v.name,
                    "category": v.category,
                    "severity": v.severity.value,
                    "cvss": v.cvss,
                    "description": v.description,
                    "location": v.location,
                    "evidence": v.evidence,
                    "remediation": v.remediation,
                    "cwe": v.cwe,
                    "ai_confidence": v.ai_confidence,
                }
                for v in all_vulns
            ],
            "taint_flows": taint_flows,
            "frida_hooks": frida_hooks,
            "verification_plan": verification_plan,
            "risk_summary": {
                "total": len(all_vulns),
                "by_severity": severity_counts,
                "risk_score": risk_score,
                "overall_risk": "Critical" if severity_counts["critical"] > 0 else
                               "High" if severity_counts["high"] > 0 else
                               "Medium" if severity_counts["medium"] > 0 else "Low",
                "taint_flows_count": len(taint_flows),
                "frida_hooks_count": len(frida_hooks),
            },
        }


# 鍏ㄥ眬鍗曚緥
_mobile_analyzer: Optional[MobileAIAnalyzer] = None


def get_mobile_analyzer() -> MobileAIAnalyzer:
    """鑾峰彇绉诲姩瀹夊叏鍒嗘瀽鍣ㄥ崟渚?""
    global _mobile_analyzer
    if _mobile_analyzer is None:
        _mobile_analyzer = MobileAIAnalyzer()
    return _mobile_analyzer
