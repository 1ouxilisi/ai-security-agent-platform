#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
绉诲姩瀹夊叏棰嗗煙娣卞害璇勪及鍣?(Mobile Security Deep Assessor)

鍩轰簬缁熶竴瀹夊叏璇勪及妗嗘灦 unified.engine.DomainAssessor 瀹炵幇銆?
绾?Python 鏍囧噯搴撳疄鐜帮紝涓嶄緷璧?apktool / jadx / frida 绛夊閮ㄥ伐鍏枫€?

妫€娴嬭兘鍔涳紙鍏ㄩ儴鍩轰簬鐪熷疄鐨勬枃浠惰鍙栦笌姝ｅ垯鍖归厤锛屾棤浠讳綍 mock 鏁版嵁锛夛細
    1. APK 缁撴瀯瑙ｆ瀽        鈥斺€?鐢?zipfile 鐪熷疄璇诲彇 ZIP 鏉＄洰锛屾彁鍙栨枃浠舵竻鍗?dex/绛惧悕/native搴?
    2. 鏉冮檺鍒嗘瀽            鈥斺€?瑙ｆ瀽/瀛楄妭鎼滅储 android.permission.*锛岃瘑鍒嵄闄╂潈闄愪笌杩囧害鐢宠
    3. 缁勪欢鏆撮湶妫€娴?       鈥斺€?Activity/Service/Receiver/Provider 鐨?exported 涓?intent-filter
    4. 纭紪鐮佸瘑閽ヤ笌鏁忔劅淇℃伅 鈥斺€?閬嶅巻鎵€鏈夋潯鐩瓧鑺傦紝姝ｅ垯鍖归厤绉侀挜/API Key/鍙ｄ护/鏄庢枃URL/IP
    5. 涓嶅畨鍏ㄩ€氫俊妫€娴?     鈥斺€?鏄庢枃HTTP銆乽sesCleartextTraffic銆佺綉缁滃畨鍏ㄩ厤缃€丼SL Pinning銆乄ebView
    6. iOS 瀹夊叏妫€娴?       鈥斺€?Info.plist銆丄TS銆乁RL Scheme銆佸悗鍙版ā寮忋€佹潈闄愭弿杩?

target 鍙互鏄細
    - APK 鏂囦欢璺緞锛?apk / 鏈川涓?ZIP 鐨勬枃浠讹級
    - IPA 鏂囦欢璺緞锛?ipa锛?
    - iOS App 搴旂敤鍖呯洰褰曡矾寰勶紙鍚?Info.plist / .app 鐩綍锛?
"""
import os
import re
import time
import plistlib
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

from unified.engine import DomainAssessor
from unified.models import DomainAssessment, DomainType, Finding


class MobileAssessor(DomainAssessor):
    """绉诲姩瀹夊叏璇勪及鍣?- 闈欐€佸垎鏋?APK / IPA / iOS 搴旂敤鍖?""

    # 缁戝畾鍒扮Щ鍔ㄥ畨鍏ㄩ鍩?
    domain: DomainType = DomainType.MOBILE
    name: str = "mobile_static_assessor"
    description: str = "鍩轰簬绾疨ython鐨凙PK/IPA闈欐€佸畨鍏ㄨ瘎浼板櫒锛堢粨鏋?鏉冮檺/缁勪欢/瀵嗛挜/閫氫俊锛?

    # ------------------------------------------------------------------ #
    # 鍐呯疆瑙勫垯搴?
    # ------------------------------------------------------------------ #

    # 鍗遍櫓鏉冮檺娓呭崟锛?=20涓級锛寁alue 涓?(涓枃鎻忚堪, 榛樿涓ラ噸绾у埆)
    DANGEROUS_PERMISSIONS: Dict[str, Tuple[str, str]] = {
        "android.permission.SEND_SMS":              ("鍙戦€佺煭淇?, "high"),
        "android.permission.RECEIVE_SMS":          ("鎺ユ敹鐭俊", "high"),
        "android.permission.READ_SMS":              ("璇诲彇鐭俊", "critical"),
        "android.permission.WRITE_SMS":             ("鍐欏叆鐭俊", "high"),
        "android.permission.CALL_PHONE":           ("鐩存帴鎷ㄦ墦鐢佃瘽", "high"),
        "android.permission.PROCESS_OUTGOING_CALLS":("鐩戞帶/鎷︽埅鎷ㄥ嚭鐢佃瘽", "high"),
        "android.permission.READ_CALL_LOG":         ("璇诲彇閫氳瘽璁板綍", "high"),
        "android.permission.WRITE_CALL_LOG":        ("鍐欏叆閫氳瘽璁板綍", "high"),
        "android.permission.READ_PHONE_STATE":      ("璇诲彇鎵嬫満鐘舵€?IMEI/IMSI)", "medium"),
        "android.permission.ACCESS_FINE_LOCATION":  ("绮剧‘瀹氫綅(GPS)", "high"),
        "android.permission.ACCESS_COARSE_LOCATION":("绮楃暐瀹氫綅(鍩虹珯/WiFi)", "medium"),
        "android.permission.ACCESS_BACKGROUND_LOCATION":("鍚庡彴鎸佺画瀹氫綅", "high"),
        "android.permission.CAMERA":               ("璋冪敤鐩告満", "medium"),
        "android.permission.RECORD_AUDIO":          ("褰曞埗楹﹀厠椋?, "high"),
        "android.permission.READ_EXTERNAL_STORAGE": ("璇诲彇澶栭儴瀛樺偍", "medium"),
        "android.permission.WRITE_EXTERNAL_STORAGE":("鍐欏叆澶栭儴瀛樺偍", "medium"),
        "android.permission.MANAGE_EXTERNAL_STORAGE":("绠＄悊鎵€鏈夋枃浠?, "critical"),
        "android.permission.READ_CONTACTS":         ("璇诲彇閫氳褰?, "high"),
        "android.permission.WRITE_CONTACTS":        ("鍐欏叆閫氳褰?, "high"),
        "android.permission.GET_ACCOUNTS":          ("鑾峰彇璐︽埛鍒楄〃", "medium"),
        "android.permission.READ_CALENDAR":         ("璇诲彇鏃ュ巻", "medium"),
        "android.permission.WRITE_CALENDAR":        ("鍐欏叆鏃ュ巻", "medium"),
        "android.permission.SYSTEM_ALERT_WINDOW":   ("鎮诞绐?鍙鐩栧睆骞?", "high"),
        "android.permission.BIND_ACCESSIBILITY_SERVICE":("鏃犻殰纰嶆湇鍔?楂樺嵄婊ョ敤鍏ュ彛)", "critical"),
        "android.permission.REQUEST_INSTALL_PACKAGES":("璇锋眰瀹夎鏈煡搴旂敤", "high"),
        "android.permission.READ_PHONE_NUMBERS":    ("璇诲彇鏈満鍙风爜", "medium"),
        "android.permission.SEND_SMS":              ("鍙戦€佺煭淇?, "high"),
    }

    # 甯歌 API Key / 瀵嗛挜姝ｅ垯锛?=10 绉嶏級锛岀敤浜庣‖缂栫爜鏁忔劅淇℃伅妫€娴?
    SECRET_PATTERNS: List[Tuple[str, str, str, str]] = [
        # (鍚嶇О, 姝ｅ垯, 涓ラ噸绾у埆, CWE)
        ("PEM绉侀挜",            r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "critical", "CWE-321"),
        ("Google API Key",     r"AIza[0-9A-Za-z_\-]{20,40}", "high", "CWE-798"),
        ("OpenAI/绫籹k瀵嗛挜",    r"\bsk-[A-Za-z0-9]{20,}", "high", "CWE-798"),
        ("AWS Access Key ID",  r"\bAKIA[0-9A-Z]{16}\b", "critical", "CWE-798"),
        ("AWS Secret Key",     r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z/+=]{20,}", "critical", "CWE-798"),
        ("GitHub Token",       r"\bgh[pousr]_[0-9A-Za-z]{36,}\b", "high", "CWE-798"),
        ("Slack Token",        r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b", "high", "CWE-798"),
        ("Google OAuth Token", r"\bya29\.[0-9A-Za-z_\-]{20,}", "high", "CWE-798"),
        ("Stripe Live Secret", r"\bsk_live_[0-9a-zA-Z]{16,}", "critical", "CWE-798"),
        ("Firebase Database",  r"[0-9a-z\-]+\.firebaseio\.com", "medium", "CWE-798"),
        ("纭紪鐮佸瘑鐮?,         r"(?i)(password|passwd|pwd|pass)\s*[:=]\s*['\"][^'\"\s]{4,}['\"]", "high", "CWE-259"),
        ("鏁版嵁搴撹繛鎺ヤ覆",       r"(?i)(mysql|postgres|mongodb|jdbc:mysql)://[^\s\"'<>]{6,}", "high", "CWE-798"),
        ("Facebook Access Token", r"\bEA[A-Za-z0-9]{20,}\b", "medium", "CWE-798"),
    ]

    # 鏄庢枃 HTTP URL锛堥潪 HTTPS锛?
    HTTP_URL_RE = re.compile(r"http://[A-Za-z0-9\.\-_]+(?::\d+)?(?:/[^\s\"'<>\\]*)?")

    # 鍘熺敓搴撴灦鏋勮瘑鍒?
    LIB_ARCHS = ("arm64-v8a", "armeabi-v7a", "armeabi", "x86", "x86_64", "mips")

    def __init__(self):
        super().__init__()

    # ================================================================== #
    # 涓诲叆鍙?
    # ================================================================== #

    def assess(self, target: str, options: Optional[Dict] = None) -> DomainAssessment:
        """鎵ц绉诲姩瀹夊叏闈欐€佽瘎浼?

        Args:
            target: APK 鏂囦欢璺緞 / IPA 鏂囦欢璺緞 / iOS App 鐩綍璺緞
            options: 璇勪及閫夐」锛堝綋鍓嶆湭浣跨敤锛岄鐣欙級

        Returns:
            DomainAssessment 瀹屾暣璇勪及缁撴灉
        """
        options = options or {}
        result = DomainAssessment(
            domain=self.domain,
            target=target or "",
            started_at=time.time(),
            status="running",
        )
        findings: List[Finding] = []
        errors: List[str] = []

        # ---- 1. 鏍￠獙鐩爣鏄惁瀛樺湪骞跺垽瀹氱被鍨?----
        if not target:
            errors.append("鐩爣涓虹┖锛氭湭鎻愪緵 APK/IPA/搴旂敤鐩綍璺緞")
            return self._complete_result(result, findings, errors)

        if not os.path.exists(target):
            errors.append(f"鐩爣涓嶅瓨鍦細{target}")
            return self._complete_result(result, findings, errors)

        try:
            target_lower = target.lower()
            if target_lower.endswith(".ipa") or target_lower.endswith(".app"):
                # iOS 搴旂敤鍖?
                self._assess_ios(target, findings, result)
            elif os.path.isdir(target):
                # 鐩綍锛氫紭鍏堟寜 iOS App Bundle 澶勭悊
                if self._looks_like_ios_bundle(target):
                    self._assess_ios(target, findings, result)
                else:
                    errors.append(f"鐩綍闈?iOS App Bundle锛堟湭鎵惧埌 Info.plist锛夛細{target}")
            elif zipfile.is_zipfile(target):
                # APK / ZIP 缁撴瀯
                self._assess_apk(target, findings, result)
            else:
                errors.append(
                    f"鏃犳硶璇嗗埆鐨勭洰鏍囨牸寮忥細{target}锛堝簲涓?.apk/.ipa 鏂囦欢鎴?iOS 搴旂敤鐩綍锛?
                    "涓?APK 鏈川涓?ZIP锛?
                )
        except Exception as e:  # 鍏滃簳锛氫换浣曠湡瀹炲紓甯搁兘璁板綍锛岀粷涓?mock
            errors.append(f"{type(e).__name__}: {e}")

        result.tools_used = ["zipfile", "re", "plistlib锛堟爣鍑嗗簱锛屾棤澶栭儴宸ュ叿锛?]
        result.checks_total = 6
        return self._complete_result(result, findings, errors)

    # ================================================================== #
    # 1. APK 缁撴瀯瑙ｆ瀽 + 鍚庣画鍚勬ā鍧?
    # ================================================================== #

    def _assess_apk(self, apk_path: str, findings: List[Finding], result: DomainAssessment) -> None:
        """浣跨敤 zipfile 鐪熷疄瑙ｆ瀽 APK锛圓PK 鏈川鏄?ZIP锛?""
        target = apk_path
        checks: List[str] = []

        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()
            infos = zf.infolist()
            checks.append("apks_structure")

            # ---------- 1.1 鏂囦欢娓呭崟涓庝綋绉?----------
            total_size = sum(i.file_size for i in infos)
            entry_count = len(names)
            findings.append(self._make_finding(
                title="APK 鍖呯粨鏋勪俊鎭?,
                severity="info", category="搴旂敤缁撴瀯",
                description=f"鎴愬姛瑙ｆ瀽 APK锛氬叡 {entry_count} 涓枃浠讹紝瑙ｅ帇鍚庢€诲ぇ灏?{total_size/1024:.1f} KB",
                target=target, location=apk_path,
                evidence=f"鏂囦欢鏁?{entry_count}, 鏈帇缂╂€诲瓧鑺?{total_size}",
                recommendation="鏃狅紙淇℃伅椤癸級",
            ))
            result.checks_run.append("apks_structure")

            # ---------- 1.2 classes.dex 瀛樺湪鎬?----------
            dex_files = [n for n in names if n.endswith(".dex")]
            if dex_files:
                findings.append(self._make_finding(
                    title="DEX 瀛楄妭鐮佹枃浠舵娴?,
                    severity="info", category="搴旂敤缁撴瀯",
                    description=f"妫€娴嬪埌 {len(dex_files)} 涓?DEX 鏂囦欢锛圖alvik 瀛楄妭鐮侊級",
                    target=target, location=",".join(dex_files),
                    evidence=",".join(dex_files),
                ))
            else:
                findings.append(self._make_finding(
                    title="鏈娴嬪埌 classes.dex",
                    severity="low", category="搴旂敤缁撴瀯",
                    description="APK 鍐呮湭鍙戠幇浠讳綍 .dex 鏂囦欢锛屽彲鑳芥槸澹宠祫婧愬寘鎴栨崯鍧忓寘",
                    target=target, location="classes.dex",
                    evidence="鍦?ZIP 鏉＄洰鍒楄〃涓湭鎵惧埌 *.dex",
                    recommendation="纭璇ユ枃浠舵槸鍚︿负瀹屾暣鍙畨瑁?APK",
                ))
            result.checks_run.append("dex_detect")

            # ---------- 1.3 绛惧悕鏂囦欢妫€娴嬶紙META-INF锛?----------
            sig_files = [n for n in names
                         if n.upper().startswith("META-INF/") and
                         n.upper().endswith((".RSA", ".DSA", ".EC"))]
            v1_sig = any(n.upper().endswith(".SF") for n in names)
            if sig_files:
                findings.append(self._make_finding(
                    title="妫€娴嬪埌 v1(JAR) 绛惧悕",
                    severity="info", category="搴旂敤绛惧悕",
                    description=f"妫€娴嬪埌绛惧悕鍧楁枃浠讹細{', '.join(sig_files)}",
                    target=target, location="META-INF",
                    evidence=f"绛惧悕鏂囦欢={sig_files}, 鏄惁鍚?SF娓呭崟={v1_sig}",
                    recommendation="寤鸿鍚屾椂浣跨敤 v2/v3 绛惧悕鏂规鎻愬崌瀹夊叏鎬?,
                ))
            else:
                findings.append(self._make_finding(
                    title="鏈娴嬪埌 v1 绛惧悕鏂囦欢",
                    severity="high", category="搴旂敤绛惧悕",
                    description="META-INF 涓嬫湭鍙戠幇 CERT.RSA/DSA/EC锛孉PK 鍙兘鏈鍚嶆垨琚噸鎵撳寘",
                    target=target, location="META-INF/",
                    evidence="META-INF 涓嬫棤 .RSA/.DSA/.EC 绛惧悕鍧?,
                    recommendation="纭 APK 绛惧悕鏂规锛屾湭绛惧悕搴旂敤涓嶅彲瀹夎鍒板彈绠¤澶?,
                    cwe="CWE-347",
                ))
            result.checks_run.append("signature_detect")

            # ---------- 1.4 Native 搴撴娴嬶紙lib/*.so + 鏋舵瀯锛?----------
            so_files = [n for n in names if n.endswith(".so") and n.startswith("lib/")]
            archs: Set[str] = set()
            for so in so_files:
                parts = so.split("/")
                if len(parts) >= 2:
                    archs.add(parts[1])
            if so_files:
                findings.append(self._make_finding(
                    title="Native 搴?.so)妫€娴?,
                    severity="info", category="搴旂敤缁撴瀯",
                    description=f"妫€娴嬪埌 {len(so_files)} 涓師鐢熷簱锛岃鐩栨灦鏋勶細{', '.join(sorted(archs)) or '鏈煡'}",
                    target=target, location="lib/",
                    evidence=f"so鏁伴噺={len(so_files)}, 鏋舵瀯={sorted(archs)}",
                    recommendation="寤鸿瀵?.so 杩涜鍔犲浐/娣锋穯锛岄槻鑼冮€嗗悜",
                ))
                # 妫€娴嬫槸鍚﹀寘鍚槗鍙楁敾鍑荤殑甯歌鏋舵瀯
                if "x86" in archs or "x86_64" in archs:
                    findings.append(self._make_finding(
                        title="鍖呭惈 x86/x86_64 鍘熺敓搴?,
                        severity="low", category="搴旂敤缁撴瀯",
                        description="APK 闄勫甫 x86 鏋舵瀯 so锛屼究浜庡湪妯℃嫙鍣?鍒嗘瀽鐜涓姩鎬佽皟璇?,
                        target=target, location="lib/",
                        evidence=f"鏋舵瀯闆嗗悎={sorted(archs)}",
                        recommendation="濡傛棤 x86 璁惧鍏煎闇€姹傦紝鍙鍓鏋舵瀯浠ュ鍔犻€嗗悜闅惧害",
                    ))
            result.checks_run.append("native_lib_detect")

            # ---------- 1.5 AndroidManifest.xml 瑙ｆ瀽 ----------
            manifest_text = ""
            manifest_is_binary = True
            manifest_raw = b""
            if "AndroidManifest.xml" in names:
                manifest_raw = zf.read("AndroidManifest.xml")
                # 鐪熷疄瑙ｇ爜锛氱湡瀹?APK 涓?Manifest 涓轰簩杩涘埗 AXML锛屾棤娉曠洿鎺?xml 瑙ｆ瀽
                head = manifest_raw[:200]
                try:
                    candidate = manifest_raw.decode("utf-8")
                    if candidate.lstrip().startswith("<?xml") or "<manifest" in candidate:
                        manifest_text = candidate
                        manifest_is_binary = False
                except UnicodeDecodeError:
                    manifest_text = ""
            if manifest_is_binary and manifest_raw:
                # AXML 鍥為€€锛氫粠浜岃繘鍒跺瓧鑺備腑鎻愬彇鍙瀛楃涓诧紙ASCII + UTF-16LE锛?
                manifest_text = self._extract_strings_from_binary(manifest_raw)
                findings.append(self._make_finding(
                    title="AndroidManifest 涓轰簩杩涘埗 AXML",
                    severity="info", category="搴旂敤缁撴瀯",
                    description="AndroidManifest.xml 涓轰簩杩涘埗 AXML 鏍煎紡锛屽凡鍒囨崲涓哄瓧鑺傚瓧绗︿覆鎻愬彇妯″紡",
                    target=target, location="AndroidManifest.xml",
                    evidence=f"鍓?6瀛楄妭hex={manifest_raw[:16].hex()}",
                ))
            elif not manifest_raw:
                errors.append("APK 鍐呮湭鎵惧埌 AndroidManifest.xml")
                findings.append(self._make_finding(
                    title="缂哄皯 AndroidManifest.xml",
                    severity="high", category="搴旂敤缁撴瀯",
                    description="APK 涓笉瀛樺湪 AndroidManifest.xml锛屽寘缁撴瀯寮傚父",
                    target=target, location="AndroidManifest.xml",
                    evidence="ZIP 鏉＄洰鍒楄〃涓棤 AndroidManifest.xml",
                    cwe="CWE-1036",
                ))
            result.checks_run.append("manifest_parse")

            # ---------- 璇诲彇鍏ㄩ儴鏉＄洰瀛楄妭锛屼緵瀵嗛挜/閫氫俊绛夋ā鍧楃粺涓€鎵弿 ----------
            all_blobs: List[Tuple[str, bytes]] = []
            for info in infos:
                if info.is_dir():
                    continue
                # 璺宠繃瓒呭ぇ鏂囦欢锛?50MB锛夐伩鍏嶅唴瀛樺帇鍔涳紝浠嶈褰曟枃浠跺悕
                if info.file_size > 50 * 1024 * 1024:
                    continue
                try:
                    all_blobs.append((info.filename, zf.read(info.filename)))
                except Exception:
                    continue

            # ---------- 2. 鏉冮檺鍒嗘瀽 ----------
            self._analyze_permissions(manifest_text, all_blobs, target, manifest_is_binary,
                                      findings, result)

            # ---------- 3. 缁勪欢鏆撮湶妫€娴?----------
            self._analyze_components(manifest_text, target, manifest_is_binary, findings, result)

            # ---------- 4. 纭紪鐮佸瘑閽ヤ笌鏁忔劅淇℃伅 ----------
            self._analyze_hardcoded_secrets(all_blobs, target, findings, result)

            # ---------- 5. 涓嶅畨鍏ㄩ€氫俊妫€娴?----------
            self._analyze_insecure_communication(manifest_text, all_blobs, names,
                                                target, findings, result)

    # ================================================================== #
    # 2. 鏉冮檺鍒嗘瀽
    # ================================================================== #

    def _analyze_permissions(self, manifest_text: str,
                             all_blobs: List[Tuple[str, bytes]],
                             target: str, is_binary: bool,
                             findings: List[Finding], result: DomainAssessment) -> None:
        """浠?Manifest锛堟枃鏈垨瀛楄妭锛変腑鎻愬彇鏉冮檺骞跺仛椋庨櫓璇勭骇"""
        perms: Set[str] = set()

        # 浼樺厛浠?manifest 鏂囨湰涓敤姝ｅ垯鎻愬彇 uses-permission 鏍囩
        for m in re.findall(r"<uses-permission[^>]*android:name=\"([^\"]+)\"", manifest_text):
            perms.add(m.strip())
        # 鍏滃簳锛氳８鍖归厤 android.permission.XXX
        for m in re.findall(r"android\.permission\.[A-Z_]+", manifest_text):
            perms.add(m.strip())

        # 濡傛灉浜岃繘鍒?Manifest 鎻愬彇涓嶅埌瓒冲鏉冮檺锛屽垯鍥為€€鍒板叏閮ㄦ潯鐩瓧鑺傛悳绱?
        if is_binary or not perms:
            for name, blob in all_blobs:
                # ASCII 褰㈠紡
                for m in re.findall(rb"android\.permission\.[A-Z_]{3,}", blob):
                    try:
                        perms.add(m.decode("ascii"))
                    except Exception:
                        pass
                # UTF-16LE 褰㈠紡锛圓XML 瀛楃涓叉睜甯歌缂栫爜锛?
                try:
                    u16 = blob.decode("utf-16-le", errors="ignore")
                    for m in re.findall(r"android\.permission\.[A-Z_]{3,}", u16):
                        perms.add(m)
                except Exception:
                    pass

        result.checks_run.append("permission_analysis")

        if not perms:
            findings.append(self._make_finding(
                title="鏈瘑鍒埌浠讳綍鏉冮檺澹版槑",
                severity="info", category="鏉冮檺",
                description="鏈兘浠?Manifest 鎴栧瓧鑺傛祦涓彁鍙栧埌 android.permission 鏉冮檺",
                target=target, location="AndroidManifest.xml",
                evidence="姝ｅ垯 android\\.permission\\.[A-Z_]+ 鏃犲尮閰?,
            ))
            return

        # 缁熻
        custom_perms = sorted(p for p in perms if not p.startswith("android.permission."))
        dangerous_hits = sorted(perms & set(self.DANGEROUS_PERMISSIONS.keys()))

        # 鏉冮檺鎬昏锛堜俊鎭」锛?
        findings.append(self._make_finding(
            title=f"鍏卞０鏄?{len(perms)} 椤规潈闄?,
            severity="info", category="鏉冮檺",
            description="搴旂敤澹版槑鐨勫叏閮ㄦ潈闄愭竻鍗曪紙鍚嚜瀹氫箟鏉冮檺锛?,
            target=target, location="AndroidManifest.xml",
            evidence=", ".join(sorted(perms)[:50]) + (" ..." if len(perms) > 50 else ""),
            extra={"permissions": sorted(perms), "count": len(perms)},
        ))

        # 閫愬嵄闄╂潈闄愯瘎绾?
        for perm in dangerous_hits:
            desc, sev = self.DANGEROUS_PERMISSIONS.get(perm, ("鏈煡鍗遍櫓鏉冮檺", "medium"))
            findings.append(self._make_finding(
                title=f"鐢宠鍗遍櫓鏉冮檺锛歿perm.split('.')[-1]}",
                severity=sev, category="鏉冮檺-鍗遍櫓鏉冮檺",
                description=f"搴旂敤鐢宠浜嗗嵄闄╂潈闄愩€寋desc}銆?{perm})",
                target=target, location="AndroidManifest.xml",
                evidence=perm,
                cwe="CWE-272",
                recommendation=f"璇勪及銆寋desc}銆嶆槸鍚︿负鏍稿績鍔熻兘鎵€蹇呴渶锛岄伒寰渶灏忔潈闄愬師鍒?,
            ))

        # 鑷畾涔夋潈闄愭娴?
        if custom_perms:
            findings.append(self._make_finding(
                title="妫€娴嬪埌鑷畾涔夋潈闄?,
                severity="low", category="鏉冮檺",
                description=f"鍙戠幇 {len(custom_perms)} 涓潪鏍囧噯鏉冮檺锛歿', '.join(custom_perms[:10])}",
                target=target, location="AndroidManifest.xml",
                evidence=", ".join(custom_perms[:10]),
                recommendation="纭鑷畾涔夋潈闄愮殑 protectionLevel 璁剧疆鍚堢悊锛岄伩鍏嶇鍚嶇骇鏉冮檺琚互鐢?,
            ))

        # 鏉冮檺杩囧害鐢宠鍚彂寮忥細璺ㄦ晱鎰熺被鐩繃澶?
        sensitive_cats = {
            "SMS": [p for p in perms if "SMS" in p],
            "CALL": [p for p in perms if "CALL" in p or "PHONE" in p],
            "LOCATION": [p for p in perms if "LOCATION" in p],
            "MEDIA": [p for p in perms if "CAMERA" in p or "RECORD_AUDIO" in p],
            "DATA": [p for p in perms if "STORAGE" in p],
            "CONTACT": [p for p in perms if "CONTACT" in p or "ACCOUNT" in p],
        }
        hit_cats = [c for c, lst in sensitive_cats.items() if lst]
        if len(hit_cats) >= 4:
            findings.append(self._make_finding(
                title="鐤戜技鏉冮檺杩囧害鐢宠",
                severity="medium", category="鏉冮檺-杩囧害鐢宠",
                description=(f"搴旂敤鍚屾椂瑕嗙洊 {len(hit_cats)} 涓晱鎰熺被鐩細{', '.join(hit_cats)}锛?
                             "瀛樺湪涓庡姛鑳戒笉鍖归厤鐨勬潈闄愯啫鑳€椋庨櫓锛堝宸ュ叿绫籄pp鐢宠鐭俊/閫氳瘽鏉冮檺锛?),
                target=target, location="AndroidManifest.xml",
                evidence="; ".join(f"{c}={sensitive_cats[c]}" for c in hit_cats),
                cwe="CWE-272",
                recommendation="鎸夋渶灏忔潈闄愬師鍒欓€愰」鏍稿锛屽垹闄ら潪鏍稿績鍔熻兘鎵€闇€鏉冮檺",
            ))

    # ================================================================== #
    # 3. 缁勪欢鏆撮湶妫€娴?
    # ================================================================== #

    def _analyze_components(self, manifest_text: str, target: str,
                            is_binary: bool,
                            findings: List[Finding], result: DomainAssessment) -> None:
        """妫€娴嬪洓澶х粍浠?exported / intent-filter / Provider authorities"""
        result.checks_run.append("component_exposure")
        comp_types = ("activity", "service", "receiver", "provider")
        exported_true: List[str] = []
        intent_filter_comps: List[str] = []
        providers_no_perm: List[str] = []
        providers_authorities: List[str] = []

        if not is_binary:
            # 鏂囨湰 Manifest锛氶€愪釜缁勪欢鏍囩瑙ｆ瀽
            for ctype in comp_types:
                for tag in re.findall(rf"<{ctype}\b[^>]*>", manifest_text, flags=re.IGNORECASE):
                    name_m = re.search(r"android:name=\"([^\"]+)\"", tag)
                    cname = name_m.group(1) if name_m else f"(unnamed {ctype})"
                    exp_m = re.search(r"android:exported=\"([^\"]+)\"", tag)
                    exported = exp_m.group(1).strip().lower() == "true" if exp_m else None
                    # 妫€娴嬫槸鍚﹀瓨鍦?intent-filter锛堢矖绮掑害锛氭爣绛惧潡鍐呭惈 <intent-filter锛?
                    has_if = "<intent-filter" in tag
                    if exported:
                        exported_true.append(f"{ctype}:{cname}")
                    elif has_if and exported is None:
                        # 鏈?intent-filter 涓旀湭鏄惧紡澹版槑 exported锛岄殣寮忓鍑?
                        intent_filter_comps.append(f"{ctype}:{cname}")
                    # Provider authorities
                    if ctype == "provider":
                        auth_m = re.search(r"android:authorities=\"([^\"]+)\"", tag)
                        perm_m = re.search(r"android:permission=\"([^\"]+)\"", tag)
                        if auth_m:
                            providers_authorities.append(f"{cname} -> {auth_m.group(1)}")
                        if not perm_m and (exported or has_if):
                            providers_no_perm.append(f"{ctype}:{cname}")
        else:
            # 浜岃繘鍒跺洖閫€锛氬瓧鑺傛悳绱㈢粍浠剁被鍚嶄笌 exported 瀛楅潰閲?
            for kw in ("exported",):
                if kw in manifest_text:
                    # 浠呭仛瀛樺湪鎬ф彁绀猴紝涓嶈噯閫犵粍浠跺悕
                    intent_filter_comps.append(f"(浜岃繘鍒禡anifest鍚?{kw}'瀛楅潰閲忥紝闇€杩涗竴姝ョ‘璁?")

        # 瀵煎嚭缁勪欢鎶ュ憡
        if exported_true:
            findings.append(self._make_finding(
                title=f"{len(exported_true)} 涓粍浠舵樉寮忓鍑?exported=true)",
                severity="medium", category="缁勪欢鏆撮湶",
                description="浠ヤ笅缁勪欢琚樉寮忓鍑猴紝鍙鍏朵粬搴旂敤鐩存帴璋冪敤锛岄渶纭鏄惁鍋氫簡鏉冮檺鏍￠獙",
                target=target, location="AndroidManifest.xml",
                evidence="\n".join(exported_true[:20]),
                cwe="CWE-926",
                recommendation="闈炲繀瑕佺粍浠惰缃?exported=false锛涘繀瑕佸鍑虹殑缁勪欢鍔″繀鍋氳皟鐢ㄦ柟韬唤鏍￠獙",
            ))
        if intent_filter_comps:
            findings.append(self._make_finding(
                title="瀛樺湪甯?intent-filter 鐨勭粍浠讹紙闅愬紡瀵煎嚭锛?,
                severity="medium", category="缁勪欢鏆撮湶",
                description="甯?intent-filter 鐨勭粍浠跺湪鏈樉寮忓０鏄?exported 鏃堕粯璁ゅ彲琚閮ㄨ皟璧?,
                target=target, location="AndroidManifest.xml",
                evidence="\n".join(intent_filter_comps[:20]),
                cwe="CWE-926",
                recommendation="鏄惧紡璁剧疆 exported=false锛堟棤闇€澶栭儴璋冭捣鏃讹級鎴栧鍔犵鍚嶇骇鏉冮檺淇濇姢",
            ))
        if providers_authorities:
            findings.append(self._make_finding(
                title="ContentProvider authorities 娉勯湶",
                severity="low", category="缁勪欢鏆撮湶",
                description="ContentProvider 鐨?authorities 鏍囪瘑鏆撮湶锛屽彲琚涓夋柟鎺㈡祴涓庢煡璇?,
                target=target, location="AndroidManifest.xml",
                evidence="\n".join(providers_authorities[:20]),
                cwe="CWE-926",
                recommendation="瀵?Provider 閰嶇疆 readPermission/writePermission锛屾晱鎰熸暟鎹蛋鏉冮檺鏍￠獙",
            ))
        if providers_no_perm:
            findings.append(self._make_finding(
                title="鏈彈淇濇姢鐨勫鍑?ContentProvider",
                severity="high", category="缁勪欢鏆撮湶",
                description="浠ヤ笅 Provider 鏃㈠鍑哄張鏈０鏄?android:permission锛屽瓨鍦ㄦ暟鎹秺鏉冭鍙栭闄?,
                target=target, location="AndroidManifest.xml",
                evidence="\n".join(providers_no_perm[:20]),
                cwe="CWE-926",
                recommendation="绔嬪嵆涓?Provider 澧炲姞 readPermission/writePermission 鎴?exported=false",
            ))

        if not (exported_true or intent_filter_comps or providers_authorities):
            findings.append(self._make_finding(
                title="鏈彂鐜板彲璇嗗埆鐨勫鍑虹粍浠堕闄?,
                severity="info", category="缁勪欢鏆撮湶",
                description="Manifest 涓湭妫€娴嬪埌鏄庢樉鐨?exported=true / intent-filter 缁勪欢",
                target=target, location="AndroidManifest.xml",
                evidence="姝ｅ垯 exported/intent-filter 鏃犻珮椋庨櫓鍖归厤",
            ))

    # ================================================================== #
    # 4. 纭紪鐮佸瘑閽ヤ笌鏁忔劅淇℃伅
    # ================================================================== #

    def _analyze_hardcoded_secrets(self, blobs: List[Tuple[str, bytes]],
                                   target: str,
                                   findings: List[Finding],
                                   result: DomainAssessment) -> None:
        """閬嶅巻 APK 鎵€鏈夋枃浠跺瓧鑺傦紝姝ｅ垯鎼滅储瀵嗛挜/鍙ｄ护/IP/URL"""
        result.checks_run.append("hardcoded_secret")
        # 浠呮壂鎻忔晱鎰熺被鍨嬫枃浠讹紝鍑忓皯璇姤
        sensitive_suffix = (".dex", ".arsc", ".xml", ".json", ".properties", ".txt",
                            ".config", ".conf", ".kt", ".java", ".js", ".html")
        hits: Dict[str, List[str]] = {}  # 鍚嶇О -> [鏂囦欢:鐗囨]

        for name, blob in blobs:
            low = name.lower()
            # 瀵?dex/arsc/so/assets 绛夐兘鎵弿锛涗絾鍥剧墖/闊宠棰戣烦杩?
            if low.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3",
                             ".mp4", ".ttf", ".otf", ".woff")):
                continue
            haystacks = self._haystacks(blob)
            for pat_name, regex, sev, cwe in self.SECRET_PATTERNS:
                try:
                    rx = re.compile(regex)
                except re.error:
                    continue
                for text in haystacks:
                    for m in rx.findall(text):
                        # 鑴辨晱锛氬彧淇濈暀鍓?8 浣?+ 鍚?2 浣嶄綔涓鸿瘉鎹紝閬垮厤瀹屾暣瀵嗛挜澶栨硠
                        snippet = self._redact_secret(m)
                        key = pat_name
                        hits.setdefault(key, [])
                        label = f"{name}: {snippet}"
                        if label not in hits[key]:
                            hits[key].append(label)

        # IP 鍦板潃锛堢鏈?鍏綉锛夋壂鎻?
        ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        ip_hits: List[str] = []
        for name, blob in blobs:
            for text in self._haystacks(blob):
                for m in ip_re.findall(text):
                    # 杩囨护鐗堟湰鍙?鍥炵幆
                    parts = m.split(".")
                    if all(0 <= int(p) <= 255 for p in parts):
                        if parts[0] in ("0", "127") or m.startswith("255."):
                            continue
                        ip_hits.append(f"{name}: {m}")

        # 姹囨€昏緭鍑?
        sev_map = {p[0]: (p[2], p[3]) for p in self.SECRET_PATTERNS}
        for pat_name, evidences in hits.items():
            if not evidences:
                continue
            sev, cwe = sev_map.get(pat_name, ("medium", "CWE-798"))
            findings.append(self._make_finding(
                title=f"纭紪鐮佹晱鎰熶俊鎭細{pat_name}",
                severity=sev, category="纭紪鐮佸瘑閽?,
                description=f"鍦?{len(evidences)} 澶勬娴嬪埌鐤戜技銆寋pat_name}銆嶏紝瀛樺湪瀵嗛挜娉勯湶椋庨櫓",
                target=target, location="classes.dex/resources/assets",
                evidence="\n".join(evidences[:10]),
                cwe=cwe,
                recommendation="灏嗗瘑閽ョЩ鑷虫湇鍔＄鎴栧彈鎺у瘑閽ュ簱锛岃疆鎹㈠凡娉勯湶瀵嗛挜锛屼唬鐮佷腑绂佹鏄庢枃瀛樺偍",
            ))

        if ip_hits:
            uniq = sorted(set(ip_hits))[:15]
            findings.append(self._make_finding(
                title="纭紪鐮?IP 鍦板潃",
                severity="low", category="鏁忔劅淇℃伅",
                description=f"妫€娴嬪埌 {len(set(ip_hits))} 涓‖缂栫爜 IP锛屽彲鑳戒负鍚庣/璋冭瘯鍦板潃",
                target=target, location="assets/dex",
                evidence="\n".join(uniq),
                recommendation="閫氳繃鍩熷悕璁块棶鍚庣骞朵娇鐢?HTTPS锛岄伩鍏嶇‖缂栫爜鍐呯綉/娴嬭瘯 IP",
            ))

    # ================================================================== #
    # 5. 涓嶅畨鍏ㄩ€氫俊妫€娴?
    # ================================================================== #

    def _analyze_insecure_communication(self, manifest_text: str,
                                        blobs: List[Tuple[str, bytes]],
                                        zip_names: List[str],
                                        target: str,
                                        findings: List[Finding],
                                        result: DomainAssessment) -> None:
        """鏄庢枃娴侀噺 / 缃戠粶瀹夊叏閰嶇疆 / SSL Pinning / WebView"""
        result.checks_run.append("insecure_communication")

        # ---- 5.1 Manifest 涓?usesCleartextTraffic="true" ----
        if re.search(r"usesCleartextTraffic\s*=\s*\"true\"", manifest_text):
            findings.append(self._make_finding(
                title="鍏佽鏄庢枃娴侀噺(usesCleartextTraffic=true)",
                severity="high", category="涓嶅畨鍏ㄩ€氫俊",
                description="Manifest 涓樉寮忓厑璁告槑鏂?HTTP 娴侀噺锛屾槗鍙椾腑闂翠汉鏀诲嚮",
                target=target, location="AndroidManifest.xml",
                evidence='android:usesCleartextTraffic="true"',
                cwe="CWE-319",
                recommendation="璁剧疆涓?false 骞堕厤缃?network_security_config.xml 浠呭厑璁?HTTPS",
            ))

        # ---- 5.2 network_security_config.xml ----
        nsc = [n for n in zip_names if n.endswith("network_security_config.xml")
               or "network_security" in n.lower()]
        if nsc:
            # 璇诲彇鍐呭鐪嬫槸鍚﹀厑璁?cleartext / 淇′换鐢ㄦ埛CA
            for name in nsc:
                blob = next((b for n, b in blobs if n == name), b"")
                txt = blob.decode("utf-8", errors="ignore")
                findings.append(self._make_finding(
                    title="瀛樺湪缃戠粶瀹夊叏閰嶇疆鏂囦欢",
                    severity="info", category="涓嶅畨鍏ㄩ€氫俊",
                    description=f"妫€娴嬪埌缃戠粶瀹夊叏閰嶇疆锛歿name}",
                    target=target, location=name,
                    evidence=txt[:300],
                ))
                if "cleartextTrafficPermitted=\"true\"" in txt:
                    findings.append(self._make_finding(
                        title="NSC 鍏佽鏄庢枃娴侀噺",
                        severity="high", category="涓嶅畨鍏ㄩ€氫俊",
                        description="network_security_config.xml 涓?cleartextTrafficPermitted=true",
                        target=target, location=name,
                        evidence="cleartextTrafficPermitted=\"true\"",
                        cwe="CWE-319",
                        recommendation="瀵圭敓浜х幆澧冨叧闂槑鏂囨祦閲?,
                    ))
                if "certificates src=\"user\"" in txt or 'android:installLocation' in txt:
                    findings.append(self._make_finding(
                        title="NSC 淇′换鐢ㄦ埛璇佷功(鎶撳寘椋庨櫓)",
                        severity="medium", category="涓嶅畨鍏ㄩ€氫俊",
                        description="缃戠粶瀹夊叏閰嶇疆淇′换浜嗙敤鎴峰畨瑁呯殑 CA锛屽彲琚敤浜庝腑闂翠汉鎶撳寘",
                        target=target, location=name,
                        evidence="certificates src=\"user\"",
                        cwe="CWE-295",
                        recommendation="浠呭湪 debug 鏋勫缓淇′换鐢ㄦ埛璇佷功锛宺elease 绉婚櫎",
                    ))
        else:
            findings.append(self._make_finding(
                title="鏈厤缃綉缁滃畨鍏ㄩ厤缃枃浠?,
                severity="low", category="涓嶅畨鍏ㄩ€氫俊",
                description="APK 鏈彁渚?res/xml/network_security_config.xml锛岄粯璁ゅ畨鍏ㄧ瓥鐣ヨ緝寮?,
                target=target, location="res/xml/",
                evidence="ZIP 涓棤 network_security_config.xml",
                recommendation="鏂板 NSC 鏂囦欢锛岄檺瀹氫俊浠荤郴缁熻瘉涔﹀苟绂佺敤鏄庢枃",
            ))

        # ---- 5.3 鏄庢枃 HTTP URL 鎵弿 ----
        http_urls: Set[str] = set()
        for name, blob in blobs:
            for text in self._haystacks(blob):
                for m in self.HTTP_URL_RE.findall(text):
                    low = m.lower()
                    # 鎺掗櫎鏂囨。/鍗犱綅/鏈湴
                    if any(x in low for x in ("w3.org", "apache.org", "localhost",
                                              "127.0.0.1", "example.com", "schemas.android")):
                        continue
                    http_urls.add(m)
        if http_urls:
            findings.append(self._make_finding(
                title=f"鍙戠幇 {len(http_urls)} 澶勬槑鏂?HTTP URL",
                severity="medium", category="涓嶅畨鍏ㄩ€氫俊",
                description="搴旂敤涓瓨鍦?http:// 鏄庢枃绔偣锛屼紶杈撳唴瀹瑰彲琚獌鍚?绡℃敼",
                target=target, location="classes.dex/assets",
                evidence="\n".join(sorted(http_urls)[:15]),
                cwe="CWE-319",
                recommendation="鍏ㄩ儴杩佺Щ鑷?https://锛屽苟寮€鍚?TLS 鏍￠獙",
            ))

        # ---- 5.4 SSL Pinning / TrustManager 鍏抽敭璇?----
        pinning_kw = ("certificatePinner", "X509TrustManager",
                      "checkServerTrusted", "TrustManagerImpl", "onReceivedSslError")
        found_kw: Set[str] = set()
        for name, blob in blobs:
            for text in self._haystacks(blob):
                for kw in pinning_kw:
                    if kw in text:
                        found_kw.add(kw)
        if found_kw:
            findings.append(self._make_finding(
                title="妫€娴嬪埌 SSL/TLS 鐩稿叧浠ｇ爜",
                severity="info", category="閫氫俊瀹夊叏",
                description=f"鍦ㄥ瓧鑺傛祦涓懡涓叧閿瘝锛歿', '.join(sorted(found_kw))}",
                target=target, location="classes.dex",
                evidence=", ".join(sorted(found_kw)),
                recommendation="纭 checkServerTrusted 鏈绌哄疄鐜扮粫杩囷紱onReceivedSslError 搴斿彇娑堝姞杞?,
            ))

        # ---- 5.5 WebView 瀹夊叏 ----
        wv_kw = {
            "setJavaScriptEnabled": "寮€鍚?JS 鎵ц",
            "addJavascriptInterface": "JS 妗ユ帴(楂樺嵄)",
            "setAllowFileAccess": "鍏佽 file:// 璁块棶",
            "setAllowUniversalAccessFromFileURLs": "璺ㄥ煙 file 璁块棶",
            "loadUrl": "WebView 鍔犺浇 URL",
        }
        found_wv: Dict[str, str] = {}
        for name, blob in blobs:
            for text in self._haystacks(blob):
                for kw, desc in wv_kw.items():
                    if kw in text:
                        found_wv[kw] = desc
        if found_wv:
            # addJavascriptInterface + setJavaScriptEnabled 鍚屾椂鍑虹幇 -> 楂樺嵄
            if "addJavascriptInterface" in found_wv and "setJavaScriptEnabled" in found_wv:
                findings.append(self._make_finding(
                    title="WebView 寮€鍚?JS 妗ユ帴锛屽瓨鍦?RCE 椋庨櫓",
                    severity="high", category="WebView瀹夊叏",
                    description="鍚屾椂鍚敤浜?JavaScript 涓?addJavascriptInterface锛屾棫鐗堟湰鍙杩滅▼浠ｇ爜鎵ц",
                    target=target, location="classes.dex",
                    evidence=",".join(found_wv.keys()),
                    cwe="CWE-749",
                    recommendation="targetSdk>=17 闄愬埗 @JavascriptInterface 鏆撮湶锛屽涓嶅彲淇￠〉闈㈢鐢ㄦˉ鎺?,
                ))
            if "setAllowFileAccess" in found_wv or "setAllowUniversalAccessFromFileURLs" in found_wv:
                findings.append(self._make_finding(
                    title="WebView 鍏佽 file:// 璁块棶",
                    severity="medium", category="WebView瀹夊叏",
                    description="WebView 寮€鏀炬枃浠惰闂紝鍙兘瀵艰嚧鏈湴鏂囦欢琚鍙?,
                    target=target, location="classes.dex",
                    evidence=",".join(found_wv.keys()),
                    cwe="CWE-73",
                    recommendation="setAllowFileAccess(false)锛岀鐢?file:// 璺ㄥ煙",
                ))

    # ================================================================== #
    # 6. iOS 瀹夊叏妫€娴?
    # ================================================================== #

    def _looks_like_ios_bundle(self, path: str) -> bool:
        """鍒ゆ柇鐩綍鏄惁鍍?iOS App Bundle锛堝惈 Info.plist 鎴?.app 瀛愮洰褰曪級"""
        try:
            for root, dirs, files in os.walk(path):
                if "Info.plist" in files:
                    return True
                for d in dirs:
                    if d.endswith(".app"):
                        return True
                # 鍙湅娴呭眰
                if root.count(os.sep) - path.count(os.sep) > 2:
                    break
        except Exception:
            pass
        return False

    def _assess_ios(self, target: str, findings: List[Finding],
                    result: DomainAssessment) -> None:
        """iOS (IPA/App Bundle) 瀹夊叏妫€娴?""
        result.checks_run.append("ios_info_plist")
        plist_path = self._find_info_plist(target)

        if not plist_path:
            findings.append(self._make_finding(
                title="鏈壘鍒?Info.plist",
                severity="medium", category="iOS缁撴瀯",
                description="iOS 搴旂敤鍖呬腑鏈畾浣嶅埌 Info.plist锛屾棤娉曡В鏋?ATS/URLScheme 绛?,
                target=target, location="Info.plist",
                evidence="閬嶅巻鐩爣鏈彂鐜?Info.plist",
            ))
            return

        findings.append(self._make_finding(
            title="瀹氫綅鍒?Info.plist",
            severity="info", category="iOS缁撴瀯",
            description=f"Info.plist 璺緞锛歿plist_path}",
            target=target, location=plist_path,
            evidence=plist_path,
        ))

        try:
            with open(plist_path, "rb") as f:
                plist_bytes = f.read()
        except Exception as e:
            findings.append(self._make_finding(
                title="璇诲彇 Info.plist 澶辫触",
                severity="medium", category="iOS缁撴瀯",
                description=f"璇诲彇澶辫触锛歿e}",
                target=target, location=plist_path, evidence=str(e),
            ))
            return

        plist = None
        plist_text = ""
        try:
            plist = plistlib.loads(plist_bytes)
            plist_text = plist_bytes.decode("utf-8", errors="ignore")
        except Exception:
            # 浜岃繘鍒?plist锛氬洖閫€瀛楃涓叉彁鍙?
            plist_text = self._extract_strings_from_binary(plist_bytes)

        # ---- ATS 妫€娴?----
        ats = {}
        if isinstance(plist, dict):
            ats = plist.get("NSAppTransportSecurity", {}) or {}
        allows_arbitrary = (isinstance(ats, dict)
                            and ats.get("NSAllowsArbitraryLoads") is True)
        if not allows_arbitrary:
            # 浜岃繘鍒跺洖閫€
            allows_arbitrary = "NSAllowsArbitraryLoads" in plist_text and "true" in plist_text
        if allows_arbitrary:
            findings.append(self._make_finding(
                title="ATS 鍏抽棴锛氬厑璁镐换鎰忓姞杞?NSAllowsArbitraryLoads=true)",
                severity="high", category="iOS閫氫俊",
                description="App Transport Security 琚叏灞€鍏抽棴锛屽厑璁告槑鏂?HTTP",
                target=target, location="Info.plist",
                evidence="NSAllowsArbitraryLoads=true",
                cwe="CWE-319",
                recommendation="鎸夊煙鍚嶉厤缃?NSExceptionDomains锛岄伩鍏嶅叏灞€鍏抽棴 ATS",
            ))
        else:
            findings.append(self._make_finding(
                title="ATS 鏈叏灞€鍏抽棴",
                severity="info", category="iOS閫氫俊",
                description="鏈彂鐜?NSAllowsArbitraryLoads=true锛堟垨 plist 涓轰簩杩涘埗锛屾寜瀛楃涓叉湭鍛戒腑锛?,
                target=target, location="Info.plist",
                evidence="鏈懡涓?NSAllowsArbitraryLoads",
            ))

        # ---- URL Scheme 妫€娴?----
        schemes: List[str] = []
        if isinstance(plist, dict):
            for item in plist.get("CFBundleURLTypes", []) or []:
                schemes.extend(item.get("CFBundleURLSchemes", []) or [])
        if not schemes:
            # 浜岃繘鍒跺洖閫€
            for m in re.findall(r"CFBundleURLSchemes", plist_text):
                schemes.append("(浜岃繘鍒跺懡涓?CFBundleURLSchemes)")
        if schemes:
            findings.append(self._make_finding(
                title="鑷畾涔?URL Scheme",
                severity="low", category="iOS鑳藉姏",
                description=f"App 娉ㄥ唽浜?{len(schemes)} 涓?URL Scheme",
                target=target, location="Info.plist",
                evidence=", ".join(map(str, schemes[:10])),
                recommendation="鏍￠獙鎺ユ敹鏂瑰弬鏁帮紝闃叉 URL Scheme 鍔寔/瓒婃潈璋冪敤",
            ))

        # ---- 鍚庡彴妯″紡 ----
        bg_modes: List[str] = []
        if isinstance(plist, dict):
            bg_modes = plist.get("UIBackgroundModes", []) or []
        if bg_modes:
            findings.append(self._make_finding(
                title="鍚庡彴杩愯妯″紡",
                severity="low", category="iOS鑳藉姏",
                description=f"鐢宠鍚庡彴妯″紡锛歿', '.join(bg_modes)}",
                target=target, location="Info.plist",
                evidence=", ".join(bg_modes),
                recommendation="浠呬繚鐣欎笟鍔″繀闇€鐨勫悗鍙版ā寮?,
            ))

        # ---- 鏁忔劅鏉冮檺鎻忚堪 ----
        usage_keys = ("NSCameraUsageDescription", "NSMicrophoneUsageDescription",
                      "NSLocationWhenInUseUsageDescription", "NSLocationAlwaysUsageDescription",
                      "NSPhotoLibraryUsageDescription", "NSContactsUsageDescription",
                      "NSCalendarsUsageDescription", "NSHealthShareUsageDescription")
        used = [k for k in usage_keys if
                (isinstance(plist, dict) and k in plist) or (k in plist_text)]
        if used:
            findings.append(self._make_finding(
                title="鏁忔劅闅愮鏉冮檺鎻忚堪",
                severity="info", category="iOS鏉冮檺",
                description=f"澹版槑浜?{len(used)} 涓殣绉佹潈闄愮敤閫旇鏄?,
                target=target, location="Info.plist",
                evidence=", ".join(used),
                recommendation="纭鏉冮檺鐢ㄩ€旀枃妗堢湡瀹烇紝浠呯敵璇峰繀瑕侀殣绉佹潈闄?,
            ))

        # ---- 浜岃繘鍒?plist 涔熻鍋氫竴娆＄‖缂栫爜瀵嗛挜鎵弿 ----
        self._analyze_hardcoded_secrets([("Info.plist", plist_bytes)], target, findings, result)

    def _find_info_plist(self, target: str) -> Optional[str]:
        """鍦?IPA(zip) 鎴栫洰褰曚腑瀹氫綅 Info.plist"""
        if os.path.isfile(target) and target.lower().endswith(".ipa"):
            try:
                with zipfile.ZipFile(target, "r") as zf:
                    for n in zf.namelist():
                        if n.endswith("Info.plist"):
                            data = zf.read(n)
                            # 涓存椂钀藉湴鍒板伐浣滅洰褰曚緵 plistlib 璇诲彇
                            tmp = os.path.join(os.getcwd(), "_ios_info.plist")
                            with open(tmp, "wb") as f:
                                f.write(data)
                            return tmp
            except Exception:
                return None
            return None
        if os.path.isdir(target):
            for root, dirs, files in os.walk(target):
                if "Info.plist" in files:
                    return os.path.join(root, "Info.plist")
        return None

    # ================================================================== #
    # 宸ュ叿鏂规硶
    # ================================================================== #

    @staticmethod
    def _haystacks(blob: bytes) -> List[str]:
        """瀵逛竴娈靛瓧鑺傜敓鎴愬绉嶇紪鐮佺殑鏂囨湰褰㈠紡锛圓SCII/UTF-8 + UTF-16LE锛夛紝
        浠ヤ究鍦ㄤ簩杩涘埗 AXML / DEX 涓婂仛姝ｅ垯鎼滅储銆?""
        out = []
        try:
            out.append(blob.decode("utf-8", errors="ignore"))
        except Exception:
            pass
        try:
            out.append(blob.decode("utf-16-le", errors="ignore"))
        except Exception:
            pass
        return out

    @staticmethod
    def _extract_strings_from_binary(data: bytes, min_len: int = 4) -> str:
        """浠庝簩杩涘埗鏁版嵁涓彁鍙栧彲鎵撳嵃瀛楃涓诧紝鎷兼垚涓€涓ぇ鏂囨湰渚涙鍒欎娇鐢ㄣ€?
        鍚屾椂鎶藉彇 ASCII 涓蹭笌 UTF-16LE 涓诧紙AXML 瀛楃涓叉睜澶氫负 UTF-16锛夈€?""
        chunks: List[str] = []
        # ASCII 鍙墦鍗板簭鍒?
        cur = bytearray()
        for b in data:
            if 32 <= b < 127:
                cur.append(b)
            else:
                if len(cur) >= min_len:
                    chunks.append(cur.decode("ascii", errors="ignore"))
                cur = bytearray()
        if len(cur) >= min_len:
            chunks.append(cur.decode("ascii", errors="ignore"))
        # UTF-16LE 鍙墦鍗板簭鍒?
        try:
            u = data.decode("utf-16-le", errors="ignore")
            runs = re.findall(r"[\x20-\x7e]{%d,}" % min_len, u)
            chunks.extend(runs)
        except Exception:
            pass
        return "\n".join(chunks)

    @staticmethod
    def _redact_secret(snippet: str) -> str:
        """瀵瑰懡涓殑瀵嗛挜鐗囨鍋氳劚鏁忥紝閬垮厤鍦ㄦ姤鍛婇噷瀹屾暣娉勯湶"""
        if not snippet:
            return snippet
        if len(snippet) <= 12:
            return snippet[:3] + "***"
        return snippet[:6] + "***" + snippet[-2:]


def register(engine):
    """娉ㄥ唽鍒扮粺涓€寮曟搸"""
    engine.register(MobileAssessor())
