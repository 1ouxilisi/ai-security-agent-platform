#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
data_classification.py 鈥?鏁版嵁鍒嗙被鍒嗙骇鍣ㄣ€?

瑕嗙洊锛?
    - 鏁忔劅鏁版嵁璇嗗埆锛氭鍒?妯″紡鍖归厤锛堣韩浠借瘉/鎵嬫満鍙?閭/閾惰鍗?鎶ょ収/杞︾墝/鍦板潃/濮撳悕绛?PII锛?
      PCI锛堜俊鐢ㄥ崱鍙?CVV/鏈夋晥鏈燂級銆丳HI锛堢梾鍘嗗彿/璇婃柇/澶勬柟/鍖讳繚鍙凤級銆?
      璐㈠姟鏁版嵁锛堣处鍙?绋庡彿/璐㈡姤/鍚堝悓閲戦锛夈€佸晢涓氭満瀵嗭紙婧愪唬鐮?閰嶆柟/瀹㈡埛鍚嶅崟/鎴樼暐鏂囨。锛?
    - 鍐呯疆 100+ 鏁忔劅鏁版嵁绫诲瀷锛堟鍒?鎻忚堪/椋庨櫓绛夌骇/琛屼笟鍒嗙被锛?
    - 鍒嗙骇鏍囧噯锛氬叕寮€ / 鍐呴儴 / 鏈哄瘑 / 缁濆瘑 鍥涚骇锛岃嚜鍔ㄥ垎绾х畻娉?
    - 鑷姩鏍囨敞锛氭壂鎻忔枃鏈?鏂囦欢鍐呭锛岃嚜鍔ㄥ垎绾э紝鐢熸垚鏁版嵁鍦板浘
    - 鏁版嵁璧勪骇娓呭崟锛氳祫浜у垪琛?浣嶇疆/绫诲瀷/鍒嗙骇/鎵€鏈夎€?璁块棶鏉冮檺/鍔犲瘑鐘舵€?
    - 鍒嗙被鍒嗙骇鎶ュ憡

璁捐瀹氫綅锛氫粎鍋氭暟鎹瘑鍒€佸垎绫诲垎绾т笌璧勪骇鐩樼偣锛岃緭鍑烘竻鍗曚笌鎶ュ憡锛屼笉杩涜浠讳綍鏁版嵁娉勯湶銆?
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 鍒嗙骇鏍囧噯锛堝叕寮€ / 鍐呴儴 / 鏈哄瘑 / 缁濆瘑锛?
# --------------------------------------------------------------------------- #
CLASSIFICATION_LEVELS: Dict[str, Dict[str, Any]] = {
    "public": {
        "level": 1, "name": "鍏紑", "color": "#52c41a",
        "desc": "鍙澶栧叕寮€鐨勬暟鎹紝娉勯湶鍚庝笉閫犳垚鎹熷锛堝畼缃戝浼犮€佸叕寮€璐㈡姤鎽樿绛夛級",
    },
    "internal": {
        "level": 2, "name": "鍐呴儴", "color": "#1890ff",
        "desc": "浠呴檺鍐呴儴浣跨敤鐨勬暟鎹紝娉勯湶鍚庨€犳垚杞诲井鎹熷锛堜竴鑸祦绋嬫枃妗ｃ€佺粍缁囨灦鏋勶級",
    },
    "confidential": {
        "level": 3, "name": "鏈哄瘑", "color": "#fa8c16",
        "desc": "鍙楅檺璁块棶鐨勬晱鎰熸暟鎹紝娉勯湶鍚庨€犳垚涓ラ噸鎹熷锛堜釜浜轰俊鎭€佸鎴疯祫鏂欍€佸悎鍚岋級",
    },
    "top_secret": {
        "level": 4, "name": "缁濆瘑", "color": "#ff4d4f",
        "desc": "鏋侀珮鏁忔劅搴︽牳蹇冩暟鎹紝娉勯湶鍚庨€犳垚鐗瑰埆涓ラ噸鎹熷锛堟牳蹇冮厤鏂广€佸瘑閽ャ€佸ぇ瑙勬āPII锛?,
    },
}

# 椋庨櫓绛夌骇鍒板垎绾х殑榛樿鏄犲皠
_RISK_TO_LEVEL = {
    "info": "public",
    "low": "internal",
    "medium": "confidential",
    "high": "confidential",
    "critical": "top_secret",
}


# --------------------------------------------------------------------------- #
# 鏁忔劅鏁版嵁绫诲瀷搴擄紙100+ 绫诲瀷锛?
# 姣忛」: id -> {name, category, industry, risk, regex(鍙€?, desc, examples(鑴辨晱)}
# 姝ｅ垯浠呯敤浜庢紨绀鸿瘑鍒紝鍛戒腑鍚庝笉鍥炴樉鐪熷疄鍊笺€?
# --------------------------------------------------------------------------- #
def _types() -> Dict[str, Dict[str, Any]]:
    T: Dict[str, Dict[str, Any]] = {}

    def add(tid: str, name: str, category: str, industry: str, risk: str,
            pattern: str, desc: str, examples: Optional[List[str]] = None,
            compiled: bool = True) -> None:
        entry: Dict[str, Any] = {
            "id": tid, "name": name, "category": category,
            "industry": industry, "risk": risk, "description": desc,
            "examples": examples or [],
        }
        if compiled and pattern:
            try:
                entry["_re"] = re.compile(pattern)
            except re.error:
                entry["_re"] = None
        T[tid] = entry

    # ---------------- PII 涓汉韬唤淇℃伅 ---------------- #
    add("pii_cn_id", "涓浗灞呮皯韬唤璇佸彿", "PII", "閫氱敤", "critical",
        r"(?<![0-9])\d{17}[\dXx](?![0-9])", "18浣嶈韩浠借瘉鍙凤紝鍚湴鍖?鐢熸棩/鏍￠獙浣?)
    add("pii_hk_id", "棣欐腐韬唤璇佸彿", "PII", "閫氱敤", "high",
        r"(?<![A-Za-z])[A-Z]\d{6}\([0-9A]\)(?![A-Za-z0-9])", "棣欐腐Smart ID鏍煎紡")
    add("pii_mo_id", "婢抽棬韬唤璇佸彿", "PII", "閫氱敤", "high",
        r"(?<![0-9])[157]\d{6}\([\d]\)(?![0-9])", "婢抽棬灞呮皯韬唤璇?)
    add("pii_tw_id", "鍙版咕韬唤璇佸彿", "PII", "閫氱敤", "high",
        r"(?<![A-Za-z])[A-Z]\d{9}(?![A-Za-z0-9])", "鍙版咕韬唤璇?)
    add("pii_passport", "鎶ょ収鍙风爜", "PII", "閫氱敤", "high",
        r"(?<![A-Za-z0-9])[A-Za-z]{1,2}\d{6,9}(?![A-Za-z0-9])", "鍥介檯閫氱敤鎶ょ収鍙?)
    add("pii_cn_mobile", "涓浗澶ч檰鎵嬫満鍙?, "PII", "閫氱敤", "high",
        r"(?<![0-9])1[3-9]\d{9}(?![0-9])", "11浣嶅ぇ闄嗘墜鏈哄彿")
    add("pii_intl_phone", "鍥介檯鐢佃瘽鍙风爜", "PII", "閫氱敤", "medium",
        r"(?<![+\d])\+?\d{1,3}[\s-]?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}(?![0-9])",
        "鍥介檯鏍煎紡鐢佃瘽")
    add("pii_email", "鐢靛瓙閭", "PII", "閫氱敤", "medium",
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "閭欢鍦板潃")
    add("pii_cn_address", "涓浗鍦板潃", "PII", "閫氱敤", "medium",
        r"[\u4e00-\u9fa5]{2,}(鐪亅鑷不鍖簗甯倈鍖簗鍘縷璺瘄琛梶閬搢鍙穦鏍媩鍗曞厓|瀹?",
        "涓枃灞呬綇/閫氳鍦板潃")
    add("pii_name_cn", "涓枃濮撳悕", "PII", "閫氱敤", "medium",
        r"[\u4e00-\u9fa5]{2,4}(?=鍏堢敓|濂冲＋|鍚屽|鑰佸笀|缁忕悊|鍖荤敓|寰嬪笀)",
        "绉拌皳涓婁笅鏂囩殑涓枃濮撳悕")
    add("pii_dob", "鍑虹敓鏃ユ湡", "PII", "閫氱敤", "medium",
        r"(19|20)\d{2}[-骞?.]\d{1,2}[-鏈?.]\d{1,2}鏃?", "鍑虹敓鏃ユ湡")
    add("pii_gender", "鎬у埆", "PII", "閫氱敤", "low",
        r"(?<=鎬у埆[:锛歕s]?)(鐢穦濂硘鏈煡)", "鎬у埆瀛楁")
    add("pii_nationality", "鍥界睄/姘戞棌", "PII", "閫氱敤", "low",
        r"(?<=鍥界睄[:锛歕s]?|姘戞棌[:锛歕s]?)[\u4e00-\u9fa5]{2,10}", "鍥界睄鎴栨皯鏃?)
    add("pii_marital", "濠氬Щ鐘跺喌", "PII", "閫氱敤", "low",
        r"(?<=濠氬Щ鐘跺喌[:锛歕s]?)(鏈|宸插|绂诲紓|涓у伓)", "濠氬Щ鐘舵€?)
    add("pii_education", "瀛﹀巻", "PII", "閫氱敤", "low",
        r"(?<=瀛﹀巻[:锛歕s]?)(鍗氬＋|纭曞＋|鏈|澶т笓|楂樹腑|鍒濅腑)", "瀛﹀巻")
    add("pii_occupation", "鑱屼笟", "PII", "閫氱敤", "low",
        r"(?<=鑱屼笟[:锛歕s]?)[\u4e00-\u9fa5]{2,15}", "鑱屼笟")
    add("pii_plate_cn", "涓浗杞︾墝鍙?, "PII", "浜ら€?, "high",
        r"(?<![\u4e00-\u9fa5A-Za-z0-9])[\u4e00-\u9fa5][A-Za-z][A-Za-z0-9]{5,6}(?![\u4e00-\u9fa5A-Za-z0-9])",
        "姘戠敤杞︾墝/鏂拌兘婧愯溅鐗?)
    add("pii_drivers_license", "椹鹃┒璇佸彿", "PII", "浜ら€?, "high",
        r"(?<![0-9])\d{15,18}[0-9Xx]?(?![0-9])", "椹鹃┒璇佸彿(澶氬悓韬唤璇?")
    add("pii_vehicle_vin", "杞﹁締VIN鐮?, "PII", "浜ら€?, "medium",
        r"(?<![A-Za-z0-9])[A-HJ-NPR-Z0-9]{17}(?![A-Za-z0-9])", "杞﹁締璇嗗埆浠ｅ彿")
    add("pii_ip", "IP鍦板潃", "PII", "閫氱敤", "low",
        r"(?<![0-9.])(\d{1,3}\.){3}\d{1,3}(?![0-9.])", "IPv4鍦板潃")
    add("pii_mac", "MAC鍦板潃", "PII", "閫氱敤", "low",
        r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])",
        "璁惧MAC鍦板潃")
    add("pii_geo", "缁忕含搴﹀潗鏍?, "PII", "閫氱敤", "medium",
        r"(缁忓害|绾害|longitude|latitude)[:锛歕s-]?(-?\d{1,3}\.\d{4,})", "绮剧‘鍦扮悊浣嶇疆")
    add("pii_biometric", "鐢熺墿鐗瑰緛妯℃澘", "PII", "閫氱敤", "critical",
        r"(鎸囩汗|浜鸿劯|澹扮汗|铏硅啘|鎺岄潤鑴?.{0,6}(妯℃澘|鐗瑰緛鍊紎hash)", "鐢熺墿璇嗗埆妯℃澘")
    add("pii_family", "瀹跺涵鎴愬憳鍏崇郴", "PII", "閫氱敤", "medium",
        r"(鐖朵翰|姣嶄翰|閰嶅伓|瀛愬コ|鍎垮瓙|濂冲効|涓堝か|濡诲瓙)[:锛歕s][\u4e00-\u9fa5]{2,4}",
        "瀹跺涵鍏崇郴淇℃伅")
    add("pii_religion", "瀹楁暀淇′话", "PII", "閫氱敤", "high",
        r"(瀹楁暀淇′话|淇′话)[:锛歕s]?[\u4e00-\u9fa5]{2,10}", "瀹楁暀淇′话")
    add("pii_political", "鏀挎不闈㈣矊", "PII", "閫氱敤", "medium",
        r"(鏀挎不闈㈣矊|鍏氭淳)[:锛歕s]?(鍏氬憳|鍥㈠憳|缇や紬|姘戜富鍏氭淳)", "鏀挎不闈㈣矊")
    add("pii_social_media", "绀句氦璐﹀彿", "PII", "閫氱敤", "medium",
        r"(寰俊鍙穦QQ|寰崥|鎶栭煶|灏忕孩涔Instagram|Twitter|Facebook)[:锛歕s]?[A-Za-z0-9_\-]{4,30}",
        "绀句氦骞冲彴璐﹀彿")
    add("pii_biometric_id", "浜鸿劯璇嗗埆ID", "PII", "閫氱敤", "high",
        r"(face_id|浜鸿劯ID|浜鸿劯鐗瑰緛ID)[:锛?][A-Za-z0-9_\-]{8,}", "浜鸿劯ID")

    # ---------------- PCI 鏀粯鍗¤涓?---------------- #
    add("pci_visa", "Visa淇＄敤鍗″彿", "PCI", "閲戣瀺", "critical",
        r"(?<![0-9])4\d{12}(?:\d{3})?(?![0-9])", "Visa鍗?13/16浣?")
    add("pci_mastercard", "Mastercard鍗″彿", "PCI", "閲戣瀺", "critical",
        r"(?<![0-9])(?:5[1-5]\d{14}|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12})(?![0-9])",
        "涓囦簨杈惧崱")
    add("pci_amex", "American Express鍗″彿", "PCI", "閲戣瀺", "critical",
        r"(?<![0-9])3[47]\d{13}(?![0-9])", "杩愰€氬崱")
    add("pci_discover", "Discover鍗″彿", "PCI", "閲戣瀺", "high",
        r"(?<![0-9])6(?:011|5\d{2})\d{12}(?![0-9])", "Discover鍗?)
    add("pci_jcb", "JCB鍗″彿", "PCI", "閲戣瀺", "high",
        r"(?<![0-9])(?:3(?:0[0-5]|[06-9])\d{12}|2131|1800\d{11})(?![0-9])", "JCB鍗?)
    add("pci_cn_unionpay", "閾惰仈鍗″彿", "PCI", "閲戣瀺", "critical",
        r"(?<![0-9])62\d{14,17}(?![0-9])", "閾惰仈鍗?62寮€澶?")
    add("pci_cvv", "CVV/CVC瀹夊叏鐮?, "PCI", "閲戣瀺", "critical",
        r"(?<![0-9])(CVV|CVV2|CVC|CVC2|瀹夊叏鐮?[:锛歕s]?(\d{3,4})(?![0-9])",
        "鍗¤儗闈㈠畨鍏ㄧ爜")
    add("pci_expiry", "淇＄敤鍗℃湁鏁堟湡", "PCI", "閲戣瀺", "high",
        r"(?<![0-9/])(0[1-9]|1[0-2])[/\-](20)?[2-9]\d(?![0-9])",
        "鍗℃湁鏁堟湡 MM/YY")
    add("pci_track1", "纾侀亾1鏁版嵁", "PCI", "閲戣瀺", "critical",
        r"%B\d{12,19}\^[^\^]{2,26}\^\d{3}", "纾佹潯Track1")
    add("pci_track2", "纾侀亾2鏁版嵁", "PCI", "閲戣瀺", "critical",
        r";\d{12,19}=\d{4,12}\?", "纾佹潯Track2")
    add("pci_pin_block", "PIN鍔犲瘑鍧?, "PCI", "閲戣瀺", "critical",
        r"(pin_block|PIN鍧?[:锛?][0-9A-Fa-f]{16,32}", "鍔犲瘑PIN")
    add("pci_bin", "鍙戝崱琛岃瘑鍒爜BIN", "PCI", "閲戣瀺", "medium",
        r"(?<![0-9])\d{6}(?![0-9])", "鍗IN(鍓?浣嶏紝闇€涓婁笅鏂?")
    add("pci_merchant", "鍟嗘埛鍙?, "PCI", "閲戣瀺", "medium",
        r"(鍟嗘埛鍙穦merchant_id|MID)[:锛?][A-Za-z0-9]{6,15}", "鏀跺崟鍟嗘埛鍙?)

    # ---------------- PHI 鍖荤枟鍋ュ悍淇℃伅 ---------------- #
    add("phi_medical_record", "鐥呭巻鍙?, "PHI", "鍖荤枟", "high",
        r"(鐥呭巻鍙穦鐥呮鍙穦medical_record_no)[:锛?]?[A-Za-z0-9\-]{4,15}", "浣忛櫌/闂ㄨ瘖鐥呭巻鍙?)
    add("phi_hisno", "浣忛櫌鍙?, "PHI", "鍖荤枟", "high",
        r"(浣忛櫌鍙穦inpatient_no)[:锛?]?[A-Za-z0-9\-]{4,15}", "浣忛櫌鐧昏鍙?)
    add("phi_outpatient", "闂ㄨ瘖鍙?, "PHI", "鍖荤枟", "medium",
        r"(闂ㄨ瘖鍙穦闂ㄨ瘖鍗″彿)[:锛?]?[A-Za-z0-9\-]{4,15}", "闂ㄨ瘖鍙?)
    add("phi_diagnosis", "璇婃柇缁撹", "PHI", "鍖荤枟", "high",
        r"(璇婃柇|璇婃柇缁撹|ICD-?10)[:锛氾細\s]?[\u4e00-\u9fa5A-Za-z0-9锛堬級()銆侊紝,]{2,40}",
        "鐤剧梾璇婃柇")
    add("phi_icd", "ICD缂栫爜", "PHI", "鍖荤枟", "medium",
        r"(?<![A-Za-z0-9])[A-Z][0-9]{2}(?:\.[0-9]{1,4})?(?![A-Za-z0-9])",
        "ICD-10缂栫爜")
    add("phi_prescription", "澶勬柟鍙?, "PHI", "鍖荤枟", "high",
        r"(澶勬柟鍙穦prescription_no)[:锛?]?[A-Za-z0-9\-]{4,15}", "澶勬柟缂栧彿")
    add("phi_drug", "澶勬柟鑽悕绉?, "PHI", "鍖荤枟", "medium",
        r"(鑽搧|鑽墿|澶勬柟)[:锛?锛歕s]?[\u4e00-\u9fa5A-Za-z]{2,15}(鐗噟鑳跺泭|娉ㄥ皠娑瞸棰楃矑|鑶??",
        "鐢ㄨ嵂淇℃伅")
    add("phi_insurance", "鍖讳繚鍙?, "PHI", "鍖荤枟", "critical",
        r"(鍖讳繚鍙穦绀句繚鍙穦鍖讳繚鍗″彿)[:锛?]?[A-Za-z0-9\-]{6,20}", "鍖讳繚/绀句繚璐﹀彿")
    add("phi_blood_type", "琛€鍨?, "PHI", "鍖荤枟", "low",
        r"(?<=琛€鍨媅:锛歕s]?)(A|B|AB|O)[Rh]{0,2}[闃撮槼]?", "琛€鍨?)
    add("phi_allergy", "杩囨晱鍙?, "PHI", "鍖荤枟", "high",
        r"(杩囨晱鍙瞸杩囨晱鍘焲鑽墿杩囨晱)[:锛?锛歕s]?[\u4e00-\u9fa5A-Za-z銆侊紝, ]{2,30}",
        "杩囨晱璁板綍")
    add("phi_surgery", "鎵嬫湳璁板綍", "PHI", "鍖荤枟", "high",
        r"(鎵嬫湳|鎵嬫湳鍙?[:锛?锛歕s]?[\u4e00-\u9fa5]{2,20}(鏈瘄娌荤枟)?", "鎵嬫湳璁板綍")
    add("phi_test_result", "妫€楠屾鏌ョ粨鏋?, "PHI", "鍖荤枟", "high",
        r"(琛€绾㈣泲鐧絴鐧界粏鑳瀨琛€绯東琛€鍘媩蹇冪巼|CT|MRI|鐥呯悊)[:锛?锛?]?\d{1,4}\.?\d{0,3}",
        "妫€楠屾暟鍊?)
    add("phi_genetic", "鍩哄洜妫€娴嬫暟鎹?, "PHI", "鍖荤枟", "critical",
        r"(鍩哄洜|鍩哄洜缁剕鍩哄洜鍨媩SNP|鏌撹壊浣?[:锛?锛歕s]?[A-Za-z0-9]{2,20}",
        "鍩哄洜/閬椾紶淇℃伅")
    add("phi_disability", "娈嬬柧璇佸彿", "PHI", "鍖荤枟", "high",
        r"(娈嬬柧璇佸彿|disability_no)[:锛?]?[0-9Xx]{10,20}", "娈嬬柧浜鸿瘉鍙?)

    # ---------------- 璐㈠姟/绋庡姟 ---------------- #
    add("fin_bank_account", "閾惰璐﹀彿", "璐㈠姟", "閲戣瀺", "critical",
        r"(?<![0-9])\d{12,19}(?![0-9])", "閾惰璐︽埛鍙?)
    add("fin_cn_tax_id", "涓浗缁熶竴绀句細淇＄敤浠ｇ爜", "璐㈠姟", "绋庡姟", "high",
        r"(?<![0-9A-Z])([0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10})(?![0-9A-Z])",
        "浼佷笟缁熶竴绀句細淇＄敤浠ｇ爜")
    add("fin_cn_tax_person", "涓汉绾崇◣浜鸿瘑鍒彿", "璐㈠姟", "绋庡姟", "high",
        r"(绾崇◣浜鸿瘑鍒彿|绋庡彿)[:锛?]?[0-9A-Za-z]{15,20}", "绋庡姟鐧昏鍙?)
    add("fin_us_tin", "缇庡浗TIN/EIN", "璐㈠姟", "绋庡姟", "high",
        r"(?<![0-9])(\d{2}-\d{7})(?![0-9])", "缇庡浗闆囦富璇嗗埆鍙?)
    add("fin_us_ssn", "缇庡浗SSN", "璐㈠姟", "閲戣瀺", "critical",
        r"(?<![0-9])\d{3}-\d{2}-\d{4}(?![0-9])", "缇庡浗绀句繚鍙?)
    add("fin_iban", "IBAN鍥介檯璐﹀彿", "璐㈠姟", "閲戣瀺", "high",
        r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}[A-Z0-9]{10,30}(?![A-Za-z0-9])", "鍥介檯閾惰璐﹀彿")
    add("fin_swift", "SWIFT浠ｇ爜", "璐㈠姟", "閲戣瀺", "medium",
        r"(?<![A-Za-z0-9])[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?(?![A-Za-z0-9])",
        "SWIFT/BIC浠ｇ爜")
    add("fin_amount", "鍚堝悓/浜ゆ槗閲戦", "璐㈠姟", "閫氱敤", "medium",
        r"(閲戦|鍚堝悓棰潀浜ゆ槗棰潀鎶ヤ环|鎬讳环)[:锛?锛歕s]?[锟?鈧?\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?涓?浜?鍏?",
        "璐㈠姟閲戦")
    add("fin_salary", "钖祫", "璐㈠姟", "HR", "high",
        r"(钖祫|宸ヨ祫|骞磋柂|鏈堣柂|钖叕)[:锛?锛歕s]?[锟?]?\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?[涓囧崈]?鍏?",
        "钖叕淇℃伅")
    add("fin_financial_report", "璐㈠姟鎶ヨ〃", "鍟嗕笟鏈哄瘑", "璐㈠姟", "high",
        r"(璧勪骇璐熷€鸿〃|鍒╂鼎琛▅鐜伴噾娴侀噺琛▅瀹¤鎶ュ憡|璐㈡姤)", "璐㈠姟鎶ヨ〃鍏抽敭璇?)
    add("fin_budget", "棰勭畻", "璐㈠姟", "鍐呴儴", "medium",
        r"(棰勭畻|budget)[:锛?锛歕s]?[锟?]?\d", "棰勭畻閲戦")
    add("fin_invoice", "鍙戠エ鍙?, "璐㈠姟", "绋庡姟", "medium",
        r"(鍙戠エ鍙穦invoice_no|invoice_number)[:锛?]?[A-Za-z0-9\-]{6,20}", "鍙戠エ鍙风爜")
    add("fin_contract_no", "鍚堝悓缂栧彿", "璐㈠姟", "娉曞姟", "medium",
        r"(鍚堝悓缂栧彿|鍚堝悓鍙穦contract_no)[:锛?]?[A-Za-z0-9\-]{4,20}", "鍚堝悓缂栧彿")
    add("fin_annual_report", "骞存姤/鎷涜偂涔?, "鍟嗕笟鏈哄瘑", "璧勬湰甯傚満", "low",
        r"(骞存姤|鎷涜偂璇存槑涔IPO|鎷涜偂涔?", "鍏紑/鎶湶鏂囨。")
    add("fin_payment_token", "鏀粯浠ょ墝", "璐㈠姟", "閲戣瀺", "critical",
        r"(payment_token|鏀粯浠ょ墝|pay_token)[:锛?][A-Za-z0-9_\-]{16,}", "鏀粯浠ょ墝")

    # ---------------- 鍟嗕笟鏈哄瘑 ---------------- #
    add("biz_source_code", "婧愪唬鐮?, "鍟嗕笟鏈哄瘑", "鐮斿彂", "high",
        r"(def |class |function |public class |#include|import .+ from )",
        "婧愪唬鐮佺壒寰?)
    add("biz_api_key", "API瀵嗛挜", "鍟嗕笟鏈哄瘑", "閫氱敤", "critical",
        r"(?<![A-Za-z0-9])(sk|pk|ak|sk_live|sk_test|api[_-]?key|apikey)['\"=:\s]+[A-Za-z0-9_\-]{16,}",
        "API瀵嗛挜")
    add("biz_secret", "Secret/瀵嗛挜", "鍟嗕笟鏈哄瘑", "閫氱敤", "critical",
        r"(?<![A-Za-z0-9])(secret|client_secret|access_key|private_key)['\"=:\s]+[A-Za-z0-9_\-/+=]{16,}",
        "鍚勭被Secret")
    add("biz_jwt", "JWT浠ょ墝", "鍟嗕笟鏈哄瘑", "閫氱敤", "high",
        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        "JWT token")
    add("biz_private_key", "绉侀挜", "鍟嗕笟鏈哄瘑", "瀹夊叏", "critical",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "PEM绉侀挜")
    add("biz_aws_key", "AWS Access Key", "鍟嗕笟鏈哄瘑", "浜?, "critical",
        r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])", "AWS璁块棶瀵嗛挜")
    add("biz_google_api", "Google API瀵嗛挜", "鍟嗕笟鏈哄瘑", "浜?, "high",
        r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}(?![A-Za-z0-9])", "Google API Key")
    add("biz_gcp_service", "GCP鏈嶅姟璐﹀彿", "鍟嗕笟鏈哄瘑", "浜?, "high",
        r"\"type\"[:锛歖\s*\"service_account\"", "GCP鏈嶅姟璐﹀彿JSON")
    add("biz_db_conn", "鏁版嵁搴撹繛鎺ヤ覆", "鍟嗕笟鏈哄瘑", "鏁版嵁搴?, "critical",
        r"(mysql|postgresql|mongodb|redis|jdbc)://[^\s:@/]+:[^\s@]+@",
        "鍚处鍙峰瘑鐮佺殑杩炴帴涓?)
    add("biz_recipe", "閰嶆柟/宸ヨ壓", "鍟嗕笟鏈哄瘑", "鐮斿彂", "critical",
        r"(閰嶆柟|宸ヨ壓|閰嶆瘮|鍘熸枡|绉樻柟|sop|SOP)[:锛?锛歕s]", "閰嶆柟鍏抽敭璇?)
    add("biz_customer_list", "瀹㈡埛鍚嶅崟", "鍟嗕笟鏈哄瘑", "閿€鍞?, "high",
        r"(瀹㈡埛鍚嶅崟|瀹㈡埛娓呭崟|澶у鎴穦瀹㈡埛妗ｆ|customer_list)", "瀹㈡埛璧勬枡")
    add("biz_strategy", "鎴樼暐鏂囨。", "鍟嗕笟鏈哄瘑", "鎴樼暐", "high",
        r"(鎴樼暐|瑙勫垝|涓夊勾瑙勫垝|鍟嗕笟璁″垝涔BP|骞惰喘|IPO璁″垝)", "鎴樼暐绫绘枃妗?)
    add("biz_pricing", "瀹氫环绛栫暐", "鍟嗕笟鏈哄瘑", "閿€鍞?, "medium",
        r"(瀹氫环|搴曚环|鎶樻墸|姣涘埄鐜噟margin)[:锛?锛歕s]", "瀹氫环淇℃伅")
    add("biz_employee_list", "鍛樺伐鑺卞悕鍐?, "鍟嗕笟鏈哄瘑", "HR", "high",
        r"(鑺卞悕鍐寍鍛樺伐鍚嶅崟|钖祫琛▅缁勭粐缁撴瀯|鍛樺伐妗ｆ)", "HR鏁忔劅鏁版嵁")
    add("biz_merger", "骞惰喘灏借皟", "鍟嗕笟鏈哄瘑", "鎴樼暐", "critical",
        r"(灏借皟|灏借亴璋冩煡|骞惰喘|鏀惰喘|target|DD鎶ュ憡)", "骞惰喘鏁忔劅鏉愭枡")
    add("biz_research", "鐮斿彂璺嚎鍥?, "鍟嗕笟鏈哄瘑", "鐮斿彂", "high",
        r"(璺嚎鍥緗roadmap|鎶€鏈矾绾縷棰勭爺|涓撳埄鐢宠)", "鐮斿彂璁″垝")
    add("biz_security_arch", "瀹夊叏鏋舵瀯", "鍟嗕笟鏈哄瘑", "瀹夊叏", "high",
        r"(瀹夊叏鏋舵瀯|缃戠粶鎷撴墤|闃茬伀澧欒鍒檤娓楅€忔姤鍛妡婕忔礊鎶ュ憡)", "瀹夊叏鏁忔劅鏂囨。")
    add("biz_supply_chain", "渚涘簲閾句俊鎭?, "鍟嗕笟鏈哄瘑", "閲囪喘", "medium",
        r"(渚涘簲鍟唡渚涘簲閾緗閲囪喘浠穦BOM|鐗╂枡娓呭崟)", "渚涘簲閾?)
    add("biz_board_minutes", "钁ｄ簨浼氱邯瑕?, "鍟嗕笟鏈哄瘑", "娌荤悊", "high",
        r"(钁ｄ簨浼殀鑲′笢浼殀绾|鍐宠)", "娌荤悊绫绘満瀵?)
    add("biz_whistleblow", "涓炬姤浜烘潗鏂?, "鍟嗕笟鏈哄瘑", "鍚堣", "critical",
        r"(涓炬姤|whistleblow|璋冩煡鏉愭枡|鍐呴儴璋冩煡)", "鏁忔劅璋冩煡")

    # ---------------- 鍏朵粬/閫氱敤鍑瘉 ---------------- #
    add("cred_password", "鏄庢枃瀵嗙爜", "閫氱敤鍑瘉", "瀹夊叏", "critical",
        r"(?<![A-Za-z0-9])(password|passwd|pwd)['\"=:\s]+[^\s'\"]{6,}",
        "鏄庢枃瀵嗙爜")
    add("cred_session", "Session ID", "閫氱敤鍑瘉", "瀹夊叏", "high",
        r"(?<![A-Za-z0-9])(sessionid|session_id|sid)['\"=:\s][A-Za-z0-9_\-\.]{16,}",
        "浼氳瘽鏍囪瘑")
    add("cred_cookie", "Cookie", "閫氱敤鍑瘉", "瀹夊叏", "medium",
        r"(?<![A-Za-z0-9])(cookie|Cookie)[:锛?]\s*[A-Za-z0-9_\-\.=%]{20,}",
        "Cookie鍊?)
    add("cred_bearer", "Bearer浠ょ墝", "閫氱敤鍑瘉", "瀹夊叏", "high",
        r"(?<![A-Za-z0-9])Bearer\s+[A-Za-z0-9_\-\.=]{16,}", "Bearer Token")
    add("cred_private_ip", "鍐呯綉IP", "鍩虹璁炬柦", "缃戠粶", "low",
        r"(?<![0-9.])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?![0-9.])",
        "鍐呯綉绉佹湁鍦板潃")
    add("cred_db_host", "鏁版嵁搴撲富鏈?, "鍩虹璁炬柦", "鏁版嵁搴?, "medium",
        r"(db_host|database_host|DB_HOST)[:锛?]\s*[A-Za-z0-9\-\.]{4,}", "鏁版嵁搴撲富鏈?)
    add("cred_ssh_key", "SSH绉侀挜", "閫氱敤鍑瘉", "瀹夊叏", "critical",
        r"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH绉侀挜")
    add("cred_github_token", "GitHub Token", "閫氱敤鍑瘉", "鐮斿彂", "high",
        r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36,}(?![A-Za-z0-9])", "GitHub PAT")
    add("cred_slack_token", "Slack Token", "閫氱敤鍑瘉", "鍗忎綔", "high",
        r"(?<![A-Za-z0-9])xox[baprs]-[0-9A-Za-z\-]{10,}(?![A-Za-z0-9])", "Slack浠ょ墝")
    add("cred_aliyun", "闃块噷浜慉ccessKey", "閫氱敤鍑瘉", "浜?, "critical",
        r"(?<![A-Za-z0-9])LTAI[0-9A-Za-z]{12,20}(?![A-Za-z0-9])", "闃块噷浜慉K")
    add("cred_tencent", "鑵捐浜慡ecretId", "閫氱敤鍑瘉", "浜?, "high",
        r"(?<![A-Za-z0-9])AKID[A-Za-z0-9]{32,}(?![A-Za-z0-9])", "鑵捐浜慡ecretId")
    add("cred_jdbc", "JDBC涓?, "閫氱敤鍑瘉", "鏁版嵁搴?, "high",
        r"jdbc:[a-z]+://[^\s]+", "JDBC杩炴帴涓?)
    add("cred_email_token", "閭欢鎺堟潈鐮?, "閫氱敤鍑瘉", "杩愮淮", "high",
        r"(閭鎺堟潈鐮亅smtp_password|mail_password)[:锛?]\s*\S{8,}", "閭欢鎺堟潈鐮?)

    # ---------------- 琛屼笟涓撳睘 ---------------- #
    add("ind_edu_student", "瀛︾睄鍙?, "鏁欒偛", "鏁欒偛", "high",
        r"(瀛︾睄鍙穦student_id|瀛﹀彿)[:锛?]?[A-Za-z0-9\-]{6,20}", "瀛︾敓瀛︾睄")
    add("ind_edu_score", "鑰冭瘯鎴愮哗", "鏁欒偛", "鏁欒偛", "medium",
        r"(鎴愮哗|鍒嗘暟|GPA|鎺掑悕)[:锛?锛?]?\d{1,3}(\.\d{1,2})?", "鎴愮哗淇℃伅")
    add("ind_law_case", "妗堜欢鍗峰畻", "娉曞緥", "鍙告硶", "high",
        r"(妗堝彿|鍗峰畻|妗堝嵎|court_case)[:锛?]?[A-Za-z0-9\-]{6,20}", "鍙告硶妗堜欢")
    add("ind_immigration", "绛捐瘉/灞呯暀", "鍑哄叆澧?, "绉绘皯", "high",
        r"(绛捐瘉鍙穦visa|灞呯暀璁稿彲|缁垮崱)[:锛?]?[A-Za-z0-9\-]{6,20}", "绛捐瘉灞呯暀")
    add("ind_realestate", "鎴夸骇淇℃伅", "涓嶅姩浜?, "鎴夸骇", "high",
        r"(鎴夸骇璇亅涓嶅姩浜ф潈璇亅鎴夸骇鍦板潃|浜ф潈鍙?[:锛?]?[\u4e00-\u9fa5A-Za-z0-9\-]{4,}",
        "涓嶅姩浜?)
    add("ind_vehicle_owner", "杞︿富淇℃伅", "浜ら€?, "杞︾", "high",
        r"(杞︿富|杞﹁締鎵€鏈変汉|鐧昏璇佷功)[:锛?]?[\u4e00-\u9fa5]{2,4}", "杞︿富")
    add("ind_logistics", "鐗╂祦杩愬崟", "渚涘簲閾?, "鐗╂祦", "medium",
        r"(杩愬崟鍙穦蹇€掑崟鍙穦tracking_no|waybill)[:锛?]?[A-Za-z0-9\-]{8,25}",
        "鐗╂祦鍗曞彿")
    add("ind_ecom_order", "鐢靛晢璁㈠崟", "鐢靛晢", "鐢靛晢", "medium",
        r"(璁㈠崟鍙穦璁㈠崟缂栧彿|order_id|order_no)[:锛?]?[A-Za-z0-9\-]{6,25}",
        "璁㈠崟鍙?)
    add("ind_game_uid", "娓告垙璐﹀彿UID", "娓告垙", "娓告垙", "low",
        r"(?<![0-9])(uid|UID|鐜╁ID|game_id)[:锛?]?\d{5,12}(?![0-9])",
        "娓告垙璐﹀彿")

    return T


SENSITIVE_TYPES_LIBRARY: Dict[str, Dict[str, Any]] = _types()


# --------------------------------------------------------------------------- #
# 鏁版嵁鍒嗙被鍒嗙骇鍣?
# --------------------------------------------------------------------------- #
class DataClassifier:
    """鏁版嵁鍒嗙被鍒嗙骇鍣細璇嗗埆鏁忔劅鏁版嵁銆佽嚜鍔ㄥ垎绾с€佺敓鎴愭暟鎹湴鍥句笌璧勪骇娓呭崟銆?""

    def __init__(self) -> None:
        self.types: Dict[str, Dict[str, Any]] = SENSITIVE_TYPES_LIBRARY
        self.findings: List[Dict[str, Any]] = []
        self.assets: List[Dict[str, Any]] = []
        self._scan_id: str = ""

    # ------------------------------------------------------------------ #
    # 鎵弿鏂囨湰鍐呭
    # ------------------------------------------------------------------ #
    def scan_text(self, content: str, source: str = "inline_text",
                  owner: str = "unknown") -> Dict[str, Any]:
        """鎵弿涓€娈垫枃鏈紝璇嗗埆鍏朵腑鐨勬晱鎰熸暟鎹被鍨嬩笌鍛戒腑娆℃暟銆?""
        self.findings = []
        hits_by_type: Dict[str, Dict[str, Any]] = {}
        if not content:
            return {"scan_id": self._scan_id, "hits": [], "total_hits": 0,
                    "level": "public", "assets": []}

        for tid, meta in self.types.items():
            rx = meta.get("_re")
            if not rx:
                continue
            try:
                matches = rx.findall(content)
            except Exception:
                matches = []
            cnt = len(matches)
            if cnt > 0:
                # 鍘婚噸鍖归厤鍊兼暟閲忥紙涓嶅洖鏄惧師鏂囷紝鍙粺璁★級
                uniq = len(set(matches if matches and isinstance(matches[0], str) else [str(m) for m in matches]))
                entry = {
                    "type_id": tid, "type_name": meta["name"],
                    "category": meta["category"], "industry": meta["industry"],
                    "risk": meta["risk"], "count": cnt, "unique": uniq,
                    "level_hint": _RISK_TO_LEVEL.get(meta["risk"], "internal"),
                    "description": meta["description"],
                }
                hits_by_type[tid] = entry
                self.findings.append(entry)

        hits = list(hits_by_type.values())
        level = self._auto_classify(hits)
        asset = self._build_asset(source, owner, hits, level)
        self.assets = [asset]
        return {
            "scan_id": self._scan_id or uuid.uuid4().hex[:10],
            "source": source, "owner": owner,
            "hits": hits, "total_hits": sum(h["count"] for h in hits),
            "distinct_types": len(hits),
            "level": level, "level_name": CLASSIFICATION_LEVELS[level]["name"],
            "asset": asset,
            "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 鎵归噺鎵弿锛堟ā鎷熸枃浠?鏁版嵁搴?浠ｇ爜锛?
    # ------------------------------------------------------------------ #
    def scan_assets(self, assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """鎵归噺鎵弿鏁版嵁璧勪骇銆?

        assets 椤? {path/source, content/preview, owner, type(鏂囦欢/搴?琛?浠ｇ爜)}
        """
        self._scan_id = uuid.uuid4().hex[:12]
        self.assets = []
        results: List[Dict[str, Any]] = []
        level_counter: Dict[str, int] = {"public": 0, "internal": 0,
                                          "confidential": 0, "top_secret": 0}
        cat_counter: Dict[str, int] = {}

        for a in assets:
            content = a.get("content") or a.get("preview") or ""
            source = a.get("path") or a.get("source") or "unknown"
            owner = a.get("owner") or "unknown"
            r = self.scan_text(content, source, owner)
            level = r["level"]
            level_counter[level] = level_counter.get(level, 0) + 1
            for h in r["hits"]:
                cat_counter[h["category"]] = cat_counter.get(h["category"], 0) + 1
            results.append({
                "source": source, "owner": owner,
                "asset_type": a.get("type", "unknown"),
                "level": level, "level_name": r["level_name"],
                "distinct_types": r["distinct_types"],
                "total_hits": r["total_hits"],
                "detected": [{"type": h["type_name"], "risk": h["risk"],
                              "count": h["count"]} for h in r["hits"]],
                "encryption": a.get("encryption", "unknown"),
                "access": a.get("access", "unknown"),
            })
            self.assets.append(results[-1])

        overall = self._overall_level(level_counter)
        return {
            "scan_id": self._scan_id,
            "assets_scanned": len(assets),
            "assets": results,
            "level_distribution": level_counter,
            "category_distribution": cat_counter,
            "overall_level": overall,
            "overall_level_name": CLASSIFICATION_LEVELS[overall]["name"],
            "total_sensitive_hits": sum(r["total_hits"] for r in results),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 鑷姩鍒嗙骇绠楁硶
    # ------------------------------------------------------------------ #
    def _auto_classify(self, hits: List[Dict[str, Any]]) -> str:
        """鍩轰簬鏁版嵁绫诲瀷/鏁伴噺/缁勫悎鏁忔劅搴﹁嚜鍔ㄥ垎绾с€?""
        if not hits:
            return "public"
        has_critical = any(h["risk"] == "critical" for h in hits)
        has_high = any(h["risk"] == "high" for h in hits)
        distinct = len(hits)
        total = sum(h["count"] for h in hits)
        # 缁勫悎鏁忔劅搴︼細critical 鍛戒腑锛屾垨鍚屼竴瀵硅薄鍚?>=3 绫婚珮鏁忕被鍨?-> 缁濆瘑
        if has_critical and (distinct >= 3 or total >= 20):
            return "top_secret"
        if has_critical:
            return "top_secret"
        if has_high and (distinct >= 4 or total >= 30):
            return "confidential"
        if has_high:
            return "confidential"
        if distinct >= 2 or total >= 5:
            return "internal"
        return "internal"

    def _overall_level(self, counter: Dict[str, int]) -> str:
        if counter.get("top_secret", 0) > 0:
            return "top_secret"
        if counter.get("confidential", 0) > 0:
            return "confidential"
        if counter.get("internal", 0) > 0:
            return "internal"
        return "public"

    # ------------------------------------------------------------------ #
    # 璧勪骇娓呭崟
    # ------------------------------------------------------------------ #
    def _build_asset(self, source: str, owner: str,
                     hits: List[Dict[str, Any]], level: str) -> Dict[str, Any]:
        return {
            "asset_id": uuid.uuid4().hex[:10],
            "location": source, "owner": owner,
            "level": level, "level_name": CLASSIFICATION_LEVELS[level]["name"],
            "sensitive_types": [h["type_name"] for h in hits],
            "count": sum(h["count"] for h in hits),
            "encryption_status": "鏈煡",
            "access_control": "鏈煡",
            "discovered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def list_assets(self) -> List[Dict[str, Any]]:
        return self.assets

    # ------------------------------------------------------------------ #
    # 绫诲瀷搴撴煡璇?
    # ------------------------------------------------------------------ #
    def list_types(self, category: Optional[str] = None,
                   industry: Optional[str] = None) -> Dict[str, Any]:
        items = []
        for t in self.types.values():
            if category and t["category"] != category:
                continue
            if industry and t["industry"] != industry:
                continue
            items.append({
                "id": t["id"], "name": t["name"], "category": t["category"],
                "industry": t["industry"], "risk": t["risk"],
                "description": t["description"],
            })
        cats: Dict[str, int] = {}
        for t in self.types.values():
            cats[t["category"]] = cats.get(t["category"], 0) + 1
        return {
            "total_types": len(self.types),
            "filtered": len(items),
            "category_breakdown": cats,
            "items": items,
        }

    # ------------------------------------------------------------------ #
    # 鎶ュ憡
    # ------------------------------------------------------------------ #
    def get_report_markdown(self, result: Dict[str, Any]) -> str:
        lines = [
            "# 鏁版嵁鍒嗙被鍒嗙骇鎶ュ憡", "",
            f"- 鎵弿 ID: {result.get('scan_id')}",
            f"- 鎵弿鏃堕棿: {result.get('generated_at')}",
            f"- 鎵弿璧勪骇鏁? {result.get('assets_scanned')}",
            f"- 鏁翠綋鍒嗙骇: {result.get('overall_level_name')}",
            f"- 鏁忔劅鍛戒腑鎬绘暟: {result.get('total_sensitive_hits')}", "",
            "## 鍒嗙骇鍒嗗竷",
        ]
        for k, v in (result.get("level_distribution") or {}).items():
            lines.append(f"- {CLASSIFICATION_LEVELS.get(k, {}).get('name', k)}: {v}")
        lines += ["", "## 璧勪骇娓呭崟"]
        for a in result.get("assets", [])[:50]:
            lines.append(f"- [{a['level_name']}] {a['source']} (鎵€鏈夎€?{a['owner']}) "
                         f"鍛戒腑 {a['total_hits']} 澶?/ {a['distinct_types']} 绫?)
        lines += ["", "## 绫诲埆鍒嗗竷"]
        for k, v in (result.get("category_distribution") or {}).items():
            lines.append(f"- {k}: {v}")
        lines += ["", "## 鍔犲浐寤鸿",
                  "- 瀵规満瀵?缁濆瘑璧勪骇鍚敤闈欐€佸姞瀵嗕笌涓ユ牸璁块棶鎺у埗",
                  "- 瀹氭湡澶嶆壂锛屽彉鏇存晱鎰熸暟鎹椂閲嶆柊鍒嗙骇",
                  "- 寤虹珛鏁版嵁鎵€鏈夎€呰矗浠讳笌鑴辨晱鍑哄彛瑙勫垯"]
        return "\n".join(lines)
