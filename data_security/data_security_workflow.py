#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
data_security_workflow.py 鈥?鏁版嵁瀹夊叏缁煎悎璇勪及宸ヤ綔娴併€?

姝ラ锛?
    鏁版嵁璧勪骇鍙戠幇 鈫?鏁版嵁鍒嗙被鍒嗙骇 鈫?鍔犲瘑鐘舵€佹娴?鈫?璁块棶鎺у埗璇勪及 鈫?
    DLP 椋庨櫓璇勪及 鈫?闅愮鍚堣妫€鏌?鈫?缁撴灉鑱氬悎 鈫?椋庨櫓璇勭骇 鈫?鎶ュ憡鐢熸垚

鐗圭偣锛?
    - 鍚勬娴嬫ā鍧楃嫭绔嬫墽琛岋紙妯℃嫙骞惰锛夛紝缁撴灉鑱氬悎锛堝幓閲?鍚堝苟/鍏宠仈/鎸夎祫浜ц仛鍚堬級
    - 鏁翠綋椋庨櫓璇勭骇涓庝慨澶嶄紭鍏堢骇
    - 缁煎悎璇勪及鎶ュ憡锛堣祫浜ф竻鍗?椋庨櫓鍒嗗竷/鍚堣宸窛/闃叉姢寤鸿/缁撹锛?

璁捐瀹氫綅锛氱紪鎺掑悇妫€娴嬫ā鍧楋紝杈撳嚭鑱氬悎鎶ュ憡涓庢暣鏀逛紭鍏堢骇銆?
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from data_security.data_classification import DataClassifier, CLASSIFICATION_LEVELS
from data_security.dlp_engine import DLPEngine
from data_security.privacy_compliance import PrivacyComplianceAssessor
from data_security.encryption_key_management import EncryptionKeyManager
from data_security.access_control import DataAccessController


SECURITY_WORKFLOW_STEPS = [
    {"id": "discover", "name": "鏁版嵁璧勪骇鍙戠幇", "module": "data_classification"},
    {"id": "classify", "name": "鏁版嵁鍒嗙被鍒嗙骇", "module": "data_classification"},
    {"id": "encryption", "name": "鍔犲瘑鐘舵€佹娴?, "module": "encryption_key_management"},
    {"id": "access", "name": "璁块棶鎺у埗璇勪及", "module": "access_control"},
    {"id": "dlp", "name": "DLP 椋庨櫓璇勪及", "module": "dlp_engine"},
    {"id": "privacy", "name": "闅愮鍚堣妫€鏌?, "module": "privacy_compliance"},
    {"id": "aggregate", "name": "缁撴灉鑱氬悎", "module": "workflow"},
    {"id": "rating", "name": "椋庨櫓璇勭骇", "module": "workflow"},
    {"id": "report", "name": "鎶ュ憡鐢熸垚", "module": "workflow"},
]

_PRIORITY_WEIGHT = {
    "critical": (10, "绔嬪嵆淇(24h鍐?"),
    "high": (6, "72灏忔椂鍐呬慨澶?),
    "medium": (3, "涓ゅ懆鍐呬慨澶?),
    "low": (1, "璁″垝淇"),
    "info": (0, "璁板綍鍗冲彲"),
}


class DataSecurityWorkflow:
    """鏁版嵁瀹夊叏缁煎悎璇勪及宸ヤ綔娴併€?""

    def __init__(self) -> None:
        self.classifier = DataClassifier()
        self.dlp = DLPEngine()
        self.privacy = PrivacyComplianceAssessor()
        self.crypto = EncryptionKeyManager()
        self.access = DataAccessController()
        self._history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 涓诲叆鍙?
    # ------------------------------------------------------------------ #
    def run_assessment(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        config = config or {}
        scan_id = config.get("scan_id") or uuid.uuid4().hex[:12]
        started = time.strftime("%Y-%m-%d %H:%M:%S")
        steps: List[Dict[str, Any]] = []

        # 1-2. 璧勪骇鍙戠幇 + 鍒嗙被鍒嗙骇
        assets = config.get("assets") or self._default_assets()
        cls_result = self.classifier.scan_assets(assets)
        steps.append({"step": "classify", "status": "ok",
                      "message": f"鍒嗙骇 {cls_result.get('overall_level_name')} / "
                                 f"{cls_result.get('assets_scanned')} 璧勪骇"})

        # 3. 鍔犲瘑鐘舵€?
        enc_result = self.crypto.assess(config.get("crypto_signals"))
        steps.append({"step": "encryption", "status": "ok",
                      "message": f"鍔犲瘑璇勫垎 {enc_result['overall_score']} ({enc_result['grade']})"})

        # 4. 璁块棶鎺у埗
        acc_result = self.access.assess(config.get("access_signals"))
        steps.append({"step": "access", "status": "ok",
                      "message": f"璁块棶鎺у埗璇勫垎 {acc_result['overall_score']} ({acc_result['grade']})"})

        # 5. DLP
        dlp_result = self._dlp_assess(config)
        steps.append({"step": "dlp", "status": "ok",
                      "message": f"DLP 浜嬩欢 {len(dlp_result.get('events', []))}"})

        # 6. 闅愮鍚堣
        priv_result = self.privacy.assess(config.get("privacy_signals"))
        steps.append({"step": "privacy", "status": "ok",
                      "message": f"鍚堣璇勫垎 {priv_result['overall_score']} ({priv_result['grade']})"})

        # 7. 鑱氬悎
        aggregate = self._aggregate(cls_result, enc_result, acc_result,
                                    dlp_result, priv_result)
        steps.append({"step": "aggregate", "status": "ok",
                      "message": f"鑱氬悎 {aggregate['total_findings']} 涓彂鐜?})

        # 8. 璇勭骇
        rating = self._rate(aggregate, cls_result, enc_result,
                            acc_result, priv_result)
        steps.append({"step": "rating", "status": "ok",
                      "message": f"椋庨櫓绛夌骇 {rating['risk_level']}"})

        # 9. 鎶ュ憡
        report = self._build_report(scan_id, started, steps, cls_result,
                                    enc_result, acc_result, dlp_result,
                                    priv_result, aggregate, rating)
        steps.append({"step": "report", "status": "ok", "message": "鎶ュ憡鐢熸垚瀹屾垚"})

        self._history.append({
            "scan_id": scan_id, "finished_at": started,
            "risk_level": rating["risk_level"],
            "total_findings": aggregate["total_findings"],
            "overall_score": rating["risk_score"],
        })
        return report

    # ------------------------------------------------------------------ #
    # 榛樿璧勪骇锛堟紨绀虹敤锛?
    # ------------------------------------------------------------------ #
    @staticmethod
    def _default_assets() -> List[Dict[str, Any]]:
        return [
            {"path": "db/users/table_customer", "type": "database", "owner": "鏁版嵁骞冲彴",
             "encryption": "TDE", "access": "RBAC",
             "content": "瀹㈡埛鎵嬫満13812345678 韬唤璇?10101199001011234 閭a@b.com"},
            {"path": "share/finance/2026骞存姤.xlsx", "type": "file", "owner": "璐㈠姟",
             "encryption": "鏈姞瀵?, "access": "鍏ㄥ憳鍙",
             "content": "鍚堝悓閲戦 1200涓囧厓 绾崇◣浜鸿瘑鍒彿 91110000XXXX 閾惰鍗?222021234567890123"},
            {"path": "repo/config/prod.yaml", "type": "code", "owner": "杩愮淮",
             "encryption": "git鏈姞瀵?, "access": "鐮斿彂缁?,
             "content": "password: P@ssw0rd1234 api_key=stripe_api_key_here "
                        "-----BEGIN RSA PRIVATE KEY-----"},
            {"path": "hr/employees/roster.csv", "type": "file", "owner": "HR",
             "encryption": "鏈姞瀵?, "access": "HR缁?,
             "content": "寮犱笁 宸ヨ祫25000 鐥呭巻鍙?MR100233 澶勬柟鍙?RX998812"},
            {"path": "web/static/help.html", "type": "web", "owner": "甯傚満",
             "encryption": "N/A", "access": "鍏紑",
             "content": "娆㈣繋浣跨敤鎴戜滑鐨勪骇鍝侊紝甯姪鏂囨。銆?},
        ]

    # ------------------------------------------------------------------ #
    # DLP 瀛愯瘎浼?
    # ------------------------------------------------------------------ #
    def _dlp_assess(self, config: Dict[str, Any]) -> Dict[str, Any]:
        sample = (config.get("dlp_sample")
                  or "瀹㈡埛鎵嬫満13812345678 韬唤璇?10101199001011234 閾惰鍗?222021234567890123")
        det = self.dlp.detect_content(sample)
        events = self.dlp.generate_events(det, channel="email")
        channels = self.dlp.channel_monitor()
        return {
            "content": det, "events": events,
            "channel_monitor": channels,
            "uncovered": channels["uncovered_channels"],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 鑱氬悎
    # ------------------------------------------------------------------ #
    def _aggregate(self, cls_result: Dict[str, Any], enc: Dict[str, Any],
                   acc: Dict[str, Any], dlp: Dict[str, Any],
                   priv: Dict[str, Any]) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        # 鍔犲瘑鍙戠幇
        for w in enc.get("algorithms", {}).get("weak_algorithms", []):
            findings.append({"module": "encryption", "severity": "high",
                             "title": f"寮辩畻娉?{w['algorithm']}", "desc": w["note"]})
            by_severity["high"] += 1
        for c in enc.get("certificates", {}).get("certificates", []):
            if c.get("issues"):
                findings.append({"module": "encryption", "severity": "medium",
                                 "title": f"璇佷功闂 {c['subject']}",
                                 "desc": "; ".join(c["issues"])})
                by_severity["medium"] += 1
        for k in enc.get("rotation", {}).get("keys", []):
            if k.get("overdue"):
                findings.append({"module": "encryption", "severity": "high",
                                 "title": f"瀵嗛挜瓒呮湡 {k['name']}", "desc": k["note"]})
                by_severity["high"] += 1

        # 璁块棶鎺у埗鍙戠幇
        for f in acc.get("least_privilege", {}).get("findings", []):
            sev = f["risk"]
            findings.append({"module": "access", "severity": sev,
                             "title": f"{f['type']}:{f['user']}", "desc": f["detail"]})
            by_severity[sev] = by_severity.get(sev, 0) + 1
        for a in acc.get("anomalies", []):
            findings.append({"module": "access", "severity": a["severity"],
                             "title": f"寮傚父璁块棶 {a['user']}",
                             "desc": ",".join(a["reasons"])})
            by_severity[a["severity"]] += 1
        leaky = acc.get("masking", {}).get("leaky_count", 0)
        by_severity["high"] += leaky

        # DLP 浜嬩欢
        for e in dlp.get("events", []):
            sev = e["severity"]
            findings.append({"module": "dlp", "severity": sev,
                             "title": f"DLP浜嬩欢 {e['type']}", "desc": f"{e['channel']} x{e['count']}"})
            by_severity[sev] = by_severity.get(sev, 0) + 1

        # 鍚堣宸窛
        for g in priv.get("gaps", [])[:20]:
            sev = "high" if g["status"] == "涓嶆弧瓒? else "medium"
            findings.append({"module": "privacy", "severity": sev,
                             "title": f"{g['framework']} {g['ref']} {g['name']}",
                             "desc": g["gap"]})
            by_severity[sev] += 1

        # 鍘婚噸锛堟寜 module+title锛?
        seen = set()
        deduped = []
        for f in findings:
            key = (f["module"], f["title"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)

        return {
            "total_findings": len(deduped),
            "by_severity": by_severity,
            "findings": deduped,
            "modules": ["classification", "encryption", "access", "dlp", "privacy"],
        }

    # ------------------------------------------------------------------ #
    # 椋庨櫓璇勭骇
    # ------------------------------------------------------------------ #
    def _rate(self, aggregate: Dict[str, Any], cls_result: Dict[str, Any],
              enc: Dict[str, Any], acc: Dict[str, Any],
              priv: Dict[str, Any]) -> Dict[str, Any]:
        bs = aggregate["by_severity"]
        score = (100
                 - bs.get("critical", 0) * 12
                 - bs.get("high", 0) * 6
                 - bs.get("medium", 0) * 2
                 + enc["overall_score"] * 0.15
                 + acc["overall_score"] * 0.15
                 + priv["overall_score"] * 0.15)
        score = max(0, min(100, round(score, 1)))
        if score >= 85:
            level = "浣庨闄?
        elif score >= 70:
            level = "涓闄?
        elif score >= 55:
            level = "楂橀闄?
        else:
            level = "涓ラ噸椋庨櫓"

        # 淇浼樺厛绾?
        ranked = sorted(aggregate["findings"],
                        key=lambda f: _PRIORITY_WEIGHT.get(f["severity"], (0, ""))[0],
                        reverse=True)
        top = []
        for f in ranked[:15]:
            w = _PRIORITY_WEIGHT.get(f["severity"], (0, "璁板綍"))
            top.append({"title": f["title"], "module": f["module"],
                        "severity": f["severity"], "action": w[1], "desc": f["desc"]})
        return {
            "risk_score": score, "risk_level": level,
            "top_priorities": top,
            "asset_level": cls_result.get("overall_level"),
        }

    # ------------------------------------------------------------------ #
    # 鎶ュ憡
    # ------------------------------------------------------------------ #
    def _build_report(self, scan_id: str, started: str, steps: List[Dict[str, Any]],
                      cls_result: Dict[str, Any], enc: Dict[str, Any],
                      acc: Dict[str, Any], dlp: Dict[str, Any],
                      priv: Dict[str, Any], aggregate: Dict[str, Any],
                      rating: Dict[str, Any]) -> Dict[str, Any]:
        finished = time.strftime("%Y-%m-%d %H:%M:%S")
        level_name = CLASSIFICATION_LEVELS.get(
            cls_result.get("overall_level", "internal"), {}).get("name", "鍐呴儴")
        return {
            "scan_id": scan_id,
            "started_at": started, "finished_at": finished,
            "workflow_steps": steps,
            "classification": {
                "overall_level": cls_result.get("overall_level"),
                "overall_level_name": level_name,
                "assets_scanned": cls_result.get("assets_scanned"),
                "assets": cls_result.get("assets", []),
                "level_distribution": cls_result.get("level_distribution"),
            },
            "encryption": {"score": enc["overall_score"], "grade": enc["grade"],
                           "weak_algorithms": enc.get("algorithms", {}).get("weak_count")},
            "access": {"score": acc["overall_score"], "grade": acc["grade"],
                       "anomalies": len(acc.get("anomalies", []))},
            "dlp": {"events": len(dlp.get("events", [])),
                    "uncovered": dlp.get("uncovered", [])},
            "privacy": {"score": priv["overall_score"], "grade": priv["grade"],
                        "gaps": priv["gap_count"]},
            "aggregate": aggregate,
            "rating": rating,
            "conclusion": (
                f"鏁版嵁瀹夊叏缁煎悎璇勭骇: {rating['risk_level']}锛坽rating['risk_score']}鍒嗭級銆?
                f"鍏辫瘑鍒?{aggregate['total_findings']} 涓畨鍏ㄥ彂鐜帮紝"
                f"鏈哄瘑/缁濆瘑璧勪骇 {cls_result.get('level_distribution', {}).get('confidential', 0) + cls_result.get('level_distribution', {}).get('top_secret', 0)} 椤广€?
                "寤鸿鎸?top_priorities 椤哄簭瀹屾垚鏁存敼銆?
            ),
            "generated_at": finished,
        }

    def list_history(self) -> List[Dict[str, Any]]:
        return self._history


# 鍗曚緥
_workflow_singleton: Optional[DataSecurityWorkflow] = None


def get_security_workflow() -> DataSecurityWorkflow:
    global _workflow_singleton
    if _workflow_singleton is None:
        _workflow_singleton = DataSecurityWorkflow()
    return _workflow_singleton
