# -*- coding: utf-8 -*-
"""移动安全真实分析控制台聚合：内存字典存储。"""
from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional

from .apk_parser import ApkRealParser
from .dynamic_analysis import DynamicAnalyzer
from .permission_risk import PermissionRiskAnalyzer
from .static_vuln import StaticVulnDetector


class MobileRealDashboard:
    def __init__(self) -> None:
        self.parser = ApkRealParser()
        self.perm = PermissionRiskAnalyzer()
        self.vuln = StaticVulnDetector()
        self.dyn = DynamicAnalyzer()
        self.analyses: Dict[str, Dict[str, Any]] = {}
        self.uploads: Dict[str, str] = {}  # id -> path

    def env(self) -> Dict[str, Any]:
        return {
            "apk_parser": self.parser.available(),
            "dynamic": self.dyn.status(),
        }

    def analyze(self, apk_path: str) -> Dict[str, Any]:
        if not os.path.exists(apk_path):
            return {"success": False, "error": f"APK 不存在: {apk_path}"}
        aid = f"apk_{uuid.uuid4().hex[:10]}"
        parsed = self.parser.parse(apk_path)
        if not parsed.get("success"):
            return parsed
        perm_report = self.perm.analyze(parsed.get("permissions", []))
        vuln_report = self.vuln.scan_apk(apk_path)
        record = {
            "id": aid,
            "ts": time.time(),
            "path": apk_path,
            "manifest": parsed,
            "permission_risk": perm_report,
            "static_vuln": vuln_report,
            "dynamic": self.dyn.status(),
        }
        self.analyses[aid] = record
        return {"success": True, "analysis_id": aid, **record}

    def list(self) -> List[Dict[str, Any]]:
        return [
            {"id": v["id"], "path": v["path"], "ts": v["ts"],
             "package": v["manifest"].get("package"),
             "risk_level": v["permission_risk"].get("risk_level")}
            for v in sorted(self.analyses.values(), key=lambda x: x["ts"], reverse=True)
        ]

    def get(self, aid: str) -> Optional[Dict[str, Any]]:
        return self.analyses.get(aid)


dashboard = MobileRealDashboard()
