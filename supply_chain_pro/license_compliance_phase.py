# -*- coding: utf-8 -*-
"""
license_compliance_phase.py — 方向2 供应链安全 Pro：阶段3 许可证合规。

功能:
    - 开源协议合规检查（GPL/MIT/Apache/BSD/MPL/LGPL 等）
    - 许可证风险评级（传染性 / 商业友好度 / 专利授权）
    - 许可证冲突检测
    - 许可证兼容性矩阵
    - 合规报告生成
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 许可证知识库
# --------------------------------------------------------------------------- #
# 风险等级: high(强传染/ Copyleft) / medium(弱传染) / low(商业友好) /
#           permissive(几乎无风险)
LICENSE_DB: Dict[str, Dict[str, Any]] = {
    "MIT": {"family": "permissive", "risk": "low",
            "commercial_friendly": True, "patent_grant": False,
            "copyleft": False, "note": "商业友好，仅需保留声明"},
    "Apache-2.0": {"family": "permissive", "risk": "low",
                   "commercial_friendly": True, "patent_grant": True,
                   "copyleft": False,
                   "note": "商业友好，含专利授权，需 NOTICE"},
    "BSD-2-Clause": {"family": "permissive", "risk": "low",
                     "commercial_friendly": True, "patent_grant": False,
                     "copyleft": False, "note": "商业友好，2 条要求"},
    "BSD-3-Clause": {"family": "permissive", "risk": "low",
                     "commercial_friendly": True, "patent_grant": False,
                     "copyleft": False, "note": "商业友好，含无背书条款"},
    "ISC": {"family": "permissive", "risk": "low",
            "commercial_friendly": True, "patent_grant": False,
            "copyleft": False, "note": "极简，商业友好"},
    "MPL-2.0": {"family": "weak-copyleft", "risk": "medium",
                "commercial_friendly": True, "patent_grant": True,
                "copyleft": True,
                "note": "文件级传染，修改文件需开源"},
    "LGPL-2.1": {"family": "weak-copyleft", "risk": "medium",
                 "commercial_friendly": True, "patent_grant": False,
                 "copyleft": True,
                 "note": "动态链接可用，静态链接需开放库修改"},
    "LGPL-3.0": {"family": "weak-copyleft", "risk": "medium",
                 "commercial_friendly": True, "patent_grant": True,
                 "copyleft": True, "note": "LGPL + 专利授权"},
    "GPL-2.0": {"family": "strong-copyleft", "risk": "high",
                "commercial_friendly": False, "patent_grant": False,
                "copyleft": True,
                "note": "强传染，整个衍生作品需 GPL 开源"},
    "GPL-3.0": {"family": "strong-copyleft", "risk": "high",
                "commercial_friendly": False, "patent_grant": True,
                "copyleft": True,
                "note": "强传染 + 专利报复，禁止 Tivoization"},
    "AGPL-3.0": {"family": "network-copyleft", "risk": "critical",
                 "commercial_friendly": False, "patent_grant": True,
                 "copyleft": True,
                 "note": "网络使用即触发开源，SaaS 高风险"},
    "EPL-1.0": {"family": "weak-copyleft", "risk": "medium",
                "commercial_friendly": True, "patent_grant": True,
                "copyleft": True, "note": "Eclipse 公共许可"},
    "EUPL-1.2": {"family": "weak-copyleft", "risk": "medium",
                 "commercial_friendly": True, "patent_grant": False,
                 "copyleft": True, "note": "欧盟公共许可"},
    "Unlicense": {"family": "public-domain", "risk": "low",
                  "commercial_friendly": True, "patent_grant": False,
                  "copyleft": False, "note": "公有域声明"},
    "Unknown": {"family": "unknown", "risk": "high",
                "commercial_friendly": False, "patent_grant": False,
                "copyleft": True, "note": "未声明许可证，法律风险高"},
}

# 兼容性矩阵: A 项目许可证 + B 依赖许可证是否兼容
# True = 兼容; False = 冲突; None = 需人工评估
COMPAT_MATRIX: Dict[str, Dict[str, Optional[bool]]] = {
    "MIT": {"MIT": True, "Apache-2.0": True, "BSD-2-Clause": True,
            "BSD-3-Clause": True, "ISC": True, "MPL-2.0": True,
            "LGPL-2.1": True, "LGPL-3.0": True,
            "GPL-2.0": True, "GPL-3.0": True, "AGPL-3.0": False},
    "Apache-2.0": {"MIT": True, "Apache-2.0": True, "BSD-2-Clause": True,
                   "BSD-3-Clause": True, "MPL-2.0": True,
                   "LGPL-3.0": True, "GPL-3.0": True,
                   "GPL-2.0": None, "AGPL-3.0": True},
    "GPL-3.0": {"MIT": True, "Apache-2.0": True, "BSD-2-Clause": True,
                "BSD-3-Clause": True, "MPL-2.0": True,
                "LGPL-3.0": True, "GPL-3.0": True,
                "GPL-2.0": None, "AGPL-3.0": True},
    "GPL-2.0": {"MIT": True, "Apache-2.0": None, "BSD-2-Clause": True,
                "BSD-3-Clause": True, "MPL-2.0": None,
                "LGPL-2.1": True, "GPL-2.0": True,
                "GPL-3.0": None, "AGPL-3.0": False},
    "LGPL-3.0": {"MIT": True, "Apache-2.0": True, "BSD-2-Clause": True,
                 "MPL-2.0": True, "LGPL-3.0": True,
                 "GPL-3.0": True, "AGPL-3.0": False},
    "MPL-2.0": {"MIT": True, "Apache-2.0": True, "BSD-2-Clause": True,
                "MPL-2.0": True, "LGPL-2.1": True,
                "GPL-2.0": None, "GPL-3.0": True, "AGPL-3.0": False},
    "AGPL-3.0": {"MIT": True, "Apache-2.0": True, "BSD-2-Clause": True,
                 "AGPL-3.0": True, "GPL-3.0": True,
                 "LGPL-3.0": False, "MPL-2.0": False},
}


def _normalize(lic: str) -> str:
    if not lic:
        return "Unknown"
    s = lic.strip()
    alias = {
        "MIT License": "MIT", "The MIT License": "MIT",
        "Apache License 2.0": "Apache-2.0",
        "Apache 2.0": "Apache-2.0", "Apache-2.0": "Apache-2.0",
        "BSD": "BSD-3-Clause", "BSD License": "BSD-3-Clause",
        "BSD 3-Clause": "BSD-3-Clause", "BSD-3": "BSD-3-Clause",
        "BSD 2-Clause": "BSD-2-Clause", "BSD-2": "BSD-2-Clause",
        "GPL": "GPL-3.0", "GPLv3": "GPL-3.0", "GPL-3": "GPL-3.0",
        "GPLv2": "GPL-2.0", "GPL-2": "GPL-2.0",
        "LGPL": "LGPL-3.0", "LGPLv3": "LGPL-3.0",
        "LGPLv2.1": "LGPL-2.1",
        "MPL": "MPL-2.0", "MPL 2.0": "MPL-2.0",
        "AGPL": "AGPL-3.0", "AGPLv3": "AGPL-3.0",
        "ISC License": "ISC", "Unlicense": "Unlicense",
    }
    return alias.get(s, s)


@dataclass
class LicenseIssue:
    component: str = ""
    version: str = ""
    license: str = ""
    risk: str = "low"
    family: str = "permissive"
    message: str = ""
    suggestion: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component, "version": self.version,
            "license": self.license, "risk": self.risk,
            "family": self.family, "message": self.message,
            "suggestion": self.suggestion,
        }


@dataclass
class LicenseReport:
    project_license: str = "Unknown"
    by_license: Dict[str, int] = field(default_factory=dict)
    by_risk: Dict[str, int] = field(default_factory=dict)
    issues: List[LicenseIssue] = field(default_factory=list)
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    unknown_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_license": self.project_license,
            "by_license": self.by_license,
            "by_risk": self.by_risk,
            "issues": [i.to_dict() for i in self.issues],
            "conflicts": self.conflicts,
            "unknown_count": self.unknown_count,
            "issue_count": len(self.issues),
        }


class LicenseCompliancePhase:
    """阶段3：许可证合规。"""

    def __init__(self, project_license: str = "Proprietary"
                 ) -> None:
        self.project_license = project_license

    # ------------------------------------------------------------------ #
    def check(self, components: List[Dict[str, Any]],
              project_license: Optional[str] = None
              ) -> LicenseReport:
        proj = _normalize(project_license or self.project_license)
        report = LicenseReport(project_license=proj)
        seen_licenses: Dict[str, str] = {}

        for c in components:
            name = c.get("name", "unknown")
            ver = c.get("version", "")
            lic_raw = c.get("license", "") or "Unknown"
            lic = _normalize(lic_raw)
            info = LICENSE_DB.get(lic, LICENSE_DB["Unknown"])

            report.by_license[lic] = report.by_license.get(lic, 0) + 1
            report.by_risk[info["risk"]] = \
                report.by_risk.get(info["risk"], 0) + 1
            if lic == "Unknown":
                report.unknown_count += 1

            seen_licenses[name] = lic

            issue = LicenseIssue(
                component=name, version=ver, license=lic,
                risk=info["risk"], family=info["family"],
                message=info["note"],
                suggestion=self._suggest(lic, proj, info))
            if info["risk"] in ("high", "critical") or lic == "Unknown":
                report.issues.append(issue)

        # 冲突检测：项目许可证 vs 每个依赖
        proj_key = "Proprietary" if proj.startswith("Proprietary") else proj
        for name, lic in seen_licenses.items():
            compat = self._compat(proj_key, lic)
            if compat is False:
                report.conflicts.append({
                    "component": name, "license": lic,
                    "project_license": proj,
                    "severity": "blocker",
                    "message": f"{lic} 与 {proj} 不兼容",
                })
            elif compat is None:
                report.conflicts.append({
                    "component": name, "license": lic,
                    "project_license": proj,
                    "severity": "review",
                    "message": f"{lic} 与 {proj} 兼容性需法务评估",
                })
        return report

    # ------------------------------------------------------------------ #
    @staticmethod
    def _compat(project_lic: str, dep_lic: str
                ) -> Optional[bool]:
        if project_lic.startswith("Proprietary"):
            # 商业闭源项目：AGPL / GPL 不兼容；MPL/LGPL 需评估
            if dep_lic == "AGPL-3.0":
                return False
            if dep_lic in ("GPL-2.0", "GPL-3.0"):
                return False
            if dep_lic in ("MPL-2.0", "LGPL-2.1", "LGPL-3.0"):
                return None
            return True
        row = COMPAT_MATRIX.get(project_lic, {})
        return row.get(dep_lic, None)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _suggest(lic: str, project: str, info: Dict[str, Any]
                 ) -> str:
        if lic == "Unknown":
            return "联系上游确认许可证；在确认前避免商用"
        if info["family"] == "network-copyleft":
            return ("AGPL 在 SaaS 场景会触发开源义务，"
                    "建议替换为商业友好等价组件")
        if info["family"] == "strong-copyleft":
            if project.startswith("Proprietary"):
                return f"商业项目避免引入 {lic}，寻找 MIT/Apache 替代"
            return "确保衍生作品以兼容许可证开源"
        if info["family"] == "weak-copyleft":
            return ("保持动态链接；如修改该组件，需公开修改部分")
        if info["patent_grant"] is False:
            return "如需专利保护，优先选择 Apache-2.0"
        return "正常使用，保留许可证声明与 NOTICE"

    # ------------------------------------------------------------------ #
    def matrix(self) -> Dict[str, Any]:
        return {
            "licenses": LICENSE_DB,
            "compatibility": COMPAT_MATRIX,
            "legend": {
                "permissive": "宽松（MIT/Apache/BSD）",
                "weak-copyleft": "弱传染（MPL/LGPL）",
                "strong-copyleft": "强传染（GPL）",
                "network-copyleft": "网络传染（AGPL）",
            },
        }


_default_lc: Optional[LicenseCompliancePhase] = None


def get_license_phase() -> LicenseCompliancePhase:
    global _default_lc
    if _default_lc is None:
        _default_lc = LicenseCompliancePhase()
    return _default_lc
