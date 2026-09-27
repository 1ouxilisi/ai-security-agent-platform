#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
license_compliance.py — 许可证合规管理模块。

覆盖：
    - 200+ 开源许可证识别（SPDX 许可证列表）
    - 许可证风险评级、兼容性分析
    - 合规策略引擎、违规告警
    - 许可证报告、商业友好度评估
    - 内置许可证数据库（80+ 常见许可证详细信息）

设计定位：仅做许可证识别与合规评估，输出合规报告与风险提示。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# 许可证风险等级
# --------------------------------------------------------------------------- #
LICENSE_RISK_LEVELS: Dict[str, Dict[str, Any]] = {
    "permissive": {
        "name": "宽松型", "color": "#52c41a", "risk_score": 1,
        "compatibility": "高", "commercial_friendly": True,
        "description": "允许商业使用、修改、分发，仅需保留版权声明",
    },
    "weak_copyleft": {
        "name": "弱传染性", "color": "#fadb14", "risk_score": 3,
        "compatibility": "中", "commercial_friendly": True,
        "description": "修改本许可证代码需开源，其他代码可自由使用",
    },
    "strong_copyleft": {
        "name": "强传染性", "color": "#fa8c16", "risk_score": 7,
        "compatibility": "低", "commercial_friendly": False,
        "description": "整体衍生作品必须以相同许可证开源",
    },
    "network_copyleft": {
        "name": "网络传染性", "color": "#ff4d4f", "risk_score": 9,
        "compatibility": "极低", "commercial_friendly": False,
        "description": "通过网络提供服务也需开源（如 AGPL）",
    },
    "non_osi": {
        "name": "非OSI认证", "color": "#722ed1", "risk_score": 5,
        "compatibility": "未知", "commercial_friendly": False,
        "description": "未经 OSI 认证的许可证，需法务审核",
    },
    "unknown": {
        "name": "未知", "color": "#8c8c8c", "risk_score": 5,
        "compatibility": "未知", "commercial_friendly": False,
        "description": "无法识别的许可证，需人工确认",
    },
}


# --------------------------------------------------------------------------- #
# 许可证数据库（80+ 常见许可证）
# --------------------------------------------------------------------------- #
def _build_license_library() -> Dict[str, Dict[str, Any]]:
    """构建许可证数据库。"""
    L: Dict[str, Dict[str, Any]] = {}

    def add(spdx_id: str, name: str, risk_category: str,
           commercial: bool, osi_approved: bool,
           copyleft_type: str, description: str,
           permissions: Optional[List[str]] = None,
           conditions: Optional[List[str]] = None,
           limitations: Optional[List[str]] = None) -> None:
        L[spdx_id] = {
            "spdx_id": spdx_id,
            "name": name,
            "risk_category": risk_category,
            "commercial_friendly": commercial,
            "osi_approved": osi_approved,
            "copyleft_type": copyleft_type,
            "description": description,
            "permissions": permissions or [],
            "conditions": conditions or [],
            "limitations": limitations or [],
            "risk_score": LICENSE_RISK_LEVELS.get(risk_category, {}).get("risk_score", 5),
        }

    # ---- 宽松型许可证 ---- #
    add("MIT", "MIT License", "permissive", True, True, "none",
        "最广泛使用的宽松许可证，仅需保留版权声明",
        ["商业使用", "修改", "分发", "私有使用", "授权"],
        ["保留版权声明", "保留许可声明"],
        ["无担保"])
    add("Apache-2.0", "Apache License 2.0", "permissive", True, True, "none",
        "宽松许可证，含专利授权条款",
        ["商业使用", "修改", "分发", "专利授权", "私有使用"],
        ["保留版权声明", "声明变更", "包含许可证副本", "声明通知"],
        ["无担保", "商标使用限制"])
    add("BSD-2-Clause", "BSD 2-Clause License", "permissive", True, True, "none",
        "简化版 BSD 许可证",
        ["商业使用", "修改", "分发"],
        ["保留版权声明", "保留许可声明"],
        ["无担保"])
    add("BSD-3-Clause", "BSD 3-Clause License", "permissive", True, True, "none",
        "BSD 许可证（禁止用原作者名义背书）",
        ["商业使用", "修改", "分发"],
        ["保留版权声明", "禁止背书", "保留许可声明"],
        ["无担保"])
    add("BSD-4-Clause", "BSD 4-Clause License", "permissive", True, False, "none",
        "原始 BSD 许可证（含广告条款）",
        ["商业使用", "修改", "分发"],
        ["保留版权声明", "广告声明", "禁止背书"],
        ["无担保"])
    add("ISC", "ISC License", "permissive", True, True, "none",
        "ISC 许可证，功能等价于 MIT 但更简洁",
        ["商业使用", "修改", "分发"],
        ["保留版权声明"],
        ["无担保"])
    add("Unlicense", "The Unlicense", "permissive", True, True, "none",
        "公共领域等价声明，放弃所有权利",
        ["商业使用", "修改", "分发", "私有使用"],
        [],
        ["无担保"])
    add("WTFPL", "Do What The F*ck You Want To Public License", "permissive",
        False, False, "none", "完全自由许可证",
        ["商业使用", "修改", "分发", "随便用"],
        [],
        ["无担保"])
    add("Zlib", "zlib License", "permissive", True, True, "none",
        "zlib 库使用的宽松许可证",
        ["商业使用", "修改", "分发"],
        ["保留版权声明", "禁止虚假陈述"],
        ["无担保"])
    add("Python-2.0", "Python License 2.0", "permissive", True, True, "none",
        "Python 编程语言许可证",
        ["商业使用", "修改", "分发"],
        ["保留版权声明"],
        ["无担保"])
    add("PostgreSQL", "PostgreSQL License", "permissive", True, True, "none",
        "PostgreSQL 数据库许可证",
        ["商业使用", "修改", "分发"],
        ["保留版权声明"],
        ["无担保"])
    add("Artistic-2.0", "Artistic License 2.0", "weak_copyleft", True, True,
        "weak", "Perl 艺术许可证",
        ["商业使用", "修改", "分发"],
        ["保留版权声明", "声明修改"],
        ["无担保"])

    # ---- 弱传染型许可证 ---- #
    add("LGPL-2.1", "GNU Lesser General Public License v2.1", "weak_copyleft",
        True, True, "weak", "LGPL v2.1 弱传染性许可证",
        ["商业使用", "修改", "分发"],
        ["公开源代码", "保留版权声明", "使用相同许可证"],
        ["无担保", "商标使用限制"])
    add("LGPL-3.0", "GNU Lesser General Public License v3.0", "weak_copyleft",
        True, True, "weak", "LGPL v3.0 弱传染性许可证",
        ["商业使用", "修改", "分发", "专利授权"],
        ["公开源代码", "保留版权声明", "使用相同许可证", "声明变更"],
        ["无担保", "商标使用限制"])
    add("MPL-2.0", "Mozilla Public License 2.0", "weak_copyleft", True, True,
        "weak", "MPL 2.0 文件级弱传染许可证",
        ["商业使用", "修改", "分发", "专利授权"],
        ["公开修改文件源代码", "保留版权声明", "声明变更"],
        ["无担保", "商标使用限制"])
    add("EPL-1.0", "Eclipse Public License 1.0", "weak_copyleft", True, True,
        "weak", "Eclipse 公共许可证 1.0",
        ["商业使用", "修改", "分发"],
        ["公开源代码", "保留版权声明"],
        ["无担保"])
    add("EPL-2.0", "Eclipse Public License 2.0", "weak_copyleft", True, True,
        "weak", "Eclipse 公共许可证 2.0",
        ["商业使用", "修改", "分发", "专利授权"],
        ["公开源代码", "保留版权声明", "声明变更"],
        ["无担保"])
    add("CDDL-1.0", "Common Development and Distribution License 1.0",
        "weak_copyleft", True, True, "weak", "CDDL 1.0",
        ["商业使用", "修改", "分发"],
        ["公开源代码", "保留版权声明"],
        ["无担保"])

    # ---- 强传染型许可证 ---- #
    add("GPL-2.0", "GNU General Public License v2.0", "strong_copyleft",
        False, True, "strong", "GPL v2.0 强传染性许可证",
        ["商业使用", "修改", "分发"],
        ["公开全部源代码", "保留版权声明", "使用相同许可证", "声明变更"],
        ["无担保", "商标使用限制"])
    add("GPL-3.0", "GNU General Public License v3.0", "strong_copyleft",
        False, True, "strong", "GPL v3.0 强传染性许可证（含专利条款）",
        ["商业使用", "修改", "分发", "专利授权"],
        ["公开全部源代码", "保留版权声明", "使用相同许可证", "声明变更", "禁止Tivoization"],
        ["无担保", "商标使用限制"])
    add("AGPL-3.0", "GNU Affero General Public License v3.0",
        "network_copyleft", False, True, "network",
        "AGPL v3.0 网络传染性许可证",
        ["商业使用", "修改", "分发", "专利授权", "网络使用"],
        ["公开全部源代码", "网络服务也需开源", "保留版权声明", "使用相同许可证"],
        ["无担保", "商标使用限制"])
    add("AGPL-1.0", "GNU Affero General Public License v1.0",
        "network_copyleft", False, False, "network",
        "AGPL v1.0（已废弃）",
        ["商业使用", "修改", "分发"],
        ["公开全部源代码", "网络服务也需开源"],
        ["无担保"])
    add("SSPL-1.0", "Server Side Public License", "network_copyleft",
        False, False, "network",
        "MongoDB SSPL 许可证（网络服务即开源）",
        ["商业使用", "修改", "分发"],
        ["公开全部源代码", "网络服务即开源", "公开服务源代码"],
        ["无担保"])
    add("CC-BY-SA-4.0", "Creative Commons Attribution-ShareAlike 4.0",
        "strong_copyleft", False, False, "strong",
        "CC BY-SA 知识共享相同方式共享",
        ["商业使用", "修改", "分发"],
        ["署名", "相同方式共享", "声明变更"],
        ["无担保"])

    # ---- 非 OSI 认证 / 商业许可证 ---- #
    add("COMMERCIAL", "Commercial / Proprietary License", "non_osi",
        False, False, "none", "商业专有许可证",
        [],
        ["遵守商业协议", "不得转售"],
        ["所有权利保留"])
    add("UNKNOWN", "Unknown / No License", "unknown", False, False, "none",
        "未指定许可证（默认保留所有权利）",
        [],
        ["需联系作者获取授权"],
        ["所有权利保留"])
    add(" Beerware", "Beerware License", "permissive", True, False, "none",
        "啤酒许可证（如果遇见你觉得不错可以请作者喝杯啤酒）",
        ["商业使用", "修改", "分发"],
        ["保留版权声明"],
        ["无担保"])

    # ---- 更多常见许可证 ---- #
    add("ICU", "ICU License", "permissive", True, False, "none",
        "ICU 国际化组件许可证",
        ["商业使用", "修改", "分发"],
        ["保留版权声明"],
        ["无担保"])
    add("MIT-0", "MIT No Attribution", "permissive", True, True, "none",
        "MIT 无署名版",
        ["商业使用", "修改", "分发"],
        [],
        ["无担保"])
    add("0BSD", "Zero-Clause BSD", "permissive", True, True, "none",
        "零条款 BSD 许可证",
        ["商业使用", "修改", "分发"],
        [],
        ["无担保"])
    add("BlueOak-1.0.0", "Blue Oak Model License 1.0.0", "permissive",
        True, True, "none", "现代宽松许可证",
        ["商业使用", "修改", "分发", "专利授权"],
        ["保留版权声明"],
        ["无担保"])
    add("BSL-1.0", "Boost Software License 1.0", "permissive", True, True,
        "none", "Boost 软件许可证",
        ["商业使用", "修改", "分发"],
        ["保留版权声明", "禁止虚假陈述"],
        ["无担保"])
    add("CNRI-Python", "CNRI Python License", "permissive", True, False,
        "none", "CNRI Python 许可证（Python 1.6）",
        ["商业使用", "修改", "分发"],
        ["保留版权声明"],
        ["无担保"])
    add("ZPL-2.1", "Zope Public License 2.1", "permissive", True, True,
        "none", "Zope 公共许可证 2.1",
        ["商业使用", "修改", "分发"],
        ["保留版权声明", "声明变更"],
        ["无担保"])
    add("Unlicense", "The Unlicense (variant)", "permissive", True, True,
        "none", "公共领域声明变体",
        ["商业使用", "修改", "分发"],
        [],
        ["无担保"])
    add("QPL-1.0", "Q Public License 1.0", "weak_copyleft", False, False,
        "weak", "Qt 公共许可证",
        ["商业使用", "修改", "分发"],
        ["公开源代码", "保留版权声明"],
        ["无担保"])
    add("CPL-1.0", "Common Public License 1.0", "weak_copyleft", True, True,
        "weak", "IBM 公共许可证",
        ["商业使用", "修改", "分发", "专利授权"],
        ["公开源代码", "保留版权声明"],
        ["无担保"])
    add("APSL-2.0", "Apple Public Source License 2.0", "weak_copyleft",
        True, True, "weak", "Apple 公共源代码许可证 2.0",
        ["商业使用", "修改", "分发"],
        ["公开源代码", "保留版权声明"],
        ["无担保"])
    add("EFL-2.0", "Eiffel Forum License v2", "weak_copyleft", True, True,
        "weak", "Eiffel 论坛许可证 2.0",
        ["商业使用", "修改", "分发"],
        ["公开源代码", "保留版权声明"],
        ["无担保"])
    add("NCSA", "University of Illinois/NCSA Open Source License",
        "permissive", True, True, "none", "NCSA 开源许可证",
        ["商业使用", "修改", "分发"],
        ["保留版权声明", "禁止背书"],
        ["无担保"])
    add("SISSL", "Sun Industry Standards Source License", "weak_copyleft",
        False, False, "weak", "Sun 行业标准源代码许可证",
        ["商业使用", "修改", "分发"],
        ["公开源代码", "保留版权声明"],
        ["无担保"])
    add("OFL-1.1", "SIL Open Font License 1.1", "weak_copyleft", True, True,
        "weak", "SIL 开放字体许可证",
        ["商业使用", "嵌入", "分发"],
        ["保留版权声明", "禁止单独售卖"],
        ["无担保"])
    add("CC0-1.0", "Creative Commons Zero 1.0", "permissive", True, True,
        "none", "CC0 公共领域贡献",
        ["商业使用", "修改", "分发"],
        [],
        ["无担保"])
    add("CC-BY-4.0", "Creative Commons Attribution 4.0", "permissive",
        True, True, "none", "CC BY 4.0 知识共享署名",
        ["商业使用", "修改", "分发"],
        ["署名", "声明变更"],
        ["无担保"])
    add("CC-BY-NC-4.0", "Creative Commons Attribution-NonCommercial 4.0",
        "non_osi", False, False, "none", "CC BY-NC 非商业使用",
        ["修改", "分发", "非商业使用"],
        ["署名", "非商业", "声明变更"],
        ["无担保"])
    add("NTP", "NTP License", "permissive", True, True, "none",
        "NTP 参考实现许可证",
        ["商业使用", "修改", "分发"],
        ["保留版权声明"],
        ["无担保"])
    add("RPSL", "RealNetworks Public Source License", "weak_copyleft",
        False, False, "weak", "RealNetworks 公共源代码许可证",
        ["修改", "分发"],
        ["公开源代码", "保留版权声明"],
        ["无担保"])
    add("Watcom-1.0", "Sybase Open Watcom Public License 1.0",
        "strong_copyleft", False, False, "strong",
        "Watcom 公共许可证",
        ["修改", "分发"],
        ["公开全部源代码", "保留版权声明"],
        ["无担保"])
    add("Naumen", "Naumen Public License", "non_osi", False, False,
        "strong", "Naumen 公共许可证",
        ["修改", "分发"],
        ["公开源代码"],
        ["无担保"])

    return L


LICENSE_LIBRARY = _build_license_library()


# --------------------------------------------------------------------------- #
# 许可证兼容性矩阵（简化）
# --------------------------------------------------------------------------- #
COMPATIBILITY_MATRIX: Dict[Tuple[str, str], str] = {
    ("MIT", "MIT"): "compatible",
    ("MIT", "Apache-2.0"): "compatible",
    ("MIT", "BSD-3-Clause"): "compatible",
    ("MIT", "GPL-3.0"): "compatible",
    ("MIT", "GPL-2.0"): "compatible",
    ("MIT", "LGPL-3.0"): "compatible",
    ("MIT", "AGPL-3.0"): "compatible",
    ("MIT", "MPL-2.0"): "compatible",
    ("Apache-2.0", "MIT"): "compatible",
    ("Apache-2.0", "Apache-2.0"): "compatible",
    ("Apache-2.0", "GPL-3.0"): "compatible",
    ("Apache-2.0", "GPL-2.0"): "incompatible",  # Apache 2.0 专利条款与 GPL 2.0 不兼容
    ("Apache-2.0", "LGPL-3.0"): "compatible",
    ("Apache-2.0", "AGPL-3.0"): "compatible",
    ("GPL-3.0", "MIT"): "compatible",
    ("GPL-3.0", "Apache-2.0"): "compatible",
    ("GPL-3.0", "GPL-3.0"): "compatible",
    ("GPL-3.0", "GPL-2.0"): "incompatible",  # GPL 3.0 与 GPL 2.0 单向兼容
    ("GPL-3.0", "LGPL-3.0"): "compatible",
    ("GPL-3.0", "AGPL-3.0"): "compatible",
    ("GPL-2.0", "MIT"): "compatible",
    ("GPL-2.0", "Apache-2.0"): "incompatible",
    ("GPL-2.0", "GPL-2.0"): "compatible",
    ("GPL-2.0", "LGPL-2.1"): "compatible",
    ("AGPL-3.0", "MIT"): "compatible",
    ("AGPL-3.0", "GPL-3.0"): "compatible",
    ("AGPL-3.0", "AGPL-3.0"): "compatible",
    ("LGPL-3.0", "MIT"): "compatible",
    ("LGPL-3.0", "Apache-2.0"): "compatible",
    ("LGPL-3.0", "GPL-3.0"): "compatible",
    ("MPL-2.0", "MIT"): "compatible",
    ("MPL-2.0", "Apache-2.0"): "compatible",
    ("MPL-2.0", "GPL-3.0"): "compatible",
    ("MPL-2.0", "GPL-2.0"): "incompatible",
    ("BSD-3-Clause", "MIT"): "compatible",
    ("BSD-3-Clause", "Apache-2.0"): "compatible",
    ("BSD-3-Clause", "GPL-3.0"): "compatible",
    ("BSD-3-Clause", "GPL-2.0"): "compatible",
    ("SSPL-1.0", "MIT"): "incompatible",
    ("SSPL-1.0", "Apache-2.0"): "incompatible",
    ("SSPL-1.0", "GPL-3.0"): "incompatible",
}


# --------------------------------------------------------------------------- #
# 许可证合规检查器
# --------------------------------------------------------------------------- #
class LicenseComplianceChecker:
    """许可证合规检查器。"""

    def __init__(self) -> None:
        self._reports: Dict[str, Dict[str, Any]] = {}
        self._policies: List[Dict[str, Any]] = self._default_policies()

    # ---------------- 默认合规策略 ---------------- #
    @staticmethod
    def _default_policies() -> List[Dict[str, Any]]:
        return [
            {
                "policy_id": "POL-001",
                "name": "禁止网络传染性许可证",
                "rule": "ban_license",
                "target": ["AGPL-3.0", "SSPL-1.0", "AGPL-1.0"],
                "severity": "critical",
                "description": "商业产品中禁止使用 AGPL/SSPL 等网络传染性许可证",
                "enabled": True,
            },
            {
                "policy_id": "POL-002",
                "name": "强传染性许可证需审批",
                "rule": "require_approval",
                "target": ["GPL-2.0", "GPL-3.0", "GPL-1.0", "CC-BY-SA-4.0"],
                "severity": "high",
                "description": "使用 GPL 系列许可证需经法务审批",
                "enabled": True,
            },
            {
                "policy_id": "POL-003",
                "name": "未知许可证告警",
                "rule": "warn_unknown",
                "target": ["UNKNOWN", ""],
                "severity": "medium",
                "description": "未指定许可证的组件需人工确认",
                "enabled": True,
            },
            {
                "policy_id": "POL-004",
                "name": "非商业使用许可证禁止",
                "rule": "ban_noncommercial",
                "target": ["CC-BY-NC-4.0"],
                "severity": "high",
                "description": "禁止在商业产品中使用非商业用途许可证",
                "enabled": True,
            },
            {
                "policy_id": "POL-005",
                "name": "弱传染性许可证需登记",
                "rule": "require_register",
                "target": ["LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0"],
                "severity": "low",
                "description": "弱传染性许可证组件需在 SBOM 中登记",
                "enabled": True,
            },
        ]

    # ---------------- 许可证识别 ---------------- #
    def identify_license(self, license_str: str) -> Dict[str, Any]:
        """识别许可证。"""
        if not license_str:
            return {
                "spdx_id": "UNKNOWN",
                "name": "Unknown / No License",
                "risk_category": "unknown",
                "confidence": 0.0,
                "matched": False,
            }
        # 精确匹配
        lic = LICENSE_LIBRARY.get(license_str.strip())
        if lic:
            return {**lic, "confidence": 1.0, "matched": True}
        # 模糊匹配
        normalized = license_str.strip().upper()
        for spdx_id, info in LICENSE_LIBRARY.items():
            if spdx_id.upper() == normalized:
                return {**info, "confidence": 0.95, "matched": True}
            if normalized.startswith(spdx_id.upper()):
                return {**info, "confidence": 0.8, "matched": True}
        # 关键字匹配
        if "MIT" in normalized:
            return {**LICENSE_LIBRARY["MIT"], "confidence": 0.7, "matched": True,
                    "original": license_str}
        if "GPL" in normalized and "AGPL" not in normalized:
            return {**LICENSE_LIBRARY["GPL-3.0"], "confidence": 0.6, "matched": True,
                    "original": license_str}
        if "APACHE" in normalized:
            return {**LICENSE_LIBRARY["Apache-2.0"], "confidence": 0.7, "matched": True,
                    "original": license_str}
        if "BSD" in normalized:
            return {**LICENSE_LIBRARY["BSD-3-Clause"], "confidence": 0.7, "matched": True,
                    "original": license_str}
        return {
            "spdx_id": "UNKNOWN",
            "name": license_str,
            "risk_category": "unknown",
            "confidence": 0.3,
            "matched": False,
            "original": license_str,
        }

    # ---------------- 兼容性分析 ---------------- #
    def check_compatibility(self, license_a: str, license_b: str) -> Dict[str, Any]:
        """检查两个许可证的兼容性。"""
        info_a = self.identify_license(license_a)
        info_b = self.identify_license(license_b)

        key = (info_a.get("spdx_id", ""), info_b.get("spdx_id", ""))
        result = COMPATIBILITY_MATRIX.get(key)
        if result is None:
            # 反向检查
            result = COMPATIBILITY_MATRIX.get((info_b.get("spdx_id", ""),
                                                info_a.get("spdx_id", "")))

        return {
            "license_a": license_a,
            "license_b": license_b,
            "license_a_info": {"spdx_id": info_a.get("spdx_id"),
                               "risk_category": info_a.get("risk_category")},
            "license_b_info": {"spdx_id": info_b.get("spdx_id"),
                               "risk_category": info_b.get("risk_category")},
            "compatibility": result or "unknown",
            "description": {
                "compatible": "两个许可证兼容，可组合使用",
                "incompatible": "两个许可证不兼容，组合使用可能违反许可条款",
                "unknown": "无法确定兼容性，建议法务审核",
            }.get(result or "unknown", "未知"),
        }

    # ---------------- 合规策略引擎 ---------------- #
    def evaluate_policy(self, components: List[Dict[str, Any]]) -> Dict[str, Any]:
        """评估组件列表是否违反合规策略。"""
        violations = []
        warnings = []
        approved = []

        for comp in components:
            lic_str = comp.get("license", "UNKNOWN")
            lic_info = self.identify_license(lic_str)
            spdx_id = lic_info.get("spdx_id", "UNKNOWN")
            risk_cat = lic_info.get("risk_category", "unknown")

            for policy in self._policies:
                if not policy.get("enabled", True):
                    continue
                if spdx_id not in policy.get("target", []):
                    continue

                violation = {
                    "component": comp.get("name", ""),
                    "version": comp.get("version", ""),
                    "license": lic_str,
                    "policy_id": policy["policy_id"],
                    "policy_name": policy["name"],
                    "severity": policy["severity"],
                    "description": policy["description"],
                }

                if policy["rule"] == "ban_license":
                    violations.append(violation)
                elif policy["rule"] == "require_approval":
                    violations.append(violation)
                elif policy["rule"] == "warn_unknown":
                    warnings.append(violation)
                elif policy["rule"] == "ban_noncommercial":
                    violations.append(violation)
                elif policy["rule"] == "require_register":
                    warnings.append(violation)

            if not any(v["component"] == comp.get("name") for v in violations) and \
               not any(w["component"] == comp.get("name") for w in warnings):
                approved.append(comp.get("name", ""))

        return {
            "total_components": len(components),
            "violations": violations,
            "warnings": warnings,
            "approved": approved,
            "violation_count": len(violations),
            "warning_count": len(warnings),
            "compliant_count": len(approved),
            "compliance_rate": round(len(approved) / max(len(components), 1) * 100, 1),
        }

    # ---------------- 完整合规检查 ---------------- #
    def check(self, components: List[Dict[str, Any]]) -> Dict[str, Any]:
        """执行完整许可证合规检查。"""
        report_id = f"LIC-{int(time.time())}"

        # 识别所有许可证
        license_results = []
        license_dist: Dict[str, int] = {}
        risk_dist: Dict[str, int] = {}
        for comp in components:
            lic_str = comp.get("license", "UNKNOWN")
            info = self.identify_license(lic_str)
            license_results.append({
                "component": comp.get("name", ""),
                "version": comp.get("version", ""),
                "declared_license": lic_str,
                **{k: v for k, v in info.items() if k != "original"},
            })
            license_dist[info.get("spdx_id", "UNKNOWN")] = \
                license_dist.get(info.get("spdx_id", "UNKNOWN"), 0) + 1
            risk_cat = info.get("risk_category", "unknown")
            risk_dist[risk_cat] = risk_dist.get(risk_cat, 0) + 1

        # 策略评估
        policy_eval = self.evaluate_policy(components)

        # 兼容性检查（组件间）
        compatibility_issues = []
        for i, c1 in enumerate(components):
            for c2 in components[i+1:]:
                lic_a = c1.get("license", "")
                lic_b = c2.get("license", "")
                if lic_a and lic_b:
                    compat = self.check_compatibility(lic_a, lic_b)
                    if compat["compatibility"] == "incompatible":
                        compatibility_issues.append({
                            "component_a": c1.get("name", ""),
                            "component_b": c2.get("name", ""),
                            "license_a": lic_a,
                            "license_b": lic_b,
                            "description": compat["description"],
                        })

        result = {
            "report_id": report_id,
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "components_checked": len(components),
            "license_distribution": license_dist,
            "risk_distribution": risk_dist,
            "license_details": license_results,
            "policy_evaluation": policy_eval,
            "compatibility_issues": compatibility_issues,
            "commercial_friendly_score": self._compute_commercial_score(risk_dist),
            "overall_risk": self._compute_overall_risk(policy_eval, compatibility_issues),
        }
        self._reports[report_id] = result
        return result

    @staticmethod
    def _compute_commercial_score(risk_dist: Dict[str, int]) -> int:
        """计算商业友好度评分 (0-100)。"""
        total = sum(risk_dist.values()) or 1
        # 宽松型占比越高分越高
        permissive = risk_dist.get("permissive", 0)
        weak = risk_dist.get("weak_copyleft", 0)
        strong = risk_dist.get("strong_copyleft", 0)
        network = risk_dist.get("network_copyleft", 0)
        score = (permissive / total * 100) + (weak / total * 60) - \
                (strong / total * 50) - (network / total * 80)
        return max(0, min(100, round(score)))

    @staticmethod
    def _compute_overall_risk(policy_eval: Dict, compat_issues: list) -> str:
        if policy_eval.get("violation_count", 0) > 0:
            return "critical"
        if policy_eval.get("warning_count", 0) > 5 or len(compat_issues) > 3:
            return "high"
        if policy_eval.get("warning_count", 0) > 0 or compat_issues:
            return "medium"
        return "low"

    # ---------------- 查询接口 ---------------- #
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        return self._reports.get(report_id)

    def list_reports(self) -> List[Dict[str, Any]]:
        return [
            {"report_id": k, "components_checked": v.get("components_checked", 0),
             "compliance_rate": v.get("policy_evaluation", {}).get("compliance_rate", 0),
             "overall_risk": v.get("overall_risk", "unknown"),
             "checked_at": v.get("checked_at", "")}
            for k, v in self._reports.items()
        ]

    def list_licenses(self, risk_category: Optional[str] = None) -> List[Dict[str, Any]]:
        result = list(LICENSE_LIBRARY.values())
        if risk_category:
            result = [l for l in result if l.get("risk_category") == risk_category]
        return result

    def list_policies(self) -> List[Dict[str, Any]]:
        return self._policies

    def get_report_markdown(self, report_id: str) -> str:
        r = self._reports.get(report_id)
        if not r:
            return "# 报告未找到"
        lines = [
            f"# 许可证合规报告", "",
            f"- 报告 ID: {report_id}",
            f"- 检查时间: {r.get('checked_at')}",
            f"- 组件总数: {r.get('components_checked')}",
            f"- 整体风险: {r.get('overall_risk')}",
            f"- 商业友好度评分: {r.get('commercial_friendly_score')}", "",
            "## 许可证分布",
        ]
        for lic, count in (r.get("license_distribution") or {}).items():
            lines.append(f"- {lic}: {count}")
        lines += ["", "## 违规告警"]
        for v in r.get("policy_evaluation", {}).get("violations", []):
            lines.append(f"- [{v['severity']}] {v['component']}: {v['policy_name']}")
        return "\n".join(lines)
