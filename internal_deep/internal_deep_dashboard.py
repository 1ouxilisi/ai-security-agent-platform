# -*- coding: utf-8 -*-
"""internal_deep_dashboard.py — 内网渗透深度控制台聚合。"""
from __future__ import annotations

from typing import Any, Dict

from .smb_enum import get_smb_enumerator
from .ad_query import get_ad_querier
from .cred_extract import get_cred_extractor
from .lateral_movement import get_lateral_mover
from .privesc_detector import get_privesc_detector
from .attack_chain import get_attack_chain, STAGES


class InternalDeepDashboard:
    """控制台聚合服务。"""

    def __init__(self) -> None:
        self.smb = get_smb_enumerator()
        self.ad = get_ad_querier()
        self.cred = get_cred_extractor()
        self.move = get_lateral_mover()
        self.priv = get_privesc_detector()
        self.chain = get_attack_chain()

    def overview(self) -> Dict[str, Any]:
        return {
            "tools_status": {
                "smb": self.smb.tools_status(),
                "ad": self.ad.tools_status(),
                "cred": self.cred.tools_status(),
                "lateral": self.move.tools_status(),
            },
            "stages": STAGES,
            "latest_chain": self.chain.latest(),
            "history_count": len(self.chain.history()),
        }

    def chain_history(self) -> list:
        return self.chain.history()


_singleton: InternalDeepDashboard | None = None


def get_dashboard() -> InternalDeepDashboard:
    global _singleton
    if _singleton is None:
        _singleton = InternalDeepDashboard()
    return _singleton
