#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web3_security/web3_dashboard.py — Web3 安全控制台数据聚合层。

聚合 7 大模块（智能合约/DeFi/NFT/DAO/节点/加密货币）的实时数据，
输出控制台所需总览、风险分布、最近事件、系统设置等。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .smart_contract import get_contract_runtime, assess_contract
from .defi_security import get_defi_registry, PROTOCOL_TYPES
from .nft_security import get_nft_registry, NFT_TYPES
from .dao_security import get_dao_registry, DAO_TYPES
from .node_security import get_node_registry, NODE_TYPES
from .crypto_security import get_crypto_registry, WALLET_TYPES


SYSTEM_SETTINGS: Dict[str, Any] = {
    "platform_name": "AI Hacking Agent — Web3 安全控制台",
    "version": "27.4.0",
    "theme": "dark",
    "chain_default": "ethereum",
    "auto_refresh_seconds": 30,
    "alert_channels": ["web", "email", "telegram"],
    "risk_threshold": "medium",
    "scan_schedule": "0 */6 * * *",
}


def overview() -> Dict[str, Any]:
    """聚合总览：各模块资产数/平均风险/最近事件。"""
    cr = get_contract_runtime()
    dr = get_defi_registry()
    nr = get_nft_registry()
    daor = get_dao_registry()
    ndr = get_node_registry()
    cyr = get_crypto_registry()

    contracts = cr.list_contracts()
    protos = dr.list()
    nfts = nr.list()
    daos = daor.list()
    nodes = ndr.list()
    wallets = cyr.list_wallets()

    avg_contract = round(sum(c["score"] for c in contracts) / max(len(contracts), 1), 1)
    avg_defi = round(sum(p["score"] for p in protos) / max(len(protos), 1), 1)
    avg_nft = round(sum(n["score"] for n in nfts) / max(len(nfts), 1), 1)
    avg_node = round(sum(n["score"] for n in nodes) / max(len(nodes), 1), 1)
    avg_wallet = round(sum(w["score"] for w in wallets) / max(len(wallets), 1), 1)

    critical_count = (
        sum(c["findings"] for c in contracts) +
        sum(len([f for f in p["findings"] if f["severity"] == "critical"])
            for p in protos) +
        sum(n["summary"]["critical"] for n in nfts) +
        sum(1 for n in nodes if n["summary"]["critical"]) +
        sum(1 for w in wallets if w["score"] < 50)
    )

    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "totals": {
            "contracts": len(contracts),
            "defi_protocols": len(protos),
            "nft_collections": len(nfts),
            "daos": len(daos),
            "nodes": len(nodes),
            "wallets": len(wallets),
        },
        "avg_scores": {
            "smart_contract": avg_contract,
            "defi": avg_defi,
            "nft": avg_nft,
            "node": avg_node,
            "wallet": avg_wallet,
        },
        "critical_issues": critical_count,
        "modules": {
            "smart_contract": {"items": contracts},
            "defi": {"items": protos},
            "nft": {"items": nfts},
            "dao": {"items": daos},
            "node": {"items": nodes},
            "crypto": {"items": wallets},
        },
    }


def recent_events(limit: int = 20) -> List[Dict[str, Any]]:
    cr = get_contract_runtime()
    events: List[Dict[str, Any]] = []
    for c in cr.calls[-limit:]:
        events.append({"ts": c["ts"], "kind": "contract_call", **c})
    for p in get_defi_registry().list():
        for f in p["findings"][:3]:
            events.append({"ts": p["assessed_at"], "kind": "defi_finding",
                            "protocol": p["protocol_name"], **f})
    events.sort(key=lambda x: x.get("ts", ""), reverse=True)
    return events[:limit]


def risk_distribution() -> Dict[str, int]:
    cr = get_contract_runtime()
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for c in cr.list_contracts():
        if c["findings"]:
            dist["high"] += c["findings"]
    for p in get_defi_registry().list():
        for f in p["findings"]:
            dist[f["severity"]] = dist.get(f["severity"], 0) + 1
    for n in get_nft_registry().list():
        for sev in ("critical", "high", "medium", "low"):
            dist[sev] += n["summary"].get(sev, 0)
    for nd in get_node_registry().list():
        for sev in ("critical", "high", "medium", "low"):
            dist[sev] += nd["summary"].get(sev, 0)
    return dist


def reference_data() -> Dict[str, Any]:
    return {
        "contract_languages": ["solidity", "vyper", "rust", "move",
                                "cairo", "clarity"],
        "defi_protocols": PROTOCOL_TYPES,
        "nft_types": NFT_TYPES,
        "dao_types": DAO_TYPES,
        "node_types": NODE_TYPES,
        "wallet_types": WALLET_TYPES,
    }


_dashboard_singleton: Optional[Dict[str, Any]] = None


def get_dashboard() -> Dict[str, Any]:
    global _dashboard_singleton
    _dashboard_singleton = {
        "overview": overview,
        "recent_events": recent_events,
        "risk_distribution": risk_distribution,
        "reference": reference_data,
        "settings": SYSTEM_SETTINGS,
    }
    return _dashboard_singleton
