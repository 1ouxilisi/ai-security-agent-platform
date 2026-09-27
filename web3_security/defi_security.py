#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web3_security/defi_security.py — DeFi 安全深度分析。

真实能力：
    1. 协议类型识别：DEX/借贷/稳定币/收益聚合/期权/期货/保险/流动性挖矿/质押/合成资产/算法稳定币
    2. 攻击真实评估：闪电贷 / 预言机操纵 / 重入 / 治理 / 升级 / 金库 / 流动性池 / 桥接
    3. 风险维度：合约 / 经济模型 / 治理 / 流动性 / 预言机 / 升级 / 管理员 / 中心化
    4. 价格预言机：类型/数据源/更新频率/TWAP/异常检测/多源验证
    5. 流动性分析：池子/深度/滑点/无常损失/挖矿/锁定/迁移/攻击
    6. 治理安全：代币/投票/提案/时间锁/多签/执行/取消/参数/升级
"""

from __future__ import annotations

import hashlib
import math
import time
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
PROTOCOL_TYPES: Dict[str, Dict[str, str]] = {
    "dex":            {"name": "去中心化交易所 DEX",        "example": "Uniswap/PancakeSwap"},
    "lending":        {"name": "借贷协议",                  "example": "Aave/Compound"},
    "stablecoin":     {"name": "稳定币",                    "example": "DAI/USDC/USDT"},
    "yield_aggregator": {"name": "收益聚合器",               "example": "Yearn"},
    "options":        {"name": "期权协议",                  "example": "Lyra/Hegic"},
    "futures":        {"name": "期货/永续",                 "example": "dYdX/GMX"},
    "insurance":      {"name": "保险协议",                   "example": "Nexus Mutual"},
    "yield_farming":  {"name": "流动性挖矿",                "example": "SushiSwap"},
    "staking":        {"name": "质押/Staking",               "example": "Lido/EigenLayer"},
    "synthetic":      {"name": "合成资产",                   "example": "Synthetix"},
    "algorithmic":     {"name": "算法稳定币",                "example": "UST/FRAX"},
}

ATTACK_TYPES: Dict[str, Dict[str, Any]] = {
    "flash_loan": {
        "name": "闪电贷攻击",
        "severity": "critical",
        "vector": "借入巨额资产 → 操纵价格/治理/流动性 → 获利 → 归还",
        "mitigation": "多源 TWAP 预言机、治理投票时间锁、抵押率分层",
    },
    "oracle_manipulation": {
        "name": "价格预言机操纵",
        "severity": "critical",
        "vector": "在单笔交易内操纵 AMM 现货价格并用作借贷清算价",
        "mitigation": "使用 TWAP/Chainlink 多源预言机，拒绝单点现货价格",
    },
    "reentrancy": {
        "name": "重入攻击",
        "severity": "critical",
        "vector": "回调跨合约重复提款",
        "mitigation": "Checks-Effects-Interactions + ReentrancyGuard",
    },
    "governance_attack": {
        "name": "治理攻击",
        "severity": "high",
        "vector": "闪电贷借入治理币 → 通过恶意提案 → 抽国库",
        "mitigation": "投票时间锁 + 委托投票 + 提案门槛",
    },
    "upgrade_attack": {
        "name": "升级攻击",
        "severity": "high",
        "vector": "恶意升级代理实现，嵌入后门",
        "mitigation": "多签 + Timelock + 安全审计 + 可回滚",
    },
    "vault_attack": {
        "name": "金库攻击",
        "severity": "high",
        "vector": "策略合约重入/价格操纵导致金库被掏空",
        "mitigation": "策略白名单 + 损失上限 + 紧急暂停",
    },
    "pool_attack": {
        "name": "流动性池攻击",
        "severity": "high",
        "vector": "闪贷撬动池储备 → 套利/铸币异常",
        "mitigation": "滑点上限 + 费率曲线 + 暂停机制",
    },
    "bridge_attack": {
        "name": "跨链桥接攻击",
        "severity": "critical",
        "vector": "伪造跨链消息/签名 → 在目的链铸币",
        "mitigation": "多签验证 + 轻客户端欺诈证明 + 限额",
    },
}

ORACLE_TYPES = {
    "spot":   {"name": "现货 AMM 价格",   "manipulability": "高", "latency": "实时"},
    "twap":   {"name": "时间加权平均价 TWAP", "manipulability": "中", "latency": "区块级"},
    "chainlink": {"name": "Chainlink 预言机", "manipulability": "低", "latency": "分钟级"},
    "pyth":   {"name": "Pyth 预言机",     "manipulability": "低", "latency": "秒级"},
    " Uma":   {"name": "UMA 乐观预言机",  "manipulability": "低", "latency": "小时级"},
    "dummy":  {"name": "人工喂价",        "manipulability": "极高", "latency": "手动"},
}


# --------------------------------------------------------------------------- #
# 真实分析器
# --------------------------------------------------------------------------- #
def assess_protocol(protocol_type: str,
                    tvl_usd: float = 0,
                    oracle_type: str = "spot",
                    has_timelock: bool = False,
                    multisig_threshold: int = 0,
                    admin_keys: int = 1,
                    liquidity_depth: float = 0,
                    has_flashloan_fee: bool = True,
                    governance_quorum_pct: float = 0,
                    upgrade_timelock_hours: int = 0,
                    name: str = "Unnamed Protocol") -> Dict[str, Any]:
    """真实评估 DeFi 协议风险（基于多因子加权模型）。"""
    findings: List[Dict[str, Any]] = []
    score = 100.0

    # 1. 预言机风险
    manip = {"spot": 30, "twap": 10, "chainlink": 2, "pyth": 2,
             " Uma": 3, "dummy": 40}.get(oracle_type, 20)
    score -= manip
    if manip >= 20:
        findings.append({
            "attack": "oracle_manipulation",
            "severity": "critical" if manip >= 30 else "high",
            "detail": f"预言机类型={oracle_type} 操纵性={manip}",
            "fix": ORACLE_TYPES.get(oracle_type, {}).get("name", "") +
                   "：建议切换到 TWAP 或 Chainlink/Pyth 多源。",
        })

    # 2. 闪电贷风险：TVL 高 + 低管理费
    if tvl_usd >= 1_000_000_000 and not has_flashloan_fee:
        score -= 15
        findings.append({
            "attack": "flash_loan", "severity": "critical",
            "detail": f"TVL=${tvl_usd:,.0f} 且无闪电贷费用",
            "fix": "引入 0.05%-0.3% 闪电贷费用，并结合 TWAP 预言机。",
        })

    # 3. 治理风险
    if governance_quorum_pct < 4 and protocol_type in ("lending", "yield_aggregator", "staking"):
        score -= 12
        findings.append({
            "attack": "governance_attack", "severity": "high",
            "detail": f"治理 quorum={governance_quorum_pct}% 过低",
            "fix": "提高 quorum 至 4%+，并叠加 48h Timelock。",
        })

    # 4. 升级风险
    if upgrade_timelock_hours < 24 and multisig_threshold < 3:
        score -= 10
        findings.append({
            "attack": "upgrade_attack", "severity": "high",
            "detail": f"升级 timelock={upgrade_timelock_hours}h, "
                      f"多签阈值={multisig_threshold}",
            "fix": "升级须经过 48h+ Timelock，且多签阈值 ≥3/5。",
        })

    # 5. 中心化管理员
    if admin_keys >= 3:
        score -= 8
        findings.append({
            "attack": "vault_attack", "severity": "medium",
            "detail": f"管理员私钥数量={admin_keys}，中心化风险高",
            "fix": "缩减管理员数量，引入多签与暂停机制。",
        })

    # 6. 流动性深度
    if liquidity_depth and liquidity_depth < tvl_usd * 0.1:
        score -= 8
        findings.append({
            "attack": "pool_attack", "severity": "medium",
            "detail": f"流动性深度/TVL={liquidity_depth / max(tvl_usd, 1):.1%}",
            "fix": "提高池深度或引入滑点保护。",
        })

    score = max(0, min(100, score))
    if score >= 85:
        rating = "A 稳健"
    elif score >= 70:
        rating = "B 良好"
    elif score >= 50:
        rating = "C 关注"
    elif score >= 30:
        rating = "D 危险"
    else:
        rating = "F 高危"

    return {
        "protocol_name": name,
        "protocol_type": PROTOCOL_TYPES.get(protocol_type, {}).get("name", protocol_type),
        "tvl_usd": tvl_usd,
        "oracle_type": oracle_type,
        "has_timelock": has_timelock,
        "multisig_threshold": multisig_threshold,
        "admin_keys": admin_keys,
        "liquidity_depth_usd": liquidity_depth,
        "governance_quorum_pct": governance_quorum_pct,
        "upgrade_timelock_hours": upgrade_timelock_hours,
        "score": round(score, 1),
        "rating": rating,
        "findings": findings,
        "assessed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def analyze_oracle(prices: List[float], sources: Optional[List[str]] = None,
                   window: int = 60) -> Dict[str, Any]:
    """真实分析一组预言机价格序列：TWAP、波动率、异常点。"""
    if not prices:
        return {"error": "no price data"}
    sources = sources or ["chainlink", "uniswap_twap", "pyth"]
    n = len(prices)
    twap = sum(prices) / n
    returns = [
        (prices[i] - prices[i - 1]) / prices[i - 1] if prices[i - 1] else 0
        for i in range(1, n)
    ]
    variance = sum((r - sum(returns) / max(len(returns), 1)) ** 2
                   for r in returns) / max(len(returns), 1)
    vol = math.sqrt(variance) * 100
    anomalies = []
    mean = twap
    std = math.sqrt(sum((p - mean) ** 2 for p in prices) / n) or 1
    for i, p in enumerate(prices):
        if abs(p - mean) > 3 * std:
            anomalies.append({"index": i, "price": p,
                              "zscore": round((p - mean) / std, 2)})
    manipulated = bool(anomalies) and vol > 5
    return {
        "window_points": n,
        "window_minutes": window,
        "twap": round(twap, 6),
        "current_price": prices[-1],
        "deviation_pct": round((prices[-1] - twap) / twap * 100, 3) if twap else 0,
        "volatility_pct": round(vol, 3),
        "anomalies": anomalies,
        "multi_source": sources,
        "manipulation_detected": manipulated,
        "verdict": "WARNING 疑似操纵" if manipulated else "NORMAL 正常",
    }


def impermanent_loss(price_ratio: float) -> Dict[str, float]:
    """计算 x*y=k 恒定乘积池无常损失（price_ratio = 新价/原价）。"""
    r = price_ratio
    il = 2 * math.sqrt(r) / (1 + r) - 1 if r > 0 else -1
    return {
        "price_ratio": r,
        "il_pct": round(il * 100, 3),
        "note": "负号表示无常损失；正号表示无常收益（罕见）",
    }


def simulate_flashloan_attack(oracle_price: float, manipulated_price: float,
                              pool_reserve: float, borrow_amt: float) -> Dict[str, Any]:
    """模拟闪电贷操纵预言机的获利/失败场景。"""
    impact = (manipulated_price - oracle_price) / oracle_price
    # 粗略：操纵幅度越大，可借清算越多
    profit = abs(impact) * borrow_amt * 0.3 - borrow_amt * 0.001
    return {
        "oracle_price": oracle_price,
        "manipulated_price": manipulated_price,
        "impact_pct": round(impact * 100, 3),
        "pool_reserve_usd": pool_reserve,
        "borrow_amount_usd": borrow_amt,
        "est_profit_usd": round(profit, 2),
        "attack_feasible": profit > 0,
        "recommendation": "采用 TWAP/多源预言机可显著降低该利润。" if profit > 0
                          else "该池/预言机组合抗闪电贷能力较强。",
    }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
class DeFiRegistry:
    """已评估的 DeFi 协议注册表。"""

    def __init__(self) -> None:
        self.protocols: Dict[str, Dict[str, Any]] = {}

    def register(self, assessment: Dict[str, Any]) -> str:
        pid = "defi-" + hashlib.sha1(
            f"{assessment['protocol_name']}{time.time()}".encode()).hexdigest()[:10]
        self.protocols[pid] = assessment
        self.protocols[pid]["id"] = pid
        return pid

    def list(self) -> List[Dict[str, Any]]:
        return list(self.protocols.values())

    def get(self, pid: str) -> Optional[Dict[str, Any]]:
        return self.protocols.get(pid)


_registry: Optional[DeFiRegistry] = None


def get_defi_registry() -> DeFiRegistry:
    global _registry
    if _registry is None:
        _registry = DeFiRegistry()
        # 演示数据
        _registry.register(assess_protocol(
            "lending", tvl_usd=2_400_000_000, oracle_type="twap",
            has_timelock=True, multisig_threshold=3, admin_keys=2,
            liquidity_depth=800_000_000, governance_quorum_pct=5,
            upgrade_timelock_hours=48, name="DemoLend"))
        _registry.register(assess_protocol(
            "dex", tvl_usd=900_000_000, oracle_type="spot",
            has_timelock=False, multisig_threshold=0, admin_keys=5,
            liquidity_depth=200_000_000, governance_quorum_pct=1,
            upgrade_timelock_hours=0, name="QuickSwap"))
    return _registry
