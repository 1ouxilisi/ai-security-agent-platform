#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web3_security 包 — 第27轮升级方向4：区块链与 Web3 安全。

模块：
    - smart_contract  智能合约安全（Solidity/Vyper/Rust/Move/Cairo/Clarity 静态/动态/形式化分析）
    - defi_security   DeFi 安全（DEX/借贷/稳定币/闪电贷/预言机/治理/流动性）
    - nft_security    NFT 安全（铸造/转账/授权/市场/元数据/洗钱/审计）
    - dao_security    DAO 安全（治理/资金/成员/投票/多签/时间锁）
    - node_security   区块链节点安全（RPC/P2P/共识/网络/合约/审计）
    - crypto_security 加密货币安全（钱包/私钥/交易/地址/洗钱）
    - web3_dashboard  Web3 安全控制台数据聚合层
"""

from __future__ import annotations

__version__ = "27.4.0"
__round__ = 27
__direction__ = 4
__codename__ = "web3-security"

__all__ = [
    "smart_contract",
    "defi_security",
    "nft_security",
    "dao_security",
    "node_security",
    "crypto_security",
    "web3_dashboard",
]
