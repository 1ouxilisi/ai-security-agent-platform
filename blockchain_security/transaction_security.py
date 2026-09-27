#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
交易安全检测器 (Transaction Security Analyzer)

纯 Python 实现，不依赖 web3.py：
    - 交易数据分析（大额转账 / 危险函数选择器 / 滑点异常）
    - 钓鱼合约特征检测
    - 合约源码中的 Rug Pull / 钓鱼特征识别

仅用于授权的安全检测与防御评估。
"""

import re
from typing import Dict, List, Optional

from blockchain_security.wallet_security import _keccak256


# ======================================================================
# 4 字节函数选择器表（由 Keccak256(signature)[:4] 生成）
# ======================================================================
def _build_selector_table() -> Dict[str, str]:
    """根据常见危险函数签名生成 4 字节选择器映射"""
    signatures = {
        "transfer(address,uint256)": "ERC20 转账",
        "approve(address,uint256)": "授权 (approve)",
        "transferFrom(address,address,uint256)": "代理转账",
        "mint(address,uint256)": "铸币 (mint)",
        "burn(uint256)": "销毁 (burn)",
        "selfdestruct(address)": "自毁合约",
        "withdraw()": "提款",
        "withdraw(uint256)": "提款(指定金额)",
        "pause()": "暂停交易",
        "unpause()": "恢复交易",
        "upgradeTo(address)": "升级代理实现",
        "upgradeToAndCall(address,bytes)": "升级并调用",
        "setOwner(address)": "转移所有权",
        "transferOwnership(address)": "转移所有权",
        "blacklist(address)": "黑名单",
        "freeze(address)": "冻结账户",
        "setFee(uint256)": "设置手续费",
        "setTax(uint256,uint256)": "设置税费",
        "claimFees()": "提取费用",
        "airdrop(address[],uint256[])": "空投",
    }
    table: Dict[str, str] = {}
    for sig, label in signatures.items():
        sel = _keccak256(sig.encode("utf-8"))[:4].hex()
        table["0x" + sel] = label
    return table


SELECTOR_TABLE = _build_selector_table()


# 知名官方合约名（用于伪装检测）
FAMOUS_PROTOCOLS = [
    "UniswapV2Router", "UniswapV3Router", "Tether USD", "Tether", "USDC",
    "USD Coin", "Binance", "WrappedBTC", "WBTC", "Aave", "Compound",
    "SushiSwap", "PancakeSwap",
]


class TransactionSecurityAnalyzer:
    """交易安全检测器"""

    # 默认大额转账阈值（ETH，可在 options 中覆盖）
    DEFAULT_LARGE_TX_THRESHOLD_ETH = 10.0

    # ------------------------------------------------------------------
    # 交易数据分析
    # ------------------------------------------------------------------
    def analyze_transaction(self, tx_data: Dict) -> List[Dict]:
        """分析交易数据

        Args:
            tx_data: 交易字段，支持：
                value (int, wei) / to / input / data / from /
                expected_price / actual_price

        Returns:
            发现列表
        """
        findings: List[Dict] = []
        if not isinstance(tx_data, dict):
            return findings

        # ---- 1. 大额转账检测 ----
        value_wei = tx_data.get("value", 0)
        try:
            value_wei = int(value_wei, 0) if isinstance(value_wei, str) else int(value_wei)
        except (ValueError, TypeError):
            value_wei = 0
        threshold_eth = tx_data.get("large_tx_threshold_eth",
                                    self.DEFAULT_LARGE_TX_THRESHOLD_ETH)
        value_eth = value_wei / 1e18
        if value_eth >= threshold_eth:
            findings.append({
                "type": "大额转账",
                "severity": "high",
                "detail": f"交易携带 {value_eth:.4f} ETH，超过阈值 {threshold_eth} ETH，"
                          f"请确认收款方地址可信。",
                "evidence": f"value = {value_wei} wei ({value_eth:.4f} ETH)",
            })

        # ---- 2. input data 中的危险函数选择器 ----
        input_data = tx_data.get("input") or tx_data.get("data") or ""
        input_data = input_data.lower().replace("0x", "")
        if len(input_data) >= 8:
            selector = "0x" + input_data[:8]
            if selector in SELECTOR_TABLE:
                label = SELECTOR_TABLE[selector]
                sev = self._selector_severity(label)
                findings.append({
                    "type": "危险函数调用",
                    "severity": sev,
                    "detail": f"交易调用了函数：{label} (selector={selector})",
                    "evidence": f"input={input_data[:80]}",
                })

        # ---- 3. 滑点异常 ----
        expected = tx_data.get("expected_price")
        actual = tx_data.get("actual_price")
        if expected and actual:
            try:
                exp = float(expected)
                act = float(actual)
                if exp > 0:
                    slippage = abs(act - exp) / exp * 100
                    if slippage > 5:
                        findings.append({
                            "type": "滑点异常",
                            "severity": "medium" if slippage < 15 else "high",
                            "detail": f"实际成交价相对预期偏离 {slippage:.1f}%，"
                                      f"可能遭遇三明治攻击或价格操纵。",
                            "evidence": f"expected={exp}, actual={act}",
                        })
            except (ValueError, TypeError):
                pass

        return findings

    @staticmethod
    def _selector_severity(label: str) -> str:
        """根据函数类型给出默认严重程度"""
        high = ("铸币", "自毁", "升级", "转移所有权", "提款", "提取费用", "黑名单", "冻结")
        if any(k in label for k in high):
            return "high"
        if "授权" in label or "转账" in label:
            return "medium"
        return "low"

    # ------------------------------------------------------------------
    # 钓鱼合约检测
    # ------------------------------------------------------------------
    def detect_phishing_contract(self, bytecode_or_patterns: str) -> List[Dict]:
        """检测钓鱼/恶意合约特征

        Args:
            bytecode_or_patterns: 合约元信息文本（名称、ABI、字节码、特征描述）
        """
        findings: List[Dict] = []
        text = (bytecode_or_patterns or "").lower()
        raw = bytecode_or_patterns or ""

        # (a) 合约名伪装
        for proto in FAMOUS_PROTOCOLS:
            if proto.lower() in text:
                findings.append({
                    "type": "合约名伪装",
                    "severity": "high",
                    "detail": f"合约名称/描述中包含知名协议「{proto}」，"
                              f"需核对部署地址是否为官方地址，谨防仿冒合约。",
                    "evidence": proto,
                })

        # (b) 隐藏 mint 权限（owner 可调用 mint）
        if re.search(r"\bmint\b", text) and re.search(r"\bowner\b", text):
            findings.append({
                "type": "隐藏铸币权限",
                "severity": "critical",
                "detail": "合约同时包含 mint 函数与 owner 角色，"
                          "owner 可无限增发代币，存在 rug pull 风险。",
                "evidence": "mint + owner",
            })

        # (c) 可升级代理
        if any(k in text for k in ("upgradeto", "upgradeable", "transparentproxy",
                                    "eip1967", "proxiable")):
            findings.append({
                "type": "可升级代理合约",
                "severity": "medium",
                "detail": "合约为可升级代理，部署方可能随时替换实现逻辑，"
                          "已部署逻辑可能被篡改。",
                "evidence": "upgrade/proxy pattern",
            })

        # (d) 黑名单 / 冻结
        if re.search(r"blacklist|freeze|frozen", text):
            findings.append({
                "type": "资产冻结/黑名单功能",
                "severity": "high",
                "detail": "合约具备 blacklist/freeze 功能，"
                          "部署方可冻结指定地址资产，资金不自主。",
                "evidence": "blacklist/freeze",
            })

        # (e) Rug pull 特征：owner 可提取资金 / 高税费
        if re.search(r"owner.*(withdraw|claim|sweep)|withdraw.*owner", text):
            findings.append({
                "type": "Owner 可提取资金",
                "severity": "critical",
                "detail": "Owner 可提取合约内资金，典型 rug pull 特征。",
                "evidence": "owner withdraw/claim/sweep",
            })
        if re.search(r"tax.*[1-9]\d|fee.*[1-9]\d", text):
            findings.append({
                "type": "高交易税费",
                "severity": "medium",
                "detail": "合约设置较高交易税费（>=10%），需确认税费去向。",
                "evidence": "high tax/fee",
            })

        return findings

    # ------------------------------------------------------------------
    # 合约源码 Rug Pull / 钓鱼特征
    # ------------------------------------------------------------------
    def analyze_contract_patterns(self, source_code: str) -> List[Dict]:
        """从 Solidity 源码检测 Rug Pull / 钓鱼特征"""
        findings: List[Dict] = []
        src = source_code or ""
        lines = src.split("\n")

        # (a) onlyOwner + mint 组合（无限增发）
        has_owner_mod = bool(re.search(r"modifier\s+onlyOwner", src))
        mint_lines = [i + 1 for i, l in enumerate(lines)
                      if re.search(r"function\s+mint\b", l)]
        if has_owner_mod and mint_lines:
            # 检查 mint 函数是否带 onlyOwner
            for i, l in enumerate(lines):
                if re.search(r"function\s+mint\b", l) and "onlyOwner" in l:
                    findings.append({
                        "type": "onlyOwner + mint（无限增发）",
                        "severity": "critical",
                        "detail": "mint 函数受 onlyOwner 保护，owner 可无限增发代币。",
                        "line": i + 1,
                        "evidence": l.strip(),
                    })
                    break

        # (b) selfdestruct + onlyOwner（可卷款跑路）
        sd_lines = [i + 1 for i, l in enumerate(lines)
                    if re.search(r"selfdestruct|suicide", l)]
        if sd_lines and has_owner_mod:
            findings.append({
                "type": "onlyOwner + selfdestruct",
                "severity": "critical",
                "detail": "owner 可调用 selfdestruct 销毁合约，卷款跑路。",
                "line": sd_lines[0],
                "evidence": lines[sd_lines[0] - 1].strip(),
            })

        # (c) transfer 税费 > 10%
        # 匹配 taxFee / totalFee 赋值为 >= 10 (假设单位为 %)
        for i, l in enumerate(lines):
            m = re.search(r"(tax|fee|taxFee|liquidityFee)\w*\s*=\s*(\d+)", l)
            if m and int(m.group(2)) >= 10:
                findings.append({
                    "type": "交易税费过高",
                    "severity": "medium",
                    "detail": f"交易税费设置为 {m.group(2)}%，超过 10% 警戒线。",
                    "line": i + 1,
                    "evidence": l.strip(),
                })
                break

        # (d) blacklist / freeze 函数
        for i, l in enumerate(lines):
            if re.search(r"function\s+\w*(blacklist|freeze|frozen)\w*", l, re.IGNORECASE):
                findings.append({
                    "type": "黑名单/冻结函数",
                    "severity": "high",
                    "detail": "合约具备黑名单/冻结功能，可冻结用户资产。",
                    "line": i + 1,
                    "evidence": l.strip(),
                })

        # (e) pause 函数
        for i, l in enumerate(lines):
            if re.search(r"function\s+pause\s*\(", l):
                findings.append({
                    "type": "暂停交易函数 (pause)",
                    "severity": "medium",
                    "detail": "owner 可暂停转账，存在交易被冻结风险。",
                    "line": i + 1,
                    "evidence": l.strip(),
                })

        # (f) 升级代理模式
        for i, l in enumerate(lines):
            if re.search(r"upgradeTo|TransparentUpgradeableProxy|EIP1967|_implementation", l):
                findings.append({
                    "type": "可升级代理模式",
                    "severity": "medium",
                    "detail": "合约使用可升级代理，逻辑可被部署方更换。",
                    "line": i + 1,
                    "evidence": l.strip(),
                })

        return findings


# 模块级单例
_tx_analyzer: Optional["TransactionSecurityAnalyzer"] = None


def get_transaction_security_analyzer() -> "TransactionSecurityAnalyzer":
    global _tx_analyzer
    if _tx_analyzer is None:
        _tx_analyzer = TransactionSecurityAnalyzer()
    return _tx_analyzer
