#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
区块链安全评估器主文件 (Blockchain Assessor)

继承统一框架 DomainAssessor，整合三大子模块：
    - SmartContractAnalyzer      智能合约静态分析
    - WalletSecurityChecker      钱包/私钥/助记词/地址安全
    - TransactionSecurityAnalyzer 交易与钓鱼/Rug Pull 检测

根据 target 自动识别评估对象类型并调度对应检测器，
最终将所有发现封装为统一 Finding 对象返回。

仅用于授权的安全评估与防御测试。
"""

import os
import re
import json
import time
from typing import Dict, List, Optional

from unified.engine import DomainAssessor
from unified.models import DomainAssessment, DomainType, Finding
from blockchain_security.smart_contract_analyzer import SmartContractAnalyzer
from blockchain_security.wallet_security import WalletSecurityChecker
from blockchain_security.transaction_security import TransactionSecurityAnalyzer


class BlockchainAssessor(DomainAssessor):
    """区块链安全领域评估器"""

    domain = DomainType.BLOCKCHAIN
    name = "blockchain_assessor"
    description = "区块链安全评估：智能合约审计、钱包安全、交易与钓鱼检测"

    def __init__(self):
        super().__init__()
        self.contract_analyzer = SmartContractAnalyzer()
        self.wallet_checker = WalletSecurityChecker()
        self.tx_analyzer = TransactionSecurityAnalyzer()

    # ======================================================================
    # 主入口
    # ======================================================================
    def assess(self, target: str, options: Optional[Dict] = None) -> DomainAssessment:
        """执行区块链安全评估

        target 自动识别类型：
            - .sol 文件路径          → 智能合约静态分析 + Rug Pull 特征
            - 内联 Solidity 源码     → 同上
            - 0x 开头长度 42         → 地址校验 + 钓鱼检测
            - BEGIN PRIVATE KEY / 64hex → 私钥检测
            - 12/24 个空格分隔词      → 助记词检测
            - .json 文件路径         → 交易安全分析
        """
        options = options or {}
        result = DomainAssessment(
            domain=self.domain,
            target=target if isinstance(target, str) else str(target),
            started_at=time.time(),
        )

        findings: List[Finding] = []
        target_str = target if isinstance(target, str) else str(target)
        kind = self._classify_target(target_str)

        try:
            if kind == "solidity_file":
                findings.extend(self._assess_solidity_file(target_str, options))
            elif kind == "solidity_inline":
                findings.extend(self._assess_solidity_source(target_str, options))
            elif kind == "address":
                findings.extend(self._assess_address(target_str, options))
            elif kind == "private_key":
                findings.extend(self._assess_private_key(target_str))
            elif kind == "mnemonic":
                findings.extend(self._assess_mnemonic(target_str))
            elif kind == "tx_json":
                findings.extend(self._assess_transaction(target_str, options))
            else:
                # 兜底：尝试文本泄露扫描
                findings.extend(self._assess_text_leak(target_str))
        except Exception as e:
            result.errors.append(f"{type(e).__name__}: {e}")

        result.tools_used = [
            "SmartContractAnalyzer", "WalletSecurityChecker", "TransactionSecurityAnalyzer"
        ]
        result.checks_run = [kind]
        result.checks_total = len(findings)
        return self._complete_result(result, findings, result.errors)

    # ======================================================================
    # 目标类型识别
    # ======================================================================
    def _classify_target(self, target: str) -> str:
        """根据 target 内容判断评估类型"""
        if not target:
            return "unknown"
        t = target.strip()

        # 文件类
        if os.path.isfile(t):
            low = t.lower()
            if low.endswith(".sol"):
                return "solidity_file"
            if low.endswith(".json"):
                return "tx_json"

        # PEM 私钥块
        if "BEGIN" in t and "PRIVATE KEY" in t:
            return "private_key"

        # 纯 64 hex（可选 0x 前缀）
        if re.fullmatch(r"(0x)?[a-fA-F0-9]{64}", t.strip()):
            return "private_key"

        # 以太坊地址 0x + 40 hex
        if re.fullmatch(r"0x[a-fA-F0-9]{40}", t.strip()):
            return "address"

        # 助记词：12/15/18/21/24 个词
        words = t.split()
        if len(words) in (12, 15, 18, 21, 24) and all(re.fullmatch(r"[a-z]+", w) for w in words):
            return "mnemonic"

        # 内联 Solidity 源码
        if "pragma solidity" in t or re.search(r"\bcontract\s+\w+", t):
            return "solidity_inline"

        # JSON 字符串（交易数据）
        if t.startswith("{") and t.rstrip().endswith("}"):
            return "tx_json"

        return "unknown"

    # ======================================================================
    # 各类型评估实现
    # ======================================================================
    def _assess_solidity_file(self, path: str, options: Dict) -> List[Finding]:
        """读取 .sol 文件并分析"""
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        return self._assess_solidity_source(source, options, location=path)

    def _assess_solidity_source(self, source: str, options: Dict,
                                location: str = "<inline>") -> List[Finding]:
        """运行智能合约静态分析 + Rug Pull 特征分析"""
        findings: List[Finding] = []

        # 1) 静态漏洞分析
        raw = self.contract_analyzer.analyze(source, "")
        for v in raw:
            findings.append(self._make_finding(
                title=f"[合约漏洞] {v['type']}",
                severity=v.get("severity", "medium"),
                category=v["type"],
                description=v.get("description", ""),
                target=location,
                location=v.get("location", ""),
                evidence=f"行号 {v.get('line','?')} | {v.get('code_snippet','')}",
                cwe=v.get("cwe", ""),
                recommendation=v.get("recommendation", ""),
                extra={"line": v.get("line")},
            ))

        # 2) Rug Pull / 钓鱼特征分析
        raw2 = self.tx_analyzer.analyze_contract_patterns(source)
        for v in raw2:
            findings.append(self._make_finding(
                title=f"[RugPull] {v['type']}",
                severity=v.get("severity", "high"),
                category=v["type"],
                description=v.get("detail", ""),
                target=location,
                location=f"Line {v.get('line', '?')}",
                evidence=v.get("evidence", ""),
                recommendation="核对合约去中心化程度、流动性锁定与权限设计。",
            ))
        return findings

    def _assess_address(self, address: str, options: Dict) -> List[Finding]:
        """地址校验 + 钓鱼合约检测"""
        findings: List[Finding] = []
        chain = options.get("chain", "ethereum")
        res = self.wallet_checker.check_address(address, chain)

        if not res.get("valid", False):
            findings.append(self._make_finding(
                title="地址格式错误",
                severity="high",
                category="地址安全",
                description="；".join(res.get("issues", [])) or "地址无效",
                target=address,
                location=address,
                evidence=address,
            ))
        elif res.get("issues"):
            findings.append(self._make_finding(
                title="地址安全提示",
                severity="medium",
                category="地址安全",
                description="；".join(res.get("issues", [])),
                target=address,
                location=address,
                evidence=address,
            ))

        # 钓鱼合约检测（基于 options 中的源码/特征）
        patterns = options.get("source_code") or options.get("patterns") or ""
        if patterns:
            for v in self.tx_analyzer.detect_phishing_contract(patterns):
                findings.append(self._make_finding(
                    title=f"[钓鱼合约] {v['type']}",
                    severity=v.get("severity", "high"),
                    category=v["type"],
                    description=v.get("detail", ""),
                    target=address,
                    location=address,
                    evidence=v.get("evidence", ""),
                ))
        return findings

    def _assess_private_key(self, key: str) -> List[Finding]:
        """私钥安全检测"""
        findings: List[Finding] = []
        res = self.wallet_checker.check_private_key(key)
        # 有效强密钥不报警；弱密钥/无效密钥都报警
        if res.get("strength") != "strong":
            sev = "critical" if res.get("strength") == "invalid" else "high"
            findings.append(self._make_finding(
                title="私钥不安全",
                severity=sev,
                category="私钥安全",
                description="；".join(res.get("issues", ["私钥无效或不安全"])),
                target="<private-key>",
                location="private_key",
                evidence=f"strength={res.get('strength')}, entropy={res.get('entropy')}",
                recommendation="使用 CSPRNG 生成的 256 位随机私钥，绝不使用弱密钥或测试向量。",
            ))
        return findings

    def _assess_mnemonic(self, words: str) -> List[Finding]:
        """助记词安全检测"""
        findings: List[Finding] = []
        res = self.wallet_checker.check_mnemonic(words)
        if not res.get("valid", False):
            findings.append(self._make_finding(
                title="助记词不安全",
                severity="high",
                category="助记词安全",
                description="；".join(res.get("issues", ["助记词强度不足"])),
                target="<mnemonic>",
                location="mnemonic",
                evidence=f"words={res.get('word_count')}, diversity={res.get('diversity')}",
                recommendation="使用钱包官方生成的标准 24 词助记词，离线抄写保管。",
            ))
        return findings

    def _assess_transaction(self, target: str, options: Dict) -> List[Finding]:
        """交易数据安全分析（.json 文件或 JSON 字符串）"""
        findings: List[Finding] = []
        try:
            if os.path.isfile(target):
                with open(target, "r", encoding="utf-8") as f:
                    tx_data = json.load(f)
            else:
                tx_data = json.loads(target)
        except Exception as e:
            findings.append(self._make_finding(
                title="交易数据解析失败",
                severity="medium",
                category="交易安全",
                description=f"无法解析交易 JSON：{e}",
                target=target,
            ))
            return findings

        for v in self.tx_analyzer.analyze_transaction(tx_data):
            findings.append(self._make_finding(
                title=f"[交易] {v['type']}",
                severity=v.get("severity", "medium"),
                category=v["type"],
                description=v.get("detail", ""),
                target=str(tx_data.get("to", "")),
                evidence=v.get("evidence", ""),
            ))
        return findings

    def _assess_text_leak(self, text: str) -> List[Finding]:
        """兜底：文本泄露扫描"""
        findings: List[Finding] = []
        for v in self.wallet_checker.scan_text_for_keys(text):
            findings.append(self._make_finding(
                title=f"[泄露] {v['type']}",
                severity=v.get("severity", "medium"),
                category="密钥泄露",
                description=v.get("detail", ""),
                target="<text>",
                evidence=v.get("detail", ""),
            ))
        return findings


# ======================================================================
# 注册函数
# ======================================================================
def register(engine) -> None:
    """将 BlockchainAssessor 注册到统一评估引擎"""
    engine.register(BlockchainAssessor())
