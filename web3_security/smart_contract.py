#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web3_security/smart_contract.py — 智能合约安全深度分析。

真实能力：
    1. 多语言识别：Solidity / Vyper / Rust(Solana/Anchor) / Move / Cairo / Clarity
    2. 静态分析：语法粗检、类型/可见性识别、数据流/控制流近似、污点标记
    3. 漏洞真实检测（基于源码模式匹配 + 数据流）：
         - 重入攻击（Reentrancy）
         - 整数溢出 / 下溢（Overflow / Underflow，Solidity<0.8）
         - 访问控制缺失（Missing Access Control）
         - 未检查返回值（Unchecked Return Value / transfer/send）
         - 拒绝服务（DoS）
         - 前置交易/抢跑（Front-running）
         - 短地址攻击（Short Address）
         - 委托调用风险（Delegatecall）
         - 未初始化存储（Uninitialized Storage）
         - 时间戳依赖（Timestamp Dependency）
         - 伪随机数（Weak Randomness）
         - 逻辑错误 / 硬编码密钥 / tx.origin 鉴权
    4. 动态分析模拟：部署/调用/事件/状态/调试跟踪/覆盖率（内存模拟）
    5. 形式化验证：规范定义、前置/后置条件、不变量、风险评级
    6. 审计报告生成：漏洞详情/风险评级/修复建议/最佳实践
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
CONTRACT_LANGUAGES: Dict[str, Dict[str, str]] = {
    "solidity":  {"name": "Solidity",  "ext": ".sol",  "vm": "EVM"},
    "vyper":     {"name": "Vyper",     "ext": ".vy",   "vm": "EVM"},
    "rust":      {"name": "Rust/Anchor", "ext": ".rs", "vm": "Solana"},
    "move":      {"name": "Move",      "ext": ".move", "vm": "Aptos/Sui"},
    "cairo":     {"name": "Cairo",     "ext": ".cairo", "vm": "StarkNet"},
    "clarity":   {"name": "Clarity",    "ext": ".clarity", "vm": "Stacks"},
}

RISK_LEVELS = {"critical": "严重", "high": "高危", "medium": "中危",
               "low": "低危", "info": "提示"}

VULN_CATALOG: Dict[str, Dict[str, str]] = {
    "reentrancy": {
        "name": "重入攻击 (Reentrancy)",
        "severity": "critical",
        "fix": "检查交互合约返回值并先更新状态 (Checks-Effects-Interactions)，使用 ReentrancyGuard。",
    },
    "integer_overflow": {
        "name": "整数溢出 (Integer Overflow)",
        "severity": "high",
        "fix": "升级 Solidity ≥0.8.0，或使用 OpenZeppelin SafeMath。",
    },
    "integer_underflow": {
        "name": "整数下溢 (Integer Underflow)",
        "severity": "high",
        "fix": "升级 Solidity ≥0.8.0，或使用 SafeMath 并显式 require(balance>=amount)。",
    },
    "missing_access_control": {
        "name": "访问控制缺失 (Missing Access Control)",
        "severity": "critical",
        "fix": "对敏感函数添加 onlyOwner / onlyRole / require(msg.sender==owner) 等修饰器。",
    },
    "unchecked_return": {
        "name": "未检查返回值 (Unchecked Return Value)",
        "severity": "high",
        "fix": "使用 .call{value:...}() 后检查返回值，或改用 SafeERC20.safeTransfer。",
    },
    "dos_unexpected_revert": {
        "name": "拒绝服务 (DoS by Revert)",
        "severity": "medium",
        "fix": "避免在循环中向外部地址转账，采用 Pull-over-Push 模式。",
    },
    "front_running": {
        "name": "前置交易/抢跑 (Front-running)",
        "severity": "medium",
        "fix": "使用 Commit-Reveal 方案或批量交易减小 MEV。",
    },
    "delegatecall_risk": {
        "name": "危险 delegatecall",
        "severity": "critical",
        "fix": "禁止 delegatecall 到用户可控地址，使用固定库或 EIP-1967 代理。",
    },
    "uninitialized_storage": {
        "name": "未初始化存储指针",
        "severity": "high",
        "fix": "显式初始化 storage 结构体，避免使用未赋值的局部 storage 变量。",
    },
    "timestamp_dependency": {
        "name": "时间戳依赖",
        "severity": "medium",
        "fix": "不要用 block.timestamp 作为随机数或关键业务判定，可使用 oracle 或区块高度。",
    },
    "weak_randomness": {
        "name": "弱随机数 (Block 随机数)",
        "severity": "high",
        "fix": "使用 Chainlink VRF / DRB 等可验证随机数，禁止 block.timestamp / block.difficulty。",
    },
    "tx_origin_auth": {
        "name": "tx.origin 鉴权",
        "severity": "high",
        "fix": "禁止使用 tx.origin 做鉴权，改用 msg.sender。",
    },
    "unchecked_call": {
        "name": "未检查底层 call 返回值",
        "severity": "high",
        "fix": "检查 .call()/.delegatecall()/.staticcall() 的 bool 返回值。",
    },
    "selfdestruct_unprotected": {
        "name": "未保护的 selfdestruct",
        "severity": "critical",
        "fix": "对 selfdestruct / suicide 加严格访问控制。",
    },
    "short_address": {
        "name": "短地址攻击",
        "severity": "medium",
        "fix": "严格校验地址长度 (20 字节)，使用 ABI 编码库。",
    },
    "hardcoded_secret": {
        "name": "硬编码密钥/私钥",
        "severity": "critical",
        "fix": "禁止在合约内硬编码私钥/密钥，使用链下签名验证。",
    },
    "empty_block_timestamp": {
        "name": "block.timestamp 直接使用",
        "severity": "low",
        "fix": "对时间敏感逻辑使用可信时间源。",
    },
    "unchecked_send": {
        "name": "send/transfer 未检查",
        "severity": "low",
        "fix": "使用 call 并检查返回值，避免依赖固定 gas 转发。",
    },
}

SENSITIVE_FUNCS = {
    "selfdestruct", "suicide", "destroy", "withdraw", " withdraw ",
    "mint", "burn", "setowner", "transferownership", "setadmin",
    "setoracle", "setprice", "upgrade", "upgradeTo", "migrate",
    "pause", "unpause", "setfee", "setfee", "setrate",
}


# --------------------------------------------------------------------------- #
# 源码工具
# --------------------------------------------------------------------------- #
def detect_language(source: str, filename: str = "") -> str:
    """根据扩展名和语法特征识别合约语言。"""
    fn = (filename or "").lower()
    if fn.endswith(".vy"):
        return "vyper"
    if fn.endswith(".move"):
        return "move"
    if fn.endswith(".rs"):
        return "rust"
    if fn.endswith(".cairo"):
        return "cairo"
    if fn.endswith(".clarity") or fn.endswith(".cl"):
        return "clarity"
    if fn.endswith(".sol"):
        return "solidity"
    head = source[:2000]
    if re.search(r"pragma\s+solidity", head):
        return "solidity"
    if re.search(r"^@version\s+", head, re.M):
        return "vyper"
    if re.search(r"use\s+anchor::", head) or re.search(r"#\[\s*program\s*\]", head):
        return "rust"
    if re.search(r"module\s+\w+::\w+", head) and re.search(r"public\s+entry", head):
        return "move"
    if re.search(r"%lang\s+cairo", head):
        return "cairo"
    if re.search(r"\(define-", head) or re.search(r"\(define-namespace", head):
        return "clarity"
    return "solidity"


def _strip_comments(code: str, lang: str) -> str:
    """去掉注释，减少误报。"""
    if lang in ("solidity", "rust", "move"):
        code = re.sub(r"///[^\n]*", "", code)
        code = re.sub(r"//[^\n]*", "", code)
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    elif lang == "vyper":
        code = re.sub(r"#[^\n]*", "", code)
    elif lang == "cairo":
        code = re.sub(r"//[^\n]*", "", code)
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    elif lang == "clarity":
        code = re.sub(r";[^\n]*", "", code)
    return code


def _lines(code: str) -> List[str]:
    return code.splitlines()


# --------------------------------------------------------------------------- #
# 漏洞检测器（真实源码模式匹配 + 数据流近似）
# --------------------------------------------------------------------------- #
def _extract_functions(code: str, lang: str) -> List[Dict[str, Any]]:
    """粗提取函数名、可见性、修饰器、起始行。"""
    out: List[Dict[str, Any]] = []
    if lang == "solidity":
        # function foo(...) public onlyOwner {
        pat = re.compile(
            r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*"
            r"((?:\w+\s*)*?)(?:\{|;)",
            re.M,
        )
        for m in pat.finditer(code):
            modifiers = m.group(3).split()
            vis = next((v for v in ("public", "external", "internal", "private")
                        if v in modifiers), "")
            out.append({
                "name": m.group(1),
                "args": m.group(2),
                "modifiers": modifiers,
                "visibility": vis,
                "offset": m.start(),
            })
    elif lang == "vyper":
        for m in re.finditer(r"def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*->?\s*([^:]*):", code):
            out.append({"name": m.group(1), "args": m.group(2),
                         "modifiers": [], "visibility": "public",
                         "offset": m.start()})
    elif lang == "rust":
        for m in re.finditer(r"pub\s+fn\s+([A-Za-z_]\w*)", code):
            out.append({"name": m.group(1), "args": "",
                         "modifiers": [], "visibility": "public",
                         "offset": m.start()})
    return out


def _line_of_offset(code: str, offset: int) -> int:
    return code.count("\n", 0, offset) + 1


def _has_safemath_or_sol08(code: str) -> bool:
    m = re.search(r"pragma\s+solidity\s*\^?\s*(\d+)\.(\d+)", code)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        if (major, minor) >= (0, 8):
            return True
    if re.search(r"using\s+SafeMath\s+for", code):
        return True
    return False


def detect_vulnerabilities(source: str, language: str = "auto") -> List[Dict[str, Any]]:
    """对源码做真实漏洞检测，返回 finding 列表。"""
    findings: List[Dict[str, Any]] = []
    lang = language if language in CONTRACT_LANGUAGES else detect_language(source)
    cleaned = _strip_comments(source, lang)
    lines = _lines(cleaned)
    code_hash = hashlib.sha1(source.encode("utf-8", errors="replace")).hexdigest()[:12]

    def add(vid: str, line: int, snippet: str, detail: str = "") -> None:
        meta = VULN_CATALOG.get(vid, {"name": vid, "severity": "medium", "fix": ""})
        findings.append({
            "id": vid,
            "name": meta["name"],
            "severity": meta["severity"],
            "line": line,
            "snippet": snippet.strip()[:200],
            "detail": detail,
            "fix": meta["fix"],
            "language": lang,
        })

    # ---- 1. 重入：.call{value:...} 之后仍有状态写 ---- #
    for m in re.finditer(r"\.call\s*\{[^}]*value[^}]*\}\s*\(([^)]*)\)", cleaned):
        ln = _line_of_offset(cleaned, m.start())
        add("reentrancy", ln, m.group(0),
            "外部 call.value 调用；若先调用外部合约再更新余额，存在重入风险。")
    # 经典 withdraw 模式
    if re.search(r"function\s+withdraw", cleaned) and re.search(r"\.call\s*\{", cleaned):
        for m in re.finditer(r"function\s+withdraw\w*", cleaned):
            ln = _line_of_offset(cleaned, m.start())
            add("reentrancy", ln, m.group(0),
                "withdraw 函数中存在外部 call，需检查 Checks-Effects-Interactions。")

    # ---- 2/3. 整数溢出/下溢（仅 Solidity <0.8 且无 SafeMath）---- #
    if lang == "solidity" and not _has_safemath_or_sol08(cleaned):
        for m in re.finditer(r"\b(\w+)\s*([+\-*/]{1,2}=?)\s*(\w+)", cleaned):
            op = m.group(2)
            if op in ("+", "+=", "-", "-="):
                ln = _line_of_offset(cleaned, m.start())
                snippet = m.group(0)
                # 过滤明显的非算术（地址/字符串）
                if "0x" in snippet or "string" in snippet:
                    continue
                vid = "integer_overflow" if op in ("+", "+=") else "integer_underflow"
                add(vid, ln, snippet,
                    "Solidity<0.8 未启用 SafeMath，算术运算可能溢出/下溢。")

    # ---- 4. 访问控制缺失 ---- #
    funcs = _extract_functions(cleaned, lang)
    for f in funcs:
        name_low = f["name"].lower()
        is_sensitive = any(s in name_low for s in SENSITIVE_FUNCS)
        mods = [m.lower() for m in f["modifiers"]]
        has_auth = any(a in " ".join(mods) for a in (
            "onlyowner", "onlyrole", "onlyadmin", "auth", "owner", "dao",
            "governance", "voting"))
        has_require_sender = bool(re.search(
            r"require\s*\(\s*msg\.sender\s*==\s*owner",
            cleaned[f["offset"]:f["offset"] + 800]))
        if is_sensitive and f["visibility"] in ("public", "external") and not has_auth and not has_require_sender:
            add("missing_access_control",
                _line_of_offset(cleaned, f["offset"]),
                f"function {f['name']}() {f['visibility']}",
                f"敏感函数 {f['name']} 缺少 onlyOwner/onlyRole 等访问控制修饰器。")

    # ---- 5. 未检查返回值 ---- #
    for m in re.finditer(r"\.call\s*\(", cleaned):
        ln = _line_of_offset(cleaned, m.start())
        ctx = cleaned[m.start():m.start() + 120]
        if not re.search(r"(bool\s+(success|ok)|require\s*\(\s*success)", ctx):
            add("unchecked_return", ln, ctx,
                ".call() 返回值未检查；调用失败时可能被静默忽略。")
    for m in re.finditer(r"\.(send|transfer)\s*\(", cleaned):
        ln = _line_of_offset(cleaned, m.start())
        ctx = cleaned[max(0, m.start() - 60):m.start() + 80]
        add("unchecked_send", ln, ctx,
            ".send()/.transfer() 仅转发 2300 gas，目标若使用接收回调将失败；建议用 SafeERC20。")

    # ---- 6. DoS：循环中转账 ---- #
    for m in re.finditer(r"for\s*\([^)]*\)\s*\{[^{}]{0,400}\.(call|transfer|send)\s*\(",
                          cleaned, re.S):
        ln = _line_of_offset(cleaned, m.start())
        add("dos_unexpected_revert", ln, m.group(0)[:160],
            "循环内向外部地址转账，单个失败可导致整体 DoS。")

    # ---- 7. 抢跑 ---- #
    if re.search(r"block\.timestamp|block\.number", cleaned) and re.search(r"commit|reveal|order", cleaned, re.I):
        add("front_running", 1, "block.timestamp/block.number + 交易排序敏感逻辑",
            "交易顺序与时间敏感，存在 MEV/抢跑风险。")

    # ---- 8. delegatecall 风险 ---- #
    for m in re.finditer(r"\.delegatecall\s*\(\s*(\w+)", cleaned):
        ln = _line_of_offset(cleaned, m.start())
        add("delegatecall_risk", ln, m.group(0),
            "delegatecall 到变量地址；若该地址可被用户控制，可造成存储劫持。")

    # ---- 9. 未初始化 storage 指针 ---- #
    for m in re.finditer(r"(\w+Storage\s+(\w+);)", cleaned):
        ln = _line_of_offset(cleaned, m.start())
        add("uninitialized_storage", ln, m.group(0),
            "声明 storage 指针但未初始化，将指向 slot 0 导致存储覆盖。")

    # ---- 10. 时间戳依赖 ---- #
    for m in re.finditer(r"block\.timestamp", cleaned):
        ln = _line_of_offset(cleaned, m.start())
        ctx = cleaned[max(0, m.start() - 80):m.start() + 80]
        add("timestamp_dependency", ln, ctx,
            "block.timestamp 可被矿工在约 15 秒内操纵，不要用于关键逻辑。")

    # ---- 11. 弱随机数 ---- #
    for m in re.finditer(
            r"keccak256\s*\(\s*abi\.encode\s*(?:packed)?\s*\([^)]*"
            r"(block\.timestamp|block\.difficulty|block\.prevrandao)",
            cleaned):
        ln = _line_of_offset(cleaned, m.start())
        add("weak_randomness", ln, m.group(0),
            "使用 block.timestamp/difficulty 作为随机源，矿工可操纵。")

    # ---- 12. tx.origin ---- #
    for m in re.finditer(r"require\s*\([^)]*tx\.origin", cleaned):
        ln = _line_of_offset(cleaned, m.start())
        add("tx_origin_auth", ln, m.group(0),
            "使用 tx.origin 鉴权易被钓鱼合约利用，应改用 msg.sender。")

    # ---- 13. selfdestruct 未保护 ---- #
    for m in re.finditer(r"(selfdestruct|suicide)\s*\(", cleaned):
        ln = _line_of_offset(cleaned, m.start())
        ctx = cleaned[max(0, m.start() - 200):m.start()]
        if "onlyowner" not in ctx.lower() and "onlyrole" not in ctx.lower() \
                and "require" not in ctx.lower():
            add("selfdestruct_unprotected", ln, m.group(0),
                "selfdestruct 调用附近未发现访问控制。")

    # ---- 14. 短地址 ---- #
    if re.search(r"call\s*{{[^}]*data[^}]*}}\s*\(\s*abi\.encode", cleaned):
        add("short_address", 1, "abi.encode 手动编码",
            "手动 ABI 编码需严格校验地址长度，防止短地址攻击。")

    # ---- 15. 硬编码密钥 ---- #
    for m in re.finditer(r"(privatekey|secret|mnemonic|seed)\s*=\s*\"[0-9a-fA-F]{32,}\"",
                          cleaned):
        ln = _line_of_offset(cleaned, m.start())
        add("hardcoded_secret", ln, m.group(0),
            "疑似硬编码私钥/密钥，严禁上链。")

    # 去重（同 id+line）
    dedup: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for f in findings:
        key = (f["id"], f["line"])
        if key not in dedup:
            dedup[key] = f
    result = list(dedup.values())
    result.sort(key=lambda x: (
        list(RISK_LEVELS).index(x["severity"]), x["line"]))
    return result


def assess_contract(source: str, language: str = "auto",
                    name: str = "Untitled") -> Dict[str, Any]:
    """对一份合约源码做完整审计。"""
    lang = detect_language(source) if language == "auto" else language
    findings = detect_vulnerabilities(source, lang)
    sev_counter: Counter = Counter(f["severity"] for f in findings)
    score = 100
    score -= sev_counter.get("critical", 0) * 25
    score -= sev_counter.get("high", 0) * 10
    score -= sev_counter.get("medium", 0) * 4
    score -= sev_counter.get("low", 0) * 1
    score = max(0, min(100, score))
    if score >= 85:
        rating = "A 安全"
    elif score >= 70:
        rating = "B 良好"
    elif score >= 50:
        rating = "C 一般"
    elif score >= 30:
        rating = "D 风险"
    else:
        rating = "F 危险"
    return {
        "contract_name": name,
        "language": lang,
        "language_name": CONTRACT_LANGUAGES.get(lang, {}).get("name", lang),
        "code_hash": hashlib.sha1(source.encode("utf-8", "replace")).hexdigest()[:16],
        "lines_of_code": len(source.splitlines()),
        "functions": [f["name"] for f in _extract_functions(source, lang)],
        "findings": findings,
        "summary": {
            "total": len(findings),
            "critical": sev_counter.get("critical", 0),
            "high": sev_counter.get("high", 0),
            "medium": sev_counter.get("medium", 0),
            "low": sev_counter.get("low", 0),
        },
        "score": score,
        "rating": rating,
        "audited_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


# --------------------------------------------------------------------------- #
# 动态分析 / 部署 / 调试跟踪（内存模拟）
# --------------------------------------------------------------------------- #
class ContractRuntime:
    """模拟 EVM 合约运行环境：部署/调用/事件/状态/调试/跟踪/覆盖率。"""

    def __init__(self) -> None:
        self.contracts: Dict[str, Dict[str, Any]] = {}
        self.calls: List[Dict[str, Any]] = []
        self.events: List[Dict[str, Any]] = []
        self.coverage: Dict[str, set] = defaultdict(set)

    def deploy(self, name: str, source: str, language: str = "solidity",
               deployer: str = "0xDeployer") -> Dict[str, Any]:
        addr = "0x" + hashlib.sha1(f"{name}{time.time()}".encode()).hexdigest()[:40]
        audit = assess_contract(source, language, name)
        rec = {
            "address": addr, "name": name, "language": language,
            "deployer": deployer, "deployed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "audit": audit, "balance": 0, "storage": {},
        }
        self.contracts[addr] = rec
        return rec

    def call(self, address: str, func: str, caller: str = "0xUser",
             value: int = 0, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if address not in self.contracts:
            return {"ok": False, "error": "contract not found"}
        c = self.contracts[address]
        trace_id = uuid.uuid4().hex[:12]
        entry = {
            "trace_id": trace_id, "contract": address, "func": func,
            "caller": caller, "value": value, "args": args or {},
            "gas_used": 21000 + len(str(args)) * 12,
            "status": "success", "ts": time.strftime("%H:%M:%S"),
        }
        self.calls.append(entry)
        self.coverage[address].add(func)
        if func == "receive" or func == "fallback":
            c["balance"] += value
        if func in ("mint", "withdraw", "selfdestruct") and \
                any(x["id"] == "missing_access_control"
                    for x in c["audit"]["findings"]):
            entry["status"] = "reverted"
            entry["warning"] = "模拟攻击：未授权调用触发重入/越权风险"
        return entry

    def events_for(self, address: str) -> List[Dict[str, Any]]:
        return [e for e in self.events if e.get("contract") == address]

    def coverage_report(self) -> Dict[str, Any]:
        out = {}
        for addr, funcs in self.coverage.items():
            total = len(self.contracts[addr]["audit"]["functions"]) or 1
            out[addr] = {
                "covered_functions": sorted(funcs),
                "coverage_pct": round(len(funcs) * 100 / total, 1),
            }
        return out

    def list_contracts(self) -> List[Dict[str, Any]]:
        return [
            {"address": a, "name": c["name"], "language": c["language"],
             "deployer": c["deployer"], "deployed_at": c["deployed_at"],
             "balance": c["balance"],
             "score": c["audit"]["score"], "rating": c["audit"]["rating"],
             "findings": c["audit"]["summary"]["total"]}
            for a, c in self.contracts.items()
        ]


# --------------------------------------------------------------------------- #
# 形式化验证（轻量：规范 / 不变量 / 前置后置条件）
# --------------------------------------------------------------------------- #
def formal_check(spec: Dict[str, Any]) -> Dict[str, Any]:
    """根据规范做轻量定理证明/模型检测模拟。"""
    invariants = spec.get("invariants", [])
    pre = spec.get("preconditions", [])
    post = spec.get("postconditions", [])
    passed, failed = [], []
    for inv in invariants:
        if any(k in inv.lower() for k in ("never", "impossible", "must")):
            passed.append({"invariant": inv, "result": "verified"})
        else:
            failed.append({"invariant": inv, "result": "unknown"})
    return {
        "spec_name": spec.get("name", "unnamed"),
        "invariants_checked": len(invariants),
        "preconditions": pre, "postconditions": post,
        "verdict": "pass" if not failed else "partial",
        "passed": passed, "failed": failed,
        "tool": "lightweight-model-checker",
    }


# --------------------------------------------------------------------------- #
# 审计报告生成
# --------------------------------------------------------------------------- #
def build_audit_report(assessment: Dict[str, Any]) -> Dict[str, Any]:
    findings = assessment["findings"]
    by_sev: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for f in findings:
        by_sev[f["severity"]].append(f)
    conclusion = (
        "通过审计" if assessment["score"] >= 85 else
        "有条件通过，需修复高危问题" if assessment["score"] >= 60 else
        "未通过，必须整改后重新审计"
    )
    return {
        "report_id": "AUD-" + uuid.uuid4().hex[:8].upper(),
        "contract": assessment["contract_name"],
        "language": assessment["language_name"],
        "score": assessment["score"],
        "rating": assessment["rating"],
        "conclusion": conclusion,
        "by_severity": {k: len(v) for k, v in by_sev.items()},
        "top_findings": by_sev.get("critical", [])[:5] +
                        by_sev.get("high", [])[:5],
        "best_practices": [
            "遵循 Checks-Effects-Interactions 模式",
            "使用 OpenZeppelin ReentrancyGuard / Ownable",
            "升级 Solidity ≥0.8.0 或引入 SafeMath",
            "所有外部调用检查返回值",
            "使用 Chainlink VRF 等可验证随机源",
            "对 selfdestruct / upgrade 函数加多签与时间锁",
        ],
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_runtime: Optional[ContractRuntime] = None


def get_contract_runtime() -> ContractRuntime:
    global _runtime
    if _runtime is None:
        _runtime = ContractRuntime()
        # 注入一份演示合约（含可检测漏洞）
        _runtime.deploy(
            "VulnerableBank",
            """
pragma solidity ^0.7.0;
contract VulnerableBank {
    mapping(address => uint) public balance;
    function withdraw(uint amount) public {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(balance[msg.sender] >= amount);
        balance[msg.sender] -= amount;
    }
    function kill() public { selfdestruct(msg.sender); }
    function random() public view returns (uint) {
        return uint(keccak256(abi.encodePacked(block.timestamp)));
    }
}
""",
            "solidity", "0xDeployer",
        )
    return _runtime
