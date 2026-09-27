#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能合约静态分析器 (Smart Contract Static Analyzer)

基于正则表达式 + 行级分析 + 函数块切分，对 Solidity 源码进行真实的静态扫描。
不依赖 web3.py / slither 等外部库，纯 Python 实现。

检测漏洞类型（>=10 种）：
    1.  重入攻击 (Reentrancy)
    2.  整数溢出/下溢 (Integer Overflow/Underflow)
    3.  访问控制缺陷 (Access Control)
    4.  未检查返回值 (Unchecked Return Value)
    5.  时间戳依赖 (Timestamp Dependency)
    6.  区块号依赖 (Block Number Dependency)
    7.  短地址攻击 (Short Address Attack)
    8.  delegatecall 风险 (delegatecall to Untrusted Callee)
    9.  强制接收 ETH / 依赖 address(this).balance
    10. DoS with Revert（循环内外部调用）
    11. 未初始化存储指针 (Uninitialized Storage Pointer)
    12. 硬编码地址 (Hardcoded Address)
    13. 可自杀合约 (selfdestruct / suicide)
    14. 缺少事件日志 (Missing Event)

仅用于授权的安全审计与防御评估。
"""

import re
from typing import Dict, List, Optional, Tuple


class SmartContractAnalyzer:
    """Solidity 智能合约静态分析器

    用法：
        analyzer = SmartContractAnalyzer()
        findings = analyzer.analyze(source_code, "VulnerableBank")
    """

    # ---------- 正则预编译 ----------
    # 外部转账调用
    RE_EXTERNAL_VALUE_CALL = re.compile(
        r"(\.call\{value\s*:|\.call\.value\s*\(|\.transfer\s*\(|\.send\s*\()"
    )
    RE_LOW_LEVEL_CALL = re.compile(r"\.call\s*[\(\{]")
    RE_SEND = re.compile(r"\.send\s*\(")
    # 函数声明
    RE_FUNC_DECL = re.compile(
        r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*"
        r"((?:public|private|internal|external|virtual|override|view|pure|"
        r"payable|constant|memory|storage|calldata|\s|:|;)*?)\{"
    )
    # 权限修饰器
    RE_MODIFIER = re.compile(r"modifier\s+([A-Za-z_]\w*)\s*\(")
    # tx.origin 认证
    RE_TX_ORIGIN_AUTH = re.compile(r"require\s*\(\s*tx\.origin\s*==")
    # 时间戳
    RE_TIMESTAMP = re.compile(r"block\.timestamp|\bnow\b")
    # 区块号
    RE_BLOCKNUMBER = re.compile(r"block\.number")
    # 随机数
    RE_RANDOM = re.compile(r"random|rand|seed|nonce", re.IGNORECASE)
    # delegatecall
    RE_DELEGATECALL = re.compile(r"\.delegatecall\s*\(")
    # selfdestruct
    RE_SELFDESTRUCT = re.compile(r"selfdestruct\s*\(|\bsuicide\s*\(")
    # 硬编码地址 0x + 40 hex
    RE_HARDCODED_ADDR = re.compile(r"0x[a-fA-F0-9]{40}")
    # address(this).balance
    RE_THIS_BALANCE = re.compile(r"address\s*\(\s*this\s*\)\s*\.balance")
    # unchecked 块
    RE_UNCHECKED = re.compile(r"unchecked\s*\{")
    # SafeMath 使用
    RE_SAFEMATH_USE = re.compile(r"\b(safeAdd|safeSub|safeMul|safeDiv|\.add\s*\(|\.sub\s*\(|\.mul\s*\(|\.div\s*\()")
    # 状态变量余额更新（重入判定用）
    RE_BALANCE_UPDATE = re.compile(
        r"(balance|balances|credited|withdrawn|debt|locked)\s*\[[^\]]*\]\s*[-+]?="
    )

    # 关键函数名（需要权限保护）
    CRITICAL_FUNCTIONS = {
        "mint", "burn", "transfer", "transferFrom", "withdraw", "withdrawAll",
        "selfdestruct", "suicide", "setOwner", "setFee", "approve", "upgradeTo",
        "deposit", "execute", "claimFees",
    }

    def __init__(self):
        self.source: str = ""
        self.lines: List[str] = []

    # ======================================================================
    # 公共入口
    # ======================================================================
    def analyze(self, source_code: str, contract_name: str = "") -> List[Dict]:
        """对 Solidity 源码执行完整静态分析

        Args:
            source_code: Solidity 源码字符串
            contract_name: 合约名（仅用于报告标注，可空）

        Returns:
            发现列表，每项为 Dict，包含：
            type / severity / description / line / location /
            code_snippet / recommendation / cwe
        """
        self.source = source_code or ""
        self.lines = self.source.split("\n")
        findings: List[Dict] = []

        if not self.source.strip():
            return findings

        # 解析 Solidity 版本
        pragma_version = self._detect_pragma_version()

        # 切分所有函数块（用于需要函数上下文的检测）
        function_blocks = self._extract_function_blocks()

        # 依次执行各检测器
        findings.extend(self._detect_reentrancy(function_blocks))
        findings.extend(self._detect_integer_overflow(pragma_version))
        findings.extend(self._detect_access_control(function_blocks))
        findings.extend(self._detect_unchecked_return_value())
        findings.extend(self._detect_timestamp_dependency())
        findings.extend(self._detect_blocknumber_dependency())
        findings.extend(self._detect_short_address_attack(function_blocks))
        findings.extend(self._detect_delegatecall())
        findings.extend(self._detect_forced_eth())
        findings.extend(self._detect_dos_with_revert(function_blocks))
        findings.extend(self._detect_uninitialized_storage(pragma_version))
        findings.extend(self._detect_hardcoded_address())
        findings.extend(self._detect_selfdestruct())
        findings.extend(self._detect_missing_event(function_blocks))

        return findings

    # ======================================================================
    # 工具方法
    # ======================================================================
    def _detect_pragma_version(self) -> Optional[Tuple[int, int]]:
        """从 pragma 语句解析 Solidity 主版本号，返回 (major, minor)，失败返回 None"""
        m = re.search(r"pragma\s+solidity\s*\^?\s*(\d+)\.(\d+)\.\d+", self.source)
        if m:
            return (int(m.group(1)), int(m.group(2)))
        return None

    def _extract_function_blocks(self) -> List[Dict]:
        """将源码按函数切分，返回每个函数的行号区间与函数体文本

        Returns:
            list of dict: {name, decl_line, start_line, end_line, body, modifiers}
        """
        blocks: List[Dict] = []
        # 先找所有函数声明行
        for idx, line in enumerate(self.lines):
            m = self.RE_FUNC_DECL.search(line)
            if not m:
                continue
            func_name = m.group(1)
            # 从声明行起做花括号配对，确定函数体范围
            start_line = idx
            depth = 0
            opened = False
            end_line = idx
            # 拼接从该行开始的剩余文本做括号配对
            joined = "\n".join(self.lines[idx:])
            brace_count = 0
            started = False
            last = len(joined)
            for ch_idx, ch in enumerate(joined):
                if ch == "{":
                    brace_count += 1
                    started = True
                elif ch == "}":
                    brace_count -= 1
                if started and brace_count == 0:
                    last = ch_idx
                    break
            # 将偏移换算成行号
            head = joined[: last + 1]
            offset_lines = head.count("\n")
            end_line = start_line + offset_lines
            body = "\n".join(self.lines[start_line:end_line + 1])
            # 提取修饰器（函数签名中紧跟 ) 之后、{ 之前的部分）
            sig = m.group(3) or ""
            mods = [
                token for token in re.findall(r"[A-Za-z_]\w*", sig)
                if token not in (
                    "public", "private", "internal", "external", "virtual",
                    "override", "view", "pure", "payable", "constant", "memory",
                    "storage", "calldata",
                )
            ]
            blocks.append({
                "name": func_name,
                "decl_line": start_line + 1,
                "start_line": start_line + 1,
                "end_line": end_line + 1,
                "body": body,
                "modifiers": mods,
            })
        return blocks

    @staticmethod
    def _make(ftype: str, severity: str, description: str, line: int,
              code_snippet: str, recommendation: str, cwe: str) -> Dict:
        """构造统一发现项字典"""
        return {
            "type": ftype,
            "severity": severity,
            "description": description,
            "line": line,
            "location": f"Line {line}",
            "code_snippet": (code_snippet or "").strip()[:240],
            "recommendation": recommendation,
            "cwe": cwe,
        }

    # ======================================================================
    # 检测器 1：重入攻击
    # ======================================================================
    def _detect_reentrancy(self, function_blocks: List[Dict]) -> List[Dict]:
        """检测重入：外部转账调用出现在状态更新之前"""
        findings: List[Dict] = []
        for fb in function_blocks:
            body_lines = fb["body"].split("\n")
            base = fb["decl_line"] - 1
            call_positions: List[Tuple[int, str]] = []   # (相对行偏移, 调用文本)
            state_update_positions: List[int] = []       # 相对行偏移
            for off, bl in enumerate(body_lines):
                if self.RE_EXTERNAL_VALUE_CALL.search(bl):
                    call_positions.append((off, bl.strip()))
                if self.RE_BALANCE_UPDATE.search(bl):
                    state_update_positions.append(off)

            for off, call_text in call_positions:
                # 状态更新发生在外部调用之后 => 经典重入（检查-生效-交互被违反）
                later_updates = [u for u in state_update_positions if u > off]
                if later_updates:
                    line_no = base + off + 1
                    findings.append(self._make(
                        "重入攻击 (Reentrancy)", "critical",
                        f"函数 {fb['name']} 在外部转账调用之后才更新余额/状态，"
                        f"攻击者可利用回调在状态更新前重复提现。",
                        line_no, call_text,
                        "遵循检查-生效-交互(Checks-Effects-Interactions)模式："
                        "先更新所有状态变量，最后再做外部调用；或使用重入锁(ReentrancyGuard)。",
                        "CWE-841",
                    ))
        return findings

    # ======================================================================
    # 检测器 2：整数溢出 / 下溢
    # ======================================================================
    def _detect_integer_overflow(self, pragma_version: Optional[Tuple[int, int]]) -> List[Dict]:
        """检测未受保护的算术运算；Solidity<0.8 默认不溢出检查，0.8+ 默认检查但 unchecked 可关闭"""
        findings: List[Dict] = []
        # 若使用了 SafeMath 则基本放行
        uses_safemath = bool(self.RE_SAFEMATH_USE.search(self.source))
        # unchecked 块：0.8+ 中显式关闭溢出检查
        for idx, line in enumerate(self.lines):
            if self.RE_UNCHECKED.search(line):
                findings.append(self._make(
                    "unchecked 块（整数溢出风险）", "medium",
                    "unchecked 块内关闭了 Solidity 0.8+ 的内置溢出/下溢检查，"
                    "若内部有算术运算则可能溢出。",
                    idx + 1, line,
                    "避免在 unchecked 块中对用户可控输入做算术；"
                    "或显式使用 SafeMath / 手动边界检查。",
                    "CWE-190",
                ))

        # Solidity < 0.8 且未使用 SafeMath：扫描裸算术
        if pragma_version is not None and pragma_version < (0, 8) and not uses_safemath:
            # 匹配 uint/int 变量参与的 + - * / 赋值或表达式
            re_arith = re.compile(
                r"\b(uint\d*|int\d*|uint|int)\b[^;=]*[-+*/]=|[A-Za-z_]\w*\s*[-+*/]\s*[A-Za-z_]"
            )
            for idx, line in enumerate(self.lines):
                stripped = line.strip()
                # 跳过注释行
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue
                if re.search(r"[-+*/]=?[^=]", stripped) and re.search(
                    r"\b(uint|int|balance|amount|total|supply|fee)\w*\b", stripped, re.IGNORECASE
                ):
                    # 只报告前若干个，避免噪声爆炸
                    findings.append(self._make(
                        "整数溢出/下溢 (Integer Overflow)", "high",
                        "Solidity <0.8 默认不做溢出检查，且未检测到 SafeMath 保护，"
                        "此处算术运算可能溢出/下溢。",
                        idx + 1, stripped,
                        "引入 OpenZeppelin SafeMath 库，或升级编译器至 Solidity 0.8+。",
                        "CWE-190",
                    ))
                    break  # 该类只报告一次代表性位置
        return findings

    # ======================================================================
    # 检测器 3：访问控制缺陷
    # ======================================================================
    def _detect_access_control(self, function_blocks: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []
        # 收集定义了的修饰器
        defined_modifiers = {m.group(1) for m in self.RE_MODIFIER.finditer(self.source)}
        # 收集被使用的修饰器
        used_modifiers = set()
        for fb in function_blocks:
            used_modifiers.update(fb["modifiers"])

        # (a) onlyOwner 定义了但从未使用
        if "onlyOwner" in defined_modifiers and "onlyOwner" not in used_modifiers:
            # 找 onlyOwner 定义行
            for idx, line in enumerate(self.lines):
                if "modifier" in line and "onlyOwner" in line:
                    findings.append(self._make(
                        "访问控制：onlyOwner 未使用", "medium",
                        "onlyOwner 修饰器已定义但未应用到任何函数，关键函数可能缺少权限保护。",
                        idx + 1, line,
                        "将 onlyOwner 应用于所有特权函数（mint/withdraw/setOwner 等）。",
                        "CWE-284",
                    ))
                    break

        # (b) 关键函数缺少权限修饰
        for fb in function_blocks:
            if fb["name"] in self.CRITICAL_FUNCTIONS:
                if not fb["modifiers"]:
                    findings.append(self._make(
                        f"访问控制：{fb['name']} 缺少权限修饰器", "high",
                        f"关键函数 {fb['name']} 未应用任何权限修饰器，任何人可能调用。",
                        fb["decl_line"], f"function {fb['name']}(...)",
                        "为特权函数添加 onlyOwner / onlyAdmin 等权限修饰器。",
                        "CWE-284",
                    ))

        # (c) tx.origin 认证
        for idx, line in enumerate(self.lines):
            if self.RE_TX_ORIGIN_AUTH.search(line):
                findings.append(self._make(
                    "tx.origin 认证漏洞", "high",
                    "使用 tx.origin 进行身份认证，易被钓鱼合约利用。",
                    idx + 1, line.strip(),
                    "改用 msg.sender 进行认证，禁止使用 tx.origin 做权限判断。",
                    "CWE-477",
                ))
        return findings

    # ======================================================================
    # 检测器 4：未检查返回值
    # ======================================================================
    def _detect_unchecked_return_value(self) -> List[Dict]:
        findings: List[Dict] = []
        for idx, line in enumerate(self.lines):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            # .send( 或 .call( 返回 bool，未检查即危险
            for pat in (self.RE_SEND, self.RE_LOW_LEVEL_CALL):
                if pat.search(stripped):
                    # 已检查：包在 require(...) 中，或赋值给变量后判断
                    checked = ("require" in stripped) or ("=" in stripped.split("(", 1)[0]) \
                              or re.search(r"=\s*[^=]*\.(send|call)\s*[\(\{]", stripped)
                    if not checked:
                        findings.append(self._make(
                            "未检查外部调用返回值", "medium",
                            ".send/.call 的返回值(bool)未被检查，调用失败会被静默忽略。",
                            idx + 1, stripped,
                            "将返回值传入 require(...)，例如 "
                            "require(addr.call{value: x}(''), 'call failed')。",
                            "CWE-252",
                        ))
        return findings

    # ======================================================================
    # 检测器 5 / 6：时间戳 / 区块号依赖
    # ======================================================================
    def _detect_timestamp_dependency(self) -> List[Dict]:
        findings: List[Dict] = []
        for idx, line in enumerate(self.lines):
            if self.RE_TIMESTAMP.search(line):
                # 若同时出现 random/seed 等，说明用时间戳做随机数，更严重
                critical = bool(self.RE_RANDOM.search(line)) or bool(
                    self.RE_RANDOM.search("\n".join(self.lines[max(0, idx - 3):idx + 3]))
                )
                sev = "high" if critical else "medium"
                findings.append(self._make(
                    "时间戳依赖" + ("（用作随机数）" if critical else ""), sev,
                    "block.timestamp/now 可被矿工在一定范围内操纵，"
                    + ("用于随机数可被预测/操纵。" if critical else "用于关键逻辑存在风险。"),
                    idx + 1, line.strip(),
                    "避免使用 block.timestamp 做随机数；改用 Chainlink VRF 等可验证随机源。",
                    "CWE-330",
                ))
        return findings

    def _detect_blocknumber_dependency(self) -> List[Dict]:
        findings: List[Dict] = []
        for idx, line in enumerate(self.lines):
            if self.RE_BLOCKNUMBER.search(line):
                critical = bool(self.RE_RANDOM.search(line)) or bool(
                    self.RE_RANDOM.search("\n".join(self.lines[max(0, idx - 3):idx + 3]))
                )
                sev = "high" if critical else "low"
                findings.append(self._make(
                    "区块号依赖" + ("（用作随机数）" if critical else ""), sev,
                    "block.number 可被矿工/时序操纵"
                    + ("用作随机数时尤其危险。" if critical else "。"),
                    idx + 1, line.strip(),
                    "不要用 block.number 生成随机数，使用可信随机源。",
                    "CWE-330",
                ))
        return findings

    # ======================================================================
    # 检测器 7：短地址攻击（ERC20 transfer 缺少长度校验）
    # ======================================================================
    def _detect_short_address_attack(self, function_blocks: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []
        for fb in function_blocks:
            if fb["name"] not in ("transfer", "transferFrom"):
                continue
            # 若函数体内未对输入长度做 ABI 编码校验（现代 ABI 一般已免疫，
            # 但老式内联汇编/手动解码仍可能中招），给出提示
            body = fb["body"]
            if "abi.decode" not in body and "assembly" not in body:
                # 现代 ABI 自动校验，仅作为低危提示
                findings.append(self._make(
                    "短地址攻击风险提示", "low",
                    f"ERC20 {fb['name']} 函数请确认接收方参数经过 ABI 长度校验，"
                    f"老式合约需防范短地址攻击。",
                    fb["decl_line"], f"function {fb['name']}(...)",
                    "使用标准 ABI 编码/解码，避免手动拼接 calldata；"
                    "现代 Solidity ABI 解码器自带长度校验。",
                    "CWE-20",
                ))
        return findings

    # ======================================================================
    # 检测器 8：delegatecall 风险
    # ======================================================================
    def _detect_delegatecall(self) -> List[Dict]:
        findings: List[Dict] = []
        for idx, line in enumerate(self.lines):
            if self.RE_DELEGATECALL.search(line):
                # 若目标是变量（非硬编码地址），则为不可信目标
                m = re.search(r"\.delegatecall\s*\(\s*([^)]*)\)", line)
                target = m.group(1) if m else ""
                is_dynamic = not self.RE_HARDCODED_ADDR.search(target)
                sev = "critical" if is_dynamic else "medium"
                findings.append(self._make(
                    "delegatecall 风险" + ("（动态目标）" if is_dynamic else ""), sev,
                    "delegatecall 在调用者存储上下文中执行代码，"
                    + ("目标地址为动态变量，若可控则可篡改本合约存储/所有权。"
                       if is_dynamic else "目标为固定地址，仍需确保目标合约可信。"),
                    idx + 1, line.strip(),
                    "delegatecall 目标必须是经过审计的固定可信地址；"
                    "避免对用户可控地址使用 delegatecall。",
                    "CWE-829",
                ))
        return findings

    # ======================================================================
    # 检测器 9：依赖 address(this).balance
    # ======================================================================
    def _detect_forced_eth(self) -> List[Dict]:
        findings: List[Dict] = []
        for idx, line in enumerate(self.lines):
            if self.RE_THIS_BALANCE.search(line):
                findings.append(self._make(
                    "强制接收 ETH / 依赖合约余额", "medium",
                    "使用 address(this).balance 做逻辑判断，"
                    "攻击者可通过 selfdestruct 强制向合约转入 ETH 破坏余额假设。",
                    idx + 1, line.strip(),
                    "不要用 address(this).balance 做业务判断，改用内部记账变量。",
                    "CWE-693",
                ))
        return findings

    # ======================================================================
    # 检测器 10：循环内外部调用（DoS with Revert）
    # ======================================================================
    def _detect_dos_with_revert(self, function_blocks: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []
        for fb in function_blocks:
            body_lines = fb["body"].split("\n")
            base = fb["decl_line"] - 1
            in_loop = False
            loop_depth = 0
            for off, bl in enumerate(body_lines):
                if re.search(r"\b(for|while)\s*\(", bl):
                    in_loop = True
                    loop_depth = bl.count("{") - bl.count("}")
                elif in_loop:
                    if self.RE_EXTERNAL_VALUE_CALL.search(bl) or self.RE_LOW_LEVEL_CALL.search(bl):
                        findings.append(self._make(
                            "循环内外部调用 (DoS)", "high",
                            f"函数 {fb['name']} 在循环内对外部地址进行调用，"
                            f"任一地址 revert 会导致整个循环失败，形成 DoS。",
                            base + off + 1, bl.strip(),
                            "将外部调用移出循环（pull-over-push 模式），让用户主动提现；"
                            "或限制循环长度并捕获失败。",
                            "CWE-400",
                        ))
                    loop_depth += bl.count("{") - bl.count("}")
                    if loop_depth <= 0 and "{" not in bl:
                        in_loop = False
        return findings

    # ======================================================================
    # 检测器 11：未初始化存储指针
    # ======================================================================
    def _detect_uninitialized_storage(self, pragma_version: Optional[Tuple[int, int]]) -> List[Dict]:
        findings: List[Dict] = []
        # 仅对 Solidity <0.5 有意义（0.5+ 强制显式指定 data location）
        if pragma_version is not None and pragma_version >= (0, 5):
            return findings
        # 匹配 "SomeData storage x;" 但未在同一行赋值
        re_storage = re.compile(r"(\w+)\s+storage\s+(\w+)\s*;")
        for idx, line in enumerate(self.lines):
            m = re_storage.search(line)
            if m and "=" not in line:
                findings.append(self._make(
                    "未初始化存储指针", "high",
                    "storage 类型局部变量未初始化，会指向槽位 0，"
                    "可被利用篡改合约存储。",
                    idx + 1, line.strip(),
                    "对所有 storage 指针显式初始化；升级到 Solidity 0.5+。",
                    "CWE-908",
                ))
        return findings

    # ======================================================================
    # 检测器 12：硬编码地址
    # ======================================================================
    def _detect_hardcoded_address(self) -> List[Dict]:
        findings: List[Dict] = []
        seen = set()
        for idx, line in enumerate(self.lines):
            for m in self.RE_HARDCODED_ADDR.finditer(line):
                addr = m.group(0)
                if addr in seen:
                    continue
                seen.add(addr)
                # 零地址/已知占位地址降级为信息
                if addr.lower() == "0x0000000000000000000000000000000000000000":
                    continue
                findings.append(self._make(
                    "硬编码地址", "low",
                    "源码中硬编码以太坊地址，地址变更需重新部署合约。",
                    idx + 1, line.strip(),
                    "将关键地址设为可配置（构造函数/setter/代理），避免硬编码。",
                    "CWE-798",
                ))
        return findings

    # ======================================================================
    # 检测器 13：可自杀合约
    # ======================================================================
    def _detect_selfdestruct(self) -> List[Dict]:
        findings: List[Dict] = []
        for idx, line in enumerate(self.lines):
            if self.RE_SELFDESTRUCT.search(line):
                findings.append(self._make(
                    "可自杀合约 (selfdestruct)", "high",
                    "合约可被 selfdestruct/suicide 销毁，若权限控制不当可导致资金/逻辑终止。",
                    idx + 1, line.strip(),
                    "严格限制 selfdestruct 的调用权限；优先使用可升级/治理机制而非销毁。",
                    "CWE-284",
                ))
        return findings

    # ======================================================================
    # 检测器 14：关键状态变更缺少事件日志
    # ======================================================================
    def _detect_missing_event(self, function_blocks: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []
        # 全文中定义的 event
        declared_events = {m.group(1) for m in re.finditer(r"event\s+(\w+)\s*\(", self.source)}
        for fb in function_blocks:
            if fb["name"] not in self.CRITICAL_FUNCTIONS:
                continue
            body = fb["body"]
            has_emit = bool(re.search(r"\bemit\s+\w+", body)) or bool(
                re.search(r"\b(Transfer|Approval|Mint|Burn)\s*\(", body)
            )
            if not has_emit and fb["name"] in (
                "mint", "burn", "transfer", "transferFrom", "withdraw", "setOwner", "setFee"
            ):
                findings.append(self._make(
                    "关键操作缺少事件日志", "low",
                    f"函数 {fb['name']} 修改了关键状态但未 emit 事件，链下监控无法感知。",
                    fb["decl_line"], f"function {fb['name']}(...)",
                    "为所有关键状态变更添加并 emit 对应事件。",
                    "CWE-778",
                ))
        return findings


# 模块级便捷单例
_analyzer: Optional[SmartContractAnalyzer] = None


def get_smart_contract_analyzer() -> SmartContractAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = SmartContractAnalyzer()
    return _analyzer
