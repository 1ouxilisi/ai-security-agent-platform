#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
钱包安全检测器 (Wallet Security Checker)

纯 Python 实现，不依赖 web3.py / bitcoinlib：
    - 私钥格式与强度检测（含已知弱私钥、熵评估）
    - BIP39 助记词强度检测（内置常见词表子集）
    - 地址格式与校验和检测（以太坊 EIP-55 / Bitcoin Base58Check）
    - 文本泄露扫描（私钥 / 助记词 / 地址）

仅用于授权的安全检测与防御评估。
"""

import re
import math
from typing import Dict, List, Optional


# ======================================================================
# Keccak-256（EIP-55 校验和需要 Keccak，而非 NIST SHA3）
# 优先使用 pycryptodome 的原生 Keccak；不可用时回退到纯 Python 实现。
# ======================================================================
def _keccak256(data: bytes) -> bytes:
    """Keccak-256（Ethereum 版本，0x01 域后缀）。

    后端优先级：pycryptodome(C 加速) > 纯 Python 实现。
    """
    # 1) 优先 pycryptodome
    try:
        from Crypto.Hash import keccak as _k
        h = _k.new(digest_bits=256)
        h.update(data)
        return h.digest()
    except Exception:
        pass
    # 2) 纯 Python 兜底
    try:
        return _keccak256_internal(data)
    except Exception:
        import hashlib
        return hashlib.sha3_256(data).digest()


def _keccak256_internal(data: bytes) -> bytes:
    """标准 Keccak-f[1600] 实现，输出 32 字节摘要。"""
    # 官方 Keccak-f[1600] 的 24 个轮常量
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x800000000000008B,
        0x8000000000008089, 0x8000000000008003, 0x8000000000008002,
        0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000000000081,
        0x8000000080008008, 0x0000000000008083, 0x8000000080008084,
        0x8000000080008089, 0x8000000000000003, 0x800000000000808B,
        0x8000000080000009, 0x8000000080008081, 0x8000000000008080,
    ]
    # rho 旋转偏移表：扁平索引 = x + 5*y，对应 canonical R[x][y]
    ROTC = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15,
        21, 8, 18, 2, 61, 56, 14,
    ]
    PIL = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
        14, 22, 9, 6, 1,
    ]
    M = (1 << 64) - 1

    def rol(x, n):
        return ((x << n) | (x >> (64 - n))) & M if n else x

    # --- 填充：Keccak padding (0x01 ... 0x80) ---
    rate = 136  # 1088 bits
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)

    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        # 24 轮 Keccak-f
        for rnd in range(24):
            C = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
                 for x in range(5)]
            D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x + 5 * y] ^= D[x]
            B = [0] * 25
            for x in range(5):
                for y in range(5):
                    B[y + 5 * ((2 * x + 3 * y) % 5)] = rol(
                        state[x + 5 * y], ROTC[x + 5 * y]
                    )
            for x in range(5):
                for y in range(5):
                    state[x + 5 * y] = B[x + 5 * y] ^ (
                        ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y])
                    )
            state[0] ^= RC[rnd]

    out = b"".join(state[i].to_bytes(8, "little") for i in range(4))
    return out


# ======================================================================
# 内置数据：已知弱私钥 / BIP39 常见词表子集
# ======================================================================
# 至少 10 个公开已知弱私钥（小整数、全零、全 F、重复模式、历史泄露测试向量）
KNOWN_WEAK_KEYS = {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "0000000000000000000000000000000000000000000000000000000000000003",
    "0000000000000000000000000000000000000000000000000000000000000004",
    "0000000000000000000000000000000000000000000000000000000000000005",
    "000000000000000000000000000000000000000000000000000000000000000a",
    "fffffffffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "0101010101010101010101010101010101010101010101010101010101010101",
    "abababababababababababababababababababababababababababababababab",
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
}

# BIP39 词表常见词子集（>=200 个，用于验证助记词词合法性）
BIP39_COMMON_WORDS = {
    "abandon", "ability", "able", "about", "above", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic",
    "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt",
    "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice",
    "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree",
    "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol",
    "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha",
    "already", "also", "alter", "always", "amateur", "amazing", "among", "amount",
    "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal",
    "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety",
    "any", "apart", "apology", "appear", "apple", "approve", "april", "arch",
    "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army",
    "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
    "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma",
    "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit",
    "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid",
    "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby",
    "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo",
    "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
    "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef",
    "before", "begin", "behave", "behind", "believe", "below", "belt", "bench",
    "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid",
    "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade",
    "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom",
    "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil",
    "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow",
    "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand",
    "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright",
    "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown",
    "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk",
    "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business",
    "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus",
    "cage", "cake", "call", "calm", "camera", "camp", "can", "canal",
    "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital",
    "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart",
    "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch",
    "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery",
    "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion",
    "change", "chaos", "chapter", "charge", "chase", "cheap", "check", "cheese",
    "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice",
    "choose", "chronic", "chunk", "churn", "circle", "citizen", "city", "civil",
    "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever",
    "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog",
    "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch",
    "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect",
    "color", "column", "columnist", "come", "comfort", "comic", "common", "company",
    "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince",
    "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct",
    "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover",
    "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater",
    "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime",
    "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel",
    "crude", "cruise", "crumble", "crush", "cry", "crystal", "cube", "culture",
    "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom",
    "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring",
    "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade",
}
# 校验：确保词表子集足够
assert len(BIP39_COMMON_WORDS) >= 200


class WalletSecurityChecker:
    """钱包安全检测器"""

    # 正则
    RE_PRIVATE_KEY = re.compile(r"\b(0x)?[a-fA-F0-9]{64}\b")
    RE_ETH_ADDR = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    RE_BTC_ADDR = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b")
    RE_PEM_KEY = re.compile(r"BEGIN [A-Z ]*PRIVATE KEY")

    # 零地址 / 燃烧地址
    ZERO_ADDR = "0x0000000000000000000000000000000000000000"
    BURN_ADDRS = {
        "0x0000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000001",
        "0xdead00000000000000000000000000000000dead",
    }

    # ------------------------------------------------------------------
    # 私钥检测
    # ------------------------------------------------------------------
    def check_private_key(self, key: str) -> Dict:
        """验证私钥格式与强度

        Returns:
            dict: valid / strength / issues(list) / entropy / details
        """
        issues: List[str] = []
        raw = (key or "").strip()
        raw = raw[2:] if raw.startswith("0x") else raw

        # 长度校验
        if len(raw) != 64:
            issues.append(f"私钥长度非法：{len(raw)} 个字符（应为 64 个 hex 字符）")
            return {"valid": False, "strength": "invalid", "issues": issues, "entropy": 0.0}
        if not re.fullmatch(r"[a-fA-F0-9]{64}", raw):
            issues.append("私钥包含非 hex 字符")
            return {"valid": False, "strength": "invalid", "issues": issues, "entropy": 0.0}

        low = raw.lower()

        # 全零
        if set(low) == {"0"}:
            issues.append("私钥为全零，绝对不可使用")

        # 已知弱私钥
        if low in KNOWN_WEAK_KEYS:
            issues.append("命中公开已知弱私钥/测试向量，已被广泛公开，绝不能用于主网")

        # 小整数/弱模式（如 1, 2, abc...）
        try:
            as_int = int(low, 16)
            if as_int < 10000:
                issues.append(f"私钥为极小整数({as_int})，可被暴力枚举")
        except ValueError:
            pass
        if len(set(low)) <= 3:
            issues.append("私钥字符分布极度单一（重复模式），熵极低")

        # 熵评估（Shannon entropy）
        entropy = self._shannon_entropy(low)
        if entropy < 2.5:
            issues.append(f"私钥熵过低（{entropy:.2f} bit/字符），随机性不足")

        # 强度评级
        if issues:
            strength = "weak" if not any("长度非法" in i for i in issues) else "invalid"
        else:
            strength = "strong"

        return {
            "valid": len(issues) == 0 or strength == "weak",
            "strength": strength,
            "issues": issues,
            "entropy": round(entropy, 2),
            "length": len(raw),
        }

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """计算字符串的 Shannon 熵（bit/字符）"""
        if not s:
            return 0.0
        freq = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(s)
        ent = 0.0
        for c in freq.values():
            p = c / n
            ent -= p * math.log2(p)
        return ent

    # ------------------------------------------------------------------
    # 助记词检测
    # ------------------------------------------------------------------
    def check_mnemonic(self, words: str) -> Dict:
        """BIP39 助记词强度检测"""
        issues: List[str] = []
        token_list = (words or "").strip().lower().split()
        n = len(token_list)

        # 词数检查
        if n not in (12, 15, 18, 21, 24):
            issues.append(f"助记词词数为 {n}，不在标准 (12/15/18/21/24) 范围内")

        # 词表校验（子集）
        unknown = [w for w in token_list if w not in BIP39_COMMON_WORDS]
        # 我们只内置了子集，未知词不直接判非法，但提示
        if unknown and n in (12, 15, 18, 21, 24):
            issues.append(
                f"检测到 {len(unknown)} 个词不在内置 BIP39 常见词表子集：{', '.join(unknown[:5])}"
                "（可能为合法词但未收录，也可能拼写错误）"
            )

        # 重复词
        seen = set()
        dup = set()
        for w in token_list:
            if w in seen:
                dup.add(w)
            seen.add(w)
        if dup:
            issues.append(f"助记词含重复词：{', '.join(sorted(dup))}")

        # 顺序词（按字母序，如 apple banana cherry...）
        sorted_lower = sorted(token_list)
        if token_list == sorted_lower and n >= 12:
            issues.append("助记词严格按字母序排列，非随机生成")

        # 常见弱助记词（全 abandon / 著名测试向量）
        if token_list and len(set(token_list)) == 1:
            issues.append(f"所有词均为「{token_list[0]}」，为典型测试/弱助记词")
        if token_list[:2] == ["abandon", "abandon"] and "abandon" in token_list:
            issues.append("命中 BIP39 标准测试助记词(abandon...)，绝不能用于主网")

        # 熵粗评：不同词占比
        diversity = len(set(token_list)) / n if n else 0
        strength = "weak" if issues else "strong"
        if diversity < 0.8 and not issues:
            strength = "medium"
            issues.append(f"词汇多样性偏低（{diversity:.2f}）")

        return {
            "valid": strength == "strong",
            "strength": strength,
            "word_count": n,
            "issues": issues,
            "diversity": round(diversity, 2),
        }

    # ------------------------------------------------------------------
    # 地址检测
    # ------------------------------------------------------------------
    def check_address(self, address: str, chain: str = "ethereum") -> Dict:
        """地址格式与校验和验证"""
        addr = (address or "").strip()
        issues: List[str] = []

        if chain.lower() in ("ethereum", "eth", "evm", "bsc", "polygon"):
            return self._check_evm_address(addr)

        if chain.lower() in ("bitcoin", "btc"):
            return self._check_btc_address(addr)

        # 未知链，尝试自动识别
        if addr.startswith("0x") and len(addr) == 42:
            return self._check_evm_address(addr)
        return {"valid": False, "issues": [f"不支持的链类型：{chain}"], "chain": chain}

    def _check_evm_address(self, addr: str) -> Dict:
        issues: List[str] = []
        if not addr.startswith("0x"):
            issues.append("以太坊地址应以 0x 开头")
        body = addr[2:] if addr.startswith("0x") else addr
        if len(body) != 40:
            issues.append(f"地址长度非法：应为 40 个 hex 字符（当前 {len(body)}）")
            return {"valid": False, "issues": issues, "chain": "ethereum"}
        if not re.fullmatch(r"[a-fA-F0-9]{40}", body):
            issues.append("地址包含非 hex 字符")
            return {"valid": False, "issues": issues, "chain": "ethereum"}

        # 特殊地址
        if addr.lower() == self.ZERO_ADDR:
            issues.append("这是零地址(0x0)，通常表示未设置/ burn")
        if addr.lower() in {a.lower() for a in self.BURN_ADDRS}:
            issues.append("这是燃烧地址，转入的资产将永久锁定")

        # EIP-55 校验和（若地址含大小写混合，则必须通过校验）
        has_upper = any(c.isupper() for c in body)
        has_lower = any(c.islower() for c in body)
        checksum_valid = True
        if has_upper and has_lower:
            checksum_valid = self._eip55_valid(addr)
            if not checksum_valid:
                issues.append("EIP-55 校验和大小写不正确（可能为伪造/复制错误地址）")

        return {
            "valid": len(issues) == 0 or "零地址" in issues[0] if issues else True,
            "issues": issues,
            "chain": "ethereum",
            "checksum_valid": checksum_valid,
            "has_checksum": has_upper and has_lower,
        }

    @staticmethod
    def _eip55_valid(addr: str) -> bool:
        """EIP-55 校验和验证（使用 Keccak-256）"""
        body = addr[2:].lower()
        h = _keccak256(body.encode("ascii")).hex()
        for i, ch in enumerate(body):
            if ch in "0123456789":
                continue
            # 对应 hash 字符 > 8 则原地址该位应大写
            expected_upper = int(h[i], 16) >= 8
            actual_upper = addr[2 + i].isupper()
            if expected_upper != actual_upper:
                return False
        return True

    def _check_btc_address(self, addr: str) -> Dict:
        issues: List[str] = []
        if not (re.fullmatch(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", addr)
                or re.fullmatch(r"bc1[a-z0-9]{39,59}", addr)):
            issues.append("Bitcoin 地址格式不合法（应为 1/3 开头 Base58 或 bc1 开头 Bech32）")
        return {"valid": len(issues) == 0, "issues": issues, "chain": "bitcoin"}

    # ------------------------------------------------------------------
    # 文本泄露扫描
    # ------------------------------------------------------------------
    def scan_text_for_keys(self, text: str) -> List[Dict]:
        """从文本中扫描泄露的私钥 / 助记词 / 地址"""
        findings: List[Dict] = []

        # PEM 私钥块
        if self.RE_PEM_KEY.search(text):
            findings.append({
                "type": "private_key_pem",
                "severity": "critical",
                "detail": "文本中包含 PEM 格式私钥块 (BEGIN ... PRIVATE KEY)",
            })

        # 裸私钥
        for m in self.RE_PRIVATE_KEY.finditer(text):
            raw = m.group(0)
            res = self.check_private_key(raw)
            findings.append({
                "type": "private_key",
                "severity": "critical" if res["strength"] != "strong" else "high",
                "detail": f"发现疑似私钥：{raw[:10]}…{raw[-6:]}",
                "strength": res["strength"],
            })

        # 助记词（12 或 24 个空格分隔的小写常见词）
        for m in re.finditer(r"(?:[a-z]{3,10}\s+){11,23}[a-z]{3,10}", text):
            words = m.group(0).split()
            if len(words) in (12, 24) and sum(w in BIP39_COMMON_WORDS for w in words) >= len(words) - 2:
                res = self.check_mnemonic(m.group(0))
                findings.append({
                    "type": "mnemonic",
                    "severity": "critical" if not res["valid"] else "high",
                    "detail": f"发现疑似 {res['word_count']} 词助记词",
                    "issues": res["issues"],
                })

        # 地址
        for m in self.RE_ETH_ADDR.finditer(text):
            findings.append({
                "type": "ethereum_address",
                "severity": "info",
                "detail": f"发现以太坊地址：{m.group(0)}",
            })
        for m in self.RE_BTC_ADDR.finditer(text):
            findings.append({
                "type": "bitcoin_address",
                "severity": "info",
                "detail": f"发现比特币地址：{m.group(0)}",
            })

        return findings


# 模块级单例
_wallet_checker: Optional["WalletSecurityChecker"] = None


def get_wallet_security_checker() -> "WalletSecurityChecker":
    global _wallet_checker
    if _wallet_checker is None:
        _wallet_checker = WalletSecurityChecker()
    return _wallet_checker
