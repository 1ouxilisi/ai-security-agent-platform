#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
advanced_password_cracking安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import asyncio
import hashlib
import json
import os
import random
import re
import struct
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from loguru import logger


@dataclass
class HashInfo:
    """哈希信息"""
    hash_value: str
    hash_type: str  # md5/sha1/sha256/ntlm/bcrypt/...
    username: str = ""
    domain: str = ""
    salt: str = ""
    cracked: bool = False
    plaintext: str = ""
    crack_time: float = 0.0
    crack_method: str = ""


@dataclass
class PasswordPolicy:
    """密码策略"""
    min_length: int = 8
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = False
    max_length: int = 128
    history_count: int = 5
    max_age_days: int = 90


@dataclass
class PasswordStrength:
    """密码强度"""
    password: str
    length: int
    entropy: float
    score: int  # 0-100
    strength: str  # very_weak/weak/medium/strong/very_strong
    crack_time: str
    issues: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


@dataclass
class DictionaryConfig:
    """字典配置"""
    base_words: List[str] = field(default_factory=list)
    min_length: int = 4
    max_length: int = 16
    leet_replace: bool = True
    number_suffix: bool = True
    special_suffix: bool = False
    year_suffix: bool = True
    case_variations: bool = True
    max_size: int = 1000000


@dataclass
class CrackingResult:
    """破解结果"""
    total_hashes: int = 0
    cracked: int = 0
    failed: int = 0
    success_rate: float = 0.0
    total_time: float = 0.0
    hashes_per_second: float = 0.0
    cracked_passwords: List[HashInfo] = field(default_factory=list)
    uncracked_hashes: List[HashInfo] = field(default_factory=list)
    method: str = ""
    dictionary_size: int = 0
    summary: str = ""


class AdvancedPasswordCracker:
    """高级密码破解器"""

    def __init__(self, config: Optional[Dict] = None):
        """初始化AdvancedPasswordCracker实例。

        Args:
            self: 类实例。
        """
        self.config = config or {}
        self.hashcat_path = self.config.get("hashcat_path", "hashcat")
        self.workload_profile = self.config.get("workload_profile", 3)
        self.common_passwords = self._load_common_passwords()
        self.leet_map = {
            'a': ['4', '@'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7'],
            'l': ['1'],
        }
        self.special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '?']
        self.hash_types = {
            0: "MD5",
            100: "SHA1",
            1400: "SHA256",
            1700: "SHA512",
            1000: "NTLM",
            3200: "bcrypt",
            7500: "Kerberos 5 TGS-REP etype 23",
            13100: "Kerberos 5 TGS-REP etype 17/18",
            5500: "NetNTLMv1",
            5600: "NetNTLMv2",
            1100: "Domain Cached Credentials (DCC)",
            2100: "Domain Cached Credentials 2 (DCC2)",
            1500: "descrypt, DES (Unix)",
            500: "md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)",
            3000: "LM",
        }
        logger.info("高级密码破解模块初始化完成")

    def _load_common_passwords(self) -> List[str]:
        """加载常见密码"""
        # 内置常见密码列表（Top 100）
        return [
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon",
            "123123", "baseball", "abc123", "football", "monkey",
            "letmein", "696969", "shadow", "master", "666666",
            "qwertyuiop", "123321", "mustang", "1234567890", "michael",
            "654321", "superman", "1qaz2wsx", "7777777", "fuckyou",
            "121212", "000000", "qazwsx", "123qwe", "killer",
            "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh",
            "hunter", "buster", "soccer", "harley", "batman",
            "andrew", "tigger", "sunshine", "iloveyou", "fuckme",
            "2000", "charlie", "robert", "thomas", "hockey",
            "ranger", "daniel", "starwars", "klaster", "112233",
            "george", "computer", "michelle", "jessica", "pepper",
            "1111", "zxcvbn", "555555", "11111111", "131313",
            "freedom", "777777", "pass", "maggie", "159753",
            "aaaaaa", "ginger", "princess", "joshua", "cheese",
            "amanda", "summer", "love", "ashley", "nicole",
            "chelsea", "biteme", "matthew", "access", "yankees",
            "987654321", "dallas", "austin", "thunder", "taylor",
            "matrix", "william", "corvette", "hello", "martin",
            "heather", "secret", "fucker", "merlin", "diamond",
            "1234qwer", "gfhjkm", "hammer", "silver", "222222",
            "88888888", "anthony", "justin", "test", "bailey",
            "q1w2e3r4t5", "patrick", "internet", "scooter", "orange",
            "11111", "golfer", "cookie", "richard", "samantha",
            "bigdog", "guitar", "jackson", "whatever", "mickey",
            "chicken", "sparky", "snoopy", "maverick", "phoenix",
            "camaro", "sexy", "peanut", "morgan", "welcome",
        ]

    def analyze_hash(self, hash_value: str) -> Tuple[str, int]:
        """分析哈希类型"""
        hash_length = len(hash_value)

        # MD5
        if hash_length == 32 and re.match(r'^[a-fA-F0-9]{32}$', hash_value):
            return "MD5", 0
        # SHA1
        elif hash_length == 40 and re.match(r'^[a-fA-F0-9]{40}$', hash_value):
            return "SHA1", 100
        # SHA256
        elif hash_length == 64 and re.match(r'^[a-fA-F0-9]{64}$', hash_value):
            return "SHA256", 1400
        # SHA512
        elif hash_length == 128 and re.match(r'^[a-fA-F0-9]{128}$', hash_value):
            return "SHA512", 1700
        # NTLM
        elif hash_length == 32 and ":" in hash_value:
            return "NTLM", 1000
        # bcrypt
        elif hash_value.startswith("$2a$") or hash_value.startswith("$2b$") or hash_value.startswith("$2y$"):
            return "bcrypt", 3200
        # NetNTLMv2
        elif ":::" in hash_value and hash_value.count(":") >= 4:
            return "NetNTLMv2", 5600
        # Kerberos
        elif hash_value.startswith("$krb5tgs$") or hash_value.startswith("$krb5asrep$"):
            return "Kerberos", 13100
        else:
            return "Unknown", -1

    def calculate_hash(self, password: str, hash_type: str = "md5", salt: str = "") -> str:
        """计算哈希"""
        if hash_type.lower() == "md5":
            return hashlib.md5(password.encode()).hexdigest()
        elif hash_type.lower() == "sha1":
            return hashlib.sha1(password.encode()).hexdigest()
        elif hash_type.lower() == "sha256":
            return hashlib.sha256(password.encode()).hexdigest()
        elif hash_type.lower() == "sha512":
            return hashlib.sha512(password.encode()).hexdigest()
        elif hash_type.lower() == "ntlm":
            # NTLM哈希计算（简化版）
            import hashlib
            return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
        else:
            return hashlib.md5(password.encode()).hexdigest()

    async def crack_hash_dictionary(
        self,
        hash_value: str,
        hash_type: str = "md5",
        dictionary: Optional[List[str]] = None,
        salt: str = "",
    ) -> HashInfo:
        """字典攻击破解哈希"""
        start_time = time.time()
        hash_info = HashInfo(hash_value=hash_value, hash_type=hash_type, salt=salt)

        if dictionary is None:
            dictionary = self.common_passwords

        logger.info(f"开始字典攻击: {hash_type}, 字典大小: {len(dictionary)}")

        for password in dictionary:
            calculated = self.calculate_hash(password, hash_type, salt)
            if calculated.lower() == hash_value.lower():
                hash_info.cracked = True
                hash_info.plaintext = password
                hash_info.crack_time = time.time() - start_time
                hash_info.crack_method = "dictionary_attack"
                logger.info(f"哈希破解成功: {password} (耗时: {hash_info.crack_time:.2f}秒)")
                return hash_info

        hash_info.crack_time = time.time() - start_time
        logger.info(f"字典攻击失败 (耗时: {hash_info.crack_time:.2f}秒)")
        return hash_info

    async def crack_hash_bruteforce(
        self,
        hash_value: str,
        hash_type: str = "md5",
        min_length: int = 1,
        max_length: int = 6,
        charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
        salt: str = "",
    ) -> HashInfo:
        """暴力破解哈希"""
        import itertools
        start_time = time.time()
        hash_info = HashInfo(hash_value=hash_value, hash_type=hash_type, salt=salt)

        logger.info(f"开始暴力破解: {hash_type}, 长度: {min_length}-{max_length}, 字符集: {len(charset)}")

        for length in range(min_length, max_length + 1):
            for attempt in itertools.product(charset, repeat=length):
                password = ''.join(attempt)
                calculated = self.calculate_hash(password, hash_type, salt)
                if calculated.lower() == hash_value.lower():
                    hash_info.cracked = True
                    hash_info.plaintext = password
                    hash_info.crack_time = time.time() - start_time
                    hash_info.crack_method = "bruteforce_attack"
                    logger.info(f"暴力破解成功: {password} (耗时: {hash_info.crack_time:.2f}秒)")
                    return hash_info

        hash_info.crack_time = time.time() - start_time
        logger.info(f"暴力破解失败 (耗时: {hash_info.crack_time:.2f}秒)")
        return hash_info

    def generate_dictionary(self, config: DictionaryConfig) -> List[str]:
        """生成字典"""
        logger.info(f"开始生成字典, 基础词数量: {len(config.base_words)}")

        passwords = set()

        for word in config.base_words:
            # 原始词
            if config.min_length <= len(word) <= config.max_length:
                passwords.add(word)

            # 大小写变化
            if config.case_variations:
                passwords.add(word.lower())
                passwords.add(word.upper())
                passwords.add(word.capitalize())

            # Leet替换
            if config.leet_replace:
                leet_variations = self._generate_leet_variations(word)
                passwords.update(leet_variations)

            # 数字后缀
            if config.number_suffix:
                for i in range(0, 100):
                    passwords.add(f"{word}{i}")
                    passwords.add(f"{word}{i:02d}")

            # 年份后缀
            if config.year_suffix:
                for year in range(1990, 2030):
                    passwords.add(f"{word}{year}")

            # 特殊字符后缀
            if config.special_suffix:
                for char in self.special_chars:
                    passwords.add(f"{word}{char}")
                    passwords.add(f"{word}{char}123")

            # 组合
            for word2 in config.base_words:
                if word != word2:
                    combined = f"{word}{word2}"
                    if config.min_length <= len(combined) <= config.max_length:
                        passwords.add(combined)

        # 过滤长度
        passwords = {p for p in passwords if config.min_length <= len(p) <= config.max_length}

        # 限制大小
        if len(passwords) > config.max_size:
            passwords = set(list(passwords)[:config.max_size])

        logger.info(f"字典生成完成, 大小: {len(passwords)}")
        return list(passwords)

    def _generate_leet_variations(self, word: str) -> List[str]:
        """生成Leet变体"""
        variations = [word]

        for i, char in enumerate(word.lower()):
            if char in self.leet_map:
                new_variations = []
                for variation in variations:
                    for replacement in self.leet_map[char]:
                        new_var = variation[:i] + replacement + variation[i+1:]
                        new_variations.append(new_var)
                variations.extend(new_variations)

        return list(set(variations))

    def analyze_password_strength(self, password: str) -> PasswordStrength:
        """分析密码强度"""
        length = len(password)
        issues = []
        suggestions = []

        # 字符集分析
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in self.special_chars for c in password)

        # 计算熵值
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += len(self.special_chars)

        if charset_size > 0:
            entropy = length * (charset_size.bit_length() - 1)
        else:
            entropy = 0

        # 检查常见密码
        if password.lower() in self.common_passwords:
            issues.append("密码在常见密码列表中")
            suggestions.append("使用更独特的密码")
            entropy = min(entropy, 10)

        # 检查长度
        if length < 8:
            issues.append("密码长度不足8位")
            suggestions.append("使用至少12位的密码")
        elif length < 12:
            issues.append("密码长度不足12位")
            suggestions.append("使用至少12位的密码")

        # 检查字符集
        if not has_upper:
            issues.append("缺少大写字母")
            suggestions.append("添加大写字母")
        if not has_lower:
            issues.append("缺少小写字母")
            suggestions.append("添加小写字母")
        if not has_digit:
            issues.append("缺少数字")
            suggestions.append("添加数字")
        if not has_special:
            issues.append("缺少特殊字符")
            suggestions.append("添加特殊字符（!@#$%^&*）")

        # 检查重复字符
        if len(set(password)) < length * 0.5:
            issues.append("重复字符过多")
            suggestions.append("使用更多不同的字符")

        # 检查连续字符
        if re.search(r'(.)\1{2,}', password):
            issues.append("存在连续重复字符（如aaa）")
            suggestions.append("避免连续重复字符")

        # 检查顺序字符
        if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            issues.append("存在顺序字符（如abc、123）")
            suggestions.append("避免顺序字符")

        # 计算评分（0-100）
        score = 0
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        else:
            score += 5

        if has_upper:
            score += 10
        if has_lower:
            score += 10
        if has_digit:
            score += 10
        if has_special:
            score += 15

        if entropy >= 80:
            score += 25
        elif entropy >= 60:
            score += 20
        elif entropy >= 40:
            score += 15
        elif entropy >= 20:
            score += 10
        else:
            score += 5

        score = min(score, 100)

        # 强度等级
        if score >= 90:
            strength = "very_strong"
        elif score >= 70:
            strength = "strong"
        elif score >= 50:
            strength = "medium"
        elif score >= 30:
            strength = "weak"
        else:
            strength = "very_weak"

        # 估算破解时间
        crack_time = self._estimate_crack_time(entropy)

        return PasswordStrength(
            password=password,
            length=length,
            entropy=entropy,
            score=score,
            strength=strength,
            crack_time=crack_time,
            issues=issues,
            suggestions=suggestions,
        )

    def _estimate_crack_time(self, entropy: float) -> str:
        """估算破解时间"""
        # 假设每秒尝试10亿次（GPU加速）
        attempts_per_second = 1e9

        if entropy <= 0:
            return "瞬间"

        total_attempts = 2 ** entropy
        seconds = total_attempts / attempts_per_second

        if seconds < 1:
            return "瞬间"
        elif seconds < 60:
            return f"{seconds:.0f}秒"
        elif seconds < 3600:
            return f"{seconds/60:.0f}分钟"
        elif seconds < 86400:
            return f"{seconds/3600:.0f}小时"
        elif seconds < 31536000:
            return f"{seconds/86400:.0f}天"
        elif seconds < 31536000 * 100:
            return f"{seconds/31536000:.0f}年"
        else:
            return f"{seconds/31536000:.0e}年（宇宙年龄级别）"

    def generate_strong_password(self, length: int = 16, include_special: bool = True) -> str:
        """生成强密码"""
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        special = "!@#$%^&*()-_=+[]{}|;:,.<>?"

        charset = lowercase + uppercase + digits
        if include_special:
            charset += special

        # 确保至少包含每种字符
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
        ]
        if include_special:
            password.append(random.choice(special))

        # 填充剩余长度
        for _ in range(length - len(password)):
            password.append(random.choice(charset))

        # 打乱顺序
        random.shuffle(password)

        return ''.join(password)

    def check_password_policy(self, password: str, policy: PasswordPolicy) -> Tuple[bool, List[str]]:
        """检查密码是否符合策略"""
        issues = []

        if len(password) < policy.min_length:
            issues.append(f"密码长度不足{policy.min_length}位")

        if len(password) > policy.max_length:
            issues.append(f"密码长度超过{policy.max_length}位")

        if policy.require_uppercase and not any(c.isupper() for c in password):
            issues.append("缺少大写字母")

        if policy.require_lowercase and not any(c.islower() for c in password):
            issues.append("缺少小写字母")

        if policy.require_digits and not any(c.isdigit() for c in password):
            issues.append("缺少数字")

        if policy.require_special and not any(c in self.special_chars for c in password):
            issues.append("缺少特殊字符")

        return len(issues) == 0, issues

    def generate_hashcat_command(
        self,
        hash_file: str,
        hash_type: int = 0,
        attack_mode: int = 0,  # 0=字典, 1=组合, 3=掩码
        dictionary: str = "",
        mask: str = "",
        rules: str = "",
        output_file: str = "cracked.txt",
    ) -> str:
        """生成Hashcat命令"""
        command = f"{self.hashcat_path} -m {hash_type} -a {attack_mode} "

        if attack_mode == 0 and dictionary:
            command += f'"{hash_file}" "{dictionary}" '
        elif attack_mode == 3 and mask:
            command += f'"{hash_file}" "{mask}" '
        else:
            command += f'"{hash_file}" '

        if rules:
            command += f'-r "{rules}" '

        command += f'-o "{output_file}" '
        command += f'--workload-profile {self.workload_profile} '
        command += '--potfile-disable '

        return command

    def list_hash_types(self) -> List[Dict]:
        """列出支持的哈希类型"""
        return [
            {"mode": mode, "name": name}
            for mode, name in sorted(self.hash_types.items())
        ]

    def generate_mask_attack_config(
        self,
        min_length: int = 8,
        max_length: int = 12,
        include_upper: bool = True,
        include_lower: bool = True,
        include_digits: bool = True,
        include_special: bool = False,
    ) -> List[str]:
        """生成掩码攻击配置"""
        masks = []

        # 构建字符集
        charset = ""
        if include_lower:
            charset += "?l"
        if include_upper:
            charset += "?u"
        if include_digits:
            charset += "?d"
        if include_special:
            charset += "?s"

        # 生成不同长度的掩码
        for length in range(min_length, max_length + 1):
            mask = charset * length
            masks.append(mask)

        # 常见模式掩码
        common_patterns = [
            "?l?l?l?l?d?d?d?d",  # 4字母+4数字
            "?u?l?l?l?l?d?d?d",  # 首字母大写+3字母+3数字
            "?l?l?l?l?l?l?d?d",  # 6字母+2数字
            "?l?l?l?l?d?d?d?d! ",  # 4字母+4数字+特殊字符
        ]
        masks.extend(common_patterns)

        return masks


# 便捷函数
def analyze_password(password: str) -> PasswordStrength:
    """分析密码强度便捷函数"""
    cracker = AdvancedPasswordCracker()
    return cracker.analyze_password_strength(password)


def generate_password(length: int = 16, include_special: bool = True) -> str:
    """生成强密码便捷函数"""
    cracker = AdvancedPasswordCracker()
    return cracker.generate_strong_password(length, include_special)


def identify_hash(hash_value: str) -> Tuple[str, int]:
    """识别哈希类型便捷函数"""
    cracker = AdvancedPasswordCracker()
    return cracker.analyze_hash(hash_value)


async def crack_password(
    hash_value: str,
    hash_type: str = "md5",
    dictionary: Optional[List[str]] = None,
) -> HashInfo:
    """破解密码便捷函数"""
    cracker = AdvancedPasswordCracker()
    return await cracker.crack_hash_dictionary(hash_value, hash_type, dictionary)


if __name__ == "__main__":
    # 测试
    print("=== 高级密码破解模块 ===")
    print()

    # 密码强度分析
    test_passwords = ["123456", "password", "P@ssw0rd123!", "CorrectHorseBatteryStaple"]
    for pwd in test_passwords:
        strength = analyze_password(pwd)
        print(f"密码: {pwd}")
        print(f"  强度: {strength.strength} ({strength.score}/100)")
        print(f"  熵值: {strength.entropy:.1f} bits")
        print(f"  破解时间: {strength.crack_time}")
        if strength.issues:
            print(f"  问题: {', '.join(strength.issues)}")
        print()

    # 生成强密码
    print("生成的强密码:")
    for i in range(5):
        print(f"  {generate_password(16)}")
    print()

    # 哈希类型识别
    test_hashes = [
        "5f4dcc3b5aa765d61d8327deb882cf99",  # md5
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd",  # sha1
    ]
    for h in test_hashes:
        hash_type, mode = identify_hash(h)
        print(f"哈希: {h[:16]}... -> 类型: {hash_type} (Hashcat模式: {mode})")
