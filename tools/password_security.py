"""
password_security安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import re
import hashlib
import math
from typing import Dict, Any, List, Optional, Tuple
from utils.logger import log


class PasswordSecurity:
    """密码安全工具"""

    # 常见弱密码
    COMMON_PASSWORDS = [
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "abc123", "football", "monkey",
        "letmein", "696969", "shadow", "master", "666666",
        "qwertyuiop", "123321", "mustang", "1234567890", "michael",
        "654321", "superman", "1qaz2wsx", "7777777", "fuckyou",
        "121212", "000000", "qazwsx", "123qwe", "killer",
        "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh",
        "hunter", "buster", "soccer", "harley", "batman",
        "andrew", "tigger", "sunshine", "iloveyou", "2000",
        "charlie", "robert", "thomas", "hockey", "ranger",
        "daniel", "starwars", "klaster", "112233", "george",
        "computer", "michelle", "jessica", "pepper", "1111",
        "zxcvbn", "555555", "11111111", "131313", "freedom",
        "777777", "pass", "maggie", "159753", "aaaaaa",
        "ginger", "princess", "joshua", "cheese", "amanda",
        "summer", "love", "ashley", "nicole", "chelsea",
        "biteme", "matthew", "access", "yankees", "987654321",
        "dallas", "austin", "thunder", "taylor", "matrix",
    ]

    # 密码字符集
    CHAR_SETS = {
        "lowercase": "abcdefghijklmnopqrstuvwxyz",
        "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "digits": "0123456789",
        "special": "!@#$%^&*()_+-=[]{}|;:,.<>?/~`",
    }

    def check_password_strength(self, password: str) -> Dict[str, Any]:
        """检查密码强度"""
        if not password:
            return {"error": "密码不能为空"}

        length = len(password)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]', password))

        # 检查常见密码
        is_common = password.lower() in [p.lower() for p in self.COMMON_PASSWORDS]

        # 检查重复字符
        has_repeating = bool(re.search(r'(.)\1{2,}', password))

        # 检查连续字符
        has_sequential = False
        for i in range(len(password) - 2):
            if ord(password[i+1]) == ord(password[i]) + 1 and ord(password[i+2]) == ord(password[i]) + 2:
                has_sequential = True
                break

        # 计算熵
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32

        entropy = length * math.log2(charset_size) if charset_size > 0 else 0

        # 评分
        score = 0
        if length >= 8:
            score += 20
        if length >= 12:
            score += 10
        if length >= 16:
            score += 10
        if has_lower:
            score += 10
        if has_upper:
            score += 10
        if has_digit:
            score += 10
        if has_special:
            score += 15
        if not is_common:
            score += 5
        if not has_repeating:
            score += 5
        if not has_sequential:
            score += 5

        score = min(100, score)

        if score >= 80:
            strength = "very_strong"
            level = "非常强"
        elif score >= 60:
            strength = "strong"
            level = "强"
        elif score >= 40:
            strength = "medium"
            level = "中等"
        elif score >= 20:
            strength = "weak"
            level = "弱"
        else:
            strength = "very_weak"
            level = "非常弱"

        issues = []
        if length < 8:
            issues.append("密码长度不足8位")
        if not has_upper:
            issues.append("缺少大写字母")
        if not has_lower:
            issues.append("缺少小写字母")
        if not has_digit:
            issues.append("缺少数字")
        if not has_special:
            issues.append("缺少特殊字符")
        if is_common:
            issues.append("使用了常见密码")
        if has_repeating:
            issues.append("包含重复字符")
        if has_sequential:
            issues.append("包含连续字符")

        return {
            "password_length": length,
            "score": score,
            "strength": strength,
            "strength_level": level,
            "entropy": round(entropy, 2),
            "crack_time_estimate": self._estimate_crack_time(entropy),
            "characteristics": {
                "has_lowercase": has_lower,
                "has_uppercase": has_upper,
                "has_digits": has_digit,
                "has_special": has_special,
                "is_common_password": is_common,
                "has_repeating_chars": has_repeating,
                "has_sequential_chars": has_sequential,
            },
            "issues": issues,
            "recommendations": [
                "使用至少12位长度的密码",
                "包含大小写字母、数字和特殊字符",
                "避免使用常见密码和字典词汇",
                "避免重复字符和连续字符",
                "每个账户使用唯一密码",
                "使用密码管理器生成和存储密码",
                "启用多因素认证（MFA）",
            ],
        }

    def _estimate_crack_time(self, entropy: float) -> str:
        """估算破解时间"""
        # 假设每秒10亿次尝试
        attempts_per_second = 1e9
        total_combinations = 2 ** entropy

        if total_combinations < attempts_per_second:
            return "瞬间"
        elif total_combinations < attempts_per_second * 60:
            return f"{int(total_combinations / attempts_per_second)}秒"
        elif total_combinations < attempts_per_second * 3600:
            return f"{int(total_combinations / (attempts_per_second * 60))}分钟"
        elif total_combinations < attempts_per_second * 86400:
            return f"{int(total_combinations / (attempts_per_second * 3600))}小时"
        elif total_combinations < attempts_per_second * 86400 * 365:
            return f"{int(total_combinations / (attempts_per_second * 86400))}天"
        elif total_combinations < attempts_per_second * 86400 * 365 * 100:
            return f"{int(total_combinations / (attempts_per_second * 86400 * 365))}年"
        else:
            return "数百年以上（实际上不可破解）"

    def hash_password(self, password: str, algorithm: str = "sha256", salt: str = "") -> str:
        """哈希密码"""
        if algorithm == "md5":
            return hashlib.md5((salt + password).encode()).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1((salt + password).encode()).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256((salt + password).encode()).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512((salt + password).encode()).hexdigest()
        elif algorithm == "ntlm":
            # NTLM哈希（MD4 of UTF-16LE）
            import hashlib
            return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
        else:
            return hashlib.sha256((salt + password).encode()).hexdigest()

    def generate_password(self, length: int = 16, use_lower: bool = True,
                          use_upper: bool = True, use_digits: bool = True,
                          use_special: bool = True) -> str:
        """生成随机密码"""
        import secrets
        charset = ""
        if use_lower:
            charset += self.CHAR_SETS["lowercase"]
        if use_upper:
            charset += self.CHAR_SETS["uppercase"]
        if use_digits:
            charset += self.CHAR_SETS["digits"]
        if use_special:
            charset += self.CHAR_SETS["special"]

        if not charset:
            charset = self.CHAR_SETS["lowercase"]

        return ''.join(secrets.choice(charset) for _ in range(length))

    def generate_wordlist(self, base_words: List[str], min_length: int = 6,
                          max_length: int = 12, include_numbers: bool = True,
                          include_special: bool = True) -> List[str]:
        """生成密码字典"""
        wordlist = set()

        for word in base_words:
            word = word.lower()
            if min_length <= len(word) <= max_length:
                wordlist.add(word)
                wordlist.add(word.capitalize())
                wordlist.add(word.upper())

                # 常见替换
                leet = word.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '$')
                wordlist.add(leet)
                wordlist.add(leet.capitalize())

                if include_numbers:
                    for i in range(10):
                        wordlist.add(f"{word}{i}")
                        wordlist.add(f"{i}{word}")
                    for year in range(2020, 2026):
                        wordlist.add(f"{word}{year}")
                        wordlist.add(f"{year}{word}")

                if include_special:
                    for special in ['!', '@', '#', '$']:
                        wordlist.add(f"{word}{special}")
                        wordlist.add(f"{special}{word}")
                        wordlist.add(f"{word}{special}123")

        # 添加常见密码
        for pwd in self.COMMON_PASSWORDS[:50]:
            if min_length <= len(pwd) <= max_length:
                wordlist.add(pwd)

        return sorted(list(wordlist))

    def check_credential_spray(self, usernames: List[str], passwords: List[str],
                                 lockout_threshold: int = 5,
                                 lockout_window: int = 300) -> Dict[str, Any]:
        """凭证喷洒攻击检测和建议"""
        return {
            "description": "凭证喷洒攻击 - 使用少量密码尝试大量账户",
            "risk_level": "high",
            "recommended_approach": {
                "passwords_to_try": min(3, len(passwords)),
                "delay_between_attempts": "30-60秒",
                "max_attempts_per_account": 1,
                "account_lockout_threshold": lockout_threshold,
                "lockout_window_seconds": lockout_window,
            },
            "detection_methods": [
                "监控同一IP的大量登录失败",
                "监控多个账户使用相同密码",
                "监控异常时间的登录尝试",
                "使用行为分析检测异常登录模式",
            ],
            "prevention": [
                "实施账户锁定策略",
                "启用多因素认证（MFA）",
                "使用密码策略禁止常见密码",
                "实施登录速率限制",
                "监控和告警异常登录行为",
                "定期轮换密码和禁用旧密码",
            ],
            "common_passwords_for_spraying": [
                "Password1", "Welcome1", "Summer2024", "Winter2024",
                "Company123", "Welcome@123", "P@ssw0rd", "Admin123",
            ],
        }


# 全局密码安全工具实例
password_security = PasswordSecurity()
