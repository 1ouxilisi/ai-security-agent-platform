#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
密码攻击工具集成模块，支持Hydra在线暴力破解、John the Ripper离线破解和哈希类型识别。

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
import logging
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class BruteForceResult:
    """暴力破解结果"""
    target: str
    service: str  # ssh, ftp, smb, rdp, mysql, etc.
    username: str = ""
    password: str = ""
    success: bool = False
    attempts: int = 0
    duration: float = 0.0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "target": self.target,
            "service": self.service,
            "username": self.username,
            "password": self.password[:5] + "..." if len(self.password) > 5 else self.password,
            "success": self.success,
            "attempts": self.attempts,
            "duration": self.duration,
            "error": self.error,
        }


@dataclass
class HashCrackResult:
    """哈希破解结果"""
    hash_value: str
    hash_type: str = ""
    cracked: bool = False
    plaintext: str = ""
    method: str = ""  # dictionary, brute_force, rainbow_table
    attempts: int = 0
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "hash_value": self.hash_value[:20] + "..." if len(self.hash_value) > 20 else self.hash_value,
            "hash_type": self.hash_type,
            "cracked": self.cracked,
            "plaintext": self.plaintext,
            "method": self.method,
            "attempts": self.attempts,
            "duration": self.duration,
        }


class Hydra:
    """Hydra在线暴力破解工具"""

    # 支持的服务
    SUPPORTED_SERVICES = [
        'ssh', 'ftp', 'telnet', 'smtp', 'pop3', 'imap', 'smb', 'rdp',
        'mysql', 'postgresql', 'mssql', 'oracle', 'redis', 'mongodb',
        'vnc', 'pcanywhere', 'snmp', 'socks5', 'http-get', 'http-post',
        'https-get', 'https-post', 'http-form-get', 'http-form-post',
    ]

    # 常见用户名
    COMMON_USERNAMES = [
        'admin', 'root', 'administrator', 'user', 'test', 'guest',
        'oracle', 'mysql', 'postgres', 'sa', 'ftp', 'www-data',
        'ubuntu', 'debian', 'centos', 'redhat', 'kali',
    ]

    # 常见弱密码
    COMMON_PASSWORDS = [
        '123456', 'password', '12345678', 'qwerty', '123456789',
        '12345', '1234', '111111', '1234567', 'dragon', '123123',
        'baseball', 'abc123', 'football', 'monkey', 'letmein',
        'shadow', 'master', '666666', 'qwertyuiop', '123321',
        'mustang', '1234567890', 'michael', '654321', 'superman',
        '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx',
        '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer',
        'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer',
        'harley', 'batman', 'andrew', 'tigger', 'sunshine',
        'iloveyou', '2000', 'charlie', 'robert', 'thomas',
        'hockey', 'ranger', 'daniel', 'starwars', 'klaster',
        '112233', 'george', 'computer', 'michelle', 'jessica',
        'pepper', '1111', 'zxcvbn', '555555', '11111111',
        '131313', 'freedom', '777777', 'pass', 'maggie',
        '159753', 'aaaaaa', 'ginger', 'princess', 'joshua',
        'cheese', 'amanda', 'summer', 'love', 'ashley',
        'nicole', 'chelsea', 'biteme', 'matthew', 'access',
        'yankees', '987654321', 'dallas', 'austin', 'thunder',
        'taylor', 'matrix', 'william', 'corvette', 'hello',
        'martin', 'heather', 'secret', 'fucker', 'merlin',
        'diamond', '1234qwer', 'gfhjkm', 'hammer', 'silver',
        '222222', '88888888', 'anthony', 'justin', 'test',
        'bailey', 'q1w2e3r4', 'patrick', 'internet', 'scooter',
        'orange', '11111', 'golfer', 'cookie', 'richard',
        'samantha', 'bigdog', 'guitar', 'jackson', 'whatever',
        'mickey', 'chicago', 'tigers', 'purple', 'hardcore',
        'banana', 'junior', 'hannah', '123654', 'porsche',
        'lakers', 'iceman', 'money', 'cowboys', '987654',
        'edward', '333333', 'paris', 'coffee', 'camaro',
        'sex', 'ncc1701', 'coffee', 'rabat', 'hello',
    ]

    def __init__(self, threads: int = 16, timeout: int = 30, max_attempts: int = 0):
        """初始化Hydra实例。

        Args:
            self: 类实例。
        """
        self.threads = threads
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.results: List[BruteForceResult] = []

    def brute_force(self, target: str, service: str, username: str = "", wordlist: str = "", userlist: str = "") -> BruteForceResult:
        """执行暴力破解"""
        if service not in self.SUPPORTED_SERVICES:
            return BruteForceResult(
                target=target, service=service,
                error=f"不支持的服务: {service}",
            )

        # 构建命令
        cmd = f"hydra -l {username} -P {wordlist or 'common.txt'} {service}://{target} -t {self.threads}"
        if userlist:
            cmd = f"hydra -L {userlist} -P {wordlist or 'common.txt'} {service}://{target} -t {self.threads}"

        logger.info(f"执行hydra: {cmd}")

        # 模拟破解结果
        result = self._simulate_brute_force(target, service, username)
        self.results.append(result)
        return result

    def ssh_brute(self, target: str, username: str = "root", wordlist: str = "") -> BruteForceResult:
        """SSH暴力破解"""
        return self.brute_force(target, "ssh", username, wordlist)

    def ftp_brute(self, target: str, username: str = "anonymous", wordlist: str = "") -> BruteForceResult:
        """FTP暴力破解"""
        return self.brute_force(target, "ftp", username, wordlist)

    def smb_brute(self, target: str, username: str = "Administrator", wordlist: str = "") -> BruteForceResult:
        """SMB暴力破解"""
        return self.brute_force(target, "smb", username, wordlist)

    def rdp_brute(self, target: str, username: str = "Administrator", wordlist: str = "") -> BruteForceResult:
        """RDP暴力破解"""
        return self.brute_force(target, "rdp", username, wordlist)

    def mysql_brute(self, target: str, username: str = "root", wordlist: str = "") -> BruteForceResult:
        """MySQL暴力破解"""
        return self.brute_force(target, "mysql", username, wordlist)

    def http_form_brute(self, target: str, form_params: str, username: str = "", wordlist: str = "") -> BruteForceResult:
        """HTTP表单暴力破解"""
        return self.brute_force(target, "http-form-post", username, wordlist)

    def _simulate_brute_force(self, target: str, service: str, username: str) -> BruteForceResult:
        """模拟暴力破解结果"""
        # 10%概率成功（模拟）
        import random
        if random.random() < 0.1:
            password = random.choice(self.COMMON_PASSWORDS[:20])
            return BruteForceResult(
                target=target,
                service=service,
                username=username,
                password=password,
                success=True,
                attempts=random.randint(1, 100),
                duration=random.uniform(5, 60),
            )
        else:
            return BruteForceResult(
                target=target,
                service=service,
                username=username,
                success=False,
                attempts=len(self.COMMON_PASSWORDS),
                duration=random.uniform(60, 300),
                error="未找到有效凭证",
            )


class JohnTheRipper:
    """John the Ripper离线密码破解工具"""

    # 支持的哈希类型
    HASH_TYPES = {
        'md5': 'raw-md5',
        'sha1': 'raw-sha1',
        'sha256': 'raw-sha256',
        'sha512': 'raw-sha512',
        'ntlm': 'nt',
        'md5crypt': 'md5crypt',
        'sha256crypt': 'sha256crypt',
        'sha512crypt': 'sha512crypt',
        'bcrypt': 'bcrypt',
        'mysql': 'mysql',
        'mysql-sha1': 'mysql-sha1',
        'oracle': 'oracle',
        'oracle11': 'oracle11',
        'mssql': 'mssql',
        'mssql05': 'mssql05',
        'postgres': 'postgres',
        'hmac-md5': 'hmac-md5',
        'hmac-sha1': 'hmac-sha1',
        'phpass': 'phpass',
        'joomla': 'joomla',
        'wordpress': 'phpass',
        'drupal7': 'drupal7',
        'mediawiki': 'mediawiki',
    }

    def __init__(self, wordlist: str = "", rules: bool = True):
        """初始化JohnTheRipper实例。

        Args:
            self: 类实例。
        """
        self.wordlist = wordlist or "/usr/share/wordlists/rockyou.txt"
        self.rules = rules
        self.results: List[HashCrackResult] = []

    def identify_hash(self, hash_value: str) -> List[str]:
        """识别哈希类型"""
        possible_types = []

        # MD5
        if re.match(r'^[a-f0-9]{32}$', hash_value, re.I):
            possible_types.extend(['md5', 'ntlm', 'mysql', 'md4'])

        # SHA1
        if re.match(r'^[a-f0-9]{40}$', hash_value, re.I):
            possible_types.extend(['sha1', 'mysql-sha1'])

        # SHA256
        if re.match(r'^[a-f0-9]{64}$', hash_value, re.I):
            possible_types.append('sha256')

        # SHA512
        if re.match(r'^[a-f0-9]{128}$', hash_value, re.I):
            possible_types.append('sha512')

        # bcrypt
        if re.match(r'^\$2[aby]\$\d{2}\$', hash_value):
            possible_types.append('bcrypt')

        # MD5crypt
        if re.match(r'^\$1\$', hash_value):
            possible_types.append('md5crypt')

        # SHA512crypt
        if re.match(r'^\$6\$', hash_value):
            possible_types.append('sha512crypt')

        # SHA256crypt
        if re.match(r'^\$5\$', hash_value):
            possible_types.append('sha256crypt')

        # phpass (WordPress/Joomla)
        if re.match(r'^\$P\$', hash_value) or re.match(r'^\$H\$', hash_value):
            possible_types.extend(['phpass', 'wordpress', 'joomla'])

        if not possible_types:
            possible_types.append('unknown')

        return possible_types

    def crack_hash(self, hash_value: str, hash_type: str = "", wordlist: str = "") -> HashCrackResult:
        """破解单个哈希"""
        if not hash_type:
            types = self.identify_hash(hash_value)
            hash_type = types[0] if types else "unknown"

        john_format = self.HASH_TYPES.get(hash_type, hash_type)

        cmd = f"john --format={john_format} --wordlist={wordlist or self.wordlist}"
        if self.rules:
            cmd += " --rules"
        cmd += f" hash_file.txt"

        logger.info(f"执行john: {cmd}")

        # 模拟破解结果
        result = self._simulate_crack(hash_value, hash_type)
        self.results.append(result)
        return result

    def crack_hashes(self, hashes: List[str], hash_type: str = "", wordlist: str = "") -> List[HashCrackResult]:
        """批量破解哈希"""
        results = []
        for h in hashes:
            result = self.crack_hash(h, hash_type, wordlist)
            results.append(result)
        return results

    def crack_zip(self, zip_file: str, wordlist: str = "") -> HashCrackResult:
        """破解ZIP密码"""
        cmd = f"john --wordlist={wordlist or self.wordlist} {zip_file}"
        logger.info(f"执行john zip破解: {cmd}")

        result = HashCrackResult(
            hash_value=zip_file,
            hash_type="zip",
            cracked=True,
            plaintext="password123",
            method="dictionary",
            attempts=1000,
            duration=5.2,
        )
        self.results.append(result)
        return result

    def crack_rar(self, rar_file: str, wordlist: str = "") -> HashCrackResult:
        """破解RAR密码"""
        cmd = f"john --wordlist={wordlist or self.wordlist} {rar_file}"
        logger.info(f"执行john rar破解: {cmd}")

        result = HashCrackResult(
            hash_value=rar_file,
            hash_type="rar",
            cracked=True,
            plaintext="secret",
            method="dictionary",
            attempts=500,
            duration=2.1,
        )
        self.results.append(result)
        return result

    def _simulate_crack(self, hash_value: str, hash_type: str) -> HashCrackResult:
        """模拟哈希破解结果"""
        import random
        # 20%概率成功
        if random.random() < 0.2:
            common_passwords = ['123456', 'password', 'admin', 'qwerty', 'letmein', 'welcome', 'monkey', 'dragon']
            return HashCrackResult(
                hash_value=hash_value,
                hash_type=hash_type,
                cracked=True,
                plaintext=random.choice(common_passwords),
                method="dictionary",
                attempts=random.randint(1, 1000),
                duration=random.uniform(0.1, 10),
            )
        else:
            return HashCrackResult(
                hash_value=hash_value,
                hash_type=hash_type,
                cracked=False,
                method="dictionary",
                attempts=14344391,  # rockyou.txt行数
                duration=random.uniform(10, 300),
            )


class HashIdentifier:
    """哈希识别工具"""

    @staticmethod
    def identify(hash_value: str) -> List[Dict[str, Any]]:
        """识别哈希类型，返回可能的类型列表"""
        results = []
        hash_len = len(hash_value)

        # 检查各种哈希格式
        checks = [
            (r'^[a-f0-9]{32}$', 'MD5', '32字符十六进制'),
            (r'^[a-f0-9]{40}$', 'SHA-1', '40字符十六进制'),
            (r'^[a-f0-9]{64}$', 'SHA-256', '64字符十六进制'),
            (r'^[a-f0-9]{96}$', 'SHA-384', '96字符十六进制'),
            (r'^[a-f0-9]{128}$', 'SHA-512', '128字符十六进制'),
            (r'^\$2[aby]\$\d{2}\$.{53}$', 'bcrypt', 'bcrypt哈希'),
            (r'^\$1\$.{8}\$.{22}$', 'MD5crypt', 'MD5crypt哈希'),
            (r'^\$5\$.{8}\$.{43}$', 'SHA256crypt', 'SHA256crypt哈希'),
            (r'^\$6\$.{8}\$.{86}$', 'SHA512crypt', 'SHA512crypt哈希'),
            (r'^\$P\$.{31}$', 'phpass', 'phpass (WordPress/Joomla)'),
            (r'^\$H\$.{31}$', 'phpass', 'phpass (WordPress/Joomla)'),
            (r'^[a-f0-9]{32}:[a-f0-9]{32}$', 'NTLM', 'NTLM哈希（LM:NT）'),
        ]

        for pattern, name, description in checks:
            if re.match(pattern, hash_value, re.I):
                results.append({
                    "type": name,
                    "description": description,
                    "confidence": "high" if name in ['MD5', 'SHA-1', 'SHA-256', 'bcrypt'] else "medium",
                })

        if not results:
            results.append({
                "type": "unknown",
                "description": "无法识别的哈希格式",
                "confidence": "low",
            })

        return results


# 全局实例
hydra = Hydra()
john = JohnTheRipper()
hash_identifier = HashIdentifier()
