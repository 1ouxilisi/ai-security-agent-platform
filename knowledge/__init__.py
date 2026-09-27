"""
__init__知识库模块，存储和管理相关安全知识、漏洞信息和攻击链数据。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

from .vuln_database import VulnDatabase, Vulnerability, get_vuln_db
from .nvd_sync import NVDSync, run_nvd_sync
from .exploit_db import ExploitDB, run_exploit_sync
from .vulners_api import VulnersAPI, run_vulners_sync
from .vuln_intel import VulnIntelligence, VulnAlert, run_vuln_check

# PoC库、指纹库、修复方案库、攻击链库
from .poc_library import poc_library, PoCLibrary, PoC
from .fingerprint_library import fingerprint_library, FingerprintLibrary, FingerprintRule
from .remediation_library import remediation_library, RemediationLibrary, Remediation
from .attack_chains import attack_chain_library, AttackChainLibrary, AttackChain, AttackStep

# 兼容别名：attack_chain（单数）→ attack_chains（复数）
# 注意：模块文件是 attack_chains.py（复数），这里提供单数形式的类和实例别名
attack_chain_lib = attack_chain_library  # 单数别名
AttackChainLib = AttackChainLibrary       # 单数别名

__all__ = [
    # 漏洞数据库
    'VulnDatabase',
    'Vulnerability',
    'get_vuln_db',
    # NVD同步
    'NVDSync',
    'run_nvd_sync',
    # Exploit-DB
    'ExploitDB',
    'run_exploit_sync',
    # Vulners API
    'VulnersAPI',
    'run_vulners_sync',
    # 漏洞情报
    'VulnIntelligence',
    'VulnAlert',
    'run_vuln_check',
    # PoC库
    'poc_library',
    'PoCLibrary',
    'PoC',
    # 指纹库
    'fingerprint_library',
    'FingerprintLibrary',
    'FingerprintRule',
    # 修复方案库
    'remediation_library',
    'RemediationLibrary',
    'Remediation',
    # 攻击链库（复数形式，实际模块名）
    'attack_chain_library',
    'AttackChainLibrary',
    'AttackChain',
    'AttackStep',
    # 攻击链库（单数别名，兼容导入）
    'attack_chain_lib',
    'AttackChainLib',
]
