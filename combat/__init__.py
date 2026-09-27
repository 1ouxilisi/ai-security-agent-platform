#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实战能力模块 - 提供真实漏洞利用和深度渗透测试功能

模块功能：
    - sqlmap集成：SQL注入自动检测和利用
    - Metasploit增强：完整的漏洞利用框架集成
    - AD域攻击链：Kerberoasting→黄金票据→域控接管完整攻击链
    - Web深度利用：XSS/SSRF/文件上传/认证绕过自动利用
    - 一键攻击模板：预设攻击流程，输入目标自动执行全流程

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

from .sqlmap.integrator import SQLMapIntegrator
from .metasploit.enhanced import MetasploitEnhanced
from .ad_attack.chain_executor import ADAttackChain
from .web_exploit.scanner import WebExploitScanner
from .workflow.attack_templates import AttackTemplateEngine

__all__ = [
    'SQLMapIntegrator',
    'MetasploitEnhanced',
    'ADAttackChain',
    'WebExploitScanner',
    'AttackTemplateEngine',
]

__version__ = '1.0.0'
