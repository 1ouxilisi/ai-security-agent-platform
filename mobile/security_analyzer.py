#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_analyzer模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import os
import re
import json
import zipfile
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import Counter
from xml.etree import ElementTree as ET

from utils.logger import log


@dataclass
class APKAnalysisResult:
    """APK分析结果"""
    file_path: str
    file_size: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    package_name: str = ""
    app_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    permissions: List[str] = field(default_factory=list)
    dangerous_permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    exported_components: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    hardcoded_secrets: List[Dict[str, Any]] = field(default_factory=list)
    insecure_apis: List[str] = field(default_factory=list)
    network_security_config: Dict[str, Any] = field(default_factory=dict)
    debuggable: bool = False
    allow_backup: bool = False
    uses_cleartext_traffic: bool = False
    analysis_time: float = 0

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "package_name": self.package_name,
            "app_name": self.app_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "permissions": self.permissions,
            "dangerous_permissions": self.dangerous_permissions,
            "activities_count": len(self.activities),
            "services_count": len(self.services),
            "receivers_count": len(self.receivers),
            "providers_count": len(self.providers),
            "exported_components": self.exported_components,
            "vulnerabilities": self.vulnerabilities,
            "hardcoded_secrets": self.hardcoded_secrets,
            "insecure_apis": self.insecure_apis,
            "network_security_config": self.network_security_config,
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
            "risk_score": self._calculate_risk_score(),
            "analysis_time": self.analysis_time
        }

    def _calculate_risk_score(self) -> int:
        """计算风险评分 0-100"""
        score = 0
        if self.debuggable:
            score += 20
        if self.allow_backup:
            score += 10
        if self.uses_cleartext_traffic:
            score += 15
        score += len(self.dangerous_permissions) * 3
        score += len(self.exported_components) * 2
        score += len(self.vulnerabilities) * 5
        score += len(self.hardcoded_secrets) * 5
        return min(score, 100)


class MobileSecurityAnalyzer:
    """移动安全分析器"""

    # Android危险权限列表
    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA", "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS", "android.permission.GET_ACCOUNTS",
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECORD_AUDIO", "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE", "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG", "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP", "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.BODY_SENSORS", "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH", "android.permission.RECEIVE_MMS",
        "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO", "android.permission.POST_NOTIFICATIONS",
        "android.permission.NEARBY_WIFI_DEVICES", "android.permission.BLUETOOTH_SCAN",
        "android.permission.BLUETOOTH_CONNECT", "android.permission.ACCESS_BACKGROUND_LOCATION"
    }

    # 硬编码密钥正则模式
    SECRET_PATTERNS = [
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API Key"),
        (r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']([^"\'\s]{8,})["\']', "Password/Secret"),
        (r'(?i)(access[_-]?token|auth[_-]?token|token)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', "Access Token"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
        (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', "Private Key"),
        (r'(?i)(firebase|google[_-]?api)[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Firebase/Google API Key"),
        (r'(?i)(stripe|paypal)[_-]?(secret|api)[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Payment API Key"),
        (r'(?i)(slack|discord|telegram)[_-]?(token|webhook|bot)\s*[=:]\s*["\']([a-zA-Z0-9_\-:]{20,})["\']', "Chat API Token"),
        (r'(?i)(jwt|bearer)\s+[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', "JWT Token"),
        (r'(?i)(smtp|mail)[_-]?(password|secret)\s*[=:]\s*["\']([^"\'\s]{8,})["\']', "SMTP Password"),
    ]

    # 不安全API模式
    INSECURE_APIS = [
        (r'getRuntime\(\)\.exec', "命令执行"),
        (r'Runtime\.getRuntime\(\)\.exec', "命令执行"),
        (r'SQLiteDatabase\.execSQL', "SQL注入风险"),
        (r'rawQuery', "SQL注入风险"),
        (r'HttpURLConnection', "HTTP通信（可能明文）"),
        (r'HttpClient', "HTTP通信（可能明文）"),
        (r'org\.apache\.http', "已废弃HTTP客户端"),
        (r'WebView\.addJavascriptInterface', "WebView JS接口（可能RCE）"),
        (r'setJavaScriptEnabled\(true\)', "WebView启用JS"),
        (r'loadUrl\("javascript:', "WebView执行JS"),
        (r'MODE_WORLD_READABLE', "全局可读文件"),
        (r'MODE_WORLD_WRITEABLE', "全局可写文件"),
        (r'getExternalStorage', "外部存储（可能泄露）"),
        (r'getSharedPreferences', "SharedPreferences（可能明文存储）"),
        (r'TextUtils\.isEmpty', "空检查（可能绕过）"),
        (r'Log\.d\(|Log\.v\(|Log\.i\(', "日志泄露（可能包含敏感信息）"),
        (r'printStackTrace', "异常栈打印（信息泄露）"),
        (r'DES\b|3DES\b|RC4\b|MD5\b|SHA1\b', "弱加密算法"),
        (r'SecureRandom\(\)', "可能使用弱随机数"),
        (r'TrustManager', "自定义TrustManager（可能忽略证书验证）"),
        (r'HostnameVerifier', "自定义HostnameVerifier（可能忽略主机验证）"),
        (r'checkServerTrusted\s*\(\s*\{\s*\}', "空TrustManager实现（忽略证书验证）"),
        (r'verify\s*\(\s*[^{]*\)\s*\{\s*return\s+true', "HostnameVerifier总是返回true"),
    ]

    def __init__(self, data_dir: str = "data/mobile_security"):
        """初始化MobileSecurityAnalyzer实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.analysis_history: List[Dict[str, Any]] = []
        os.makedirs(data_dir, exist_ok=True)

    def analyze_apk(self, apk_path: str) -> APKAnalysisResult:
        """分析APK文件"""
        import time
        start_time = time.time()

        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK文件不存在: {apk_path}")

        result = APKAnalysisResult(file_path=apk_path)
        result.file_size = os.path.getsize(apk_path)

        # 计算文件哈希
        with open(apk_path, 'rb') as f:
            data = f.read()
            result.md5 = hashlib.md5(data).hexdigest()
            result.sha1 = hashlib.sha1(data).hexdigest()
            result.sha256 = hashlib.sha256(data).hexdigest()

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # 解析AndroidManifest.xml
                self._parse_manifest(zf, result)

                # 检查网络安全配置
                self._check_network_security(zf, result)

                # 扫描硬编码密钥
                self._scan_hardcoded_secrets(zf, result)

                # 扫描不安全API
                self._scan_insecure_apis(zf, result)

                # 检测漏洞
                self._detect_vulnerabilities(result)

        except Exception as e:
            log.error(f"APK分析失败: {e}")
            result.vulnerabilities.append({
                "type": "analysis_error",
                "severity": "info",
                "description": f"APK解析失败: {str(e)}",
                "remediation": "确保APK文件格式正确"
            })

        result.analysis_time = round(time.time() - start_time, 2)
        self.analysis_history.append(result.to_dict())
        return result

    def _parse_manifest(self, zf: zipfile.ZipFile, result: APKAnalysisResult):
        """解析AndroidManifest.xml（二进制XML）"""
        try:
            # 尝试读取二进制AndroidManifest.xml
            # 注意：AndroidManifest.xml是二进制AXML格式，这里使用简单的字符串提取
            manifest_data = zf.read("AndroidManifest.xml")

            # 简单的二进制XML解析（提取字符串）
            # 实际项目中应使用androguard或axmlprinter
            manifest_str = manifest_data.decode('utf-8', errors='ignore')

            # 提取包名
            pkg_match = re.search(r'([a-z][a-z0-9_]*(\.[a-z0-9_]+)+)', manifest_str)
            if pkg_match:
                result.package_name = pkg_match.group(1)

            # 提取权限
            perm_matches = re.findall(r'android\.permission\.[A-Z_]+', manifest_str)
            result.permissions = list(set(perm_matches))
            result.dangerous_permissions = [p for p in result.permissions if p in self.DANGEROUS_PERMISSIONS]

            # 检查debuggable
            result.debuggable = 'android:debuggable="true"' in manifest_str or b'debuggable' in manifest_data

            # 检查allowBackup
            result.allow_backup = 'android:allowBackup="true"' in manifest_str or b'allowBackup' in manifest_data

            # 提取组件（简单字符串匹配）
            for component_type in ['activity', 'service', 'receiver', 'provider']:
                pattern = rf'android:name="([a-zA-Z0-9_\.]+{component_type}[a-zA-Z0-9_\.]*)"'
                matches = re.findall(pattern, manifest_str, re.IGNORECASE)
                if component_type == 'activity':
                    result.activities = matches
                elif component_type == 'service':
                    result.services = matches
                elif component_type == 'receiver':
                    result.receivers = matches
                elif component_type == 'provider':
                    result.providers = matches

            # 检查导出组件
            exported_pattern = r'android:exported="true"'
            if exported_pattern in manifest_str:
                result.exported_components = ["检测到exported=true的组件（需详细分析）"]

        except Exception as e:
            log.warning(f"Manifest解析失败: {e}")

    def _check_network_security(self, zf: zipfile.ZipFile, result: APKAnalysisResult):
        """检查网络安全配置"""
        try:
            # 检查是否存在network_security_config.xml
            ns_config_files = [f for f in zf.namelist() if 'network_security_config' in f.lower()]
            if ns_config_files:
                ns_data = zf.read(ns_config_files[0]).decode('utf-8', errors='ignore')
                result.network_security_config = {
                    "exists": True,
                    "file": ns_config_files[0],
                    "cleartext_traffic_permitted": 'cleartextTrafficPermitted="true"' in ns_data,
                    "trust_anchors": re.findall(r'<certificates src="([^"]+)"', ns_data)
                }
                result.uses_cleartext_traffic = result.network_security_config.get("cleartext_traffic_permitted", False)
            else:
                # 没有network_security_config，检查targetSdkVersion
                # targetSdk < 28 默认允许明文流量
                result.network_security_config = {"exists": False}
                try:
                    target_sdk = int(result.target_sdk) if result.target_sdk else 0
                    if target_sdk < 28:
                        result.uses_cleartext_traffic = True
                except:
                    pass
        except Exception as e:
            log.warning(f"网络安全配置检查失败: {e}")

    def _scan_hardcoded_secrets(self, zf: zipfile.ZipFile, result: APKAnalysisResult):
        """扫描硬编码密钥"""
        try:
            # 扫描dex文件和资源文件中的字符串
            scan_files = [f for f in zf.namelist() if f.endswith('.dex') or f.endswith('.xml') or f.endswith('.json') or f.endswith('.properties')]

            for filename in scan_files[:10]:  # 限制扫描文件数量
                try:
                    data = zf.read(filename)
                    text = data.decode('utf-8', errors='ignore')

                    for pattern, secret_type in self.SECRET_PATTERNS:
                        matches = re.findall(pattern, text)
                        for match in matches[:5]:  # 每种类型最多5个
                            secret_value = match[1] if isinstance(match, tuple) and len(match) > 1 else str(match)
                            # 过滤误报
                            if len(secret_value) >= 8 and secret_value.lower() not in ['password', 'secret', 'token', 'key']:
                                result.hardcoded_secrets.append({
                                    "type": secret_type,
                                    "value": secret_value[:20] + "..." if len(secret_value) > 20 else secret_value,
                                    "file": filename,
                                    "severity": "high" if "Key" in secret_type or "Token" in secret_type else "medium"
                                })
                except:
                    continue

            # 去重
            seen = set()
            unique_secrets = []
            for s in result.hardcoded_secrets:
                key = (s["type"], s["value"])
                if key not in seen:
                    seen.add(key)
                    unique_secrets.append(s)
            result.hardcoded_secrets = unique_secrets[:20]  # 最多20个

        except Exception as e:
            log.warning(f"硬编码密钥扫描失败: {e}")

    def _scan_insecure_apis(self, zf: zipfile.ZipFile, result: APKAnalysisResult):
        """扫描不安全API使用"""
        try:
            dex_files = [f for f in zf.namelist() if f.endswith('.dex')]

            for filename in dex_files[:5]:  # 限制扫描文件数量
                try:
                    data = zf.read(filename)
                    text = data.decode('utf-8', errors='ignore')

                    for pattern, description in self.INSECURE_APIS:
                        if re.search(pattern, text):
                            result.insecure_apis.append(f"{description}: {pattern}")
                except:
                    continue

            result.insecure_apis = list(set(result.insecure_apis))[:30]  # 最多30个

        except Exception as e:
            log.warning(f"不安全API扫描失败: {e}")

    def _detect_vulnerabilities(self, result: APKAnalysisResult):
        """检测漏洞"""
        vulns = []

        # 1. Debuggable
        if result.debuggable:
            vulns.append({
                "type": "debuggable_apk",
                "severity": "high",
                "title": "APK可调试",
                "description": "应用设置了android:debuggable=\"true\"，攻击者可以附加调试器，读取内存数据，动态分析应用逻辑",
                "impact": "敏感数据泄露、应用逻辑被逆向、动态调试",
                "remediation": "在发布版本中设置android:debuggable=\"false\"，在build.gradle中设置debuggable false"
            })

        # 2. 允许备份
        if result.allow_backup:
            vulns.append({
                "type": "allow_backup",
                "severity": "medium",
                "title": "允许应用数据备份",
                "description": "应用设置了android:allowBackup=\"true\"，攻击者可以通过adb backup备份应用数据，包括SharedPreferences、数据库等",
                "impact": "应用数据泄露、用户隐私泄露",
                "remediation": "设置android:allowBackup=\"false\"，或配置backupRules.xml排除敏感数据"
            })

        # 3. 明文流量
        if result.uses_cleartext_traffic:
            vulns.append({
                "type": "cleartext_traffic",
                "severity": "high",
                "title": "允许明文网络流量",
                "description": "应用允许明文HTTP流量，攻击者可以通过中间人攻击窃取或篡改网络数据",
                "impact": "数据泄露、会话劫持、数据篡改",
                "remediation": "设置android:usesCleartextTraffic=\"false\"，配置network_security_config.xml只允许HTTPS，targetSdkVersion >= 28"
            })

        # 4. 危险权限过多
        if len(result.dangerous_permissions) >= 5:
            vulns.append({
                "type": "excessive_dangerous_permissions",
                "severity": "medium",
                "title": "申请过多危险权限",
                "description": f"应用申请了{len(result.dangerous_permissions)}个危险权限，可能存在权限过度申请问题",
                "impact": "用户隐私泄露、权限滥用",
                "remediation": "遵循最小权限原则，只申请必要的权限，运行时动态申请权限"
            })

        # 5. 硬编码密钥
        if len(result.hardcoded_secrets) > 0:
            high_secrets = [s for s in result.hardcoded_secrets if s["severity"] == "high"]
            if high_secrets:
                vulns.append({
                    "type": "hardcoded_secrets",
                    "severity": "critical",
                    "title": "硬编码敏感密钥",
                    "description": f"在应用中发现{len(high_secrets)}个硬编码的敏感密钥（API Key/Token/密码等）",
                    "impact": "API密钥泄露、账户被盗、服务被滥用",
                    "remediation": "将密钥存储在服务器端，通过安全API获取；使用Android Keystore存储敏感密钥；使用NDK将密钥存储在native层"
                })

        # 6. 导出组件
        if len(result.exported_components) > 0:
            vulns.append({
                "type": "exported_components",
                "severity": "medium",
                "title": "存在导出组件",
                "description": "应用存在exported=true的组件，可能被其他应用调用，存在组件安全风险",
                "impact": "未授权访问、数据泄露、权限提升",
                "remediation": "只导出必要的组件，为导出组件设置permission保护，检查组件内部的权限验证"
            })

        # 7. 弱目标SDK
        try:
            target_sdk = int(result.target_sdk) if result.target_sdk else 0
            if target_sdk > 0 and target_sdk < 26:
                vulns.append({
                    "type": "low_target_sdk",
                    "severity": "medium",
                    "title": "目标SDK版本过低",
                    "description": f"应用targetSdkVersion为{target_sdk}，低于Android 8.0(API 26)，无法享受最新的安全特性",
                    "impact": "无法使用最新安全特性，存在已知安全漏洞",
                    "remediation": "升级targetSdkVersion到最新版本（建议33+），适配最新Android版本的安全特性"
                })
        except:
            pass

        # 8. WebView安全问题
        webview_issues = [a for a in result.insecure_apis if "WebView" in a]
        if webview_issues:
            vulns.append({
                "type": "webview_security",
                "severity": "high",
                "title": "WebView安全配置问题",
                "description": "应用存在WebView安全问题（启用JS/添加JS接口/执行JS等），可能存在XSS或RCE风险",
                "impact": "XSS攻击、远程代码执行、Cookie窃取",
                "remediation": "除非必要，不启用setJavaScriptEnabled；不使用addJavascriptInterface；设置WebViewClient和WebChromeClient；启用DOM存储和数据库时注意安全"
            })

        # 9. 弱加密算法
        weak_crypto = [a for a in result.insecure_apis if "弱加密" in a or "DES" in a or "MD5" in a or "SHA1" in a]
        if weak_crypto:
            vulns.append({
                "type": "weak_cryptography",
                "severity": "medium",
                "title": "使用弱加密算法",
                "description": "应用使用了弱加密算法（DES/3DES/RC4/MD5/SHA1），容易被破解",
                "impact": "加密数据被破解、数据泄露",
                "remediation": "使用AES-256-GCM替代DES/3DES；使用SHA-256/SHA-3替代MD5/SHA1；使用RSA-2048+或ECC；使用SecureRandom生成随机数"
            })

        # 10. 证书验证问题
        cert_issues = [a for a in result.insecure_apis if "TrustManager" in a or "HostnameVerifier" in a or "证书" in a]
        if cert_issues:
            vulns.append({
                "type": "insecure_certificate_validation",
                "severity": "critical",
                "title": "不安全的证书验证",
                "description": "应用存在自定义TrustManager或HostnameVerifier实现，可能忽略证书验证，存在中间人攻击风险",
                "impact": "中间人攻击、数据泄露、会话劫持",
                "remediation": "不要自定义TrustManager或HostnameVerifier来忽略证书验证；使用系统默认的证书验证；使用CertificatePinning（证书锁定）"
            })

        result.vulnerabilities = vulns

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total_vulns = sum(len(h.get("vulnerabilities", [])) for h in self.analysis_history)
        by_severity = Counter()
        for h in self.analysis_history:
            for v in h.get("vulnerabilities", []):
                by_severity[v.get("severity", "unknown")] += 1

        return {
            "total_analyses": len(self.analysis_history),
            "total_vulnerabilities": total_vulns,
            "by_severity": dict(by_severity),
            "supported_features": [
                "APK静态分析", "Manifest解析", "权限分析", "组件安全分析",
                "硬编码密钥扫描", "不安全API检测", "网络安全配置检查",
                "漏洞自动检测", "风险评分", "文件哈希计算"
            ]
        }


# 全局实例
mobile_security_analyzer = MobileSecurityAnalyzer()
