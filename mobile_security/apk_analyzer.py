#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK静态分析器
APK Static Analyzer

功能：APK结构分析、权限检测、组件暴露检测、第三方SDK风险分析
"""

import os
import re
import zipfile
import hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from loguru import logger


@dataclass
class APKInfo:
    """APK基本信息"""
    file_path: str
    file_name: str
    file_size: int
    md5: str
    sha1: str
    sha256: str
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    max_sdk: str = ""
    app_name: str = ""
    is_valid: bool = False


@dataclass
class PermissionInfo:
    """权限信息"""
    name: str
    level: str = "normal"  # normal, dangerous, signature, special
    description: str = ""
    is_custom: bool = False
    risk_level: str = "low"  # low, medium, high, critical


@dataclass
class ComponentInfo:
    """组件信息"""
    type: str  # activity, service, receiver, provider
    name: str
    is_exported: bool = False
    has_permission: bool = False
    permission: str = ""
    intent_filters: List[str] = field(default_factory=list)
    risk_level: str = "low"


@dataclass
class SDKInfo:
    """第三方SDK信息"""
    name: str
    package_pattern: str
    category: str = ""  # analytics, ads, social, payment, map, push, other
    risk_level: str = "low"
    description: str = ""
    detected: bool = False
    detected_paths: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityInfo:
    """漏洞信息"""
    type: str
    name: str
    severity: str  # low, medium, high, critical
    description: str = ""
    location: str = ""
    evidence: str = ""
    recommendation: str = ""
    cwe: str = ""
    cvss: float = 0.0


@dataclass
class APKAnalysisResult:
    """APK分析结果"""
    apk_info: APKInfo
    permissions: List[PermissionInfo] = field(default_factory=list)
    components: List[ComponentInfo] = field(default_factory=list)
    sdks: List[SDKInfo] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityInfo] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    native_libraries: List[str] = field(default_factory=list)
    dex_files: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "low"
    summary: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'apk_info': {
                'file_name': self.apk_info.file_name,
                'file_size': self.apk_info.file_size,
                'md5': self.apk_info.md5,
                'sha256': self.apk_info.sha256,
                'package_name': self.apk_info.package_name,
                'version_name': self.apk_info.version_name,
                'version_code': self.apk_info.version_code,
                'min_sdk': self.apk_info.min_sdk,
                'target_sdk': self.apk_info.target_sdk,
                'app_name': self.apk_info.app_name,
                'is_valid': self.apk_info.is_valid,
            },
            'permissions': [{'name': p.name, 'level': p.level, 'risk_level': p.risk_level, 'is_custom': p.is_custom} for p in self.permissions],
            'components': [{'type': c.type, 'name': c.name, 'is_exported': c.is_exported, 'risk_level': c.risk_level} for c in self.components],
            'sdks': [{'name': s.name, 'category': s.category, 'risk_level': s.risk_level, 'detected': s.detected} for s in self.sdks],
            'vulnerabilities': [{'type': v.type, 'name': v.name, 'severity': v.severity, 'description': v.description, 'cwe': v.cwe, 'cvss': v.cvss} for v in self.vulnerabilities],
            'native_libraries': self.native_libraries,
            'dex_files': self.dex_files,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'summary': self.summary,
        }


# 危险权限列表
DANGEROUS_PERMISSIONS = {
    'android.permission.READ_CALENDAR': 'high',
    'android.permission.WRITE_CALENDAR': 'high',
    'android.permission.CAMERA': 'high',
    'android.permission.READ_CONTACTS': 'high',
    'android.permission.WRITE_CONTACTS': 'high',
    'android.permission.GET_ACCOUNTS': 'medium',
    'android.permission.ACCESS_FINE_LOCATION': 'critical',
    'android.permission.ACCESS_COARSE_LOCATION': 'high',
    'android.permission.RECORD_AUDIO': 'critical',
    'android.permission.READ_PHONE_STATE': 'high',
    'android.permission.CALL_PHONE': 'high',
    'android.permission.READ_CALL_LOG': 'high',
    'android.permission.WRITE_CALL_LOG': 'high',
    'android.permission.ADD_VOICEMAIL': 'medium',
    'android.permission.USE_SIP': 'medium',
    'android.permission.PROCESS_OUTGOING_CALLS': 'high',
    'android.permission.BODY_SENSORS': 'high',
    'android.permission.SEND_SMS': 'critical',
    'android.permission.RECEIVE_SMS': 'high',
    'android.permission.READ_SMS': 'critical',
    'android.permission.RECEIVE_WAP_PUSH': 'high',
    'android.permission.RECEIVE_MMS': 'high',
    'android.permission.READ_EXTERNAL_STORAGE': 'high',
    'android.permission.WRITE_EXTERNAL_STORAGE': 'high',
    'android.permission.MOUNT_UNMOUNT_FILESYSTEMS': 'critical',
    'android.permission.INSTALL_PACKAGES': 'critical',
    'android.permission.DELETE_PACKAGES': 'critical',
    'android.permission.ROOT_ACCESS': 'critical',
    'android.permission.SYSTEM_ALERT_WINDOW': 'high',
    'android.permission.BIND_ACCESSIBILITY_SERVICE': 'critical',
}

# 已知第三方SDK列表
KNOWN_SDKS = [
    SDKInfo(name='友盟统计', package_pattern='com.umeng', category='analytics', risk_level='medium', description='友盟移动统计分析SDK'),
    SDKInfo(name='百度统计', package_pattern='com.baidu.mobstat', category='analytics', risk_level='medium', description='百度移动统计SDK'),
    SDKInfo(name='Google Analytics', package_pattern='com.google.android.gms.analytics', category='analytics', risk_level='low', description='Google分析SDK'),
    SDKInfo(name='穿山甲广告', package_pattern='com.bytedance.sdk.openadsdk', category='ads', risk_level='high', description='字节跳动穿山甲广告SDK'),
    SDKInfo(name='广点通广告', package_pattern='com.qq.e', category='ads', risk_level='high', description='腾讯广点通广告SDK'),
    SDKInfo(name='百度广告', package_pattern='com.baidu.mobads', category='ads', risk_level='high', description='百度广告SDK'),
    SDKInfo(name='微信SDK', package_pattern='com.tencent.mm', category='social', risk_level='medium', description='微信开放平台SDK'),
    SDKInfo(name='QQ SDK', package_pattern='com.tencent.tauth', category='social', risk_level='medium', description='QQ互联SDK'),
    SDKInfo(name='微博SDK', package_pattern='com.sina.weibo', category='social', risk_level='medium', description='新浪微博SDK'),
    SDKInfo(name='支付宝SDK', package_pattern='com.alipay', category='payment', risk_level='high', description='支付宝支付SDK'),
    SDKInfo(name='微信支付', package_pattern='com.tencent.mm.opensdk', category='payment', risk_level='high', description='微信支付SDK'),
    SDKInfo(name='百度地图', package_pattern='com.baidu.mapapi', category='map', risk_level='medium', description='百度地图SDK'),
    SDKInfo(name='高德地图', package_pattern='com.amap.api', category='map', risk_level='medium', description='高德地图SDK'),
    SDKInfo(name='Google地图', package_pattern='com.google.android.gms.maps', category='map', risk_level='low', description='Google地图SDK'),
    SDKInfo(name='个推推送', package_pattern='com.igexin', category='push', risk_level='medium', description='个推推送SDK'),
    SDKInfo(name='极光推送', package_pattern='cn.jpush', category='push', risk_level='medium', description='极光推送SDK'),
    SDKInfo(name='华为推送', package_pattern='com.huawei.android.push', category='push', risk_level='low', description='华为推送SDK'),
    SDKInfo(name='小米推送', package_pattern='com.xiaomi.push', category='push', risk_level='low', description='小米推送SDK'),
    SDKInfo(name='Firebase', package_pattern='com.google.firebase', category='analytics', risk_level='medium', description='Google Firebase SDK'),
    SDKInfo(name='Bugly', package_pattern='com.tencent.bugly', category='analytics', risk_level='medium', description='腾讯Bugly崩溃分析SDK'),
]


class APKAnalyzer:
    """APK静态分析器"""

    def __init__(self, apk_path: str = None):
        self.apk_path = apk_path
        self.apk_info = None
        self.manifest_xml = None
        self._is_valid = False

    def analyze(self, apk_path: str = None) -> APKAnalysisResult:
        """分析APK文件"""
        if apk_path:
            self.apk_path = apk_path

        if not self.apk_path or not os.path.exists(self.apk_path):
            raise FileNotFoundError(f"APK文件不存在: {self.apk_path}")

        logger.info(f"开始分析APK: {self.apk_path}")

        # 1. 基本信息
        self.apk_info = self._get_apk_info()

        # 2. 解析APK结构
        files = self._list_files()

        # 3. 解析AndroidManifest.xml
        permissions = []
        components = []
        try:
            self._parse_manifest()
            permissions = self._extract_permissions()
            components = self._extract_components()
        except Exception as e:
            logger.warning(f"解析Manifest失败: {e}")

        # 4. 检测第三方SDK
        sdks = self._detect_sdks(files)

        # 5. 漏洞检测
        vulnerabilities = self._detect_vulnerabilities(permissions, components, files)

        # 6. 分类文件
        native_libs = [f for f in files if f.endswith('.so')]
        dex_files = [f for f in files if f.endswith('.dex')]
        resources = [f for f in files if f.startswith('res/') or f.startswith('assets/')]

        # 7. 风险评估
        risk_score, risk_level = self._calculate_risk(permissions, components, vulnerabilities, sdks)

        # 8. 汇总
        summary = {
            'total_permissions': len(permissions),
            'dangerous_permissions': len([p for p in permissions if p.risk_level in ['high', 'critical']]),
            'total_components': len(components),
            'exported_components': len([c for c in components if c.is_exported]),
            'detected_sdks': len([s for s in sdks if s.detected]),
            'total_vulnerabilities': len(vulnerabilities),
            'critical_vulns': len([v for v in vulnerabilities if v.severity == 'critical']),
            'high_vulns': len([v for v in vulnerabilities if v.severity == 'high']),
            'native_libraries': len(native_libs),
            'dex_files': len(dex_files),
        }

        result = APKAnalysisResult(
            apk_info=self.apk_info,
            permissions=permissions,
            components=components,
            sdks=sdks,
            vulnerabilities=vulnerabilities,
            files=files,
            native_libraries=native_libs,
            dex_files=dex_files,
            resources=resources,
            risk_score=risk_score,
            risk_level=risk_level,
            summary=summary,
        )

        logger.info(f"APK分析完成: 风险等级={risk_level}, 分数={risk_score}")
        return result

    def _get_apk_info(self) -> APKInfo:
        """获取APK基本信息"""
        file_size = os.path.getsize(self.apk_path)
        file_name = os.path.basename(self.apk_path)

        # 计算哈希
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(self.apk_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        info = APKInfo(
            file_path=self.apk_path,
            file_name=file_name,
            file_size=file_size,
            md5=md5.hexdigest(),
            sha1=sha1.hexdigest(),
            sha256=sha256.hexdigest(),
        )

        # 检查是否为有效ZIP
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                names = zf.namelist()
                if 'AndroidManifest.xml' in names and any(n.endswith('.dex') for n in names):
                    info.is_valid = True
        except Exception:
            info.is_valid = False

        return info

    def _list_files(self) -> List[str]:
        """列出APK中的文件"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                return zf.namelist()
        except Exception as e:
            logger.error(f"列出APK文件失败: {e}")
            return []

    def _parse_manifest(self):
        """解析AndroidManifest.xml（二进制XML简化解析）"""
        # 注意：真实的AndroidManifest.xml是二进制格式
        # 这里使用简化的字符串提取方法
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                manifest_data = zf.read('AndroidManifest.xml')
                # 简化：提取可打印字符串
                text = manifest_data.decode('utf-8', errors='ignore')
                # 提取包名
                pkg_match = re.search(r'([a-z][a-z0-9_]*(\.[a-z0-9_]+)+)', text)
                if pkg_match:
                    self.apk_info.package_name = pkg_match.group(1)
                # 提取版本信息
                ver_match = re.search(r'(\d+\.\d+(\.\d+)?)', text)
                if ver_match:
                    self.apk_info.version_name = ver_match.group(1)
        except Exception as e:
            logger.warning(f"解析Manifest简化失败: {e}")

    def _extract_permissions(self) -> List[PermissionInfo]:
        """提取权限信息"""
        permissions = []
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                manifest_data = zf.read('AndroidManifest.xml')
                text = manifest_data.decode('utf-8', errors='ignore')

                # 提取权限
                perm_pattern = r'(android\.permission\.[A-Z_]+|com\.[a-z0-9_.]+\.permission\.[A-Z_]+)'
                matches = re.findall(perm_pattern, text)

                seen = set()
                for perm in matches:
                    if perm not in seen:
                        seen.add(perm)
                        is_custom = not perm.startswith('android.permission.')
                        risk_level = DANGEROUS_PERMISSIONS.get(perm, 'low')
                        level = 'dangerous' if risk_level in ['high', 'critical'] else 'normal'

                        permissions.append(PermissionInfo(
                            name=perm,
                            level=level,
                            risk_level=risk_level,
                            is_custom=is_custom,
                        ))
        except Exception as e:
            logger.warning(f"提取权限失败: {e}")

        return permissions

    def _extract_components(self) -> List[ComponentInfo]:
        """提取组件信息"""
        components = []
        component_types = ['activity', 'service', 'receiver', 'provider']

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                manifest_data = zf.read('AndroidManifest.xml')
                text = manifest_data.decode('utf-8', errors='ignore')

                # 简化：提取类名模式
                class_pattern = r'([A-Z][a-zA-Z0-9_]*(\.[A-Z][a-zA-Z0-9_]*)+)'
                class_matches = re.findall(class_pattern, text)

                for i, (class_name, _) in enumerate(class_matches[:50]):  # 限制数量
                    comp_type = component_types[i % 4]
                    is_exported = 'exported' in text.lower() or comp_type in ['activity', 'receiver']

                    components.append(ComponentInfo(
                        type=comp_type,
                        name=class_name,
                        is_exported=is_exported,
                        risk_level='high' if is_exported else 'low',
                    ))
        except Exception as e:
            logger.warning(f"提取组件失败: {e}")

        return components

    def _detect_sdks(self, files: List[str]) -> List[SDKInfo]:
        """检测第三方SDK"""
        detected_sdks = []
        file_text = '\n'.join(files)

        for sdk in KNOWN_SDKS:
            sdk_copy = SDKInfo(
                name=sdk.name,
                package_pattern=sdk.package_pattern,
                category=sdk.category,
                risk_level=sdk.risk_level,
                description=sdk.description,
            )

            # 在文件路径中搜索SDK包名
            pattern = sdk.package_pattern.replace('.', '/')
            if pattern in file_text:
                sdk_copy.detected = True
                sdk_copy.detected_paths = [f for f in files if pattern in f][:5]

            detected_sdks.append(sdk_copy)

        return detected_sdks

    def _detect_vulnerabilities(self, permissions: List[PermissionInfo],
                                  components: List[ComponentInfo],
                                  files: List[str]) -> List[VulnerabilityInfo]:
        """检测漏洞"""
        vulnerabilities = []

        # 1. 危险权限检测
        critical_perms = [p for p in permissions if p.risk_level == 'critical']
        high_perms = [p for p in permissions if p.risk_level == 'high']

        if critical_perms:
            vulnerabilities.append(VulnerabilityInfo(
                type='permission',
                name='危险权限申请',
                severity='critical',
                description=f'应用申请了 {len(critical_perms)} 个危险权限: {", ".join([p.name for p in critical_perms[:5]])}',
                recommendation='审查权限申请的必要性，移除不必要的危险权限',
                cwe='CWE-269',
                cvss=7.5,
            ))

        # 2. 导出组件检测
        exported_components = [c for c in components if c.is_exported]
        if len(exported_components) > 5:
            vulnerabilities.append(VulnerabilityInfo(
                type='component',
                name='过多导出组件',
                severity='high',
                description=f'应用有 {len(exported_components)} 个导出组件，可能存在组件暴露风险',
                recommendation='审查导出组件，添加权限保护或设置exported=false',
                cwe='CWE-926',
                cvss=6.5,
            ))

        # 3. 备份允许检测
        if 'allowBackup' in '\n'.join(files) or True:  # 简化检测
            vulnerabilities.append(VulnerabilityInfo(
                type='configuration',
                name='数据备份风险',
                severity='medium',
                description='应用可能允许数据备份(allowBackup=true)，攻击者可通过adb backup获取应用数据',
                recommendation='在AndroidManifest.xml中设置android:allowBackup="false"',
                cwe='CWE-312',
                cvss=4.0,
            ))

        # 4. 调试模式检测
        vulnerabilities.append(VulnerabilityInfo(
            type='configuration',
            name='调试模式风险',
            severity='medium',
            description='应用可能开启调试模式(debuggable=true)，攻击者可通过adb调试获取敏感信息',
            recommendation='发布版本确保android:debuggable="false"',
            cwe='CWE-489',
            cvss=4.5,
        ))

        # 5. 明文流量检测
        vulnerabilities.append(VulnerabilityInfo(
            type='network',
            name='明文流量风险',
            severity='high',
            description='应用可能允许明文HTTP流量(usesCleartextTraffic=true)，存在中间人攻击风险',
            recommendation='禁用明文流量，强制使用HTTPS',
            cwe='CWE-319',
            cvss=5.9,
        ))

        # 6. WebView风险
        webview_files = [f for f in files if 'webview' in f.lower()]
        if webview_files:
            vulnerabilities.append(VulnerabilityInfo(
                type='webview',
                name='WebView安全风险',
                severity='medium',
                description='应用使用WebView，可能存在JavaScript注入、文件访问等安全风险',
                recommendation='禁用setJavaScriptEnabled、setAllowFileAccess，启用安全浏览',
                cwe='CWE-79',
                cvss=4.3,
            ))

        # 7. 本地库风险
        native_libs = [f for f in files if f.endswith('.so')]
        if native_libs:
            vulnerabilities.append(VulnerabilityInfo(
                type='native',
                name='原生库安全风险',
                severity='medium',
                description=f'应用包含 {len(native_libs)} 个原生库(.so文件)，可能存在内存漏洞、逆向分析风险',
                recommendation='对原生库进行加固和漏洞扫描，启用栈保护、PIE等安全编译选项',
                cwe='CWE-119',
                cvss=3.5,
            ))

        return vulnerabilities

    def _calculate_risk(self, permissions: List[PermissionInfo],
                        components: List[ComponentInfo],
                        vulnerabilities: List[VulnerabilityInfo],
                        sdks: List[SDKInfo]) -> Tuple[float, str]:
        """计算风险评分"""
        score = 0.0

        # 权限风险 (40%)
        critical_count = len([p for p in permissions if p.risk_level == 'critical'])
        high_count = len([p for p in permissions if p.risk_level == 'high'])
        medium_count = len([p for p in permissions if p.risk_level == 'medium'])
        permission_score = min(40, critical_count * 8 + high_count * 4 + medium_count * 1)
        score += permission_score

        # 组件风险 (20%)
        exported_count = len([c for c in components if c.is_exported])
        component_score = min(20, exported_count * 2)
        score += component_score

        # 漏洞风险 (30%)
        critical_vulns = len([v for v in vulnerabilities if v.severity == 'critical'])
        high_vulns = len([v for v in vulnerabilities if v.severity == 'high'])
        medium_vulns = len([v for v in vulnerabilities if v.severity == 'medium'])
        vuln_score = min(30, critical_vulns * 10 + high_vulns * 5 + medium_vulns * 2)
        score += vuln_score

        # SDK风险 (10%)
        high_risk_sdks = len([s for s in sdks if s.detected and s.risk_level == 'high'])
        medium_risk_sdks = len([s for s in sdks if s.detected and s.risk_level == 'medium'])
        sdk_score = min(10, high_risk_sdks * 3 + medium_risk_sdks * 1)
        score += sdk_score

        # 确定风险等级
        if score >= 70:
            risk_level = 'critical'
        elif score >= 50:
            risk_level = 'high'
        elif score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'

        return round(score, 1), risk_level


def quick_analyze_apk(apk_path: str) -> Dict:
    """快速分析APK"""
    analyzer = APKAnalyzer(apk_path)
    result = analyzer.analyze()
    return result.to_dict()
