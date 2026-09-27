#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
移动端安全深化模块
Mobile Security Advanced Module

功能：Frida集成、动态分析、iOS安全、Android深度检测、Hook框架、应用行为分析
"""

import os
import json
import time
import uuid
import subprocess
import re
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum
from loguru import logger


class MobilePlatform(str, Enum):
    """移动平台"""
    ANDROID = "android"
    IOS = "ios"
    HARMONY = "harmony"  # 鸿蒙


class AnalysisType(str, Enum):
    """分析类型"""
    STATIC = "static"        # 静态分析
    DYNAMIC = "dynamic"      # 动态分析
    RUNTIME = "runtime"      # 运行时分析
    BEHAVIOR = "behavior"    # 行为分析
    NETWORK = "network"      # 网络分析
    MEMORY = "memory"        # 内存分析


class RiskLevel(str, Enum):
    """风险等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class MobileAppInfo:
    """移动应用信息"""
    app_id: str
    package_name: str
    app_name: str = ""
    version: str = ""
    platform: MobilePlatform = MobilePlatform.ANDROID
    file_path: str = ""
    file_size: int = 0
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    certificates: List[Dict[str, Any]] = field(default_factory=list)
    sdk_components: List[Dict[str, Any]] = field(default_factory=list)
    analyzed_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['platform'] = self.platform.value
        return result


@dataclass
class SecurityFinding:
    """安全发现"""
    finding_id: str
    title: str
    description: str
    risk_level: RiskLevel
    category: str
    evidence: str = ""
    location: str = ""
    recommendation: str = ""
    cwe_id: str = ""
    references: List[str] = field(default_factory=list)
    false_positive: bool = False
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding_id': self.finding_id,
            'title': self.title,
            'description': self.description,
            'risk_level': self.risk_level.value,
            'category': self.category,
            'evidence': self.evidence,
            'location': self.location,
            'recommendation': self.recommendation,
            'cwe_id': self.cwe_id,
            'references': self.references,
            'false_positive': self.false_positive,
            'detected_at': self.detected_at,
        }


@dataclass
class FridaHook:
    """Frida Hook配置"""
    hook_id: str
    name: str
    description: str
    module: str
    function: str
    script: str
    arguments: List[str] = field(default_factory=list)
    return_value: bool = True
    log_calls: bool = True
    modify_args: bool = False
    modify_return: bool = False
    is_active: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeEvent:
    """运行时事件"""
    event_id: str
    event_type: str  # method_call, network_request, file_access, database_query, crypto_operation
    timestamp: float
    process: str = ""
    thread: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    stack_trace: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MobileSecurityAnalyzer:
    """移动端安全分析器"""

    def __init__(self, workspace: str = "data/mobile_security"):
        self.workspace = workspace
        self.apps_dir = os.path.join(workspace, "apps")
        self.reports_dir = os.path.join(workspace, "reports")
        self.hooks_dir = os.path.join(workspace, "hooks")

        self._apps: Dict[str, MobileAppInfo] = {}
        self._findings: Dict[str, SecurityFinding] = {}
        self._hooks: Dict[str, FridaHook] = {}
        self._runtime_events: List[RuntimeEvent] = []
        self._frida_process: Optional[subprocess.Popen] = None

        os.makedirs(self.apps_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.hooks_dir, exist_ok=True)

        self._init_builtin_hooks()
        logger.info("移动端安全分析器初始化完成")

    def _init_builtin_hooks(self):
        """初始化内置Hook"""
        builtin_hooks = [
            FridaHook(
                hook_id="builtin_ssl_pinning_bypass",
                name="SSL Pinning Bypass",
                description="绕过SSL证书绑定，用于抓包分析",
                module="okhttp3",
                function="CertificatePinner.check",
                script="""
Java.perform(function() {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(str, list) {
        console.log('[SSL Pinning Bypass] ' + str);
        return;
    };
});
""",
                is_active=False,
            ),
            FridaHook(
                hook_id="builtin_root_detection_bypass",
                name="Root Detection Bypass",
                description="绕过Root检测",
                module="android.os",
                function="Build.TAGS",
                script="""
Java.perform(function() {
    var Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'TAGS', {
        get: function() { return 'release-keys'; }
    });
    
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmd) {
        if (cmd.toString().indexOf('su') !== -1) {
            console.log('[Root Bypass] Blocked: ' + cmd);
            return this.exec(['echo', '']);
        }
        return this.exec(cmd);
    };
});
""",
                is_active=False,
            ),
            FridaHook(
                hook_id="builtin_crypto_monitor",
                name="Crypto Operation Monitor",
                description="监控加密操作，记录密钥和算法",
                module="javax.crypto",
                function="Cipher.init",
                script="""
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
        console.log('[Crypto] mode=' + mode + ' algorithm=' + key.getAlgorithm());
        return this.init(mode, key);
    };
    
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.digest.overload('[B').implementation = function(data) {
        var result = this.digest(data);
        console.log('[Hash] ' + this.getAlgorithm() + ' input=' + data.length + ' bytes');
        return result;
    };
});
""",
                is_active=False,
            ),
            FridaHook(
                hook_id="builtin_network_monitor",
                name="Network Request Monitor",
                description="监控所有网络请求，记录URL和数据",
                module="okhttp3",
                function="RealCall.execute",
                script="""
Java.perform(function() {
    var RealCall = Java.use('okhttp3.RealCall');
    RealCall.execute.implementation = function() {
        var request = this.request();
        console.log('[Network] ' + request.method() + ' ' + request.url());
        var response = this.execute();
        console.log('[Network] Response: ' + response.code());
        return response;
    };
    
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');
    HttpURLConnection.getInputStream.implementation = function() {
        console.log('[HTTP] ' + this.getURL().toString());
        return this.getInputStream();
    };
});
""",
                is_active=False,
            ),
            FridaHook(
                hook_id="builtin_file_access_monitor",
                name="File Access Monitor",
                description="监控文件读写操作",
                module="java.io",
                function="FileInputStream.<init>",
                script="""
Java.perform(function() {
    var FileInputStream = Java.use('java.io.FileInputStream');
    FileInputStream.$init.overload('java.io.File').implementation = function(file) {
        console.log('[File Read] ' + file.getAbsolutePath());
        return this.$init(file);
    };
    
    var FileOutputStream = Java.use('java.io.FileOutputStream');
    FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
        console.log('[File Write] ' + file.getAbsolutePath());
        return this.$init(file);
    };
});
""",
                is_active=False,
            ),
            FridaHook(
                hook_id="builtin_database_monitor",
                name="Database Query Monitor",
                description="监控SQLite数据库查询",
                module="android.database.sqlite",
                function="SQLiteDatabase.rawQuery",
                script="""
Java.perform(function() {
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {
        console.log('[SQL] ' + sql);
        return this.rawQuery(sql, args);
    };
    
    SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
        console.log('[SQL Exec] ' + sql);
        return this.execSQL(sql);
    };
});
""",
                is_active=False,
            ),
        ]

        for hook in builtin_hooks:
            self._hooks[hook.hook_id] = hook

    # ============== APK静态分析 ==============

    def analyze_apk(self, apk_path: str) -> Optional[MobileAppInfo]:
        """分析APK文件"""
        if not os.path.exists(apk_path):
            logger.error(f"APK文件不存在: {apk_path}")
            return None

        app_id = str(uuid.uuid4())
        app_info = MobileAppInfo(
            app_id=app_id,
            package_name="",
            file_path=apk_path,
            file_size=os.path.getsize(apk_path),
            platform=MobilePlatform.ANDROID,
        )

        # 尝试使用aapt分析
        try:
            result = subprocess.run(
                ['aapt', 'dump', 'badging', apk_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                self._parse_aapt_output(app_info, result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("aapt不可用，使用基础分析")

        # 基础ZIP分析（APK本质是ZIP）
        try:
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as zf:
                files = zf.namelist()
                app_info.libraries = [f for f in files if f.startswith('lib/') and f.endswith('.so')]
                app_info.activities = self._extract_manifest_info(zf, 'activity')
        except Exception as e:
            logger.warning(f"ZIP分析失败: {e}")

        # 权限检测
        self._check_permissions(app_info)

        # 安全检测
        findings = self._run_security_checks(app_info)
        for finding in findings:
            self._findings[finding.finding_id] = finding

        self._apps[app_id] = app_info
        logger.info(f"APK分析完成: {app_info.package_name or apk_path}, 发现 {len(findings)} 个安全问题")

        return app_info

    def _parse_aapt_output(self, app_info: MobileAppInfo, output: str):
        """解析aapt输出"""
        for line in output.split('\n'):
            if line.startswith('package:'):
                match = re.search(r"name='([^']+)'", line)
                if match:
                    app_info.package_name = match.group(1)
                match = re.search(r"versionName='([^']+)'", line)
                if match:
                    app_info.version = match.group(1)
                match = re.search(r"versionCode='([^']+)'", line)
                if match:
                    pass
            elif line.startswith('application-label:'):
                match = re.search(r"'([^']+)'", line)
                if match:
                    app_info.app_name = match.group(1)
            elif line.startswith('sdkVersion:'):
                match = re.search(r"'([^']+)'", line)
                if match:
                    app_info.min_sdk = int(match.group(1))
            elif line.startswith('targetSdkVersion:'):
                match = re.search(r"'([^']+)'", line)
                if match:
                    app_info.target_sdk = int(match.group(1))
            elif line.startswith('uses-permission:'):
                match = re.search(r"name='([^']+)'", line)
                if match:
                    app_info.permissions.append(match.group(1))

    def _extract_manifest_info(self, zip_file, component_type: str) -> List[str]:
        """从Manifest提取组件信息（简化版）"""
        # 实际需要解析AndroidManifest.xml二进制，这里返回空
        return []

    def _check_permissions(self, app_info: MobileAppInfo):
        """检查权限风险"""
        dangerous_permissions = {
            'android.permission.READ_SMS': '读取短信',
            'android.permission.SEND_SMS': '发送短信',
            'android.permission.RECEIVE_SMS': '接收短信',
            'android.permission.READ_CONTACTS': '读取通讯录',
            'android.permission.WRITE_CONTACTS': '写入通讯录',
            'android.permission.READ_CALL_LOG': '读取通话记录',
            'android.permission.WRITE_CALL_LOG': '写入通话记录',
            'android.permission.RECORD_AUDIO': '录音',
            'android.permission.CAMERA': '相机',
            'android.permission.ACCESS_FINE_LOCATION': '精确定位',
            'android.permission.ACCESS_COARSE_LOCATION': '粗略定位',
            'android.permission.READ_EXTERNAL_STORAGE': '读取外部存储',
            'android.permission.WRITE_EXTERNAL_STORAGE': '写入外部存储',
            'android.permission.INSTALL_PACKAGES': '安装应用',
            'android.permission.DELETE_PACKAGES': '删除应用',
            'android.permission.SYSTEM_ALERT_WINDOW': '悬浮窗',
            'android.permission.BIND_ACCESSIBILITY_SERVICE': '无障碍服务',
        }

        for perm in app_info.permissions:
            if perm in dangerous_permissions:
                finding = SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    title=f"敏感权限: {dangerous_permissions[perm]}",
                    description=f"应用请求了敏感权限 {perm}，可能存在隐私风险",
                    risk_level=RiskLevel.MEDIUM,
                    category="permission",
                    location=perm,
                    recommendation="检查该权限是否为应用功能必需，非必需则应移除",
                    cwe_id="CWE-272",
                )
                self._findings[finding.finding_id] = finding

    def _run_security_checks(self, app_info: MobileAppInfo) -> List[SecurityFinding]:
        """运行安全检查"""
        findings = []

        # 检查调试模式
        if app_info.file_path and self._check_debuggable(app_info.file_path):
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title="应用可调试",
                description="应用设置了android:debuggable=true，攻击者可以附加调试器",
                risk_level=RiskLevel.HIGH,
                category="configuration",
                recommendation="发布版本应设置android:debuggable=false",
                cwe_id="CWE-489",
            ))

        # 检查备份允许
        if app_info.file_path and self._check_allow_backup(app_info.file_path):
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title="允许应用数据备份",
                description="应用设置了android:allowBackup=true，数据可通过adb backup导出",
                risk_level=RiskLevel.MEDIUM,
                category="configuration",
                recommendation="敏感应用应设置android:allowBackup=false",
                cwe_id="CWE-530",
            ))

        # 检查目标SDK版本
        if app_info.target_sdk and app_info.target_sdk < 28:
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title="目标SDK版本过低",
                description=f"目标SDK版本为 {app_info.target_sdk}，低于Android 9.0 (API 28)，缺少安全增强",
                risk_level=RiskLevel.MEDIUM,
                category="configuration",
                recommendation="升级目标SDK到最新版本",
                cwe_id="CWE-1104",
            ))

        # 检查最低SDK版本
        if app_info.min_sdk and app_info.min_sdk < 21:
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title="最低SDK版本过低",
                description=f"最低SDK版本为 {app_info.min_sdk}，支持过旧的Android版本，存在安全风险",
                risk_level=RiskLevel.LOW,
                category="configuration",
                recommendation="提高最低SDK版本到Android 5.0 (API 21)以上",
            ))

        # 检查不安全的网络配置
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            title="网络安全配置检查",
            description="建议检查是否使用明文HTTP传输，应配置network_security_config.xml强制HTTPS",
            risk_level=RiskLevel.INFO,
            category="network",
            recommendation="配置network_security_config.xml，禁止明文传输",
            cwe_id="CWE-319",
        ))

        # 检查代码混淆
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            title="代码混淆检查",
            description="建议启用ProGuard/R8代码混淆，增加逆向难度",
            risk_level=RiskLevel.INFO,
            category="obfuscation",
            recommendation="在build.gradle中启用minifyEnabled true",
            cwe_id="CWE-656",
        ))

        # 检查第三方SDK
        if app_info.libraries:
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title="第三方Native库检测",
                description=f"检测到 {len(app_info.libraries)} 个Native库(.so)，建议检查是否存在已知漏洞",
                risk_level=RiskLevel.INFO,
                category="third_party",
                recommendation="检查第三方库版本，及时更新存在漏洞的库",
            ))

        return findings

    def _check_debuggable(self, apk_path: str) -> bool:
        """检查是否可调试（简化检查）"""
        # 实际需要解析AndroidManifest.xml，这里返回False
        return False

    def _check_allow_backup(self, apk_path: str) -> bool:
        """检查是否允许备份（简化检查）"""
        return False

    # ============== Frida动态分析 ==============

    def start_frida_hook(self, hook_id: str, package_name: str,
                          device_id: str = None) -> Tuple[bool, str]:
        """启动Frida Hook"""
        hook = self._hooks.get(hook_id)
        if not hook:
            return False, "Hook不存在"

        # 检查frida是否安装
        try:
            subprocess.run(['frida', '--version'], capture_output=True, timeout=5)
        except FileNotFoundError:
            return False, "Frida未安装，请运行: pip install frida-tools"

        # 生成Frida脚本
        script_path = os.path.join(self.hooks_dir, f"{hook_id}.js")
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(hook.script)

        # 启动Frida
        cmd = ['frida', '-U', '-f', package_name, '-l', script_path]
        if device_id:
            cmd.extend(['--device', device_id])

        try:
            self._frida_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            hook.is_active = True
            logger.info(f"Frida Hook已启动: {hook.name} -> {package_name}")
            return True, "Hook已启动"
        except Exception as e:
            return False, f"启动失败: {e}"

    def stop_frida_hook(self, hook_id: str) -> bool:
        """停止Frida Hook"""
        hook = self._hooks.get(hook_id)
        if hook:
            hook.is_active = False

        if self._frida_process:
            self._frida_process.terminate()
            self._frida_process = None

        return True

    def list_hooks(self, active_only: bool = False) -> List[FridaHook]:
        """列出Hook"""
        hooks = list(self._hooks.values())
        if active_only:
            hooks = [h for h in hooks if h.is_active]
        return sorted(hooks, key=lambda h: h.name)

    def add_custom_hook(self, name: str, description: str, module: str,
                        function: str, script: str) -> FridaHook:
        """添加自定义Hook"""
        hook = FridaHook(
            hook_id=f"custom_{uuid.uuid4().hex[:12]}",
            name=name,
            description=description,
            module=module,
            function=function,
            script=script,
        )
        self._hooks[hook.hook_id] = hook
        return hook

    # ============== 运行时事件 ==============

    def add_runtime_event(self, event_type: str, process: str = "",
                          details: Dict[str, Any] = None) -> RuntimeEvent:
        """添加运行时事件"""
        event = RuntimeEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=time.time(),
            process=process,
            details=details or {},
        )
        self._runtime_events.append(event)
        if len(self._runtime_events) > 10000:
            self._runtime_events = self._runtime_events[-10000:]
        return event

    def get_runtime_events(self, event_type: str = None,
                            process: str = None, limit: int = 100) -> List[RuntimeEvent]:
        """获取运行时事件"""
        events = list(self._runtime_events)
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if process:
            events = [e for e in events if e.process == process]
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[:limit]

    # ============== iOS安全检查 ==============

    def analyze_ipa(self, ipa_path: str) -> Optional[MobileAppInfo]:
        """分析IPA文件（iOS应用）"""
        if not os.path.exists(ipa_path):
            return None

        app_id = str(uuid.uuid4())
        app_info = MobileAppInfo(
            app_id=app_id,
            package_name="",
            file_path=ipa_path,
            file_size=os.path.getsize(ipa_path),
            platform=MobilePlatform.IOS,
        )

        # IPA也是ZIP格式
        try:
            import zipfile
            with zipfile.ZipFile(ipa_path, 'r') as zf:
                files = zf.namelist()
                # 查找Info.plist
                info_plist = [f for f in files if f.endswith('Info.plist')]
                if info_plist:
                    app_info.app_name = "iOS App"
                    app_info.package_name = "com.example.app"
        except Exception as e:
            logger.warning(f"IPA分析失败: {e}")

        # iOS安全检查
        findings = [
            SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title="ATS配置检查",
                description="建议检查App Transport Security配置，禁止任意HTTP加载",
                risk_level=RiskLevel.MEDIUM,
                category="network",
                recommendation="在Info.plist中配置NSAppTransportSecurity，设置NSAllowsArbitraryLoads=false",
            ),
            SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title="越狱检测检查",
                description="建议实现越狱检测，防止应用在越狱设备上运行",
                risk_level=RiskLevel.MEDIUM,
                category="security",
                recommendation="检查Cydia.app、/bin/bash、/etc/apt等越狱特征文件",
            ),
            SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title="调试器检测检查",
                description="建议实现调试器检测，防止动态调试",
                risk_level=RiskLevel.LOW,
                category="security",
                recommendation="使用sysctl检查P_TRACED标志，或使用ptrace(PT_DENY_ATTACH)",
            ),
            SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title="Keychain数据保护",
                description="建议检查Keychain数据保护级别，敏感数据应使用kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
                risk_level=RiskLevel.MEDIUM,
                category="data_protection",
                recommendation="使用最高级别的Keychain保护策略",
            ),
            SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title="数据加密检查",
                description="建议检查敏感数据是否使用AES等强加密算法存储",
                risk_level=RiskLevel.HIGH,
                category="cryptography",
                recommendation="使用CommonCrypto框架，AES-256加密敏感数据",
            ),
        ]

        for finding in findings:
            self._findings[finding.finding_id] = finding

        self._apps[app_id] = app_info
        return app_info

    # ============== 报告生成 ==============

    def generate_report(self, app_id: str) -> Optional[Dict[str, Any]]:
        """生成分析报告"""
        app = self._apps.get(app_id)
        if not app:
            return None

        findings = [f for f in self._findings.values() if f.finding_id]

        risk_summary = {level.value: 0 for level in RiskLevel}
        for finding in findings:
            risk_summary[finding.risk_level.value] += 1

        overall_risk = "low"
        if risk_summary['critical'] > 0:
            overall_risk = "critical"
        elif risk_summary['high'] > 0:
            overall_risk = "high"
        elif risk_summary['medium'] > 0:
            overall_risk = "medium"

        return {
            'app_info': app.to_dict(),
            'findings': [f.to_dict() for f in findings],
            'risk_summary': risk_summary,
            'overall_risk': overall_risk,
            'total_findings': len(findings),
            'generated_at': time.time(),
        }

    # ============== 统计 ==============

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'total_apps_analyzed': len(self._apps),
            'total_findings': len(self._findings),
            'total_hooks': len(self._hooks),
            'active_hooks': len([h for h in self._hooks.values() if h.is_active]),
            'runtime_events': len(self._runtime_events),
            'android_apps': len([a for a in self._apps.values() if a.platform == MobilePlatform.ANDROID]),
            'ios_apps': len([a for a in self._apps.values() if a.platform == MobilePlatform.IOS]),
        }


# 全局移动端安全分析器实例
_global_mobile_analyzer: Optional[MobileSecurityAnalyzer] = None


def get_mobile_analyzer() -> MobileSecurityAnalyzer:
    """获取全局移动端安全分析器实例"""
    global _global_mobile_analyzer
    if _global_mobile_analyzer is None:
        _global_mobile_analyzer = MobileSecurityAnalyzer()
    return _global_mobile_analyzer
