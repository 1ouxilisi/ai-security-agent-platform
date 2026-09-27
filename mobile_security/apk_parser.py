#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK解析模块
解析Android APK文件，提取Manifest、权限、组件、签名等信息
"""

import os
import re
import zipfile
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class APKInfo:
    """APK基本信息"""
    file_path: str = ""
    file_name: str = ""
    file_size: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    max_sdk: str = ""
    compile_sdk: str = ""
    app_name: str = ""
    permissions: List[str] = field(default_factory=list)
    activities: List[Dict] = field(default_factory=list)
    services: List[Dict] = field(default_factory=list)
    receivers: List[Dict] = field(default_factory=list)
    providers: List[Dict] = field(default_factory=list)
    exported_components: List[Dict] = field(default_factory=list)
    signature: Dict = field(default_factory=dict)
    features: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    native_libs: List[str] = field(default_factory=list)
    sdk_list: List[Dict] = field(default_factory=list)
    hardcoded_strings: List[Dict] = field(default_factory=list)
    is_packed: bool = False
    packer_name: str = ""
    is_debuggable: bool = False
    allow_backup: bool = True
    cleartext_traffic: bool = False
    network_security_config: str = ""
    webview_activities: List[str] = field(default_factory=list)
    intent_filters: List[Dict] = field(default_factory=list)
    meta_data: Dict = field(default_factory=dict)
    analysis_time: str = ""


class APKParser:
    """APK解析器"""

    # 危险权限列表
    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.BODY_SENSORS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
        "android.permission.INSTALL_PACKAGES",
        "android.permission.DELETE_PACKAGES",
        "android.permission.INSTALL_LOCATION_PROVIDER",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.READ_LOGS",
        "android.permission.CHANGE_WIFI_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.CHANGE_NETWORK_STATE",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.INTERNET",
        "android.permission.BLUETOOTH",
        "android.permission.BLUETOOTH_ADMIN",
        "android.permission.NFC",
        "android.permission.FLASHLIGHT",
        "android.permission.VIBRATE",
        "android.permission.WAKE_LOCK",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.REQUEST_DELETE_PACKAGES",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.NEARBY_WIFI_DEVICES",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
    }

    # 加壳特征
    PACKER_SIGNATURES = {
        "360加固": ["libjiagu.so", "libjiagu_art.so", "libjiagu_x86.so", "com.stub.StubApp"],
        "腾讯乐固": ["libshell.so", "libshella.so", "libshellx-2.10.0.0.so", "com.tencent.StubShell"],
        "爱加密": ["libexec.so", "libexecmain.so", "libexecservice.so", "com.secshell.shellwrapper"],
        "梆梆安全": ["libsecexe.so", "libsecmain.so", "libsecshell.so", "com.bangcle.antiemulator"],
        "百度加固": ["libbaiduprotect.so", "libbaiduprotect_x86.so", "com.baidu.protect.StubApplication"],
        "阿里聚安全": ["libsgmain.so", "libsgsecuritybody.so", "libsgavmp.so", "com.alibaba.wireless.security"],
        "网易易盾": ["libnesec.so", "libntp.so", "com.netease.nesec"],
        "顶象": ["libDexHelper.so", "libDexHelper-x86.so", "com.dingxiang.anticheat"],
        "通付盾": ["libTDSafekey.so", "libTDShell.so", "com.payegis.anti"],
        "娜迦": ["libchaosvmp.so", "libddog.so", "libfdog.so", "com.nagapt.security"],
    }

    def __init__(self):
        self.apk_info = APKInfo()

    def parse(self, apk_path: str) -> APKInfo:
        """解析APK文件"""
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK文件不存在: {apk_path}")

        self.apk_info = APKInfo()
        self.apk_info.file_path = apk_path
        self.apk_info.file_name = os.path.basename(apk_path)
        self.apk_info.file_size = os.path.getsize(apk_path)
        self.apk_info.analysis_time = datetime.now().isoformat()

        # 计算文件哈希
        self._calculate_hashes(apk_path)

        # 解析ZIP内容
        self._parse_zip(apk_path)

        # 解析AndroidManifest.xml
        self._parse_manifest(apk_path)

        # 检测加壳
        self._detect_packer(apk_path)

        # 提取硬编码字符串
        self._extract_hardcoded_strings(apk_path)

        # 分析第三方SDK
        self._analyze_sdks(apk_path)

        return self.apk_info

    def _calculate_hashes(self, apk_path: str):
        """计算文件哈希"""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(apk_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        self.apk_info.md5 = md5.hexdigest()
        self.apk_info.sha1 = sha1.hexdigest()
        self.apk_info.sha256 = sha256.hexdigest()

    def _parse_zip(self, apk_path: str):
        """解析ZIP文件内容"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                file_list = zf.namelist()

                # 提取Native库
                self.apk_info.native_libs = [
                    f for f in file_list
                    if f.startswith('lib/') and f.endswith('.so')
                ]

                # 提取assets文件
                assets = [f for f in file_list if f.startswith('assets/')]

                # 检查网络安全配置
                if 'res/xml/network_security_config.xml' in file_list:
                    self.apk_info.network_security_config = 'res/xml/network_security_config.xml'

        except Exception as e:
            print(f"ZIP解析错误: {e}")

    def _parse_manifest(self, apk_path: str):
        """解析AndroidManifest.xml（简化版，使用正则从二进制中提取）"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                if 'AndroidManifest.xml' in zf.namelist():
                    manifest_data = zf.read('AndroidManifest.xml')

                    # 简化解析：从二进制中提取可读字符串
                    text = manifest_data.decode('utf-8', errors='ignore')

                    # 提取包名
                    pkg_match = re.search(r'([a-z][a-z0-9_]*(\.[a-z0-9_]+)+)', text)
                    if pkg_match:
                        self.apk_info.package_name = pkg_match.group(1)

                    # 提取权限
                    permissions = re.findall(r'(android\.permission\.[A-Z_]+)', text)
                    self.apk_info.permissions = list(set(permissions))

                    # 提取版本信息
                    version_match = re.search(r'versionName["\s=]+([0-9.]+)', text)
                    if version_match:
                        self.apk_info.version_name = version_match.group(1)

                    # 检测debuggable
                    if 'debuggable' in text.lower():
                        self.apk_info.is_debuggable = True

                    # 检测allowBackup
                    if 'allowBackup="false"' in text or 'allowBackup=false' in text:
                        self.apk_info.allow_backup = False

                    # 检测cleartextTraffic
                    if 'usesCleartextTraffic="true"' in text or 'usesCleartextTraffic=true' in text:
                        self.apk_info.cleartext_traffic = True

                    # 提取组件（简化）
                    activities = re.findall(r'(\.([A-Z][a-zA-Z0-9_]*)Activity)', text)
                    self.apk_info.activities = [{"name": a[0]} for a in activities[:50]]

                    services = re.findall(r'(\.([A-Z][a-zA-Z0-9_]*)Service)', text)
                    self.apk_info.services = [{"name": s[0]} for s in services[:50]]

                    receivers = re.findall(r'(\.([A-Z][a-zA-Z0-9_]*)Receiver)', text)
                    self.apk_info.receivers = [{"name": r[0]} for r in receivers[:50]]

                    providers = re.findall(r'(\.([A-Z][a-zA-Z0-9_]*)Provider)', text)
                    self.apk_info.providers = [{"name": p[0]} for p in providers[:50]]

                    # 检测WebView Activity
                    webview_keywords = ['WebView', 'webview', 'X5WebView', 'TBS']
                    for act in self.apk_info.activities:
                        if any(kw in act['name'] for kw in webview_keywords):
                            self.apk_info.webview_activities.append(act['name'])

        except Exception as e:
            print(f"Manifest解析错误: {e}")

    def _detect_packer(self, apk_path: str):
        """检测加壳"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                file_list = zf.namelist()
                lib_files = [f for f in file_list if f.endswith('.so')]

                for packer_name, signatures in self.PACKER_SIGNATURES.items():
                    for sig in signatures:
                        if any(sig in f for f in lib_files) or any(sig in f for f in file_list):
                            self.apk_info.is_packed = True
                            self.apk_info.packer_name = packer_name
                            return

        except Exception as e:
            print(f"加壳检测错误: {e}")

    def _extract_hardcoded_strings(self, apk_path: str):
        """提取硬编码字符串（简化版）"""
        sensitive_patterns = {
            'url': r'https?://[^\s"\'<>]+',
            'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'api_key': r'(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)["\s:=]+["\']?([a-zA-Z0-9_\-]{16,})',
            'password': r'(password|passwd|pwd)["\s:=]+["\']?([a-zA-Z0-9_\-]{6,})',
            'phone': r'1[3-9]\d{9}',
            'id_card': r'\d{17}[\dXx]',
        }

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # 从dex文件中提取字符串
                dex_files = [f for f in zf.namelist() if f.endswith('.dex')]
                for dex_file in dex_files[:3]:  # 只分析前3个dex
                    try:
                        data = zf.read(dex_file)
                        text = data.decode('utf-8', errors='ignore')

                        for pattern_name, pattern in sensitive_patterns.items():
                            matches = re.findall(pattern, text)
                            for match in matches[:20]:  # 每种最多20个
                                if isinstance(match, tuple):
                                    value = match[-1] if match[-1] else match[0]
                                else:
                                    value = match

                                if len(str(value)) > 5:  # 过滤太短的
                                    self.apk_info.hardcoded_strings.append({
                                        'type': pattern_name,
                                        'value': str(value)[:100],
                                        'source': dex_file
                                    })
                    except Exception:
                        continue

        except Exception as e:
            print(f"硬编码字符串提取错误: {e}")

    def _analyze_sdks(self, apk_path: str):
        """分析第三方SDK（简化版）"""
        sdk_signatures = {
            '微信SDK': ['com.tencent.mm', 'wxapi', 'WXEntryActivity'],
            '支付宝SDK': ['com.alipay', 'AlipayResult', 'PayTask'],
            'QQ SDK': ['com.tencent.tauth', 'Tencent', 'QQShare'],
            '微博SDK': ['com.sina.weibo', 'WbSdk', 'Weibo'],
            '百度地图': ['com.baidu.map', 'BaiduMap', 'MapView'],
            '高德地图': ['com.amap.api', 'AMap', 'MapView'],
            '腾讯地图': ['com.tencent.map', 'TencentMap', 'MapView'],
            '友盟统计': ['com.umeng', 'UMConfigure', 'MobclickAgent'],
            '百度统计': ['com.baidu.mobstat', 'StatService'],
            '腾讯统计': ['com.tencent.stat', 'StatService'],
            '个推推送': ['com.igexin', 'PushManager', 'GeTuiSdk'],
            '极光推送': ['cn.jpush', 'JPushInterface', 'PushService'],
            '小米推送': ['com.xiaomi.push', 'MiPushClient', 'PushMessageHelper'],
            '华为推送': ['com.huawei.push', 'HmsMessageService', 'PushReceiver'],
            'OPPO推送': ['com.heytap.msp', 'PushService', 'DataMessage'],
            'vivo推送': ['com.vivo.push', 'PushClient', 'PushMessageReceiver'],
            'Firebase': ['com.google.firebase', 'FirebaseApp', 'FirebaseMessaging'],
            'Google Analytics': ['com.google.android.gms.analytics', 'GoogleAnalytics'],
            'Facebook SDK': ['com.facebook', 'FacebookSdk', 'CallbackManager'],
            'Twitter SDK': ['com.twitter.sdk', 'Twitter', 'TwitterAuthClient'],
            'Bugly': ['com.tencent.bugly', 'Bugly', 'CrashReport'],
            'Crashlytics': ['com.crashlytics', 'Fabric', 'Crashlytics'],
            'Sentry': ['io.sentry', 'Sentry', 'SentryClient'],
            '融云IM': ['io.rong', 'RongIM', 'RongIMClient'],
            '环信IM': ['com.hyphenate', 'EMClient', 'EMChat'],
            '腾讯云IM': ['com.tencent.imsdk', 'TIMManager', 'V2TIMManager'],
            '阿里云IM': ['com.alibaba.dingtalk', 'DingTalk', 'OpenDingTalk'],
            '声网Agora': ['io.agora', 'RtcEngine', 'Agora'],
            '腾讯云TRTC': ['com.tencent.trtc', 'TRTCCloud', 'TRTC'],
            '即构Zego': ['im.zego', 'ZegoExpressEngine', 'Zego'],
            '七牛云': ['com.qiniu', 'UploadManager', 'Qiniu'],
            '阿里云OSS': ['com.alibaba.sdk.android.oss', 'OSS', 'OSSClient'],
            '腾讯云COS': ['com.qcloud.cos', 'CosXmlService', 'TransferService'],
            '百度云': ['com.baidubce', 'BceClientConfiguration', 'BosClient'],
            'Retrofit': ['retrofit2', 'Retrofit', 'Converter'],
            'OkHttp': ['okhttp3', 'OkHttpClient', 'Request'],
            'Glide': ['com.bumptech.glide', 'Glide', 'RequestManager'],
            'Picasso': ['com.squareup.picasso', 'Picasso', 'RequestCreator'],
            'Fresco': ['com.facebook.drawee', 'Fresco', 'DraweeView'],
            'EventBus': ['org.greenrobot.eventbus', 'EventBus', 'Subscribe'],
            'RxJava': ['io.reactivex', 'Observable', 'Flowable'],
            'Dagger': ['dagger', 'Component', 'Module'],
            'ButterKnife': ['butterknife', 'ButterKnife', 'BindView'],
            'Room': ['androidx.room', 'Room', 'Database'],
            'LiveData': ['androidx.lifecycle', 'LiveData', 'ViewModel'],
            'DataBinding': ['androidx.databinding', 'DataBindingUtil', 'ViewDataBinding'],
            'Jetpack Compose': ['androidx.compose', 'Composable', 'remember'],
            'Kotlin Coroutines': ['kotlinx.coroutines', 'CoroutineScope', 'launch'],
            'Flutter': ['io.flutter', 'FlutterActivity', 'FlutterView'],
            'React Native': ['com.facebook.react', 'ReactActivity', 'ReactNative'],
            'Cordova': ['org.apache.cordova', 'CordovaActivity', 'CordovaWebView'],
            'Ionic': ['io.ionic', 'Ionic', 'CordovaActivity'],
            'Unity': ['com.unity3d', 'UnityPlayer', 'UnityPlayerActivity'],
            'Cocos2d': ['org.cocos2dx', 'Cocos2dxActivity', 'Cocos2dxGLSurfaceView'],
            'Unreal': ['com.epicgames', 'UE4', 'GameActivity'],
        }

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # 从dex文件中检测SDK
                dex_files = [f for f in zf.namelist() if f.endswith('.dex')]
                all_text = ""
                for dex_file in dex_files[:3]:
                    try:
                        data = zf.read(dex_file)
                        all_text += data.decode('utf-8', errors='ignore')
                    except Exception:
                        continue

                for sdk_name, signatures in sdk_signatures.items():
                    for sig in signatures:
                        if sig in all_text:
                            self.apk_info.sdk_list.append({
                                'name': sdk_name,
                                'signature': sig,
                                'detected': True
                            })
                            break

        except Exception as e:
            print(f"SDK分析错误: {e}")

    def get_dangerous_permissions(self) -> List[str]:
        """获取危险权限列表"""
        return [p for p in self.apk_info.permissions if p in self.DANGEROUS_PERMISSIONS]

    def get_exported_components(self) -> List[Dict]:
        """获取导出的组件（简化版）"""
        exported = []
        for act in self.apk_info.activities:
            if 'MainActivity' not in act.get('name', ''):
                exported.append(act)
        return exported

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'file_info': {
                'path': self.apk_info.file_path,
                'name': self.apk_info.file_name,
                'size': self.apk_info.file_size,
                'md5': self.apk_info.md5,
                'sha1': self.apk_info.sha1,
                'sha256': self.apk_info.sha256,
            },
            'app_info': {
                'package_name': self.apk_info.package_name,
                'version_name': self.apk_info.version_name,
                'version_code': self.apk_info.version_code,
                'min_sdk': self.apk_info.min_sdk,
                'target_sdk': self.apk_info.target_sdk,
                'app_name': self.apk_info.app_name,
            },
            'permissions': {
                'total': len(self.apk_info.permissions),
                'dangerous': self.get_dangerous_permissions(),
                'all': self.apk_info.permissions,
            },
            'components': {
                'activities': len(self.apk_info.activities),
                'services': len(self.apk_info.services),
                'receivers': len(self.apk_info.receivers),
                'providers': len(self.apk_info.providers),
                'exported': self.get_exported_components(),
            },
            'security': {
                'is_packed': self.apk_info.is_packed,
                'packer_name': self.apk_info.packer_name,
                'is_debuggable': self.apk_info.is_debuggable,
                'allow_backup': self.apk_info.allow_backup,
                'cleartext_traffic': self.apk_info.cleartext_traffic,
                'network_security_config': self.apk_info.network_security_config,
                'webview_activities': self.apk_info.webview_activities,
            },
            'native_libs': self.apk_info.native_libs,
            'sdk_list': self.apk_info.sdk_list,
            'hardcoded_strings': self.apk_info.hardcoded_strings[:50],
            'analysis_time': self.apk_info.analysis_time,
        }

    def save_report(self, output_path: str):
        """保存分析报告"""
        report = self.to_dict()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        return output_path


# 全局单例
_apk_parser = None

def get_apk_parser() -> APKParser:
    """获取APK解析器单例"""
    global _apk_parser
    if _apk_parser is None:
        _apk_parser = APKParser()
    return _apk_parser
