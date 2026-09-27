#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida集成模块
提供Frida脚本生成、注入、Hook管理功能，用于移动App动态分析
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class FridaScript:
    """Frida脚本"""
    name: str = ""
    description: str = ""
    category: str = ""
    code: str = ""
    created_time: str = ""


class FridaHelper:
    """Frida辅助工具"""

    # 预置Frida脚本模板
    SCRIPT_TEMPLATES = {
        'ssl_pinning_bypass': {
            'name': 'SSL Pinning Bypass',
            'description': '绕过SSL证书固定，用于抓包HTTPS流量',
            'category': 'network',
            'code': '''
// SSL Pinning Bypass
Java.perform(function() {
    // OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(str, list) {
            return;
        };
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(str, certs) {
            return;
        };
    } catch(e) {}

    // TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({
            name: 'com.frida.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(k, t, r) {
            this.init(k, [TrustManager.$new()], r);
        };
    } catch(e) {}

    // WebView
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log('[WebView] loadUrl: ' + url);
            this.loadUrl(url);
        };
    } catch(e) {}

    console.log('[*] SSL Pinning Bypass loaded');
});
'''
        },

        'class_tracer': {
            'name': 'Class Tracer',
            'description': '跟踪指定类的所有方法调用',
            'category': 'analysis',
            'code': '''
// Class Tracer
Java.perform(function() {
    var targetClass = 'TARGET_CLASS'; // 替换为目标类名

    try {
        var clazz = Java.use(targetClass);
        var methods = clazz.class.getDeclaredMethods();

        methods.forEach(function(method) {
            var methodName = method.getName();
            try {
                var overloads = clazz[methodName].overloads;
                overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var args = Array.prototype.slice.call(arguments);
                        var argStr = args.map(function(a) {
                            return String(a);
                        }).join(', ');

                        console.log('[Call] ' + targetClass + '.' + methodName + '(' + argStr + ')');

                        var result = this[methodName].apply(this, arguments);
                        if (result !== undefined) {
                            console.log('[Return] ' + methodName + ' => ' + String(result));
                        }
                        return result;
                    };
                });
            } catch(e) {}
        });

        console.log('[*] Class Tracer loaded for: ' + targetClass);
    } catch(e) {
        console.log('[!] Class not found: ' + targetClass);
    }
});
'''
        },

        'sensitive_api_monitor': {
            'name': 'Sensitive API Monitor',
            'description': '监控敏感API调用（位置、相机、麦克风、通讯录等）',
            'category': 'privacy',
            'code': '''
// Sensitive API Monitor
Java.perform(function() {
    // 位置监控
    try {
        var LocationManager = Java.use('android.location.LocationManager');
        LocationManager.getLastKnownLocation.implementation = function(provider) {
            console.log('[Location] getLastKnownLocation: ' + provider);
            return this.getLastKnownLocation(provider);
        };
        LocationManager.requestLocationUpdates.overload('java.lang.String', 'long', 'float', 'android.location.LocationListener').implementation = function(p, minTime, minDist, listener) {
            console.log('[Location] requestLocationUpdates: ' + p);
            return this.requestLocationUpdates(p, minTime, minDist, listener);
        };
    } catch(e) {}

    // 相机监控
    try {
        var Camera = Java.use('android.hardware.Camera');
        Camera.open.implementation = function() {
            console.log('[Camera] Camera.open()');
            return this.open();
        };
        Camera.open.overload('int').implementation = function(cameraId) {
            console.log('[Camera] Camera.open(' + cameraId + ')');
            return this.open(cameraId);
        };
    } catch(e) {}

    // 麦克风监控
    try {
        var MediaRecorder = Java.use('android.media.MediaRecorder');
        MediaRecorder.start.implementation = function() {
            console.log('[Microphone] MediaRecorder.start()');
            return this.start();
        };
        var AudioRecord = Java.use('android.media.AudioRecord');
        AudioRecord.startRecording.implementation = function() {
            console.log('[Microphone] AudioRecord.startRecording()');
            return this.startRecording();
        };
    } catch(e) {}

    // 通讯录监控
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
            if (uri.toString().indexOf('contacts') >= 0) {
                console.log('[Contacts] Query: ' + uri.toString());
            }
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
    } catch(e) {}

    // 剪贴板监控
    try {
        var ClipboardManager = Java.use('android.content.ClipboardManager');
        ClipboardManager.getPrimaryClip.implementation = function() {
            console.log('[Clipboard] getPrimaryClip()');
            return this.getPrimaryClip();
        };
        ClipboardManager.setPrimaryClip.implementation = function(clip) {
            console.log('[Clipboard] setPrimaryClip()');
            return this.setPrimaryClip(clip);
        };
    } catch(e) {}

    // 设备信息监控
    try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');
        TelephonyManager.getDeviceId.implementation = function() {
            console.log('[DeviceInfo] getDeviceId()');
            return this.getDeviceId();
        };
        TelephonyManager.getImei.overload('int').implementation = function(slot) {
            console.log('[DeviceInfo] getImei(' + slot + ')');
            return this.getImei(slot);
        };
    } catch(e) {}

    console.log('[*] Sensitive API Monitor loaded');
});
'''
        },

        'crypto_inspector': {
            'name': 'Crypto Inspector',
            'description': '监控加密操作，检测弱加密算法和硬编码密钥',
            'category': 'crypto',
            'code': '''
// Crypto Inspector
Java.perform(function() {
    // Cipher监控
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
            console.log('[Crypto] Cipher.getInstance: ' + transformation);

            // 检测弱加密算法
            var weakAlgos = ['DES', 'DESede', 'RC4', 'Blowfish', 'ECB'];
            weakAlgos.forEach(function(algo) {
                if (transformation.toUpperCase().indexOf(algo) >= 0) {
                    console.log('[!] Weak crypto algorithm detected: ' + transformation);
                }
            });

            return this.getInstance(transformation);
        };

        Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
            console.log('[Crypto] Cipher.init mode=' + mode + ' key=' + key.getAlgorithm());
            return this.init(mode, key);
        };
    } catch(e) {}

    // MessageDigest监控
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log('[Crypto] MessageDigest.getInstance: ' + algorithm);

            // 检测弱哈希算法
            var weakHashes = ['MD5', 'SHA-1', 'SHA1'];
            weakHashes.forEach(function(hash) {
                if (algorithm.toUpperCase() === hash) {
                    console.log('[!] Weak hash algorithm detected: ' + algorithm);
                }
            });

            return this.getInstance(algorithm);
        };
    } catch(e) {}

    // SecretKeySpec监控
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algorithm) {
            var keyHex = '';
            for (var i = 0; i < Math.min(key.length, 16); i++) {
                keyHex += ('0' + (key[i] & 0xFF).toString(16)).slice(-2);
            }
            console.log('[Crypto] SecretKeySpec algo=' + algorithm + ' key(hex)=' + keyHex);
            return this.$init(key, algorithm);
        };
    } catch(e) {}

    console.log('[*] Crypto Inspector loaded');
});
'''
        },

        'file_access_monitor': {
            'name': 'File Access Monitor',
            'description': '监控文件读写操作，检测敏感文件访问',
            'category': 'storage',
            'code': '''
// File Access Monitor
Java.perform(function() {
    // FileInputStream监控
    try {
        var FileInputStream = Java.use('java.io.FileInputStream');
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            console.log('[File] Read: ' + file.getAbsolutePath());
            return this.$init(file);
        };
        FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
            console.log('[File] Read: ' + path);
            return this.$init(path);
        };
    } catch(e) {}

    // FileOutputStream监控
    try {
        var FileOutputStream = Java.use('java.io.FileOutputStream');
        FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
            console.log('[File] Write: ' + file.getAbsolutePath());
            return this.$init(file);
        };
        FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
            console.log('[File] Write: ' + path);
            return this.$init(path);
        };
    } catch(e) {}

    // SharedPreferences监控
    try {
        var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
        SharedPreferencesImpl.getString.implementation = function(key, defValue) {
            var result = this.getString(key, defValue);
            console.log('[SharedPref] Get: ' + key + ' = ' + result);
            return result;
        };
        SharedPreferencesImpl.putString.implementation = function(key, value) {
            console.log('[SharedPref] Put: ' + key + ' = ' + value);
            return this.putString(key, value);
        };
    } catch(e) {}

    console.log('[*] File Access Monitor loaded');
});
'''
        },
    }

    def __init__(self):
        self.scripts: Dict[str, FridaScript] = {}
        self._load_templates()

    def _load_templates(self):
        """加载预置脚本模板"""
        for key, template in self.SCRIPT_TEMPLATES.items():
            script = FridaScript(
                name=template['name'],
                description=template['description'],
                category=template['category'],
                code=template['code'],
                created_time=datetime.now().isoformat()
            )
            self.scripts[key] = script

    def get_script(self, script_key: str) -> Optional[FridaScript]:
        """获取指定脚本"""
        return self.scripts.get(script_key)

    def get_all_scripts(self) -> List[Dict]:
        """获取所有脚本列表"""
        return [
            {
                'key': key,
                'name': script.name,
                'description': script.description,
                'category': script.category,
            }
            for key, script in self.scripts.items()
        ]

    def get_scripts_by_category(self, category: str) -> List[Dict]:
        """按类别获取脚本"""
        return [
            {
                'key': key,
                'name': script.name,
                'description': script.description,
                'category': script.category,
            }
            for key, script in self.scripts.items()
            if script.category == category
        ]

    def generate_custom_script(self, class_name: str = "",
                               method_name: str = "",
                               hook_type: str = "trace") -> str:
        """生成自定义Hook脚本"""
        if hook_type == "trace" and class_name:
            return f'''
Java.perform(function() {{
    try {{
        var clazz = Java.use('{class_name}');
        var methods = clazz.class.getDeclaredMethods();
        methods.forEach(function(method) {{
            var methodName = method.getName();
            try {{
                var overloads = clazz[methodName].overloads;
                overloads.forEach(function(overload) {{
                    overload.implementation = function() {{
                        console.log('[Call] {class_name}.' + methodName);
                        return this[methodName].apply(this, arguments);
                    }};
                }});
            }} catch(e) {{}}
        }});
        console.log('[*] Hook loaded: {class_name}');
    }} catch(e) {{
        console.log('[!] Class not found: {class_name}');
    }}
}});
'''
        elif hook_type == "method" and class_name and method_name:
            return f'''
Java.perform(function() {{
    try {{
        var clazz = Java.use('{class_name}');
        var overloads = clazz['{method_name}'].overloads;
        overloads.forEach(function(overload) {{
            overload.implementation = function() {{
                var args = Array.prototype.slice.call(arguments);
                console.log('[Call] {class_name}.{method_name}(' + args.join(', ') + ')');
                var result = this['{method_name}'].apply(this, arguments);
                console.log('[Return] {method_name} => ' + String(result));
                return result;
            }};
        }});
        console.log('[*] Method hook loaded: {class_name}.{method_name}');
    }} catch(e) {{
        console.log('[!] Error: ' + e.message);
    }}
}});
'''
        else:
            return "// 请提供类名和方法名"

    def save_script(self, name: str, code: str, description: str = "",
                    category: str = "custom") -> str:
        """保存自定义脚本"""
        script_key = f"custom_{name.lower().replace(' ', '_')}"
        script = FridaScript(
            name=name,
            description=description,
            category=category,
            code=code,
            created_time=datetime.now().isoformat()
        )
        self.scripts[script_key] = script

        # 保存到文件
        script_dir = os.path.join('mobile_security', 'frida_scripts')
        os.makedirs(script_dir, exist_ok=True)
        script_path = os.path.join(script_dir, f'{script_key}.js')
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(code)

        return script_key


# 全局单例
_frida_helper = None

def get_frida_helper() -> FridaHelper:
    """获取Frida辅助工具单例"""
    global _frida_helper
    if _frida_helper is None:
        _frida_helper = FridaHelper()
    return _frida_helper
