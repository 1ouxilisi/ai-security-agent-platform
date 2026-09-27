#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
移动App动态分析模块
通过ADB控制Android设备，进行动态行为分析、敏感API监控、网络流量分析
"""

import os
import re
import json
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class DynamicAnalysisResult:
    """动态分析结果"""
    package_name: str = ""
    device_id: str = ""
    is_installed: bool = False
    is_running: bool = False
    activities_visited: List[str] = field(default_factory=list)
    network_requests: List[Dict] = field(default_factory=list)
    sensitive_api_calls: List[Dict] = field(default_factory=list)
    file_accesses: List[Dict] = field(default_factory=list)
    logcat_output: List[str] = field(default_factory=list)
    crashes: List[Dict] = field(default_factory=list)
    permissions_used: List[str] = field(default_factory=list)
    analysis_time: str = ""
    duration_seconds: int = 0


class DynamicAnalyzer:
    """移动App动态分析器"""

    # 敏感API关键词
    SENSITIVE_APIS = {
        'camera': ['Camera', 'camera', 'takePicture', 'startPreview'],
        'microphone': ['MediaRecorder', 'AudioRecord', 'startRecording', 'setAudioSource'],
        'location': ['LocationManager', 'getLastKnownLocation', 'requestLocationUpdates', 'FusedLocationProvider'],
        'contacts': ['ContactsContract', 'ContentResolver', 'query', 'Contacts'],
        'sms': ['SmsManager', 'sendTextMessage', 'SmsMessage', 'Telephony.Sms'],
        'call_log': ['CallLog', 'Calls', 'getContentResolver'],
        'storage': ['Environment', 'getExternalStorageDirectory', 'openFileOutput', 'FileOutputStream'],
        'clipboard': ['ClipboardManager', 'getPrimaryClip', 'setPrimaryClip'],
        'telephony': ['TelephonyManager', 'getDeviceId', 'getImei', 'getSubscriberId', 'getLine1Number'],
        'bluetooth': ['BluetoothAdapter', 'BluetoothDevice', 'createBond'],
        'nfc': ['NfcAdapter', 'NdefMessage', 'Tag'],
    }

    def __init__(self, adb_path: str = "adb"):
        self.adb_path = adb_path
        self.result = DynamicAnalysisResult()

    def _run_adb(self, args: List[str], device_id: str = "", timeout: int = 30) -> str:
        """执行ADB命令"""
        cmd = [self.adb_path]
        if device_id:
            cmd.extend(['-s', device_id])
        cmd.extend(args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return "ERROR: Command timeout"
        except Exception as e:
            return f"ERROR: {str(e)}"

    def get_devices(self) -> List[str]:
        """获取连接的设备列表"""
        output = self._run_adb(['devices'])
        devices = []
        for line in output.split('\n')[1:]:
            if '\tdevice' in line:
                devices.append(line.split('\t')[0])
        return devices

    def install_apk(self, apk_path: str, device_id: str = "") -> bool:
        """安装APK"""
        if not os.path.exists(apk_path):
            return False

        output = self._run_adb(['install', '-r', apk_path], device_id)
        return 'Success' in output

    def uninstall_app(self, package_name: str, device_id: str = "") -> bool:
        """卸载应用"""
        output = self._run_adb(['uninstall', package_name], device_id)
        return 'Success' in output

    def start_app(self, package_name: str, activity: str = "", device_id: str = "") -> bool:
        """启动应用"""
        if activity:
            output = self._run_adb(['shell', 'am', 'start', '-n', f'{package_name}/{activity}'], device_id)
        else:
            output = self._run_adb(['shell', 'monkey', '-p', package_name, '-c',
                                    'android.intent.category.LAUNCHER', '1'], device_id)
        return 'Starting' in output or 'Events injected' in output

    def stop_app(self, package_name: str, device_id: str = "") -> bool:
        """停止应用"""
        output = self._run_adb(['shell', 'am', 'force-stop', package_name], device_id)
        return True

    def is_app_running(self, package_name: str, device_id: str = "") -> bool:
        """检查应用是否在运行"""
        output = self._run_adb(['shell', 'pidof', package_name], device_id)
        return bool(output.strip())

    def get_logcat(self, device_id: str = "", lines: int = 100, filter_tag: str = "") -> List[str]:
        """获取Logcat输出"""
        args = ['logcat', '-d', '-t', str(lines)]
        if filter_tag:
            args.extend([filter_tag + ':V', '*:S'])
        output = self._run_adb(args, device_id)
        return output.split('\n')

    def get_current_activity(self, device_id: str = "") -> str:
        """获取当前前台Activity"""
        output = self._run_adb(['shell', 'dumpsys', 'activity', 'activities'], device_id)
        match = re.search(r'mResumedActivity.*?(\S+/\S+)', output)
        if match:
            return match.group(1)
        return ""

    def get_network_connections(self, package_name: str, device_id: str = "") -> List[Dict]:
        """获取应用网络连接（简化版）"""
        # 通过/proc/net/tcp获取网络连接
        output = self._run_adb(['shell', 'cat', '/proc/net/tcp'], device_id)
        connections = []
        for line in output.split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 4:
                local = parts[1]
                remote = parts[2]
                state = parts[3]
                if state == '01':  # ESTABLISHED
                    connections.append({
                        'local': local,
                        'remote': remote,
                        'state': 'ESTABLISHED'
                    })
        return connections[:20]

    def get_installed_packages(self, device_id: str = "") -> List[str]:
        """获取设备已安装应用列表"""
        output = self._run_adb(['shell', 'pm', 'list', 'packages'], device_id)
        packages = []
        for line in output.split('\n'):
            if line.startswith('package:'):
                packages.append(line.replace('package:', '').strip())
        return packages

    def get_app_permissions(self, package_name: str, device_id: str = "") -> List[str]:
        """获取应用已授予的权限"""
        output = self._run_adb(['shell', 'dumpsys', 'package', package_name], device_id)
        permissions = []
        in_perms = False
        for line in output.split('\n'):
            if 'requested permissions:' in line:
                in_perms = True
                continue
            if in_perms:
                if line.strip().startswith('android.permission.'):
                    permissions.append(line.strip())
                elif not line.strip().startswith('android.permission.') and line.strip():
                    break
        return permissions

    def take_screenshot(self, device_id: str = "", save_path: str = "") -> str:
        """截屏"""
        if not save_path:
            save_path = f"screenshot_{int(time.time())}.png"

        self._run_adb(['shell', 'screencap', '-p', '/sdcard/screenshot.png'], device_id)
        self._run_adb(['pull', '/sdcard/screenshot.png', save_path], device_id)
        self._run_adb(['shell', 'rm', '/sdcard/screenshot.png'], device_id)

        return save_path if os.path.exists(save_path) else ""

    def analyze_sensitive_apis(self, logcat_lines: List[str]) -> List[Dict]:
        """从Logcat中分析敏感API调用"""
        sensitive_calls = []
        for line in logcat_lines:
            for category, keywords in self.SENSITIVE_APIS.items():
                for keyword in keywords:
                    if keyword in line:
                        sensitive_calls.append({
                            'category': category,
                            'keyword': keyword,
                            'log': line[:200],
                            'timestamp': datetime.now().isoformat()
                        })
                        break
        return sensitive_calls

    def start_analysis(self, package_name: str, device_id: str = "",
                      duration: int = 60) -> DynamicAnalysisResult:
        """开始动态分析"""
        self.result = DynamicAnalysisResult()
        self.result.package_name = package_name
        self.result.device_id = device_id
        self.result.analysis_time = datetime.now().isoformat()
        start_time = time.time()

        # 检查应用是否安装
        packages = self.get_installed_packages(device_id)
        self.result.is_installed = package_name in packages

        if not self.result.is_installed:
            return self.result

        # 启动应用
        self.start_app(package_name, device_id=device_id)
        time.sleep(3)

        # 监控应用行为
        end_time = start_time + duration
        while time.time() < end_time:
            # 检查是否在运行
            self.result.is_running = self.is_app_running(package_name, device_id)

            # 获取当前Activity
            activity = self.get_current_activity(device_id)
            if activity and activity not in self.result.activities_visited:
                self.result.activities_visited.append(activity)

            # 获取网络连接
            try:
                connections = self.get_network_connections(package_name, device_id)
                for conn in connections:
                    if conn not in self.result.network_requests:
                        self.result.network_requests.append(conn)
            except Exception:
                pass

            # 获取Logcat
            try:
                logcat = self.get_logcat(device_id, lines=50, filter_tag=package_name)
                self.result.logcat_output.extend(logcat[-20:])

                # 分析敏感API
                sensitive = self.analyze_sensitive_apis(logcat)
                self.result.sensitive_api_calls.extend(sensitive)
            except Exception:
                pass

            time.sleep(5)

        # 获取已使用权限
        self.result.permissions_used = self.get_app_permissions(package_name, device_id)

        # 计算分析时长
        self.result.duration_seconds = int(time.time() - start_time)

        return self.result

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'package_name': self.result.package_name,
            'device_id': self.result.device_id,
            'is_installed': self.result.is_installed,
            'is_running': self.result.is_running,
            'activities_visited': self.result.activities_visited,
            'network_requests': self.result.network_requests,
            'sensitive_api_calls': self.result.sensitive_api_calls,
            'file_accesses': self.result.file_accesses,
            'crashes': self.result.crashes,
            'permissions_used': self.result.permissions_used,
            'analysis_time': self.result.analysis_time,
            'duration_seconds': self.result.duration_seconds,
        }


# 全局单例
_dynamic_analyzer = None

def get_dynamic_analyzer() -> DynamicAnalyzer:
    """获取动态分析器单例"""
    global _dynamic_analyzer
    if _dynamic_analyzer is None:
        _dynamic_analyzer = DynamicAnalyzer()
    return _dynamic_analyzer
