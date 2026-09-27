# -*- coding: utf-8 -*-
"""自测脚本：构造模拟 APK（ZIP）并运行 MobileAssessor.assess()"""
import os
import sys
import zipfile

ROOT = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent"
sys.path.insert(0, ROOT)

from unified.mobile_assessor import MobileAssessor  # noqa: E402

TEST_APK = os.path.join(ROOT, "test_sample.apk")

# ---- 1. 构造 AndroidManifest.xml（文本 XML，含丰富风险点）----
manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.vulnapp">
    <uses-permission android:name="android.permission.SEND_SMS"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="com.test.vulnapp.CUSTOM_PERM"/>
    <application android:usesCleartextTraffic="true"
                 android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>
        </activity>
        <activity android:name=".SecretActivity">
            <intent-filter><action android:name="android.intent.action.VIEW"/></intent-filter>
        </activity>
        <service android:name=".SecretService" android:exported="true"/>
        <provider android:name=".DataProvider"
                  android:authorities="com.test.vulnapp.data"
                  android:exported="true"/>
    </application>
</manifest>
"""

# ---- 2. 伪造 classes.dex 字节：塞入密钥/URL/WebView关键词 ----
dex_payload = b"""
const char* API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
const char* AWS = "AKIAIOSFODNN7EXAMPLE";
const char* PWD = "password=SuperSecret123";
const char* STMT = "BEGIN RSA PRIVATE KEY-----FAKE-----END";
const char* URL1 = "http://api.test-vuln.com/v1/login";
const char* URL2 = "https://safe.example.com/";
const char* IP   = "http://192.168.1.10:8080/admin";
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(obj, "bridge");
webView.setAllowFileAccess(true);
TrustManager tm = checkServerTrusted;
"""

nsc_xml = ('<?xml version="1.0" encoding="utf-8"?>'
           "<network-security-config>"
           "<base-config cleartextTrafficPermitted=\"true\"/>"
           "</network-security-config>").encode()

# ---- 3. 打包成 ZIP（模拟 APK）----
with zipfile.ZipFile(TEST_APK, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("AndroidManifest.xml", manifest)
    z.writestr("classes.dex", dex_payload)
    z.writestr("META-INF/CERT.RSA", b"-----CERT FAKE DATA-----")
    z.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF fake so")
    z.writestr("lib/x86/libnative.so", b"\x7fELF fake so x86")
    z.writestr("res/xml/network_security_config.xml", nsc_xml)
    z.writestr("resources.arsc", b"\x02\x01 fake arsc")

print(f"[+] 构造测试APK: {TEST_APK} ({os.path.getsize(TEST_APK)} bytes)")

# ---- 4. 运行评估器 ----
assessor = MobileAssessor()
result = assessor.assess(TEST_APK, {})

print("=" * 70)
print(f"状态: {result.status}")
print(f"摘要: {result.summary}")
print(f"风险分: {result.risk_score}  等级: {result.risk_level}")
print(f"错误: {result.errors}")
print(f"checks_run: {result.checks_run}")
print("=" * 70)
print(f"共 {len(result.findings)} 个 Finding：")
for i, f in enumerate(result.findings, 1):
    print(f"\n[{i}] [{f.severity.label()}] {f.title}  (cat={f.category})")
    if f.evidence:
        ev = f.evidence.replace("\n", " | ")
        print(f"     evidence: {ev[:200]}")

# ---- 5. 断言关键能力真实触发 ----
titles = [f.title for f in result.findings]
assert any("SEND_SMS" in (f.evidence or "") or "危险权限" in f.title for f in result.findings), "权限分析未触发"
assert any("硬编码" in f.category for f in result.findings), "密钥检测未触发"
assert any("明文" in f.title or "HTTP URL" in f.title for f in result.findings), "明文HTTP未触发"
assert any("导出" in f.title for f in result.findings), "组件暴露未触发"
assert any("usesCleartextTraffic" in (f.evidence or "") for f in result.findings), "cleartext未触发"
print("\n[PASS] 所有关键检测模块均触发真实 Finding")
