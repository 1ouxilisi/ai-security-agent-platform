# -*- coding: utf-8 -*-
"""移动端安全模块 - APK分析/权限检测/组件导出/安全检查清单"""
from fastapi import APIRouter, UploadFile, File
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
import zipfile, os, re, json, hashlib, struct

router = APIRouter(prefix="/api/v1/mobile", tags=["移动端安全"])

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "mobile_uploads")

# Android危险权限列表
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR": "读取日历",
    "android.permission.WRITE_CALENDAR": "写入日历",
    "android.permission.CAMERA": "相机",
    "android.permission.READ_CONTACTS": "读取联系人",
    "android.permission.WRITE_CONTACTS": "写入联系人",
    "android.permission.GET_ACCOUNTS": "获取账户",
    "android.permission.ACCESS_FINE_LOCATION": "精确定位",
    "android.permission.ACCESS_COARSE_LOCATION": "粗略定位",
    "android.permission.RECORD_AUDIO": "录音",
    "android.permission.READ_PHONE_STATE": "读取手机状态",
    "android.permission.CALL_PHONE": "拨打电话",
    "android.permission.READ_CALL_LOG": "读取通话记录",
    "android.permission.WRITE_CALL_LOG": "写入通话记录",
    "android.permission.ADD_VOICEMAIL": "添加语音邮件",
    "android.permission.USE_SIP": "使用SIP",
    "android.permission.PROCESS_OUTGOING_CALLS": "处理呼出电话",
    "android.permission.BODY_SENSORS": "身体传感器",
    "android.permission.SEND_SMS": "发送短信",
    "android.permission.RECEIVE_SMS": "接收短信",
    "android.permission.READ_SMS": "读取短信",
    "android.permission.RECEIVE_WAP_PUSH": "接收WAP推送",
    "android.permission.RECEIVE_MMS": "接收彩信",
    "android.permission.READ_EXTERNAL_STORAGE": "读取外部存储",
    "android.permission.WRITE_EXTERNAL_STORAGE": "写入外部存储",
    "android.permission.READ_MEDIA_IMAGES": "读取媒体图片",
    "android.permission.READ_MEDIA_VIDEO": "读取媒体视频",
    "android.permission.READ_MEDIA_AUDIO": "读取媒体音频",
    "android.permission.NEARBY_WIFI_DEVICES": "附近WiFi设备",
    "android.permission.POST_NOTIFICATIONS": "发送通知",
}

# 移动端安全检查清单
MOBILE_SECURITY_CHECKLIST = [
    {"id": "M001", "category": "数据存储", "title": "敏感数据明文存储检测", "description": "检查SharedPreferences、SQLite数据库、文件中是否明文存储密码、令牌、个人信息", "severity": "high", "test_method": "反编译后检查shared_prefs目录、数据库文件、日志文件"},
    {"id": "M002", "category": "数据传输", "title": "不安全通信检测", "description": "检查是否使用HTTP明文传输、SSL/TLS配置是否安全、是否忽略证书验证", "severity": "critical", "test_method": "抓包分析、检查网络安全配置、检查TrustManager实现"},
    {"id": "M003", "category": "认证授权", "title": "弱认证/授权检测", "description": "检查是否存在硬编码密码、默认凭证、会话管理不当、权限提升漏洞", "severity": "high", "test_method": "代码审计、反编译搜索硬编码字符串、测试会话固定"},
    {"id": "M004", "category": "代码安全", "title": "代码混淆检测", "description": "检查APK是否进行代码混淆、是否可被轻易反编译、是否包含调试符号", "severity": "medium", "test_method": "使用apktool/jadx反编译、检查proguard配置、检查classes.dex"},
    {"id": "M005", "category": "组件安全", "title": "组件导出检测", "description": "检查Activity、Service、BroadcastReceiver、ContentProvider是否存在不必要的导出", "severity": "high", "test_method": "解析AndroidManifest.xml、检查exported属性、测试组件调用"},
    {"id": "M006", "category": "输入验证", "title": "输入验证缺失检测", "description": "检查是否存在SQL注入、命令注入、路径穿越、XSS等输入验证问题", "severity": "high", "test_method": "代码审计、Fuzz测试、检查WebView设置"},
    {"id": "M007", "category": "WebView安全", "title": "WebView安全配置检测", "description": "检查WebView是否启用JavaScript、是否设置setAllowFileAccess、是否存在JS接口注入风险", "severity": "high", "test_method": "代码审计、检查WebView设置、测试JS Bridge"},
    {"id": "M008", "category": "加密安全", "title": "弱加密算法检测", "description": "检查是否使用MD5、SHA1、DES、RC4等弱加密算法，密钥是否硬编码", "severity": "medium", "test_method": "代码审计、搜索加密算法调用、检查密钥管理"},
    {"id": "M009", "category": "日志泄露", "title": "敏感信息日志泄露检测", "description": "检查是否在Log中输出敏感信息（密码、令牌、用户数据）、release版本是否关闭日志", "severity": "medium", "test_method": "反编译搜索Log.d/Log.e/System.out、运行时抓取logcat"},
    {"id": "M010", "category": "完整性保护", "title": "签名/完整性校验检测", "description": "检查APK签名是否安全、是否存在篡改检测、是否校验服务器证书", "severity": "medium", "test_method": "检查签名证书、检查完整性校验代码、测试重打包攻击"},
    {"id": "M011", "category": "本地拒绝服务", "title": "本地拒绝服务检测", "description": "检查是否存在空指针、异常未捕获、资源耗尽等导致应用崩溃的问题", "severity": "low", "test_method": "Fuzz测试Intent、测试异常输入、检查崩溃日志"},
    {"id": "M012", "category": "隐私合规", "title": "隐私合规检测", "description": "检查是否过度申请权限、是否存在隐私政策、是否合规收集个人信息", "severity": "medium", "test_method": "权限分析、检查隐私政策、对比权限与功能必要性"},
]

def _parse_binary_axml(data: bytes) -> Dict:
    """简易解析二进制AndroidManifest.xml（提取权限和组件名）"""
    result = {"permissions": [], "activities": [], "services": [], "receivers": [], "providers": [], "package": "", "version": ""}
    try:
        # 提取字符串（UTF-16LE）
        strings = re.findall(rb'[\x20-\x7e]{4,}', data)
        text = b' '.join(strings).decode('ascii', errors='ignore')
        # 提取权限
        perms = re.findall(r'android\.permission\.[A-Z_]+', text)
        result["permissions"] = list(set(perms))
        # 提取包名
        pkg = re.search(r'([a-z]+\.)+[a-z]+', text)
        if pkg: result["package"] = pkg.group(0)
        # 提取组件（通过类名模式）
        classes = re.findall(r'([A-Z][a-zA-Z0-9_]*(Activity|Service|Receiver|Provider))', text)
        for cls, ctype in classes:
            if ctype == "Activity": result["activities"].append(cls)
            elif ctype == "Service": result["services"].append(cls)
            elif ctype == "Receiver": result["receivers"].append(cls)
            elif ctype == "Provider": result["providers"].append(cls)
    except: pass
    return result

@router.post("/apk/analyze")
async def analyze_apk(file: UploadFile = File(...)):
    """APK文件分析（权限/组件/文件结构）"""
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    content = await file.read()
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, 'wb') as f:
        f.write(content)

    result = {"filename": file.filename, "size": len(content), "md5": hashlib.md5(content).hexdigest(),
              "sha256": hashlib.sha256(content).hexdigest(), "analyzed_at": datetime.now().isoformat()}

    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            file_list = zf.namelist()
            result["file_count"] = len(file_list)
            result["file_types"] = {}
            for fn in file_list:
                ext = os.path.splitext(fn)[1].lower() or "(no ext)"
                result["file_types"][ext] = result["file_types"].get(ext, 0) + 1

            # 检查关键文件
            result["has_manifest"] = "AndroidManifest.xml" in file_list
            result["has_dex"] = any(f.endswith(".dex") for f in file_list)
            result["has_native_libs"] = any(f.endswith(".so") for f in file_list)
            result["has_resources"] = "resources.arsc" in file_list
            result["dex_count"] = sum(1 for f in file_list if f.endswith(".dex"))
            result["native_lib_count"] = sum(1 for f in file_list if f.endswith(".so"))

            # 解析AndroidManifest
            if result["has_manifest"]:
                manifest_data = zf.read("AndroidManifest.xml")
                manifest = _parse_binary_axml(manifest_data)
                result["manifest"] = manifest

                # 危险权限分析
                dangerous = []
                normal = []
                for perm in manifest["permissions"]:
                    full_perm = perm if perm.startswith("android.permission.") else "android.permission." + perm
                    if full_perm in DANGEROUS_PERMISSIONS:
                        dangerous.append({"permission": full_perm, "description": DANGEROUS_PERMISSIONS[full_perm]})
                    else:
                        normal.append(perm)
                result["permission_analysis"] = {
                    "total": len(manifest["permissions"]),
                    "dangerous": dangerous,
                    "dangerous_count": len(dangerous),
                    "normal": normal[:20],
                    "normal_count": len(normal)
                }

                # 组件分析
                result["component_analysis"] = {
                    "activities": manifest["activities"][:30],
                    "activity_count": len(manifest["activities"]),
                    "services": manifest["services"][:20],
                    "service_count": len(manifest["services"]),
                    "receivers": manifest["receivers"][:20],
                    "receiver_count": len(manifest["receivers"]),
                    "providers": manifest["providers"][:10],
                    "provider_count": len(manifest["providers"]),
                }

            # 安全风险初评
            risks = []
            if result.get("permission_analysis", {}).get("dangerous_count", 0) > 5:
                risks.append({"severity": "medium", "title": "过度申请危险权限", "detail": f"申请了{result['permission_analysis']['dangerous_count']}个危险权限，请确认是否全部必要"})
            if result.get("component_analysis", {}).get("activity_count", 0) > 20:
                risks.append({"severity": "low", "title": "Activity数量较多", "detail": f"包含{result['component_analysis']['activity_count']}个Activity，建议检查是否存在不必要的导出"})
            if result.get("has_native_libs"):
                risks.append({"severity": "info", "title": "包含Native库", "detail": f"包含{result.get('native_lib_count',0)}个.so文件，需检查是否存在二进制漏洞"})
            result["initial_risks"] = risks
            result["risk_count"] = len(risks)

    except zipfile.BadZipFile:
        result["error"] = "不是有效的APK文件（ZIP格式损坏）"
    except Exception as e:
        result["error"] = f"分析失败: {str(e)}"

    return {"success": True, "data": result}

@router.get("/checklist")
def get_checklist(category: Optional[str] = None, severity: Optional[str] = None):
    """移动端安全检查清单"""
    items = MOBILE_SECURITY_CHECKLIST
    if category:
        items = [i for i in items if i["category"] == category]
    if severity:
        items = [i for i in items if i["severity"] == severity]
    categories = list(set(i["category"] for i in MOBILE_SECURITY_CHECKLIST))
    return {"success": True, "data": {"items": items, "total": len(items), "categories": sorted(categories)}}

@router.get("/permissions/dangerous")
def get_dangerous_permissions():
    """Android危险权限列表"""
    return {"success": True, "data": {"permissions": DANGEROUS_PERMISSIONS, "total": len(DANGEROUS_PERMISSIONS)}}

@router.post("/scan/url")
def scan_mobile_url(url: str):
    """移动端URL安全检测（API接口/移动端H5）"""
    import urllib.request
    result = {"url": url, "scanned_at": datetime.now().isoformat(), "findings": []}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Linux; Android 13) Mobile"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            result["status_code"] = resp.status
            result["headers"] = dict(resp.headers)
            body = resp.read().decode('utf-8', errors='ignore')[:5000]
            # 安全头检查
            security_headers = {
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy": "CSP",
                "X-Frame-Options": "点击劫持防护",
                "X-Content-Type-Options": "MIME类型嗅探防护",
                "X-XSS-Protection": "XSS防护",
            }
            for header, name in security_headers.items():
                if header not in resp.headers:
                    result["findings"].append({"severity": "medium", "title": f"缺少{name}头", "detail": f"响应头中缺少{header}"})
            # HTTP检查
            if url.startswith("http://"):
                result["findings"].append({"severity": "critical", "title": "使用HTTP明文传输", "detail": "应使用HTTPS加密传输"})
            # 检查是否包含敏感信息
            if re.search(r'(password|passwd|secret|token|api_key)', body, re.I):
                result["findings"].append({"severity": "high", "title": "响应中可能包含敏感信息", "detail": "响应体中包含password/secret/token等关键词"})
    except Exception as e:
        result["error"] = str(e)
    result["finding_count"] = len(result["findings"])
    return {"success": True, "data": result}


# ========== 移动安全AI模型端点（新增 v2.0） ==========

class _AIAnalyzeRequest(BaseModel):
    apk_path: Optional[str] = ""
    manifest_path: Optional[str] = ""
    smali_dir: Optional[str] = ""
    package_name: Optional[str] = "com.example.app"


@router.post("/ai/analyze")
def ai_analyze_apk(request: _AIAnalyzeRequest):
    """AI驱动的完整移动安全分析（借鉴A2+Thorfinn架构：发现+验证+污点流）"""
    try:
        from mobile_security import get_mobile_analyzer
        analyzer = get_mobile_analyzer()
        result = analyzer.full_analysis(
            apk_path=request.apk_path,
            manifest_path=request.manifest_path,
            smali_dir=request.smali_dir,
        )
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/ai/analyze/manifest")
def ai_analyze_manifest(request: _AIAnalyzeRequest):
    """AI驱动的Manifest分析（权限/组件/深链接/配置）"""
    try:
        from mobile_security import get_mobile_analyzer
        analyzer = get_mobile_analyzer()
        apk_info, vulns = analyzer.analyze_manifest(request.manifest_path)
        return {
            "success": True,
            "data": {
                "apk_info": {
                    "package": apk_info.package_name,
                    "version": apk_info.version_name,
                    "min_sdk": apk_info.min_sdk,
                    "target_sdk": apk_info.target_sdk,
                    "permissions": apk_info.permissions,
                    "exported_components": apk_info.exported_components,
                    "deeplinks": apk_info.deeplinks,
                },
                "vulnerabilities": [
                    {
                        "id": v.vuln_id, "name": v.name, "category": v.category,
                        "severity": v.severity.value, "cvss": v.cvss,
                        "description": v.description, "location": v.location,
                        "evidence": v.evidence, "remediation": v.remediation,
                        "cwe": v.cwe, "ai_confidence": v.ai_confidence,
                    }
                    for v in vulns
                ],
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/ai/analyze/taint")
def ai_analyze_taint(request: _AIAnalyzeRequest):
    """AI驱动的污点流分析（Source→Sink数据流追踪）"""
    try:
        from mobile_security import get_mobile_analyzer
        analyzer = get_mobile_analyzer()
        flows = analyzer.analyze_taint_flows(request.smali_dir)
        return {"success": True, "data": {"taint_flows": flows, "count": len(flows)}}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/ai/frida/generate")
def ai_generate_frida_hooks(request: _AIAnalyzeRequest):
    """AI生成Frida Hook验证脚本"""
    try:
        from mobile_security import get_mobile_analyzer
        analyzer = get_mobile_analyzer()
        _, vulns = analyzer.analyze_manifest(request.manifest_path)
        hooks = analyzer.generate_frida_hooks(vulns)
        return {"success": True, "data": {"frida_hooks": hooks, "count": len(hooks)}}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/ai/verification-plan")
def ai_generate_verification_plan(request: _AIAnalyzeRequest):
    """AI生成漏洞验证计划（多模态：UI/组件/文件/加密/网络）"""
    try:
        from mobile_security import get_mobile_analyzer
        analyzer = get_mobile_analyzer()
        _, vulns = analyzer.analyze_manifest(request.manifest_path)
        plan = analyzer.generate_verification_plan(vulns)
        return {"success": True, "data": plan}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/ai/patterns")
def ai_get_patterns():
    """获取AI支持的15类移动端漏洞检测模式"""
    try:
        from mobile_security import get_mobile_analyzer
        analyzer = get_mobile_analyzer()
        patterns = []
        for key, info in analyzer.vulnerability_patterns.items():
            patterns.append({
                "type": key, "name": info["name"],
                "severity": info["severity"].value, "cvss": info["cvss"],
                "cwe": info["cwe"], "has_regex": "patterns" in info,
            })
        return {"success": True, "data": {"patterns": patterns, "total": len(patterns)}}
    except Exception as e:
        return {"success": False, "error": str(e)}
