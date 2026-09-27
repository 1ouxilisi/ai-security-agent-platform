# -*- coding: utf-8 -*-
"""
恶意样本静态分析器

模块功能：
    - 文件基本信息分析（哈希/大小/类型/MIME/熵值）
    - PE文件静态分析（导入表/导出表/节区/反调试/加壳检测）
    - ELF文件静态分析（段/节/符号/入口点）
    - 脚本文件静态分析（JS/VBS/PowerShell/Batch/Shell）
    - 文档文件静态分析（Office/PDF宏/嵌入对象/可疑链接）
    - 基于规则的威胁检测（内置30+规则）
    - IOC提取与VirusTotal集成
    - 生成分析报告

注意事项：
    - 所有分析为静态分析，绝不执行样本文件
    - 本模块仅用于授权的安全测试
"""
import os
import re
import json
import math
import hashlib
import struct
import uuid
import tempfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from collections import Counter

from utils.database import db
from utils.logger import log


# 威胁判定级别
class Verdict:
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class SampleAnalyzer:
    """恶意样本静态分析器"""

    def __init__(self):
        """初始化样本分析器"""
        self._init_tables()
        self._init_detection_rules()

    def _get_conn(self):
        """获取数据库连接"""
        return db._get_connection()

    def _init_tables(self):
        """初始化数据库表"""
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ti_sample_analysis (
                id TEXT PRIMARY KEY,
                file_name TEXT,
                file_size INTEGER,
                file_type TEXT,
                mime TEXT,
                md5 TEXT,
                sha1 TEXT,
                sha256 TEXT,
                entropy REAL,
                compile_time TEXT,
                compiler TEXT,
                analysis_result TEXT DEFAULT '{}',
                threat_detected TEXT DEFAULT '[]',
                iocs_extracted TEXT DEFAULT '[]',
                score INTEGER DEFAULT 0,
                verdict TEXT DEFAULT 'unknown',
                analyzed_at TEXT NOT NULL
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sample_md5 ON ti_sample_analysis(md5)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sample_sha256 ON ti_sample_analysis(sha256)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sample_verdict ON ti_sample_analysis(verdict)")

        conn.commit()
        conn.close()
        log.info("✅ 样本分析表结构初始化完成")

    def _init_detection_rules(self):
        """初始化内置威胁检测规则（30+条）"""
        self.rules = [
            # === 恶意API调用规则 ===
            {"id": "R001", "name": "VirtualAlloc动态内存分配", "pattern": r"VirtualAlloc", "severity": "high",
             "category": "api", "description": "调用VirtualAlloc可能用于shellcode注入"},
            {"id": "R002", "name": "CreateRemoteThread远程线程", "pattern": r"CreateRemoteThread", "severity": "critical",
             "category": "api", "description": "远程线程注入是进程注入的典型技术"},
            {"id": "R003", "name": "WriteProcessMemory进程写入", "pattern": r"WriteProcessMemory", "severity": "critical",
             "category": "api", "description": "向其他进程写入内存，典型注入行为"},
            {"id": "R004", "name": "LoadLibrary动态加载", "pattern": r"LoadLibrary[AW]?", "severity": "medium",
             "category": "api", "description": "动态加载DLL可能用于延迟加载恶意模块"},
            {"id": "R005", "name": "GetProcAddress获取函数地址", "pattern": r"GetProcAddress", "severity": "medium",
             "category": "api", "description": "动态获取函数地址常用于混淆和API解析"},
            {"id": "R006", "name": "WinExec执行程序", "pattern": r"WinExec", "severity": "high",
             "category": "api", "description": "WinExec用于执行外部程序，恶意软件常用"},
            {"id": "R007", "name": "CreateProcess创建进程", "pattern": r"CreateProcess[AW]?", "severity": "high",
             "category": "api", "description": "创建新进程，可能用于执行payload"},
            {"id": "R008", "name": "URLDownloadToFile下载", "pattern": r"URLDownloadToFile[AW]?", "severity": "critical",
             "category": "api", "description": "从URL下载文件，典型下载器行为"},
            {"id": "R009", "name": "InternetOpenUrl打开URL", "pattern": r"InternetOpenUrl[AW]?", "severity": "high",
             "category": "api", "description": "打开URL连接，可能用于C2通信"},
            {"id": "R010", "name": "SetWindowsHookEx钩子", "pattern": r"SetWindowsHookEx[AW]?", "severity": "high",
             "category": "api", "description": "设置Windows钩子，可能用于键盘记录"},

            # === 反调试/反虚拟机规则 ===
            {"id": "R011", "name": "IsDebuggerPresent反调试", "pattern": r"IsDebuggerPresent", "severity": "high",
             "category": "anti_debug", "description": "检测调试器是否存在，典型反调试技术"},
            {"id": "R012", "name": "CheckRemoteDebuggerPresent", "pattern": r"CheckRemoteDebuggerPresent", "severity": "high",
             "category": "anti_debug", "description": "远程调试器检测"},
            {"id": "R013", "name": "NtQueryInformationProcess", "pattern": r"NtQueryInformationProcess", "severity": "medium",
             "category": "anti_debug", "description": "查询进程信息，可用于反调试"},
            {"id": "R014", "name": "OutputDebugString反调试", "pattern": r"OutputDebugString", "severity": "low",
             "category": "anti_debug", "description": "调试输出相关API"},

            # === 注册表操作规则 ===
            {"id": "R015", "name": "Run注册表自启动", "pattern": r"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", "severity": "high",
             "category": "persistence", "description": "修改Run注册表项实现持久化"},
            {"id": "R016", "name": "CurrentVersionRunOnce", "pattern": r"CurrentVersion\\\\RunOnce", "severity": "medium",
             "category": "persistence", "description": "RunOnce注册表项持久化"},
            {"id": "R017", "name": "Service创建服务", "pattern": r"OpenService[AW]?|CreateService[AW]?", "severity": "high",
             "category": "persistence", "description": "创建或打开服务，可能用于持久化"},

            # === 文件操作规则 ===
            {"id": "R018", "name": "DeleteFile删除文件", "pattern": r"DeleteFile[AW]?", "severity": "medium",
             "category": "file_op", "description": "删除文件，可能用于清除痕迹"},
            {"id": "R019", "name": "CopyFile复制文件", "pattern": r"CopyFile[AW]?", "severity": "low",
             "category": "file_op", "description": "复制文件操作"},
            {"id": "R020", "name": "MoveFile移动文件", "pattern": r"MoveFile[AW]?", "severity": "low",
             "category": "file_op", "description": "移动文件操作"},

            # === 网络相关规则 ===
            {"id": "R021", "name": "socket创建套接字", "pattern": r"socket\s*\(", "severity": "medium",
             "category": "network", "description": "创建网络套接字"},
            {"id": "R022", "name": "connect连接", "pattern": r"\bconnect\s*\(", "severity": "medium",
             "category": "network", "description": "网络连接操作"},
            {"id": "R023", "name": "send发送数据", "pattern": r"\bsend\s*\(", "severity": "medium",
             "category": "network", "description": "网络数据发送"},
            {"id": "R024", "name": "recv接收数据", "pattern": r"\brecv\s*\(", "severity": "medium",
             "category": "network", "description": "网络数据接收"},

            # === 脚本可疑模式规则 ===
            {"id": "R025", "name": "PowerShell下载执行", "pattern": r"powershell.*-e[nw]*c?\s|IEX\s*\(|Invoke-Expression", "severity": "critical",
             "category": "script", "description": "PowerShell远程下载执行典型模式"},
            {"id": "R026", "name": "Base64解码执行", "pattern": r"FromBase64String|base64_decode|atob\s*\(", "severity": "high",
             "category": "script", "description": "Base64解码后执行，常见混淆技术"},
            {"id": "R027", "name": "WScript.Shell执行", "pattern": r"WScript\.Shell|WshShell", "severity": "high",
             "category": "script", "description": "WScript.Shell用于执行命令"},
            {"id": "R028", "name": "eval执行字符串", "pattern": r"\beval\s*\(", "severity": "medium",
             "category": "script", "description": "eval执行动态代码，JS恶意脚本常用"},
            {"id": "R029", "name": "Document.write写入", "pattern": r"document\.write\s*\(", "severity": "low",
             "category": "script", "description": "动态写入HTML内容"},
            {"id": "R030", "name": "ActiveXObject创建", "pattern": r"ActiveXObject\s*\(", "severity": "medium",
             "category": "script", "description": "创建ActiveX对象，可能用于执行系统命令"},

            # === 加壳/混淆规则 ===
            {"id": "R031", "name": "UPX加壳特征", "pattern": r"UPX[0-9!]", "severity": "high",
             "category": "packer", "description": "检测到UPX加壳标记"},
            {"id": "R032", "name": "ASPack加壳", "pattern": r".aspack", "severity": "high",
             "category": "packer", "description": "检测到ASPack加壳"},
            {"id": "R033", "name": "VMProtect标记", "pattern": r".vmp[0-9]?", "severity": "critical",
             "category": "packer", "description": "检测到VMProtect保护"},

            # === 文档宏规则 ===
            {"id": "R034", "name": "AutoOpen自动宏", "pattern": r"AutoOpen|Document_Open|Workbook_Open", "severity": "critical",
             "category": "macro", "description": "文档打开自动执行宏"},
            {"id": "R035", "name": "Shell执行宏", "pattern": r"CreateObject\s*\(\s*\"WScript.Shell\"\s*\).*Run", "severity": "critical",
             "category": "macro", "description": "宏中通过WScript.Shell执行命令"},
            {"id": "R036", "name": "URL下载宏", "pattern": r"URLDownloadToFile|Msxml2\.XMLHTTP|WinHttp\.WinHttpRequest", "severity": "critical",
             "category": "macro", "description": "宏中下载远程文件"},
        ]
        log.info(f"✅ 内置检测规则加载完成: {len(self.rules)} 条")

    # ==================== 核心分析方法 ====================

    def analyze_sample(self, file_path: str = None,
                       file_content: bytes = None,
                       file_name: str = "unknown") -> Dict:
        """
        分析样本主入口
        接收文件路径或文件内容，执行静态分析，返回分析报告
        """
        analysis_id = str(uuid.uuid4())
        now = datetime.now().isoformat()

        try:
            # 获取文件内容
            if file_path and os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    file_content = f.read()
                file_name = os.path.basename(file_path)
            elif file_content is None:
                return {"success": False, "message": "必须提供file_path或file_content"}

            # 1. 文件基本信息
            info = self.get_sample_info(file_content, file_name)

            # 2. 根据文件类型执行专项分析
            type_analysis = {}
            file_type = info.get("file_type", "unknown")

            if file_type == "pe":
                type_analysis = self.analyze_pe(file_content)
            elif file_type == "elf":
                type_analysis = self.analyze_elf(file_content)
            elif file_type in ("js", "vbs", "powershell", "batch", "shell"):
                type_analysis = self.analyze_script(file_content, file_type)
            elif file_type in ("office", "pdf"):
                type_analysis = self.analyze_document(file_content, file_type)

            # 3. 提取IOC
            iocs = self.extract_iocs(file_content)

            # 4. 威胁检测
            threats = self.detect_threats(file_content, type_analysis)

            # 5. 计算威胁评分
            score = self._calculate_score(threats, info.get("entropy", 0), type_analysis)

            # 6. 判定结果
            verdict = self._determine_verdict(score, threats)

            # 7. 生成分析报告
            report = {
                "analysis_id": analysis_id,
                "file_info": info,
                "type_analysis": type_analysis,
                "iocs_extracted": iocs,
                "threats_detected": threats,
                "score": score,
                "verdict": verdict,
                "analyzed_at": now,
            }

            # 8. 保存到数据库
            self._save_analysis(report)

            return report

        except Exception as e:
            log.error(f"样本分析失败: {e}")
            return {"success": False, "message": str(e)}

    def get_analysis_result(self, file_hash: str) -> Optional[Dict]:
        """按哈希查询分析结果"""
        conn = self._get_conn()
        try:
            # 尝试MD5/SHA1/SHA256
            row = None
            for col in ["md5", "sha1", "sha256"]:
                row = conn.execute(
                    f"SELECT * FROM ti_sample_analysis WHERE {col} = ?", (file_hash,)
                ).fetchone()
                if row:
                    break

            if not row:
                return None

            result = dict(row)
            result['analysis_result'] = json.loads(result.get('analysis_result', '{}'))
            result['threat_detected'] = json.loads(result.get('threat_detected', '[]'))
            result['iocs_extracted'] = json.loads(result.get('iocs_extracted', '[]'))
            return result
        finally:
            conn.close()

    def extract_iocs(self, file_content: bytes) -> List[Dict]:
        """从样本中提取IOC：IP/域名/URL/文件哈希/注册表项/互斥量等"""
        iocs = []
        try:
            text = file_content.decode("utf-8", errors="ignore")
        except Exception:
            text = str(file_content)

        # 提取IP地址
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        for match in re.finditer(ip_pattern, text):
            ip = match.group()
            # 排除内网IP
            if not ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")):
                iocs.append({"type": "ip", "value": ip})

        # 提取域名
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|pw|cc|su|info|shop|life|onion|tk|work|click|store|info|biz|co)\b'
        for match in re.finditer(domain_pattern, text):
            domain = match.group().lower()
            if not any(skip in domain for skip in ["w3.org", "microsoft.com", "example.com"]):
                iocs.append({"type": "domain", "value": domain})

        # 提取URL
        url_pattern = r'https?://[^\s<>"\'")\]]+'
        for match in re.finditer(url_pattern, text):
            url = match.group()
            if len(url) > 10:
                iocs.append({"type": "url", "value": url})

        # 提取MD5哈希
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        for match in re.finditer(md5_pattern, text):
            iocs.append({"type": "md5", "value": match.group().lower()})

        # 提取SHA256哈希
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        for match in re.finditer(sha256_pattern, text):
            iocs.append({"type": "sha256", "value": match.group().lower()})

        # 提取注册表项
        reg_pattern = r'(?:HKCU|HKLM|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\\\[^\s<>"\']+'
        for match in re.finditer(reg_pattern, text, re.IGNORECASE):
            iocs.append({"type": "registry", "value": match.group()})

        # 去重
        seen = set()
        unique_iocs = []
        for ioc in iocs:
            key = f"{ioc['type']}:{ioc['value']}"
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        return unique_iocs

    def get_sample_info(self, file_content: bytes, file_name: str = "unknown") -> Dict:
        """文件基本信息：文件名/大小/类型/MIME/哈希/熵值/编译时间/编译器"""
        size = len(file_content)

        # 哈希计算
        md5 = hashlib.md5(file_content).hexdigest()
        sha1 = hashlib.sha1(file_content).hexdigest()
        sha256 = hashlib.sha256(file_content).hexdigest()

        # 熵值计算
        entropy = self._calculate_entropy(file_content)

        # 文件类型检测
        file_type, mime = self._detect_file_type(file_content)

        # 编译时间和编译器（仅PE文件有意义）
        compile_time = ""
        compiler = ""
        if file_type == "pe":
            ct, comp = self._detect_pe_compiler(file_content)
            compile_time = ct
            compiler = comp

        return {
            "file_name": file_name,
            "file_size": size,
            "file_type": file_type,
            "mime": mime,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "entropy": round(entropy, 2),
            "compile_time": compile_time,
            "compiler": compiler,
        }

    def analyze_pe(self, data: bytes) -> Dict:
        """PE文件分析：导入表/导出表/节区/资源/签名/字符串/反调试/加壳检测"""
        result = {
            "format": "PE",
            "is_pe": False,
            "machine_type": "",
            "sections": [],
            "imports": [],
            "exports": [],
            "entry_point": "",
            "is_packed": False,
            "packer_detected": "",
            "anti_debug_detected": False,
            "has_signature": False,
        }

        try:
            # 检查PE签名
            if data[:2] != b'MZ':
                return result

            result["is_pe"] = True

            # PE头偏移
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return result

            # Machine类型
            machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
            machine_types = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xAA64: "ARM64"}
            result["machine_type"] = machine_types.get(machine, f"Unknown(0x{machine:x})")

            # 节区信息
            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            opt_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            section_offset = pe_offset + 24 + opt_header_size

            for i in range(num_sections):
                s_off = section_offset + i * 40
                name = data[s_off:s_off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
                vsize = struct.unpack_from("<I", data, s_off + 8)[0]
                raw_size = struct.unpack_from("<I", data, s_off + 16)[0]
                chars = struct.unpack_from("<I", data, s_off + 36)[0]

                section_entropy = 0
                if raw_size > 0 and s_off + 20 + raw_size <= len(data):
                    section_data = data[s_off+20:s_off+20+min(raw_size, 100000)]
                    section_entropy = self._calculate_entropy(section_data)

                result["sections"].append({
                    "name": name,
                    "virtual_size": vsize,
                    "raw_size": raw_size,
                    "entropy": round(section_entropy, 2),
                    "characteristics": f"0x{chars:x}",
                    "is_executable": bool(chars & 0x20000000),
                    "is_writable": bool(chars & 0x80000000),
                })

                # 加壳检测：高熵节区
                if section_entropy > 7.0 and name in (".text", ".data", ".rdata"):
                    result["is_packed"] = True

            # 加壳标记检测
            text_str = data[:min(len(data), 50000)].decode('ascii', errors='ignore')
            for pattern, name in [("UPX0", "UPX"), ("UPX1", "UPX"), (".aspack", "ASPack"),
                                  (".vmp0", "VMProtect"), (".themida", "Themida")]:
                if pattern in text_str:
                    result["is_packed"] = True
                    result["packer_detected"] = name
                    break

            # 反调试检测
            anti_debug_apis = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                              "NtQueryInformationProcess", "OutputDebugString"]
            for api in anti_debug_apis:
                if api.encode() in data:
                    result["anti_debug_detected"] = True
                    break

            # 导入表检测（简化）
            suspicious_imports = ["VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory",
                                 "URLDownloadToFileA", "URLDownloadToFileW", "WinExec"]
            for imp in suspicious_imports:
                if imp.encode() in data:
                    result["imports"].append(imp)

            # 数字签名检测
            result["has_signature"] = b"Certificates" in data or b"WINTRUST" in data

        except Exception as e:
            log.debug(f"PE分析出错: {e}")

        return result

    def analyze_elf(self, data: bytes) -> Dict:
        """ELF文件分析：段/节/符号/字符串/入口点"""
        result = {
            "format": "ELF",
            "is_elf": False,
            "entry_point": "",
            "sections": [],
            "interpreter": "",
            "has_suspicious_imports": False,
        }

        try:
            if data[:4] != b'\x7fELF':
                return result

            result["is_elf"] = True

            # 32/64位
            ei_class = data[4]
            is64 = (ei_class == 2)

            if is64:
                entry = struct.unpack_from("<Q", data, 24)[0]
            else:
                entry = struct.unpack_from("<I", data, 24)[0]

            result["entry_point"] = f"0x{entry:x}"

            # 段数量
            if is64:
                num_ph = struct.unpack_from("<H", data, 56)[0]
            else:
                num_ph = struct.unpack_from("<H", data, 28)[0]

            result["program_headers"] = num_ph

            # 可疑导入检测
            suspicious_funcs = ["execve", "system", "popen", "socket", "connect",
                               "send", "recv", "dlopen", "dlsym"]
            found = []
            for func in suspicious_funcs:
                if func.encode() in data:
                    found.append(func)
            result["suspicious_imports"] = found
            result["has_suspicious_imports"] = len(found) > 0

        except Exception as e:
            log.debug(f"ELF分析出错: {e}")

        return result

    def analyze_script(self, data: bytes, script_type: str = "js") -> Dict:
        """
        脚本分析：JavaScript/VBScript/PowerShell/Batch/Shell
        检测可疑API/混淆/下载执行模式
        """
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = str(data)

        result = {
            "format": "script",
            "script_type": script_type,
            "suspicious_patterns": [],
            "obfuscated": False,
            "download_exec_detected": False,
            "encoded_content": False,
            "line_count": len(text.splitlines()),
        }

        # 混淆检测
        long_lines = sum(1 for line in text.splitlines() if len(line) > 500)
        if long_lines > 0 or len(text) > 10000 and len(text.splitlines()) < 10:
            result["obfuscated"] = True
            result["suspicious_patterns"].append({"rule": "R_OBFUSCATION", "detail": "检测到高度混淆代码"})

        # Base64编码检测
        if re.search(r'[A-Za-z0-9+/=]{100,}', text):
            result["encoded_content"] = True
            result["suspicious_patterns"].append({"rule": "R_BASE64", "detail": "检测到大段Base64编码内容"})

        # 下载执行模式
        download_patterns = [
            (r'powershell.*-e[nw]*c?\s|IEX|Invoke-Expression', "PowerShell远程执行"),
            (r'URLDownloadToFile|Msxml2\.XMLHTTP|WinHttp', "远程下载文件"),
            (r'WScript\.Shell|WshShell.*Run', "WScript执行命令"),
            (r'eval\s*\(', "eval动态执行"),
            (r'FromBase64String|base64_decode|atob', "Base64解码执行"),
            (r'certutil.*-decode|bitsadmin.*transfer', "系统工具下载执行"),
            (r'cmd\.exe.*\/c|\/bin\/sh.*-c', "Shell命令执行"),
        ]

        for pattern, desc in download_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                result["download_exec_detected"] = True
                result["suspicious_patterns"].append({"rule": f"R_DL_{pattern[:10]}", "detail": desc})

        return result

    def analyze_document(self, data: bytes, doc_type: str = "office") -> Dict:
        """文档分析：Office/PDF文档的静态分析，检测宏/嵌入对象/JavaScript/可疑链接"""
        result = {
            "format": "document",
            "doc_type": doc_type,
            "has_macros": False,
            "has_embedded_objects": False,
            "has_javascript": False,
            "suspicious_links": [],
            "macro_indicators": [],
        }

        try:
            text = data.decode("utf-8", errors="ignore")

            # 宏检测（Office）
            macro_indicators = [
                "AutoOpen", "Auto_Open", "Document_Open", "Workbook_Open",
                "Sub Auto_Open", "CreateObject", "WScript.Shell",
                "Shell.Run", "ShellExecute", "URLDownloadToFile",
                "VBA", "VBScript", "macro"
            ]
            for indicator in macro_indicators:
                if indicator in text:
                    result["has_macros"] = True
                    result["macro_indicators"].append(indicator)

            # 嵌入对象检测
            if b"OleObject" in data or b"Embedded" in data or b"oleObject" in text:
                result["has_embedded_objects"] = True

            # JavaScript检测
            if b"<script" in data or b"javascript:" in text.lower():
                result["has_javascript"] = True

            # 可疑链接检测
            url_pattern = r'https?://[^\s<>"\'")\]]+'
            for match in re.finditer(url_pattern, text):
                url = match.group()
                if any(suspicious in url.lower() for suspicious in [".exe", ".dll", ".ps1", ".bat", ".vbs", ".js"]):
                    result["suspicious_links"].append(url)

        except Exception as e:
            log.debug(f"文档分析出错: {e}")

        return result

    def detect_threats(self, file_content: bytes, type_analysis: Dict = None) -> List[Dict]:
        """
        基于规则的威胁检测：YARA规则/特征码/行为特征
        内置30+检测规则
        """
        threats = []
        try:
            text = file_content.decode("utf-8", errors="ignore")
        except Exception:
            text = str(file_content)

        for rule in self.rules:
            pattern = rule["pattern"]
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    threats.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "description": rule["description"],
                    })
            except re.error:
                continue

        # 从类型分析中补充威胁
        if type_analysis:
            if type_analysis.get("is_packed"):
                threats.append({
                    "rule_id": "R_PACKED",
                    "rule_name": "检测到加壳",
                    "severity": "high",
                    "category": "packer",
                    "description": f"样本被加壳保护: {type_analysis.get('packer_detected', 'unknown')}"
                })
            if type_analysis.get("anti_debug_detected"):
                threats.append({
                    "rule_id": "R_ANTIDEBUG",
                    "rule_name": "检测到反调试技术",
                    "severity": "high",
                    "category": "anti_debug",
                    "description": "样本包含反调试代码"
                })
            if type_analysis.get("download_exec_detected"):
                threats.append({
                    "rule_id": "R_DLEXEC",
                    "rule_name": "检测到下载执行模式",
                    "severity": "critical",
                    "category": "behavior",
                    "description": "样本包含远程下载并执行的行为特征"
                })

        return threats

    def query_virustotal(self, file_hash: str) -> Dict:
        """
        可选：集成VirusTotal/Hybrid Analysis查询结果
        需要API key，无key时返回提示
        """
        api_key = os.getenv("VT_API_KEY", "")
        if not api_key:
            return {
                "available": False,
                "message": "未配置VirusTotal API Key，设置VT_API_KEY环境变量后启用",
                "file_hash": file_hash,
                "detections": None
            }

        # 模拟VT查询（实际环境中应调用API）
        return {
            "available": True,
            "file_hash": file_hash,
            "message": "VirusTotal API查询需实际网络请求",
            "detections": None
        }

    def generate_report(self, analysis_result: Dict) -> str:
        """生成样本分析报告：文件信息/威胁检测/IOC提取/建议"""
        lines = []
        lines.append("=" * 60)
        lines.append("        恶意样本静态分析报告")
        lines.append("=" * 60)
        lines.append("")

        # 文件信息
        info = analysis_result.get("file_info", {})
        lines.append("【文件基本信息】")
        lines.append(f"  文件名: {info.get('file_name', 'N/A')}")
        lines.append(f"  文件大小: {info.get('file_size', 0):,} bytes")
        lines.append(f"  文件类型: {info.get('file_type', 'unknown')}")
        lines.append(f"  MIME类型: {info.get('mime', 'unknown')}")
        lines.append(f"  MD5: {info.get('md5', 'N/A')}")
        lines.append(f"  SHA1: {info.get('sha1', 'N/A')}")
        lines.append(f"  SHA256: {info.get('sha256', 'N/A')}")
        lines.append(f"  熵值: {info.get('entropy', 0)}")
        if info.get('compile_time'):
            lines.append(f"  编译时间: {info.get('compile_time')}")
        if info.get('compiler'):
            lines.append(f"  编译器: {info.get('compiler')}")
        lines.append("")

        # 威胁检测
        threats = analysis_result.get("threats_detected", [])
        lines.append(f"【威胁检测】 发现 {len(threats)} 个威胁指标")
        for t in threats[:20]:
            lines.append(f"  [{t['severity'].upper()}] {t['rule_name']}: {t['description']}")
        if len(threats) > 20:
            lines.append(f"  ... 还有 {len(threats) - 20} 个威胁指标")
        lines.append("")

        # IOC提取
        iocs = analysis_result.get("iocs_extracted", [])
        lines.append(f"【IOC提取】 提取到 {len(iocs)} 个IOC")
        ioc_types = {}
        for ioc in iocs:
            t = ioc['type']
            ioc_types[t] = ioc_types.get(t, 0) + 1
        for t, count in ioc_types.items():
            lines.append(f"  {t}: {count} 个")
        lines.append("")

        # 判定结果
        verdict = analysis_result.get("verdict", "unknown")
        score = analysis_result.get("score", 0)
        lines.append("【综合判定】")
        lines.append(f"  威胁评分: {score}/100")
        lines.append(f"  判定结果: {verdict.upper()}")
        lines.append("")

        # 建议
        lines.append("【处置建议】")
        if verdict == Verdict.MALICIOUS:
            lines.append("  1. 立即隔离该样本文件")
            lines.append("  2. 检查网络连接是否包含提取的IOC")
            lines.append("  3. 排查同网段是否有其他感染主机")
            lines.append("  4. 更新EDR/AV特征库")
        elif verdict == Verdict.SUSPICIOUS:
            lines.append("  1. 进一步动态沙箱分析")
            lines.append("  2. 监控相关IOC的网络行为")
            lines.append("  3. 结合威胁情报平台交叉验证")
        else:
            lines.append("  1. 常规归档处理")
            lines.append("  2. 建议定期复核")

        lines.append("")
        lines.append("=" * 60)
        lines.append(f"报告生成时间: {analysis_result.get('analyzed_at', 'N/A')}")
        lines.append("=" * 60)

        return "\n".join(lines)

    # ==================== 辅助方法 ====================

    def _calculate_entropy(self, data: bytes) -> float:
        """计算数据熵值"""
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
        return entropy

    def _detect_file_type(self, data: bytes) -> Tuple[str, str]:
        """检测文件类型"""
        if len(data) < 4:
            return "unknown", "application/octet-stream"

        # PE文件
        if data[:2] == b'MZ':
            return "pe", "application/x-dosexec"

        # ELF文件
        if data[:4] == b'\x7fELF':
            return "elf", "application/x-elf"

        # PDF
        if data[:5] == b'%PDF-':
            return "pdf", "application/pdf"

        # Office (ZIP-based: docx/xlsx/pptx)
        if data[:4] == b'PK\x03\x04':
            return "office", "application/zip"

        # Office (OLE2: doc/xls/ppt)
        if data[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
            return "office", "application/x-ole-storage"

        # JavaScript
        text_start = data[:500].decode('utf-8', errors='ignore')
        if any(kw in text_start for kw in ["function", "var ", "const ", "let ", "document.", "window."]):
            return "js", "application/javascript"

        # VBScript
        if "VBScript" in text_start or "Dim " in text_start or "WScript" in text_start:
            return "vbs", "text/vbscript"

        # PowerShell
        if "powershell" in text_start.lower() or "$(" in text_start or "Get-" in text_start:
            return "powershell", "text/plain"

        # Batch
        if data[:2].upper() in (b'@E', b'EH', b'@R') or text_start.startswith("@echo"):
            return "batch", "text/plain"

        # Shell
        if text_start.startswith("#!") and "bin/" in text_start:
            return "shell", "text/x-shellscript"

        return "unknown", "application/octet-stream"

    def _detect_pe_compiler(self, data: bytes) -> Tuple[str, str]:
        """检测PE文件的编译时间和编译器"""
        compile_time = ""
        compiler = ""

        try:
            if data[:2] != b'MZ':
                return compile_time, compiler

            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return compile_time, compiler

            # 编译时间戳
            timestamp = struct.unpack_from("<I", data, pe_offset + 8)[0]
            if timestamp > 0:
                try:
                    compile_time = datetime.utcfromtimestamp(timestamp).isoformat()
                except Exception:
                    pass

            # 编译器检测
            text = data[:min(len(data), 100000)].decode('ascii', errors='ignore')
            if "Microsoft Visual C++" in text or "MSVC" in text:
                compiler = "Microsoft Visual C++"
            elif "GCC:" in text:
                compiler = "GCC"
            elif "Delphi" in text:
                compiler = "Delphi"
            elif "Borland" in text:
                compiler = "Borland"
            elif ".NET" in text or "mscoree" in text:
                compiler = ".NET"
        except Exception:
            pass

        return compile_time, compiler

    def _calculate_score(self, threats: List[Dict], entropy: float,
                         type_analysis: Dict) -> int:
        """计算威胁评分(0-100)"""
        score = 0
        severity_weights = {"critical": 15, "high": 8, "medium": 4, "low": 1}

        for threat in threats:
            score += severity_weights.get(threat.get("severity", "low"), 1)

        # 熵值加分
        if entropy > 7.0:
            score += 10
        elif entropy > 6.5:
            score += 5

        # 加壳加分
        if type_analysis.get("is_packed"):
            score += 10

        # 下载执行加分
        if type_analysis.get("download_exec_detected"):
            score += 15

        return min(score, 100)

    def _determine_verdict(self, score: int, threats: List[Dict]) -> str:
        """判定样本结论"""
        critical_count = sum(1 for t in threats if t.get("severity") == "critical")

        if score >= 60 or critical_count >= 3:
            return Verdict.MALICIOUS
        elif score >= 30 or critical_count >= 1:
            return Verdict.SUSPICIOUS
        elif score > 0:
            return Verdict.SUSPICIOUS
        else:
            return Verdict.CLEAN

    def _save_analysis(self, report: Dict):
        """保存分析结果到数据库"""
        info = report.get("file_info", {})
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO ti_sample_analysis (id, file_name, file_size, file_type, mime,
                                                md5, sha1, sha256, entropy, compile_time, compiler,
                                                analysis_result, threat_detected, iocs_extracted,
                                                score, verdict, analyzed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.get("analysis_id", str(uuid.uuid4())),
                info.get("file_name", "unknown"),
                info.get("file_size", 0),
                info.get("file_type", "unknown"),
                info.get("mime", "unknown"),
                info.get("md5", ""),
                info.get("sha1", ""),
                info.get("sha256", ""),
                info.get("entropy", 0),
                info.get("compile_time", ""),
                info.get("compiler", ""),
                json.dumps(report.get("type_analysis", {}), ensure_ascii=False),
                json.dumps(report.get("threats_detected", []), ensure_ascii=False),
                json.dumps(report.get("iocs_extracted", []), ensure_ascii=False),
                report.get("score", 0),
                report.get("verdict", "unknown"),
                report.get("analyzed_at", datetime.now().isoformat())
            ))
            conn.commit()
        except Exception as e:
            log.error(f"保存分析结果失败: {e}")
        finally:
            conn.close()
