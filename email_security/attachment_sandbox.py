# -*- coding: utf-8 -*-
"""attachment_sandbox.py — 邮件附件静态分析 + 模拟动态沙箱。

边界声明：本模块只对"已被隔离的附件样本"进行分析、哈希匹配、规则命中与
行为仿真报告生成，不落地、不传播、不执行任何样本。动态行为为模型化推演。
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from typing import Any, Dict, List, Optional

from .phishing_detector import (ARCHIVE_EXTENSIONS, DOC_EXTENSIONS,
                                EXECUTABLE_EXTENSIONS, MACRO_DOC_EXTENSIONS)

# --------------------------------------------------------------------------- #
# 已知恶意哈希库（示例样本，仅作演示匹配）
# --------------------------------------------------------------------------- #
MALWARE_HASH_DB: Dict[str, Dict[str, str]] = {
    "44d88612fea8a8f36de82e1278abb02f": {"family": "EICAR-Test", "type": "test",
                                          "first_seen": "2026-01-01"},
    "d41d8cd98f00b204e9800998ecf8427e": {"family": "(空文件)", "type": "benign",
                                          "first_seen": "-"},
    "5f4dcc3b5aa765d61d8327deb882cf99": {"family": "DemoPayload", "type": "trojan",
                                          "first_seen": "2026-08-11"},
    "25d55ad283aa400af464c76d713c07ad": {"family": "Emotet-like", "type": "banker",
                                          "first_seen": "2026-06-20"},
}

# YARA 规则库（仅规则元数据，不依赖 yara-python）
YARA_RULES: List[Dict[str, Any]] = [
    {"id": "YR-01", "name": "Win32_Emotet_Heur", "category": "trojan",
     "description": "Emotet 家族启发式特征", "severity": "high", "enabled": True},
    {"id": "YR-02", "name": "Office_Macro_AutoOpen", "category": "macro",
     "description": "Office 文档 AutoOpen/Document_Open 宏自动执行", "severity": "high",
     "enabled": True},
    {"id": "YR-03", "name": "PE_Packed_UPX", "category": "packer",
     "description": "UPX 加壳可疑样本", "severity": "medium", "enabled": True},
    {"id": "YR-04", "name": "Script_PowerShell_Download", "category": "script",
     "description": "PowerShell 下载执行片段", "severity": "critical", "enabled": True},
    {"id": "YR-05", "name": "Rtf_OLELink_Exploit", "category": "exploit",
     "description": "RTF OLELink 远程模板注入", "severity": "critical", "enabled": True},
    {"id": "YR-06", "name": "Html_File_Application", "category": "html",
     "description": "HTML Application (HTA) 可疑结构", "severity": "high",
     "enabled": True},
    {"id": "YR-07", "name": "Archive_DoubleExtension", "category": "archive",
     "description": "压缩包内双扩展名文件", "severity": "medium", "enabled": True},
    {"id": "YR-08", "name": "Pdf_JavaScript_OpenAction", "category": "pdf",
     "description": "PDF 内嵌 JS OpenAction", "severity": "high", "enabled": True},
]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


class AttachmentSandbox:
    """附件沙箱分析器。"""

    # ------------------------------------------------------------------ #
    # 静态分析
    # ------------------------------------------------------------------ #
    def static_analyze(self, filename: str,
                       payload_b64: Optional[str] = None,
                       size_bytes: int = 0) -> Dict[str, Any]:
        name = (filename or "unnamed.bin").lower()
        ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        payload_b64 = payload_b64 or ""
        try:
            raw = __import__("base64").b64decode(payload_b64) if payload_b64 else b""
        except Exception:
            raw = b""
        size = size_bytes or len(raw)

        hashes = {
            "md5": _md5(raw), "sha1": _sha1(raw), "sha256": _sha256(raw),
        } if raw else {"md5": "-", "sha1": "-", "sha256": "-"}

        # 字符串提取（仅可打印部分）
        strings: List[str] = []
        if raw:
            printable = re.findall(rb"[\x20-\x7e]{6,}", raw)
            strings = [s.decode("latin1") for s in printable[:60]]

        is_pe = raw[:2] == b"MZ" if raw else False
        is_ole = raw[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" if raw else False
        has_macro = ext in MACRO_DOC_EXTENSIONS or (
            is_ole and any(b"AutoOpen" in s or b"Document_Open" in s
                           for s in (raw[i:i+20] for i in range(0, min(len(raw), 4096), 1))))
        is_script = ext in {".js", ".vbs", ".ps1", ".hta"} or \
                    any(s in raw.lower() for s in (b"powershell", b"wscript")) if raw else False

        # 哈希库命中
        hash_hit = MALWARE_HASH_DB.get(hashes["md5"]) if raw else None

        # 类型判定
        if ext in EXECUTABLE_EXTENSIONS:
            ftype = "executable"
        elif ext in MACRO_DOC_EXTENSIONS or is_ole:
            ftype = "office_document"
        elif ext in ARCHIVE_EXTENSIONS:
            ftype = "archive"
        elif ext in DOC_EXTENSIONS:
            ftype = "document"
        elif ext == ".pdf":
            ftype = "pdf"
        else:
            ftype = "other"

        suspicious_indicators: List[str] = []
        if is_pe:
            suspicious_indicators.append("PE 文件头 (MZ)")
        if has_macro:
            suspicious_indicators.append("检测到可能的宏")
        if is_script:
            suspicious_indicators.append("脚本载荷特征")
        if hash_hit:
            suspicious_indicators.append(f"哈希命中恶意库: {hash_hit['family']}")
        if ext in EXECUTABLE_EXTENSIONS:
            suspicious_indicators.append("可执行扩展名")

        return {
            "filename": filename, "extension": ext, "file_type": ftype,
            "size_bytes": size, "hashes": hashes,
            "is_pe": is_pe, "is_ole": is_ole, "has_macro": bool(has_macro),
            "is_script": is_script,
            "sample_strings": strings[:30],
            "hash_db_hit": hash_hit,
            "indicators": suspicious_indicators,
        }

    # ------------------------------------------------------------------ #
    # YARA 规则扫描（模拟）
    # ------------------------------------------------------------------ #
    def yara_scan(self, static: Dict[str, Any]) -> Dict[str, Any]:
        hits: List[Dict[str, Any]] = []
        inds = " ".join(static.get("indicators", [])).lower()
        if static.get("has_macro"):
            hits.append({"rule_id": "YR-02", "name": "Office_Macro_AutoOpen",
                         "severity": "high", "category": "macro"})
        if static.get("is_pe"):
            hits.append({"rule_id": "YR-03", "name": "PE_Packed_UPX",
                         "severity": "medium", "category": "packer"})
        if static.get("is_script"):
            hits.append({"rule_id": "YR-04", "name": "Script_PowerShell_Download",
                         "severity": "critical", "category": "script"})
        if static.get("file_type") == "pdf":
            hits.append({"rule_id": "YR-08", "name": "Pdf_JavaScript_OpenAction",
                         "severity": "high", "category": "pdf"})
        if static.get("file_type") == "archive":
            hits.append({"rule_id": "YR-07", "name": "Archive_DoubleExtension",
                         "severity": "medium", "category": "archive"})
        if static.get("hash_db_hit") and static["hash_db_hit"].get("type") != "benign":
            hits.append({"rule_id": "YR-01", "name": "Win32_Emotet_Heur",
                         "severity": "high", "category": "trojan"})
        return {"hits": hits, "hit_count": len(hits),
                "rules_available": len(YARA_RULES),
                "rules_enabled": sum(1 for r in YARA_RULES if r["enabled"])}

    # ------------------------------------------------------------------ #
    # 动态沙箱（模型化行为推演，不真正执行）
    # ------------------------------------------------------------------ #
    def dynamic_sandbox(self, static: Dict[str, Any]) -> Dict[str, Any]:
        seed = static.get("hashes", {}).get("md5", "0")
        sv = int(seed[:8], 16) if len(seed) >= 8 else 0
        malicious = bool(static.get("hash_db_hit")) and \
                    static["hash_db_hit"].get("type") not in ("benign",)
        behavior_tree: List[Dict[str, Any]] = []
        network: List[Dict[str, str]] = []
        files: List[Dict[str, str]] = []
        registry: List[Dict[str, str]] = []
        processes: List[Dict[str, str]] = []
        timeline: List[Dict[str, Any]] = []

        base = 100 if (static.get("is_pe") or static.get("is_script") or malicious) else 0
        timeline.append({"t": "00:00", "event": "样本在隔离沙箱中初始化（不连接生产网络）"})

        if static.get("has_macro"):
            behavior_tree.append({"action": "宏自动执行", "risk": "high",
                                  "detail": "Document_Open 触发 VBA"})
            timeline.append({"t": "00:01", "event": "宏触发 Document_Open 自动执行"})
            base += 15
        if malicious or base >= 60:
            c2 = f"185.{sv % 250}.{(sv >> 4) % 250}.{(sv >> 8) % 250}"
            network.append({"dst_ip": c2, "port": "443", "proto": "TCP",
                            "purpose": "C2 beacon"})
            files.append({"path": f"C:\\Users\\Public\\svc{sv % 999}.exe",
                          "action": "write"})
            registry.append({"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                             "value": f"svc{sv % 999}", "action": "persist"})
            processes.append({"pid": 1200 + (sv % 800), "name": "svchost.exe",
                              "parent": "explorer.exe", "cmdline": f"-svc{sv % 999}"})
            behavior_tree.extend([
                {"action": "连接 C2", "risk": "critical",
                 "detail": f"出站 {c2}:443"},
                {"action": "写入本地载荷", "risk": "high", "detail": "Public 目录"},
                {"action": "注册表持久化", "risk": "high", "detail": "Run 键"},
                {"action": "创建可疑进程", "risk": "high", "detail": "svchost 伪装"},
            ])
            timeline.append({"t": "00:03", "event": f"样本连接 C2 {c2}:443"})
            timeline.append({"t": "00:05", "event": "写入持久化注册表项"})

        score = min(100, base)
        verdict = "malicious" if score >= 70 else ("suspicious" if score >= 35 else "benign")

        return {
            "sandbox": "modeled-isolated", "duration_seconds": 12,
            "behavior_tree": behavior_tree, "network": network,
            "file_ops": files, "registry": registry, "process_tree": processes,
            "timeline": timeline, "risk_score": score, "verdict": verdict,
            "iocs": {
                "ips": list({n["dst_ip"] for n in network}),
                "files": [f["path"] for f in files],
                "registry_keys": [r["key"] for r in registry],
            },
        }

    # ------------------------------------------------------------------ #
    # 可疑文件提取（模拟）
    # ------------------------------------------------------------------ #
    def extract_suspicious(self, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        extracted: List[Dict[str, Any]] = []
        for att in attachments:
            fn = (att.get("filename") or "").lower()
            item = {"source": fn}
            if fn.endswith(".zip") or fn.endswith(".rar") or fn.endswith(".7z"):
                item["extracted_from"] = "archive"
                item["contents"] = ["document.pdf", "invoice.exe"]
            elif fn.endswith((".docm", ".xlsm", ".dotm")):
                item["extracted_from"] = "office_macro"
                item["contents"] = ["VBA/ThisDocument", "VBA/Module1"]
            elif fn.endswith(".rtf"):
                item["extracted_from"] = "rtf_object"
                item["contents"] = ["EmbeddedObject1.bin"]
            else:
                continue
            extracted.append(item)
        return {"items": extracted, "total": len(extracted)}

    # ------------------------------------------------------------------ #
    # 报告生成
    # ------------------------------------------------------------------ #
    def analyze(self, filename: str, payload_b64: str = "",
                attachments: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        static = self.static_analyze(filename, payload_b64)
        yara = self.yara_scan(static)
        dyn = self.dynamic_sandbox(static)
        extracted = self.extract_suspicious(attachments or [])

        # 综合评分
        score = dyn["risk_score"]
        if yara["hit_count"]:
            score = min(100, score + 8 * yara["hit_count"])
        if static.get("hash_db_hit") and static["hash_db_hit"].get("type") != "benign":
            score = max(score, 90)
        if score >= 75:
            verdict, vname = "malicious", "恶意"
        elif score >= 40:
            verdict, vname = "suspicious", "可疑"
        else:
            verdict, vname = "clean", "干净"

        advice: List[str] = []
        if verdict == "malicious":
            advice.append("立即隔离邮件并全网删除该附件，提交 IOC 至 EDR/网关")
            advice.append("检查所有打开过该附件终端的 IOC 命中情况")
        elif verdict == "suspicious":
            advice.append("人工复核，禁止在生产环境打开")

        return {
            "report_id": hashlib.md5((filename + str(time.time())).encode()).hexdigest()[:12],
            "reported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "static": static, "yara": yara, "dynamic": dyn,
            "extracted": extracted,
            "final_score": score, "verdict": verdict, "verdict_name": vname,
            "disposition_advice": advice,
        }

    def list_yara_rules(self) -> List[Dict[str, Any]]:
        return YARA_RULES
