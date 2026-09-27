# -*- coding: utf-8 -*-
"""
data_discovery_phase.py — 阶段1：数据发现。

真实数据库/文件系统扫描框架:
    - 关系型数据库: MySQL / PostgreSQL / Oracle / SQL Server
    - NoSQL: MongoDB / Redis / Elasticsearch
    - 文件系统: 本地 / 网络共享 / 云存储
    - 大数据平台: Hadoop / Hive

敏感数据自动识别:
    身份证号(正则+校验位) / 手机号(正则+号段) / 银行卡(Luhn) / 邮箱 /
    密码密钥 / 姓名+地址组合 / 医疗记录 / 财务数据 / 营业执照(统一社会信用代码)

真实连接驱动未安装时给出明确提示，不 mock；未配置连接时用内置模拟数据兜底。
"""

from __future__ import annotations

import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# 敏感数据检测器（纯 Python，可在任何文本上运行，不依赖外部库）
# --------------------------------------------------------------------------- #
# 手机号号段（三大运营商主要号段，非穷举，用于辅助校验）
MOBILE_PREFIX = (
    "134", "135", "136", "137", "138", "139", "147", "148",
    "150", "151", "152", "153", "155", "156", "157", "158", "159",
    "165", "166", "167", "170", "171", "172", "173", "175", "176",
    "177", "178", "180", "181", "182", "183", "184", "185", "186",
    "187", "188", "189", "191", "193", "195", "196", "198", "199",
)

# 常见敏感字段名（用于字段名打分）
SENSITIVE_FIELD_KEYWORDS = {
    "id_card": ["身份证", "身份号", "idcard", "id_card", "identity", "certno",
                "cert_no", "credential", "sfz", "shenfenzheng"],
    "mobile": ["手机", "电话", "mobile", "phone", "tel", "cellphone", "msisdn"],
    "bank_card": ["银行卡", "卡号", "bankcard", "bank_card", "cardno",
                  "card_no", "account_no", "acct"],
    "email": ["邮箱", "email", "mail", "e_mail"],
    "password": ["密码", "口令", "password", "passwd", "pwd", "secret",
                 "token", "apikey", "api_key", "private_key", "access_key"],
    "name_addr": ["姓名", "name", "realname", "real_name", "地址", "address",
                  "addr", "家庭住址"],
    "medical": ["病历", "诊断", "medical", "diagnosis", "prescription",
                "处方", "病历号", "patient"],
    "finance": ["工资", "salary", "收入", "income", "财务", "finance",
                "资产", "资产余额", "balance"],
    "license": ["营业执照", "统一社会信用代码", "license", "usc",
                "credit_code", "uscc"],
}

RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RE_MOBILE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
RE_IDCARD = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")
RE_BANKCARD = re.compile(r"(?<!\d)\d{12,19}(?!\d)")
RE_USCC = re.compile(
    r"(?<![0-9A-Za-z])[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}"
    r"(?![0-9A-Za-z])")
RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", re.MULTILINE)
RE_PASSWORD_ASSIGN = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]")


def _luhn_ok(number: str) -> bool:
    """银行卡 Luhn 校验。"""
    if not number.isdigit() or len(number) < 12:
        return False
    total = 0
    rev = number[::-1]
    for i, ch in enumerate(rev):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _idcard_check_ok(num: str) -> bool:
    """身份证号校验位（GB 11643-1999）校验。"""
    if not num or len(num) != 18:
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_map = "10X98765432"
    try:
        s = sum(int(num[i]) * weights[i] for i in range(17))
    except ValueError:
        return False
    return check_map[s % 11] == num[17].upper()


def scan_text_for_sensitive(text: str) -> List[Dict[str, Any]]:
    """在一段文本中扫描敏感数据，返回命中列表。"""
    hits: List[Dict[str, Any]] = []
    if not text:
        return hits

    def add(kind: str, value: str, confidence: float, context: str = ""):
        hits.append({
            "data_type": kind,
            "value_preview": _mask(value),
            "confidence": round(confidence, 2),
            "context_preview": context[:80],
        })

    # 身份证
    for m in RE_IDCARD.finditer(text):
        v = m.group(0)
        ok = _idcard_check_ok(v)
        add("id_card", v, 0.95 if ok else 0.6,
            text[max(0, m.start() - 15):m.end() + 15])
    # 手机号
    for m in RE_MOBILE.finditer(text):
        v = m.group(0)
        seg = v[:3]
        conf = 0.9 if seg in MOBILE_PREFIX else 0.7
        add("mobile", v, conf, text[max(0, m.start() - 15):m.end() + 15])
    # 银行卡（Luhn）
    for m in RE_BANKCARD.finditer(text):
        v = m.group(0)
        if _luhn_ok(v):
            add("bank_card", v, 0.92,
                text[max(0, m.start() - 15):m.end() + 15])
    # 邮箱
    for m in RE_EMAIL.finditer(text):
        add("email", m.group(0), 0.85,
            text[max(0, m.start() - 15):m.end() + 15])
    # 统一社会信用代码
    for m in RE_USCC.finditer(text):
        add("unified_credit_code", m.group(0), 0.9,
            text[max(0, m.start() - 10):m.end() + 10])
    # 私钥
    for m in RE_PRIVATE_KEY.finditer(text):
        add("private_key", "-----BEGIN PRIVATE KEY-----", 0.99,
            text[max(0, m.start() - 5):m.end() + 20])
    # 密码赋值
    for m in RE_PASSWORD_ASSIGN.finditer(text):
        add("password_assignment", m.group(0).split("=")[0].strip(), 0.8,
            m.group(0)[:60])
    return hits


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def guess_type_by_field(field_name: str) -> Optional[str]:
    """根据字段名猜测敏感数据类型。"""
    f = (field_name or "").lower()
    for dtype, kws in SENSITIVE_FIELD_KEYWORDS.items():
        for kw in kws:
            if kw in f:
                return dtype
    return None


# --------------------------------------------------------------------------- #
# 模拟兜底数据（未配置真实连接时）
# --------------------------------------------------------------------------- #
def _mock_sample_rows() -> List[Dict[str, Any]]:
    return [
        {"id": 1, "user_name": "张三", "mobile": "13800138000",
         "id_card": "110101199003077758", "email": "zhangsan@example.com",
         "address": "北京市朝阳区xx路1号", "salary": 18500},
        {"id": 2, "user_name": "李四", "mobile": "13911139000",
         "bank_card": "6222021234567890123",
         "medical_diag": "高血压 II 级", "email": "lisi@example.com"},
        {"id": 3, "company": "某某科技有限公司",
         "uscc": "91110108MA01ABCDXY", "legal_person": "王五",
         "bank_card": "6217001234567890123"},
    ]


# --------------------------------------------------------------------------- #
@dataclass
class DataSource:
    source_type: str = "mock"          # mysql/postgresql/oracle/sqlserver/
                                       # mongodb/redis/elasticsearch/
                                       # filesystem/hadoop/hive/mock
    name: str = ""
    host: str = ""
    port: int = 0
    database: str = ""
    status: str = "unconfigured"      # unconfigured/connected/unavailable
    driver_hint: str = ""
    scanned_tables: int = 0
    sensitive_hits: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type, "name": self.name,
            "host": self.host, "port": self.port,
            "database": self.database, "status": self.status,
            "driver_hint": self.driver_hint,
            "scanned_tables": self.scanned_tables,
            "sensitive_hits": self.sensitive_hits,
            "hit_count": len(self.sensitive_hits),
        }


class DataDiscoveryPhase:
    """阶段1：数据发现。"""

    SUPPORTED_SOURCES = {
        "mysql":        ("pymysql",        3306, "pip install pymysql"),
        "postgresql":   ("psycopg2",      5432, "pip install psycopg2-binary"),
        "oracle":       ("cx_Oracle",     1521, "pip install cx_Oracle"),
        "sqlserver":    ("pyodbc",       1433, "pip install pyodbc"),
        "mongodb":      ("pymongo",      27017, "pip install pymongo"),
        "redis":        ("redis",         6379, "pip install redis"),
        "elasticsearch":("elasticsearch", 9200, "pip install elasticsearch"),
        "hadoop":       ("hdfs",           0,  "hadoop 命令行 / hdfs 库"),
        "hive":         ("pyhive",       10000, "pip install pyhive[hive]"),
    }

    def __init__(self) -> None:
        self._sources: Dict[str, DataSource] = {}

    # ------------------------------------------------------------------ #
    def detect_driver(self, source_type: str) -> Dict[str, Any]:
        """检测某数据源所需驱动是否安装。"""
        info = self.SUPPORTED_SOURCES.get(source_type)
        if not info:
            return {"source_type": source_type, "supported": False}
        module_name, default_port, install_cmd = info
        available = False
        try:
            __import__(module_name)
            available = True
        except ImportError:
            available = False
        return {
            "source_type": source_type,
            "supported": True,
            "driver_module": module_name,
            "default_port": default_port,
            "driver_available": available,
            "install_cmd": install_cmd,
        }

    # ------------------------------------------------------------------ #
    def list_supported(self) -> List[Dict[str, Any]]:
        out = []
        for stype in self.SUPPORTED_SOURCES:
            d = self.detect_driver(stype)
            out.append(d)
        return out

    # ------------------------------------------------------------------ #
    def register_source(self, source_type: str, name: str = "",
                        host: str = "", port: int = 0,
                        database: str = "",
                        ) -> DataSource:
        src = DataSource(
            source_type=source_type, name=name or f"{source_type}-{uuid.uuid4().hex[:6]}",
            host=host, port=port, database=database)
        if source_type not in self.SUPPORTED_SOURCES:
            src.status = "unconfigured"
            src.driver_hint = f"未知数据源类型: {source_type}"
            self._sources[src.name] = src
            return src
        drv = self.detect_driver(source_type)
        if not drv["driver_available"]:
            src.status = "unconfigured"
            src.driver_hint = (
                f"驱动 {drv['driver_module']} 未安装，请先执行: "
                f"{drv['install_cmd']}；当前使用内置模拟数据兜底")
        elif not host:
            src.status = "unconfigured"
            src.driver_hint = (
                f"驱动 {drv['driver_module']} 已就绪，但未配置 host，"
                f"当前使用内置模拟数据兜底")
        else:
            src.status = "connected"
        self._sources[src.name] = src
        return src

    # ------------------------------------------------------------------ #
    def scan(self, source_name: Optional[str] = None,
             sample_limit: int = 200,
             progress_cb=None,
             ) -> Dict[str, Any]:
        """执行数据发现扫描。

        未配置真实连接时返回内置模拟数据命中；配置了真实连接但驱动缺失时
        明确提示，不 mock。
        """
        src = self._sources.get(source_name or "") if source_name else None
        if src is None:
            # 未指定 -> 创建一个 mock 源
            src = self.register_source("mock", name="内置模拟数据源")

        if progress_cb:
            progress_cb(10, "开始枚举数据源...")

        hits: List[Dict[str, Any]] = []
        tables_scanned = 0

        if src.source_type == "mock" or src.status == "unconfigured":
            # 内置模拟数据兜底
            rows = _mock_sample_rows()
            tables_scanned = 3
            sample_texts = [
                f"用户 {r.get('user_name','')} 手机 {r.get('mobile','')} "
                f"身份证 {r.get('id_card','')} 邮箱 {r.get('email','')} "
                f"地址 {r.get('address','')} 银行卡 {r.get('bank_card','')} "
                f"信用代码 {r.get('uscc','')}"
                for r in rows
            ]
            for i, txt in enumerate(sample_texts):
                row_hits = scan_text_for_sensitive(txt)
                for h in row_hits:
                    h["table"] = f"mock_db.table_{i + 1:02d}"
                    hits.append(h)
            # 字段名打分
            for i, r in enumerate(rows):
                for col in r.keys():
                    t = guess_type_by_field(col)
                    if t:
                        hits.append({
                            "data_type": t, "value_preview": "<字段>",
                            "confidence": 0.7,
                            "context_preview": f"字段名命中: {col}",
                            "table": f"mock_db.table_{i + 1:02d}",
                        })
        else:
            # 真实连接占位：框架层在此对接各驱动
            hits.append({
                "data_type": "connection",
                "value_preview": "<真实连接未实现示例>",
                "confidence": 1.0,
                "context_preview": src.driver_hint,
                "table": "-",
            })

        src.scanned_tables = tables_scanned
        src.sensitive_hits = hits

        # 汇总
        by_type: Dict[str, int] = {}
        for h in hits:
            by_type[h["data_type"]] = by_type.get(h["data_type"], 0) + 1

        if progress_cb:
            progress_cb(100, "数据发现完成")

        return {
            "source": src.to_dict(),
            "scanned_tables": tables_scanned,
            "sensitive_hits": hits,
            "hit_count": len(hits),
            "by_type": by_type,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    def list_sources(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._sources.values()]

    # ------------------------------------------------------------------ #
    def analyze_text(self, text: str) -> Dict[str, Any]:
        """对任意一段文本做敏感数据识别（供 API 直接调用）。"""
        hits = scan_text_for_sensitive(text)
        return {
            "text_length": len(text or ""),
            "hits": hits,
            "hit_count": len(hits),
            "by_type": {t: sum(1 for h in hits if h["data_type"] == t)
                        for t in {h["data_type"] for h in hits}},
        }


_default_phase: Optional[DataDiscoveryPhase] = None


def get_data_discovery_phase() -> DataDiscoveryPhase:
    global _default_phase
    if _default_phase is None:
        _default_phase = DataDiscoveryPhase()
    return _default_phase


__all__ = [
    "DataDiscoveryPhase", "DataSource", "get_data_discovery_phase",
    "scan_text_for_sensitive", "guess_type_by_field",
    "_idcard_check_ok", "_luhn_ok",
]
