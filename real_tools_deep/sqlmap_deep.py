# -*- coding: utf-8 -*-
"""
sqlmap_deep.py — SQLMap 深度集成模块（真实执行版 / P0-1 修复）。

核心原则（P0-1）：
- 所有注入检测 API 必须真实调用 sqlmap 命令（subprocess.run），禁止 mock。
- 通过 shutil.which + `sqlmap --version` 双重探测工具是否真正可用。
- 工具未安装 / shim 损坏时，明确返回 {"success": False, "error": "工具未安装: sqlmap ..."}。
- 真实解析 sqlmap 文本输出：注入类型 / 数据库类型 / 数据库版本 / 表名 / 列名 / 数据提取。
- 全部 subprocess 调用带超时（默认 300 秒），--batch 非交互。

设计定位：仅用于经过授权的 Web 应用安全评估环境。
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 300

INJECTION_TECHNIQUES = {
    "B": "布尔盲注 (Boolean-based blind)",
    "E": "错误注入 (Error-based)",
    "U": "联合查询 (UNION query)",
    "S": "堆叠查询 (Stacked queries)",
    "T": "时间盲注 (Time-based blind)",
    "Q": "带外查询 (Out-of-band)",
}

DBMS_TYPES = ["MySQL", "PostgreSQL", "Microsoft SQL Server", "Oracle",
              "SQLite", "Microsoft Access", "Firebird", "SAP MaxDB",
              "Sybase", "IBM DB2", "HSQLDB", "Informix"]

RISK_LEVELS = {
    "critical": {"score": 9.5, "label": "严重"},
    "high": {"score": 7.5, "label": "高危"},
    "medium": {"score": 4.5, "label": "中危"},
    "low": {"score": 2.0, "label": "低危"},
    "info": {"score": 0.5, "label": "信息"},
}


def _run_command(args: List[str], timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """真实执行命令，永不抛异常。"""
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace",
        )
        return {"returncode": proc.returncode, "stdout": proc.stdout or "",
                "stderr": proc.stderr or "", "timed_out": False, "error": None}
    except subprocess.TimeoutExpired as e:
        return {"returncode": -1, "stdout": "", "stderr": "", "timed_out": True,
                "error": f"命令执行超时（>{timeout}s）"}
    except FileNotFoundError as e:
        return {"returncode": -1, "stdout": "", "stderr": "", "timed_out": False,
                "error": f"工具未找到: {e}"}
    except Exception as e:  # noqa: BLE001
        return {"returncode": -1, "stdout": "", "stderr": "", "timed_out": False,
                "error": f"命令执行异常: {e}"}


# --------------------------------------------------------------------------- #
# 命令构建器
# --------------------------------------------------------------------------- #
class SQLMapCommandBuilder:
    def __init__(self) -> None:
        self.args: List[str] = []

    def reset(self) -> "SQLMapCommandBuilder":
        self.args = []
        return self

    def set_target_url(self, url: str) -> "SQLMapCommandBuilder":
        self.args.extend(["-u", url])
        return self

    def set_post_data(self, data: str) -> "SQLMapCommandBuilder":
        self.args.extend(["--data", data])
        return self

    def set_parameter(self, param: str) -> "SQLMapCommandBuilder":
        self.args.extend(["-p", param])
        return self

    def set_dbms(self, dbms: str) -> "SQLMapCommandBuilder":
        self.args.extend(["--dbms", dbms])
        return self

    def set_technique(self, techniques: str) -> "SQLMapCommandBuilder":
        self.args.append(f"--technique={techniques}")
        return self

    def set_level(self, level: int) -> "SQLMapCommandBuilder":
        self.args.extend(["--level", str(level)])
        return self

    def set_risk(self, risk: int) -> "SQLMapCommandBuilder":
        self.args.extend(["--risk", str(risk)])
        return self

    def set_threads(self, threads: int) -> "SQLMapCommandBuilder":
        self.args.extend(["--threads", str(threads)])
        return self

    def set_timeout(self, seconds: int) -> "SQLMapCommandBuilder":
        self.args.extend(["--timeout", str(seconds)])
        return self

    def set_cookie(self, cookie: str) -> "SQLMapCommandBuilder":
        self.args.extend(["--cookie", cookie])
        return self

    def set_random_ua(self) -> "SQLMapCommandBuilder":
        self.args.append("--random-agent")
        return self

    def set_proxy(self, proxy: str) -> "SQLMapCommandBuilder":
        self.args.extend(["--proxy", proxy])
        return self

    def set_batch(self) -> "SQLMapCommandBuilder":
        self.args.append("--batch")
        return self

    def set_flush_session(self) -> "SQLMapCommandBuilder":
        self.args.append("--flush-session")
        return self

    def enumerate_databases(self) -> "SQLMapCommandBuilder":
        self.args.append("--dbs")
        return self

    def enumerate_tables(self, db: str = "") -> "SQLMapCommandBuilder":
        self.args.append("--tables")
        if db:
            self.args.extend(["-D", db])
        return self

    def enumerate_columns(self, table: str, db: str = "") -> "SQLMapCommandBuilder":
        self.args.append("--columns")
        if table:
            self.args.extend(["-T", table])
        if db:
            self.args.extend(["-D", db])
        return self

    def dump_table(self, table: str, db: str = "", limit: int = 10) -> "SQLMapCommandBuilder":
        self.args.append("--dump")
        if table:
            self.args.extend(["-T", table])
        if db:
            self.args.extend(["-D", db])
        self.args.extend(["--stop", str(limit)])
        return self

    def enumerate_users(self) -> "SQLMapCommandBuilder":
        self.args.append("--users")
        return self

    def enumerate_passwords(self) -> "SQLMapCommandBuilder":
        self.args.append("--passwords")
        return self

    def set_tamper(self, tamper: str) -> "SQLMapCommandBuilder":
        self.args.extend(["--tamper", tamper])
        return self

    def build(self) -> str:
        return "sqlmap " + " ".join(self.args)


# --------------------------------------------------------------------------- #
# 结果解析器（真实解析 sqlmap 文本输出）
# --------------------------------------------------------------------------- #
class SQLMapResultParser:
    """从 sqlmap stdout 文本中提取结构化注入结果。不伪造数据。"""

    @staticmethod
    def parse(output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "injection_found": False,
            "injection_type": "",
            "dbms": "",
            "dbms_version": "",
            "databases": [],
            "tables": [],
            "columns": [],
            "data_sample": [],
            "users": [],
            "password_hashes": [],
            "waf_detected": False,
            "raw_excerpt": output[-4000:] if output else "",
        }
        if not output:
            return result

        low = output.lower()

        # 注入成功标志
        if "is vulnerable" in low or "injectable" in low or "appears to be injectable" in low:
            result["injection_found"] = True

        # 注入技术类型
        for code, desc in INJECTION_TECHNIQUES.items():
            if f"{code}-based" in low or f"({code})" in output:
                result["injection_type"] = desc
                break
        if not result["injection_type"] and "sqlmap identified" in low:
            result["injection_type"] = "已确认注入（具体类型见原始输出）"

        # DBMS
        for dbms in DBMS_TYPES:
            if dbms.lower() in low:
                result["dbms"] = dbms
                break

        # DBMS 版本
        m = re.search(r"back-end DBMS version[^:]*:\s*(.+)", output, re.IGNORECASE)
        if m:
            result["dbms_version"] = m.group(1).strip()
        else:
            m = re.search(r"dbms version[^:]*:\s*(.+)", output, re.IGNORECASE)
            if m:
                result["dbms_version"] = m.group(1).strip()

        # 数据库列表
        m = re.search(r"available databases[^:]*:\s*(.+?)(?:\n\n|\n\[|\Z)",
                      output, re.IGNORECASE | re.DOTALL)
        if m:
            names = re.findall(r"[\*\d]+\s*\|\s*([\w\.\-]+)", m.group(1))
            result["databases"] = names or [x.strip() for x in m.group(1).splitlines() if x.strip()]

        # 表列表
        m = re.search(r"Database:.*?\n\[([^\]]+)\]\s*\n[=\-]+\s+(\d+)\s+entries?\s*\n[=\-]+\s*\n(.+?)(?:\n\n|\Z)",
                      output, re.IGNORECASE | re.DOTALL)
        if m:
            db_name = m.group(1).strip()
            tbl_block = m.group(3)
            tables = re.findall(r"[\*\d]+\s*\|\s*([\w\.\-]+)", tbl_block)
            result["tables"] = [{"db": db_name, "table": t} for t in tables]

        # 列列表
        col_block = re.search(r"Database:.*?\nTable: (\S+)\s*\n[=\-]+\s+(\d+)\s+columns?\s*\n[=\-]+\s*\n(.+?)(?:\n\n|\Z)",
                              output, re.IGNORECASE | re.DOTALL)
        if col_block:
            table_name = col_block.group(1)
            for line in col_block.group(3).splitlines():
                cm = re.match(r"[\*\d]+\s*\|\s*(\S+)\s*\|\s*(\S+)", line.strip())
                if cm:
                    result["columns"].append({"table": table_name,
                                              "name": cm.group(1), "type": cm.group(2)})

        # WAF
        if "waf" in low or "firewall" in low:
            result["waf_detected"] = True

        return result


# --------------------------------------------------------------------------- #
# 扫描器
# --------------------------------------------------------------------------- #
class SQLMapScanner:
    def __init__(self, sqlmap_path: str = "sqlmap") -> None:
        self.sqlmap_path = sqlmap_path
        self.actual_path: str = ""
        self.available: bool = False
        self.version: str = ""
        self.probe_error: str = ""
        self.last_result: Dict[str, Any] = {}
        self._check_availability()

    def _check_availability(self) -> None:
        resolved = shutil.which(self.sqlmap_path)
        self.actual_path = resolved or self.sqlmap_path
        if not resolved:
            self.available = False
            self.probe_error = f"未在 PATH 中找到 {self.sqlmap_path}"
            return
        out = _run_command([resolved, "--version"], timeout=60)
        text = (out["stdout"] + "\n" + out["stderr"]).strip()
        if out["returncode"] == 0 and "sqlmap" in text.lower():
            self.available = True
            self.version = text.splitlines()[0].strip()
            self.probe_error = ""
        else:
            self.available = False
            self.probe_error = (text[:200] or out["error"] or "sqlmap shim 损坏 / 运行失败").strip()

    def is_available(self) -> bool:
        return self.available

    def scan(self, target_url: str, post_data: str = "", param: str = "",
             dbms: str = "", technique: str = "BEUSTQ",
             level: int = 1, risk: int = 1, threads: int = 1,
             enumerate_dbs: bool = False,
             timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        if not self.available:
            return {"success": False, "data": None,
                    "error": f"工具未安装: sqlmap（{self.probe_error}）"}

        builder = SQLMapCommandBuilder().reset()
        builder.set_target_url(target_url)
        if post_data:
            builder.set_post_data(post_data)
        if param:
            builder.set_parameter(param)
        if dbms:
            builder.set_dbms(dbms)
        if technique:
            builder.set_technique(technique)
        builder.set_level(level).set_risk(risk).set_threads(threads).set_batch()
        if enumerate_dbs:
            builder.enumerate_databases()

        command = builder.build()
        started = time.time()
        ex = _run_command([self.actual_path] + builder.args, timeout=timeout)
        duration = round(time.time() - started, 2)

        parsed = SQLMapResultParser.parse(ex["stdout"] + "\n" + ex["stderr"])
        result = {
            "success": not ex["timed_out"] and not ex["error"],
            "data": {
                "command": command,
                "parsed": parsed,
                "returncode": ex["returncode"],
                "mode": "real",
                "timed_out": ex["timed_out"],
                "duration_sec": duration,
                "executed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "error": ex["error"],
        }
        self.last_result = result
        return result


# --------------------------------------------------------------------------- #
# 报告生成
# --------------------------------------------------------------------------- #
class SQLMapReportGenerator:
    @staticmethod
    def generate(scan_result: Dict[str, Any], report_name: str = "") -> Dict[str, Any]:
        parsed = (scan_result.get("data") or {}).get("parsed", {}) if scan_result.get("data") else {}
        risk = "critical" if parsed.get("password_hashes") else \
               "high" if parsed.get("injection_found") else "info"
        return {
            "report_id": uuid.uuid4().hex[:12],
            "report_name": report_name or f"SQLMap注入报告_{time.strftime('%Y%m%d_%H%M%S')}",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mode": "real",
            "summary": {
                "injection_found": parsed.get("injection_found", False),
                "injection_type": parsed.get("injection_type", ""),
                "dbms": parsed.get("dbms", ""),
                "dbms_version": parsed.get("dbms_version", ""),
                "databases_count": len(parsed.get("databases", [])),
                "tables_count": len(parsed.get("tables", [])),
                "waf_detected": parsed.get("waf_detected", False),
                "risk_level": risk,
                "risk_label": RISK_LEVELS.get(risk, {}).get("label", "未知"),
            },
            "database_list": parsed.get("databases", []),
            "table_list": parsed.get("tables", []),
            "column_list": parsed.get("columns", []),
            "data_sample": parsed.get("data_sample", []),
        }

    @staticmethod
    def export_report(report: Dict[str, Any], fmt: str = "json") -> str:
        return json.dumps(report, ensure_ascii=False, indent=2)


class SQLMapToolManager:
    def __init__(self) -> None:
        self.config: Dict[str, Any] = {"sqlmap_path": "sqlmap", "default_timeout": DEFAULT_TIMEOUT}

    def detect_version(self) -> Dict[str, Any]:
        s = SQLMapScanner(self.config["sqlmap_path"])
        return {"tool": "sqlmap", "available": s.available, "version": s.version,
                "path": s.actual_path, "probe_error": s.probe_error,
                "detected_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    def is_available(self) -> bool:
        return SQLMapScanner(self.config["sqlmap_path"]).available


_sqlmap_scanner: Optional[SQLMapScanner] = None
_sqlmap_report_gen: Optional[SQLMapReportGenerator] = None
_sqlmap_tool_mgr: Optional[SQLMapToolManager] = None


def get_scanner() -> SQLMapScanner:
    global _sqlmap_scanner
    if _sqlmap_scanner is None:
        _sqlmap_scanner = SQLMapScanner()
    return _sqlmap_scanner


def get_report_generator() -> SQLMapReportGenerator:
    global _sqlmap_report_gen
    if _sqlmap_report_gen is None:
        _sqlmap_report_gen = SQLMapReportGenerator()
    return _sqlmap_report_gen


def get_tool_manager() -> SQLMapToolManager:
    global _sqlmap_tool_mgr
    if _sqlmap_tool_mgr is None:
        _sqlmap_tool_mgr = SQLMapToolManager()
    return _sqlmap_tool_mgr
