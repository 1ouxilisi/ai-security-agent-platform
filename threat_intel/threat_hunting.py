# -*- coding: utf-8 -*-
"""
威胁狩猎器

模块功能：
    - 预定义狩猎规则管理（20+条，覆盖常见TTP）
    - 狩猎任务启动、状态跟踪、结果查询
    - 狩猎报告生成
    - 狩猎仪表盘统计

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
"""
import json
import uuid
import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from utils.database import db
from utils.logger import log


class HuntingQueryType:
    """狩猎查询类型"""
    LOG = "log"
    NETWORK = "network"
    ENDPOINT = "endpoint"


class HuntingStatus:
    """狩猎任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class HuntingSeverity:
    """狩猎规则严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ThreatHuntingManager:
    """威胁狩猎管理器"""

    def __init__(self):
        """初始化威胁狩猎管理器"""
        self._init_tables()
        self._init_seed_rules()

    def _get_conn(self):
        """获取数据库连接"""
        return db._get_connection()

    def _init_tables(self):
        """初始化数据库表"""
        conn = self._get_conn()
        cursor = conn.cursor()

        # 狩猎规则表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ti_hunting_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                hypothesis TEXT DEFAULT '',
                ttp TEXT DEFAULT '',
                query_type TEXT NOT NULL DEFAULT 'log',
                query TEXT DEFAULT '{}',
                severity TEXT DEFAULT 'medium',
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)

        # 狩猎任务表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ti_hunting_tasks (
                id TEXT PRIMARY KEY,
                rule_id TEXT,
                name TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                results_count INTEGER DEFAULT 0,
                query_params TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY (rule_id) REFERENCES ti_hunting_rules(id)
            )
        """)

        # 狩猎结果表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ti_hunting_results (
                id TEXT PRIMARY KEY,
                task_id TEXT,
                rule_id TEXT,
                matched_data TEXT DEFAULT '{}',
                asset_id TEXT DEFAULT '',
                user_id TEXT DEFAULT '',
                process_name TEXT DEFAULT '',
                network_connection TEXT DEFAULT '',
                severity TEXT DEFAULT 'medium',
                found_at TEXT NOT NULL,
                FOREIGN KEY (task_id) REFERENCES ti_hunting_tasks(id)
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunt_rules_ttp ON ti_hunting_rules(ttp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunt_rules_severity ON ti_hunting_rules(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunt_tasks_status ON ti_hunting_tasks(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunt_results_task ON ti_hunting_results(task_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunt_results_severity ON ti_hunting_results(severity)")

        conn.commit()
        conn.close()
        log.info("✅ 威胁狩猎表结构初始化完成")

    def _init_seed_rules(self):
        """初始化种子狩猎规则（20+条）"""
        conn = self._get_conn()
        count = conn.execute("SELECT COUNT(*) FROM ti_hunting_rules").fetchone()[0]
        if count >= 20:
            conn.close()
            return

        now = datetime.now().isoformat()
        rules = self._get_seed_rules()

        batch = []
        for rule in rules:
            batch.append((
                str(uuid.uuid4()),
                rule["name"],
                rule.get("description", ""),
                rule.get("hypothesis", ""),
                rule.get("ttp", ""),
                rule.get("query_type", "log"),
                json.dumps(rule.get("query", {}), ensure_ascii=False),
                rule.get("severity", "medium"),
                1,
                now
            ))

        conn.executemany("""
            INSERT INTO ti_hunting_rules (id, name, description, hypothesis, ttp,
                                         query_type, query, severity, enabled, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, batch)

        conn.commit()
        conn.close()
        log.info(f"✅ 威胁狩猎规则种子数据初始化完成，共 {len(batch)} 条")

    def _get_seed_rules(self) -> List[Dict]:
        """获取种子狩猎规则数据（20+条）"""
        return [
            # 1. 钓鱼攻击检测
            {
                "name": "钓鱼邮件附件执行检测",
                "description": "检测来自可疑发件人的邮件附件被执行的行为",
                "hypothesis": "攻击者通过钓鱼邮件投递恶意Office文档或可执行文件，用户打开后执行恶意代码",
                "ttp": "T1566",
                "query_type": "endpoint",
                "query": {"event": "file_create", "conditions": {"process_chain": ["outlook.exe", "excel.exe", "cmd.exe"]}},
                "severity": "high"
            },
            # 2. 横向移动检测
            {
                "name": "SMB横向移动检测",
                "description": "检测通过SMB协议进行的异常横向移动行为",
                "hypothesis": "攻击者通过SMB协议访问远程管理共享(ADMIN$)进行横向移动",
                "ttp": "T1021.002",
                "query_type": "network",
                "query": {"protocol": "smb", "destination_port": 445, "conditions": {"source_internal": True}},
                "severity": "high"
            },
            # 3. 权限提升检测
            {
                "name": "异常权限提升检测",
                "description": "检测普通用户异常获取管理员权限的行为",
                "hypothesis": "攻击者利用漏洞或配置错误进行权限提升",
                "ttp": "T1068",
                "query_type": "endpoint",
                "query": {"event": "privilege_escalation", "conditions": {"new_privileges": ["SeDebugPrivilege", "SeTakeOwnershipPrivilege"]}},
                "severity": "critical"
            },
            # 4. 持久化检测
            {
                "name": "Run注册表项异常修改检测",
                "description": "检测注册表Run/RunOnce项的异常修改",
                "hypothesis": "攻击者修改注册表Run项实现开机自启动持久化",
                "ttp": "T1060",
                "query_type": "endpoint",
                "query": {"event": "registry_modify", "conditions": {"path_contains": "CurrentVersion\\Run"}},
                "severity": "high"
            },
            # 5. 数据渗出检测
            {
                "name": "异常数据渗出检测",
                "description": "检测大量数据通过异常通道向外传输",
                "hypothesis": "攻击者将窃取的数据通过FTP/SFTP/HTTP等通道渗出",
                "ttp": "T1041",
                "query_type": "network",
                "query": {"protocol": ["ftp", "sftp", "https"], "conditions": {"upload_volume_mb_gt": 100}},
                "severity": "critical"
            },
            # 6. 命令控制检测
            {
                "name": "C2 Beacon通信检测",
                "description": "检测周期性Beacon式命令控制通信",
                "hypothesis": "恶意软件通过周期性HTTP/HTTPS请求与C2服务器保持通信",
                "ttp": "T1071",
                "query_type": "network",
                "query": {"protocol": "http", "conditions": {"interval_seconds_between": 60, "same_destination": True}},
                "severity": "high"
            },
            # 7. 勒索软件行为检测
            {
                "name": "勒索软件批量加密行为检测",
                "description": "检测短时间内大量文件被修改或加密",
                "hypothesis": "勒索软件在短时间内批量加密用户文件",
                "ttp": "T1486",
                "query_type": "endpoint",
                "query": {"event": "file_modify", "conditions": {"file_count_per_min_gt": 50, "file_types": [".docx", ".pdf", ".jpg"]}},
                "severity": "critical"
            },
            # 8. 异常登录检测
            {
                "name": "异常登录时间检测",
                "description": "检测用户在异常时间的登录行为",
                "hypothesis": "攻击者在非工作时间使用窃取的凭据登录系统",
                "ttp": "T1078",
                "query_type": "log",
                "query": {"event": "login", "conditions": {"hour_range": ["00:00", "06:00"], "user_type": "standard"}},
                "severity": "medium"
            },
            # 9. 异常进程检测
            {
                "name": "可疑进程创建检测",
                "description": "检测从临时目录或下载目录启动的可疑进程",
                "hypothesis": "攻击者将恶意文件放在临时目录并执行",
                "ttp": "T1204",
                "query_type": "endpoint",
                "query": {"event": "process_create", "conditions": {"path_contains": ["\\Temp\\", "\\Downloads\\", "\\AppData\\"]}},
                "severity": "high"
            },
            # 10. 异常网络连接检测
            {
                "name": "可疑外联连接检测",
                "description": "检测到已知恶意IP或可疑域名的出站连接",
                "hypothesis": "受感染主机连接到已知C2服务器或恶意基础设施",
                "ttp": "T1071",
                "query_type": "network",
                "query": {"event": "connection", "conditions": {"destination_in_threat_intel": True}},
                "severity": "critical"
            },
            # 11. PowerShell恶意使用检测
            {
                "name": "PowerShell恶意使用检测",
                "description": "检测PowerShell的可疑命令行参数",
                "hypothesis": "攻击者使用PowerShell进行代码执行和下载",
                "ttp": "T1059.001",
                "query_type": "endpoint",
                "query": {"event": "process_create", "conditions": {"process_name": "powershell.exe", "cmdline_contains": ["-enc", "-noni", "-w hidden", "IEX"]}},
                "severity": "high"
            },
            # 12. WMI滥用检测
            {
                "name": "WMI远程执行检测",
                "description": "检测通过WMI进行的远程命令执行",
                "hypothesis": "攻击者利用WMI进行横向移动和命令执行",
                "ttp": "T1047",
                "query_type": "endpoint",
                "query": {"event": "process_create", "conditions": {"process_name": ["wmic.exe", "wmiprvse.exe"], "cmdline_contains": ["/node:", "process call create"]}},
                "severity": "high"
            },
            # 13. 计划任务异常
            {
                "name": "异常计划任务创建检测",
                "description": "检测计划任务的异常创建和修改",
                "hypothesis": "攻击者创建计划任务实现持久化",
                "ttp": "T1053",
                "query_type": "endpoint",
                "query": {"event": "task_create", "conditions": {"action_contains": ["cmd.exe", "powershell.exe", "cscript.exe"]}},
                "severity": "medium"
            },
            # 14. 服务创建异常
            {
                "name": "可疑服务创建检测",
                "description": "检测异常的Windows服务创建",
                "hypothesis": "攻击者创建恶意服务实现持久化",
                "ttp": "T1050",
                "query_type": "endpoint",
                "query": {"event": "service_create", "conditions": {"service_path_contains": ["\\Temp\\", "powershell", "cmd.exe"]}},
                "severity": "high"
            },
            # 15. 注册表异常修改
            {
                "name": "注册表启动项修改检测",
                "description": "检测注册表自启动项的异常修改",
                "hypothesis": "攻击者修改注册表实现持久化",
                "ttp": "T1547",
                "query_type": "endpoint",
                "query": {"event": "registry_modify", "conditions": {"path_contains": ["Run", "RunOnce", "Winlogon", "Explorer"]}},
                "severity": "medium"
            },
            # 16. DLL劫持检测
            {
                "name": "DLL侧载检测",
                "description": "检测可疑的DLL加载行为",
                "hypothesis": "攻击者通过DLL劫持或侧载执行恶意代码",
                "ttp": "T1574",
                "query_type": "endpoint",
                "query": {"event": "dll_load", "conditions": {"dll_path_contains": ["\\Temp\\", "\\Downloads\\"], "not_in_system32": True}},
                "severity": "high"
            },
            # 17. 进程注入检测
            {
                "name": "远程线程注入检测",
                "description": "检测CreateRemoteThread等进程注入行为",
                "hypothesis": "攻击者通过进程注入隐藏恶意代码",
                "ttp": "T1055",
                "query_type": "endpoint",
                "query": {"event": "process_inject", "conditions": {"api_called": ["CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC"]}},
                "severity": "critical"
            },
            # 18. 凭据转储检测
            {
                "name": "凭据转储行为检测",
                "description": "检测Mimikatz等凭据窃取工具的行为",
                "hypothesis": "攻击者使用Mimikatz等工具转储LSASS内存中的凭据",
                "ttp": "T1003",
                "query_type": "endpoint",
                "query": {"event": "memory_access", "conditions": {"target_process": "lsass.exe", "access_type": ["PROCESS_VM_READ", "PROCESS_DUP_HANDLE"]}},
                "severity": "critical"
            },
            # 19. 防御规避检测
            {
                "name": "安全软件禁用检测",
                "description": "检测Windows Defender或其他安全软件的异常禁用",
                "hypothesis": "攻击者禁用安全软件以规避检测",
                "ttp": "T1562.001",
                "query_type": "endpoint",
                "query": {"event": "security_disable", "conditions": {"target": ["WinDefend", "Windows Defender", "antivirus"]}},
                "severity": "critical"
            },
            # 20. 漏洞利用检测
            {
                "name": "Web应用漏洞利用检测",
                "description": "检测针对Web应用的常见攻击尝试",
                "hypothesis": "攻击者利用Web漏洞获取初始访问",
                "ttp": "T1190",
                "query_type": "log",
                "query": {"event": "http_request", "conditions": {"url_contains": ["../", "union select", "exec(", "<script"]}},
                "severity": "high"
            },
            # 21. 账号枚举检测
            {
                "name": "暴力破解检测",
                "description": "检测针对SSH/RDP/HTTP的暴力破解行为",
                "hypothesis": "攻击者通过暴力破解获取合法凭据",
                "ttp": "T1110",
                "query_type": "log",
                "query": {"event": "auth_failure", "conditions": {"attempts_per_min_gt": 10, "target_services": ["ssh", "rdp", "http"]}},
                "severity": "high"
            },
            # 22. 批量文件删除检测
            {
                "name": "批量文件删除检测",
                "description": "检测大量文件被删除的行为",
                "hypothesis": "攻击者删除日志或用户文件进行破坏",
                "ttp": "T1485",
                "query_type": "endpoint",
                "query": {"event": "file_delete", "conditions": {"file_count_per_min_gt": 30}},
                "severity": "high"
            },
            # 23. DNS隧道检测
            {
                "name": "DNS隧道通信检测",
                "description": "检测可疑的DNS查询模式，可能用于数据渗出",
                "hypothesis": "攻击者通过DNS隧道进行隐蔽通信",
                "ttp": "T1071.004",
                "query_type": "network",
                "query": {"protocol": "dns", "conditions": {"query_length_gt": 100, "high_frequency_queries": True}},
                "severity": "medium"
            },
            # 24. 可疑服务安装检测
            {
                "name": "可疑驱动加载检测",
                "description": "检测未签名或可疑驱动程序的加载",
                "hypothesis": "攻击者加载恶意驱动实现内核级持久化",
                "ttp": "T1014",
                "query_type": "endpoint",
                "query": {"event": "driver_load", "conditions": {"unsigned": True, "path_not_whitelisted": True}},
                "severity": "high"
            },
        ]

    # ==================== 规则管理 ====================

    def list_rules(self, enabled: bool = None,
                   severity: str = None, ttp: str = None,
                   page: int = 1, page_size: int = 20) -> Dict:
        """列出狩猎规则"""
        conn = self._get_conn()
        try:
            query = "SELECT * FROM ti_hunting_rules WHERE 1=1"
            count_query = "SELECT COUNT(*) FROM ti_hunting_rules WHERE 1=1"
            params = []

            if enabled is not None:
                query += " AND enabled = ?"
                count_query += " AND enabled = ?"
                params.append(1 if enabled else 0)
            if severity:
                query += " AND severity = ?"
                count_query += " AND severity = ?"
                params.append(severity)
            if ttp:
                query += " AND ttp LIKE ?"
                count_query += " AND ttp LIKE ?"
                params.append(f"%{ttp}%")

            total = conn.execute(count_query, params).fetchone()[0]
            offset = (page - 1) * page_size
            query += " ORDER BY severity DESC, name LIMIT ? OFFSET ?"
            params.extend([page_size, offset])

            rows = conn.execute(query, params).fetchall()
            rules = []
            for row in rows:
                rule = dict(row)
                rule['query'] = json.loads(rule.get('query', '{}'))
                rules.append(rule)

            return {
                "total": total,
                "page": page,
                "page_size": page_size,
                "pages": (total + page_size - 1) // page_size,
                "items": rules
            }
        finally:
            conn.close()

    def create_rule(self, name: str, description: str = "",
                    hypothesis: str = "", ttp: str = "",
                    query_type: str = "log", query: Dict = None,
                    severity: str = "medium") -> Dict:
        """创建狩猎规则"""
        now = datetime.now().isoformat()
        rule_id = str(uuid.uuid4())

        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO ti_hunting_rules (id, name, description, hypothesis, ttp,
                                             query_type, query, severity, enabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (rule_id, name, description, hypothesis, ttp,
                  query_type, json.dumps(query or {}), severity, 1, now))
            conn.commit()
            return {"success": True, "message": "规则创建成功", "rule_id": rule_id}
        except Exception as e:
            return {"success": False, "message": str(e)}
        finally:
            conn.close()

    def update_rule(self, rule_id: str, **kwargs) -> Dict:
        """更新狩猎规则"""
        allowed = ["name", "description", "hypothesis", "ttp", "query_type", "query", "severity", "enabled"]
        updates = []
        params = []

        for field in allowed:
            if field in kwargs and kwargs[field] is not None:
                if field == "query":
                    updates.append("query = ?")
                    params.append(json.dumps(kwargs[field]))
                else:
                    updates.append(f"{field} = ?")
                    params.append(kwargs[field])

        if not updates:
            return {"success": False, "message": "没有可更新的字段"}

        params.append(rule_id)
        conn = self._get_conn()
        try:
            conn.execute(f"UPDATE ti_hunting_rules SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()
            return {"success": True, "message": "规则更新成功"}
        except Exception as e:
            return {"success": False, "message": str(e)}
        finally:
            conn.close()

    def delete_rule(self, rule_id: str) -> Dict:
        """删除狩猎规则"""
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM ti_hunting_rules WHERE id = ?", (rule_id,))
            conn.commit()
            return {"success": True, "message": "规则删除成功"}
        except Exception as e:
            return {"success": False, "message": str(e)}
        finally:
            conn.close()

    # ==================== 狩猎任务 ====================

    def start_hunting(self, rule_id: str = None,
                      query_params: Dict = None) -> Dict:
        """
        启动狩猎任务
        模拟执行：基于规则生成模拟匹配结果
        """
        now = datetime.now()
        task_id = str(uuid.uuid4())

        # 获取规则
        conn = self._get_conn()
        try:
            if rule_id:
                rule = conn.execute("SELECT * FROM ti_hunting_rules WHERE id = ? AND enabled = 1",
                                   (rule_id,)).fetchone()
            else:
                # 随机选一条启用的规则
                rule = conn.execute("SELECT * FROM ti_hunting_rules WHERE enabled = 1 ORDER BY RANDOM() LIMIT 1").fetchone()

            if not rule:
                return {"success": False, "message": "未找到可用的狩猎规则"}

            rule = dict(rule)
            rule['query'] = json.loads(rule.get('query', '{}'))

            # 创建任务
            conn.execute("""
                INSERT INTO ti_hunting_tasks (id, rule_id, name, status, started_at,
                                             results_count, query_params, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (task_id, rule["id"], f"狩猎任务: {rule['name']}",
                  HuntingStatus.RUNNING, now.isoformat(),
                  0, json.dumps(query_params or {}), now.isoformat()))
            conn.commit()

            # 模拟执行：生成匹配结果
            match_count = random.randint(0, 20)
            results = self._generate_simulated_results(rule, match_count)

            # 保存结果
            for result in results:
                conn.execute("""
                    INSERT INTO ti_hunting_results (id, task_id, rule_id, matched_data,
                                                   asset_id, user_id, process_name,
                                                   network_connection, severity, found_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()), task_id, rule["id"],
                    json.dumps(result.get("matched_data", {}), ensure_ascii=False),
                    result.get("asset_id", ""),
                    result.get("user_id", ""),
                    result.get("process_name", ""),
                    result.get("network_connection", ""),
                    result.get("severity", rule["severity"]),
                    result.get("found_at", now.isoformat())
                ))

            # 更新任务状态
            completed_at = now + timedelta(seconds=random.randint(2, 30))
            conn.execute("""
                UPDATE ti_hunting_tasks
                SET status = ?, completed_at = ?, results_count = ?
                WHERE id = ?
            """, (HuntingStatus.COMPLETED, completed_at.isoformat(), len(results), task_id))
            conn.commit()

            log.info(f"✅ 狩猎任务完成: {task_id}, 结果数: {len(results)}")

            return {
                "success": True,
                "task_id": task_id,
                "rule_name": rule["name"],
                "status": HuntingStatus.COMPLETED,
                "results_count": len(results),
                "started_at": now.isoformat(),
                "completed_at": completed_at.isoformat(),
            }

        except Exception as e:
            log.error(f"狩猎任务启动失败: {e}")
            return {"success": False, "message": str(e)}
        finally:
            conn.close()

    def _generate_simulated_results(self, rule: Dict, count: int) -> List[Dict]:
        """生成模拟狩猎结果"""
        results = []
        now = datetime.now()
        ttp = rule.get("ttp", "")
        severity = rule.get("severity", "medium")

        # 根据规则类型生成不同的模拟结果
        sample_assets = [f"PC-{random.randint(100,999)}", f"Server-{random.randint(1,50)}"]
        sample_users = [f"user{random.randint(1,50)}", f"admin{random.randint(1,10)}"]
        sample_ips = [f"192.168.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(3)]

        for i in range(count):
            result_time = now - timedelta(minutes=random.randint(1, 120))

            if ttp in ("T1566", "T1204"):
                results.append({
                    "matched_data": {"event": "suspicious_attachment", "source": "email"},
                    "asset_id": random.choice(sample_assets),
                    "user_id": random.choice(sample_users),
                    "process_name": random.choice(["outlook.exe", "excel.exe", "winword.exe"]),
                    "network_connection": "",
                    "severity": severity,
                    "found_at": result_time.isoformat(),
                })
            elif ttp in ("T1071", "T1041", "T1071.004"):
                results.append({
                    "matched_data": {"event": "suspicious_connection", "dst_ip": random.choice(sample_ips)},
                    "asset_id": random.choice(sample_assets),
                    "user_id": random.choice(sample_users),
                    "process_name": random.choice(["powershell.exe", "cmd.exe", "unknown"]),
                    "network_connection": f"{random.choice(sample_ips)}:443",
                    "severity": severity,
                    "found_at": result_time.isoformat(),
                })
            elif ttp in ("T1486", "T1485", "T1490"):
                results.append({
                    "matched_data": {"event": "mass_file_modify", "file_count": random.randint(50, 500)},
                    "asset_id": random.choice(sample_assets),
                    "user_id": random.choice(sample_users),
                    "process_name": random.choice(["unknown.exe", "svchost.exe"]),
                    "network_connection": "",
                    "severity": "critical",
                    "found_at": result_time.isoformat(),
                })
            elif ttp in ("T1059.001", "T1047", "T1053", "T1050"):
                results.append({
                    "matched_data": {"event": "suspicious_process", "command": "powershell -enc ..."},
                    "asset_id": random.choice(sample_assets),
                    "user_id": random.choice(sample_users),
                    "process_name": random.choice(["powershell.exe", "wmic.exe", "schtasks.exe"]),
                    "network_connection": "",
                    "severity": severity,
                    "found_at": result_time.isoformat(),
                })
            else:
                results.append({
                    "matched_data": {"event": "generic_suspicious", "ttp": ttp},
                    "asset_id": random.choice(sample_assets),
                    "user_id": random.choice(sample_users),
                    "process_name": "unknown",
                    "network_connection": random.choice(sample_ips),
                    "severity": severity,
                    "found_at": result_time.isoformat(),
                })

        return results

    def get_hunting_status(self, task_id: str) -> Optional[Dict]:
        """获取狩猎任务状态"""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM ti_hunting_tasks WHERE id = ?", (task_id,)).fetchone()
            if not row:
                return None
            task = dict(row)
            task['query_params'] = json.loads(task.get('query_params', '{}'))
            return task
        finally:
            conn.close()

    def get_hunting_results(self, task_id: str,
                            page: int = 1, page_size: int = 20,
                            severity: str = None) -> Dict:
        """获取狩猎结果（分页/筛选）"""
        conn = self._get_conn()
        try:
            query = "SELECT * FROM ti_hunting_results WHERE task_id = ?"
            count_query = "SELECT COUNT(*) FROM ti_hunting_results WHERE task_id = ?"
            params = [task_id]

            if severity:
                query += " AND severity = ?"
                count_query += " AND severity = ?"
                params.append(severity)

            total = conn.execute(count_query, params).fetchone()[0]
            offset = (page - 1) * page_size
            query += " ORDER BY found_at DESC LIMIT ? OFFSET ?"
            params.extend([page_size, offset])

            rows = conn.execute(query, params).fetchall()
            results = []
            for row in rows:
                r = dict(row)
                r['matched_data'] = json.loads(r.get('matched_data', '{}'))
                results.append(r)

            return {
                "total": total,
                "page": page,
                "page_size": page_size,
                "pages": (total + page_size - 1) // page_size,
                "items": results
            }
        finally:
            conn.close()

    def generate_hunting_report(self, task_id: str) -> Dict:
        """生成狩猎报告：假设/查询/结果/分析/建议"""
        conn = self._get_conn()
        try:
            # 获取任务
            task_row = conn.execute("SELECT * FROM ti_hunting_tasks WHERE id = ?", (task_id,)).fetchone()
            if not task_row:
                return {"error": "任务不存在"}

            task = dict(task_row)

            # 获取规则
            rule_row = conn.execute("SELECT * FROM ti_hunting_rules WHERE id = ?",
                                   (task["rule_id"],)).fetchone()
            rule = dict(rule_row) if rule_row else {}
            rule['query'] = json.loads(rule.get('query', '{}'))
            rule['query_params'] = json.loads(rule.get('query_params', '{}'))

            # 获取结果
            results_row = conn.execute("SELECT * FROM ti_hunting_results WHERE task_id = ?",
                                      (task_id,)).fetchall()
            results = []
            for row in results_row:
                r = dict(row)
                r['matched_data'] = json.loads(r.get('matched_data', '{}'))
                results.append(r)

            # 按严重程度统计
            severity_counts = {}
            for r in results:
                s = r.get("severity", "medium")
                severity_counts[s] = severity_counts.get(s, 0) + 1

            report = {
                "task_id": task_id,
                "task_name": task["name"],
                "rule_name": rule.get("name", "N/A"),
                "hypothesis": rule.get("hypothesis", ""),
                "ttp": rule.get("ttp", ""),
                "query_type": rule.get("query_type", ""),
                "query": rule.get("query", {}),
                "status": task["status"],
                "started_at": task.get("started_at"),
                "completed_at": task.get("completed_at"),
                "total_results": len(results),
                "severity_breakdown": severity_counts,
                "results": results[:50],  # 最多返回50条
                "analysis": self._analyze_hunting_results(rule, results),
                "recommendations": self._generate_recommendations(rule, results),
            }

            return report
        finally:
            conn.close()

    def _analyze_hunting_results(self, rule: Dict, results: List[Dict]) -> str:
        """分析狩猎结果"""
        if not results:
            return f"规则「{rule.get('name', '')}」未发现匹配项，当前环境可能不存在对应的威胁行为。"

        critical = sum(1 for r in results if r.get("severity") == "critical")
        high = sum(1 for r in results if r.get("severity") == "high")

        analysis = f"规则「{rule.get('name', '')}」共发现 {len(results)} 个匹配项。"
        if critical > 0:
            analysis += f" 其中 {critical} 个为严重级别，需要立即处置。"
        if high > 0:
            analysis += f" {high} 个为高危级别，建议优先调查。"

        # 按资产统计
        assets = set(r.get("asset_id", "") for r in results if r.get("asset_id"))
        if assets:
            analysis += f" 涉及 {len(assets)} 个资产: {', '.join(list(assets)[:5])}"

        return analysis

    def _generate_recommendations(self, rule: Dict, results: List[Dict]) -> List[str]:
        """生成狩猎建议"""
        if not results:
            return ["继续监控，定期运行此狩猎规则", "考虑扩大规则覆盖范围"]

        recommendations = []
        ttp = rule.get("ttp", "")

        if ttp == "T1486":
            recommendations.append("立即隔离受感染主机，防止勒索软件扩散")
            recommendations.append("检查备份是否可用，准备恢复方案")
            recommendations.append("检查是否有数据泄露到外部")
        elif ttp == "T1071":
            recommendations.append("阻断相关C2 IP/域名的出站连接")
            recommendations.append("对受感染主机进行全面取证分析")
            recommendations.append("检查是否存在持久化机制")
        elif ttp == "T1566":
            recommendations.append("通知相关用户进行安全意识培训")
            recommendations.append("拦截相关发件人地址")
            recommendations.append("检查邮件网关规则配置")
        else:
            recommendations.append("对匹配资产进行详细调查")
            recommendations.append("确认是否为误报")
            recommendations.append("根据发现调整防护策略")

        return recommendations

    def get_hunting_dashboard(self) -> Dict:
        """狩猎仪表盘：任务概览/结果统计/规则命中率"""
        conn = self._get_conn()
        try:
            # 任务统计
            total_tasks = conn.execute("SELECT COUNT(*) FROM ti_hunting_tasks").fetchone()[0]
            completed_tasks = conn.execute("SELECT COUNT(*) FROM ti_hunting_tasks WHERE status = 'completed'").fetchone()[0]
            running_tasks = conn.execute("SELECT COUNT(*) FROM ti_hunting_tasks WHERE status = 'running'").fetchone()[0]
            failed_tasks = conn.execute("SELECT COUNT(*) FROM ti_hunting_tasks WHERE status = 'failed'").fetchone()[0]

            # 结果统计
            total_results = conn.execute("SELECT COUNT(*) FROM ti_hunting_results").fetchone()[0]
            critical_results = conn.execute("SELECT COUNT(*) FROM ti_hunting_results WHERE severity = 'critical'").fetchone()[0]
            high_results = conn.execute("SELECT COUNT(*) FROM ti_hunting_results WHERE severity = 'high'").fetchone()[0]

            # 规则统计
            total_rules = conn.execute("SELECT COUNT(*) FROM ti_hunting_rules").fetchone()[0]
            enabled_rules = conn.execute("SELECT COUNT(*) FROM ti_hunting_rules WHERE enabled = 1").fetchone()[0]

            # 最近任务
            recent_tasks = conn.execute("""
                SELECT id, name, status, results_count, started_at
                FROM ti_hunting_tasks ORDER BY created_at DESC LIMIT 10
            """).fetchall()

            return {
                "overview": {
                    "total_rules": total_rules,
                    "enabled_rules": enabled_rules,
                    "total_tasks": total_tasks,
                    "completed_tasks": completed_tasks,
                    "running_tasks": running_tasks,
                    "failed_tasks": failed_tasks,
                    "total_results": total_results,
                    "critical_results": critical_results,
                    "high_results": high_results,
                },
                "recent_tasks": [dict(row) for row in recent_tasks]
            }
        finally:
            conn.close()

    def list_tasks(self, status: str = None,
                   page: int = 1, page_size: int = 20) -> Dict:
        """列出狩猎任务"""
        conn = self._get_conn()
        try:
            query = "SELECT * FROM ti_hunting_tasks WHERE 1=1"
            count_query = "SELECT COUNT(*) FROM ti_hunting_tasks WHERE 1=1"
            params = []

            if status:
                query += " AND status = ?"
                count_query += " AND status = ?"
                params.append(status)

            total = conn.execute(count_query, params).fetchone()[0]
            offset = (page - 1) * page_size
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([page_size, offset])

            rows = conn.execute(query, params).fetchall()
            tasks = []
            for row in rows:
                task = dict(row)
                task['query_params'] = json.loads(task.get('query_params', '{}'))
                tasks.append(task)

            return {
                "total": total,
                "page": page,
                "page_size": page_size,
                "pages": (total + page_size - 1) // page_size,
                "items": tasks
            }
        finally:
            conn.close()

    def get_task(self, task_id: str) -> Optional[Dict]:
        """获取单个狩猎任务详情"""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM ti_hunting_tasks WHERE id = ?", (task_id,)).fetchone()
            if not row:
                return None
            task = dict(row)
            task['query_params'] = json.loads(task.get('query_params', '{}'))
            return task
        finally:
            conn.close()
