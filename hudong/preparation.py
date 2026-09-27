"""
护网准备管理器（Preparation Manager）

模块功能：
    - 护网准备任务的创建与状态跟踪
    - 资产梳理（全面资产列表/分类/分组/重要性评级/责任人）
    - 攻击面梳理（互联网暴露资产/开放端口/运行服务/Web应用/API/远程管理）
    - 漏洞扫描结果与优先级排序
    - 风险评估（资产风险评级/攻击路径/业务影响/整体风险）
    - 加固建议与加固任务的分配、执行、验证
    - 生成护网准备报告

合法定位：
    本模块为防御视角的护网准备系统，用于己方资产防护，不提供攻击能力。

注意事项：
    - 本模块仅用于授权的护网演练与安全运营
    - 请勿用于非法用途
"""
import json
import uuid
import hashlib
import random
from datetime import datetime
from typing import Optional, List, Dict, Any

from utils.database import db
from utils.logger import log


# 合法枚举约束
VALID_PREP_STATUS = ("pending", "in_progress", "completed")
VALID_EXPOSURE = ("internet", "intranet", "isolated")
VALID_RISK = ("critical", "high", "medium", "low")
VALID_PRIORITY = ("critical", "high", "medium", "low")
VALID_HARDEN_STATUS = ("pending", "in_progress", "completed")


class PreparationManager:
    """护网准备管理器：负责准备阶段的资产梳理、攻击面、漏洞与加固"""

    def __init__(self):
        """初始化准备管理器，自动建表"""
        self._init_tables()

    # ==================== 数据库初始化 ====================

    def _init_tables(self):
        """初始化护网准备相关数据表（幂等）"""
        conn = db._get_connection()
        try:
            cur = conn.cursor()
            # 准备任务主表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hd_preparations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    status TEXT DEFAULT 'pending',
                    started_at TEXT,
                    completed_at TEXT,
                    asset_count INTEGER DEFAULT 0,
                    attack_surface_count INTEGER DEFAULT 0,
                    vuln_count INTEGER DEFAULT 0,
                    high_risk_asset_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            """)
            # 攻击面表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hd_attack_surfaces (
                    id TEXT PRIMARY KEY,
                    preparation_id TEXT NOT NULL,
                    asset_id TEXT,
                    ip TEXT,
                    domain TEXT,
                    exposure_type TEXT DEFAULT 'intranet',
                    open_ports TEXT,
                    running_services TEXT,
                    web_apps TEXT,
                    apis TEXT,
                    remote_management TEXT,
                    risk_level TEXT DEFAULT 'medium',
                    created_at TEXT NOT NULL
                )
            """)
            # 加固任务表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hd_hardening_tasks (
                    id TEXT PRIMARY KEY,
                    preparation_id TEXT NOT NULL,
                    asset_id TEXT,
                    vulnerability_id TEXT,
                    title TEXT NOT NULL,
                    description TEXT,
                    priority TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'pending',
                    assignee TEXT,
                    due_date TEXT,
                    hardening_steps TEXT,
                    completed_at TEXT,
                    verification_result TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            # 索引
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_prep_status ON hd_preparations(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_as_prep ON hd_attack_surfaces(preparation_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_as_exposure ON hd_attack_surfaces(exposure_type)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_hard_prep ON hd_hardening_tasks(preparation_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_hard_status ON hd_hardening_tasks(status)")
            conn.commit()
            log.info("✅ 护网准备表初始化完成")
        except Exception as e:
            log.error(f"护网准备表初始化失败: {e}")
        finally:
            conn.close()

    # ==================== 工具方法 ====================

    @staticmethod
    def _now() -> str:
        """返回当前ISO时间字符串"""
        return datetime.now().isoformat()

    @staticmethod
    def _seed(prep_id: str) -> random.Random:
        """根据准备任务ID生成确定性随机源，保证多次调用结果一致"""
        h = hashlib.md5(prep_id.encode("utf-8")).hexdigest()
        return random.Random(int(h[:8], 16))

    @staticmethod
    def _row_to_dict(row) -> dict:
        """将SQLite Row转为字典，并反序列化JSON字段"""
        if row is None:
            return {}
        item = dict(row)
        for jf in ("open_ports", "running_services", "web_apps", "apis",
                   "remote_management", "hardening_steps"):
            raw = item.get(jf)
            if isinstance(raw, str):
                try:
                    item[jf] = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    item[jf] = []
            elif raw is None:
                item[jf] = []
        return item

    # ==================== 模拟数据生成 ====================

    # 模拟资产目录：类型 / 用途 / 重要性
    _ASSET_CATALOG = [
        ("门户网站Web服务器", "web", "critical", "运维一组"),
        ("核心交易数据库", "database", "critical", "DBA组"),
        ("会员管理系统", "web", "critical", "研发二组"),
        ("OA办公系统", "web", "medium", "行政IT"),
        ("邮件服务器", "server", "medium", "运维一组"),
        ("文件存储服务器", "server", "medium", "运维二组"),
        ("API网关", "network", "critical", "架构组"),
        ("VPN接入网关", "network", "high", "网络组"),
        ("DNS服务器", "network", "medium", "网络组"),
        ("备份服务器", "server", "high", "运维二组"),
        ("测试环境Web服务器", "web", "low", "测试组"),
        ("日志审计平台", "server", "high", "安全组"),
    ]

    _PORT_POOL = [80, 443, 22, 3306, 5432, 6379, 8080, 8443, 9000, 21, 25, 3389]
    _SERVICE_POOL = ["nginx", "apache", "openssh", "mysql", "postgresql",
                     "redis", "tomcat", "iis", "ftp", "postfix", "rdp"]
    _VULN_POOL = [
        ("Apache Log4j2 远程代码执行", "critical", "CVE-2021-44228", "远程代码执行"),
        ("Nginx 目录遍历漏洞", "high", "CVE-2017-7529", "信息泄露"),
        ("MySQL 弱口令", "high", "WEAK-MYSQL", "权限获取"),
        ("Redis 未授权访问", "critical", "CVE-2015-4335", "远程代码执行"),
        ("OpenSSH 用户名枚举", "medium", "CVE-2018-15473", "信息泄露"),
        ("Tomcat 管理后台弱口令", "high", "WEAK-TOMCAT", "权限获取"),
        ("Web应用SQL注入", "high", "CWE-89", "数据泄露"),
        ("Web应用XSS跨站脚本", "medium", "CWE-79", "会话劫持"),
        ("FTP 匿名登录开启", "medium", "MISCONF-FTP", "信息泄露"),
        ("RDP 暴力破解暴露", "high", "MISCONF-RDP", "权限获取"),
        ("过期SSL证书", "low", "MISCONF-SSL", "中间人风险"),
        ("DNS区域传送未限制", "medium", "MISCONF-DNS", "信息泄露"),
    ]

    def _seed_attack_surfaces(self, prep_id: str, count: int = 12) -> List[dict]:
        """为准备任务生成并写入模拟攻击面数据，返回攻击面列表"""
        rng = self._seed(prep_id)
        surfaces = []
        # 互联网暴露资产数量约占 1/3
        exposure_plan = (["internet"] * max(1, count // 3) +
                         ["intranet"] * (count // 2) +
                         ["isolated"] * (count - max(1, count // 3) - count // 2))
        rng.shuffle(exposure_plan)

        now = self._now()
        conn = db._get_connection()
        try:
            for i, exposure in enumerate(exposure_plan[:count]):
                catalog = self._ASSET_CATALOG[i % len(self._ASSET_CATALOG)]
                surf_id = str(uuid.uuid4())
                asset_id = f"asset-{i+1:03d}"
                ip = f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
                if exposure == "internet":
                    ip = f"{rng.choice([1,112,120,183,220])}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
                    domain = f"www{i+1}.example{catalog[1]}.com"
                elif exposure == "intranet":
                    domain = f"intranet-{i+1}.local"
                else:
                    domain = ""

                port_count = rng.randint(1, 5) if exposure != "isolated" else rng.randint(0, 2)
                open_ports = rng.sample(self._PORT_POOL, min(port_count, len(self._PORT_POOL)))
                services = rng.sample(self._SERVICE_POOL, min(len(open_ports), len(self._SERVICE_POOL)))
                web_apps = [f"{catalog[0]}(端口{p})" for p in open_ports if p in (80, 443, 8080, 8443)]
                apis = [f"/api/v1/{catalog[1]}/{ep}" for ep in ("query", "update", "export")] if exposure == "internet" else []
                remote_mgmt = []
                if 22 in open_ports:
                    remote_mgmt.append("SSH(22)")
                if 3389 in open_ports:
                    remote_mgmt.append("RDP(3389)")

                # 风险等级：互联网暴露 + critical重要性 = critical
                importance = catalog[2]
                if exposure == "internet" and importance in ("critical", "high"):
                    risk = "critical" if importance == "critical" else "high"
                elif exposure == "internet":
                    risk = "medium"
                elif exposure == "isolated":
                    risk = "low"
                else:
                    risk = "medium"

                conn.execute("""
                    INSERT INTO hd_attack_surfaces (
                        id, preparation_id, asset_id, ip, domain, exposure_type,
                        open_ports, running_services, web_apps, apis,
                        remote_management, risk_level, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    surf_id, prep_id, asset_id, ip, domain, exposure,
                    json.dumps(open_ports, ensure_ascii=False),
                    json.dumps(services, ensure_ascii=False),
                    json.dumps(web_apps, ensure_ascii=False),
                    json.dumps(apis, ensure_ascii=False),
                    json.dumps(remote_mgmt, ensure_ascii=False),
                    risk, now,
                ))
                surfaces.append({
                    "id": surf_id, "asset_id": asset_id, "ip": ip, "domain": domain,
                    "exposure_type": exposure, "open_ports": open_ports,
                    "running_services": services, "web_apps": web_apps,
                    "apis": apis, "remote_management": remote_mgmt,
                    "risk_level": risk, "asset_name": catalog[0],
                    "asset_type": catalog[1], "importance": importance, "owner": catalog[3],
                })
            conn.commit()
        except Exception as e:
            log.error(f"写入攻击面数据失败: {e}")
        finally:
            conn.close()
        return surfaces

    # ==================== 核心流程 ====================

    def start_preparation(self, name: str = "", description: str = "") -> dict:
        """启动护网准备，创建准备任务并生成模拟资产/攻击面/漏洞数据

        Args:
            name: 准备任务名称
            description: 任务描述

        Returns:
            创建后的准备任务字典
        """
        prep_id = str(uuid.uuid4())
        now = self._now()
        name = name or f"护网准备-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO hd_preparations (
                    id, name, description, status, started_at,
                    asset_count, attack_surface_count, vuln_count,
                    high_risk_asset_count, created_at
                ) VALUES (?, ?, ?, 'in_progress', ?, 0, 0, 0, 0, ?)
            """, (prep_id, name, description, now, now))
            conn.commit()
        except Exception as e:
            log.error(f"创建护网准备任务失败: {e}")
            raise
        finally:
            conn.close()

        # 生成模拟攻击面数据
        surfaces = self._seed_attack_surfaces(prep_id, count=12)
        vulns = self.get_vulnerabilities(prep_id)
        high_risk = sum(1 for s in surfaces if s["risk_level"] in ("critical", "high"))

        conn = db._get_connection()
        try:
            conn.execute("""
                UPDATE hd_preparations
                SET asset_count = ?, attack_surface_count = ?,
                    vuln_count = ?, high_risk_asset_count = ?
                WHERE id = ?
            """, (len(surfaces), len(surfaces), len(vulns), high_risk, prep_id))
            conn.commit()
        finally:
            conn.close()

        log.info(f"✅ 护网准备任务已启动: {prep_id} - {name}（资产{len(surfaces)}）")
        return self.get_preparation_status(prep_id)

    def get_preparation_status(self, preparation_id: str) -> Optional[dict]:
        """获取护网准备任务状态"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM hd_preparations WHERE id = ?", (preparation_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    # ==================== 资产梳理 ====================

    def get_asset_inventory(self, preparation_id: str) -> dict:
        """资产梳理结果：全面资产列表/分类/分组/重要性评级/责任人"""
        surfaces = self._get_surfaces(preparation_id)
        assets = []
        type_groups: Dict[str, int] = {}
        importance_groups: Dict[str, int] = {}
        owner_groups: Dict[str, int] = {}

        for s in surfaces:
            a = {
                "asset_id": s["asset_id"], "name": s["asset_name"],
                "ip": s["ip"], "domain": s["domain"],
                "type": s["asset_type"], "importance": s["importance"],
                "owner": s["owner"], "exposure_type": s["exposure_type"],
                "risk_level": s["risk_level"],
            }
            assets.append(a)
            type_groups[a["type"]] = type_groups.get(a["type"], 0) + 1
            importance_groups[a["importance"]] = importance_groups.get(a["importance"], 0) + 1
            owner_groups[a["owner"]] = owner_groups.get(a["owner"], 0) + 1

        return {
            "preparation_id": preparation_id,
            "total_assets": len(assets),
            "assets": assets,
            "groups_by_type": type_groups,
            "groups_by_importance": importance_groups,
            "groups_by_owner": owner_groups,
        }

    # ==================== 攻击面 ====================

    def _get_surfaces(self, preparation_id: str) -> List[dict]:
        """读取攻击面记录并补全模拟资产属性"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM hd_attack_surfaces WHERE preparation_id = ? ORDER BY created_at",
                (preparation_id,),
            ).fetchall()
        finally:
            conn.close()

        surfaces = []
        for idx, r in enumerate(rows):
            item = self._row_to_dict(r)
            catalog = self._ASSET_CATALOG[idx % len(self._ASSET_CATALOG)]
            item["asset_name"] = catalog[0]
            item["asset_type"] = catalog[1]
            item["importance"] = catalog[2]
            item["owner"] = catalog[3]
            surfaces.append(item)
        return surfaces

    def get_attack_surface(self, preparation_id: str) -> dict:
        """攻击面梳理结果：互联网暴露资产/开放端口/运行服务/Web应用/API/远程管理"""
        surfaces = self._get_surfaces(preparation_id)
        internet_assets = [s for s in surfaces if s["exposure_type"] == "internet"]
        all_ports: Dict[int, int] = {}
        all_services: Dict[str, int] = {}
        all_web_apps: List[str] = []
        all_apis: List[str] = []
        all_remote: List[str] = []

        for s in surfaces:
            for p in s.get("open_ports", []):
                all_ports[p] = all_ports.get(p, 0) + 1
            for svc in s.get("running_services", []):
                all_services[svc] = all_services.get(svc, 0) + 1
            all_web_apps.extend(s.get("web_apps", []))
            all_apis.extend(s.get("apis", []))
            all_remote.extend(s.get("remote_management", []))

        return {
            "preparation_id": preparation_id,
            "total_surfaces": len(surfaces),
            "internet_exposed_count": len(internet_assets),
            "internet_exposed_assets": internet_assets,
            "all_surfaces": surfaces,
            "open_ports_distribution": dict(sorted(all_ports.items())),
            "running_services_distribution": dict(sorted(all_services.items())),
            "web_apps": all_web_apps,
            "apis": all_apis,
            "remote_management": all_remote,
        }

    # ==================== 漏洞扫描 ====================

    def get_vulnerabilities(self, preparation_id: str) -> dict:
        """漏洞扫描结果：漏洞列表/验证结果/优先级排序"""
        surfaces = self._get_surfaces(preparation_id)
        rng = self._seed(preparation_id + ":vuln")
        vulns = []
        # 为每个互联网暴露资产生成 1~3 个漏洞
        idx = 0
        for s in surfaces:
            n = rng.randint(1, 3) if s["exposure_type"] == "internet" else rng.randint(0, 1)
            for _ in range(n):
                idx += 1
                title, severity, cve, vtype = self._VULN_POOL[
                    rng.randrange(len(self._VULN_POOL))]
                vulns.append({
                    "id": f"vuln-{idx:04d}",
                    "asset_id": s["asset_id"],
                    "asset_name": s["asset_name"],
                    "ip": s["ip"],
                    "title": title,
                    "type": vtype,
                    "severity": severity,
                    "cve_id": cve,
                    "verified": rng.random() > 0.25,
                    "cvss": {"critical": 9.5, "high": 7.8, "medium": 5.3,
                             "low": 3.1}.get(severity, 5.0),
                })

        # 优先级排序：critical > high > medium > low
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        vulns.sort(key=lambda v: (order.get(v["severity"], 9), v["asset_id"]))
        sev_count: Dict[str, int] = {}
        for v in vulns:
            sev_count[v["severity"]] = sev_count.get(v["severity"], 0) + 1

        return {
            "preparation_id": preparation_id,
            "total": len(vulns),
            "by_severity": sev_count,
            "verified_count": sum(1 for v in vulns if v["verified"]),
            "vulnerabilities": vulns,
        }

    # ==================== 风险评估 ====================

    def get_risk_assessment(self, preparation_id: str) -> dict:
        """风险评估：资产风险评级/攻击路径分析/业务影响分析/整体风险评估"""
        surfaces = self._get_surfaces(preparation_id)
        vuln_data = self.get_vulnerabilities(preparation_id)

        # 资产风险评级
        asset_risks = []
        for s in surfaces:
            related = [v for v in vuln_data["vulnerabilities"]
                       if v["asset_id"] == s["asset_id"]]
            score = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s["risk_level"], 2)
            score += sum({"critical": 3, "high": 2, "medium": 1, "low": 0}.get(v["severity"], 0)
                         for v in related)
            asset_risks.append({
                "asset_id": s["asset_id"], "name": s["asset_name"],
                "risk_level": s["risk_level"], "vuln_count": len(related),
                "risk_score": score,
                "importance": s["importance"],
            })

        # 攻击路径分析（模拟）
        attack_paths = [
            {"path": "互联网 → Web应用 → SQL注入 → 数据库",
             "affected_assets": ["核心交易数据库", "门户网站Web服务器"],
             "feasibility": "high"},
            {"path": "互联网 → Redis未授权访问 → 写计划任务 → 服务器沦陷",
             "affected_assets": ["缓存/存储类服务器"],
             "feasibility": "critical"},
            {"path": "VPN弱口令 → 内网横向 → OA系统",
             "affected_assets": ["VPN接入网关", "OA办公系统"],
             "feasibility": "high"},
        ]

        # 业务影响分析
        business_impact = [
            {"asset": "核心交易数据库", "impact": "交易中断/数据泄露",
             "business_loss": "极高"},
            {"asset": "门户网站Web服务器", "impact": "业务中断/声誉受损",
             "business_loss": "高"},
            {"asset": "会员管理系统", "impact": "会员数据泄露",
             "business_loss": "高"},
        ]

        critical_assets = sum(1 for a in asset_risks if a["risk_level"] == "critical")
        high_assets = sum(1 for a in asset_risks if a["risk_level"] == "high")
        overall = "高" if critical_assets > 0 else ("中高" if high_assets > 0 else "中")

        return {
            "preparation_id": preparation_id,
            "asset_risks": asset_risks,
            "attack_paths": attack_paths,
            "business_impact": business_impact,
            "overall_risk_level": overall,
            "risk_matrix": {
                "critical": critical_assets,
                "high": high_assets,
                "medium": sum(1 for a in asset_risks if a["risk_level"] == "medium"),
                "low": sum(1 for a in asset_risks if a["risk_level"] == "low"),
            },
        }

    # ==================== 加固 ====================

    def get_hardening_suggestions(self, preparation_id: str) -> List[dict]:
        """加固建议：针对高风险资产/高危漏洞/薄弱配置"""
        vuln_data = self.get_vulnerabilities(preparation_id)
        suggestions = []
        for v in vuln_data["vulnerabilities"]:
            if v["severity"] not in ("critical", "high"):
                continue
            steps = []
            if "弱口令" in v["title"] or "未授权" in v["title"]:
                steps = ["立即修改强口令/开启访问认证", "限制源IP白名单", "升级到最新版本"]
            elif "注入" in v["title"] or "XSS" in v["title"]:
                steps = ["部署WAF规则", "代码层参数化查询/输出编码", "上线前回归测试"]
            elif "RCE" in v["title"].upper() or "远程代码执行" in v["title"]:
                steps = ["立即安装安全补丁", "临时下线受影响服务", "验证补丁有效性"]
            else:
                steps = ["核实漏洞真实性", "按厂商公告修复", "复测验证"]
            suggestions.append({
                "asset_id": v["asset_id"],
                "asset_name": v["asset_name"],
                "vulnerability_id": v["id"],
                "title": v["title"],
                "severity": v["severity"],
                "suggested_priority": v["severity"],
                "hardening_steps": steps,
            })
        return suggestions

    def list_hardening_tasks(self, preparation_id: str,
                             status: Optional[str] = None) -> List[dict]:
        """加固任务列表"""
        conn = db._get_connection()
        try:
            if status:
                rows = conn.execute(
                    """SELECT * FROM hd_hardening_tasks
                       WHERE preparation_id = ? AND status = ?
                       ORDER BY created_at""",
                    (preparation_id, status),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM hd_hardening_tasks
                       WHERE preparation_id = ? ORDER BY created_at""",
                    (preparation_id,),
                ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def start_hardening(self, preparation_id: str, title: str,
                        asset_id: str = "", vulnerability_id: str = "",
                        description: str = "", priority: str = "high",
                        assignee: str = "", due_date: str = "") -> dict:
        """分配加固任务

        Args:
            preparation_id: 准备任务ID
            title: 加固任务标题
            asset_id: 关联资产ID
            vulnerability_id: 关联漏洞ID
            description: 任务描述
            priority: 优先级 critical/high/medium/low
            assignee: 责任人
            due_date: 截止日期

        Returns:
            创建后的加固任务字典
        """
        if priority not in VALID_PRIORITY:
            priority = "high"
        task_id = str(uuid.uuid4())
        now = self._now()
        steps = ["核实漏洞/配置", "实施加固操作", "复测验证", "关闭任务"]

        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO hd_hardening_tasks (
                    id, preparation_id, asset_id, vulnerability_id, title,
                    description, priority, status, assignee, due_date,
                    hardening_steps, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'in_progress', ?, ?, ?, ?)
            """, (
                task_id, preparation_id, asset_id, vulnerability_id, title,
                description, priority, assignee, due_date,
                json.dumps(steps, ensure_ascii=False), now,
            ))
            conn.commit()
        finally:
            conn.close()
        log.info(f"✅ 加固任务已分配: {task_id} - {title} → {assignee or '未指定'}")
        return self._get_hardening_task(task_id)

    def _get_hardening_task(self, task_id: str) -> Optional[dict]:
        """获取单个加固任务"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM hd_hardening_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def verify_hardening(self, task_id: str, passed: bool = True,
                        verification_result: str = "") -> Optional[dict]:
        """加固验证：更新任务状态与验证结果"""
        now = self._now()
        conn = db._get_connection()
        try:
            new_status = "completed" if passed else "pending"
            conn.execute("""
                UPDATE hd_hardening_tasks
                SET status = ?, completed_at = ?, verification_result = ?
                WHERE id = ?
            """, (new_status, now, verification_result or ("验证通过" if passed else "验证未通过"), task_id))
            conn.commit()
        finally:
            conn.close()
        log.info(f"加固任务 {task_id} 验证结果: {'通过' if passed else '未通过'}")
        return self._get_hardening_task(task_id)

    # ==================== 准备报告 ====================

    def generate_preparation_report(self, preparation_id: str) -> dict:
        """生成护网准备报告：资产清单/攻击面/漏洞清单/风险评估/加固建议/加固执行情况"""
        prep = self.get_preparation_status(preparation_id)
        if not prep:
            return {}

        assets = self.get_asset_inventory(preparation_id)
        surface = self.get_attack_surface(preparation_id)
        vulns = self.get_vulnerabilities(preparation_id)
        risk = self.get_risk_assessment(preparation_id)
        suggestions = self.get_hardening_suggestions(preparation_id)
        tasks = self.list_hardening_tasks(preparation_id)

        done = sum(1 for t in tasks if t.get("status") == "completed")
        now = self._now()
        # 准备完成
        conn = db._get_connection()
        try:
            conn.execute(
                "UPDATE hd_preparations SET status = 'completed', completed_at = ? WHERE id = ?",
                (now, preparation_id),
            )
            conn.commit()
        finally:
            conn.close()

        return {
            "report_type": "preparation",
            "preparation_id": preparation_id,
            "title": f"护网准备报告 - {prep['name']}",
            "generated_at": now,
            "asset_inventory": {
                "total": assets["total_assets"],
                "by_type": assets["groups_by_type"],
                "by_importance": assets["groups_by_importance"],
            },
            "attack_surface": {
                "total": surface["total_surfaces"],
                "internet_exposed": surface["internet_exposed_count"],
                "ports": surface["open_ports_distribution"],
            },
            "vulnerabilities": {
                "total": vulns["total"],
                "by_severity": vulns["by_severity"],
                "verified": vulns["verified_count"],
            },
            "risk_assessment": {
                "overall": risk["overall_risk_level"],
                "matrix": risk["risk_matrix"],
            },
            "hardening_suggestions_count": len(suggestions),
            "hardening_execution": {
                "total_tasks": len(tasks),
                "completed_tasks": done,
                "pending_tasks": len(tasks) - done,
            },
        }


# 全局单例
preparation_manager = PreparationManager()
