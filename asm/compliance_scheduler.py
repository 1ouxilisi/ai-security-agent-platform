"""
OWASP Top10映射 + 定时任务调度 + 扫描历史聚合 - 第八轮升级
"""
import json
import os
import time
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta


# OWASP Top 10 (2021) 映射规则
OWASP_TOP10_2021 = {
    "A01": {"name": "失效的访问控制", "patterns": ["未授权", "越权", "IDOR", "访问控制", "权限绕过", "目录遍历"]},
    "A02": {"name": "加密机制失效", "patterns": ["弱加密", "明文传输", "SSL", "证书", "TLS", "加密", "敏感数据暴露"]},
    "A03": {"name": "注入", "patterns": ["SQL注入", "XSS", "命令注入", "代码注入", "LDAP注入", "XPath注入", "SSTI", "模板注入", "反射型XSS", "存储型XSS"]},
    "A04": {"name": "不安全设计", "patterns": ["安全设计缺陷", "业务逻辑", "流程缺陷", "竞争条件"]},
    "A05": {"name": "安全配置错误", "patterns": ["默认密码", "目录列表", "调试模式", "不必要服务", "错误信息泄露", "安全头缺失", "CORS"]},
    "A06": {"name": "易受攻击的组件", "patterns": ["过时", "版本", "组件", "依赖", "库", "框架", "CVE", "已知漏洞"]},
    "A07": {"name": "身份识别和认证失败", "patterns": ["弱密码", "会话", "认证", "登录", " brute force", "密码策略", "JWT", "令牌"]},
    "A08": {"name": "软件和数据完整性故障", "patterns": ["反序列化", "完整性", "更新机制", "CI/CD", "供应链"]},
    "A09": {"name": "安全日志和监控失效", "patterns": ["日志缺失", "监控不足", "告警缺失", "审计"]},
    "A10": {"name": "服务器端请求伪造", "patterns": ["SSRF", "服务器端请求", "URL获取", "内网请求"]}
}


class OWASPMapper:
    """将发现的漏洞自动映射到OWASP Top 10分类"""

    @staticmethod
    def map(vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """将漏洞列表映射到OWASP Top 10"""
        categories = {key: {"name": val["name"], "vulns": []} for key, val in OWASP_TOP10_2021.items()}
        unmapped = []

        for vuln in vulnerabilities:
            name = (vuln.get("name", "") + " " + vuln.get("category", "") + " " + vuln.get("description", "")).lower()
            matched = False
            for code, info in OWASP_TOP10_2021.items():
                for pattern in info["patterns"]:
                    if pattern.lower() in name:
                        categories[code]["vulns"].append(vuln)
                        matched = True
                        break
                if matched:
                    break
            if not matched:
                unmapped.append(vuln)

        # 统计
        summary = {}
        for code, cat in categories.items():
            summary[code] = {
                "name": cat["name"],
                "count": len(cat["vulns"]),
                "severity": OWASPMapper._max_severity(cat["vulns"])
            }

        return {
            "framework": "OWASP Top 10 (2021)",
            "categories": summary,
            "total_mapped": sum(1 for c in categories.values() if c["vulns"]),
            "unmapped_count": len(unmapped),
            "unmapped": unmapped[:10]
        }

    @staticmethod
    def _max_severity(vulns: List[Dict]) -> str:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_sev = "none"
        max_val = 0
        for v in vulns:
            sev = v.get("severity", "low")
            if order.get(sev, 0) > max_val:
                max_val = order.get(sev, 0)
                max_sev = sev
        return max_sev


class ScanHistory:
    """扫描历史记录管理"""

    def __init__(self, db_path: str = "data/scan_history.json"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._load()

    def _load(self):
        if os.path.exists(self.db_path):
            with open(self.db_path, "r", encoding="utf-8") as f:
                self.history = json.load(f)
        else:
            self.history = {"scans": []}

    def _save(self):
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(self.history, f, ensure_ascii=False, indent=2, default=str)

    def add_scan(self, target: str, scan_type: str, result: Dict) -> str:
        scan_id = f"scan_{int(time.time())}"
        record = {
            "id": scan_id,
            "target": target,
            "type": scan_type,
            "timestamp": datetime.now().isoformat(),
            "summary": result.get("summary", {}),
            "vuln_count": len(result.get("phases", {}).get("vuln_scan", {}).get("vulnerabilities", [])),
            "port_count": result.get("phases", {}).get("port_scan", {}).get("open_ports_count", 0)
        }
        self.history["scans"].insert(0, record)
        self.history["scans"] = self.history["scans"][:100]  # 保留最近100条
        self._save()
        return scan_id

    def list_scans(self, target: str = None, limit: int = 20) -> List[Dict]:
        scans = self.history["scans"]
        if target:
            scans = [s for s in scans if target in s.get("target", "")]
        return scans[:limit]

    def get_stats(self) -> Dict:
        scans = self.history["scans"]
        total_vulns = sum(s.get("vuln_count", 0) for s in scans)
        total_ports = sum(s.get("port_count", 0) for s in scans)
        targets = len(set(s.get("target") for s in scans))
        return {
            "total_scans": len(scans),
            "unique_targets": targets,
            "total_vulns_found": total_vulns,
            "total_ports_detected": total_ports,
            "latest_scan": scans[0] if scans else None
        }


class ScheduledScanner:
    """定时扫描任务调度"""

    def __init__(self):
        self.jobs = {}
        self._lock = threading.Lock()

    def add_job(self, job_id: str, target: str, interval_minutes: int, scan_type: str = "full"):
        """添加定时扫描任务"""
        self.jobs[job_id] = {
            "id": job_id,
            "target": target,
            "interval_minutes": interval_minutes,
            "scan_type": scan_type,
            "created_at": datetime.now().isoformat(),
            "last_run": None,
            "next_run": (datetime.now() + timedelta(minutes=interval_minutes)).isoformat(),
            "enabled": True,
            "run_count": 0
        }
        return self.jobs[job_id]

    def list_jobs(self) -> List[Dict]:
        return list(self.jobs.values())

    def remove_job(self, job_id: str) -> bool:
        if job_id in self.jobs:
            del self.jobs[job_id]
            return True
        return False

    def toggle_job(self, job_id: str) -> Optional[Dict]:
        if job_id in self.jobs:
            self.jobs[job_id]["enabled"] = not self.jobs[job_id]["enabled"]
            return self.jobs[job_id]
        return None
