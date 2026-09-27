# -*- coding: utf-8 -*-
"""
漏洞生命周期管理模块

提供漏洞从发现到关闭的全生命周期状态管理：
    - 状态机：discovered -> confirmed -> fixing -> fixed -> verifying -> closed
      任意状态可 reopened（重新打开）
    - SLA 期限：按严重程度计算修复截止日期
    - 分配 / 状态流转 / 验证 / 历史记录 / 逾期检测 / 统计

注意：本模块仅用于授权安全评估与防御整改，不用于攻击。
"""
import os
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from utils.logger import log

# 项目根目录（security 包的上一级）
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data", "vuln_lifecycle")


class VulnerabilityLifecycle:
    """漏洞生命周期管理器"""

    # 状态定义
    STATUS_DISCOVERED = "discovered"      # 发现
    STATUS_CONFIRMED = "confirmed"        # 确认
    STATUS_FIXING = "fixing"              # 修复中
    STATUS_FIXED = "fixed"                # 已修复
    STATUS_VERIFYING = "verifying"        # 验证中
    STATUS_CLOSED = "closed"              # 已关闭
    STATUS_REOPENED = "reopened"          # 重新打开

    ALL_STATUSES = (
        STATUS_DISCOVERED, STATUS_CONFIRMED, STATUS_FIXING,
        STATUS_FIXED, STATUS_VERIFYING, STATUS_CLOSED, STATUS_REOPENED,
    )

    # 允许的状态流转规则
    VALID_TRANSITIONS: Dict[str, List[str]] = {
        STATUS_DISCOVERED: [STATUS_CONFIRMED, STATUS_REOPENED, STATUS_FIXING],
        STATUS_CONFIRMED: [STATUS_FIXING, STATUS_DISCOVERED, STATUS_REOPENED],
        STATUS_FIXING: [STATUS_FIXED, STATUS_CONFIRMED, STATUS_REOPENED],
        STATUS_FIXED: [STATUS_VERIFYING, STATUS_FIXING, STATUS_REOPENED],
        STATUS_VERIFYING: [STATUS_CLOSED, STATUS_FIXING, STATUS_REOPENED],
        STATUS_CLOSED: [STATUS_REOPENED],
        # reopened 视为重新激活，可回到修复流程
        STATUS_REOPENED: [STATUS_FIXING, STATUS_CONFIRMED, STATUS_DISCOVERED],
    }

    # SLA 期限（天）：按严重程度
    SLA_DAYS: Dict[str, int] = {
        "critical": 7,
        "high": 15,
        "medium": 30,
        "low": 90,
        "info": 90,
    }

    def __init__(self, data_dir: Optional[str] = None):
        """初始化生命周期管理器，加载已有数据。"""
        self.data_dir = data_dir or DATA_DIR
        os.makedirs(self.data_dir, exist_ok=True)
        self.vuln_file = os.path.join(self.data_dir, "vulnerabilities.json")
        self.history_file = os.path.join(self.data_dir, "history.json")
        self.vulnerabilities: Dict[str, Dict[str, Any]] = {}
        self.history: Dict[str, List[Dict[str, Any]]] = {}
        self._load()
        log.info("漏洞生命周期管理器初始化完成，共 %d 个漏洞" % len(self.vulnerabilities))

    # ------------------------------------------------------------------ #
    # 持久化
    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        """从 JSON 文件加载漏洞与历史数据。"""
        try:
            if os.path.exists(self.vuln_file):
                with open(self.vuln_file, "r", encoding="utf-8") as f:
                    self.vulnerabilities = json.load(f)
            if os.path.exists(self.history_file):
                with open(self.history_file, "r", encoding="utf-8") as f:
                    self.history = json.load(f)
        except Exception as e:  # pragma: no cover
            log.warning("加载漏洞生命周期数据失败: %s" % e)
            self.vulnerabilities = {}
            self.history = {}

    def _save(self) -> None:
        """持久化漏洞与历史数据到 JSON 文件。"""
        try:
            with open(self.vuln_file, "w", encoding="utf-8") as f:
                json.dump(self.vulnerabilities, f, ensure_ascii=False, indent=2)
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self.history, f, ensure_ascii=False, indent=2)
        except Exception as e:  # pragma: no cover
            log.error("保存漏洞生命周期数据失败: %s" % e)

    # ------------------------------------------------------------------ #
    # 业务方法
    # ------------------------------------------------------------------ #
    @staticmethod
    def can_transition(from_status: str, to_status: str) -> bool:
        """校验是否允许从 from_status 流转到 to_status。"""
        allowed = VulnerabilityLifecycle.VALID_TRANSITIONS.get(from_status, [])
        return to_status in allowed

    @staticmethod
    def get_due_date(severity: str, discovered_at: Optional[float] = None) -> float:
        """根据严重程度和发现时间计算 SLA 截止日期（时间戳）。"""
        discovered_at = discovered_at or time.time()
        days = VulnerabilityLifecycle.SLA_DAYS.get(severity.lower(), 90)
        dt = datetime.fromtimestamp(discovered_at) + timedelta(days=days)
        return dt.timestamp()

    def create_vulnerability(self, title: str, severity: str,
                             target: str = "", description: str = "",
                             cve: str = "") -> Dict[str, Any]:
        """创建一个新漏洞（初始状态 discovered）。"""
        vuln_id = "vuln-%s" % uuid.uuid4().hex[:10]
        now = time.time()
        severity = severity.lower()
        vuln = {
            "id": vuln_id,
            "title": title,
            "severity": severity,
            "target": target,
            "description": description,
            "cve": cve,
            "status": self.STATUS_DISCOVERED,
            "assignee": None,
            "assigned_at": None,
            "assigned_by": None,
            "discovered_at": now,
            "due_date": self.get_due_date(severity, now),
            "fixed_at": None,
            "closed_at": None,
            "created_at": now,
            "updated_at": now,
        }
        self.vulnerabilities[vuln_id] = vuln
        self.history[vuln_id] = [{
            "time": now,
            "operator": "system",
            "from_status": None,
            "to_status": self.STATUS_DISCOVERED,
            "note": "漏洞创建",
        }]
        self._save()
        log.info("创建漏洞 %s (%s)" % (vuln_id, title))
        return vuln

    def assign(self, vuln_id: str, assignee: str, note: str = "") -> Dict[str, Any]:
        """为漏洞分配负责人。"""
        if vuln_id not in self.vulnerabilities:
            raise KeyError("漏洞不存在: %s" % vuln_id)
        vuln = self.vulnerabilities[vuln_id]
        now = time.time()
        vuln["assignee"] = assignee
        vuln["assigned_at"] = now
        vuln["assigned_by"] = assignee
        vuln["updated_at"] = now
        self._append_history(vuln_id, now, assignee, vuln["status"],
                             vuln["status"], "分配负责人: %s. %s" % (assignee, note))
        self._save()
        return vuln

    def transition(self, vuln_id: str, to_status: str,
                  changed_by: str = "system", note: str = "") -> Dict[str, Any]:
        """状态流转：校验规则后更新状态并记录历史。"""
        if vuln_id not in self.vulnerabilities:
            raise KeyError("漏洞不存在: %s" % vuln_id)
        if to_status not in self.ALL_STATUSES:
            raise ValueError("非法目标状态: %s" % to_status)
        vuln = self.vulnerabilities[vuln_id]
        from_status = vuln["status"]
        if not self.can_transition(from_status, to_status):
            raise ValueError(
                "不允许的状态流转: %s -> %s" % (from_status, to_status))
        now = time.time()
        vuln["status"] = to_status
        vuln["updated_at"] = now
        if to_status == self.STATUS_FIXED:
            vuln["fixed_at"] = now
        if to_status == self.STATUS_CLOSED:
            vuln["closed_at"] = now
        self._append_history(vuln_id, now, changed_by, from_status, to_status, note)
        self._save()
        return vuln

    def verify(self, vuln_id: str, verification_result: bool,
               verified_by: str = "system") -> Dict[str, Any]:
        """漏洞验证：通过则 closed，不通过则 reopened。"""
        if vuln_id not in self.vulnerabilities:
            raise KeyError("漏洞不存在: %s" % vuln_id)
        vuln = self.vulnerabilities[vuln_id]
        from_status = vuln["status"]
        # 验证应在 verifying 或 fixed 状态进行
        if from_status not in (self.STATUS_VERIFYING, self.STATUS_FIXED):
            # 自动流转到 verifying
            if self.can_transition(from_status, self.STATUS_VERIFYING):
                self.transition(vuln_id, self.STATUS_VERIFYING, verified_by, "发起验证")
                from_status = self.STATUS_VERIFYING
        now = time.time()
        if verification_result:
            # 验证通过 -> closed
            self.transition(vuln_id, self.STATUS_CLOSED, verified_by, "验证通过")
            vuln = self.vulnerabilities[vuln_id]
            vuln["verification"] = {"result": "pass", "verified_by": verified_by, "time": now}
        else:
            # 验证不通过 -> reopened
            self.transition(vuln_id, self.STATUS_REOPENED, verified_by, "验证不通过")
            vuln = self.vulnerabilities[vuln_id]
            vuln["verification"] = {"result": "fail", "verified_by": verified_by, "time": now}
        self._save()
        return vuln

    def check_overdue(self) -> List[Dict[str, Any]]:
        """返回所有超过 SLA 截止日期且未关闭的漏洞。"""
        now = time.time()
        overdue = []
        for vuln in self.vulnerabilities.values():
            if vuln["status"] == self.STATUS_CLOSED:
                continue
            due = vuln.get("due_date")
            if due and now > due:
                item = dict(vuln)
                item["overdue_days"] = round((now - due) / 86400, 1)
                overdue.append(item)
        # 按逾期天数倒序
        overdue.sort(key=lambda x: x.get("overdue_days", 0), reverse=True)
        return overdue

    def get_history(self, vuln_id: str) -> List[Dict[str, Any]]:
        """返回某漏洞的全部状态变更历史。"""
        if vuln_id not in self.history:
            return []
        return self.history.get(vuln_id, [])

    def list_vulnerabilities(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出漏洞，可按状态过滤。"""
        items = list(self.vulnerabilities.values())
        if status:
            items = [v for v in items if v["status"] == status]
        return items

    def get_stats(self) -> Dict[str, Any]:
        """统计：按状态 / 按负责人 / 逾期数 / 平均修复时长。"""
        by_status: Dict[str, int] = {}
        by_assignee: Dict[str, int] = {}
        fix_durations: List[float] = []
        for vuln in self.vulnerabilities.values():
            by_status[vuln["status"]] = by_status.get(vuln["status"], 0) + 1
            assignee = vuln.get("assignee") or "未分配"
            by_assignee[assignee] = by_assignee.get(assignee, 0) + 1
            if vuln.get("fixed_at") and vuln.get("discovered_at"):
                fix_durations.append(vuln["fixed_at"] - vuln["discovered_at"])
        overdue = self.check_overdue()
        avg_fix_hours = (
            round(sum(fix_durations) / len(fix_durations) / 3600, 1)
            if fix_durations else 0.0
        )
        return {
            "total": len(self.vulnerabilities),
            "by_status": by_status,
            "by_assignee": by_assignee,
            "overdue_count": len(overdue),
            "avg_fix_time_hours": avg_fix_hours,
        }

    # ------------------------------------------------------------------ #
    def _append_history(self, vuln_id: str, ts: float, operator: str,
                        from_status: Optional[str], to_status: str, note: str) -> None:
        """追加一条历史记录。"""
        self.history.setdefault(vuln_id, []).append({
            "time": ts,
            "time_str": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
            "operator": operator,
            "from_status": from_status,
            "to_status": to_status,
            "note": note,
        })


# 全局单例
_lifecycle: Optional[VulnerabilityLifecycle] = None


def get_lifecycle() -> VulnerabilityLifecycle:
    """获取全局漏洞生命周期管理器单例。"""
    global _lifecycle
    if _lifecycle is None:
        _lifecycle = VulnerabilityLifecycle()
    return _lifecycle
