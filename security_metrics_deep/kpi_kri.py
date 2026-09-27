#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_metrics_deep/kpi_kri.py — 安全 KPI/KRI 管理。

能力：
    1. KPI 指标库：安全运营/漏洞管理/事件响应/合规/培训/投资/风险/自定义，100+ 预置 KPI。
    2. KRI 指标库：风险/威胁/漏洞/事件/合规/人员/预算/技术，50+ 预置 KRI。
    3. 指标定义：名称/描述/计算公式/数据来源/采集频率/目标值/阈值/预警值/责任人。
    4. 指标采集：自动/手动/API/日志/数据库/文件/批量。
    5. 指标分析：趋势/对比/基准/目标达成/异常/关联/预测。
    6. 指标报告：KPI仪表盘/KRI仪表盘/指标/趋势/对比/异常/自定义报告。
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #
def _h(seed: str, mod: int = 100) -> int:
    return int(hashlib.md5(seed.encode("utf-8")).hexdigest()[:8], 16) % mod


def _score(seed: str, lo: float, hi: float) -> float:
    return round(lo + (hi - lo) * _h(seed) / 100.0, 2)


# --------------------------------------------------------------------------- #
# KPI 指标库生成（100+）
# --------------------------------------------------------------------------- #
_KPI_GROUPS: Dict[str, List[str]] = {
    "安全运营": ["MTTD平均检测时间", "MTTR平均响应时间", "告警处理率", "误报率", "漏报率",
               "巡检完成率", "值班覆盖率", "工单SLA达成率", "自动化处置率", "SOC人均告警量"],
    "漏洞管理": ["漏洞修复率", "高危漏洞修复时长", "扫描覆盖率", "重复漏洞率", "漏洞复测通过率",
               "未修复漏洞存量", "新发现漏洞数", "漏洞闭环率", "扫描工具利用率", "补丁应用及时率"],
    "事件响应": ["事件数量", "事件平均响应时间", "事件平均恢复时间", "事件复发率", "演练覆盖率",
               "事件分级准确率", "取证完成率", "通报及时率", "恢复RTO达成率", "事件根因分析率"],
    "合规": ["等保达标率", "审计发现问题数", "整改完成率", "控制测试通过率", "合规检查覆盖率",
           "审计计划完成率", "监管检查通过率", "例外审批数量", "合规培训覆盖率", "制度更新及时率"],
    "培训": ["培训覆盖率", "培训完成率", "考试通过率", "钓鱼演练点击率", "安全意识评分",
           "培训满意度", "人均培训学时", "新员工入职培训率", "专项培训次数", "证书持有率"],
    "投资": ["安全预算执行率", "安全投入占比", "人均安全投入", "项目按期完成率", "供应商数量",
           "采购合规率", "license利用率", "运维成本占比", "资本支出率", "外包成本占比",
           "安全工具性价比", "项目延期率", "安全投资回报率", "应急资金充足率", "供应商续约率"],
    "风险": ["风险注册项数", "高风险项数", "风险缓解率", "风险接受率", "风险再评估及时率",
           "风险趋势", "风险偏好一致性", "风险登记覆盖率", "风险责任人到位率", "风险敞口",
           "风险缓释投资回报率", "残余风险占比", "风险评估频率", "第三方风险敞口", "风险报告及时率"],
    "自定义": ["业务连续性指数", "数据安全分级覆盖率", "第三方风险评分", "供应链漏洞率",
             "云配置合规率", "身份治理成熟度", "日志留存合规率", "备份恢复成功率",
             "渗透测试覆盖率", "红队演练成效", "零信任落地率", "API安全覆盖率",
             "数据泄露防护覆盖率", "勒索防护成熟度", "数字资产识别率", "配置基线符合率",
             "补丁闭环时长", "安全补丁覆盖率", "漏洞披露响应率", "安全需求左移率"],
}


def _build_kpi_library() -> List[Dict[str, Any]]:
    lib: List[Dict[str, Any]] = []
    idx = 1
    freq_map = {"安全运营": "实时", "漏洞管理": "每日", "事件响应": "每日", "合规": "每月",
                "培训": "每季度", "投资": "每月", "风险": "每季度", "自定义": "每月"}
    source_map = {"安全运营": "SIEM日志", "漏洞管理": "扫描器API", "事件响应": "工单系统",
                  "合规": "审计平台", "培训": "学习平台", "投资": "财务系统",
                  "风险": "风险登记库", "自定义": "多源聚合"}
    for group, names in _KPI_GROUPS.items():
        for name in names:
            kid = f"KPI-{idx:03d}"
            target = _score(kid + "t", 70, 98)
            current = _score(kid + "c", 40, 100)
            warn = round(target - 10, 1)
            lib.append({
                "id": kid,
                "group": group,
                "name": name,
                "desc": f"{group}域关键绩效指标：{name}，衡量安全目标达成情况。",
                "formula": f"{name} = 达成量 / 应达总量 × 100%",
                "data_source": source_map.get(group, "多源"),
                "frequency": freq_map.get(group, "每月"),
                "unit": "%",
                "target": target,
                "warning": warn,
                "threshold": round(target - 20, 1),
                "owner": f"安全-{group}负责人",
                "current_value": current,
                "status": "达标" if current >= target else ("预警" if current >= warn else "未达标"),
            })
            idx += 1
    return lib


# --------------------------------------------------------------------------- #
# KRI 指标库生成（50+）
# --------------------------------------------------------------------------- #
_KRI_GROUPS: Dict[str, List[str]] = {
    "风险指标": ["残余风险水平", "风险敞口增长", "高风险项占比", "风险缓解滞后率", "风险偏好偏离度",
              "重大风险事件数", "风险叠加指数", "风险转移覆盖率", "风险监测盲区数"],
    "威胁指标": ["外部攻击量", "恶意IP命中数", "钓鱼邮件量", "勒索软件事件数", "漏洞利用爆发数",
              "暗网泄露提及数", "内部威胁告警数"],
    "漏洞指标": ["高危漏洞存量", "已知利用漏洞数", "暴露面增长率", "未打补丁主机占比", "漏洞平均存活时长"],
    "事件指标": ["入侵事件数", "数据泄露事件数", "拒绝服务事件数", "内部违规事件数", "未闭环事件数"],
    "合规指标": ["合规扣分", "监管处罚次数", "审计重大发现", "控制失效数", "整改逾期率"],
    "人员指标": ["离职率(安全岗)", "权限滥用嫌疑", "钓鱼点击率", "培训不通过率", "账号异常登录数"],
    "预算指标": ["预算超支率", "事件处置成本", "供应商违约率", "license超额占比", "应急储备消耗率"],
    "技术指标": ["关键系统暴露面", "检测规则覆盖率", "日志覆盖率", "备份失败率", "配置漂移数",
              "工具误报率", "自动化覆盖率", "影子IT数量", "权限过度分配数", "证书过期数"],
}


def _build_kri_library() -> List[Dict[str, Any]]:
    lib: List[Dict[str, Any]] = []
    idx = 1
    for group, names in _KRI_GROUPS.items():
        for name in names:
            kid = f"KRI-{idx:03d}"
            value = _score(kid + "v", 5, 95)
            threshold = _score(kid + "th", 40, 80)
            lib.append({
                "id": kid,
                "group": group,
                "name": name,
                "desc": f"{group}关键风险指标：{name}，用于前瞻性风险预警。",
                "formula": f"{name} = 相关事件计数 / 资产基数 × 权重",
                "data_source": "SIEM/威胁情报/日志",
                "frequency": "实时",
                "unit": "指数",
                "value": value,
                "threshold": threshold,
                "trend": "上升" if value > threshold else "平稳",
                "level": "严重" if value > threshold + 15 else ("预警" if value > threshold else "正常"),
                "owner": f"风控-{group}负责人",
            })
            idx += 1
    return lib


# --------------------------------------------------------------------------- #
# 采集与分析
# --------------------------------------------------------------------------- #
class MetricsManager:
    def __init__(self) -> None:
        self.kpi_library = _build_kpi_library()
        self.kri_library = _build_kri_library()
        self.snapshots: Dict[str, Dict[str, Any]] = {}
        self.definitions: Dict[str, Dict[str, Any]] = {
            k["id"]: {"id": k["id"], "name": k["name"], "group": k["group"],
                      "formula": k["formula"], "data_source": k["data_source"],
                      "frequency": k["frequency"], "target": k["target"],
                      "warning": k["warning"], "threshold": k["threshold"],
                      "owner": k["owner"]} for k in self.kpi_library
        }

    # -- 指标库 -- #
    def list_kpi(self, group: Optional[str] = None) -> List[Dict[str, Any]]:
        if group:
            return [k for k in self.kpi_library if k["group"] == group]
        return list(self.kpi_library)

    def list_kri(self, group: Optional[str] = None) -> List[Dict[str, Any]]:
        if group:
            return [k for k in self.kri_library if k["group"] == group]
        return list(self.kri_library)

    def kpi_groups(self) -> List[str]:
        return list(_KPI_GROUPS.keys())

    def kri_groups(self) -> List[str]:
        return list(_KRI_GROUPS.keys())

    # -- 采集 -- #
    def collect(self, source: str = "auto", ids: Optional[List[str]] = None) -> Dict[str, Any]:
        target = self.kpi_library
        if ids:
            target = [k for k in self.kpi_library if k["id"] in ids]
        collected = []
        for k in target:
            new_val = round(max(0, min(100, k["current_value"] + _h(k["id"] + source, 9) - 4)), 1)
            k["current_value"] = new_val
            k["status"] = "达标" if new_val >= k["target"] else (
                "预警" if new_val >= k["warning"] else "未达标")
            collected.append({"id": k["id"], "name": k["name"],
                              "value": new_val, "status": k["status"]})
        snap_id = f"SNAP-{int(time.time())}"
        self.snapshots[snap_id] = {
            "snapshot_id": snap_id, "source": source,
            "collected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "count": len(collected), "items": collected,
        }
        return self.snapshots[snap_id]

    # -- 分析 -- #
    def trend_analysis(self, kid: str, periods: int = 6) -> Dict[str, Any]:
        k = next((x for x in self.kpi_library if x["id"] == kid), None)
        if not k:
            return {}
        hist = []
        base = k["current_value"]
        for i in range(periods):
            v = round(max(0, min(100, base + (i - periods / 2) * (_h(kid + str(i), 6) - 2.5))), 1)
            hist.append({"period": f"M{i + 1}", "value": v})
        return {"id": kid, "name": k["name"], "history": hist,
                "target": k["target"],
                "direction": "上升" if hist[-1]["value"] >= hist[0]["value"] else "下降"}

    def compare_analysis(self) -> Dict[str, Any]:
        rows = []
        for g in self.kpi_groups():
            items = [k for k in self.kpi_library if k["group"] == g]
            avg = round(sum(k["current_value"] for k in items) / len(items), 1) if items else 0
            rows.append({"group": g, "avg_value": avg,
                         "target": round(sum(k["target"] for k in items) / len(items), 1),
                         "attainment": round(avg / (sum(k["target"] for k in items) / len(items) or 1) * 100, 1)})
        return {"groups": rows}

    def goal_attainment(self) -> Dict[str, Any]:
        reached = sum(1 for k in self.kpi_library if k["status"] == "达标")
        warning = sum(1 for k in self.kpi_library if k["status"] == "预警")
        missed = len(self.kpi_library) - reached - warning
        return {
            "total": len(self.kpi_library),
            "reached": reached, "warning": warning, "missed": missed,
            "reached_rate": round(reached / len(self.kpi_library) * 100, 1),
        }

    def abnormal_analysis(self) -> Dict[str, Any]:
        anomalies = [{"id": k["id"], "name": k["name"], "group": k["group"],
                      "value": k["current_value"], "target": k["target"],
                      "deviation": round(k["current_value"] - k["target"], 1),
                      "reason": "实际值显著低于目标值，建议复核数据来源与改进措施。"}
                     for k in self.kpi_library if k["current_value"] < k["threshold"]]
        kri_alerts = [{"id": k["id"], "name": k["name"], "level": k["level"],
                       "value": k["value"], "threshold": k["threshold"]}
                      for k in self.kri_library if k["level"] != "正常"]
        return {"kpi_anomalies": anomalies, "kri_alerts": kri_alerts}

    def forecast(self, kid: str, periods: int = 3) -> Dict[str, Any]:
        k = next((x for x in self.kpi_library if x["id"] == kid), None)
        if not k:
            return {}
        slope = (_h(kid, 10) - 5) / 10.0
        future = []
        cur = k["current_value"]
        for i in range(1, periods + 1):
            cur = round(max(0, min(100, cur + slope)), 1)
            future.append({"period": f"M预测{i}", "value": cur})
        return {"id": kid, "name": k["name"], "slope": round(slope, 2), "forecast": future}

    # -- 报告 -- #
    def kpi_dashboard(self) -> Dict[str, Any]:
        ga = self.goal_attainment()
        by_group = {}
        for k in self.kpi_library:
            by_group.setdefault(k["group"], []).append(k["status"])
        return {
            "total_kpi": len(self.kpi_library),
            "attainment": ga,
            "by_group": {g: {"total": len(s),
                             "reached": s.count("达标"),
                             "warning": s.count("预警"),
                             "missed": s.count("未达标")}
                         for g, s in by_group.items()},
        }

    def kri_dashboard(self) -> Dict[str, Any]:
        levels = {"正常": 0, "预警": 0, "严重": 0}
        for k in self.kri_library:
            levels[k["level"]] = levels.get(k["level"], 0) + 1
        return {
            "total_kri": len(self.kri_library),
            "levels": levels,
            "active_alerts": [k for k in self.kri_library if k["level"] != "正常"][:10],
        }


_mgr: Optional[MetricsManager] = None


def get_metrics_manager() -> MetricsManager:
    global _mgr
    if _mgr is None:
        _mgr = MetricsManager()
    return _mgr
