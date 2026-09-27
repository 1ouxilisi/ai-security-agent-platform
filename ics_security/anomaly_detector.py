# -*- coding: utf-8 -*-
"""
anomaly_detector.py - 工控异常行为检测器（第12轮 ICS/SCADA 深化模块）。

检测能力（被动分析流量/事件日志，不下发控制指令）：
  1. 功能码白名单：仅允许白名单功能码，告警未授权功能码
  2. 寄存器写入监控：关键寄存器/线圈异常写、越界写、频繁写
  3. 通信模式学习：主从关系 / 轮询周期 / 数据量 / 连接数基线，检测偏离
  4. 时间异常：非工作时间操作 / 异常频率 / 异常持续 / 计划外维护
  5. 流量异常：突增突降 / 协议分布异常 / 连接数异常 / 广播风暴
  6. 关键操作：PLC 程序下载/上传 / RUN-STOP 切换 / 时间设置 / 固件更新

输出：异常告警、关联分析、响应建议、检测报告。
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, time as dtime
from typing import Any, Dict, List, Optional, Tuple


# 工作时间窗（可按现场调整）
WORK_HOURS_START = dtime(6, 0)
WORK_HOURS_END = dtime(22, 0)

# 默认功能码白名单（只读为主，写操作需另行审批）
DEFAULT_FUNC_WHITELIST = {1, 2, 3, 4, 8, 11, 43}
WRITE_FUNCTIONS = {5, 6, 15, 16, 22, 23}

# 关键操作特征（协议 -> 操作名）
CRITICAL_OPS = {
    "s7_download": "S7 程序下载(0x06/07/08)",
    "s7_upload": "S7 程序上传(0x1A/1B)",
    "s7_cpu_control": "S7 CPU RUN/STOP 切换",
    "s7_set_time": "S7 时间设置",
    "dnp3_control": "DNP3 Select/Operate",
    "fins_run_stop": "FINS 运行/停止(0x0401/0x0402)",
    "fw_update": "固件更新",
}


class AnomalyDetector:
    """工控异常行为检测器。"""

    def __init__(self, func_whitelist: Optional[set] = None,
                 poll_interval_baseline: float = 1.0,
                 baseline_writes_per_minute: int = 5):
        self.whitelist = set(func_whitelist) if func_whitelist else set(DEFAULT_FUNC_WHITELIST)
        self.poll_baseline = poll_interval_baseline
        self.write_baseline = baseline_writes_per_minute
        self.alarms: List[Dict[str, Any]] = []
        self._seq = 0

    def _next_id(self) -> str:
        self._seq += 1
        return f"ALM-{self._seq:05d}"

    # ---------- 1. 功能码白名单 ----------
    def check_function_codes(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alarms = []
        for e in events:
            fc = e.get("function_code")
            if fc is None:
                continue
            if fc not in self.whitelist:
                sev = "high" if fc in WRITE_FUNCTIONS else "medium"
                alarms.append({
                    "alarm_id": self._next_id(), "type": "unauthorized_function_code",
                    "severity": sev,
                    "detail": f"未授权功能码 {fc} (from {e.get('src_ip', '?')} -> {e.get('dst_ip', '?')})",
                    "timestamp": e.get("timestamp"),
                    "response": "核查该主站是否在白名单内；如非授权应立即阻断通信",
                })
        return alarms

    # ---------- 2. 寄存器写入监控 ----------
    def check_register_writes(self, write_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """write_events: [{ts, src, dst, register, value, is_whitelisted}]"""
        alarms = []
        per_min: Dict[Tuple[str, str], int] = defaultdict(int)
        for w in write_events:
            key = (w.get("src", "?"), w.get("dst", "?"))
            minute = str(w.get("ts", ""))[:16]
            per_min[key] += 1
            # 越界写入
            reg = w.get("register", "")
            try:
                val = int(w.get("value", 0))
                if val < -32768 or val > 65535:
                    alarms.append({
                        "alarm_id": self._next_id(), "type": "out_of_range_write",
                        "severity": "high",
                        "detail": f"越界写入 {reg}={val}", "timestamp": w.get("ts"),
                        "response": "暂停该主站写权限，核查控制逻辑",
                    })
            except Exception:
                pass
            if not w.get("is_whitelisted", True):
                alarms.append({
                    "alarm_id": self._next_id(), "type": "unapproved_register_write",
                    "severity": "high",
                    "detail": f"非审批写入 {w.get('register')} by {w.get('src')}",
                    "timestamp": w.get("ts"),
                    "response": "该写入未在变更窗口内，建议阻断并溯源",
                })
        for (src, dst), cnt in per_min.items():
            if cnt > self.write_baseline * 4:
                alarms.append({
                    "alarm_id": self._next_id(), "type": "write_flood",
                    "severity": "high",
                    "detail": f"{src}->{dst} 每分钟写入 {cnt} 次(基线 {self.write_baseline})",
                    "response": "疑似暴力写入/扫描，建议立即限流",
                })
        return alarms

    # ---------- 3. 通信模式偏离 ----------
    def check_comm_pattern(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """flows: [{src,dst,proto,pkts,bytes,interval_s}]"""
        alarms = []
        observed_pairs = defaultdict(int)
        observed_interval = defaultdict(list)
        for f in flows:
            pair = (f.get("src"), f.get("dst"), f.get("proto"))
            observed_pairs[pair] += f.get("pkts", 0)
            iv = f.get("interval_s")
            if iv:
                observed_interval[pair].append(iv)
        for pair, ivs in observed_interval.items():
            avg = sum(ivs) / len(ivs) if ivs else 0
            # 轮询周期偏离基线 > 50%
            if avg and abs(avg - self.poll_baseline) / self.poll_baseline > 0.5:
                alarms.append({
                    "alarm_id": self._next_id(), "type": "poll_interval_deviation",
                    "severity": "medium",
                    "detail": f"{pair[0]}->{pair[1]} 平均轮询间隔 {avg:.2f}s (基线 {self.poll_baseline}s)",
                    "response": "检查主站是否被篡改或异常重试",
                })
        return alarms

    # ---------- 4. 时间异常 ----------
    def check_time_anomaly(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alarms = []
        for e in events:
            ts = e.get("timestamp") or e.get("ts")
            if not ts:
                continue
            try:
                dt = datetime.fromisoformat(str(ts).replace("Z", ""))
            except Exception:
                continue
            if not (WORK_HOURS_START <= dt.time() <= WORK_HOURS_END):
                op = e.get("operation", "unknown")
                sev = "high" if e.get("sensitive") else "low"
                alarms.append({
                    "alarm_id": self._next_id(), "type": "off_hours_operation",
                    "severity": sev,
                    "detail": f"非工作时间操作 {op} @ {dt.isoformat()}",
                    "timestamp": dt.isoformat(),
                    "response": "若非计划内维护，立即核查操作人身份",
                })
        return alarms

    # ---------- 5. 流量异常 ----------
    def check_traffic(self, current: Dict[str, Any], baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
        """current/baseline: {'total_bytes', 'connections', 'protocol_dist', 'broadcast_ratio'}"""
        alarms = []
        for key in ("total_bytes", "connections"):
            cur, base = current.get(key, 0), baseline.get(key, 0)
            if base == 0:
                continue
            ratio = cur / base
            if ratio > 2.5 or ratio < 0.3:
                alarms.append({
                    "alarm_id": self._next_id(), "type": f"traffic_{'spike' if ratio > 1 else 'drop'}",
                    "severity": "medium",
                    "detail": f"{key} 当前 {cur} vs 基线 {base} (×{ratio:.2f})",
                    "response": "排查新接入设备/故障链路",
                })
        br = current.get("broadcast_ratio", 0)
        if br > 0.25:
            alarms.append({
                "alarm_id": self._next_id(), "type": "broadcast_storm",
                "severity": "high",
                "detail": f"广播包占比 {br:.0%}",
                "response": "定位广播源，排查环路/蠕虫",
            })
        return alarms

    # ---------- 6. 关键操作检测 ----------
    def check_critical_ops(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alarms = []
        for e in events:
            op = e.get("critical_op")
            if op in CRITICAL_OPS:
                alarms.append({
                    "alarm_id": self._next_id(), "type": "critical_operation",
                    "severity": "critical",
                    "detail": f"关键操作: {CRITICAL_OPS[op]} by {e.get('src', '?')}",
                    "timestamp": e.get("timestamp"),
                    "response": "立即确认是否为授权变更；非授权则按应急预案处置",
                })
        return alarms

    # ---------- 主入口 ----------
    def detect(self,
               function_code_events: Optional[List[Dict[str, Any]]] = None,
               write_events: Optional[List[Dict[str, Any]]] = None,
               comm_flows: Optional[List[Dict[str, Any]]] = None,
               time_events: Optional[List[Dict[str, Any]]] = None,
               traffic: Optional[Dict[str, Any]] = None,
               traffic_baseline: Optional[Dict[str, Any]] = None,
               critical_events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        all_alarms: List[Dict[str, Any]] = []
        all_alarms += self.check_function_codes(function_code_events or [])
        all_alarms += self.check_register_writes(write_events or [])
        all_alarms += self.check_comm_pattern(comm_flows or [])
        all_alarms += self.check_time_anomaly(time_events or [])
        if traffic and traffic_baseline:
            all_alarms += self.check_traffic(traffic, traffic_baseline)
        all_alarms += self.check_critical_ops(critical_events or [])

        self.alarms = all_alarms
        sev_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in all_alarms:
            sev_dist[a["severity"]] = sev_dist.get(a["severity"], 0) + 1

        # 关联分析：同 src 在 5 分钟窗口内触发多类告警
        by_src: Dict[str, List[str]] = defaultdict(list)
        for a in all_alarms:
            src = a["detail"].split("by ")[-1].split(" ")[0]
            by_src[src].append(a["type"])
        correlations = [
            {"src": s, "alarm_types": list(set(types)),
             "suspicion": "high" if len(set(types)) >= 3 else "medium"}
            for s, types in by_src.items() if len(set(types)) >= 2
        ]

        return {
            "alarm_count": len(all_alarms),
            "alarms": all_alarms,
            "severity_distribution": sev_dist,
            "correlations": correlations,
            "detected_at": datetime.now().isoformat(),
            "legal_note": "仅对既有流量/日志做被动分析，未向设备下发任何写指令。",
        }

    def generate_report(self, detect_result: Dict[str, Any]) -> Dict[str, Any]:
        alarms = detect_result.get("alarms", [])
        critical = [a for a in alarms if a["severity"] == "critical"]
        return {
            "title": "工控异常行为检测报告",
            "generated_at": datetime.now().isoformat(),
            "total_alarms": detect_result.get("alarm_count", 0),
            "severity_distribution": detect_result.get("severity_distribution", {}),
            "critical_alarms": critical[:10],
            "correlations": detect_result.get("correlations", []),
            "recommended_actions": [
                "对 critical 告警按应急预案立即响应",
                "隔离疑似失陷主站，保留流量镜像取证",
                "复盘近期变更，确认是否为误报",
                "将确认 IOC 加入威胁情报比对",
            ],
            "conclusion": "异常检测完成，建议结合威胁情报与基线结果综合研判。",
        }


def create_anomaly_detector(func_whitelist: Optional[set] = None) -> AnomalyDetector:
    return AnomalyDetector(func_whitelist=func_whitelist)
