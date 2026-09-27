# -*- coding: utf-8 -*-
"""
ai_analysis.py — 工控IoT Pro AI 分析。

- 自动分析工控/IoT 安全风险
- 生成整改建议与优先级排序
- 攻击路径推理（杀链）
- 异常流量识别 / 设备风险评估 / 合规风险预警
- 思考过程可视化
离线启发式引擎，不依赖外部 LLM。
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional


class IotOtAIAnalysis:
    """工控IoT AI 风险分析引擎（启发式，离线可用）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    def analyze_device(self, device: Dict[str, Any],
                       vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        dtype = device.get("device_type", "UNKNOWN")
        ip = device.get("ip", "")
        n_crit = sum(1 for v in vulns if v.get("severity") == "critical")
        n_high = sum(1 for v in vulns if v.get("severity") == "high")
        score = 20 + n_crit * 25 + n_high * 12 + (
            10 if dtype in ("PLC", "DCS", "SCADA_SERVER") else 0)
        score = min(99, score)
        verdict = "高危" if score >= 75 else "中危" if score >= 45 else "低危"
        reasons: List[str] = []
        if n_crit:
            reasons.append(f"含 {n_crit} 个 critical 漏洞（如未授权 PLC 控制）")
        if dtype in ("PLC", "DCS"):
            reasons.append("核心控制设备，一旦被控制直接影响生产安全")
        if device.get("protocols") and "opc_ua" in device.get("protocols"):
            reasons.append("OPC UA 若未强制签名加密，存在中间人风险")
        advice = self._remediate(dtype, vulns)
        chain = self._attack_chain(dtype, vulns)
        thought = (f"正在评估设备 {ip}({dtype})：critical={n_crit}, "
                   f"high={n_high}。{';'.join(reasons) or '无明显风险特征'}"
                   f"。综合判定：{verdict}。")
        result = {
            "device": ip, "device_type": dtype,
            "risk_score": score, "verdict": verdict,
            "critical_count": n_crit, "high_count": n_high,
            "reasons": reasons, "remediation": advice,
            "attack_chain": chain, "thought": thought,
            "priority": "P0" if score >= 75 else
                       "P1" if score >= 45 else "P2",
        }
        with self._lock:
            self._history.append(result)
            self._history = self._history[-500:]
        return result

    # ------------------------------------------------------------------ #
    def _remediate(self, dtype: str,
                   vulns: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        has_s7 = any(v.get("category") in ("unauth_s7",)
                     for v in vulns)
        has_mqtt = any(v.get("category") == "mqtt_anon" for v in vulns)
        if has_s7:
            out.append({"priority": "P0", "action":
                        "对 S7 PLC 启用保护级别/修改连接密码，"
                        "限制 102 端口仅工程师站可达"})
        if has_mqtt:
            out.append({"priority": "P1", "action":
                        "MQTT Broker 禁用匿名访问，启用用户名密码+TLS，"
                        "收敛敏感 Topic 订阅权限"})
        if dtype in ("PLC", "DCS", "SCADA_SERVER"):
            out.append({"priority": "P0", "action":
                        "工控网与管理网/互联网严格分段，"
                        "部署工业防火墙白名单"})
        out.append({"priority": "P1", "action":
                    "升级固件至厂商最新版本，关闭默认口令与 Telnet"})
        out.append({"priority": "P2", "action":
                    "对未加密协议(Modbus/S7)引入加密或专用网关隧道"})
        out.sort(key=lambda x: x["priority"])
        return out

    # ------------------------------------------------------------------ #
    def _attack_chain(self, dtype: str,
                      vulns: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        chain = [
            {"stage": "侦察", "technique": "T1046 工控端口扫描",
             "evidence": "502/102/4840 暴露"},
            {"stage": "初始访问", "technique": "T1190 利用未授权访问",
             "evidence": "Modbus/S7 匿名读写"},
        ]
        if dtype in ("PLC", "DCS", "SCADA_SERVER"):
            chain += [
                {"stage": "执行", "technique": "工业控制指令注入",
                 "evidence": "写寄存器/写线圈/PLC Stop"},
                {"stage": "影响", "technique": "T08xx 生产过程破坏",
                 "evidence": "异常工艺参数/停机"},
            ]
        else:
            chain += [
                {"stage": "横向移动", "technique": "T1021 远程服务",
                 "evidence": "IoT 网关作为跳板"},
                {"stage": "数据收集", "technique": "T1005",
                 "evidence": "摄像头/传感器数据采集"},
            ]
        return chain

    # ------------------------------------------------------------------ #
    def analyze_traffic(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        likely_attack = [a for a in alerts if a.get("severity") in (
            "critical", "high")]
        fp = [a for a in alerts if a.get("category") == "unusual_conn"
              and "monitor" in a.get("detail", "")]
        return {
            "total": len(alerts),
            "likely_attack": len(likely_attack),
            "likely_false_positive": len(fp),
            "noise_ratio": round(len(fp) / max(1, len(alerts)), 2),
            "thought": f"流量告警 {len(alerts)} 条，疑似攻击 "
                       f"{len(likely_attack)} 条，疑似误报 {len(fp)} 条",
            "top_action": "优先研判 critical 级数据外泄/C2 通信告警",
        }

    # ------------------------------------------------------------------ #
    def compliance_risk_alert(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        by_std = summary.get("by_standard", {})
        warns: List[str] = []
        for std, s in by_std.items():
            if s.get("fail", 0) >= 2:
                warns.append(f"{std} 有 {s.get('fail',0)} 项未通过，"
                            f"存在合规缺口")
        return {
            "overall_score": summary.get("overall_score", 0),
            "warnings": warns,
            "thought": f"合规评分 {summary.get('overall_score', 0)}，"
                       f"{'存在合规风险' if warns else '基本可控'}",
        }

    # ------------------------------------------------------------------ #
    def batch_overview(self, devices: List[Dict[str, Any]],
                       vulns: List[Dict[str, Any]],
                       alerts: List[Dict[str, Any]],
                       compliance: Dict[str, Any]) -> Dict[str, Any]:
        dev_reports = [self.analyze_device(
            d, [v for v in vulns if d.get("ip", "") in v.get("target", "")])
            for d in devices[:8]]
        return {
            "devices": dev_reports,
            "traffic": self.analyze_traffic(alerts),
            "compliance": self.compliance_risk_alert(compliance),
            "thought": "AI 已完成设备/流量/合规三维关联分析，"
                       "P0 项优先处置",
        }

    def history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._history[-limit:])


_default: Optional[IotOtAIAnalysis] = None


def get_ai_analysis() -> IotOtAIAnalysis:
    global _default
    if _default is None:
        _default = IotOtAIAnalysis()
    return _default
