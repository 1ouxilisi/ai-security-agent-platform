# -*- coding: utf-8 -*-
"""
attack_navigator.py — 方向4：MITRE ATT&CK Navigator 集成。

生成:
    - attack_coverage   红队攻击技术覆盖（按战术/技术）
    - detection_coverage 蓝队检测技术覆盖
    - gap_coverage      攻击 vs 检测 差距可视化
    - navigator_layer   导出 ATT&CK Navigator 兼容 JSON 层（可直接导入 navigator）
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# 红队八战术技术基线（真实映射到 ATT&CK）
RED_TECHNIQUES: Dict[str, List[Dict[str, str]]] = {
    "initial-access": [
        {"id": "T1566", "name": "钓鱼"}, {"id": "T1190", "name": "利用面向公众应用"},
    ],
    "execution": [
        {"id": "T1059", "name": "命令脚本解释器"},
        {"id": "T1055", "name": "进程注入"}, {"id": "T1105", "name": "入站工具传输"},
    ],
    "persistence": [
        {"id": "T1547", "name": "启动项"}, {"id": "T1053", "name": "计划任务"},
        {"id": "T1543", "name": "服务"}, {"id": "T1546", "name": "事件触发执行"},
    ],
    "privilege-escalation": [
        {"id": "T1068", "name": "利用提升权限"}, {"id": "T1134", "name": "令牌操纵"},
    ],
    "defense-evasion": [
        {"id": "T1562", "name": "禁用安全工具"}, {"id": "T1027", "name": "混淆文件信息"},
        {"id": "T1497", "name": "规避虚机/沙箱"},
    ],
    "credential-access": [
        {"id": "T1003", "name": "OS凭证转储"}, {"id": "T1555", "name": "凭证管理器"},
        {"id": "T1040", "name": "网络凭证捕获"},
    ],
    "lateral-movement": [
        {"id": "T1021", "name": "远程服务"}, {"id": "T1047", "name": "WMI"},
        {"id": "T1550", "name": "备用认证材料"},
    ],
    "exfiltration": [
        {"id": "T1041", "name": "C2外泄"}, {"id": "T1048", "name": "替代协议外泄"},
        {"id": "T1560", "name": "归档数据"},
    ],
}


class AttackNavigator:
    """ATT&CK Navigator 层生成与覆盖分析。"""

    def attack_coverage(self, red_steps: Optional[List[Dict[str, Any]]] = None
                        ) -> Dict[str, Any]:
        red_steps = red_steps or []
        seen = {s.get("tech", "") for s in red_steps}
        rows = []
        for tactic, techs in RED_TECHNIQUES.items():
            covered = [t for t in techs if t["id"] in seen]
            rows.append({"tactic": tactic, "total": len(techs),
                         "covered": len(covered),
                         "pct": round(len(covered) / max(len(techs), 1) * 100),
                         "techniques": techs})
        return {"view": "attack_coverage", "rows": rows,
                "viewpoint": "red_team"}

    def detection_coverage(self, detected_techs: Optional[List[str]] = None
                           ) -> Dict[str, Any]:
        detected = set(detected_techs or [])
        rows = []
        for tactic, techs in RED_TECHNIQUES.items():
            hit = [t for t in techs if t["id"] in detected]
            rows.append({"tactic": tactic, "total": len(techs),
                         "detected": len(hit),
                         "pct": round(len(hit) / max(len(techs), 1) * 100)})
        return {"view": "detection_coverage", "rows": rows,
                "viewpoint": "blue_team"}

    def gap_coverage(self, red_steps: List[Dict[str, Any]],
                    detected_techs: List[str]) -> Dict[str, Any]:
        detected = set(detected_techs)
        gaps = []
        for s in red_steps:
            tech = s.get("tech", "")
            if tech and tech not in detected:
                gaps.append({"tech": tech, "name": s.get("name", tech),
                             "severity": "high" if tech.startswith(
                                 ("T1003", "T1021", "T1068")) else "medium"})
        return {"view": "gap", "gaps": gaps, "gap_count": len(gaps)}

    def navigator_layer(self, red_steps: List[Dict[str, Any]],
                       detected_techs: List[str]) -> Dict[str, Any]:
        """生成 ATT&CK Navigator 兼容 layer JSON。"""
        detected = set(detected_techs)
        marks: List[Dict[str, Any]] = []
        for s in red_steps:
            tech = s.get("tech", "")
            if not tech:
                continue
            color = "#2ecc71" if tech in detected else "#e74c3c"
            marks.append({"techniqueID": tech, "color": color,
                          "comment": s.get("name", ""),
                          "enabled": True})
        return {"name": "Red-Blue Real Debrief",
                "versions": {"attack": "v14", "navigator": "4.9.1"},
                "domain": "enterprise-attack",
                "gradient": {"colors": ["#e74c3c", "#f1c40f", "#2ecc71"]},
                "techniqueCount": len(marks),
                "techniques": marks}


_default: Optional[AttackNavigator] = None


def get_attack_navigator() -> AttackNavigator:
    global _default
    if _default is None:
        _default = AttackNavigator()
    return _default
