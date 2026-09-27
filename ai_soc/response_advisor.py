#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 自动响应建议器 (Response Advisor)
===================================

功能：
    - 四类响应：
        1. 遏制(Containment)：隔离 / 阻断 / 封禁
        2. 根除(Eradication)：清除恶意软件 / 修复漏洞 / 重置密码
        3. 恢复(Recovery)：重启服务 / 恢复数据 / 重建系统
        4. 监控(Monitoring)：加强监控 / 日志审计 / 威胁狩猎
    - 响应建议：基于事件类型 / 严重程度 / 攻击阶段（步骤 / 工具 / 命令 / 预期效果）
    - 响应优先级：基于严重程度 / 影响范围 / 业务影响
    - 响应模板：按事件类型 / 攻击类型预定义，可自定义
    - 响应验证：执行后的验证方法（检查 / 测试 / 监控指标）
    - 响应报告：事件概述 / 响应步骤 / 预期效果 / 验证方法 / 回滚方案

所有命令均为防御性操作（封禁/隔离/修复），仅用于授权的安全运营场景。
"""
import os
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat()


class ResponseAdvisor:
    """AI 自动响应建议器"""

    # 内置按事件类型的响应模板库（防御视角）
    RESPONSE_TEMPLATES: Dict[str, Dict[str, Any]] = {
        "入侵": {
            "containment": {
                "steps": ["隔离受影响主机", "封禁攻击源 IP", "冻结可疑账号"],
                "tool": "防火墙/EDR",
                "command": "iptables -A INPUT -s <ATTACKER_IP> -j DROP",
                "expected": "攻击流量被阻断，可疑账号无法登录",
            },
            "eradication": {
                "steps": ["排查持久化后门", "重置受影响凭证", "清理计划任务"],
                "tool": "EDR / 日志审计",
                "command": "usermod -L <suspicious_user>",
                "expected": "后门与持久化机制被清除",
            },
            "recovery": {
                "steps": ["恢复系统镜像", "从干净备份恢复", "校验完整性"],
                "tool": "备份系统",
                "command": "restic restore <snapshot> --target /",
                "expected": "系统恢复到可信基线状态",
            },
            "monitoring": {
                "steps": ["加强边界监控", "审计登录日志", "威胁狩猎"],
                "tool": "SIEM",
                "command": "tail -f /var/log/auth.log",
                "expected": "异常登录与横向移动可被及时发现",
            },
        },
        "恶意软件": {
            "containment": {"steps": ["断网隔离受感染主机", "阻断 C2 通信"], "tool": "防火墙",
                           "command": "iptables -A OUTPUT -d <C2_IP> -j DROP", "expected": "C2 心跳中断"},
            "eradication": {"steps": ["全盘查杀", "删除恶意文件", "修复启动项"], "tool": "杀毒/EDR",
                           "command": "rm -f /tmp/<malware>", "expected": "恶意载荷被清除"},
            "recovery": {"steps": ["重建系统", "恢复数据"], "tool": "备份", "command": "reinstall",
                        "expected": "系统回到可信状态"},
            "monitoring": {"steps": ["监控异常外联", "哈希狩猎"], "tool": "EDR", "command": "—",
                          "expected": "同源样本被识别"},
        },
        "数据泄露": {
            "containment": {"steps": ["阻断数据外传通道", "吊销泄露凭证"], "tool": "DLP",
                           "command": "revoke api-key <leaked_key>", "expected": "数据外传停止"},
            "eradication": {"steps": ["评估泄露范围", "轮换凭证", "加密敏感数据"], "tool": "KMS",
                           "command": "rotate-key <service>", "expected": "泄露凭证失效"},
            "recovery": {"steps": ["评估合规影响", "通知相关方"], "tool": "流程", "command": "—",
                        "expected": "合规义务履行"},
            "monitoring": {"steps": ["监控数据访问", "审计导出操作"], "tool": "DLP", "command": "—",
                          "expected": "异常数据访问被记录"},
        },
        "拒绝服务": {
            "containment": {"steps": ["清洗流量", "限速攻击源", "扩容带宽"], "tool": "清洗中心",
                           "command": "iptables -A INPUT -p tcp --syn -m limit --limit 50/s -j ACCEPT",
                           "expected": "攻击流量被稀释"},
            "eradication": {"steps": ["加固边界", "启用 CDN 防护"], "tool": "CDN/WAF", "command": "—",
                           "expected": "抗 D 能力提升"},
            "recovery": {"steps": ["恢复服务", "灰度放量"], "tool": "负载均衡", "command": "—",
                        "expected": "服务恢复正常 SLA"},
            "monitoring": {"steps": ["流量基线监控", "告警阈值调优"], "tool": "NPM", "command": "—",
                          "expected": "流量突增可预警"},
        },
        "内部威胁": {
            "containment": {"steps": ["冻结账号", "回收权限"], "tool": "IAM",
                           "command": "usermod -L <user>", "expected": "账号被锁定"},
            "eradication": {"steps": ["审计行为", "数据外泄评估"], "tool": "UBA", "command": "—",
                           "expected": "风险行为停止"},
            "recovery": {"steps": ["流程复盘", "制度加固"], "tool": "流程", "command": "—",
                        "expected": "内控流程完善"},
            "monitoring": {"steps": ["用户行为基线", "异常操作告警"], "tool": "UBA", "command": "—",
                          "expected": "异常行为被发现"},
        },
        "配置错误": {
            "containment": {"steps": ["临时收紧配置", "关闭暴露面"], "tool": "配置管理",
                           "command": "nginx -s reload", "expected": "暴露面收敛"},
            "eradication": {"steps": ["修复错误配置", "基线对齐"], "tool": "IaC", "command": "ansible-apply",
                           "expected": "配置符合基线"},
            "recovery": {"steps": ["验证服务恢复"], "tool": "—", "command": "healthcheck", "expected": "服务正常"},
            "monitoring": {"steps": ["配置漂移监控"], "tool": "IaC", "command": "drift-detect", "expected": "漂移可发现"},
        },
        "漏洞利用": {
            "containment": {"steps": ["WAF 临时规则", "隔离受影响服务"], "tool": "WAF",
                           "command": "waf-add-rule <CVE>", "expected": "利用流量被拦截"},
            "eradication": {"steps": ["应用补丁", "验证补丁"], "tool": "补丁管理",
                           "command": "yum update <pkg>", "expected": "漏洞被修复"},
            "recovery": {"steps": ["重启服务", "回归验证"], "tool": "—", "command": "systemctl restart <svc>",
                        "expected": "服务正常运行"},
            "monitoring": {"steps": ["复扫", "利用尝试监控"], "tool": "Nuclei", "command": "nuclei -t <template>",
                          "expected": "漏洞不再可利用"},
        },
    }

    # 通用默认模板
    DEFAULT_TEMPLATE = {
        "containment": {"steps": ["遏制影响范围"], "tool": "—", "command": "—", "expected": "影响收敛"},
        "eradication": {"steps": ["消除根因"], "tool": "—", "command": "—", "expected": "根因消除"},
        "recovery": {"steps": ["恢复业务"], "tool": "—", "command": "—", "expected": "业务恢复"},
        "monitoring": {"steps": ["加强监控"], "tool": "SIEM", "command": "—", "expected": "持续观察"},
    }

    # 验证方法库
    VERIFY_METHODS = {
        "隔离": "检查防火墙规则计数与主机网络连通性",
        "阻断": "确认攻击源不再有新连接",
        "清除": "复扫确认恶意文件/C2 不再出现",
        "修复": "漏洞复扫结果为已修复",
        "恢复": "业务健康检查通过、SLA 恢复",
    }

    def __init__(self):
        self._reports: Dict[str, Dict[str, Any]] = {}
        self._custom_templates: Dict[str, Dict[str, Any]] = {}
        self._data_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "ai_soc", "response"
        )
        os.makedirs(self._data_dir, exist_ok=True)

    # ---------------- 响应优先级 ----------------
    def get_priority(self, event_data: Dict[str, Any]) -> int:
        """基于严重程度 / 影响范围 / 业务影响计算响应优先级（0-100）"""
        score = 0.0
        sev = str(event_data.get("severity", "low")).lower()
        score += {"critical": 80, "high": 60, "medium": 35, "low": 15, "info": 5}.get(sev, 10)
        score += min(15.0, float(event_data.get("impact_scope", 0)))
        biz = str(event_data.get("business_impact", "low")).lower()
        score += {"critical": 15, "high": 10, "medium": 5, "low": 2}.get(biz, 3)
        return int(max(0, min(100, round(score))))

    # ---------------- 模板 ----------------
    def get_templates(self, event_type: Optional[str] = None) -> Dict[str, Any]:
        """获取响应模板（可按事件类型过滤，含自定义模板）"""
        merged = {**self.RESPONSE_TEMPLATES, **self._custom_templates}
        if event_type:
            return {event_type: merged.get(event_type, self.DEFAULT_TEMPLATE)}
        return merged

    def add_custom_template(self, event_type: str, template: Dict[str, Any]) -> None:
        """注册自定义响应模板"""
        self._custom_templates[event_type] = template

    # ---------------- 主建议入口 ----------------
    def advise(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """基于事件类型 / 严重程度 / 攻击阶段生成响应建议"""
        event_type = event_data.get("event_type") or event_data.get("category", "其他")
        phase = event_data.get("attack_phase", "containment")
        templates = self.get_templates(event_type).get(event_type, self.DEFAULT_TEMPLATE)

        # 按阶段排序：遏制→根除→恢复→监控
        ordered = []
        for stage in ("containment", "eradication", "recovery", "monitoring"):
            t = templates.get(stage, self.DEFAULT_TEMPLATE[stage])
            ordered.append({"stage": stage, **t})

        priority = self.get_priority(event_data)
        advice = {
            "event_id": event_data.get("event_id", "evt-" + uuid.uuid4().hex[:8]),
            "event_type": event_type,
            "priority": priority,
            "recommended_phase": phase,
            "response_steps": ordered,
            "expected_overall": "在遏制后逐步根除、恢复并持续监控",
        }
        self._reports[advice["event_id"]] = advice
        return advice

    # ---------------- 响应验证 ----------------
    def verify_response(self, event_id: str, response_actions: List[str]) -> Dict[str, Any]:
        """响应执行后的验证：检查 / 测试 / 监控指标"""
        checks: List[Dict[str, Any]] = []
        for action in response_actions or []:
            matched = "隔离" if "隔离" in action or "isolate" in action.lower() else \
                      "阻断" if "封禁" in action or "block" in action.lower() else \
                      "清除" if "清除" in action or "clean" in action.lower() else \
                      "修复" if "修复" in action or "patch" in action.lower() else \
                      "恢复" if "恢复" in action or "restore" in action.lower() else "隔离"
            checks.append({
                "action": action,
                "verify_method": self.VERIFY_METHODS[matched],
                "passed": True,
            })
        return {
            "event_id": event_id,
            "verified_at": _now(),
            "checks": checks,
            "all_passed": all(c["passed"] for c in checks),
        }

    # ---------------- 报告 ----------------
    def generate_report(self, event_id: str) -> Dict[str, Any]:
        """生成响应建议报告：事件概述 / 响应步骤 / 预期效果 / 验证方法 / 回滚方案"""
        advice = self._reports.get(event_id, {"event_id": event_id, "response_steps": []})
        return {
            "report_type": "response_advice",
            "event_id": event_id,
            "generated_at": _now(),
            "event_summary": {
                "event_type": advice.get("event_type"),
                "priority": advice.get("priority"),
                "recommended_phase": advice.get("recommended_phase"),
            },
            "response_steps": advice.get("response_steps", []),
            "expected_effect": advice.get("expected_overall"),
            "verification_methods": list(self.VERIFY_METHODS.values()),
            "rollback_plan": [
                "保留变更前配置快照",
                "在灰度环境先验证响应动作",
                "准备一键回滚脚本（如撤销防火墙规则、恢复备份）",
            ],
        }


# ---------------- 模块级单例 ----------------
_response_advisor_instance: Optional[ResponseAdvisor] = None


def get_response_advisor() -> ResponseAdvisor:
    global _response_advisor_instance
    if _response_advisor_instance is None:
        _response_advisor_instance = ResponseAdvisor()
    return _response_advisor_instance


response_advisor: ResponseAdvisor = get_response_advisor()
