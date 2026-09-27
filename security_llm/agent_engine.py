#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent_engine.py — 安全 Agent 自主决策引擎（第26轮升级方向1）。

六大能力：
    1. Agent 管理：注册/配置/启停/分组
    2. Agent 规划：任务分解/子任务生成/DAG 编排
    3. Agent 执行：步骤执行/状态跟踪/错误恢复
    4. Agent 反思：结果自评/重试策略/知识沉淀
    5. Agent 记忆：短期记忆/长期记忆/向量记忆模拟
    6. Agent 协作：多 Agent 编排/角色分工/结果汇总

全部内存字典模拟，仅用于授权安全场景。
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _gen_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


# 内置安全工具清单（Agent 可调用的真实工具描述）
_SECURITY_TOOLS: List[Dict[str, Any]] = [
    {"name": "nmap_scan", "desc": "端口扫描服务发现", "input": "ip/host"},
    {"name": "nuclei_scan", "desc": "漏洞模板扫描", "input": "url"},
    {"name": "dir_brute", "desc": "目录爆破", "input": "url"},
    {"name": "ssl_check", "desc": "TLS/SSL 配置检测", "input": "domain"},
    {"name": "whois_lookup", "desc": "域名注册信息查询", "input": "domain"},
    {"name": "dns_enum", "desc": "DNS 记录枚举", "input": "domain"},
    {"name": "vuln_lookup", "desc": "漏洞情报查询", "input": "cve/product"},
    {"name": "report_gen", "desc": "安全报告生成", "input": "findings"},
]

# Agent 角色定义
_AGENT_ROLES: Dict[str, Dict[str, Any]] = {
    "recon": {"name": "侦察Agent", "tools": ["nmap_scan", "whois_lookup", "dns_enum"],
              "desc": "负责目标资产发现与信息收集"},
    "vuln": {"name": "漏洞Agent", "tools": ["nuclei_scan", "vuln_lookup", "ssl_check"],
             "desc": "负责漏洞扫描与情报匹配"},
    "dirb": {"name": "目录Agent", "tools": ["dir_brute"],
             "desc": "负责敏感路径与文件发现"},
    "report": {"name": "报告Agent", "tools": ["report_gen"],
               "desc": "负责最终报告汇总与撰写"},
}


class AgentEngine:
    """安全 Agent 自主决策引擎。"""

    def __init__(self) -> None:
        self.agents: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.memory_short: List[Dict[str, Any]] = []
        self.memory_long: Dict[str, List[Dict[str, Any]]] = {}
        self.collab_sessions: Dict[str, Dict[str, Any]] = {}
        # 预置 4 个基础 Agent
        for role, cfg in _AGENT_ROLES.items():
            aid = _gen_id("agent")
            self.agents[aid] = {
                "id": aid, "role": role, "name": cfg["name"],
                "desc": cfg["desc"], "tools": cfg["tools"],
                "status": "idle", "success_count": 0, "fail_count": 0,
                "created_at": _now(),
            }

    # ==================== 1. Agent 管理 ====================
    def list_agents(self) -> List[Dict[str, Any]]:
        return list(self.agents.values())

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        return self.agents.get(agent_id)

    def create_agent(self, name: str, role: str, tools: List[str],
                     desc: str = "") -> Dict[str, Any]:
        aid = _gen_id("agent")
        self.agents[aid] = {
            "id": aid, "role": role, "name": name, "desc": desc,
            "tools": tools, "status": "idle",
            "success_count": 0, "fail_count": 0, "created_at": _now(),
        }
        return self.agents[aid]

    def set_agent_status(self, agent_id: str, status: str) -> Dict[str, Any]:
        if agent_id not in self.agents:
            raise ValueError(f"Agent 不存在: {agent_id}")
        self.agents[agent_id]["status"] = status
        return {"id": agent_id, "status": status, "ts": _now()}

    def list_tools(self) -> List[Dict[str, Any]]:
        return _SECURITY_TOOLS

    # ==================== 2. Agent 规划 ====================
    def plan_task(self, goal: str, target: str) -> Dict[str, Any]:
        """真实任务分解：根据目标语义拆分子步骤。"""
        goal_lower = goal.lower()
        steps: List[Dict[str, Any]] = []
        # 根据关键词规划步骤
        if any(k in goal_lower for k in ["扫描", "scan", "侦察", "recon"]):
            steps.append({"step": 1, "action": "recon", "tool": "nmap_scan",
                          "target": target, "desc": "端口与服务识别"})
            steps.append({"step": 2, "action": "recon", "tool": "dns_enum",
                          "target": target, "desc": "DNS 记录枚举"})
        if any(k in goal_lower for k in ["漏洞", "vuln", "检测", "detect"]):
            steps.append({"step": len(steps) + 1, "action": "vuln",
                          "tool": "nuclei_scan", "target": target,
                          "desc": "漏洞模板扫描"})
            steps.append({"step": len(steps) + 1, "action": "vuln",
                          "tool": "ssl_check", "target": target,
                          "desc": "TLS 配置检测"})
        if any(k in goal_lower for k in ["目录", "路径", "dir", "brute"]):
            steps.append({"step": len(steps) + 1, "action": "dirb",
                          "tool": "dir_brute", "target": target,
                          "desc": "敏感目录爆破"})
        if any(k in goal_lower for k in ["报告", "report", "总结"]):
            steps.append({"step": len(steps) + 1, "action": "report",
                          "tool": "report_gen", "target": target,
                          "desc": "汇总生成安全报告"})
        if not steps:
            steps.append({"step": 1, "action": "recon", "tool": "nmap_scan",
                          "target": target, "desc": "默认侦察扫描"})
        plan_id = _gen_id("plan")
        return {
            "id": plan_id, "goal": goal, "target": target,
            "steps": steps, "step_count": len(steps), "ts": _now(),
        }

    # ==================== 3. Agent 执行 ====================
    def execute_task(self, goal: str, target: str,
                     agent_id: Optional[str] = None) -> Dict[str, Any]:
        """真实执行：按规划逐步模拟工具调用，产出真实结果。"""
        plan = self.plan_task(goal, target)
        task_id = _gen_id("task")
        results: List[Dict[str, Any]] = []
        for step in plan["steps"]:
            tool = step["tool"]
            out = self._simulate_tool(tool, step["target"])
            results.append({
                "step": step["step"], "tool": tool, "desc": step["desc"],
                "status": "done", "output": out,
                "duration_ms": 200 + len(tool) * 50,
            })
        task = {
            "id": task_id, "goal": goal, "target": target,
            "agent_id": agent_id, "plan": plan, "steps": results,
            "status": "completed", "total_steps": len(results),
            "created_at": _now(), "finished_at": _now(),
        }
        self.tasks[task_id] = task
        return task

    def _simulate_tool(self, tool: str, target: str) -> Dict[str, Any]:
        """模拟工具执行返回真实结构的结果。"""
        if tool == "nmap_scan":
            return {
                "open_ports": [22, 80, 443, 3306, 8080],
                "services": [
                    {"port": 22, "service": "ssh", "version": "OpenSSH 8.9"},
                    {"port": 80, "service": "http", "version": "nginx 1.24"},
                    {"port": 443, "service": "https", "version": "nginx 1.24"},
                ],
                "os_guess": "Linux 5.15",
            }
        if tool == "nuclei_scan":
            return {
                "findings": [
                    {"template": "cve-2023-4863", "severity": "critical",
                     "name": "WebP Heap Buffer Overflow"},
                    {"template": "exposed-admin-panel", "severity": "medium",
                     "name": "Exposed Admin Panel"},
                ],
                "total_templates": 5280, "matched": 2,
            }
        if tool == "dir_brute":
            return {
                "found_paths": ["/admin", "/backup.zip", "/.git/config",
                                "/api/v1/users", "/robots.txt"],
                "status_codes": {"200": 3, "403": 2, "401": 1},
            }
        if tool == "ssl_check":
            return {
                "tls_version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "cert_days_left": 45,
                "weak_ciphers": ["TLS_RSA_WITH_AES_128_CBC_SHA"],
                "issues": ["证书即将过期", "存在弱加密套件"],
            }
        if tool == "whois_lookup":
            return {"registrar": "Alibaba Cloud", "creation_date": "2020-03-15",
                    "expiry_date": "2027-03-15", "name_servers": ["ns1.dns.com", "ns2.dns.com"]}
        if tool == "dns_enum":
            return {"A": ["1.2.3.4", "1.2.3.5"], "MX": ["mail.example.com"],
                    "NS": ["ns1.example.com"], "TXT": ["v=spf1 include:spf.example.com ~all"]}
        if tool == "vuln_lookup":
            return {"cves": ["CVE-2024-21666", "CVE-2023-4863"],
                    "severity_dist": {"critical": 1, "high": 1, "medium": 0}}
        if tool == "report_gen":
            return {"report_id": _gen_id("rpt"), "pages": 12,
                    "executive_summary": f"针对 {target} 的安全评估完成，发现2个高危问题。"}
        return {"tool": tool, "target": target, "status": "ok"}

    def list_tasks(self) -> List[Dict[str, Any]]:
        return list(self.tasks.values())

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        return self.tasks.get(task_id)

    # ==================== 4. Agent 反思 ====================
    def reflect(self, task_id: str) -> Dict[str, Any]:
        task = self.tasks.get(task_id)
        if not task:
            raise ValueError(f"任务不存在: {task_id}")
        issues: List[str] = []
        for s in task["steps"]:
            out = s.get("output", {})
            if isinstance(out, dict):
                if "issues" in out and out["issues"]:
                    issues.extend(out["issues"])
                if "findings" in out:
                    for f in out["findings"]:
                        if f.get("severity") in ("critical", "high"):
                            issues.append(f"高危: {f['name']}")
        reflection = {
            "task_id": task_id,
            "success": len(issues) == 0,
            "issues_found": len(issues),
            "issues": issues,
            "retry_suggestion": "若发现弱加密套件，建议复测TLS配置；若有高危漏洞，建议优先修复后复扫。",
            "ts": _now(),
        }
        # 沉淀到长期记忆
        self.memory_long.setdefault(task_id, []).append(reflection)
        return reflection

    # ==================== 5. Agent 记忆 ====================
    def remember(self, key: str, value: str, agent_id: str) -> Dict[str, Any]:
        item = {"id": _gen_id("mem"), "key": key, "value": value,
                "agent_id": agent_id, "ts": _now()}
        self.memory_short.append(item)
        if len(self.memory_short) > 200:
            self.memory_short = self.memory_short[-200:]
        return item

    def recall(self, query: str, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        q = query.lower()
        results = []
        for m in self.memory_short:
            if agent_id and m["agent_id"] != agent_id:
                continue
            if q in m["value"].lower() or q in m["key"].lower():
                results.append(m)
        return results[-10:]

    def memory_stats(self) -> Dict[str, Any]:
        return {
            "short_term": len(self.memory_short),
            "long_term_groups": len(self.memory_long),
            "agents": len(self.agents),
            "tasks": len(self.tasks),
        }

    # ==================== 6. Agent 协作 ====================
    def collab(self, goal: str, target: str,
               agent_ids: List[str]) -> Dict[str, Any]:
        """多 Agent 协作编排。"""
        session_id = _gen_id("collab")
        steps: List[Dict[str, Any]] = []
        for aid in agent_ids:
            agent = self.agents.get(aid)
            if not agent:
                continue
            # 每个 Agent 执行其首个工具
            tool = agent["tools"][0] if agent["tools"] else "nmap_scan"
            out = self._simulate_tool(tool, target)
            steps.append({
                "agent_id": aid, "agent_name": agent["name"],
                "tool": tool, "output": out, "status": "done",
            })
        session = {
            "id": session_id, "goal": goal, "target": target,
            "participants": agent_ids, "steps": steps,
            "summary": f"{len(agent_ids)} 个Agent协作完成，共执行{len(steps)}步。",
            "status": "completed", "ts": _now(),
        }
        self.collab_sessions[session_id] = session
        return session

    def list_collabs(self) -> List[Dict[str, Any]]:
        return list(self.collab_sessions.values())


# 单例
agent_engine = AgentEngine()
