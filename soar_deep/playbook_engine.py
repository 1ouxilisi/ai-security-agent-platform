#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar_deep/playbook_engine.py — 深度剧本编排引擎。

覆盖：
    1. 可视化剧本编辑器：拖拽节点/连线/条件分支/循环/并行/子流程/变量/函数
    2. 剧本节点库：触发器/动作/条件/循环/并行/等待/人工审核/通知/数据处理
    3. 变量管理：全局/局部/环境/密钥/动态/变量传递/变量转换
    4. 执行引擎：剧本实例/执行状态/进度/日志/异常/重试/超时/取消
    5. 版本管理：版本列表/对比/回滚/发布/审批/审计
    6. 测试调试：单步/断点/变量查看/日志查看/模拟输入/dry run/性能测试

全部内存字典模拟，不实际下发动作。
"""

from __future__ import annotations

import copy
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 节点类型库（深度版：9 大类节点）
# --------------------------------------------------------------------------- #
NODE_TYPE_REGISTRY: Dict[str, Dict[str, Any]] = {
    "trigger":       {"name": "触发器节点", "color": "#52c41a", "category": "entry",
                      "desc": "事件入口：告警/Webhook/定时/手动/API", "icon": "⚡"},
    "action":        {"name": "响应动作", "color": "#1890ff", "category": "action",
                      "desc": "调用响应动作库（网络/终端/账户/云/应用/通知）", "icon": "🔧"},
    "condition":     {"name": "条件分支", "color": "#fa8c16", "category": "logic",
                      "desc": "基于表达式走不同分支（if/else/switch）", "icon": "🔀"},
    "loop":          {"name": "循环节点", "color": "#13c2c2", "category": "logic",
                      "desc": "对集合/资产/列表循环执行子流程", "icon": "🔁"},
    "parallel":      {"name": "并行节点", "color": "#722ed1", "category": "logic",
                      "desc": "多分支同时执行，全部完成后汇合", "icon": "🔗"},
    "wait":          {"name": "等待节点", "color": "#8c8c8c", "category": "flow",
                      "desc": "延时 N 秒或等待外部事件", "icon": "⏳"},
    "approval":      {"name": "人工审核", "color": "#eb2f96", "category": "human",
                      "desc": "暂停等待人工审批（通过/驳回/超时）", "icon": "👤"},
    "notification":  {"name": "通知节点", "color": "#faad14", "category": "communication",
                      "desc": "邮件/短信/IM/工单通知", "icon": "📢"},
    "data_process":  {"name": "数据处理", "color": "#2f54eb", "category": "data",
                      "desc": "变量转换/JSON路径提取/正则/拼接/映射", "icon": "🔄"},
    "subflow":       {"name": "子流程", "color": "#a0d911", "category": "flow",
                      "desc": "调用另一个剧本作为子流程", "icon": "📦"},
    "end":           {"name": "结束节点", "color": "#ff4d4f", "category": "exit",
                      "desc": "剧本出口（成功/失败/取消）", "icon": "🏁"},
}

# 触发器类型
TRIGGER_TYPES: Dict[str, str] = {
    "alert":   "告警触发（接入告警自动启动）",
    "webhook": "Webhook 触发（外部 HTTP 回调）",
    "schedule": "定时触发（Cron 表达式）",
    "manual":  "手动触发（人工点击执行）",
    "api":     "API 触发（外部系统调用）",
    "event":   "事件触发（资产变更/用户行为）",
}

# 数据处理函数库
DATA_FUNCTIONS: Dict[str, Dict[str, str]] = {
    "json_path":   {"name": "JSON路径提取", "desc": "从JSON中按$path提取字段", "usage": "json_path(data, '$.alerts[0].src_ip')"},
    "regex_extract": {"name": "正则提取", "desc": "从文本中提取匹配组", "usage": "regex_extract(text, r'(\\d+\\.\\d+\\.\\d+\\.\\d+)')"},
    "concat":      {"name": "字符串拼接", "desc": "拼接多个变量", "usage": "concat(var1, ':', var2)"},
    "upper":       {"name": "转大写", "desc": "字符串转大写", "usage": "upper(str)"},
    "lower":       {"name": "转小写", "desc": "字符串转小写", "usage": "lower(str)"},
    "split":       {"name": "字符串分割", "desc": "按分隔符分割为数组", "usage": "split(str, ',')"},
    "join":        {"name": "数组拼接", "desc": "数组按分隔符拼接", "usage": "join(arr, ';')"},
    "length":      {"name": "长度计算", "desc": "字符串/数组长度", "usage": "length(arr)"},
    "default":     {"name": "默认值", "desc": "空值时使用默认值", "usage": "default(var, 'N/A')"},
    "type_cast":   {"name": "类型转换", "desc": "字符串转数字/布尔", "usage": "type_cast('123', 'int')"},
}


# --------------------------------------------------------------------------- #
# 变量管理
# --------------------------------------------------------------------------- #
class VariableManager:
    """剧本变量管理器：全局/局部/环境/密钥/动态变量。"""

    def __init__(self) -> None:
        self.globals: Dict[str, Any] = {
            "system_name": "AI Hacking Agent SOAR Deep",
            "env": "production",
            "auto_response_enabled": True,
            "default_timeout_sec": 300,
            "max_retry": 3,
        }
        self.envs: Dict[str, Dict[str, str]] = {
            "production": {"tier": "prod", "region": "cn-east-1"},
            "staging":    {"tier": "staging", "region": "cn-north-1"},
            "development": {"tier": "dev", "region": "local"},
        }
        self.secrets: Dict[str, str] = {
            "slack_webhook": "https://hooks.slack.com/services/xxx/yyy/zzz",
            "smtp_password": "********",
            "api_token": "sk-xxxxxxxx",
        }
        # 动态变量（运行时注入）
        self.dynamic: Dict[str, Any] = {}

    def get_global(self, key: str, default: Any = None) -> Any:
        return self.globals.get(key, default)

    def set_global(self, key: str, value: Any) -> None:
        self.globals[key] = value

    def get_env(self, name: str) -> Dict[str, str]:
        return self.envs.get(name, {})

    def list_secrets(self) -> List[Dict[str, str]]:
        return [{"key": k, "value_masked": v} for k, v in self.secrets.items()]

    def resolve(self, expr: str, local_vars: Optional[Dict[str, Any]] = None) -> Any:
        """解析 {{var}} 模板变量，支持 global. / env. / secret. / local. 前缀。"""
        local_vars = local_vars or {}
        if not isinstance(expr, str):
            return expr
        out = expr
        # 先替换 local
        for k, v in local_vars.items():
            out = out.replace("{{local." + k + "}}", str(v))
        for k, v in self.globals.items():
            out = out.replace("{{global." + k + "}}", str(v))
        for k, v in self.dynamic.items():
            out = out.replace("{{dynamic." + k + "}}", str(v))
        for k in self.secrets:
            out = out.replace("{{secret." + k + "}}", "***MASKED***")
        return out

    def transform(self, func: str, args: List[Any]) -> Any:
        """数据处理函数执行。"""
        try:
            if func == "json_path":
                data, path = args[0], args[1] if len(args) > 1 else ""
                # 模拟 JSONPath（简化）
                parts = path.replace("$.", "").split(".")
                cur: Any = data
                for p in parts:
                    if "[" in p:
                        key, idx = p.split("[")
                        idx = int(idx.rstrip("]"))
                        cur = cur.get(key, [])[idx] if isinstance(cur, dict) else None
                    else:
                        cur = cur.get(p) if isinstance(cur, dict) else None
                return cur
            if func == "regex_extract":
                import re
                text, pattern = str(args[0]), str(args[1])
                m = re.search(pattern, text)
                return m.group(1) if m else None
            if func == "concat":
                return "".join(str(a) for a in args)
            if func == "upper":
                return str(args[0]).upper()
            if func == "lower":
                return str(args[0]).lower()
            if func == "split":
                return str(args[0]).split(str(args[1]) if len(args) > 1 else ",")
            if func == "join":
                return str(args[1]) if len(args) > 1 else ",".join(str(x) for x in args[0])
            if func == "length":
                return len(args[0]) if hasattr(args[0], "__len__") else 0
            if func == "default":
                return args[0] if args[0] not in (None, "") else args[1]
            if func == "type_cast":
                val, typ = str(args[0]), str(args[1])
                if typ == "int":
                    return int(float(val))
                if typ == "float":
                    return float(val)
                if typ == "bool":
                    return val.lower() in ("true", "1", "yes")
                return val
        except Exception:
            return None
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "globals": self.globals,
            "envs": self.envs,
            "secrets_count": len(self.secrets),
            "dynamic_count": len(self.dynamic),
        }


# 全局变量管理器单例
_var_mgr = VariableManager()


def get_variable_manager() -> VariableManager:
    return _var_mgr


# --------------------------------------------------------------------------- #
# 剧本定义与版本
# --------------------------------------------------------------------------- #
class Playbook:
    """单个剧本定义，含版本历史。"""

    def __init__(self, pb_id: str, name: str, category: str = "general") -> None:
        self.id = pb_id
        self.name = name
        self.category = category
        self.status = "draft"  # draft / published / deprecated
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self.trigger: Dict[str, Any] = {"type": "manual", "config": {}}
        self.description = ""
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.updated_at = self.created_at
        self.version = 1
        self.versions: List[Dict[str, Any]] = []
        self.approvals: List[Dict[str, Any]] = []
        self.audit_logs: List[Dict[str, Any]] = []
        self.schedule: Optional[Dict[str, Any]] = None

    def add_node(self, ntype: str, node_id: Optional[str] = None,
                 config: Optional[Dict[str, Any]] = None,
                 position: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
        node_id = node_id or f"node_{uuid.uuid4().hex[:8]}"
        node = {
            "id": node_id, "type": ntype,
            "name": NODE_TYPE_REGISTRY.get(ntype, {}).get("name", ntype),
            "config": config or {},
            "position": position or {"x": 100.0, "y": 100.0},
        }
        self.nodes.append(node)
        self.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return node

    def add_edge(self, source: str, target: str,
                 condition: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        edge = {
            "id": f"edge_{uuid.uuid4().hex[:8]}",
            "source": source, "target": target,
            "condition": condition,  # None=无条件, {expr:"..."}=条件分支
        }
        self.edges.append(edge)
        return edge

    def remove_node(self, node_id: str) -> bool:
        before = len(self.nodes)
        self.nodes = [n for n in self.nodes if n["id"] != node_id]
        self.edges = [e for e in self.edges
                      if e["source"] != node_id and e["target"] != node_id]
        self.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return len(self.nodes) < before

    def save_version(self, note: str = "", author: str = "") -> Dict[str, Any]:
        """保存当前快照为新版本。"""
        snap = {
            "version": self.version,
            "note": note,
            "author": author,
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "nodes": copy.deepcopy(self.nodes),
            "edges": copy.deepcopy(self.edges),
            "trigger": copy.deepcopy(self.trigger),
        }
        self.versions.append(snap)
        self.version += 1
        self.updated_at = snap["saved_at"]
        return snap

    def rollback(self, version: int) -> bool:
        """回滚到指定版本。"""
        target = next((v for v in self.versions if v["version"] == version), None)
        if not target:
            return False
        # 回滚前先保存当前为新版本
        self.save_version(note=f"自动保存-回滚v{version}前", author="system")
        self.nodes = copy.deepcopy(target["nodes"])
        self.edges = copy.deepcopy(target["edges"])
        self.trigger = copy.deepcopy(target["trigger"])
        self.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return True

    def publish(self, note: str = "", approver: str = "") -> Dict[str, Any]:
        """发布剧本：保存版本 + 状态变更 + 审计。"""
        snap = self.save_version(note=note, author=approver or "publisher")
        self.status = "published"
        entry = {
            "action": "publish", "version": snap["version"],
            "operator": approver or "system",
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "note": note,
        }
        self.audit_logs.append(entry)
        return entry

    def request_approval(self, requester: str = "", reason: str = "") -> Dict[str, Any]:
        req = {
            "approval_id": uuid.uuid4().hex[:12],
            "requester": requester, "reason": reason,
            "status": "pending", "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.approvals.append(req)
        return req

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "status": self.status, "description": self.description,
            "nodes": self.nodes, "edges": self.edges, "trigger": self.trigger,
            "node_count": len(self.nodes), "edge_count": len(self.edges),
            "version": self.version, "created_at": self.created_at,
            "updated_at": self.updated_at, "schedule": self.schedule,
            "versions": [{"version": v["version"], "note": v["note"],
                          "author": v["author"], "saved_at": v["saved_at"]}
                         for v in self.versions],
            "approvals": self.approvals,
            "audit_logs": self.audit_logs,
        }


# --------------------------------------------------------------------------- #
# 执行引擎
# --------------------------------------------------------------------------- #
class ExecutionInstance:
    """剧本执行实例。"""

    def __init__(self, inst_id: str, playbook: Playbook,
                 input_vars: Optional[Dict[str, Any]] = None,
                 triggered_by: str = "manual") -> None:
        self.id = inst_id
        self.playbook_id = playbook.id
        self.playbook_name = playbook.name
        self.status = "running"  # running / paused / completed / failed / cancelled / waiting_approval
        self.current_node_id: Optional[str] = None
        self.progress = 0.0
        self.local_vars: Dict[str, Any] = dict(input_vars or {})
        self.logs: List[Dict[str, Any]] = []
        self.node_results: Dict[str, Any] = {}
        self.started_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.finished_at: Optional[str] = None
        self.error: Optional[str] = None
        self.retry_count = 0
        self.breakpoints: List[str] = []
        self.step_mode = False  # 单步模式
        self.triggered_by = triggered_by

    def log(self, level: str, message: str, node_id: Optional[str] = None) -> None:
        self.logs.append({
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "level": level, "message": message, "node_id": node_id,
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "playbook_id": self.playbook_id,
            "playbook_name": self.playbook_name, "status": self.status,
            "current_node_id": self.current_node_id, "progress": round(self.progress, 1),
            "local_vars": self.local_vars, "node_results": self.node_results,
            "logs": self.logs, "started_at": self.started_at,
            "finished_at": self.finished_at, "error": self.error,
            "retry_count": self.retry_count, "triggered_by": self.triggered_by,
            "log_count": len(self.logs),
        }


class PlaybookEngine:
    """深度剧本编排引擎主类。"""

    def __init__(self) -> None:
        self.playbooks: Dict[str, Playbook] = {}
        self.instances: Dict[str, ExecutionInstance] = {}
        self.var_mgr = get_variable_manager()
        self._seed_demo_playbooks()

    def _seed_demo_playbooks(self) -> None:
        """预置演示剧本。"""
        # 演示剧本1：勒索软件快速隔离
        pb1 = Playbook("pb_demo_ransomware", "勒索软件快速隔离剧本", "勒索软件")
        n_start = pb1.add_node("trigger", config={"type": "alert",
                                                  "conditions": [{"field": "alert.severity", "op": "==", "value": "critical"}]})
        n_enrich = pb1.add_node("data_process", config={"function": "json_path",
                                                        "args": ["{{local.alert_data}}", "$.host.ip"]})
        n_isolate = pb1.add_node("action", config={"action_id": "network.block_ip",
                                                   "params": {"ip": "{{local.target_ip}}"}})
        n_cond = pb1.add_node("condition", config={"expr": "{{local.target_risk}} > 70"})
        n_lock = pb1.add_node("action", config={"action_id": "account.lock",
                                                "params": {"account": "{{local.user}}"}})
        n_notify = pb1.add_node("notification", config={"channel": "email",
                                                        "to": "soc-team@corp.com",
                                                        "subject": "勒索软件告警已自动隔离"})
        n_end = pb1.add_node("end")
        pb1.add_edge(n_start["id"], n_enrich["id"])
        pb1.add_edge(n_enrich["id"], n_isolate["id"])
        pb1.add_edge(n_isolate["id"], n_cond["id"])
        pb1.add_edge(n_cond["id"], n_lock["id"], condition={"expr": "true"})
        pb1.add_edge(n_cond["id"], n_notify["id"], condition={"expr": "false"})
        pb1.add_edge(n_lock["id"], n_end["id"])
        pb1.add_edge(n_notify["id"], n_end["id"])
        pb1.description = "检测到勒索软件告警后，自动提取受害主机IP、封禁IP、锁定可疑账户并通知SOC团队"
        pb1.status = "published"
        self.playbooks[pb1.id] = pb1

        # 演示剧本2：钓鱼邮件处置
        pb2 = Playbook("pb_demo_phishing", "钓鱼邮件处置剧本", "钓鱼攻击")
        n2_start = pb2.add_node("trigger", config={"type": "alert"})
        n2_extract = pb2.add_node("data_process", config={"function": "regex_extract",
                                                          "args": ["{{local.email_body}}", "https?://[^\\s]+"]})
        n2_block = pb2.add_node("action", config={"action_id": "network.block_url"})
        n2_quarantine = pb2.add_node("action", config={"action_id": "application.waf_rule_update"})
        n2_approve = pb2.add_node("approval", config={"approvers": ["soc-lead"], "timeout": 3600})
        n2_end = pb2.add_node("end")
        pb2.add_edge(n2_start["id"], n2_extract["id"])
        pb2.add_edge(n2_extract["id"], n2_block["id"])
        pb2.add_edge(n2_block["id"], n2_quarantine["id"])
        pb2.add_edge(n2_quarantine["id"], n2_approve["id"])
        pb2.add_edge(n2_approve["id"], n2_end["id"])
        pb2.description = "钓鱼邮件触发后，提取恶意URL、封禁URL、更新WAF规则，等待人工审批后闭环"
        self.playbooks[pb2.id] = pb2

        # 演示剧本3：暴力破解防护
        pb3 = Playbook("pb_demo_bruteforce", "SSH暴力破解自动防护剧本", "暴力破解")
        n3_start = pb3.add_node("trigger", config={"type": "alert"})
        n3_loop = pb3.add_node("loop", config={"collection": "{{local.attacker_ips}}",
                                               "item_var": "ip"})
        n3_block = pb3.add_node("action", config={"action_id": "network.block_ip"})
        n3_wait = pb3.add_node("wait", config={"seconds": 300})
        n3_unblock = pb3.add_node("action", config={"action_id": "network.unblock_ip"})
        n3_end = pb3.add_node("end")
        pb3.add_edge(n3_start["id"], n3_loop["id"])
        pb3.add_edge(n3_loop["id"], n3_block["id"])
        pb3.add_edge(n3_block["id"], n3_wait["id"])
        pb3.add_edge(n3_wait["id"], n3_unblock["id"])
        pb3.add_edge(n3_unblock["id"], n3_end["id"])
        pb3.description = "检测到SSH暴力破解后，循环封禁攻击IP 5分钟后自动解封"
        self.playbooks[pb3.id] = pb3

    # ---- CRUD ----
    def create(self, name: str, category: str = "general",
               description: str = "") -> Playbook:
        pb_id = f"pb_{uuid.uuid4().hex[:10]}"
        pb = Playbook(pb_id, name, category)
        pb.description = description
        self.playbooks[pb_id] = pb
        return pb

    def get(self, pb_id: str) -> Optional[Playbook]:
        return self.playbooks.get(pb_id)

    def list_playbooks(self, status: Optional[str] = None,
                       category: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.playbooks.values())
        if status:
            items = [p for p in items if p.status == status]
        if category:
            items = [p for p in items if p.category == category]
        return [p.to_dict() for p in items]

    def delete(self, pb_id: str) -> bool:
        if pb_id in self.playbooks:
            del self.playbooks[pb_id]
            return True
        return False

    # ---- 版本管理 ----
    def list_versions(self, pb_id: str) -> List[Dict[str, Any]]:
        pb = self.get(pb_id)
        if not pb:
            return []
        return pb.versions

    def diff_versions(self, pb_id: str, v1: int, v2: int) -> Dict[str, Any]:
        """对比两个版本的差异。"""
        pb = self.get(pb_id)
        if not pb:
            return {}
        s1 = next((v for v in pb.versions if v["version"] == v1), None)
        s2 = next((v for v in pb.versions if v["version"] == v2), None)
        if not s1 or not s2:
            return {"error": "版本不存在"}
        n1 = {n["id"]: n for n in s1["nodes"]}
        n2 = {n["id"]: n for n in s2["nodes"]}
        added = [n for nid, n in n2.items() if nid not in n1]
        removed = [n for nid, n in n1.items() if nid not in n2]
        modified = []
        for nid in n1:
            if nid in n2 and n1[nid] != n2[nid]:
                modified.append({"id": nid, "before": n1[nid], "after": n2[nid]})
        return {
            "version_from": v1, "version_to": v2,
            "added_nodes": added, "removed_nodes": removed,
            "modified_nodes": modified,
            "added_count": len(added), "removed_count": len(removed),
            "modified_count": len(modified),
        }

    # ---- 执行 ----
    def execute(self, pb_id: str,
                input_vars: Optional[Dict[str, Any]] = None,
                triggered_by: str = "manual",
                dry_run: bool = False) -> Optional[ExecutionInstance]:
        """执行剧本（模拟）。"""
        pb = self.get(pb_id)
        if not pb:
            return None
        inst_id = f"inst_{uuid.uuid4().hex[:12]}"
        inst = ExecutionInstance(inst_id, pb, input_vars, triggered_by)
        inst.local_vars["dry_run"] = dry_run
        self.instances[inst_id] = inst

        # 模拟执行：遍历节点
        inst.log("info", f"剧本 [{pb.name}] 开始执行", None)
        total_nodes = len(pb.nodes) or 1
        for i, node in enumerate(pb.nodes):
            inst.current_node_id = node["id"]
            inst.progress = round((i + 1) / total_nodes * 100, 1)
            inst.log("info", f"执行节点 [{node['name']}] ({node['type']})", node["id"])

            # 模拟节点执行结果
            result = {"executed": True, "dry_run": dry_run,
                      "node_type": node["type"], "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
            if node["type"] == "action":
                result["action_id"] = node["config"].get("action_id", "unknown")
                result["status"] = "simulated"
            elif node["type"] == "condition":
                result["condition_eval"] = True
            elif node["type"] == "approval":
                inst.status = "waiting_approval"
                inst.log("warn", "等待人工审批...", node["id"])
                inst.finished_at = None
                return inst
            inst.node_results[node["id"]] = result

        inst.status = "completed"
        inst.progress = 100.0
        inst.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        inst.log("info", "剧本执行完成", None)
        return inst

    def approve(self, inst_id: str, decision: str,
                approver: str = "") -> bool:
        inst = self.instances.get(inst_id)
        if not inst:
            return False
        inst.approver = approver
        inst.log("info", f"审批决策: {decision} by {approver or 'unknown'}")
        if decision == "approve":
            inst.status = "completed"
            inst.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
            inst.progress = 100.0
        else:
            inst.status = "failed"
            inst.error = "人工审批驳回"
            inst.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return True

    def cancel(self, inst_id: str) -> bool:
        inst = self.instances.get(inst_id)
        if not inst:
            return False
        inst.status = "cancelled"
        inst.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        inst.log("warn", "剧本执行被取消")
        return True

    def list_instances(self, status: Optional[str] = None,
                       pb_id: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.instances.values())
        if status:
            items = [i for i in items if i.status == status]
        if pb_id:
            items = [i for i in items if i.playbook_id == pb_id]
        return [i.to_dict() for i in items]

    # ---- 测试调试 ----
    def debug_dry_run(self, pb_id: str,
                      input_vars: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Dry run：模拟执行但不实际触发动作。"""
        inst = self.execute(pb_id, input_vars=input_vars, triggered_by="dry_run", dry_run=True)
        if not inst:
            return {"error": "剧本不存在"}
        return {
            "instance": inst.to_dict(),
            "dry_run": True,
            "note": "本次为模拟执行，所有动作均未实际下发",
        }

    def set_breakpoint(self, inst_id: str, node_id: str) -> bool:
        inst = self.instances.get(inst_id)
        if not inst:
            return False
        if node_id not in inst.breakpoints:
            inst.breakpoints.append(node_id)
        return True

    def list_node_types(self) -> Dict[str, Dict[str, Any]]:
        return NODE_TYPE_REGISTRY

    def list_trigger_types(self) -> Dict[str, str]:
        return TRIGGER_TYPES

    def list_data_functions(self) -> Dict[str, Dict[str, str]]:
        return DATA_FUNCTIONS

    def stats(self) -> Dict[str, Any]:
        total = len(self.playbooks)
        published = sum(1 for p in self.playbooks.values() if p.status == "published")
        running = sum(1 for i in self.instances.values() if i.status == "running")
        completed = sum(1 for i in self.instances.values() if i.status == "completed")
        failed = sum(1 for i in self.instances.values() if i.status == "failed")
        return {
            "total_playbooks": total,
            "published": published,
            "draft": total - published,
            "total_instances": len(self.instances),
            "running": running,
            "completed": completed,
            "failed": failed,
            "success_rate": round(completed / max(1, completed + failed) * 100, 1),
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_engine: Optional[PlaybookEngine] = None


def get_playbook_engine() -> PlaybookEngine:
    global _engine
    if _engine is None:
        _engine = PlaybookEngine()
    return _engine
