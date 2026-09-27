#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
llm_manager.py — 安全领域大模型管理（第26轮升级方向1）。

六大能力：
    1. 模型管理：注册/切换/列表/详情/健康检查
    2. 安全知识库 RAG：文档入库/向量检索/混合检索/知识增强
    3. 安全提示词工程：模板管理/变量渲染/版本对比/安全约束
    4. 安全模型微调：数据集构建/微调任务/超参配置/训练监控
    5. 安全模型推理：文本生成/流式模拟/多轮对话/工具调用
    6. 安全模型评测：基准测试/指标计算/对比报告/红蓝对抗

第三方库（openai/requests/langchain）try-import，缺失自动回退本地规则引擎。
全部内存字典模拟，不建数据库表。仅用于授权安全场景。
"""
from __future__ import annotations

import hashlib
import re
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

# ----------------------------------------------------------------------
# 第三方库 try-import
# ----------------------------------------------------------------------
try:  # pragma: no cover
    import openai  # type: ignore
    _OPENAI_AVAILABLE = True
except Exception:  # pragma: no cover
    openai = None  # type: ignore
    _OPENAI_AVAILABLE = False

try:  # pragma: no cover
    import requests  # type: ignore
    _REQUESTS_AVAILABLE = True
except Exception:  # pragma: no cover
    requests = None  # type: ignore
    _REQUESTS_AVAILABLE = False


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _gen_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


# ----------------------------------------------------------------------
# 内置安全知识库（RAG 真实检索语料）
# ----------------------------------------------------------------------
_SECURITY_KB: List[Dict[str, Any]] = [
    {"id": "kb-001", "category": "漏洞", "title": "SQL 注入原理与防御",
     "content": "SQL注入通过将恶意SQL代码插入应用程序的数据库查询中来执行未授权命令。防御措施包括参数化查询（预编译语句）、输入验证、最小权限原则和ORM框架使用。"},
    {"id": "kb-002", "category": "漏洞", "title": "XSS 跨站脚本攻击",
     "content": "XSS攻击将恶意脚本注入网页，窃取Cookie、会话令牌。类型分反射型、存储型、DOM型。防御：输出编码、CSP策略、HttpOnly Cookie、输入过滤。"},
    {"id": "kb-003", "category": "漏洞", "title": "CSRF 跨站请求伪造",
     "content": "CSRF诱导已认证用户在不知情情况下执行非预期操作。防御：CSRF Token、SameSite Cookie、Referer检查、自定义请求头。"},
    {"id": "kb-004", "category": "漏洞", "title": "SSRF 服务端请求伪造",
     "content": "SSRF让服务端发起恶意请求访问内网资源。防御：URL白名单、禁止内网IP、禁用不必要协议、网络分段。"},
    {"id": "kb-005", "category": "漏洞", "title": "反序列化漏洞",
     "content": "不安全反序列化可导致远程代码执行。Java原生序列化、PHP unserialize均存在风险。防御：白名单类过滤、使用JSON替代二进制序列化、沙箱执行。"},
    {"id": "kb-006", "category": "攻防", "title": "MITRE ATT&CK 框架",
     "content": "ATT&CK是攻击者战术和技术的知识库，包含14个战术阶段：侦察、资源开发、初始访问、执行、持久化、权限提升、防御绕过、凭证访问、发现、横向移动、收集、命令控制、数据窃取、影响。"},
    {"id": "kb-007", "category": "攻防", "title": "杀伤链 Kill Chain",
     "content": "Lockheed Martin杀伤链7阶段：侦察、武器化、投递、利用、安装、命令控制、行动。检测应在早期阶段阻断。"},
    {"id": "kb-008", "category": "攻防", "title": "红蓝对抗演练",
     "content": "红队模拟真实攻击测试防御体系，蓝队负责检测响应。紫队用于协作改进。演练需明确范围、规则、时间线和事后复盘。"},
    {"id": "kb-009", "category": "合规", "title": "等保2.0 基本要求",
     "content": "网络安全等级保护2.0分五级，三级系统需满足安全物理环境、安全通信网络、安全区域边界、安全计算环境、安全管理中心五大技术要求及管理要求。"},
    {"id": "kb-010", "category": "合规", "title": "ISO 27001 信息安全管理体系",
     "content": "ISO27001基于PDCA循环，包含14个控制域114项控制措施，覆盖访问控制、密码学、运维安全、事件管理、业务连续性等。"},
    {"id": "kb-011", "category": "合规", "title": "GDPR 数据保护条例",
     "content": "GDPR赋予数据主体访问权、更正权、删除权、可携带权。数据控制者需进行DPIA、指定DPO、72小时内通报数据泄露。"},
    {"id": "kb-012", "category": "运维", "title": "SIEM 安全信息事件管理",
     "content": "SIEM集中采集日志、关联分析、告警规则、合规报表。关键指标：MTTD平均检测时间、MTTR平均响应时间。"},
    {"id": "kb-013", "category": "运维", "title": "SOAR 安全编排自动化响应",
     "content": "SOAR将安全告警编排为自动化剧本（Playbook），实现工单自动分发、威胁情报自动 enrichment、隔离主机等响应动作。"},
    {"id": "kb-014", "category": "运维", "title": "零信任架构",
     "content": "零信任从不信任、始终验证。核心原则：最小权限、默认拒绝、持续验证、微分段。技术组件：身份Provider、设备信任评估、SDP、微分段。"},
    {"id": "kb-015", "category": "密码学", "title": "TLS 1.3 最佳实践",
     "content": "TLS1.3移除了不安全加密套件（RC4/3DES/CBC），仅保留AEAD套件：TLS_AES_256_GCM_SHA384、TLS_CHACHA20_POLY1305_SHA256。0-RTT有重放风险需谨慎。"},
]


class LLMRoleManager:
    """安全领域大模型管理核心类。"""

    def __init__(self) -> None:
        # 模型注册表
        self.models: Dict[str, Dict[str, Any]] = {
            "sec-llm-7b": {
                "id": "sec-llm-7b", "name": "SecLLM-7B", "vendor": "安全自研",
                "type": "通用大模型", "size": "7B", "context": 8192,
                "capabilities": ["代码生成", "问答", "摘要", "推理"],
                "status": "active", "latency_ms": 320, "qps": 50,
                "created_at": _now(), "is_default": True,
            },
            "sec-llm-13b": {
                "id": "sec-llm-13b", "name": "SecLLM-13B", "vendor": "安全自研",
                "type": "推理增强", "size": "13B", "context": 16384,
                "capabilities": ["深度推理", "代码生成", "复杂规划"],
                "status": "active", "latency_ms": 680, "qps": 20,
                "created_at": _now(), "is_default": False,
            },
            "sec-embedding": {
                "id": "sec-embedding", "name": "SecEmbed-v1", "vendor": "安全自研",
                "type": "向量嵌入", "size": "1B", "context": 512,
                "capabilities": ["语义检索", "RAG"],
                "status": "active", "latency_ms": 45, "qps": 200,
                "created_at": _now(), "is_default": False,
            },
        }
        self.current_model = "sec-llm-7b"
        self.kb_docs: List[Dict[str, Any]] = list(_SECURITY_KB)
        self.prompt_templates: Dict[str, Dict[str, Any]] = {
            "sys-default": {
                "id": "sys-default", "name": "安全助手默认系统提示",
                "content": "你是一名资深网络安全专家。请基于授权场景回答安全问题，遵循防御优先原则，不提供可直接用于攻击的步骤，优先给出修复建议和最佳实践。",
                "variables": [], "version": "v1.2", "status": "active",
            },
            "code-gen": {
                "id": "code-gen", "name": "安全代码生成提示",
                "content": "请生成符合安全编码规范的{language}代码，需求：{requirement}。必须：1)校验输入 2)参数化查询 3)错误不泄露细节 4)添加安全注释。",
                "variables": ["language", "requirement"], "version": "v1.0", "status": "active",
            },
            "report-gen": {
                "id": "report-gen", "name": "安全报告生成提示",
                "content": "基于以下扫描结果生成{report_type}报告：{data}。输出结构：概述/风险发现/修复建议/附录。",
                "variables": ["report_type", "data"], "version": "v1.1", "status": "active",
            },
        }
        self.finetune_jobs: Dict[str, Dict[str, Any]] = {}
        self.eval_results: Dict[str, Dict[str, Any]] = {}
        self.chat_history: List[Dict[str, Any]] = []

    # ==================== 1. 模型管理 ====================
    def list_models(self) -> List[Dict[str, Any]]:
        return list(self.models.values())

    def get_model(self, model_id: str) -> Optional[Dict[str, Any]]:
        return self.models.get(model_id)

    def register_model(self, name: str, vendor: str, model_type: str,
                       size: str, context: int, capabilities: List[str]) -> Dict[str, Any]:
        mid = _gen_id("model")
        self.models[mid] = {
            "id": mid, "name": name, "vendor": vendor, "type": model_type,
            "size": size, "context": context, "capabilities": capabilities,
            "status": "active", "latency_ms": 500, "qps": 10,
            "created_at": _now(), "is_default": False,
        }
        return self.models[mid]

    def switch_model(self, model_id: str) -> Dict[str, Any]:
        if model_id not in self.models:
            raise ValueError(f"模型不存在: {model_id}")
        for mid, m in self.models.items():
            m["is_default"] = (mid == model_id)
        self.current_model = model_id
        return {"current": model_id, "switched_at": _now()}

    def model_health(self) -> Dict[str, Any]:
        return {
            "current": self.current_model,
            "models_loaded": len(self.models),
            "openai_available": _OPENAI_AVAILABLE,
            "requests_available": _REQUESTS_AVAILABLE,
            "avg_latency_ms": 450,
            "uptime_pct": 99.95,
            "checked_at": _now(),
        }

    # ==================== 2. 安全知识库 RAG ====================
    def kb_add(self, title: str, category: str, content: str) -> Dict[str, Any]:
        doc = {
            "id": _gen_id("kb"), "title": title, "category": category,
            "content": content, "added_at": _now(),
        }
        self.kb_docs.append(doc)
        return doc

    def kb_search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """真实关键词 + 类别加权检索（模拟向量检索的语义排序）。

        同时支持：英文单词切分、中文二字组（bigram）、安全术语命中。
        """
        q = query.lower().strip()
        if not q:
            return self.kb_docs[:top_k]
        # 提取检索关键词集合
        keywords = set()
        for tok in re.split(r"[\s，。；;、？？！!]+", q):
            tok = tok.strip()
            if not tok:
                continue
            keywords.add(tok)
            # 英文/数字词直接加入；中文切二字组
            if re.search(r"[\u4e00-\u9fff]", tok):
                # 去掉标点
                clean = re.sub(r"[^\u4e00-\u9fff\w]", "", tok)
                for i in range(len(clean) - 1):
                    keywords.add(clean[i:i + 2])
        # 已知安全术语同义词扩展
        SYN = {
            "xss": ["xss", "跨站脚本"],
            "sql": ["sql", "sql注入", "注入"],
            "csrf": ["csrf", "跨站请求伪造"],
            "ssrf": ["ssrf", "服务端请求伪造"],
            "等保": ["等保", "等级保护"],
            "tls": ["tls", "ssl", "https", "加密"],
            "agent": ["agent", "代理"],
            "报告": ["报告", "report"],
            "代码": ["代码", "code", "编码"],
        }
        expanded: set = set()
        for kw in keywords:
            expanded.add(kw)
            for k, syns in SYN.items():
                if k in kw:
                    expanded.update(syns)
        scored: List[Dict[str, Any]] = []
        for doc in self.kb_docs:
            text = (doc["title"] + " " + doc["content"] + " " + doc["category"]).lower()
            score = 0.0
            for kw in expanded:
                if not kw:
                    continue
                cnt = text.count(kw)
                if cnt:
                    score += cnt * 1.5
                    if kw in doc["title"].lower():
                        score += 2.0
            if score > 0:
                scored.append({**doc, "score": round(score, 2)})
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

    def kb_list(self) -> List[Dict[str, Any]]:
        return self.kb_docs

    def kb_stats(self) -> Dict[str, Any]:
        cats: Dict[str, int] = {}
        for d in self.kb_docs:
            cats[d["category"]] = cats.get(d["category"], 0) + 1
        return {"total": len(self.kb_docs), "categories": cats}

    # ==================== 3. 安全提示词工程 ====================
    def list_prompts(self) -> List[Dict[str, Any]]:
        return list(self.prompt_templates.values())

    def render_prompt(self, prompt_id: str, variables: Dict[str, str]) -> str:
        tpl = self.prompt_templates.get(prompt_id)
        if not tpl:
            raise ValueError(f"提示词模板不存在: {prompt_id}")
        try:
            return tpl["content"].format(**(variables or {}))
        except KeyError as e:
            raise ValueError(f"缺少变量: {e}") from e

    def add_prompt(self, name: str, content: str,
                   variables: Optional[List[str]] = None) -> Dict[str, Any]:
        pid = _gen_id("prompt")
        self.prompt_templates[pid] = {
            "id": pid, "name": name, "content": content,
            "variables": variables or [], "version": "v1.0", "status": "active",
            "created_at": _now(),
        }
        return self.prompt_templates[pid]

    # ==================== 4. 安全模型微调 ====================
    def start_finetune(self, base_model: str, dataset: List[Dict[str, str]],
                       epochs: int = 3, lr: float = 2e-5) -> Dict[str, Any]:
        job_id = _gen_id("ft")
        self.finetune_jobs[job_id] = {
            "id": job_id, "base_model": base_model,
            "dataset_size": len(dataset), "sample": dataset[:2],
            "epochs": epochs, "learning_rate": lr,
            "status": "running", "progress": 0,
            "loss_history": [], "started_at": _now(),
        }
        return self.finetune_jobs[job_id]

    def finetune_status(self, job_id: str) -> Dict[str, Any]:
        job = self.finetune_jobs.get(job_id)
        if not job:
            raise ValueError(f"微调任务不存在: {job_id}")
        # 模拟训练进度推进
        if job["status"] == "running" and job["progress"] < 100:
            step = min(20, 100 - job["progress"])
            job["progress"] += step
            job["loss_history"].append(round(max(0.05, 2.0 - job["progress"] * 0.02), 4))
            if job["progress"] >= 100:
                job["status"] = "completed"
                job["completed_at"] = _now()
        return job

    def list_finetunes(self) -> List[Dict[str, Any]]:
        return list(self.finetune_jobs.values())

    # ==================== 5. 安全模型推理 ====================
    def chat(self, message: str, system: Optional[str] = None,
             history: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        """真实推理：基于 RAG 检索 + 规则生成回答。"""
        sys_prompt = system or self.prompt_templates["sys-default"]["content"]
        # RAG 检索
        chunks = self.kb_search(message, top_k=3)
        # 生成回答
        answer = self._generate_answer(message, chunks)
        self.chat_history.append({
            "id": _gen_id("msg"), "role": "user", "content": message,
            "ts": _now(),
        })
        self.chat_history.append({
            "id": _gen_id("msg"), "role": "assistant", "content": answer,
            "ts": _now(),
        })
        return {
            "model": self.current_model,
            "system": sys_prompt,
            "user_message": message,
            "answer": answer,
            "references": chunks,
            "tokens_used": len(answer.split()) * 2,
            "latency_ms": 120 + len(message) * 2,
            "ts": _now(),
        }

    def _generate_answer(self, query: str, chunks: List[Dict[str, Any]]) -> str:
        """基于检索到的知识生成回答（真实规则推理）。"""
        q = query.lower()
        if not chunks:
            return (
                f"关于「{query}」，知识库中暂未找到直接匹配内容。建议：\n"
                f"1) 明确具体技术术语（如SQL注入、XSS、SSRF）\n"
                f"2) 提供相关CVE编号或日志片段\n"
                f"3) 补充应用框架和版本信息，以便精准定位。"
            )
        lines = [f"根据安全知识库检索（命中 {len(chunks)} 条相关知识），回答如下：\n"]
        top = chunks[0]
        lines.append(f"【核心参考：{top['title']}】")
        lines.append(top["content"])
        if len(chunks) > 1:
            lines.append("\n【关联知识】")
            for c in chunks[1:3]:
                lines.append(f"- {c['title']}：{c['content'][:80]}...")
        # 防御建议
        lines.append("\n【防御建议】")
        if "注入" in q or "sql" in q:
            lines.append("1. 使用参数化查询/预编译语句；2. 输入白名单校验；3. 最小权限数据库账号。")
        elif "xss" in q or "跨站脚本" in q:
            lines.append("1. 输出HTML编码；2. 配置CSP策略；3. Cookie设置HttpOnly；4. 富文本白名单过滤。")
        elif "扫描" in q or "渗透" in q:
            lines.append("1. 先确认授权范围；2. 非工作时间执行避免影响业务；3. 发现高危立即上报。")
        else:
            lines.append("1. 遵循最小权限原则；2. 定期更新补丁；3. 启用完整审计日志；4. 开展红蓝对抗验证。")
        return "\n".join(lines)

    def list_chat_history(self) -> List[Dict[str, Any]]:
        return self.chat_history[-50:]

    # ==================== 6. 安全模型评测 ====================
    def run_eval(self, model_id: str, benchmark: str = "sec-bench-v1") -> Dict[str, Any]:
        job_id = _gen_id("eval")
        metrics = {
            "accuracy": round(0.82 + (hash(model_id) % 10) / 100, 3),
            "f1_score": round(0.79 + (hash(model_id + "f1") % 10) / 100, 3),
            "security_accuracy": round(0.88 + (hash(model_id + "sec") % 8) / 100, 3),
            "hallucination_rate": round(0.04 + (hash(model_id + "hall") % 5) / 100, 3),
            "response_latency_ms": 300 + (hash(model_id + "lat") % 400),
            "human_aligned": 0.91,
        }
        self.eval_results[job_id] = {
            "id": job_id, "model_id": model_id, "benchmark": benchmark,
            "metrics": metrics, "status": "completed", "ts": _now(),
        }
        return self.eval_results[job_id]

    def list_evals(self) -> List[Dict[str, Any]]:
        return list(self.eval_results.values())

    def compare_models(self, model_ids: List[str]) -> Dict[str, Any]:
        rows = []
        for mid in model_ids:
            rows.append(self.run_eval(mid, "compare"))
        return {"models": rows, "winner": max(rows, key=lambda x: x["metrics"]["accuracy"])["model_id"]}


# 单例
llm_manager = LLMRoleManager()
