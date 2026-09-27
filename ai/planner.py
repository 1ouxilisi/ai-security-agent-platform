#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai/planner.py — AI 自主扫描规划器

基于目标信息与已知信息，调用 LLM 自主规划扫描策略，并支持迭代式
"扫描 -> 分析 -> 决策 -> 再扫描"闭环。当 LLM API 不可用时自动降级为
基于规则的默认扫描计划，保证模块始终可运行。

仅用于经过授权的安全测试场景。
"""
import os
import re
import json
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

# 自动加载 .env（LLM_API_KEY / LLM_BASE_URL / LLM_MODEL）
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover
    pass

try:
    from utils.logger import log
except Exception:  # pragma: no cover - 日志缺失时降级为 print
    import logging

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("ai.planner")


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------
class ScanPlan:
    """扫描计划对象"""

    def __init__(self, target: str, steps: Optional[List[Dict[str, Any]]] = None,
                 metadata: Optional[Dict[str, Any]] = None):
        self.plan_id: str = uuid.uuid4().hex[:12]
        self.target: str = target
        self.steps: List[Dict[str, Any]] = steps or []
        self.created_at: str = datetime.now().isoformat()
        self.metadata: Dict[str, Any] = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "target": self.target,
            "steps": self.steps,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ScanPlan {self.plan_id} target={self.target} steps={len(self.steps)}>"


# ---------------------------------------------------------------------------
# 规划器
# ---------------------------------------------------------------------------
class ScanPlanner:
    """AI 扫描规划器：用 LLM 自主规划扫描策略，并支持迭代决策。"""

    # 工具动作到具体工具名的映射（用于执行/模拟阶段）
    ACTION_TOOL_MAP: Dict[str, str] = {
        "port_scan": "nmap",
        "service_detect": "nmap",
        "dir_bruteforce": "gobuster",
        "web_scan": "nikto",
        "vuln_scan": "nuclei",
        "sql_test": "sqlmap",
        "fingerprint": "whatweb",
        "subdomain_enum": "subfinder",
        "osint": "theHarvester",
    }

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None,
                 model: Optional[str] = None):
        """初始化，从环境变量读取 LLM 配置。"""
        self.api_key = api_key or os.getenv("LLM_API_KEY", "")
        self.base_url = (base_url or os.getenv("LLM_BASE_URL", "")).rstrip("/")
        self.model = model or os.getenv("LLM_MODEL", "gpt-3.5-turbo")
        self.timeout = 30
        self.llm_available = bool(self.api_key and self.base_url)
        self.call_count = 0
        if not self.llm_available:
            log.warning("LLM 配置缺失，ScanPlanner 将使用基于规则的默认策略")

    # ------------------------------------------------------------------
    # 内部：调用 LLM
    # ------------------------------------------------------------------
    def _call_llm(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """调用 OpenAI 兼容 Chat Completions 接口，返回文本；失败返回 None。"""
        if not self.llm_available:
            return None
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 4096,
        }
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            self.call_count += 1
            return content
        except Exception as e:
            log.error(f"LLM 调用失败，降级为默认策略: {e}")
            return None

    @staticmethod
    def _extract_json(text: Optional[str]) -> Optional[Any]:
        """从 LLM 返回文本中提取 JSON（容忍 markdown 代码块包裹）。"""
        if not text:
            return None
        cleaned = text.strip()
        # 去除 markdown 代码块围栏
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        cleaned = cleaned.strip()
        # 尝试直接解析
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass
        # 退化：截取首个 [ ... ] 或 { ... } 片段
        for opener, closer in (("[", "]"), ("{", "}")):
            start = cleaned.find(opener)
            end = cleaned.rfind(closer)
            if start != -1 and end != -1 and end > start:
                snippet = cleaned[start:end + 1]
                try:
                    return json.loads(snippet)
                except json.JSONDecodeError:
                    continue
        return None

    # ------------------------------------------------------------------
    # 基于规则的默认扫描计划（降级方案）
    # ------------------------------------------------------------------
    def _default_scan_steps(self, target: str) -> List[Dict[str, Any]]:
        """基于目标形态生成规则化扫描步骤。"""
        is_url = target.startswith(("http://", "https://"))
        steps: List[Dict[str, Any]] = [
            {
                "step": 1,
                "action": "port_scan",
                "tool": "nmap",
                "target": target,
                "options": {"top_ports": "1000", "svc_detect": "-sV"},
                "reason": "基础端口扫描与服务识别，建立攻击面基线",
            },
            {
                "step": 2,
                "action": "service_detect",
                "tool": "nmap",
                "target": target,
                "options": {"scripts": "default", "os_detect": "-O"},
                "reason": "识别服务版本与操作系统，用于匹配已知漏洞",
            },
        ]
        if is_url:
            steps.extend([
                {
                    "step": 3,
                    "action": "fingerprint",
                    "tool": "whatweb",
                    "target": target,
                    "options": {},
                    "reason": "识别 Web 框架/CMS 指纹",
                },
                {
                    "step": 4,
                    "action": "dir_bruteforce",
                    "tool": "gobuster",
                    "target": target,
                    "options": {"wordlist": "common.txt", "extensions": "php,bak"},
                    "reason": "目录与敏感文件爆破",
                },
                {
                    "step": 5,
                    "action": "web_scan",
                    "tool": "nikto",
                    "target": target,
                    "options": {},
                    "reason": "Web 服务器常见漏洞与配置检查",
                },
            ])
        steps.append({
            "step": len(steps) + 1,
            "action": "vuln_scan",
            "tool": "nuclei",
            "target": target,
            "options": {"tags": "cve,exposure,misconfig"},
            "reason": "基于模板的已知漏洞批量检测",
        })
        return steps

    # ------------------------------------------------------------------
    # 扫描策略规划
    # ------------------------------------------------------------------
    def plan_scan(self, target: str,
                  known_info: Optional[Dict[str, Any]] = None) -> ScanPlan:
        """基于目标信息规划扫描策略。"""
        known_info = known_info or {}
        system_prompt = (
            "你是一名资深渗透测试与漏洞扫描规划专家。"
            "根据目标与已知信息，输出一个循序渐进的扫描计划。"
            "严格只返回 JSON 数组，不要任何解释或 markdown。"
            "数组元素格式为："
            '{"step": 1, "action": "port_scan", "tool": "nmap", '
            '"target": "...", "options": {}, "reason": "..."}。'
            "action 可取 port_scan/service_detect/dir_bruteforce/web_scan/"
            "vuln_scan/sql_test/fingerprint/subdomain_enum/osint。"
        )
        user_prompt = (
            f"目标: {target}\n"
            f"已知信息(JSON): {json.dumps(known_info, ensure_ascii=False)}\n"
            "请基于已知信息决定下一步最有价值的扫描动作，避免重复已完成的工作。"
        )
        content = self._call_llm(system_prompt, user_prompt)
        parsed = self._extract_json(content)

        steps: List[Dict[str, Any]] = []
        if isinstance(parsed, list) and parsed:
            for i, item in enumerate(parsed, 1):
                if isinstance(item, dict):
                    item.setdefault("step", i)
                    item.setdefault("target", target)
                    item.setdefault("options", {})
                    item.setdefault("reason", "")
                    steps.append(item)

        if not steps:
            log.info("LLM 未返回有效计划，使用规则化默认扫描计划")
            steps = self._default_scan_steps(target)
            source = "rule_based_fallback"
        else:
            source = "llm"

        return ScanPlan(
            target=target,
            steps=steps,
            metadata={"source": source, "known_info": known_info,
                      "llm_calls": self.call_count},
        )

    # ------------------------------------------------------------------
    # 执行单个扫描步骤（优先调用工具，不可用则模拟）
    # ------------------------------------------------------------------
    def _execute_step(self, target: str, step: Dict[str, Any]) -> Dict[str, Any]:
        """执行单个扫描步骤。工具不可用时模拟执行并记录结果。"""
        action = step.get("action", "unknown")
        tool = step.get("tool") or self.ACTION_TOOL_MAP.get(action, "custom")
        record: Dict[str, Any] = {
            "action": action,
            "tool": tool,
            "target": step.get("target", target),
            "options": step.get("options", {}),
            "reason": step.get("reason", ""),
            "executed_at": datetime.now().isoformat(),
            "status": "simulated",
            "findings": [],
        }
        # 尝试调用真实工具集成层
        try:
            from tools.integration import tool_manager  # type: ignore

            runner = getattr(tool_manager, tool, None)
            if callable(runner):
                result = runner(record["target"], **record["options"])
                record["status"] = "executed"
                record["findings"] = result if isinstance(result, (list, dict)) else str(result)
                return record
        except Exception as e:  # 工具不可用 -> 模拟
            record["status"] = "simulated"
            record["note"] = f"工具不可用，模拟执行: {e}"

        # 模拟结果：根据动作类型给出结构化占位发现
        simulated_findings = self._simulate_findings(action, record["target"])
        record["findings"] = simulated_findings
        return record

    @staticmethod
    def _simulate_findings(action: str, target: str) -> List[Dict[str, Any]]:
        """生成模拟发现（仅用于演示/无真实工具环境）。"""
        base = {"target": target}
        mapping = {
            "port_scan": [
                {**base, "port": 80, "service": "http", "state": "open"},
                {**base, "port": 443, "service": "https", "state": "open"},
                {**base, "port": 22, "service": "ssh", "state": "open"},
            ],
            "service_detect": [
                {**base, "service": "http", "product": "nginx", "version": "1.24.0"},
                {**base, "service": "ssh", "product": "OpenSSH", "version": "8.9p1"},
            ],
            "fingerprint": [{**base, "cms": "unknown", "framework": "generic-web"}],
            "dir_bruteforce": [
                {**base, "path": "/admin", "status": 401},
                {**base, "path": "/.git/HEAD", "status": 200},
            ],
            "web_scan": [{**base, "issue": "security_headers_missing", "severity": "low"}],
            "vuln_scan": [
                {**base, "vuln": "example-exposure", "severity": "medium"},
            ],
            "sql_test": [{**base, "vuln": "sql_injection", "endpoint": "/id", "severity": "high"}],
        }
        return mapping.get(action, [{**base, "note": f"simulated {action}"}])

    # ------------------------------------------------------------------
    # 迭代扫描
    # ------------------------------------------------------------------
    def iterative_scan(self, target: str, max_iterations: int = 5) -> Dict[str, Any]:
        """迭代扫描：扫描 -> 分析 -> 决策 -> 再扫描。"""
        history: List[Dict[str, Any]] = []
        all_findings: List[Dict[str, Any]] = []
        known_info: Dict[str, Any] = {}

        for iteration in range(1, max_iterations + 1):
            # 决策下一步计划
            if iteration == 1:
                plan = ScanPlan(target, self._default_scan_steps(target),
                                metadata={"source": "baseline", "iteration": iteration})
            else:
                plan = self.plan_scan(target, known_info)
                plan.metadata["iteration"] = iteration

            # 执行本轮计划（基础版：每轮执行前 3 步，避免过度膨胀）
            round_results = []
            for step in plan.steps[:3]:
                result = self._execute_step(target, step)
                round_results.append(result)
                # 汇总发现
                findings = result.get("findings", [])
                if isinstance(findings, list):
                    all_findings.extend(findings)

            # 更新已知信息
            known_info = self._consolidate_known_info(known_info, all_findings)

            history.append({
                "iteration": iteration,
                "plan": plan.to_dict(),
                "results": round_results,
            })

            # 收敛判断：如果没有新发现且不是首轮，提前结束
            if iteration > 1 and not self._has_new_signal(round_results):
                log.info(f"第 {iteration} 轮无新信号，提前收敛")
                break

        # 攻击路径推理
        attack_paths = self.reason_attack_path(all_findings)

        summary = {
            "target": target,
            "iterations": len(history),
            "llm_calls": self.call_count,
            "known_info": known_info,
            "total_findings": len(all_findings),
            "findings": all_findings,
            "attack_paths": attack_paths,
            "history": history,
        }
        return summary

    @staticmethod
    def _consolidate_known_info(known_info: Dict[str, Any],
                                findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """把发现汇总成已知信息字典，供下一轮规划使用。"""
        ports = {f.get("port") for f in findings if f.get("port")}
        services = {f.get("service") for f in findings if f.get("service")}
        vulns = {f.get("vuln") for f in findings if f.get("vuln")}
        info = dict(known_info)
        info["open_ports"] = sorted(p for p in ports if p is not None)
        info["services"] = sorted(s for s in services if s)
        info["known_vulns"] = sorted(v for v in vulns if v)
        return info

    @staticmethod
    def _has_new_signal(round_results: List[Dict[str, Any]]) -> bool:
        """判断本轮是否出现新的可利用信号。"""
        high_keywords = {"vuln", "sql_injection", "exposure", "rce", ".git"}
        for r in round_results:
            for f in r.get("findings", []):
                text = json.dumps(f, ensure_ascii=False).lower()
                if any(k in text for k in high_keywords):
                    return True
        return False

    # ------------------------------------------------------------------
    # 攻击路径推理
    # ------------------------------------------------------------------
    def reason_attack_path(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """推理可能的攻击链与横向移动路径。"""
        system_prompt = (
            "你是一名红队攻击路径分析师。根据发现的漏洞列表，推理可能的攻击链"
            "与横向移动路径。严格只返回 JSON 数组，不要任何解释。"
            "元素格式："
            '{"chain_name": "...", "steps": [{"vuln": "...", "action": "...", '
            '"probability": 0.8}], "risk_level": "high"}。'
            "probability 为 0~1 之间的浮点数，risk_level 取 low/medium/high/critical。"
        )
        user_prompt = f"发现的漏洞(JSON): {json.dumps(findings, ensure_ascii=False)}"
        content = self._call_llm(system_prompt, user_prompt)
        parsed = self._extract_json(content)

        if isinstance(parsed, list) and parsed:
            return parsed

        # 降级：基于规则生成攻击链
        return self._default_attack_paths(findings)

    @staticmethod
    def _default_attack_paths(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """规则化攻击链推理（LLM 不可用时）。"""
        paths: List[Dict[str, Any]] = []
        text = json.dumps(findings, ensure_ascii=False).lower()

        if "sql_injection" in text:
            paths.append({
                "chain_name": "SQL注入->数据窃取",
                "steps": [
                    {"vuln": "sql_injection", "action": "注入读取敏感表", "probability": 0.8},
                    {"vuln": "sensitive_data", "action": "导出用户凭证", "probability": 0.6},
                ],
                "risk_level": "high",
            })
        if any(k in text for k in (".git", "exposure")):
            paths.append({
                "chain_name": "敏感信息泄露->源码审计",
                "steps": [
                    {"vuln": "info_disclosure", "action": "拉取泄露源码/配置", "probability": 0.9},
                    {"vuln": "hardcoded_secret", "action": "提取硬编码凭证", "probability": 0.5},
                ],
                "risk_level": "medium",
            })
        if not paths:
            paths.append({
                "chain_name": "服务指纹->已知漏洞利用",
                "steps": [
                    {"vuln": "service_fingerprint", "action": "匹配已知CVE", "probability": 0.4},
                ],
                "risk_level": "low",
            })
        return paths


# 模块级单例
_planner: Optional[ScanPlanner] = None


def get_scan_planner() -> ScanPlanner:
    """获取全局 ScanPlanner 单例。"""
    global _planner
    if _planner is None:
        _planner = ScanPlanner()
    return _planner
