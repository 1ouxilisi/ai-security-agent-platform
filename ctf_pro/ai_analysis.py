# -*- coding: utf-8 -*-
"""
ai_analysis.py — CTF Pro AI 分析（启发式，离线可用）。

功能:
    - AI 自动分析题目难度
    - AI 生成解题思路 / 题解（步骤/脚本/工具）
    - AI 推荐学习路径（基于能力评估/短板）
    - AI 出题（自动生成题目/flag/提示）
    - AI 比赛复盘分析 / 战队训练建议
    - 思考过程可视化
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from typing import Any, Dict, List, Optional


class CtfAIAnalysis:
    """CTF AI 分析引擎（规则启发式，不依赖外部 LLM）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    def _think(self, text: str) -> str:
        return f"[AI思考] {text}"

    # ------------------------------------------------------------------ #
    def analyze_difficulty(self, title: str, category: str,
                         description: str,
                         tags: Optional[List[str]] = None
                         ) -> Dict[str, Any]:
        tags = tags or []
        score = 3.0
        reasons: List[str] = []
        hard_kw = {"heap", "uaf", "rop", "vm", "混淆", "格",
                   "椭圆曲线", "反调试", "脱壳", "内核"}
        easy_kw = {"注入", "xss", "编码", "隐写", "入门", "简单"}
        blob = (title + description + " ".join(tags)).lower()
        for kw in hard_kw:
            if kw in blob:
                score += 1.5
                reasons.append(f"含硬核知识点「{kw}」")
        for kw in easy_kw:
            if kw in blob:
                score -= 1.0
                reasons.append(f"含基础考点「{kw}」")
        if category in ("Pwn", "Reverse", "Blockchain"):
            score += 1.0
            reasons.append(f"{category} 类题目天然门槛较高")
        score = max(1.0, min(5.0, score))
        level = ("入门" if score < 2 else "简单" if score < 3
                 else "中等" if score < 3.8 else "困难"
                 if score < 4.5 else "地狱")
        result = {
            "category": category,
            "difficulty_score": round(score, 1),
            "recommended_difficulty": level,
            "reasons": reasons or ["综合题型与描述判定"],
            "estimated_base_score": {"入门": 100, "简单": 200,
                                     "中等": 350, "困难": 500,
                                     "地狱": 800}[level],
            "thought": self._think(
                f"正在评估「{title}」难度，命中 {len(reasons)} 个特征"),
        }
        with self._lock:
            self._history.append(result)
        return result

    # ------------------------------------------------------------------ #
    def solve_hint(self, category: str,
                   subcategory: str = "") -> Dict[str, Any]:
        playbooks: Dict[str, Dict[str, Any]] = {
            "Web": {"思路": ["识别输入点", "构造 payload",
                            "观察回显/报错", "验证利用"],
                    "工具": ["BurpSuite", "sqlmap", "dirsearch",
                            "ffuf"],
                    "脚本": "sqlmap -u 'http://target/?id=1' --dbs"},
            "Reverse": {"思路": ["查壳", "动态调试定位关键函数",
                                "还原算法", "编写求解器"],
                        "工具": ["IDA Pro", "Ghidra", "x64dbg",
                                "Frida"],
                        "脚本": "gdb ./chal -q -ex 'b main'"},
            "Pwn": {"思路": ["checksec", "确定溢出点",
                            "构造 ROP", "泄露 libc", "getshell"],
                    "工具": ["pwntools", "checksec", "ROPgadget"],
                    "脚本": "from pwn import *; r=remote('h',p)"},
            "Crypto": {"思路": ["识别算法", "找弱参数",
                              "数学推导", "写 exp"],
                      "工具": ["RsaCtfTool", "sage", "openssl"],
                      "脚本": "from Crypto.Util.number import *"},
            "Misc": {"思路": ["看文件头", "分离数据流",
                            "解码", "脑洞"],
                    "工具": ["zsteg", "steghide", "Wireshark"],
                    "脚本": "zsteg challenge.png"},
        }
        pb = playbooks.get(category, {
            "思路": ["阅读题目", "分析附件", "尝试常见解法"],
            "工具": ["strings", "binwalk", "file"],
            "脚本": "file challenge.bin"})
        result = {"category": category, "subcategory": subcategory,
                  **pb,
                  "thought": self._think(
                      f"为 {category}/{subcategory} 生成解题思路")}
        with self._lock:
            self._history.append(result)
        return result

    # ------------------------------------------------------------------ #
    def recommend_path(self,
                       ability: Dict[str, float]) -> Dict[str, Any]:
        weak = sorted(ability.items(), key=lambda x: x[1])[:3]
        paths = []
        mapping = {"Web": "web_path", "Pwn": "pwn_path",
                   "Reverse": "reverse_path"}
        for cat, score in weak:
            paths.append({"category": cat, "current": round(score, 1),
                          "path": mapping.get(cat, "web_path"),
                          "reason": f"{cat} 能力分仅 {score:.0f}，建议专项突破"})
        result = {"recommendations": paths,
                  "thought": self._think(
                      f"基于短板 {[w[0] for w in weak]} 推荐学习路径")}
        with self._lock:
            self._history.append(result)
        return result

    # ------------------------------------------------------------------ #
    def auto_generate_challenge(self, category: str = "Web",
                               difficulty: str = "简单"
                               ) -> Dict[str, Any]:
        seed = uuid.uuid4().hex[:8]
        flag = "flag{" + hashlib.md5(seed.encode()).hexdigest()[:16] + "}"
        titles = {"Web": "万能密码与登录绕过",
                  "Reverse": "简单的异或校验",
                  "Pwn": "栈溢出入门",
                  "Crypto": "RSA 小指数攻击",
                  "Misc": "图片里的秘密"}
        result = {
            "category": category, "difficulty": difficulty,
            "title": titles.get(category, f"{category} 练习 {seed}"),
            "description": f"AI 自动生成的 {difficulty} 难度题目，"
                           f"seed={seed}。请分析并获取 flag。",
            "flag": flag,
            "hints": ["注意输入校验", "尝试常见绕过方式",
                      "观察返回信息"],
            "thought": self._think(
                f"自动出题：{category}/{difficulty}，已生成动态 flag"),
        }
        with self._lock:
            self._history.append(result)
        return result

    # ------------------------------------------------------------------ #
    def postmortem_analysis(self,
                           solve_stats: List[Dict[str, Any]]
                           ) -> Dict[str, Any]:
        if not solve_stats:
            return {"conclusion": "暂无数据", "thought": ""}
        over = [s for s in solve_stats if s.get("difficulty_gap", 0) > 0.2]
        under = [s for s in solve_stats if s.get("difficulty_gap", 0) < -0.2]
        result = {
            "too_easy": [s["title"] for s in over],
            "too_hard": [s["title"] for s in under],
            "conclusion": (f"{len(over)} 题偏易，{len(under)} 题偏难，"
                          f"建议下次调整难度梯度"),
            "thought": self._think("正在分析题目区分度与难度分布"),
        }
        with self._lock:
            self._history.append(result)
        return result

    def team_training_advice(self,
                            team_stats: Dict[str, Any]
                            ) -> List[str]:
        return [
            "每周固定 2 次 Web 专项训练，覆盖注入到反序列化",
            "赛前两周进行 AWD 攻防演练，熟悉防守与打流量",
            "建立队内 Writeup 库，赛后 48h 内完成复盘",
            "针对短板题型安排 1v1 讲解，每周轮换",
        ]

    def history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._history[-limit:])


_default: Optional[CtfAIAnalysis] = None


def get_ai_analysis() -> CtfAIAnalysis:
    global _default
    if _default is None:
        _default = CtfAIAnalysis()
    return _default
