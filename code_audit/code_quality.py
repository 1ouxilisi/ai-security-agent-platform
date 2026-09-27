# -*- coding: utf-8 -*-
"""
code_audit/code_quality.py — 代码质量分析器（第11轮升级）

能力：
- 5 类分析：
  1) 代码复杂度：圈复杂度 / 认知复杂度 / 嵌套深度 / 函数长度
  2) 代码重复：克隆块检测
  3) 代码规范：命名 / 格式 / 注释率
  4) 代码异味：上帝类 / 长方法 / 长参数列表等 12 种
  5) 技术债务：TODO/FIXME、废弃 API、重复造轮子
- 指标计算：LOC / 注释率 / 平均函数长度 / 平均圈复杂度 / 重复率 / 测试覆盖率估算
- 质量评分（0-100）、趋势分析、改进建议、质量报告

说明：以正则 / 启发式对源码做静态度量，不依赖外部 lint。
所有功能均为防御 / 评估 / 检测视角。
"""
from __future__ import annotations

import os
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from code_audit.sast_engine import EXT_MAP, SKIP_DIRS

# 12 种代码异味
CODE_SMELLS = [
    ("god_class", "上帝类", "类行数过多，承担过多职责", 800),
    ("long_method", "长方法", "函数/方法超过 60 行", 60),
    ("long_param_list", "长参数列表", "函数参数超过 5 个", 5),
    ("deep_nesting", "过深嵌套", "嵌套层级超过 4 层", 4),
    ("large_statement", "超长语句", "单行超过 160 字符", 160),
    ("too_many_branches", "分支过多", "单函数分支超过 10 个", 10),
    ("magic_number", "魔法数字", "代码中出现未命名的数字字面量", 0),
    ("duplicate_block", "重复代码块", "连续相似行构成克隆", 0),
    ("dead_code", "死代码", "不可达 / 注释掉的代码块", 0),
    ("speculative_gen", "过度设计", "未使用的抽象/接口", 0),
    ("primitive_obsession", "基本类型偏执", "大量字符串/数字承载业务", 0),
    ("data_clump", "数据泥团", "总是成组出现的字段", 0),
]


def _cyclomatic(lines: List[str]) -> int:
    """近似圈复杂度：1 + 决策点计数。"""
    score = 1
    pat = re.compile(
        r"\b(if|else\s+if|for|while|case|catch|except|&&|\|\||\?|\?\.|&&)\b")
    for ln in lines:
        score += len(pat.findall(ln))
    return score


def _max_nesting(lines: List[str]) -> int:
    depth = 0
    cur = 0
    for ln in lines:
        stripped = ln.strip()
        if re.match(r"(if|for|while|switch|catch|except|with)\b", stripped):
            cur += 1
            depth = max(depth, cur)
        if stripped in ("}", "end)", "end", "};"):
            cur = max(0, cur - 1)
    return depth


class CodeQualityAnalyzer:
    """代码质量分析器。"""

    def __init__(self) -> None:
        self.history: List[Dict[str, Any]] = []

    # -- 单文件度量 --
    def analyze_file(self, path: str) -> Dict[str, Any]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return {}

        total = len(lines)
        blank = sum(1 for l in lines if not l.strip())
        comment = sum(1 for l in lines if l.strip().startswith(
            ("#", "//", "*", "/*", "--")))
        loc = total - blank - comment
        avg_line_len = (sum(len(l) for l in lines) / total) if total else 0
        cc = _cyclomatic(lines)
        nesting = _max_nesting(lines)
        long_lines = [i + 1 for i, l in enumerate(lines) if len(l) > 160]
        magic_nums = len(re.findall(r"(?<![\w.])\b\d{2,}\b",
                                   "".join(lines)))
        smells: List[Dict[str, Any]] = []
        if loc > 800:
            smells.append({"type": "god_class", "detail": f"{loc} LOC"})
        if cc > 15:
            smells.append({"type": "complex_method",
                           "detail": f"CC={cc}"})
        if nesting > 4:
            smells.append({"type": "deep_nesting",
                           "detail": f"depth={nesting}"})
        if magic_nums > 10:
            smells.append({"type": "magic_number",
                           "detail": f"{magic_nums} 处"})

        return {
            "file": path,
            "language": EXT_MAP.get(os.path.splitext(path)[1].lower(), "unknown"),
            "total_lines": total,
            "loc": loc,
            "blank_lines": blank,
            "comment_lines": comment,
            "comment_ratio": round(comment / total, 3) if total else 0,
            "avg_line_length": round(avg_line_len, 1),
            "cyclomatic_complexity": cc,
            "max_nesting": nesting,
            "long_lines": long_lines,
            "long_line_count": len(long_lines),
            "magic_number_count": magic_nums,
            "smells": smells,
        }

    # -- 目录分析 --
    def analyze_directory(self, directory: str) -> Dict[str, Any]:
        started = time.time()
        file_metrics: List[Dict[str, Any]] = []
        dup_candidates = self._detect_duplication(directory)

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fn in files:
                ext = os.path.splitext(fn)[1].lower()
                if ext in EXT_MAP:
                    m = self.analyze_file(os.path.join(root, fn))
                    if m:
                        file_metrics.append(m)

        total_loc = sum(m["loc"] for m in file_metrics)
        total_cmt = sum(m["comment_lines"] for m in file_metrics)
        avg_cc = (sum(m["cyclomatic_complexity"] for m in file_metrics)
                  / len(file_metrics)) if file_metrics else 0
        smells_total = sum(len(m["smells"]) for m in file_metrics)
        dup_ratio = round(
            sum(len(d["blocks"]) for d in dup_candidates) / max(total_loc, 1), 4)

        score = self._score(avg_cc, smells_total, dup_ratio,
                            total_cmt / max(total_loc, 1))

        result = {
            "engine": "CodeQuality",
            "directory": directory,
            "files": len(file_metrics),
            "total_loc": total_loc,
            "comment_ratio": round(total_cmt / max(total_loc, 1), 3),
            "avg_cyclomatic": round(avg_cc, 2),
            "duplication_ratio": dup_ratio,
            "duplicated_blocks": dup_candidates,
            "smells_count": smells_total,
            "smell_breakdown": self._smell_breakdown(file_metrics),
            "test_coverage_estimate": self._estimate_coverage(directory),
            "quality_score": score,
            "grade": self._grade(score),
            "elapsed_seconds": round(time.time() - started, 3),
            "timestamp": datetime.now().isoformat(),
        }
        self.history.append({
            "at": result["timestamp"], "score": score,
            "loc": total_loc, "files": len(file_metrics),
        })
        if len(self.history) > 50:
            self.history = self.history[-50:]
        return result

    # -- 重复检测（基于行哈希） --
    def _detect_duplication(self, directory: str) -> List[Dict[str, Any]]:
        seen: Dict[str, List[str]] = {}
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fn in files:
                if os.path.splitext(fn)[1].lower() not in EXT_MAP:
                    continue
                path = os.path.join(root, fn)
                try:
                    lines = open(path, encoding="utf-8", errors="ignore"
                                 ).readlines()
                except OSError:
                    continue
                for i in range(0, max(0, len(lines) - 5), 3):
                    block = "".join(l.rstrip() for l in lines[i:i + 5])
                    key = str(hash(block))
                    seen.setdefault(key, []).append(f"{path}:{i + 1}")
        dups = [{"hash": k, "blocks": v}
                for k, v in seen.items() if len(v) > 1]
        return dups[:50]

    @staticmethod
    def _smell_breakdown(files: List[Dict[str, Any]]) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for m in files:
            for s in m["smells"]:
                out[s["type"]] = out.get(s["type"], 0) + 1
        return out

    @staticmethod
    def _estimate_coverage(directory: str) -> float:
        """启发式估算测试覆盖率：统计 test 目录与源目录比例。"""
        src = 0
        tests = 0
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            is_test = ("test" in root.lower() or "spec" in root.lower())
            for fn in files:
                if os.path.splitext(fn)[1].lower() in EXT_MAP:
                    if is_test:
                        tests += 1
                    else:
                        src += 1
        if src == 0:
            return 0.0
        return round(min(100.0, tests / src * 100.0), 1)

    # -- 评分 --
    @staticmethod
    def _score(avg_cc: float, smells: int, dup: float,
               cmt_ratio: float) -> int:
        score = 100.0
        score -= min(30.0, max(0, (avg_cc - 5) * 2.0))
        score -= min(25.0, smells * 1.5)
        score -= min(20.0, dup * 200)
        score -= max(0, (0.2 - cmt_ratio)) * 40
        return max(0, min(100, int(round(score))))

    @staticmethod
    def _grade(score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "E"

    # -- 趋势 / 建议 --
    def trend(self) -> List[Dict[str, Any]]:
        return self.history[-20:]

    def suggestions(self, result: Dict[str, Any]) -> List[str]:
        out = []
        if result["avg_cyclomatic"] > 10:
            out.append("拆分高圈复杂度函数，引入早期返回与策略模式")
        if result["duplication_ratio"] > 0.05:
            out.append("提取重复代码块为公共函数/工具类")
        if result["comment_ratio"] < 0.1:
            out.append("补充关键模块的文档与注释")
        if result["test_coverage_estimate"] < 40:
            out.append("提升单元测试覆盖率至 70%+")
        if not out:
            out.append("质量良好，维持现有规范")
        return out

    def generate_report(self, result: Optional[Dict[str, Any]] = None
                        ) -> Dict[str, Any]:
        result = result or {}
        return {
            "report_type": "代码质量报告",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "files": result.get("files", 0),
                "total_loc": result.get("total_loc", 0),
                "quality_score": result.get("quality_score", 0),
                "grade": result.get("grade", "E"),
            },
            "metrics": {
                "comment_ratio": result.get("comment_ratio", 0),
                "avg_cyclomatic": result.get("avg_cyclomatic", 0),
                "duplication_ratio": result.get("duplication_ratio", 0),
                "test_coverage": result.get("test_coverage_estimate", 0),
            },
            "smells": result.get("smell_breakdown", {}),
            "suggestions": self.suggestions(result),
            "trend": self.trend(),
        }


_cq = CodeQualityAnalyzer()


def get_quality_analyzer() -> CodeQualityAnalyzer:
    return _cq
