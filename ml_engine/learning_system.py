#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
learning_system模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, Counter

from utils.logger import log


@dataclass
class LearningCase:
    """学习案例"""
    case_id: str
    target: str
    target_type: str = ""
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    success: bool = False
    total_actions: int = 0
    successful_actions: int = 0
    failed_actions: int = 0
    vulnerabilities_found: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities_exploited: List[Dict[str, Any]] = field(default_factory=list)
    tools_used: List[Dict[str, Any]] = field(default_factory=list)
    attack_chain: List[str] = field(default_factory=list)
    duration_seconds: float = 0
    notes: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "case_id": self.case_id,
            "target": self.target,
            "target_type": self.target_type,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "success": self.success,
            "total_actions": self.total_actions,
            "successful_actions": self.successful_actions,
            "failed_actions": self.failed_actions,
            "vulnerabilities_found": self.vulnerabilities_found,
            "vulnerabilities_exploited": self.vulnerabilities_exploited,
            "tools_used": self.tools_used,
            "attack_chain": self.attack_chain,
            "duration_seconds": self.duration_seconds,
            "notes": self.notes,
            "tags": self.tags
        }


@dataclass
class ToolPerformance:
    """工具性能统计"""
    tool_name: str
    total_uses: int = 0
    successful_uses: int = 0
    failed_uses: int = 0
    avg_duration_ms: float = 0
    total_findings: int = 0
    success_rate: float = 0.0
    best_for: List[str] = field(default_factory=list)  # 最适合的场景
    worst_for: List[str] = field(default_factory=list)  # 最不适合的场景

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "tool_name": self.tool_name,
            "total_uses": self.total_uses,
            "successful_uses": self.successful_uses,
            "failed_uses": self.failed_uses,
            "avg_duration_ms": round(self.avg_duration_ms, 2),
            "total_findings": self.total_findings,
            "success_rate": round(self.success_rate * 100, 2),
            "best_for": self.best_for[:5],
            "worst_for": self.worst_for[:5]
        }


@dataclass
class StrategyPattern:
    """策略模式"""
    pattern_id: str
    name: str
    description: str
    pattern_type: str = "success"  # success/failure
    frequency: int = 0
    confidence: float = 0.0
    conditions: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    avoid_actions: List[str] = field(default_factory=list)
    related_cases: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "pattern_id": self.pattern_id,
            "name": self.name,
            "description": self.description,
            "pattern_type": self.pattern_type,
            "frequency": self.frequency,
            "confidence": round(self.confidence * 100, 2),
            "conditions": self.conditions,
            "recommended_actions": self.recommended_actions,
            "avoid_actions": self.avoid_actions,
            "related_cases": self.related_cases[:10]
        }


class ContinuousLearningSystem:
    """持续学习系统"""

    def __init__(self, data_dir: str = "data/learning"):
        """初始化ContinuousLearningSystem实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.cases: Dict[str, LearningCase] = {}
        self.tool_performances: Dict[str, ToolPerformance] = {}
        self.patterns: Dict[str, StrategyPattern] = {}
        self.learning_iterations: int = 0

        os.makedirs(data_dir, exist_ok=True)
        self._load_data()

    def _load_data(self):
        """从文件加载数据"""
        # 加载案例
        cases_file = os.path.join(self.data_dir, "cases.json")
        if os.path.exists(cases_file):
            try:
                with open(cases_file, 'r', encoding='utf-8') as f:
                    cases_data = json.load(f)
                for case_id, case_data in cases_data.items():
                    self.cases[case_id] = LearningCase(**case_data)
            except Exception as e:
                log.error(f"加载学习案例失败: {e}")

        # 加载工具性能
        tools_file = os.path.join(self.data_dir, "tool_performances.json")
        if os.path.exists(tools_file):
            try:
                with open(tools_file, 'r', encoding='utf-8') as f:
                    tools_data = json.load(f)
                for tool_name, tool_data in tools_data.items():
                    self.tool_performances[tool_name] = ToolPerformance(**tool_data)
            except Exception as e:
                log.error(f"加载工具性能失败: {e}")

        # 加载策略模式
        patterns_file = os.path.join(self.data_dir, "patterns.json")
        if os.path.exists(patterns_file):
            try:
                with open(patterns_file, 'r', encoding='utf-8') as f:
                    patterns_data = json.load(f)
                for pattern_id, pattern_data in patterns_data.items():
                    self.patterns[pattern_id] = StrategyPattern(**pattern_data)
            except Exception as e:
                log.error(f"加载策略模式失败: {e}")

    def _save_data(self):
        """保存数据到文件"""
        # 保存案例
        cases_file = os.path.join(self.data_dir, "cases.json")
        try:
            cases_data = {cid: c.to_dict() for cid, c in self.cases.items()}
            with open(cases_file, 'w', encoding='utf-8') as f:
                json.dump(cases_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存学习案例失败: {e}")

        # 保存工具性能
        tools_file = os.path.join(self.data_dir, "tool_performances.json")
        try:
            tools_data = {name: tp.to_dict() for name, tp in self.tool_performances.items()}
            with open(tools_file, 'w', encoding='utf-8') as f:
                json.dump(tools_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存工具性能失败: {e}")

        # 保存策略模式
        patterns_file = os.path.join(self.data_dir, "patterns.json")
        try:
            patterns_data = {pid: p.to_dict() for pid, p in self.patterns.items()}
            with open(patterns_file, 'w', encoding='utf-8') as f:
                json.dump(patterns_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存策略模式失败: {e}")

    # ===== 案例管理 =====
    def record_case(self, target: str, target_type: str = "",
                    success: bool = False, total_actions: int = 0,
                    successful_actions: int = 0, failed_actions: int = 0,
                    vulnerabilities_found: List[Dict] = None,
                    vulnerabilities_exploited: List[Dict] = None,
                    tools_used: List[Dict] = None,
                    attack_chain: List[str] = None,
                    duration_seconds: float = 0,
                    notes: str = "", tags: List[str] = None) -> str:
        """记录学习案例"""
        case_id = f"case-{uuid.uuid4().hex[:8]}"
        case = LearningCase(
            case_id=case_id,
            target=target,
            target_type=target_type,
            success=success,
            total_actions=total_actions,
            successful_actions=successful_actions,
            failed_actions=failed_actions,
            vulnerabilities_found=vulnerabilities_found or [],
            vulnerabilities_exploited=vulnerabilities_exploited or [],
            tools_used=tools_used or [],
            attack_chain=attack_chain or [],
            duration_seconds=duration_seconds,
            notes=notes,
            tags=tags or []
        )
        case.completed_at = time.time()
        self.cases[case_id] = case

        # 更新工具性能
        for tool in tools_used or []:
            self._update_tool_performance(tool)

        self._save_data()
        log.info(f"记录学习案例: {case_id}, 目标={target}, 成功={success}")
        return case_id

    def _update_tool_performance(self, tool_data: Dict[str, Any]):
        """更新工具性能统计"""
        tool_name = tool_data.get("name", "unknown")
        success = tool_data.get("success", False)
        duration = tool_data.get("duration_ms", 0)
        findings = tool_data.get("findings", 0)
        scenario = tool_data.get("scenario", "")

        if tool_name not in self.tool_performances:
            self.tool_performances[tool_name] = ToolPerformance(tool_name=tool_name)

        tp = self.tool_performances[tool_name]
        tp.total_uses += 1
        if success:
            tp.successful_uses += 1
            if scenario and scenario not in tp.best_for:
                tp.best_for.append(scenario)
        else:
            tp.failed_uses += 1
            if scenario and scenario not in tp.worst_for:
                tp.worst_for.append(scenario)

        tp.avg_duration_ms = (tp.avg_duration_ms * (tp.total_uses - 1) + duration) / tp.total_uses
        tp.total_findings += findings
        tp.success_rate = tp.successful_uses / tp.total_uses if tp.total_uses > 0 else 0

    # ===== 模式分析 =====
    def analyze_patterns(self):
        """分析成功/失败模式"""
        if len(self.cases) < 3:
            log.info("案例不足3个，跳过模式分析")
            return

        self.learning_iterations += 1
        new_patterns = []

        # 分析成功案例的共同特征
        success_cases = [c for c in self.cases.values() if c.success]
        failure_cases = [c for c in self.cases.values() if not c.success]

        # 模式1：成功案例中最常用的工具组合
        if success_cases:
            tool_combinations = Counter()
            for case in success_cases:
                tools = tuple(sorted(t.get("name", "") for t in case.tools_used))
                tool_combinations[tools] += 1

            top_combo = tool_combinations.most_common(1)
            if top_combo and top_combo[0][1] >= 2:
                pattern = StrategyPattern(
                    pattern_id=f"pat-{uuid.uuid4().hex[:6]}",
                    name="高效工具组合",
                    description=f"以下工具组合在成功案例中频繁出现: {', '.join(top_combo[0][0])}",
                    pattern_type="success",
                    frequency=top_combo[0][1],
                    confidence=top_combo[0][1] / len(success_cases),
                    conditions=["目标类型匹配"],
                    recommended_actions=list(top_combo[0][0]),
                    related_cases=[c.case_id for c in success_cases[:5]]
                )
                self.patterns[pattern.pattern_id] = pattern
                new_patterns.append(pattern)

        # 模式2：失败案例中常见的无效操作
        if failure_cases:
            failed_tools = Counter()
            for case in failure_cases:
                for tool in case.tools_used:
                    if not tool.get("success", False):
                        failed_tools[tool.get("name", "")] += 1

            top_failed = failed_tools.most_common(3)
            if top_failed:
                pattern = StrategyPattern(
                    pattern_id=f"pat-{uuid.uuid4().hex[:6]}",
                    name="低效工具预警",
                    description=f"以下工具在失败案例中频繁失败: {', '.join(t[0] for t in top_failed)}",
                    pattern_type="failure",
                    frequency=sum(t[1] for t in top_failed),
                    confidence=0.7,
                    conditions=["类似目标场景"],
                    avoid_actions=[t[0] for t in top_failed],
                    related_cases=[c.case_id for c in failure_cases[:5]]
                )
                self.patterns[pattern.pattern_id] = pattern
                new_patterns.append(pattern)

        # 模式3：最有效的攻击链
        if success_cases:
            chain_counter = Counter()
            for case in success_cases:
                if case.attack_chain:
                    chain_counter[tuple(case.attack_chain)] += 1

            top_chain = chain_counter.most_common(1)
            if top_chain and top_chain[0][1] >= 2:
                pattern = StrategyPattern(
                    pattern_id=f"pat-{uuid.uuid4().hex[:6]}",
                    name="推荐攻击链",
                    description=f"以下攻击链在成功案例中验证有效: {' -> '.join(top_chain[0][0])}",
                    pattern_type="success",
                    frequency=top_chain[0][1],
                    confidence=top_chain[0][1] / len(success_cases),
                    conditions=["目标类型匹配"],
                    recommended_actions=list(top_chain[0][0]),
                    related_cases=[c.case_id for c in success_cases[:5]]
                )
                self.patterns[pattern.pattern_id] = pattern
                new_patterns.append(pattern)

        self._save_data()
        log.info(f"模式分析完成: 发现{len(new_patterns)}个新模式，累计{len(self.patterns)}个模式")
        return new_patterns

    # ===== 策略优化建议 =====
    def get_optimization_suggestions(self, target_type: str = "") -> List[Dict[str, Any]]:
        """获取策略优化建议"""
        suggestions = []

        # 基于工具性能的建议
        for tp in sorted(self.tool_performances.values(), key=lambda x: x.success_rate, reverse=True):
            if tp.total_uses >= 3:
                if tp.success_rate >= 0.8:
                    suggestions.append({
                        "type": "tool_recommendation",
                        "tool": tp.tool_name,
                        "suggestion": f"工具 {tp.tool_name} 成功率 {tp.success_rate*100:.1f}%，建议优先使用",
                        "confidence": tp.success_rate,
                        "evidence": f"共使用{tp.total_uses}次，成功{tp.successful_uses}次"
                    })
                elif tp.success_rate <= 0.3:
                    suggestions.append({
                        "type": "tool_warning",
                        "tool": tp.tool_name,
                        "suggestion": f"工具 {tp.tool_name} 成功率仅 {tp.success_rate*100:.1f}%，建议谨慎使用或替换",
                        "confidence": 1 - tp.success_rate,
                        "evidence": f"共使用{tp.total_uses}次，失败{tp.failed_uses}次"
                    })

        # 基于模式的建议
        for pattern in self.patterns.values():
            if pattern.pattern_type == "success" and pattern.confidence >= 0.6:
                suggestions.append({
                    "type": "pattern_recommendation",
                    "pattern": pattern.name,
                    "suggestion": pattern.description,
                    "recommended_actions": pattern.recommended_actions,
                    "confidence": pattern.confidence,
                    "evidence": f"在{pattern.frequency}个案例中出现"
                })
            elif pattern.pattern_type == "failure" and pattern.confidence >= 0.6:
                suggestions.append({
                    "type": "pattern_warning",
                    "pattern": pattern.name,
                    "suggestion": pattern.description,
                    "avoid_actions": pattern.avoid_actions,
                    "confidence": pattern.confidence,
                    "evidence": f"在{pattern.frequency}个案例中出现"
                })

        # 基于案例统计的建议
        if self.cases:
            avg_duration = sum(c.duration_seconds for c in self.cases.values()) / len(self.cases)
            avg_actions = sum(c.total_actions for c in self.cases.values()) / len(self.cases)
            success_rate = sum(1 for c in self.cases.values() if c.success) / len(self.cases)

            suggestions.append({
                "type": "performance_summary",
                "suggestion": f"历史统计: 平均耗时{avg_duration:.0f}秒, 平均操作{avg_actions:.1f}次, 成功率{success_rate*100:.1f}%",
                "confidence": 1.0,
                "evidence": f"基于{len(self.cases)}个历史案例"
            })

        return suggestions[:10]  # 最多返回10条建议

    # ===== 学习报告 =====
    def generate_learning_report(self) -> Dict[str, Any]:
        """生成学习报告"""
        total_cases = len(self.cases)
        success_cases = sum(1 for c in self.cases.values() if c.success)
        failure_cases = total_cases - success_cases

        # 漏洞统计
        all_vulns = []
        for case in self.cases.values():
            all_vulns.extend(case.vulnerabilities_found)
        vuln_counter = Counter(v.get("type", "unknown") for v in all_vulns)

        # 工具排名
        tool_ranking = sorted(
            self.tool_performances.values(),
            key=lambda x: x.success_rate * x.total_uses,
            reverse=True
        )[:10]

        # 最有效的攻击链
        chain_counter = Counter()
        for case in self.cases.values():
            if case.attack_chain and case.success:
                chain_counter[tuple(case.attack_chain)] += 1

        report = {
            "report_title": "持续学习系统报告",
            "generated_at": time.time(),
            "learning_iterations": self.learning_iterations,
            "summary": {
                "total_cases": total_cases,
                "success_cases": success_cases,
                "failure_cases": failure_cases,
                "success_rate": round(success_cases / total_cases * 100, 2) if total_cases > 0 else 0,
                "total_vulnerabilities_found": len(all_vulns),
                "total_tools_tracked": len(self.tool_performances),
                "total_patterns": len(self.patterns)
            },
            "vulnerability_distribution": dict(vuln_counter.most_common(10)),
            "tool_ranking": [tp.to_dict() for tp in tool_ranking],
            "top_attack_chains": [
                {"chain": list(chain), "frequency": freq}
                for chain, freq in chain_counter.most_common(5)
            ],
            "patterns": [p.to_dict() for p in self.patterns.values()],
            "optimization_suggestions": self.get_optimization_suggestions()
        }

        return report

    # ===== 统计 =====
    def get_statistics(self) -> Dict[str, Any]:
        """获取系统统计"""
        return {
            "total_cases": len(self.cases),
            "success_rate": round(sum(1 for c in self.cases.values() if c.success) / len(self.cases) * 100, 2) if self.cases else 0,
            "tools_tracked": len(self.tool_performances),
            "patterns_discovered": len(self.patterns),
            "learning_iterations": self.learning_iterations,
            "total_vulnerabilities": sum(len(c.vulnerabilities_found) for c in self.cases.values()),
            "avg_duration_seconds": round(sum(c.duration_seconds for c in self.cases.values()) / len(self.cases), 2) if self.cases else 0
        }


# 全局实例
learning_system = ContinuousLearningSystem()
