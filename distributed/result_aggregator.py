#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式结果汇总器模块，支持多节点扫描结果合并、漏洞去重、风险评分和报告生成。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import re
import json
import hashlib
import logging
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AggregatedResult:
    """汇总结果"""
    task_id: str
    target: str
    total_scans: int = 0
    total_ports: int = 0
    open_ports: int = 0
    filtered_ports: int = 0
    total_vulnerabilities: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    info_vulns: int = 0
    unique_services: List[str] = field(default_factory=list)
    unique_technologies: List[str] = field(default_factory=list)
    worker_contributions: Dict[str, int] = field(default_factory=dict)
    scan_duration: float = 0.0
    started_at: str = ""
    completed_at: str = ""
    status: str = "pending"  # pending, scanning, completed, failed
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "task_id": self.task_id,
            "target": self.target,
            "total_scans": self.total_scans,
            "total_ports": self.total_ports,
            "open_ports": self.open_ports,
            "filtered_ports": self.filtered_ports,
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_vulns": self.critical_vulns,
            "high_vulns": self.high_vulns,
            "medium_vulns": self.medium_vulns,
            "low_vulns": self.low_vulns,
            "info_vulns": self.info_vulns,
            "unique_services": self.unique_services,
            "unique_technologies": self.unique_technologies,
            "worker_contributions": self.worker_contributions,
            "scan_duration": self.scan_duration,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "error": self.error,
        }


class ResultAggregator:
    """结果汇总器"""

    def __init__(self):
        """初始化ResultAggregator实例。

        Args:
            self: 类实例。
        """
        self.results: Dict[str, AggregatedResult] = {}
        self.raw_results: List[Dict[str, Any]] = []
        self.deduplicated_vulns: Set[str] = set()

    def start_aggregation(self, task_id: str, target: str) -> AggregatedResult:
        """开始汇总"""
        result = AggregatedResult(
            task_id=task_id,
            target=target,
            status="scanning",
            started_at=datetime.now().isoformat(),
        )
        self.results[task_id] = result
        return result

    def add_scan_result(self, task_id: str, worker_id: str, scan_data: Dict[str, Any]) -> bool:
        """添加扫描结果"""
        if task_id not in self.results:
            logger.error(f"任务 {task_id} 不存在")
            return False

        result = self.results[task_id]
        result.total_scans += 1

        # 统计端口
        if 'ports' in scan_data:
            ports = scan_data['ports']
            result.total_ports += len(ports)
            result.open_ports += sum(1 for p in ports if p.get('state') == 'open')
            result.filtered_ports += sum(1 for p in ports if p.get('state') == 'filtered')

            # 收集唯一服务
            for port in ports:
                service = port.get('service', '')
                if service and service not in result.unique_services:
                    result.unique_services.append(service)

        # 统计漏洞
        if 'vulnerabilities' in scan_data:
            vulns = scan_data['vulnerabilities']
            for vuln in vulns:
                # 去重
                vuln_key = self._generate_vuln_key(vuln)
                if vuln_key in self.deduplicated_vulns:
                    continue
                self.deduplicated_vulns.add(vuln_key)

                result.total_vulnerabilities += 1
                severity = vuln.get('severity', 'info').lower()
                if severity == 'critical':
                    result.critical_vulns += 1
                elif severity == 'high':
                    result.high_vulns += 1
                elif severity == 'medium':
                    result.medium_vulns += 1
                elif severity == 'low':
                    result.low_vulns += 1
                else:
                    result.info_vulns += 1

        # 收集技术
        if 'technologies' in scan_data:
            for tech in scan_data['technologies']:
                if tech not in result.unique_technologies:
                    result.unique_technologies.append(tech)

        # 工作节点贡献
        result.worker_contributions[worker_id] = result.worker_contributions.get(worker_id, 0) + 1

        # 保存原始结果
        self.raw_results.append({
            'task_id': task_id,
            'worker_id': worker_id,
            'data': scan_data,
            'timestamp': datetime.now().isoformat(),
        })

        return True

    def complete_aggregation(self, task_id: str) -> Optional[AggregatedResult]:
        """完成汇总"""
        if task_id not in self.results:
            return None

        result = self.results[task_id]
        result.status = "completed"
        result.completed_at = datetime.now().isoformat()
        if result.started_at:
            start = datetime.fromisoformat(result.started_at)
            end = datetime.fromisoformat(result.completed_at)
            result.scan_duration = (end - start).total_seconds()

        logger.info(f"任务 {task_id} 汇总完成: {result.total_vulnerabilities} 个漏洞, {result.open_ports} 个开放端口")
        return result

    def fail_aggregation(self, task_id: str, error: str) -> Optional[AggregatedResult]:
        """标记汇总失败"""
        if task_id not in self.results:
            return None

        result = self.results[task_id]
        result.status = "failed"
        result.error = error
        result.completed_at = datetime.now().isoformat()
        return result

    def get_result(self, task_id: str) -> Optional[AggregatedResult]:
        """获取汇总结果"""
        return self.results.get(task_id)

    def list_results(self, status: str = "") -> List[AggregatedResult]:
        """列出汇总结果"""
        if status:
            return [r for r in self.results.values() if r.status == status]
        return list(self.results.values())

    def get_vulnerability_summary(self, task_id: str) -> Dict[str, Any]:
        """获取漏洞摘要"""
        result = self.get_result(task_id)
        if not result:
            return {}

        return {
            "task_id": task_id,
            "target": result.target,
            "total": result.total_vulnerabilities,
            "by_severity": {
                "critical": result.critical_vulns,
                "high": result.high_vulns,
                "medium": result.medium_vulns,
                "low": result.low_vulns,
                "info": result.info_vulns,
            },
            "risk_score": self._calculate_risk_score(result),
            "unique_services": result.unique_services,
            "unique_technologies": result.unique_technologies,
        }

    def get_worker_contributions(self, task_id: str) -> Dict[str, Any]:
        """获取工作节点贡献统计"""
        result = self.get_result(task_id)
        if not result:
            return {}

        total = sum(result.worker_contributions.values())
        contributions = []
        for worker_id, count in sorted(result.worker_contributions.items(), key=lambda x: x[1], reverse=True):
            contributions.append({
                "worker_id": worker_id,
                "scans": count,
                "percentage": f"{count/total*100:.1f}%" if total > 0 else "0%",
            })

        return {
            "task_id": task_id,
            "total_scans": total,
            "total_workers": len(result.worker_contributions),
            "contributions": contributions,
        }

    def merge_results(self, task_ids: List[str], merged_task_id: str = "") -> AggregatedResult:
        """合并多个任务结果"""
        if not merged_task_id:
            merged_task_id = f"merged_{datetime.now().strftime('%Y%m%d%H%M%S')}"

        merged = AggregatedResult(
            task_id=merged_task_id,
            target="multiple",
            status="completed",
            started_at=datetime.now().isoformat(),
            completed_at=datetime.now().isoformat(),
        )

        all_services = set()
        all_technologies = set()

        for task_id in task_ids:
            result = self.get_result(task_id)
            if not result:
                continue

            merged.total_scans += result.total_scans
            merged.total_ports += result.total_ports
            merged.open_ports += result.open_ports
            merged.filtered_ports += result.filtered_ports
            merged.total_vulnerabilities += result.total_vulnerabilities
            merged.critical_vulns += result.critical_vulns
            merged.high_vulns += result.high_vulns
            merged.medium_vulns += result.medium_vulns
            merged.low_vulns += result.low_vulns
            merged.info_vulns += result.info_vulns

            all_services.update(result.unique_services)
            all_technologies.update(result.unique_technologies)

            for worker_id, count in result.worker_contributions.items():
                merged.worker_contributions[worker_id] = merged.worker_contributions.get(worker_id, 0) + count

        merged.unique_services = list(all_services)
        merged.unique_technologies = list(all_technologies)
        self.results[merged_task_id] = merged

        return merged

    def export_report(self, task_id: str, format: str = "json") -> str:
        """导出报告"""
        result = self.get_result(task_id)
        if not result:
            return ""

        if format == "json":
            return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
        elif format == "markdown":
            return self._generate_markdown_report(result)
        elif format == "csv":
            return self._generate_csv_report(result)
        return ""

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total = len(self.results)
        completed = sum(1 for r in self.results.values() if r.status == "completed")
        scanning = sum(1 for r in self.results.values() if r.status == "scanning")
        failed = sum(1 for r in self.results.values() if r.status == "failed")

        total_vulns = sum(r.total_vulnerabilities for r in self.results.values())
        total_ports = sum(r.open_ports for r in self.results.values())
        total_scans = sum(r.total_scans for r in self.results.values())

        return {
            "total_tasks": total,
            "completed": completed,
            "scanning": scanning,
            "failed": failed,
            "total_scans": total_scans,
            "total_open_ports": total_ports,
            "total_vulnerabilities": total_vulns,
            "deduplicated_vulns": len(self.deduplicated_vulns),
            "raw_results_count": len(self.raw_results),
        }

    def _generate_vuln_key(self, vuln: Dict[str, Any]) -> str:
        """生成漏洞唯一键"""
        key_parts = [
            vuln.get('url', ''),
            vuln.get('vulnerability', ''),
            vuln.get('parameter', ''),
            vuln.get('cve', ''),
        ]
        key_str = '|'.join(key_parts)
        return hashlib.md5(key_str.encode()).hexdigest()

    def _calculate_risk_score(self, result: AggregatedResult) -> int:
        """计算风险评分"""
        score = 0
        score += result.critical_vulns * 25
        score += result.high_vulns * 10
        score += result.medium_vulns * 5
        score += result.low_vulns * 2
        score += result.open_ports * 0.5
        return min(int(score), 100)

    def _generate_markdown_report(self, result: AggregatedResult) -> str:
        """生成Markdown报告"""
        lines = [
            f"# 扫描报告 - {result.target}",
            "",
            f"**任务ID**: {result.task_id}",
            f"**扫描时间**: {result.started_at} 至 {result.completed_at}",
            f"**扫描时长**: {result.scan_duration:.2f} 秒",
            f"**扫描次数**: {result.total_scans}",
            "",
            "## 端口统计",
            "",
            f"- 总端口数: {result.total_ports}",
            f"- 开放端口: {result.open_ports}",
            f"- 过滤端口: {result.filtered_ports}",
            "",
            "## 漏洞统计",
            "",
            f"- 总漏洞数: {result.total_vulnerabilities}",
            f"- 严重: {result.critical_vulns}",
            f"- 高危: {result.high_vulns}",
            f"- 中危: {result.medium_vulns}",
            f"- 低危: {result.low_vulns}",
            f"- 信息: {result.info_vulns}",
            "",
            "## 发现的服务",
            "",
        ]
        for service in result.unique_services:
            lines.append(f"- {service}")
        lines.extend([
            "",
            "## 工作节点贡献",
            "",
        ])
        for worker_id, count in result.worker_contributions.items():
            lines.append(f"- {worker_id}: {count} 次扫描")
        return "\n".join(lines)

    def _generate_csv_report(self, result: AggregatedResult) -> str:
        """生成CSV报告"""
        lines = ["指标,数值"]
        lines.append(f"任务ID,{result.task_id}")
        lines.append(f"目标,{result.target}")
        lines.append(f"扫描次数,{result.total_scans}")
        lines.append(f"总端口数,{result.total_ports}")
        lines.append(f"开放端口,{result.open_ports}")
        lines.append(f"总漏洞数,{result.total_vulnerabilities}")
        lines.append(f"严重漏洞,{result.critical_vulns}")
        lines.append(f"高危漏洞,{result.high_vulns}")
        lines.append(f"中危漏洞,{result.medium_vulns}")
        lines.append(f"低危漏洞,{result.low_vulns}")
        lines.append(f"扫描时长,{result.scan_duration}")
        return "\n".join(lines)


# 全局实例
result_aggregator = ResultAggregator()
