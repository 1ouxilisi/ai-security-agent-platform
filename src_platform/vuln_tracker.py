#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_tracker模块，提供相关安全测试功能。

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
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

from utils.logger import log


class SubmissionStatus(str, Enum):
    """提交状态"""
    DRAFT = "draft"  # 草稿
    SUBMITTED = "submitted"  # 已提交
    TRIAGED = "triaged"  # 已分诊（有效）
    NEEDS_MORE_INFO = "needs_more_info"  # 需要更多信息
    RESOLVED = "resolved"  # 已解决（已奖励）
    DUPLICATE = "duplicate"  # 重复
    NOT_APPLICABLE = "not_applicable"  # 不适用
    INFORMATIVE = "informative"  # 信息性
    SPAM = "spam"  # 垃圾
    DISPUTED = "disputed"  # 有争议
    CLOSED = "closed"  # 已关闭


class BountyStatus(str, Enum):
    """奖励状态"""
    NONE = "none"  # 无奖励
    PENDING = "pending"  # 待发放
    AWARDED = "awarded"  # 已发放
    PARTIAL = "partial"  # 部分奖励


@dataclass
class VulnerabilitySubmission:
    """漏洞提交记录"""
    submission_id: str
    target_id: str  # 所属目标项目
    target_name: str = ""
    platform: str = "hackerone"  # hackerone/bugcrowd/intigriti/yeswehack
    platform_report_id: str = ""  # 平台上的报告ID
    title: str = ""
    severity: str = "medium"  # critical/high/medium/low/none
    weakness: str = ""  # CWE编号
    cve_id: str = ""
    url: str = ""
    parameter: str = ""
    status: SubmissionStatus = SubmissionStatus.DRAFT
    bounty_status: BountyStatus = BountyStatus.NONE
    bounty_amount: float = 0.0
    currency: str = "USD"
    bonus_amount: float = 0.0  # 额外奖励
    submitted_at: Optional[float] = None
    triaged_at: Optional[float] = None
    resolved_at: Optional[float] = None
    bounty_awarded_at: Optional[float] = None
    first_response_at: Optional[float] = None  # 首次响应时间
    time_to_triage: float = 0.0  # 分诊耗时（小时）
    time_to_resolve: float = 0.0  # 解决耗时（小时）
    time_to_bounty: float = 0.0  # 奖励发放耗时（小时）
    duplicate_of: str = ""  # 重复的原始报告ID
    duplicate_count: int = 0  # 被重复次数
    reporter_feedback: str = ""  # 报告者反馈
    program_feedback: str = ""  # 项目方反馈
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    timeline: List[Dict[str, Any]] = field(default_factory=list)  # 事件时间线

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "submission_id": self.submission_id,
            "target_id": self.target_id,
            "target_name": self.target_name,
            "platform": self.platform,
            "platform_report_id": self.platform_report_id,
            "title": self.title,
            "severity": self.severity,
            "weakness": self.weakness,
            "cve_id": self.cve_id,
            "url": self.url,
            "parameter": self.parameter,
            "status": self.status.value,
            "bounty_status": self.bounty_status.value,
            "bounty_amount": self.bounty_amount,
            "currency": self.currency,
            "bonus_amount": self.bonus_amount,
            "total_earned": self.bounty_amount + self.bonus_amount,
            "submitted_at": self.submitted_at,
            "triaged_at": self.triaged_at,
            "resolved_at": self.resolved_at,
            "bounty_awarded_at": self.bounty_awarded_at,
            "first_response_at": self.first_response_at,
            "time_to_triage_hours": round(self.time_to_triage, 2),
            "time_to_resolve_hours": round(self.time_to_resolve, 2),
            "time_to_bounty_hours": round(self.time_to_bounty, 2),
            "duplicate_of": self.duplicate_of,
            "duplicate_count": self.duplicate_count,
            "tags": self.tags,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }


@dataclass
class EarningsRecord:
    """收益记录"""
    record_id: str
    submission_id: str = ""
    target_id: str = ""
    target_name: str = ""
    platform: str = ""
    amount: float = 0.0
    currency: str = "USD"
    type: str = "bounty"  # bounty/bonus/swag/referral
    description: str = ""
    awarded_at: float = field(default_factory=time.time)
    payout_status: str = "pending"  # pending/paid
    paid_at: Optional[float] = None
    payment_method: str = ""  # paypal/crypto/bank
    transaction_id: str = ""
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "record_id": self.record_id,
            "submission_id": self.submission_id,
            "target_id": self.target_id,
            "target_name": self.target_name,
            "platform": self.platform,
            "amount": self.amount,
            "currency": self.currency,
            "type": self.type,
            "description": self.description,
            "awarded_at": self.awarded_at,
            "payout_status": self.payout_status,
            "paid_at": self.paid_at,
            "payment_method": self.payment_method,
            "transaction_id": self.transaction_id,
            "notes": self.notes
        }


class SRCVulnerabilityTracker:
    """SRC漏洞跟踪系统"""

    def __init__(self, data_dir: str = "data/src_platform/tracker"):
        """初始化SRCVulnerabilityTracker实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.submissions: Dict[str, VulnerabilitySubmission] = {}
        self.earnings: Dict[str, EarningsRecord] = {}
        os.makedirs(data_dir, exist_ok=True)
        self._load_data()

    def _load_data(self):
        """从文件加载数据"""
        subs_file = os.path.join(self.data_dir, "submissions.json")
        if os.path.exists(subs_file):
            try:
                with open(subs_file, 'r', encoding='utf-8') as f:
                    subs_data = json.load(f)
                for sub_id, data in subs_data.items():
                    self.submissions[sub_id] = VulnerabilitySubmission(
                        submission_id=data["submission_id"],
                        target_id=data.get("target_id", ""),
                        target_name=data.get("target_name", ""),
                        platform=data.get("platform", "hackerone"),
                        platform_report_id=data.get("platform_report_id", ""),
                        title=data.get("title", ""),
                        severity=data.get("severity", "medium"),
                        weakness=data.get("weakness", ""),
                        url=data.get("url", ""),
                        parameter=data.get("parameter", ""),
                        status=SubmissionStatus(data.get("status", "draft")),
                        bounty_status=BountyStatus(data.get("bounty_status", "none")),
                        bounty_amount=data.get("bounty_amount", 0),
                        currency=data.get("currency", "USD"),
                        bonus_amount=data.get("bonus_amount", 0),
                        submitted_at=data.get("submitted_at"),
                        triaged_at=data.get("triaged_at"),
                        resolved_at=data.get("resolved_at"),
                        bounty_awarded_at=data.get("bounty_awarded_at"),
                        first_response_at=data.get("first_response_at"),
                        time_to_triage=data.get("time_to_triage", 0),
                        time_to_resolve=data.get("time_to_resolve", 0),
                        time_to_bounty=data.get("time_to_bounty", 0),
                        duplicate_of=data.get("duplicate_of", ""),
                        duplicate_count=data.get("duplicate_count", 0),
                        tags=data.get("tags", []),
                        notes=data.get("notes", ""),
                        created_at=data.get("created_at", time.time()),
                        timeline=data.get("timeline", [])
                    )
            except Exception as e:
                log.error(f"加载提交记录失败: {e}")

        earnings_file = os.path.join(self.data_dir, "earnings.json")
        if os.path.exists(earnings_file):
            try:
                with open(earnings_file, 'r', encoding='utf-8') as f:
                    earnings_data = json.load(f)
                for rec_id, data in earnings_data.items():
                    self.earnings[rec_id] = EarningsRecord(
                        record_id=data["record_id"],
                        submission_id=data.get("submission_id", ""),
                        target_id=data.get("target_id", ""),
                        target_name=data.get("target_name", ""),
                        platform=data.get("platform", ""),
                        amount=data.get("amount", 0),
                        currency=data.get("currency", "USD"),
                        type=data.get("type", "bounty"),
                        description=data.get("description", ""),
                        awarded_at=data.get("awarded_at", time.time()),
                        payout_status=data.get("payout_status", "pending"),
                        paid_at=data.get("paid_at"),
                        payment_method=data.get("payment_method", ""),
                        transaction_id=data.get("transaction_id", ""),
                        notes=data.get("notes", "")
                    )
            except Exception as e:
                log.error(f"加载收益记录失败: {e}")

    def _save_data(self):
        """保存数据到文件"""
        subs_file = os.path.join(self.data_dir, "submissions.json")
        try:
            subs_data = {sid: s.to_dict() for sid, s in self.submissions.items()}
            with open(subs_file, 'w', encoding='utf-8') as f:
                json.dump(subs_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存提交记录失败: {e}")

        earnings_file = os.path.join(self.data_dir, "earnings.json")
        try:
            earnings_data = {rid: r.to_dict() for rid, r in self.earnings.items()}
            with open(earnings_file, 'w', encoding='utf-8') as f:
                json.dump(earnings_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存收益记录失败: {e}")

    # ===== 提交管理 =====
    def add_submission(self, target_id: str, title: str, severity: str = "medium",
                       platform: str = "hackerone", url: str = "",
                       parameter: str = "", weakness: str = "",
                       tags: List[str] = None) -> str:
        """添加漏洞提交记录"""
        submission_id = f"sub-{uuid.uuid4().hex[:8]}"
        submission = VulnerabilitySubmission(
            submission_id=submission_id,
            target_id=target_id,
            title=title,
            severity=severity,
            platform=platform,
            url=url,
            parameter=parameter,
            weakness=weakness,
            tags=tags or []
        )
        submission.timeline.append({
            "time": time.time(),
            "event": "提交记录创建",
            "description": f"创建漏洞提交记录: {title}"
        })
        self.submissions[submission_id] = submission
        self._save_data()
        log.info(f"添加提交记录: {title} ({submission_id})")
        return submission_id

    def update_submission_status(self, submission_id: str, status: str,
                                   notes: str = "") -> bool:
        """更新提交状态"""
        submission = self.submissions.get(submission_id)
        if not submission:
            return False

        old_status = submission.status
        submission.status = SubmissionStatus(status)
        submission.updated_at = time.time()

        now = time.time()
        if status == "submitted" and not submission.submitted_at:
            submission.submitted_at = now
        elif status == "triaged" and not submission.triaged_at:
            submission.triaged_at = now
            if submission.submitted_at:
                submission.time_to_triage = (now - submission.submitted_at) / 3600
        elif status == "resolved" and not submission.resolved_at:
            submission.resolved_at = now
            if submission.submitted_at:
                submission.time_to_resolve = (now - submission.submitted_at) / 3600

        if notes:
            submission.notes = notes

        submission.timeline.append({
            "time": now,
            "event": "状态变更",
            "description": f"状态从 {old_status.value} 变更为 {status}",
            "notes": notes
        })

        self._save_data()
        log.info(f"更新提交状态: {submission_id} -> {status}")
        return True

    def record_bounty(self, submission_id: str, amount: float,
                       currency: str = "USD", bonus: float = 0,
                       payment_method: str = "") -> bool:
        """记录奖励"""
        submission = self.submissions.get(submission_id)
        if not submission:
            return False

        submission.bounty_amount = amount
        submission.currency = currency
        submission.bonus_amount = bonus
        submission.bounty_status = BountyStatus.AWARDED
        submission.bounty_awarded_at = time.time()
        if submission.submitted_at:
            submission.time_to_bounty = (time.time() - submission.submitted_at) / 3600

        # 创建收益记录
        record_id = f"earn-{uuid.uuid4().hex[:8]}"
        earning = EarningsRecord(
            record_id=record_id,
            submission_id=submission_id,
            target_id=submission.target_id,
            target_name=submission.target_name,
            platform=submission.platform,
            amount=amount,
            currency=currency,
            type="bounty",
            description=f"漏洞奖励: {submission.title}",
            payment_method=payment_method
        )
        self.earnings[record_id] = earning

        if bonus > 0:
            bonus_record_id = f"earn-{uuid.uuid4().hex[:8]}"
            bonus_earning = EarningsRecord(
                record_id=bonus_record_id,
                submission_id=submission_id,
                target_id=submission.target_id,
                target_name=submission.target_name,
                platform=submission.platform,
                amount=bonus,
                currency=currency,
                type="bonus",
                description=f"额外奖励: {submission.title}",
                payment_method=payment_method
            )
            self.earnings[bonus_record_id] = bonus_earning

        submission.timeline.append({
            "time": time.time(),
            "event": "奖励发放",
            "description": f"获得奖励: {amount} {currency}" + (f" + 额外奖励 {bonus}" if bonus > 0 else "")
        })

        self._save_data()
        log.info(f"记录奖励: {submission_id} -> {amount} {currency}")
        return True

    def mark_duplicate(self, submission_id: str, original_id: str = "") -> bool:
        """标记为重复"""
        submission = self.submissions.get(submission_id)
        if not submission:
            return False

        submission.status = SubmissionStatus.DUPLICATE
        submission.duplicate_of = original_id
        submission.updated_at = time.time()

        # 增加原始报告的重复计数
        if original_id and original_id in self.submissions:
            self.submissions[original_id].duplicate_count += 1

        submission.timeline.append({
            "time": time.time(),
            "event": "标记为重复",
            "description": f"标记为重复，原始报告: {original_id}"
        })

        self._save_data()
        return True

    def check_duplicate(self, title: str, url: str = "",
                         parameter: str = "") -> Optional[Dict[str, Any]]:
        """检查是否可能重复"""
        for submission in self.submissions.values():
            if submission.status.value in ["duplicate", "spam", "not_applicable"]:
                continue
            # 简单的重复检测：标题相似度 + URL + 参数
            title_match = title.lower() == submission.title.lower()
            url_match = url and url.lower() == submission.url.lower()
            param_match = parameter and parameter.lower() == submission.parameter.lower()

            if title_match or (url_match and param_match):
                return {
                    "possible_duplicate": True,
                    "existing_submission": submission.to_dict(),
                    "match_reason": "标题完全匹配" if title_match else "URL和参数匹配"
                }
        return {"possible_duplicate": False}

    def get_submissions(self, status: str = None, severity: str = None,
                        platform: str = None, target_id: str = None) -> List[Dict[str, Any]]:
        """获取提交列表"""
        results = []
        for submission in self.submissions.values():
            if status and submission.status.value != status:
                continue
            if severity and submission.severity != severity:
                continue
            if platform and submission.platform != platform:
                continue
            if target_id and submission.target_id != target_id:
                continue
            results.append(submission.to_dict())
        results.sort(key=lambda x: x["created_at"], reverse=True)
        return results

    def get_submission_detail(self, submission_id: str) -> Optional[Dict[str, Any]]:
        """获取提交详情"""
        submission = self.submissions.get(submission_id)
        if not submission:
            return None
        data = submission.to_dict()
        data["timeline"] = submission.timeline
        return data

    # ===== 收益管理 =====
    def get_earnings(self, platform: str = None, type: str = None,
                     payout_status: str = None) -> List[Dict[str, Any]]:
        """获取收益记录"""
        results = []
        for earning in self.earnings.values():
            if platform and earning.platform != platform:
                continue
            if type and earning.type != type:
                continue
            if payout_status and earning.payout_status != payout_status:
                continue
            results.append(earning.to_dict())
        results.sort(key=lambda x: x["awarded_at"], reverse=True)
        return results

    def mark_payout_paid(self, record_id: str, transaction_id: str = "") -> bool:
        """标记收益已支付"""
        earning = self.earnings.get(record_id)
        if not earning:
            return False
        earning.payout_status = "paid"
        earning.paid_at = time.time()
        if transaction_id:
            earning.transaction_id = transaction_id
        self._save_data()
        return True

    # ===== 统计分析 =====
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total = len(self.submissions)
        submitted = sum(1 for s in self.submissions.values() if s.status.value not in ["draft"])
        triaged = sum(1 for s in self.submissions.values() if s.status.value == "triaged")
        resolved = sum(1 for s in self.submissions.values() if s.status.value == "resolved")
        duplicates = sum(1 for s in self.submissions.values() if s.status.value == "duplicate")
        not_applicable = sum(1 for s in self.submissions.values() if s.status.value == "not_applicable")
        informative = sum(1 for s in self.submissions.values() if s.status.value == "informative")

        # 收益统计
        total_earned = sum(e.amount for e in self.earnings.values())
        total_paid = sum(e.amount for e in self.earnings.values() if e.payout_status == "paid")
        total_pending = sum(e.amount for e in self.earnings.values() if e.payout_status == "pending")

        # 按严重程度统计
        by_severity = {
            "critical": sum(1 for s in self.submissions.values() if s.severity == "critical"),
            "high": sum(1 for s in self.submissions.values() if s.severity == "high"),
            "medium": sum(1 for s in self.submissions.values() if s.severity == "medium"),
            "low": sum(1 for s in self.submissions.values() if s.severity == "low"),
            "none": sum(1 for s in self.submissions.values() if s.severity == "none"),
        }

        # 按平台统计
        by_platform = {}
        for submission in self.submissions.values():
            p = submission.platform
            if p not in by_platform:
                by_platform[p] = {"total": 0, "resolved": 0, "earned": 0}
            by_platform[p]["total"] += 1
            if submission.status.value == "resolved":
                by_platform[p]["resolved"] += 1
            by_platform[p]["earned"] += submission.bounty_amount + submission.bonus_amount

        # 平均耗时
        avg_triage = sum(s.time_to_triage for s in self.submissions.values() if s.time_to_triage > 0)
        avg_triage = avg_triage / triaged if triaged > 0 else 0
        avg_resolve = sum(s.time_to_resolve for s in self.submissions.values() if s.time_to_resolve > 0)
        avg_resolve = avg_resolve / resolved if resolved > 0 else 0
        avg_bounty = sum(s.time_to_bounty for s in self.submissions.values() if s.time_to_bounty > 0)
        avg_bounty = avg_bounty / resolved if resolved > 0 else 0

        # 有效率
        valid_submissions = triaged + resolved
        validity_rate = valid_submissions / submitted * 100 if submitted > 0 else 0
        duplicate_rate = duplicates / submitted * 100 if submitted > 0 else 0

        # 平均奖励
        avg_bounty_amount = total_earned / resolved if resolved > 0 else 0

        return {
            "total_submissions": total,
            "submitted": submitted,
            "triaged": triaged,
            "resolved": resolved,
            "duplicates": duplicates,
            "not_applicable": not_applicable,
            "informative": informative,
            "validity_rate": round(validity_rate, 2),
            "duplicate_rate": round(duplicate_rate, 2),
            "resolution_rate": round(resolved / submitted * 100, 2) if submitted > 0 else 0,
            "by_severity": by_severity,
            "by_platform": by_platform,
            "earnings": {
                "total_earned": total_earned,
                "total_paid": total_paid,
                "total_pending": total_pending,
                "average_bounty": round(avg_bounty_amount, 2),
                "currency": "USD"
            },
            "timing": {
                "avg_time_to_triage_hours": round(avg_triage, 2),
                "avg_time_to_resolve_hours": round(avg_resolve, 2),
                "avg_time_to_bounty_hours": round(avg_bounty, 2)
            },
            "total_earnings_records": len(self.earnings)
        }

    def get_monthly_earnings(self, months: int = 12) -> List[Dict[str, Any]]:
        """获取月度收益"""
        monthly = {}
        for earning in self.earnings.values():
            month = time.strftime("%Y-%m", time.localtime(earning.awarded_at))
            if month not in monthly:
                monthly[month] = {"month": month, "total": 0, "count": 0, "by_type": {}}
            monthly[month]["total"] += earning.amount
            monthly[month]["count"] += 1
            etype = earning.type
            monthly[month]["by_type"][etype] = monthly[month]["by_type"].get(etype, 0) + earning.amount

        result = sorted(monthly.values(), key=lambda x: x["month"], reverse=True)[:months]
        return result


# 全局实例
src_tracker = SRCVulnerabilityTracker()
