#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_intel知识库模块，存储和管理相关安全知识、漏洞信息和攻击链数据。

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
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable
from pathlib import Path
from dataclasses import dataclass, field, asdict
from loguru import logger
from .vuln_database import VulnDatabase, Vulnerability, get_vuln_db
from .nvd_sync import NVDSync


@dataclass
class VulnAlert:
    """漏洞告警"""
    alert_id: str = ""
    cve_id: str = ""
    title: str = ""
    severity: str = "high"
    cvss_score: float = 0.0
    description: str = ""
    published_date: str = ""
    matched_keywords: List[str] = field(default_factory=list)
    notification_channels: List[str] = field(default_factory=list)
    created_at: str = ""
    status: str = "new"  # new/acknowledged/ignored

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return asdict(self)


class VulnIntelligence:
    """漏洞情报推送系统"""

    def __init__(self, db: Optional[VulnDatabase] = None):
        """初始化VulnIntelligence实例。

        Args:
            self: 类实例。
        """
        self.db = db or get_vuln_db()
        self.project_root = Path(__file__).parent.parent
        self.alerts_path = str(self.project_root / "data" / "vuln_alerts.json")
        self.subscriptions_path = str(self.project_root / "data" / "vuln_subscriptions.json")
        self.alerts: List[VulnAlert] = []
        self.subscriptions: Dict[str, Any] = {
            "enabled": True,
            "min_severity": "high",  # critical/high/medium/low
            "keywords": ["rce", "sql injection", "xss", "ssrf", "0day", "ransomware", "wormable"],
            "vendors": ["microsoft", "apache", "oracle", "cisco", "fortinet", "vmware", "adobe"],
            "products": [],
            "check_interval_hours": 6,
            "notification_channels": {
                "webhook": {"enabled": False, "url": ""},
                "email": {"enabled": False, "smtp_host": "", "smtp_port": 587, "username": "", "password": "", "to": []},
                "dingtalk": {"enabled": False, "webhook": "", "secret": ""},
                "wecom": {"enabled": False, "webhook": ""},
                "console": {"enabled": True},
            },
        }
        self.session: Optional[aiohttp.ClientSession] = None
        self._load()

    def _load(self):
        """加载告警和订阅配置"""
        try:
            if Path(self.alerts_path).exists():
                with open(self.alerts_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.alerts = [VulnAlert(**a) for a in data.get("alerts", [])]
        except Exception as e:
            logger.error(f"加载告警失败: {e}")

        try:
            if Path(self.subscriptions_path).exists():
                with open(self.subscriptions_path, "r", encoding="utf-8") as f:
                    self.subscriptions = json.load(f)
        except Exception as e:
            logger.error(f"加载订阅配置失败: {e}")

    def _save(self):
        """保存告警和订阅配置"""
        try:
            Path(self.alerts_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.alerts_path, "w", encoding="utf-8") as f:
                json.dump({"alerts": [a.to_dict() for a in self.alerts], "updated_at": datetime.now().isoformat()}, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存告警失败: {e}")

        try:
            with open(self.subscriptions_path, "w", encoding="utf-8") as f:
                json.dump(self.subscriptions, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存订阅配置失败: {e}")

    def _severity_rank(self, severity: str) -> int:
        """执行相关操作。

        Args:
            severity: 相关参数。

        Returns:
            操作结果。
        """
        ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return ranks.get(severity.lower(), 0)

    def _matches_subscription(self, vuln: Vulnerability) -> tuple:
        """检查漏洞是否匹配订阅条件，返回(是否匹配, 匹配的关键词)"""
        if not self.subscriptions.get("enabled", True):
            return False, []

        # 严重程度过滤
        min_severity = self.subscriptions.get("min_severity", "high")
        if self._severity_rank(vuln.severity) < self._severity_rank(min_severity):
            return False, []

        matched_keywords = []
        search_text = f"{vuln.title} {vuln.description} {vuln.vendor} {vuln.product}".lower()

        # 关键词匹配
        for kw in self.subscriptions.get("keywords", []):
            if kw.lower() in search_text:
                matched_keywords.append(kw)

        # 厂商匹配
        for vendor in self.subscriptions.get("vendors", []):
            if vendor.lower() in vuln.vendor.lower():
                matched_keywords.append(f"vendor:{vendor}")

        # 产品匹配
        for product in self.subscriptions.get("products", []):
            if product.lower() in vuln.product.lower():
                matched_keywords.append(f"product:{product}")

        # 如果有关键词/厂商/产品订阅，必须匹配至少一个
        has_filters = (self.subscriptions.get("keywords") or
                       self.subscriptions.get("vendors") or
                       self.subscriptions.get("products"))
        if has_filters and not matched_keywords:
            return False, []

        return True, matched_keywords

    async def check_new_vulnerabilities(self, hours: int = 24) -> List[VulnAlert]:
        """检查最近N小时发布的新漏洞，生成告警"""
        logger.info(f"开始检查最近 {hours} 小时的新漏洞...")
        new_alerts = []

        # 从NVD同步最近的漏洞
        nvd = NVDSync(db=self.db)
        try:
            days = max(1, hours // 24 + 1)
            await nvd.sync_recent(days=days, max_results=500)
        finally:
            await nvd.close()

        # 检查本地数据库中的新漏洞
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        existing_cve_ids = {a.cve_id for a in self.alerts}

        for vuln in self.db.db.values():
            if vuln.cve_id in existing_cve_ids:
                continue
            if vuln.published_date < cutoff[:10]:
                continue

            matches, keywords = self._matches_subscription(vuln)
            if matches:
                alert = VulnAlert(
                    alert_id=f"ALERT-{int(time.time())}-{vuln.cve_id}",
                    cve_id=vuln.cve_id,
                    title=vuln.title,
                    severity=vuln.severity,
                    cvss_score=vuln.cvss_score,
                    description=vuln.description[:500],
                    published_date=vuln.published_date,
                    matched_keywords=keywords,
                    created_at=datetime.now().isoformat(),
                    status="new",
                )
                new_alerts.append(alert)
                self.alerts.append(alert)

        # 按严重程度排序
        new_alerts.sort(key=lambda x: (self._severity_rank(x.severity), x.cvss_score), reverse=True)

        # 保存
        self._save()

        logger.info(f"发现 {len(new_alerts)} 个新漏洞告警")
        return new_alerts

    async def send_notification(self, alert: VulnAlert) -> Dict[str, bool]:
        """发送告警通知到所有已启用的渠道"""
        results = {}
        channels = self.subscriptions.get("notification_channels", {})

        # 构建消息
        message = self._build_alert_message(alert)

        # Console输出
        if channels.get("console", {}).get("enabled", True):
            logger.info(f"[漏洞告警] {alert.cve_id} - {alert.title} (CVSS: {alert.cvss_score})")
            results["console"] = True

        # Webhook
        webhook_cfg = channels.get("webhook", {})
        if webhook_cfg.get("enabled") and webhook_cfg.get("url"):
            results["webhook"] = await self._send_webhook(webhook_cfg["url"], message)

        # 钉钉
        dingtalk_cfg = channels.get("dingtalk", {})
        if dingtalk_cfg.get("enabled") and dingtalk_cfg.get("webhook"):
            results["dingtalk"] = await self._send_dingtalk(dingtalk_cfg, message)

        # 企业微信
        wecom_cfg = channels.get("wecom", {})
        if wecom_cfg.get("enabled") and wecom_cfg.get("webhook"):
            results["wecom"] = await self._send_wecom(wecom_cfg["webhook"], message)

        alert.notification_channels = [k for k, v in results.items() if v]
        return results

    def _build_alert_message(self, alert: VulnAlert) -> Dict[str, Any]:
        """构建告警消息"""
        return {
            "msgtype": "markdown",
            "markdown": {
                "title": f"【漏洞告警】{alert.severity.upper()} - {alert.cve_id}",
                "text": f"""## 🔴 漏洞告警

**CVE编号**: {alert.cve_id}
**漏洞名称**: {alert.title}
**严重程度**: {alert.severity.upper()}
**CVSS分数**: {alert.cvss_score}
**发布日期**: {alert.published_date}
**匹配关键词**: {', '.join(alert.matched_keywords)}

**漏洞描述**:
{alert.description[:300]}

> 请及时评估影响并采取修复措施。
""",
            },
        }

    async def _send_webhook(self, url: str, message: Dict[str, Any]) -> bool:
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            async with self.session.post(url, json=message, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                return resp.status in (200, 201, 204)
        except Exception as e:
            logger.error(f"Webhook发送失败: {e}")
            return False

    async def _send_dingtalk(self, config: Dict[str, Any], message: Dict[str, Any]) -> bool:
        try:
            webhook = config.get("webhook", "")
            # 钉钉签名（如果配置了secret）
            if config.get("secret"):
                import hmac, hashlib, base64, urllib.parse
                timestamp = str(round(time.time() * 1000))
                secret_enc = config["secret"].encode("utf-8")
                string_to_sign = f"{timestamp}\n{config['secret']}"
                hmac_code = hmac.new(secret_enc, string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
                sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
                webhook = f"{webhook}&timestamp={timestamp}&sign={sign}"

            return await self._send_webhook(webhook, message)
        except Exception as e:
            logger.error(f"钉钉发送失败: {e}")
            return False

    async def _send_wecom(self, webhook: str, message: Dict[str, Any]) -> bool:
        # 企业微信使用相同的webhook格式
        return await self._send_webhook(webhook, message)

    def get_alerts(self, status: str = "", severity: str = "",
                    limit: int = 50, offset: int = 0) -> tuple:
        """获取告警列表"""
        results = self.alerts
        if status:
            results = [a for a in results if a.status == status]
        if severity:
            results = [a for a in results if a.severity == severity]
        results.sort(key=lambda x: x.created_at, reverse=True)
        total = len(results)
        return results[offset:offset + limit], total

    def acknowledge_alert(self, alert_id: str) -> bool:
        """确认告警"""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.status = "acknowledged"
                self._save()
                return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """获取情报系统统计"""
        return {
            "total_alerts": len(self.alerts),
            "new_alerts": len([a for a in self.alerts if a.status == "new"]),
            "acknowledged": len([a for a in self.alerts if a.status == "acknowledged"]),
            "by_severity": {
                "critical": len([a for a in self.alerts if a.severity == "critical"]),
                "high": len([a for a in self.alerts if a.severity == "high"]),
                "medium": len([a for a in self.alerts if a.severity == "medium"]),
            },
            "subscription_enabled": self.subscriptions.get("enabled", False),
            "min_severity": self.subscriptions.get("min_severity", "high"),
            "keywords_count": len(self.subscriptions.get("keywords", [])),
            "vendors_count": len(self.subscriptions.get("vendors", [])),
        }

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None


def run_vuln_check(hours: int = 24) -> Dict[str, Any]:
    """运行漏洞检查（入口函数）"""
    intel = VulnIntelligence()
    try:
        alerts = asyncio.run(intel.check_new_vulnerabilities(hours=hours))
        # 发送通知
        for alert in alerts:
            asyncio.run(intel.send_notification(alert))
        return {
            "new_alerts": len(alerts),
            "alerts": [a.to_dict() for a in alerts[:10]],
        }
    finally:
        asyncio.run(intel.close())


if __name__ == "__main__":
    import sys
    hours = int(sys.argv[1]) if len(sys.argv) > 1 else 24
    print(f"开始检查最近 {hours} 小时的漏洞...")
    result = run_vuln_check(hours)
    print(f"发现 {result['new_alerts']} 个新告警")
