"""
enterprise_enhancement模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
from typing import Dict, Any
from utils.plugin_system import Plugin


class EnterpriseEnhancementPlugin(Plugin):
    """企业级增强插件"""

    name = "enterprise_enhancement"
    version = "1.0.0"
    description = "企业级增强 - CVE漏洞库+多租户/RBAC+合规报告+漏洞利用引擎"
    author = "AI Hacking Agent"
    category = "enterprise"
    tags = ["cve", "enterprise", "compliance", "exploit", "rbac", "audit"]

    def get_parameters(self) -> Dict[str, Any]:
        """获取相关数据。

        Returns:
            操作结果。
        """
        return {
            "action": {
                "type": "string",
                "description": "操作: cve_search/cve_detail/cve_match/enterprise_stats/audit_log/compliance_report/poc_search/auto_exploit",
                "required": True,
            },
            "keyword": {"type": "string", "description": "搜索关键词", "required": False},
            "cve_id": {"type": "string", "description": "CVE ID", "required": False},
            "severity": {"type": "string", "description": "严重程度", "required": False},
            "target": {"type": "string", "description": "目标地址", "required": False},
            "standard": {"type": "string", "description": "合规标准: mlps2.0/iso27001/both", "required": False, "default": "both"},
            "limit": {"type": "integer", "description": "返回数量限制", "required": False, "default": 20},
        }

    def execute(self, action: str = "", keyword: str = "", cve_id: str = "",
                severity: str = "", target: str = "", standard: str = "both",
                limit: int = 20, **kwargs) -> Dict[str, Any]:
        """执行企业级增强操作"""
        if not action:
            return {"success": False, "error": "必须指定action参数"}

        action = action.lower()

        try:
            if action == "cve_search":
                return self._cve_search(keyword, severity, limit)
            elif action == "cve_detail":
                return self._cve_detail(cve_id)
            elif action == "cve_match":
                return self._cve_match(keyword)
            elif action == "cve_stats":
                return self._cve_stats()
            elif action == "enterprise_stats":
                return self._enterprise_stats()
            elif action == "audit_log":
                return self._audit_log(limit)
            elif action == "compliance_report":
                return self._compliance_report(standard)
            elif action == "poc_search":
                return self._poc_search(keyword, severity, limit)
            elif action == "poc_stats":
                return self._poc_stats()
            elif action == "auto_exploit":
                return self._auto_exploit(target)
            else:
                return {
                    "success": False,
                    "error": f"未知操作: {action}",
                    "available_actions": [
                        "cve_search", "cve_detail", "cve_match", "cve_stats",
                        "enterprise_stats", "audit_log",
                        "compliance_report",
                        "poc_search", "poc_stats", "auto_exploit",
                    ],
                }
        except Exception as e:
            return {"success": False, "error": f"执行失败: {e}"}

    def _cve_search(self, keyword: str, severity: str, limit: int) -> Dict[str, Any]:
        """搜索CVE漏洞"""
        from tools.cve_database import cve_database
        results = cve_database.search_cves(keyword=keyword, severity=severity, limit=limit)
        return {
            "success": True,
            "result": {
                "type": "cve_search",
                "keyword": keyword,
                "severity": severity,
                "count": len(results),
                "results": [
                    {
                        "cve_id": c.cve_id,
                        "description": c.description[:200],
                        "severity": c.severity,
                        "cvss_v31_score": c.cvss_v31_score,
                        "published_date": c.published_date,
                    }
                    for c in results
                ],
            },
        }

    def _cve_detail(self, cve_id: str) -> Dict[str, Any]:
        """获取CVE详情"""
        from tools.cve_database import cve_database
        cve = cve_database.get_cve(cve_id)
        if not cve:
            return {"success": False, "error": f"CVE {cve_id} 不存在"}
        return {
            "success": True,
            "result": {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "severity": cve.severity,
                "cvss_v2_score": cve.cvss_v2_score,
                "cvss_v3_score": cve.cvss_v3_score,
                "cvss_v31_score": cve.cvss_v31_score,
                "cwe_ids": cve.cwe_ids,
                "cpe_list": cve.cpe_list,
                "published_date": cve.published_date,
                "exploitability": cve.exploitability,
                "patch_available": cve.patch_available,
            },
        }

    def _cve_match(self, service: str) -> Dict[str, Any]:
        """根据服务匹配CVE漏洞"""
        from tools.cve_database import cve_database
        results = cve_database.match_vulnerabilities(service=service)
        return {
            "success": True,
            "result": {
                "type": "cve_match",
                "service": service,
                "matched_count": len(results),
                "results": [
                    {
                        "cve_id": c.cve_id,
                        "severity": c.severity,
                        "cvss_v31_score": c.cvss_v31_score,
                        "description": c.description[:150],
                    }
                    for c in results[:20]
                ],
            },
        }

    def _cve_stats(self) -> Dict[str, Any]:
        """获取CVE漏洞库统计"""
        from tools.cve_database import cve_database
        return {"success": True, "result": cve_database.get_statistics()}

    def _enterprise_stats(self) -> Dict[str, Any]:
        """获取企业级功能统计"""
        from tools.enterprise_manager import enterprise_manager
        return {"success": True, "result": enterprise_manager.get_statistics()}

    def _audit_log(self, limit: int) -> Dict[str, Any]:
        """查询审计日志"""
        from tools.enterprise_manager import enterprise_manager
        logs = enterprise_manager.query_audit_logs(limit=limit)
        return {
            "success": True,
            "result": {
                "type": "audit_log",
                "count": len(logs),
                "logs": logs,
            },
        }

    def _compliance_report(self, standard: str) -> Dict[str, Any]:
        """生成合规报告"""
        from tools.compliance_manager import compliance_manager
        report = compliance_manager.generate_compliance_report(standard=standard)
        return {"success": True, "result": report}

    def _poc_search(self, keyword: str, severity: str, limit: int) -> Dict[str, Any]:
        """搜索POC库"""
        from tools.exploit_engine import exploit_engine
        results = exploit_engine.search_pocs(keyword=keyword, severity=severity)
        return {
            "success": True,
            "result": {
                "type": "poc_search",
                "keyword": keyword,
                "count": len(results),
                "results": results[:limit],
            },
        }

    def _poc_stats(self) -> Dict[str, Any]:
        """获取POC库统计"""
        from tools.exploit_engine import exploit_engine
        return {"success": True, "result": exploit_engine.get_poc_statistics()}

    def _auto_exploit(self, target: str) -> Dict[str, Any]:
        """自动漏洞利用编排"""
        if not target:
            return {"success": False, "error": "必须指定target参数"}
        from tools.exploit_engine import exploit_engine
        result = exploit_engine.auto_exploit(target=target)
        return {"success": True, "result": result}

    def is_available(self) -> bool:
        """是...。

        Returns:
            操作结果。
        """
        return True
