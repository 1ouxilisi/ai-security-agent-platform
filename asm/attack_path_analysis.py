"""
攻击路径分析引擎
基于暴露面评估结果，模拟攻击者可能的攻击路径，映射MITRE ATT&CK战术
"""
from typing import List, Dict, Any, Optional
import time


class AttackPathAnalysisEngine:
    """攻击路径分析引擎"""

    # MITRE ATT&CK 战术映射
    ATTACK_TACTICS = {
        "reconnaissance": {
            "name": "侦察",
            "name_en": "Reconnaissance",
            "id": "TA0043",
            "description": "攻击者试图收集可用于规划未来操作的信息",
            "techniques": ["主动扫描", "被动信息收集", "搜索引擎发现", "DNS查询"]
        },
        "initial_access": {
            "name": "初始访问",
            "name_en": "Initial Access",
            "id": "TA0001",
            "description": "攻击者试图进入你的网络",
            "techniques": ["利用公开-facing应用", "暴力破解", "钓鱼", "利用外部远程服务"]
        },
        "execution": {
            "name": "执行",
            "name_en": "Execution",
            "id": "TA0002",
            "description": "攻击者试图在受害者系统上运行恶意代码",
            "techniques": ["命令行解释器", "PowerShell", "利用客户端执行", "服务执行"]
        },
        "persistence": {
            "name": "持久化",
            "name_en": "Persistence",
            "id": "TA0003",
            "description": "攻击者试图保持立足点",
            "techniques": ["注册表运行键", "计划任务", "服务创建", "启动文件夹"]
        },
        "privilege_escalation": {
            "name": "权限提升",
            "name_en": "Privilege Escalation",
            "id": "TA0004",
            "description": "攻击者试图获得更高权限",
            "techniques": ["利用漏洞提权", "令牌窃取", "绕过UAC", "服务权限配置错误"]
        },
        "defense_evasion": {
            "name": "防御规避",
            "name_en": "Defense Evasion",
            "id": "TA0005",
            "description": "攻击者试图逃避检测",
            "techniques": ["禁用安全工具", "混淆文件", "进程注入", "根包"]
        },
        "credential_access": {
            "name": "凭证访问",
            "name_en": "Credential Access",
            "id": "TA0006",
            "description": "攻击者试图窃取账户名和密码",
            "techniques": ["凭证转储", "键盘记录", "凭据文件中的凭证", "暴力破解"]
        },
        "discovery": {
            "name": "发现",
            "name_en": "Discovery",
            "id": "TA0007",
            "description": "攻击者试图了解你的环境",
            "techniques": ["系统信息发现", "网络服务发现", "账户发现", "文件目录发现"]
        },
        "lateral_movement": {
            "name": "横向移动",
            "name_en": "Lateral Movement",
            "id": "TA0008",
            "description": "攻击者试图在你的环境中移动",
            "techniques": ["远程桌面协议", "SMB/Windows管理共享", "SSH", "WMI"]
        },
        "collection": {
            "name": "收集",
            "name_en": "Collection",
            "id": "TA0009",
            "description": "攻击者试图收集感兴趣的数据",
            "techniques": ["数据从本地系统收集", "剪贴板数据", "输入捕获", "邮件收集"]
        },
        "exfiltration": {
            "name": "数据外泄",
            "name_en": "Exfiltration",
            "id": "TA0010",
            "description": "攻击者试图窃取数据",
            "techniques": ["通过C2通道外泄", "通过备用通道外泄", "自动外泄", "传输数据大小限制"]
        },
        "impact": {
            "name": "影响",
            "name_en": "Impact",
            "id": "TA0040",
            "description": "攻击者试图破坏可用性或完整性",
            "techniques": ["数据加密用于影响", "数据销毁", "服务停止", "资源耗尽"]
        }
    }

    # 漏洞到ATT&CK技术映射
    VULNERABILITY_TO_ATTACK = {
        "sql_injection": {"tactic": "initial_access", "technique": "利用公开-facing应用", "impact": "数据库数据泄露/篡改"},
        "xss": {"tactic": "initial_access", "technique": "利用公开-facing应用", "impact": "用户会话劫持/钓鱼"},
        "rce": {"tactic": "execution", "technique": "利用客户端执行", "impact": "远程代码执行/服务器控制"},
        "ssrf": {"tactic": "discovery", "technique": "网络服务发现", "impact": "内网探测/云元数据访问"},
        "idor": {"tactic": "collection", "technique": "数据从本地系统收集", "impact": "越权访问他人数据"},
        "weak_password": {"tactic": "credential_access", "technique": "暴力破解", "impact": "账户被破解"},
        "default_credentials": {"tactic": "initial_access", "technique": "利用外部远程服务", "impact": "未授权访问"},
        "sensitive_data_exposure": {"tactic": "collection", "technique": "凭据文件中的凭证", "impact": "敏感信息泄露"},
        "misconfiguration": {"tactic": "defense_evasion", "technique": "禁用安全工具", "impact": "安全控制失效"},
        "outdated_software": {"tactic": "privilege_escalation", "technique": "利用漏洞提权", "impact": "已知漏洞利用"},
    }

    def __init__(self):
        self.attack_paths = []
        self.attack_chain = []

    def analyze_all(self, assessment_results: Dict[str, Any], assets: Dict[str, Any]) -> Dict[str, Any]:
        """
        全面攻击路径分析
        :param assessment_results: 暴露面评估结果
        :param assets: 资产发现结果
        :return: 攻击路径分析结果
        """
        self.attack_paths = []
        self.attack_chain = []

        findings = assessment_results.get("findings", [])

        # 1. 识别可能的入口点
        entry_points = self._identify_entry_points(findings, assets)

        # 2. 构建攻击路径
        for entry in entry_points:
            paths = self._build_attack_paths(entry, findings)
            self.attack_paths.extend(paths)

        # 3. 生成攻击链图谱
        self.attack_chain = self._build_attack_chain(entry_points, findings)

        # 4. 映射ATT&CK战术
        attack_mapping = self._map_to_attack(findings)

        # 5. 计算攻击可行性评分
        feasibility = self._calculate_feasibility()

        # 6. 生成防御建议
        defenses = self._generate_defense_recommendations()

        return {
            "entry_points": entry_points,
            "attack_paths": self.attack_paths,
            "attack_chain": self.attack_chain,
            "attack_mapping": attack_mapping,
            "feasibility": feasibility,
            "defense_recommendations": defenses,
            "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    def _identify_entry_points(self, findings: List[Dict], assets: Dict) -> List[Dict]:
        """识别可能的攻击入口点"""
        entry_points = []

        # 高危端口作为入口点
        for finding in findings:
            if finding.get("type") == "port_exposure" and finding.get("severity") in ["critical", "high"]:
                entry = {
                    "type": "open_service",
                    "asset": finding.get("asset"),
                    "port": finding.get("port"),
                    "service": finding.get("service"),
                    "description": finding.get("title"),
                    "exploitability": self._estimate_exploitability(finding),
                    "impact": self._estimate_impact(finding)
                }
                entry_points.append(entry)

        # Web应用作为入口点
        web_ports = [80, 443, 8080, 8443, 8000, 8888]
        for port_info in assets.get("open_ports", []):
            if port_info["port"] in web_ports:
                entry = {
                    "type": "web_application",
                    "asset": port_info["ip"],
                    "port": port_info["port"],
                    "service": "HTTP/HTTPS",
                    "description": f"Web应用在{port_info['ip']}:{port_info['port']}",
                    "exploitability": "medium",
                    "impact": "high"
                }
                if not any(e["asset"] == entry["asset"] and e["port"] == entry["port"] for e in entry_points):
                    entry_points.append(entry)

        # 云存储桶作为入口点
        for bucket in assets.get("cloud_buckets", []):
            entry = {
                "type": "cloud_storage",
                "asset": bucket.get("name"),
                "port": None,
                "service": bucket.get("provider"),
                "description": f"云存储桶公开访问",
                "exploitability": "critical",
                "impact": "critical"
            }
            entry_points.append(entry)

        # 按可利用性排序
        exploit_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        entry_points.sort(key=lambda x: exploit_order.get(x["exploitability"], 9))
        return entry_points[:10]

    def _build_attack_paths(self, entry_point: Dict, findings: List[Dict]) -> List[Dict]:
        """构建攻击路径"""
        paths = []

        # 路径1：直接利用入口点
        path1 = {
            "name": f"直接利用 - {entry_point.get('service', '未知服务')}",
            "steps": [
                {"phase": "侦察", "action": f"扫描{entry_point['asset']}:{entry_point.get('port', 'N/A')}", "status": "已完成"},
                {"phase": "初始访问", "action": f"利用{entry_point.get('service')}服务漏洞", "status": "可能"},
                {"phase": "执行", "action": "在目标系统执行代码", "status": "可能"},
                {"phase": "影响", "action": "数据泄露/系统控制", "status": "可能"}
            ],
            "probability": self._path_probability(entry_point),
            "impact": entry_point.get("impact", "medium"),
            "entry_point": entry_point
        }
        paths.append(path1)

        # 路径2：通过入口点进入内网横向移动
        if entry_point.get("type") in ["open_service", "web_application"]:
            path2 = {
                "name": f"入口突破 + 内网横向移动",
                "steps": [
                    {"phase": "侦察", "action": f"扫描{entry_point['asset']}", "status": "已完成"},
                    {"phase": "初始访问", "action": f"利用{entry_point.get('service')}获得初始访问", "status": "可能"},
                    {"phase": "发现", "action": "内网扫描，发现其他主机", "status": "可能"},
                    {"phase": "凭证访问", "action": "窃取凭证/哈希传递", "status": "可能"},
                    {"phase": "横向移动", "action": "使用窃取凭证访问其他主机", "status": "可能"},
                    {"phase": "影响", "action": "内网多主机控制/数据泄露", "status": "可能"}
                ],
                "probability": "medium",
                "impact": "critical",
                "entry_point": entry_point
            }
            paths.append(path2)

        return paths

    def _build_attack_chain(self, entry_points: List[Dict], findings: List[Dict]) -> List[Dict]:
        """构建攻击链图谱"""
        chain = []

        # 按ATT&CK战术顺序构建
        tactic_order = ["reconnaissance", "initial_access", "execution", "persistence",
                         "privilege_escalation", "defense_evasion", "credential_access",
                         "discovery", "lateral_movement", "collection", "exfiltration", "impact"]

        for tactic_key in tactic_order:
            tactic = self.ATTACK_TACTICS[tactic_key]
            related_findings = self._find_findings_for_tactic(tactic_key, findings)

            chain_node = {
                "tactic_id": tactic["id"],
                "tactic_name": tactic["name"],
                "tactic_name_en": tactic["name_en"],
                "description": tactic["description"],
                "techniques": tactic["techniques"],
                "related_findings": related_findings,
                "risk_level": self._tactic_risk_level(tactic_key, related_findings),
                "possible": len(related_findings) > 0
            }
            chain.append(chain_node)

        return chain

    def _map_to_attack(self, findings: List[Dict]) -> Dict:
        """映射到ATT&CK"""
        mapping = {tactic: [] for tactic in self.ATTACK_TACTICS}

        for finding in findings:
            # 根据发现类型映射
            ftype = finding.get("type", "")
            if "port" in ftype:
                mapping["reconnaissance"].append(finding)
                mapping["initial_access"].append(finding)
            elif "information" in ftype:
                mapping["discovery"].append(finding)
            elif "plaintext" in ftype:
                mapping["credential_access"].append(finding)
            elif "certificate" in ftype:
                mapping["defense_evasion"].append(finding)
            elif "cloud" in ftype:
                mapping["collection"].append(finding)
                mapping["exfiltration"].append(finding)
            elif "dns" in ftype:
                mapping["reconnaissance"].append(finding)

        # 统计
        stats = {}
        for tactic, items in mapping.items():
            if items:
                stats[tactic] = {
                    "name": self.ATTACK_TACTICS[tactic]["name"],
                    "count": len(items),
                    "findings": items[:5]
                }

        return {
            "total_tactics_affected": len(stats),
            "tactics": stats
        }

    def _calculate_feasibility(self) -> Dict:
        """计算攻击可行性评分"""
        if not self.attack_paths:
            return {"score": 0, "level": "low", "description": "未发现明显攻击路径"}

        total_prob = 0
        for path in self.attack_paths:
            prob_map = {"critical": 100, "high": 75, "medium": 50, "low": 25}
            total_prob += prob_map.get(path.get("probability", "low"), 25)

        avg_prob = total_prob / len(self.attack_paths)

        if avg_prob >= 75:
            level = "critical"
        elif avg_prob >= 50:
            level = "high"
        elif avg_prob >= 25:
            level = "medium"
        else:
            level = "low"

        return {
            "score": round(avg_prob, 1),
            "level": level,
            "total_paths": len(self.attack_paths),
            "description": f"发现{len(self.attack_paths)}条可能的攻击路径，平均可行性{round(avg_prob)}%"
        }

    def _generate_defense_recommendations(self) -> List[Dict]:
        """生成防御建议"""
        recommendations = []

        # 按攻击链阶段生成防御建议
        defense_map = {
            "reconnaissance": "减少信息暴露：关闭不必要的端口和服务，配置防火墙限制访问来源",
            "initial_access": "强化入口防护：及时修补漏洞，使用强密码和多因素认证，部署WAF",
            "execution": "应用白名单：限制可执行程序运行，启用脚本拦截，最小权限原则",
            "persistence": "监控持久化点：定期检查注册表/计划任务/服务，启用变更检测",
            "privilege_escalation": "权限最小化：遵循最小权限原则，及时修补系统漏洞，启用UAC",
            "defense_evasion": "部署EDR：启用终端检测和响应，定期更新安全软件，监控异常行为",
            "credential_access": "凭证保护：使用密码管理器，启用多因素认证，定期轮换密码，监控异常登录",
            "discovery": "网络分段：实施网络分段，限制横向扫描，监控异常网络流量",
            "lateral_movement": "访问控制：限制远程管理端口，使用特权访问管理，监控异常远程连接",
            "collection": "数据分类：对敏感数据分类标记，实施数据防泄漏(DLP)，监控异常文件访问",
            "exfiltration": "流量监控：监控异常出站流量，限制数据传输大小，部署数据防泄漏",
            "impact": "备份恢复：定期备份重要数据，测试恢复流程，部署勒索软件防护"
        }

        for tactic_key, defense in defense_map.items():
            tactic = self.ATTACK_TACTICS[tactic_key]
            recommendations.append({
                "tactic": tactic["name"],
                "tactic_id": tactic["id"],
                "recommendation": defense,
                "priority": self._defense_priority(tactic_key)
            })

        return recommendations

    def _estimate_exploitability(self, finding: Dict) -> str:
        """估算可利用性"""
        severity = finding.get("severity", "low")
        exploit_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "low"}
        return exploit_map.get(severity, "low")

    def _estimate_impact(self, finding: Dict) -> str:
        """估算影响"""
        return finding.get("severity", "medium")

    def _path_probability(self, entry_point: Dict) -> str:
        """路径概率"""
        return entry_point.get("exploitability", "medium")

    def _find_findings_for_tactic(self, tactic_key: str, findings: List[Dict]) -> List[Dict]:
        """查找与战术相关的发现"""
        related = []
        for finding in findings:
            ftype = finding.get("type", "")
            if tactic_key == "reconnaissance" and "port" in ftype:
                related.append(finding)
            elif tactic_key == "initial_access" and ("port" in ftype or "cloud" in ftype):
                related.append(finding)
            elif tactic_key == "credential_access" and "plaintext" in ftype:
                related.append(finding)
            elif tactic_key == "collection" and ("cloud" in ftype or "sensitive" in ftype):
                related.append(finding)
        return related[:3]

    def _tactic_risk_level(self, tactic_key: str, findings: List[Dict]) -> str:
        """战术风险等级"""
        if not findings:
            return "low"
        severities = [f.get("severity", "low") for f in findings]
        if "critical" in severities:
            return "critical"
        if "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
        return "low"

    def _defense_priority(self, tactic_key: str) -> str:
        """防御优先级"""
        high_priority = ["initial_access", "execution", "credential_access", "lateral_movement", "impact"]
        if tactic_key in high_priority:
            return "high"
        return "medium"
