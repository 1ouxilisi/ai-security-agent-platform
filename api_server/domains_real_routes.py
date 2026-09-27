# -*- coding: utf-8 -*-
"""domains_real_routes.py — 所有领域真实可用 API 路由（30+端点）。

路由前缀：/api/v1/domains-real

覆盖：
    - 仪表盘聚合（总览/健康/领域详情）
    - 红蓝对抗（红队攻击流程/蓝队检测规则）
    - 供应链安全（SBOM生成/漏洞扫描）
    - DevSecOps（CI/CD集成/SAST扫描）
    - 取证分析（内存/磁盘/网络/日志）
    - 工控/IoT（Modbus/S7/设备发现）
"""
from __future__ import annotations

import os
import sys
from typing import List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domains_real import (
    red_blue_real,
    supply_chain_real,
    devsecops_real,
    forensics_real,
    iot_ics_real,
    domains_real_dashboard,
)

router = APIRouter(prefix="/api/v1/domains-real", tags=["领域真实可用（方向2）"])


def _ok(data=None, error=None) -> dict:
    return {"success": error is None, "data": data, "error": error}


# ==================== 请求模型 ====================

class SubdomainReq(BaseModel):
    domain: str
    timeout: Optional[int] = 300


class PortScanReq(BaseModel):
    target: str
    ports: Optional[str] = None
    timeout: Optional[int] = 300


class ServiceReq(BaseModel):
    target: str
    ports: Optional[str] = None
    timeout: Optional[int] = 300


class VulnScanReq(BaseModel):
    target: str
    templates: Optional[str] = None
    timeout: Optional[int] = 300


class PersistenceReq(BaseModel):
    task_name: str
    command: str
    schedule: str = "ONLOGON"


class CrontabReq(BaseModel):
    entry: str


class AttackChainReq(BaseModel):
    domain: str
    target_ip: str
    timeout: Optional[int] = 300


class IDSRuleReq(BaseModel):
    name: str
    engine: str = "suricata"
    rule_text: str
    severity: str = "medium"
    description: str = ""


class AlertReq(BaseModel):
    alert_name: str
    source: str
    details: str
    severity: str = "medium"


class SBOMSyftReq(BaseModel):
    target: str
    output_format: str = "cyclonedx-json"
    output_file: Optional[str] = None
    timeout: Optional[int] = 300


class SBOMCycloneReq(BaseModel):
    project_dir: str
    output_format: str = "json"
    timeout: Optional[int] = 300


class GrypeScanReq(BaseModel):
    sbom_file: str
    output_format: str = "json"
    timeout: Optional[int] = 300


class TrivyScanReq(BaseModel):
    target: str
    scan_type: str = "fs"
    severity: str = "CRITICAL,HIGH,MEDIUM"
    timeout: Optional[int] = 300


class JenkinsBuildReq(BaseModel):
    jenkins_url: str
    job_name: str
    token: str
    params: Optional[dict] = None


class JenkinsStatusReq(BaseModel):
    jenkins_url: str
    job_name: str
    build_number: Optional[int] = None


class GitlabPipelineReq(BaseModel):
    gitlab_url: str
    project_id: str
    token: str
    ref: str = "main"
    variables: Optional[dict] = None


class GitlabStatusReq(BaseModel):
    gitlab_url: str
    project_id: str
    pipeline_id: int
    token: str


class SemgrepScanReq(BaseModel):
    target_path: str
    config: str = "p/security-audit"
    lang: Optional[str] = None
    timeout: Optional[int] = 300


class CustomRuleReq(BaseModel):
    name: str
    rule_yaml: str
    description: str = ""


class SecurityGateReq(BaseModel):
    name: str
    stage: str
    condition: str
    action: str
    description: str = ""


class EvaluateGateReq(BaseModel):
    scan_results: dict


class ForensicCaseReq(BaseModel):
    case_name: str
    description: str = ""


class EvidenceReq(BaseModel):
    case_id: str
    evidence_path: str
    evidence_type: str = "disk_image"


class MemoryReq(BaseModel):
    memory_image: str
    plugin: str = "windows.pslist"
    timeout: Optional[int] = 300


class DiskPartitionReq(BaseModel):
    image_path: str
    timeout: Optional[int] = 120


class DiskFilesReq(BaseModel):
    image_path: str
    offset: int = 0
    timeout: Optional[int] = 120


class DiskExtractReq(BaseModel):
    image_path: str
    inode: int
    offset: int = 0
    output_dir: Optional[str] = None


class PcapReq(BaseModel):
    pcap_file: str
    timeout: Optional[int] = 120


class LogAnalysisReq(BaseModel):
    log_file: str
    pattern: Optional[str] = None
    top_n: int = 20


class ModbusReadReq(BaseModel):
    host: str
    port: int = 502
    slave_id: int = 1
    start_addr: int = 0
    quantity: int = 10
    timeout: int = 10


class ModbusScanReq(BaseModel):
    cidr: str
    port: int = 502
    timeout: int = 5


class S7DetectReq(BaseModel):
    host: str
    port: int = 102
    timeout: int = 10


class ICSDiscoverReq(BaseModel):
    cidr: str
    timeout: Optional[int] = 120


class IoTDiscoverReq(BaseModel):
    cidr: str
    timeout: Optional[int] = 120


class IoTFingerprintReq(BaseModel):
    ip: str
    port: int = 80
    timeout: int = 10


# ============================================================
# 仪表盘聚合（4端点）
# ============================================================
@router.get("/overview")
def dashboard_overview():
    """仪表盘总览：5大领域 + 工具可用性 + 统计"""
    return _ok(domains_real_dashboard.get_dashboard_overview())


@router.get("/health")
def all_health():
    """全部健康检查"""
    return _ok(domains_real_dashboard.get_all_health())


@router.get("/domain/{domain_id}")
def domain_detail(domain_id: str):
    """单个领域详情"""
    return _ok(domains_real_dashboard.get_domain_detail(domain_id))


@router.get("/tools-status")
def tools_status():
    """所有领域工具可用性矩阵"""
    overview = domains_real_dashboard.get_dashboard_overview()
    return _ok(overview["tool_status"])


# ============================================================
# 红蓝对抗做实（12端点）
# ============================================================
@router.get("/red-blue/tools")
def rb_tools():
    """红蓝对抗工具可用性"""
    return _ok(red_blue_real.tool_availability())


@router.post("/red-blue/subdomain-enum")
def rb_subdomain_enum(req: SubdomainReq):
    """红队：子域名枚举（subfinder）"""
    return _ok(red_blue_real.red_subdomain_enum(req.domain, req.timeout))


@router.post("/red-blue/port-scan")
def rb_port_scan(req: PortScanReq):
    """红队：端口扫描（nmap）"""
    return _ok(red_blue_real.red_port_scan(req.target, req.ports, req.timeout))


@router.post("/red-blue/service-detect")
def rb_service_detect(req: ServiceReq):
    """红队：服务识别（nmap -sV）"""
    return _ok(red_blue_real.red_service_detect(req.target, req.ports, req.timeout))


@router.post("/red-blue/vuln-scan")
def rb_vuln_scan(req: VulnScanReq):
    """红队：漏洞扫描（nuclei）"""
    return _ok(red_blue_real.red_vuln_scan(req.target, req.templates, req.timeout))


@router.post("/red-blue/persistence-schtasks")
def rb_persistence_schtasks(req: PersistenceReq):
    """红队：Windows 计划任务后门"""
    return _ok(red_blue_real.red_persistence_schtasks(req.task_name, req.command, req.schedule))


@router.post("/red-blue/persistence-crontab")
def rb_persistence_crontab(req: CrontabReq):
    """红队：Linux crontab 后门"""
    return _ok(red_blue_real.red_persistence_crontab(req.entry))


@router.post("/red-blue/log-cleanup-windows")
def rb_log_cleanup_windows():
    """红队：Windows 日志清理"""
    return _ok(red_blue_real.red_log_cleanup_windows())


@router.post("/red-blue/log-cleanup-linux")
def rb_log_cleanup_linux():
    """红队：Linux 日志清理"""
    return _ok(red_blue_real.red_log_cleanup_linux())


@router.post("/red-blue/attack-chain")
def rb_attack_chain(req: AttackChainReq):
    """红队：完整攻击链编排"""
    return _ok(red_blue_real.run_full_attack_chain(req.domain, req.target_ip, req.timeout))


@router.get("/red-blue/attack-sessions")
def rb_attack_sessions():
    """红队：攻击会话列表"""
    return _ok(red_blue_real.list_attack_sessions())


@router.get("/red-blue/ids-rules")
def rb_ids_rules():
    """蓝队：IDS 检测规则列表"""
    return _ok(red_blue_real.list_ids_rules())


@router.post("/red-blue/ids-rules")
def rb_create_ids_rule(req: IDSRuleReq):
    """蓝队：创建自定义 IDS 规则"""
    return _ok(red_blue_real.create_ids_rule(req.name, req.engine, req.rule_text, req.severity, req.description))


@router.post("/red-blue/ids-rules/validate")
def rb_validate_ids_rule(req: IDSRuleReq):
    """蓝队：校验 IDS 规则语法"""
    return _ok(red_blue_real.validate_ids_rule(req.rule_text, req.engine))


@router.get("/red-blue/anomaly-detection")
def rb_anomaly_detection():
    """蓝队：异常行为检测模板"""
    return _ok(red_blue_real.list_anomaly_detection())


@router.get("/red-blue/alert-rules")
def rb_alert_rules():
    """蓝队：告警规则列表"""
    return _ok(red_blue_real.list_alert_rules())


@router.post("/red-blue/alerts")
def rb_trigger_alert(req: AlertReq):
    """蓝队：记录告警事件"""
    return _ok(red_blue_real.trigger_alert(req.alert_name, req.source, req.details, req.severity))


@router.get("/red-blue/alerts")
def rb_list_alerts(severity: Optional[str] = None, status: Optional[str] = None):
    """蓝队：告警事件列表"""
    return _ok(red_blue_real.list_alerts(severity, status))


@router.get("/red-blue/ir-playbooks")
def rb_ir_playbooks():
    """蓝队：事件响应 Playbook"""
    return _ok(red_blue_real.list_ir_playbooks())


@router.get("/red-blue/ir-playbooks/{playbook_id}")
def rb_get_ir_playbook(playbook_id: str):
    """蓝队：单个事件响应 Playbook 详情"""
    pb = red_blue_real.get_ir_playbook(playbook_id)
    if pb:
        return _ok(pb)
    return _ok(None, f"Playbook 不存在: {playbook_id}")


# ============================================================
# 供应链安全做实（7端点）
# ============================================================
@router.get("/supply-chain/tools")
def sc_tools():
    """供应链安全工具可用性"""
    return _ok(supply_chain_real.tool_availability())


@router.post("/supply-chain/sbom-syft")
def sc_sbom_syft(req: SBOMSyftReq):
    """生成 SBOM（syft）"""
    return _ok(supply_chain_real.generate_sbom_syft(req.target, req.output_format, req.output_file, req.timeout))


@router.post("/supply-chain/sbom-cyclonedx")
def sc_sbom_cyclonedx(req: SBOMCycloneReq):
    """生成 SBOM（cyclonedx）"""
    return _ok(supply_chain_real.generate_sbom_cyclonedx(req.project_dir, req.output_format, req.timeout))


@router.get("/supply-chain/sbom")
def sc_list_sbom():
    """SBOM 记录列表"""
    return _ok(supply_chain_real.list_sbom_records())


@router.post("/supply-chain/scan-grype")
def sc_scan_grype(req: GrypeScanReq):
    """漏洞扫描（grype）"""
    return _ok(supply_chain_real.scan_vulns_grype(req.sbom_file, req.output_format, req.timeout))


@router.post("/supply-chain/scan-trivy")
def sc_scan_trivy(req: TrivyScanReq):
    """漏洞扫描（trivy）"""
    return _ok(supply_chain_real.scan_vulns_trivy(req.target, req.scan_type, req.severity, req.timeout))


@router.get("/supply-chain/vuln-scans")
def sc_list_vuln_scans():
    """漏洞扫描记录列表"""
    return _ok(supply_chain_real.list_vuln_scans())


@router.get("/supply-chain/risk-summary")
def sc_risk_summary():
    """风险评级汇总"""
    return _ok(supply_chain_real.risk_rating_summary())


# ============================================================
# DevSecOps 做实（10端点）
# ============================================================
@router.get("/devsecops/tools")
def ds_tools():
    """DevSecOps 工具可用性"""
    return _ok(devsecops_real.tool_availability())


@router.post("/devsecops/jenkins/build")
def ds_jenkins_build(req: JenkinsBuildReq):
    """触发 Jenkins 构建"""
    return _ok(devsecops_real.jenkins_trigger_build(req.jenkins_url, req.job_name, req.token, req.params))


@router.post("/devsecops/jenkins/status")
def ds_jenkins_status(req: JenkinsStatusReq):
    """查询 Jenkins 构建状态"""
    return _ok(devsecops_real.jenkins_get_build_status(req.jenkins_url, req.job_name, req.build_number))


@router.post("/devsecops/gitlab/pipeline")
def ds_gitlab_pipeline(req: GitlabPipelineReq):
    """触发 GitLab CI 流水线"""
    return _ok(devsecops_real.gitlab_ci_trigger_pipeline(req.gitlab_url, req.project_id, req.token, req.ref, req.variables))


@router.post("/devsecops/gitlab/status")
def ds_gitlab_status(req: GitlabStatusReq):
    """查询 GitLab CI 流水线状态"""
    return _ok(devsecops_real.gitlab_ci_get_pipeline_status(req.gitlab_url, req.project_id, req.pipeline_id, req.token))


@router.get("/devsecops/security-gates")
def ds_security_gates():
    """安全门禁规则列表"""
    return _ok(devsecops_real.list_security_gates())


@router.post("/devsecops/security-gates")
def ds_create_gate(req: SecurityGateReq):
    """创建安全门禁规则"""
    return _ok(devsecops_real.create_security_gate(req.name, req.stage, req.condition, req.action, req.description))


@router.post("/devsecops/security-gates/evaluate")
def ds_evaluate_gates(req: EvaluateGateReq):
    """评估安全门禁"""
    return _ok(devsecops_real.evaluate_gates(req.scan_results))


@router.get("/devsecops/semgrep-rules")
def ds_semgrep_rules():
    """Semgrep 规则包列表"""
    return _ok(devsecops_real.list_semgrep_rules())


@router.post("/devsecops/semgrep-scan")
def ds_semgrep_scan(req: SemgrepScanReq):
    """Semgrep SAST 静态代码分析"""
    return _ok(devsecops_real.semgrep_scan(req.target_path, req.config, req.lang, req.timeout))


@router.get("/devsecops/sast-scans")
def ds_sast_scans():
    """SAST 扫描记录列表"""
    return _ok(devsecops_real.list_sast_scans())


@router.post("/devsecops/semgrep-custom-rule")
def ds_add_custom_rule(req: CustomRuleReq):
    """添加自定义 Semgrep 规则"""
    return _ok(devsecops_real.add_custom_semgrep_rule(req.name, req.rule_yaml, req.description))


@router.get("/devsecops/semgrep-custom-rules")
def ds_list_custom_rules():
    """自定义 Semgrep 规则列表"""
    return _ok(devsecops_real.list_custom_semgrep_rules())


# ============================================================
# 取证分析做实（10端点）
# ============================================================
@router.get("/forensics/tools")
def fr_tools():
    """取证工具可用性"""
    return _ok(forensics_real.tool_availability())


@router.post("/forensics/cases")
def fr_create_case(req: ForensicCaseReq):
    """创建取证案件"""
    return _ok(forensics_real.create_case(req.case_name, req.description))


@router.get("/forensics/cases")
def fr_list_cases():
    """取证案件列表"""
    return _ok(forensics_real.list_cases())


@router.post("/forensics/evidence")
def fr_add_evidence(req: EvidenceReq):
    """添加证据文件"""
    return _ok(forensics_real.add_evidence(req.case_id, req.evidence_path, req.evidence_type))


@router.post("/forensics/memory-analysis")
def fr_memory(req: MemoryReq):
    """内存取证分析（Volatility3）"""
    return _ok(forensics_real.memory_analyze(req.memory_image, req.plugin, req.timeout))


@router.get("/forensics/volatility-plugins")
def fr_vol_plugins():
    """可用 Volatility 插件列表"""
    return _ok(forensics_real.list_volatility_plugins())


@router.post("/forensics/disk-partitions")
def fr_disk_partitions(req: DiskPartitionReq):
    """磁盘分区表分析（mmls）"""
    return _ok(forensics_real.disk_list_partitions(req.image_path, req.timeout))


@router.post("/forensics/disk-files")
def fr_disk_files(req: DiskFilesReq):
    """文件系统文件列表（fls）"""
    return _ok(forensics_real.disk_list_files(req.image_path, req.offset, req.timeout))


@router.post("/forensics/disk-extract")
def fr_disk_extract(req: DiskExtractReq):
    """从磁盘镜像提取文件（icat）"""
    return _ok(forensics_real.disk_extract_file(req.image_path, req.inode, req.offset, req.output_dir))


@router.post("/forensics/pcap-info")
def fr_pcap_info(req: PcapReq):
    """PCAP 基本信息（capinfos）"""
    return _ok(forensics_real.network_pcap_info(req.pcap_file, req.timeout))


@router.post("/forensics/pcap-protocols")
def fr_pcap_protocols(req: PcapReq):
    """PCAP 协议分布分析（tshark）"""
    return _ok(forensics_real.network_pcap_protocol_stats(req.pcap_file, req.timeout))


@router.post("/forensics/pcap-http")
def fr_pcap_http(req: PcapReq):
    """PCAP HTTP 流量提取（tshark）"""
    return _ok(forensics_real.network_extract_http(req.pcap_file, req.timeout))


@router.post("/forensics/log-analysis")
def fr_log_analysis(req: LogAnalysisReq):
    """日志文件取证分析"""
    return _ok(forensics_real.analyze_log_file(req.log_file, req.pattern, req.top_n))


# ============================================================
# 工控/IoT 做实（10端点）
# ============================================================
@router.get("/iot-ics/tools")
def iot_tools():
    """工控/IoT 工具可用性"""
    return _ok(iot_ics_real.tool_availability())


@router.post("/iot-ics/modbus-read")
def iot_modbus_read(req: ModbusReadReq):
    """Modbus TCP 寄存器读取"""
    return _ok(iot_ics_real.modbus_read_holding_registers(req.host, req.port, req.slave_id, req.start_addr, req.quantity, req.timeout))


@router.post("/iot-ics/modbus-scan")
def iot_modbus_scan(req: ModbusScanReq):
    """Modbus 设备扫描"""
    return _ok(iot_ics_real.modbus_scan_devices(req.cidr, req.port, req.timeout))


@router.post("/iot-ics/s7-detect")
def iot_s7_detect(req: S7DetectReq):
    """S7 设备检测"""
    return _ok(iot_ics_real.s7_device_detect(req.host, req.port, req.timeout))


@router.get("/iot-ics/s7-functions")
def iot_s7_functions():
    """S7 常用功能码"""
    return _ok(iot_ics_real.S7_COMMON_FUNCTIONS)


@router.post("/iot-ics/ics-discover")
def iot_ics_discover(req: ICSDiscoverReq):
    """工控设备发现"""
    return _ok(iot_ics_real.discover_ics_devices(req.cidr, req.timeout))


@router.get("/iot-ics/ics-discoveries")
def iot_list_ics():
    """工控设备发现记录"""
    return _ok(iot_ics_real.list_ics_discoveries())


@router.post("/iot-ics/iot-discover")
def iot_iot_discover(req: IoTDiscoverReq):
    """IoT 设备发现"""
    return _ok(iot_ics_real.discover_iot_devices(req.cidr, req.timeout))


@router.get("/iot-ics/iot-discoveries")
def iot_list_iot():
    """IoT 设备发现记录"""
    return _ok(iot_ics_real.list_iot_discoveries())


@router.post("/iot-ics/device-fingerprint")
def iot_fingerprint(req: IoTFingerprintReq):
    """IoT 设备指纹识别"""
    return _ok(iot_ics_real.iot_device_fingerprint(req.ip, req.port, req.timeout))


@router.get("/iot-ics/vulns-catalog")
def iot_vulns_catalog():
    """常见 IoT 漏洞目录"""
    return _ok(iot_ics_real.list_common_iot_vulns())


@router.get("/iot-ics/modbus-analyses")
def iot_modbus_analyses():
    """Modbus 分析记录"""
    return _ok(iot_ics_real.list_modbus_analyses())


@router.get("/iot-ics/s7-analyses")
def iot_s7_analyses():
    """S7 分析记录"""
    return _ok(iot_ics_real.list_s7_analyses())
