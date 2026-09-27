# -*- coding: utf-8 -*-
"""
web3_security_routes.py — 第27轮升级方向4：区块链与 Web3 安全 REST API。

路由前缀: /api/v1/web3-security
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。
"""

from __future__ import annotations

import logging
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/web3-security",
                    tags=["Web3 安全"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import，带 fallback）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from web3_security.smart_contract import (
        detect_vulnerabilities, assess_contract, build_audit_report,
        formal_check, get_contract_runtime, CONTRACT_LANGUAGES,
        VULN_CATALOG, RISK_LEVELS,
    )
    from web3_security.defi_security import (
        assess_protocol, analyze_oracle, impermanent_loss,
        simulate_flashloan_attack, get_defi_registry,
        PROTOCOL_TYPES, ATTACK_TYPES, ORACLE_TYPES,
    )
    from web3_security.nft_security import (
        assess_nft_collection, detect_nft_vulns, detect_money_laundering,
        get_nft_registry, NFT_TYPES, MARKET_RISKS,
    )
    from web3_security.dao_security import (
        assess_governance, assess_treasury, get_dao_registry,
        DAO_TYPES, ATTACK_TYPES as DAO_ATTACK_TYPES,
    )
    from web3_security.node_security import (
        audit_node_config, probe_rpc, list_network_attacks,
        get_node_registry, NODE_TYPES, CONSENSUS_ALGOS, NETWORK_ATTACKS,
    )
    from web3_security.crypto_security import (
        validate_address, assess_wallet, detect_approval_risk,
        analyze_transaction_risk, risk_score_address, get_crypto_registry,
        WALLET_TYPES, THREAT_PATTERNS,
    )
    from web3_security.web3_dashboard import (
        get_dashboard, overview, recent_events, risk_distribution,
        reference_data, SYSTEM_SETTINGS,
    )
    _MOD_AVAILABLE = True
    logger.info("web3_security_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("web3_security_routes: load failed: %s", e)
    try:
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from web3_security.smart_contract import (  # noqa
            detect_vulnerabilities, assess_contract, build_audit_report,
            formal_check, get_contract_runtime, CONTRACT_LANGUAGES,
            VULN_CATALOG, RISK_LEVELS,
        )
        from web3_security.defi_security import (  # noqa
            assess_protocol, analyze_oracle, impermanent_loss,
            simulate_flashloan_attack, get_defi_registry,
            PROTOCOL_TYPES, ATTACK_TYPES, ORACLE_TYPES,
        )
        from web3_security.nft_security import (  # noqa
            assess_nft_collection, detect_nft_vulns, detect_money_laundering,
            get_nft_registry, NFT_TYPES, MARKET_RISKS,
        )
        from web3_security.dao_security import (  # noqa
            assess_governance, assess_treasury, get_dao_registry,
            DAO_TYPES, ATTACK_TYPES as DAO_ATTACK_TYPES,
        )
        from web3_security.node_security import (  # noqa
            audit_node_config, probe_rpc, list_network_attacks,
            get_node_registry, NODE_TYPES, CONSENSUS_ALGOS, NETWORK_ATTACKS,
        )
        from web3_security.crypto_security import (  # noqa
            validate_address, assess_wallet, detect_approval_risk,
            analyze_transaction_risk, risk_score_address, get_crypto_registry,
            WALLET_TYPES, THREAT_PATTERNS,
        )
        from web3_security.web3_dashboard import (  # noqa
            get_dashboard, overview, recent_events, risk_distribution,
            reference_data, SYSTEM_SETTINGS,
        )
        _MOD_AVAILABLE = True
        logger.info("web3_security_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("web3_security_routes: fallback load failed: %s", e2)


# --------------------------------------------------------------------------- #
# 任务存储
# --------------------------------------------------------------------------- #
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    tid = uuid.uuid4().hex[:16]
    TASKS[tid] = {
        "task_id": tid, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return tid


def _finish_task(tid: str, result: Any, error: Optional[str] = None) -> None:
    if tid in TASKS:
        t = TASKS[tid]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        chars = [c for c in obj if ord(c) >= 32 or c in ("\t", "\n", "\r")]
        s = "".join(chars)
        return s.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("Web3 安全模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class AnalyzeReq(BaseModel):
    source: str
    language: str = "auto"
    name: str = "Untitled"


class DeployReq(BaseModel):
    name: str
    source: str
    language: str = "solidity"
    deployer: str = "0xDeployer"


class CallReq(BaseModel):
    address: str
    func: str
    caller: str = "0xUser"
    value: int = 0
    args: Dict[str, Any] = Field(default_factory=dict)


class FormalSpecReq(BaseModel):
    name: str = "spec"
    invariants: List[str] = Field(default_factory=list)
    preconditions: List[str] = Field(default_factory=list)
    postconditions: List[str] = Field(default_factory=list)


class DeFiAssessReq(BaseModel):
    protocol_type: str = "lending"
    name: str = "Unnamed"
    tvl_usd: float = 0
    oracle_type: str = "spot"
    has_timelock: bool = False
    multisig_threshold: int = 0
    admin_keys: int = 1
    liquidity_depth: float = 0
    has_flashloan_fee: bool = True
    governance_quorum_pct: float = 0
    upgrade_timelock_hours: int = 0


class OracleReq(BaseModel):
    prices: List[float] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    window: int = 60


class ILReq(BaseModel):
    price_ratio: float = 1.0


class FlashLoanReq(BaseModel):
    oracle_price: float = 100.0
    manipulated_price: float = 120.0
    pool_reserve: float = 1_000_000
    borrow_amt: float = 5_000_000


class NFTAssessReq(BaseModel):
    name: str
    source: str = ""
    nft_type: str = "art"
    holders: int = 0
    items: int = 0
    floor_price_usd: float = 0


class MlReq(BaseModel):
    transactions: List[Dict[str, Any]] = Field(default_factory=list)


class DAOCreateReq(BaseModel):
    name: str
    dao_type: str = "governance"


class ProposalReq(BaseModel):
    title: str
    description: str = ""
    proposer: str = "0xProposer"
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    deposit_usd: float = 0


class VoteReq(BaseModel):
    voter: str
    choice: str = "for"
    weight: float = 1.0


class GovAssessReq(BaseModel):
    voting_turnout_pct: float = 0
    quorum_pct: float = 0
    timelock_hours: int = 0
    proposal_threshold_pct: float = 0
    multisig_signers: int = 0
    multisig_threshold: int = 0
    delegation_enabled: bool = False
    has_emergency_pause: bool = False


class TreasuryReq(BaseModel):
    total_usd: float = 0
    monthly_outflow_usd: float = 0
    multisig_threshold: int = 0
    multisig_signers: int = 0
    timelock_hours: int = 0
    verified_signers: bool = False
    external_auditor: bool = False


class NodeAuditReq(BaseModel):
    node_type: str = "full"
    name: str = "node-1"
    rpc_enabled: bool = True
    rpc_auth: bool = False
    rpc_tls: bool = False
    rpc_exposed_public: bool = False
    p2p_max_peers: int = 50
    p2p_allow_private: bool = False
    consensus: str = "pos"
    pruning: bool = True
    snapshot_sync: bool = False
    log_level: str = "info"
    has_firewall: bool = True
    ufw_enabled: bool = True
    rate_limit_rps: int = 0
    exposed_ports: List[int] = Field(default_factory=list)


class RpcProbeReq(BaseModel):
    endpoint: str
    timeout: float = 1.0


class AddressReq(BaseModel):
    address: str
    chain: str = "ethereum"


class WalletReq(BaseModel):
    name: str = "wallet-1"
    wallet_type: str = "hot"
    encryption_enabled: bool = True
    biometric_enabled: bool = False
    seed_phrase_backup: bool = False
    seed_offline_stored: bool = False
    mfa_enabled: bool = False
    multi_approval: bool = False
    daily_limit_usd: float = 0
    whitelist_enabled: bool = False
    was_ever_online: bool = True


class ApprovalReq(BaseModel):
    spender_allowance: float = 0
    expected_max: float = 0
    spender_is_verified: bool = False


class TxReq(BaseModel):
    transactions: List[Dict[str, Any]] = Field(default_factory=list)


class AddressRiskReq(BaseModel):
    address: str = ""
    tx_count: int = 0
    connected_sanctioned: bool = False
    connected_mixer: bool = False
    anomaly_count: int = 0


class SettingsReq(BaseModel):
    platform_name: Optional[str] = None
    theme: Optional[str] = None
    chain_default: Optional[str] = None
    auto_refresh_seconds: Optional[int] = None
    risk_threshold: Optional[str] = None
    alert_channels: Optional[List[str]] = None


# =========================================================================== #
# 1. Web3 总览 / 控制台（6 个端点）
# =========================================================================== #
@router.get("/overview")
def w3_overview():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(overview())
    except Exception as e:
        return fail(f"总览失败: {e}", 500)


@router.get("/events")
def w3_events(limit: int = Query(20, ge=1, le=100)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(recent_events(limit))
    except Exception as e:
        return fail(f"事件查询失败: {e}", 500)


@router.get("/risk-distribution")
def w3_risk_dist():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(risk_distribution())
    except Exception as e:
        return fail(f"风险分布失败: {e}", 500)


@router.get("/reference")
def w3_reference():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(reference_data())
    except Exception as e:
        return fail(f"参考数据失败: {e}", 500)


@router.get("/settings")
def w3_settings():
    try:
        return ok(SYSTEM_SETTINGS)
    except Exception as e:
        return fail(f"读取设置失败: {e}", 500)


@router.post("/settings")
def w3_update_settings(req: SettingsReq):
    try:
        for k, v in req.dict(exclude_none=True).items():
            SYSTEM_SETTINGS[k] = v
        return ok(SYSTEM_SETTINGS)
    except Exception as e:
        return fail(f"更新设置失败: {e}", 500)


# =========================================================================== #
# 2. 智能合约安全（12 个端点）
# =========================================================================== #
@router.get("/contract/languages")
def sc_languages():
    try:
        return ok(CONTRACT_LANGUAGES)
    except Exception as e:
        return fail(f"查询语言列表失败: {e}", 500)


@router.get("/contract/vuln-catalog")
def sc_catalog():
    try:
        return ok(VULN_CATALOG)
    except Exception as e:
        return fail(f"查询漏洞目录失败: {e}", 500)


@router.post("/contract/analyze")
def sc_analyze(req: AnalyzeReq):
    try:
        g = _guard()
        if g is not None:
            return g
        result = assess_contract(req.source, req.language, req.name)
        return ok(result)
    except Exception as e:
        return fail(f"合约分析失败: {e}", 500)


@router.post("/contract/detect")
def sc_detect(req: AnalyzeReq):
    try:
        g = _guard()
        if g is not None:
            return g
        findings = detect_vulnerabilities(req.source, req.language)
        return ok({"findings": findings, "count": len(findings)})
    except Exception as e:
        return fail(f"漏洞检测失败: {e}", 500)


@router.post("/contract/deploy")
def sc_deploy(req: DeployReq):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_contract_runtime().deploy(
            req.name, req.source, req.language, req.deployer)
        return ok(c)
    except Exception as e:
        return fail(f"部署合约失败: {e}", 500)


@router.get("/contract/list")
def sc_list():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_contract_runtime().list_contracts())
    except Exception as e:
        return fail(f"合约列表失败: {e}", 500)


@router.get("/contract/{address}")
def sc_detail(address: str):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_contract_runtime().contracts.get(address)
        if not c:
            return fail("合约不存在", 404)
        return ok(c)
    except Exception as e:
        return fail(f"查询合约失败: {e}", 500)


@router.post("/contract/call")
def sc_call(req: CallReq):
    try:
        g = _guard()
        if g is not None:
            return g
        result = get_contract_runtime().call(
            req.address, req.func, req.caller, req.value, req.args)
        return ok(result)
    except Exception as e:
        return fail(f"调用合约失败: {e}", 500)


@router.get("/contract/{address}/events")
def sc_events(address: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_contract_runtime().events_for(address))
    except Exception as e:
        return fail(f"事件查询失败: {e}", 500)


@router.get("/contract/coverage/report")
def sc_coverage():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_contract_runtime().coverage_report())
    except Exception as e:
        return fail(f"覆盖率失败: {e}", 500)


@router.post("/contract/formal-check")
def sc_formal(req: FormalSpecReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(formal_check(req.dict()))
    except Exception as e:
        return fail(f"形式化验证失败: {e}", 500)


@router.post("/contract/audit-report")
def sc_report(req: AnalyzeReq):
    try:
        g = _guard()
        if g is not None:
            return g
        a = assess_contract(req.source, req.language, req.name)
        return ok(build_audit_report(a))
    except Exception as e:
        return fail(f"生成审计报告失败: {e}", 500)


# =========================================================================== #
# 3. DeFi 安全（10 个端点）
# =========================================================================== #
@router.get("/defi/protocol-types")
def df_types():
    return ok(PROTOCOL_TYPES)


@router.get("/defi/attack-types")
def df_attacks():
    return ok(ATTACK_TYPES)


@router.get("/defi/oracle-types")
def df_oracles():
    return ok(ORACLE_TYPES)


@router.post("/defi/assess")
def df_assess(req: DeFiAssessReq):
    try:
        g = _guard()
        if g is not None:
            return g
        a = assess_protocol(**req.dict())
        pid = get_defi_registry().register(a)
        return ok({"id": pid, **a})
    except Exception as e:
        return fail(f"DeFi 评估失败: {e}", 500)


@router.get("/defi/list")
def df_list():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_defi_registry().list())
    except Exception as e:
        return fail(f"DeFi 列表失败: {e}", 500)


@router.get("/defi/{pid}")
def df_get(pid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        a = get_defi_registry().get(pid)
        if not a:
            return fail("协议不存在", 404)
        return ok(a)
    except Exception as e:
        return fail(f"查询协议失败: {e}", 500)


@router.post("/defi/oracle/analyze")
def df_oracle(req: OracleReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(analyze_oracle(req.prices, req.sources, req.window))
    except Exception as e:
        return fail(f"预言机分析失败: {e}", 500)


@router.post("/defi/impermanent-loss")
def df_il(req: ILReq):
    try:
        return ok(impermanent_loss(req.price_ratio))
    except Exception as e:
        return fail(f"无常损失计算失败: {e}", 500)


@router.post("/defi/flashloan/simulate")
def df_flash(req: FlashLoanReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(simulate_flashloan_attack(
            req.oracle_price, req.manipulated_price,
            req.pool_reserve, req.borrow_amt))
    except Exception as e:
        return fail(f"闪电贷模拟失败: {e}", 500)


# =========================================================================== #
# 4. NFT 安全（8 个端点）
# =========================================================================== #
@router.get("/nft/types")
def nft_types():
    return ok(NFT_TYPES)


@router.get("/nft/market-risks")
def nft_market():
    return ok(MARKET_RISKS)


@router.post("/nft/assess")
def nft_assess(req: NFTAssessReq):
    try:
        g = _guard()
        if g is not None:
            return g
        a = assess_nft_collection(
            req.name, req.source, req.nft_type,
            req.holders, req.items, req.floor_price_usd)
        cid = get_nft_registry().register(a)
        return ok({"id": cid, **a})
    except Exception as e:
        return fail(f"NFT 评估失败: {e}", 500)


@router.post("/nft/detect-vulns")
def nft_detect(req: AnalyzeReq):
    try:
        g = _guard()
        if g is not None:
            return g
        findings = detect_nft_vulns(req.source)
        return ok({"findings": findings, "count": len(findings)})
    except Exception as e:
        return fail(f"NFT 漏洞检测失败: {e}", 500)


@router.get("/nft/list")
def nft_list():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_nft_registry().list())
    except Exception as e:
        return fail(f"NFT 列表失败: {e}", 500)


@router.post("/nft/ml/scan")
def nft_ml(req: MlReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(detect_money_laundering(req.transactions))
    except Exception as e:
        return fail(f"洗钱扫描失败: {e}", 500)


# =========================================================================== #
# 5. DAO 安全（10 个端点）
# =========================================================================== #
@router.get("/dao/types")
def dao_types():
    return ok(DAO_TYPES)


@router.get("/dao/attack-types")
def dao_attacks():
    return ok(DAO_ATTACK_TYPES)


@router.post("/dao/create")
def dao_create(req: DAOCreateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        d = get_dao_registry().create(req.name, req.dao_type)
        return ok({"id": "todo", "name": d.name, "type": d.dao_type})
    except Exception as e:
        return fail(f"创建 DAO 失败: {e}", 500)


@router.get("/dao/list")
def dao_list():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_dao_registry().list())
    except Exception as e:
        return fail(f"DAO 列表失败: {e}", 500)


@router.get("/dao/{did}")
def dao_detail(did: str):
    try:
        g = _guard()
        if g is not None:
            return g
        d = get_dao_registry().get(did)
        if not d:
            return fail("DAO 不存在", 404)
        return ok({"name": d.name, "type": d.dao_type,
                   "members": list(d.members.values()),
                   "proposals": d.proposals,
                   "treasury_usd": d.treasury_usd})
    except Exception as e:
        return fail(f"DAO 详情失败: {e}", 500)


@router.post("/dao/{did}/propose")
def dao_propose(did: str, req: ProposalReq):
    try:
        g = _guard()
        if g is not None:
            return g
        d = get_dao_registry().get(did)
        if not d:
            return fail("DAO 不存在", 404)
        return ok(d.propose(req.title, req.description, req.proposer,
                            req.actions, req.deposit_usd))
    except Exception as e:
        return fail(f"提交提案失败: {e}", 500)


@router.post("/dao/{did}/vote")
def dao_vote(did: str, req: VoteReq):
    try:
        g = _guard()
        if g is not None:
            return g
        d = get_dao_registry().get(did)
        if not d:
            return fail("DAO 不存在", 404)
        # 找最近的活动提案
        active = [p for p in d.proposals if p["status"] == "active"]
        if not active:
            return fail("无活动提案", 400)
        return ok(d.vote(active[-1]["id"], req.voter, req.choice, req.weight))
    except Exception as e:
        return fail(f"投票失败: {e}", 500)


@router.post("/dao/{did}/execute")
def dao_execute(did: str):
    try:
        g = _guard()
        if g is not None:
            return g
        d = get_dao_registry().get(did)
        if not d:
            return fail("DAO 不存在", 404)
        active = [p for p in d.proposals if p["status"] == "active"]
        if not active:
            return fail("无活动提案", 400)
        return ok(d.execute(active[-1]["id"]))
    except Exception as e:
        return fail(f"执行提案失败: {e}", 500)


@router.post("/dao/governance/assess")
def dao_gov(req: GovAssessReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(assess_governance(**req.dict()))
    except Exception as e:
        return fail(f"治理评估失败: {e}", 500)


@router.post("/dao/treasury/assess")
def dao_treasury(req: TreasuryReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(assess_treasury(**req.dict()))
    except Exception as e:
        return fail(f"国库评估失败: {e}", 500)


# =========================================================================== #
# 6. 节点安全（8 个端点）
# =========================================================================== #
@router.get("/node/types")
def node_types():
    return ok(NODE_TYPES)


@router.get("/node/consensus")
def node_consensus():
    return ok(CONSENSUS_ALGOS)


@router.get("/node/attacks")
def node_attacks():
    try:
        return ok(list_network_attacks())
    except Exception as e:
        return fail(f"攻击列表失败: {e}", 500)


@router.post("/node/audit")
def node_audit(req: NodeAuditReq):
    try:
        g = _guard()
        if g is not None:
            return g
        a = audit_node_config(**req.dict())
        nid = get_node_registry().register(a)
        return ok({"id": nid, **a})
    except Exception as e:
        return fail(f"节点审计失败: {e}", 500)


@router.get("/node/list")
def node_list():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_node_registry().list())
    except Exception as e:
        return fail(f"节点列表失败: {e}", 500)


@router.post("/node/rpc/probe")
def node_rpc_probe(req: RpcProbeReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(probe_rpc(req.endpoint, req.timeout))
    except Exception as e:
        return fail(f"RPC 探测失败: {e}", 500)


# =========================================================================== #
# 7. 加密货币安全（12 个端点）
# =========================================================================== #
@router.get("/crypto/wallet-types")
def cr_wallet_types():
    return ok(WALLET_TYPES)


@router.get("/crypto/threat-patterns")
def cr_threats():
    return ok(THREAT_PATTERNS)


@router.post("/crypto/address/validate")
def cr_validate(req: AddressReq):
    try:
        return ok(validate_address(req.address, req.chain))
    except Exception as e:
        return fail(f"地址校验失败: {e}", 500)


@router.post("/crypto/address/risk")
def cr_addr_risk(req: AddressRiskReq):
    try:
        return ok(risk_score_address(
            req.tx_count, req.connected_sanctioned,
            req.connected_mixer, req.anomaly_count))
    except Exception as e:
        return fail(f"地址风险评分失败: {e}", 500)


@router.post("/crypto/wallet/assess")
def cr_wallet(req: WalletReq):
    try:
        g = _guard()
        if g is not None:
            return g
        a = assess_wallet(**req.dict())
        wid = get_crypto_registry().register_wallet(a)
        return ok({"id": wid, **a})
    except Exception as e:
        return fail(f"钱包评估失败: {e}", 500)


@router.get("/crypto/wallets")
def cr_wallets():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_crypto_registry().list_wallets())
    except Exception as e:
        return fail(f"钱包列表失败: {e}", 500)


@router.post("/crypto/approval/risk")
def cr_approval(req: ApprovalReq):
    try:
        return ok(detect_approval_risk(
            req.spender_allowance, req.expected_max,
            req.spender_is_verified))
    except Exception as e:
        return fail(f"授权风险失败: {e}", 500)


@router.post("/crypto/tx/analyze")
def cr_tx(req: TxReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(analyze_transaction_risk(req.transactions))
    except Exception as e:
        return fail(f"交易分析失败: {e}", 500)


# =========================================================================== #
# 8. 任务查询（2 个端点）
# =========================================================================== #
@router.get("/tasks")
def task_list():
    return ok(TASKS)


@router.get("/tasks/{tid}")
def task_get(tid: str):
    t = TASKS.get(tid)
    if not t:
        return fail("任务不存在", 404)
    return ok(t)


# =========================================================================== #
# 9. 健康检查
# =========================================================================== #
@router.get("/health")
def w3_health():
    return ok({
        "module": "web3_security",
        "version": "27.4.0",
        "available": _MOD_AVAILABLE,
        "tasks": len(TASKS),
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
