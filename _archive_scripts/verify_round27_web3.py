# -*- coding: utf-8 -*-
"""第27轮方向4 Web3 安全模块验证脚本"""
import os, sys, py_compile, importlib

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

FILES = [
    "web3_security/__init__.py",
    "web3_security/smart_contract.py",
    "web3_security/defi_security.py",
    "web3_security/nft_security.py",
    "web3_security/dao_security.py",
    "web3_security/node_security.py",
    "web3_security/crypto_security.py",
    "web3_security/web3_dashboard.py",
    "api_server/web3_security_routes.py",
]

print("=" * 60)
print("【1】py_compile 语法检查")
print("=" * 60)
ok = True
for f in FILES:
    try:
        py_compile.compile(os.path.join(ROOT, f), doraise=True)
        print(f"  [OK] {f}")
    except Exception as e:
        ok = False
        print(f"  [FAIL] {f}: {e}")
print(f"语法检查: {'全部通过' if ok else '存在错误'}")

print("\n" + "=" * 60)
print("【2】独立 import 验证")
print("=" * 60)
imports = [
    "web3_security",
    "web3_security.smart_contract",
    "web3_security.defi_security",
    "web3_security.nft_security",
    "web3_security.dao_security",
    "web3_security.node_security",
    "web3_security.crypto_security",
    "web3_security.web3_dashboard",
]
for m in imports:
    try:
        mod = importlib.import_module(m)
        print(f"  [OK] {m}")
    except Exception as e:
        ok = False
        print(f"  [FAIL] {m}: {e}")

# 路由文件独立 import（不启动 app）
try:
    sys.path.insert(0, os.path.join(ROOT, "api_server"))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "web3_security_routes", os.path.join(ROOT, "api_server", "web3_security_routes.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ep_count = len([r for r in dir(mod.router.routes)]) if hasattr(mod.router, 'routes') else 0
    routes_count = len(mod.router.routes)
    print(f"  [OK] api_server/web3_security_routes.py (路由数={routes_count})")
except Exception as e:
    ok = False
    print(f"  [FAIL] routes: {e}")

print("\n" + "=" * 60)
print("【3】真实功能冒烟测试")
print("=" * 60)

# 3.1 智能合约漏洞检测
from web3_security.smart_contract import assess_contract, detect_vulnerabilities
vuln_src = """
pragma solidity ^0.7.0;
contract Bank {
    mapping(address=>uint) public bal;
    function withdraw(uint amt) public {
        (bool ok,) = msg.sender.call{value: amt}("");
        bal[msg.sender] -= amt;
    }
    function kill() public { selfdestruct(msg.sender); }
}
"""
a = assess_contract(vuln_src, "solidity", "Test")
vids = {f["id"] for f in a["findings"]}
print(f"  合约分析: score={a['score']} rating={a['rating']} findings={len(a['findings'])}")
print(f"  检测到漏洞: {sorted(vids)}")
assert "reentrancy" in vids or "integer_underflow" in vids, "未检测到重入/下溢"
assert a["score"] < 80, "危险合约评分应较低"

# 干净合约
safe_src = """
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Safe is ReentrancyGuard {
    mapping(address=>uint) public bal;
    function withdraw(uint amt) public nonReentrant {
        require(bal[msg.sender]>=amt, "no bal");
        bal[msg.sender] -= amt;
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok, "send fail");
    }
}
"""
s = assess_contract(safe_src, "solidity", "Safe")
print(f"  安全合约: score={s['score']} findings={len(s['findings'])}")

# 3.2 DeFi 评估
from web3_security.defi_security import assess_protocol, simulate_flashloan_attack, analyze_oracle
d = assess_protocol("lending", tvl_usd=2e9, oracle_type="spot",
                    has_timelock=False, multisig_threshold=1, admin_keys=5,
                    governance_quorum_pct=1, upgrade_timelock_hours=0)
print(f"  DeFi 风险协议: score={d['score']} findings={len(d['findings'])}")
fl = simulate_flashloan_attack(100, 130, 1e6, 5e6)
print(f"  闪电贷模拟: profit=${fl['est_profit_usd']} feasible={fl['attack_feasible']}")
oa = analyze_oracle([100, 101, 99, 200, 100, 100])
print(f"  预言机分析: twap={oa['twap']} anomalies={len(oa['anomalies'])} verdict={oa['verdict']}")

# 3.3 NFT
from web3_security.nft_security import assess_nft_collection, detect_money_laundering
n = assess_nft_collection("Test", vuln_src, "art", 100, 1000, 1.0)
print(f"  NFT 评估: score={n['score']} findings={n['summary']['total']}")
ml = detect_money_laundering([
    {"from": "0xA", "to": "0xB", "note": "tornado cash deposit"},
    {"from": "0xA", "to": "0xA", "note": "self"},
] * 20)
print(f"  洗钱扫描: flagged={len(ml['flagged'])} clean%={ml['clean_pct']}")

# 3.4 DAO
from web3_security.dao_security import assess_governance, get_dao_registry
g = assess_governance(voting_turnout_pct=5, quorum_pct=1, timelock_hours=0,
                       proposal_threshold_pct=0.2, multisig_signers=5,
                       multisig_threshold=1, delegation_enabled=False,
                       has_emergency_pause=False)
print(f"  DAO 治理: score={g['score']} findings={len(g['findings'])}")
dao = get_dao_registry()
print(f"  DAO 注册数: {len(dao.list())}")

# 3.5 节点
from web3_security.node_security import audit_node_config
nd = audit_node_config("validator", rpc_enabled=True, rpc_auth=False,
                       rpc_exposed_public=True, name="test-node")
print(f"  节点审计: score={nd['score']} critical={nd['summary']['critical']}")

# 3.6 加密货币
from web3_security.crypto_security import validate_address, assess_wallet, risk_score_address
va = validate_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "ethereum")
print(f"  地址校验: {va['address'][:10]}... valid={va['valid']}")
w = assess_wallet("hot", encryption_enabled=True, seed_phrase_backup=True,
                  seed_offline_stored=False, mfa_enabled=False)
print(f"  钱包评估: score={w['score']} findings={len(w['findings'])}")
ra = risk_score_address(100, True, True, 5)
print(f"  地址风险: score={ra['address_risk_score']} level={ra['level']}")

# 3.7 Dashboard
from web3_security.web3_dashboard import overview, risk_distribution
ov = overview()
print(f"  Dashboard: totals={ov['totals']} critical={ov['critical_issues']}")
print(f"  风险分布: {risk_distribution()}")

print("\n" + "=" * 60)
print("【4】HTML 文件大小检查")
print("=" * 60)
hp = os.path.join(ROOT, "api_server", "web3_security_console.html")
sz = os.path.getsize(hp)
print(f"  HTML 大小: {sz} bytes ({sz/1024:.1f} KB)")
assert sz > 15 * 1024, "HTML 必须 > 15KB"

print("\n" + "=" * 60)
print("【5】API 端点数统计")
print("=" * 60)
routes = mod.router.routes
print(f"  端点数: {len(routes)}")
assert len(routes) >= 50, "端点必须 ≥50"

print("\n" + "=" * 60)
print(f"验证结果: {'全部通过 ✅' if ok else '存在失败 ❌'}")
print("=" * 60)
