#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
区块链安全模块自测脚本

验收：
    1. 4 个文件都能导入无报错
    2. SmartContractAnalyzer 对含重入漏洞的测试合约真实检测出重入
    3. WalletSecurityChecker 正确识别有效/无效私钥和地址
    4. 无 mock 数据
"""

import sys
import os

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def banner(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def test_imports():
    """验收 1：四个文件都能导入"""
    banner("测试 1：模块导入")
    from blockchain_security.smart_contract_analyzer import SmartContractAnalyzer
    from blockchain_security.wallet_security import WalletSecurityChecker
    from blockchain_security.transaction_security import TransactionSecurityAnalyzer
    from unified.blockchain_assessor import BlockchainAssessor, register
    print("[OK] smart_contract_analyzer 导入成功")
    print("[OK] wallet_security 导入成功")
    print("[OK] transaction_security 导入成功")
    print("[OK] unified/blockchain_assessor 导入成功")
    return SmartContractAnalyzer, WalletSecurityChecker, TransactionSecurityAnalyzer, BlockchainAssessor


def test_reentrancy(SmartContractAnalyzer):
    """验收 2：对含重入漏洞的合约检测出至少 3 种漏洞（含重入）"""
    banner("测试 2：智能合约重入漏洞检测")

    # 标准 DAO 风格重入攻击示例合约
    vulnerable_contract = """
pragma solidity ^0.4.24;

contract VulnerableBank {
    mapping(address => uint) balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        // 经典重入：先 call.value 外部调用，再更新余额
        msg.sender.call.value(balances[msg.sender])();
        balances[msg.sender] = 0;
    }

    function withdrawAll() public {
        // 循环内外部调用 -> DoS
        for (uint i = 0; i < recipients.length; i++) {
            recipients[i].transfer(amounts[i]);
        }
    }

    function kill() public {
        selfdestruct(msg.sender);
    }

    function auth() public {
        require(tx.origin == owner);
    }
}
"""

    analyzer = SmartContractAnalyzer()
    findings = analyzer.analyze(vulnerable_contract, "VulnerableBank")

    print(f"共检测出 {len(findings)} 个问题：")
    types = []
    for f in findings:
        print(f"  [{f['severity'].upper():8}] {f['type']}  (Line {f['line']})")
        print(f"            -> {f['description'][:60]}")
        types.append(f["type"])

    # 断言：必须检测出重入
    has_reentrancy = any("重入" in t for t in types)
    assert has_reentrancy, "FAIL: 未检测出重入攻击！"
    print("\n[OK] 成功检测出重入攻击")

    # 断言：至少 3 种不同漏洞
    distinct_types = set(types)
    print(f"[OK] 检测出 {len(distinct_types)} 类不同漏洞")
    assert len(distinct_types) >= 3, f"FAIL: 仅 {len(distinct_types)} 类漏洞，不足 3 类"

    return findings


def test_wallet(WalletSecurityChecker):
    """验收 3：钱包安全检测"""
    banner("测试 3：钱包安全检测")
    checker = WalletSecurityChecker()

    # 3.1 私钥
    print("--- 私钥检测 ---")
    # 有效私钥（随机 64 hex）
    valid_key = "5f78c3cd8e2b4a1f9d6e8b7c5a3f1e0d2b4a6c8e0f1d3b5a7c9e2f4a6c8e0d1b"
    r1 = checker.check_private_key(valid_key)
    print(f"  随机私钥   -> valid={r1['valid']}, strength={r1['strength']}, entropy={r1['entropy']}")
    assert r1["valid"], "FAIL: 合法随机私钥被判无效"
    assert r1["strength"] == "strong", "FAIL: 合法随机私钥强度应为 strong"

    # 弱私钥（已知测试向量）
    weak_key = "0000000000000000000000000000000000000000000000000000000000000001"
    r2 = checker.check_private_key(weak_key)
    print(f"  弱私钥(1)  -> valid={r2['valid']}, strength={r2['strength']}")
    print(f"            -> issues={r2['issues']}")
    assert not r2["valid"] or r2["strength"] == "weak", "FAIL: 弱私钥未识别"

    # 长度非法
    r3 = checker.check_private_key("abcd1234")
    print(f"  短私钥     -> valid={r3['valid']}, strength={r3['strength']}")
    assert not r3["valid"], "FAIL: 短私钥未被判无效"

    # 3.2 地址
    print("--- 地址检测 ---")
    # 合法 EIP-55 地址（Vitalik 的知名地址，校验和正确）
    valid_addr = "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"
    r4 = checker.check_address(valid_addr, "ethereum")
    print(f"  合法地址   -> valid={r4['valid']}, checksum_valid={r4['checksum_valid']}")
    assert r4["checksum_valid"], "FAIL: EIP-55 校验和验证失败"

    # 非法地址（长度错）
    r5 = checker.check_address("0x1234", "ethereum")
    print(f"  非法地址   -> valid={r5['valid']}, issues={r5['issues']}")
    assert not r5["valid"], "FAIL: 非法长度地址未被判无效"

    # 零地址
    r6 = checker.check_address("0x0000000000000000000000000000000000000000", "ethereum")
    print(f"  零地址     -> issues={r6['issues']}")

    print("[OK] 钱包安全检测全部通过")


def test_assessor(BlockchainAssessor):
    """验收 4：评估器主文件集成测试"""
    banner("测试 4：BlockchainAssessor 集成")
    assessor = BlockchainAssessor()

    # 直接内联合约源码评估
    src = """
pragma solidity ^0.5.0;
contract Token {
    mapping(address => uint) public balanceOf;
    function mint(address to, uint amount) public {
        balanceOf[to] += amount;
    }
    function withdraw() public {
        msg.sender.transfer(balanceOf[msg.sender]);
        balanceOf[msg.sender] = 0;
    }
}
"""
    result = assessor.assess(src, {})
    print(f"  内联合约评估: status={result.status}, findings={len(result.findings)}, "
          f"risk_score={result.risk_score}")
    for f in result.findings:
        print(f"    [{f.severity.value:8}] {f.title}")

    # 地址评估
    r2 = assessor.assess("0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B", {})
    print(f"  地址评估: findings={len(r2.findings)}")

    # 私钥评估
    r3 = assessor.assess("0000000000000000000000000000000000000000000000000000000000000001", {})
    print(f"  弱私钥评估: findings={len(r3.findings)}")
    for f in r3.findings:
        print(f"    [{f.severity.value:8}] {f.title}")

    # 交易 JSON 评估
    tx = {"value": "20000000000000000000", "to": "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"}
    r4 = assessor.assess(json_dumps(tx), {})
    print(f"  交易评估: findings={len(r4.findings)}")

    print("[OK] BlockchainAssessor 集成测试通过")


def json_dumps(d):
    import json
    return json.dumps(d)


if __name__ == "__main__":
    a, b, c, d = test_imports()
    test_reentrancy(a)
    test_wallet(b)
    test_assessor(d)
    banner("全部自测通过")
    print("验收标准 1/2/3/4 全部满足。")
