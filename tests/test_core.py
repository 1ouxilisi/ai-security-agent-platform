"""核心模块单元测试"""
import sys, os, asyncio
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_server.v13_ai_mobile_chain import contract_analyze, ContractAnalysisRequest, LLM_TEST_CASES

def test_reentrancy():
    code = """pragma solidity ^0.7.0;
contract C {
  function w() public { msg.sender.call.value(1)(); }
}"""
    r = asyncio.run(contract_analyze(ContractAnalysisRequest(source_code=code)))
    assert r['risk_score'] >= 10, f"Expected critical, got {r}"
    print("PASS: reentrancy detected")

def test_tx_origin():
    code = """pragma solidity ^0.8.0;
contract C {
  function admin() public { require(tx.origin == owner); }
}"""
    r = asyncio.run(contract_analyze(ContractAnalysisRequest(source_code=code)))
    assert any("tx.origin" in i['vuln'] for i in r['issues']), f"tx.origin not found: {r}"
    print("PASS: tx.origin detected")

def test_safe_contract():
    code = """pragma solidity ^0.8.0;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract C is ReentrancyGuard {
  function w() public nonReentrant { payable(msg.sender).transfer(1); }
}"""
    r = asyncio.run(contract_analyze(ContractAnalysisRequest(source_code=code)))
    assert r['risk_score'] == 0, f"Safe contract flagged: {r}"
    print("PASS: safe contract clean")

def test_llm_cases_loaded():
    assert len(LLM_TEST_CASES) == 7, f"Expected 7 test types, got {len(LLM_TEST_CASES)}"
    for k, v in LLM_TEST_CASES.items():
        assert len(v['payloads']) >= 3, f"{k} has <3 payloads"
    print(f"PASS: {len(LLM_TEST_CASES)} LLM test types loaded")

if __name__ == "__main__":
    test_reentrancy()
    test_tx_origin()
    test_safe_contract()
    test_llm_cases_loaded()
    print("\nAll tests passed.")
