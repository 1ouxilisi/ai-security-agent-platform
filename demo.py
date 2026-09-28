"""端到端demo：不启动服务，直接调用核心函数"""
import sys, os, json
sys.path.insert(0, os.path.dirname(__file__))

from api_server.v13_ai_mobile_chain import contract_analyze, LLM_TEST_CASES

async def demo_contract():
    print("=" * 60)
    print("Demo 1: 智能合约审计")
    print("=" * 60)
    vulnerable = """
pragma solidity ^0.7.0;
contract EtherBank {
    mapping(address => uint256) balances;
    function withdraw() public {
        msg.sender.call.value(balances[msg.sender])();
        balances[msg.sender] = 0;
    }
    function kill() public { selfdestruct(msg.sender); }
}
"""
    from api_server.v13_ai_mobile_chain import ContractAnalysisRequest
    r = await contract_analyze(ContractAnalysisRequest(source_code=vulnerable))
    print(f"Risk Score: {r['risk_score']}")
    print(f"Issues: {r['issues_found']}")
    for i in r['issues']:
        print(f"  [{i['severity'].upper()}] {i['vuln']}")
        print(f"    Fix: {i['fix']}")

async def demo_llm_cases():
    print("\n" + "=" * 60)
    print("Demo 2: LLM安全测试用例（共7类）")
    print("=" * 60)
    for k, v in LLM_TEST_CASES.items():
        print(f"  {k}: {v['name']} ({len(v['payloads'])} payloads, {v['severity']})")

if __name__ == "__main__":
    import asyncio
    asyncio.run(demo_contract())
    asyncio.run(demo_llm_cases())
    print("\n" + "=" * 60)
    print("Demo完成。启动服务: python app_lite.py")
    print("=" * 60)
