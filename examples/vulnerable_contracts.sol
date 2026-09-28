// Example vulnerable smart contracts for testing the auditor
// Run: python demo.py

// ============================================================
// 1. Reentrancy vulnerability (The DAO style)
// ============================================================
pragma solidity ^0.7.0;

contract EtherBank {
    mapping(address => uint256) balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        msg.sender.call.value(balances[msg.sender])("");
        balances[msg.sender] = 0;
    }
}

// ============================================================
// 2. Unprotected mint (infinite token creation)
// ============================================================
pragma solidity ^0.8.0;

contract BadToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) public {
        balances[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) public {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}

// ============================================================
// 3. tx.origin phishing vulnerability
// ============================================================
pragma solidity ^0.8.0;

contract Wallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) public {
        require(tx.origin == owner);
        owner = newOwner;
    }
}

// ============================================================
// 4. delegatecall to arbitrary address
// ============================================================
pragma solidity ^0.8.0;

contract Proxy {
    address public implementation;

    function setImplementation(address _impl) public {
        implementation = _impl;
    }

    function execute(bytes calldata data) public {
        implementation.delegatecall(data);
    }
}

// ============================================================
// 5. Hardcoded address + exposed selfdestruct
// ============================================================
pragma solidity ^0.8.0;

contract Dangerous {
    address public admin = 0x1234567890123456789012345678901234567890;

    function kill() public {
        selfdestruct(payable(admin));
    }
}

// ============================================================
// 6. Safe contract (should produce few/no findings)
// ============================================================
pragma solidity 0.8.20;

contract SafeVault {
    mapping(address => uint256) private balances;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public onlyOwner {
        (bool ok, ) = msg.sender.call{value: balances[msg.sender]}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }
}
