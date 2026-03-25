### [H-1] Looping through the players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential a Denial of Service (DoS) attack, incrementing gas costs for future entrants

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle:players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle starts will be dramatically lower than those who enter later. Every additional address in the `players` array is an additional check the loop will have to make.
​
'''javascript
// @audit Dos Attack
@> for(uint256 i = 0; i < players.length -1; i++){
    for(uint256 j = i+1; j< players.length; j++){
    require(players[i] != players[j],"PuppyRaffle: Duplicate Player");
  }
}
'''
**Impact:** The gas consts for raffle entrants will greatly increase as more players enter the raffle, discouraging later users from entering and causing a rush at the start of a raffle to be one of the first entrants in queue.
​
An attacker might make the `PuppyRaffle:entrants` array so big that no one else enters, guaranteeing themselves the win.

**Proof of Concept:**
​
If we have 2 sets of 100 players enter, the gas costs will be as such:
- 1st 100 players: ~6252048 gas
- 2nd 100 players: ~18068138 gas
​
This is more than 3x more expensive for the second 100 players.
​
<details>
<summary>Proof of Code</summary>
​
'''js
function testDenialOfService() public {
      // Foundry lets us set a gas price
      vm.txGasPrice(1);
​
      // Creates 100 addresses
      uint256 playersNum = 100;
      address[] memory players = new address[](playersNum);
      for (uint256 i = 0; i < players.length; i++) {
          players[i] = address(i);
      }
​
      // Gas calculations for first 100 players
      uint256 gasStart = gasleft();
      puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
      uint256 gasEnd = gasleft();
      uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;
      console.log("Gas cost of the first 100 players: ", gasUsedFirst);
​
      // Creates another array of 100 players
      address[] memory playersTwo = new address[](playersNum);
      for (uint256 i = 0; i < playersTwo.length; i++) {
          playersTwo[i] = address(i + playersNum);
      }
​
      // Gas calculations for second 100 players
      uint256 gasStartTwo = gasleft();
      puppyRaffle.enterRaffle{value: entranceFee * players.length}(playersTwo);
      uint256 gasEndTwo = gasleft();
      uint256 gasUsedSecond = (gasStartTwo - gasEndTwo) * tx.gasprice;
      console.log("Gas cost of the second 100 players: ", gasUsedSecond);
​
      assert(gasUsedSecond > gasUsedFirst);
  }
'''
​
</details>

**Recommended Mitigation**
There are a few recommended mitigations.

Consider allowing duplicates. Users can make new wallet addresses anyways, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.

Consider using a mapping to check duplicates. This would allow you to check for duplicates in constant time, rather than linear time. You could have each raffle have a uint256 id, and the mapping would be a player address mapped to the raffle Id.

```diff
+    mapping(address => uint256) public addressToRaffleId;
+    uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+            addressToRaffleId[newPlayers[i]] = raffleId;
        }
​
-        // Check for duplicates
+       // Check for duplicates only from the new players
+       for (uint256 i = 0; i < newPlayers.length; i++) {
+          require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+       }
-        for (uint256 i = 0; i < players.length; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
        emit RaffleEnter(newPlayers);
    }
.
.
.
    function selectWinner() external {
+       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
```

### [H-2] Weak randomness in `PuppyRaffle::selectWinner` allows anyone to choose winner

**Description:** Hashing `msg.sender`, `block.timestamp`, `block.difficulty` together creates a predictable final number. A predictable number is not a good random number. Malicious users can manipulate these values or know them ahead of time to choose the winner of the raffle themselves. 

**Impact:** Any user can choose the winner of the raffle, winning the money and selecting the "rarest" puppy, essentially making it such that all puppies have the same rarity, since you can choose the puppy. 

**Proof of Concept:** 

There are a few attack vectors here. 

1. Validators can know ahead of time the `block.timestamp` and `block.difficulty` and use that knowledge to predict when / how to participate. See the [solidity blog on prevrando](https://soliditydeveloper.com/prevrandao) here. `block.difficulty` was recently replaced with `prevrandao`.
2. Users can manipulate the `msg.sender` value to result in their index being the winner.

Using on-chain values as a randomness seed is a [well-known attack vector](https://betterprogramming.pub/how-to-generate-truly-random-numbers-in-solidity-and-blockchain-9ced6472dbdf) in the blockchain space.

**Recommended Mitigation:** Consider using an oracle for your randomness like [Chainlink VRF](https://docs.chain.link/vrf/v2/introduction).

### [H-3] Integer overflow of `PuppyRaffle::totalFees` loses fees

**Description:** In Solidity versions prior to `0.8.0`, integers were subject to integer overflows. 

```javascript
uint64 myVar = type(uint64).max; 
// myVar will be 18446744073709551615
myVar = myVar + 1;
// myVar will be 0
```

**Impact:** In `PuppyRaffle::selectWinner`, `totalFees` are accumulated for the `feeAddress` to collect later in `withdrawFees`. However, if the `totalFees` variable overflows, the `feeAddress` may not collect the correct amount of fees, leaving fees permanently stuck in the contract.

**Proof of Concept:** 
1. We first conclude a raffle of 4 players to collect some fees.
2. We then have 89 additional players enter a new raffle, and we conclude that raffle as well.
3. `totalFees` will be:
```javascript
totalFees = totalFees + uint64(fee);
// substituted
totalFees = 800000000000000000 + 17800000000000000000;
// due to overflow, the following is now the case
totalFees = 153255926290448384;
```
4. You will now not be able to withdraw, due to this line in `PuppyRaffle::withdrawFees`:
```javascript
require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

Although you could use `selfdestruct` to send ETH to this contract in order for the values to match and withdraw the fees, this is clearly not what the protocol is intended to do. 

<details>
<summary>Proof Of Code</summary>
Place this into the `PuppyRaffleTest.t.sol` file.

```javascript
function testTotalFeesOverflow() public playersEntered {
        // We finish a raffle of 4 to collect some fees
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();
        uint256 startingTotalFees = puppyRaffle.totalFees();
        // startingTotalFees = 800000000000000000

        // We then have 89 players enter a new raffle
        uint256 playersNum = 89;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        // We end the raffle
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        // And here is where the issue occurs
        // We will now have fewer fees even though we just finished a second raffle
        puppyRaffle.selectWinner();

        uint256 endingTotalFees = puppyRaffle.totalFees();
        console.log("ending total fees", endingTotalFees);
        assert(endingTotalFees < startingTotalFees);

        // We are also unable to withdraw any fees because of the require check
        vm.prank(puppyRaffle.feeAddress());
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }
```
</details>

**Recommended Mitigation:** There are a few recommended mitigations here.

1. Use a newer version of Solidity that does not allow integer overflows by default.

```diff 
- pragma solidity ^0.7.6;
+ pragma solidity ^0.8.18;
```

Alternatively, if you want to use an older version of Solidity, you can use a library like OpenZeppelin's `SafeMath` to prevent integer overflows. 

2. Use a `uint256` instead of a `uint64` for `totalFees`. 

```diff
- uint64 public totalFees = 0;
+ uint256 public totalFees = 0;
```

3. Remove the balance check in `PuppyRaffle::withdrawFees` 

```diff
- require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

We additionally want to bring your attention to another attack vector as a result of this line in a future finding.

# Gas

### G-1 Unchanged state variables should be declared constant or immutable.

Reading from storage is much more expensive than reading from a constant or immutable variable.

Instances:
- `PuppyRaffle:raffleDuration` should be `immutable`
- `PuppyRaffle:commonImageUri`should be `constant`
- `PuppyRaffle:rareImageUri`should be `constant`
- `PuppyRaffle:legendaryUri` should be `constant`

### G-2 Storage variables in a loop should be cached.

Everytime you call `players.length` you read from storage, as opposed to memory which is more gas efficient

```diff
+ uint256 playersLength = players.length;
- for (uint256 i = 0; i < players.length - 1; i++) {
+ for (uint256 i = 0; i < playersLength - 1; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
+            for (uint256 j = i + 1; j < playersLength; j++) {

                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```


### I-1: Solidity pragma should be specific, not wide
​
Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`
​
- Found in src/PuppyRaffle.sol [Line: 3](src/PuppyRaffle.sol#L3)
​
	```solidity
	pragma solidity ^0.7.6;
	```

### I-2: Using an outdated version of solidity is not recommended

solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement.

**Recommendation**
Deploy with a recent version of Solidity (at least 0.8.0) with no known severe issues.

Use a simple pragma version that allows any of these versions. Consider using the latest version of Solidity for testing.

Please see [Slither](https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity) documentation for more information

### I-3: Missing checks for `address(0)` when assigning values to address state variables

Check for `address(0)` when assigning values to address state variables.

<details><summary>2 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 69](src/PuppyRaffle.sol#L69)

	```solidity
	        feeAddress = _feeAddress;
	```

- Found in src/PuppyRaffle.sol [Line: 203](src/PuppyRaffle.sol#L203)

	```solidity
	        feeAddress = newFeeAddress;
	```

</details>