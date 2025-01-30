# SecretStore - Technical Design Document

## Original Requirements

The SecretStore protocol was developed to meet the following requirements:

1. Enable any two parties to store a mutually agreed secret on-chain
2. Prove agreement between parties at a specific block
3. Allow either party to reveal the secret at a later block
4. Delete the agreement after revelation
5. Ensure atomic registration (single transaction)
6. Prevent secret value observation before revelation
7. Emit events for transparency

### Atomic Registration Requirement

The requirement for registration to "take place in the same block" drives a key security feature:
both parties' agreement must be atomic. This prevents several potential attack vectors:

1. **Front-running**: An attacker cannot intercept and modify the agreement between parties
2. **Race Conditions**: No possibility of partial agreements where one party is committed and the other isn't
3. **MEV (Miner Extractable Value)**: No opportunity for block producers to manipulate agreement ordering
4. **Party Withdrawal**: One party cannot back out after the other has committed

This is achieved by:
- Collecting both signatures off-chain
- Submitting both signatures in a single transaction
- Verifying both signatures atomically
- Recording the agreement only if both signatures are valid

Framework choice was flexible, with permission to use truffle, hardhat, or forge along with any necessary libraries.

As this contract is designed for production use within a protocol ecosystem, additional requirements were considered:

1. **Protocol Integration**
   - Security-first design approach:
     - EIP-712 for human-readable, replay-resistant signatures
     - Salted hashes to prevent rainbow table attacks
     - Domain separation to prevent cross-chain/contract attacks
   - Upgradeable architecture for protocol evolution
   - Clear event emission for indexing
   - Gas-optimized for protocol users

2. **Production Requirements**
   - Role-based access control for protocol governance
   - Emergency pause functionality
   - Comprehensive security measures
   - Cross-chain compatibility
   - Protocol-grade testing coverage

## System Architecture

### Core Components

1. **UUPS Proxy (EIP-1822)**
   - Universal Upgradeable Proxy Standard for contract upgradeability
   - Key Features:
     - Implementation address stored in standard slot (`keccak256("PROXIABLE")`)
     - Upgrade logic in implementation contract, not proxy
     - No admin address stored in proxy
     - Lower gas costs for regular function calls
   - Advantages over Transparent Proxy:
     - ~2100 gas saved per call (no delegate call overhead)
     - More secure (can't be bricked by admin mistakes)
     - Self-contained upgrade logic (easier to audit)
     - Universal verification through `proxiableUUID()`
   - Implementation Details:
     - Uses OpenZeppelin's `UUPSUpgradeable` base contract
     - Upgrade restricted to `UPGRADER_ROLE`
     - State variables properly initialized through initializer pattern
     - Chain ID cached and monitored for cross-chain deployments

2. **EIP-712: Typed Structured Data Hashing and Signing**
   - Secure signature scheme for human-readable data
   - Components:
     - Domain Separator: Prevents cross-chain/contract replay attacks
       ```solidity
       keccak256(abi.encode(
           DOMAIN_TYPE_HASH,
           keccak256(bytes("SecretStore")),  // Name hash
           keccak256(bytes("1")),            // Version hash
           block.chainid,
           address(this)
       ))
       ```
     - Structured Data: Type-safe agreement format
       ```solidity
       struct Agreement {
           address partyA;
           address partyB;
           bytes32 secretHash;
       }
       ```
   - Security Benefits:
     - Human-readable signing messages in wallets
     - Domain separation prevents replay across:
       - Different contracts (address)
       - Different versions (version string)
       - Different chains (chainId)
       - Different contract instances (address)
     - Type safety prevents parameter confusion
   - Gas Optimizations:
     - Domain separator cached after initialization
     - Only recomputed on chain ID changes
     - Type hashes computed at compile time
     - Signature verification using OpenZeppelin's ECDSA

3. **Access Control**
   - Role-based permissions using OpenZeppelin's AccessControl
   - Roles:
     - DEFAULT_ADMIN_ROLE: Manages other roles
     - UPGRADER_ROLE: Can upgrade the contract
     - PAUSER_ROLE: Can pause/unpause operations

### Data Model

```solidity
// The secret hash is used as the key in the agreements mapping
struct Agreement {
    address partyA;      // First party address (20 bytes)
    address partyB;      // Second party address (20 bytes)
    uint96 timestamp;    // Registration time (12 bytes)
    uint64 blockNumber; // Registration block (8 bytes)
}

// Mapping from secretHash to Agreement
mapping(bytes32 => Agreement) public agreements;
```

The struct is carefully designed for gas optimization:
- Packed into 2 storage slots (320 bits + 160 bits)
- secretHash as mapping key for efficient lookups
- Zero address for partyA indicates non-existent agreement

### Security Considerations

1. **Signature Security (EIP-712)**
   - Signatures are bound to:
     - Specific secret hash
     - Specific parties (addresses)
     - Specific contract instance
     - Current chain
   - Prevents:
     - Cross-chain replay attacks
     - Cross-contract replay attacks
     - Signature reuse

2. **Upgrade Security (EIP-1822)**
   - Only UPGRADER_ROLE can perform upgrades
   - Upgrades must preserve storage layout
   - New implementations must support UUPS
   - Initialization can only happen once

3. **General Security**
   - Reentrancy protection
   - Emergency pause capability
   - Role-based access control
   - Events for transparency
   - Gas optimization through storage packing

### Emergency Controls

The contract implements emergency control mechanisms through OpenZeppelin's `PausableUpgradeable`:

1. **Pause Functionality**
   - Immediate suspension of all contract operations
   - Only executable by accounts with `PAUSER_ROLE`
   - Affects all state-changing functions
   - Events emitted for transparency

2. **Access Control**
   - `PAUSER_ROLE` is separate from admin roles
   - Multiple pausers can be designated
   - Role can be granted/revoked by admin

3. **Operations**
   - Dedicated scripts for pause/unpause operations
   - Clear documentation for emergency response
   - Can be integrated into automated monitoring

4. **Recovery**
   - Unpause functionality to resume operations
   - Same role restrictions as pause
   - No state loss during pause

This provides a quick "emergency brake" that's separate from the upgrade mechanism, allowing for immediate response to security concerns.

### Core Workflows

1. **Secret Registration**
   ```
   Off-chain                                              On-chain
   ---------                                              --------
   PartyA                              PartyB             Contract
     |                                   |                   |
     |-- Generate secret + salt -------->|                   |
     |-- Calculate secretHash ---------->|                   |
     |                                   |                   |
     |-- Sign EIP-712 message ----------|                   |
     |                                   |                   |
     |                    Sign EIP-712 message              |
     |<----------------------------------|                   |
     |                                   |                   |
     |-------- Submit registerSecret() with both ---------->|
     |          signatures and secretHash                   |
     |                                   |                   |
     |                                   |    Verify sigs    |
     |                                   |    Store agreement|
     |                                   |    Emit event     |
   ```

2. **Secret Revelation**
   ```
   Either Party                        Contract
     |                                    |
     |--- Submit revealSecret() --------->|
     |                                    |---- Verify caller is party -------|
     |                                    |---- Verify secret hash ------------|
     |                                    |---- Delete agreement -------------|
     |                                    |---- Emit SecretRevealed ----------|
   ```

### Signature Generation

The contract supports two methods of generating EIP-712 signatures:

1. **Frontend Integration (Production)**
   ```javascript
   // Using ethers.js
   const domain = {
       name: "SecretStore",
       version: "1",
       chainId: chainId,
       verifyingContract: contractAddress
   };

   const types = {
       Agreement: [
           { name: "secretHash", type: "bytes32" },
           { name: "partyA", type: "address" },
           { name: "partyB", type: "address" }
       ]
   };

   const value = {
       secretHash: secretHash,
       partyA: partyA,
       partyB: partyB
   };

   // Get signature using MetaMask or other wallet
   const signature = await signer._signTypedData(domain, types, value);
   ```

2. **Testing Implementation (Foundry)**
   ```solidity
   // Using Foundry's vm.sign for testing
   bytes32 digest = _hashTypedDataV4(
       keccak256(abi.encode(
           AGREEMENT_TYPEHASH,
           secretHash,
           partyA,
           partyB
       ))
   );
   (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
   bytes memory signature = abi.encodePacked(r, s, v);
   ```

Both methods produce valid EIP-712 signatures that can be verified on-chain. The Foundry implementation is used for testing and demonstration, while the JavaScript implementation represents how dApps would integrate with the protocol in production.

### Gas Optimization

1. **Storage Packing**
   - Agreement struct packed into 2 slots:
     - Slot 1: partyA (160 bits) + partyB (160 bits)
     - Slot 2: timestamp (96 bits) + blockNumber (64 bits)

2. **Memory Usage**
   - Use calldata for function parameters
   - Minimize storage reads/writes
   - Delete storage before events

3. **Computation**
   - Cache domain separator
   - Efficient signature verification
   - Optimized role checking

### Future Considerations

1. **Potential Upgrades**
   - Multi-party secret sharing
   - Time-locked revelations
   - Encrypted partial reveals
   - Gas optimizations

2. **Limitations**
   - Maximum secret size (gas limits)
   - Public blockchain visibility
   - Upgrade risks

3. **Monitoring**
   - Track registration patterns
   - Monitor gas costs
   - Watch for suspicious activities