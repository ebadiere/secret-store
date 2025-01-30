# SecretStore — Technical Design Document

## 1. Original Requirements

The **SecretStore** protocol is designed to meet the following core requirements:

1. **Two-Party Agreement**: Any two parties can agree and sign off on a secret
2. **Single Transaction**: Secret registration must occur in a single transaction to guarantee same-block execution
3. **Secret Storage**: Secrets must be stored in a way that prevents value observation on-chain
4. **Revelation Rights**: Either party can reveal the secret at any time
5. **Deletion**: Upon revelation, the stored secret should be deleted
6. **Block Timing**: Agreement must be provable with revelation possible at a later block
7. **Event Emission**: The contract must emit an event upon secret revelation, including the revealer's address and the secret value. Additionally, as a best practice for state changes, the contract also emits events for secret registration.
8. **Signature Validation**: Must validate off-chain signatures on-chain

## Enhanced Features

1. **Access Control**: Role-based access control for administrative functions
2. **Upgradability**: UUPS proxy pattern for future upgrades
3. **Emergency Controls**: Pause mechanism for emergency situations

---

## 2. Atomic Registration Requirement

Enforcing registration in a **single transaction** is critical for security:

- **Front-Running Avoidance**: No attacker can intercept and replace the agreement.  
- **No Partial Commitment**: Eliminates scenarios where one party commits while the other does not.  
- **MEV Protection**: Miners cannot reorder partial transactions.  
- **Party Non-Withdrawal**: Prevents a party from backing out after the other signs.

The contract achieves this by requiring **both parties’ signatures** in one `registerSecret` call.

---

## 3. Production Requirements

SecretStore addresses broader protocol needs:

1. **Security-First Design**  
   - Relies on **EIP-712** typed data for replay-resistant, user-friendly signatures.  
   - Uses **salted hashes** to conceal the secret on-chain.  
   - Implements **UUPSUpgradeable** for future expansion while preserving security.

2. **Gas Optimization**  
   - Packs data in storage.  
   - Minimizes on-chain computations.  
   - Uses efficient hashing and signature checks.

3. **Role-Based Access Control**  
   - Separates roles for upgrading (`UPGRADER_ROLE`) and pausing (`PAUSER_ROLE`).

4. **Emergency Pause**  
   - Suspends key operations instantly during a crisis.

5. **Cross-Chain Compatibility**  
   - Incorporates `chainId` into signatures to block replay on other networks.

6. **Protocol-Grade Testing**  
   - Comprehensive test suite including:
     - Unit tests for core functionality
     - Invariant tests to verify critical properties
     - Fuzz tests with randomized inputs
     - Upgrade safety tests
   - Tests cover signature verification, replay attack prevention, and access control.

---

## 4. Why EIP-712 Over Plain `ecrecover`?

### Vulnerabilities of Plain `ecrecover`

- **No Domain Separation**: A single signature can be reused across different chains or contracts.  
- **Unreadable Signing Prompts**: Users see only a raw hash, increasing phishing risk.  
- **Parameter Confusion**: A single hash can ambiguously represent multiple data sets without typed structures.

### How EIP-712 Addresses These Issues

1. **Structured Data**  
   Shows fields like `secretHash`, `partyA`, and `partyB` in the wallet’s signing prompt.

2. **Domain Separator**  
   Binds signatures to a specific chain ID, contract address, and version.

3. **User-Friendly**  
   Improves clarity by labeling each parameter in a human-readable way.

4. **Replay Prevention**  
   Ties the signature strictly to this contract on this chain.

### Signature Specifications Considered

1. **EIP-712**
   - Best for user-friendly, typed data signatures that include addresses, domain info, and unique fields
   - Addresses replay attacks across different chains or contracts
   - Typically the best fit for multi-field agreement requirements

2. **EIP-1271**
   - Consider if participants might be smart contracts that need to validate signatures or act as signers
   - Adds complexity and gas overhead
   - Not needed for our current use case with EOA participants

3. **EIP-2098**
   - Micro-optimization to compress signatures from 65 bytes to 64
   - Saves minimal gas or storage
   - Added complexity outweighs minor benefits for our use case

4. **EIP-191**
   - Simpler "personal_sign" approach
   - Lacks typed data structure
   - Less secure and user-friendly than EIP-712 for multi-field agreements

5. **Meta-Transaction frameworks (EIP-2770)**
   - Useful when needing relayer or user gas abstraction
   - Adds unnecessary complexity for our direct two-party interaction

### Decision
For our "two parties sign a secret agreement" scenario, EIP-712 is the robust choice because it:
- Enforces strong domain separation
- Provides excellent wallet support and user experience
- Prevents replay attacks effectively
- Has become the de facto standard for structured data signing

Unless there is a strong requirement for contract-based signers (EIP-1271) or signature compression (EIP-2098), EIP-712 provides the best balance of security, usability, and widespread wallet support.

---

## 5. System Architecture

### UUPS Proxy (EIP-1822)

- **Minimal Proxy** delegates all calls to the **implementation** contract.  
- Implementation maintains both logic and state.  
- `_authorizeUpgrade` is restricted to `UPGRADER_ROLE`.  
- Adheres to EIP-1967 for standardized storage slots.

### Access Control

- **OpenZeppelin AccessControl**:  
  - `DEFAULT_ADMIN_ROLE` for overall management.  
  - `UPGRADER_ROLE` for upgrades.  
  - `PAUSER_ROLE` to pause/unpause the contract.

### Pausable

- **Emergency Mechanism**  
  - Halts `registerSecret` and `revealSecret` when paused, stopping critical functionality during potential exploits.

### EIP-712

- **Domain Separation**  
  - Captures `chainId`, contract address, and version.  

- **Structured Data**  
  - Off-chain signing of typed fields to thwart replay attacks.

---

## 6. Data Model

    struct Agreement {
        address partyA;       // 160 bits
        address partyB;       // 160 bits
        uint96  timestamp;    // 96 bits
        uint64  blockNumber;  // 64 bits
    }

    // Mapping from secretHash => Agreement
    mapping(bytes32 => Agreement) public agreements;

- **Key**: `secretHash` = `keccak256(abi.encodePacked(secret, salt))`.  
- **Value**: An `Agreement` storing participants and block/timestamp of registration.  
- **Packed** to minimize storage slots.

---

## 7. Core Workflows

### 7.1 Secret Registration

1. **Off-Chain**  
   - Both parties generate `(secret, salt)` off-chain.  
   - Compute `secretHash = keccak256(abi.encodePacked(secret, salt))`.  
   - Each party signs an EIP-712 typed message `(secretHash, partyA, partyB)`.

2. **On-Chain**  
   - `registerSecret(secretHash, partyA, partyB, signatureA, signatureB)`:  
     - Checks agreement does not exist for this `secretHash`.  
     - Uses `_hashTypedDataV4` to recover signers and confirm they match `partyA` and `partyB`.  
     - Stores `agreements[secretHash]`.  
     - Emits `SecretRegistered(secretHash, partyA, partyB)`.

### 7.2 Secret Revelation

Either party reveals later by calling:

- `revealSecret(secretHash, secret, salt)`:  
  - Confirms `msg.sender` is `partyA` or `partyB`.  
  - Re-hashes `(secret, salt)` and compares to `secretHash`.  
  - **Deletes** the agreement from storage.  
  - Emits `SecretRevealed(secretHash, msg.sender, secret)`.

---

## 8. Signature Generation

SecretStore supports two primary methods for generating EIP-712 signatures:

### 8.1 Frontend Integration (Production)

Using ethers.js:

    const domain = {
      name: "SecretStore",
      version: "1",
      chainId: chainId,
      verifyingContract: contractAddress,
    };

    const types = {
      Agreement: [
        { name: "secretHash", type: "bytes32" },
        { name: "partyA", type: "address" },
        { name: "partyB", type: "address" },
      ],
    };

    const value = {
      secretHash: secretHash,
      partyA: partyA,
      partyB: partyB,
    };

    // Get signature using MetaMask or another wallet
    const signature = await signer._signTypedData(domain, types, value);

### 8.2 Testing Implementation (Foundry)

Using Foundry’s `vm.sign`:

    // Using Foundry's vm.sign for testing

    // First get the domain separator which binds the signature to this chain and contract
    bytes32 domainSeparator = keccak256(abi.encode(
        DOMAIN_TYPE_HASH,
        keccak256(bytes("SecretStore")),
        keccak256(bytes("1")),
        block.chainid,           // Binds to current chain
        address(this)            // Binds to this contract instance
    ));

    // Create the struct hash
    bytes32 structHash = keccak256(abi.encode(
        AGREEMENT_TYPEHASH,
        secretHash,
        partyA,
        partyB
    ));

    // Combine domain separator and struct hash per EIP-712
    bytes32 digest = keccak256(abi.encodePacked(
        "\x19\x01",
        domainSeparator,        // Includes chainId and contract address
        structHash
    ));

    // Sign the combined digest
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
    bytes memory signature = abi.encodePacked(r, s, v);

Both approaches produce valid EIP-712 signatures that are verified on-chain. The **Foundry** version is ideal for automated tests, while the **JavaScript** snippet shows how a production dApp integrates with user wallets.

---

## 9. Security Considerations

### Data Privacy
- The actual secret is never stored on-chain and is only revealed through an explicit transaction
- The `Agreement` struct stores only the `secretHash`, participating addresses, and timing metadata
- Observers cannot discover the actual secret until reveal, as it is protected by the salt

### EIP-712 Defenses
- Domain separation ties signatures to the chain ID, contract address, and version
- Structured data clarifies to users what they are signing

### Upgrade Security
- Only `UPGRADER_ROLE` can call `_authorizeUpgrade`
- Adheres to a stable storage layout

### Emergency Pause
- Pausable contract halts key functions if a vulnerability arises

### Reentrancy Protection
- Uses `nonReentrant` modifier on state-changing functions as a defensive measure:
  - **Future-Proofing**: Protects against potential reentrancy vectors in future upgrades
  - **Human Oversight**: Guards against accidental introduction of vulnerable patterns
  - **Defense in Depth**: Adds an extra layer of security at minimal cost
  - **Low Overhead**: The small gas cost is justified by the security benefit
- Note: This protection may be removed if security auditors determine it's unnecessary

### No Partial Agreements
- Registration is atomic with both signatures required in a single transaction

---

## 10. Upgrade Process and Safety Requirements

### Critical: Pre-Upgrade Requirements
Due to EIP-712's domain separator including contract version information, all secrets MUST be revealed before performing an upgrade. This requirement exists because:

1. **Signature Invalidation**: An upgrade would invalidate existing signatures, making it impossible to reveal previously registered secrets
2. **Data Loss Risk**: Any unrevealed secrets would become permanently inaccessible

### Upgrade Process
To safely upgrade the contract:

1. **Announcement**: Notify all users of the upcoming upgrade with sufficient notice
2. **Secret Revelation Period**: Allow time for all parties to reveal their secrets
3. **Verification**: Confirm no active secrets remain in storage
4. **Upgrade Execution**: Only proceed with upgrade after all secrets are revealed

### Storage Compatibility
The contract uses the UUPS proxy pattern for upgrades. New implementations must:

1. Maintain the same storage layout for existing state variables
2. Preserve all events and their signatures
3. Keep access control roles and permissions consistent

### Upgrade Restrictions
To protect user interests:
1. Only addresses with the `UPGRADER_ROLE` can perform upgrades
2. Upgrades must be announced in advance
3. New implementations must be thoroughly tested
4. Consider implementing a timelock mechanism for future upgrades

---

## 11. Gas Optimization

- **Storage Packing**  
  - The `Agreement` struct is designed to occupy minimal slots.

- **Calldata Usage**  
  - Functions use `calldata` parameters to reduce memory copies.

- **Cached Domain Separator**  
  - Recalculated only if chain ID changes.

- **UUPS Minimal Proxy**  
  - Lower overhead compared to the transparent proxy approach.

---

## 12. Limitations and Considerations

### Secret Size Limitations
- The `secretHash` is a fixed `bytes32` value but does not limit the secret size
- Practical limitations for `revealSecret` are:
  - **Block Gas Limit**: Each byte of the secret consumes gas (4 gas per zero byte, 68 gas per non-zero byte)
  - **Transaction Size**: Maximum ~128KB total transaction size on most networks
  - **Tested Sizes**: Successfully tested with various secret sizes:
    - 1KB: Minimal gas usage
    - 10KB: Moderate gas usage
    - 50KB: Higher but still practical gas usage
    - 100KB: Very high gas usage, may be impractical on congested networks
  - **Recommendation**: Keep secrets under 50KB for reliable execution
  - **Large Data**: For larger secrets, consider storing them off-chain (e.g., IPFS) and only storing their hash on-chain

Note: Actual gas costs and size limits will vary based on network conditions and the specific blockchain being used. The contract itself can handle larger secrets (tested up to 1MB in development), but network constraints make this impractical in production.

---

## 13. Monitoring and Maintenance

- **Event Indexing**  
  - Off-chain services track `SecretRegistered(secretHash, partyA, partyB)` and `SecretRevealed(secretHash, revealer, secret)`.

- **Gas Usage Observance**  
  - Operators monitor for sudden increases in gas costs.

- **Security Alerts**  
  - Automated watchers can detect unusual registration or reveal patterns.

---

## 14. Conclusion

The **SecretStore** contract provides a **secure, upgradeable** solution for two-party secret storage, aligned with atomic registration and delayed revelation. By leveraging **EIP-712** signatures, **salted hashing**, and **UUPS**-based upgradeability, the system maintains robust security, ensures confidentiality until reveal, and offers emergency controls for swift response.

A **security-first** methodology pervades this design, from preventing replay attacks to requiring full signatures in a single transaction, all while incorporating role-based access control and pausable operations. Future enhancements, such as explicit salt validation and upgrade timelocks, can further strengthen the platform’s resilience and user confidence.

---

## 15. Possible Future Enhancements

### Version-Aware Signature Validation
A more sophisticated version handling system could be implemented to allow secrets to persist across upgrades. This would:
1. Store the contract version with each agreement
2. Use agreement-specific versions when validating reveal signatures
3. Allow upgrades without requiring all secrets to be revealed first

However, this enhancement should only be implemented with:
- A thorough security audit
- Comprehensive upgrade testing
- A timelock mechanism to ensure proper migration
- Clear documentation of version compatibility

### Additional Features

1. **Automated Secret Deletion**
2. **Timelock for Upgrades**
   - Implement a timelock that enforces a delay between scheduling and executing an upgrade. This approach gives stakeholders time to review proposed changes and cancel any potentially harmful upgrades before they take effect.
