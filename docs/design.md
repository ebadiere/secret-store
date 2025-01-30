# SecretStore — Technical Design Document

## 1. Original Requirements

The **SecretStore** protocol is designed to meet the following core requirements:

1. **Mutual Secret Storage**  
   Enables any two parties (Party A and Party B) to store a mutually agreed secret on-chain.

2. **Agreement Proof**  
   Proves that both parties agreed to the secret at a specific block.

3. **Delayed Reveal**  
   Either party may reveal the secret at a later block.

4. **Cleanup on Reveal**  
   Once a secret is revealed, the contract deletes the agreement.

5. **Atomic Registration**  
   Registration must happen in a **single transaction** to ensure both parties commit in the same block.

6. **Secret Privacy**  
   The secret must not be discoverable by simply observing the chain prior to reveal.

7. **Event Emission**  
   The contract emits events for both registration and revelation, ensuring transparency.

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

1. **Hash Privacy**  
   - Only `secretHash` is stored on-chain, preventing observers from discovering the actual secret until reveal.  
   - A random salt prevents brute-forcing small or guessable secrets.

2. **EIP-712 Defenses**  
   - Domain separation ties signatures to the chain ID, contract address, and version.  
   - Structured data clarifies to users what they are signing.

3. **Upgrade Security**  
   - Only `UPGRADER_ROLE` can call `_authorizeUpgrade`.  
   - Adheres to a stable storage layout.

4. **Emergency Pause**  
   - Pausable contract halts key functions if a vulnerability arises.

5. **Reentrancy Protection**  
   - Uses `nonReentrant` modifier on state-changing functions as a defensive measure:
     - **Future-Proofing**: Protects against potential reentrancy vectors in future upgrades
     - **Human Oversight**: Guards against accidental introduction of vulnerable patterns
     - **Defense in Depth**: Adds an extra layer of security at minimal cost
     - **Low Overhead**: The small gas cost is justified by the security benefit
   - Note: This protection may be removed if security auditors determine it's unnecessary

6. **No Partial Agreements**  
   - Registration is atomic with both signatures required in a single transaction.

---

## 10. Gas Optimization

- **Storage Packing**  
  - The `Agreement` struct is designed to occupy minimal slots.

- **Calldata Usage**  
  - Functions use `calldata` parameters to reduce memory copies.

- **Cached Domain Separator**  
  - Recalculated only if chain ID changes.

- **UUPS Minimal Proxy**  
  - Lower overhead compared to the transparent proxy approach.

---

## 11. Emergency Controls

- **Pause/Unpause**  
  - `PAUSER_ROLE` can suspend state-changing methods quickly.

- **Role Separation**  
  - `DEFAULT_ADMIN_ROLE` manages roles, `UPGRADER_ROLE` handles upgrades, and `PAUSER_ROLE` handles pauses.

---

## 12. Possible Future Enhancements

1. **Salt Parameter Validation**  
   - Consider adding more explicit checks on `salt` during `revealSecret`, such as validating its length or ensuring it follows a particular format. This could help catch user errors or maliciously short salt values that might simplify brute-force attacks.

2. **Timelock for Upgrades**  
   - Implement a timelock that enforces a delay between scheduling and executing an upgrade. This approach gives stakeholders time to review proposed changes and cancel any potentially harmful upgrades before they take effect.

---

## 13. Limitations

- **Secret Size**  
  - Large secrets are expensive to reveal on-chain due to transaction data costs.

- **Public Blockchain**  
  - Once revealed, the secret is publicly visible in transaction logs.

- **Off-Chain Coordination**  
  - Both signatures must be obtained before registration, which can cause delays if a party is unresponsive.

---

## 14. Monitoring

- **Event Indexing**  
  - Off-chain services track `SecretRegistered(secretHash, partyA, partyB)` and `SecretRevealed(secretHash, revealer, secret)`.

- **Gas Usage Observance**  
  - Operators monitor for sudden increases in gas costs.

- **Security Alerts**  
  - Automated watchers can detect unusual registration or reveal patterns.

---

## Conclusion

The **SecretStore** contract provides a **secure, upgradeable** solution for two-party secret storage, aligned with atomic registration and delayed revelation. By leveraging **EIP-712** signatures, **salted hashing**, and **UUPS**-based upgradeability, the system maintains robust security, ensures confidentiality until reveal, and offers emergency controls for swift response.

A **security-first** methodology pervades this design, from preventing replay attacks to requiring full signatures in a single transaction, all while incorporating role-based access control and pausable operations. Future enhancements, such as explicit salt validation and upgrade timelocks, can further strengthen the platform’s resilience and user confidence.
