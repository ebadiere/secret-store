# **SecretStore** - Secure Two-Party Secret Management Contract

## Overview
A smart contract system enabling two parties to securely register and reveal secrets on-chain. The registration process is atomic - both parties sign the salted hash of the secret and their signatures are validated in a single transaction. The secret's hash is stored on-chain until one party reveals it.

## Core Requirements
- **Secret Registration**: Two-party agreement in a single transaction
- **Privacy**: Secret stored as a hash (with addresses) to prevent value observation
- **Access Control**: Either party can reveal at any time
- **Cleanup**: Automatic deletion post-revelation
- **Transparency**: Event emission upon revelation with actual secret value

## Technical Architecture

### Data Structures
```solidity
struct SecretAgreement {
    bytes32 secretHash;      // Hash of secret+salt from off-chain
    address partyA;         // First participant
    address partyB;         // Second participant
    uint256 registeredAt;   // Block timestamp
}

// Mapping from agreementId to agreement
mapping(bytes32 => SecretAgreement) public agreements;
```

### Core Functions

#### 1. Register Secret
```solidity
function registerSecret(
    bytes32 secretHash,    // Hash of the secret with salt (created off-chain)
    address partyA,
    address partyB,
    bytes memory signatureA,
    bytes memory signatureB
) external whenNotPaused nonReentrant returns (bytes32 agreementId) {
    // Generate unique agreementId
    agreementId = keccak256(abi.encodePacked(
        secretHash,
        partyA,
        partyB,
        block.timestamp,
        block.number
    ));

    require(
        agreements[agreementId].registeredAt == 0,
        "Agreement already exists"
    );

    // Create typed data hash for EIP-712
    bytes32 structHash = keccak256(abi.encode(
        AGREEMENT_TYPEHASH,
        secretHash,
        partyA,
        partyB
    ));
    bytes32 hash = _hashTypedDataV4(structHash);

    // Verify signatures
    require(_verify(hash, signatureA, partyA), "Invalid signature A");
    require(_verify(hash, signatureB, partyB), "Invalid signature B");

    // Store agreement
    agreements[agreementId] = SecretAgreement({
        secretHash: secretHash,
        partyA: partyA,
        partyB: partyB,
        registeredAt: block.timestamp
    });

    emit SecretRegistered(agreementId, partyA, partyB);
    return agreementId;
}
```

#### 2. Reveal Secret
```solidity
function revealSecret(
    bytes32 agreementId,
    string memory secret,
    bytes32 salt
) external whenNotPaused nonReentrant {
    SecretAgreement storage agreement = agreements[agreementId];
    require(
        msg.sender == agreement.partyA || msg.sender == agreement.partyB,
        "Only participants can reveal"
    );
    
    // Hash the secret with the provided salt
    bytes32 secretHash = keccak256(abi.encodePacked(secret, salt));
    
    // Verify it matches the stored hash
    require(
        secretHash == agreement.secretHash,
        "Invalid secret or salt"
    );

    // Store locally for event (CEI pattern)
    address revealer = msg.sender;
    
    // Delete first
    delete agreements[agreementId];

    // Emit event with actual secret value
    emit SecretRevealed(agreementId, revealer, secret);
}
```

### Events
```solidity
event SecretRegistered(
    bytes32 indexed agreementId,
    address indexed partyA,
    address indexed partyB
);

event SecretRevealed(
    bytes32 indexed agreementId,
    address indexed revealer,
    string secret              // The actual secret value
);
```

### Implementation Architecture

#### Base Contract
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract SecretStore is 
    Initializable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    EIP712Upgradeable
{
    using ECDSA for bytes32;

    // EIP712 type hashes
    bytes32 private constant AGREEMENT_TYPEHASH = keccak256(
        "Agreement(bytes32 secretHash,address partyA,address partyB)"
    );

    // UUPS upgrade authorization
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        // Only owner can upgrade implementation
    }

    // ... rest of the contract implementation
}
```

### Off-Chain Signature Generation
The signature process happens off-chain before calling the `registerSecret` function:

```javascript
// Using ethers.js for off-chain signing

// 1. Generate random salt and hash the secret
const secret = "my secret message";
const salt = ethers.utils.randomBytes(32);  // Save this for later revelation!
const secretHash = ethers.utils.solidityKeccak256(
    ['string', 'bytes32'],
    [secret, salt]
);

// 2. Prepare the domain and types for EIP-712
const domain = {
    name: "SecretStore",
    version: "1.0.0",
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

// 3. Prepare the value to sign (using the hash)
const value = {
    secretHash: secretHash,
    partyA: partyA,
    partyB: partyB
};

// 4. Get signatures from both parties using EIP-712
const signatureA = await walletA._signTypedData(domain, types, value);
const signatureB = await walletB._signTypedData(domain, types, value);

// 5. Submit both signatures in a single transaction
const tx = await contract.registerSecret(
    secretHash,
    partyA,
    partyB,
    signatureA,
    signatureB
);
await tx.wait();

// 6. Store the salt securely off-chain for later revelation
// Both parties should store: { agreementId, secret, salt }
```

### Off-Chain Secret Revelation
The process of revealing a secret:

```javascript
// 1. Retrieve the original secret and salt
const agreementId = "0x..."; // from registration
const secret = "my secret message"; // original secret
const salt = "0x..."; // original salt from registration

// 2. Call reveal function with original secret and salt
const tx = await contract.revealSecret(agreementId, secret, salt);
await tx.wait();

// 3. Listen for SecretRevealed event
contract.on("SecretRevealed", (agreementId, revealer, secret) => {
    console.log({
        agreementId: agreementId,
        revealer: revealer,
        secret: secret        // This is the actual secret value
    });
});
```

### Security Considerations

1. **Hash Security**
   - Uses random salt to prevent rainbow table attacks
   - Even simple secrets become unique due to random salt
   - Hash cannot be reversed to reveal secret
   - Salt must be stored securely off-chain

2. **Signature Verification**
   - Uses EIP-712 for structured data signing
   - Validates both signatures in single transaction
   - Prevents front-running through atomic execution

3. **Access Control**
   - Only registered parties can reveal
   - Requires both secret and correct salt for revelation
   - Owner can pause in emergency
   - Reentrancy protection on state-changing functions

4. **Secret Storage**
   - Only stores the salted hash on-chain
   - Original secret and salt kept off-chain
   - Immediate cleanup after revelation

### State Management

#### State Transitions
1. **Unregistered** → **Registered**
   - Trigger: Valid registration transaction
   - Validation: Signatures, uniqueness
   - Action: Hash secret with addresses for storage

2. **Registered** → **Revealed**
   - Trigger: Valid revelation with correct secret
   - Validation: Hash matches stored value
   - Effects: Event emission, data cleanup

### Gas Optimization
- Single-slot packing for core data
- Efficient storage cleanup through deletion
- No unnecessary storage of derivable data

### Error Handling
1. **Registration Failures**
   - Invalid signatures
   - Duplicate agreements
   - Invalid participants

2. **Revelation Failures**
   - Invalid secret
   - Unauthorized caller
   - Non-existent agreement

### Testing Strategy
1. Unit tests for core functions
2. Integration tests for full flows
3. Fuzz testing for edge cases
4. Gas optimization tests