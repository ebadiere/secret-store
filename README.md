# SecretStore Smart Contract

**Looking for in-depth details about this contract’s architecture and security?**  
Head to the [**design doc**](./docs/design.md) right away for a deep dive into the security model, upgrade patterns, and overall technical specifications.

## Overview

A secure smart contract implementation that enables two parties to store and reveal secrets on-chain, satisfying these key requirements:
- Store secrets that both parties have agreed to
- Keep secrets hidden until revelation
- Allow either party to reveal the secret
- Delete the agreement after revelation
- Ensure atomic registration in a single transaction

## Features

- **Secure Secret Storage**: Cryptographic verification of both parties' consent using EIP-712 signatures
- **Atomic Registration**: Single-transaction guarantee for secret registration
- **Access Control**: Role-based administration using OpenZeppelin's AccessControl
- **Upgradeable**: UUPS proxy pattern (EIP-1822) for future improvements
- **Emergency Controls**: Pausable functionality for safety
- **Gas Optimized**: Efficient storage and operation patterns

## Quick Start

### Local Development
```bash
# Install Foundry (if not already installed)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install dependencies
cd secret-store
forge install

# Run tests
forge test
```

### Sanity Check
```bash
forge clean && forge build --force && forge test -vvv
```
> Note: The `_authorizeUpgrade` function includes a pause check to ensure upgrades can only occur when the contract is paused. This is an important security feature that prevents upgrades during active operations.

## Project Structure

```
secret-store/
├── src/
│   └── SecretStore.sol
├── test/
│   ├── SecretStore.t.sol
│   ├── SecretStoreFuzz.t.sol
│   ├── SecretStoreInvariant.t.sol
│   ├── SecretStoreSizeLimits.t.sol
│   └── SecretStoreUpgrade.t.sol
├── docs/
│   └── design.md
├── scripts/
│   ├── Deploy.s.sol
│   ├── ManageRoles.s.sol
│   └── VerifyRoles.s.sol
└── README.md
```

## Testing

The project includes comprehensive test suites:

- `SecretStore.t.sol`: Core functionality tests including secret registration, revelation, and access control
- `SecretStoreFuzz.t.sol`: Fuzz tests with randomized inputs
- `SecretStoreInvariant.t.sol`: Invariant tests for critical security properties
- `SecretStoreSizeLimits.t.sol`: Tests for secret size limitations and gas usage analysis
- `SecretStoreUpgrade.t.sol`: Tests for upgrade safety and proxy functionality

To run the tests:

```bash
forge test
```

For detailed output including gas measurements:

```bash
forge test -vvv
```

### Secret Size Limitations

The contract has been thoroughly tested with secrets of various sizes:
- Successfully handles secrets up to 50KB (recommended maximum)
- Includes gas usage analysis for different secret sizes (1KB to 100KB)
- Network conditions (block gas limits, transaction size) may affect maximum practical size
- For larger secrets, consider storing them off-chain and only storing their hash on-chain

## Security Features

- EIP-712 typed signatures for secure message signing
- Protection against replay attacks
- Role-based access control for administrative functions
- Upgrades require contract to be paused first
- Comprehensive security testing including fuzz and invariant tests
- Pausable functionality for emergency stops
- Upgradeable pattern for future security improvements

## Contract Interaction

### 1. Secret Registration
```solidity
function registerSecret(
    bytes32 secretHash,
    uint8 v1, bytes32 r1, bytes32 s1,  // Party A's signature
    uint8 v2, bytes32 r2, bytes32 s2   // Party B's signature
) external
```

### 2. Secret Revelation
```solidity
function revealSecret(
    string calldata secret,
    address partyA,
    address partyB
) external
```

## Production Deployment

### Prerequisites
1. Set up required environment variables:
```bash
# RPC endpoint for target network
export RPC_URL="https://your-rpc-endpoint"

# For contract verification
export ETHERSCAN_KEY="your-etherscan-api-key"
export VERIFIER_URL="https://api.etherscan.io/api"

# Multisig wallet address that will receive admin roles
export MULTISIG_ADDRESS="0x..."

# For non-hardware wallet deployment
export PRIVATE_KEY="your-private-key"  # Only if not using hardware wallet
```

### Development Deployment (Recommended First Step)
Before deploying to testnet or mainnet, practice the deployment process locally:

```bash
# Start local Ethereum node
anvil

# In a new terminal, deploy to local node
# This will use Anvil's default test accounts
forge script script/Deploy.s.sol \
    --rpc-url http://localhost:8545 \
    --broadcast \
    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Verify the deployment output:
# - Check Implementation address
# - Check Proxy address
# - Confirm role setup for admin/upgrader/pauser
# - Test basic functionality
```

### Testnet Deployment
After successful local testing, deploy to your chosen testnet:

```bash
# Deploy to testnet (e.g., Sepolia)
forge script script/Deploy.s.sol \
    --rpc-url $RPC_URL \
    --broadcast \
    --verify \
    --verifier-url $VERIFIER_URL \
    --etherscan-api-key $ETHERSCAN_KEY \
    --private-key $PRIVATE_KEY
```

### Mainnet Deployment

#### Option 1: Using Hardware Wallet (Recommended)
For secure production deployment, use a hardware wallet like Ledger:

```bash
# Deploy using Ledger
forge script script/Deploy.s.sol \
    --rpc-url $RPC_URL \
    --broadcast \
    --ledger \
    --hd-paths "m/44'/60'/0'/0/0" \  # Derivation path for Ethereum account
    --verify \
    --verifier-url $VERIFIER_URL \
    --etherscan-api-key $ETHERSCAN_KEY
```

#### Option 2: Using Private Key
```bash
# Deploy using private key (less secure)
forge script script/Deploy.s.sol \
    --rpc-url $RPC_URL \
    --broadcast \
    --private-key $PRIVATE_KEY \
    --verify \
    --verifier-url $VERIFIER_URL \
    --etherscan-api-key $ETHERSCAN_KEY
```

### Post-Deployment Verification
After any deployment:
1. Verify the implementation and proxy addresses in the deployment output
2. Confirm that all roles (DEFAULT_ADMIN_ROLE, UPGRADER_ROLE, PAUSER_ROLE) are properly set
3. Test basic functionality (secret registration and revelation)
4. For mainnet, conduct a thorough security review of the deployment

## Role Management

The project includes two scripts for managing and verifying roles:

### VerifyRoles Script

Used to verify the role configuration of a deployed contract. It checks:
- Multisig wallet has all required roles (DEFAULT_ADMIN_ROLE, UPGRADER_ROLE, PAUSER_ROLE)
- Deployer has no roles
- Zero address has no roles

```bash
# Local testing
export PROXY_ADDRESS="0x..." # Address of the deployed proxy
export MULTISIG_ADDRESS="0x..." # Address to verify roles for
forge script script/VerifyRoles.s.sol --rpc-url http://localhost:8545

# Production
export PROXY_ADDRESS="0x..." # Address of the deployed proxy
export MULTISIG_ADDRESS="0x..." # Address of the multisig wallet
forge script script/VerifyRoles.s.sol --rpc-url $RPC_URL
```

### ManageRoles Script

Used to grant or revoke roles on the contract. For production, this should be executed through the multisig wallet.

```bash
# Local testing
export PROXY_ADDRESS="0x..."      # Address of the deployed proxy
export TARGET_ACCOUNT="0x..."     # Account to grant/revoke role for
export ROLE="PAUSER"             # Role to manage (must be: PAUSER, UPGRADER, or DEFAULT_ADMIN)
export ACTION="GRANT"            # Action to take (must be: GRANT or REVOKE)
export PRIVATE_KEY="0x..."       # Private key of an account that has DEFAULT_ADMIN_ROLE

# Execute the transaction (requires --broadcast)
forge script script/ManageRoles.s.sol --rpc-url http://localhost:8545 --broadcast

# Production
# 1. Generate transaction data (no --broadcast)
forge script script/ManageRoles.s.sol --rpc-url $RPC_URL
# 2. Submit transaction through multisig UI
```

Available roles:
- `DEFAULT_ADMIN_ROLE`: Can grant and revoke all roles
- `UPGRADER_ROLE`: Can upgrade the contract implementation
- `PAUSER_ROLE`: Can pause and unpause the contract

## Administration

### Emergency Controls
```bash
# Pause contract
export CONTRACT_ADDRESS=<address>
export PRIVATE_KEY=<pauser-key>
export OPERATION=pause
forge script script/EmergencyControls.s.sol --rpc-url $RPC_URL --broadcast

# Unpause contract
export CONTRACT_ADDRESS=<address>
export PRIVATE_KEY=<pauser-key>
export OPERATION=unpause
forge script script/EmergencyControls.s.sol --rpc-url $RPC_URL --broadcast
```

### Contract Upgrades
```bash
# Deploy new implementation
export PRIVATE_KEY=<upgrader-key>
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast --verify
```

## Documentation

For detailed technical information, see:
- [Technical Design](./docs/design.md)
- [Contract Documentation](./src/SecretStore.sol)

## Test Coverage

The core `SecretStore.sol` contract has **100% test coverage** across all metrics:
- 100% Line Coverage
- 100% Statement Coverage
- 100% Branch Coverage
- 100% Function Coverage

This comprehensive test suite includes:
- Unit tests for all contract functionality
- Fuzz testing with randomized inputs
- Invariant testing for critical security properties
- Size limit and gas usage analysis
- Upgrade safety tests

## Demo
There are two ways to run the demo:

### Option 1: Interactive Demo (Recommended)
This option runs the demo step by step with pauses and clear output:

```bash
# Start a local Ethereum node (in a separate terminal)
anvil

# Set environment variables for the demo
export SECRET="my secret message"  # The secret to store
export REVEAL_PARTY="A"           # Which party reveals the secret (A or B)

# Run the interactive demo
./demo_runner.sh
```

### Option 2: Quick Demo
This option runs through all steps at once and shows the output at the end:

```bash
# Start a local Ethereum node (in a separate terminal)
anvil

# Set environment variables for the demo
export SECRET="my secret message"  # The secret to store
export REVEAL_PARTY="A"           # Which party reveals the secret (A or B)

# Run the demo script (uses Anvil's default test accounts)
forge script script/DemoSecretStore.s.sol --fork-url http://localhost:8545
```

Both demos will show:
1. Contract deployment addresses
2. Secret details and hashes
3. Signatures from both parties
4. The revealed secret
