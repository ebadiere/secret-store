# SecretStore Smart Contract

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

## Project Structure

```
secret-store/
├── src/
│   └── SecretStore.sol        # Main contract implementation
├── test/
│   ├── SecretStore.t.sol      # Core functionality tests
│   ├── SecretStoreProxy.t.sol # Proxy and upgrade tests
│   ├── SecretStorePause.t.sol # Pause functionality tests
│   └── SecretStoreSizeLimits.t.sol # Secret size limits and gas usage tests
├── docs/
│   └── design.md              # Design documentation and specifications
├── scripts/
│   └── Deploy.s.sol           # Deployment script
└── README.md                  # Project documentation
```

The project follows a standard Foundry structure:

## Testing

The project includes comprehensive test suites:

- `SecretStore.t.sol`: Core functionality tests including secret registration, revelation, and access control
- `SecretStoreProxy.t.sol`: Tests for proxy deployment and upgrade functionality
- `SecretStorePause.t.sol`: Tests for emergency pause functionality
- `SecretStoreSizeLimits.t.sol`: Tests for secret size limitations and gas usage analysis

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

### Option 1: Using Hardware Wallet (Recommended)
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

### Option 2: Using Private Key
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

### Deployment Process
The deployment script will:
1. Deploy implementation contract
2. Deploy proxy contract
3. Initialize with deployer as temporary admin
4. Transfer all roles to multisig wallet:
   - DEFAULT_ADMIN_ROLE
   - UPGRADER_ROLE
   - PAUSER_ROLE
5. Renounce all deployer roles
6. Verify role configuration:
   - Confirm multisig has all required roles
   - Verify deployer has no remaining roles
   - Check no roles assigned to zero address

### Post-Deployment Verification
After deployment, verify:
1. Contract addresses are correct
2. Multisig has received all roles
3. Deployer has no remaining roles
4. Contract is properly initialized

You can verify the role setup using the provided script:
```bash
forge script script/VerifyRoles.s.sol \
    --rpc-url $RPC_URL \
    --sig "verify(address)" $PROXY_ADDRESS
```

The `--hd-paths` option specifies which account to use on your Ledger:
- `m/44'/60'/0'/0/0` - First Ethereum account
- `m/44'/60'/0'/0/1` - Second Ethereum account
- `m/44'/60'/0'/0/2` - Third Ethereum account

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
- [Test Coverage Report](./coverage.md)
