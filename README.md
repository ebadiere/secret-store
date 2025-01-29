# SecretStore Smart Contract

A secure smart contract for storing and revealing secrets between two parties, leveraging advanced Ethereum features:

- **UUPS Upgradeable Pattern (EIP-1822)** for contract upgradeability
- **EIP-712 Typed Signatures** for secure message signing
- **Role-based Access Control** for administrative functions
- **Pausable Functionality** for emergency stops

## Overview

The SecretStore contract enables two parties to securely store and reveal secrets on-chain:
1. Party A registers a secret hash with signatures from both parties
2. Either party can later reveal the secret, which is verified against the hash
3. The contract maintains security through:
   - Cryptographic verification of both parties' consent
   - Protection against replay attacks
   - Secure upgrade mechanism for future improvements

For detailed technical information, see [DESIGN.md](./DESIGN.md).

## Development

### Prerequisites
- [Foundry](https://book.getfoundry.sh/getting-started/installation)

### Installation
```bash
git clone https://github.com/yourusername/secret-store.git
cd secret-store
forge install
```

### Testing
```bash
# Run all tests
forge test

# Run tests with gas reporting
forge test --gas-report

# Run tests with verbosity
forge test -vvv

# Run specific test
forge test --match-test testSecretRegistration
```

### Code Coverage
```bash
forge coverage
```

## Interactive Demo

The project includes a demo that showcases the contract's functionality:

```bash
# Start local node (in a separate terminal)
anvil

# Run demo as Party A revealing the secret
SECRET="my secret message" REVEAL_PARTY="A" ./demo_runner.sh

# Run demo as Party B revealing the secret
SECRET="my secret message" REVEAL_PARTY="B" ./demo_runner.sh
```

## Production Deployment

For production deployments, follow these security best practices:

1. Each party must use a separate wallet (different seed phrases)
2. Never share private keys between parties
3. Store the contract address and verify it matches your deployment
4. Always verify signatures are from the correct addresses
5. Consider using a multi-sig wallet for admin operations

### Deploy to Network
```bash
# Set your environment variables
export RPC_URL=your_rpc_url
export PRIVATE_KEY=your_private_key

# Deploy and verify
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast --verify
```

### Emergency Controls
```bash
# Pause contract operations
export CONTRACT_ADDRESS=<deployed-contract-address>
export PRIVATE_KEY=<private-key-with-pauser-role>
export OPERATION=pause
forge script script/EmergencyControls.s.sol --rpc-url $RPC_URL --broadcast

# Unpause contract operations
export OPERATION=unpause
forge script script/EmergencyControls.s.sol --rpc-url $RPC_URL --broadcast
```

Note: Emergency controls should only be used by authorized operators with the `PAUSER_ROLE`.
