## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```

### Deployment

To deploy the contract:

1. Set up your environment variables:
```shell
# Create a .env file with your private key
echo "PRIVATE_KEY=your_private_key_here" > .env
```

2. Deploy to local Anvil network:
```shell
# Start local network
anvil

# Deploy contract
forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast
```

3. Deploy to testnet/mainnet:
```shell
# Deploy to Sepolia testnet
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast --verify

# Deploy to mainnet
forge script script/Deploy.s.sol --rpc-url $MAINNET_RPC_URL --broadcast --verify
```

Note: Make sure to have sufficient ETH in your deployer account for gas fees.

# SecretStore Smart Contract

A secure smart contract for storing and revealing secrets between two parties, featuring role-based access control, upgradeability, and pausability.

## Overview

The SecretStore contract demonstrates secure smart contract development practices:
- Role-based access control (RBAC) for administrative functions
- Upgradeable proxy pattern (UUPS)
- Pausable functionality for emergency stops
- Multi-sig wallet integration
- Secure deployment process

## Development and Testing

### Prerequisites
- Foundry toolkit (forge, cast, anvil)
- Node.js and npm (optional, for development tools)

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/secret-store.git
cd secret-store

# Install dependencies
forge install
```

### Local Development

1. Start a local Anvil node:
```bash
anvil
```

2. Deploy the contract:
```bash
# Deploy using the deployment script
forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast -vvv
```

This will:
- Deploy the implementation contract
- Deploy the proxy
- Initialize the contract
- Transfer all roles to the multi-sig (Account #1 in Anvil)
- Renounce the deployer's roles

3. Verify the deployment:
```bash
# Check that multi-sig (Account #1) has admin role
cast call <PROXY_ADDRESS> "hasRole(bytes32,address)(bool)" \
  0x0000000000000000000000000000000000000000000000000000000000000000 \
  0x70997970C51812dc3A010C7d01b50e0d17dc79C8

# Check that multi-sig has PAUSER_ROLE
cast call <PROXY_ADDRESS> "PAUSER_ROLE()(bytes32)"
# Copy the returned role hash and use it in the next command
cast call <PROXY_ADDRESS> "hasRole(bytes32,address)(bool)" \
  <PAUSER_ROLE_HASH> \
  0x70997970C51812dc3A010C7d01b50e0d17dc79C8
```

4. Manage roles using the ManageRoles script:
```bash
# Grant PAUSER_ROLE to a new account
forge script script/ManageRoles.s.sol --rpc-url http://localhost:8545 --broadcast -vvv
```

This will:
- Use the multi-sig account to grant PAUSER_ROLE to Account #2
- The script defaults to granting PAUSER_ROLE for testing
- In production, use environment variables to specify roles and actions

5. Verify role assignment:
```bash
# Check that Account #2 has PAUSER_ROLE
cast call <PROXY_ADDRESS> "hasRole(bytes32,address)(bool)" \
  <PAUSER_ROLE_HASH> \
  0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
```

## Production Deployment

For production deployments, follow these security best practices:

1. Set up environment variables:
```bash
# Copy the example env file
cp env.example .env

# Edit .env with your values:
# - RPC endpoints
# - Multi-sig address
# - Hardware wallet or encrypted keystore configuration
```

2. Deploy using one of these secure methods:

a. Hardware Wallet (recommended):
```bash
forge script script/Deploy.s.sol \
  --rpc-url $RPC_URL \
  --broadcast \
  --ledger \
  --sender $SENDER_ADDRESS
```

b. Encrypted Keystore:
```bash
# First time: Create encrypted keystore
cast wallet import deployer --interactive

# Deploy using keystore
forge script script/Deploy.s.sol \
  --rpc-url $RPC_URL \
  --broadcast \
  --account deployer
```

3. Manage roles through multi-sig:
```bash
# Generate role management transaction
PROXY_ADDRESS=<address> \
TARGET_ACCOUNT=<address> \
ROLE=PAUSER \
ACTION=GRANT \
forge script script/ManageRoles.s.sol --rpc-url $RPC_URL

# Submit the generated transaction through your multi-sig UI
```

## Security Features

1. Role-Based Access Control:
   - DEFAULT_ADMIN_ROLE: Can grant/revoke all roles
   - UPGRADER_ROLE: Can upgrade the contract
   - PAUSER_ROLE: Can pause/unpause the contract

2. Multi-sig Integration:
   - All admin roles transferred to multi-sig after deployment
   - Role changes must go through multi-sig
   - Prevents single point of failure

3. Secure Deployment:
   - Hardware wallet support
   - Encrypted keystore support
   - No hardcoded private keys
   - Clear separation of test/production configs

## For Interview Evaluators

This project demonstrates:

1. Smart Contract Security:
   - Role-based access control implementation
   - Secure upgrade pattern (UUPS)
   - Emergency pause functionality
   - Multi-sig integration

2. Development Best Practices:
   - Clear separation of concerns in scripts
   - Comprehensive documentation
   - Secure deployment options
   - Environment-specific configurations

3. Testing and Verification:
   - Easy local testing with Anvil
   - Role verification using cast
   - Clear deployment steps
   - Security-first approach

4. Production Readiness:
   - Hardware wallet support
   - Multi-sig integration
   - Environment variable handling
   - Clear security documentation
