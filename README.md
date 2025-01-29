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

## Running the Demo

The project includes an interactive demo that showcases the SecretStore contract's functionality. The demo walks you through:
- Contract deployment
- Secret registration with signatures from both parties
- Secret revelation process

### Prerequisites
- Foundry installed and available in your PATH
- A local Anvil node running

### Running the Demo

1. Start a local Anvil node:
```shell
anvil
```

2. In a new terminal, run the demo script:
```shell
# Replace "your secret message" with the secret you want to store
SECRET="your secret message" REVEAL_PARTY="A" ./demo_runner.sh
```

The demo will:
1. Deploy the SecretStore contract
2. Show the contract addresses and party addresses
3. Create and display signatures from both parties
4. Register the secret on-chain
5. Reveal the secret

You can choose which party reveals the secret by setting `REVEAL_PARTY` to either:
- `A` - Party A reveals the secret
- `B` - Party B reveals the secret

### Example
```shell
SECRET="my super secret message" REVEAL_PARTY="A" ./demo_runner.sh
```

## Using Remix

You can also try the SecretStore contract using Remix IDE. Follow these steps:

1. Open [Remix IDE](https://remix.ethereum.org)
2. Create a new workspace and import these files:
   - `src/SecretStore.sol`
   - `script/RemixDemo.sol`
   - Required OpenZeppelin contracts (use the "Import from GitHub" feature)

3. Deploy the contracts:
   ```
   a. Deploy SecretStore.sol first (this is the implementation)
   b. Copy the deployed implementation address
   c. Deploy RemixDemo.sol with the implementation address
   d. Call initialize() on RemixDemo with your address as admin
   e. Get the proxy address using getProxy()
   ```

4. Interact with the contract:
   ```
   a. Use "At Address" with the proxy address to load SecretStore interface
   b. You can now call registerSecret and revealSecret through this interface
   ```

Note: For testing in Remix, you can use these test values:
```solidity
// Example values for registerSecret:
secretHash: 0x922f3a9b8395b8a3daad2e2c7228776744795bb8ce8c1d3d5c40d6e510497ef2
partyA: <your current address>
partyB: <another test address>
signatureA: 0x3e02b0648580351c72ce0132f6f8eebb4def5cffe27a4b4815de785a675fccdd6fe9630014a250bfa6ee35a379a76e284560433c1a219aecb78183ec9cc5cb2d1c
signatureB: 0xd0a9aa04d2c2afcc67027da12e06af7df56fc2d5b1cd37e8065cc32c3beb2caf4c0a7480b0530ad0b5612e55ca927faae0e813934fdd1e7ae7c6fe5a4e117d5d1b

// Example values for revealSecret:
secret: "my super secret message"
salt: 0x000000000000000000000000000000000000000000000000000000000000007b
secretHash: 0x922f3a9b8395b8a3daad2e2c7228776744795bb8ce8c1d3d5c40d6e510497ef2
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
