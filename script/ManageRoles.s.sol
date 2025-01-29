// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "forge-std/Script.sol";
import "../src/SecretStore.sol";

/**
 * @title ManageRoles
 * @notice Script for managing roles in the SecretStore contract
 * @dev This script should be executed through the multi-sig for production environments
 *      For local testing, we use Anvil's default accounts
 *
 * Usage:
 * 1. Local testing:
 *    forge script script/ManageRoles.s.sol --rpc-url http://localhost:8545 --broadcast
 *    # Uses Anvil's default accounts:
 *    # - Account #0 (0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266) - Initial deployer
 *    # - Account #1 (0x70997970C51812dc3A010C7d01b50e0d17dc79C8) - Multi-sig
 *    # - Account #2 (0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC) - New role recipient
 *
 * 2. Production:
 *    # Generate transaction data for multi-sig
 *    forge script script/ManageRoles.s.sol --rpc-url $RPC_URL
 *    # Submit transaction through multi-sig UI
 */
contract ManageRoles is Script {
    // Role management actions
    enum Action { Grant, Revoke }
    
    struct RoleConfig {
        address proxyAddress;  // Address of the proxy contract
        address account;       // Account to grant/revoke role
        bytes32 role;         // Role to grant/revoke
        Action action;        // Whether to grant or revoke
        address sender;       // Account executing the transaction (multi-sig)
        uint256 senderKey;    // Private key for the sender (only for testing)
    }

    function run() external {
        // Load configuration
        RoleConfig memory config = _getConfig();
        
        // Get contract instance
        SecretStore secretStore = SecretStore(config.proxyAddress);

        // Execute role change
        vm.startBroadcast(config.senderKey);
        
        if (config.action == Action.Grant) {
            secretStore.grantRole(config.role, config.account);
            console.log("Granted role", vm.toString(config.role), "to", config.account);
        } else {
            secretStore.revokeRole(config.role, config.account);
            console.log("Revoked role", vm.toString(config.role), "from", config.account);
        }

        vm.stopBroadcast();
    }

    function _getConfig() internal view returns (RoleConfig memory config) {
        if (block.chainid == 31337) {
            // ====== Local Testing Configuration ======
            // Using Anvil's default accounts:
            // Account #0 (deployer): 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
            // Account #1 (multi-sig): 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
            // Account #2 (role recipient): 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
            
            // Use the last deployed proxy address or set manually for testing
            config.proxyAddress = address(0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512);  // Default Anvil deployment
            
            // Multi-sig is Account #1
            config.senderKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
            config.sender = vm.addr(config.senderKey);
            
            // New role recipient is Account #2
            config.account = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;
            
            // Default to granting PAUSER_ROLE for testing
            config.role = SecretStore(config.proxyAddress).PAUSER_ROLE();
            config.action = Action.Grant;
        } else {
            // ====== Production Configuration ======
            config.proxyAddress = vm.envAddress("PROXY_ADDRESS");
            config.account = vm.envAddress("TARGET_ACCOUNT");
            config.senderKey = vm.envUint("PRIVATE_KEY");
            config.sender = vm.addr(config.senderKey);
            
            // Parse role from environment
            string memory roleStr = vm.envString("ROLE");
            if (keccak256(bytes(roleStr)) == keccak256(bytes("PAUSER"))) {
                config.role = SecretStore(config.proxyAddress).PAUSER_ROLE();
            } else if (keccak256(bytes(roleStr)) == keccak256(bytes("UPGRADER"))) {
                config.role = SecretStore(config.proxyAddress).UPGRADER_ROLE();
            } else if (keccak256(bytes(roleStr)) == keccak256(bytes("DEFAULT_ADMIN"))) {
                config.role = bytes32(0);
            } else {
                revert("Invalid role specified");
            }

            // Parse action from environment
            string memory actionStr = vm.envString("ACTION");
            if (keccak256(bytes(actionStr)) == keccak256(bytes("GRANT"))) {
                config.action = Action.Grant;
            } else if (keccak256(bytes(actionStr)) == keccak256(bytes("REVOKE"))) {
                config.action = Action.Revoke;
            } else {
                revert("Invalid action specified");
            }
        }

        // Validate configuration
        require(config.proxyAddress != address(0), "Proxy address not configured");
        require(config.account != address(0), "Target account not configured");
        require(config.sender != address(0), "Sender address not configured");
        require(config.senderKey != 0, "Sender private key not configured");
        
        // Log configuration
        console.log("\nRole Management Configuration:");
        console.log("------------------------");
        console.log("Network:", block.chainid == 31337 ? "Anvil" : "Production");
        console.log("Proxy:", config.proxyAddress);
        console.log("Target Account:", config.account);
        console.log("Role:", vm.toString(config.role));
        console.log("Action:", config.action == Action.Grant ? "GRANT" : "REVOKE");
        console.log("Sender (multi-sig):", config.sender);
        console.log("------------------------\n");
    }
}
