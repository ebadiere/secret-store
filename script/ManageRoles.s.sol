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
        
        console.log("\nRole Management Configuration:");
        console.log("------------------------");
        console.log("Network:", block.chainid == 31337 ? "Anvil" : "Production");
        console.log("Proxy:", config.proxyAddress);
        console.log("Target Account:", config.account);
        console.log("Role:", vm.toString(config.role));
        console.log("Action:", config.action == Action.Grant ? "GRANT" : "REVOKE");
        console.log("Sender (multi-sig):", config.sender);
        console.log("------------------------\n");

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

    function _getConfig() internal returns (RoleConfig memory config) {
        // Always get proxy address from environment
        config.proxyAddress = vm.envAddress("PROXY_ADDRESS");
        
        if (block.chainid == 31337) {
            // ====== Local Testing Configuration ======
            // Get configuration from environment variables or use defaults
            config.account = vm.envOr("TARGET_ACCOUNT", address(0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC));
            
            // Use Account #1 (multisig) as sender by default
            config.senderKey = vm.envOr("PRIVATE_KEY", uint256(0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d));
            config.sender = vm.addr(config.senderKey);
            
            // Get role from environment or default to PAUSER_ROLE
            string memory roleStr = vm.envOr("ROLE", string("PAUSER"));
            config.role = _parseRole(roleStr, config.proxyAddress);
            
            // Get action from environment or default to Grant
            string memory actionStr = vm.envOr("ACTION", string("GRANT"));
            config.action = _parseAction(actionStr);
        } else {
            // ====== Production Configuration ======
            config.account = vm.envAddress("TARGET_ACCOUNT");
            config.senderKey = vm.envUint("PRIVATE_KEY");
            config.sender = vm.addr(config.senderKey);
            config.role = _parseRole(vm.envString("ROLE"), config.proxyAddress);
            config.action = _parseAction(vm.envString("ACTION"));
        }
    }

    function _parseRole(string memory roleStr, address proxyAddr) internal returns (bytes32) {
        SecretStore store = SecretStore(proxyAddr);
        
        if (keccak256(bytes(roleStr)) == keccak256(bytes("PAUSER"))) {
            return store.PAUSER_ROLE();
        } else if (keccak256(bytes(roleStr)) == keccak256(bytes("UPGRADER"))) {
            return store.UPGRADER_ROLE();
        } else if (keccak256(bytes(roleStr)) == keccak256(bytes("DEFAULT_ADMIN"))) {
            return bytes32(0);
        } else {
            revert("Invalid role specified");
        }
    }

    function _parseAction(string memory actionStr) internal pure returns (Action) {
        if (keccak256(bytes(actionStr)) == keccak256(bytes("GRANT"))) {
            return Action.Grant;
        } else if (keccak256(bytes(actionStr)) == keccak256(bytes("REVOKE"))) {
            return Action.Revoke;
        } else {
            revert("Invalid action specified");
        }
    }
}
