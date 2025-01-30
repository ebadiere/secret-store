// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Script} from "forge-std/Script.sol";
import {SecretStore} from "../src/SecretStore.sol";

/// @title EmergencyControls
/// @notice Emergency circuit breaker controls for SecretStore
/// @dev Implements critical pause functionality:
/// 1. Emergency Pause: Halts all non-admin operations
/// 2. Controlled Unpause: Resumes normal operation
/// 3. Role-based access control
///
/// Security considerations:
/// - Requires PAUSER_ROLE for execution
/// - Should be executed through multi-sig in production
/// - Logs all control operations
///
/// Usage:
/// 1. Local Testing:
///    forge script script/EmergencyControls.s.sol \
///      --rpc-url localhost:8545 \
///      -vvvv \
///      --broadcast \
///      --sig "run()" \
///      --env-file .env.local
///
/// 2. Production:
///    # First dry-run to verify:
///    forge script script/EmergencyControls.s.sol \
///      --rpc-url $RPC_URL \
///      -vvvv \
///      --sig "run()"
///
///    # Then execute through multi-sig:
///    forge script script/EmergencyControls.s.sol \
///      --rpc-url $RPC_URL \
///      --broadcast \
///      --sig "run()" \
///      --verify
///
/// Required Environment Variables:
/// - PRIVATE_KEY: Executor's private key
/// - CONTRACT_ADDRESS: Deployed SecretStore address
/// - OPERATION: Either "pause" or "unpause"
contract EmergencyControls is Script {
    /// @notice Emergency pause function
    /// @dev Security critical operation that:
    /// 1. Halts all non-admin contract operations
    /// 2. Prevents new secret registrations
    /// 3. Prevents secret revelations
    /// 4. Maintains existing storage state
    ///
    /// Access Control:
    /// - Requires PAUSER_ROLE
    /// - Should be executed via multi-sig
    /// - Fails if already paused
    /// @param contractAddress The SecretStore proxy address
    function pause(address contractAddress) public {
        require(contractAddress != address(0), "Invalid contract address");
        
        // Get the private key from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        SecretStore store = SecretStore(contractAddress);
        
        vm.startBroadcast(deployerPrivateKey);
        store.pause();
        vm.stopBroadcast();
    }
    
    /// @notice Controlled unpause function
    /// @dev Resumes normal contract operation:
    /// 1. Re-enables secret registration
    /// 2. Re-enables secret revelation
    /// 3. Maintains all stored agreements
    ///
    /// Access Control:
    /// - Requires PAUSER_ROLE
    /// - Should be executed via multi-sig
    /// - Fails if not paused
    /// @param contractAddress The SecretStore proxy address
    function unpause(address contractAddress) public {
        require(contractAddress != address(0), "Invalid contract address");
        
        // Get the private key from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        SecretStore store = SecretStore(contractAddress);
        
        vm.startBroadcast(deployerPrivateKey);
        store.unpause();
        vm.stopBroadcast();
    }

    /// @notice Script entry point
    /// @dev Execution flow:
    /// 1. Loads configuration from environment
    /// 2. Validates operation type
    /// 3. Executes requested operation
    /// 4. Logs results
    ///
    /// Error handling:
    /// - Validates contract address
    /// - Validates operation type
    /// - Proper revert messages
    function run() external {
        // Get contract address from environment
        address contractAddress = vm.envAddress("CONTRACT_ADDRESS");
        
        // Get operation type from environment (pause/unpause)
        string memory operation = vm.envString("OPERATION");
        
        if (keccak256(bytes(operation)) == keccak256(bytes("pause"))) {
            pause(contractAddress);
        } else if (keccak256(bytes(operation)) == keccak256(bytes("unpause"))) {
            unpause(contractAddress);
        } else {
            revert("Invalid operation. Use 'pause' or 'unpause'");
        }
    }
}
