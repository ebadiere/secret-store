// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Script} from "forge-std/Script.sol";
import {SecretStore} from "../src/SecretStore.sol";

/// @title EmergencyControls
/// @notice Foundry script for emergency control operations (pause/unpause) of the SecretStore contract
/// @dev Requires PAUSER_ROLE to execute these functions
contract EmergencyControls is Script {
    /// @notice Pauses all operations on the SecretStore contract
    /// @param contractAddress The address of the deployed SecretStore contract
    function pause(address contractAddress) public {
        require(contractAddress != address(0), "Invalid contract address");
        
        // Get the private key from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        SecretStore store = SecretStore(contractAddress);
        
        vm.startBroadcast(deployerPrivateKey);
        store.pause();
        vm.stopBroadcast();
    }
    
    /// @notice Unpauses all operations on the SecretStore contract
    /// @param contractAddress The address of the deployed SecretStore contract
    function unpause(address contractAddress) public {
        require(contractAddress != address(0), "Invalid contract address");
        
        // Get the private key from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        SecretStore store = SecretStore(contractAddress);
        
        vm.startBroadcast(deployerPrivateKey);
        store.unpause();
        vm.stopBroadcast();
    }

    /// @notice Main function to run the script with command line arguments
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
