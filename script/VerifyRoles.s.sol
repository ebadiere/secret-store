// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "forge-std/Script.sol";
import "../src/SecretStore.sol";

/// @title SecretStore Role Verification Script
/// @notice Production-ready script to verify the role configuration of a deployed SecretStore contract
/// @dev This script verifies:
///      1. Multisig has all required roles (admin, upgrader, pauser)
///      2. Deployer has renounced all roles
///      3. Zero address has no roles
///
/// How to run:
/// ```bash
/// # Set environment variables
/// export PROXY_ADDRESS=<deployed-proxy-address>
/// export MULTISIG_ADDRESS=<multisig-wallet-address>
///
/// # Run verification
/// forge script script/VerifyRoles.s.sol --rpc-url <your-rpc-url>
/// ```
///
/// Expected role configuration:
/// - Multisig: Should have DEFAULT_ADMIN_ROLE, UPGRADER_ROLE, and PAUSER_ROLE
/// - Deployer: Should have no roles (all renounced)
/// - Zero Address: Should have no roles
contract VerifyRoles is Script {
    /// @notice Entry point for the verification script
    /// @dev Reads proxy address from environment and calls verify()
    function run() external {
        address proxyAddress = vm.envAddress("PROXY_ADDRESS");
        verify(proxyAddress);
    }

    /// @notice Main verification function that checks role configuration
    /// @param proxyAddress Address of the deployed SecretStore proxy contract
    /// @dev Performs comprehensive role verification:
    ///      1. Checks multisig has required roles
    ///      2. Verifies deployer has renounced roles
    ///      3. Ensures zero address has no roles
    ///      Reverts with descriptive message if any check fails
    function verify(address proxyAddress) public view {
        SecretStore store = SecretStore(proxyAddress);
        address multiSig = vm.envAddress("MULTISIG_ADDRESS");
        
        console.log("\nVerifying role configuration for proxy:", proxyAddress);
        console.log("Multisig address:", multiSig);
        console.log("------------------------");

        // Check multisig roles - these should all be true
        bool hasAdminRole = store.hasRole(store.DEFAULT_ADMIN_ROLE(), multiSig);
        bool hasUpgraderRole = store.hasRole(store.UPGRADER_ROLE(), multiSig);
        bool hasPauserRole = store.hasRole(store.PAUSER_ROLE(), multiSig);

        console.log("Multisig roles:");
        console.log("- DEFAULT_ADMIN_ROLE:", hasAdminRole ? "[YES]" : "[NO]");
        console.log("- UPGRADER_ROLE:", hasUpgraderRole ? "[YES]" : "[NO]");
        console.log("- PAUSER_ROLE:", hasPauserRole ? "[YES]" : "[NO]");

        // Check deployer roles - these should all be false (deployer should have no roles)
        address deployer = msg.sender;
        bool noDeployerAdmin = !store.hasRole(store.DEFAULT_ADMIN_ROLE(), deployer);
        bool noDeployerUpgrader = !store.hasRole(store.UPGRADER_ROLE(), deployer);
        bool noDeployerPauser = !store.hasRole(store.PAUSER_ROLE(), deployer);

        console.log("\nDeployer roles (should all be [YES] for none):");
        console.log("- No DEFAULT_ADMIN_ROLE:", noDeployerAdmin ? "[YES]" : "[NO]");
        console.log("- No UPGRADER_ROLE:", noDeployerUpgrader ? "[YES]" : "[NO]");
        console.log("- No PAUSER_ROLE:", noDeployerPauser ? "[YES]" : "[NO]");

        // Check zero address - should have no roles for security
        bool noZeroAdmin = !store.hasRole(store.DEFAULT_ADMIN_ROLE(), address(0));
        bool noZeroUpgrader = !store.hasRole(store.UPGRADER_ROLE(), address(0));
        bool noZeroPauser = !store.hasRole(store.PAUSER_ROLE(), address(0));

        console.log("\nZero address roles (should all be [YES] for none):");
        console.log("- No DEFAULT_ADMIN_ROLE:", noZeroAdmin ? "[YES]" : "[NO]");
        console.log("- No UPGRADER_ROLE:", noZeroUpgrader ? "[YES]" : "[NO]");
        console.log("- No PAUSER_ROLE:", noZeroPauser ? "[YES]" : "[NO]");

        // Verify all conditions are met
        require(
            hasAdminRole && hasUpgraderRole && hasPauserRole,
            "Multisig missing required roles"
        );
        require(
            noDeployerAdmin && noDeployerUpgrader && noDeployerPauser,
            "Deployer still has roles"
        );
        require(
            noZeroAdmin && noZeroUpgrader && noZeroPauser,
            "Zero address has roles"
        );

        console.log("\n[SUCCESS] All role checks passed successfully!");
    }
}
