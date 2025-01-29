// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "forge-std/Script.sol";
import "../src/SecretStore.sol";

contract VerifyRoles is Script {
    function verify(address proxyAddress) public view {
        SecretStore store = SecretStore(proxyAddress);
        address multiSig = vm.envAddress("MULTISIG_ADDRESS");
        
        console.log("\nVerifying role configuration for proxy:", proxyAddress);
        console.log("Multisig address:", multiSig);
        console.log("------------------------");

        // Check multisig roles
        bool hasAdminRole = store.hasRole(store.DEFAULT_ADMIN_ROLE(), multiSig);
        bool hasUpgraderRole = store.hasRole(store.UPGRADER_ROLE(), multiSig);
        bool hasPauserRole = store.hasRole(store.PAUSER_ROLE(), multiSig);

        console.log("Multisig roles:");
        console.log("- DEFAULT_ADMIN_ROLE:", hasAdminRole ? "✓" : "✗");
        console.log("- UPGRADER_ROLE:", hasUpgraderRole ? "✓" : "✗");
        console.log("- PAUSER_ROLE:", hasPauserRole ? "✓" : "✗");

        // Check deployer roles (should be none)
        address deployer = msg.sender;
        bool noDeployerAdmin = !store.hasRole(store.DEFAULT_ADMIN_ROLE(), deployer);
        bool noDeployerUpgrader = !store.hasRole(store.UPGRADER_ROLE(), deployer);
        bool noDeployerPauser = !store.hasRole(store.PAUSER_ROLE(), deployer);

        console.log("\nDeployer roles (should all be ✓ for none):");
        console.log("- No DEFAULT_ADMIN_ROLE:", noDeployerAdmin ? "✓" : "✗");
        console.log("- No UPGRADER_ROLE:", noDeployerUpgrader ? "✓" : "✗");
        console.log("- No PAUSER_ROLE:", noDeployerPauser ? "✓" : "✗");

        // Check zero address
        bool noZeroAdmin = !store.hasRole(store.DEFAULT_ADMIN_ROLE(), address(0));
        bool noZeroUpgrader = !store.hasRole(store.UPGRADER_ROLE(), address(0));
        bool noZeroPauser = !store.hasRole(store.PAUSER_ROLE(), address(0));

        console.log("\nZero address roles (should all be ✓ for none):");
        console.log("- No DEFAULT_ADMIN_ROLE:", noZeroAdmin ? "✓" : "✗");
        console.log("- No UPGRADER_ROLE:", noZeroUpgrader ? "✓" : "✗");
        console.log("- No PAUSER_ROLE:", noZeroPauser ? "✓" : "✗");

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

        console.log("\n✅ All role checks passed successfully!");
    }
}
