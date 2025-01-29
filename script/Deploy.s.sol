// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "forge-std/Script.sol";
import "../src/SecretStore.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Deploy is Script {
    struct DeployConfig {
        address deployer;
        uint256 deployerKey;
        address multiSig;
    }

    function run() external {
        // Get deployment configuration
        DeployConfig memory config = _getConfig();

        console.log("\nDeployment Configuration:");
        console.log("------------------------");
        console.log("Network:", block.chainid == 31337 ? "Anvil" : "Production");
        console.log("Deployer:", config.deployer);
        console.log("Multi-sig:", config.multiSig);
        console.log("------------------------\n");

        vm.startBroadcast(config.deployerKey);

        // Deploy implementation
        SecretStore implementation = new SecretStore();
        console.log("Implementation deployed at:", address(implementation));

        // Encode initialization call
        bytes memory initData = abi.encodeWithSelector(
            SecretStore.initialize.selector,
            config.deployer  // Set deployer as initial admin
        );

        // Deploy proxy
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );
        console.log("Proxy deployed at:", address(proxy));

        // Get SecretStore interface for proxy
        SecretStore secretStore = SecretStore(address(proxy));

        // Set up roles
        _setupRoles(secretStore, config);

        // Verify role setup
        _verifyRoles(secretStore, config);

        vm.stopBroadcast();

        console.log("\nDeployment complete!");
        console.log("------------------------");
        console.log("Implementation:", address(implementation));
        console.log("Proxy:", address(proxy));
        console.log("------------------------");
    }

    function _setupRoles(SecretStore secretStore, DeployConfig memory config) internal {
        // Grant roles to multi-sig first (defense in depth)
        console.log("\nGranting roles to multi-sig:", config.multiSig);
        secretStore.grantRole(secretStore.DEFAULT_ADMIN_ROLE(), config.multiSig);
        secretStore.grantRole(secretStore.UPGRADER_ROLE(), config.multiSig);
        secretStore.grantRole(secretStore.PAUSER_ROLE(), config.multiSig);

        // Then renounce deployer roles
        console.log("Revoking roles from deployer");
        secretStore.renounceRole(secretStore.DEFAULT_ADMIN_ROLE(), config.deployer);
        secretStore.renounceRole(secretStore.UPGRADER_ROLE(), config.deployer);
        secretStore.renounceRole(secretStore.PAUSER_ROLE(), config.deployer);
    }

    function _verifyRoles(SecretStore secretStore, DeployConfig memory config) internal view {
        console.log("\nVerifying role configuration:");
        console.log("------------------------");
        
        // Check multisig has all required roles
        bool hasAllRoles = secretStore.hasRole(secretStore.DEFAULT_ADMIN_ROLE(), config.multiSig) &&
                          secretStore.hasRole(secretStore.UPGRADER_ROLE(), config.multiSig) &&
                          secretStore.hasRole(secretStore.PAUSER_ROLE(), config.multiSig);
        
        require(hasAllRoles, "Multisig missing required roles");
        console.log(" Multisig has all required roles");

        // Verify deployer has no roles
        bool noDeployerRoles = !secretStore.hasRole(secretStore.DEFAULT_ADMIN_ROLE(), config.deployer) &&
                              !secretStore.hasRole(secretStore.UPGRADER_ROLE(), config.deployer) &&
                              !secretStore.hasRole(secretStore.PAUSER_ROLE(), config.deployer);
        
        require(noDeployerRoles, "Deployer still has roles");
        console.log(" Deployer has no roles");

        // Additional safety check: verify no roles granted to zero address
        bool noZeroAddressRoles = !secretStore.hasRole(secretStore.DEFAULT_ADMIN_ROLE(), address(0)) &&
                                 !secretStore.hasRole(secretStore.UPGRADER_ROLE(), address(0)) &&
                                 !secretStore.hasRole(secretStore.PAUSER_ROLE(), address(0));
        
        require(noZeroAddressRoles, "Zero address has roles");
        console.log(" No roles assigned to zero address");
        
        console.log("------------------------");
        console.log("Role verification successful!");
    }

    function _getConfig() internal view returns (DeployConfig memory config) {
        if (block.chainid == 31337) {
            // Local testing with Anvil
            // Using default accounts:
            // Account #0 (0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266) - Deployer
            // Account #1 (0x70997970C51812dc3A010C7d01b50e0d17dc79C8) - Multi-sig
            config.deployerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
            config.deployer = vm.addr(config.deployerKey);
            config.multiSig = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
        } else {
            // Production deployment
            config.deployerKey = vm.envUint("PRIVATE_KEY");
            config.deployer = vm.addr(config.deployerKey);
            config.multiSig = vm.envAddress("MULTISIG_ADDRESS");
            require(config.multiSig != address(0), "Multi-sig address not configured");
        }
    }
}
