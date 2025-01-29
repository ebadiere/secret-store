// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "forge-std/Script.sol";
import "../src/SecretStore.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title DeployScript
 * @notice Deployment script for SecretStore contract with production-grade security practices
 * 
 * @dev This script supports three deployment scenarios:
 * 1. Local (Anvil) - Uses Anvil's deterministic accounts for easy testing
 * 2. Testnet/Mainnet with Hardware Wallet - Recommended for production deployments
 * 3. Testnet/Mainnet with Encrypted Keystore - Alternative when hardware wallet isn't available
 *
 * Security best practices implemented:
 * - Hardware wallet support (Ledger) for secure transaction signing
 * - Encrypted keystore support instead of raw private keys
 * - Multi-sig transfer after deployment
 * - Clear separation between test and production configurations
 * 
 * Usage:
 * 1. Local deployment:
 *    forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast
 * 
 * 2. Testnet/Mainnet with Hardware Wallet (recommended):
 *    forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast --ledger --sender $SENDER_ADDRESS
 * 
 * 3. Testnet/Mainnet with Encrypted Keystore:
 *    # First time: Create encrypted keystore
 *    cast wallet import deployer --interactive
 *    # Deploy using keystore
 *    forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast --account deployer
 *
 * Environment Variables:
 * - LEDGER=true                  # Enable hardware wallet signing
 * - SENDER_ADDRESS=0x...         # Your ledger account address
 * - MULTISIG_ADDRESS=0x...       # Gnosis Safe or other multi-sig address
 */
contract DeployScript is Script {
    // Configuration struct to hold deployment parameters
    struct DeployConfig {
        address deployer;
        address multiSig;
        uint256 chainId;
    }

    function _getConfig() internal returns (DeployConfig memory config) {
        config.chainId = block.chainid;
        
        if (config.chainId == 31337) {
            // ====== Local Testing Configuration ======
            // Using Anvil's deterministic accounts:
            // Account #0 (0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266) - Deployer
            // - Private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
            // Account #1 (0x70997970C51812dc3A010C7d01b50e0d17dc79C8) - Mock multi-sig
            uint256 privKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
            config.deployer = vm.addr(privKey);
            config.multiSig = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
            vm.startBroadcast(privKey);
        } else {
            // ====== Production Configuration ======
            // Multi-sig should be a Gnosis Safe or similar
            config.multiSig = vm.envAddress("MULTISIG_ADDRESS");
            
            // Production deployments should use either:
            // 1. Hardware wallet (preferred)
            // 2. Encrypted keystore (alternative)
            // Never use raw private keys in production!
            if (vm.envOr("LEDGER", false)) {
                // Hardware wallet configuration
                config.deployer = vm.envAddress("SENDER_ADDRESS");
                // Note: No need for vm.startBroadcast() with --ledger flag
            } else {
                // Using encrypted keystore (deployment command must include --account deployer)
                config.deployer = msg.sender;
                // Broadcasting will be handled by the --account flag
            }
        }

        require(config.multiSig != address(0), "Multi-sig address not configured");
        require(config.deployer != address(0), "Deployer address not configured");
        
        console.log("\nDeployment Configuration:");
        console.log("------------------------");
        console.log("Network:", _getNetworkName(config.chainId));
        console.log("Deployer:", config.deployer);
        console.log("Multi-sig:", config.multiSig);
        console.log("------------------------\n");
    }

    function _getNetworkName(uint256 chainId) internal pure returns (string memory) {
        if (chainId == 1) return "Mainnet";
        if (chainId == 5) return "Goerli";
        if (chainId == 11155111) return "Sepolia";
        if (chainId == 31337) return "Anvil";
        return string(abi.encodePacked("Chain ID: ", vm.toString(chainId)));
    }

    function run() external {
        DeployConfig memory config = _getConfig();

        // Step 1: Deploy implementation contract
        SecretStore implementation = new SecretStore();
        console.log("Implementation deployed to:", address(implementation));

        // Step 2: Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            SecretStore.initialize.selector,
            config.deployer  // Set deployer as initial admin
        );

        // Step 3: Deploy proxy
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );
        console.log("Proxy deployed to:", address(proxy));

        // Step 4: Transfer admin roles to multi-sig
        SecretStore secretStore = SecretStore(address(proxy));
        bytes32 defaultAdminRole = 0x00;
        bytes32 upgraderRole = secretStore.UPGRADER_ROLE();
        bytes32 pauserRole = secretStore.PAUSER_ROLE();

        // Grant roles to multi-sig first (defense in depth)
        secretStore.grantRole(defaultAdminRole, config.multiSig);
        secretStore.grantRole(upgraderRole, config.multiSig);
        secretStore.grantRole(pauserRole, config.multiSig);

        // Then renounce deployer roles
        secretStore.renounceRole(defaultAdminRole, config.deployer);
        secretStore.renounceRole(upgraderRole, config.deployer);
        secretStore.renounceRole(pauserRole, config.deployer);

        console.log("Admin roles transferred to multi-sig");

        vm.stopBroadcast();

        // Step 5: Output next steps
        if (config.chainId != 31337) {
            console.log("\nIMPORTANT: Next steps");
            console.log("------------------------");
            console.log("1. Verify implementation contract:");
            console.log("   forge verify-contract", address(implementation), "SecretStore --watch");
            console.log("2. Verify proxy contract:");
            console.log("   forge verify-contract", address(proxy), "ERC1967Proxy --watch");
            console.log("3. Confirm on multi-sig that all roles were transferred correctly");
            console.log("4. Document deployed addresses in your project repository");
        } else {
            console.log("\nLocal deployment complete!");
            console.log("------------------------");
            console.log("To test admin functions:");
            console.log("1. Impersonate multi-sig account:");
            console.log("   cast rpc anvil_impersonateAccount", config.multiSig);
            console.log("2. Use the multi-sig address in your transactions");
        }
    }
}
