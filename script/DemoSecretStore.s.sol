// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {SecretStore} from "../src/SecretStore.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract DemoSecretStore is Script {
    using MessageHashUtils for bytes32;

    // Test private keys (don't use these in production!)
    uint256 constant PARTY_A_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant PARTY_B_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    address partyA;
    address partyB;
    SecretStore store;

    function setUp() public {
        // Get addresses first since they don't need broadcasting
        partyA = vm.addr(PARTY_A_KEY);
        partyB = vm.addr(PARTY_B_KEY);

        vm.startBroadcast(PARTY_A_KEY);
        // Deploy implementation
        SecretStore implementation = new SecretStore();
        
        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            implementation.initialize.selector,
            partyA  // Use partyA as admin
        );
        store = SecretStore(
            address(new ERC1967Proxy(address(implementation), initData))
        );
        vm.stopBroadcast();

        // Log deployment info
        console2.log("\n=== Deployment Info ===");
        console2.log("Implementation address:", address(implementation));
        console2.log("Proxy address:", address(store));
        console2.log("Party A address:", partyA);
        console2.log("Party B address:", partyB);
    }

    function run() public {
        // Get inputs with better error handling
        (string memory secret, string memory revealParty) = getInputs();

        bytes32 salt = bytes32(uint256(123)); // Fixed salt for demo
        bytes32 secretHash = keccak256(abi.encodePacked(secret, salt));

        console2.log("\n=== Secret Details ===");
        console2.log("Clear text secret:", secret);
        console2.log("Salt (hex):", vm.toString(salt));
        console2.log("Secret hash:", vm.toString(secretHash));

        // Create signatures from both parties
        bytes32 structHash = keccak256(
            abi.encode(
                store.TYPEHASH(),
                secretHash,
                partyA,
                partyB
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        
        // Sign with Party A's key
        vm.startBroadcast(PARTY_A_KEY);
        bytes memory signatureA = _sign(PARTY_A_KEY, hash);
        vm.stopBroadcast();

        console2.log("\n=== Party A Signature ===");
        console2.log("Message hash:", vm.toString(hash));
        console2.log("Signature:", vm.toString(signatureA));

        // Sign with Party B's key
        vm.startBroadcast(PARTY_B_KEY);
        bytes memory signatureB = _sign(PARTY_B_KEY, hash);
        vm.stopBroadcast();

        console2.log("\n=== Party B Signature ===");
        console2.log("Signature:", vm.toString(signatureB));

        vm.startBroadcast(PARTY_A_KEY);
        store.registerSecret(
            secretHash,
            partyA,
            partyB,
            signatureA,
            signatureB
        );
        vm.stopBroadcast();

        // Reveal the secret if requested
        if (bytes(revealParty).length > 0) {
            // Wait for a block to ensure registration is mined
            vm.roll(block.number + 1);
            
            uint256 privateKey = keccak256(bytes(revealParty)) == keccak256(bytes("A")) ? PARTY_A_KEY : PARTY_B_KEY;
            
            vm.startBroadcast(privateKey);
            store.revealSecret(secret, bytes32(uint256(123)), secretHash);
            vm.stopBroadcast();

            console2.log("\n=== Revealed Secret ===");
            console2.log("Clear text secret:", secret);
            console2.log("Revealed by:", keccak256(bytes(revealParty)) == keccak256(bytes("A")) ? "Party A" : "Party B");
            console2.log("Revealer address:", vm.addr(privateKey));
        }
    }

    function getInputs() internal view returns (string memory secret, string memory revealParty) {
        secret = vm.envString("SECRET");
        revealParty = vm.envString("REVEAL_PARTY");
        require(bytes(secret).length > 0, "SECRET environment variable not set");
        require(
            keccak256(bytes(revealParty)) == keccak256(bytes("A")) ||
            keccak256(bytes(revealParty)) == keccak256(bytes("B")),
            "REVEAL_PARTY must be 'A' or 'B'"
        );
    }

    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), structHash);
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("SecretStore")),
                keccak256(bytes("1")),
                block.chainid,
                address(store)
            )
        );
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
