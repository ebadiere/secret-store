// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {Test, console2} from "forge-std/Test.sol";
import {SecretStore} from "../src/SecretStore.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SecretStore Invariant Tests
/// @notice Tests that verify core invariants of the SecretStore contract
/// @dev Uses Foundry's invariant testing to ensure properties hold under all conditions
/// @custom:security Tests verify:
///  1. Agreement state consistency
///  2. Access control invariants
///  3. Deletion guarantees
contract SecretStoreInvariantTest is Test {
    SecretStore public secretStore;
    address public partyA;
    address public partyB;
    uint256 constant PARTY_A_PRIVATE_KEY = 0xA11CE;
    uint256 constant PARTY_B_PRIVATE_KEY = 0xB0B;

    function setUp() public {
        // Deploy implementation and proxy
        SecretStore implementation = new SecretStore();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeWithSelector(SecretStore.initialize.selector)
        );
        secretStore = SecretStore(address(proxy));

        partyA = vm.addr(PARTY_A_PRIVATE_KEY);
        partyB = vm.addr(PARTY_B_PRIVATE_KEY);
    }

    /// @notice Verify that a revealed secret is always deleted
    /// @dev After any successful reveal, the agreement should be deleted
    function invariant_revealedSecretsAreDeleted() public {
        // Create and register a secret
        string memory secret = "test secret";
        bytes32 salt = bytes32(uint256(123));
        bytes32 secretHash = keccak256(abi.encodePacked(secret, salt));
        
        (bytes memory signatureA, bytes memory signatureB) = _createSignatures(secretHash);
        secretStore.registerSecret(secretHash, partyA, partyB, signatureA, signatureB);
        
        // Reveal the secret
        vm.prank(partyA);
        secretStore.revealSecret(secret, salt, secretHash);
        
        // Verify the agreement is deleted
        (bool exists, address storedPartyA,) = secretStore.agreementExists(secretHash);
        assertFalse(exists, "Agreement should be deleted after reveal");
        assertEq(storedPartyA, address(0), "PartyA should be zero after deletion");
    }

    /// @notice Verify that non-existent secrets cannot be revealed
    /// @dev Ensures that only registered secrets can be revealed
    function invariant_onlyRegisteredSecretsCanBeRevealed() public {
        string memory secret = "unregistered secret";
        bytes32 salt = bytes32(uint256(456));
        bytes32 secretHash = keccak256(abi.encodePacked(secret, salt));
        
        vm.prank(partyA);
        vm.expectRevert("Agreement does not exist");
        secretStore.revealSecret(secret, salt, secretHash);
    }

    /// @notice Verify that only parties can reveal their secrets
    /// @dev Tests access control for secret revelation
    function invariant_onlyPartiesCanReveal() public {
        // Create and register a secret
        string memory secret = "test secret";
        bytes32 salt = bytes32(uint256(123));
        bytes32 secretHash = keccak256(abi.encodePacked(secret, salt));
        
        (bytes memory signatureA, bytes memory signatureB) = _createSignatures(secretHash);
        secretStore.registerSecret(secretHash, partyA, partyB, signatureA, signatureB);
        
        // Try to reveal as non-party
        address nonParty = address(0x123);
        vm.prank(nonParty);
        vm.expectRevert("Not a party to agreement");
        secretStore.revealSecret(secret, salt, secretHash);
    }

    /// @notice Helper function to create test signatures
    function _createSignatures(bytes32 hash) internal view returns (bytes memory signatureA, bytes memory signatureB) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Agreement(bytes32 secretHash,address partyA,address partyB)"),
                hash,
                partyA,
                partyB
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                secretStore.DOMAIN_SEPARATOR(),
                structHash
            )
        );

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(PARTY_A_PRIVATE_KEY, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(PARTY_B_PRIVATE_KEY, digest);
        
        signatureA = abi.encodePacked(r1, s1, v1);
        signatureB = abi.encodePacked(r2, s2, v2);
    }
}
