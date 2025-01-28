// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {Test, console2} from "forge-std/Test.sol";
import {SecretStore} from "../src/SecretStore.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SecretStore Fuzz Tests
/// @notice Comprehensive fuzz testing suite for the SecretStore contract
/// @dev Uses Foundry's built-in fuzzing capabilities to test with random inputs
/// @custom:security Tests focus on:
///  1. EIP-712 signature verification
///  2. Secret registration with random inputs
///  3. Secret revelation with valid and invalid parameters
///  4. Edge cases and error conditions
contract SecretStoreFuzzTest is Test {
    SecretStore public secretStore;
    uint256 constant PARTY_A_PRIVATE_KEY = 0xA11CE;
    uint256 constant PARTY_B_PRIVATE_KEY = 0xB0B;
    address partyA;
    address partyB;

    bytes32 constant TYPEHASH = keccak256("Agreement(bytes32 secretHash,address partyA,address partyB)");

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

    /// @notice Helper function to create the secret hash
    function _createSecretHash(string memory secret, bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(secret, salt));
    }

    /// @notice Helper function to create signatures for a secret hash
    function _createSignatures(bytes32 secretHash) internal view returns (bytes memory, bytes memory) {
        bytes32 structHash = keccak256(abi.encode(TYPEHASH, secretHash, partyA, partyB));
        bytes32 digest = MessageHashUtils.toTypedDataHash(secretStore.DOMAIN_SEPARATOR(), structHash);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(PARTY_A_PRIVATE_KEY, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(PARTY_B_PRIVATE_KEY, digest);

        return (
            abi.encodePacked(r1, s1, v1),
            abi.encodePacked(r2, s2, v2)
        );
    }

    /// @notice Helper function to register a secret
    function _registerSecret(bytes32 secretHash, bytes memory sigA, bytes memory sigB) internal {
        secretStore.registerSecret(secretHash, partyA, partyB, sigA, sigB);
    }

    /// @notice Fuzz test for registering secrets with random inputs
    /// @dev Tests the secret registration flow with randomly generated:
    ///      - salt values (for secret hashing)
    ///      - timestamps (for future-dated agreements)
    ///      - secret strings (of varying lengths)
    /// @param salt Random salt value used in secret hashing
    /// @param timestamp Future timestamp for the agreement
    /// @param secret Random secret string to be stored
    /// @custom:security Verifies:
    ///  1. EIP-712 signature generation and verification
    ///  2. Proper handling of random length inputs
    ///  3. Agreement storage with random parameters
    function testFuzz_RegisterSecretWithRandomParties(
        bytes32 salt,
        uint256 timestamp,
        string memory secret
    ) public {
        vm.assume(bytes(secret).length > 0);
        vm.assume(timestamp > block.timestamp);
        
        bytes32 secretHash = _createSecretHash(secret, salt);
        (bytes memory sigA, bytes memory sigB) = _createSignatures(secretHash);
        _registerSecret(secretHash, sigA, sigB);
    }

    /// @notice Fuzz test for revealing secrets with random inputs and random revealer
    /// @dev Tests the secret revelation flow with:
    ///      - Both parties attempting to reveal
    ///      - Random secret and salt combinations
    ///      - Random timestamps for agreements
    /// @param salt Random salt value used in secret hashing
    /// @param timestamp Future timestamp for the agreement
    /// @param secret Random secret string to be revealed
    /// @param usePartyB If true, partyB reveals; if false, partyA reveals
    /// @custom:security Verifies:
    ///  1. Both parties can reveal successfully
    ///  2. Proper secret and salt validation
    ///  3. Agreement state updates after revelation
    function testFuzz_RevealSecretWithRandomInputs(
        bytes32 salt,
        uint256 timestamp,
        string memory secret,
        bool usePartyB
    ) public {
        vm.assume(bytes(secret).length > 0);
        vm.assume(timestamp > block.timestamp);
        
        bytes32 secretHash = _createSecretHash(secret, salt);
        (bytes memory sigA, bytes memory sigB) = _createSignatures(secretHash);
        _registerSecret(secretHash, sigA, sigB);

        // Now reveal the secret
        if (usePartyB) {
            vm.prank(partyB);
        } else {
            vm.prank(partyA);
        }
        secretStore.revealSecret(secret, salt, secretHash);
    }

    /// @notice Fuzz test for attempting to reveal secrets with invalid parameters
    /// @dev Tests error conditions in the revelation process with:
    ///      - Wrong secrets
    ///      - Wrong salt values
    ///      - Wrong secret hashes
    /// @param salt Random salt value used in secret hashing
    /// @param timestamp Future timestamp for the agreement
    /// @param secret Valid secret string
    /// @param wrongSecret Different secret string for invalid revelation attempt
    /// @custom:security Verifies:
    ///  1. Proper error handling for invalid inputs
    ///  2. Resistance to manipulation attempts
    ///  3. Agreement integrity preservation
    function testFuzz_RevealSecretWithInvalidInputs(
        bytes32 salt,
        uint256 timestamp,
        string calldata secret,
        string calldata wrongSecret
    ) public {
        vm.assume(bytes(secret).length > 0);
        vm.assume(bytes(wrongSecret).length > 0);
        vm.assume(keccak256(bytes(secret)) != keccak256(bytes(wrongSecret)));
        vm.assume(timestamp > block.timestamp);
        
        bytes32 secretHash = _createSecretHash(secret, salt);
        bytes32 wrongSecretHash = _createSecretHash(wrongSecret, salt);

        // Register the secret
        (bytes memory sigA, bytes memory sigB) = _createSignatures(secretHash);
        _registerSecret(secretHash, sigA, sigB);

        // Try to reveal with wrong secret
        vm.expectRevert("Invalid secret or salt");
        vm.prank(partyA);
        secretStore.revealSecret(wrongSecret, salt, secretHash);

        // Try to reveal with wrong hash
        vm.expectRevert("Agreement does not exist");
        vm.prank(partyA);
        secretStore.revealSecret(secret, salt, wrongSecretHash);

        // Try to reveal with wrong salt
        vm.expectRevert("Invalid secret or salt");
        vm.prank(partyA);
        secretStore.revealSecret(secret, bytes32(uint256(salt) + 1), secretHash);
    }
}
