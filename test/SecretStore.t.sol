// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "../src/SecretStore.sol";

contract SecretStoreTest is Test {
    using MessageHashUtils for bytes32;

    SecretStore store;
    SecretStore implementation;

    // Test accounts
    address owner = makeAddr("owner");
    address partyA = makeAddr("partyA");
    address partyB = makeAddr("partyB");
    uint256 partyAKey = uint256(keccak256(bytes("partyA")));
    uint256 partyBKey = uint256(keccak256(bytes("partyB")));

    // Test data
    string constant TEST_SECRET = "my secret message";
    bytes constant TEST_SALT = "random salt";
    bytes32 secretHash;

    // Events
    event SecretRegistered(
        address indexed partyA,
        address indexed partyB,
        bytes32 secretHash
    );

    event SecretRevealed(
        bytes32 indexed agreementId,
        address indexed revealer,
        string secret,
        bytes salt
    );

    function setUp() public {
        // Deploy implementation
        implementation = new SecretStore();
        
        // Deploy proxy and initialize
        store = SecretStore(payable(address(new ERC1967Proxy(
            address(implementation),
            abi.encodeWithSelector(SecretStore.initialize.selector, owner)
        ))));

        // Pre-calculate secret hash
        secretHash = keccak256(abi.encodePacked(TEST_SECRET, TEST_SALT));
    }

    function testInitialization() public {
        assertTrue(store.hasRole(store.DEFAULT_ADMIN_ROLE(), owner));
        assertTrue(store.hasRole(store.PAUSER_ROLE(), owner));
        assertTrue(store.hasRole(store.UPGRADER_ROLE(), owner));
    }

    function testRegisterSecret() public {
        // Create signatures
        bytes32 messageHash = store.getMessageHash(secretHash, partyA, partyB);
        (bytes memory signatureA, bytes memory signatureB) = _createSignatures(messageHash);

        vm.expectEmit(true, true, true, true);
        emit SecretRegistered(partyA, partyB, secretHash);

        store.registerSecret(
            secretHash,
            partyA,
            partyB,
            signatureA,
            signatureB
        );
    }

    function testRevealSecret() public {
        // First register a secret
        bytes32 messageHash = store.getMessageHash(secretHash, partyA, partyB);
        (bytes memory signatureA, bytes memory signatureB) = _createSignatures(messageHash);

        store.registerSecret(
            secretHash,
            partyA,
            partyB,
            signatureA,
            signatureB
        );

        // Get the agreementId
        bytes32 agreementId = keccak256(abi.encodePacked(secretHash, partyA, partyB, block.timestamp));

        // Try to reveal as partyA
        vm.prank(partyA);
        vm.expectEmit(true, true, true, true);
        emit SecretRevealed(agreementId, partyA, TEST_SECRET, TEST_SALT);

        store.revealSecret(TEST_SECRET, TEST_SALT, agreementId);
    }

    function testFailRevealWrongSecret() public {
        // First register a secret
        bytes32 messageHash = store.getMessageHash(secretHash, partyA, partyB);
        (bytes memory signatureA, bytes memory signatureB) = _createSignatures(messageHash);

        store.registerSecret(
            secretHash,
            partyA,
            partyB,
            signatureA,
            signatureB
        );

        bytes32 agreementId = keccak256(abi.encodePacked(secretHash, partyA, partyB, block.timestamp));

        // Try to reveal with wrong secret
        vm.prank(partyA);
        store.revealSecret("wrong secret", TEST_SALT, agreementId);
    }

    function testFailRevealWrongParty() public {
        // First register a secret
        bytes32 messageHash = store.getMessageHash(secretHash, partyA, partyB);
        (bytes memory signatureA, bytes memory signatureB) = _createSignatures(messageHash);

        store.registerSecret(
            secretHash,
            partyA,
            partyB,
            signatureA,
            signatureB
        );

        bytes32 agreementId = keccak256(abi.encodePacked(secretHash, partyA, partyB, block.timestamp));

        // Try to reveal as non-participant
        address nonParticipant = address(4);
        vm.prank(nonParticipant);
        store.revealSecret(TEST_SECRET, TEST_SALT, agreementId);
    }

    // Helper functions
    function _createSignatures(bytes32 messageHash) internal returns (bytes memory, bytes memory) {
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        bytes memory signatureA = _sign(partyAKey, ethSignedMessageHash);
        bytes memory signatureB = _sign(partyBKey, ethSignedMessageHash);
        return (signatureA, signatureB);
    }

    function _sign(uint256 privateKey, bytes32 hash) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }
}
