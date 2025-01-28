// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

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
    bytes32 secretHash;

    // Events
    event SecretRegistered(
        address indexed partyA,
        address indexed partyB,
        bytes32 indexed secretHash,
        uint256 blockNumber
    );

    event SecretRevealed(
        bytes32 indexed secretHash,
        address indexed revealer,
        string secret,
        uint256 registeredBlockNumber,
        uint256 revealedBlockNumber
    );

    function setUp() public {
        // Deploy implementation
        implementation = new SecretStore();
        
        // Deploy proxy and initialize
        store = SecretStore(payable(address(new ERC1967Proxy(
            address(implementation),
            abi.encodeWithSelector(SecretStore.initialize.selector, owner)
        ))));

        // Calculate secret hash (this would normally be done off-chain)
        secretHash = keccak256(abi.encodePacked(TEST_SECRET));
    }

    function testInitialization() public {
        assertTrue(store.hasRole(store.DEFAULT_ADMIN_ROLE(), owner));
        assertTrue(store.hasRole(store.PAUSER_ROLE(), owner));
        assertTrue(store.hasRole(store.UPGRADER_ROLE(), owner));
    }

    function testRegisterSecret() public {
        // Sign the secret hash (this would normally be done off-chain)
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(secretHash);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(partyAKey, ethSignedHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(partyBKey, ethSignedHash);
        bytes memory signatureA = abi.encodePacked(r1, s1, v1);
        bytes memory signatureB = abi.encodePacked(r2, s2, v2);

        vm.expectEmit(true, true, true, true);
        emit SecretRegistered(partyA, partyB, secretHash, block.number);

        store.registerSecret(
            secretHash,
            partyA,
            partyB,
            signatureA,
            signatureB
        );

        // Verify agreement storage
        (
            address storedPartyA,
            address storedPartyB,
            uint256 timestamp,
            uint256 blockNumber
        ) = store.agreements(secretHash);
        assertEq(storedPartyA, partyA);
        assertEq(storedPartyB, partyB);
        assertEq(timestamp, block.timestamp);
        assertEq(blockNumber, block.number);
    }

    function testRevealSecret() public {
        // First register a secret
        testRegisterSecret();

        uint256 registeredBlock = block.number;
        vm.roll(block.number + 1); // Move to next block for revelation

        vm.expectEmit(true, true, true, true);
        emit SecretRevealed(
            secretHash,
            partyA,
            TEST_SECRET,
            registeredBlock,
            block.number
        );

        // Reveal from partyA
        vm.prank(partyA);
        store.revealSecret(TEST_SECRET, secretHash);

        // Verify agreement is deleted
        (address storedPartyA, address storedPartyB,,) = store.agreements(secretHash);
        assertEq(storedPartyA, address(0));
        assertEq(storedPartyB, address(0));
    }

    function testRevealSecretByPartyB() public {
        // First register a secret
        testRegisterSecret();

        uint256 registeredBlock = block.number;
        vm.roll(block.number + 1); // Move to next block for revelation

        vm.expectEmit(true, true, true, true);
        emit SecretRevealed(
            secretHash,
            partyB,
            TEST_SECRET,
            registeredBlock,
            block.number
        );

        // Reveal from partyB
        vm.prank(partyB);
        store.revealSecret(TEST_SECRET, secretHash);
    }

    function testCannotRevealWithWrongSecret() public {
        // First register a secret
        testRegisterSecret();

        vm.prank(partyA);
        vm.expectRevert("Invalid secret");
        store.revealSecret("wrong secret", secretHash);
    }

    function testCannotRevealByNonParticipant() public {
        // First register a secret
        testRegisterSecret();

        address nonParticipant = makeAddr("nonParticipant");
        vm.prank(nonParticipant);
        vm.expectRevert("Only participants can reveal");
        store.revealSecret(TEST_SECRET, secretHash);
    }

    // Helper functions
    function _createSignatures(bytes32 messageHash) internal view returns (bytes memory, bytes memory) {
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        bytes memory signatureA = _sign(partyAKey, ethSignedMessageHash);
        bytes memory signatureB = _sign(partyBKey, ethSignedMessageHash);
        return (signatureA, signatureB);
    }

    function _sign(uint256 privateKey, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }
}
