// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {SecretStore} from "../src/SecretStore.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

interface IUpgradeableProxy {
    function upgradeTo(address newImplementation) external;
}

/// @title SecretStore Test Suite
/// @notice Comprehensive test suite for the SecretStore contract
/// @dev Tests cover core functionality, security measures, and edge cases
/// @custom:security Tests specifically verify:
///  1. Access control for registration and revelation
///  2. Signature verification and replay protection
///  3. State management and existence checks
///  4. Salt handling and secret hashing
contract SecretStoreTest is Test {
    using MessageHashUtils for bytes32;

    /// @notice Test constants for consistent secret and signature testing
    string constant TEST_SECRET = "my secret message";
    bytes32 constant TEST_SALT = bytes32(uint256(123)); // Random salt for testing
    bytes32 constant TEST_SECRET_HASH = keccak256(abi.encodePacked(TEST_SECRET, TEST_SALT));
    
    /// @notice Contract instance and test addresses
    SecretStore public store;
    address public partyA;
    address public partyB;
    uint256 public PARTY_A_PRIVATE_KEY = 0x1234;
    uint256 public PARTY_B_PRIVATE_KEY = 0x5678;

    /// @notice Setup function run before each test
    /// @dev Creates a fresh contract instance and sets up test accounts
    function setUp() public {
        // Deploy implementation and proxy
        SecretStore implementation = new SecretStore();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(SecretStore.initialize, ())
        );
        store = SecretStore(address(proxy));

        // Set up test addresses
        partyA = vm.addr(PARTY_A_PRIVATE_KEY);
        partyB = vm.addr(PARTY_B_PRIVATE_KEY);
    }

    /// @notice Test initialization of the contract
    /// @dev Verifies that the contract is initialized correctly
    function testInitialization() public {
        assertTrue(store.hasRole(store.DEFAULT_ADMIN_ROLE(), address(this)));
        assertTrue(store.hasRole(store.PAUSER_ROLE(), address(this)));
        assertTrue(store.hasRole(store.UPGRADER_ROLE(), address(this)));
    }

    /// @notice Test basic secret registration functionality
    /// @dev Verifies that a secret can be registered with valid signatures
    function testRegisterSecret() public {
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        
        vm.expectEmit(true, true, true, true);
        emit SecretStore.SecretRegistered(
            TEST_SECRET_HASH,
            partyA,
            partyB,
            block.timestamp,
            block.number
        );

        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        (address storedPartyA, address storedPartyB,,,) = store.agreements(TEST_SECRET_HASH);
        assertEq(storedPartyA, partyA);
        assertEq(storedPartyB, partyB);
    }

    /// @notice Test prevention of duplicate secret registration
    /// @dev Verifies that the same secret hash cannot be registered twice
    /// @custom:security Critical for preventing replay attacks
    function testCannotRegisterSameSecretTwice() public {
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        vm.expectRevert("Secret already registered");
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);
    }

    /// @notice Test prevention of using same address for both parties
    /// @dev Verifies that partyA and partyB must be different addresses
    /// @custom:security Important for maintaining proper two-party security model
    function testCannotRegisterWithSameParties() public {
        (bytes memory signatureA, ) = _createSignaturesHelper(TEST_SECRET_HASH);

        vm.expectRevert("Parties must be different");
        store.registerSecret(TEST_SECRET_HASH, partyA, partyA, signatureA, signatureA);
    }

    /// @notice Test secret revelation by authorized party
    /// @dev Verifies that partyA can reveal the secret with correct salt
    function testRevealSecret() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Reveal the secret as partyA
        vm.prank(partyA);
        vm.expectEmit(true, true, true, true);
        emit SecretStore.SecretRevealed(
            TEST_SECRET_HASH,
            TEST_SECRET,
            partyA,
            block.timestamp,
            block.number
        );

        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);

        // Verify agreement is deleted
        (address storedPartyA,,,,) = store.agreements(TEST_SECRET_HASH);
        assertEq(storedPartyA, address(0), "Agreement should be deleted");
    }

    /// @notice Test secret revelation by second party
    /// @dev Verifies that partyB can also reveal the secret
    /// @custom:security Demonstrates equal access rights for both parties
    function testRevealSecretByPartyB() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Reveal the secret as partyB
        vm.prank(partyB);
        vm.expectEmit(true, true, true, true);
        emit SecretStore.SecretRevealed(
            TEST_SECRET_HASH,
            TEST_SECRET,
            partyB,
            block.timestamp,
            block.number
        );

        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);

        // Verify agreement is deleted
        (address storedPartyA,,,,) = store.agreements(TEST_SECRET_HASH);
        assertEq(storedPartyA, address(0), "Agreement should be deleted");
    }

    /// @notice Test prevention of unauthorized revelation
    /// @dev Verifies that non-participants cannot reveal secrets
    /// @custom:security Critical access control test
    function testCannotRevealByNonParticipant() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Try to reveal as non-participant
        vm.prank(address(4));
        vm.expectRevert("Only participants can reveal");
        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);
    }

    /// @notice Test prevention of wrong secret revelation
    /// @dev Verifies that incorrect secrets are rejected
    function testCannotRevealWithWrongSecret() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Try to reveal with wrong secret
        vm.prank(partyA);
        vm.expectRevert("Invalid secret or salt");
        store.revealSecret("wrong secret", TEST_SALT, TEST_SECRET_HASH);
    }

    /// @notice Test prevention of wrong salt usage
    /// @dev Verifies that incorrect salts are rejected
    /// @custom:security Important for rainbow table attack prevention
    function testCannotRevealWithWrongSalt() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Try to reveal with wrong salt
        vm.prank(partyA);
        vm.expectRevert("Invalid secret or salt");
        store.revealSecret(TEST_SECRET, bytes32(uint256(456)), TEST_SECRET_HASH);
    }

    /// @notice Test prevention of revealing non-existent secrets
    /// @dev Verifies proper handling of non-existent agreements
    /// @custom:security Critical for preventing unauthorized access through default values
    function testCannotRevealNonExistentSecret() public {
        // Try to reveal a secret that was never registered
        vm.prank(partyA);
        vm.expectRevert("Agreement does not exist");
        store.revealSecret(TEST_SECRET, TEST_SALT, bytes32(uint256(999)));
    }

    /// @notice Test double revelation prevention
    /// @dev Verifies that revealed secrets cannot be revealed again
    /// @custom:security Important for preventing replay attacks
    function testCannotRevealTwice() public {
        // First register and reveal
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);
        
        vm.prank(partyA);
        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);

        // Try to reveal again - should fail because agreement is deleted
        vm.prank(partyB);
        vm.expectRevert("Agreement does not exist");
        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);
    }

    /// @notice Test agreement existence checks
    /// @dev Verifies proper handling of agreement existence states
    /// @custom:security Critical for preventing operations on non-existent agreements
    function testAgreementExistsCheck() public {
        // Check non-existent agreement
        (bool exists, address partyA_, address partyB_) = store.agreementExists(TEST_SECRET_HASH);
        assertFalse(exists, "Agreement should not exist");
        assertEq(partyA_, address(0), "PartyA should be zero");
        assertEq(partyB_, address(0), "PartyB should be zero");

        // Register agreement
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Check existing agreement
        (exists, partyA_, partyB_) = store.agreementExists(TEST_SECRET_HASH);
        assertTrue(exists, "Agreement should exist");
        assertEq(partyA_, partyA, "PartyA should match");
        assertEq(partyB_, partyB, "PartyB should match");

        // Reveal secret and verify agreement is deleted
        vm.prank(partyA);
        vm.expectEmit(true, true, true, true);
        emit SecretStore.AgreementDeleted(TEST_SECRET_HASH, partyA);
        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);

        // Check agreement is deleted
        (exists, partyA_, partyB_) = store.agreementExists(TEST_SECRET_HASH);
        assertFalse(exists, "Agreement should not exist after deletion");
        assertEq(partyA_, address(0), "PartyA should be zero after deletion");
        assertEq(partyB_, address(0), "PartyB should be zero after deletion");
    }

    // EIP-712 type hashes
    bytes32 constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant AGREEMENT_TYPE_HASH =
        keccak256("Agreement(bytes32 secretHash,address partyA,address partyB)");

    event Debug_Signature(
        bytes32 structHash,
        bytes32 digest,
        address recovered,
        address expected
    );

    /// @notice Helper function to create test signatures
    /// @dev Generates EIP-712 compliant signatures for both parties
    function _createSignaturesHelper(bytes32 hash) 
        internal 
        returns (bytes memory signatureA, bytes memory signatureB) 
    {
        bytes32 structHash = keccak256(
            abi.encode(
                AGREEMENT_TYPE_HASH,
                hash,
                partyA,
                partyB
            )
        );

        bytes32 domainSeparator = store.DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(PARTY_A_PRIVATE_KEY, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(PARTY_B_PRIVATE_KEY, digest);

        signatureA = abi.encodePacked(r1, s1, v1);
        signatureB = abi.encodePacked(r2, s2, v2);

        emit Debug_Signature(structHash, digest, ecrecover(digest, v1, r1, s1), partyA);
        emit Debug_Signature(structHash, digest, ecrecover(digest, v2, r2, s2), partyB);
    }
}
