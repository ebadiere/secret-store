// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {SecretStore} from "../src/SecretStore.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC1967} from "@openzeppelin/contracts/interfaces/IERC1967.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

interface IUpgradeableProxy {
    function upgradeTo(address newImplementation) external;
}

/// @title SecretStore Test Suite
/// @notice Comprehensive test coverage for SecretStore functionality and security
/// @dev Tests verify:
/// 1. EIP-712 signature validation and replay protection
/// 2. Two-party registration with single-party revelation flow
/// 3. Storage efficiency and state management
/// 4. Access control and upgrade safety
///
/// Key security aspects tested:
/// 1. Role-based access control enforcement
/// 2. Domain separation for signatures
/// 3. Agreement lifecycle management
/// 4. Upgrade path protection
contract SecretStoreTest is Test {
    using MessageHashUtils for bytes32;

    /// @notice Core test values for secret management
    /// @dev Constants ensure consistent and reproducible test scenarios:
    /// - Secret and salt combine to create a unique hash
    /// - Hash function matches production implementation
    /// - 32-byte hash provides fixed storage footprint
    string constant TEST_SECRET = "my secret message";
    bytes32 constant TEST_SALT = bytes32(uint256(123));
    bytes32 constant TEST_SECRET_HASH = keccak256(abi.encodePacked(TEST_SECRET, TEST_SALT));
    
    /// @notice Test participant configuration
    /// @dev Uses deterministic keys for reproducible tests:
    /// - Addresses derived from known private keys
    /// - Keys used only for testing, never in production
    SecretStore public store;
    address public partyA;
    address public partyB;
    uint256 public PARTY_A_PRIVATE_KEY = 0x1234;
    uint256 public PARTY_B_PRIVATE_KEY = 0x5678;

    // Events for validating pause functionality
    event SecretStorePaused(address indexed account);
    event SecretStoreUnpaused(address indexed account);

    /// @notice Test environment initialization
    /// @dev Follows production deployment pattern:
    /// 1. Implementation contract deployment
    /// 2. Proxy deployment with implementation address
    /// 3. Initialization through proxy
    /// Note: While we use UUPS pattern (EIP-1822) for upgrade logic placement,
    /// we use ERC1967Proxy as it implements both UUPS compatibility and
    /// standardized storage slots (ERC1967) for proxy state
    function setUp() public {
        store = new SecretStore();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(store),
            abi.encodeCall(SecretStore.initialize, (address(this)))
        );
        store = SecretStore(address(proxy));

        // Set up test addresses
        partyA = vm.addr(PARTY_A_PRIVATE_KEY);
        partyB = vm.addr(PARTY_B_PRIVATE_KEY);
    }

    /// @notice Test initialization of roles
    /// @dev Verifies that the deployer address (test contract) is granted:
    /// - DEFAULT_ADMIN_ROLE for overall access control
    /// - PAUSER_ROLE for emergency stops
    /// - UPGRADER_ROLE for contract upgrades
    function testInitialization() public {
        // Verify all required roles are granted to deployer
        bytes32 adminRole = store.DEFAULT_ADMIN_ROLE();
        bytes32 pauserRole = store.PAUSER_ROLE();
        bytes32 upgraderRole = store.UPGRADER_ROLE();
        
        assertTrue(store.hasRole(adminRole, address(this)), "Admin role not granted");
        assertTrue(store.hasRole(pauserRole, address(this)), "Pauser role not granted");
        assertTrue(store.hasRole(upgraderRole, address(this)), "Upgrader role not granted");
    }

    /// @notice Test zero address admin initialization
    function testCannotInitializeWithZeroAddress() public {
        SecretStore implementation = new SecretStore();
        vm.expectRevert("Deployer cannot be zero address");
        new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(SecretStore.initialize, (address(0)))
        );
    }

    /// @notice Test basic secret registration functionality
    /// @dev Verifies that a secret can be registered with valid signatures
    /// @custom:security Verifies proper EIP-712 signature validation
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

        (address storedPartyA, address storedPartyB) = _getParties(TEST_SECRET_HASH);
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
    /// @custom:security Verifies proper access control and event emission
    function testRevealSecret() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Reveal the secret as partyA
        vm.prank(partyA);
        vm.expectEmit(true, true, true, true);
        emit SecretStore.SecretRevealed(
            TEST_SECRET_HASH,
            partyA,
            TEST_SECRET
        );

        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);

        // Verify agreement is deleted
        (address storedPartyA, ) = _getParties(TEST_SECRET_HASH);
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
            partyB,
            TEST_SECRET
        );

        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);

        // Verify agreement is deleted
        (address storedPartyA, ) = _getParties(TEST_SECRET_HASH);
        assertEq(storedPartyA, address(0), "Agreement should be deleted");
    }

    /// @notice Test prevention of unauthorized revelation
    /// @dev Verifies that non-participants cannot reveal secrets
    /// @custom:security Critical access control test
    function testCannotRevealByNonParticipant() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Verify agreement is stored
        (address storedPartyA, address storedPartyB) = _getParties(TEST_SECRET_HASH);
        assertEq(storedPartyA, partyA, "PartyA not stored correctly");
        assertEq(storedPartyB, partyB, "PartyB not stored correctly");

        // Try to reveal as non-party
        vm.prank(address(4));
        vm.expectRevert("Not a party to agreement");
        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);
    }

    /// @notice Test prevention of wrong secret revelation
    /// @dev Verifies that incorrect secrets are rejected
    /// @custom:security Ensures secrets can only be revealed with correct values
    function testCannotRevealWithWrongSecret() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Verify agreement is stored
        (address storedPartyA, address storedPartyB) = _getParties(TEST_SECRET_HASH);
        assertEq(storedPartyA, partyA, "PartyA not stored correctly");
        assertEq(storedPartyB, partyB, "PartyB not stored correctly");

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
        (bool exists, address partyA_, address partyB_) = _checkAgreement(TEST_SECRET_HASH);
        assertFalse(exists, "Agreement should not exist");
        assertEq(partyA_, address(0), "PartyA should be zero");
        assertEq(partyB_, address(0), "PartyB should be zero");

        // Register agreement
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Check existing agreement
        (exists, partyA_, partyB_) = _checkAgreement(TEST_SECRET_HASH);
        assertTrue(exists, "Agreement should exist");
        assertEq(partyA_, partyA, "PartyA should match");
        assertEq(partyB_, partyB, "PartyB should match");

        // Reveal secret and verify agreement is deleted
        vm.prank(partyA);
        vm.expectEmit(true, true, true, true);
        emit SecretStore.AgreementDeleted(TEST_SECRET_HASH, partyA);
        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);

        // Check agreement is deleted
        (exists, partyA_, partyB_) = _checkAgreement(TEST_SECRET_HASH);
        assertFalse(exists, "Agreement should not exist after deletion");
        assertEq(partyA_, address(0), "PartyA should be zero after deletion");
        assertEq(partyB_, address(0), "PartyB should be zero after deletion");
    }

    /// @notice Test pausing functionality
    /// @dev Verifies that contract can be paused and operations are blocked
    function testPause() public {
        // First register a secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Pause the contract
        store.pause();
        assertTrue(store.paused(), "Contract should be paused");

        // Try to register a new secret while paused
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Try to reveal a secret while paused
        vm.prank(partyA);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);

        // Unpause and verify operations work again
        store.unpause();
        assertFalse(store.paused(), "Contract should not be paused");
        
        // Should be able to register a new secret after unpausing
        bytes32 newSecretHash = keccak256(abi.encodePacked("new secret"));
        (signatureA, signatureB) = _createSignaturesHelper(newSecretHash);
        store.registerSecret(newSecretHash, partyA, partyB, signatureA, signatureB);
    }

    /// @notice Test pause access control
    /// @dev Verifies that only PAUSER_ROLE can pause/unpause
    function testPauseAccessControl() public {
        address nonPauser = makeAddr("nonPauser");
        
        // Try to pause from non-pauser account
        vm.startPrank(nonPauser);
        vm.expectRevert(accessControlError(nonPauser, store.PAUSER_ROLE()));
        store.pause();
        vm.stopPrank();

        // Pause from authorized account
        store.pause();
        assertTrue(store.paused(), "Contract should be paused");

        // Try to unpause from non-pauser account
        vm.startPrank(nonPauser);
        vm.expectRevert(accessControlError(nonPauser, store.PAUSER_ROLE()));
        store.unpause();
        vm.stopPrank();

        // Unpause from authorized account
        store.unpause();
        assertFalse(store.paused(), "Contract should not be paused");
    }

    /// @notice Test role management functionality
    /// @dev Verifies role granting, revoking, and renouncing
    function testRoleManagement() public {
        address newAdmin = makeAddr("newAdmin");
        address newPauser = makeAddr("newPauser");
        address another = makeAddr("another");

        // Grant roles
        store.grantRole(store.DEFAULT_ADMIN_ROLE(), newAdmin);
        assertTrue(store.hasRole(store.DEFAULT_ADMIN_ROLE(), newAdmin), "Role should be granted");

        vm.startPrank(newAdmin);
        store.grantRole(store.PAUSER_ROLE(), newPauser);
        assertTrue(store.hasRole(store.PAUSER_ROLE(), newPauser), "Role should be granted");
        vm.stopPrank();

        // Non-admin cannot grant roles
        vm.startPrank(newPauser);
        bytes32 role = store.PAUSER_ROLE();
        vm.expectRevert(accessControlError(newPauser, store.DEFAULT_ADMIN_ROLE()));
        store.grantRole(role, another);
        vm.stopPrank();

        // Admin can revoke roles
        vm.startPrank(newAdmin);
        store.revokeRole(store.PAUSER_ROLE(), newPauser);
        assertFalse(store.hasRole(store.PAUSER_ROLE(), newPauser), "Role should be revoked");
        vm.stopPrank();

        // Account can renounce its own role
        store.renounceRole(store.DEFAULT_ADMIN_ROLE(), address(this));
        assertFalse(store.hasRole(store.DEFAULT_ADMIN_ROLE(), address(this)), "Role should be renounced");
    }

    /// @notice Test role hierarchy
    /// @dev Verifies that only admin can manage other roles
    function testRoleHierarchy() public {
        address admin = makeAddr("admin");
        address pauser = makeAddr("pauser");
        address upgrader = makeAddr("upgrader");
        address another = makeAddr("another");

        // Grant admin role
        store.grantRole(store.DEFAULT_ADMIN_ROLE(), admin);

        // Admin can grant other roles
        vm.startPrank(admin);
        store.grantRole(store.PAUSER_ROLE(), pauser);
        store.grantRole(store.UPGRADER_ROLE(), upgrader);
        vm.stopPrank();

        // Non-admin roles cannot grant roles
        vm.startPrank(pauser);
        bytes32 role = store.PAUSER_ROLE();
        vm.expectRevert(accessControlError(pauser, store.DEFAULT_ADMIN_ROLE()));
        store.grantRole(role, another);
        vm.stopPrank();

        vm.startPrank(upgrader);
        role = store.UPGRADER_ROLE();
        vm.expectRevert(accessControlError(upgrader, store.DEFAULT_ADMIN_ROLE()));
        store.grantRole(role, another);
        vm.stopPrank();

        // Only admin can revoke roles
        vm.startPrank(pauser);
        role = store.PAUSER_ROLE();
        vm.expectRevert(accessControlError(pauser, store.DEFAULT_ADMIN_ROLE()));
        store.revokeRole(role, another);
        vm.stopPrank();

        // Admin can revoke all roles
        vm.startPrank(admin);
        store.revokeRole(store.PAUSER_ROLE(), pauser);
        store.revokeRole(store.UPGRADER_ROLE(), upgrader);
        assertFalse(store.hasRole(store.PAUSER_ROLE(), pauser), "Pauser role should be revoked");
        assertFalse(store.hasRole(store.UPGRADER_ROLE(), upgrader), "Upgrader role should be revoked");
        vm.stopPrank();
    }

    /// @notice Test role separation
    /// @dev Verifies that roles have distinct permissions
    function testRoleSeparation() public {
        address pauser = makeAddr("pauser");
        address upgrader = makeAddr("upgrader");
        address newImplementation = makeAddr("newImplementation");

        // Grant specific roles
        store.grantRole(store.PAUSER_ROLE(), pauser);
        store.grantRole(store.UPGRADER_ROLE(), upgrader);

        // Pauser can pause but not upgrade
        vm.startPrank(pauser);
        store.pause();
        vm.expectRevert(accessControlError(pauser, store.UPGRADER_ROLE()));
        store.upgradeToAndCall(newImplementation, "");
        vm.stopPrank();

        // Upgrader can upgrade but not pause
        vm.startPrank(upgrader);
        vm.expectRevert(accessControlError(upgrader, store.PAUSER_ROLE()));
        store.unpause();
        vm.stopPrank();
    }

    /// @notice Test that invalid signatures are rejected
    /// @dev Verifies that signatures must be from the correct parties
    function testCannotRegisterWithInvalidSignatures() public {
        // Create signatures but swap them (partyA signs for partyB and vice versa)
        bytes32 structHash = keccak256(
            abi.encode(
                store.AGREEMENT_TYPE_HASH(),
                TEST_SECRET_HASH,
                partyA,
                partyB
            )
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(
            store.DOMAIN_SEPARATOR(),  // Using first contract's domain
            structHash
        );

        // First test: invalid partyA signature
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(0x9999, digest); // random address signs
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(PARTY_B_PRIVATE_KEY, digest); // partyB signs correctly

        bytes memory invalidSigA = abi.encodePacked(r1, s1, v1);
        bytes memory validSigB = abi.encodePacked(r2, s2, v2);

        // Try to register with invalid partyA signature
        vm.expectRevert("Invalid signature from partyA");
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, invalidSigA, validSigB);

        // Second test: swapped signatures
        (v1, r1, s1) = vm.sign(PARTY_B_PRIVATE_KEY, digest); // partyB signs
        (v2, r2, s2) = vm.sign(PARTY_A_PRIVATE_KEY, digest); // partyA signs

        bytes memory wrongSigA = abi.encodePacked(r1, s1, v1); // Using partyB's signature for partyA
        bytes memory wrongSigB = abi.encodePacked(r2, s2, v2); // Using partyA's signature for partyB

        // Try to register with wrong signatures
        vm.expectRevert("Invalid signature from partyA");
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, wrongSigA, wrongSigB);

        // Third test: valid partyA but invalid partyB signature
        (v1, r1, s1) = vm.sign(PARTY_A_PRIVATE_KEY, digest); // partyA signs correctly
        (v2, r2, s2) = vm.sign(0x8888, digest); // different random address signs

        bytes memory validSigA = abi.encodePacked(r1, s1, v1);
        bytes memory invalidSigB = abi.encodePacked(r2, s2, v2);

        // Try to register with invalid partyB signature
        vm.expectRevert("Invalid signature from partyB");
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, validSigA, invalidSigB);
    }

    /// @notice Test verifyingContract protection in EIP-712
    function testCannotReuseSignatureAcrossContracts() public {
        // Deploy a second instance of SecretStore with proper initialization
        SecretStore implementation = new SecretStore();
        address storeAdmin = makeAddr("storeAdmin");
        
        // Deploy proxy and initialize
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(SecretStore.initialize, (storeAdmin))
        );
        SecretStore storeTwo = SecretStore(address(proxy));
        
        vm.startPrank(storeAdmin);
        storeTwo.grantRole(store.DEFAULT_ADMIN_ROLE(), storeAdmin);
        storeTwo.grantRole(store.UPGRADER_ROLE(), storeAdmin);
        storeTwo.grantRole(store.PAUSER_ROLE(), storeAdmin);
        vm.stopPrank();

        // Create signatures using domain separator from first contract
        bytes32 structHash = keccak256(
            abi.encode(
                store.AGREEMENT_TYPE_HASH(),
                TEST_SECRET_HASH,
                partyA,
                partyB
            )
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(
            store.DOMAIN_SEPARATOR(),  // Using first contract's domain
            structHash
        );

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(PARTY_A_PRIVATE_KEY, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(PARTY_B_PRIVATE_KEY, digest);

        bytes memory sigA = abi.encodePacked(r1, s1, v1);
        bytes memory sigB = abi.encodePacked(r2, s2, v2);

        // Try to use these signatures with the second contract
        vm.expectRevert("Invalid signature from partyA");
        storeTwo.registerSecret(TEST_SECRET_HASH, partyA, partyB, sigA, sigB);

        // Verify the signatures still work with the original contract
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, sigA, sigB);
        
        // Check agreement exists in original contract
        (address storedPartyA, ) = _getParties(TEST_SECRET_HASH);
        assertEq(storedPartyA, partyA, "Agreement should be registered in original contract");
    }

    /// @notice Helper to format AccessControl error message
    /// @dev Creates the expected error message for role-based access control
    function accessControlError(address account, bytes32 role) internal pure returns (bytes memory) {
        return abi.encodeWithSignature(
            "AccessControlUnauthorizedAccount(address,bytes32)",
            account,
            role
        );
    }

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

    /// @notice Helper function to create signatures for testing
    /// @dev Creates EIP-712 signatures for partyA and partyB
    /// @param hash The secret hash to sign
    /// @return signatureA The signature from partyA
    /// @return signatureB The signature from partyB
    function _createSignaturesHelper(bytes32 hash) 
        internal 
        returns (bytes memory signatureA, bytes memory signatureB) 
    {
        bytes32 structHash = keccak256(
            abi.encode(
                store.AGREEMENT_TYPE_HASH(),
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

    /// @notice Helper function to get parties from an agreement
    /// @dev Extracts party addresses while ignoring timestamp and blockNumber
    /// @param secretHash The hash identifying the agreement
    /// @return Two addresses: partyA and partyB (zero addresses if agreement doesn't exist)
    function _getParties(bytes32 secretHash) internal view returns (address, address) {
        (address storedPartyA, address storedPartyB, , ) = store.agreements(secretHash);
        return (storedPartyA, storedPartyB);
    }

    /// @notice Helper function to check agreement existence and get party addresses
    /// @dev Replaces the contract's agreementExists function for testing purposes
    function _checkAgreement(bytes32 secretHash)
        internal
        view
        returns (bool exists, address partyA_, address partyB_)
    {
        (partyA_, partyB_, ,) = store.agreements(secretHash);
        exists = partyA_ != address(0);
    }

    /// @notice Test pause event emission
    /// @dev Verifies that the SecretStorePaused event is emitted with correct parameters
    function testPauseEvent() public {
        address pauser = makeAddr("pauser");
        bytes32 pauserRole = store.PAUSER_ROLE();
        vm.startPrank(address(this));
        store.grantRole(pauserRole, pauser);
        vm.stopPrank();

        vm.startPrank(pauser);
        vm.expectEmit(true, false, false, false);
        emit SecretStorePaused(pauser);
        store.pause();
        vm.stopPrank();
    }

    /// @notice Test unpause event emission
    /// @dev Verifies that the SecretStoreUnpaused event is emitted with correct parameters
    function testUnpauseEvent() public {
        address pauser = makeAddr("pauser");
        bytes32 pauserRole = store.PAUSER_ROLE();
        vm.startPrank(address(this));
        store.grantRole(pauserRole, pauser);
        vm.stopPrank();

        vm.startPrank(pauser);
        store.pause();
        vm.expectEmit(true, false, false, false);
        emit SecretStoreUnpaused(pauser);
        store.unpause();
        vm.stopPrank();
    }
}
