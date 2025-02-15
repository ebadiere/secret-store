// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Test} from "forge-std/Test.sol";
import {SecretStore} from "../src/SecretStore.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/// @title SecretStoreUpgradeTest
/// @notice Comprehensive testing of UUPS proxy upgrade mechanisms
contract SecretStoreUpgradeTest is Test {
    using MessageHashUtils for bytes32;

    event Upgraded(address indexed implementation);

    // Test constants
    bytes32 constant TEST_SECRET_HASH =
        0x1234567890123456789012345678901234567890123456789012345678901234;
    string constant TEST_SECRET = "test_secret";
    bytes32 constant TEST_SALT =
        0x4321432143214321432143214321432143214321432143214321432143214321;

    // Contract instances
    SecretStore public implementation;
    SecretStore public store;
    ERC1967Proxy public proxy;
    address public admin;
    uint256 constant PARTY_A_KEY = 0x1;
    uint256 constant PARTY_B_KEY = 0x2;
    address partyA;
    address partyB;

    // ERC1967 implementation slot
    bytes32 internal constant _IMPLEMENTATION_SLOT = 
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    bytes32 private constant AGREEMENT_TYPE_HASH =
        keccak256("Agreement(bytes32 secretHash,address partyA,address partyB)");

    /// @notice Set up the test environment
    /// @dev Creates a new proxy contract and initializes it with test data
    function setUp() public {
        admin = address(this);
        partyA = vm.addr(PARTY_A_KEY);
        partyB = vm.addr(PARTY_B_KEY);
        
        implementation = new SecretStore();
        proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(SecretStore.initialize, (address(this)))
        );
        store = SecretStore(address(proxy));

        store.grantRole(store.UPGRADER_ROLE(), admin);
        store.grantRole(store.PAUSER_ROLE(), admin);
    }

    /// @notice Test initialization with zero address
    /// @dev Verifies:
    /// 1. Initialization with zero address is rejected
    /// 2. Prevents accidental proxy bricking
    /// 3. Maintains upgrade safety checks
    function testCannotInitializeWithZeroAddress() public {
        vm.startPrank(admin);
        store.pause();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        store.initialize(address(0));
        vm.stopPrank();
    }

    /// @notice Test double initialization
    /// @dev Verifies:
    /// 1. Double initialization is rejected
    /// 2. Prevents accidental state corruption
    /// 3. Maintains upgrade safety checks
    function testCannotDoubleInitialize() public {
        vm.startPrank(admin);
        store.pause();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        store.initialize(admin);
        vm.stopPrank();
    }

    /// @notice Test upgrade with zero address
    /// @dev Verifies:
    /// 1. Upgrade to zero address is rejected
    /// 2. Prevents accidental proxy bricking
    /// 3. Maintains upgrade safety checks
    function testCannotUpgradeToZeroAddress() public {
        store.pause();
        vm.expectRevert(SecretStore.ZeroAddress.selector);
        store.upgradeToAndCall(address(0), "");
    }

    /// @notice Test upgrade without required role
    /// @dev Verifies:
    /// 1. Only UPGRADER_ROLE can perform upgrades
    /// 2. Prevents unauthorized upgrades
    /// 3. Maintains upgrade safety checks
    function testCannotUpgradeWithoutRole() public {
        SecretStore newImplementation = new SecretStore();
        store.revokeRole(store.UPGRADER_ROLE(), admin);
        store.pause();

        bytes memory expectedError = abi.encodeWithSignature(
            "AccessControlUnauthorizedAccount(address,bytes32)",
            admin,
            store.UPGRADER_ROLE()
        );
        vm.expectRevert(expectedError);
        store.upgradeToAndCall(address(newImplementation), "");
    }

    /// @notice Test upgrade requires pause
    /// @dev Verifies:
    /// 1. Upgrades are rejected when contract is not paused
    /// 2. Upgrades succeed after pausing
    /// 3. Maintains upgrade safety checks
    function testUpgradeRequiresPause() public {
        SecretStore newImplementation = new SecretStore();
        
        // Try to upgrade without pausing first
        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.ExpectedPause.selector));
        store.upgradeToAndCall(address(newImplementation), "");
        
        // Now pause and upgrade should work
        store.pause();
        store.upgradeToAndCall(address(newImplementation), "");
        
        // Check implementation slot
        bytes32 implSlot = vm.load(address(store), _IMPLEMENTATION_SLOT);
        assertEq(address(uint160(uint256(implSlot))), address(newImplementation));
    }

    /// @notice Test storage preservation during upgrade
    /// @dev Verifies:
    /// 1. Agreement data is preserved during upgrade
    /// 2. New implementation can access old storage
    /// 3. Maintains data integrity
    function testStoragePreservation() public {
        bytes32 secretHash = keccak256(abi.encodePacked("test secret"));
        
        bytes32 structHash = keccak256(
            abi.encode(
                AGREEMENT_TYPE_HASH,
                secretHash,
                partyA,
                partyB
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                store.DOMAIN_SEPARATOR(),
                structHash
            )
        );

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(PARTY_A_KEY, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(PARTY_B_KEY, digest);
        bytes memory signatureA = abi.encodePacked(r1, s1, v1);
        bytes memory signatureB = abi.encodePacked(r2, s2, v2);
        
        store.registerSecret(secretHash, partyA, partyB, signatureA, signatureB);
        
        SecretStore newImplementation = new SecretStore();
        store.pause();
        store.upgradeToAndCall(address(newImplementation), "");
        
        (address storedPartyA, uint96 timestamp, address storedPartyB, uint64 blockNumber) = store.agreements(secretHash);
        assertEq(storedPartyA, partyA, "PartyA not preserved after upgrade");
        assertEq(storedPartyB, partyB, "PartyB not preserved after upgrade");
        assertTrue(timestamp > 0, "Timestamp should be set");
        assertTrue(blockNumber > 0, "Block number should be set");
        
        assertTrue(store.hasRole(store.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(store.hasRole(store.PAUSER_ROLE(), admin));
        assertTrue(store.hasRole(store.UPGRADER_ROLE(), admin));
    }

    /// @dev Helper function to generate test signatures
    /// This simulates both parties signing the agreement
    function _generateTestSignatures() internal {
        // Create signing keys
        uint256 privKeyA = 0x1234;
        uint256 privKeyB = 0x5678;
        address signerA = vm.addr(privKeyA);
        address signerB = vm.addr(privKeyB);

        // Prepare EIP-712 hash
        bytes32 structHash = keccak256(
            abi.encode(
                store.AGREEMENT_TYPE_HASH(),
                TEST_SECRET_HASH,
                partyA,
                partyB
            )
        );

        bytes32 digest = structHash.toEthSignedMessageHash();

        // Generate signatures
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privKeyA, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privKeyB, digest);

        // Format signatures
        bytes memory signatureA = abi.encodePacked(r1, s1, v1);
        bytes memory signatureB = abi.encodePacked(r2, s2, v2);
    }
}
