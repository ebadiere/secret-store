// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Test} from "forge-std/Test.sol";
import {SecretStore} from "../src/SecretStore.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/// @title SecretStoreUpgradeTest
/// @notice Test suite for upgrade-specific functionality of SecretStore
/// @dev Tests upgradeability concerns and security
contract SecretStoreUpgradeTest is Test {
    using MessageHashUtils for bytes32;

    SecretStore public implementation;
    SecretStore public store;
    ERC1967Proxy public proxy;
    address public admin;
    uint256 constant PARTY_A_KEY = 0x1;
    uint256 constant PARTY_B_KEY = 0x2;
    address partyA;
    address partyB;

    // EIP-712 type hashes
    bytes32 private constant AGREEMENT_TYPE_HASH =
        keccak256("Agreement(bytes32 secretHash,address partyA,address partyB)");

    function setUp() public {
        admin = address(this);
        partyA = vm.addr(PARTY_A_KEY);
        partyB = vm.addr(PARTY_B_KEY);
        
        // Deploy implementation and proxy
        implementation = new SecretStore();
        proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(SecretStore.initialize, (address(this)))
        );
        store = SecretStore(address(proxy));

        // Grant roles
        store.grantRole(store.UPGRADER_ROLE(), admin);
        store.grantRole(store.PAUSER_ROLE(), admin);
    }

    /// @notice Test proper initialization
    /// @dev Verifies that initialize can only be called once
    function testCannotInitializeTwice() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        store.initialize(address(this));
    }

    /// @notice Test upgrade authorization
    /// @dev Verifies that only UPGRADER_ROLE can upgrade
    function testOnlyUpgraderCanUpgrade() public {
        SecretStore newImplementation = new SecretStore();
        
        // Try to upgrade from non-upgrader account
        address nonUpgrader = address(0x123);
        vm.startPrank(nonUpgrader);
        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")),
                nonUpgrader,
                store.UPGRADER_ROLE()
            )
        );
        store.upgradeToAndCall(address(newImplementation), "");
        vm.stopPrank();

        // Upgrade from authorized account should work
        store.upgradeToAndCall(address(newImplementation), "");
    }

    /// @notice Test upgrade with invalid implementation
    /// @dev Verifies that zero address implementations are rejected
    function testCannotUpgradeToZeroAddress() public {
        vm.expectRevert("Invalid implementation address");
        store.upgradeToAndCall(address(0), "");
    }

    /// @notice Test state preservation during upgrade
    /// @dev Verifies that storage and roles are preserved after upgrade
    function testUpgradePreservesState() public {
        // Register a secret before upgrade
        bytes32 secretHash = keccak256(abi.encodePacked("test secret"));
        
        // Create valid signatures
        bytes32 structHash = keccak256(
            abi.encode(
                store.AGREEMENT_TYPE_HASH(),
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
        
        // Perform upgrade
        SecretStore newImplementation = new SecretStore();
        store.upgradeToAndCall(address(newImplementation), "");
        
        // Verify agreement storage after upgrade
        (address storedPartyA, address storedPartyB, , ) = store.agreements(secretHash);
        assertEq(storedPartyA, partyA, "PartyA not preserved after upgrade");
        assertEq(storedPartyB, partyB, "PartyB not preserved after upgrade");
        
        // Verify roles are preserved
        assertTrue(store.hasRole(store.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(store.hasRole(store.PAUSER_ROLE(), admin));
        assertTrue(store.hasRole(store.UPGRADER_ROLE(), admin));
    }

    /// @notice Helper function to get parties from an agreement
    /// @dev Extracts party addresses from the agreement mapping
    function _getParties(bytes32 secretHash) internal view returns (address, address) {
        (address storedPartyA, address storedPartyB, , ) = store.agreements(secretHash);
        return (storedPartyA, storedPartyB);
    }

    /// @notice Helper function to create EIP-712 signatures
    /// @dev Creates signatures for both parties using their private keys
    /// @param secretHash Hash of the secret and salt
    /// @return signatureA PartyA's signature
    /// @return signatureB PartyB's signature
    function _createSignaturesHelper(bytes32 secretHash) internal view returns (bytes memory signatureA, bytes memory signatureB) {
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
        signatureA = abi.encodePacked(r1, s1, v1);
        signatureB = abi.encodePacked(r2, s2, v2);
    }
}
