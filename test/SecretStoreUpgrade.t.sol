// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Test} from "forge-std/Test.sol";
import {SecretStore} from "../src/SecretStore.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/// @title SecretStoreUpgradeTest
/// @notice Comprehensive testing of UUPS proxy upgrade mechanisms
/// @dev Tests focus on critical upgrade security aspects:
/// 1. Initialization Safety: Preventing re-initialization attacks
/// 2. Access Control: Proper role-based upgrade permissions
/// 3. State Preservation: Data integrity across upgrades
/// 4. Implementation Validation: Preventing invalid upgrades
///
/// Security Considerations:
/// - Uses OpenZeppelin's UUPS pattern
/// - Follows ERC1967 proxy standards
/// - Implements role-based access control
contract SecretStoreUpgradeTest is Test {
    using MessageHashUtils for bytes32;

    event Upgraded(address indexed implementation);  // Standard UUPSUpgradeable event

    /// @dev Core contract instances and test accounts
    SecretStore public implementation;
    SecretStore public store;
    ERC1967Proxy public proxy;
    address public admin;
    uint256 constant PARTY_A_KEY = 0x1;
    uint256 constant PARTY_B_KEY = 0x2;
    address partyA;
    address partyB;

    /// @dev EIP-712 type hash for Agreement struct
    /// Matches the structure in the main contract
    bytes32 private constant AGREEMENT_TYPE_HASH =
        keccak256("Agreement(bytes32 secretHash,address partyA,address partyB)");

    /// @notice Test environment setup
    /// @dev Deployment process:
    /// 1. Deploy implementation contract
    /// 2. Deploy ERC1967 proxy
    /// 3. Initialize with admin
    /// 4. Configure upgrade permissions
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

    /// @notice Initialization security test
    /// @dev Verifies:
    /// 1. Initialization can only occur once
    /// 2. Prevents re-initialization attacks
    /// 3. Maintains initialization state integrity
    function testCannotInitializeTwice() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        store.initialize(address(this));
    }

    /// @notice Upgrade access control test
    /// @dev Verifies:
    /// 1. Only UPGRADER_ROLE can perform upgrades
    /// 2. Non-upgraders are properly rejected
    /// 3. Access control errors are properly formatted
    /// 
    /// Security note: Tests both positive and negative cases
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
        vm.startPrank(admin);
        vm.expectEmit(true, false, false, false);
        emit Upgraded(address(newImplementation));
        store.upgradeToAndCall(address(newImplementation), "");
        vm.stopPrank();
    }

    /// @notice Implementation address validation
    /// @dev Verifies:
    /// 1. Zero address upgrades are rejected
    /// 2. Prevents accidental proxy bricking
    /// 3. Maintains upgrade safety checks
    function testCannotUpgradeToZeroAddress() public {
        vm.expectRevert("Invalid implementation address");
        store.upgradeToAndCall(address(0), "");
    }

    /// @notice State preservation verification
    /// @dev Comprehensive upgrade state test:
    /// 1. Tests storage slots remain intact
    /// 2. Verifies role assignments persist
    /// 3. Validates agreement data integrity
    /// 
    /// Process:
    /// 1. Register pre-upgrade agreement
    /// 2. Perform upgrade
    /// 3. Verify all state remains accessible
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
        (address storedPartyA, , address storedPartyB, ) = store.agreements(secretHash);
        assertEq(storedPartyA, partyA, "PartyA not preserved after upgrade");
        assertEq(storedPartyB, partyB, "PartyB not preserved after upgrade");
        
        // Verify roles are preserved
        assertTrue(store.hasRole(store.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(store.hasRole(store.PAUSER_ROLE(), admin));
        assertTrue(store.hasRole(store.UPGRADER_ROLE(), admin));
    }

    /// @notice Agreement party retrieval utility
    /// @dev Storage access helper:
    /// 1. Reads from agreement mapping
    /// 2. Extracts only party addresses
    /// 3. Ignores other agreement data
    /// 
    /// Used for:
    /// - State verification after upgrades
    /// - Party address validation
    /// @param secretHash Identifier for the agreement
    /// @return tuple(address, address) PartyA and PartyB addresses
    function _getParties(bytes32 secretHash) internal view returns (address, address) {
        (address storedPartyA, , address storedPartyB, ) = store.agreements(secretHash);
        return (storedPartyA, storedPartyB);
    }

    /// @notice EIP-712 signature generation utility
    /// @dev Signature creation process:
    /// 1. Builds typed data struct hash
    /// 2. Combines with domain separator
    /// 3. Signs with both party keys
    /// 
    /// Security considerations:
    /// - Uses EIP-712 for replay protection
    /// - Maintains signature order (A then B)
    /// - Uses deterministic keys for reproducibility
    /// @param secretHash Agreement identifier to sign
    /// @return signatureA EIP-712 signature from Party A
    /// @return signatureB EIP-712 signature from Party B
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
